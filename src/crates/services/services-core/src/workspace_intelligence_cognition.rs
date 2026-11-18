//! Durable cognition partition store for Workspace Intelligence P1.
//!
//! This module owns one SQLite database per **opaque scope**. Each database
//! holds a single `partition_state` row whose `cursor` and `incarnation_token`
//! are shape-only: this module never interprets, advances, assigns or checks
//! governance meaning for either value. Incarnation advancement (WP1.4) and
//! cursor/gap consumption (WP1.5) are owned elsewhere and are out of scope
//! here. The governed commit gate is the narrow runtime caller of this seam.
//!
//! # Layout and scope opacity
//!
//! A scope is stored at `<root>/<sha256_lower_hex(scope)>.sqlite`. The raw scope
//! string is never stored and never becomes a path component: the digest is the
//! only untrusted-input-derived part of the path, so a scope can never inject a
//! separator, a parent segment or a drive prefix.
//!
//! A scope key is an opaque storage identity, not an authorization grant. This
//! module derives no permission, project id or product fact from it; deciding
//! which scope a caller may touch belongs to the caller.
//!
//! Construction performs no IO: no directory creation, no open, no schema.
//!
//! # `read` observes, `initialize` writes
//!
//! [`WorkspaceIntelligenceCognitionStore::read`] opens the record read-only and
//! never creates the root, the record, a journal or a schema. It validates the
//! version, the table, the required columns and the row inside one deferred
//! read-only transaction, so a version check and the row read can never observe
//! different versions. `Ok(None)` means only "this call did not observe a file";
//! it is not proof of an accepted close, reset or delete, and it says nothing
//! about a file another process is about to publish.
//!
//! [`WorkspaceIntelligenceCognitionStore::initialize`] is the only writer. It
//! creates the schema only for a database that is version `0` and holds no user
//! objects, and it never adopts, repairs, resets or deletes a database it did
//! not create. An initialized database is returned as
//! [`CognitionInitialization::Existing`] without writing any user field.
//!
//! # Schema v1
//!
//! ```sql
//! CREATE TABLE partition_state (
//!     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
//!     partition_key TEXT NOT NULL,
//!     cursor TEXT,
//!     incarnation_token TEXT
//! );
//! ```
//!
//! `user_version` is `1` for this shape. A read accepts unknown extra columns,
//! unknown extra tables and unrelated objects and ignores them; it requires the
//! four columns above, exactly one row with `state_id = 1`, and a
//! `partition_key` that equals the caller's own scope digest.
//!
//! # Durability
//!
//! A returned initialization reports SQLite transactional commit semantics and
//! nothing more. This module adds no fsync of its own and makes no power-loss
//! claim about data that never reached the device. It also makes no
//! cross-process kill-testing claim, and a `cargo test` run of this module is
//! single-process evidence only.
//!
//! # Failed initialization
//!
//! Every error inside the initialization transaction rolls back, so no partial
//! table, no partial row and no advanced `user_version` survives. One honest
//! exception is the file itself: when `initialize` had to create a new record
//! file, a failed transaction may leave an empty `user_version == 0` file with no
//! user objects. The next explicit `initialize` legitimately retries that state.
//! This module never deletes or rewrites an existing file to recover from a
//! failure.
//!
//! # Blocking boundary
//!
//! This module is synchronous on purpose: no `tokio`, no async signature and no
//! runtime handle. The commit gate calls `initialize` through `spawn_blocking`
//! while holding the control guard. The API stays synchronous and gains no
//! cursor/token write path.

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Physical schema version this module writes and accepts.
pub const COGNITION_SCHEMA_VERSION: i64 = 1;

/// Record file extension; the file stem is the opaque scope digest.
const RECORD_FILE_EXTENSION: &str = "sqlite";

/// Name of the single table this module owns.
const PARTITION_STATE_TABLE: &str = "partition_state";

/// Columns a stored v1 partition row must provide.
const PARTITION_STATE_REQUIRED_COLUMNS: [&str; 4] = [
    "state_id",
    "partition_key",
    "cursor",
    "incarnation_token",
];

/// The only accepted `state_id`; the table is a singleton by construction.
const PARTITION_STATE_ID: i64 = 1;

/// How long an initialization waits for another writer's transaction.
const BUSY_TIMEOUT: Duration = Duration::from_secs(10);

/// Exactly the v1 physical shape. This v1 slice adds no `revision` or
/// `epoch_baseline_id`; WP1.6 defines those later and a future versioned
/// migration may add them. `control_generation` and policy never live here:
/// the authoritative control record stays their single truth.
const CREATE_PARTITION_STATE_SQL: &str = r#"
CREATE TABLE partition_state (
    state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
    partition_key TEXT NOT NULL,
    cursor TEXT,
    incarnation_token TEXT
);
"#;

/// A plain insert; the module never replaces an existing row.
const INSERT_PARTITION_ROW_SQL: &str = r#"
INSERT INTO partition_state (state_id, partition_key, cursor, incarnation_token)
VALUES (1, ?1, NULL, NULL);
"#;

const SET_SCHEMA_VERSION_SQL: &str = "PRAGMA user_version = 1;";
const READ_SCHEMA_VERSION_SQL: &str = "PRAGMA user_version;";
/// Names only: whether an object is internal is decided in Rust by an exact
/// prefix test, never by a SQL pattern. In SQL `LIKE 'sqlite_%'` the `_` is a
/// single-character wildcard, so that pattern also matches a legal user object
/// such as `sqliteXforeign`, and a foreign database would then look empty.
const SELECT_SCHEMA_OBJECT_NAMES_SQL: &str = "SELECT name FROM sqlite_master;";

/// Reserved prefix SQLite uses for objects it creates itself.
const INTERNAL_SCHEMA_OBJECT_PREFIX: &str = "sqlite_";
const SCHEMA_OBJECT_NAMED_SQL: &str =
    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1;";
const COUNT_PARTITION_ROWS_SQL: &str = "SELECT COUNT(*) FROM partition_state;";
const SELECT_PARTITION_ROW_SQL: &str =
    "SELECT state_id, partition_key, cursor, incarnation_token FROM partition_state;";

/// Structurally unusable parts of a stored v1 partition shape.
///
/// Codes are stable and never echo a stored value, so they are safe for logs and
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionShapeFault {
    /// `sqlite_master` has no `partition_state` table.
    StateTableMissing,
    /// `partition_state` has no `state_id` column.
    StateIdColumnMissing,
    /// `partition_state` has no `partition_key` column.
    PartitionKeyColumnMissing,
    /// `partition_state` has no `cursor` column.
    CursorColumnMissing,
    /// `partition_state` has no `incarnation_token` column.
    IncarnationTokenColumnMissing,
    /// `partition_state` does not hold exactly one row.
    PartitionRowCountNotSingleton,
    /// `state_id` is not an integer.
    StateIdNotInteger,
    /// `state_id` is an integer other than `1`.
    StateIdNotOne,
    /// `partition_key` is not a text value (including invalid UTF-8 text).
    PartitionKeyNotText,
    /// `partition_key` is text but empty or entirely whitespace.
    PartitionKeyEmpty,
    /// `cursor` is neither `NULL` nor a text value.
    CursorNotText,
    /// `incarnation_token` is neither `NULL` nor a text value.
    IncarnationTokenNotText,
}

impl PartitionShapeFault {
    /// Stable machine-readable code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateTableMissing => "state_table_missing",
            Self::StateIdColumnMissing => "state_id_column_missing",
            Self::PartitionKeyColumnMissing => "partition_key_column_missing",
            Self::CursorColumnMissing => "cursor_column_missing",
            Self::IncarnationTokenColumnMissing => "incarnation_token_column_missing",
            Self::PartitionRowCountNotSingleton => "partition_row_count_not_singleton",
            Self::StateIdNotInteger => "state_id_not_integer",
            Self::StateIdNotOne => "state_id_not_one",
            Self::PartitionKeyNotText => "partition_key_not_text",
            Self::PartitionKeyEmpty => "partition_key_empty",
            Self::CursorNotText => "cursor_not_text",
            Self::IncarnationTokenNotText => "incarnation_token_not_text",
        }
    }
}

impl fmt::Display for PartitionShapeFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Failures of the cognition partition store.
///
/// Error text never contains the raw scope string: a record path carries only
/// the scope digest.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceIntelligenceCognitionError {
    #[error("Cognition partition scope must be a non-blank opaque identifier")]
    EmptyScope,

    #[error("Cognition partition record {path} exists but is not a regular file")]
    RecordPathNotFile { path: PathBuf },

    #[error("Cognition partition record {path} is uninitialized (schema version 0)")]
    UninitializedDatabase { path: PathBuf },

    #[error(
        "Cognition partition record {path} holds objects this store did not create; the database is preserved and never adopted"
    )]
    UnrecognizedDatabase { path: PathBuf },

    #[error("Cognition partition record {path} uses unsupported schema version {observed}")]
    UnsupportedSchemaVersion { path: PathBuf, observed: i64 },

    #[error("Cognition partition record {path} has an unusable v1 shape: {fault}")]
    InvalidPartitionShape {
        path: PathBuf,
        fault: PartitionShapeFault,
    },

    #[error("Cognition partition record {path} has no partition_state row")]
    MissingPartitionRow { path: PathBuf },

    #[error("Cognition partition record {path} belongs to a different scope")]
    PartitionScopeMismatch { path: PathBuf },

    #[error("Cognition partition record {path} is not a readable SQLite database: {detail}")]
    CorruptDatabase { path: PathBuf, detail: String },

    #[error("Cognition partition record storage failed: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("Cognition partition record IO failed: {0}")]
    Io(#[from] std::io::Error),
}

impl WorkspaceIntelligenceCognitionError {
    /// Stable machine-readable code for the known failure modes.
    pub fn code(&self) -> &'static str {
        match self {
            Self::EmptyScope => "empty_scope",
            Self::RecordPathNotFile { .. } => "record_path_not_file",
            Self::UninitializedDatabase { .. } => "uninitialized_database",
            Self::UnrecognizedDatabase { .. } => "unrecognized_database",
            Self::UnsupportedSchemaVersion { .. } => "unsupported_schema_version",
            Self::InvalidPartitionShape { .. } => "invalid_partition_shape",
            Self::MissingPartitionRow { .. } => "missing_partition_row",
            Self::PartitionScopeMismatch { .. } => "partition_scope_mismatch",
            Self::CorruptDatabase { .. } => "corrupt_database",
            Self::Storage(_) => "sqlite_storage",
            Self::Io(_) => "io",
        }
    }

    /// Alias for [`Self::code`].
    pub fn as_str(&self) -> &'static str {
        self.code()
    }

    /// True when the stored v1 shape is structurally unusable.
    ///
    /// This covers a missing table or column, a wrong row shape, an unusable
    /// `partition_key` and a non-text `cursor` or `incarnation_token`. A
    /// partition key that belongs to another scope is a separate failure; see
    /// [`Self::is_scope_mismatch`].
    pub fn is_invalid_shape(&self) -> bool {
        matches!(self, Self::InvalidPartitionShape { .. } | Self::MissingPartitionRow { .. })
    }

    /// True when the stored row was written for a different scope.
    pub fn is_scope_mismatch(&self) -> bool {
        matches!(self, Self::PartitionScopeMismatch { .. })
    }

    /// Fault code of an invalid v1 shape, when the failure carries one.
    pub fn shape_fault_code(&self) -> Option<&'static str> {
        match self {
            Self::InvalidPartitionShape { fault, .. } => Some(fault.as_str()),
            _ => None,
        }
    }
}

/// Shape-only cognition partition state.
///
/// `cursor` and `incarnation_token` are opaque nullable text. This module never
/// interprets them, never advances them and never assigns governance meaning to
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitionPartitionState {
    /// Opaque cursor text, stored verbatim. Consumption is owned elsewhere.
    pub cursor: Option<String>,
    /// Opaque incarnation token text, stored verbatim. Advancement is owned
    /// elsewhere.
    pub incarnation_token: Option<String>,
}

/// Result of an explicit [`WorkspaceIntelligenceCognitionStore::initialize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CognitionInitialization {
    /// This call created the v1 schema and its single partition row.
    Initialized(CognitionPartitionState),
    /// The v1 partition already existed; no user field was written.
    Existing(CognitionPartitionState),
}

impl CognitionInitialization {
    /// The stored state after the call.
    pub fn state(&self) -> &CognitionPartitionState {
        match self {
            Self::Initialized(state) | Self::Existing(state) => state,
        }
    }

    /// True when this call created the schema.
    pub fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized(_))
    }
}

/// Durable cognition partition store over a host-injected, host-local root.
///
/// Each opaque scope maps to one SQLite database directly inside `root`.
#[derive(Debug)]
pub struct WorkspaceIntelligenceCognitionStore {
    root: PathBuf,
    #[cfg(test)]
    inject_initialize_failure: bool,
}

impl WorkspaceIntelligenceCognitionStore {
    /// Builds a store over a host-injected root.
    ///
    /// Construction performs no IO.
    pub fn new(root: PathBuf) -> Self {
        Self::build(root)
    }

    #[cfg(not(test))]
    fn build(root: PathBuf) -> Self {
        Self { root }
    }

    #[cfg(test)]
    fn build(root: PathBuf) -> Self {
        Self {
            root,
            inject_initialize_failure: false,
        }
    }

    /// Test-only constructor that makes the partition-creation transaction fail
    /// after it has written the table, the row and the version.
    ///
    /// This exists to prove rollback and is not part of the public API.
    #[cfg(test)]
    fn with_injected_initialize_failure(root: PathBuf) -> Self {
        Self {
            root,
            inject_initialize_failure: true,
        }
    }

    /// Creates the v1 partition for `scope` if, and only if, it does not exist.
    ///
    /// The call opens the record read-write without creating it, and creates the
    /// root directory plus the record only when the file is absent. Inside one
    /// immediate transaction it re-reads the schema version and the user objects
    /// and then decides. Objects SQLite creates itself (`sqlite_sequence`,
    /// `sqlite_stat1`, `sqlite_autoindex_*`) are classified by an exact
    /// `sqlite_` name prefix; every other object is a user object this store did
    /// not create:
    ///
    /// - version `0` with no user objects: create the v1 schema, insert the
    ///   single partition row and stamp the version, then commit;
    /// - version `0` with any user object: [`WorkspaceIntelligenceCognitionError::UnrecognizedDatabase`],
    ///   rolled back, bytes and objects untouched;
    /// - version `1`: validate exactly like [`Self::read`] and report
    ///   [`CognitionInitialization::Existing`] without writing any user field;
    /// - any other version: [`WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion`],
    ///   rolled back, file untouched.
    ///
    /// An invalid v1 shape is an explicit error: this call never repairs,
    /// migrates, resets or replaces what it did not write.
    pub fn initialize(
        &self,
        scope: &str,
    ) -> Result<CognitionInitialization, WorkspaceIntelligenceCognitionError> {
        let partition_key = scope_digest(scope)?;
        let path = self.record_path(&partition_key);

        let mut connection = match self.open_existing_record(&path, WRITE_FLAGS)? {
            Some(connection) => connection,
            None => self.create_and_open_record(&path)?,
        };
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|error| sqlite_error(&path, error))?;

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(&path, error))?;

        let observed_version = schema_version(&transaction, &path)?;
        let initialization = match observed_version {
            COGNITION_SCHEMA_VERSION => CognitionInitialization::Existing(
                observe_v1_partition(&transaction, &path, &partition_key)?,
            ),
            0 => {
                if user_object_count(&transaction, &path)? > 0 {
                    // A foreign database is preserved, never adopted, repaired,
                    // reset or deleted: the transaction rolls back and no
                    // partition_state table or version stamp is written.
                    return Err(
                        WorkspaceIntelligenceCognitionError::UnrecognizedDatabase { path },
                    );
                }
                self.create_v1_partition(&transaction, &path, &partition_key)?;
                CognitionInitialization::Initialized(CognitionPartitionState {
                    cursor: None,
                    incarnation_token: None,
                })
            }
            observed => {
                return Err(
                    WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion {
                        path,
                        observed,
                    },
                );
            }
        };

        transaction
            .commit()
            .map_err(|error| sqlite_error(&path, error))?;
        Ok(initialization)
    }

    /// Observes the partition state for `scope`.
    ///
    /// The record is opened read-only and is never created. Validation runs
    /// inside one deferred read-only transaction, so the version check, the
    /// table and column check and the row read all describe the same snapshot.
    ///
    /// `Ok(None)` means only that this call did not observe a file. It is not
    /// proof of an accepted close, reset or delete, and a caller must not treat
    /// it as one. A hot journal, a non-SQLite file, a permission problem or any
    /// other unreadable state is an explicit error, never `Ok(None)`.
    ///
    /// An uninitialized database is an explicit error: a read never creates a
    /// schema.
    pub fn read(
        &self,
        scope: &str,
    ) -> Result<Option<CognitionPartitionState>, WorkspaceIntelligenceCognitionError> {
        let partition_key = scope_digest(scope)?;
        let path = self.record_path(&partition_key);

        let Some(mut connection) = self.open_existing_record(&path, READ_FLAGS)? else {
            return Ok(None);
        };

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| sqlite_error(&path, error))?;

        let observed_version = schema_version(&transaction, &path)?;
        let state = match observed_version {
            COGNITION_SCHEMA_VERSION => {
                observe_v1_partition(&transaction, &path, &partition_key)?
            }
            0 => return Err(WorkspaceIntelligenceCognitionError::UninitializedDatabase { path }),
            observed => {
                return Err(
                    WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion {
                        path,
                        observed,
                    },
                );
            }
        };

        // A read-only transaction has nothing to commit; dropping it releases
        // the shared snapshot lock without letting SQLite write anything.
        drop(transaction);
        Ok(Some(state))
    }

    /// Record path for an already-hashed scope.
    ///
    /// The digest is the only untrusted-input-derived path component, so a scope
    /// can never introduce a separator, parent segment or drive prefix.
    fn record_path(&self, partition_key: &str) -> PathBuf {
        self.root
            .join(format!("{partition_key}.{RECORD_FILE_EXTENSION}"))
    }

    /// Opens an existing record without ever creating it.
    ///
    /// `Ok(None)` is returned only when the path does not exist at all. A path
    /// that exists but is not a regular file, or an existing record that cannot
    /// be opened, is an explicit error.
    fn open_existing_record(
        &self,
        path: &Path,
        flags: OpenFlags,
    ) -> Result<Option<Connection>, WorkspaceIntelligenceCognitionError> {
        match Connection::open_with_flags(path, flags) {
            Ok(connection) => Ok(Some(connection)),
            Err(error) => match std::fs::metadata(path) {
                Ok(metadata) if metadata.is_file() => Err(sqlite_error(path, error)),
                Ok(_) => Err(WorkspaceIntelligenceCognitionError::RecordPathNotFile {
                    path: path.to_path_buf(),
                }),
                Err(io_error) if io_error.kind() == ErrorKind::NotFound => Ok(None),
                Err(io_error) => Err(WorkspaceIntelligenceCognitionError::Io(io_error)),
            },
        }
    }

    /// Creates the root directory and a new empty record file.
    ///
    /// Only [`Self::initialize`] reaches this path, and only after confirming
    /// that the record file is absent.
    fn create_and_open_record(
        &self,
        path: &Path,
    ) -> Result<Connection, WorkspaceIntelligenceCognitionError> {
        std::fs::create_dir_all(&self.root)
            .map_err(WorkspaceIntelligenceCognitionError::Io)?;
        match Connection::open_with_flags(path, CREATE_FLAGS) {
            Ok(connection) => Ok(connection),
            Err(error) => match std::fs::metadata(path) {
                Ok(metadata) if !metadata.is_file() => {
                    Err(WorkspaceIntelligenceCognitionError::RecordPathNotFile {
                        path: path.to_path_buf(),
                    })
                }
                _ => Err(sqlite_error(path, error)),
            },
        }
    }

    /// Writes the whole v1 partition inside the caller's transaction.
    fn create_v1_partition(
        &self,
        transaction: &Transaction<'_>,
        path: &Path,
        partition_key: &str,
    ) -> Result<(), WorkspaceIntelligenceCognitionError> {
        transaction
            .execute_batch(CREATE_PARTITION_STATE_SQL)
            .map_err(|error| sqlite_error(path, error))?;
        transaction
            .execute(INSERT_PARTITION_ROW_SQL, params![partition_key])
            .map_err(|error| sqlite_error(path, error))?;
        transaction
            .execute_batch(SET_SCHEMA_VERSION_SQL)
            .map_err(|error| sqlite_error(path, error))?;

        // Test-only failpoint: fail after the table, the row and the version
        // were written, so the rollback proof covers all three.
        #[cfg(test)]
        {
            if self.inject_initialize_failure {
                return Err(WorkspaceIntelligenceCognitionError::Io(
                    std::io::Error::other(
                        "injected cognition initialize failure (test-only failpoint)",
                    ),
                ));
            }
        }

        Ok(())
    }
}

const READ_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
const WRITE_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_WRITE.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);
const CREATE_FLAGS: OpenFlags = OpenFlags::SQLITE_OPEN_READ_WRITE
    .union(OpenFlags::SQLITE_OPEN_CREATE)
    .union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Hashes the opaque scope into the only untrusted record-path component.
///
/// A blank scope is rejected before any filesystem or SQLite work.
fn scope_digest(scope: &str) -> Result<String, WorkspaceIntelligenceCognitionError> {
    if scope.trim().is_empty() {
        return Err(WorkspaceIntelligenceCognitionError::EmptyScope);
    }
    let digest = Sha256::digest(scope.as_bytes());
    Ok(format!("{digest:x}"))
}

fn sqlite_error(path: &Path, error: rusqlite::Error) -> WorkspaceIntelligenceCognitionError {
    match error.sqlite_error_code() {
        Some(rusqlite::ErrorCode::NotADatabase | rusqlite::ErrorCode::DatabaseCorrupt) => {
            WorkspaceIntelligenceCognitionError::CorruptDatabase {
                path: path.to_path_buf(),
                detail: error.to_string(),
            }
        }
        _ => WorkspaceIntelligenceCognitionError::Storage(error),
    }
}

fn invalid_shape(path: &Path, fault: PartitionShapeFault) -> WorkspaceIntelligenceCognitionError {
    WorkspaceIntelligenceCognitionError::InvalidPartitionShape {
        path: path.to_path_buf(),
        fault,
    }
}

fn schema_version(
    connection: &Connection,
    path: &Path,
) -> Result<i64, WorkspaceIntelligenceCognitionError> {
    connection
        .query_row(READ_SCHEMA_VERSION_SQL, [], |row| row.get::<_, i64>(0))
        .map_err(|error| sqlite_error(path, error))
}

/// True only for objects SQLite itself creates: names beginning with the exact
/// ASCII prefix `sqlite_`.
///
/// This is an exact, case-sensitive prefix test, not a SQL pattern. SQLite
/// refuses to create a user object whose name begins with `sqlite_`
/// case-insensitively, so any name that does not match this exact prefix is a
/// user object: preserve it and refuse to initialize rather than adopt the
/// database. A name that only looks reserved, such as `sqliteXforeign`, is a
/// user object; a name SQLite would never have produced, such as `SQLITE_FOO`,
/// is conservatively a user object too.
fn is_internal_schema_object(name: &str) -> bool {
    name.starts_with(INTERNAL_SCHEMA_OBJECT_PREFIX)
}

/// Counts schema objects this store did not create inside the caller's
/// transaction.
///
/// `sqlite_sequence`, `sqlite_stat1` and `sqlite_autoindex_*` are internal and do
/// not count. Every other object, including a name that merely resembles the
/// reserved prefix, counts as a user object so `initialize` refuses to adopt the
/// database instead of writing into it.
fn user_object_count(
    connection: &Connection,
    path: &Path,
) -> Result<i64, WorkspaceIntelligenceCognitionError> {
    let mut statement = connection
        .prepare(SELECT_SCHEMA_OBJECT_NAMES_SQL)
        .map_err(|error| sqlite_error(path, error))?;
    let mut rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|error| sqlite_error(path, error))?;
    let mut count = 0_i64;
    for name in rows.by_ref() {
        let name = name.map_err(|error| sqlite_error(path, error))?;
        if !is_internal_schema_object(&name) {
            count += 1;
        }
    }
    Ok(count)
}

fn table_columns(
    connection: &Connection,
    path: &Path,
) -> Result<Vec<String>, WorkspaceIntelligenceCognitionError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({PARTITION_STATE_TABLE});"))
        .map_err(|error| sqlite_error(path, error))?;
    let mut rows = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| sqlite_error(path, error))?;
    let mut columns = Vec::new();
    for column in rows.by_ref() {
        columns.push(column.map_err(|error| sqlite_error(path, error))?);
    }
    Ok(columns)
}

/// Reads and validates the v1 partition inside the caller's transaction.
///
/// The validation order is fixed: table presence, required columns, row
/// cardinality, then the row itself. Extra columns and extra tables are allowed
/// and ignored.
fn observe_v1_partition(
    connection: &Connection,
    path: &Path,
    expected_partition_key: &str,
) -> Result<CognitionPartitionState, WorkspaceIntelligenceCognitionError> {
    let present: i64 = connection
        .query_row(SCHEMA_OBJECT_NAMED_SQL, params![PARTITION_STATE_TABLE], |row| {
            row.get(0)
        })
        .map_err(|error| sqlite_error(path, error))?;
    if present == 0 {
        return Err(invalid_shape(path, PartitionShapeFault::StateTableMissing));
    }

    let columns = table_columns(connection, path)?;
    let required_faults = [
        PartitionShapeFault::StateIdColumnMissing,
        PartitionShapeFault::PartitionKeyColumnMissing,
        PartitionShapeFault::CursorColumnMissing,
        PartitionShapeFault::IncarnationTokenColumnMissing,
    ];
    for (column, fault) in PARTITION_STATE_REQUIRED_COLUMNS.into_iter().zip(required_faults) {
        if !columns.iter().any(|observed| observed == column) {
            return Err(invalid_shape(path, fault));
        }
    }

    let row_count: i64 = connection
        .query_row(COUNT_PARTITION_ROWS_SQL, [], |row| row.get::<_, i64>(0))
        .map_err(|error| sqlite_error(path, error))?;
    if row_count == 0 {
        return Err(WorkspaceIntelligenceCognitionError::MissingPartitionRow {
            path: path.to_path_buf(),
        });
    }
    if row_count != 1 {
        return Err(invalid_shape(
            path,
            PartitionShapeFault::PartitionRowCountNotSingleton,
        ));
    }

    let mut statement = connection
        .prepare(SELECT_PARTITION_ROW_SQL)
        .map_err(|error| sqlite_error(path, error))?;
    let mut queried = statement
        .query([])
        .map_err(|error| sqlite_error(path, error))?;
    let row = queried
        .next()
        .map_err(|error| sqlite_error(path, error))?
        .ok_or_else(|| WorkspaceIntelligenceCognitionError::MissingPartitionRow {
            path: path.to_path_buf(),
        })?;

    match row
        .get_ref(0)
        .map_err(|error| sqlite_error(path, error))?
    {
        ValueRef::Integer(PARTITION_STATE_ID) => {}
        ValueRef::Integer(_) => {
            return Err(invalid_shape(path, PartitionShapeFault::StateIdNotOne));
        }
        ValueRef::Null | ValueRef::Real(_) | ValueRef::Text(_) | ValueRef::Blob(_) => {
            return Err(invalid_shape(path, PartitionShapeFault::StateIdNotInteger));
        }
    }

    let partition_key = match row
        .get_ref(1)
        .map_err(|error| sqlite_error(path, error))?
    {
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| invalid_shape(path, PartitionShapeFault::PartitionKeyNotText))?,
        ValueRef::Null | ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Blob(_) => {
            return Err(invalid_shape(path, PartitionShapeFault::PartitionKeyNotText));
        }
    };
    if partition_key.trim().is_empty() {
        return Err(invalid_shape(path, PartitionShapeFault::PartitionKeyEmpty));
    }
    if partition_key != expected_partition_key {
        return Err(WorkspaceIntelligenceCognitionError::PartitionScopeMismatch {
            path: path.to_path_buf(),
        });
    }

    let cursor = read_optional_text(row, 2, path, PartitionShapeFault::CursorNotText)?;
    let incarnation_token =
        read_optional_text(row, 3, path, PartitionShapeFault::IncarnationTokenNotText)?;

    Ok(CognitionPartitionState {
        cursor,
        incarnation_token,
    })
}

/// Reads a nullable text column without coercing any other storage class.
fn read_optional_text(
    row: &rusqlite::Row<'_>,
    index: usize,
    path: &Path,
    fault: PartitionShapeFault,
) -> Result<Option<String>, WorkspaceIntelligenceCognitionError> {
    match row
        .get_ref(index)
        .map_err(|error| sqlite_error(path, error))?
    {
        ValueRef::Null => Ok(None),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .map(|text| Some(text.to_string()))
            .map_err(|_| invalid_shape(path, fault)),
        ValueRef::Integer(_) | ValueRef::Real(_) | ValueRef::Blob(_) => {
            Err(invalid_shape(path, fault))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    const SCOPE: &str = "cognition-scope:alpha";

    fn store_root(temp: &TempDir) -> PathBuf {
        temp.path().join("cognition")
    }

    fn record_path_for(store: &WorkspaceIntelligenceCognitionStore, scope: &str) -> PathBuf {
        store.record_path(&scope_digest(scope).expect("fixture scope is not blank"))
    }

    fn raw_read_connection(path: &Path) -> Connection {
        Connection::open_with_flags(path, READ_FLAGS).expect("fixture record opens read-only")
    }

    fn raw_write_connection(path: &Path) -> Connection {
        Connection::open_with_flags(path, CREATE_FLAGS).expect("fixture record opens read-write")
    }

    fn file_bytes(path: &Path) -> Vec<u8> {
        fs::read(path).expect("fixture record is readable")
    }

    fn user_version_of(connection: &Connection) -> i64 {
        connection
            .query_row(READ_SCHEMA_VERSION_SQL, [], |row| row.get::<_, i64>(0))
            .expect("fixture schema version is readable")
    }

    fn table_names(connection: &Connection) -> Vec<String> {
        let mut statement = connection
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name;")
            .expect("sqlite_master is readable");
        statement
            .query_map([], |row| row.get::<_, String>(0))
            .expect("sqlite_master rows are readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("sqlite_master names are readable")
    }

    fn column_names(connection: &Connection, table: &str) -> Vec<String> {
        let mut statement = connection
            .prepare(&format!("PRAGMA table_info({table});"))
            .expect("table info is readable");
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .expect("table info rows are readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("table info names are readable")
    }

    fn partition_row_count(connection: &Connection) -> i64 {
        connection
            .query_row(COUNT_PARTITION_ROWS_SQL, [], |row| row.get::<_, i64>(0))
            .expect("partition row count is readable")
    }

    fn assert_rejected_v1_error(
        error: &WorkspaceIntelligenceCognitionError,
        expected_code: &str,
        expected_fault: Option<&str>,
    ) {
        assert!(
            error.is_invalid_shape(),
            "expected an invalid-shape error, got: {error}"
        );
        assert_eq!(error.code(), expected_code, "unexpected error code: {error}");
        assert_eq!(
            error.shape_fault_code(),
            expected_fault,
            "unexpected shape fault: {error}"
        );
    }

    #[test]
    fn construction_and_missing_reads_create_nothing() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());

        assert_eq!(
            store.read(SCOPE).expect("a missing record is an observation"),
            None
        );
        assert!(
            !root.exists(),
            "read must not create the root directory, a record or a journal"
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .expect("temporary directory is readable")
                .count(),
            0
        );

        for blank in ["", "   ", "\t\n "] {
            let read_error = store
                .read(blank)
                .expect_err("a blank scope is rejected by read");
            assert_eq!(read_error.code(), "empty_scope");
            assert_eq!(read_error.as_str(), "empty_scope");
            let initialize_error = store
                .initialize(blank)
                .expect_err("a blank scope is rejected by initialize");
            assert_eq!(initialize_error.code(), "empty_scope");
        }

        assert!(
            !root.exists(),
            "a blank scope is rejected before any filesystem work"
        );
        assert_eq!(
            fs::read_dir(temp.path())
                .expect("temporary directory is readable")
                .count(),
            0
        );
    }

    #[test]
    fn initialize_creates_v1_schema_singleton_row_and_version() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());

        let initialization = store.initialize(SCOPE).expect("initialize succeeds");
        assert!(initialization.is_initialized());
        assert_eq!(
            initialization.state(),
            &CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }
        );

        let path = record_path_for(&store, SCOPE);
        assert_eq!(path.parent(), Some(root.as_path()));
        assert!(path.is_file());
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("record file name is text");
        assert_eq!(
            file_name,
            format!("{}.sqlite", scope_digest(SCOPE).expect("scope digest"))
        );

        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);

        let columns = column_names(&connection, PARTITION_STATE_TABLE);
        for required in PARTITION_STATE_REQUIRED_COLUMNS {
            assert!(
                columns.contains(&required.to_string()),
                "missing required column {required} in {columns:?}"
            );
        }
        assert_eq!(partition_row_count(&connection), 1);

        let mut statement = connection
            .prepare(SELECT_PARTITION_ROW_SQL)
            .expect("partition row is readable");
        let mut rows = statement.query([]).expect("partition row query runs");
        let row = rows
            .next()
            .expect("partition row query returns")
            .expect("partition row exists");
        assert_eq!(
            row.get::<_, i64>(0).expect("state_id is an integer"),
            PARTITION_STATE_ID
        );
        assert_eq!(
            row.get::<_, String>(1).expect("partition_key is text"),
            scope_digest(SCOPE).expect("scope digest")
        );
        assert!(matches!(
            row.get_ref(2).expect("cursor is readable"),
            ValueRef::Null
        ));
        assert!(matches!(
            row.get_ref(3).expect("incarnation_token is readable"),
            ValueRef::Null
        ));
    }

    #[test]
    fn initialize_is_idempotent_and_reports_existing() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root);

        let first = store.initialize(SCOPE).expect("first initialize succeeds");
        assert!(first.is_initialized());

        // Shape fixture: a non-NULL cursor/incarnation_token is written through
        // raw SQL because this slice has no production write path for these
        // fields; WP1.4 and WP1.5 own their values.
        let path = record_path_for(&store, SCOPE);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute(
                    "UPDATE partition_state SET cursor = 'fixture-cursor', \
                     incarnation_token = 'fixture-token'",
                    [],
                )
                .expect("fixture cursor and token are written");
        }
        let bytes_before = file_bytes(&path);

        let second = store
            .initialize(SCOPE)
            .expect("second initialize succeeds without writing");
        assert!(!second.is_initialized());
        assert_eq!(
            second.state(),
            &CognitionPartitionState {
                cursor: Some("fixture-cursor".to_string()),
                incarnation_token: Some("fixture-token".to_string()),
            },
            "Existing must report the stored values, not a default overwrite"
        );
        assert_eq!(
            file_bytes(&path),
            bytes_before,
            "an existing v1 record is not rewritten"
        );

        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
        assert_eq!(partition_row_count(&connection), 1);
        let (cursor, token) = connection
            .query_row(
                "SELECT cursor, incarnation_token FROM partition_state WHERE state_id = 1;",
                [],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                    ))
                },
            )
            .expect("stored shape values are readable");
        assert_eq!(cursor, "fixture-cursor");
        assert_eq!(token, "fixture-token");
    }

    #[test]
    fn concurrent_initialize_has_exactly_one_winner() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = Arc::new(WorkspaceIntelligenceCognitionStore::new(root));
        let barrier = Arc::new(Barrier::new(2));

        let mut handles = Vec::new();
        for _ in 0..2 {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                store.initialize(SCOPE)
            }));
        }

        let results = handles
            .into_iter()
            .map(|handle| handle.join().expect("initialize thread joins"))
            .collect::<Vec<_>>();

        let initialized = results
            .iter()
            .filter(|result| result.as_ref().expect("initialize succeeds").is_initialized())
            .count();
        assert_eq!(
            initialized, 1,
            "exactly one caller creates the partition: {results:?}"
        );

        let state = store
            .read(SCOPE)
            .expect("partition is readable")
            .expect("partition exists");
        assert_eq!(
            state,
            CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }
        );
        let path = record_path_for(&store, SCOPE);
        let connection = raw_read_connection(&path);
        assert_eq!(partition_row_count(&connection), 1);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
    }

    #[test]
    fn the_same_scope_reopens_and_restores_state() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);

        {
            let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
            assert!(store.initialize(SCOPE).expect("initialize succeeds").is_initialized());
        }

        // A fresh store over the same root simulates a process restart.
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        assert_eq!(
            store.read(SCOPE).expect("record is readable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );

        // Shape fixture, not a production write path: it proves that a
        // cursor/incarnation_token shape survives a reopen. Neither value is
        // interpreted here.
        let path = record_path_for(&store, SCOPE);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute(
                    "UPDATE partition_state SET cursor = 'cursor-7', \
                     incarnation_token = 'incarnation-2'",
                    [],
                )
                .expect("fixture shape is written");
        }
        drop(store);

        let reopened = WorkspaceIntelligenceCognitionStore::new(root);
        assert_eq!(
            reopened.read(SCOPE).expect("record is readable after reopen"),
            Some(CognitionPartitionState {
                cursor: Some("cursor-7".to_string()),
                incarnation_token: Some("incarnation-2".to_string()),
            })
        );
        let existing = reopened
            .initialize(SCOPE)
            .expect("initialize reports the existing record");
        assert!(!existing.is_initialized());
        assert_eq!(existing.state().cursor.as_deref(), Some("cursor-7"));
        assert_eq!(
            existing.state().incarnation_token.as_deref(),
            Some("incarnation-2")
        );
    }

    #[test]
    fn two_scopes_get_distinct_files_and_are_isolated() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());

        let first_scope = "scope:first";
        let second_scope = "scope:second";
        store.initialize(first_scope).expect("first scope initializes");
        store.initialize(second_scope).expect("second scope initializes");

        let first_path = record_path_for(&store, first_scope);
        let second_path = record_path_for(&store, second_scope);
        assert_ne!(first_path, second_path);
        assert!(first_path.is_file());
        assert!(second_path.is_file());

        fs::write(&first_path, b"this is not a sqlite database at all").expect("first record is corrupted");
        assert!(
            store.read(first_scope).is_err(),
            "a corrupted record is an explicit error, not Ok(None)"
        );
        assert_eq!(
            store.read(second_scope).expect("second record is readable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }),
            "corrupting one scope must not affect another"
        );

        let hostile_scopes = ["../", "a/b", "/etc/passwd", "C:\\Windows"];
        let entries_before = fs::read_dir(&root)
            .expect("root is readable")
            .count();
        for scope in hostile_scopes {
            store
                .initialize(scope)
                .unwrap_or_else(|error| panic!("hostile scope {scope:?} is initialized: {error}"));
            let path = record_path_for(&store, scope);
            assert_eq!(
                path.parent(),
                Some(root.as_path()),
                "a hostile scope stays inside the root"
            );
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .expect("record file name is text");
            let digest = file_name
                .strip_suffix(".sqlite")
                .expect("record file name carries the sqlite extension");
            assert_eq!(digest.len(), 64, "digest length for {scope:?}");
            assert!(
                digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
                "digest is lowercase hex for {scope:?}"
            );
            assert!(path.is_file(), "record file exists for {scope:?}");
        }

        let entries = fs::read_dir(&root)
            .expect("root is readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("root entries are readable");
        assert_eq!(entries.len(), entries_before + hostile_scopes.len());
        for entry in entries {
            assert_eq!(entry.path().parent(), Some(root.as_path()));
            assert!(
                entry.file_type().expect("entry type").is_file(),
                "only record files live directly in the root"
            );
        }
    }

    #[test]
    fn a_database_copied_to_another_scope_is_rejected() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root);

        let source_scope = "scope:source";
        let copied_scope = "scope:copied";
        store.initialize(source_scope).expect("source scope initializes");

        let source_path = record_path_for(&store, source_scope);
        let copied_path = record_path_for(&store, copied_scope);
        fs::copy(&source_path, &copied_path).expect("record is copied");
        let bytes_before = file_bytes(&copied_path);

        let read_error = store
            .read(copied_scope)
            .expect_err("a foreign partition key is not accepted by read");
        assert_eq!(read_error.code(), "partition_scope_mismatch");
        assert!(read_error.is_scope_mismatch());
        assert!(!read_error.is_invalid_shape());

        let initialize_error = store
            .initialize(copied_scope)
            .expect_err("a foreign partition key is not adopted by initialize");
        assert_eq!(initialize_error.code(), "partition_scope_mismatch");

        assert_eq!(
            file_bytes(&copied_path),
            bytes_before,
            "the copied record is not rewritten"
        );
        assert_eq!(
            store.read(source_scope).expect("source record is readable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
    }

    #[test]
    fn unknown_version_and_corrupt_files_are_preserved() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        let future_scope = "scope:future";
        let future_path = record_path_for(&store, future_scope);
        {
            let connection = raw_write_connection(&future_path);
            connection
                .execute_batch(
                    "CREATE TABLE future_sentinel (id INTEGER PRIMARY KEY, value TEXT);
                     INSERT INTO future_sentinel (id, value) VALUES (1, 'keep-me');
                     PRAGMA user_version = 2;",
                )
                .expect("future-shaped fixture is created");
        }
        let future_bytes = file_bytes(&future_path);

        let read_error = store
            .read(future_scope)
            .expect_err("an unknown version is rejected by read");
        assert!(
            matches!(
                read_error,
                WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { observed: 2, .. }
            ),
            "unexpected read error: {read_error}"
        );
        let initialize_error = store
            .initialize(future_scope)
            .expect_err("an unknown version is rejected by initialize");
        assert!(
            matches!(
                initialize_error,
                WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { observed: 2, .. }
            ),
            "unexpected initialize error: {initialize_error}"
        );
        assert_eq!(
            file_bytes(&future_path),
            future_bytes,
            "an unsupported database is left untouched"
        );
        {
            let connection = raw_read_connection(&future_path);
            assert_eq!(user_version_of(&connection), 2);
            let sentinel: String = connection
                .query_row("SELECT value FROM future_sentinel WHERE id = 1;", [], |row| {
                    row.get(0)
                })
                .expect("sentinel row survives");
            assert_eq!(sentinel, "keep-me");
        }

        let corrupt_scope = "scope:corrupt";
        let corrupt_path = record_path_for(&store, corrupt_scope);
        let corrupt_bytes = b"this file is not a sqlite database, it is a fixture".to_vec();
        fs::write(&corrupt_path, &corrupt_bytes).expect("corrupt fixture is written");

        let read_error = store
            .read(corrupt_scope)
            .expect_err("a non-SQLite file is rejected by read");
        assert_eq!(read_error.code(), "corrupt_database");
        let initialize_error = store
            .initialize(corrupt_scope)
            .expect_err("a non-SQLite file is rejected by initialize");
        assert_eq!(initialize_error.code(), "corrupt_database");
        assert_eq!(
            file_bytes(&corrupt_path),
            corrupt_bytes,
            "a non-SQLite file is never rewritten"
        );
    }

    #[test]
    fn unknown_extra_columns_and_tables_survive_existing_initialize() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root);

        store.initialize(SCOPE).expect("initialize succeeds");
        let path = record_path_for(&store, SCOPE);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute_batch(
                    "ALTER TABLE partition_state ADD COLUMN note TEXT;
                     UPDATE partition_state SET note = 'sentinel' WHERE state_id = 1;
                     CREATE TABLE extra_sentinel (id INTEGER PRIMARY KEY, value TEXT);
                     INSERT INTO extra_sentinel (id, value) VALUES (7, 'keep-me');",
                )
                .expect("extra column and table fixture is created");
        }

        assert_eq!(
            store.read(SCOPE).expect("extra objects are ignored by read"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
        let existing = store.initialize(SCOPE).expect("initialize reports existing");
        assert!(!existing.is_initialized());
        assert_eq!(
            existing.state(),
            &CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }
        );

        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
        assert!(
            column_names(&connection, PARTITION_STATE_TABLE).contains(&"note".to_string()),
            "the extra column survives"
        );
        let note: String = connection
            .query_row(
                "SELECT note FROM partition_state WHERE state_id = 1;",
                [],
                |row| row.get(0),
            )
            .expect("extra column value survives");
        assert_eq!(note, "sentinel");
        let sentinel: String = connection
            .query_row("SELECT value FROM extra_sentinel WHERE id = 7;", [], |row| {
                row.get(0)
            })
            .expect("extra table row survives");
        assert_eq!(sentinel, "keep-me");
    }

    #[test]
    fn unrecognized_v0_database_is_not_adopted() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        let scope = "scope:foreign";
        let path = record_path_for(&store, scope);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE foreign_owner (id INTEGER PRIMARY KEY, value TEXT);
                     INSERT INTO foreign_owner (id, value) VALUES (1, 'keep-me');",
                )
                .expect("foreign v0 fixture is created");
        }
        let bytes_before = file_bytes(&path);

        let error = store
            .initialize(scope)
            .expect_err("a v0 database with user objects is not adopted");
        assert_eq!(error.code(), "unrecognized_database");
        assert_eq!(
            file_bytes(&path),
            bytes_before,
            "a foreign database is left untouched"
        );

        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), 0);
        let tables = table_names(&connection);
        assert!(tables.contains(&"foreign_owner".to_string()));
        assert!(
            !tables.contains(&"partition_state".to_string()),
            "initialize must not create the owned table in a foreign database"
        );
        let value: String = connection
            .query_row("SELECT value FROM foreign_owner WHERE id = 1;", [], |row| {
                row.get(0)
            })
            .expect("foreign row survives");
        assert_eq!(value, "keep-me");
    }

    #[test]
    fn internal_schema_object_classification_uses_exact_prefix() {
        // Objects SQLite creates itself.
        assert!(is_internal_schema_object("sqlite_sequence"));
        assert!(is_internal_schema_object("sqlite_stat1"));
        assert!(is_internal_schema_object("sqlite_autoindex_t_1"));
        assert!(is_internal_schema_object("sqlite_"));

        // Everything else is a user object. `sqliteXforeign` is the case a SQL
        // `LIKE 'sqlite_%'` pattern wrongly treated as internal, because `_` is a
        // single-character wildcard there.
        for user_object in [
            "sqlite",
            "SQLITE_FOO",
            "sqliteXforeign",
            "my_table",
            "my_table_extra",
        ] {
            assert!(
                !is_internal_schema_object(user_object),
                "{user_object} must count as a user object"
            );
        }
    }

    #[test]
    fn reserved_looking_table_name_is_not_treated_as_internal() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        // `sqliteXforeign` begins with `sqlite` but not with the exact reserved
        // prefix `sqlite_`, so SQLite accepts it as a user table and this store
        // must treat it as one. A SQL `LIKE 'sqlite_%'` pattern matched it,
        // which made this foreign database look empty.
        let scope = "scope:reserved-looking";
        let path = record_path_for(&store, scope);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE sqliteXforeign (payload TEXT);
                     INSERT INTO sqliteXforeign (payload) VALUES ('keep-me');",
                )
                .expect("reserved-looking v0 fixture is created");
        }
        let bytes_before = file_bytes(&path);

        let error = store
            .initialize(scope)
            .expect_err("a table named sqliteXforeign is a user object");
        assert_eq!(error.code(), "unrecognized_database");
        assert!(
            error.to_string().contains("preserved"),
            "the error states that the database is preserved: {error}"
        );
        assert_eq!(
            file_bytes(&path),
            bytes_before,
            "the foreign database is not rewritten"
        );

        {
            let connection = raw_read_connection(&path);
            assert_eq!(
                user_version_of(&connection),
                0,
                "initialize must not stamp a foreign database"
            );
            let tables = table_names(&connection);
            assert!(tables.contains(&"sqliteXforeign".to_string()));
            assert!(
                !tables.contains(&"partition_state".to_string()),
                "initialize must not create the owned table in a foreign database"
            );
            let payload: String = connection
                .query_row("SELECT payload FROM sqliteXforeign;", [], |row| row.get(0))
                .expect("sentinel row survives");
            assert_eq!(payload, "keep-me");
        }

        // A follow-up read reports an explicit error; it is never `Ok(None)`,
        // which would claim this call did not observe a file.
        let read_error = match store.read(scope) {
            Ok(state) => panic!("read must not accept the foreign fixture, got {state:?}"),
            Err(error) => error,
        };
        assert_eq!(read_error.code(), "uninitialized_database");
        assert_eq!(
            file_bytes(&path),
            bytes_before,
            "the read does not rewrite the foreign database either"
        );
    }

    #[test]
    fn internal_sqlite_objects_do_not_block_initialize() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        // Dropping a table with an AUTOINCREMENT key leaves SQLite's own
        // `sqlite_sequence` table behind in a `user_version == 0` database with
        // no user objects. That state is still an uninitialized record, not
        // something this store did not create.
        let path = record_path_for(&store, SCOPE);
        {
            let connection = raw_write_connection(&path);
            connection
                .execute_batch(
                    "CREATE TABLE fixture_autoincrement (id INTEGER PRIMARY KEY AUTOINCREMENT);
                     DROP TABLE fixture_autoincrement;",
                )
                .expect("internal-object fixture is created");
        }
        {
            let connection = raw_read_connection(&path);
            assert_eq!(user_version_of(&connection), 0);
            assert!(table_names(&connection).contains(&"sqlite_sequence".to_string()));
        }

        assert!(store
            .initialize(SCOPE)
            .expect("an internal object does not block initialization")
            .is_initialized());
        assert_eq!(
            store.read(SCOPE).expect("record is readable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
    }

    #[test]
    fn failed_initialize_rolls_back_schema_and_version() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let failing = WorkspaceIntelligenceCognitionStore::with_injected_initialize_failure(
            root.clone(),
        );

        let error = failing
            .initialize(SCOPE)
            .expect_err("the injected failure aborts the transaction");
        assert_eq!(error.code(), "io", "unexpected error: {error}");

        let path = record_path_for(&failing, SCOPE);
        assert!(
            path.is_file(),
            "a newly created record file may remain after the rollback"
        );
        {
            let connection = raw_read_connection(&path);
            assert_eq!(
                user_version_of(&connection),
                0,
                "the version stamp rolls back with the schema"
            );
            assert!(
                table_names(&connection).is_empty(),
                "no partial table survives: {:?}",
                table_names(&connection)
            );
        }

        // A later explicit initialize retries the empty v0 file, which is the
        // documented consequence of a failed first creation.
        let retry = WorkspaceIntelligenceCognitionStore::new(root);
        assert!(retry
            .initialize(SCOPE)
            .expect("the empty v0 file is retried")
            .is_initialized());
        assert_eq!(
            retry.read(SCOPE).expect("record is readable after retry"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
    }

    fn fixture_missing_table(connection: &Connection, _partition_key: &str) {
        connection
            .execute_batch("PRAGMA user_version = 1;")
            .expect("missing-table fixture is created");
    }

    fn fixture_missing_column(connection: &Connection, partition_key: &str) {
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY,
                     partition_key TEXT,
                     cursor TEXT
                 );
                 INSERT INTO partition_state (state_id, partition_key, cursor)
                 VALUES (1, '{partition_key}', NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("missing-column fixture is created");
    }

    fn fixture_zero_rows(connection: &Connection, _partition_key: &str) {
        connection
            .execute_batch(&format!(
                "{CREATE_PARTITION_STATE_SQL} PRAGMA user_version = 1;"
            ))
            .expect("zero-row fixture is created");
    }

    fn fixture_two_rows(connection: &Connection, partition_key: &str) {
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER,
                     partition_key TEXT,
                     cursor TEXT,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES (1, '{partition_key}', NULL, NULL);
                 INSERT INTO partition_state VALUES (1, '{partition_key}', NULL, NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("two-row fixture is created");
    }

    fn fixture_state_id_not_one(connection: &Connection, partition_key: &str) {
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER,
                     partition_key TEXT,
                     cursor TEXT,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES (2, '{partition_key}', NULL, NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("state_id fixture is created");
    }

    fn fixture_state_id_text(connection: &Connection, partition_key: &str) {
        // `state_id` is declared without INTEGER affinity and without the
        // `CHECK (state_id = 1)` singleton constraint, so SQLite stores the TEXT
        // value instead of coercing or rejecting it.
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id,
                     partition_key TEXT,
                     cursor TEXT,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES ('one', '{partition_key}', NULL, NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("text state_id fixture is created");
    }

    fn fixture_integer_cursor(connection: &Connection, partition_key: &str) {
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                     partition_key TEXT,
                     cursor,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES (1, '{partition_key}', 42, NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("integer cursor fixture is created");
    }

    fn fixture_blob_token(connection: &Connection, partition_key: &str) {
        connection
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                     partition_key TEXT,
                     cursor TEXT,
                     incarnation_token
                 );
                 INSERT INTO partition_state VALUES (1, '{partition_key}', NULL, x'00ff');
                 PRAGMA user_version = 1;"
            ))
            .expect("blob token fixture is created");
    }

    fn fixture_partition_key_blob(connection: &Connection, _partition_key: &str) {
        // `partition_key` has no TEXT affinity, so the blob literal stays a BLOB
        // storage class value. The correct key is deliberately not stored.
        connection
            .execute_batch(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                     partition_key,
                     cursor TEXT,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES (1, x'00ff', NULL, NULL);
                 PRAGMA user_version = 1;",
            )
            .expect("blob partition key fixture is created");
    }

    fn fixture_partition_key_invalid_utf8(connection: &Connection, _partition_key: &str) {
        // `CAST(x'80' AS TEXT)` stores a TEXT storage class value whose bytes are
        // not valid UTF-8; a column without TEXT affinity keeps it as TEXT. The
        // correct key is deliberately not stored.
        connection
            .execute_batch(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                     partition_key,
                     cursor TEXT,
                     incarnation_token TEXT
                 );
                 INSERT INTO partition_state VALUES (1, CAST(x'80' AS TEXT), NULL, NULL);
                 PRAGMA user_version = 1;",
            )
            .expect("invalid-utf8 partition key fixture is created");
    }

    fn fixture_empty_partition_key(connection: &Connection, _partition_key: &str) {
        connection
            .execute_batch(&format!(
                "{CREATE_PARTITION_STATE_SQL}
                 INSERT INTO partition_state VALUES (1, '', NULL, NULL);
                 PRAGMA user_version = 1;"
            ))
            .expect("empty partition key fixture is created");
    }

    #[test]
    fn invalid_v1_shapes_are_explicit_errors() {
        type Fixture = fn(&Connection, &str);

        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        let fixtures: [(&str, Fixture, &str, Option<&str>); 11] = [
            (
                "fixture:missing-table",
                fixture_missing_table as Fixture,
                "invalid_partition_shape",
                Some("state_table_missing"),
            ),
            (
                "fixture:missing-column",
                fixture_missing_column as Fixture,
                "invalid_partition_shape",
                Some("incarnation_token_column_missing"),
            ),
            (
                "fixture:zero-rows",
                fixture_zero_rows as Fixture,
                "missing_partition_row",
                None,
            ),
            (
                "fixture:two-rows",
                fixture_two_rows as Fixture,
                "invalid_partition_shape",
                Some("partition_row_count_not_singleton"),
            ),
            (
                "fixture:state-id",
                fixture_state_id_not_one as Fixture,
                "invalid_partition_shape",
                Some("state_id_not_one"),
            ),
            (
                "fixture:state-id-text",
                fixture_state_id_text as Fixture,
                "invalid_partition_shape",
                Some("state_id_not_integer"),
            ),
            (
                "fixture:integer-cursor",
                fixture_integer_cursor as Fixture,
                "invalid_partition_shape",
                Some("cursor_not_text"),
            ),
            (
                "fixture:blob-token",
                fixture_blob_token as Fixture,
                "invalid_partition_shape",
                Some("incarnation_token_not_text"),
            ),
            (
                "fixture:blob-partition-key",
                fixture_partition_key_blob as Fixture,
                "invalid_partition_shape",
                Some("partition_key_not_text"),
            ),
            (
                "fixture:invalid-utf8-partition-key",
                fixture_partition_key_invalid_utf8 as Fixture,
                "invalid_partition_shape",
                Some("partition_key_not_text"),
            ),
            (
                "fixture:empty-partition-key",
                fixture_empty_partition_key as Fixture,
                "invalid_partition_shape",
                Some("partition_key_empty"),
            ),
        ];

        for (scope, build, expected_code, expected_fault) in fixtures {
            let path = record_path_for(&store, scope);
            {
                let connection = raw_write_connection(&path);
                build(
                    &connection,
                    &scope_digest(scope).expect("fixture scope is not blank"),
                );
            }
            let bytes_before = file_bytes(&path);

            let read_error = match store.read(scope) {
                Ok(state) => {
                    panic!("read must reject the invalid fixture {scope}, got {state:?}")
                }
                Err(error) => error,
            };
            assert_rejected_v1_error(&read_error, expected_code, expected_fault);

            let initialize_error = match store.initialize(scope) {
                Ok(initialization) => panic!(
                    "initialize must reject the invalid fixture {scope}, got {initialization:?}"
                ),
                Err(error) => error,
            };
            assert_rejected_v1_error(&initialize_error, expected_code, expected_fault);

            assert_eq!(
                file_bytes(&path),
                bytes_before,
                "an invalid v1 fixture is never repaired ({scope})"
            );
            let connection = raw_read_connection(&path);
            assert_eq!(
                user_version_of(&connection),
                1,
                "the invalid fixture keeps its version ({scope})"
            );
        }
    }

    #[test]
    fn a_directory_at_the_record_path_is_rejected() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());
        fs::create_dir_all(&root).expect("fixture root is created");

        let path = record_path_for(&store, SCOPE);
        fs::create_dir(&path).expect("directory fixture is created");

        let read_error = store
            .read(SCOPE)
            .expect_err("a directory is not a cognition record");
        assert_eq!(read_error.code(), "record_path_not_file");
        let initialize_error = store
            .initialize(SCOPE)
            .expect_err("initialize does not replace a directory");
        assert_eq!(initialize_error.code(), "record_path_not_file");

        assert!(path.is_dir());
        assert_eq!(
            fs::read_dir(&path).expect("fixture directory is readable").count(),
            0
        );
        assert_eq!(
            fs::read_dir(&root).expect("root is readable").count(),
            1,
            "no record file or journal is created next to the directory"
        );
    }
}
