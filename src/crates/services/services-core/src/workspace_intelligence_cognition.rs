//! Durable cognition partition store for Workspace Intelligence P1.
//!
//! This module owns one SQLite database per **opaque scope**. Each database
//! holds a single `partition_state` row. The plain cognition / bootstrap contract,
//! without `workspace-intelligence-claim`, initializes and reads partitions with
//! shape-only `cursor` and `incarnation_token` values; it does not advance or
//! interpret either value. Under `workspace-intelligence-claim` a raw cursor
//! compare-and-swap primitive exists, but cursor/gap decision making and gap
//! recording (WP1.5) remain out of scope, and nothing here encodes or decodes a
//! cursor payload. The governed commit gate is the narrow runtime caller of this
//! seam.
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
//! [`WorkspaceIntelligenceCognitionStore::initialize`] is the only writer in the
//! plain cognition / bootstrap contract, without `workspace-intelligence-claim`.
//! It creates the schema only for a database that is version `0` and holds no
//! user objects, and it never adopts, repairs, resets or deletes a database it
//! did not create. An initialized database is returned as
//! [`CognitionInitialization::Existing`] without writing any user field.
//! `initialize` remains a public low-level primitive, not an authorization path.
//!
//! Only under `workspace-intelligence-claim`, three `pub(crate)` operations extend
//! this seam. `advance_incarnation` and `advance_cursor` are the claim-gated
//! surface's only two real mutations: each runs one IMMEDIATE transaction through
//! COMMIT and writes exactly one column. `advance_incarnation` creates or
//! validates the partition, generates the tenure marker inside that transaction
//! and writes `incarnation_token`. `advance_cursor` creates nothing: it requires an
//! existing partition, compares the stored cursor text exactly against the
//! caller's expectation and replaces it only on a match. It is the only cursor
//! writer in this crate and it still does not interpret the value: the cursor
//! envelope belongs to the caller, so this module compares and stores raw text
//! only. `verify_incarnation` is read-only, never creates a root, database, table
//! or row, and refuses on any disagreement between the stored, live-claim and
//! request markers. All three accept the v1 and the v2 shape and never upgrade a
//! record themselves; extra columns/tables remain unchanged. This is not an
//! enabling path, a WP1.4 exit or a P1 exit.
//!
//! An empty v0 database (no user objects) is a valid starting point that
//! `advance_incarnation` initializes as v2. A v0 database carrying user objects
//! returns `UnrecognizedDatabase` on advancement and is never adopted, repaired
//! or reset. `verify_incarnation` returns `UninitializedDatabase` for any v0
//! database without writing.
//!
//! The stored incarnation value is an opaque tenure marker, returned verbatim,
//! never trimmed or parsed; it is not a secret, authorization or grant. Token
//! generation promises only `new != immediate previous`. Historical ABA
//! resistance rests on UUID v4 collision resistance, with residual collision
//! risk.
//!
//! # Content entries
//!
//! [`WorkspaceIntelligenceCognitionStore::read_entries`] is the only content
//! reader. It opens the record read-only, never creates it, and answers
//! `Ok(None)` only when this call did not observe a file. A v1 record has no
//! content table and is reported as
//! [`WorkspaceIntelligenceCognitionError::ContentTableAbsent`]; the read never
//! upgrades it.
//!
//! Under `workspace-intelligence-commit` one primitive writes content:
//! [`WorkspaceIntelligenceCognitionStore::commit_entries_with_cursor`] inserts new
//! entries, retires stored entries with an exact revision expectation and
//! optionally replaces the cursor, all inside one IMMEDIATE transaction. It
//! derives `content_digest` from the statement text, compares the cursor exactly
//! like `advance_cursor`, never creates a record, a table or a row for a missing
//! partition and never upgrades a v1 record.
//!
//! # Schema v2
//!
//! `partition_state` keeps the v1 shape:
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
//! v2 adds the two content tables this store also owns, `cognition_entries` and
//! `cognition_dependencies`, plus two indexes on `cognition_entries`.
//! `user_version` is `2` for this shape.
//!
//! A read accepts unknown extra columns, unknown extra tables and unrelated
//! objects and ignores them; for `partition_state` it requires the four columns
//! above, exactly one row with `state_id = 1`, and a `partition_key` that equals
//! the caller's own scope digest. The two v2 tables are required with exactly the
//! column sequence this module creates and with no extra column, because a
//! content shape this store did not write is reported rather than adopted.
//!
//! # v1 to v2 upgrade
//!
//! A `user_version == 1` record is the v1 shape: `partition_state` only. The
//! explicit [`WorkspaceIntelligenceCognitionStore::initialize`] validates that v1
//! shape first, then creates the two v2 tables and the two indexes and stamps
//! `user_version = 2`, all inside the same IMMEDIATE transaction, and reports
//! [`CognitionInitialization::Upgraded`]. No other field of the partition row
//! changes, and an upgrade never turns a v1 record into a content-bearing one.
//!
//! Read-only paths never upgrade: [`WorkspaceIntelligenceCognitionStore::read`]
//! and [`WorkspaceIntelligenceCognitionStore::read_entries`] observe a v1 record
//! as v1 and write nothing. A v1 record with an unusable shape stays v1 and is
//! reported as an explicit error, never repaired.
//!
//! A v2 record whose content-table shape is not exactly this module's own is
//! fail-closed on every path: `advance_cursor`, `advance_incarnation` and
//! `verify_incarnation` each require the complete v2 shape, so a missing or
//! altered content table makes lease verification and cursor advancement fail
//! together with `invalid_partition_shape`. That is request refusal, not a
//! control-plane fault: the control record and the partition bytes stay
//! untouched.
//!
//! # Version policy
//!
//! The v2 content-table shape is matched by exact column name and order with no
//! extra column. Adding a column or changing the order therefore needs a new
//! physical version, never an in-place `ALTER TABLE` on v2: an altered v2 table
//! makes every already-upgraded record report `entries_column_missing` instead of
//! being read.
//!
//! Mixed versions stay explicit. An older build that knows only v1 opens a v2
//! record as `UnsupportedSchemaVersion` and leaves it byte-identical: it never
//! downgrades, repairs or deletes it. A build that knows v2 opens a v1 record as
//! v1 and upgrades it only through an explicit `initialize`; no read path upgrades
//! anything.
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
//! while holding the control guard. The plain cognition / bootstrap API gains no
//! cursor/token write path. The claim-gated operations also run synchronously
//! through the governed fence's blocking hand-off, under its control guard and
//! held lease; only `advance_incarnation` writes the tenure marker.

use rusqlite::types::ValueRef;
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Physical schema version this module writes and accepts.
///
/// v2 adds the two content tables to the v1 `partition_state` shape. Only an
/// explicit `initialize` upgrades a v1 record; every read path observes v1 as v1.
pub const COGNITION_SCHEMA_VERSION: i64 = 2;

/// Physical schema version of the `partition_state`-only shape a v2 upgrade reads.
const V1_SCHEMA_VERSION: i64 = 1;

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

/// Name of the v2 entry table this module owns.
const COGNITION_ENTRIES_TABLE: &str = "cognition_entries";

/// Name of the v2 dependency table this module owns.
const COGNITION_DEPENDENCIES_TABLE: &str = "cognition_dependencies";

/// Columns a stored v2 entry row must provide, in the order this module creates
/// them. The order is part of the shape check, so a table with the same names in
/// another order is not accepted as this store's own.
const COGNITION_ENTRIES_REQUIRED_COLUMNS: [&str; 21] = [
    "entry_id",
    "kind",
    "category",
    "authority",
    "state",
    "statement",
    "workspace_partition",
    "visibility",
    "shared_scope",
    "shared_authorization",
    "source_owner",
    "source_resource",
    "source_revision",
    "observed_at_unix_ms",
    "valid_until_unix_ms",
    "confidence",
    "revision",
    "epoch",
    "supersedes",
    "invalidated_reason",
    "content_digest",
];

/// Columns a stored v2 dependency row must provide, in creation order.
const COGNITION_DEPENDENCIES_REQUIRED_COLUMNS: [&str; 3] =
    ["downstream_id", "upstream_id", "upstream_revision"];

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

/// The two v2 content tables and their indexes.
///
/// `IF NOT EXISTS` lets one statement serve both a fresh v2 record and the v1 to
/// v2 upgrade without rewriting an object that already exists; the exact shape
/// check in `observe_v2_partition` is what rejects a foreign content shape
/// afterwards. The `CHECK` constraints are the storage half of the closed
/// `category`, `authority` and `visibility` sets, so a row this module can read
/// back is a row a caller could have meant.
const CREATE_COGNITION_CONTENT_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS cognition_entries (
    entry_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('fact', 'asserted')),
    authority TEXT NOT NULL CHECK (authority IN ('human', 'derived')),
    state TEXT NOT NULL,
    statement TEXT NOT NULL,
    workspace_partition TEXT NOT NULL,
    visibility TEXT NOT NULL CHECK (visibility IN ('partition', 'shared')),
    shared_scope TEXT,
    shared_authorization TEXT,
    source_owner TEXT NOT NULL,
    source_resource TEXT,
    source_revision TEXT,
    observed_at_unix_ms INTEGER NOT NULL,
    valid_until_unix_ms INTEGER,
    confidence REAL,
    revision INTEGER NOT NULL,
    epoch INTEGER NOT NULL,
    supersedes TEXT,
    invalidated_reason TEXT,
    content_digest TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS cognition_dependencies (
    downstream_id TEXT NOT NULL REFERENCES cognition_entries(entry_id),
    upstream_id TEXT NOT NULL REFERENCES cognition_entries(entry_id),
    upstream_revision INTEGER NOT NULL,
    PRIMARY KEY (downstream_id, upstream_id)
);
CREATE INDEX IF NOT EXISTS idx_cognition_entries_state ON cognition_entries(state);
CREATE INDEX IF NOT EXISTS idx_cognition_entries_workspace_state ON cognition_entries(workspace_partition, state);
"#;

/// Reads the 21 stored columns in [`COGNITION_ENTRIES_REQUIRED_COLUMNS`] order.
const SELECT_ENTRIES_SQL: &str = "SELECT entry_id, kind, category, authority, state, \
     statement, workspace_partition, visibility, shared_scope, shared_authorization, \
     source_owner, source_resource, source_revision, observed_at_unix_ms, \
     valid_until_unix_ms, confidence, revision, epoch, supersedes, invalidated_reason, \
     content_digest FROM cognition_entries WHERE workspace_partition = ?1 \
     ORDER BY kind, entry_id;";

/// Inserts one entry; the caller supplies every column except `content_digest`,
/// which this module derives from the statement text.
#[cfg(feature = "workspace-intelligence-commit")]
const INSERT_ENTRY_SQL: &str = "INSERT INTO cognition_entries (entry_id, kind, category, \
     authority, state, statement, workspace_partition, visibility, shared_scope, \
     shared_authorization, source_owner, source_resource, source_revision, \
     observed_at_unix_ms, valid_until_unix_ms, confidence, revision, epoch, supersedes, \
     invalidated_reason, content_digest) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, \
     ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21);";

#[cfg(feature = "workspace-intelligence-commit")]
const COUNT_ENTRY_SQL: &str = "SELECT COUNT(*) FROM cognition_entries WHERE entry_id = ?1;";

/// Retires one entry only when it still carries the expected revision and still
/// belongs to this partition.
#[cfg(feature = "workspace-intelligence-commit")]
const RETIRE_ENTRY_SQL: &str = "UPDATE cognition_entries SET state = ?1, \
     revision = revision + 1, invalidated_reason = ?2 \
     WHERE entry_id = ?3 AND revision = ?4 AND workspace_partition = ?5;";

#[cfg(feature = "workspace-intelligence-commit")]
const UPDATE_CURSOR_SQL: &str = "UPDATE partition_state SET cursor = ?1 WHERE state_id = 1";

const SET_SCHEMA_VERSION_SQL: &str = "PRAGMA user_version = 2;";
/// Test-fixture statement that stamps the v1 shape. Production code only ever
/// writes [`SET_SCHEMA_VERSION_SQL`].
#[cfg(test)]
const SET_V1_SCHEMA_VERSION_SQL: &str = "PRAGMA user_version = 1;";
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
    /// `sqlite_master` has no `cognition_entries` table.
    EntriesTableMissing,
    /// `cognition_entries` does not have exactly the v2 column sequence.
    EntriesColumnMissing,
    /// `sqlite_master` has no `cognition_dependencies` table.
    DependenciesTableMissing,
    /// `cognition_dependencies` does not have exactly the v2 column sequence.
    DependenciesColumnMissing,
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
            Self::EntriesTableMissing => "entries_table_missing",
            Self::EntriesColumnMissing => "entries_column_missing",
            Self::DependenciesTableMissing => "dependencies_table_missing",
            Self::DependenciesColumnMissing => "dependencies_column_missing",
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

    #[error(
        "Cognition partition record {path} is a v1 shape without a cognition content table; it is read as v1 and never upgraded by a read"
    )]
    ContentTableAbsent { path: PathBuf },

    #[cfg(feature = "workspace-intelligence-claim")]
    #[error("Cognition partition record {path} has a stale incarnation")]
    StaleIncarnation { path: PathBuf },

    #[cfg(feature = "workspace-intelligence-commit")]
    #[error("Cognition partition record {path} has no initialized partition this write requires")]
    CursorPartitionUnavailable { path: PathBuf },

    #[cfg(feature = "workspace-intelligence-commit")]
    #[error("Cognition partition record {path} cursor changed since it was observed")]
    CursorConflict { path: PathBuf },

    #[cfg(feature = "workspace-intelligence-commit")]
    #[error("Cognition entry {entry_id} is not at the revision this commit expected")]
    EntryRevisionConflict { entry_id: String },

    #[cfg(feature = "workspace-intelligence-commit")]
    #[error("Cognition entry {entry_id} already exists in this partition")]
    EntryDuplicate { entry_id: String },

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
            Self::ContentTableAbsent { .. } => "content_table_absent",
            #[cfg(feature = "workspace-intelligence-claim")]
            Self::StaleIncarnation { .. } => "stale_incarnation",
            #[cfg(feature = "workspace-intelligence-commit")]
            Self::CursorPartitionUnavailable { .. } => "cursor_partition_unavailable",
            #[cfg(feature = "workspace-intelligence-commit")]
            Self::CursorConflict { .. } => "cursor_conflict",
            #[cfg(feature = "workspace-intelligence-commit")]
            Self::EntryRevisionConflict { .. } => "entry_revision_conflict",
            #[cfg(feature = "workspace-intelligence-commit")]
            Self::EntryDuplicate { .. } => "entry_duplicate",
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

/// Opaque cognition partition state.
///
/// `cursor` and `incarnation_token` are opaque nullable text. This module never
/// interprets either value and never assigns governance meaning to them.
/// `advance_incarnation` is the only writer of the token and `advance_cursor` the
/// only writer of the cursor (both gated on `workspace-intelligence-claim`);
/// `read` and `initialize` never write either field of an existing row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CognitionPartitionState {
    /// Opaque cursor text, stored verbatim. Consumption is owned elsewhere.
    pub cursor: Option<String>,
    /// Opaque incarnation token text, stored verbatim. Advancement is owned
    /// elsewhere.
    pub incarnation_token: Option<String>,
}

/// One stored v2 content row, returned verbatim.
///
/// The five closed-set columns (`kind`, `category`, `authority`, `state`,
/// `visibility`) are stored text, not this crate's enums: the storage layer never
/// interprets them, and the caller owns their projection. No field is trimmed,
/// parsed or defaulted.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredCognitionEntry {
    /// Stable record identity.
    pub entry_id: String,
    /// Stored kind code.
    pub kind: String,
    /// Stored category code (`fact` or `asserted`).
    pub category: String,
    /// Stored authority code (`human` or `derived`).
    pub authority: String,
    /// Stored lifecycle state code.
    pub state: String,
    /// Stored statement text.
    pub statement: String,
    /// Partition this row belongs to, as stored.
    pub workspace_partition: String,
    /// Stored visibility code (`partition` or `shared`).
    pub visibility: String,
    /// Stored shared scope, when the caller wrote one.
    pub shared_scope: Option<String>,
    /// Stored shared authorization source, when the caller wrote one.
    pub shared_authorization: Option<String>,
    /// Stored source owner.
    pub source_owner: String,
    /// Stored source resource, when the caller wrote one.
    pub source_resource: Option<String>,
    /// Stored source revision, when the caller wrote one.
    pub source_revision: Option<String>,
    /// Observation time in Unix milliseconds.
    pub observed_at_unix_ms: i64,
    /// Validity bound in Unix milliseconds, when the caller wrote one.
    pub valid_until_unix_ms: Option<i64>,
    /// Stored confidence, when the caller wrote one.
    pub confidence: Option<f64>,
    /// Stored record revision.
    pub revision: i64,
    /// Stored partition epoch baseline.
    pub epoch: i64,
    /// Record this row supersedes, when the caller wrote one.
    pub supersedes: Option<String>,
    /// Stored invalidation reason, when the caller wrote one.
    pub invalidated_reason: Option<String>,
    /// Digest this store derived from the statement text at commit time.
    pub content_digest: String,
}

/// Result of an explicit [`WorkspaceIntelligenceCognitionStore::initialize`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CognitionInitialization {
    /// This call created the v2 schema and its single partition row.
    Initialized(CognitionPartitionState),
    /// The v2 partition already existed; no user field was written.
    Existing(CognitionPartitionState),
    /// This call upgraded a v1 partition to v2: it added the two content tables
    /// and the version stamp and wrote no other field of the partition row.
    Upgraded(CognitionPartitionState),
}

impl CognitionInitialization {
    /// The stored state after the call.
    pub fn state(&self) -> &CognitionPartitionState {
        match self {
            Self::Initialized(state) | Self::Existing(state) | Self::Upgraded(state) => state,
        }
    }

    /// True when this call created the schema.
    ///
    /// An upgrade is not a creation: it reports `false` and is distinguishable
    /// only through [`Self::Upgraded`].
    pub fn is_initialized(&self) -> bool {
        matches!(self, Self::Initialized(_))
    }
}

/// Result of advancement called only by the governed fence under a live lease;
/// this is not a general-purpose writer or a constructible public token result.
#[cfg(feature = "workspace-intelligence-claim")]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct IncarnationAdvance {
    /// Stored token before this advance, verbatim, including arbitrary legacy text.
    pub(crate) previous_token: Option<String>,
    /// Newly generated tenure marker, not an authorization or secret.
    pub(crate) token: String,
}

#[cfg(feature = "workspace-intelligence-claim")]
impl std::fmt::Debug for IncarnationAdvance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IncarnationAdvance")
            .field("previous_token", &self.previous_token.as_ref().map(|_| "<redacted>"))
            .field("token", &"<redacted>")
            .finish()
    }
}

/// Result of one accepted cursor advance, called only by the governed fence
/// under a live lease. Both fields are opaque cursor text, stored and returned
/// verbatim; this module attaches no meaning to them.
#[cfg(feature = "workspace-intelligence-claim")]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CursorAdvance {
    /// Stored cursor before this advance; `None` means the column held NULL.
    pub(crate) previous: Option<String>,
    /// Cursor text this call wrote.
    pub(crate) written: String,
}

#[cfg(feature = "workspace-intelligence-claim")]
impl WorkspaceIntelligenceCognitionStore {
    /// Advance only incarnation_token in one IMMEDIATE transaction through COMMIT.
    /// Precondition: called only by the governed fence under a live lease, never
    /// as a general-purpose writer.
    pub(crate) fn advance_incarnation(
        &self, scope: &str,
    ) -> Result<IncarnationAdvance, WorkspaceIntelligenceCognitionError> {
        let key = scope_digest(scope)?;
        let path = self.record_path(&key);
        let mut connection = match self.open_existing_record(&path, WRITE_FLAGS)? {
            Some(connection) => connection,
            None => self.create_and_open_record(&path)?,
        };
        connection.busy_timeout(BUSY_TIMEOUT).map_err(|e| sqlite_error(&path, e))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sqlite_error(&path, e))?;
        match schema_version(&transaction, &path)? {
            V1_SCHEMA_VERSION => { observe_v1_partition(&transaction, &path, &key)?; }
            COGNITION_SCHEMA_VERSION => { observe_v2_partition(&transaction, &path, &key)?; }
            0 => {
                if user_object_count(&transaction, &path)? > 0 {
                    return Err(WorkspaceIntelligenceCognitionError::UnrecognizedDatabase { path });
                }
                self.create_v2_partition(&transaction, &path, &key)?;
            }
            observed => return Err(WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { path, observed }),
        }
        let previous_token = read_incarnation(&transaction, &path)?;
        let mut token = uuid::Uuid::new_v4().to_string();
        while previous_token.as_deref() == Some(token.as_str()) {
            token = uuid::Uuid::new_v4().to_string();
        }
        transaction.execute(
            "UPDATE partition_state SET incarnation_token = ?1 WHERE state_id = 1",
            params![token],
        ).map_err(|e| sqlite_error(&path, e))?;
        transaction.commit().map_err(|e| sqlite_error(&path, e))?;
        Ok(IncarnationAdvance { previous_token, token })
    }

    /// Replace only the `cursor` column in one IMMEDIATE transaction through COMMIT.
    ///
    /// This is the crate's only cursor writer and it is the narrow primitive behind
    /// the governed fence; it is never a general-purpose writer. It requires a
    /// partition a claim already created: a missing record, an uninitialized
    /// database (version `0`) and any other version are
    /// [`WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable`], and this
    /// call never creates a root, a record, a table or a row.
    ///
    /// `expected` is compared with the stored cursor text exactly — no trim, no case
    /// folding, no parsing — so `None` (SQL NULL) and `Some("")` are different
    /// stored states. A mismatch is
    /// [`WorkspaceIntelligenceCognitionError::CursorConflict`] and the transaction
    /// rolls back, leaving the file bytes unchanged. The replacement is stored
    /// verbatim and never interpreted here: any envelope, affinity or gap decision
    /// belongs to the caller.
    pub(crate) fn advance_cursor(
        &self,
        scope: &str,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<CursorAdvance, WorkspaceIntelligenceCognitionError> {
        let key = scope_digest(scope)?;
        let path = self.record_path(&key);
        let Some(mut connection) = self.open_existing_record(&path, WRITE_FLAGS)? else {
            return Err(WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable { path });
        };
        connection.busy_timeout(BUSY_TIMEOUT).map_err(|e| sqlite_error(&path, e))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sqlite_error(&path, e))?;
        match schema_version(&transaction, &path)? {
            V1_SCHEMA_VERSION => {
                observe_v1_partition(&transaction, &path, &key)?;
            }
            COGNITION_SCHEMA_VERSION => {
                observe_v2_partition(&transaction, &path, &key)?;
            }
            // Deliberately not `UninitializedDatabase`: a cursor advance states that a
            // claim already established the partition, and unlike the token path this
            // operation never creates one.
            _ => {
                return Err(WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable { path });
            }
        }
        let stored = read_cursor(&transaction, &path)?;
        if stored.as_deref() != expected {
            return Err(WorkspaceIntelligenceCognitionError::CursorConflict { path });
        }
        transaction.execute(
            "UPDATE partition_state SET cursor = ?1 WHERE state_id = 1",
            params![replacement],
        ).map_err(|e| sqlite_error(&path, e))?;
        // Test-only failpoint: fail after the row was written, so the rollback proof
        // covers the write itself.
        #[cfg(test)]
        {
            if self.cursor_failpoint {
                return Err(WorkspaceIntelligenceCognitionError::Io(
                    std::io::Error::other(
                        "injected cognition cursor advance failure (test-only failpoint)",
                    ),
                ));
            }
        }
        transaction.commit().map_err(|e| sqlite_error(&path, e))?;
        Ok(CursorAdvance { previous: stored, written: replacement.to_owned() })
    }

    /// Verification with no data writes in ONE IMMEDIATE transaction, acquiring
    /// SQLite's reserved writer lock (not a read-only connection). Compare stored/live
    /// first, request/live second, exactly (no trim, parsing or case folding),
    /// then validate shape. Never create any root, record, table or row.
    /// The transaction is dropped and rolled back on return, never committed.
    ///
    /// A store call that returns has already ended its transaction: an
    /// after-return comparison cannot be in-transaction. Passing both expected
    /// markers into this typed operation is the callback-free way to keep the
    /// provenance comparison in the same IMMEDIATE transaction as the
    /// authoritative stored/live comparison. This strengthens the draft
    /// single-marker contract rather than weakening it.
    pub(crate) fn verify_incarnation(
        &self, scope: &str, live_token: &str, request_token: &str,
    ) -> Result<CognitionInitialization, WorkspaceIntelligenceCognitionError> {
        let key = scope_digest(scope)?;
        let path = self.record_path(&key);
        let Some(mut connection) = self.open_existing_record(&path, WRITE_FLAGS)? else {
            return Err(WorkspaceIntelligenceCognitionError::StaleIncarnation { path });
        };
        connection.busy_timeout(BUSY_TIMEOUT).map_err(|e| sqlite_error(&path, e))?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| sqlite_error(&path, e))?;
        match schema_version(&transaction, &path)? {
            V1_SCHEMA_VERSION | COGNITION_SCHEMA_VERSION => {}
            0 => return Err(WorkspaceIntelligenceCognitionError::UninitializedDatabase { path }),
            observed => return Err(WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { path, observed }),
        }
        #[cfg(test)]
        if let Some(pause) = &self.verify_pause {
            pause.0.send(()).unwrap();
            let _ = pause.1.lock().unwrap().recv();
        }
        let stored = read_incarnation(&transaction, &path)?;
        if stored.as_deref() != Some(live_token) {
            return Err(WorkspaceIntelligenceCognitionError::StaleIncarnation { path });
        }
        if request_token != live_token {
            return Err(WorkspaceIntelligenceCognitionError::StaleIncarnation { path });
        }
        let state = observe_v1_partition(&transaction, &path, &key)?;
        drop(transaction);
        Ok(CognitionInitialization::Existing(state))
    }
}

#[cfg(feature = "workspace-intelligence-claim")]
fn read_incarnation(connection: &Connection, path: &Path) -> Result<Option<String>, WorkspaceIntelligenceCognitionError> {
    // The same strict nullable-text rule used by the shape-only reader.
    let mut statement = connection.prepare(
        "SELECT incarnation_token FROM partition_state WHERE state_id = 1"
    ).map_err(|e| sqlite_error(path, e))?;
    let mut rows = statement.query([]).map_err(|e| sqlite_error(path, e))?;
    let row = rows.next().map_err(|e| sqlite_error(path, e))?
        .ok_or_else(|| WorkspaceIntelligenceCognitionError::MissingPartitionRow { path: path.to_path_buf() })?;
    read_optional_text(row, 0, path, PartitionShapeFault::IncarnationTokenNotText)
}

#[cfg(feature = "workspace-intelligence-commit")]
fn read_cursor(connection: &Connection, path: &Path) -> Result<Option<String>, WorkspaceIntelligenceCognitionError> {
    // The same strict nullable-text rule used by the shape-only reader.
    let mut statement = connection.prepare(
        "SELECT cursor FROM partition_state WHERE state_id = 1"
    ).map_err(|e| sqlite_error(path, e))?;
    let mut rows = statement.query([]).map_err(|e| sqlite_error(path, e))?;
    let row = rows.next().map_err(|e| sqlite_error(path, e))?
        .ok_or_else(|| WorkspaceIntelligenceCognitionError::MissingPartitionRow { path: path.to_path_buf() })?;
    read_optional_text(row, 0, path, PartitionShapeFault::CursorNotText)
}

/// One entry a caller asks [`WorkspaceIntelligenceCognitionStore::commit_entries_with_cursor`]
/// to insert.
///
/// The caller supplies every stored column except `content_digest`: this store
/// derives that digest from `statement`, so a caller cannot commit a digest that
/// disagrees with the stored text.
#[cfg(feature = "workspace-intelligence-commit")]
#[derive(Debug, Clone, PartialEq)]
pub struct NewCognitionEntry {
    /// Stable record identity; a duplicate aborts the whole commit.
    pub entry_id: String,
    /// Kind code, stored verbatim.
    pub kind: String,
    /// Category code; the schema accepts only `fact` and `asserted`.
    pub category: String,
    /// Authority code; the schema accepts only `human` and `derived`.
    pub authority: String,
    /// Lifecycle state code, stored verbatim.
    pub state: String,
    /// Statement text; the content digest is derived from these bytes.
    pub statement: String,
    /// Partition this row belongs to; readers filter on it.
    pub workspace_partition: String,
    /// Visibility code; the schema accepts only `partition` and `shared`.
    pub visibility: String,
    /// Shared scope, when the visibility is shared.
    pub shared_scope: Option<String>,
    /// Shared authorization source, when the visibility is shared.
    pub shared_authorization: Option<String>,
    /// Source owner of this record.
    pub source_owner: String,
    /// Source resource, when the caller has one.
    pub source_resource: Option<String>,
    /// Source revision, when the caller has one.
    pub source_revision: Option<String>,
    /// Observation time in Unix milliseconds.
    pub observed_at_unix_ms: i64,
    /// Validity bound in Unix milliseconds, when the caller has one.
    pub valid_until_unix_ms: Option<i64>,
    /// Confidence, when the caller has one.
    pub confidence: Option<f64>,
    /// Record revision this insert states.
    pub revision: i64,
    /// Partition epoch baseline this insert states.
    pub epoch: i64,
    /// Record this row supersedes, when the caller has one.
    pub supersedes: Option<String>,
    /// Invalidation reason, when the caller has one.
    pub invalidated_reason: Option<String>,
}

/// One stored entry a caller asks
/// [`WorkspaceIntelligenceCognitionStore::commit_entries_with_cursor`] to retire.
///
/// The retirement applies only when the stored row still carries
/// `expected_revision` and still belongs to the committing partition; otherwise
/// the whole commit aborts. A retirement never inserts a row.
#[cfg(feature = "workspace-intelligence-commit")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRetirement {
    /// Stored entry this retirement targets.
    pub entry_id: String,
    /// Revision the caller observed; the update applies only on an exact match.
    pub expected_revision: i64,
    /// State text to store.
    pub new_state: String,
    /// Invalidation reason text to store, when the caller has one.
    pub reason: Option<String>,
}

/// What one entries commit wrote, in the order it wrote it.
///
/// Both id lists are empty when the corresponding input was empty. The commit is
/// all-or-nothing: a returned value means every listed write committed, and an
/// error means none did.
#[cfg(feature = "workspace-intelligence-commit")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntriesCommit {
    /// Entry ids this commit inserted, in input order.
    pub committed_entry_ids: Vec<String>,
    /// Entry ids this commit retired, in input order.
    pub retired_entry_ids: Vec<String>,
    /// Cursor change this commit applied, or `None` when it wrote no cursor.
    pub cursor: Option<EntriesCursorAdvance>,
}

/// Cursor change one entries commit applied.
#[cfg(feature = "workspace-intelligence-commit")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntriesCursorAdvance {
    /// Stored cursor before this commit; `None` means the column held NULL.
    pub previous: Option<String>,
    /// Cursor text this commit wrote.
    pub written: String,
}

#[cfg(feature = "workspace-intelligence-commit")]
impl WorkspaceIntelligenceCognitionStore {
    /// Commits new entries, retirements and one optional cursor replacement in a
    /// single IMMEDIATE transaction.
    ///
    /// The schema check, the cursor comparison, every retirement, every insert and
    /// the cursor replacement all happen inside that one transaction, so a failure
    /// anywhere writes nothing: no entry, no retirement and no cursor change
    /// survives.
    ///
    /// `expected_cursor` is compared with the stored cursor text exactly — no trim,
    /// no case folding, no parsing — with the same semantics as
    /// [`Self::advance_cursor`], and a mismatch is
    /// [`WorkspaceIntelligenceCognitionError::CursorConflict`]. A retirement whose
    /// stored revision or partition does not match is
    /// [`WorkspaceIntelligenceCognitionError::EntryRevisionConflict`], and an
    /// entry id that already exists is
    /// [`WorkspaceIntelligenceCognitionError::EntryDuplicate`]; both abort the
    /// whole commit.
    ///
    /// This call requires an existing v2 partition and never creates a root, a
    /// record, a table or a row for a missing one, and it never upgrades a v1
    /// record: a missing or v1 record is
    /// [`WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable`]. It is
    /// the crate's only content writer and it is never a general-purpose writer;
    /// like [`Self::advance_cursor`] it is a narrow primitive behind the governed
    /// commit path.
    pub fn commit_entries_with_cursor(
        &self,
        scope: &str,
        expected_cursor: Option<&str>,
        replacement_cursor: Option<&str>,
        entries: &[NewCognitionEntry],
        retirements: &[EntryRetirement],
    ) -> Result<EntriesCommit, WorkspaceIntelligenceCognitionError> {
        let key = scope_digest(scope)?;
        let path = self.record_path(&key);
        let Some(mut connection) = self.open_existing_record(&path, WRITE_FLAGS)? else {
            return Err(WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable { path });
        };
        connection
            .busy_timeout(BUSY_TIMEOUT)
            .map_err(|error| sqlite_error(&path, error))?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| sqlite_error(&path, error))?;
        match schema_version(&transaction, &path)? {
            COGNITION_SCHEMA_VERSION => {
                observe_v2_partition(&transaction, &path, &key)?;
            }
            // No creation and no upgrade: the caller states that a governed commit
            // already established a v2 partition.
            _ => {
                return Err(WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable {
                    path,
                });
            }
        }

        let stored = read_cursor(&transaction, &path)?;
        if stored.as_deref() != expected_cursor {
            return Err(WorkspaceIntelligenceCognitionError::CursorConflict { path });
        }

        let mut retired_entry_ids = Vec::with_capacity(retirements.len());
        for retirement in retirements {
            let changed = transaction
                .execute(
                    RETIRE_ENTRY_SQL,
                    params![
                        &retirement.new_state,
                        &retirement.reason,
                        &retirement.entry_id,
                        retirement.expected_revision,
                        &key,
                    ],
                )
                .map_err(|error| sqlite_error(&path, error))?;
            if changed != 1 {
                return Err(
                    WorkspaceIntelligenceCognitionError::EntryRevisionConflict {
                        entry_id: retirement.entry_id.clone(),
                    },
                );
            }
            retired_entry_ids.push(retirement.entry_id.clone());
        }

        let mut committed_entry_ids = Vec::with_capacity(entries.len());
        for entry in entries {
            let existing: i64 = transaction
                .query_row(COUNT_ENTRY_SQL, params![&entry.entry_id], |row| row.get(0))
                .map_err(|error| sqlite_error(&path, error))?;
            if existing > 0 {
                return Err(WorkspaceIntelligenceCognitionError::EntryDuplicate {
                    entry_id: entry.entry_id.clone(),
                });
            }
            let digest = Sha256::digest(entry.statement.as_bytes());
            transaction
                .execute(
                    INSERT_ENTRY_SQL,
                    params![
                        &entry.entry_id,
                        &entry.kind,
                        &entry.category,
                        &entry.authority,
                        &entry.state,
                        &entry.statement,
                        &entry.workspace_partition,
                        &entry.visibility,
                        &entry.shared_scope,
                        &entry.shared_authorization,
                        &entry.source_owner,
                        &entry.source_resource,
                        &entry.source_revision,
                        entry.observed_at_unix_ms,
                        entry.valid_until_unix_ms,
                        entry.confidence,
                        entry.revision,
                        entry.epoch,
                        &entry.supersedes,
                        &entry.invalidated_reason,
                        format!("{digest:x}"),
                    ],
                )
                .map_err(|error| sqlite_error(&path, error))?;
            committed_entry_ids.push(entry.entry_id.clone());
        }

        let cursor = match replacement_cursor {
            Some(replacement) => {
                transaction
                    .execute(UPDATE_CURSOR_SQL, params![replacement])
                    .map_err(|error| sqlite_error(&path, error))?;
                Some(EntriesCursorAdvance {
                    previous: stored,
                    written: replacement.to_owned(),
                })
            }
            None => None,
        };

        // Test-only failpoint: fail after every write, so the rollback proof
        // covers the entries and the cursor together.
        #[cfg(test)]
        {
            if self.commit_failpoint {
                return Err(WorkspaceIntelligenceCognitionError::Io(
                    std::io::Error::other(
                        "injected cognition entries commit failure (test-only failpoint)",
                    ),
                ));
            }
        }

        transaction
            .commit()
            .map_err(|error| sqlite_error(&path, error))?;
        Ok(EntriesCommit {
            committed_entry_ids,
            retired_entry_ids,
            cursor,
        })
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
    #[cfg(all(test, feature = "workspace-intelligence-claim"))]
    pub(crate) verify_pause: Option<crate::workspace_intelligence_commit::TestPause>,
    /// Test-only failpoint that fails a cursor advance after the row was written.
    #[cfg(all(test, feature = "workspace-intelligence-claim"))]
    pub(crate) cursor_failpoint: bool,
    /// Test-only failpoint that fails an entries commit after every write.
    #[cfg(all(test, feature = "workspace-intelligence-commit"))]
    pub(crate) commit_failpoint: bool,
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
            #[cfg(feature = "workspace-intelligence-claim")]
            verify_pause: None,
            #[cfg(feature = "workspace-intelligence-claim")]
            cursor_failpoint: false,
            #[cfg(feature = "workspace-intelligence-commit")]
            commit_failpoint: false,
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
            #[cfg(feature = "workspace-intelligence-claim")]
            verify_pause: None,
            #[cfg(feature = "workspace-intelligence-claim")]
            cursor_failpoint: false,
            #[cfg(feature = "workspace-intelligence-commit")]
            commit_failpoint: false,
        }
    }

    /// Creates the v2 partition for `scope` if, and only if, it does not exist,
    /// and upgrades an existing v1 partition to v2.
    ///
    /// The call opens the record read-write without creating it, and creates the
    /// root directory plus the record only when the file is absent. Inside one
    /// immediate transaction it re-reads the schema version and the user objects
    /// and then decides. Objects SQLite creates itself (`sqlite_sequence`,
    /// `sqlite_stat1`, `sqlite_autoindex_*`) are classified by an exact
    /// `sqlite_` name prefix; every other object is a user object this store did
    /// not create:
    ///
    /// - version `0` with no user objects: create the v2 schema, insert the
    ///   single partition row and stamp the version, then commit;
    /// - version `0` with any user object: [`WorkspaceIntelligenceCognitionError::UnrecognizedDatabase`],
    ///   rolled back, bytes and objects untouched;
    /// - version `1`: validate the v1 shape first, then add the two v2 content
    ///   tables and the version stamp, and report
    ///   [`CognitionInitialization::Upgraded`]; no partition field changes;
    /// - version `2`: validate exactly like [`Self::read`] and report
    ///   [`CognitionInitialization::Existing`] without writing any user field;
    /// - any other version: [`WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion`],
    ///   rolled back, file untouched.
    ///
    /// An invalid v1 or v2 shape is an explicit error: this call never repairs,
    /// resets or replaces what it did not write, and a failed upgrade leaves the
    /// record at v1 with no content table.
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
                observe_v2_partition(&transaction, &path, &partition_key)?,
            ),
            V1_SCHEMA_VERSION => {
                // The v1 shape must be usable before any v2 object is created, so a
                // broken v1 record is reported and stays exactly as it was.
                observe_v1_partition(&transaction, &path, &partition_key)?;
                create_v2_content_tables(&transaction, &path)?;
                set_v2_version(&transaction, &path)?;
                // Test-only failpoint: fail after the tables and the version were
                // written, so the rollback proof covers the upgrade itself.
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
                CognitionInitialization::Upgraded(observe_v2_partition(
                    &transaction,
                    &path,
                    &partition_key,
                )?)
            }
            0 => {
                if user_object_count(&transaction, &path)? > 0 {
                    // A foreign database is preserved, never adopted, repaired,
                    // reset or deleted: the transaction rolls back and no
                    // partition_state table or version stamp is written.
                    return Err(
                        WorkspaceIntelligenceCognitionError::UnrecognizedDatabase { path },
                    );
                }
                self.create_v2_partition(&transaction, &path, &partition_key)?;
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
                observe_v2_partition(&transaction, &path, &partition_key)?
            }
            V1_SCHEMA_VERSION => {
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

    /// Observes the stored content entries of one partition.
    ///
    /// The record is opened read-only and is never created. `Ok(None)` means only
    /// that this call did not observe a file, exactly like [`Self::read`]; it is
    /// not proof of an accepted close, reset or delete.
    ///
    /// A v1 record has no content table: it is
    /// [`WorkspaceIntelligenceCognitionError::ContentTableAbsent`] and stays v1.
    /// An uninitialized record, an unsupported version and an unusable shape are
    /// the same explicit errors [`Self::read`] reports. This call never creates,
    /// upgrades, repairs or deletes anything.
    ///
    /// Rows are returned in the stored order of `kind` then `entry_id`, and only
    /// for this partition.
    pub fn read_entries(
        &self,
        scope: &str,
    ) -> Result<Option<Vec<StoredCognitionEntry>>, WorkspaceIntelligenceCognitionError> {
        let partition_key = scope_digest(scope)?;
        let path = self.record_path(&partition_key);

        let Some(mut connection) = self.open_existing_record(&path, READ_FLAGS)? else {
            return Ok(None);
        };

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|error| sqlite_error(&path, error))?;

        let observed_version = schema_version(&transaction, &path)?;
        let entries = match observed_version {
            COGNITION_SCHEMA_VERSION => {
                observe_v2_partition(&transaction, &path, &partition_key)?;
                read_entry_rows(&transaction, &path, &partition_key)?
            }
            V1_SCHEMA_VERSION => {
                return Err(WorkspaceIntelligenceCognitionError::ContentTableAbsent {
                    path: path.to_path_buf(),
                });
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

        drop(transaction);
        Ok(Some(entries))
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

    /// Writes the whole v2 partition inside the caller's transaction.
    ///
    /// The partition table, its single row, the two content tables, the two
    /// indexes and the version stamp all belong to the same transaction, so a
    /// failure anywhere leaves no partial schema and no advanced `user_version`.
    fn create_v2_partition(
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
        create_v2_content_tables(transaction, path)?;
        set_v2_version(transaction, path)?;

        // Test-only failpoint: fail after the tables, the row and the version
        // were written, so the rollback proof covers all of them.
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

/// Creates the v2 content tables and indexes inside the caller's transaction.
///
/// Every statement uses `IF NOT EXISTS`, so the upgrade never rewrites an object
/// that already exists; a foreign content shape is rejected by the exact shape
/// check, not by a failed `CREATE`.
///
/// A table that already exists is validated before any DDL runs. Otherwise a
/// foreign `cognition_entries` would make the index statement fail with a raw
/// SQLite error instead of the shape fault a caller can act on.
fn create_v2_content_tables(
    transaction: &Transaction<'_>,
    path: &Path,
) -> Result<(), WorkspaceIntelligenceCognitionError> {
    let owned: [(&str, &[&str], PartitionShapeFault); 2] = [
        (
            COGNITION_ENTRIES_TABLE,
            &COGNITION_ENTRIES_REQUIRED_COLUMNS,
            PartitionShapeFault::EntriesColumnMissing,
        ),
        (
            COGNITION_DEPENDENCIES_TABLE,
            &COGNITION_DEPENDENCIES_REQUIRED_COLUMNS,
            PartitionShapeFault::DependenciesColumnMissing,
        ),
    ];
    for (table, required, column_fault) in owned {
        if table_exists(transaction, path, table)? {
            require_table_shape(
                transaction,
                path,
                table,
                required,
                column_fault,
                column_fault,
            )?;
        }
    }
    transaction
        .execute_batch(CREATE_COGNITION_CONTENT_SQL)
        .map_err(|error| sqlite_error(path, error))
}

/// Stamps `user_version = 2` inside the caller's transaction.
fn set_v2_version(
    transaction: &Transaction<'_>,
    path: &Path,
) -> Result<(), WorkspaceIntelligenceCognitionError> {
    transaction
        .execute_batch(SET_SCHEMA_VERSION_SQL)
        .map_err(|error| sqlite_error(path, error))
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
pub(crate) fn scope_digest(scope: &str) -> Result<String, WorkspaceIntelligenceCognitionError> {
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
    table_columns_named(connection, path, PARTITION_STATE_TABLE)
}

/// Column names of `table` in declaration order.
///
/// The table name is always one of this module's own constants, so it is never
/// untrusted input.
fn table_columns_named(
    connection: &Connection,
    path: &Path,
    table: &str,
) -> Result<Vec<String>, WorkspaceIntelligenceCognitionError> {
    let mut statement = connection
        .prepare(&format!("PRAGMA table_info({table});"))
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
/// and ignored. Claim verification compares markers first, failing closed on
/// disagreement; this full shape check runs only after those comparisons succeed.
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

/// Reads and validates the v2 partition inside the caller's transaction.
///
/// The v1 checks run first, so a v2 record is never accepted with a broken
/// `partition_state`. The two content tables must then exist with exactly the
/// column sequence this module creates: a missing table is an explicit error
/// rather than an empty read, and a table this store did not write is reported
/// instead of adopted.
fn observe_v2_partition(
    connection: &Connection,
    path: &Path,
    expected_partition_key: &str,
) -> Result<CognitionPartitionState, WorkspaceIntelligenceCognitionError> {
    let state = observe_v1_partition(connection, path, expected_partition_key)?;
    require_table_shape(
        connection,
        path,
        COGNITION_ENTRIES_TABLE,
        &COGNITION_ENTRIES_REQUIRED_COLUMNS,
        PartitionShapeFault::EntriesTableMissing,
        PartitionShapeFault::EntriesColumnMissing,
    )?;
    require_table_shape(
        connection,
        path,
        COGNITION_DEPENDENCIES_TABLE,
        &COGNITION_DEPENDENCIES_REQUIRED_COLUMNS,
        PartitionShapeFault::DependenciesTableMissing,
        PartitionShapeFault::DependenciesColumnMissing,
    )?;
    Ok(state)
}

/// Requires one owned table to exist with exactly `required` as its column
/// sequence.
///
/// No extra column is accepted: the sequence is written and read by this module
/// only, so a different sequence means another writer owns the table.
///
/// This covers column names and their order only. Declared types, `NOT NULL`
/// markers and `CHECK` constraints are not compared, so a table with the same
/// sequence and weaker constraints is accepted; `entry_id TEXT PRIMARY KEY` in
/// SQLite does not imply `NOT NULL` either, and this check does not add that
/// requirement.
fn require_table_shape(
    connection: &Connection,
    path: &Path,
    table: &str,
    required: &[&str],
    missing_fault: PartitionShapeFault,
    column_fault: PartitionShapeFault,
) -> Result<(), WorkspaceIntelligenceCognitionError> {
    if !table_exists(connection, path, table)? {
        return Err(invalid_shape(path, missing_fault));
    }
    let observed = table_columns_named(connection, path, table)?;
    let exact = observed.len() == required.len()
        && observed
            .iter()
            .zip(required.iter())
            .all(|(observed_column, required_column)| observed_column.as_str() == *required_column);
    if !exact {
        return Err(invalid_shape(path, column_fault));
    }
    Ok(())
}

/// True when `table` is a table this record holds.
fn table_exists(
    connection: &Connection,
    path: &Path,
    table: &str,
) -> Result<bool, WorkspaceIntelligenceCognitionError> {
    let present: i64 = connection
        .query_row(SCHEMA_OBJECT_NAMED_SQL, params![table], |row| row.get(0))
        .map_err(|error| sqlite_error(path, error))?;
    Ok(present != 0)
}

/// Reads every stored entry of one partition, ordered by `kind` then `entry_id`.
fn read_entry_rows(
    connection: &Connection,
    path: &Path,
    partition_key: &str,
) -> Result<Vec<StoredCognitionEntry>, WorkspaceIntelligenceCognitionError> {
    let mut statement = connection
        .prepare(SELECT_ENTRIES_SQL)
        .map_err(|error| sqlite_error(path, error))?;
    let mut mapped = statement
        .query_map(params![partition_key], |row| {
            Ok(StoredCognitionEntry {
                entry_id: row.get(0)?,
                kind: row.get(1)?,
                category: row.get(2)?,
                authority: row.get(3)?,
                state: row.get(4)?,
                statement: row.get(5)?,
                workspace_partition: row.get(6)?,
                visibility: row.get(7)?,
                shared_scope: row.get(8)?,
                shared_authorization: row.get(9)?,
                source_owner: row.get(10)?,
                source_resource: row.get(11)?,
                source_revision: row.get(12)?,
                observed_at_unix_ms: row.get(13)?,
                valid_until_unix_ms: row.get(14)?,
                confidence: row.get(15)?,
                revision: row.get(16)?,
                epoch: row.get(17)?,
                supersedes: row.get(18)?,
                invalidated_reason: row.get(19)?,
                content_digest: row.get(20)?,
            })
        })
        .map_err(|error| sqlite_error(path, error))?;
    let mut entries = Vec::new();
    for entry in mapped.by_ref() {
        entries.push(entry.map_err(|error| sqlite_error(path, error))?);
    }
    Ok(entries)
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
    fn initialize_creates_v2_schema_singleton_row_and_version() {
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
            "an existing v2 record is not rewritten"
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
                     PRAGMA user_version = 3;",
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
                WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { observed: 3, .. }
            ),
            "unexpected read error: {read_error}"
        );
        let initialize_error = store
            .initialize(future_scope)
            .expect_err("an unknown version is rejected by initialize");
        assert!(
            matches!(
                initialize_error,
                WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { observed: 3, .. }
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
            assert_eq!(user_version_of(&connection), 3);
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

    /// A record exactly as the pre-v2 module wrote it: `partition_state` only,
    /// `user_version = 1`, cursor and token already set.
    fn write_v1_record(path: &Path, partition_key: &str, cursor: &str, token: &str) {
        raw_write_connection(path)
            .execute_batch(&format!(
                "{CREATE_PARTITION_STATE_SQL}
                 INSERT INTO partition_state (state_id, partition_key, cursor, incarnation_token)
                 VALUES (1, '{partition_key}', '{cursor}', '{token}');
                 {SET_V1_SCHEMA_VERSION_SQL}"
            ))
            .expect("the v1 fixture is created");
    }

    fn content_row_count(connection: &Connection, table: &str) -> i64 {
        connection
            .query_row(&format!("SELECT COUNT(*) FROM {table};"), [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("the fixture content row count is readable")
    }

    fn expected_columns(columns: &[&str]) -> Vec<String> {
        columns.iter().map(|column| (*column).to_string()).collect()
    }

    #[test]
    fn initialize_on_an_empty_v0_creates_the_v2_shape() {
        let temp = TempDir::new().expect("temporary directory");
        let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));

        let initialization = store.initialize(SCOPE).expect("initialize succeeds");

        assert!(initialization.is_initialized());
        assert!(
            matches!(initialization, CognitionInitialization::Initialized(_)),
            "a fresh record is a creation, not an upgrade"
        );
        assert_eq!(
            initialization.state(),
            &CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }
        );

        let path = record_path_for(&store, SCOPE);
        let connection = raw_read_connection(&path);
        assert_eq!(COGNITION_SCHEMA_VERSION, 2, "v2 is the current physical version");
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
        let tables = table_names(&connection);
        for table in [
            PARTITION_STATE_TABLE,
            COGNITION_ENTRIES_TABLE,
            COGNITION_DEPENDENCIES_TABLE,
        ] {
            assert!(
                tables.contains(&table.to_string()),
                "missing table {table} in {tables:?}"
            );
        }
        assert_eq!(partition_row_count(&connection), 1);
        assert_eq!(
            column_names(&connection, COGNITION_ENTRIES_TABLE),
            expected_columns(&COGNITION_ENTRIES_REQUIRED_COLUMNS),
            "the entry table carries exactly the v2 column sequence"
        );
        assert_eq!(
            column_names(&connection, COGNITION_DEPENDENCIES_TABLE),
            expected_columns(&COGNITION_DEPENDENCIES_REQUIRED_COLUMNS),
            "the dependency table carries exactly the v2 column sequence"
        );
        assert_eq!(content_row_count(&connection, COGNITION_ENTRIES_TABLE), 0);
        assert_eq!(
            content_row_count(&connection, COGNITION_DEPENDENCIES_TABLE),
            0
        );
        assert_eq!(
            column_names(&connection, PARTITION_STATE_TABLE),
            expected_columns(&PARTITION_STATE_REQUIRED_COLUMNS),
            "the partition table keeps the v1 shape"
        );
    }

    #[test]
    fn initialize_upgrades_a_v1_record_and_leaves_the_partition_row_alone() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let store = WorkspaceIntelligenceCognitionStore::new(root);
        let path = record_path_for(&store, SCOPE);
        write_v1_record(&path, &scope_digest(SCOPE).expect("scope digest"), "abc", "tok");

        let initialization = store.initialize(SCOPE).expect("a v1 record upgrades");

        assert!(
            !initialization.is_initialized(),
            "an upgrade is not a creation"
        );
        assert!(
            matches!(initialization, CognitionInitialization::Upgraded(_)),
            "a v1 record must report the upgrade, got {initialization:?}"
        );
        assert_eq!(
            initialization.state(),
            &CognitionPartitionState {
                cursor: Some("abc".to_string()),
                incarnation_token: Some("tok".to_string()),
            },
            "the upgrade reports the stored partition values"
        );

        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
        assert_eq!(partition_row_count(&connection), 1);
        let (state_id, partition_key, cursor, token): (i64, String, Option<String>, Option<String>) =
            connection
                .query_row(
                    "SELECT state_id, partition_key, cursor, incarnation_token \
                     FROM partition_state;",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .expect("the upgraded partition row is readable");
        assert_eq!(state_id, PARTITION_STATE_ID, "the singleton id is unchanged");
        assert_eq!(
            partition_key,
            scope_digest(SCOPE).expect("scope digest"),
            "the partition key is unchanged"
        );
        assert_eq!(cursor.as_deref(), Some("abc"), "the cursor survives unchanged");
        assert_eq!(token.as_deref(), Some("tok"), "the token survives unchanged");
        assert_eq!(
            content_row_count(&connection, COGNITION_ENTRIES_TABLE),
            0,
            "an upgrade adds no content row"
        );

        let again = store.initialize(SCOPE).expect("a second initialize reports existing");
        assert!(
            matches!(again, CognitionInitialization::Existing(_)),
            "an upgraded record is existing on the next call, got {again:?}"
        );
    }

    #[test]
    fn initialize_refuses_an_unusable_v1_shape_and_never_upgrades() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let store = WorkspaceIntelligenceCognitionStore::new(root);
        let path = record_path_for(&store, SCOPE);
        raw_write_connection(&path)
            .execute_batch(&format!(
                "CREATE TABLE partition_state (
                     state_id INTEGER PRIMARY KEY CHECK (state_id = 1),
                     partition_key TEXT,
                     cursor TEXT
                 );
                 INSERT INTO partition_state VALUES (1, '{}', NULL);
                 {SET_V1_SCHEMA_VERSION_SQL}",
                scope_digest(SCOPE).expect("scope digest")
            ))
            .expect("unusable v1 fixture is created");
        let bytes = file_bytes(&path);

        let error = store
            .initialize(SCOPE)
            .expect_err("an unusable v1 shape is never upgraded");

        assert_rejected_v1_error(
            &error,
            "invalid_partition_shape",
            Some("incarnation_token_column_missing"),
        );
        assert_eq!(file_bytes(&path), bytes, "a refused upgrade writes nothing");
        let connection = raw_read_connection(&path);
        assert_eq!(
            user_version_of(&connection),
            1,
            "the refused record stays v1"
        );
        assert!(
            !table_names(&connection).contains(&COGNITION_ENTRIES_TABLE.to_string()),
            "a refused upgrade creates no content table"
        );
    }

    #[test]
    fn a_failed_v1_upgrade_rolls_back_the_tables_and_the_version() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let failing =
            WorkspaceIntelligenceCognitionStore::with_injected_initialize_failure(root.clone());
        let path = record_path_for(&failing, SCOPE);
        write_v1_record(&path, &scope_digest(SCOPE).expect("scope digest"), "abc", "tok");

        let error = failing
            .initialize(SCOPE)
            .expect_err("the injected failure aborts the upgrade");
        assert_eq!(error.code(), "io", "unexpected error: {error}");

        let connection = raw_read_connection(&path);
        assert_eq!(
            user_version_of(&connection),
            1,
            "the version stamp rolls back with the upgrade"
        );
        assert_eq!(
            table_names(&connection),
            vec![PARTITION_STATE_TABLE.to_string()],
            "no content table survives the rollback"
        );
        let cursor: Option<String> = connection
            .query_row(
                "SELECT cursor FROM partition_state WHERE state_id = 1;",
                [],
                |row| row.get(0),
            )
            .expect("the fixture cursor is readable");
        assert_eq!(cursor.as_deref(), Some("abc"), "the partition row is unchanged");

        // The same record still upgrades through a healthy store.
        let healthy = WorkspaceIntelligenceCognitionStore::new(root);
        assert!(
            matches!(
                healthy.initialize(SCOPE).expect("the record still upgrades"),
                CognitionInitialization::Upgraded(_)
            ),
            "a rolled-back upgrade is retryable"
        );
    }

    #[test]
    fn a_future_schema_version_is_reported_and_never_upgraded() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let store = WorkspaceIntelligenceCognitionStore::new(root);
        let path = record_path_for(&store, SCOPE);
        write_v1_record(&path, &scope_digest(SCOPE).expect("scope digest"), "abc", "tok");
        raw_write_connection(&path)
            .execute_batch("PRAGMA user_version = 3;")
            .expect("future version fixture is created");
        let bytes = file_bytes(&path);

        let error = store
            .initialize(SCOPE)
            .expect_err("a future version is rejected by initialize");

        assert!(
            matches!(
                error,
                WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { observed: 3, .. }
            ),
            "unexpected error: {error}"
        );
        assert_eq!(error.code(), "unsupported_schema_version");
        assert_eq!(file_bytes(&path), bytes, "a future record is untouched");
        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), 3);
        assert!(
            !table_names(&connection).contains(&COGNITION_ENTRIES_TABLE.to_string()),
            "a future record gains no content table"
        );
    }

    #[test]
    fn read_reports_the_v2_partition_shape() {
        let temp = TempDir::new().expect("temporary directory");
        let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
        store.initialize(SCOPE).expect("initialize succeeds");
        let path = record_path_for(&store, SCOPE);
        raw_write_connection(&path)
            .execute_batch(
                "UPDATE partition_state SET cursor = 'c1', incarnation_token = 't1';",
            )
            .expect("fixture shape values are written");

        assert_eq!(
            store.read(SCOPE).expect("record is readable"),
            Some(CognitionPartitionState {
                cursor: Some("c1".to_string()),
                incarnation_token: Some("t1".to_string()),
            })
        );
        let connection = raw_read_connection(&path);
        assert_eq!(
            column_names(&connection, PARTITION_STATE_TABLE),
            expected_columns(&PARTITION_STATE_REQUIRED_COLUMNS),
            "the v2 read exposes the unchanged partition shape"
        );
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
    }

    #[test]
    fn read_entries_on_a_v1_record_is_explicit_and_keeps_the_version() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let store = WorkspaceIntelligenceCognitionStore::new(root);
        let path = record_path_for(&store, SCOPE);
        write_v1_record(&path, &scope_digest(SCOPE).expect("scope digest"), "abc", "tok");
        let bytes = file_bytes(&path);

        let error = store
            .read_entries(SCOPE)
            .expect_err("a v1 record has no content table");

        assert_eq!(error.code(), "content_table_absent");
        assert!(
            error.to_string().contains("never upgraded by a read"),
            "the error states that a read does not upgrade: {error}"
        );
        assert_eq!(file_bytes(&path), bytes, "a v1 read writes nothing");
        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), 1, "the v1 record stays v1");
        assert!(!table_names(&connection).contains(&COGNITION_ENTRIES_TABLE.to_string()));
    }

    #[test]
    fn read_entries_on_a_missing_record_observes_nothing() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        let store = WorkspaceIntelligenceCognitionStore::new(root.clone());

        assert_eq!(
            store
                .read_entries(SCOPE)
                .expect("a missing record is an observation"),
            None
        );

        assert!(
            !root.exists(),
            "read_entries must not create the root directory, a record or a journal"
        );
    }

    #[test]
    fn an_extra_column_on_the_entries_table_is_reported_not_adopted() {
        let temp = TempDir::new().expect("temporary directory");
        let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
        store.initialize(SCOPE).expect("initialize succeeds");
        let path = record_path_for(&store, SCOPE);
        raw_write_connection(&path)
            .execute_batch("ALTER TABLE cognition_entries ADD COLUMN extra TEXT;")
            .expect("extra entry-column fixture is created");
        let bytes = file_bytes(&path);

        let read_error = store
            .read(SCOPE)
            .expect_err("an altered entry table is not adopted by read");
        assert_rejected_v1_error(
            &read_error,
            "invalid_partition_shape",
            Some("entries_column_missing"),
        );

        let entries_error = store
            .read_entries(SCOPE)
            .expect_err("an altered entry table is not adopted by read_entries");
        assert_rejected_v1_error(
            &entries_error,
            "invalid_partition_shape",
            Some("entries_column_missing"),
        );

        let initialize_error = store
            .initialize(SCOPE)
            .expect_err("an altered entry table is not adopted by initialize");
        assert_rejected_v1_error(
            &initialize_error,
            "invalid_partition_shape",
            Some("entries_column_missing"),
        );

        assert_eq!(
            file_bytes(&path),
            bytes,
            "a refused v2 shape is never rewritten, repaired or adopted"
        );
        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), COGNITION_SCHEMA_VERSION);
        assert!(
            column_names(&connection, COGNITION_ENTRIES_TABLE).contains(&"extra".to_string()),
            "the foreign column is preserved, not dropped"
        );
    }

    #[test]
    fn a_missing_dependencies_table_is_reported() {
        let temp = TempDir::new().expect("temporary directory");
        let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
        store.initialize(SCOPE).expect("initialize succeeds");
        let path = record_path_for(&store, SCOPE);
        raw_write_connection(&path)
            .execute_batch("DROP TABLE cognition_dependencies;")
            .expect("missing dependency-table fixture is created");
        let bytes = file_bytes(&path);

        let error = store
            .read_entries(SCOPE)
            .expect_err("a v2 record without its dependency table is incomplete");

        assert_rejected_v1_error(
            &error,
            "invalid_partition_shape",
            Some("dependencies_table_missing"),
        );
        assert_eq!(file_bytes(&path), bytes, "a refused read writes nothing");
    }

    #[test]
    fn a_polluted_v1_record_refuses_the_upgrade_and_stays_v1() {
        let temp = TempDir::new().expect("temporary directory");
        let root = store_root(&temp);
        fs::create_dir_all(&root).expect("fixture root is created");
        let store = WorkspaceIntelligenceCognitionStore::new(root);
        let path = record_path_for(&store, SCOPE);
        write_v1_record(&path, &scope_digest(SCOPE).expect("scope digest"), "abc", "tok");
        // A v1 record that already carries a same-named table with a foreign
        // column sequence must not be "completed" into v2.
        raw_write_connection(&path)
            .execute_batch(
                "CREATE TABLE cognition_entries (
                     entry_id TEXT,
                     kind TEXT,
                     statement TEXT
                 );",
            )
            .expect("polluted v1 fixture is created");
        let bytes = file_bytes(&path);

        let error = store
            .initialize(SCOPE)
            .expect_err("a polluted v1 record is not upgraded");

        assert_rejected_v1_error(
            &error,
            "invalid_partition_shape",
            Some("entries_column_missing"),
        );
        assert_eq!(
            file_bytes(&path),
            bytes,
            "the refused upgrade leaves the record byte-identical"
        );
        let connection = raw_read_connection(&path);
        assert_eq!(user_version_of(&connection), 1, "the record stays v1");
        let tables = table_names(&connection);
        assert!(
            tables.contains(&PARTITION_STATE_TABLE.to_string()),
            "the v1 partition table survives: {tables:?}"
        );
        assert!(
            !tables.contains(&COGNITION_DEPENDENCIES_TABLE.to_string()),
            "the upgrade table is rolled back: {tables:?}"
        );
    }

    #[cfg(feature = "workspace-intelligence-claim")]
    mod claim {
        use super::*;

        #[test]
        fn advance_incarnation_creates_the_partition_then_writes_token_in_one_transaction() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            let advance = store.advance_incarnation(SCOPE).unwrap();
            assert_eq!(advance.previous_token, None);
            assert!(!advance.token.is_empty());
            let state = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(state.cursor, None);
            assert_eq!(state.incarnation_token, Some(advance.token));
            let db = raw_read_connection(&record_path_for(&store, SCOPE));
            assert_eq!(user_version_of(&db), COGNITION_SCHEMA_VERSION);
            assert_eq!(partition_row_count(&db), 1);
        }

        #[test]
        fn advance_incarnation_preserves_cursor_extra_columns_and_legacy_token() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            store.initialize(SCOPE).unwrap();
            let path = record_path_for(&store, SCOPE);
            raw_write_connection(&path).execute_batch(
                "ALTER TABLE partition_state ADD COLUMN note TEXT;
                 UPDATE partition_state SET cursor='c7', incarnation_token=' legacy token ', note='keep';
                 CREATE TABLE extra (value TEXT); INSERT INTO extra VALUES ('sentinel');"
            ).unwrap();
            let advance = store.advance_incarnation(SCOPE).unwrap();
            assert_eq!(advance.previous_token.as_deref(), Some(" legacy token "));
            assert_ne!(advance.token, " legacy token ");
            assert_eq!(store.read(SCOPE).unwrap().unwrap().cursor.as_deref(), Some("c7"));
            let db = raw_read_connection(&path);
            assert_eq!(user_version_of(&db), COGNITION_SCHEMA_VERSION);
            assert_eq!(db.query_row("SELECT note FROM partition_state", [], |r| r.get::<_, String>(0)).unwrap(), "keep");
            assert_eq!(db.query_row("SELECT value FROM extra", [], |r| r.get::<_, String>(0)).unwrap(), "sentinel");
        }

        #[test]
        fn advance_incarnation_failure_inside_the_transaction_leaves_no_partial_row() {
            let temp = TempDir::new().unwrap();
            let mut store = WorkspaceIntelligenceCognitionStore::with_injected_initialize_failure(store_root(&temp));
            let path = record_path_for(&store, SCOPE);
            assert!(matches!(store.advance_incarnation(SCOPE), Err(WorkspaceIntelligenceCognitionError::Io(_))));
            assert!(path.is_file(), "rollback preserves the empty v0 file");
            {
                let db = raw_read_connection(&path);
                assert_eq!(user_version_of(&db), 0);
                assert_eq!(user_object_count(&db, &path).unwrap(), 0);
                assert_eq!(db.query_row("SELECT count(*) FROM sqlite_master WHERE name='partition_state'", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
            }
            let bytes = file_bytes(&path);
            assert!(matches!(store.verify_incarnation(SCOPE, "live", "live"), Err(WorkspaceIntelligenceCognitionError::UninitializedDatabase { .. })));
            assert_eq!(file_bytes(&path), bytes);
            store.inject_initialize_failure = false;
            let advance = store.advance_incarnation(SCOPE).unwrap();
            assert_eq!(advance.previous_token, None);
            assert!(!advance.token.is_empty());
            assert_eq!(format!("{advance:?}"), "IncarnationAdvance { previous_token: None, token: \"<redacted>\" }");
            let state = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(state.incarnation_token.as_deref(), Some(advance.token.as_str()));
            assert_eq!(state.cursor, None);
            let db = raw_read_connection(&path);
            assert_eq!(user_version_of(&db), COGNITION_SCHEMA_VERSION);
            assert_eq!(partition_row_count(&db), 1);
        }

        #[test]
        fn advance_incarnation_after_a_failed_creation_preserves_the_previous_token_cursor_and_unknown_columns() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            store.initialize(SCOPE).unwrap();
            let path = record_path_for(&store, SCOPE);
            raw_write_connection(&path).execute_batch(
                "ALTER TABLE partition_state ADD COLUMN note TEXT;
                 UPDATE partition_state SET cursor='c7', incarnation_token=' opaque token ', note='keep';
                 CREATE TABLE extra (value TEXT); INSERT INTO extra VALUES ('sentinel');
                 CREATE TRIGGER reject_incarnation BEFORE UPDATE ON partition_state
                 BEGIN SELECT RAISE(ABORT, 'fixture rejects token update'); END;"
            ).unwrap();
            let bytes = file_bytes(&path);
            let error = store.advance_incarnation(SCOPE).unwrap_err();
            assert!(matches!(error, WorkspaceIntelligenceCognitionError::Storage(ref source)
                if source.sqlite_error_code() == Some(rusqlite::ErrorCode::ConstraintViolation)));
            assert_eq!(file_bytes(&path), bytes);
            let state = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(state.cursor.as_deref(), Some("c7"));
            assert_eq!(state.incarnation_token.as_deref(), Some(" opaque token "));
            let db = raw_read_connection(&path);
            assert_eq!(user_version_of(&db), COGNITION_SCHEMA_VERSION);
            assert_eq!(partition_row_count(&db), 1);
            assert_eq!(db.query_row("SELECT note FROM partition_state", [], |r| r.get::<_, String>(0)).unwrap(), "keep");
            assert_eq!(db.query_row("SELECT value FROM extra", [], |r| r.get::<_, String>(0)).unwrap(), "sentinel");
        }

        #[test]
        fn verify_incarnation_on_empty_v0_is_uninitialized_without_writes() {
            let temp = TempDir::new().unwrap();
            let root = store_root(&temp);
            fs::create_dir_all(&root).unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(root);
            let path = record_path_for(&store, SCOPE);
            raw_write_connection(&path).execute_batch("PRAGMA user_version=0").unwrap();
            let bytes = file_bytes(&path);
            assert!(matches!(store.verify_incarnation(SCOPE, "live", "live"), Err(WorkspaceIntelligenceCognitionError::UninitializedDatabase { .. })));
            assert_eq!(file_bytes(&path), bytes);
            assert_eq!(user_version_of(&raw_read_connection(&path)), 0);
        }

        #[test]
        fn advance_incarnation_never_reuses_the_immediately_previous_token() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            let mut previous = None;
            for _ in 0..32 {
                let advance = store.advance_incarnation(SCOPE).unwrap();
                assert_eq!(advance.previous_token, previous);
                assert_ne!(advance.previous_token.as_deref(), Some(advance.token.as_str()));
                previous = Some(advance.token);
            }
        }

        #[test]
        fn verify_incarnation_rejects_stale_and_absent_without_writes() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            assert_eq!(store.verify_incarnation(SCOPE, "live", "live").unwrap_err().code(), "stale_incarnation");
            assert!(!store_root(&temp).exists());
            store.initialize(SCOPE).unwrap();
            let path = record_path_for(&store, SCOPE);
            let bytes = file_bytes(&path);
            assert_eq!(store.verify_incarnation(SCOPE, "live", "live").unwrap_err().code(), "stale_incarnation");
            assert_eq!(file_bytes(&path), bytes);
            store.advance_incarnation(SCOPE).unwrap();
            let bytes = file_bytes(&path);
            assert_eq!(store.verify_incarnation(SCOPE, "wrong", "wrong").unwrap_err().code(), "stale_incarnation");
            assert_eq!(file_bytes(&path), bytes);
        }

        #[test]
        fn verify_incarnation_checks_both_tokens_in_one_transaction() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            let advance = store.advance_incarnation(SCOPE).unwrap();
            let path = record_path_for(&store, SCOPE);
            let bytes = file_bytes(&path);
            for (live, request) in [
                (advance.token.as_str(), "wrong"), ("wrong", "wrong"),
                ("wrong", advance.token.as_str()),
            ] {
                assert_eq!(store.verify_incarnation(SCOPE, live, request).unwrap_err().code(), "stale_incarnation");
                assert_eq!(file_bytes(&path), bytes);
            }
            assert!(matches!(store.verify_incarnation(SCOPE, &advance.token, &advance.token).unwrap(), CognitionInitialization::Existing(_)));
            assert_eq!(file_bytes(&path), bytes);
        }

        #[test]
        fn unknown_schema_and_corrupt_partitions_are_never_reset() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            store.initialize(SCOPE).unwrap();
            let path = record_path_for(&store, SCOPE);
            raw_write_connection(&path).execute_batch("PRAGMA user_version=3").unwrap();
            for (code, corrupt) in [("unsupported_schema_version", false), ("corrupt_database", true)] {
                if corrupt { fs::write(&path, b"not a SQLite database").unwrap(); }
                let bytes = file_bytes(&path);
                assert_eq!(store.advance_incarnation(SCOPE).unwrap_err().code(), code);
                assert_eq!(store.verify_incarnation(SCOPE, "live", "live").unwrap_err().code(), code);
                assert_eq!(file_bytes(&path), bytes);
            }
        }

        fn cursor_of(path: &Path) -> Option<String> {
            raw_read_connection(path)
                .query_row(
                    "SELECT cursor FROM partition_state WHERE state_id = 1",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
                .expect("the fixture cursor is readable")
        }

        /// A partition a claim already created, as `advance_cursor` requires.
        fn claimed(temp: &TempDir) -> (WorkspaceIntelligenceCognitionStore, PathBuf) {
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(temp));
            store
                .advance_incarnation(SCOPE)
                .expect("a claim creates the fixture partition");
            let path = record_path_for(&store, SCOPE);
            (store, path)
        }

        #[test]
        fn advance_cursor_from_null_writes_only_the_cursor() {
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            let before = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(before.cursor, None);

            let advance = store.advance_cursor(SCOPE, None, "m-1").unwrap();

            assert_eq!(advance.previous, None);
            assert_eq!(advance.written, "m-1");
            assert_eq!(cursor_of(&path).as_deref(), Some("m-1"));
            let after = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(after.cursor.as_deref(), Some("m-1"));
            assert_eq!(after.incarnation_token, before.incarnation_token);
            let db = raw_read_connection(&path);
            assert_eq!(user_version_of(&db), COGNITION_SCHEMA_VERSION, "the schema version does not move");
            assert_eq!(partition_row_count(&db), 1);
            assert_eq!(
                column_names(&db, "partition_state"),
                ["state_id", "partition_key", "cursor", "incarnation_token"],
                "no column is added or removed"
            );
        }

        #[test]
        fn advance_cursor_requires_the_exact_stored_text() {
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            store.advance_cursor(SCOPE, None, "x").unwrap();

            let advance = store.advance_cursor(SCOPE, Some("x"), "y").unwrap();

            assert_eq!(advance.previous.as_deref(), Some("x"));
            assert_eq!(advance.written, "y");
            assert_eq!(cursor_of(&path).as_deref(), Some("y"));
        }

        #[test]
        fn advance_cursor_cas_mismatch_writes_nothing() {
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            // Stored NULL accepts no text expectation, including the empty string.
            let bytes = file_bytes(&path);
            for expected in [Some("x"), Some("")] {
                let error = store.advance_cursor(SCOPE, expected, "next").unwrap_err();
                assert_eq!(error.code(), "cursor_conflict", "{expected:?}");
                assert_eq!(file_bytes(&path), bytes, "{expected:?}");
            }
            store.advance_cursor(SCOPE, None, " x ").unwrap();
            // Stored " x ": no trim, no case folding, no parsing.
            let bytes = file_bytes(&path);
            for expected in [None, Some("x"), Some("X"), Some(" x"), Some("x ")] {
                let error = store.advance_cursor(SCOPE, expected, "next").unwrap_err();
                assert_eq!(error.code(), "cursor_conflict", "{expected:?}");
                assert_eq!(file_bytes(&path), bytes, "{expected:?}");
            }
            assert_eq!(cursor_of(&path).as_deref(), Some(" x "));
        }

        #[test]
        fn advance_cursor_requires_an_existing_partition() {
            // No record at all: this operation never creates the root or the record.
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            let error = store.advance_cursor(SCOPE, None, "m-1").unwrap_err();
            assert_eq!(error.code(), "cursor_partition_unavailable");
            assert!(!store_root(&temp).exists(), "no root is created");

            // An empty version-0 database is not adopted either, and keeps its own code
            // rather than the token path's `uninitialized_database`.
            let temp = TempDir::new().unwrap();
            let root = store_root(&temp);
            fs::create_dir_all(&root).unwrap();
            let path = root.join(format!("{}.sqlite", scope_digest(SCOPE).unwrap()));
            drop(raw_write_connection(&path));
            let store = WorkspaceIntelligenceCognitionStore::new(root);
            let error = store.advance_cursor(SCOPE, None, "m-1").unwrap_err();
            assert_eq!(error.code(), "cursor_partition_unavailable");
            assert!(file_bytes(&path).is_empty(), "the empty fixture stays empty");

            // An unsupported version and a foreign partition key keep their existing codes.
            for (label, statement, code) in [
                ("version", "PRAGMA user_version=3", "cursor_partition_unavailable"),
                ("foreign-key", "UPDATE partition_state SET partition_key='other'", "partition_scope_mismatch"),
            ] {
                let temp = TempDir::new().unwrap();
                let (store, path) = claimed(&temp);
                raw_write_connection(&path).execute_batch(statement).unwrap();
                let bytes = file_bytes(&path);
                let error = store.advance_cursor(SCOPE, None, "m-1").unwrap_err();
                assert_eq!(error.code(), code, "{label}");
                assert_eq!(file_bytes(&path), bytes, "{label}");
            }

            // Bytes that are not a database are corrupt, never reset.
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            fs::write(&path, b"not a SQLite database").unwrap();
            let bytes = file_bytes(&path);
            let error = store.advance_cursor(SCOPE, None, "m-1").unwrap_err();
            assert_eq!(error.code(), "corrupt_database");
            assert_eq!(file_bytes(&path), bytes);
        }

        #[test]
        fn a_failed_cursor_advance_rolls_back() {
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            let mut failing = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            failing.cursor_failpoint = true;
            let bytes = file_bytes(&path);

            let error = failing.advance_cursor(SCOPE, None, "m-1").unwrap_err();

            assert!(matches!(error, WorkspaceIntelligenceCognitionError::Io(_)), "{error}");
            assert_eq!(error.code(), "io");
            assert_eq!(cursor_of(&path), None, "the written row was rolled back");
            assert_eq!(file_bytes(&path), bytes, "the file bytes are unchanged");
            // The same store without the failpoint still advances, so the fixture proves
            // the rollback rather than a broken record.
            assert_eq!(store.advance_cursor(SCOPE, None, "m-1").unwrap().written, "m-1");
        }

        #[test]
        fn cursor_and_incarnation_advances_are_independent() {
            let temp = TempDir::new().unwrap();
            let (store, path) = claimed(&temp);
            store.advance_cursor(SCOPE, None, "m-1").unwrap();
            let token_before = store.read(SCOPE).unwrap().unwrap().incarnation_token;

            let advance = store.advance_incarnation(SCOPE).unwrap();

            assert_eq!(advance.previous_token, token_before);
            let state = store.read(SCOPE).unwrap().unwrap();
            assert_eq!(state.cursor.as_deref(), Some("m-1"), "the cursor survives a tenure advance");
            assert_eq!(state.incarnation_token, Some(advance.token));
            assert_eq!(cursor_of(&path).as_deref(), Some("m-1"));
        }

        #[test]
        fn claim_operations_accept_a_v2_partition() {
            let temp = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            assert!(store.initialize(SCOPE).unwrap().is_initialized());

            let cursor = store.advance_cursor(SCOPE, None, "x").unwrap();
            assert_eq!(cursor.written, "x");

            let token = store.advance_incarnation(SCOPE).unwrap();
            assert!(!token.token.is_empty());

            let verified = store.verify_incarnation(SCOPE, &token.token, &token.token).unwrap();
            assert!(matches!(verified, CognitionInitialization::Existing(_)));
            assert_eq!(
                user_version_of(&raw_read_connection(&record_path_for(&store, SCOPE))),
                COGNITION_SCHEMA_VERSION
            );
        }

        #[test]
        fn claim_operations_still_accept_a_v1_record_without_upgrading_it() {
            let temp = TempDir::new().unwrap();
            let root = store_root(&temp);
            fs::create_dir_all(&root).unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(root);
            let path = record_path_for(&store, SCOPE);
            write_v1_record(&path, &scope_digest(SCOPE).unwrap(), "abc", "tok");

            assert_eq!(
                store.advance_cursor(SCOPE, Some("abc"), "xyz").unwrap().written,
                "xyz"
            );
            let advance = store.advance_incarnation(SCOPE).unwrap();
            assert_eq!(advance.previous_token.as_deref(), Some("tok"));
            let verified = store
                .verify_incarnation(SCOPE, &advance.token, &advance.token)
                .unwrap();
            assert!(matches!(verified, CognitionInitialization::Existing(_)));

            let connection = raw_read_connection(&path);
            assert_eq!(
                user_version_of(&connection),
                1,
                "a claim operation never upgrades a v1 record"
            );
            assert!(!table_names(&connection).contains(&COGNITION_ENTRIES_TABLE.to_string()));
        }
    }

    #[cfg(feature = "workspace-intelligence-commit")]
    mod entries {
        use super::*;

        fn new_entry(entry_id: &str, kind: &str, statement: &str) -> NewCognitionEntry {
            NewCognitionEntry {
                entry_id: entry_id.to_string(),
                kind: kind.to_string(),
                category: "fact".to_string(),
                authority: "human".to_string(),
                state: "active".to_string(),
                statement: statement.to_string(),
                workspace_partition: scope_digest(SCOPE).expect("scope digest"),
                visibility: "partition".to_string(),
                shared_scope: None,
                shared_authorization: None,
                source_owner: "human:fixture".to_string(),
                source_resource: None,
                source_revision: None,
                observed_at_unix_ms: 1_700_000_000_000,
                valid_until_unix_ms: None,
                confidence: None,
                revision: 1,
                epoch: 1,
                supersedes: None,
                invalidated_reason: None,
            }
        }

        fn hex_digest(text: &str) -> String {
            format!("{:x}", Sha256::digest(text.as_bytes()))
        }

        fn stored_cursor(path: &Path) -> Option<String> {
            raw_read_connection(path)
                .query_row(
                    "SELECT cursor FROM partition_state WHERE state_id = 1",
                    [],
                    |row| row.get::<_, Option<String>>(0),
                )
                .expect("the fixture cursor is readable")
        }

        /// A v2 partition a commit can target.
        fn v2_partition(temp: &TempDir) -> (WorkspaceIntelligenceCognitionStore, PathBuf) {
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(temp));
            store.initialize(SCOPE).expect("the fixture partition is created");
            let path = record_path_for(&store, SCOPE);
            (store, path)
        }

        #[test]
        fn commit_inserts_one_entry_with_a_derived_digest() {
            let temp = TempDir::new().unwrap();
            let (store, _path) = v2_partition(&temp);

            let commit = store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[new_entry("e-1", "knowledge", "the build is green")],
                    &[],
                )
                .unwrap();

            assert_eq!(commit.committed_entry_ids, vec!["e-1".to_string()]);
            assert!(commit.retired_entry_ids.is_empty());
            assert_eq!(commit.cursor, None);
            let stored = store.read_entries(SCOPE).unwrap().expect("the record exists");
            assert_eq!(stored.len(), 1);
            assert_eq!(stored[0].entry_id, "e-1");
            assert_eq!(stored[0].revision, 1);
            assert_eq!(stored[0].workspace_partition, scope_digest(SCOPE).unwrap());
            assert_eq!(stored[0].content_digest, hex_digest("the build is green"));
        }

        #[test]
        fn a_duplicate_entry_id_aborts_the_whole_commit() {
            let temp = TempDir::new().unwrap();
            let (store, _path) = v2_partition(&temp);
            store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[new_entry("e-1", "knowledge", "first")],
                    &[],
                )
                .unwrap();

            let error = store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[
                        new_entry("e-1", "knowledge", "second"),
                        new_entry("e-2", "knowledge", "third"),
                    ],
                    &[],
                )
                .unwrap_err();

            assert_eq!(error.code(), "entry_duplicate");
            assert!(
                matches!(&error, WorkspaceIntelligenceCognitionError::EntryDuplicate { entry_id } if entry_id.as_str() == "e-1"),
                "unexpected error: {error}"
            );
            let stored = store.read_entries(SCOPE).unwrap().unwrap();
            assert_eq!(stored.len(), 1, "the duplicate aborts the whole commit");
            assert_eq!(stored[0].statement, "first");
        }

        #[test]
        fn a_cursor_mismatch_aborts_the_commit_before_any_content_write() {
            let temp = TempDir::new().unwrap();
            let (store, path) = v2_partition(&temp);

            let error = store
                .commit_entries_with_cursor(
                    SCOPE,
                    Some("wrong"),
                    Some("c1"),
                    &[new_entry("e-1", "knowledge", "text")],
                    &[],
                )
                .unwrap_err();

            assert_eq!(error.code(), "cursor_conflict");
            assert_eq!(
                store.read_entries(SCOPE).unwrap().unwrap().len(),
                0,
                "no entry is written"
            );
            assert_eq!(stored_cursor(&path), None, "no cursor is written");
        }

        #[test]
        fn a_revision_mismatch_aborts_the_whole_commit() {
            let temp = TempDir::new().unwrap();
            let (store, path) = v2_partition(&temp);
            store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[new_entry("e-1", "knowledge", "first")],
                    &[],
                )
                .unwrap();

            let retirement = EntryRetirement {
                entry_id: "e-1".to_string(),
                expected_revision: 2,
                new_state: "superseded".to_string(),
                reason: None,
            };
            let error = store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    Some("c1"),
                    &[new_entry("e-2", "knowledge", "second")],
                    &[retirement],
                )
                .unwrap_err();

            assert_eq!(error.code(), "entry_revision_conflict");
            assert!(
                matches!(&error, WorkspaceIntelligenceCognitionError::EntryRevisionConflict { entry_id } if entry_id.as_str() == "e-1"),
                "unexpected error: {error}"
            );
            let stored = store.read_entries(SCOPE).unwrap().unwrap();
            assert_eq!(stored.len(), 1, "the new entry is not written");
            assert_eq!(stored[0].state, "active", "the retirement is not applied");
            assert_eq!(stored[0].revision, 1, "the revision does not move");
            assert_eq!(stored_cursor(&path), None, "the cursor write is rolled back");
        }

        #[test]
        fn a_retirement_bumps_the_revision_and_stores_the_reason() {
            let temp = TempDir::new().unwrap();
            let (store, _path) = v2_partition(&temp);
            store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[new_entry("e-1", "knowledge", "first")],
                    &[],
                )
                .unwrap();

            let commit = store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[],
                    &[EntryRetirement {
                        entry_id: "e-1".to_string(),
                        expected_revision: 1,
                        new_state: "superseded".to_string(),
                        reason: Some("replaced by a newer decision".to_string()),
                    }],
                )
                .unwrap();

            assert_eq!(commit.retired_entry_ids, vec!["e-1".to_string()]);
            assert!(commit.committed_entry_ids.is_empty());
            let stored = store.read_entries(SCOPE).unwrap().unwrap();
            assert_eq!(stored[0].state, "superseded");
            assert_eq!(stored[0].revision, 2);
            assert_eq!(
                stored[0].invalidated_reason.as_deref(),
                Some("replaced by a newer decision")
            );
            assert_eq!(stored[0].statement, "first", "the statement is untouched");
        }

        #[test]
        fn a_failed_commit_rolls_back_entries_and_the_cursor_together() {
            let temp = TempDir::new().unwrap();
            let (store, path) = v2_partition(&temp);
            let mut failing = WorkspaceIntelligenceCognitionStore::new(store_root(&temp));
            failing.commit_failpoint = true;

            let error = failing
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    Some("c1"),
                    &[new_entry("e-1", "knowledge", "text")],
                    &[],
                )
                .unwrap_err();

            assert_eq!(error.code(), "io");
            assert_eq!(
                store.read_entries(SCOPE).unwrap().unwrap().len(),
                0,
                "the entry is rolled back"
            );
            assert_eq!(stored_cursor(&path), None, "the cursor is rolled back");

            // The same store without the failpoint still commits, so the fixture
            // proves the rollback rather than a broken record.
            let commit = store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    Some("c1"),
                    &[new_entry("e-1", "knowledge", "text")],
                    &[],
                )
                .unwrap();
            assert_eq!(commit.cursor.expect("the cursor was written").written, "c1");
            assert_eq!(stored_cursor(&path).as_deref(), Some("c1"));
        }

        #[test]
        fn stored_entries_are_read_in_kind_then_entry_id_order() {
            let temp = TempDir::new().unwrap();
            let (store, _path) = v2_partition(&temp);

            store
                .commit_entries_with_cursor(
                    SCOPE,
                    None,
                    None,
                    &[
                        new_entry("e-2", "knowledge", "knowledge two"),
                        new_entry("e-3", "action", "action three"),
                        new_entry("e-1", "knowledge", "knowledge one"),
                    ],
                    &[],
                )
                .unwrap();

            let order = store
                .read_entries(SCOPE)
                .unwrap()
                .unwrap()
                .into_iter()
                .map(|entry| (entry.kind, entry.entry_id))
                .collect::<Vec<_>>();
            assert_eq!(
                order,
                vec![
                    ("action".to_string(), "e-3".to_string()),
                    ("knowledge".to_string(), "e-1".to_string()),
                    ("knowledge".to_string(), "e-2".to_string()),
                ]
            );
        }

        #[test]
        fn a_commit_against_a_v1_record_is_refused_without_upgrading_it() {
            let temp = TempDir::new().unwrap();
            let root = store_root(&temp);
            fs::create_dir_all(&root).unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(root);
            let path = record_path_for(&store, SCOPE);
            write_v1_record(&path, &scope_digest(SCOPE).unwrap(), "abc", "tok");

            let error = store
                .commit_entries_with_cursor(
                    SCOPE,
                    Some("abc"),
                    None,
                    &[new_entry("e-1", "knowledge", "text")],
                    &[],
                )
                .unwrap_err();

            assert_eq!(error.code(), "cursor_partition_unavailable");
            let connection = raw_read_connection(&path);
            assert_eq!(
                user_version_of(&connection),
                1,
                "a refused commit never upgrades the record"
            );
            assert!(!table_names(&connection).contains(&COGNITION_ENTRIES_TABLE.to_string()));

            // A missing record is refused too and never created.
            let missing = TempDir::new().unwrap();
            let store = WorkspaceIntelligenceCognitionStore::new(store_root(&missing));
            assert_eq!(
                store
                    .commit_entries_with_cursor(SCOPE, None, None, &[], &[])
                    .unwrap_err()
                    .code(),
                "cursor_partition_unavailable"
            );
            assert!(!store_root(&missing).exists(), "no root is created");
        }
    }
}
