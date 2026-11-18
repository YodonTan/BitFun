//! Durable workspace intelligence control records.
//!
//! This module owns exactly one authoritative sidecar file per caller-provided
//! opaque scope. A record holds the control switch, the workspace model
//! reference, one opaque caller-owned policy payload and one monotonic control
//! generation. It never derives the workspace tier, interprets policy, resolves
//! a model, or decides which scope a workspace belongs to.
//!
//! # Storage contract
//!
//! - The host injects a host-local storage root and the opaque scope. The scope
//!   is the stable workspace plus its owning host/execution domain, composed by
//!   the caller; this module only hashes it into a file name and never rebuilds
//!   workspace identity, project ids or grant keys. The scope itself is never
//!   stored in the record, so no path or identity leaks into the payload. The
//!   root is local storage of the host that owns the record, not a remote
//!   workspace path, and this module performs no remote execution.
//! - Reads never create the root, the record or a lock file.
//! - Mutations reload the document under the JSON cross-process OS lock, compare
//!   the expected control generation, and replace the file strictly and
//!   atomically. A rejected, failed or identical mutation never rewrites the
//!   document and never advances the generation. That lock serializes writers of
//!   this record that use it; it makes no claim of coordination with an external
//!   writer that ignores it.
//! - Fields this module does not model are preserved with JSON `Value`
//!   semantics. A patch modifies only the fields it names; every other field,
//!   including its nested content, keeps its semantics across a successful
//!   rewrite, which may still normalize whitespace and key order. Rejections and
//!   no-ops leave the stored bytes unchanged.
//! - `policy` is one opaque whole value owned by the caller. `Set` replaces the
//!   entire value and `Clear` removes the key; the store never merges inside it
//!   and never interprets it. A policy owner that must keep unknown payload
//!   content merges it itself into a fresh raw read and then commits with
//!   `Exactly(generation)`. There is no merge framework here.
//! - Corrupt JSON, an unsupported schema version and structurally invalid fields
//!   are explicit errors. Stored bytes are never reset, deleted or replaced by a
//!   fallback.
//!
//! [`WorkspaceIntelligenceStore::read_payload`] is a narrow diagnostics channel
//! for exactly that case: it returns the stored payload without validating it.
//!
//! # What a read observes
//!
//! A lock-free read reports the file it observed during that call, and the
//! underlying JSON owner reports a target that is momentarily unavailable in two
//! different ways: it returns `Ok(None)` when its existence probe already sees no
//! file, and an explicit read error when that probe succeeded but the actual read
//! did not. Both are *observations*, not facts about authority:
//!
//! - `Ok(None)` means this call did not observe a record. It is not proof that no
//!   record ever existed, that an existing authoritative record was deleted or
//!   reset, or that a switch was accepted as off. The initial missing case is the
//!   same observation.
//! - A read error is likewise not proof of damage to a stored record.
//!
//! Neither observation may be turned into a control change. The caller decides
//! from its own startup, re-read or degradation policy whether to retry, treat the
//! record as unreadable, or derive the default; deriving `Off` from a genuinely
//! absent record is the product policy of the owning caller, not a decision of
//! this store. This module adds no retry loop and no product state.
//!
//! # Control generation
//!
//! `control_generation` is the single generation truth of a control record; a
//! later control owner reuses this field instead of introducing a second
//! revision:
//!
//! - a stored record without the field predates it and reads as `0`;
//! - an explicitly stored `0` is invalid, because it cannot be told apart from
//!   that legacy absence;
//! - a newly created record starts at `1`;
//! - every applied control change advances it by exactly one, and a record at
//!   `u64::MAX` cannot advance at all;
//! - a no-op and a rejection leave it unchanged.
//!
//! # Accepted schema versions
//!
//! The caller injects the accepted version list and must keep it equal to the
//! versions its own projection accepts (the workspace intelligence control-record
//! read), so the store can never publish a shape the projection rejects. A host
//! integration passes exactly the one version it currently understands.
//! Stamping a new record with the highest accepted version is an explicit caller
//! decision about the shape it writes; it is not the store understanding a newer
//! shape, because every read and write still rejects a version outside the
//! injected list.
//!
//! # Durability boundary
//!
//! Strict replacement publishes a complete document and never falls back to
//! deleting the target and renaming into place, which is the guarantee this
//! module's tests exercise: a successful mutation leaves a complete previous or
//! complete new document, never a partial one. Concurrent reads are a separate
//! matter and are described under "What a read observes"; the transient
//! observation seen while another writer replaces the target is a possible
//! explanation observed in testing, not a proven platform root cause. This is not
//! a power-loss `fsync` contract either: the module adds no fsync, so it makes no
//! claim about data that never reached the device.
//!
//! # Cancellation
//!
//! Once accepted, a mutation runs on an owned task: the cross-process lock guard
//! and the strict atomic replacement live inside that task, so dropping the
//! caller's future cannot release the lock while the replacement is still
//! running. The caller loses the result, not the transaction, so an accepted
//! mutation with an unknown return value may still have been committed.

use crate::json_store::{JsonFileStore, JsonFileStoreError};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Structurally invalid parts of a stored control record.
///
/// Codes are stable and never echo a payload value, so they are safe for logs
/// and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRecordFault {
    /// The document root is not a JSON object.
    PayloadNotObject,
    /// `schema_version` is present but is not an unsigned 32-bit integer.
    SchemaVersionMalformed,
    /// `control_generation` is present but is not an unsigned 64-bit integer.
    ControlGenerationMalformed,
    /// `control_generation` is present and zero; zero is reserved for records
    /// that predate the field.
    ControlGenerationZero,
    /// `enabled` is present but is not a boolean.
    EnabledMalformed,
    /// `model_ref` is present but is not a non-blank string.
    ModelRefMalformed,
}

impl ControlRecordFault {
    /// Stable machine-readable code.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayloadNotObject => "payload_not_object",
            Self::SchemaVersionMalformed => "schema_version_malformed",
            Self::ControlGenerationMalformed => "control_generation_malformed",
            Self::ControlGenerationZero => "control_generation_zero",
            Self::EnabledMalformed => "enabled_malformed",
            Self::ModelRefMalformed => "model_ref_malformed",
        }
    }
}

impl fmt::Display for ControlRecordFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Generation the caller expects to compare and swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlGenerationExpectation {
    /// The caller expects to create the record and has not observed one.
    ///
    /// This is a creation intent, not a claim that a record never existed: a
    /// caller that finds no record cannot tell a first write from a record it
    /// failed to observe, so the store only creates under the transaction lock.
    Absent,
    /// The caller read this control generation and expects it to be current.
    Exactly(u64),
}

impl fmt::Display for ControlGenerationExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Not "absent": a single observation only failed to find a record, and
            // this text is also used for a caller's own pre-write expectation.
            Self::Absent => formatter.write_str("a record not yet observed"),
            Self::Exactly(generation) => write!(formatter, "control generation {generation}"),
        }
    }
}

/// Explicit update of one control field.
///
/// `Clear` is distinct from `Set` with a default value: an absent switch reads
/// as off, and an absent reference or policy stays absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFieldUpdate<T> {
    /// Leave the stored value untouched.
    Keep,
    /// Store the supplied value.
    Set(T),
    /// Remove the stored value.
    Clear,
}

impl<T> Default for ControlFieldUpdate<T> {
    fn default() -> Self {
        Self::Keep
    }
}

/// Fields one compare-and-swap mutation may change.
///
/// The patch never carries the schema version: upgrading a record shape is a
/// migration, not a control change. Only the named fields are touched, so every
/// other field, including its nested content, keeps its semantics.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WorkspaceIntelligenceControlPatch {
    /// Control switch.
    pub enabled: ControlFieldUpdate<bool>,
    /// Workspace model reference, stored verbatim when non-blank.
    pub model_ref: ControlFieldUpdate<String>,
    /// Opaque caller-owned policy payload.
    ///
    /// This is a whole value, not a merge: `Set` replaces whatever is stored and
    /// `Clear` removes the key. The store never inspects or merges inside it, so
    /// a policy owner that must retain unknown payload content merges it into a
    /// fresh raw read and only then commits here with `Exactly(generation)`.
    pub policy: ControlFieldUpdate<Value>,
}

/// Decoded authoritative control record.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkspaceIntelligenceControlRecord {
    /// Declared record schema version. `None` is a legacy record that never
    /// declared one; an existing record is never silently upgraded.
    pub schema_version: Option<u32>,
    /// Monotonic control generation. `0` means the stored record predates the
    /// field; a new record starts at `1`, and a stored `0` is invalid.
    pub control_generation: u64,
    /// Control switch. `None` means the field is absent, which reads as off.
    pub enabled: Option<bool>,
    /// Workspace model reference, kept verbatim and never resolved here.
    pub model_ref: Option<String>,
    /// Opaque caller-owned policy payload.
    pub policy: Option<Value>,
    /// The complete decoded document, including fields this module does not
    /// model. JSON `Value` semantics, not stored bytes.
    pub raw: Value,
}

/// Result of an accepted compare-and-swap mutation.
#[derive(Debug, Clone, PartialEq)]
pub enum WorkspaceIntelligenceControlWrite {
    /// The mutation changed the document; the strict atomic replacement
    /// published the complete new document and the generation advanced by one.
    Applied(WorkspaceIntelligenceControlRecord),
    /// The mutation matched the stored values; the document was not rewritten
    /// and the control generation did not advance.
    Unchanged(WorkspaceIntelligenceControlRecord),
}

impl WorkspaceIntelligenceControlWrite {
    /// The stored record after the mutation.
    pub fn record(&self) -> &WorkspaceIntelligenceControlRecord {
        match self {
            Self::Applied(record) | Self::Unchanged(record) => record,
        }
    }

    /// True when the document was rewritten.
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied(_))
    }
}

/// Failures of the authoritative control-record store.
#[derive(Debug, thiserror::Error)]
pub enum WorkspaceIntelligenceStoreError {
    #[error("Workspace intelligence scope must be a non-empty opaque identifier")]
    EmptyScope,

    #[error("Workspace intelligence record {path} is not valid JSON: {source}")]
    CorruptRecord {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("Workspace intelligence record {path} is invalid: {fault}")]
    InvalidRecord {
        path: PathBuf,
        fault: ControlRecordFault,
    },

    #[error("Workspace intelligence record {path} uses unsupported schema version {version}")]
    UnsupportedSchemaVersion { path: PathBuf, version: u32 },

    #[error(
        "Workspace intelligence control generation mismatch: expected {expected}, observed {actual}"
    )]
    ControlGenerationConflict {
        expected: ControlGenerationExpectation,
        actual: ControlGenerationExpectation,
    },

    #[error("Workspace intelligence control generation cannot advance past u64::MAX in {path}")]
    ControlGenerationOverflow { path: PathBuf },

    #[error("Workspace model reference must not be empty or blank")]
    BlankModelReference,

    #[error("Workspace intelligence record storage failed: {0}")]
    Storage(#[from] JsonFileStoreError),

    #[error("Workspace intelligence control transaction task failed: {0}")]
    Transaction(#[from] tokio::task::JoinError),
}

impl WorkspaceIntelligenceStoreError {
    /// True when another writer changed the record after the caller read it.
    ///
    /// A conflict is never a data error: the stored document is intact.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::ControlGenerationConflict { .. })
    }
}

/// Authoritative per-scope control records over a host-injected, host-local
/// sidecar root.
#[derive(Debug, Clone)]
pub struct WorkspaceIntelligenceStore {
    root: PathBuf,
    accepted_schema_versions: Vec<u32>,
}

impl WorkspaceIntelligenceStore {
    /// Builds a store over a host-injected sidecar root.
    ///
    /// `accepted_schema_versions` lists the record schema versions this host
    /// understands. The store refuses to read or mutate any other version, and
    /// stamps a new record with the newest accepted version. An empty list means
    /// the host understands unversioned legacy records only, so new records also
    /// stay unversioned. The injected list must match the versions the caller's
    /// own projection accepts; the store never guesses.
    ///
    /// Construction performs no IO.
    pub fn new(root: PathBuf, accepted_schema_versions: Vec<u32>) -> Self {
        Self {
            root,
            accepted_schema_versions,
        }
    }

    /// Hashes the opaque scope into a file name inside the injected root.
    ///
    /// The digest is the only untrusted-input-derived path component, so a scope
    /// can never introduce a separator, parent segment or drive prefix.
    fn record_path(&self, scope: &str) -> Result<PathBuf, WorkspaceIntelligenceStoreError> {
        if scope.is_empty() {
            return Err(WorkspaceIntelligenceStoreError::EmptyScope);
        }
        let digest = Sha256::digest(scope.as_bytes());
        Ok(self.root.join(format!("{digest:x}.json")))
    }

    #[cfg(feature = "workspace-intelligence-commit")]
    pub(crate) fn control_root(&self) -> &Path {
        &self.root
    }

    /// Hands one writer guard and its fresh observation to the governed owner commit.
    /// This adds no second write path into the control record.
    #[cfg(feature = "workspace-intelligence-commit")]
    pub(crate) async fn lock_and_read_authority(
        &self,
        scope: &str,
    ) -> Result<
        (crate::json_store::JsonFileCrossProcessLock, Option<WorkspaceIntelligenceControlRecord>),
        WorkspaceIntelligenceStoreError,
    > {
        let path = self.record_path(scope)?;
        let guard = JsonFileStore.acquire_cross_process_lock(&path).await?;
        let record = match self.read_document(&path).await? {
            Some(document) => Some(self.decode(&path, document)?),
            None => None,
        };
        Ok((guard, record))
    }

    fn newest_accepted_schema_version(&self) -> Option<u32> {
        self.accepted_schema_versions.iter().copied().max()
    }

    /// Reads the authoritative record for an opaque scope.
    ///
    /// The read is lock-free: a strict replacement never leaves a partially
    /// written target, so a reader never decodes a truncated document. It never
    /// creates the root directory, the record or a lock file.
    ///
    /// `Ok(None)` means this call did not observe a record, which is the same
    /// observation as a record that was never written. It is not proof that the
    /// record is absent, that an existing authoritative record was deleted, or
    /// that the switch is off; a concurrent replacement can also make one call
    /// miss the target. A corrupt, unsupported or structurally invalid record is
    /// an explicit error, and its bytes stay untouched. Deciding what either
    /// observation means for the product belongs to the caller.
    ///
    /// The document is read exactly once, so `record.raw` and the decoded fields
    /// describe one snapshot. A separate [`Self::read_payload`] call is a
    /// different snapshot and must not be combined with this record's generation
    /// when committing.
    pub async fn read(
        &self,
        scope: &str,
    ) -> Result<Option<WorkspaceIntelligenceControlRecord>, WorkspaceIntelligenceStoreError> {
        let path = self.record_path(scope)?;
        match self.read_document(&path).await? {
            Some(document) => self.decode(&path, document).map(Some),
            None => Ok(None),
        }
    }

    /// Reads the stored payload without validating it.
    ///
    /// This is a diagnostics channel, not an authority: it exists so a caller can
    /// report `preserved` content for a record whose schema version or field
    /// shape it does not accept. It performs the same single JSON read as
    /// [`Self::read`] and applies no schema, generation, switch or reference
    /// validation, so it never creates the root directory, a record or a lock
    /// file. Corrupt JSON and read errors stay explicit errors.
    ///
    /// Like [`Self::read`], `Ok(None)` only means this call did not observe the
    /// file, and an error is not proof that a stored record was damaged.
    ///
    /// A returned payload proves nothing about validity or activatability: the
    /// record may be unparsable to [`Self::read`] or unusable by the tier
    /// derivation. Activation must pass authority validation as well. There is
    /// deliberately no raw write path; every mutation validates and fails closed.
    ///
    /// This is an independent snapshot. A legitimate typed read's `raw` comes
    /// from that same read, so content taken from another `read_payload` call
    /// must not be merged with the typed record's generation and committed: the
    /// generation would then describe a different snapshot than the payload. A
    /// raw payload obtained after the typed read failed is diagnostics only.
    pub async fn read_payload(
        &self,
        scope: &str,
    ) -> Result<Option<Value>, WorkspaceIntelligenceStoreError> {
        let path = self.record_path(scope)?;
        self.read_document(&path).await
    }

    /// Compare-and-swaps the record for an opaque scope.
    ///
    /// The transaction reloads the current document under the cross-process OS
    /// lock, so a stale snapshot can never overwrite a newer record, and then
    /// replaces the file strictly and atomically. `Absent` creates a record at
    /// generation `1`; `Exactly(0)` upgrades a legacy record that predates the
    /// generation field. When the patch matches the stored values the document is
    /// left byte-identical and the generation does not advance.
    ///
    /// A rejection or an identical mutation is decided from one lock-free read,
    /// which is also their linearization point, so neither creates the root
    /// directory or a lock file. An observation that cannot decide defers to the
    /// locked reload. The generation is compared before the values, so a stale
    /// expectation is always reported as a conflict and never as an unchanged
    /// no-op. The transaction lock serializes the writers of this record that use
    /// it; it does not coordinate an external writer that ignores it. After
    /// acceptance the mutation runs to completion on an owned task, which means an
    /// accepted call whose result the caller never observes may still have been
    /// committed.
    pub async fn update(
        &self,
        scope: &str,
        expectation: ControlGenerationExpectation,
        patch: WorkspaceIntelligenceControlPatch,
    ) -> Result<WorkspaceIntelligenceControlWrite, WorkspaceIntelligenceStoreError> {
        // Reject invalid write input before touching the root or the lock file.
        validate_patch(&patch)?;
        // Once accepted, finish the transaction even if the caller stops awaiting
        // it. The owned task holds the JSON transaction lock until every
        // underlying file write and the strict replacement have completed.
        let store = self.clone();
        let scope = scope.to_owned();
        tokio::spawn(async move { store.update_owned(&scope, expectation, patch).await }).await?
    }

    async fn update_owned(
        &self,
        scope: &str,
        expectation: ControlGenerationExpectation,
        patch: WorkspaceIntelligenceControlPatch,
    ) -> Result<WorkspaceIntelligenceControlWrite, WorkspaceIntelligenceStoreError> {
        let path = self.record_path(scope)?;
        // Rejections and no-ops are decided from a lock-free read, so they never
        // create the root directory or a lock file and never rewrite the
        // document. That read is the linearization point of an `Unchanged`
        // result; it is never authoritative for an applied write, which reloads
        // the document under the transaction lock below.
        if let Some(outcome) = self.precheck(&path, expectation, &patch).await? {
            return Ok(outcome);
        }
        let _transaction = JsonFileStore.acquire_cross_process_lock(&path).await?;
        let current = self.read_document(&path).await?;

        match expectation {
            ControlGenerationExpectation::Absent => {
                if let Some(document) = current {
                    let record = self.decode(&path, document)?;
                    return Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                        expected: ControlGenerationExpectation::Absent,
                        actual: ControlGenerationExpectation::Exactly(record.control_generation),
                    });
                }
                let mut document = Map::new();
                if let Some(version) = self.newest_accepted_schema_version() {
                    document.insert("schema_version".to_string(), json!(version));
                }
                document.insert("control_generation".to_string(), json!(1));
                apply_patch(&mut document, &patch)?;
                let document = Value::Object(document);
                JsonFileStore
                    .write_atomic_strict(&path, &document)
                    .await?;
                let record = self.decode(&path, document)?;
                Ok(WorkspaceIntelligenceControlWrite::Applied(record))
            }
            ControlGenerationExpectation::Exactly(expected) => {
                let Some(document) = current else {
                    return Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                        expected: ControlGenerationExpectation::Exactly(expected),
                        actual: ControlGenerationExpectation::Absent,
                    });
                };
                let record = self.decode(&path, document)?;
                let actual = record.control_generation;
                if actual != expected {
                    return Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                        expected: ControlGenerationExpectation::Exactly(expected),
                        actual: ControlGenerationExpectation::Exactly(actual),
                    });
                }

                let mut document = match &record.raw {
                    Value::Object(document) => document.clone(),
                    // Decoding already rejected a non-object root.
                    _ => {
                        return Err(WorkspaceIntelligenceStoreError::InvalidRecord {
                            path: path.clone(),
                            fault: ControlRecordFault::PayloadNotObject,
                        })
                    }
                };
                let previous = document.clone();
                apply_patch(&mut document, &patch)?;
                if document == previous {
                    return Ok(WorkspaceIntelligenceControlWrite::Unchanged(record));
                }

                let generation = actual.checked_add(1).ok_or_else(|| {
                    WorkspaceIntelligenceStoreError::ControlGenerationOverflow {
                        path: path.clone(),
                    }
                })?;
                document.insert("control_generation".to_string(), json!(generation));
                let document = Value::Object(document);
                JsonFileStore
                    .write_atomic_strict(&path, &document)
                    .await?;
                let record = self.decode(&path, document)?;
                Ok(WorkspaceIntelligenceControlWrite::Applied(record))
            }
        }
    }

    /// Reads the document once and hands the observation to [`Self::decide`].
    async fn precheck(
        &self,
        path: &Path,
        expectation: ControlGenerationExpectation,
        patch: &WorkspaceIntelligenceControlPatch,
    ) -> Result<Option<WorkspaceIntelligenceControlWrite>, WorkspaceIntelligenceStoreError> {
        let observed = self.read_document(path).await;
        self.decide(path, observed, expectation, patch)
    }

    /// Decides a rejection or a no-op from one lock-free observation, with no IO.
    ///
    /// `Ok(None)` from this method means the observation could not settle the
    /// call, so the transaction continues under the lock, which reloads the
    /// document and re-decides everything; this can never mask a stale
    /// compare-and-swap. Every rejection it does return is final: the patch, the
    /// expectation and a decoded document cannot become acceptable without the
    /// generation changing, and any accepted write bumps the generation.
    ///
    /// Failure to observe a file is not proof of absence, but it is still not a
    /// reason to write. A caller that expects a specific generation cannot be
    /// answered, so it receives a conflict and nothing is created or rewritten;
    /// `Absent` defers, because creating a record is a real write. The
    /// momentarily-unreadable observation is the same: it defers instead of
    /// deciding. Every other error is returned unchanged.
    fn decide(
        &self,
        path: &Path,
        observed: Result<Option<Value>, WorkspaceIntelligenceStoreError>,
        expectation: ControlGenerationExpectation,
        patch: &WorkspaceIntelligenceControlPatch,
    ) -> Result<Option<WorkspaceIntelligenceControlWrite>, WorkspaceIntelligenceStoreError> {
        let document = match observed {
            Ok(document) => document,
            // The target was momentarily unreadable. That is not evidence about
            // the record, so it cannot be turned into an absence decision.
            Err(error) if is_unreadable_observation(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(document) = document else {
            if let ControlGenerationExpectation::Exactly(expected) = expectation {
                return Err(
                    WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                        expected: ControlGenerationExpectation::Exactly(expected),
                        actual: ControlGenerationExpectation::Absent,
                    },
                );
            }
            // Creating the record is a real write and takes the lock.
            return Ok(None);
        };

        // Decoding is pure: an unreadable document is reported before any lock
        // file exists.
        let record = self.decode(path, document)?;
        if let ControlGenerationExpectation::Absent = expectation {
            return Err(
                WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                    expected: ControlGenerationExpectation::Absent,
                    actual: ControlGenerationExpectation::Exactly(record.control_generation),
                },
            );
        }
        if let ControlGenerationExpectation::Exactly(expected) = expectation {
            // The generation is compared before the no-op check, so a stale
            // caller can never be answered with `Unchanged`.
            if record.control_generation != expected {
                return Err(
                    WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                        expected: ControlGenerationExpectation::Exactly(expected),
                        actual: ControlGenerationExpectation::Exactly(record.control_generation),
                    },
                );
            }
        }

        let Value::Object(fields) = &record.raw else {
            return Ok(None);
        };
        let mut patched = fields.clone();
        let previous = patched.clone();
        apply_patch(&mut patched, patch)?;
        if patched == previous {
            return Ok(Some(WorkspaceIntelligenceControlWrite::Unchanged(record)));
        }
        Ok(None)
    }

    async fn read_document(
        &self,
        path: &Path,
    ) -> Result<Option<Value>, WorkspaceIntelligenceStoreError> {
        match JsonFileStore.read_optional::<Value>(path).await {
            Ok(document) => Ok(document),
            Err(JsonFileStoreError::Deserialize { path, source }) => {
                Err(WorkspaceIntelligenceStoreError::CorruptRecord { path, source })
            }
            Err(error) => Err(WorkspaceIntelligenceStoreError::Storage(error)),
        }
    }

    fn decode(
        &self,
        path: &Path,
        document: Value,
    ) -> Result<WorkspaceIntelligenceControlRecord, WorkspaceIntelligenceStoreError> {
        let invalid = |fault| WorkspaceIntelligenceStoreError::InvalidRecord {
            path: path.to_path_buf(),
            fault,
        };
        let Value::Object(fields) = &document else {
            return Err(invalid(ControlRecordFault::PayloadNotObject));
        };

        let schema_version = match fields.get("schema_version") {
            None => None,
            Some(value) => Some(
                value
                    .as_u64()
                    .and_then(|version| u32::try_from(version).ok())
                    .ok_or_else(|| invalid(ControlRecordFault::SchemaVersionMalformed))?,
            ),
        };
        if let Some(version) = schema_version {
            if !self.accepted_schema_versions.contains(&version) {
                return Err(
                    WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion {
                        path: path.to_path_buf(),
                        version,
                    },
                );
            }
        }

        let control_generation = match fields.get("control_generation") {
            None => 0,
            Some(value) => {
                let generation = value
                    .as_u64()
                    .ok_or_else(|| invalid(ControlRecordFault::ControlGenerationMalformed))?;
                if generation == 0 {
                    return Err(invalid(ControlRecordFault::ControlGenerationZero));
                }
                generation
            }
        };

        let enabled = match fields.get("enabled") {
            None => None,
            Some(Value::Bool(enabled)) => Some(*enabled),
            Some(_) => return Err(invalid(ControlRecordFault::EnabledMalformed)),
        };

        let model_ref = match fields.get("model_ref") {
            None => None,
            Some(Value::String(model_ref)) if !model_ref.trim().is_empty() => {
                Some(model_ref.clone())
            }
            Some(_) => return Err(invalid(ControlRecordFault::ModelRefMalformed)),
        };

        Ok(WorkspaceIntelligenceControlRecord {
            schema_version,
            control_generation,
            enabled,
            model_ref,
            policy: fields.get("policy").cloned(),
            raw: document,
        })
    }
}

/// True when an error says only that the target was unreadable at that instant.
///
/// The JSON owner reports a not-found *read* error for a target whose existence
/// probe already succeeded; that also happens while a replacement is in flight.
/// Nothing else is treated as undecidable, so a permission problem, a corrupt
/// document or an unsupported version always surfaces as its own error.
fn is_unreadable_observation(error: &WorkspaceIntelligenceStoreError) -> bool {
    match error {
        WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read { source, .. }) => {
            source.kind() == ErrorKind::NotFound
        }
        _ => false,
    }
}

/// Validates write input that would otherwise publish a record every reader has
/// to reject, before the transaction creates its root or lock file.
fn validate_patch(
    patch: &WorkspaceIntelligenceControlPatch,
) -> Result<(), WorkspaceIntelligenceStoreError> {
    if let ControlFieldUpdate::Set(model_ref) = &patch.model_ref {
        if model_ref.trim().is_empty() {
            return Err(WorkspaceIntelligenceStoreError::BlankModelReference);
        }
    }
    Ok(())
}

/// Applies the modeled fields of a patch, leaving every other field untouched.
fn apply_patch(
    document: &mut Map<String, Value>,
    patch: &WorkspaceIntelligenceControlPatch,
) -> Result<(), WorkspaceIntelligenceStoreError> {
    match &patch.enabled {
        ControlFieldUpdate::Keep => {}
        ControlFieldUpdate::Set(enabled) => {
            document.insert("enabled".to_string(), Value::Bool(*enabled));
        }
        ControlFieldUpdate::Clear => {
            document.remove("enabled");
        }
    }

    match &patch.model_ref {
        ControlFieldUpdate::Keep => {}
        ControlFieldUpdate::Set(model_ref) => {
            // Same structural rule as the control-record projection: a blank
            // reference is not a binding, and storing one would publish a record
            // that every reader has to reject.
            if model_ref.trim().is_empty() {
                return Err(WorkspaceIntelligenceStoreError::BlankModelReference);
            }
            document.insert("model_ref".to_string(), Value::String(model_ref.clone()));
        }
        ControlFieldUpdate::Clear => {
            document.remove("model_ref");
        }
    }

    match &patch.policy {
        ControlFieldUpdate::Keep => {}
        ControlFieldUpdate::Set(policy) => {
            document.insert("policy".to_string(), policy.clone());
        }
        ControlFieldUpdate::Clear => {
            document.remove("policy");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::process::Stdio;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    const FIXTURE_DIR_ENV: &str = "OPENBITFUN_WORKSPACE_INTELLIGENCE_FIXTURE_DIR";
    const FIXTURE_ROLE_ENV: &str = "OPENBITFUN_WORKSPACE_INTELLIGENCE_FIXTURE_ROLE";
    const FIXTURE_SCOPE: &str = "workspace-fixture@host-fixture";
    const CHILD_DEADLINE: Duration = Duration::from_secs(30);

    struct Child(std::process::Child);

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn store(root: &Path) -> WorkspaceIntelligenceStore {
        WorkspaceIntelligenceStore::new(root.to_path_buf(), vec![1])
    }

    fn enabled(value: bool) -> WorkspaceIntelligenceControlPatch {
        WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(value),
            ..Default::default()
        }
    }

    fn model_ref(value: &str) -> WorkspaceIntelligenceControlPatch {
        WorkspaceIntelligenceControlPatch {
            model_ref: ControlFieldUpdate::Set(value.to_string()),
            ..Default::default()
        }
    }

    fn policy(value: Value) -> WorkspaceIntelligenceControlPatch {
        WorkspaceIntelligenceControlPatch {
            policy: ControlFieldUpdate::Set(value),
            ..Default::default()
        }
    }

    fn lock_path(record: &Path) -> PathBuf {
        PathBuf::from(format!("{}.lock", record.display()))
    }

    async fn bytes(path: &Path) -> Vec<u8> {
        tokio::fs::read(path).await.unwrap()
    }

    /// Reads the raw document a test or another writer left on disk.
    async fn document_at(path: &Path) -> Value {
        JsonFileStore
            .read_optional::<Value>(path)
            .await
            .unwrap()
            .unwrap()
    }

    /// Polls a record while another writer may be replacing it.
    ///
    /// While a replacement is in flight the JSON owner may report the target as
    /// unobserved (`Ok(None)`) or as an unreadable-now error, depending on which
    /// step of its existence probe and read it sampled. Both are observations
    /// rather than data, so they are retried until the deadline, using the same
    /// predicate production uses to defer. The deadline remains a hard failure
    /// whose message carries the complete last observation, so a real regression
    /// is never retried away.
    async fn read_while_writing(
        store: &WorkspaceIntelligenceStore,
        scope: &str,
        deadline: Instant,
    ) -> WorkspaceIntelligenceControlRecord {
        let mut last: String;
        loop {
            match store.read(scope).await {
                Ok(Some(record)) => return record,
                Ok(None) => last = "reading the record observed no file".to_string(),
                Err(error) if is_unreadable_observation(&error) => {
                    last = format!("the record was momentarily unreadable: {error}");
                }
                Err(error) => panic!("unexpected read error: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "the record never became readable before the deadline; last observation: {last}"
            );
            tokio::task::yield_now().await;
        }
    }

    fn hex_name(name: &str) -> &str {
        name.strip_suffix(".lock")
            .unwrap_or(name)
            .strip_suffix(".json")
            .unwrap_or_else(|| panic!("unexpected sidecar entry {name}"))
    }

    #[derive(Clone, Copy)]
    enum Case {
        Corrupt,
        Unsupported(u32),
        Fault(ControlRecordFault),
    }

    fn assert_case(error: WorkspaceIntelligenceStoreError, case: Case, context: &str) {
        match case {
            Case::Corrupt => assert!(
                matches!(error, WorkspaceIntelligenceStoreError::CorruptRecord { .. }),
                "{context}: {error}"
            ),
            Case::Unsupported(version) => assert!(
                matches!(
                    error,
                    WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion {
                        version: found,
                        ..
                    } if found == version
                ),
                "{context}: {error}"
            ),
            Case::Fault(fault) => assert!(
                matches!(
                    error,
                    WorkspaceIntelligenceStoreError::InvalidRecord { fault: found, .. }
                        if found == fault
                ),
                "{context}: {error}"
            ),
        }
    }

    #[cfg(windows)]
    fn deny_rewrite(path: &Path) -> std::fs::File {
        use std::os::windows::fs::OpenOptionsExt;

        // FILE_SHARE_READ only: readers keep working, while any replacement
        // needs DELETE access and fails deterministically.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(path)
            .unwrap()
    }

    #[test]
    fn the_lock_free_decision_defers_exactly_the_undecidable_observations() {
        let store = store(Path::new("unused-root"));
        let path = PathBuf::from("unused-root").join("record.json");
        let patch = enabled(true);
        let exactly = |generation| ControlGenerationExpectation::Exactly(generation);

        // 1. An unobserved file with a concrete expectation is a conflict with an
        //    absent record, for any generation the caller may have read.
        for generation in [0, 1] {
            let decision = store.decide(&path, Ok(None), exactly(generation), &patch);
            match decision {
                Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                    expected: ControlGenerationExpectation::Exactly(expected),
                    actual: ControlGenerationExpectation::Absent,
                }) => assert_eq!(expected, generation),
                other => panic!("generation {generation}: {other:?}"),
            }
        }

        // 2. An unobserved file with an `Absent` expectation is undecidable here:
        //    creating the record has to happen under the transaction lock.
        assert!(
            matches!(
                store.decide(&path, Ok(None), ControlGenerationExpectation::Absent, &patch),
                Ok(None)
            ),
            "an unobserved file must defer instead of completing"
        );

        // 3. A target that was momentarily unreadable is undecidable too.
        let unreadable = || WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read {
            path: path.clone(),
            source: std::io::Error::from(ErrorKind::NotFound),
        });
        for expectation in [ControlGenerationExpectation::Absent, exactly(3)] {
            assert!(
                matches!(
                    store.decide(&path, Err(unreadable()), expectation, &patch),
                    Ok(None)
                ),
                "{expectation} must defer on an unreadable observation"
            );
        }

        // 4. The exemption is exactly not-found: any other IO failure is returned
        //    unchanged, whatever the expectation.
        let denied = || WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read {
            path: path.clone(),
            source: std::io::Error::from(ErrorKind::PermissionDenied),
        });
        for expectation in [ControlGenerationExpectation::Absent, exactly(1)] {
            match store.decide(&path, Err(denied()), expectation, &patch) {
                Err(WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read {
                    source,
                    ..
                })) => assert_eq!(source.kind(), ErrorKind::PermissionDenied),
                other => panic!("{expectation}: {other:?}"),
            }
        }
        let metadata_failure = || {
            WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::ReadMetadata {
                path: path.clone(),
                source: std::io::Error::from(ErrorKind::PermissionDenied),
            })
        };
        assert!(store
            .decide(
                &path,
                Err(metadata_failure()),
                ControlGenerationExpectation::Absent,
                &patch
            )
            .is_err());

        // 5. Data faults are never deferred either: a caller that cannot read the
        //    record must see the fault, not a silent retry.
        fn fault_case(index: u8, path: &Path) -> WorkspaceIntelligenceStoreError {
            match index {
                0 => WorkspaceIntelligenceStoreError::CorruptRecord {
                    path: path.to_path_buf(),
                    source: serde_json::from_str::<Value>("not json").unwrap_err(),
                },
                1 => WorkspaceIntelligenceStoreError::InvalidRecord {
                    path: path.to_path_buf(),
                    fault: ControlRecordFault::EnabledMalformed,
                },
                _ => WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion {
                    path: path.to_path_buf(),
                    version: 7,
                },
            }
        }
        for index in 0..3 {
            for expectation in [ControlGenerationExpectation::Absent, exactly(1)] {
                let decision =
                    store.decide(&path, Err(fault_case(index, &path)), expectation, &patch);
                assert_eq!(
                    decision.unwrap_err().to_string(),
                    fault_case(index, &path).to_string(),
                    "fault {index} {expectation}"
                );
            }
        }

        // A decodable document still decides a conflict and a no-op, so the
        // deferral above is not hiding the ordinary paths.
        let document = json!({ "control_generation": 3, "enabled": true });
        assert!(matches!(
            store.decide(
                &path,
                Ok(Some(document.clone())),
                ControlGenerationExpectation::Absent,
                &patch
            ),
            Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict { .. })
        ));
        assert!(matches!(
            store.decide(&path, Ok(Some(document.clone())), exactly(2), &patch),
            Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict { .. })
        ));
        assert!(matches!(
            store.decide(&path, Ok(Some(document)), exactly(3), &patch),
            Ok(Some(WorkspaceIntelligenceControlWrite::Unchanged(_)))
        ));
    }

    #[tokio::test]
    async fn construction_and_missing_reads_create_nothing() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);

        assert_eq!(store.read("workspace-a@host-1").await.unwrap(), None);
        assert_eq!(store.read("workspace-a@host-2").await.unwrap(), None);
        assert!(!root.exists(), "reads must not initialize the sidecar root");

        let error = store.read("").await.unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::EmptyScope
        ));
        let error = store
            .update(
                "",
                ControlGenerationExpectation::Absent,
                enabled(true),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::EmptyScope
        ));

        // Invalid write input is rejected before the root or lock file exists.
        let error = store
            .update(
                "fresh-scope",
                ControlGenerationExpectation::Absent,
                model_ref("   "),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::BlankModelReference
        ));
        assert!(!root.exists());
    }

    #[tokio::test]
    async fn rejections_on_a_missing_record_create_nothing() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";

        // A compare-and-swap against a record that does not exist is rejected
        // from the lock-free precheck, so not even a lock file appears.
        for expectation in [
            ControlGenerationExpectation::Exactly(1),
            ControlGenerationExpectation::Exactly(0),
        ] {
            let error = store
                .update(scope, expectation, enabled(true))
                .await
                .unwrap_err();
            assert!(error.is_conflict(), "{expectation}: {error}");
            assert!(!root.exists(), "{expectation} created the sidecar root");
        }

        // `Absent` with an empty patch is not a no-op: it publishes a new record,
        // which is a real write and must be reported as applied.
        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch::default(),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        assert_eq!(write.record().control_generation, 1);
        assert!(root.exists());
    }

    #[tokio::test]
    async fn a_no_op_on_an_externally_written_record_takes_no_write_lock() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let document = json!({
            "schema_version": 1,
            "control_generation": 4,
            "enabled": true,
            "model_ref": "workspace-model-a",
        });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();
        let stored = bytes(&record_path).await;
        assert!(
            !lock_path(&record_path).exists(),
            "the fixture must start without a transaction lock"
        );

        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(4),
                model_ref("workspace-model-a"),
            )
            .await
            .unwrap();
        assert!(matches!(
            write,
            WorkspaceIntelligenceControlWrite::Unchanged(ref record)
                if record.control_generation == 4
        ));
        assert_eq!(bytes(&record_path).await, stored);
        assert!(
            !lock_path(&record_path).exists(),
            "an unchanged result must not create a transaction lock"
        );

        // The same expectation against a document that does need a change takes
        // the lock and is applied.
        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(4),
                model_ref("workspace-model-b"),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        assert_eq!(write.record().control_generation, 5);
        assert_eq!(
            write.record().model_ref.as_deref(),
            Some("workspace-model-b")
        );
        assert!(write.record().raw["enabled"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn scopes_are_independent_and_hashed_names_cannot_escape_the_root() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let records = store(&root);

        let write = records
            .update("workspace-a@host-1", ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        assert!(write.is_applied());
        assert_eq!(
            records
                .read("workspace-a@host-1")
                .await
                .unwrap()
                .unwrap()
                .enabled,
            Some(true)
        );
        assert_eq!(records.read("workspace-a@host-2").await.unwrap(), None);
        assert_eq!(records.read("workspace-b@host-1").await.unwrap(), None);

        let escapes = [
            "../escape",
            "..\\escape",
            "a/b",
            "C:\\Windows\\system32",
            "/etc/passwd",
        ];
        for scope in escapes {
            let write = records
                .update(scope, ControlGenerationExpectation::Absent, enabled(true))
                .await
                .unwrap();
            assert!(write.is_applied(), "{scope}");
        }

        let mut entries: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        entries.sort();
        assert_eq!(entries.len(), (escapes.len() + 1) * 2);
        for entry in &entries {
            let digest = hex_name(entry);
            assert_eq!(digest.len(), 64, "{entry}");
            assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()), "{entry}");
        }

        // The same scope read through a different injected root is unrelated.
        let other = store(&fixture.path().join("other-sidecar"));
        assert_eq!(other.read("workspace-a@host-1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn legacy_payloads_round_trip_and_unknown_fields_survive_changes() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let record_path = store.record_path("workspace-a@host-1").unwrap();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let legacy = json!({
            "enabled": true,
            "unknown_root": { "nested": [1, { "deep": null }], "flag": false },
            "policy": { "keep": true, "nested": { "future": "value" } },
        });
        JsonFileStore
            .write_atomic_strict(&record_path, &legacy)
            .await
            .unwrap();

        let read = store.read("workspace-a@host-1").await.unwrap().unwrap();
        assert_eq!(read.control_generation, 0);
        assert_eq!(read.schema_version, None);
        assert_eq!(read.enabled, Some(true));
        assert_eq!(read.model_ref, None);
        assert_eq!(read.policy, legacy.get("policy").cloned());
        assert_eq!(read.raw, legacy);
        assert!(
            !lock_path(&record_path).exists(),
            "a read must not create the transaction lock"
        );

        let write = store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Exactly(0),
                model_ref("workspace-model-a"),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        let record = write.record().clone();
        assert_eq!(record.control_generation, 1);
        assert_eq!(
            record.schema_version, None,
            "an existing legacy record is not silently upgraded"
        );
        assert_eq!(record.model_ref.as_deref(), Some("workspace-model-a"));
        assert_eq!(record.raw["unknown_root"], legacy["unknown_root"]);
        assert_eq!(record.raw["policy"], legacy["policy"]);
        assert_eq!(record.enabled, Some(true));

        let cleared = store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Exactly(1),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Clear,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(cleared.is_applied());
        let record = cleared.record().clone();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.policy, None);
        assert_eq!(record.raw["unknown_root"], legacy["unknown_root"]);
    }

    #[tokio::test]
    async fn unsupported_and_invalid_documents_error_without_touching_bytes() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let record_path = store.record_path("workspace-a@host-1").unwrap();
        tokio::fs::create_dir_all(&root).await.unwrap();

        let cases: &[(&[u8], Case, &str)] = &[
            (b"broken", Case::Corrupt, "corrupt json"),
            (b"[]", Case::Fault(ControlRecordFault::PayloadNotObject), "array root"),
            (b"\"enabled\"", Case::Fault(ControlRecordFault::PayloadNotObject), "string root"),
            (
                br#"{"schema_version":"1","enabled":true}"#,
                Case::Fault(ControlRecordFault::SchemaVersionMalformed),
                "string version",
            ),
            (
                br#"{"schema_version":99,"enabled":true}"#,
                Case::Unsupported(99),
                "unknown version",
            ),
            (
                br#"{"control_generation":0}"#,
                Case::Fault(ControlRecordFault::ControlGenerationZero),
                "explicit zero generation",
            ),
            (
                br#"{"control_generation":-1}"#,
                Case::Fault(ControlRecordFault::ControlGenerationMalformed),
                "negative generation",
            ),
            (
                br#"{"control_generation":"1"}"#,
                Case::Fault(ControlRecordFault::ControlGenerationMalformed),
                "string generation",
            ),
            (
                br#"{"control_generation":1.5}"#,
                Case::Fault(ControlRecordFault::ControlGenerationMalformed),
                "fractional generation",
            ),
            (
                br#"{"enabled":"true"}"#,
                Case::Fault(ControlRecordFault::EnabledMalformed),
                "string switch",
            ),
            (
                br#"{"enabled":1}"#,
                Case::Fault(ControlRecordFault::EnabledMalformed),
                "numeric switch",
            ),
            (
                br#"{"model_ref":""}"#,
                Case::Fault(ControlRecordFault::ModelRefMalformed),
                "empty reference",
            ),
            (
                br#"{"model_ref":"   "}"#,
                Case::Fault(ControlRecordFault::ModelRefMalformed),
                "blank reference",
            ),
            (
                br#"{"model_ref":42}"#,
                Case::Fault(ControlRecordFault::ModelRefMalformed),
                "numeric reference",
            ),
        ];

        for (invalid, case, label) in cases {
            tokio::fs::write(&record_path, invalid).await.unwrap();

            let error = store.read("workspace-a@host-1").await.unwrap_err();
            assert_case(error, *case, label);

            let error = store
                .update(
                    "workspace-a@host-1",
                    ControlGenerationExpectation::Exactly(0),
                    enabled(false),
                )
                .await
                .unwrap_err();
            assert_case(error, *case, label);

            // A corrupt or unreadable record is never mistaken for absence.
            let error = store
                .update(
                    "workspace-a@host-1",
                    ControlGenerationExpectation::Absent,
                    enabled(false),
                )
                .await
                .unwrap_err();
            assert_case(error, *case, label);

            // The raw diagnostics channel reports the stored payload verbatim for
            // every payload that is valid JSON, even when the typed authority
            // rejects it. Corrupt JSON stays an explicit error there too.
            match serde_json::from_slice::<Value>(invalid) {
                Ok(expected) => {
                    let payload = store.read_payload("workspace-a@host-1").await.unwrap();
                    assert_eq!(payload, Some(expected), "raw payload: {label}");
                }
                Err(_) => {
                    let error = store
                        .read_payload("workspace-a@host-1")
                        .await
                        .unwrap_err();
                    assert!(matches!(
                        error,
                        WorkspaceIntelligenceStoreError::CorruptRecord { .. }
                    ));
                }
            }

            assert_eq!(bytes(&record_path).await, *invalid, "{label}");
        }

        // Every rejection above came from the lock-free precheck, so the fixture
        // directory still holds only the record written by the test itself.
        let entries: Vec<String> = std::fs::read_dir(&root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        assert!(entries[0].ends_with(".json"), "{entries:?}");

        // A read error that is not a JSON problem is reported as an error on both
        // channels and never resets the target.
        tokio::fs::remove_file(&record_path).await.unwrap();
        tokio::fs::create_dir_all(&record_path).await.unwrap();
        let error = store.read("workspace-a@host-1").await.unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read { .. })
        ));
        let error = store.read_payload("workspace-a@host-1").await.unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Read { .. })
        ));
        assert!(record_path.is_dir());
    }

    #[tokio::test]
    async fn the_raw_diagnostics_channel_validates_nothing_and_writes_nothing() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);

        // Absence is still absence on the raw channel, and it creates nothing.
        assert_eq!(store.read_payload("workspace-a@host-1").await.unwrap(), None);
        assert!(!root.exists());

        let record_path = store.record_path("workspace-a@host-1").unwrap();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let unsupported = json!({
            "schema_version": 99,
            "control_generation": "not-a-number",
            "enabled": { "nested": true },
            "model_ref": [""],
            "policy": { "unknown": { "deep": [1, 2] } },
        });
        JsonFileStore
            .write_atomic_strict(&record_path, &unsupported)
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        // The typed authority rejects this document; the raw channel still hands
        // back exactly what is on disk so diagnostics can preserve it.
        assert!(store.read("workspace-a@host-1").await.is_err());
        assert_eq!(
            store.read_payload("workspace-a@host-1").await.unwrap(),
            Some(unsupported.clone())
        );
        // No authority may be inferred, and no raw write path exists.
        assert!(store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Exactly(0),
                enabled(true)
            )
            .await
            .is_err());

        assert_eq!(bytes(&record_path).await, stored);
        assert!(!lock_path(&record_path).exists());
    }

    #[tokio::test]
    async fn a_policy_patch_replaces_the_whole_value_and_leaves_other_fields_alone() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(
                scope,
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    policy: ControlFieldUpdate::Set(
                        json!({ "keep": 1, "future": { "nested": [1, 2] } }),
                    ),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut document = document_at(&record_path).await;
        document["unknown_root"] = json!({ "nested": { "kept": true } });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();

        // `Set` is a whole-value replacement: the store never merges inside the
        // payload, so content the caller did not carry forward is gone by design.
        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(1),
                policy(json!({ "replaced": true })),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        let record = write.record().clone();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.policy, Some(json!({ "replaced": true })));
        assert_eq!(
            record.raw["unknown_root"],
            json!({ "nested": { "kept": true } }),
            "a policy replacement must not touch fields outside the patch"
        );
        assert_eq!(record.enabled, Some(true));

        // `Clear` removes only the policy key.
        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(2),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Clear,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        let record = write.record().clone();
        assert_eq!(record.control_generation, 3);
        assert_eq!(record.policy, None);
        assert!(
            !record.raw.as_object().unwrap().contains_key("policy"),
            "clear removes the key instead of storing null"
        );
        assert_eq!(record.raw["unknown_root"], json!({ "nested": { "kept": true } }));
        assert_eq!(record.enabled, Some(true));
    }

    #[tokio::test]
    async fn new_records_start_at_one_and_stale_or_absent_expectations_conflict() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = WorkspaceIntelligenceStore::new(root.clone(), vec![1, 2]);
        let record_path = store.record_path("workspace-a@host-1").unwrap();

        let write = store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Absent,
                enabled(true),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        assert_eq!(write.record().control_generation, 1);
        assert_eq!(write.record().schema_version, Some(2));

        let stored = bytes(&record_path).await;
        let error = store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Absent,
                enabled(false),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                expected: ControlGenerationExpectation::Absent,
                actual: ControlGenerationExpectation::Exactly(1),
            }
        ));
        assert!(error.is_conflict());

        for stale in [0, 2, u64::MAX] {
            let error = store
                .update(
                    "workspace-a@host-1",
                    ControlGenerationExpectation::Exactly(stale),
                    enabled(false),
                )
                .await
                .unwrap_err();
            assert!(error.is_conflict(), "{stale}");
        }
        assert_eq!(bytes(&record_path).await, stored);

        let write = store
            .update(
                "workspace-a@host-1",
                ControlGenerationExpectation::Exactly(1),
                enabled(false),
            )
            .await
            .unwrap();
        assert!(write.is_applied());
        assert_eq!(write.record().control_generation, 2);
        assert_eq!(
            write.record().schema_version,
            Some(2),
            "an existing record keeps its schema version"
        );

        // A host that only understands legacy records stamps no version at all,
        // so it never publishes a version its own projection would reject.
        let legacy_only = WorkspaceIntelligenceStore::new(
            fixture.path().join("legacy-sidecar"),
            Vec::new(),
        );
        let write = legacy_only
            .update(
                "workspace-b@host-1",
                ControlGenerationExpectation::Absent,
                enabled(true),
            )
            .await
            .unwrap();
        assert_eq!(write.record().schema_version, None);
        assert_eq!(
            legacy_only
                .read("workspace-b@host-1")
                .await
                .unwrap()
                .unwrap()
                .schema_version,
            None
        );
    }

    #[tokio::test]
    async fn identical_mutations_neither_rewrite_nor_advance_the_generation() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let record_path = store.record_path("workspace-a@host-1").unwrap();
        let scope = "workspace-a@host-1";

        store
            .update(
                scope,
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Set("workspace-model-a".to_string()),
                    policy: ControlFieldUpdate::Set(json!({ "keep": [1, 2] })),
                },
            )
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(1),
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Set("workspace-model-a".to_string()),
                    policy: ControlFieldUpdate::Set(json!({ "keep": [1, 2] })),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            write,
            WorkspaceIntelligenceControlWrite::Unchanged(ref record)
                if record.control_generation == 1
        ));
        assert_eq!(bytes(&record_path).await, stored);

        let error = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(1),
                model_ref(" "),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::BlankModelReference
        ));
        assert_eq!(bytes(&record_path).await, stored);
    }

    #[tokio::test]
    async fn clearing_a_field_that_is_already_absent_is_a_zero_write_no_op() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let stored = bytes(&record_path).await;
        // The creation above already took the OS lock. A no-op must not change
        // that footprint at all, so the footprint is captured, not assumed.
        let lock_before = lock_path(&record_path).exists();
        let modified_before = std::fs::metadata(&record_path).unwrap().modified().unwrap();

        // Both keys are already absent, so `Clear` changes nothing: no rewrite and
        // no generation advance.
        for patch in [
            WorkspaceIntelligenceControlPatch {
                model_ref: ControlFieldUpdate::Clear,
                ..Default::default()
            },
            WorkspaceIntelligenceControlPatch {
                policy: ControlFieldUpdate::Clear,
                ..Default::default()
            },
        ] {
            let write = store
                .update(scope, ControlGenerationExpectation::Exactly(1), patch)
                .await
                .unwrap();
            assert!(matches!(
                write,
                WorkspaceIntelligenceControlWrite::Unchanged(ref record)
                    if record.control_generation == 1
            ));
            assert_eq!(bytes(&record_path).await, stored);
        }
        assert_eq!(
            lock_path(&record_path).exists(),
            lock_before,
            "a zero-write no-op must not change the transaction lock footprint"
        );
        assert_eq!(
            std::fs::metadata(&record_path).unwrap().modified().unwrap(),
            modified_before,
            "a zero-write no-op must not touch the record file"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn an_identical_mutation_does_not_attempt_a_write() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        // Replacement is impossible while this handle denies DELETE access, so
        // an accepted no-op can only succeed if the store never attempted a write.
        let denial = deny_rewrite(&record_path);
        let write = store
            .update(scope, ControlGenerationExpectation::Exactly(1), enabled(true))
            .await
            .unwrap();
        assert!(matches!(
            write,
            WorkspaceIntelligenceControlWrite::Unchanged(_)
        ));
        drop(denial);

        assert_eq!(bytes(&record_path).await, stored);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn strict_replace_failure_preserves_the_previous_document() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        let denial = deny_rewrite(&record_path);
        let error = store
            .update(scope, ControlGenerationExpectation::Exactly(1), enabled(false))
            .await
            .unwrap_err();
        drop(denial);

        assert!(
            matches!(
                error,
                WorkspaceIntelligenceStoreError::Storage(JsonFileStoreError::Replace { .. })
            ),
            "{error}"
        );
        assert_eq!(bytes(&record_path).await, stored);
        assert_eq!(
            store.read(scope).await.unwrap().unwrap().control_generation,
            1
        );
        for entry in std::fs::read_dir(&root).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(!name.ends_with(".tmp"), "temp file left behind: {name}");
        }
    }

    #[tokio::test]
    async fn generation_overflow_is_rejected_without_wrapping() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();
        tokio::fs::create_dir_all(&root).await.unwrap();
        let fixture_document = json!({
            "schema_version": 1,
            "control_generation": u64::MAX,
            "enabled": true,
        });
        JsonFileStore
            .write_atomic_strict(&record_path, &fixture_document)
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        let write = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(u64::MAX),
                enabled(true),
            )
            .await
            .unwrap();
        assert!(matches!(
            write,
            WorkspaceIntelligenceControlWrite::Unchanged(ref record)
                if record.control_generation == u64::MAX
        ));
        assert_eq!(bytes(&record_path).await, stored);

        let error = store
            .update(
                scope,
                ControlGenerationExpectation::Exactly(u64::MAX),
                enabled(false),
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            WorkspaceIntelligenceStoreError::ControlGenerationOverflow { .. }
        ));
        assert_eq!(bytes(&record_path).await, stored);
        assert_eq!(
            store.read(scope).await.unwrap().unwrap().control_generation,
            u64::MAX
        );
    }

    #[tokio::test]
    async fn competing_cas_updates_accept_exactly_one_writer() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let mut document = document_at(&record_path).await;
        document["unknown_root"] = json!({ "nested": { "kept": true } });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();

        let first = store.clone();
        let second = store.clone();
        let (left, right) = tokio::join!(
            first.update(
                scope,
                ControlGenerationExpectation::Exactly(1),
                model_ref("writer-a"),
            ),
            second.update(
                scope,
                ControlGenerationExpectation::Exactly(1),
                policy(json!({ "writer": "b" })),
            ),
        );

        let left_applied = matches!(
            left,
            Ok(WorkspaceIntelligenceControlWrite::Applied(_))
        );
        let right_applied = matches!(
            right,
            Ok(WorkspaceIntelligenceControlWrite::Applied(_))
        );
        assert!(
            left_applied ^ right_applied,
            "exactly one writer must win: left={left:?} right={right:?}"
        );
        let loser = if left_applied { &right } else { &left };
        assert!(
            matches!(loser, Err(error) if error.is_conflict()),
            "the losing writer must see a conflict: {loser:?}"
        );

        let record = store.read(scope).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.enabled, Some(true));
        assert_eq!(record.raw["unknown_root"], json!({ "nested": { "kept": true } }));
        if left_applied {
            assert_eq!(record.model_ref.as_deref(), Some("writer-a"));
            assert_eq!(record.policy, None);
        } else {
            assert_eq!(record.model_ref, None);
            assert_eq!(record.policy, Some(json!({ "writer": "b" })));
        }
    }

    #[tokio::test]
    async fn cross_process_cas_accepts_exactly_one_writer() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let record_path = store.record_path(FIXTURE_SCOPE).unwrap();

        store
            .update(
                FIXTURE_SCOPE,
                ControlGenerationExpectation::Absent,
                enabled(true),
            )
            .await
            .unwrap();
        let mut document = document_at(&record_path).await;
        document["unknown_root"] = json!({ "nested": { "kept": true } });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();

        let children: Vec<Child> = ["a", "b"]
            .into_iter()
            .map(|role| {
                // Fixture precedent: this test re-executes its own test binary
                // without the `process-runtime` owner feature, and an explicit
                // `CREATE_NO_WINDOW` keeps a GUI or redirected host from
                // flashing a console.
                let mut command = std::process::Command::new(std::env::current_exe().unwrap());
                #[cfg(windows)]
                {
                    use std::os::windows::process::CommandExt;
                    // CREATE_NO_WINDOW: the fixture child must not flash a console.
                    command.creation_flags(0x0800_0000);
                }
                Child(
                    command
                        .args([
                            "--exact",
                            "workspace_intelligence_store::tests::record_transaction_process_fixture",
                            "--nocapture",
                        ])
                        .env(FIXTURE_DIR_ENV, fixture.path())
                        .env(FIXTURE_ROLE_ENV, role)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();

        let deadline = Instant::now() + CHILD_DEADLINE;
        let mut outcomes = Vec::new();
        for role in ["a", "b"] {
            outcomes.push(wait_for_outcome(fixture.path(), role, deadline).await);
        }
        drop(children);

        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.starts_with("applied "))
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome.as_str() == "conflict")
                .count(),
            1,
            "{outcomes:?}"
        );

        let record = store.read(FIXTURE_SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.enabled, Some(true));
        assert_eq!(record.raw["unknown_root"], json!({ "nested": { "kept": true } }));
        let model_won = record.model_ref.as_deref() == Some("child-a");
        let policy_won = record.policy == Some(json!({ "winner": "b" }));
        assert!(
            model_won ^ policy_won,
            "the losing writer must not leave a field behind: {record:?}"
        );
    }

    /// Child-process fixture for the cross-process CAS test.
    ///
    /// Both children announce readiness, wait for the peer, and then race the
    /// same expected generation. Each child owns one distinct patch field so a
    /// stale writer would be visible in the surviving document.
    #[tokio::test]
    async fn record_transaction_process_fixture() {
        let Some(directory) = std::env::var_os(FIXTURE_DIR_ENV) else {
            return;
        };
        let directory = PathBuf::from(directory);
        let role = std::env::var(FIXTURE_ROLE_ENV).expect("fixture role");
        let peer = if role == "a" { "b" } else { "a" };
        let store = store(&directory.join("sidecar"));

        tokio::fs::write(directory.join(format!("{role}.ready")), b"ready")
            .await
            .unwrap();
        let deadline = Instant::now() + CHILD_DEADLINE;
        while !directory.join(format!("{peer}.ready")).exists() {
            assert!(Instant::now() < deadline, "peer never became ready");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let patch = match role.as_str() {
            "a" => model_ref("child-a"),
            _ => policy(json!({ "winner": "b" })),
        };
        let outcome = store
            .update(
                FIXTURE_SCOPE,
                ControlGenerationExpectation::Exactly(1),
                patch,
            )
            .await;
        let line = match outcome {
            Ok(WorkspaceIntelligenceControlWrite::Applied(record)) => {
                format!("applied {}", record.control_generation)
            }
            Ok(WorkspaceIntelligenceControlWrite::Unchanged(record)) => {
                format!("unchanged {}", record.control_generation)
            }
            Err(error) if error.is_conflict() => "conflict".to_string(),
            Err(error) => format!("error {error}"),
        };
        // Published atomically, so the parent can never read a partially written
        // outcome and misclassify this child.
        JsonFileStore
            .write_text_atomic_strict(&directory.join(format!("{role}.outcome")), &line)
            .await
            .unwrap();
    }

    async fn wait_for_outcome(directory: &Path, role: &str, deadline: Instant) -> String {
        let path = directory.join(format!("{role}.outcome"));
        loop {
            if let Ok(outcome) = tokio::fs::read_to_string(&path).await {
                if !outcome.is_empty() {
                    return outcome;
                }
            }
            assert!(
                Instant::now() < deadline,
                "fixture child {role} did not report an outcome"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn dropping_the_caller_future_does_not_cancel_the_accepted_transaction() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let mut document = document_at(&record_path).await;
        document["unknown_root"] = json!({ "nested": [1, 2] });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();

        let mut transaction = Box::pin(store.update(
            scope,
            ControlGenerationExpectation::Exactly(1),
            model_ref("cancelled-caller"),
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(transaction.as_mut().poll(&mut context), Poll::Pending),
            "the first poll must only hand the transaction to the owned task"
        );
        drop(transaction);

        let deadline = Instant::now() + CHILD_DEADLINE;
        let record = loop {
            let observed = read_while_writing(&store, scope, deadline).await;
            if observed.control_generation == 2 {
                break observed;
            }
            assert!(
                Instant::now() < deadline,
                "the accepted transaction did not finish after the caller was dropped"
            );
            tokio::task::yield_now().await;
        };
        assert_eq!(record.model_ref.as_deref(), Some("cancelled-caller"));
        assert_eq!(record.raw["unknown_root"], json!({ "nested": [1, 2] }));
        assert_eq!(record.enabled, Some(true));

        // A writer that still holds the pre-cancellation generation is rejected.
        let error = store
            .update(scope, ControlGenerationExpectation::Exactly(1), enabled(false))
            .await
            .unwrap_err();
        assert!(error.is_conflict());
        assert_eq!(store.read(scope).await.unwrap().unwrap().enabled, Some(true));
    }

    /// Cancellation while the transaction is still waiting for the OS lock.
    ///
    /// A second handle holds the record's cross-process lock, which no correct
    /// writer can bypass. The caller polls once and drops its future, the
    /// generation provably stays unchanged while the lock is held, and the
    /// released lock lets the already accepted transaction publish generation 2
    /// with no further caller action.
    #[tokio::test]
    async fn a_transaction_queued_behind_the_os_lock_survives_caller_cancellation() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("sidecar");
        let store = store(&root);
        let observer = store.clone();
        let scope = "workspace-a@host-1";
        let record_path = store.record_path(scope).unwrap();

        store
            .update(scope, ControlGenerationExpectation::Absent, enabled(true))
            .await
            .unwrap();
        let mut document = document_at(&record_path).await;
        document["unknown_root"] = json!({ "nested": ["queued"] });
        JsonFileStore
            .write_atomic_strict(&record_path, &document)
            .await
            .unwrap();
        let stored = bytes(&record_path).await;

        // This is the same OS lock the store takes, held by an independent handle,
        // so the transaction cannot publish while it is held.
        let held = JsonFileStore
            .acquire_cross_process_lock(&record_path)
            .await
            .unwrap();

        let mut transaction = Box::pin(store.update(
            scope,
            ControlGenerationExpectation::Exactly(1),
            model_ref("queued-caller"),
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(transaction.as_mut().poll(&mut context), Poll::Pending),
            "the first poll must only hand the transaction to the owned task"
        );
        drop(transaction);

        // Bounded cooperative progress rounds: the transaction may run, but it
        // cannot pass the lock, so no generation can appear. No writer is active
        // here, so these reads are stable.
        for _ in 0..64 {
            tokio::task::yield_now().await;
            assert_eq!(
                observer
                    .read(scope)
                    .await
                    .unwrap()
                    .unwrap()
                    .control_generation,
                1,
                "the transaction published while the transaction lock was held"
            );
        }
        assert_eq!(bytes(&record_path).await, stored);

        drop(held);

        let deadline = Instant::now() + CHILD_DEADLINE;
        let record = loop {
            let observed = read_while_writing(&observer, scope, deadline).await;
            if observed.control_generation == 2 {
                break observed;
            }
            assert!(
                Instant::now() < deadline,
                "the queued transaction did not finish after the lock was released"
            );
            tokio::task::yield_now().await;
        };
        assert_eq!(record.model_ref.as_deref(), Some("queued-caller"));
        assert_eq!(record.enabled, Some(true));
        assert_eq!(record.raw["unknown_root"], json!({ "nested": ["queued"] }));

        // A fresh store instance holding the pre-cancellation generation is
        // rejected, so the surviving authority is the transaction's own.
        let restarted = WorkspaceIntelligenceStore::new(root.clone(), vec![1]);
        let error = restarted
            .update(scope, ControlGenerationExpectation::Exactly(1), enabled(false))
            .await
            .unwrap_err();
        assert!(error.is_conflict());
        assert_eq!(
            restarted.read(scope).await.unwrap().unwrap().enabled,
            Some(true)
        );
    }
}
