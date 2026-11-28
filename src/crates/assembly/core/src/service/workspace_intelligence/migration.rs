//! Migration decision of the WP2.3 legacy Memory migration (slice 40a).
//!
//! # What this module is
//!
//! It owns the durable decision record of one migration pass:
//!
//! - the source the user decided on, as a fingerprint of the legacy Memory source;
//! - one assignment per legacy item: keep it shared, assign it to a workspace, or
//!   defer recalling it;
//! - an idempotency key and the decision time, so a repeated confirmation can be
//!   recognized instead of applied twice.
//!
//! It is pure: no file, no database, no control record, no clock and no log line.
//! The caller supplies the decision time and the source fingerprint, and the
//! control owner stores the encoded value as an opaque payload.
//!
//! # Where the decision lives
//!
//! The encoded decision is a top-level `migration` key of the authority control
//! record, not part of its `schema_version` and not inside `policy`. It is a new
//! field, so an older build that does not model it keeps it as preserved raw
//! content and can still read, write and roll back the record. The decision is a
//! user decision, not a record-shape change, so it must not force a schema bump.
//!
//! The store only checks that the stored value is a JSON object; this module owns
//! the shape. A record whose `migration` value is present but not an object is
//! rejected by the store instead of being preserved as raw content, because a
//! decision that cannot be understood must not look like "no decision yet".
//!
//! # Idempotency and payload identity
//!
//! [`migration_payload_digest`] is the identity of one payload: the idempotency
//! key, the source fingerprint and the assignment set, with the assignments
//! sorted first so the same decision in a different input order has the same
//! identity. The decision time is deliberately not part of it, so a replayed
//! confirmation carrying a fresh timestamp reconciles as
//! [`MigrationOutcome::Unchanged`] instead of rewriting the record.
//!
//! [`reconcile_existing`] is the whole replay rule: no stored decision applies the
//! incoming one, a different idempotency key is a new decision and replaces the
//! stored one, the same key with the same payload is a no-op, and the same key
//! with a different payload is a conflict the caller must resolve — it is never
//! silently overwritten.
//!
//! [`MigrationOutcome::Apply`] assumes the incoming decision is the newest
//! confirmation for that scope. This module deliberately does not compare
//! `decided_at_unix_ms`, so a late confirmation that carries a different key
//! overwrites a newer decision. The confirmation surface (WP2.4 confirm) must
//! therefore guarantee that only one confirmation per scope is in flight at a
//! time; that is a precondition of consuming this rule, not something the rule
//! can enforce from a single payload comparison.
//!
//! # Staleness
//!
//! [`is_stale`] compares the recorded source fingerprint with a fresh one, so a
//! decision can be recognized as being about a source that moved. The fingerprint
//! covers the row set, the column shape this build expects, both file trees and
//! whether the legacy database exists at all. `schema_shape` is a read-side
//! constant, not an observation: a source whose shape is unsupported or
//! unreadable produces the same fingerprint as an equivalent usable empty
//! database, so those changes are outside the fingerprint. The confirmation
//! surface must re-read `preview.diagnostics` before applying a decision.
//!
//! # Remote scenarios
//!
//! This contract is workspace-local and host-local: it carries no path, no device
//! identity and no delivery profile, and it reads nothing itself. A remote
//! workspace stays unsupported here exactly as it does in the read-only preview
//! that feeds it.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

#[cfg(all(feature = "workspace-intelligence-cognition", feature = "agent-runtime"))]
use super::legacy_preview::LegacySourceFingerprint;

/// Largest number of assignments one decision may carry.
///
/// Both the number of assignments and the length of one assignment field are
/// bounded, so one confirmation cannot turn into an unbounded record; the counts
/// are far above any real legacy Memory row count.
pub(crate) const MAX_ASSIGNMENTS: usize = 10_000;

/// Largest accepted length of one assignment field, in characters.
///
/// It covers the item key and the target workspace id: both are stable
/// identifiers, so a longer value is a malformed payload rather than a large one.
pub(crate) const MAX_ASSIGNMENT_FIELD_CHARS: usize = 1024;

/// Largest accepted idempotency key length, in characters.
const MAX_IDEMPOTENCY_KEY_CHARS: usize = 128;

/// Persisted assignment of one legacy item.
///
/// The variants are exhaustive on purpose: an item is either kept shared, moved
/// into one workspace, or deferred, and a consumer must handle all three.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Assignment {
    /// Keep the item shared across workspaces.
    KeepShared { key: String },
    /// Assign the item to exactly one workspace, by stable workspace id.
    AssignTo { key: String, workspace: String },
    /// Do not recall the item for now.
    DeferRecall { key: String },
}

impl Assignment {
    /// Stable key of the legacy item this assignment is about.
    pub(crate) fn key(&self) -> &str {
        match self {
            Self::KeepShared { key } | Self::AssignTo { key, .. } | Self::DeferRecall { key } => {
                key
            }
        }
    }

    /// Stable machine-readable kind code, also the persisted `kind` value.
    pub(crate) fn kind_code(&self) -> &'static str {
        match self {
            Self::KeepShared { .. } => "keep_shared",
            Self::AssignTo { .. } => "assign_to",
            Self::DeferRecall { .. } => "defer_recall",
        }
    }

    /// Target workspace of an assignment that moves an item, if any.
    fn workspace(&self) -> Option<&str> {
        match self {
            Self::AssignTo { workspace, .. } => Some(workspace),
            Self::KeepShared { .. } | Self::DeferRecall { .. } => None,
        }
    }
}

/// Source fingerprint a decision was made on.
///
/// It is a separate persisted shape from the read-only preview fingerprint on
/// purpose: the decision outlives the preview code, so the stored field set must
/// not change silently when the preview projection changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationSourceFingerprint {
    /// Number of legacy rows the decision saw.
    pub(crate) row_count: u64,
    /// Digest over every projected field of every legacy row.
    pub(crate) rows_digest: String,
    /// The projected legacy column list in schema order.
    pub(crate) schema_shape: String,
    /// Hash over the derived legacy files.
    pub(crate) derived_tree_hash: String,
    /// Hash over the hand-written note files.
    pub(crate) notes_tree_hash: String,
    /// Whether the legacy database existed when the decision was made.
    ///
    /// An absent database and an equivalent empty one produce the same rows, shape
    /// and trees, so without this bit a decision made on a missing database would
    /// look current after the database appeared empty.
    pub(crate) db_present: bool,
}

#[cfg(all(feature = "workspace-intelligence-cognition", feature = "agent-runtime"))]
impl MigrationSourceFingerprint {
    /// Projects the read-only preview fingerprint into the persisted shape.
    pub(crate) fn from_preview(fingerprint: &LegacySourceFingerprint) -> Self {
        Self {
            row_count: fingerprint.row_count,
            rows_digest: fingerprint.rows_digest.clone(),
            schema_shape: fingerprint.schema_shape.clone(),
            derived_tree_hash: fingerprint.derived_tree_hash.clone(),
            notes_tree_hash: fingerprint.notes_tree_hash.clone(),
            db_present: fingerprint.db_present,
        }
    }
}

/// One durable migration decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationDecision {
    /// Caller-supplied identity of this decision, stable across retries.
    pub(crate) idempotency_key: String,
    /// When the user decided, in Unix milliseconds. Stored for diagnostics only:
    /// it is not part of [`migration_payload_digest`].
    pub(crate) decided_at_unix_ms: i64,
    /// Source the decision was made on.
    pub(crate) source: MigrationSourceFingerprint,
    /// One assignment per legacy item.
    pub(crate) assignments: Vec<Assignment>,
}

/// Why a decision cannot be stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationValidationError {
    /// The idempotency key is empty or whitespace only.
    BlankIdempotencyKey,
    /// The idempotency key is longer than the accepted bound.
    IdempotencyKeyTooLong,
    /// The decision carries more assignments than the accepted bound.
    TooManyAssignments,
    /// Two assignments name the same legacy item.
    DuplicateKey,
    /// An assignment names no legacy item.
    BlankKey,
    /// An assignment moves an item into no workspace.
    BlankWorkspace,
    /// An assignment key or target workspace is longer than the accepted bound.
    FieldTooLong,
}

impl MigrationValidationError {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BlankIdempotencyKey => "blank_idempotency_key",
            Self::IdempotencyKeyTooLong => "idempotency_key_too_long",
            Self::TooManyAssignments => "too_many_assignments",
            Self::DuplicateKey => "duplicate_key",
            Self::BlankKey => "blank_key",
            Self::BlankWorkspace => "blank_workspace",
            Self::FieldTooLong => "field_too_long",
        }
    }
}

/// Validates one decision before it can be stored.
///
/// The checks run in a fixed order — key, size, then each assignment in input
/// order, where one assignment is checked for a blank key, a duplicate key, a
/// blank target and an oversized key or target — so the same invalid decision
/// always reports the same reason.
pub(crate) fn validate_migration(
    decision: &MigrationDecision,
) -> Result<(), MigrationValidationError> {
    if decision.idempotency_key.trim().is_empty() {
        return Err(MigrationValidationError::BlankIdempotencyKey);
    }
    if decision.idempotency_key.chars().count() > MAX_IDEMPOTENCY_KEY_CHARS {
        return Err(MigrationValidationError::IdempotencyKeyTooLong);
    }
    if decision.assignments.len() > MAX_ASSIGNMENTS {
        return Err(MigrationValidationError::TooManyAssignments);
    }

    let mut seen: HashSet<&str> = HashSet::new();
    for assignment in &decision.assignments {
        let key = assignment.key();
        if key.trim().is_empty() {
            return Err(MigrationValidationError::BlankKey);
        }
        if !seen.insert(key) {
            return Err(MigrationValidationError::DuplicateKey);
        }
        if key.chars().count() > MAX_ASSIGNMENT_FIELD_CHARS {
            return Err(MigrationValidationError::FieldTooLong);
        }
        if let Some(workspace) = assignment.workspace() {
            if workspace.trim().is_empty() {
                return Err(MigrationValidationError::BlankWorkspace);
            }
            if workspace.chars().count() > MAX_ASSIGNMENT_FIELD_CHARS {
                return Err(MigrationValidationError::FieldTooLong);
            }
        }
    }

    Ok(())
}

/// Identity of one payload, as a hex SHA-256 digest.
///
/// The digest covers the idempotency key, every source fingerprint field and the
/// assignments in sorted order, each field length-prefixed so two different field
/// splits cannot collide. The decision time is excluded: a replayed confirmation
/// keeps its identity even though it carries a new timestamp.
pub(crate) fn migration_payload_digest(decision: &MigrationDecision) -> String {
    let mut hasher = Sha256::new();
    update_digest_field(&mut hasher, decision.idempotency_key.as_bytes());
    update_digest_field(&mut hasher, &decision.source.row_count.to_le_bytes());
    update_digest_field(&mut hasher, decision.source.rows_digest.as_bytes());
    update_digest_field(&mut hasher, decision.source.schema_shape.as_bytes());
    update_digest_field(&mut hasher, decision.source.derived_tree_hash.as_bytes());
    update_digest_field(&mut hasher, decision.source.notes_tree_hash.as_bytes());
    update_digest_field(&mut hasher, &[u8::from(decision.source.db_present)]);

    let mut assignments: Vec<&Assignment> = decision.assignments.iter().collect();
    assignments.sort_by(|left, right| {
        (left.key(), left.kind_code(), left.workspace())
            .cmp(&(right.key(), right.kind_code(), right.workspace()))
    });
    update_digest_field(&mut hasher, &(assignments.len() as u64).to_le_bytes());
    for assignment in assignments {
        update_digest_field(&mut hasher, assignment.kind_code().as_bytes());
        update_digest_field(&mut hasher, assignment.key().as_bytes());
        match assignment.workspace() {
            Some(workspace) => {
                update_digest_field(&mut hasher, &[1]);
                update_digest_field(&mut hasher, workspace.as_bytes());
            }
            None => update_digest_field(&mut hasher, &[0]),
        }
    }

    format!("{:x}", hasher.finalize())
}

/// Length-prefixed digest update, so field boundaries cannot be confused.
fn update_digest_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// What a repeated confirmation means against the stored decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationOutcome {
    /// Store the incoming decision.
    ///
    /// This assumes the incoming decision is the newest confirmation for that
    /// scope: [`reconcile_existing`] does not compare `decided_at_unix_ms`, so a
    /// late confirmation carrying a different idempotency key overwrites a newer
    /// decision. The confirmation surface must keep at most one confirmation per
    /// scope in flight; that is a precondition, not something this outcome checks.
    Apply,
    /// The stored decision already is this decision; nothing is rewritten.
    Unchanged,
    /// The same idempotency key was used for a different payload. The stored
    /// decision is kept as is and the caller must resolve the difference.
    PayloadConflict,
}

/// Decides what an incoming decision means next to the stored one.
///
/// The rule compares the idempotency key and the payload identity only. It never
/// reads the decision time, so it cannot tell a late confirmation from a current
/// one: only one confirmation per scope may be in flight.
pub(crate) fn reconcile_existing(
    existing: Option<&MigrationDecision>,
    incoming: &MigrationDecision,
) -> MigrationOutcome {
    let Some(existing) = existing else {
        return MigrationOutcome::Apply;
    };
    if existing.idempotency_key != incoming.idempotency_key {
        return MigrationOutcome::Apply;
    }
    if migration_payload_digest(existing) == migration_payload_digest(incoming) {
        return MigrationOutcome::Unchanged;
    }
    MigrationOutcome::PayloadConflict
}

/// Encodes one decision as the JSON object stored under the record's `migration`
/// key.
///
/// The field names are the persisted contract, so they are written explicitly
/// instead of being derived from the Rust field names. Encoding does not validate:
/// running [`validate_migration`] first is the caller's step. The other end of the
/// round trip is checked where the payload is accepted — [`decode_migration`]
/// rejects an unknown shape, and the control plan applies it before any write.
pub(crate) fn encode_migration(decision: &MigrationDecision) -> Value {
    let source = &decision.source;
    let assignments: Vec<Value> = decision.assignments.iter().map(encode_assignment).collect();

    json!({
        "idempotency_key": decision.idempotency_key.as_str(),
        "decided_at_unix_ms": decision.decided_at_unix_ms,
        "source": {
            "row_count": source.row_count,
            "rows_digest": source.rows_digest.as_str(),
            "schema_shape": source.schema_shape.as_str(),
            "derived_tree_hash": source.derived_tree_hash.as_str(),
            "notes_tree_hash": source.notes_tree_hash.as_str(),
            "db_present": source.db_present,
        },
        "assignments": assignments,
    })
}

/// Encodes one assignment.
fn encode_assignment(assignment: &Assignment) -> Value {
    let kind = assignment.kind_code();
    match assignment {
        Assignment::KeepShared { key } => json!({ "kind": kind, "key": key.as_str() }),
        Assignment::AssignTo { key, workspace } => json!({
            "kind": kind,
            "key": key.as_str(),
            "workspace": workspace.as_str(),
        }),
        Assignment::DeferRecall { key } => json!({ "kind": kind, "key": key.as_str() }),
    }
}

/// Why a stored value is not a decision.
///
/// Codes are stable and never echo a stored value, so they are safe for logs and
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MigrationDecodeError {
    /// A required field is absent.
    MissingField(&'static str),
    /// A field is present with the wrong JSON type.
    WrongType(&'static str),
    /// The value cannot be a decision at all: not an object, or an assignment
    /// whose kind this build does not know.
    Shape,
}

impl MigrationDecodeError {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::MissingField(_) => "missing_field",
            Self::WrongType(_) => "wrong_type",
            Self::Shape => "shape",
        }
    }

    /// The offending field, when the error names one.
    pub(crate) fn field(self) -> Option<&'static str> {
        match self {
            Self::MissingField(field) | Self::WrongType(field) => Some(field),
            Self::Shape => None,
        }
    }
}

/// Decodes the value stored under the record's `migration` key.
///
/// This is the shape contract only: it does not re-run [`validate_migration`],
/// because a decoded decision is a historical record and a later build may accept
/// a payload this build would refuse to write.
pub(crate) fn decode_migration(value: &Value) -> Result<MigrationDecision, MigrationDecodeError> {
    let fields = value
        .as_object()
        .ok_or(MigrationDecodeError::WrongType("migration"))?;

    let source = match fields.get("source") {
        None => return Err(MigrationDecodeError::MissingField("source")),
        Some(Value::Object(source)) => source,
        Some(_) => return Err(MigrationDecodeError::WrongType("source")),
    };

    let assignments = match fields.get("assignments") {
        None => return Err(MigrationDecodeError::MissingField("assignments")),
        Some(Value::Array(items)) => items,
        Some(_) => return Err(MigrationDecodeError::WrongType("assignments")),
    };
    let mut decoded = Vec::with_capacity(assignments.len());
    for assignment in assignments {
        decoded.push(decode_assignment(assignment)?);
    }

    Ok(MigrationDecision {
        idempotency_key: string_field(fields, "idempotency_key", "idempotency_key")?,
        decided_at_unix_ms: integer_field(fields, "decided_at_unix_ms", "decided_at_unix_ms")?,
        source: MigrationSourceFingerprint {
            row_count: unsigned_field(source, "row_count", "source.row_count")?,
            rows_digest: string_field(source, "rows_digest", "source.rows_digest")?,
            schema_shape: string_field(source, "schema_shape", "source.schema_shape")?,
            derived_tree_hash: string_field(
                source,
                "derived_tree_hash",
                "source.derived_tree_hash",
            )?,
            notes_tree_hash: string_field(source, "notes_tree_hash", "source.notes_tree_hash")?,
            // Required, not optional: the persisted shape carries it, and a value
            // without it cannot say whether the database existed.
            db_present: boolean_field(source, "db_present", "source.db_present")?,
        },
        assignments: decoded,
    })
}

/// Decodes one assignment, refusing a kind this build does not know.
fn decode_assignment(value: &Value) -> Result<Assignment, MigrationDecodeError> {
    let Value::Object(fields) = value else {
        return Err(MigrationDecodeError::Shape);
    };
    let kind = string_field(fields, "kind", "kind")?;
    let key = string_field(fields, "key", "key")?;

    match kind.as_str() {
        "keep_shared" => Ok(Assignment::KeepShared { key }),
        "defer_recall" => Ok(Assignment::DeferRecall { key }),
        "assign_to" => Ok(Assignment::AssignTo {
            key,
            workspace: string_field(fields, "workspace", "workspace")?,
        }),
        // Never echo the stored value: an unknown kind is a shape fault.
        _ => Err(MigrationDecodeError::Shape),
    }
}

/// Reads one string field, reporting `path` in the error.
///
/// `key` is the lookup key inside `fields`; `path` is the dotted path the error
/// names, so a nested fault reads as `source.rows_digest` rather than as an
/// ambiguous `rows_digest`.
fn string_field(
    fields: &Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<String, MigrationDecodeError> {
    match fields.get(key) {
        None => Err(MigrationDecodeError::MissingField(path)),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(MigrationDecodeError::WrongType(path)),
    }
}

/// Reads one unsigned integer field, reporting `path` in the error.
fn unsigned_field(
    fields: &Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<u64, MigrationDecodeError> {
    match fields.get(key) {
        None => Err(MigrationDecodeError::MissingField(path)),
        Some(value) => value.as_u64().ok_or(MigrationDecodeError::WrongType(path)),
    }
}

/// Reads one signed integer field, reporting `path` in the error.
fn integer_field(
    fields: &Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<i64, MigrationDecodeError> {
    match fields.get(key) {
        None => Err(MigrationDecodeError::MissingField(path)),
        Some(value) => value.as_i64().ok_or(MigrationDecodeError::WrongType(path)),
    }
}

/// Reads one boolean field, reporting `path` in the error.
fn boolean_field(
    fields: &Map<String, Value>,
    key: &str,
    path: &'static str,
) -> Result<bool, MigrationDecodeError> {
    match fields.get(key) {
        None => Err(MigrationDecodeError::MissingField(path)),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(MigrationDecodeError::WrongType(path)),
    }
}

/// Whether the source moved since the decision was made.
///
/// Only the source matters: a decision stays current while the source it decided
/// on is unchanged, whatever the current preview diagnostics say.
#[cfg(all(feature = "workspace-intelligence-cognition", feature = "agent-runtime"))]
pub(crate) fn is_stale(decision: &MigrationDecision, now: &LegacySourceFingerprint) -> bool {
    MigrationSourceFingerprint::from_preview(now) != decision.source
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(seed: &str) -> MigrationSourceFingerprint {
        MigrationSourceFingerprint {
            row_count: 1,
            rows_digest: format!("rows-{seed}"),
            schema_shape: "thread_id,workspace_path".to_string(),
            derived_tree_hash: "derived".to_string(),
            notes_tree_hash: "notes".to_string(),
            db_present: true,
        }
    }

    fn decision(assignments: Vec<Assignment>) -> MigrationDecision {
        MigrationDecision {
            idempotency_key: "decision-1".to_string(),
            decided_at_unix_ms: 1_700_000_000_000,
            source: source("a"),
            assignments,
        }
    }

    #[test]
    fn validation_rejects_each_unusable_decision() {
        let mut blank_key = decision(Vec::new());
        blank_key.idempotency_key = "   ".to_string();
        assert_eq!(
            validate_migration(&blank_key),
            Err(MigrationValidationError::BlankIdempotencyKey)
        );

        let mut long_key = decision(Vec::new());
        long_key.idempotency_key = "k".repeat(MAX_IDEMPOTENCY_KEY_CHARS + 1);
        assert_eq!(
            validate_migration(&long_key),
            Err(MigrationValidationError::IdempotencyKeyTooLong)
        );

        let mut too_many = decision(Vec::new());
        too_many.assignments = (0..=MAX_ASSIGNMENTS)
            .map(|index| Assignment::DeferRecall {
                key: format!("item-{index}"),
            })
            .collect();
        assert_eq!(
            validate_migration(&too_many),
            Err(MigrationValidationError::TooManyAssignments)
        );

        let duplicate = decision(vec![
            Assignment::DeferRecall {
                key: "item-a".to_string(),
            },
            Assignment::KeepShared {
                key: "item-a".to_string(),
            },
        ]);
        assert_eq!(
            validate_migration(&duplicate),
            Err(MigrationValidationError::DuplicateKey)
        );

        let blank_item = decision(vec![Assignment::KeepShared {
            key: "  ".to_string(),
        }]);
        assert_eq!(
            validate_migration(&blank_item),
            Err(MigrationValidationError::BlankKey)
        );

        let blank_workspace = decision(vec![Assignment::AssignTo {
            key: "item-a".to_string(),
            workspace: "".to_string(),
        }]);
        assert_eq!(
            validate_migration(&blank_workspace),
            Err(MigrationValidationError::BlankWorkspace)
        );

        assert_eq!(validate_migration(&decision(Vec::new())), Ok(()));
        assert_eq!(
            validate_migration(&decision(vec![
                Assignment::KeepShared {
                    key: "item-a".to_string(),
                },
                Assignment::AssignTo {
                    key: "item-b".to_string(),
                    workspace: "workspace-1".to_string(),
                },
                Assignment::DeferRecall {
                    key: "item-c".to_string(),
                },
            ])),
            Ok(())
        );
    }

    #[test]
    fn the_idempotency_key_bound_is_inclusive() {
        let mut at_bound = decision(Vec::new());
        at_bound.idempotency_key = "k".repeat(MAX_IDEMPOTENCY_KEY_CHARS);
        assert_eq!(validate_migration(&at_bound), Ok(()));
    }

    #[test]
    fn an_oversized_assignment_field_is_refused() {
        // The bound itself is accepted for both the item key and the target.
        let at_bound = decision(vec![
            Assignment::KeepShared {
                key: "k".repeat(MAX_ASSIGNMENT_FIELD_CHARS),
            },
            Assignment::AssignTo {
                key: "item-b".to_string(),
                workspace: "w".repeat(MAX_ASSIGNMENT_FIELD_CHARS),
            },
        ]);
        assert_eq!(validate_migration(&at_bound), Ok(()));

        let oversized_key = decision(vec![Assignment::DeferRecall {
            key: "k".repeat(MAX_ASSIGNMENT_FIELD_CHARS + 1),
        }]);
        assert_eq!(
            validate_migration(&oversized_key),
            Err(MigrationValidationError::FieldTooLong)
        );

        let oversized_workspace = decision(vec![Assignment::AssignTo {
            key: "item-a".to_string(),
            workspace: "w".repeat(MAX_ASSIGNMENT_FIELD_CHARS + 1),
        }]);
        assert_eq!(
            validate_migration(&oversized_workspace),
            Err(MigrationValidationError::FieldTooLong)
        );
    }

    #[test]
    fn validation_codes_are_stable() {
        assert_eq!(
            MigrationValidationError::BlankIdempotencyKey.as_str(),
            "blank_idempotency_key"
        );
        assert_eq!(
            MigrationValidationError::IdempotencyKeyTooLong.as_str(),
            "idempotency_key_too_long"
        );
        assert_eq!(
            MigrationValidationError::TooManyAssignments.as_str(),
            "too_many_assignments"
        );
        assert_eq!(
            MigrationValidationError::DuplicateKey.as_str(),
            "duplicate_key"
        );
        assert_eq!(MigrationValidationError::BlankKey.as_str(), "blank_key");
        assert_eq!(
            MigrationValidationError::BlankWorkspace.as_str(),
            "blank_workspace"
        );
        assert_eq!(
            MigrationValidationError::FieldTooLong.as_str(),
            "field_too_long"
        );
    }

    #[test]
    fn assignment_kind_codes_are_stable() {
        assert_eq!(
            Assignment::KeepShared {
                key: "item-a".to_string()
            }
            .kind_code(),
            "keep_shared"
        );
        assert_eq!(
            Assignment::AssignTo {
                key: "item-a".to_string(),
                workspace: "workspace-1".to_string(),
            }
            .kind_code(),
            "assign_to"
        );
        assert_eq!(
            Assignment::DeferRecall {
                key: "item-a".to_string()
            }
            .kind_code(),
            "defer_recall"
        );
        assert_eq!(
            Assignment::DeferRecall {
                key: "item-a".to_string()
            }
            .key(),
            "item-a"
        );
    }

    #[test]
    fn the_payload_digest_is_independent_of_assignment_order() {
        let first = decision(vec![
            Assignment::AssignTo {
                key: "item-b".to_string(),
                workspace: "workspace-1".to_string(),
            },
            Assignment::KeepShared {
                key: "item-a".to_string(),
            },
        ]);
        let second = decision(vec![
            Assignment::KeepShared {
                key: "item-a".to_string(),
            },
            Assignment::AssignTo {
                key: "item-b".to_string(),
                workspace: "workspace-1".to_string(),
            },
        ]);

        assert_eq!(
            migration_payload_digest(&first),
            migration_payload_digest(&second)
        );
        assert_eq!(migration_payload_digest(&first).len(), 64);

        // A changed assignment, workspace or decision time is a different payload
        // only where the identity is defined to cover it.
        let mut other_workspace = first.clone();
        other_workspace.assignments[0] = Assignment::AssignTo {
            key: "item-b".to_string(),
            workspace: "workspace-2".to_string(),
        };
        assert_ne!(
            migration_payload_digest(&first),
            migration_payload_digest(&other_workspace)
        );

        let mut later = first.clone();
        later.decided_at_unix_ms += 1;
        assert_eq!(migration_payload_digest(&first), migration_payload_digest(&later));

        let mut absent_database = first.clone();
        absent_database.source.db_present = false;
        assert_ne!(
            migration_payload_digest(&first),
            migration_payload_digest(&absent_database)
        );
    }

    #[test]
    fn reconcile_applies_unchanged_and_conflicts_the_stored_decision() {
        let incoming = decision(vec![Assignment::KeepShared {
            key: "item-a".to_string(),
        }]);

        assert_eq!(
            reconcile_existing(None, &incoming),
            MigrationOutcome::Apply
        );

        // A new idempotency key is a new decision and replaces the stored one.
        let mut replaced = incoming.clone();
        replaced.idempotency_key = "decision-2".to_string();
        assert_eq!(
            reconcile_existing(Some(&incoming), &replaced),
            MigrationOutcome::Apply
        );

        // The same key with the same payload is a replay, even with a new time.
        let mut replay = incoming.clone();
        replay.decided_at_unix_ms += 5_000;
        assert_eq!(
            reconcile_existing(Some(&incoming), &replay),
            MigrationOutcome::Unchanged
        );

        // The same key with a different payload must not be overwritten.
        let mut conflicting = incoming.clone();
        conflicting.assignments = vec![Assignment::DeferRecall {
            key: "item-a".to_string(),
        }];
        assert_eq!(
            reconcile_existing(Some(&incoming), &conflicting),
            MigrationOutcome::PayloadConflict
        );
    }

    #[test]
    fn an_encoded_decision_decodes_back_to_itself() {
        let original = decision(vec![
            Assignment::KeepShared {
                key: "item-a".to_string(),
            },
            Assignment::AssignTo {
                key: "item-b".to_string(),
                workspace: "workspace-1".to_string(),
            },
            Assignment::DeferRecall {
                key: "item-c".to_string(),
            },
        ]);

        let encoded = encode_migration(&original);
        assert!(encoded.is_object());
        assert_eq!(encoded["source"]["db_present"], Value::Bool(true));
        assert_eq!(
            encoded["assignments"][1]["kind"],
            Value::String("assign_to".to_string())
        );

        assert_eq!(decode_migration(&encoded), Ok(original));
    }

    #[test]
    fn decoding_refuses_a_missing_field_a_wrong_type_and_an_unknown_shape() {
        let encoded = encode_migration(&decision(Vec::new()));

        let mut missing = encoded.clone();
        missing
            .as_object_mut()
            .expect("an encoded decision is an object")
            .remove("idempotency_key");
        assert_eq!(
            decode_migration(&missing),
            Err(MigrationDecodeError::MissingField("idempotency_key"))
        );

        let mut missing_database_bit = encoded.clone();
        missing_database_bit["source"]
            .as_object_mut()
            .expect("the source is an object")
            .remove("db_present");
        assert_eq!(
            decode_migration(&missing_database_bit),
            Err(MigrationDecodeError::MissingField("source.db_present"))
        );

        let mut wrong_type = encoded.clone();
        wrong_type["decided_at_unix_ms"] = Value::String("yesterday".to_string());
        assert_eq!(
            decode_migration(&wrong_type),
            Err(MigrationDecodeError::WrongType("decided_at_unix_ms"))
        );

        let mut not_an_object = encoded;
        not_an_object["assignments"] = json!([{ "kind": "move_somewhere", "key": "item-a" }]);
        assert_eq!(
            decode_migration(&not_an_object),
            Err(MigrationDecodeError::Shape)
        );

        assert_eq!(
            decode_migration(&Value::Null),
            Err(MigrationDecodeError::WrongType("migration"))
        );
    }

    #[test]
    fn decode_codes_are_stable_and_name_the_offending_field() {
        assert_eq!(
            MigrationDecodeError::MissingField("idempotency_key").as_str(),
            "missing_field"
        );
        assert_eq!(
            MigrationDecodeError::WrongType("source").as_str(),
            "wrong_type"
        );
        assert_eq!(MigrationDecodeError::Shape.as_str(), "shape");

        assert_eq!(
            MigrationDecodeError::MissingField("idempotency_key").field(),
            Some("idempotency_key")
        );
        assert_eq!(
            MigrationDecodeError::WrongType("source").field(),
            Some("source")
        );
        assert_eq!(MigrationDecodeError::Shape.field(), None);
    }

    #[cfg(all(feature = "workspace-intelligence-cognition", feature = "agent-runtime"))]
    mod preview_fingerprint {
        use super::*;
        use crate::agentic::memories::workspace::MEMORY_SUMMARY_FILE_NAME;
        use crate::service::workspace_intelligence::legacy_preview::read_legacy_preview;

        fn preview_fingerprint(root: &std::path::Path, db_exists: bool) -> LegacySourceFingerprint {
            let memory_root = root.join("memories");
            std::fs::create_dir_all(&memory_root).expect("create the memory root");
            std::fs::write(memory_root.join(MEMORY_SUMMARY_FILE_NAME), "summary")
                .expect("write a derived file");
            let db_path = root.join("memories.sqlite");
            if db_exists {
                let connection = rusqlite::Connection::open(&db_path).expect("create a database");
                drop(connection);
            }
            read_legacy_preview(&db_path, &memory_root).source
        }

        #[test]
        fn the_recorded_source_projects_the_preview_fingerprint() {
            let root = tempfile::tempdir().expect("temporary root");
            let fingerprint = preview_fingerprint(root.path(), true);

            let projected = MigrationSourceFingerprint::from_preview(&fingerprint);

            assert_eq!(projected.row_count, fingerprint.row_count);
            assert_eq!(projected.rows_digest, fingerprint.rows_digest);
            assert_eq!(projected.schema_shape, fingerprint.schema_shape);
            assert_eq!(projected.derived_tree_hash, fingerprint.derived_tree_hash);
            assert_eq!(projected.notes_tree_hash, fingerprint.notes_tree_hash);
            assert!(projected.db_present);
        }

        #[test]
        fn a_decision_is_stale_when_the_database_appears() {
            let root = tempfile::tempdir().expect("temporary root");
            let absent = preview_fingerprint(root.path(), false);
            let present = preview_fingerprint(root.path(), true);

            assert!(!absent.db_present);
            assert!(present.db_present);
            assert_ne!(absent, present);

            let mut recorded = decision(Vec::new());
            recorded.source = MigrationSourceFingerprint::from_preview(&absent);

            // The stored decision was made on a missing database, so the same
            // now-empty but existing database is a moved source.
            assert!(is_stale(&recorded, &present));

            recorded.source = MigrationSourceFingerprint::from_preview(&present);
            assert!(!is_stale(&recorded, &present));
        }
    }
}
