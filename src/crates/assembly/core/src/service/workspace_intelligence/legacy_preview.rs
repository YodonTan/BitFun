//! Read-only preview of the legacy Memory rows and files for workspace
//! intelligence WP2.3.
//!
//! # What this module is
//!
//! It projects two legacy sources into one preview struct and one source
//! fingerprint:
//!
//! - which legacy rows can be attributed to a local workspace root, and which
//!   cannot;
//! - which hand-written notes exist and why none of them is attributable;
//! - a stable fingerprint of the exact source the preview was built from — the row
//!   count, every projected row field, the projected column shape and both file
//!   trees — so a later pass can tell that the source moved and the preview is
//!   stale.
//!
//! It is read-only in the strict sense: it never creates a file or a directory,
//! never repairs or recreates a schema, never drops a table, never runs a
//! statement that writes, never takes an index lock, never calls a model, never
//! reads a clock and never reuses the offline legacy migration engine. Every
//! failure becomes a typed diagnostic; nothing here panics on IO or SQLite
//! errors, and nothing here deletes or rewrites user data it cannot parse.
//!
//! # Three layers, one authority
//!
//! - L1 rows in `stage1_outputs` are authoritative. The row's own
//!   `workspace_path` is the only direct evidence of attribution; there is no
//!   path-to-scope derivation here, no heuristic and no fallback guess. A row
//!   whose path cannot be normalized is listed as unattributed.
//! - L2 hand-written notes under the ad-hoc notes directory are pure human
//!   input. They carry no workspace field, so every note is unattributed by
//!   construction rather than by a failed lookup.
//! - L3 derived files (`memory_summary.md`, `raw_memories.md`, `MEMORY.md` and
//!   everything under `rollout_summaries/`) are shadows of L1. They are never
//!   counted as attribution evidence and never produce a candidate. They only
//!   feed the derived tree hash so a preview can be recognized as stale.
//!
//! The fingerprint therefore proves "the source is still the one this preview
//! read", not "the projection is still correct".
//!
//! # What the preview deliberately does not decide
//!
//! The preview lists candidates and reasons only. It does not pre-fill the
//! per-row migration decision (keep, skip or defer) that the confirmation
//! surface owns, and it carries no scope identifier, no action and no side
//! effect. A normalized workspace string is an attribution fact, not a scope:
//! naming the scope a candidate belongs to stays an obligation of the
//! confirmation slice that consumes this preview.
//!
//! # Remote scenarios
//!
//! This module reads one local filesystem path pair through the caller. It adds
//! no remote-workspace path resolution, no device identity and no delivery
//! profile behavior, and a remote workspace remains unsupported here instead of
//! silently reading a controller-side path.

use crate::agentic::memories::workspace::{
    ad_hoc_notes_dir, MEMORY_FILE_NAME, MEMORY_SUMMARY_FILE_NAME, RAW_MEMORIES_FILENAME,
    ROLLOUT_SUMMARIES_DIR_NAME,
};
use openbitfun_services_core::memory_store::{
    read_memory_store_snapshot, MemoryRecord, MemoryStoreError, EXPECTED_STAGE1_COLUMNS,
};
use openbitfun_services_core::workspace_identity::normalize_local_workspace_root_for_stable_id;
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Read-only, no-mutex flags, the same shape the cognition partition reader
/// uses for an existing record.
///
/// `SQLITE_OPEN_READ_ONLY` is the whole point of this module: an open that
/// cannot write cannot create, repair, migrate or drop anything.
const READ_FLAGS: OpenFlags =
    OpenFlags::SQLITE_OPEN_READ_ONLY.union(OpenFlags::SQLITE_OPEN_NO_MUTEX);

/// Depth bound for the two read-only tree walks.
///
/// The legacy Memory layout is flat, so this bound is never reached in practice;
/// it exists so an unexpected deep tree, a junction or a reparse point cycle
/// cannot turn a read into an unbounded walk.
const MAX_TREE_DEPTH: usize = 8;

/// One stable fingerprint of the legacy source a preview was built from.
///
/// The five parts cover the five ways the source can move, so a preview is called
/// stale exactly when something the preview projected changed:
///
/// - `row_count` covers a row being added or removed;
/// - `rows_digest` covers any projected field of an existing row being edited:
///   the row identifier, its raw workspace path, its source timestamp and its body;
/// - `schema_shape` covers the projected column list changing;
/// - `derived_tree_hash` covers the L3 derived files changing;
/// - `notes_tree_hash` covers the L2 note files changing.
///
/// Two fingerprints compare equal only when all five are equal, so an unrelated
/// file elsewhere in the Memory root, or a path that merely looks similar, cannot
/// make a preview look stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacySourceFingerprint {
    /// Number of L1 rows the preview saw, or zero when the database was absent
    /// or unsupported.
    pub(crate) row_count: u64,
    /// Digest over every projected field of every L1 row the preview saw.
    ///
    /// [`project_preview`] owns this value: it aggregates one digest per row in
    /// row-identifier order, so a change to any field the preview projects — the
    /// identifier, the raw workspace path, the source timestamp or the body —
    /// changes the digest, and the result stays independent of the order the rows
    /// were read in. Zero rows produce the digest of no bytes.
    pub(crate) rows_digest: String,
    /// The projected `stage1_outputs` column list in schema order.
    ///
    /// The shape is recorded as a value rather than as a boole: a reader that
    /// understands a different list produces a different fingerprint instead of
    /// silently reusing this one.
    pub(crate) schema_shape: String,
    /// Hash over the L3 derived files.
    pub(crate) derived_tree_hash: String,
    /// Hash over the L2 note files.
    pub(crate) notes_tree_hash: String,
}

impl LegacySourceFingerprint {
    /// Builds the fingerprint parts that do not depend on the rows.
    ///
    /// `rows_digest` is left empty on purpose: it is derived from the rows
    /// themselves, and [`project_preview`] is its single owner. A fingerprint built
    /// here is only observed as an argument to that function.
    fn of_source(row_count: u64, derived_tree_hash: String, notes_tree_hash: String) -> Self {
        Self {
            row_count,
            rows_digest: String::new(),
            schema_shape: EXPECTED_STAGE1_COLUMNS.join(","),
            derived_tree_hash,
            notes_tree_hash,
        }
    }
}

/// The narrow projection of one L1 row this module reasons about.
///
/// It keeps the fields attribution and staleness need and drops the rest, so no
/// other column can leak into the preview by accident.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyRow {
    pub(crate) thread_id: String,
    pub(crate) workspace_path: String,
    pub(crate) source_updated_at: i64,
    pub(crate) raw_memory: String,
    pub(crate) rollout_summary: String,
}

impl LegacyRow {
    /// Projects one stored record into the narrow row shape.
    fn from_record(record: &MemoryRecord) -> Self {
        Self {
            thread_id: record.session_id.clone(),
            workspace_path: record.workspace_path.clone(),
            source_updated_at: record.source_updated_at_unix_secs,
            raw_memory: record.raw_memory.clone(),
            rollout_summary: record.rollout_summary.clone(),
        }
    }
}

/// One attributed candidate: a legacy row whose workspace path normalized.
///
/// The content hash travels instead of the content, so a preview can be logged,
/// compared and cached without carrying memory bodies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AttributedCandidate {
    pub(crate) thread_id: String,
    pub(crate) normalized_workspace: String,
    pub(crate) source_updated_at: i64,
    pub(crate) content_hash: String,
}

/// Which legacy layer one unattributed item came from.
///
/// The declaration order is also the ordering used to make a preview
/// deterministic, so it must not be reordered casually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnattributedKind {
    LegacyRow,
    AdHocNote,
}

/// Why one item could not be attributed to a workspace root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnattributedReason {
    /// The row names a path that does not normalize to a stable local root.
    ///
    /// Normalization requires the path to exist on the filesystem at the moment of
    /// this read, so a workspace that was deleted, a disk that is offline and a
    /// network drive that is not mounted all land here for a row that was valid
    /// when it was written. A consumer must not read this reason as "was never a
    /// workspace".
    UnnormalizablePath,
    /// The note has no workspace field at all, so no lookup could attribute it.
    NoWorkspaceField,
}

/// One item that stayed unattributed, with its stable key and typed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UnattributedItem {
    pub(crate) kind: UnattributedKind,
    /// Row thread id, or the slash-normalized relative note path.
    pub(crate) key: String,
    pub(crate) reason: UnattributedReason,
}

/// One typed preview diagnostic.
///
/// A diagnostic never replaces the preview: a caller always receives a preview,
/// and the diagnostics say which parts of the source it could not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum PreviewDiagnostic {
    /// The database file does not exist. It is never created by this module.
    DbAbsent,
    /// The database exists but does not match the expected Memory store shape. It
    /// is never repaired, recreated or dropped.
    SchemaUnsupported,
    /// The ad-hoc notes directory does not exist. It is never created.
    NotesDirAbsent,
    /// An IO or SQLite error other than the two above.
    ReadFailure,
}

impl PreviewDiagnostic {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DbAbsent => "db_absent",
            Self::SchemaUnsupported => "schema_unsupported",
            Self::NotesDirAbsent => "notes_dir_absent",
            Self::ReadFailure => "read_failure",
        }
    }
}

/// One read-only preview of the legacy Memory source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyPreview {
    pub(crate) source: LegacySourceFingerprint,
    pub(crate) attributed: Vec<AttributedCandidate>,
    pub(crate) unattributed: Vec<UnattributedItem>,
    pub(crate) diagnostics: Vec<PreviewDiagnostic>,
}

impl LegacyPreview {
    /// Whether the source moved since this preview was built.
    pub(crate) fn is_stale(&self, now: &LegacySourceFingerprint) -> bool {
        self.source != *now
    }
}

/// Projects rows, note names and a fingerprint into a preview.
///
/// This is the pure half: no IO, no clock, no logging. Attribution asks exactly
/// one question per row, whether its `workspace_path` normalizes to a stable
/// local root, and sorts the result by normalized workspace and then by thread
/// id, so two previews of the same source are equal regardless of the order the
/// rows arrived in.
pub(crate) fn project_preview(
    rows: Vec<LegacyRow>,
    notes: Vec<String>,
    mut fingerprint: LegacySourceFingerprint,
) -> LegacyPreview {
    let mut attributed = Vec::new();
    let mut unattributed = Vec::new();

    // The row digest is derived from the rows this call projects, so the caller
    // cannot hand over a digest of a different row set and the projection stays the
    // single owner of that value.
    fingerprint.rows_digest = rows_digest(&rows);

    for row in rows {
        match normalize_local_workspace_root_for_stable_id(Path::new(&row.workspace_path)) {
            Ok(normalized_workspace) => attributed.push(AttributedCandidate {
                content_hash: content_hash(&row.raw_memory, &row.rollout_summary),
                normalized_workspace,
                source_updated_at: row.source_updated_at,
                thread_id: row.thread_id,
            }),
            Err(_) => unattributed.push(UnattributedItem {
                kind: UnattributedKind::LegacyRow,
                key: row.thread_id,
                reason: UnattributedReason::UnnormalizablePath,
            }),
        }
    }

    for note in notes {
        unattributed.push(UnattributedItem {
            kind: UnattributedKind::AdHocNote,
            key: note,
            reason: UnattributedReason::NoWorkspaceField,
        });
    }

    attributed.sort_by(|left, right| {
        (&left.normalized_workspace, &left.thread_id)
            .cmp(&(&right.normalized_workspace, &right.thread_id))
    });
    unattributed.sort_by(|left, right| {
        (left.kind, &left.key, left.reason).cmp(&(right.kind, &right.key, right.reason))
    });

    LegacyPreview {
        source: fingerprint,
        attributed,
        unattributed,
        diagnostics: Vec::new(),
    }
}

/// Reads one read-only preview of the legacy Memory source.
///
/// `db_path` is the Memory database file and `memory_root` is the Memory
/// workspace root the layout helpers below are anchored at. Neither path is
/// created, repaired or reorganized: a missing database and a missing notes
/// directory are typed diagnostics with an empty projection, not errors.
pub(crate) fn read_legacy_preview(db_path: &Path, memory_root: &Path) -> LegacyPreview {
    let mut diagnostics = Vec::new();
    let rows = read_rows(db_path, &mut diagnostics);
    let notes = read_notes(memory_root, &mut diagnostics);

    let fingerprint = LegacySourceFingerprint::of_source(
        rows.len() as u64,
        derived_tree_hash(memory_root),
        notes_tree_hash(memory_root),
    );

    let mut preview = project_preview(rows, notes, fingerprint);
    preview.diagnostics = diagnostics;
    preview
}

/// Reads the L1 rows, or returns an empty projection with one diagnostic.
fn read_rows(db_path: &Path, diagnostics: &mut Vec<PreviewDiagnostic>) -> Vec<LegacyRow> {
    let Some(connection) = open_existing_read_only(db_path, diagnostics) else {
        return Vec::new();
    };

    match read_memory_store_snapshot(&connection) {
        Ok(snapshot) => snapshot.records.iter().map(LegacyRow::from_record).collect(),
        Err(MemoryStoreError::UnsupportedSchema(_)) => {
            diagnostics.push(PreviewDiagnostic::SchemaUnsupported);
            Vec::new()
        }
        Err(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            Vec::new()
        }
    }
}

/// Opens an existing database read-only without ever creating it.
///
/// The metadata probe distinguishes "absent" from "present but not a regular
/// file", so a missing database is a normal diagnostic and an unusable path is
/// reported as a read failure instead of being silently treated as empty.
///
/// A `db_path` that is a symbolic link or a junction is refused and never
/// followed: the probe reads the link itself, not its target, and reports a read
/// failure. That is a deliberate refusal to read through a link, not a statement
/// that the database is corrupt.
fn open_existing_read_only(
    db_path: &Path,
    diagnostics: &mut Vec<PreviewDiagnostic>,
) -> Option<Connection> {
    match std::fs::symlink_metadata(db_path) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            return None;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            diagnostics.push(PreviewDiagnostic::DbAbsent);
            return None;
        }
        Err(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            return None;
        }
    }

    match Connection::open_with_flags(db_path, READ_FLAGS) {
        Ok(connection) => Some(connection),
        Err(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            None
        }
    }
}

/// Lists the L2 note files, or returns an empty listing with one diagnostic.
fn read_notes(memory_root: &Path, diagnostics: &mut Vec<PreviewDiagnostic>) -> Vec<String> {
    let notes_root = ad_hoc_notes_dir(memory_root);

    match std::fs::symlink_metadata(&notes_root) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            return Vec::new();
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            diagnostics.push(PreviewDiagnostic::NotesDirAbsent);
            return Vec::new();
        }
        Err(_) => {
            diagnostics.push(PreviewDiagnostic::ReadFailure);
            return Vec::new();
        }
    }

    walk_files(&notes_root, include_note_file)
        .into_iter()
        .map(|(relative, _)| relative)
        .collect()
}

/// Hash over the L3 derived files.
fn derived_tree_hash(memory_root: &Path) -> String {
    tree_hash(memory_root, include_derived_file)
}

/// Hash over the L2 note files.
fn notes_tree_hash(memory_root: &Path) -> String {
    tree_hash(&ad_hoc_notes_dir(memory_root), include_note_file)
}

/// Hashes the files under `root` that `include` accepts.
///
/// The hash covers each relative path and its bytes in path order, so a rename, a
/// content edit, an addition and a removal all change it. Missing roots and files
/// that cannot be read contribute nothing; this function never creates, repairs or
/// follows a link.
pub(crate) fn tree_hash(root: &Path, include: fn(&Path) -> bool) -> String {
    let mut hasher = Sha256::new();

    for (relative, path) in walk_files(root, include) {
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        hasher.update((relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(&bytes);
    }

    format!("{:x}", hasher.finalize())
}

/// Collects the relative and absolute paths of the accepted files under `root`.
///
/// Entries are sorted by relative path, so callers get a deterministic order even
/// though the filesystem does not provide one.
fn walk_files(root: &Path, include: fn(&Path) -> bool) -> Vec<(String, PathBuf)> {
    let mut files = Vec::new();
    collect_files(root, root, include, 0, &mut files);
    files.sort();
    files
}

/// Recurses one level of the bounded, read-only tree walk.
fn collect_files(
    root: &Path,
    dir: &Path,
    include: fn(&Path) -> bool,
    depth: usize,
    files: &mut Vec<(String, PathBuf)>,
) {
    if depth > MAX_TREE_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            collect_files(root, &path, include, depth + 1, files);
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        if include(relative) {
            files.push((stable_relative_path(relative), path));
        }
    }
}

/// One slash-normalized relative path, so a hash does not depend on the host
/// separator.
fn stable_relative_path(relative: &Path) -> String {
    relative.to_string_lossy().replace('\\', "/")
}

/// Whether one relative path is an L3 derived file.
fn include_derived_file(relative: &Path) -> bool {
    let stable = stable_relative_path(relative);
    let rollout_prefix = format!("{ROLLOUT_SUMMARIES_DIR_NAME}/");

    stable == MEMORY_SUMMARY_FILE_NAME
        || stable == RAW_MEMORIES_FILENAME
        || stable == MEMORY_FILE_NAME
        || stable.starts_with(&rollout_prefix)
}

/// Whether one relative path is an L2 note file.
fn include_note_file(relative: &Path) -> bool {
    relative
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("md"))
}

/// Hashes one row's memory content without keeping the content.
///
/// Both parts are length-prefixed, so two different splits of the same bytes
/// cannot collide into one hash.
fn content_hash(raw_memory: &str, rollout_summary: &str) -> String {
    let mut hasher = Sha256::new();
    for part in [raw_memory, rollout_summary] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

/// Hashes every projected field of one row.
///
/// The row identifier, the raw workspace path, the source timestamp and the body
/// hash are all length-prefixed before hashing, so two different splits of the same
/// bytes cannot collide and no projected field can change without changing the
/// digest.
fn row_digest(row: &LegacyRow) -> String {
    let mut hasher = Sha256::new();
    for part in [row.thread_id.as_str(), row.workspace_path.as_str()] {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part.as_bytes());
    }
    hasher.update(row.source_updated_at.to_le_bytes());
    hasher.update(content_hash(&row.raw_memory, &row.rollout_summary).as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Aggregates one digest per row into one digest of the projected rows.
///
/// The per-row digests are concatenated in row-identifier order and then hashed
/// once. Each per-row digest is a fixed 64-character hex string, so concatenation
/// needs no separator and stays unambiguous; an empty row set produces the digest
/// of no bytes, the same convention the tree hashes use for a missing tree.
///
/// The result depends on the row set and on every projected field of each row,
/// never on the order the rows were read in.
fn rows_digest(rows: &[LegacyRow]) -> String {
    let mut digests = rows
        .iter()
        .map(|row| (row.thread_id.as_str(), row_digest(row)))
        .collect::<Vec<_>>();
    digests.sort_by(|left, right| left.0.cmp(right.0));

    let mut hasher = Sha256::new();
    for (_, digest) in &digests {
        hasher.update(digest.as_bytes());
    }
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn row(thread_id: &str, workspace_path: &str, raw_memory: &str) -> LegacyRow {
        LegacyRow {
            thread_id: thread_id.to_string(),
            workspace_path: workspace_path.to_string(),
            source_updated_at: 1,
            raw_memory: raw_memory.to_string(),
            rollout_summary: String::new(),
        }
    }

    fn fingerprint(seed: &str) -> LegacySourceFingerprint {
        LegacySourceFingerprint {
            row_count: 1,
            rows_digest: rows_digest(&[]),
            schema_shape: EXPECTED_STAGE1_COLUMNS.join(","),
            derived_tree_hash: seed.to_string(),
            notes_tree_hash: seed.to_string(),
        }
    }

    fn include_everything(_relative: &Path) -> bool {
        true
    }

    #[test]
    fn project_preview_attributes_by_workspace_path_only() {
        let workspace = tempfile::tempdir().expect("workspace root");
        let workspace_path = workspace.path().to_string_lossy().to_string();
        let normalized = normalize_local_workspace_root_for_stable_id(workspace.path())
            .expect("normalizes an existing directory");

        let preview = project_preview(
            vec![
                row("thread-a", &workspace_path, "raw-a"),
                row("thread-b", "", "raw-b"),
            ],
            vec!["note-a.md".to_string()],
            fingerprint("derived"),
        );

        assert_eq!(preview.attributed.len(), 1);
        assert_eq!(preview.source.row_count, 1);
        assert_eq!(preview.source.schema_shape, EXPECTED_STAGE1_COLUMNS.join(","));
        // This only proves the projection filled the digest. That the digest tracks
        // the rows is covered by the order-independence and changed-field cases.
        assert_eq!(
            preview.source.rows_digest,
            rows_digest(&[
                row("thread-a", &workspace_path, "raw-a"),
                row("thread-b", "", "raw-b"),
            ])
        );
        assert_eq!(preview.attributed[0].thread_id, "thread-a");
        assert_eq!(preview.attributed[0].normalized_workspace, normalized);
        assert_eq!(preview.attributed[0].source_updated_at, 1);
        assert_eq!(
            preview.attributed[0].content_hash,
            content_hash("raw-a", "")
        );
        assert!(!preview.attributed[0].content_hash.is_empty());

        assert_eq!(preview.unattributed.len(), 2);
        assert_eq!(preview.unattributed[0].kind, UnattributedKind::LegacyRow);
        assert_eq!(preview.unattributed[0].key, "thread-b");
        assert_eq!(
            preview.unattributed[0].reason,
            UnattributedReason::UnnormalizablePath
        );
        assert_eq!(preview.unattributed[1].kind, UnattributedKind::AdHocNote);
        assert_eq!(preview.unattributed[1].key, "note-a.md");
        assert_eq!(
            preview.unattributed[1].reason,
            UnattributedReason::NoWorkspaceField
        );

        assert!(preview.diagnostics.is_empty());
    }

    #[test]
    fn project_preview_is_independent_of_input_order() {
        let workspace = tempfile::tempdir().expect("workspace root");
        let workspace_path = workspace.path().to_string_lossy().to_string();

        let first = project_preview(
            vec![
                row("thread-b", &workspace_path, "raw-b"),
                row("thread-a", &workspace_path, "raw-a"),
                row("thread-c", "", "raw-c"),
            ],
            vec!["note-b.md".to_string(), "note-a.md".to_string()],
            fingerprint("derived"),
        );
        let second = project_preview(
            vec![
                row("thread-c", "", "raw-c"),
                row("thread-a", &workspace_path, "raw-a"),
                row("thread-b", &workspace_path, "raw-b"),
            ],
            vec!["note-a.md".to_string(), "note-b.md".to_string()],
            fingerprint("derived"),
        );

        assert_eq!(first, second);
        assert_eq!(
            first
                .attributed
                .iter()
                .map(|candidate| candidate.thread_id.as_str())
                .collect::<Vec<_>>(),
            vec!["thread-a", "thread-b"]
        );
        assert_eq!(
            first
                .unattributed
                .iter()
                .map(|item| item.key.as_str())
                .collect::<Vec<_>>(),
            vec!["thread-c", "note-a.md", "note-b.md"]
        );
    }

    #[test]
    fn content_hash_separates_the_two_parts() {
        assert_ne!(content_hash("ab", ""), content_hash("a", "b"));
        assert_eq!(content_hash("raw", "summary").len(), 64);
    }

    #[test]
    fn rows_digest_is_independent_of_row_order() {
        let mut rows = vec![
            row("thread-a", "", "raw-a"),
            row("thread-b", "", "raw-b"),
            row("thread-c", "", "raw-c"),
        ];
        let ordered = rows_digest(&rows);

        rows.reverse();
        assert_eq!(rows_digest(&rows), ordered);
        rows.rotate_left(1);
        assert_eq!(rows_digest(&rows), ordered);

        rows[0] = row(rows[0].thread_id.as_str(), "", "changed");
        assert_ne!(rows_digest(&rows), ordered);
    }

    #[test]
    fn rows_digest_tracks_every_projected_field() {
        let baseline = row("thread-a", "C:/workspace", "raw-a");
        let digest = rows_digest(std::slice::from_ref(&baseline));

        // The body and the raw path are the two fields the preview projects verbatim.
        let mut edited_body = baseline.clone();
        edited_body.raw_memory = "raw-b".to_string();
        assert_ne!(rows_digest(&[edited_body]), digest);

        let mut edited_path = baseline.clone();
        edited_path.workspace_path = "C:/workspace-other".to_string();
        assert_ne!(rows_digest(&[edited_path]), digest);

        // The identifier and the timestamp are projected as well.
        let mut edited_id = baseline.clone();
        edited_id.thread_id = "thread-b".to_string();
        assert_ne!(rows_digest(&[edited_id]), digest);

        let mut edited_timestamp = baseline.clone();
        edited_timestamp.source_updated_at += 1;
        assert_ne!(rows_digest(&[edited_timestamp]), digest);

        assert_eq!(rows_digest(&[baseline]), digest);
    }

    #[test]
    fn rows_digest_of_no_rows_is_the_empty_digest() {
        let root = tempfile::tempdir().expect("root");
        let missing = root.path().join("missing");

        assert_eq!(rows_digest(&[]), tree_hash(&missing, include_everything));
        assert_eq!(rows_digest(&[]).len(), 64);
        assert_ne!(rows_digest(&[]), rows_digest(&[row("thread-a", "", "raw-a")]));
    }

    #[test]
    fn is_stale_compares_the_whole_fingerprint() {
        let current = fingerprint("derived");
        let preview = project_preview(Vec::new(), Vec::new(), current.clone());

        assert!(!preview.is_stale(&current));
        assert!(preview.is_stale(&fingerprint("other")));
        assert!(preview.is_stale(&LegacySourceFingerprint {
            row_count: current.row_count + 1,
            ..current.clone()
        }));
        assert!(preview.is_stale(&LegacySourceFingerprint {
            rows_digest: rows_digest(&[row("thread-a", "", "raw-a")]),
            ..current.clone()
        }));
        assert!(preview.is_stale(&LegacySourceFingerprint {
            schema_shape: "stage1_outputs".to_string(),
            ..current
        }));
    }

    #[test]
    fn tree_hash_of_a_missing_root_is_the_empty_digest() {
        let root = tempfile::tempdir().expect("root");
        let missing = root.path().join("missing");

        assert_eq!(
            tree_hash(&missing, include_everything),
            tree_hash(&root.path().join("also-missing"), include_everything)
        );
        assert!(!tree_hash(&missing, include_everything).is_empty());
    }

    #[test]
    fn tree_hash_tracks_content_nesting_and_removal() {
        let root = tempfile::tempdir().expect("root");
        let empty = tree_hash(root.path(), include_everything);

        let flat = root.path().join("flat.md");
        fs::write(&flat, "one").expect("write flat");
        let single = tree_hash(root.path(), include_everything);
        assert_ne!(empty, single);

        fs::write(&flat, "two").expect("rewrite flat");
        let changed = tree_hash(root.path(), include_everything);
        assert_ne!(single, changed);

        let nested_dir = root.path().join("nested");
        fs::create_dir_all(&nested_dir).expect("create nested");
        fs::write(nested_dir.join("deep.md"), "deep").expect("write deep");
        let nested = tree_hash(root.path(), include_everything);
        assert_ne!(changed, nested);

        fs::remove_file(nested_dir.join("deep.md")).expect("remove deep");
        assert_eq!(tree_hash(root.path(), include_everything), changed);
    }

    #[test]
    fn tree_hash_include_filter_selects_derived_files_only() {
        let memory_root = tempfile::tempdir().expect("memory root");
        fs::write(memory_root.path().join(MEMORY_SUMMARY_FILE_NAME), "summary")
            .expect("write summary");
        fs::write(memory_root.path().join("unrelated.txt"), "unrelated").expect("write unrelated");

        let with_summary = derived_tree_hash(memory_root.path());
        fs::remove_file(memory_root.path().join(MEMORY_SUMMARY_FILE_NAME)).expect("remove summary");

        assert_ne!(with_summary, derived_tree_hash(memory_root.path()));
        assert_eq!(
            derived_tree_hash(memory_root.path()),
            tree_hash(memory_root.path(), include_derived_file)
        );
    }

    #[test]
    fn note_filter_accepts_markdown_at_any_depth() {
        assert!(include_note_file(Path::new("note.md")));
        assert!(include_note_file(Path::new("nested/note.MD")));
        assert!(!include_note_file(Path::new("note.txt")));
        assert!(!include_note_file(Path::new("note")));
    }

    #[test]
    fn preview_diagnostic_codes_are_stable() {
        assert_eq!(PreviewDiagnostic::DbAbsent.as_str(), "db_absent");
        assert_eq!(
            PreviewDiagnostic::SchemaUnsupported.as_str(),
            "schema_unsupported"
        );
        assert_eq!(
            PreviewDiagnostic::NotesDirAbsent.as_str(),
            "notes_dir_absent"
        );
        assert_eq!(PreviewDiagnostic::ReadFailure.as_str(), "read_failure");
    }

    #[test]
    fn the_read_only_open_cannot_write() {
        let root = tempfile::tempdir().expect("root");
        let db_path = root.path().join("memory.sqlite");

        let writer = Connection::open(&db_path).expect("create database");
        writer
            .execute_batch("CREATE TABLE probe (value TEXT NOT NULL)")
            .expect("create probe table");
        drop(writer);

        let mut diagnostics = Vec::new();
        let reader =
            open_existing_read_only(&db_path, &mut diagnostics).expect("open existing database");

        assert!(reader
            .is_readonly(rusqlite::DatabaseName::Main)
            .expect("read the read-only flag"));
        assert!(diagnostics.is_empty());
        assert!(reader
            .execute("INSERT INTO probe (value) VALUES ('x')", [])
            .is_err());
        assert_eq!(
            reader
                .query_row("SELECT COUNT(*) FROM probe", [], |row| row.get::<_, i64>(0))
                .expect("count rows"),
            0
        );
    }

    #[test]
    fn a_missing_database_is_reported_and_not_created() {
        let root = tempfile::tempdir().expect("root");
        let db_path = root.path().join("memory.sqlite");
        let mut diagnostics = Vec::new();

        assert!(open_existing_read_only(&db_path, &mut diagnostics).is_none());
        assert_eq!(diagnostics, vec![PreviewDiagnostic::DbAbsent]);
        assert!(!db_path.exists());
    }

    /// A link inside the notes tree is skipped by both the listing and the hash.
    ///
    /// Unix-only on purpose: the standard library cannot create a Windows junction,
    /// so the Windows run cannot build the fixture this test needs. The production
    /// code path it exercises (skip a `symlink_metadata` entry whose file type is a
    /// link) is the same on every host.
    #[cfg(unix)]
    #[test]
    fn a_linked_note_entry_is_never_followed() {
        let outside = tempfile::tempdir().expect("outside root");
        let memory_root = tempfile::tempdir().expect("memory root");
        let notes_root = ad_hoc_notes_dir(memory_root.path());

        fs::create_dir_all(&notes_root).expect("create the notes directory");
        fs::write(notes_root.join("real.md"), "real").expect("write a real note");
        fs::write(outside.path().join("external.md"), "external").expect("write an external note");

        let hash_without_link = tree_hash(&notes_root, include_note_file);
        std::os::unix::fs::symlink(outside.path(), notes_root.join("linked"))
            .expect("create the link");

        assert_eq!(tree_hash(&notes_root, include_note_file), hash_without_link);

        let mut diagnostics = Vec::new();
        let notes = read_notes(memory_root.path(), &mut diagnostics);
        assert_eq!(notes, vec!["real.md".to_string()]);
        assert!(diagnostics.is_empty());
    }
}
