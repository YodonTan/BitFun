//! Read-only legacy Memory preview for workspace intelligence WP2.3.
//!
//! # What this file proves
//!
//! The preview reads one legacy Memory database and one Memory workspace root and
//! answers three things without writing anything: which rows normalize to a local
//! workspace root, which rows and notes stay unattributed, and one stable
//! fingerprint of the source it read.
//!
//! The tests below use a real SQLite file and a real directory tree under one
//! temporary root. They assert four kinds of evidence only:
//!
//! - the read-only contract: an absent database is reported and never created, an
//!   unsupported schema is reported and restored neither by repair nor by drop,
//!   the source bytes and the file listing are identical before and after, and a
//!   read-only connection cannot write;
//! - attribution: one direct evidence per row (`workspace_path`), no path-to-scope
//!   derivation, and notes unattributed by construction;
//! - staleness: a row edit changes the fingerprint and marks the previous preview
//!   stale;
//! - determinism: two previews of one unchanged source are equal.
//!
//! It is not a migration test. It never runs the offline legacy migration engine,
//! never enables a scope, never writes a cognition partition and never calls a
//! model. A `cargo test` run of this file is single-process, local-filesystem
//! evidence only: no cross-process evidence, no Unix evidence and no
//! remote-scenario evidence.

use crate::agentic::memories::workspace::ad_hoc_notes_dir;
use crate::service::workspace_intelligence::legacy_preview::{
    read_legacy_preview, PreviewDiagnostic, UnattributedKind, UnattributedReason,
};
use openbitfun_services_core::memory_store::read_memory_store_snapshot;
use openbitfun_services_core::workspace_identity::normalize_local_workspace_root_for_stable_id;
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};

/// The documented `stage1_outputs` shape, written as a literal on purpose.
///
/// The preview must recognize the real shape and must not repair a different one,
/// so the fixture spells the columns out instead of calling an initialize helper.
const STAGE1_OUTPUTS_DDL: &str = "
CREATE TABLE stage1_outputs (
    thread_id TEXT PRIMARY KEY NOT NULL,
    workspace_path TEXT NOT NULL,
    rollout_path TEXT NOT NULL,
    source_updated_at INTEGER NOT NULL,
    raw_memory TEXT NOT NULL,
    rollout_summary TEXT NOT NULL,
    rollout_slug TEXT,
    generated_at INTEGER NOT NULL,
    usage_count INTEGER,
    last_usage INTEGER,
    selected_for_phase2 INTEGER NOT NULL DEFAULT 0,
    selected_for_phase2_source_updated_at INTEGER
)";

/// The documented `jobs` shape, needed because the store reader validates both
/// tables before it reads any row.
const JOBS_DDL: &str = "
CREATE TABLE jobs (
    kind TEXT NOT NULL,
    job_key TEXT NOT NULL,
    status TEXT NOT NULL,
    worker_id TEXT,
    ownership_token TEXT,
    started_at INTEGER,
    finished_at INTEGER,
    lease_until INTEGER,
    retry_at INTEGER,
    retry_remaining INTEGER NOT NULL,
    last_error TEXT,
    input_watermark INTEGER,
    last_success_watermark INTEGER,
    PRIMARY KEY (kind, job_key)
)";

fn create_memory_db(db_path: &Path) -> Connection {
    let connection = Connection::open(db_path).expect("create the memory database");
    connection
        .execute_batch(&format!("{STAGE1_OUTPUTS_DDL};{JOBS_DDL};"))
        .expect("create the memory schema");
    connection
}

fn insert_row(
    connection: &Connection,
    thread_id: &str,
    workspace_path: &str,
    source_updated_at: i64,
    raw_memory: &str,
    rollout_summary: &str,
) {
    connection
        .execute(
            "INSERT INTO stage1_outputs (
                thread_id, workspace_path, rollout_path, source_updated_at, raw_memory,
                rollout_summary, rollout_slug, generated_at, usage_count, last_usage,
                selected_for_phase2, selected_for_phase2_source_updated_at
             ) VALUES (?1, ?2, '', ?3, ?4, ?5, NULL, 0, 0, NULL, 0, NULL)",
            params![
                thread_id,
                workspace_path,
                source_updated_at,
                raw_memory,
                rollout_summary
            ],
        )
        .expect("insert a memory row");
}

fn write_note(memory_root: &Path, name: &str, body: &str) {
    let notes_root = ad_hoc_notes_dir(memory_root);
    fs::create_dir_all(&notes_root).expect("create the notes directory");
    fs::write(notes_root.join(name), body).expect("write a note");
}

fn write_text(path: &Path, body: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create the parent directory");
    }
    fs::write(path, body).expect("write a file");
}

/// Every entry under `root`, slash-normalized and sorted, so a listing can be
/// compared before and after a read.
fn file_listing(root: &Path) -> Vec<String> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(relative) = path.strip_prefix(root) else {
                continue;
            };
            out.push(relative.to_string_lossy().replace('\\', "/"));
            if path.is_dir() {
                walk(root, &path, out);
            }
        }
    }

    let mut listing = Vec::new();
    walk(root, root, &mut listing);
    listing.sort();
    listing
}

fn sidecar(db_path: &Path, suffix: &str) -> PathBuf {
    PathBuf::from(format!("{}{suffix}", db_path.display()))
}

#[test]
fn an_absent_database_is_reported_and_never_created() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(
        preview.diagnostics,
        vec![
            PreviewDiagnostic::DbAbsent,
            PreviewDiagnostic::NotesDirAbsent
        ]
    );
    assert!(preview.attributed.is_empty());
    assert!(preview.unattributed.is_empty());
    assert_eq!(preview.source.row_count, 0);
    assert!(!preview.source.db_present);
    assert!(!db_path.exists());
    assert!(!memory_root.exists());
    assert!(!ad_hoc_notes_dir(&memory_root).exists());
}

/// An absent database and an equivalent empty one project the same rows, shape and
/// trees, so only the presence bit can tell them apart — and it must.
#[test]
fn an_absent_database_is_distinguishable_from_an_equivalent_empty_one() {
    let root = tempfile::tempdir().expect("temporary root");
    let absent_db = root.path().join("absent-memories.sqlite");
    let present_db = root.path().join("present-memories.sqlite");
    let memory_root = root.path().join("memories");

    let empty = create_memory_db(&present_db);
    let present_rows: i64 = empty
        .query_row("SELECT COUNT(*) FROM stage1_outputs", [], |row| row.get(0))
        .expect("count the fixture rows");
    assert_eq!(present_rows, 0, "the fixture must be an empty database");
    drop(empty);

    let absent = read_legacy_preview(&absent_db, &memory_root);
    let present = read_legacy_preview(&present_db, &memory_root);

    assert!(absent.diagnostics.contains(&PreviewDiagnostic::DbAbsent));
    assert!(!present
        .diagnostics
        .contains(&PreviewDiagnostic::DbAbsent));

    // Everything except the presence bit matches.
    assert_eq!(absent.source.row_count, present.source.row_count);
    assert_eq!(absent.source.rows_digest, present.source.rows_digest);
    assert_eq!(absent.source.schema_shape, present.source.schema_shape);
    assert_eq!(
        absent.source.derived_tree_hash,
        present.source.derived_tree_hash
    );
    assert_eq!(absent.source.notes_tree_hash, present.source.notes_tree_hash);
    assert!(!absent.source.db_present);
    assert!(present.source.db_present);
    assert_ne!(absent.source, present.source);

    // A preview taken on the missing database recognizes that the source moved
    // once the database exists, even though it is still empty.
    assert!(absent.is_stale(&present.source));
    assert!(!present.is_stale(&present.source));
}

#[test]
fn an_unsupported_schema_is_reported_without_repair_or_drop() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");

    let connection = Connection::open(&db_path).expect("create the memory database");
    connection
        .execute_batch(
            "CREATE TABLE stage1_outputs (
                thread_id TEXT PRIMARY KEY NOT NULL,
                workspace_path TEXT NOT NULL
             )",
        )
        .expect("create a partial stage1_outputs table");
    connection
        .execute(
            "INSERT INTO stage1_outputs (thread_id, workspace_path) VALUES ('thread-a', 'C:/ws')",
            [],
        )
        .expect("insert a row into the partial table");
    drop(connection);

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert!(preview
        .diagnostics
        .contains(&PreviewDiagnostic::SchemaUnsupported));
    assert!(preview.attributed.is_empty());
    assert!(preview.unattributed.is_empty());
    assert_eq!(preview.source.row_count, 0);
    // The file exists; it is only its shape that is unsupported.
    assert!(preview.source.db_present);

    let connection = Connection::open(&db_path).expect("reopen the memory database");
    let tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'stage1_outputs'",
            [],
            |row| row.get(0),
        )
        .expect("count the stage1_outputs table");
    assert_eq!(tables, 1);
    let rows: i64 = connection
        .query_row("SELECT COUNT(*) FROM stage1_outputs", [], |row| row.get(0))
        .expect("count the surviving rows");
    assert_eq!(rows, 1);
}

#[test]
fn a_supported_source_splits_attributed_and_unattributed_items() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let first_workspace = root.path().join("workspace-a");
    let second_workspace = root.path().join("workspace-b");
    fs::create_dir_all(&first_workspace).expect("create workspace a");
    fs::create_dir_all(&second_workspace).expect("create workspace b");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-b",
        &second_workspace.to_string_lossy(),
        11,
        "raw-b",
        "summary-b",
    );
    insert_row(
        &connection,
        "thread-a",
        &first_workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    insert_row(&connection, "thread-c", "", 12, "raw-c", "summary-c");
    drop(connection);

    write_note(&memory_root, "note-a.md", "note a");
    write_note(&memory_root, "note-b.md", "note b");

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert!(preview.diagnostics.is_empty());
    assert_eq!(preview.source.row_count, 3);
    assert_eq!(preview.attributed.len(), 2);

    let first_normalized =
        normalize_local_workspace_root_for_stable_id(&first_workspace).expect("normalize a");
    let second_normalized =
        normalize_local_workspace_root_for_stable_id(&second_workspace).expect("normalize b");
    assert_eq!(preview.attributed[0].thread_id, "thread-a");
    assert_eq!(preview.attributed[0].normalized_workspace, first_normalized);
    assert_eq!(preview.attributed[0].source_updated_at, 10);
    assert_eq!(preview.attributed[1].thread_id, "thread-b");
    assert_eq!(
        preview.attributed[1].normalized_workspace,
        second_normalized
    );

    for candidate in &preview.attributed {
        assert_eq!(candidate.content_hash.len(), 64);
        assert!(!candidate.content_hash.contains("raw-"));
        assert!(!candidate.content_hash.contains("summary-"));
    }
    assert_ne!(
        preview.attributed[0].content_hash,
        preview.attributed[1].content_hash
    );

    assert_eq!(preview.unattributed.len(), 3);
    assert_eq!(preview.unattributed[0].kind, UnattributedKind::LegacyRow);
    assert_eq!(preview.unattributed[0].key, "thread-c");
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
    assert_eq!(preview.unattributed[2].key, "note-b.md");
}

#[test]
fn a_preview_leaves_the_source_byte_identical() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    insert_row(
        &connection,
        "thread-b",
        &workspace.to_string_lossy(),
        11,
        "raw-b",
        "summary-b",
    );
    drop(connection);

    write_text(&memory_root.join("memory_summary.md"), "summary");
    write_text(&memory_root.join("raw_memories.md"), "raw memories");
    write_text(&memory_root.join("MEMORY.md"), "memory index");
    write_text(&memory_root.join("rollout_summaries/one.md"), "rollout");
    write_note(&memory_root, "note-a.md", "note a");

    let records_before = {
        let connection = Connection::open(&db_path).expect("open the source database");
        read_memory_store_snapshot(&connection)
            .expect("read the source snapshot")
            .records
            .len()
    };
    let files_before = file_listing(&memory_root);
    let bytes_before = fs::read(&db_path).expect("read the database bytes");
    let first = read_legacy_preview(&db_path, &memory_root);
    let second = read_legacy_preview(&db_path, &memory_root);

    assert!(first.diagnostics.is_empty());
    assert_eq!(first.source.row_count, 2);
    assert_eq!(
        first.source.derived_tree_hash,
        second.source.derived_tree_hash
    );
    assert_eq!(first.source.notes_tree_hash, second.source.notes_tree_hash);

    let records_after = {
        let connection = Connection::open(&db_path).expect("reopen the source database");
        read_memory_store_snapshot(&connection)
            .expect("reread the source snapshot")
            .records
            .len()
    };
    assert_eq!(records_before, records_after);
    assert_eq!(file_listing(&memory_root), files_before);
    assert_eq!(
        fs::read(&db_path).expect("reread the database bytes"),
        bytes_before
    );
    assert!(!sidecar(&db_path, "-wal").exists());
    assert!(!sidecar(&db_path, "-shm").exists());
}

#[test]
fn repeated_previews_of_one_source_are_equal() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);
    write_note(&memory_root, "note-a.md", "note a");

    let first = read_legacy_preview(&db_path, &memory_root);
    let second = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(first, second);
    assert!(!first.is_stale(&second.source));
}

#[test]
fn a_row_set_change_makes_the_previous_preview_stale() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);
    write_note(&memory_root, "note-a.md", "note a");

    let first = read_legacy_preview(&db_path, &memory_root);
    assert!(first.diagnostics.is_empty());
    assert_eq!(first.source.row_count, 1);
    assert!(!first.is_stale(&first.source));

    let connection = Connection::open(&db_path).expect("reopen the source database");
    insert_row(
        &connection,
        "thread-b",
        &workspace.to_string_lossy(),
        11,
        "raw-b",
        "summary-b",
    );
    drop(connection);

    let second = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(second.source.row_count, 2);
    assert!(first.is_stale(&second.source));
    assert!(!second.is_stale(&second.source));
    assert_eq!(second.attributed.len(), 2);
}

/// Pins the fingerprint coverage WP2.3 delivers: the row set, the row contents, the
/// projected column shape and both derived trees.
///
/// An in-place edit therefore changes the row digest and marks the previous preview
/// stale, and the candidate it produces carries a different content hash.
#[test]
fn an_in_place_row_edit_makes_the_previous_preview_stale() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);
    write_note(&memory_root, "note-a.md", "note a");

    let first = read_legacy_preview(&db_path, &memory_root);
    assert!(first.diagnostics.is_empty());

    let connection = Connection::open(&db_path).expect("reopen the source database");
    connection
        .execute(
            "UPDATE stage1_outputs SET raw_memory = 'changed' WHERE thread_id = 'thread-a'",
            [],
        )
        .expect("update one row");
    drop(connection);

    let second = read_legacy_preview(&db_path, &memory_root);

    assert_ne!(
        first.attributed[0].content_hash,
        second.attributed[0].content_hash
    );
    assert_ne!(first, second);
    assert_ne!(first.source.rows_digest, second.source.rows_digest);
    assert_eq!(first.source.row_count, second.source.row_count);
    assert_eq!(
        first.source.derived_tree_hash,
        second.source.derived_tree_hash
    );
    assert_eq!(first.source.notes_tree_hash, second.source.notes_tree_hash);
    assert!(first.is_stale(&second.source));
    assert!(!second.is_stale(&second.source));
}

/// The preview leaves the database byte-identical and creates no SQLite side file.
///
/// The read-only proof of the production open lives in the module's own unit test
/// (`the_read_only_open_cannot_write`), which calls that open directly; this test
/// only proves the observable result of a full preview.
#[test]
fn a_preview_leaves_the_database_without_wal_or_shm_side_files() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);
    write_note(&memory_root, "note-a.md", "note a");

    let bytes_before = fs::read(&db_path).expect("read the database bytes");
    let preview = read_legacy_preview(&db_path, &memory_root);

    assert!(preview.diagnostics.is_empty());
    assert_eq!(
        fs::read(&db_path).expect("reread the database bytes"),
        bytes_before
    );
    assert!(!sidecar(&db_path, "-wal").exists());
    assert!(!sidecar(&db_path, "-shm").exists());
}

#[test]
fn an_absent_notes_directory_is_reported_and_never_created() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(preview.diagnostics, vec![PreviewDiagnostic::NotesDirAbsent]);
    assert_eq!(preview.attributed.len(), 1);
    assert!(preview.unattributed.is_empty());
    assert!(!ad_hoc_notes_dir(&memory_root).exists());
    assert!(!memory_root.exists());
}

#[test]
fn a_workspace_path_edit_alone_makes_the_previous_preview_stale() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let first_workspace = root.path().join("workspace-a");
    let second_workspace = root.path().join("workspace-b");
    fs::create_dir_all(&first_workspace).expect("create workspace a");
    fs::create_dir_all(&second_workspace).expect("create workspace b");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &first_workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    insert_row(
        &connection,
        "thread-b",
        &second_workspace.to_string_lossy(),
        11,
        "raw-b",
        "summary-b",
    );
    drop(connection);
    write_note(&memory_root, "note-a.md", "note a");

    let first = read_legacy_preview(&db_path, &memory_root);
    assert!(first.diagnostics.is_empty());
    assert_eq!(first.attributed.len(), 2);
    let first_normalized =
        normalize_local_workspace_root_for_stable_id(&first_workspace).expect("normalize a");
    let second_normalized =
        normalize_local_workspace_root_for_stable_id(&second_workspace).expect("normalize b");
    assert_eq!(first.attributed[0].normalized_workspace, first_normalized);

    // The body, the timestamp and the row set stay untouched: only the workspace
    // path of one row changes.
    let connection = Connection::open(&db_path).expect("reopen the source database");
    connection
        .execute(
            "UPDATE stage1_outputs SET workspace_path = ?1 WHERE thread_id = 'thread-a'",
            params![second_workspace.to_string_lossy()],
        )
        .expect("update one workspace path");
    drop(connection);

    let second = read_legacy_preview(&db_path, &memory_root);

    assert!(second.diagnostics.is_empty());
    assert_eq!(second.source.row_count, first.source.row_count);
    assert_ne!(first.source.rows_digest, second.source.rows_digest);
    assert!(first.is_stale(&second.source));
    assert!(!second.is_stale(&second.source));

    let moved = second
        .attributed
        .iter()
        .find(|candidate| candidate.thread_id == "thread-a")
        .expect("thread-a is still attributed");
    assert_eq!(moved.normalized_workspace, second_normalized);
    assert_ne!(moved.normalized_workspace, first_normalized);
    assert_eq!(
        moved.content_hash,
        first
            .attributed
            .iter()
            .find(|candidate| candidate.thread_id == "thread-a")
            .expect("thread-a was attributed before")
            .content_hash
    );
}

#[test]
fn a_database_path_that_is_a_directory_is_a_read_failure() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    fs::create_dir_all(&db_path).expect("create a directory where the database belongs");

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(
        preview.diagnostics,
        vec![
            PreviewDiagnostic::ReadFailure,
            PreviewDiagnostic::NotesDirAbsent
        ]
    );
    assert!(preview.attributed.is_empty());
    assert!(preview.unattributed.is_empty());
    assert_eq!(preview.source.row_count, 0);
    assert!(db_path.is_dir());
}

#[test]
fn a_notes_path_that_is_a_file_is_a_read_failure() {
    let root = tempfile::tempdir().expect("temporary root");
    let db_path = root.path().join("memories.sqlite");
    let memory_root = root.path().join("memories");
    let workspace = root.path().join("workspace-a");
    fs::create_dir_all(&workspace).expect("create the workspace");

    let connection = create_memory_db(&db_path);
    insert_row(
        &connection,
        "thread-a",
        &workspace.to_string_lossy(),
        10,
        "raw-a",
        "summary-a",
    );
    drop(connection);

    let notes_root = ad_hoc_notes_dir(&memory_root);
    fs::create_dir_all(notes_root.parent().expect("notes parent")).expect("create notes parent");
    fs::write(&notes_root, "not a directory").expect("create a file where notes belong");

    let preview = read_legacy_preview(&db_path, &memory_root);

    assert_eq!(preview.diagnostics, vec![PreviewDiagnostic::ReadFailure]);
    assert_eq!(preview.attributed.len(), 1);
    assert!(preview.unattributed.is_empty());
    assert!(notes_root.is_file());
}
