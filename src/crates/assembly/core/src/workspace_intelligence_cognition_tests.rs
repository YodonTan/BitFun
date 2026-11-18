//! Legacy memory reset separation for the workspace intelligence P1 cognition
//! partition root (WP1.3 core assembly).
//!
//! # What this file proves
//!
//! The legacy memory reset deletes rows from the memory database and empties the
//! memory workspace root. The cognition partition root is a sibling of the
//! control root under the host-local user data directory and is deliberately
//! outside both legacy memory roots, so the reset cannot reach it.
//!
//! This test runs the two real reset owners
//! (`MemoryDatabase::reset_memory_state` and `reset_memory_workspace`) in
//! isolation, in the same order the desktop `reset_memory` command calls them. It
//! does not call the Tauri command, it never touches real user data (every path
//! below lives under one temporary user root), and it proves two things only:
//!
//! - separation of deletion radii: the legacy reset removes memory rows and
//!   memory workspace content and leaves every cognition partition database
//!   byte-identical and observable;
//! - an unchanged legacy shape contract: the documented `stage1_outputs` and
//!   `jobs` column literals still hold before and after the reset.
//!
//! It is not a migration test, it does not advance a claim, a cursor or an
//! incarnation token, and it makes no durability claim beyond the stores' own
//! transactional semantics: no fsync evidence, no cross-process or process-kill
//! evidence, no Unix evidence and no remote-scenario evidence. A `cargo test` run
//! of this file is single-process, local-filesystem evidence only.
//!
//! # Why the crate root
//!
//! The test needs both `service::workspace_intelligence` and `agentic::memories`.
//! It sits at the crate root so neither production module gains an edge to the
//! other.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use openbitfun_services_core::memory_store::{
    read_memory_store_snapshot, validate_memory_schema, EXPECTED_JOBS_COLUMNS,
    EXPECTED_STAGE1_COLUMNS,
};
use rusqlite::Connection;

use crate::agentic::memories::db::{MemoryDatabase, MemoryRow};
use crate::agentic::memories::workspace::{ensure_memory_workspace, reset_memory_workspace};
use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::partition::WorkspaceIntelligenceCognition;
use crate::service::workspace_intelligence::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// The documented legacy memory shape, spelled out literally.
///
/// The owner constants are compared against their own documented column list, so
/// a silent edit of either constant is a test failure instead of a passing no-op.
fn assert_legacy_memory_shape_contract() {
    assert_eq!(EXPECTED_STAGE1_COLUMNS.len(), 12);
    assert_eq!(
        EXPECTED_STAGE1_COLUMNS.to_vec(),
        vec![
            "thread_id",
            "workspace_path",
            "rollout_path",
            "source_updated_at",
            "raw_memory",
            "rollout_summary",
            "rollout_slug",
            "generated_at",
            "usage_count",
            "last_usage",
            "selected_for_phase2",
            "selected_for_phase2_source_updated_at",
        ]
    );
    assert_eq!(EXPECTED_JOBS_COLUMNS.len(), 13);
    assert_eq!(
        EXPECTED_JOBS_COLUMNS.to_vec(),
        vec![
            "kind",
            "job_key",
            "status",
            "worker_id",
            "ownership_token",
            "started_at",
            "finished_at",
            "lease_until",
            "retry_at",
            "retry_remaining",
            "last_error",
            "input_watermark",
            "last_success_watermark",
        ]
    );
}

/// The partition databases directly inside a root, sorted.
fn database_files(root: &Path) -> Vec<PathBuf> {
    let mut files = std::fs::read_dir(root)
        .expect("the cognition root must exist after an initialization")
        .map(|entry| entry.expect("readable directory entry").path())
        .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("sqlite"))
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[tokio::test]
async fn legacy_memory_reset_leaves_cognition_partitions_and_memory_shape_intact() {
    // The two reset owners below are the ones the desktop `reset_memory` command
    // calls, invoked in isolation and in the same order. Everything lives under
    // one temporary user root, so no real user data is read, and no Tauri command
    // is built.
    let fixture = tempfile::tempdir().expect("temp dir");
    let paths = Arc::new(PathManager::with_user_root_for_tests(fixture.path().join("user")));
    let legacy_db = paths.memories_database_file();
    let legacy_workspace = paths.memories_root_dir();
    let control_root = paths.workspace_intelligence_control_dir();
    let cognition_root = paths.workspace_intelligence_cognition_dir();

    // Data-safety guard: every destination this test creates, writes or clears
    // must live inside `fixture` (one `TempDir`). The user root handed to the
    // helper is `fixture.path().join("user")` on purpose, because
    // `PathManager::with_user_root_for_tests` derives the product home from
    // `user_root.parent()` as `base.join("home").join(".openbitfun")`. Passing
    // `fixture.path()` directly would therefore put the memory workspace root in
    // the shared temp parent instead of inside the fixture. Nothing here may ever
    // create, clear or scan anything outside `fixture.path()`: no shared temp
    // parent, no real user data.
    for (destination, path) in [
        ("legacy memory database", &legacy_db),
        ("legacy memory workspace", &legacy_workspace),
        ("workspace intelligence control root", &control_root),
        ("workspace intelligence cognition root", &cognition_root),
    ] {
        assert!(
            path.starts_with(fixture.path()),
            "{destination} escaped the temp dir at {}: a reset outside the fixture \
             would delete real user data, so the fixture user root must stay inside the TempDir",
            path.display()
        );
    }
    assert_eq!(
        control_root.parent(),
        cognition_root.parent(),
        "the control and cognition roots must be siblings under the same workspace-intelligence parent"
    );
    for (destination, path) in [
        ("workspace intelligence control root", &control_root),
        ("workspace intelligence cognition root", &cognition_root),
    ] {
        assert!(
            !path.starts_with(&legacy_workspace),
            "{destination} must not live under the legacy memory workspace root"
        );
        let legacy_db_parent = legacy_db
            .parent()
            .expect("the legacy memory database file must have a parent");
        assert!(
            !path.starts_with(legacy_db_parent),
            "{destination} must not live under the legacy memory database directory"
        );
    }

    // 1. A legacy memory database with one fully populated row, read back through
    //    the owner so the row is genuinely present.
    let memory = MemoryDatabase::new(paths.clone());
    memory
        .initialize()
        .await
        .expect("the legacy memory database must initialize");
    let row = MemoryRow {
        session_id: "fixture-session".to_string(),
        workspace_path: "/fixtures/wi-cognition/workspace".to_string(),
        rollout_path: "/fixtures/wi-cognition/workspace/rollout.jsonl".to_string(),
        source_updated_at_unix_secs: 1_700_000_000,
        raw_memory: "the legacy row must survive until the reset".to_string(),
        rollout_summary: "legacy summary".to_string(),
        rollout_slug: Some("fixture-slug".to_string()),
        generated_at_unix_secs: 1_700_000_100,
        usage_count: 3,
        last_usage_unix_secs: Some(1_700_000_200),
        selected_for_phase2: 1,
        selected_for_phase2_source_updated_at: Some(1_700_000_000),
    };
    memory
        .upsert_memory(&row)
        .await
        .expect("the legacy row must be written");
    {
        let connection = Connection::open(&legacy_db)
            .expect("the legacy memory database must open");
        validate_memory_schema(&connection).expect("the legacy memory shape must validate");
        let snapshot =
            read_memory_store_snapshot(&connection).expect("the legacy memory store must read");
        assert_eq!(snapshot.records, vec![row.clone()]);
        assert!(snapshot.jobs.is_empty());
    }
    assert_legacy_memory_shape_contract();

    // 2. A legacy memory workspace with real content.
    ensure_memory_workspace(&legacy_workspace)
        .await
        .expect("the legacy memory workspace must initialize");
    let legacy_index = legacy_workspace.join("MEMORY.md");
    std::fs::write(&legacy_index, "# Legacy memory index\n\n- legacy row\n")
        .expect("the legacy index file must be writable");
    assert!(legacy_index.is_file(), "the legacy workspace must have content");
    assert!(
        legacy_workspace.join("rollout_summaries").is_dir(),
        "the legacy workspace must hold its own directories before the reset"
    );

    // 3. Two cognition partitions of one host, each with its own database file.
    let host = HostExecutionDomainKey::new("host-1", "local").expect("test host is not blank");
    let cognition = WorkspaceIntelligenceCognition::for_host(&paths, host.clone());
    assert_eq!(cognition.host(), &host);
    assert!(
        !cognition_root.exists(),
        "composing the cognition handle must not create the root"
    );
    let first_scope =
        WorkspaceControlScope::new(&host, "workspace-a").expect("test scope is not blank");
    let second_scope =
        WorkspaceControlScope::new(&host, "workspace-b").expect("test scope is not blank");

    cognition
        .initialize(&first_scope)
        .expect("the first cognition partition must initialize");
    let after_first = database_files(&cognition_root);
    assert_eq!(after_first.len(), 1);
    let first_partition = after_first
        .into_iter()
        .next()
        .expect("the first partition database");

    cognition
        .initialize(&second_scope)
        .expect("the second cognition partition must initialize");
    let after_second = database_files(&cognition_root);
    assert_eq!(after_second.len(), 2);
    let second_partition = after_second
        .into_iter()
        .find(|path| path.as_path() != first_partition.as_path())
        .expect("the second scope must add its own partition database");
    assert_ne!(first_partition, second_partition);
    assert_eq!(first_partition.parent(), Some(cognition_root.as_path()));
    assert_eq!(second_partition.parent(), Some(cognition_root.as_path()));

    let first_partition_bytes =
        std::fs::read(&first_partition).expect("the first partition must be readable");
    let second_partition_bytes =
        std::fs::read(&second_partition).expect("the second partition must be readable");
    assert_ne!(
        first_partition_bytes, second_partition_bytes,
        "each scope owns its own partition record"
    );
    let first_state_before = cognition
        .observe(&first_scope)
        .expect("the first partition must be observable");
    let second_state_before = cognition
        .observe(&second_scope)
        .expect("the second partition must be observable");
    assert!(first_state_before.is_some());
    assert!(second_state_before.is_some());

    // 4. Run the two real reset owners exactly as the desktop command does.
    memory
        .reset_memory_state()
        .await
        .expect("the legacy memory database reset must succeed");
    reset_memory_workspace(&legacy_workspace)
        .await
        .expect("the legacy memory workspace reset must succeed");

    // 5. The legacy radii are cleared and the legacy shape contract still holds.
    assert!(
        legacy_db.is_file(),
        "the legacy reset clears rows, not the database file"
    );
    {
        let connection = Connection::open(&legacy_db)
            .expect("the legacy memory database must open after the reset");
        validate_memory_schema(&connection)
            .expect("the legacy memory shape must still validate after the reset");
        let snapshot = read_memory_store_snapshot(&connection)
            .expect("the legacy memory store must read after the reset");
        assert!(
            snapshot.records.is_empty(),
            "the legacy reset must remove the memory rows"
        );
        assert!(
            snapshot.jobs.is_empty(),
            "the legacy reset must remove the memory jobs"
        );
    }
    assert_legacy_memory_shape_contract();
    assert!(
        legacy_workspace.is_dir(),
        "the legacy memory workspace root itself must stay"
    );
    assert_eq!(
        std::fs::read_dir(&legacy_workspace)
            .expect("the legacy memory workspace must be readable")
            .count(),
        0,
        "the legacy memory workspace reset must empty the root"
    );

    // 6. Both cognition partitions are untouched and still observable.
    assert!(first_partition.is_file());
    assert!(second_partition.is_file());
    assert_eq!(
        std::fs::read(&first_partition).expect("the first partition must be readable"),
        first_partition_bytes,
        "the legacy reset must not rewrite a cognition partition database"
    );
    assert_eq!(
        std::fs::read(&second_partition).expect("the second partition must be readable"),
        second_partition_bytes,
        "the legacy reset must not rewrite a cognition partition database"
    );
    assert_eq!(
        cognition
            .observe(&first_scope)
            .expect("the first partition must still be observable"),
        first_state_before
    );
    assert_eq!(
        cognition
            .observe(&second_scope)
            .expect("the second partition must still be observable"),
        second_state_before
    );
    let remaining_partitions = database_files(&cognition_root);
    assert_eq!(
        remaining_partitions.len(),
        2,
        "the legacy reset must not add or remove a cognition partition database"
    );
    assert!(remaining_partitions.contains(&first_partition));
    assert!(remaining_partitions.contains(&second_partition));

    // 7. The deletion radii do not overlap in either direction.
    assert!(
        !cognition_root.starts_with(&legacy_workspace),
        "the cognition root must not live under the legacy memory workspace root"
    );
    let legacy_db_dir = legacy_db
        .parent()
        .expect("the legacy memory database file must have a parent")
        .to_path_buf();
    assert!(
        !cognition_root.starts_with(&legacy_db_dir),
        "the legacy memory database directory must not be an ancestor of the cognition root"
    );
}
