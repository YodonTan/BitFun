//! Migration decision of the WP2.3 legacy Memory migration, end to end.
//!
//! # What this file proves
//!
//! The decision record is only useful if the three owners agree: the read-only
//! preview produces the source fingerprint, the pure decision module encodes and
//! decodes it, and the authority control record stores it next to the switch. No
//! single-module test can see all three, so the tests below run the real path over
//! one temporary root and one real SQLite file:
//!
//! - one control mutation opens the switch and stores the decision;
//! - the stored payload decodes back to the decision that was confirmed;
//! - the recorded source is current while the legacy source is unchanged, and
//!   stale once the database appears — the presence bit is part of the fingerprint
//!   precisely because an absent database and an equivalent empty one project the
//!   same rows, shape and trees.
//!
//! It never runs the offline legacy migration engine, never writes a cognition
//! partition and never calls a model. A `cargo test` run of this file is
//! single-process, local-filesystem evidence only: no cross-process evidence, no
//! Unix evidence and no remote-scenario evidence.

use crate::agentic::memories::workspace::MEMORY_SUMMARY_FILE_NAME;
use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::control::{
    ControlMutation, ControlMutationOutcome, HostExecutionDomainKey, WorkspaceControlScope,
    WorkspaceIntelligenceControl,
};
use crate::service::workspace_intelligence::legacy_preview::read_legacy_preview;
use crate::service::workspace_intelligence::migration::{
    decode_migration, encode_migration, is_stale, MigrationDecision, MigrationSourceFingerprint,
};
use crate::service::workspace_intelligence::mode::{
    CapabilityDelivery, WorkspaceIntelligenceTier, WorkspaceModelRef, WorkspaceModelResolution,
};
use openbitfun_services_core::workspace_intelligence_store::ControlGenerationExpectation;
use rusqlite::Connection;
use std::fs;
use std::path::Path;

/// The documented `stage1_outputs` shape, spelled out so a fixture does not depend
/// on an initialize helper the preview is forbidden to call.
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

fn host() -> HostExecutionDomainKey {
    HostExecutionDomainKey::new("host-1", "local").expect("test host key must be non-blank")
}

fn scope_of(host: &HostExecutionDomainKey, workspace_id: &str) -> WorkspaceControlScope {
    WorkspaceControlScope::new(host, workspace_id).expect("test scope must be non-blank")
}

/// Resolver for observations that must not be interpreted here.
fn resolved(_: &WorkspaceModelRef) -> WorkspaceModelResolution {
    WorkspaceModelResolution::Resolved
}

/// One memory workspace root with a derived file, so the fingerprint has real tree
/// content instead of two empty hashes.
fn memory_root(root: &Path) -> std::path::PathBuf {
    let memory_root = root.join("memories");
    fs::create_dir_all(&memory_root).expect("create the memory root");
    fs::write(memory_root.join(MEMORY_SUMMARY_FILE_NAME), "summary")
        .expect("write a derived file");
    memory_root
}

fn create_empty_memory_db(db_path: &Path) {
    let connection = Connection::open(db_path).expect("create the memory database");
    connection
        .execute_batch(&format!("{STAGE1_OUTPUTS_DDL};{JOBS_DDL};"))
        .expect("create the memory schema");
    drop(connection);
}

/// The decision a confirmation surface would produce for the given preview source.
fn decision_for(source: MigrationSourceFingerprint, idempotency_key: &str) -> MigrationDecision {
    MigrationDecision {
        idempotency_key: idempotency_key.to_string(),
        decided_at_unix_ms: 1_700_000_000_000,
        source,
        assignments: Vec::new(),
    }
}

#[tokio::test]
async fn a_confirmed_decision_lands_in_the_control_record_and_is_readable() {
    let fixture = tempfile::tempdir().expect("temporary root");
    let db_path = fixture.path().join("memories.sqlite");
    let memory_root = memory_root(fixture.path());
    let user_root = fixture.path().join("user");
    let paths = PathManager::with_user_root_for_tests(user_root);
    let control = WorkspaceIntelligenceControl::for_host(&paths, host());
    let scope = scope_of(control.host(), "workspace-a");

    // The legacy source does not exist yet; the preview says so instead of failing.
    let preview = read_legacy_preview(&db_path, &memory_root);
    assert!(!preview.source.db_present);

    let decision = decision_for(MigrationSourceFingerprint::from_preview(&preview.source), "dec-1");
    let outcome = control
        .apply(
            &scope,
            ControlGenerationExpectation::Absent,
            ControlMutation::EnableWithMigration {
                migration: encode_migration(&decision),
            },
        )
        .await
        .expect("enabling with a decision must succeed");
    assert!(matches!(outcome, ControlMutationOutcome::Applied(_)));

    // The switch and the decision are one record, and the decision decodes back to
    // exactly what was confirmed.
    let observation = control
        .observe(&scope, CapabilityDelivery::Delivered, resolved)
        .await
        .expect("the record must be observable");
    assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Baseline);
    assert_eq!(observation.read.enabled, Some(true));
    let stored = decode_migration(&observation.read.preserved["migration"])
        .expect("the stored decision must decode");
    assert_eq!(stored, decision);
    assert!(!is_stale(&stored, &preview.source), "the source has not moved");

    // A fresh read of the same unchanged source still matches, so a repeated
    // confirmation would reconcile as unchanged rather than as a moved source.
    let again = read_legacy_preview(&db_path, &memory_root);
    assert!(!is_stale(&stored, &again.source));
}

#[tokio::test]
async fn a_decision_made_on_a_missing_database_is_stale_once_it_appears() {
    let fixture = tempfile::tempdir().expect("temporary root");
    let db_path = fixture.path().join("memories.sqlite");
    let memory_root = memory_root(fixture.path());
    let user_root = fixture.path().join("user");
    let paths = PathManager::with_user_root_for_tests(user_root);
    let control = WorkspaceIntelligenceControl::for_host(&paths, host());
    let scope = scope_of(control.host(), "workspace-a");

    let absent = read_legacy_preview(&db_path, &memory_root);
    assert!(!absent.source.db_present);
    let decision = decision_for(MigrationSourceFingerprint::from_preview(&absent.source), "dec-1");
    control
        .apply(
            &scope,
            ControlGenerationExpectation::Absent,
            ControlMutation::EnableWithMigration {
                migration: encode_migration(&decision),
            },
        )
        .await
        .expect("enabling with a decision must succeed");

    // An equivalent but existing empty database is a moved source: the rows, shape
    // and trees are identical, so only the presence bit can tell the difference.
    create_empty_memory_db(&db_path);
    let present = read_legacy_preview(&db_path, &memory_root);
    assert!(present.source.db_present);
    assert_eq!(absent.source.row_count, present.source.row_count);
    assert_eq!(absent.source.rows_digest, present.source.rows_digest);
    assert_eq!(absent.source.schema_shape, present.source.schema_shape);

    let observation = control
        .observe(&scope, CapabilityDelivery::Delivered, resolved)
        .await
        .expect("the record must be observable");
    let stored = decode_migration(&observation.read.preserved["migration"])
        .expect("the stored decision must decode");
    assert!(
        is_stale(&stored, &present.source),
        "a decision made on a missing database must not stay current for an empty one"
    );
}
