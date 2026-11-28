//! The app-facing facade (WP3.1a), end to end over real storage.
//!
//! # What this file proves
//!
//! The facade is the only surface an application will drive, so every claim it makes has
//! to be true against real storage and not only against a hand-built value:
//!
//! - an off workspace is projected without this feature writing anything at all;
//! - the three tiers are projected with the availability that belongs to them;
//! - a queued preparation survives returning from `prepare_enable`, can be cancelled, and
//!    releases the scope lease exactly once;
//! - a confirmation through the facade stores the switch plus the decision, initializes
//!    the partition and reports the generation it left behind;
//! - a moved source, a tampered fingerprint, an unprepared target, an already-enabled
//!    target and a conflicting decision are refused with their own stable codes and write
//!    nothing;
//! - disabling is a compare-and-swap: a stale generation is refused, and the owner of the
//!    scope releases it after the pass this call triggers;
//! - a host that stopped reports the surface as unavailable instead of pretending.
//!
//! It never runs the offline legacy migration engine, never calls a model and never
//! claims cross-process or remote evidence: a `cargo test` run of this file is
//! single-process, local-filesystem evidence only.

use std::path::Path;
use std::sync::Arc;

use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
use openbitfun_services_core::workspace_intelligence_host_anchor::{
    HostAnchorState, HostAnchorStore,
};
use openbitfun_services_core::workspace_intelligence_store::{
    ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
    WorkspaceIntelligenceStore,
};

use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::host::WorkspaceIntelligenceHost;
use crate::service::workspace_intelligence::host_binding::LOCAL_EXECUTION_DOMAIN;
use crate::service::workspace_intelligence::host_fixture::{
    disable_workspace, enable_workspace, seed_legacy_memory_rows, seed_local_workspace,
    test_path_manager,
};
use crate::service::workspace_intelligence::legacy_preview::read_legacy_preview;
use crate::service::workspace_intelligence::migration::{
    encode_migration, MigrationDecision, MigrationSourceFingerprint,
};
use crate::service::workspace_intelligence::policy::CONTROL_SCHEMA_VERSION;
use crate::service::workspace_intelligence::scope::{
    HostExecutionDomainKey, WorkspaceControlScope,
};
use crate::service::workspace_intelligence::{
    AppRefusal, AssignmentInput, FingerprintDto, MigrationDecisionInput,
    WorkspaceIntelligenceHostSurface,
};

const WORKSPACE_ID: &str = "workspace-app";
const MODEL_REF: &str = "model-x";
const DECISION_KEY: &str = "decision-1";

/// One isolated user-data root with a seeded workspace and, optionally, a legacy source.
struct Fixture {
    _temp: tempfile::TempDir,
    paths: Arc<PathManager>,
}

async fn fixture(legacy_rows: usize) -> Fixture {
    let temp = tempfile::tempdir().expect("temporary root");
    let paths = test_path_manager(&temp.path().join("user"));
    seed_local_workspace(&paths, WORKSPACE_ID, &temp.path().join("workspace"))
        .await
        .expect("seed one local workspace");
    if legacy_rows > 0 {
        seed_legacy_memory_rows(&paths, legacy_rows)
            .await
            .expect("seed the legacy memory source");
    }
    Fixture {
        _temp: temp,
        paths,
    }
}

async fn host_of(fixture: &Fixture) -> WorkspaceIntelligenceHost {
    WorkspaceIntelligenceHost::bootstrap(
        Arc::clone(&fixture.paths),
        None,
        WorkspaceIntelligenceHostSurface::Desktop,
        RuntimeDeployment::Embedded,
    )
    .await
}

fn control_store(paths: &PathManager) -> WorkspaceIntelligenceStore {
    WorkspaceIntelligenceStore::new(
        paths.workspace_intelligence_control_dir(),
        vec![CONTROL_SCHEMA_VERSION],
    )
}

async fn scope_key(paths: &PathManager) -> String {
    let anchor = HostAnchorStore::new(paths.workspace_intelligence_dir())
        .read_strict()
        .await
        .expect("the anchor must be readable");
    let HostAnchorState::Present(anchor) = anchor else {
        panic!("a prepared scope always has an anchor");
    };
    let host = HostExecutionDomainKey::new(anchor.host_id(), LOCAL_EXECUTION_DOMAIN)
        .expect("a validated anchor id is never blank");
    WorkspaceControlScope::new(&host, WORKSPACE_ID)
        .expect("a seeded workspace id is never blank")
        .as_str()
}

async fn write_record(
    paths: &PathManager,
    expectation: ControlGenerationExpectation,
    patch: WorkspaceIntelligenceControlPatch,
) {
    let scope = scope_key(paths).await;
    control_store(paths)
        .update(&scope, expectation, patch)
        .await
        .expect("the fixture must be able to write the control record");
}

/// Number of stored control record files, so a refusal can prove it wrote nothing.
fn control_records(paths: &PathManager) -> usize {
    let Ok(entries) = std::fs::read_dir(paths.workspace_intelligence_control_dir()) else {
        return 0;
    };
    entries
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .count()
}

/// The one stored control record file of a single-scope fixture.
///
/// A test that must hand-patch the document reads and rewrites exactly this file, which is
/// the only way to produce a shape the store itself would never write.
fn single_control_record(paths: &PathManager) -> std::path::PathBuf {
    let mut files: Vec<std::path::PathBuf> =
        std::fs::read_dir(paths.workspace_intelligence_control_dir())
            .expect("the control directory must exist")
            .map(|entry| entry.expect("readable entry").path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
            .collect();
    files.sort();
    assert_eq!(files.len(), 1, "the fixture holds exactly one control record");
    files.pop().expect("one record")
}

/// Inserts one legacy row with an explicit workspace path.
///
/// [`seed_legacy_memory_rows`] always writes POSIX paths that cannot be attributed on this
/// host, so a test that needs a real attribution writes the row itself.
fn insert_legacy_row(database: &Path, thread_id: &str, workspace_path: &str) {
    let connection = rusqlite::Connection::open(database).expect("open the legacy database");
    connection
        .execute(
            "INSERT INTO stage1_outputs (thread_id, workspace_path, rollout_path, \
             source_updated_at, raw_memory, rollout_summary, generated_at, selected_for_phase2) \
             VALUES (?1, ?2, ?3, 5, 'raw memory', 'summary', 5, 0)",
            rusqlite::params![thread_id, workspace_path, format!("/legacy/{thread_id}.json")],
        )
        .expect("insert one legacy row");
}

/// Number of initialized cognition partition files.
fn partitions(paths: &PathManager) -> usize {
    let Ok(entries) = std::fs::read_dir(paths.workspace_intelligence_cognition_dir()) else {
        return 0;
    };
    entries
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite"))
        .count()
}

/// The stable fingerprint of the current legacy source, as a surface would echo it back.
fn fingerprint_of(paths: &PathManager) -> FingerprintDto {
    let preview = read_legacy_preview(&paths.memories_database_file(), &paths.memories_root_dir());
    FingerprintDto {
        row_count: preview.source.row_count,
        rows_digest: preview.source.rows_digest,
        schema_shape: preview.source.schema_shape,
        derived_tree_hash: preview.source.derived_tree_hash,
        notes_tree_hash: preview.source.notes_tree_hash,
        db_present: preview.source.db_present,
    }
}

/// One submitted decision that matches the current source.
fn decision_input(paths: &PathManager) -> MigrationDecisionInput {
    MigrationDecisionInput {
        idempotency_key: DECISION_KEY.to_owned(),
        decided_at_unix_ms: 1_700_000_000_000,
        source: fingerprint_of(paths),
        assignments: vec![AssignmentInput {
            kind: "keep_shared".to_owned(),
            key: "legacy-thread-0".to_owned(),
            workspace: None,
        }],
    }
}

fn append_legacy_row(database: &Path) {
    let connection = rusqlite::Connection::open(database).expect("open the legacy database");
    connection
        .execute(
            "INSERT INTO stage1_outputs (thread_id, workspace_path, rollout_path, \
             source_updated_at, raw_memory, rollout_summary, generated_at, selected_for_phase2) \
             VALUES ('late', '/legacy/late', '/legacy/late.json', 9, 'raw', 'summary', 9, 0)",
            [],
        )
        .expect("append one legacy row");
}

#[tokio::test]
async fn an_off_workspace_is_projected_without_writing_anything() {
    // No legacy source on purpose: this test is about the status projection alone.
    let fixture = fixture(0).await;
    let host = host_of(&fixture).await;
    let app = host.app();

    let status = app.status().await;
    assert_eq!(status.host_state, "inactive");
    assert!(status.surface_available);
    assert_eq!(status.unavailability, None);
    // An inactive host enumerated nothing, so it reports no rows instead of inventing one.
    assert!(status.scopes.is_empty());

    let row = app
        .scope_status(WORKSPACE_ID)
        .await
        .expect("a catalogued workspace must be projectable");
    assert_eq!(row.workspace_id, WORKSPACE_ID);
    assert_eq!(row.tier, "off");
    assert_eq!(row.availability, "available");
    assert!(!row.degraded);
    assert_eq!(row.generation, None);
    assert_eq!(row.migration, None);
    assert!(!row.binding_review_required);

    // Projecting a workspace must not create a control record, a lease or a cognition
    // root: this whole slice is a reader until a caller asks for a write.
    assert_eq!(control_records(&fixture.paths), 0);
    assert!(!fixture.paths.workspace_intelligence_lease_dir().exists());
    assert!(!fixture.paths.workspace_intelligence_cognition_dir().exists());

    let unknown = app
        .scope_status("workspace-not-in-catalog")
        .await
        .expect_err("an unknown workspace must be refused");
    assert_eq!(unknown, AppRefusal::WorkspaceNotFound);
    assert_eq!(unknown.code(), "workspace_not_found");
}

#[tokio::test]
async fn the_three_tiers_are_projected_with_their_own_availability() {
    // Baseline: the switch is on and no model reference is configured.
    let baseline = fixture(0).await;
    let seeded = enable_workspace(&baseline.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    assert_eq!(seeded.generation(), 1);
    let row = host_of(&baseline)
        .await
        .app()
        .scope_status(WORKSPACE_ID)
        .await
        .expect("an enabled workspace must be projectable");
    assert_eq!(row.tier, "baseline");
    assert_eq!(row.availability, "available");
    assert!(!row.degraded);
    assert_eq!(row.generation, Some(1));

    // Intelligent: the switch is on and a model reference is stored. The tree has no model
    // catalogue yet, so the reference is reported as unresolvable and the row is degraded
    // while keeping its tier.
    let intelligent = fixture(0).await;
    let seeded = disable_workspace(&intelligent.paths, WORKSPACE_ID, Some(MODEL_REF))
        .await
        .expect("seed one disabled record with a reference");
    write_record(
        &intelligent.paths,
        ControlGenerationExpectation::Exactly(seeded.generation()),
        WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            ..Default::default()
        },
    )
    .await;
    let host = host_of(&intelligent).await;
    let app = host.app();
    let row = app
        .scope_status(WORKSPACE_ID)
        .await
        .expect("an intelligent workspace must be projectable");
    assert_eq!(row.tier, "intelligent");
    assert_eq!(row.availability, "model_ref_unresolved");
    assert!(row.degraded);
    assert_eq!(row.generation, Some(2));
    // The batch projection reports the same two facts. The pass itself reports the scope
    // as blocked, because this fixture seeds a record without an execution binding: the
    // tier projection must not turn that host fact into a different tier or availability.
    let status = app.status().await;
    assert_eq!(status.scopes.len(), 1);
    let projected = &status.scopes[0];
    assert_eq!(projected.workspace_id, WORKSPACE_ID);
    assert_eq!(projected.tier, "intelligent");
    assert_eq!(projected.availability, "model_ref_unresolved");
    assert!(projected.host_state.is_some());
}

#[tokio::test]
async fn a_queued_preparation_can_be_cancelled_and_releases_the_lease() {
    let fixture = fixture(0).await;
    let host = host_of(&fixture).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 1);
    assert!(app.cancel_enable(WORKSPACE_ID).await);
    assert!(!app.cancel_enable(WORKSPACE_ID).await);
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 0);
    // The cancelled target can no longer be confirmed, and the lease it held is free.
    let error = app
        .confirm_enable(WORKSPACE_ID, decision_input(&fixture.paths))
        .await
        .expect_err("a cancelled preparation cannot be confirmed");
    assert_eq!(error, AppRefusal::NotPrepared);
    let second = host_of(&fixture).await;
    second
        .app()
        .prepare_enable(WORKSPACE_ID)
        .await
        .expect("a cancelled preparation must not keep the scope lease");
}

#[tokio::test]
async fn a_queued_preparation_is_not_revoked_by_returning_from_prepare() {
    let fixture = fixture(0).await;
    let host = host_of(&fixture).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    // The permit lives in the host's own book, not in the caller: nothing about returning
    // from `prepare_enable` may revoke it.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 1);
}

#[tokio::test]
async fn the_facade_confirms_an_initial_enable() {
    let fixture = fixture(2).await;
    let host = host_of(&fixture).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let report = app
        .confirm_enable(WORKSPACE_ID, decision_input(&fixture.paths))
        .await
        .expect("the confirmation must succeed");
    assert_eq!(report.outcome, "enabled");
    assert_eq!(report.generation, Some(1));
    assert_eq!(report.intelligent, Some(false));

    let record = control_store(&fixture.paths)
        .read(&scope_key(&fixture.paths).await)
        .await
        .expect("readable")
        .expect("the confirmation must have stored a record");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(record.control_generation, 1);
    assert!(record.migration.is_some());
    assert_eq!(partitions(&fixture.paths), 1);
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 0);

    // The stored decision is projected, so a surface can show what it confirmed without
    // reading the record itself.
    let row = app
        .scope_status(WORKSPACE_ID)
        .await
        .expect("the enabled workspace must be projectable");
    let migration = row.migration.expect("the confirmation stored a decision");
    assert_eq!(migration.idempotency_key, DECISION_KEY);
    assert_eq!(migration.assignment_counts.keep_shared, 1);
    assert_eq!(migration.assignment_counts.assign_to, 0);
    assert_eq!(migration.assignment_counts.defer_recall, 0);
}

#[tokio::test]
async fn the_facade_refuses_an_unprepared_and_an_already_enabled_workspace() {
    let unprepared = fixture(1).await;
    let host = host_of(&unprepared).await;
    let error = host
        .app()
        .confirm_enable(WORKSPACE_ID, decision_input(&unprepared.paths))
        .await
        .expect_err("nothing was prepared");
    assert_eq!(error, AppRefusal::NotPrepared);
    assert_eq!(error.code(), "not_prepared");
    assert_eq!(control_records(&unprepared.paths), 0);

    let enabled = fixture(1).await;
    let host = host_of(&enabled).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    write_record(
        &enabled.paths,
        ControlGenerationExpectation::Absent,
        WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            ..Default::default()
        },
    )
    .await;
    let error = app
        .confirm_enable(WORKSPACE_ID, decision_input(&enabled.paths))
        .await
        .expect_err("an enabled scope needs no initial enable");
    assert_eq!(error, AppRefusal::AlreadyEnabled);
    assert_eq!(error.code(), "already_enabled");
}

#[tokio::test]
async fn the_facade_refuses_a_moved_source_and_a_conflicting_decision() {
    let moved = fixture(2).await;
    let host = host_of(&moved).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_input(&moved.paths);
    append_legacy_row(&moved.paths.memories_database_file());
    let error = app
        .confirm_enable(WORKSPACE_ID, decision)
        .await
        .expect_err("a moved source must refuse");
    assert_eq!(error, AppRefusal::SourceChanged);
    assert_eq!(error.code(), "source_changed");
    assert_eq!(control_records(&moved.paths), 0);

    // Same idempotency key, different payload: a conflict, never a silent replacement.
    let conflicting = fixture(2).await;
    let decision = decision_input(&conflicting.paths);
    let stored = MigrationDecision {
        idempotency_key: DECISION_KEY.to_owned(),
        decided_at_unix_ms: decision.decided_at_unix_ms,
        source: MigrationSourceFingerprint {
            row_count: decision.source.row_count + 1,
            rows_digest: decision.source.rows_digest.clone(),
            schema_shape: decision.source.schema_shape.clone(),
            derived_tree_hash: decision.source.derived_tree_hash.clone(),
            notes_tree_hash: decision.source.notes_tree_hash.clone(),
            db_present: decision.source.db_present,
        },
        assignments: Vec::new(),
    };
    let seeded = disable_workspace(&conflicting.paths, WORKSPACE_ID, None)
        .await
        .expect("seed one disabled record");
    write_record(
        &conflicting.paths,
        ControlGenerationExpectation::Exactly(seeded.generation()),
        WorkspaceIntelligenceControlPatch {
            migration: ControlFieldUpdate::Set(encode_migration(&stored)),
            ..Default::default()
        },
    )
    .await;
    let host = host_of(&conflicting).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let error = app
        .confirm_enable(WORKSPACE_ID, decision)
        .await
        .expect_err("a conflicting payload must refuse");
    assert_eq!(error, AppRefusal::DecisionConflict);
    assert_eq!(error.code(), "decision_conflict");
}

#[tokio::test]
async fn a_tampered_fingerprint_is_refused_as_a_moved_source() {
    let fixture = fixture(2).await;
    let host = host_of(&fixture).await;
    let app = host.app();
    app.prepare_enable(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let mut decision = decision_input(&fixture.paths);
    // A surface that hands back a fingerprint other than the one it previewed is
    // describing a source that is not the one on disk.
    decision.source.row_count += 1;
    let error = app
        .confirm_enable(WORKSPACE_ID, decision)
        .await
        .expect_err("a tampered fingerprint must refuse");
    assert_eq!(error, AppRefusal::SourceChanged);
    assert_eq!(control_records(&fixture.paths), 0);
    assert_eq!(partitions(&fixture.paths), 0);
}

#[tokio::test]
async fn the_facade_disables_a_workspace_under_its_generation() {
    let fixture = fixture(0).await;
    let seeded = enable_workspace(&fixture.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    let host = host_of(&fixture).await;
    let app = host.app();
    let report = app
        .disable(WORKSPACE_ID, seeded.generation())
        .await
        .expect("the disable must succeed");
    assert!(report.changed);
    assert_eq!(report.generation, seeded.generation() + 1);
    let record = control_store(&fixture.paths)
        .read(&scope_key(&fixture.paths).await)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(false));
    // Disabling never deletes content: the partition the enable initialized stays.
    assert_eq!(partitions(&fixture.paths), 1);
    // The pass this call triggered reported the scope as off.
    let status = app.status().await;
    assert_eq!(
        status.scopes.first().map(|row| row.tier.as_str()),
        Some("off")
    );

    // Already off at the current generation: nothing is rewritten.
    let again = app
        .disable(WORKSPACE_ID, report.generation)
        .await
        .expect("a repeated disable is a no-op");
    assert!(!again.changed);
    assert_eq!(again.generation, report.generation);
}

#[tokio::test]
async fn the_facade_refuses_a_stale_disable_generation() {
    let fixture = fixture(0).await;
    let seeded = enable_workspace(&fixture.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    let host = host_of(&fixture).await;
    let app = host.app();
    let error = app
        .disable(WORKSPACE_ID, seeded.generation() - 1)
        .await
        .expect_err("a stale generation must refuse");
    assert_eq!(error, AppRefusal::StaleGeneration);
    assert_eq!(error.code(), "stale_generation");
    let record = control_store(&fixture.paths)
        .read(&scope_key(&fixture.paths).await)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(record.control_generation, seeded.generation());
}

#[tokio::test]
async fn a_standby_host_can_disable_that_the_owner_releases_after_its_pass() {
    let fixture = fixture(0).await;
    let seeded = enable_workspace(&fixture.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    let owner = host_of(&fixture).await;
    let standby = host_of(&fixture).await;
    // The owner holds the scope lease; the standby is only a candidate.
    let owner_status = owner.app().status().await;
    assert_eq!(
        owner_status.scopes.first().map(|row| row.host_state.as_deref()),
        Some(Some("active"))
    );
    // A control write is not lease-gated: the standby can switch the scope off.
    let report = standby
        .app()
        .disable(WORKSPACE_ID, seeded.generation())
        .await
        .expect("a standby host may write the control record");
    assert!(report.changed);
    // The owner releases the tenure on its next pass, which the disable already asked for.
    owner.evaluate_for_tests().await;
    let owner_status = owner.app().status().await;
    assert_eq!(
        owner_status.scopes.first().map(|row| row.host_state.as_deref()),
        Some(Some("disabled"))
    );
    // Its lease is free again, so the standby can prepare the scope.
    standby
        .app()
        .prepare_enable(WORKSPACE_ID)
        .await
        .expect("the released lease must be acquirable");
}

#[tokio::test]
async fn a_stopped_host_reports_the_surface_as_unavailable() {
    let fixture = fixture(0).await;
    let host = host_of(&fixture).await;
    let app = host.app();
    host.shutdown().await;
    let status = app.status().await;
    assert!(!status.surface_available);
    let code = status.unavailability.as_deref().unwrap_or_default();
    assert!(
        code == "host_draining" || code == "host_stopped",
        "unexpected unavailability {code}"
    );
    assert!(status.scopes.is_empty());
}

#[tokio::test]
async fn a_preview_is_projected_for_one_workspace() {
    let fixture = fixture(2).await;
    let host = host_of(&fixture).await;
    let report = host
        .app()
        .preview_legacy(WORKSPACE_ID)
        .await
        .expect("a preview must be readable");
    assert_eq!(report.fingerprint.row_count, 2);
    assert!(report.fingerprint.db_present);
    assert_eq!(report.fingerprint.schema_shape, fingerprint_of(&fixture.paths).schema_shape);
    // The seeded rows name POSIX paths that do not resolve on this host, so they stay
    // unattributed instead of being attributed to this workspace.
    assert!(report.attributed.is_empty());
    assert!(report.unattributed.len() >= 2);
    assert!(report
        .unattributed
        .iter()
        .any(|row| row.kind == "legacy_row" && row.reason == "unnormalizable_path"));
    // The seeded source has no notes directory, which is a legitimate empty note set: the
    // only diagnostic allowed here is that absence, never an unreadable-source code.
    assert!(
        report
            .diagnostics
            .iter()
            .all(|code| code == "notes_dir_absent"),
        "{:?}",
        report.diagnostics
    );
}

#[tokio::test]
async fn a_row_of_this_workspace_is_attributed_and_a_foreign_one_is_not() {
    // One row that names this workspace's own root, next to the POSIX rows the shared
    // seeder writes: the attribution has to separate the two, not just drop everything.
    let fixture = fixture(0).await;
    let root = fixture._temp.path().join("workspace");
    seed_legacy_memory_rows(&fixture.paths, 1)
        .await
        .expect("seed the legacy memory source");
    insert_legacy_row(
        &fixture.paths.memories_database_file(),
        "thread-here",
        &root.to_string_lossy(),
    );
    let report = host_of(&fixture)
        .await
        .app()
        .preview_legacy(WORKSPACE_ID)
        .await
        .expect("a preview must be readable");
    assert_eq!(report.fingerprint.row_count, 2);
    assert_eq!(report.attributed.len(), 1, "one row names this workspace");
    assert_eq!(report.attributed[0].thread_id, "thread-here");
    assert!(!report.attributed[0].content_hash.is_empty());
    // The seeded POSIX row cannot be normalized on this host, so it is never attributed to
    // this workspace and travels as an unattributed item.
    assert!(report
        .unattributed
        .iter()
        .any(|row| row.key == "legacy-thread-0" && row.reason == "unnormalizable_path"));
    assert!(!report
        .diagnostics
        .iter()
        .any(|code| code == "workspace_root_unresolvable"));
}

#[tokio::test]
async fn a_workspace_root_that_cannot_be_normalized_is_reported() {
    // The rows are readable and the source is fresh, but the workspace root the attribution
    // compares against is gone: the report must say so instead of returning an empty
    // attributed list a surface would read as "this workspace has no legacy content".
    let fixture = fixture(1).await;
    let root = fixture._temp.path().join("workspace");
    std::fs::remove_dir_all(&root).expect("remove the workspace root");
    let report = host_of(&fixture)
        .await
        .app()
        .preview_legacy(WORKSPACE_ID)
        .await
        .expect("a preview must be readable");
    assert!(report.attributed.is_empty());
    assert_eq!(report.fingerprint.row_count, 1);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|code| code == "workspace_root_unresolvable"),
        "{:?}",
        report.diagnostics
    );
}

#[tokio::test]
async fn an_unreadable_record_is_reported_as_unknown_and_not_as_off() {
    let fixture = fixture(0).await;
    let seeded = enable_workspace(&fixture.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    assert_eq!(seeded.generation(), 1);
    // Exactly what a rollback to an older binary sees when a newer build wrote the record:
    // the document declares a schema version this build does not accept.
    let path = single_control_record(&fixture.paths);
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("read the record"))
            .expect("the record is JSON");
    document["schema_version"] = serde_json::json!(CONTROL_SCHEMA_VERSION + 1);
    std::fs::write(&path, serde_json::to_vec(&document).expect("encode the record"))
        .expect("rewrite the record");
    let hand_patched = std::fs::read(&path).expect("read the record back");

    let host = host_of(&fixture).await;
    let row = host
        .app()
        .scope_status(WORKSPACE_ID)
        .await
        .expect("a workspace with an unreadable record must still be projectable");
    assert_eq!(row.tier, "off", "off is the fail-closed placeholder here");
    assert_eq!(row.availability, "control_unreadable");
    assert_eq!(row.control_fault.as_deref(), Some("schema_version_unsupported"));
    assert!(!row.degraded);
    assert_eq!(row.generation, None, "an unreadable record has no authority");
    assert_eq!(row.migration, None);
    // The batch projection answers the same way, and neither read rewrites the document.
    let status = host.app().status().await;
    let projected = status
        .scopes
        .iter()
        .find(|row| row.workspace_id == WORKSPACE_ID)
        .expect("the pass must report the workspace");
    assert_eq!(projected.availability, "control_unreadable");
    assert_eq!(
        projected.control_fault.as_deref(),
        Some("schema_version_unsupported")
    );
    assert_eq!(
        std::fs::read(&path).expect("read the record"),
        hand_patched,
        "projecting an unreadable record must not rewrite it"
    );
}
