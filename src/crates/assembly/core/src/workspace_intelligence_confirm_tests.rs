//! The confirmed initial enable (WP2.4b), end to end over real storage.
//!
//! # What this file proves
//!
//! One confirmation is the only OFF-to-ON transition of a scope, and it is only
//! safe if five owners agree: the catalog seed names the workspace, the
//! preparation mints the anchor and queues one lease, the legacy preview produces
//! the fingerprint the decision recorded, the control store holds the switch and
//! the decision in one record, and the claim pass initializes the partition. No
//! single-module test can see all five, so the tests below run the real path over
//! one temporary user-data root, one real SQLite control store and one real SQLite
//! legacy database:
//!
//! - one confirmation stores the switch plus the decision, advances the generation
//!   once, and leaves the partition initialized;
//! - a moved, unreadable, already-enabled, conflicting or unprepared target is
//!   refused with a typed code and writes nothing;
//! - a cancelled confirmation releases the tenure it had already taken;
//! - a record that reads ON without a partition is recovered by the ordinary
//!   evaluation pass, which is the crash window the confirmation leaves behind
//!   when its fence refuses.
//!
//! It never runs the offline legacy migration engine, never calls a model and
//! never claims cross-process or remote evidence: a `cargo test` run of this file
//! is single-process, local-filesystem evidence only.

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
use crate::service::workspace_intelligence::confirm::{ConfirmOutcome, ConfirmRefusal};
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
use crate::service::workspace_intelligence::WorkspaceIntelligenceHostSurface;

const WORKSPACE_ID: &str = "workspace-confirm";
const MODEL_REF: &str = "model-x";

/// One isolated user-data root with a seeded workspace and a legacy source.
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
    seed_legacy_memory_rows(&paths, legacy_rows)
        .await
        .expect("seed the legacy memory source");
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

/// The decision a confirmation surface would produce for the current source.
fn decision_for(paths: &PathManager, key: &str) -> MigrationDecision {
    let preview = read_legacy_preview(&paths.memories_database_file(), &paths.memories_root_dir());
    MigrationDecision {
        idempotency_key: key.to_owned(),
        decided_at_unix_ms: 1_700_000_000_000,
        source: MigrationSourceFingerprint::from_preview(&preview.source),
        assignments: Vec::new(),
    }
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

fn control_store(paths: &PathManager) -> WorkspaceIntelligenceStore {
    WorkspaceIntelligenceStore::new(
        paths.workspace_intelligence_control_dir(),
        vec![CONTROL_SCHEMA_VERSION],
    )
}

/// Number of control record files, so a refusal can prove it wrote nothing.
fn control_records(paths: &PathManager) -> usize {
    let Ok(entries) = std::fs::read_dir(paths.workspace_intelligence_control_dir()) else {
        return 0;
    };
    entries
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .count()
}

/// Number of cognition partition files.
fn partitions(paths: &PathManager) -> usize {
    let Ok(entries) = std::fs::read_dir(paths.workspace_intelligence_cognition_dir()) else {
        return 0;
    };
    entries
        .map(|entry| entry.expect("readable entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("sqlite"))
        .count()
}

async fn write_record(
    paths: &PathManager,
    scope: &str,
    expectation: ControlGenerationExpectation,
    patch: WorkspaceIntelligenceControlPatch,
) {
    control_store(paths)
        .update(scope, expectation, patch)
        .await
        .expect("the fixture must be able to write the control record");
}

fn replace_with_garbage(path: &Path) {
    std::fs::write(path, b"not a sqlite database").expect("replace the legacy database");
}

#[tokio::test]
async fn a_confirmed_initial_enable_turns_the_scope_on_and_initializes_the_partition() {
    let fixture = fixture(2).await;
    let host = host_of(&fixture).await;
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    let outcome = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision.clone())
        .await
        .expect("the confirmation must succeed");
    assert_eq!(
        outcome,
        ConfirmOutcome::Enabled {
            generation: 1,
            intelligent: false
        }
    );
    let record = control_store(&fixture.paths)
        .read(&scope_key(&fixture.paths).await)
        .await
        .expect("the record must be readable")
        .expect("the confirmation must have stored a record");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(record.control_generation, 1);
    assert_eq!(record.migration, Some(encode_migration(&decision)));
    // The confirmation drops the claim it promoted, so no queued tenure is left and
    // the ordinary pass initialized the partition.
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 0);
    assert_eq!(partitions(&fixture.paths), 1);
    drop(permit);
}

#[tokio::test]
async fn a_confirmed_initial_enable_keeps_a_configured_model_reference() {
    let fixture = fixture(1).await;
    let seeded = disable_workspace(&fixture.paths, WORKSPACE_ID, Some(MODEL_REF))
        .await
        .expect("seed one disabled record");
    assert_eq!(seeded.generation(), 1);
    let host = host_of(&fixture).await;
    let _permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    let outcome = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision)
        .await
        .expect("the confirmation must succeed");
    assert_eq!(
        outcome,
        ConfirmOutcome::Enabled {
            generation: 2,
            intelligent: true
        }
    );
    let record = control_store(&fixture.paths)
        .read(&scope_key(&fixture.paths).await)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(record.model_ref.as_deref(), Some(MODEL_REF));
    assert_eq!(record.control_generation, 2);
}

#[tokio::test]
async fn a_moved_legacy_source_refuses_the_confirmation_and_writes_nothing() {
    let fixture = fixture(2).await;
    let host = host_of(&fixture).await;
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    // The source moves after the decision was taken.
    let database = fixture.paths.memories_database_file();
    let connection = rusqlite::Connection::open(&database).expect("open the legacy database");
    connection
        .execute(
            "INSERT INTO stage1_outputs (thread_id, workspace_path, rollout_path, \
             source_updated_at, raw_memory, rollout_summary, generated_at, selected_for_phase2) \
             VALUES ('late', '/legacy/late', '/legacy/late.json', 9, 'raw', 'summary', 9, 0)",
            [],
        )
        .expect("append one legacy row");
    drop(connection);
    let error = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision)
        .await
        .expect_err("a moved source must refuse");
    assert_eq!(error, ConfirmRefusal::SourceChanged);
    assert_eq!(error.code(), "source_changed");
    assert_eq!(control_records(&fixture.paths), 0, "a refusal writes no record");
    assert_eq!(partitions(&fixture.paths), 0, "a refusal creates no partition");
    drop(permit);
    // The refusal released the tenure it had taken: another host can prepare.
    let second = host_of(&fixture).await;
    assert!(second
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .is_ok());
}

#[tokio::test]
async fn an_unreadable_legacy_source_refuses_the_confirmation() {
    // Zero rows on purpose: replacing the file then leaves the fingerprint equal
    // (no rows, same trees, still present), so the refusal can only come from the
    // unreadable diagnostic and not from staleness.
    let fixture = fixture(0).await;
    let host = host_of(&fixture).await;
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    replace_with_garbage(&fixture.paths.memories_database_file());
    let error = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision)
        .await
        .expect_err("an unreadable source must refuse");
    assert_eq!(error, ConfirmRefusal::SourceUnreadable);
    assert_eq!(error.code(), "source_unreadable");
    assert_eq!(control_records(&fixture.paths), 0);
    drop(permit);
}

#[tokio::test]
async fn a_scope_enabled_by_another_writer_refuses_the_confirmation() {
    let fixture = fixture(1).await;
    let host = host_of(&fixture).await;
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    let scope = scope_key(&fixture.paths).await;
    write_record(
        &fixture.paths,
        &scope,
        ControlGenerationExpectation::Absent,
        WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            ..Default::default()
        },
    )
    .await;
    let error = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision)
        .await
        .expect_err("an enabled scope needs no initial enable");
    assert_eq!(error, ConfirmRefusal::AlreadyEnabled);
    assert_eq!(error.code(), "already_enabled");
    drop(permit);
}

#[tokio::test]
async fn a_stored_decision_with_a_different_payload_refuses_the_confirmation() {
    let fixture = fixture(2).await;
    let decision = decision_for(&fixture.paths, "decision-1");
    // Same idempotency key, different source: a conflicting confirmation, not a
    // replay. It is stored before the preparation, because a write between the
    // preparation and the confirmation is refused earlier as a changed record.
    let mut conflicting = decision.clone();
    conflicting.source.row_count = 99;
    let seeded = disable_workspace(&fixture.paths, WORKSPACE_ID, None)
        .await
        .expect("seed one disabled record");
    let scope = scope_key(&fixture.paths).await;
    write_record(
        &fixture.paths,
        &scope,
        ControlGenerationExpectation::Exactly(seeded.generation()),
        WorkspaceIntelligenceControlPatch {
            migration: ControlFieldUpdate::Set(encode_migration(&conflicting)),
            ..Default::default()
        },
    )
    .await;
    let host = host_of(&fixture).await;
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let error = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision)
        .await
        .expect_err("a conflicting payload must refuse");
    assert_eq!(error, ConfirmRefusal::DecisionConflict);
    assert_eq!(error.code(), "decision_conflict");
    let record = control_store(&fixture.paths)
        .read(&scope)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(false), "the refusal must not open the switch");
    assert_eq!(
        record.migration,
        Some(encode_migration(&conflicting)),
        "the stored decision must stay exactly as it was"
    );
    drop(permit);
}

#[tokio::test]
async fn an_already_stored_identical_decision_only_replays_the_enable() {
    let fixture = fixture(1).await;
    let host = host_of(&fixture).await;
    let decision = decision_for(&fixture.paths, "decision-1");
    let seeded = disable_workspace(&fixture.paths, WORKSPACE_ID, None)
        .await
        .expect("seed one disabled record");
    let scope = scope_key(&fixture.paths).await;
    write_record(
        &fixture.paths,
        &scope,
        ControlGenerationExpectation::Exactly(seeded.generation()),
        WorkspaceIntelligenceControlPatch {
            migration: ControlFieldUpdate::Set(encode_migration(&decision)),
            ..Default::default()
        },
    )
    .await;
    let _permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let outcome = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision.clone())
        .await
        .expect("an identical decision replays");
    // The decision did not change, so only the switch moved: the generation is the
    // one the record already had plus that one write.
    assert_eq!(
        outcome,
        ConfirmOutcome::Enabled {
            generation: 3,
            intelligent: false
        }
    );
    let record = control_store(&fixture.paths)
        .read(&scope)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(record.migration, Some(encode_migration(&decision)));
}

#[tokio::test]
async fn an_unprepared_scope_refuses_the_confirmation() {
    let fixture = fixture(1).await;
    let host = host_of(&fixture).await;
    let error = host
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision_for(&fixture.paths, "decision-1"))
        .await
        .expect_err("nothing was prepared");
    assert_eq!(error, ConfirmRefusal::NotPrepared);
    assert_eq!(error.code(), "not_prepared");
    assert_eq!(control_records(&fixture.paths), 0);
}

#[tokio::test]
async fn only_one_host_can_prepare_and_confirm_one_scope() {
    let fixture = fixture(1).await;
    let first = host_of(&fixture).await;
    let second = host_of(&fixture).await;
    let permit = first
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the first preparation must succeed");
    let error = second
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .err()
        .expect("the lease is already held");
    assert_eq!(error.code(), "reserve_busy");
    // The second host queued nothing, so it cannot confirm anything either.
    let error = second
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision_for(&fixture.paths, "decision-1"))
        .await
        .expect_err("nothing was prepared on this host");
    assert_eq!(error, ConfirmRefusal::NotPrepared);
    let outcome = first
        .confirm_initial_enable_for_tests(WORKSPACE_ID, decision_for(&fixture.paths, "decision-1"))
        .await
        .expect("the prepared host confirms");
    assert!(matches!(outcome, ConfirmOutcome::Enabled { .. }));
    drop(permit);
}

#[tokio::test]
async fn a_record_that_reads_on_without_a_partition_is_recovered_by_the_next_pass() {
    // The crash window a fence refusal can leave behind: the switch is stored, the
    // execution binding is stored, but no partition was initialized. The ordinary
    // evaluation pass must recover it, so recovery never depends on a second
    // confirmation.
    let fixture = fixture(1).await;
    let seeded = enable_workspace(&fixture.paths, WORKSPACE_ID)
        .await
        .expect("seed one enabled record");
    assert_eq!(seeded.generation(), 1);
    assert_eq!(
        partitions(&fixture.paths),
        0,
        "the fixture starts without a partition"
    );
    let host = host_of(&fixture).await;
    host.evaluate_for_tests().await;
    assert_eq!(
        partitions(&fixture.paths),
        1,
        "the pass must initialize the partition"
    );
    let scope = scope_key(&fixture.paths).await;
    let record = control_store(&fixture.paths)
        .read(&scope)
        .await
        .expect("readable")
        .expect("stored");
    assert_eq!(record.enabled, Some(true));
    assert_eq!(
        record.control_generation, 1,
        "recovery must not rewrite the authority"
    );
}

#[tokio::test]
async fn a_cancelled_confirmation_releases_the_tenure_it_took() {
    let fixture = fixture(1).await;
    let host = host_of(&fixture).await;
    let mut pause = WorkspaceIntelligenceHost::install_confirm_take_pause_for_tests(&fixture.paths);
    let permit = host
        .prepare_initial_enable_for_tests(WORKSPACE_ID)
        .await
        .expect("the preparation must succeed");
    let decision = decision_for(&fixture.paths, "decision-1");
    let mut confirmation = Box::pin(host.confirm_initial_enable_for_tests(WORKSPACE_ID, decision));
    tokio::select! {
        () = pause.entered() => {}
        outcome = &mut confirmation => panic!("the confirmation must park: {outcome:?}"),
    }
    // Parked after the take and before any read: the tenure is out of its slot.
    assert_eq!(host.live_initial_enable_pendings_for_tests().await, 0);
    drop(confirmation);
    pause.release();
    // The lease the guard released is free again: a fresh host can prepare.
    let second = host_of(&fixture).await;
    assert!(
        second
            .prepare_initial_enable_for_tests(WORKSPACE_ID)
            .await
            .is_ok(),
        "a cancelled confirmation must not keep the scope lease"
    );
    drop(permit);
}
