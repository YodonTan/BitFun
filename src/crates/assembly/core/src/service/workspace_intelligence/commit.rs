//! Thin core wrapper over the services governed-commit fence. The fence belongs
//! to services and is not re-implemented here.
//!
//! Recovers the cognition partition of an already-enabled scope only: NOT the
//! OFF-to-ON enabling path, no bootstrap/claim or lease, no cursor or incarnation-
//! token write. This is not a WP1.2b exit and not a P1 exit.
//!
//! Construction is pure assembly with no IO or side effects. There is no
//! background task, runtime, scheduler, provider, model resolution or UI here.
//! `accepts` is a pure policy seam executed outside any guard; services never
//! executes it. Today it equals the services structural `enabled == Some(true)`
//! precondition. It can only make admission stricter, never license a stale
//! commit. BASELINE recovery needs no model reference or model resolution.
//!
//! Direct `WorkspaceIntelligenceCognitionStore::initialize` remains an
//! unauthorized low-level storage primitive, not a governance path. This wrapper
//! never writes the control record, holds no cognition transaction and takes no
//! lock of its own: control-guard -> SQLite ordering belongs entirely to services.
//!
//! Windows-local two-process evidence exists for the services gate (commit 1);
//! Unix, remote scenarios and process-kill behaviour are unverified here.

use std::path::PathBuf;

use openbitfun_services_core::workspace_intelligence_cognition::CognitionInitialization;
use openbitfun_services_core::workspace_intelligence_commit::{
    GovernedCommitAuthority, GovernedCommitIntent, GovernedCommitOutcome, GovernedCommitRefusal,
    GovernedOwnerCommitResult, WorkspaceIntelligenceCommitError, WorkspaceIntelligenceCommitGate,
};
use openbitfun_services_core::workspace_intelligence_store::{
    WorkspaceIntelligenceStore, WorkspaceIntelligenceStoreError,
};

use crate::infrastructure::PathManager;

use super::policy::CONTROL_SCHEMA_VERSION;
use super::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// One host's internal assembly of the services fence, with no cached authority.
#[derive(Debug)]
pub(crate) struct WorkspaceIntelligenceCommit {
    gate: WorkspaceIntelligenceCommitGate,
    host: HostExecutionDomainKey,
}

impl WorkspaceIntelligenceCommit {
    /// Pure assembly over the host's own roots; no reads or directory creation.
    pub(crate) fn for_host(paths: &PathManager, host: HostExecutionDomainKey) -> Self {
        Self::with_roots(
            paths.workspace_intelligence_control_dir(),
            paths.workspace_intelligence_cognition_dir(),
            host,
        )
    }

    /// Pure assembly over explicit host-local roots and exactly one schema version.
    pub(crate) fn with_roots(
        control_root: PathBuf,
        cognition_root: PathBuf,
        host: HostExecutionDomainKey,
    ) -> Self {
        let store = WorkspaceIntelligenceStore::new(control_root, vec![CONTROL_SCHEMA_VERSION]);
        Self {
            gate: WorkspaceIntelligenceCommitGate::new(store, cognition_root),
            host,
        }
    }

    pub(crate) fn host(&self) -> &HostExecutionDomainKey {
        &self.host
    }

    /// Observes internally and asks the services fence to recover an enabled scope.
    /// No caller-supplied snapshot, expected generation or local fallback exists.
    pub(crate) async fn recover_enabled_partition(
        &self,
        scope: &WorkspaceControlScope,
    ) -> Result<PartitionRecovery, CommitError> {
        if !scope.host_matches(&self.host) {
            return Err(CommitError::HostScopeMismatch);
        }
        let observed = match self.gate.observe(&scope.as_str()).await {
            Ok(observed) => observed,
            Err(WorkspaceIntelligenceCommitError::Control(error)) => {
                return Err(CommitError::Store(error));
            }
            // observe produces only Control today; preserve future errors losslessly.
            Err(error) => return Err(CommitError::Commit(error)),
        };
        let Some(snapshot) = observed else {
            return Ok(PartitionRecovery::Refused(GovernedCommitRefusal::NotObserved));
        };
        // Pure policy outside any guard; only services owns the guarded fresh read.
        if !accepts(snapshot.authority()) {
            return Ok(PartitionRecovery::Refused(GovernedCommitRefusal::NotEnabled));
        }
        let outcome = self
            .gate
            .commit(&snapshot, GovernedCommitIntent::RecoverEnabledCognitionPartition)
            .await?;
        Ok(recovery_of(outcome))
    }
}

#[derive(Debug)]
pub(crate) enum PartitionRecovery {
    Recovered {
        control_generation: u64,
        initialization: CognitionInitialization,
    },
    Refused(GovernedCommitRefusal),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CommitError {
    #[error("the scope is owned by a different host and execution domain")]
    HostScopeMismatch,
    /// The authoritative control record could not be read; its own fault is preserved.
    #[error(transparent)]
    Store(WorkspaceIntelligenceStoreError),
    /// Any other governed-commit failure, preserved losslessly.
    #[error(transparent)]
    Commit(#[from] WorkspaceIntelligenceCommitError),
}

/// Pure policy seam: zero IO, clock, environment or global state. Services never
/// executes it. Currently equivalent to its structural enabled precondition;
/// model quality and model references do not participate in recovery admission.
fn accepts(authority: &GovernedCommitAuthority) -> bool {
    authority.enabled() == Some(true)
}

fn recovery_of(outcome: GovernedCommitOutcome) -> PartitionRecovery {
    match outcome {
        GovernedCommitOutcome::Committed {
            authority,
            owner: GovernedOwnerCommitResult::CognitionPartition(initialization),
        } => PartitionRecovery::Recovered {
            control_generation: authority.control_generation(),
            initialization,
        },
        GovernedCommitOutcome::Refused(reason) => PartitionRecovery::Refused(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbitfun_services_core::workspace_intelligence_cognition::{
        CognitionPartitionState, WorkspaceIntelligenceCognitionStore,
    };
    use openbitfun_services_core::workspace_intelligence_store::{
        ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
    };
    use std::path::Path;

    fn host(id: &str, domain: &str) -> HostExecutionDomainKey {
        HostExecutionDomainKey::new(id, domain).unwrap()
    }

    fn scope(handle: &WorkspaceIntelligenceCommit, workspace: &str) -> WorkspaceControlScope {
        WorkspaceControlScope::new(handle.host(), workspace).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, PathManager, WorkspaceIntelligenceCommit) {
        let fixture = tempfile::tempdir().unwrap();
        let paths = PathManager::with_user_root_for_tests(fixture.path().join("user"));
        let handle = WorkspaceIntelligenceCommit::for_host(&paths, host("host-1", "local"));
        (fixture, paths, handle)
    }

    fn store(handle: &WorkspaceIntelligenceCommit) -> WorkspaceIntelligenceStore {
        WorkspaceIntelligenceStore::new(
            handle.gate.control_root().to_path_buf(),
            vec![CONTROL_SCHEMA_VERSION],
        )
    }

    async fn seed(
        handle: &WorkspaceIntelligenceCommit,
        scope: &WorkspaceControlScope,
        enabled: bool,
        model_ref: Option<&str>,
    ) {
        store(handle)
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(enabled),
                    model_ref: model_ref
                        .map(|value| ControlFieldUpdate::Set(value.to_owned()))
                        .unwrap_or_default(),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    fn files(root: &Path, extension: &str) -> Vec<PathBuf> {
        if !root.exists() {
            return Vec::new();
        }
        let mut files: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
            .collect();
        files.sort();
        files
    }

    fn control_bytes(handle: &WorkspaceIntelligenceCommit) -> Vec<u8> {
        let records = files(handle.gate.control_root(), "json");
        assert_eq!(records.len(), 1);
        std::fs::read(&records[0]).unwrap()
    }

    fn recovered(result: PartitionRecovery, generation: u64, initialized: bool) {
        let PartitionRecovery::Recovered { control_generation, initialization } = result else {
            panic!("expected recovery: {result:?}");
        };
        assert_eq!(control_generation, generation);
        assert_eq!(initialization.is_initialized(), initialized);
        assert_eq!(initialization.state(), &CognitionPartitionState {
            cursor: None,
            incarnation_token: None,
        });
    }

    fn refused(result: PartitionRecovery, code: &str) {
        match result {
            PartitionRecovery::Refused(reason) => assert_eq!(reason.code(), code),
            other => panic!("expected {code}: {other:?}"),
        }
    }

    #[test]
    fn for_host_is_pure_and_uses_the_host_roots() {
        let (fixture, paths, handle) = fixture();
        assert_eq!(handle.host(), &host("host-1", "local"));
        assert_eq!(handle.gate.control_root(), paths.workspace_intelligence_control_dir());
        assert_eq!(handle.gate.cognition_root(), paths.workspace_intelligence_cognition_dir());
        assert!(!paths.user_data_dir().exists());
        assert!(!handle.gate.control_root().exists());
        assert!(!handle.gate.cognition_root().exists());
        // The entire fixture is empty: construction created no lock file either.
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn host_mismatch_is_rejected_before_any_storage() {
        let (fixture, paths, handle) = fixture();
        for foreign in [host("host-2", "local"), host("host-1", "sandbox")] {
            let scope = WorkspaceControlScope::new(&foreign, "workspace-a").unwrap();
            assert!(matches!(handle.recover_enabled_partition(&scope).await,
                Err(CommitError::HostScopeMismatch)));
        }
        assert!(!paths.user_data_dir().exists());
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn missing_record_is_not_observed_without_creating_anything() {
        let (fixture, _, handle) = fixture();
        refused(handle.recover_enabled_partition(&scope(&handle, "a")).await.unwrap(),
            "not_observed");
        assert!(!handle.gate.control_root().exists());
        assert!(!handle.gate.cognition_root().exists());
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn disabled_record_is_not_enabled_without_cognition_writes() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, false, None).await;
        let before = control_bytes(&handle);
        refused(handle.recover_enabled_partition(&scope).await.unwrap(), "not_enabled");
        assert_eq!(control_bytes(&handle), before);
        assert!(!handle.gate.cognition_root().exists());
    }

    #[tokio::test]
    async fn baseline_enabled_without_a_model_reference_recovers() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, true, None).await;
        recovered(handle.recover_enabled_partition(&scope).await.unwrap(), 1, true);
        let record = store(&handle).read(&scope.as_str()).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.schema_version, Some(CONTROL_SCHEMA_VERSION));
        assert_eq!(record.model_ref, None);
        assert!(!record.raw.as_object().unwrap().contains_key("model_ref"));
        // read validates the v1 schema and scope binding, not just file existence.
        let state = WorkspaceIntelligenceCognitionStore::new(handle.gate.cognition_root().to_path_buf())
            .read(&scope.as_str()).unwrap().unwrap();
        assert_eq!(state, CognitionPartitionState { cursor: None, incarnation_token: None });
    }

    #[tokio::test]
    async fn an_enabled_model_reference_does_not_change_acceptance() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, true, Some("workspace-model-a")).await;
        // There is no resolver parameter at all: neither this call nor accepts resolves a model.
        recovered(handle.recover_enabled_partition(&scope).await.unwrap(), 1, true);
        let record = store(&handle).read(&scope.as_str()).await.unwrap().unwrap();
        assert_eq!(record.model_ref.as_deref(), Some("workspace-model-a"));
    }

    #[tokio::test]
    async fn second_recovery_reports_existing_without_rewriting() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, true, None).await;
        let control = control_bytes(&handle);
        recovered(handle.recover_enabled_partition(&scope).await.unwrap(), 1, true);
        assert_eq!(control_bytes(&handle), control);
        let databases = files(handle.gate.cognition_root(), "sqlite");
        assert_eq!(databases.len(), 1);
        let bytes = std::fs::read(&databases[0]).unwrap();
        recovered(handle.recover_enabled_partition(&scope).await.unwrap(), 1, false);
        assert_eq!(control_bytes(&handle), control);
        assert_eq!(files(handle.gate.cognition_root(), "sqlite"), databases);
        assert_eq!(std::fs::read(&databases[0]).unwrap(), bytes);
    }

    #[tokio::test]
    async fn committed_outcome_preserves_generation_and_initialization() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, true, None).await;
        // Obtain a genuine projection, not a stale race or fabricated authority.
        let snapshot = handle.gate.observe(&scope.as_str()).await.unwrap().unwrap();
        for initialized in [true, false] {
            let state = CognitionPartitionState { cursor: None, incarnation_token: None };
            let initialization = if initialized {
                CognitionInitialization::Initialized(state)
            } else {
                CognitionInitialization::Existing(state)
            };
            recovered(recovery_of(GovernedCommitOutcome::Committed {
                authority: snapshot.authority().clone(),
                owner: GovernedOwnerCommitResult::CognitionPartition(initialization),
            }), 1, initialized);
        }
        assert!(!handle.gate.cognition_root().exists());
    }

    #[test]
    fn refusal_mapping_preserves_every_services_code() {
        for reason in [
            GovernedCommitRefusal::AuthorityChanged,
            GovernedCommitRefusal::NotEnabled,
            GovernedCommitRefusal::NotObserved,
            GovernedCommitRefusal::ForeignSnapshot,
        ] {
            let code = reason.code();
            refused(recovery_of(GovernedCommitOutcome::Refused(reason)), code);
        }
    }

    #[test]
    fn recovery_surface_accepts_scope_only_and_exposes_no_observation() {
        // Design-level assertion, not a runtime race: callers cannot supply a
        // snapshot, authority or expected generation. Inspect production source
        // only, excluding this test's strings. No test hook or observation API.
        let production = include_str!("commit.rs").split("#[cfg(test)]").next().unwrap();
        assert_eq!(production.matches("pub(crate) async fn ").count(), 1);
        assert_eq!(production.matches("pub(crate) fn ").count(), 3);
        assert!(!production.contains("pub(crate) async fn observe"));
        assert!(production.contains(
            "pub(crate) async fn recover_enabled_partition(\n        &self,\n        scope: &WorkspaceControlScope,\n    ) -> Result<PartitionRecovery, CommitError>"
        ));
    }

    #[tokio::test]
    async fn recovery_publishes_one_partition_per_scope() {
        let (_fixture, _, handle) = fixture();
        let first = scope(&handle, "a");
        let second = scope(&handle, "b");
        seed(&handle, &first, true, None).await;
        seed(&handle, &second, true, None).await;
        recovered(handle.recover_enabled_partition(&first).await.unwrap(), 1, true);
        let databases = files(handle.gate.cognition_root(), "sqlite");
        assert_eq!(databases.len(), 1);
        let bytes = std::fs::read(&databases[0]).unwrap();
        let cognition = WorkspaceIntelligenceCognitionStore::new(handle.gate.cognition_root().to_path_buf());
        assert!(cognition.read(&first.as_str()).unwrap().is_some());
        assert!(cognition.read(&second.as_str()).unwrap().is_none());
        recovered(handle.recover_enabled_partition(&second).await.unwrap(), 1, true);
        assert_eq!(files(handle.gate.cognition_root(), "sqlite").len(), 2);
        assert_eq!(std::fs::read(&databases[0]).unwrap(), bytes);
        assert!(cognition.read(&second.as_str()).unwrap().is_some());
    }

    #[test]
    fn the_recovery_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        assert_send(handle.recover_enabled_partition(&scope));
    }

    #[tokio::test]
    async fn observation_store_errors_are_preserved_without_cognition_writes() {
        let (_fixture, _, handle) = fixture();
        let scope = scope(&handle, "a");
        seed(&handle, &scope, true, None).await;
        let record = files(handle.gate.control_root(), "json").remove(0);
        for bytes in [b"broken".as_slice(), br#"{"schema_version":99}"#.as_slice()] {
            std::fs::write(&record, bytes).unwrap();
            let error = handle.recover_enabled_partition(&scope).await.unwrap_err();
            match error {
                CommitError::Store(WorkspaceIntelligenceStoreError::CorruptRecord { .. }) => {
                    assert_eq!(bytes, b"broken");
                }
                CommitError::Store(WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion { version, .. }) => {
                    assert_eq!(version, 99);
                }
                other => panic!("store fault was masked: {other:?}"),
            }
            assert_eq!(std::fs::read(&record).unwrap(), bytes);
            assert!(!handle.gate.cognition_root().exists());
        }
    }
}
