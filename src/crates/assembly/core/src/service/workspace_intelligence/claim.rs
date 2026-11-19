//! Internal wrapper over the services already-enabled-scope owner lifecycle;
//! NOT a WP1.4 exit or P1 exit. No app bootstrap, first enable, `allow_off`, host
//! identity source, execution-binding change detection, Shared-profile gate,
//! pending cursor, revision/epoch, model run, background task, registry or UI.
//!
//! The injected lease root is a caller-chosen storage namespace trusted like the
//! control and cognition roots. Per-scope mutual exclusion assumes one consistent
//! lease root per scope: cross-lease-root exclusion is not provided. Host-wide
//! authority belongs to a later bootstrap. This wrapper does not detect conflicting
//! roots, take locks, write control records or expose incarnation markers.
//!
//! There is deliberately no core admits/accepts predicate: services owns both the
//! enabled pre-check and the guarded fresh check. The enabled-true precondition is
//! NOT re-implemented here; workspace-intelligence-commit is not opened or shared
//! for a one-line predicate. Generation equivalence and lease -> control -> SQLite
//! ordering stay entirely inside services. Model references are irrelevant to
//! admission: BASELINE works without one, with no resolution or fallback.

use std::path::PathBuf;

use openbitfun_services_core::workspace_intelligence_claim::{
    ClaimAttempt, ClaimVerification, GovernedClaim, OriginTicket, WorkspaceIntelligenceClaimError,
};
use openbitfun_services_core::workspace_intelligence_commit::GovernedClaimRefusal;
use openbitfun_services_core::workspace_intelligence_store::WorkspaceIntelligenceStore;

use crate::infrastructure::PathManager;

use super::policy::CONTROL_SCHEMA_VERSION;
use super::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// Immutable host/scope assembly over services' redacted, non-Clone tenure handle.
#[derive(Debug)]
pub(crate) struct WorkspaceIntelligenceClaim {
    host: HostExecutionDomainKey,
    scope: WorkspaceControlScope,
    claim: GovernedClaim,
}

impl WorkspaceIntelligenceClaim {
    /// One claim attempt over the host's own roots. Host/domain mismatch is
    /// refused before any storage access.
    pub(crate) async fn acquire(
        paths: &PathManager,
        host: HostExecutionDomainKey,
        scope: WorkspaceControlScope,
    ) -> Result<ClaimStart, ClaimError> {
        if !scope.host_matches(&host) {
            return Err(ClaimError::HostScopeMismatch);
        }
        Self::with_roots(
            paths.workspace_intelligence_control_dir(),
            paths.workspace_intelligence_cognition_dir(),
            paths.workspace_intelligence_lease_dir(),
            host,
            scope,
        )
        .await
    }

    /// Trusted assembly over explicit host-local roots. Callers must pass one
    /// consistent lease root per scope: different roots for the same pairing
    /// create distinct lock inodes, so per-scope exclusion is not guaranteed.
    /// This wrapper does not detect that or claim host-wide exclusion.
    pub(crate) async fn with_roots(
        control_root: PathBuf,
        cognition_root: PathBuf,
        lease_root: PathBuf,
        host: HostExecutionDomainKey,
        scope: WorkspaceControlScope,
    ) -> Result<ClaimStart, ClaimError> {
        if !scope.host_matches(&host) {
            return Err(ClaimError::HostScopeMismatch);
        }
        let store = WorkspaceIntelligenceStore::new(control_root, vec![CONTROL_SCHEMA_VERSION]);
        Ok(match GovernedClaim::claim(store, cognition_root, lease_root, &scope.as_str()).await? {
            ClaimAttempt::Claimed(claim) => ClaimStart::Claimed(Self { host, scope, claim }),
            ClaimAttempt::Standby => ClaimStart::Standby,
            ClaimAttempt::Refused(reason) => ClaimStart::Refused(reason),
        })
    }

    pub(crate) fn host(&self) -> &HostExecutionDomainKey {
        &self.host
    }

    pub(crate) fn scope(&self) -> &WorkspaceControlScope {
        &self.scope
    }

    /// Opaque origin ticket; it carries no marker accessor and grants nothing.
    pub(crate) fn origin(&self) -> &OriginTicket {
        self.claim.ticket()
    }

    /// Read-only tenure verification through the services binding check.
    pub(crate) async fn verify_tenure(
        &self,
        origin: &OriginTicket,
    ) -> Result<TenureVerification, ClaimError> {
        Ok(match self.claim.verify(origin).await? {
            ClaimVerification::Verified { control_generation } => {
                TenureVerification::Live { control_generation }
            }
            ClaimVerification::Refused(reason) => TenureVerification::Refused(reason),
        })
    }
}

#[derive(Debug)]
pub(crate) enum ClaimStart {
    Claimed(WorkspaceIntelligenceClaim),
    Standby,
    Refused(GovernedClaimRefusal),
}

#[derive(Debug)]
pub(crate) enum TenureVerification {
    Live { control_generation: u64 },
    Refused(GovernedClaimRefusal),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ClaimError {
    /// The scope is owned by a different host and execution domain.
    #[error("the scope is owned by a different host and execution domain")]
    HostScopeMismatch,
    #[error(transparent)]
    Claim(#[from] WorkspaceIntelligenceClaimError),
}

#[cfg(test)]
mod tests {
    //! The schema version and singleton shape are asserted through the owner's
    //! validating reader rather than a duplicated direct SQL query, because raw
    //! SQL over another layer's schema is not a core responsibility.

    use super::*;
    use openbitfun_services_core::workspace_intelligence_cognition::WorkspaceIntelligenceCognitionStore;
    use openbitfun_services_core::workspace_intelligence_store::{
        ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
    };
    use std::path::Path;

    fn host() -> HostExecutionDomainKey {
        HostExecutionDomainKey::new("host-1", "local").unwrap()
    }

    fn scope(id: &str) -> WorkspaceControlScope {
        WorkspaceControlScope::new(&host(), id).unwrap()
    }

    fn fixture() -> (tempfile::TempDir, PathManager) {
        let fixture = tempfile::tempdir().unwrap();
        let paths = PathManager::with_user_root_for_tests(fixture.path().join("user"));
        (fixture, paths)
    }

    fn store(paths: &PathManager) -> WorkspaceIntelligenceStore {
        WorkspaceIntelligenceStore::new(
            paths.workspace_intelligence_control_dir(),
            vec![CONTROL_SCHEMA_VERSION],
        )
    }

    async fn seed(paths: &PathManager, scope: &WorkspaceControlScope, enabled: bool, model: Option<&str>) {
        store(paths).update(&scope.as_str(), ControlGenerationExpectation::Absent,
            WorkspaceIntelligenceControlPatch {
                enabled: ControlFieldUpdate::Set(enabled),
                model_ref: model.map(|value| ControlFieldUpdate::Set(value.to_owned())).unwrap_or_default(),
                ..Default::default()
            }).await.unwrap();
    }

    async fn update(paths: &PathManager, scope: &WorkspaceControlScope, patch: WorkspaceIntelligenceControlPatch) {
        store(paths).update(&scope.as_str(), ControlGenerationExpectation::Exactly(1), patch).await.unwrap();
    }

    async fn acquire(paths: &PathManager, scope: &WorkspaceControlScope) -> WorkspaceIntelligenceClaim {
        match WorkspaceIntelligenceClaim::acquire(paths, host(), scope.clone()).await.unwrap() {
            ClaimStart::Claimed(handle) => handle,
            other => panic!("expected claim: {other:?}"),
        }
    }

    fn files(root: &Path, extension: &str) -> Vec<PathBuf> {
        if !root.exists() {
            return Vec::new();
        }
        let mut files: Vec<_> = std::fs::read_dir(root).unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some(extension))
            .collect();
        files.sort();
        files
    }

    fn database(paths: &PathManager) -> PathBuf {
        let files = files(&paths.workspace_intelligence_cognition_dir(), "sqlite");
        assert_eq!(files.len(), 1);
        files[0].clone()
    }

    fn marker(paths: &PathManager, scope: &WorkspaceControlScope) -> String {
        WorkspaceIntelligenceCognitionStore::new(paths.workspace_intelligence_cognition_dir())
            .read(&scope.as_str())
            .unwrap()
            .expect("the validating owner reader must observe a v1 singleton partition")
            .incarnation_token
            .expect("a claimed partition must have an incarnation marker")
    }

    fn refused(result: TenureVerification, expected: GovernedClaimRefusal) {
        assert!(matches!(result, TenureVerification::Refused(reason) if reason == expected));
    }

    fn live(result: TenureVerification, generation: u64) {
        assert!(matches!(result, TenureVerification::Live { control_generation } if control_generation == generation));
    }

    #[tokio::test]
    async fn missing_control_record_refuses_with_no_footprint() {
        let (fixture, paths) = fixture();
        assert!(matches!(WorkspaceIntelligenceClaim::acquire(&paths, host(), scope("a")).await.unwrap(),
            ClaimStart::Refused(GovernedClaimRefusal::NotObserved)));
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn host_scope_mismatch_is_refused_before_any_storage() {
        let (fixture, paths) = fixture();
        for foreign in [HostExecutionDomainKey::new("other", "local").unwrap(),
            HostExecutionDomainKey::new("host-1", "sandbox").unwrap()] {
            let foreign_scope = WorkspaceControlScope::new(&foreign, "a").unwrap();
            assert!(matches!(WorkspaceIntelligenceClaim::acquire(&paths, host(), foreign_scope.clone()).await,
                Err(ClaimError::HostScopeMismatch)));
            assert!(matches!(WorkspaceIntelligenceClaim::with_roots(
                paths.workspace_intelligence_control_dir(), paths.workspace_intelligence_cognition_dir(),
                paths.workspace_intelligence_lease_dir(), host(), foreign_scope).await,
                Err(ClaimError::HostScopeMismatch)));
        }
        assert_eq!(std::fs::read_dir(fixture.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn disabled_scope_refuses_with_zero_lease_and_cognition_footprint() {
        let (_fixture, paths) = fixture();
        seed(&paths, &scope("a"), false, None).await;
        assert!(matches!(WorkspaceIntelligenceClaim::acquire(&paths, host(), scope("a")).await.unwrap(),
            ClaimStart::Refused(GovernedClaimRefusal::NotEnabled)));
        assert!(!paths.workspace_intelligence_lease_dir().exists());
        assert!(files(&paths.workspace_intelligence_lease_dir(), "lock").is_empty());
        assert!(!paths.workspace_intelligence_cognition_dir().exists());
    }

    #[tokio::test]
    async fn enabled_scope_claims_and_initializes_the_partition() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let handle = acquire(&paths, &scope).await;
        assert_eq!(handle.host(), &host());
        assert_eq!(handle.scope(), &scope);
        let state = WorkspaceIntelligenceCognitionStore::new(paths.workspace_intelligence_cognition_dir())
            .read(&scope.as_str())
            .unwrap()
            .expect("successful owner validation asserts the v1 schema and singleton shape");
        assert_eq!(state.cursor, None);
        assert!(!state.incarnation_token.expect("claim marker").is_empty());
        let locks = files(&paths.workspace_intelligence_lease_dir(), "lock");
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].file_stem(), database(&paths).file_stem());
    }

    #[tokio::test]
    async fn same_pairing_second_handle_is_standby_and_writes_nothing() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let _held = acquire(&paths, &scope).await;
        let control = files(&paths.workspace_intelligence_control_dir(), "json").remove(0);
        let control_bytes = std::fs::read(&control).unwrap();
        let db = database(&paths);
        let bytes = std::fs::read(&db).unwrap();
        assert!(matches!(WorkspaceIntelligenceClaim::acquire(&paths, host(), scope).await.unwrap(), ClaimStart::Standby));
        assert_eq!(std::fs::read(control).unwrap(), control_bytes);
        assert_eq!(std::fs::read(db).unwrap(), bytes);
    }

    #[tokio::test]
    async fn dropping_the_handle_allows_takeover_with_a_new_marker() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let first = acquire(&paths, &scope).await;
        let previous = marker(&paths, &scope);
        drop(first);
        let _second = acquire(&paths, &scope).await;
        assert_ne!(marker(&paths, &scope), previous);
    }

    #[tokio::test]
    async fn ticket_from_a_replaced_claim_is_refused_and_the_live_ticket_verifies() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let first = acquire(&paths, &scope).await;
        let old = first.origin().clone();
        drop(first);
        let second = acquire(&paths, &scope).await;
        let db = database(&paths);
        let bytes = std::fs::read(&db).unwrap();
        refused(second.verify_tenure(&old).await.unwrap(), GovernedClaimRefusal::StaleIncarnation);
        live(second.verify_tenure(second.origin()).await.unwrap(), 1);
        assert_eq!(std::fs::read(db).unwrap(), bytes);
    }

    #[tokio::test]
    async fn foreign_scope_ticket_is_refused_by_the_services_binding_check() {
        let (_fixture, paths) = fixture();
        seed(&paths, &scope("a"), true, None).await;
        seed(&paths, &scope("b"), true, None).await;
        let first = acquire(&paths, &scope("a")).await;
        let second = acquire(&paths, &scope("b")).await;
        refused(first.verify_tenure(second.origin()).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
    }

    #[tokio::test]
    async fn model_ref_absent_and_present_both_claim() {
        for model in [None, Some("model-x")] {
            let (_fixture, paths) = fixture();
            seed(&paths, &scope("a"), true, model).await;
            // No resolver parameter, resolution or fallback exists in this wrapper.
            let handle = acquire(&paths, &scope("a")).await;
            live(handle.verify_tenure(handle.origin()).await.unwrap(), 1);
        }
    }

    #[tokio::test]
    async fn control_generation_is_not_frozen_for_the_lease_lifetime() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let handle = acquire(&paths, &scope).await;
        update(&paths, &scope, WorkspaceIntelligenceControlPatch {
            model_ref: ControlFieldUpdate::Set("model-x".to_owned()), ..Default::default()
        }).await;
        live(handle.verify_tenure(handle.origin()).await.unwrap(), 2);
    }

    #[tokio::test]
    async fn close_after_a_claim_refuses_verification_and_keeps_data() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let handle = acquire(&paths, &scope).await;
        let previous = marker(&paths, &scope);
        let db = database(&paths);
        let bytes = std::fs::read(&db).unwrap();
        update(&paths, &scope, WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(false), ..Default::default()
        }).await;
        refused(handle.verify_tenure(handle.origin()).await.unwrap(), GovernedClaimRefusal::NotEnabled);
        assert_eq!(marker(&paths, &scope), previous);
        assert_eq!(std::fs::read(db).unwrap(), bytes);
        assert_eq!(files(&paths.workspace_intelligence_lease_dir(), "lock").len(), 1);
        assert_eq!(handle.scope(), &scope);
        refused(handle.verify_tenure(handle.origin()).await.unwrap(), GovernedClaimRefusal::NotEnabled);
    }

    #[tokio::test]
    async fn debug_output_never_contains_the_stored_marker() {
        let (_fixture, paths) = fixture();
        let scope = scope("a");
        seed(&paths, &scope, true, None).await;
        let handle = acquire(&paths, &scope).await;
        let marker = marker(&paths, &scope);
        for debug in [format!("{handle:?}"), format!("{:?}", handle.origin())] {
            assert!(!debug.contains(&marker));
            assert!(debug.contains("workspace") || debug.contains("wi-scope-v1"));
            assert!(debug.contains("<redacted>"));
            assert!(debug.contains("host-1"));
        }
    }

    #[test]
    fn core_never_mints_a_ticket_or_reimplements_the_binding_check() {
        let production = include_str!("claim.rs").split("#[cfg(test)]").next().unwrap();
        // A borrowed return type followed by a function body is not a ticket literal.
        let production = production.replace("-> &OriginTicket {", "-> &OriginTicket\n{");
        for forbidden in ["OriginTicket {", "enabled == Some(true)", "WorkspaceIntelligenceCommitGate",
            "pub fn", "pub struct", "pub enum", "pub async fn"] {
            assert!(!production.contains(forbidden), "unexpected production surface: {forbidden}");
        }
        assert!(production.contains("self.claim.verify(origin).await?"));
        assert!(!production.contains("origin.scope"));
    }
}
