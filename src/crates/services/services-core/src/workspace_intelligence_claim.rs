//! Owner-lifecycle evidence for an already-enabled scope, NOT a WP1.4 exit or
//! P1 exit and NOT the OFF-to-ON enabling path. No PrepareInitialEnabling or
//! allow_off. No host bootstrap, apps wiring, standby retry loop, background
//! task, cursor/gap, revision/epoch, or content mutation.
//!
//! The lease is the only tenure object. A token is a tenure marker, not a
//! secret, authorization or grant. Fixed lock order: lease -> control -> SQLite;
//! taking a lease while holding a control guard is forbidden.
//!
//! The lease root is caller-selected storage, not gate authority. Per-scope
//! mutual exclusion is guaranteed only while a caller uses one consistent lease
//! root for a given scope: two different lease roots for the same pairing produce
//! two distinct inodes, which this primitive cannot detect. Committing a durable,
//! host-wide lease-root authority belongs to host bootstrap and is not provided
//! or claimed here.
//!
//! The sealed proof owns the lease and carries its exact root pairing, scope and
//! lease path. A proof acquired for another root pairing or scope cannot authorize
//! this one. The five gate checks run before taking the control lock. Private,
//! immutable fields with no interior mutability prevent invalidation afterwards;
//! the blocking closure owns its own lease Arc, so cancellation cannot lose tenure.
//!
//! Observe-first static OFF creates no lease file/root or cognition artifact.
//! A concurrent close after observation admitted a claim may leave a payload-free
//! .lock file and lease root. Never delete lock inodes at runtime: another
//! process may be flocking that inode, and deletion breaks mutual exclusion.
//!
//! Stored tokens are verbatim, including whitespace-only and legacy text.
//! Comparison is exact string equality, without trimming, parsing or case folding.
//! Unknown schema/shape and corrupt records produce explicit errors, never reset
//! or deletion. UUID v4 generation occurs inside SQLite; regenerate while equal
//! to the immediate previous token. Only inequality with that predecessor is
//! guaranteed. Historical ABA resistance rests on v4 collision resistance;
//! residual collision risk remains and correctness never relies on secrecy.
//!
//! A returned store call has already ended its transaction; an after-return
//! comparison cannot be in-transaction. Both expected markers therefore enter
//! the concrete typed store operation, without callbacks, so provenance and
//! authoritative stored/live comparisons share ONE IMMEDIATE transaction. This
//! is a stronger contract than the draft single-marker signature, not a weakening.
//!
//! Roots are host-injected local storage paths. No remote execution or host
//! lifecycle integration is supplied by this primitive.

use crate::exclusive_file_lease::{ExclusiveFileLease, ExclusiveFileLeaseError};
use crate::workspace_intelligence_cognition::scope_digest;
use crate::workspace_intelligence_commit::{
    GovernedClaimRefusal, GovernedFenceOperation, GovernedFenceOutcome,
    WorkspaceIntelligenceCommitError, WorkspaceIntelligenceCommitGate,
};
use crate::workspace_intelligence_store::{WorkspaceIntelligenceStore, WorkspaceIntelligenceStoreError};
use std::path::PathBuf;
use std::sync::Arc;

/// Sealed crate-internal tenure proof. Owns the OS lease and the exact tuple it
/// was acquired for. Fields are private; there are no setters, no public
/// constructor, no Clone and no serialization, so a binding cannot be rebound to
/// another root, scope or lease path. Same root pairing and scope may be bound by
/// more than one handle: the values are the authority, not an instance identity.
pub(crate) struct ClaimLeaseBinding {
    lease: Arc<ExclusiveFileLease>,
    control_root: PathBuf,
    cognition_root: PathBuf,
    scope: String,
    lease_path: PathBuf,
}

impl std::fmt::Debug for ClaimLeaseBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimLeaseBinding")
            .field("control_root", &self.control_root)
            .field("cognition_root", &self.cognition_root)
            .field("scope", &self.scope)
            .field("lease_path", &self.lease_path)
            .finish_non_exhaustive()
    }
}

impl ClaimLeaseBinding {
    /// The production caller is GovernedClaim::claim, only after try_acquire
    /// succeeds for exactly lease_path. Gate tests also model foreign pairings.
    pub(crate) fn bind(
        lease: Arc<ExclusiveFileLease>, control_root: PathBuf, cognition_root: PathBuf,
        scope: String, lease_path: PathBuf,
    ) -> Self { Self { lease, control_root, cognition_root, scope, lease_path } }
    pub(crate) fn control_root(&self) -> &std::path::Path { &self.control_root }
    pub(crate) fn cognition_root(&self) -> &std::path::Path { &self.cognition_root }
    pub(crate) fn scope(&self) -> &str { &self.scope }
    pub(crate) fn lease_path(&self) -> &std::path::Path { &self.lease_path }
    /// Owned clone so a blocking closure can own tenure independently.
    pub(crate) fn lease(&self) -> Arc<ExclusiveFileLease> { Arc::clone(&self.lease) }
}

/// Live tenure; deliberately not Clone and never rebindable.
pub struct GovernedClaim {
    gate: WorkspaceIntelligenceCommitGate,
    binding: ClaimLeaseBinding,
    scope: String,
    token: String,
    ticket: OriginTicket,
}

/// Sealed request-scoped statement, not a lease, grant, or serializable token.
#[derive(Clone)]
pub struct OriginTicket {
    scope: String,
    control_root: PathBuf,
    cognition_root: PathBuf,
    lease_path: PathBuf,
    token: String,
}

impl std::fmt::Debug for GovernedClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GovernedClaim")
            .field("scope", &self.scope)
            .field("control_root", &self.binding.control_root())
            .field("cognition_root", &self.binding.cognition_root())
            .field("lease_path", &self.binding.lease_path())
            .field("token", &"<redacted>")
            .finish()
    }
}

impl std::fmt::Debug for OriginTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OriginTicket")
            .field("scope", &self.scope)
            .field("control_root", &self.control_root)
            .field("cognition_root", &self.cognition_root)
            .field("lease_path", &self.lease_path)
            .field("token", &"<redacted>")
            .finish()
    }
}

#[derive(Debug)]
pub enum ClaimAttempt {
    Claimed(GovernedClaim),
    Standby,
    Refused(GovernedClaimRefusal),
}

/// Outcome of a read-only incarnation verification performed by a live claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimVerification {
    /// The stored marker, this live claim's marker and the presented ticket all agree.
    Verified { control_generation: u64 },
    /// Typed refusal; `StaleIncarnation` means the stored marker, the live claim
    /// or the presented ticket disagreed. Nothing was written.
    Refused(GovernedClaimRefusal),
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceIntelligenceClaimError {
    #[error("Workspace intelligence claim lease failed: {0}")]
    Lease(#[from] ExclusiveFileLeaseError),
    #[error("Workspace intelligence claim control failed: {0}")]
    Control(#[from] WorkspaceIntelligenceStoreError),
    #[error("Workspace intelligence claim fence failed: {0}")]
    Fence(#[from] WorkspaceIntelligenceCommitError),
    #[error("Workspace intelligence claim fence returned an unexpected outcome for {operation}")]
    UnexpectedFenceOutcome { operation: &'static str },
}

impl GovernedClaim {
    /// One lease attempt. The observation is read-only; no lease or cognition
    /// write happens before the precheck admits the claim.
    pub async fn claim(
        control: WorkspaceIntelligenceStore, cognition_root: PathBuf,
        lease_root: PathBuf, scope: &str,
    ) -> Result<ClaimAttempt, WorkspaceIntelligenceClaimError> {
        let gate = WorkspaceIntelligenceCommitGate::new(control, cognition_root);
        #[cfg(test)]
        let gate = tests::install_claim_pauses(gate);
        let digest = scope_digest(scope).map_err(WorkspaceIntelligenceCommitError::Cognition)?;
        let lease_path = lease_root.join(format!("{digest}.lock"));
        let Some(snapshot) = gate.observe(scope).await? else {
            return Ok(ClaimAttempt::Refused(GovernedClaimRefusal::NotObserved));
        };
        if snapshot.authority().enabled() != Some(true) {
            return Ok(ClaimAttempt::Refused(GovernedClaimRefusal::NotEnabled));
        }
        let path = lease_path.clone();
        let lease = match tokio::task::spawn_blocking(move || ExclusiveFileLease::try_acquire(&path))
            .await.map_err(WorkspaceIntelligenceCommitError::OwnerTask)? {
            Ok(lease) => Arc::new(lease),
            Err(ExclusiveFileLeaseError::InUse) => return Ok(ClaimAttempt::Standby),
            Err(error) => return Err(error.into()),
        };
        let binding = ClaimLeaseBinding::bind(lease, gate.control_root().to_path_buf(),
            gate.cognition_root().to_path_buf(), scope.to_owned(), lease_path.clone());
        match gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await? {
            GovernedFenceOutcome::Advanced(advance) => {
                let ticket = OriginTicket {
                    scope: scope.to_owned(), control_root: gate.control_root().to_path_buf(),
                    cognition_root: gate.cognition_root().to_path_buf(),
                    lease_path: lease_path.clone(), token: advance.token.clone(),
                };
                Ok(ClaimAttempt::Claimed(Self { gate, binding,
                    scope: scope.to_owned(), token: advance.token, ticket }))
            }
            GovernedFenceOutcome::Refused(refusal) => Ok(ClaimAttempt::Refused(refusal)),
            GovernedFenceOutcome::Verified { .. } => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                operation: "advance_incarnation",
            }),
        }
    }

    pub fn scope(&self) -> &str { &self.scope }
    /// Opaque origin ticket; no token accessor.
    pub fn ticket(&self) -> &OriginTicket { &self.ticket }

    /// Read-only verification, using fresh control authority for every request.
    /// Its SQLite transaction always rolls back on return/drop; it never commits.
    pub async fn verify(&self, origin: &OriginTicket) -> Result<ClaimVerification, WorkspaceIntelligenceClaimError> {
        if origin.scope != self.scope
            || origin.control_root.as_os_str() != self.gate.control_root().as_os_str()
            || origin.cognition_root.as_os_str() != self.gate.cognition_root().as_os_str()
            || origin.control_root.as_os_str() != self.binding.control_root().as_os_str()
            || origin.cognition_root.as_os_str() != self.binding.cognition_root().as_os_str()
            || origin.scope != self.binding.scope()
            || origin.lease_path.as_os_str() != self.binding.lease_path().as_os_str()
        {
            return Ok(ClaimVerification::Refused(GovernedClaimRefusal::ForeignBinding));
        }
        let Some(snapshot) = self.gate.observe(&self.scope).await? else {
            return Ok(ClaimVerification::Refused(GovernedClaimRefusal::NotObserved));
        };
        match self.gate.commit_governed(&snapshot, GovernedFenceOperation::VerifyIncarnation {
            expected: self.token.clone(), origin: origin.token.clone(),
        }, &self.binding).await? {
            GovernedFenceOutcome::Verified { control_generation } => Ok(ClaimVerification::Verified { control_generation }),
            GovernedFenceOutcome::Refused(refusal) => Ok(ClaimVerification::Refused(refusal)),
            GovernedFenceOutcome::Advanced(_) => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                operation: "verify_incarnation",
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_store::JsonFileStore;
    use crate::workspace_intelligence_cognition::WorkspaceIntelligenceCognitionStore;
    use crate::workspace_intelligence_store::{ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch};
    use std::path::Path;
    use std::time::{Duration, Instant};
    const SCOPE: &str = "claim:alpha";
    const DEADLINE: Duration = Duration::from_secs(30);

    fn control(base: &Path) -> WorkspaceIntelligenceStore { WorkspaceIntelligenceStore::new(base.join("control"), vec![1]) }
    async fn seed(base: &Path, scope: &str, enabled: bool) {
        control(base).update(scope, ControlGenerationExpectation::Absent, patch(enabled)).await.unwrap();
    }
    fn patch(enabled: bool) -> WorkspaceIntelligenceControlPatch {
        WorkspaceIntelligenceControlPatch { enabled: ControlFieldUpdate::Set(enabled), ..Default::default() }
    }
    async fn attempt(base: &Path, scope: &str) -> ClaimAttempt {
        GovernedClaim::claim(control(base), base.join("cognition"), base.join("leases"), scope).await.unwrap()
    }
    async fn acquire(base: &Path, scope: &str) -> GovernedClaim {
        match attempt(base, scope).await { ClaimAttempt::Claimed(claim) => claim, other => panic!("{other:?}") }
    }
    fn db(base: &Path, scope: &str) -> PathBuf { base.join("cognition").join(format!("{}.sqlite", scope_digest(scope).unwrap())) }
    fn stored(base: &Path, scope: &str) -> String {
        WorkspaceIntelligenceCognitionStore::new(base.join("cognition")).read(scope).unwrap().unwrap().incarnation_token.unwrap()
    }
    fn refused(outcome: ClaimVerification, reason: GovernedClaimRefusal) {
        assert!(matches!(outcome, ClaimVerification::Refused(actual) if actual == reason), "{outcome:?}");
    }
    struct ReleasePause(std::sync::mpsc::Sender<()>);
    impl ReleasePause {
        fn send(&self, value: ()) -> Result<(), std::sync::mpsc::SendError<()>> { self.0.send(value) }
    }
    impl Drop for ReleasePause {
        fn drop(&mut self) { let _ = self.0.send(()); }
    }

    fn pause() -> (crate::workspace_intelligence_commit::TestPause, tokio::sync::mpsc::UnboundedReceiver<()>, ReleasePause) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        ((sender, Arc::new(std::sync::Mutex::new(wait))), receiver, ReleasePause(release))
    }
    async fn entered(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
        tokio::time::timeout(DEADLINE, receiver.recv()).await.unwrap().unwrap();
    }

    // Only cfg(test) pause hooks: no alternate claim entry point or token factory.
    type ClaimPauses = (PathBuf, Option<crate::workspace_intelligence_commit::TestPause>, Option<crate::workspace_intelligence_commit::TestPause>);
    static CLAIM_PAUSES: std::sync::Mutex<Vec<ClaimPauses>> = std::sync::Mutex::new(Vec::new());
    struct ClaimPauseRegistration(PathBuf);
    impl Drop for ClaimPauseRegistration {
        fn drop(&mut self) {
            CLAIM_PAUSES.lock().unwrap().retain(|entry| entry.0.as_os_str() != self.0.as_os_str());
        }
    }
    fn register_claim_pauses(base: &Path, precheck: Option<crate::workspace_intelligence_commit::TestPause>, fresh: Option<crate::workspace_intelligence_commit::TestPause>) -> ClaimPauseRegistration {
        let root = base.join("control");
        CLAIM_PAUSES.lock().unwrap().push((root.clone(), precheck, fresh));
        ClaimPauseRegistration(root)
    }
    pub(super) fn install_claim_pauses(mut gate: WorkspaceIntelligenceCommitGate) -> WorkspaceIntelligenceCommitGate {
        if let Some((_, precheck, fresh)) = CLAIM_PAUSES.lock().unwrap().iter()
            .find(|entry| entry.0.as_os_str() == gate.control_root().as_os_str()) {
            gate.after_precheck = precheck.clone();
            gate.after_fresh = fresh.clone();
        }
        gate
    }

    #[tokio::test]
    async fn same_process_second_claim_is_standby_and_writes_no_token() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let first = acquire(tmp.path(), SCOPE).await;
        let bytes = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Standby));
        assert_eq!(stored(tmp.path(), SCOPE), first.token);
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), bytes);
    }

    #[tokio::test]
    async fn debug_redacts_tenure_markers_but_preserves_scope_and_roots() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        let token = stored(tmp.path(), SCOPE);
        let control_root = tmp.path().join("control");
        let cognition_root = tmp.path().join("cognition");
        let path = lease_path(tmp.path());
        for (name, output) in [("GovernedClaim", format!("{claim:?}")), ("OriginTicket", format!("{:?}", claim.ticket()))] {
            assert!(!output.contains(&token));
            let expected = format!("{name} {{ scope: {SCOPE:?}, control_root: {control_root:?}, cognition_root: {cognition_root:?}, lease_path: {path:?}, token: \"<redacted>\" }}");
            assert_eq!(output, expected);
        }
        let binding_debug = format!("{:?}", claim.binding);
        assert!(!binding_debug.contains(&token));
        assert_eq!(binding_debug, format!("ClaimLeaseBinding {{ control_root: {control_root:?}, cognition_root: {cognition_root:?}, scope: {SCOPE:?}, lease_path: {path:?}, .. }}"));
        let snapshot = claim.gate.observe(SCOPE).await.unwrap().unwrap();
        let outcome = claim.gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &claim.binding).await.unwrap();
        let GovernedFenceOutcome::Advanced(advance) = outcome else { panic!("{outcome:?}") };
        assert_eq!(advance.previous_token.as_deref(), Some(token.as_str()));
        let output = format!("{advance:?}");
        assert!(!output.contains(&token));
        assert!(!output.contains(&advance.token));
        assert_eq!(output, "IncarnationAdvance { previous_token: Some(\"<redacted>\"), token: \"<redacted>\" }");
    }

    #[tokio::test]
    async fn release_then_takeover_advances_the_token() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let first = acquire(tmp.path(), SCOPE).await;
        let token = first.token.clone(); drop(first);
        // Observe the exact advance result through the same governed fence.
        let gate = WorkspaceIntelligenceCommitGate::new(control(tmp.path()), tmp.path().join("cognition"));
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let lease = Arc::new(ExclusiveFileLease::try_acquire(&tmp.path().join("leases").join(format!("{}.lock", scope_digest(SCOPE).unwrap()))).unwrap());
        let binding = ClaimLeaseBinding::bind(lease.clone(), gate.control_root().to_path_buf(),
            gate.cognition_root().to_path_buf(), SCOPE.into(), lease.lock_path().to_path_buf());
        drop(lease);
        let result = gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await.unwrap();
        drop(binding);
        let GovernedFenceOutcome::Advanced(advance) = result else { panic!("{result:?}") };
        assert_eq!(advance.previous_token.as_deref(), Some(token.as_str()));
        assert_ne!(advance.token, token);
        let next = acquire(tmp.path(), SCOPE).await;
        assert_ne!(next.token, advance.token);
    }

    #[tokio::test]
    async fn old_ticket_is_rejected_inside_a_new_live_claim_transaction() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let first = acquire(tmp.path(), SCOPE).await;
        let old = first.ticket().clone(); drop(first);
        let mut next = acquire(tmp.path(), SCOPE).await;
        let bytes = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        let (hook, mut receiver, release) = pause();
        next.gate.inside_verification = Some(hook);
        let next = Arc::new(next);
        let cloned = Arc::clone(&next);
        let task = tokio::spawn(async move { cloned.verify(&old).await });
        // This hook runs only AFTER the store opened its IMMEDIATE transaction.
        entered(&mut receiver).await;
        let mut probe = rusqlite::Connection::open(db(tmp.path(), SCOPE)).unwrap();
        probe.busy_timeout(Duration::ZERO).unwrap();
        let error = probe.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap_err();
        assert_eq!(error.sqlite_error_code(), Some(rusqlite::ErrorCode::DatabaseBusy));
        drop(probe);
        drop(release);
        refused(tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap().unwrap(), GovernedClaimRefusal::StaleIncarnation);
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), bytes);
        let mut next = Arc::try_unwrap(next).unwrap(); next.gate.inside_verification = None;
        assert!(matches!(next.verify(next.ticket()).await.unwrap(), ClaimVerification::Verified { .. }));
    }

    #[tokio::test]
    async fn restored_database_token_cannot_revive_an_old_ticket() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let first = acquire(tmp.path(), SCOPE).await; let old = first.ticket().clone(); drop(first);
        let next = acquire(tmp.path(), SCOPE).await;
        rusqlite::Connection::open(db(tmp.path(), SCOPE)).unwrap().execute("UPDATE partition_state SET incarnation_token=?1", [&old.token]).unwrap();
        let bytes = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        refused(next.verify(next.ticket()).await.unwrap(), GovernedClaimRefusal::StaleIncarnation);
        refused(next.verify(&old).await.unwrap(), GovernedClaimRefusal::StaleIncarnation);
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), bytes);
    }

    #[tokio::test]
    async fn foreign_ticket_bindings_are_rejected_before_any_io() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        // Make any attempted control IO fail. Binding refusals must take priority.
        let path = tmp.path().join("control").join(format!("{}.json", scope_digest(SCOPE).unwrap()));
        std::fs::write(path, b"corrupt control").unwrap();
        for field in 0..4 {
            let mut ticket = claim.ticket().clone();
            match field {
                0 => ticket.scope.push_str("foreign"),
                1 => ticket.control_root.push("foreign"),
                2 => ticket.cognition_root.push("foreign"),
                _ => ticket.lease_path.push("foreign"),
            }
            refused(claim.verify(&ticket).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
        }
        let mut ticket = claim.ticket().clone();
        let mut spelling = ticket.control_root.into_os_string(); spelling.push(std::path::MAIN_SEPARATOR.to_string());
        ticket.control_root = spelling.into();
        refused(claim.verify(&ticket).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
    }

    #[tokio::test]
    async fn static_off_leaves_no_lease_or_cognition_footprint() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Refused(GovernedClaimRefusal::NotObserved)));
        assert!(!tmp.path().join("control").exists());
        seed(tmp.path(), SCOPE, false).await;
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Refused(GovernedClaimRefusal::NotEnabled)));
        assert!(!tmp.path().join("leases").exists()); assert!(!tmp.path().join("cognition").exists());
    }

    #[tokio::test]
    async fn close_before_claim_and_claim_before_close_are_both_linearizable() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(1), patch(false)).await.unwrap();
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Refused(GovernedClaimRefusal::NotEnabled)));
        assert!(!tmp.path().join("cognition").exists()); assert!(!tmp.path().join("leases").exists());
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(2), patch(true)).await.unwrap();
        // Drive the exact claim fence with an owner pause; lease is taken first.
        let mut gate = WorkspaceIntelligenceCommitGate::new(control(tmp.path()), tmp.path().join("cognition"));
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let lease = Arc::new(ExclusiveFileLease::try_acquire(&tmp.path().join("leases").join(format!("{}.lock", scope_digest(SCOPE).unwrap()))).unwrap());
        let binding = ClaimLeaseBinding::bind(lease.clone(), gate.control_root().to_path_buf(),
            gate.cognition_root().to_path_buf(), SCOPE.into(), lease.lock_path().to_path_buf());
        drop(lease);
        let (hook, mut receiver, release) = pause(); gate.inside_owner = Some(hook);
        let task = tokio::spawn(async move { gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await });
        entered(&mut receiver).await;
        let lock = tmp.path().join("control").join(format!("{}.json.lock", scope_digest(SCOPE).unwrap()));
        let probe = std::fs::OpenOptions::new().read(true).write(true).open(lock).unwrap();
        let error = fs2::FileExt::try_lock_exclusive(&probe).unwrap_err();
        assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error()); drop(probe);
        let closer = control(tmp.path());
        let mut close = Box::pin(closer.update(SCOPE, ControlGenerationExpectation::Exactly(3), patch(false)));
        {
            use std::future::Future;
            use std::task::{Context, Poll, Waker};
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(close.as_mut().poll(&mut context), Poll::Pending));
        }
        assert_eq!(control(tmp.path()).read(SCOPE).await.unwrap().unwrap().control_generation, 3);
        assert!(!db(tmp.path(), SCOPE).exists());
        release.send(()).unwrap();
        let result = tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap().unwrap();
        assert!(matches!(result, GovernedFenceOutcome::Advanced(_)));
        let result = tokio::time::timeout(DEADLINE, close).await.unwrap().unwrap();
        assert_eq!(result.record().control_generation, 4);
        assert!(!stored(tmp.path(), SCOPE).is_empty());
    }

    #[tokio::test]
    async fn two_scope_leases_are_independent() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await; seed(tmp.path(), "other", true).await;
        let a = acquire(tmp.path(), SCOPE).await; let b = acquire(tmp.path(), "other").await;
        assert_ne!(a.binding.lease_path(), b.binding.lease_path()); assert_ne!(a.token, b.token);
        assert!(matches!(a.verify(a.ticket()).await.unwrap(), ClaimVerification::Verified { .. }));
        assert!(matches!(b.verify(b.ticket()).await.unwrap(), ClaimVerification::Verified { .. }));
        // Control generation is not frozen for a claim's lifetime.
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(1), patch(false)).await.unwrap();
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(2), patch(true)).await.unwrap();
        assert!(matches!(a.verify(a.ticket()).await.unwrap(), ClaimVerification::Verified { control_generation: 3, .. }));
    }


    fn lease_path(base: &Path) -> PathBuf { base.join("leases").join(format!("{}.lock", scope_digest(SCOPE).unwrap())) }
    fn control_path(base: &Path) -> PathBuf { base.join("control").join(format!("{}.json", scope_digest(SCOPE).unwrap())) }
    fn control_bytes(base: &Path) -> Vec<u8> { std::fs::read(control_path(base)).unwrap() }
    fn cognition_bytes(base: &Path) -> Option<Vec<u8>> {
        match std::fs::read(db(base, SCOPE)) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("unexpected cognition IO: {error}"),
        }
    }
    fn assert_contended(path: &Path) {
        let probe = std::fs::OpenOptions::new().read(true).write(true).open(path).unwrap();
        let result = fs2::FileExt::try_lock_exclusive(&probe);
        drop(probe);
        let error = result.unwrap_err();
        assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error());
    }
    fn assert_no_partition(base: &Path) {
        assert_eq!(WorkspaceIntelligenceCognitionStore::new(base.join("cognition")).read(SCOPE).unwrap(), None);
        assert!(!base.join("cognition").exists());
    }

    #[tokio::test]
    async fn claim_cancelled_while_queued_on_the_control_guard_writes_no_token() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let before_control = control_bytes(tmp.path());
        let before_database = cognition_bytes(tmp.path());
        let mut gate = WorkspaceIntelligenceCommitGate::new(control(tmp.path()), tmp.path().join("cognition"));
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        // A is a gate-level guard holder, with an auxiliary lease path, so B can
        // own its real claim lease while queued. This tests control ordering, not
        // mutual exclusion across different caller-selected lease roots.
        let a_path = tmp.path().join("guard-holder").join(format!("{}.lock", scope_digest(SCOPE).unwrap()));
        let binding = ClaimLeaseBinding::bind(Arc::new(ExclusiveFileLease::try_acquire(&a_path).unwrap()),
            gate.control_root().to_path_buf(), gate.cognition_root().to_path_buf(), SCOPE.into(), a_path);
        let (hook_a, mut entered_a, release_a) = pause();
        gate.after_fresh = Some(hook_a);
        let a = tokio::spawn(async move { gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await });
        entered(&mut entered_a).await;

        let (hook_b, mut entered_b, release_b) = pause();
        let _registration = register_claim_pauses(tmp.path(), Some(hook_b), None);
        // Pre-release only the hook. The poll reporting its notification must
        // continue into the real control-lock acquisition before returning Pending.
        release_b.send(()).unwrap();
        let base = tmp.path().to_path_buf();
        let (queued, queued_rx) = tokio::sync::oneshot::channel();
        let mut b = tokio::spawn(async move {
            use std::future::Future;
            use std::task::{Context, Poll, Waker};
            let mut future = Box::pin(GovernedClaim::claim(control(&base), base.join("cognition"), base.join("leases"), SCOPE));
            loop {
                {
                    let mut context = Context::from_waker(Waker::noop());
                    assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
                }
                if entered_b.try_recv().is_ok() { break; }
                tokio::task::yield_now().await;
            }
            queued.send(()).unwrap();
            future.await
        });
        tokio::time::timeout(DEADLINE, queued_rx).await.unwrap().unwrap();
        assert!(!b.is_finished());
        assert_contended(&lease_path(tmp.path()));
        b.abort();
        assert!((&mut b).await.unwrap_err().is_cancelled());
        assert!(b.is_finished());
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), before_database);
        assert_no_partition(tmp.path());
        // Tokio never polls an aborted task again. Its detached lock acquisition
        // may finish, but cannot resume B's future or schedule an owner write.
        drop(release_a);
        let reacquired = ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap();
        drop(reacquired);
        let outcome = tokio::time::timeout(DEADLINE, a).await.unwrap().unwrap().unwrap();
        let GovernedFenceOutcome::Advanced(advance) = outcome else { panic!("{outcome:?}") };
        assert_eq!(stored(tmp.path(), SCOPE), advance.token);
        let committed = cognition_bytes(tmp.path());
        let (guard, _) = tokio::time::timeout(DEADLINE, control(tmp.path()).lock_and_read_authority(SCOPE)).await.unwrap().unwrap();
        drop(guard);
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), committed);
        assert_eq!(stored(tmp.path(), SCOPE), advance.token);
        assert!(b.is_finished());
    }

    #[tokio::test]
    async fn claim_cancelled_between_fresh_read_and_handoff_writes_no_partition() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let before = control_bytes(tmp.path());
        let (hook, mut receiver, release) = pause();
        let _registration = register_claim_pauses(tmp.path(), None, Some(hook));
        let base = tmp.path().to_path_buf();
        let mut task = tokio::spawn(async move { attempt(&base, SCOPE).await });
        entered(&mut receiver).await;
        assert_contended(&lease_path(tmp.path()));
        // after_fresh is a test-only pause, not an extra production await point.
        task.abort();
        assert!((&mut task).await.unwrap_err().is_cancelled());
        assert!(task.is_finished());
        assert_no_partition(tmp.path());
        assert_eq!(control_bytes(tmp.path()), before);
        let lease = ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap();
        drop(lease);
        drop(release);
    }

    #[tokio::test]
    async fn close_wins_after_the_new_path_passed_its_precheck() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let (hook, mut receiver, release) = pause();
        let _registration = register_claim_pauses(tmp.path(), Some(hook), None);
        let base = tmp.path().to_path_buf();
        let task = tokio::spawn(async move { attempt(&base, SCOPE).await });
        entered(&mut receiver).await;
        assert_contended(&lease_path(tmp.path()));
        let close = control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(1), patch(false)).await.unwrap();
        assert_eq!(close.record().control_generation, 2);
        let closed = control_bytes(tmp.path());
        drop(release);
        assert!(matches!(tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(), ClaimAttempt::Refused(GovernedClaimRefusal::AuthorityChanged)));
        assert_no_partition(tmp.path());
        assert_eq!(control_bytes(tmp.path()), closed);
        let lease = ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap();
        drop(lease);
        // Retain this empty inode: another process may already be flocking it.
        assert!(tmp.path().join("leases").is_dir());
        assert_eq!(std::fs::metadata(lease_path(tmp.path())).unwrap().len(), 0);
    }

    #[tokio::test]
    async fn claim_over_an_unrecognized_cognition_schema_preserves_bytes_and_releases_the_lease() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        std::fs::create_dir_all(tmp.path().join("cognition")).unwrap();
        rusqlite::Connection::open(db(tmp.path(), SCOPE)).unwrap().execute_batch("PRAGMA user_version=2").unwrap();
        let before_control = control_bytes(tmp.path());
        let before_database = cognition_bytes(tmp.path());
        let error = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap_err();
        assert!(matches!(error, WorkspaceIntelligenceClaimError::Fence(WorkspaceIntelligenceCommitError::Cognition(error)) if error.code() == "unsupported_schema_version"));
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), before_database);
        drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
    }

    #[tokio::test]
    async fn claim_over_a_v0_database_with_unrecognized_user_objects_fails_and_releases_the_lease() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        std::fs::create_dir_all(tmp.path().join("cognition")).unwrap();
        // A v0 database containing unrecognized user objects is never adopted.
        // This is distinct from the supported empty-v0 starting point.
        let connection = rusqlite::Connection::open(db(tmp.path(), SCOPE)).unwrap();
        connection.execute_batch("CREATE TABLE foreign_state (value TEXT); INSERT INTO foreign_state VALUES ('keep'); PRAGMA user_version=0").unwrap();
        assert_eq!(connection.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        drop(connection);
        let before_control = control_bytes(tmp.path());
        let before_database = cognition_bytes(tmp.path());
        let error = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap_err();
        assert!(matches!(error, WorkspaceIntelligenceClaimError::Fence(WorkspaceIntelligenceCommitError::Cognition(
            crate::workspace_intelligence_cognition::WorkspaceIntelligenceCognitionError::UnrecognizedDatabase { .. }))));
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), before_database);
        drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
    }

    #[tokio::test]
    async fn claim_over_an_empty_v0_pairing_initializes_the_partition() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        std::fs::create_dir_all(tmp.path().join("cognition")).unwrap();
        let path = db(tmp.path(), SCOPE);
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection.execute_batch("PRAGMA user_version=0").unwrap();
        assert_eq!(connection.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(connection.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        drop(connection);
        assert!(path.is_file());
        let outcome = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap();
        let ClaimAttempt::Claimed(claim) = outcome else { panic!("empty v0 must be claimed, got {outcome:?}") };
        let connection = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(connection.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(connection.query_row("SELECT count(*) FROM partition_state", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        let (token, cursor) = connection.query_row(
            "SELECT incarnation_token, cursor FROM partition_state WHERE state_id=1", [],
            |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?)),
        ).unwrap();
        let token = token.expect("claimed v1 has a stored tenure marker");
        assert!(!token.is_empty());
        assert_eq!(token, claim.token);
        assert_eq!(cursor, None);
    }

    #[tokio::test]
    async fn claim_over_a_non_file_record_preserves_the_directory_and_releases_the_lease() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let path = db(tmp.path(), SCOPE);
        std::fs::create_dir_all(&path).unwrap();
        let before_control = control_bytes(tmp.path());
        let error = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap_err();
        assert!(matches!(error, WorkspaceIntelligenceClaimError::Fence(WorkspaceIntelligenceCommitError::Cognition(
            crate::workspace_intelligence_cognition::WorkspaceIntelligenceCognitionError::RecordPathNotFile { .. }))));
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(tmp.path().join("cognition")).unwrap().count(), 1);
        drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
    }

    #[tokio::test]
    async fn claim_over_a_corrupt_or_foreign_cognition_partition_changes_nothing() {
        for code in ["corrupt_database", "partition_scope_mismatch"] {
            let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
            std::fs::create_dir_all(tmp.path().join("cognition")).unwrap();
            if code == "corrupt_database" {
                std::fs::write(db(tmp.path(), SCOPE), b"not a SQLite database").unwrap();
            } else {
                WorkspaceIntelligenceCognitionStore::new(tmp.path().join("cognition")).initialize("foreign").unwrap();
                std::fs::copy(db(tmp.path(), "foreign"), db(tmp.path(), SCOPE)).unwrap();
            }
            let before_control = control_bytes(tmp.path());
            let before_database = cognition_bytes(tmp.path());
            let error = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap_err();
            assert!(matches!(error, WorkspaceIntelligenceClaimError::Fence(WorkspaceIntelligenceCommitError::Cognition(error)) if error.code() == code));
            assert_eq!(control_bytes(tmp.path()), before_control);
            assert_eq!(cognition_bytes(tmp.path()), before_database);
            drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
        }
    }

    #[tokio::test]
    async fn unreadable_control_refuses_before_creating_any_lease_artifact() {
        for io_failure in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join("control")).unwrap();
            if io_failure { std::fs::create_dir(control_path(tmp.path())).unwrap(); }
            else { std::fs::write(control_path(tmp.path()), b"unreadable JSON").unwrap(); }
            let error = GovernedClaim::claim(control(tmp.path()), tmp.path().join("cognition"), tmp.path().join("leases"), SCOPE).await.unwrap_err();
            match error {
                WorkspaceIntelligenceClaimError::Fence(WorkspaceIntelligenceCommitError::Control(error)) => {
                    if io_failure { assert!(matches!(error, WorkspaceIntelligenceStoreError::Storage(_))); }
                    else { assert!(matches!(error, WorkspaceIntelligenceStoreError::CorruptRecord { .. })); }
                }
                other => panic!("unexpected control error: {other:?}"),
            }
            assert!(!tmp.path().join("leases").exists());
            assert!(!lease_path(tmp.path()).exists());
            assert_no_partition(tmp.path());
            if !io_failure { assert_eq!(std::fs::read(control_path(tmp.path())).unwrap(), b"unreadable JSON"); }
        }
    }

    const CHILD_DIR: &str = "OPENBITFUN_WI_CLAIM_CHILD_DIR";
    const CHILD_ROLE: &str = "OPENBITFUN_WI_CLAIM_CHILD_ROLE";
    struct Child(std::process::Child);
    impl Drop for Child { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    fn child(base: &Path, role: &str) -> Child {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        #[cfg(windows)] { use std::os::windows::process::CommandExt; command.creation_flags(0x0800_0000); }
        Child(command.args(["--exact", "workspace_intelligence_claim::tests::claim_process_fixture", "--nocapture"])
            .env(CHILD_DIR, base).env(CHILD_ROLE, role)
            .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap())
    }
    async fn marker(path: &Path) -> String {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await { return text; }
            assert!(Instant::now() < deadline, "marker deadline: {}", path.display());
            tokio::task::yield_now().await;
        }
    }
    async fn write_marker(path: &Path, text: &str) { JsonFileStore.write_text_atomic_strict(path, text).await.unwrap(); }

    #[tokio::test]
    async fn cross_process_claim_single_winner_and_standby() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let mut children = [child(tmp.path(), "a"), child(tmp.path(), "b")];
        marker(&tmp.path().join("a.ready")).await; marker(&tmp.path().join("b.ready")).await;
        write_marker(&tmp.path().join("start.ready"), "start").await;
        let a = marker(&tmp.path().join("a.outcome")).await;
        let b = marker(&tmp.path().join("b.outcome")).await;
        let outcomes = [a, b];
        assert_eq!(outcomes.iter().filter(|s| s.as_str() == "standby").count(), 1);
        let winner = outcomes.iter().find_map(|s| s.strip_prefix("claimed ")).unwrap();
        assert_eq!(stored(tmp.path(), SCOPE), winner);
        assert_eq!(std::fs::read_dir(tmp.path().join("cognition")).unwrap().count(), 1);
        write_marker(&tmp.path().join("release.ready"), "release").await;
        let deadline = Instant::now() + DEADLINE;
        for child in &mut children {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() { assert!(status.success()); break; }
                assert!(Instant::now() < deadline); tokio::task::yield_now().await;
            }
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn killed_owner_lease_is_released_by_the_os_and_takeover_advances_the_token() {
        let tmp = tempfile::tempdir().unwrap(); seed(tmp.path(), SCOPE, true).await;
        let mut owner = child(tmp.path(), "kill"); marker(&tmp.path().join("kill.ready")).await;
        write_marker(&tmp.path().join("start.ready"), "start").await;
        let outcome = marker(&tmp.path().join("kill.outcome")).await;
        let old = outcome.strip_prefix("claimed ").unwrap();
        owner.0.kill().unwrap(); owner.0.wait().unwrap();
        let next = acquire(tmp.path(), SCOPE).await;
        assert_ne!(next.token, old);
        let store = WorkspaceIntelligenceCognitionStore::new(tmp.path().join("cognition"));
        assert_eq!(store.verify_incarnation(SCOPE, old, old).unwrap_err().code(), "stale_incarnation");
        assert!(matches!(next.verify(next.ticket()).await.unwrap(), ClaimVerification::Verified { .. }));
    }

    #[tokio::test]
    async fn claim_process_fixture() {
        let Some(base) = std::env::var_os(CHILD_DIR) else { return; };
        let base = PathBuf::from(base); let role = std::env::var(CHILD_ROLE).unwrap();
        write_marker(&base.join(format!("{role}.ready")), "ready").await;
        marker(&base.join("start.ready")).await;
        match attempt(&base, SCOPE).await {
            ClaimAttempt::Claimed(claim) => {
                write_marker(&base.join(format!("{role}.outcome")), &format!("claimed {}", claim.token)).await;
                marker(&base.join("release.ready")).await;
                drop(claim);
            }
            ClaimAttempt::Standby => write_marker(&base.join(format!("{role}.outcome")), "standby").await,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn claim_surface_exposes_no_public_token_or_rebind() {
        let source = include_str!("workspace_intelligence_claim.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        let ticket = production.split("pub struct OriginTicket {").nth(1).unwrap().split('}').next().unwrap();
        assert!(!ticket.contains("pub "));
        assert!(!production.contains("Serialize"));
        assert!(!production.contains("impl OriginTicket"));
        assert!(!production.contains("pub fn token"));
        assert!(!production.contains("pub fn rebind"));
        assert!(!production.contains("impl Clone for GovernedClaim"));
        for name in ["GovernedClaim", "OriginTicket", "ClaimLeaseBinding"] {
            assert!(production.contains(&format!("impl std::fmt::Debug for {name}")));
            let declaration = if name == "ClaimLeaseBinding" { "pub(crate) struct" } else { "pub struct" };
            assert!(!production.contains(&format!("#[derive(Debug)]\n{declaration} {name}")));
            assert!(!production.contains(&format!("#[derive(Debug, Clone)]\n{declaration} {name}")));
        }
        assert!(include_str!("workspace_intelligence_cognition.rs").contains("impl std::fmt::Debug for IncarnationAdvance"));
        assert!(production.contains("-> Result<ClaimVerification, WorkspaceIntelligenceClaimError>"));
        assert!(include_str!("workspace_intelligence_commit.rs").contains("pub(crate) async fn commit_governed"));
        let cognition = include_str!("workspace_intelligence_cognition.rs");
        assert!(cognition.contains("pub(crate) fn advance_incarnation"));
        assert!(cognition.contains("pub(crate) fn verify_incarnation"));
    }
}
