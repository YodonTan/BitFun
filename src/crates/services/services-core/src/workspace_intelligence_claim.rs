//! Owner-lifecycle evidence for an already-enabled scope, plus one single-purpose
//! pre-held lease for an initial-enable preparation. NOT a WP1.4 exit or P1 exit
//! and NOT the OFF-to-ON enabling path: no enabling write, no `allow_off`, no
//! tenure marker outside a claim, no host bootstrap, apps wiring, standby retry
//! loop, background task, gap recording, revision/epoch, or content mutation.
//!
//! One cursor entry point exists under this feature: [`GovernedClaim::advance_cursor`]
//! replaces the scope's opaque cursor text through the governed fence, under the
//! same lease, the same five binding checks and the same control guard as tenure
//! advancement. It records no gap, keeps no dedup window, performs no cognition
//! update and has no consumer in this tree; it stores a caller-supplied string
//! verbatim and never interprets, orders or compares it beyond exact equality
//! against the caller's own expectation.
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
//!
//! # Initial enable preparation (single purpose, reservation only)
//!
//! [`InitialEnableReservation::reserve`] is the one preparation entry point this
//! module adds. It exists so a caller can pre-hold the scope tenure BEFORE any
//! enabling decision is taken, instead of turning a scope on and then waiting for
//! a lease it may never get. It performs no control write, mints no tenure marker,
//! and takes no cognition root at all, so it structurally cannot create a
//! partition or a cursor; it is not a generic `allow_off`, not a standby retry
//! loop, and not a host start-up path.
//!
//! The caller states its own belief about the persisted record
//! ([`InitialEnableExpectation`]): either "no record" or "this generation with
//! exactly this whole raw policy". `None` inside `Present` is a real expectation
//! and never a wildcard. A truly absent record and a stored record that does not
//! read enabled (`false`, or the key absent) are the only states it can reserve
//! over; an already-enabled record refuses.
//!
//! Admission runs in two stages. The lock-free pre-read may only REFUSE what it
//! proves wrong - an already-enabled record, or a stored generation/policy the
//! caller did not state - and a pre-read refusal returns before any lease,
//! control or cognition artifact exists. It never ADMITS: a missing observation
//! proves nothing, so the scope lease is taken first and the authoritative
//! decision is made from `lock_and_read_authority`, which re-reads the record
//! under the control record's own cross-process guard. That locked read must
//! match the projection this attempt observed (the five-field equivalence unit of
//! the commit fence, never a re-derived subset), must still not read enabled, and
//! must match the caller's exact generation and whole raw policy.
//!
//! Scope of that comparison, stated plainly so it is not over-read:
//!
//! - The caller's expectation is deliberately narrow: a control generation plus
//!   one whole raw policy value. It is NOT a complete admission projection, and
//!   `schema_version` and `model_ref` are not caller-stated at all.
//! - The five-field comparison is an internal window, from this attempt's own
//!   lock-free observation to its own locked re-read. It detects drift that lands
//!   inside that window; it is not a host admission decision, not a substitute
//!   for one, and it proves nothing about the record after the guard is released.
//! - A host (or later in-crate consumer) that admits an initial enable still has
//!   to re-observe the record itself and compare its own complete expectation,
//!   `model_ref` and `schema_version` included, before it writes. This primitive
//!   supplies a pre-held lease and a verified snapshot, never permission.
//!
//! Retained snapshot. The handle stores the authority this attempt itself
//! verified under the guard - absent, or the complete five-field projection it
//! observed and re-checked - together with the control root it was decided
//! against, alongside the scope and the lease. It stays crate-internal and opaque:
//! there is no accessor for the snapshot, the control root or the lease path in
//! production builds, so it cannot be read as a grant or used as a path/permission
//! handle. It exists so a later in-crate step (P2) can compare without re-deriving
//! a subset, and it is never "ON first": the scope is still off on every path.
//!
//! Footprint. A refusal decided before the lease leaves nothing behind. A
//! successful reservation, and any refusal decided after the lease, may leave the
//! payload-free scope `.lock` and the payload-free control `.json.lock`; both
//! stay, because another process may already be flocking that inode. No control
//! record is written and no cognition file, partition or tenure marker is created
//! on this path.
//!
//! # Fixed order: anchor, then reservation, then one same-lease promotion
//!
//! [`InitialEnableReservation::reserve`] is valid only after the namespace's host
//! anchor already exists: obtain the anchor, reserve the scope, then run the
//! governed promotion that turns the scope on while carrying this same lease
//! forward. Calling `reserve` with no anchor is not a supported state and is not
//! recoverable here. Reaching the authoritative read creates the control root when
//! it was absent and leaves the payload-free `<digest>.json.lock` inside it. The
//! protected initial-enable anchor mint proves that same-namespace control root
//! vacant and counts every entry, `.lock` included, so the later authentic mint
//! refuses (`host_anchor_initial_enable_control_occupied`) instead of minting.
//! Nothing here deletes that lock - another process may be flocking its inode - so
//! a namespace prepared ahead of its anchor is left with a mint that can no longer
//! succeed. The scope lease itself lives in the lease root and is not part of that
//! vacancy proof; the ordering hazard is the control guard, not the tenure.
//!
//! Tenure. The reservation owns its OS lease until the handle is dropped. It is
//! not Clone, has no public constructor, no tenure-marker accessor and a fully
//! redacted Debug. The lease lives in the caller's future, not inside the
//! control-read blocking task, so cancelling the future releases tenure and the
//! detached blocking work can only observe or release, never write. There is
//! deliberately no public way to take the lease out: a later promotion consumes
//! this handle inside this crate, so the same lease is moved between steps instead
//! of being dropped and re-acquired, which is what keeps "never enable while
//! waiting" intact. Promote - the OFF-to-ON write that would reuse this lease - is
//! deliberately NOT implemented here.

use crate::exclusive_file_lease::{ExclusiveFileLease, ExclusiveFileLeaseError};
use crate::workspace_intelligence_cognition::scope_digest;
use crate::workspace_intelligence_commit::{
    GovernedClaimRefusal, GovernedCommitAuthority, GovernedFenceOperation, GovernedFenceOutcome,
    WorkspaceIntelligenceCommitError, WorkspaceIntelligenceCommitGate,
};
use crate::workspace_intelligence_store::{
    WorkspaceIntelligenceControlRecord, WorkspaceIntelligenceStore, WorkspaceIntelligenceStoreError,
};
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

/// Result of one accepted cursor advance.
///
/// Both fields are the opaque cursor text stored in the cognition partition. They
/// carry no ordering, no secret and no decoded envelope: a caller decides what the
/// text means and the fence only guarantees the compare-and-swap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorOutcome {
    /// Stored cursor before this advance; `None` means the column held NULL.
    pub previous: Option<String>,
    /// Cursor text this call wrote, verbatim.
    pub written: String,
}

/// Outcome of one governed cursor advance request.
#[derive(Debug)]
pub enum CursorAttempt {
    /// The fence accepted the compare-and-swap and the transaction committed.
    Advanced(CursorOutcome),
    /// The stored cursor was no longer the expected text, so nothing was written. This is
    /// a stale cursor snapshot, not an ownership refusal: the caller re-reads the cursor,
    /// decides again and retries, and must not give up the scope because of it.
    Conflict,
    /// Typed refusal; nothing was written.
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
            GovernedFenceOutcome::Verified { .. } | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                operation: "advance_incarnation",
            }),
        }
    }

    /// One lease attempt whose admission also requires the caller's expected
    /// execution binding, after the same read-only observation `claim` performs.
    ///
    /// The comparison is a caller-belief gate over the WHOLE raw persisted
    /// `policy` value, never over selected sub-keys: this layer does not model a
    /// policy schema, so unknown keys, unknown nesting and JSON number identity
    /// participate in equality exactly as stored.
    ///
    /// The expectation is exact equality of `Option<&Value>` against the stored
    /// `Option<Value>`, and `None` is a real expectation, not a wildcard: it
    /// states "no policy is stored", so a record that carries any policy refuses
    /// instead of being admitted, and a record with no stored policy is admitted.
    /// That is deliberately the same rule as `Some(value)`, which must equal the
    /// stored value exactly; there is no caller state that means "any binding".
    ///
    /// The mismatch answer is the existing `AuthorityChanged` refusal, reusing
    /// the vocabulary the lock-internal comparison already reports. Because the
    /// expected value is only compared here, the lock-internal fresh-versus-
    /// observed `AuthorityChanged` re-check inside `commit_governed` remains the
    /// thing that additionally rejects a change that lands after `observe`,
    /// including a same-generation policy edit made by another writer. This
    /// function therefore adds no new lock, no second transaction and no new
    /// write.
    ///
    /// Refusal timing differs by refusal source. The pre-lease refusals
    /// (`NotObserved`, `NotEnabled`, and the `AuthorityChanged` from this
    /// caller-belief comparison) return before the lease is taken and before any
    /// store or cognition write, so they leave no lease file and no cognition
    /// root. A refusal reported later by `commit_governed` — the same-generation
    /// re-check, or `NotEnabled` after a concurrent close — happens after this
    /// call already holds the lease and leaves a payload-free `.lock` file
    /// behind. That file is never unlinked, by design: another process may be
    /// flocking that inode, so deleting it would break mutual exclusion.
    ///
    /// This is the entry point production hosts are required to use, because a
    /// host knows which persisted binding it believes the scope is enabled
    /// under. That requirement is a repository convention here, not a
    /// structurally enforced property: `claim` stays public and would still admit
    /// an enabled scope without expressing a binding, and this primitive cannot
    /// detect a caller that uses it. `claim` remains for fixtures.
    pub async fn claim_expecting(
        control: WorkspaceIntelligenceStore, cognition_root: PathBuf,
        lease_root: PathBuf, scope: &str, expected_policy: Option<&serde_json::Value>,
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
        if snapshot.authority().policy() != expected_policy {
            return Ok(ClaimAttempt::Refused(GovernedClaimRefusal::AuthorityChanged));
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
            GovernedFenceOutcome::Verified { .. } | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
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
            GovernedFenceOutcome::Advanced(_) | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                operation: "verify_incarnation",
            }),
        }
    }

    /// Read-only verification that also re-checks the caller's expected
    /// execution binding on every call.
    ///
    /// The `origin`-versus-live-claim binding checks are identical to `verify`,
    /// so a foreign ticket is still refused before any IO. The added gate is the
    /// caller's belief over the WHOLE raw persisted `policy`, compared against a
    /// fresh observation; a mismatch refuses with the existing
    /// `AuthorityChanged` refusal and touches nothing.
    ///
    /// As in `claim_expecting`, the expectation is exact `Option<Value>`
    /// equality and `None` is not a wildcard: it means "no policy is stored", so
    /// a scope that now carries a policy refuses instead of being verified. The
    /// refusal returns before the typed store operation runs, so it leaves the
    /// cognition partition untouched.
    ///
    /// This remains rollback-only: the SQLite transaction opened by the typed
    /// store operation always rolls back, no new tenure token is minted, and the
    /// double-marker check is unchanged. Lock-internal fresh-versus-observed
    /// comparison still covers a change that lands after this observation.
    pub async fn verify_expecting(
        &self, origin: &OriginTicket, expected_policy: Option<&serde_json::Value>,
    ) -> Result<ClaimVerification, WorkspaceIntelligenceClaimError> {
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
        if snapshot.authority().policy() != expected_policy {
            return Ok(ClaimVerification::Refused(GovernedClaimRefusal::AuthorityChanged));
        }
        match self.gate.commit_governed(&snapshot, GovernedFenceOperation::VerifyIncarnation {
            expected: self.token.clone(), origin: origin.token.clone(),
        }, &self.binding).await? {
            GovernedFenceOutcome::Verified { control_generation } => Ok(ClaimVerification::Verified { control_generation }),
            GovernedFenceOutcome::Refused(refusal) => Ok(ClaimVerification::Refused(refusal)),
            GovernedFenceOutcome::Advanced(_) | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict => Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                operation: "verify_incarnation",
            }),
        }
    }

    /// Replace the scope's opaque cursor text under the live lease.
    ///
    /// The `origin`-versus-live-claim binding checks are identical to `verify`, so a
    /// foreign ticket is refused before any IO. The admission then re-checks the
    /// caller's expected execution binding against a fresh observation, exactly like
    /// `verify_expecting`: `expected_policy` is an exact `Option<Value>` expectation
    /// and `None` is not a wildcard. A mismatch refuses with `AuthorityChanged`
    /// before the fence runs.
    ///
    /// Enabling is deliberately not re-checked here: the fence's own projection
    /// comparison refuses a scope that is not enabled with `NotEnabled`, so that
    /// decision stays in one authoritative place.
    ///
    /// `expected` is the exact cursor text the caller observed; `None` states "the
    /// column is NULL". A stale expectation is answered as
    /// [`CursorAttempt::Conflict`] and writes nothing: the caller's cursor snapshot is
    /// old, so the right response is to re-read the cursor, decide again and retry, not
    /// to abandon the scope, and it is therefore not a `Refused` refusal. The
    /// replacement is stored verbatim: this records no gap, decodes no envelope and
    /// derives no ordering, and a returned [`CursorOutcome`] is evidence of one
    /// committed compare-and-swap, nothing more.
    pub async fn advance_cursor(
        &self,
        origin: &OriginTicket,
        expected_policy: Option<&serde_json::Value>,
        expected: Option<&str>,
        replacement: &str,
    ) -> Result<CursorAttempt, WorkspaceIntelligenceClaimError> {
        if origin.scope != self.scope
            || origin.control_root.as_os_str() != self.gate.control_root().as_os_str()
            || origin.cognition_root.as_os_str() != self.gate.cognition_root().as_os_str()
            || origin.control_root.as_os_str() != self.binding.control_root().as_os_str()
            || origin.cognition_root.as_os_str() != self.binding.cognition_root().as_os_str()
            || origin.scope != self.binding.scope()
            || origin.lease_path.as_os_str() != self.binding.lease_path().as_os_str()
        {
            return Ok(CursorAttempt::Refused(GovernedClaimRefusal::ForeignBinding));
        }
        let Some(snapshot) = self.gate.observe(&self.scope).await? else {
            return Ok(CursorAttempt::Refused(GovernedClaimRefusal::NotObserved));
        };
        if snapshot.authority().policy() != expected_policy {
            return Ok(CursorAttempt::Refused(GovernedClaimRefusal::AuthorityChanged));
        }
        match self.gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceCursor {
            expected: expected.map(str::to_owned),
            replacement: replacement.to_owned(),
        }, &self.binding).await? {
            GovernedFenceOutcome::CursorAdvanced(advance) => Ok(CursorAttempt::Advanced(CursorOutcome {
                previous: advance.previous, written: advance.written,
            })),
            GovernedFenceOutcome::CursorConflict => Ok(CursorAttempt::Conflict),
            GovernedFenceOutcome::Refused(refusal) => Ok(CursorAttempt::Refused(refusal)),
            GovernedFenceOutcome::Advanced(_) | GovernedFenceOutcome::Verified { .. } =>
                Err(WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome {
                    operation: "advance_cursor",
                }),
        }
    }
}

/// One caller-stated belief about the persisted control record of a scope.
///
/// This is a belief, never a permit: no value of it can authorize an enabling
/// write, and it is not an `allow_off` switch. [`Self::Absent`] states that no
/// record was observed; [`Self::Present`] states one record at an exact
/// generation with an exact whole raw policy. There is deliberately no variant
/// meaning "any record" or "any policy", so a policy value of `None` inside
/// [`Self::Present`] stays an exact expectation.
#[derive(Debug, Clone, PartialEq)]
pub enum InitialEnableExpectation {
    /// The caller observed no control record for the scope.
    Absent,
    /// The caller observed exactly this control generation and this whole raw
    /// policy value.
    ///
    /// `policy: None` states "no policy is stored" and is not a wildcard: a
    /// record that carries any policy refuses. `Some(value)` must equal the
    /// stored value exactly, including unknown keys, unknown nesting and JSON
    /// number identity; this layer models no policy schema and never filters
    /// inside the value.
    Present {
        control_generation: u64,
        policy: Option<serde_json::Value>,
    },
}

/// Typed refusal of one reservation attempt.
///
/// Codes are stable and echo no scope, path or payload value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitialEnableRefusal {
    /// The stored record already reads enabled; nothing was reserved.
    AlreadyEnabled,
    /// The stored record is not the one the caller prepared: it appeared, it
    /// disappeared, its generation moved, or its whole raw policy differs. A
    /// change that lands after this attempt observed the record is reported the
    /// same way, because the observed projection is compared under the guard.
    AuthorityChanged,
}

impl InitialEnableRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AlreadyEnabled => "already_enabled",
            Self::AuthorityChanged => "authority_changed",
        }
    }
}

/// Outcome of one reservation attempt. Nothing here is a grant: only
/// [`Self::Reserved`] carries tenure, and that tenure authorizes no write.
#[derive(Debug)]
pub enum InitialEnableAttempt {
    /// The scope lease is pre-held and the authoritative read still did not see
    /// an enabled record. No enabling decision has been taken.
    Reserved(InitialEnableReservation),
    /// Another owner holds the scope lease. Nothing was written or created.
    Standby,
    /// Typed refusal; see [`InitialEnableRefusal`] and the module footprint rule.
    Refused(InitialEnableRefusal),
}

/// The authority one reservation attempt itself verified under the control guard.
///
/// Crate-internal and opaque on purpose. It exists so a later in-crate consumer
/// (P2) can compare against the exact snapshot this attempt validated instead of
/// re-deriving a subset, and so the handle never has to be re-read to know what it
/// was decided against. It is deliberately not public, carries no path, lease or
/// permission, and is not a host admission projection: a host still re-observes
/// the record and compares its own complete expectation before writing.
///
/// `Absent` is a verified observation that this attempt's locked read found no
/// record; it is not a permanent statement that no record exists, and it never
/// authorizes creating one. `Present` is the complete five-field projection
/// (generation, schema version, switch, model reference, whole raw policy) this
/// attempt observed and then re-checked under the guard.
#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)] // Read only by the later in-crate consumer; never widened to `pub` for that.
pub(crate) enum VerifiedInitialAuthority {
    Absent,
    Present(GovernedCommitAuthority),
}

/// Sealed single-purpose pre-held lease for one initial-enable preparation.
///
/// Fields are private, there is no public constructor, no Clone and no
/// serialization, so a handle cannot be forged or rebound to another scope, and
/// the only way to obtain one is [`Self::reserve`]. It holds exactly the OS lease
/// the [`GovernedClaim`] lifecycle would take for the same scope digest and lease
/// root, keeps it alive until the handle is dropped, and exposes no tenure marker:
/// the incarnation marker is minted only by the governed owner commit of the later
/// enabling step.
///
/// It carries no path or permission accessor, and no public way to take the lease
/// or the snapshot out. Everything below is filled by the same `reserve` call, so
/// the scope, the control root identity, the lease and the verified authority can
/// never describe different attempts.
pub struct InitialEnableReservation {
    /// The held OS tenure. A later in-crate promotion step moves this handle and
    /// reuses this same lease; there is deliberately no public extractor, so a
    /// caller cannot take tenure out and use it for anything else.
    ///
    /// It is held for its `Drop`, which is what releases the OS lock, so it is
    /// never read in a production build. That is the intended shape, not missing
    /// code: giving it a reader to silence this would mean handing tenure out.
    #[allow(dead_code)]
    lease: ExclusiveFileLease,
    /// Control store root this decision was taken against, kept so a later
    /// in-crate consumer can prove the handle is not applied to another control
    /// root. Never exposed: no path accessor exists.
    #[allow(dead_code)] // Consumed in-crate by the later promotion; not de-dead-coded by `pub`.
    control_root: PathBuf,
    /// Opaque scope; [`Self::scope`] is the only public accessor.
    scope: String,
    /// What this attempt itself verified under the guard. Never exposed: no
    /// accessor exists, public or otherwise, so it cannot be read as authority.
    #[allow(dead_code)] // Consumed in-crate by the later promotion; not de-dead-coded by `pub`.
    authority: VerifiedInitialAuthority,
}

impl std::fmt::Debug for InitialEnableReservation {
    /// Fully redacted: scope, roots, lease path, the held tenure object and the
    /// verified snapshot are all withheld, so a log line can never be mistaken
    /// for tenure or a grant. Use [`InitialEnableReservation::scope`] for
    /// deliberate diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialEnableReservation")
            .field("tenure", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl InitialEnableReservation {
    /// Pre-holds the scope lease for one initial-enable preparation.
    ///
    /// The footprint contract, in order: a lock-free observation, the scope
    /// lease, then the authoritative re-read under the control record's own
    /// cross-process guard. The observation may only refuse; the lease is taken
    /// before that guard, never while holding it, so the fixed order
    /// lease -> control -> SQLite of this module is preserved and no new lock
    /// order is introduced. No control record, cognition partition, cursor or
    /// tenure marker is created, and no enabling write happens on any path.
    ///
    /// The caller must already hold the namespace's host anchor (see the module
    /// "Fixed order" section); reaching the authoritative read leaves the
    /// payload-free control `.json.lock` behind, and the protected initial-enable
    /// anchor mint refuses a control root holding any entry.
    ///
    /// The returned handle carries this attempt's verified authority snapshot, but
    /// that snapshot is this primitive's own guarded comparison, not a host
    /// admission decision: the expectation here is a generation plus one whole raw
    /// policy, and `model_ref`/`schema_version` are only carried, never asserted.
    ///
    /// Cancellation: the lease is a local of this future until the handle is
    /// returned, so dropping the future releases it. The detached blocking
    /// acquisition may still create and take the payload-free `.lock`, and a
    /// detached control-guard wait may still take and drop that guard, but
    /// neither can resume this future, reach the decision or write anything.
    pub async fn reserve(
        control: WorkspaceIntelligenceStore,
        lease_root: PathBuf,
        scope: &str,
        expectation: InitialEnableExpectation,
    ) -> Result<InitialEnableAttempt, WorkspaceIntelligenceClaimError> {
        let control_root = control.control_root().to_path_buf();
        let digest = scope_digest(scope).map_err(WorkspaceIntelligenceCommitError::Cognition)?;
        let lease_path = lease_root.join(format!("{digest}.lock"));
        // Reject only: this lock-free read can prove the caller wrong, and it can
        // never admit. A missing observation is not proof of absence, so it is
        // not a refusal either.
        let observed_projection = match control.read(scope).await? {
            Some(record) => {
                if let Some(refusal) = Self::observed_refusal(&record, &expectation) {
                    return Ok(InitialEnableAttempt::Refused(refusal));
                }
                Some(GovernedCommitAuthority::project(record))
            }
            None => None,
        };
        let path = lease_path.clone();
        let lease = match tokio::task::spawn_blocking(move || ExclusiveFileLease::try_acquire(&path))
            .await.map_err(WorkspaceIntelligenceCommitError::OwnerTask)? {
            Ok(lease) => lease,
            Err(ExclusiveFileLeaseError::InUse) => return Ok(InitialEnableAttempt::Standby),
            Err(error) => return Err(error.into()),
        };
        // Held, not decided: only tests pause here, to cancel or to edit the
        // record between the lease and the authoritative read. No production
        // await point is added.
        #[cfg(test)]
        if let Some(pause) = tests::reservation_pause(control.control_root()) {
            tests::wait_reservation_pause(&pause).await;
        }
        // The authoritative decision, under the control record's own guard. The
        // guard is dropped before the handle exists, so the reservation never
        // holds it across the caller's tenure.
        let authority = {
            let (guard, fresh) = control.lock_and_read_authority(scope).await?;
            let fresh_projection = fresh
                .map(GovernedCommitAuthority::project);
            let authority = Self::locked_decision(&observed_projection, fresh_projection, &expectation);
            drop(guard);
            authority
        };
        match authority {
            Err(refusal) => Ok(InitialEnableAttempt::Refused(refusal)),
            Ok(authority) => Ok(InitialEnableAttempt::Reserved(Self {
                lease, control_root, scope: scope.to_owned(), authority,
            })),
        }
    }

    /// The opaque scope this reservation was taken for.
    pub fn scope(&self) -> &str { &self.scope }

    /// The exact `.lock` this reservation holds, and the path the [`GovernedClaim`]
    /// lifecycle derives for the same scope and lease root.
    ///
    /// Test-only: production callers get no path accessor, so a lease path can
    /// never be used to re-acquire, re-bind or bypass this handle.
    #[cfg(test)]
    fn lease_path(&self) -> &std::path::Path { self.lease.lock_path() }

    /// Refuses only what one lock-free observation proves wrong: a record that
    /// already reads enabled, or a stored generation/policy the caller did not
    /// state.
    fn observed_refusal(
        record: &WorkspaceIntelligenceControlRecord, expectation: &InitialEnableExpectation,
    ) -> Option<InitialEnableRefusal> {
        if record.enabled == Some(true) { return Some(InitialEnableRefusal::AlreadyEnabled); }
        if Self::stated(record.control_generation, record.policy.as_ref(), expectation) {
            None
        } else {
            Some(InitialEnableRefusal::AuthorityChanged)
        }
    }

    /// The authoritative decision, taken under the control record's guard.
    ///
    /// An enabled record is reported first, so a scope that is already on answers
    /// the actionable truth even when the caller's belief is stale as well. Then
    /// the fresh projection must be the one this attempt observed, which covers a
    /// record that appeared, a record that disappeared and a same-generation edit
    /// to any equivalence field. Then the caller's exact generation and whole raw
    /// policy are re-checked. On success the verified snapshot is returned so the
    /// handle can carry what this attempt actually validated.
    ///
    /// This is a guarded internal comparison, not a host admission decision: the
    /// caller's expectation never states `model_ref` or `schema_version`, so those
    /// two fields are carried rather than asserted, and no conclusion about the
    /// record survives this guard.
    fn locked_decision(
        observed: &Option<GovernedCommitAuthority>,
        fresh: Option<GovernedCommitAuthority>,
        expectation: &InitialEnableExpectation,
    ) -> Result<VerifiedInitialAuthority, InitialEnableRefusal> {
        let Some(fresh) = fresh else {
            return match expectation {
                InitialEnableExpectation::Absent => Ok(VerifiedInitialAuthority::Absent),
                InitialEnableExpectation::Present { .. } => Err(InitialEnableRefusal::AuthorityChanged),
            };
        };
        if fresh.enabled() == Some(true) { return Err(InitialEnableRefusal::AlreadyEnabled); }
        if observed.as_ref() != Some(&fresh) { return Err(InitialEnableRefusal::AuthorityChanged); }
        if !Self::stated(fresh.control_generation(), fresh.policy(), expectation) {
            return Err(InitialEnableRefusal::AuthorityChanged);
        }
        Ok(VerifiedInitialAuthority::Present(fresh))
    }

    fn stated(
        control_generation: u64, policy: Option<&serde_json::Value>,
        expectation: &InitialEnableExpectation,
    ) -> bool {
        match expectation {
            InitialEnableExpectation::Absent => false,
            InitialEnableExpectation::Present { control_generation: expected, policy: expected_policy } => {
                control_generation == *expected && policy == expected_policy.as_ref()
            }
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
    fn refused_claim(outcome: ClaimAttempt, reason: GovernedClaimRefusal) {
        assert!(matches!(outcome, ClaimAttempt::Refused(actual) if actual == reason), "{outcome:?}");
    }
    const HOST_ID: &str = "wi-host-v1:0123456789abcdef0123456789abcdef";
    const OTHER_HOST_ID: &str = "wi-host-v1:ffffffffffffffffffffffffffffffff";
    fn bound_policy(host_id: &str) -> serde_json::Value {
        serde_json::json!({
            "execution_binding": {"schema_version": 1, "host_id": host_id},
            "domains": {"memory": {"enabled": true}},
        })
    }
    async fn seed_policy(base: &Path, scope: &str, policy: serde_json::Value) {
        control(base).update(scope, ControlGenerationExpectation::Absent, WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            policy: ControlFieldUpdate::Set(policy),
            ..Default::default()
        }).await.unwrap();
    }
    async fn expecting(base: &Path, scope: &str, expected: Option<&serde_json::Value>) -> ClaimAttempt {
        GovernedClaim::claim_expecting(control(base), base.join("cognition"), base.join("leases"), scope, expected).await.unwrap()
    }
    /// Recursive walk so a nested `.lock` cannot hide a lease footprint.
    fn lock_files(root: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else { return found };
        for entry in entries {
            let path = entry.unwrap().path();
            if path.is_dir() { found.extend(lock_files(&path)); }
            else if path.extension().and_then(|value| value.to_str()) == Some("lock") { found.push(path); }
        }
        found
    }
    /// Test-only external-writer fixture: it edits the persisted control document
    /// under the store's OWN cross-process lock, but without the store's
    /// generation CAS, so `control_generation` does not move. That is exactly the
    /// external-writer shape the lock-internal fresh-versus-observed comparison in
    /// `commit_governed` has to catch; routing the edit through
    /// `WorkspaceIntelligenceStore::update` would commit a NEW generation instead
    /// and could never model this case. Never a production path.
    async fn raw_policy_edit_same_generation(base: &Path, policy: serde_json::Value) -> serde_json::Value {
        let path = control_path(base);
        let guard = JsonFileStore.acquire_cross_process_lock(&path).await.unwrap();
        let previous: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(previous["control_generation"], serde_json::json!(1), "the fixture only models a same-generation edit");
        let previous_object = previous.as_object().expect("the control record is a JSON object");
        let mut document = previous_object.clone();
        document.insert("policy".to_string(), policy);
        let document = serde_json::Value::Object(document);
        assert_eq!(document.as_object().unwrap().len(), previous_object.len(),
            "the fixture must not add or remove root keys");
        let changed: Vec<&str> = previous_object.keys()
            .filter(|key| document.get(key.as_str()) != previous_object.get(key.as_str()))
            .map(String::as_str)
            .collect();
        assert_eq!(changed, ["policy"], "exactly one root key may differ");
        assert_eq!(document["control_generation"], serde_json::json!(1),
            "a same-generation edit must not move the generation");
        JsonFileStore.write_text_atomic_strict(&path, &serde_json::to_string(&document).unwrap()).await.unwrap();
        drop(guard);
        previous
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
        rusqlite::Connection::open(db(tmp.path(), SCOPE)).unwrap().execute_batch("PRAGMA user_version=3").unwrap();
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
        assert_eq!(connection.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 2);
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
        assert!(cognition.contains("pub(crate) fn advance_cursor"));
    }

    #[tokio::test]
    async fn claim_expecting_with_the_observed_policy_claims() {
        let tmp = tempfile::tempdir().unwrap();
        let expected = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, expected.clone()).await;
        let ClaimAttempt::Claimed(claim) = expecting(tmp.path(), SCOPE, Some(&expected)).await else {
            panic!("the observed binding must claim");
        };
        assert!(!claim.token.is_empty());
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);
    }

    #[tokio::test]
    async fn claim_expecting_with_a_different_binding_refuses_with_zero_footprint() {
        let tmp = tempfile::tempdir().unwrap();
        seed_policy(tmp.path(), SCOPE, bound_policy(HOST_ID)).await;
        let before = control_bytes(tmp.path());
        let other = bound_policy(OTHER_HOST_ID);
        refused_claim(expecting(tmp.path(), SCOPE, Some(&other)).await, GovernedClaimRefusal::AuthorityChanged);
        // A caller-belief mismatch is decided from the observation alone: the
        // control record, the lease root and the cognition root stay untouched.
        assert_eq!(control_bytes(tmp.path()), before);
        assert_eq!(cognition_bytes(tmp.path()), None);
        assert!(lock_files(&tmp.path().join("leases")).is_empty());
    }

    #[tokio::test]
    async fn claim_expecting_compares_unknown_policy_keys_and_never_filters() {
        // A whole-value comparison must carry keys this layer does not model,
        // including keys nested inside other unknown keys.
        let document = serde_json::json!({
            "execution_binding": {"schema_version": 1, "host_id": HOST_ID,
                "future_field": {"unknown": [1, 2, 3]}},
            "domains": {"memory": {"enabled": true, "future_flag": "kept"}},
            "future_policy_block": {"version": 9},
        });
        let text = serde_json::to_string(&document).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        seed_policy(tmp.path(), SCOPE, document.clone()).await;
        let expected: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(expected, document);
        let ClaimAttempt::Claimed(claim) = expecting(tmp.path(), SCOPE, Some(&expected)).await else {
            panic!("unknown policy keys must compare exactly as stored, never be filtered out");
        };
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);

        // The other direction: an unknown key is not ignored either. Two temp
        // roots keep the lease and claim state of the two assertions apart.
        let tmp = tempfile::tempdir().unwrap();
        seed_policy(tmp.path(), SCOPE, document.clone()).await;
        let mut drifted = expected.clone();
        drifted["future_policy_block"]["version"] = serde_json::json!(10);
        assert_ne!(drifted, document);
        refused_claim(expecting(tmp.path(), SCOPE, Some(&drifted)).await, GovernedClaimRefusal::AuthorityChanged);
        assert_eq!(cognition_bytes(tmp.path()), None);
        assert_eq!(control(tmp.path()).read(SCOPE).await.unwrap().unwrap().policy.as_ref(), Some(&document));
    }

    #[tokio::test]
    async fn claim_expecting_refuses_a_new_generation_policy_that_lands_after_observe() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        let (hook, mut receiver, release) = pause();
        let _registration = register_claim_pauses(tmp.path(), Some(hook), None);
        let base = tmp.path().to_path_buf();
        let expected = observed.clone();
        let task = tokio::spawn(async move { expecting(&base, SCOPE, Some(&expected)).await });
        entered(&mut receiver).await;
        // The claim has observed the previous binding and already holds its
        // lease; another writer now replaces the policy through the store's own
        // generation CAS, so this commits generation 2.
        let changed = bound_policy(OTHER_HOST_ID);
        let write = control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(1),
            WorkspaceIntelligenceControlPatch { policy: ControlFieldUpdate::Set(changed.clone()), ..Default::default() })
            .await.unwrap();
        assert_eq!(write.record().control_generation, 2);
        drop(release);
        refused_claim(tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(), GovernedClaimRefusal::AuthorityChanged);
        // Scope of this test: the writer committed generation 2, so the refusal
        // here is explainable by the generation change alone. This proves the
        // NEW-GENERATION path and deliberately says nothing about whether a
        // same-generation policy edit is rejected; that is the separate
        // same-generation test below.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.policy.as_ref(), Some(&changed));
        assert_eq!(cognition_bytes(tmp.path()), None);
    }

    #[tokio::test]
    async fn claim_expecting_refuses_a_same_generation_policy_edit_that_lands_after_observe() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        // The caller's belief and the persisted policy agree before the attempt,
        // so the caller-belief gate cannot be the source of the refusal below.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.policy.as_ref(), Some(&observed));
        let (hook, mut receiver, release) = pause();
        let _registration = register_claim_pauses(tmp.path(), Some(hook), None);
        let base = tmp.path().to_path_buf();
        let expected = observed.clone();
        let task = tokio::spawn(async move { expecting(&base, SCOPE, Some(&expected)).await });
        entered(&mut receiver).await;
        let changed = bound_policy(OTHER_HOST_ID);
        let previous = raw_policy_edit_same_generation(tmp.path(), changed.clone()).await;
        assert_eq!(previous["control_generation"], serde_json::json!(1));
        assert_eq!(previous["policy"], observed);
        let edited = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(edited.control_generation, 1, "the edit must not move the generation");
        assert_eq!(edited.policy.as_ref(), Some(&changed));
        let after_edit = control_bytes(tmp.path());
        drop(release);
        refused_claim(tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap(), GovernedClaimRefusal::AuthorityChanged);
        // The caller's expected value still equals the snapshot it observed and
        // the generation never moved, so the only place that can reject here is
        // the lock-internal fresh-read-versus-observed comparison inside
        // commit_governed. A generation-only check would admit this attempt.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.policy.as_ref(), Some(&changed));
        assert_eq!(control_bytes(tmp.path()), after_edit);
        assert_eq!(cognition_bytes(tmp.path()), None);
        // The refusal came from the fence, after this attempt already held its
        // lease, so the payload-free .lock file remains by design; the claim
        // still wrote no control record and no cognition partition.
    }

    #[tokio::test]
    async fn verify_expecting_refuses_a_same_generation_policy_edit_that_lands_after_observe() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        let mut claim = match expecting(tmp.path(), SCOPE, Some(&observed)).await {
            ClaimAttempt::Claimed(claim) => claim, other => panic!("{other:?}") };
        assert_eq!(control(tmp.path()).read(SCOPE).await.unwrap().unwrap().policy.as_ref(), Some(&observed));
        let bytes = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        // Arming the gate hook after acquisition is the same test-only gate
        // mutation the existing claim tests already rely on; it adds no
        // production await point.
        let (hook, mut receiver, release) = pause();
        claim.gate.after_precheck = Some(hook);
        let claim = Arc::new(claim);
        let ticket = claim.ticket().clone();
        let cloned = Arc::clone(&claim);
        let expected = observed.clone();
        let task = tokio::spawn(async move { cloned.verify_expecting(&ticket, Some(&expected)).await });
        entered(&mut receiver).await;
        let changed = bound_policy(OTHER_HOST_ID);
        let previous = raw_policy_edit_same_generation(tmp.path(), changed.clone()).await;
        assert_eq!(previous["control_generation"], serde_json::json!(1));
        assert_eq!(previous["policy"], observed);
        let edited = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(edited.control_generation, 1, "the edit must not move the generation");
        assert_eq!(edited.policy.as_ref(), Some(&changed));
        drop(release);
        refused(tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap().unwrap(), GovernedClaimRefusal::AuthorityChanged);
        // Rollback-only: the refused verification wrote no partition byte, and
        // the record is still the same generation carrying the edited policy.
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), bytes);
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.policy.as_ref(), Some(&changed));
        let mut claim = Arc::try_unwrap(claim).unwrap();
        claim.gate.after_precheck = None;
        // The refusal did not damage tenure: once the caller's belief matches the
        // edited policy, the same live claim verifies again at generation 1.
        assert!(matches!(claim.verify_expecting(claim.ticket(), Some(&changed)).await.unwrap(),
            ClaimVerification::Verified { control_generation: 1 }));
    }

    #[tokio::test]
    async fn verify_expecting_rejects_an_old_ticket_inside_a_new_live_claim_transaction() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        let ClaimAttempt::Claimed(first) = expecting(tmp.path(), SCOPE, Some(&observed)).await else {
            panic!("the observed binding must claim");
        };
        let old = first.ticket().clone(); drop(first);
        let mut next = match expecting(tmp.path(), SCOPE, Some(&observed)).await {
            ClaimAttempt::Claimed(claim) => claim, other => panic!("{other:?}") };
        let bytes = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        let (hook, mut receiver, release) = pause();
        next.gate.inside_verification = Some(hook);
        let next = Arc::new(next);
        let cloned = Arc::clone(&next);
        let expected = observed.clone();
        let task = tokio::spawn(async move { cloned.verify_expecting(&old, Some(&expected)).await });
        // This hook runs only AFTER the store opened its IMMEDIATE transaction,
        // so the stale-origin decision is made by the double-token check inside
        // one transaction, not by the caller-belief gate above it.
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
        assert!(matches!(next.verify_expecting(next.ticket(), Some(&observed)).await.unwrap(),
            ClaimVerification::Verified { .. }));
    }

    #[tokio::test]
    async fn verify_expecting_with_the_observed_policy_verifies_and_with_a_different_one_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        let ClaimAttempt::Claimed(claim) = expecting(tmp.path(), SCOPE, Some(&observed)).await else {
            panic!("the observed binding must claim");
        };
        let before = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        assert!(matches!(claim.verify_expecting(claim.ticket(), Some(&observed)).await.unwrap(),
            ClaimVerification::Verified { control_generation: 1 }));
        let other = bound_policy(OTHER_HOST_ID);
        refused(claim.verify_expecting(claim.ticket(), Some(&other)).await.unwrap(), GovernedClaimRefusal::AuthorityChanged);
        // The refused verification stayed rollback-only.
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), before);
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);
    }

    #[tokio::test]
    async fn claim_expecting_refuses_a_legacy_enabled_record_without_policy() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let before = control_bytes(tmp.path());
        let expected = bound_policy(HOST_ID);
        refused_claim(expecting(tmp.path(), SCOPE, Some(&expected)).await, GovernedClaimRefusal::AuthorityChanged);
        // A legacy ON record without a policy is never downgraded or rewritten.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.enabled, Some(true));
        assert_eq!(record.policy, None);
        assert_eq!(control_bytes(tmp.path()), before);
        assert_eq!(cognition_bytes(tmp.path()), None);
        assert!(lock_files(&tmp.path().join("leases")).is_empty());
    }

    #[tokio::test]
    async fn claim_and_verify_keep_their_existing_behaviour() {
        // The unbound fixture entry points ignore the policy entirely.
        let tmp = tempfile::tempdir().unwrap();
        seed_policy(tmp.path(), SCOPE, bound_policy(HOST_ID)).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);
        assert!(matches!(claim.verify(claim.ticket()).await.unwrap(),
            ClaimVerification::Verified { control_generation: 1 }));
    }

    #[tokio::test]
    async fn claim_expecting_with_none_expectation_refuses_a_record_that_carries_a_policy() {
        // `None` states "no policy is stored". It must not act as a wildcard:
        // a scope enabled under some other host's binding must be refused, not
        // admitted, when the caller cannot name that binding.
        let tmp = tempfile::tempdir().unwrap();
        seed_policy(tmp.path(), SCOPE, bound_policy(HOST_ID)).await;
        let before = control_bytes(tmp.path());
        refused_claim(expecting(tmp.path(), SCOPE, None).await, GovernedClaimRefusal::AuthorityChanged);
        assert_eq!(control_bytes(tmp.path()), before);
        assert_eq!(cognition_bytes(tmp.path()), None);
        assert!(lock_files(&tmp.path().join("leases")).is_empty());

        // The other side of the same exact-equality rule: `None` against a
        // record that really stores no policy is admitted, in its own root so
        // the refused attempt above cannot influence it.
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let ClaimAttempt::Claimed(claim) = expecting(tmp.path(), SCOPE, None).await else {
            panic!("an absent stored policy must satisfy a None expectation");
        };
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);
    }

    #[tokio::test]
    async fn verify_expecting_with_none_expectation_refuses_a_record_that_carries_a_policy() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_policy(tmp.path(), SCOPE, observed.clone()).await;
        let ClaimAttempt::Claimed(claim) = expecting(tmp.path(), SCOPE, Some(&observed)).await else {
            panic!("the observed binding must claim");
        };
        let before = std::fs::read(db(tmp.path(), SCOPE)).unwrap();
        refused(claim.verify_expecting(claim.ticket(), None).await.unwrap(), GovernedClaimRefusal::AuthorityChanged);
        // Rollback-only: the partition bytes and the tenure are unchanged.
        assert_eq!(std::fs::read(db(tmp.path(), SCOPE)).unwrap(), before);
        assert_eq!(stored(tmp.path(), SCOPE), claim.token);
        // The refusal left the live claim usable with its real binding.
        assert!(matches!(claim.verify_expecting(claim.ticket(), Some(&observed)).await.unwrap(),
            ClaimVerification::Verified { control_generation: 1 }));
    }

    #[tokio::test]
    async fn claim_expecting_reports_not_enabled_before_a_policy_mismatch() {
        // Pins the gate order: a disabled scope reports NotEnabled even when the
        // caller's binding also mismatches, so a future reorder is detected.
        let tmp = tempfile::tempdir().unwrap();
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Absent,
            WorkspaceIntelligenceControlPatch {
                enabled: ControlFieldUpdate::Set(false),
                policy: ControlFieldUpdate::Set(bound_policy(HOST_ID)),
                ..Default::default()
            }).await.unwrap();
        let before = control_bytes(tmp.path());
        let other = bound_policy(OTHER_HOST_ID);
        refused_claim(expecting(tmp.path(), SCOPE, Some(&other)).await, GovernedClaimRefusal::NotEnabled);
        assert_eq!(control_bytes(tmp.path()), before);
        assert_eq!(cognition_bytes(tmp.path()), None);
        assert!(lock_files(&tmp.path().join("leases")).is_empty());
    }

    // Initial enable preparation: one pre-held lease, no enabling write.

    fn present(control_generation: u64, policy: Option<serde_json::Value>) -> InitialEnableExpectation {
        InitialEnableExpectation::Present { control_generation, policy }
    }
    async fn reserve(base: &Path, scope: &str, expectation: InitialEnableExpectation) -> InitialEnableAttempt {
        InitialEnableReservation::reserve(control(base), base.join("leases"), scope, expectation).await.unwrap()
    }
    fn reserved(outcome: InitialEnableAttempt) -> InitialEnableReservation {
        match outcome {
            InitialEnableAttempt::Reserved(reservation) => reservation,
            other => panic!("expected a reservation: {other:?}"),
        }
    }
    fn refused_reservation(outcome: InitialEnableAttempt, reason: InitialEnableRefusal) {
        assert!(matches!(outcome, InitialEnableAttempt::Refused(actual) if actual == reason), "{outcome:?}");
    }
    async fn seed_disabled(base: &Path, scope: &str, policy: Option<serde_json::Value>) {
        control(base).update(scope, ControlGenerationExpectation::Absent, WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(false),
            policy: policy.map(ControlFieldUpdate::Set).unwrap_or_default(),
            ..Default::default()
        }).await.unwrap();
    }
    fn control_lock_path(base: &Path) -> PathBuf {
        base.join("control").join(format!("{}.json.lock", scope_digest(SCOPE).unwrap()))
    }
    /// No scope lease artifact at all: the refusal happened before the lease.
    fn assert_no_lease_artifact(base: &Path) {
        assert!(lock_files(&base.join("leases")).is_empty(),
            "a refusal decided before the lease must leave no lease artifact");
    }
    /// Deterministic wait on the real OS lock: the scope lease is free again.
    async fn wait_until_free(path: &Path) {
        let deadline = Instant::now() + DEADLINE;
        loop {
            let observed = std::fs::OpenOptions::new().read(true).write(true).open(path).map(|probe| {
                let outcome = fs2::FileExt::try_lock_exclusive(&probe);
                drop(probe);
                outcome
            });
            match observed {
                Ok(Ok(())) => return,
                Ok(Err(error)) => assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("unexpected scope lease IO: {error}"),
            }
            assert!(Instant::now() < deadline, "the scope lease was never released: {}", path.display());
            tokio::task::yield_now().await;
        }
    }

    // Test-only pause registry. The reservation signals, through a channel, that
    // it already holds the scope lease and has not taken the authoritative
    // decision yet, so a race test never has to probe the lease and can never
    // steal it. There is no production await point and no alternate entry point.
    static RESERVATION_PAUSES: std::sync::Mutex<Vec<(PathBuf, crate::workspace_intelligence_commit::TestPause)>> =
        std::sync::Mutex::new(Vec::new());
    struct ReservationPauseRegistration(PathBuf);
    impl Drop for ReservationPauseRegistration {
        fn drop(&mut self) {
            RESERVATION_PAUSES.lock().unwrap().retain(|entry| entry.0.as_os_str() != self.0.as_os_str());
        }
    }
    fn register_reservation_pause(base: &Path)
        -> (ReservationPauseRegistration, tokio::sync::mpsc::UnboundedReceiver<()>, ReleasePause) {
        let root = base.join("control");
        let (hook, receiver, release) = pause();
        RESERVATION_PAUSES.lock().unwrap().push((root.clone(), hook));
        (ReservationPauseRegistration(root), receiver, release)
    }
    pub(super) fn reservation_pause(control_root: &Path) -> Option<crate::workspace_intelligence_commit::TestPause> {
        RESERVATION_PAUSES.lock().unwrap().iter()
            .find(|entry| entry.0.as_os_str() == control_root.as_os_str())
            .map(|entry| entry.1.clone())
    }
    pub(super) async fn wait_reservation_pause(pause: &crate::workspace_intelligence_commit::TestPause) {
        pause.0.send(()).unwrap();
        loop {
            // Bind first: the guard must not live across the yield.
            let released = pause.1.lock().unwrap().try_recv();
            match released {
                Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
            }
        }
    }

    #[tokio::test]
    async fn a_truly_absent_scope_is_reserved_without_a_control_record_or_partition() {
        let tmp = tempfile::tempdir().unwrap();
        let reservation = reserved(reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await);
        assert_eq!(reservation.scope(), SCOPE);
        // The tenure is the exact inode the claim lifecycle derives for the scope.
        assert_eq!(reservation.lease_path(), lease_path(tmp.path()));
        let lease = lease_path(tmp.path());
        assert!(lease.is_file());
        assert_eq!(std::fs::metadata(&lease).unwrap().len(), 0, "the scope lease carries no payload");
        // No control record and no cognition partition; the authoritative read
        // leaves only the control record's own payload-free guard.
        assert!(!control_path(tmp.path()).exists());
        assert!(control_lock_path(tmp.path()).is_file());
        assert_eq!(std::fs::metadata(control_lock_path(tmp.path())).unwrap().len(), 0);
        assert_no_partition(tmp.path());
        drop(reservation);
    }

    /// The fixed order is anchor -> reserve -> same-lease promotion. This pins the
    /// fact the anchor owner depends on: reaching the authoritative read creates
    /// the control root and leaves exactly one payload-free `.json.lock` in it, and
    /// the protected initial-enable anchor mint proves that root vacant by counting
    /// every entry, `.lock` included. A reservation taken before the anchor
    /// therefore blocks the later authentic mint, and nothing here unlinks the
    /// lock. The scope lease lives in the lease root, so it is not the cause.
    #[tokio::test]
    async fn reserving_before_the_anchor_leaves_a_control_lock_the_mint_counts() {
        let tmp = tempfile::tempdir().unwrap();
        let reservation = reserved(reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await);
        let control_root = tmp.path().join("control");
        let entries: Vec<String> = std::fs::read_dir(&control_root).unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        let lock_name = format!("{}.json.lock", scope_digest(SCOPE).unwrap());
        assert_eq!(entries, [lock_name.clone()], "the control root must hold exactly the guard");
        assert_eq!(std::fs::read(control_root.join(&lock_name)).unwrap(), Vec::<u8>::new());
        assert!(!control_path(tmp.path()).exists(), "no control record may be created");
        // The tenure is not inside the namespace the mint proves vacant.
        assert!(reservation.lease_path().starts_with(tmp.path().join("leases")));
        assert!(!reservation.lease_path().starts_with(&control_root));
        // Order cannot be repaired from here: release the tenure and the entry stays.
        drop(reservation);
        let entries: Vec<String> = std::fs::read_dir(&control_root).unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, [lock_name], "the guard is never unlinked by design");
        assert!(!control_path(tmp.path()).exists());
        assert_no_partition(tmp.path());
    }

    #[tokio::test]
    async fn stored_records_that_are_not_enabled_are_reserved() {
        for policy in [None, Some(bound_policy(HOST_ID))] {
            let tmp = tempfile::tempdir().unwrap();
            seed_disabled(tmp.path(), SCOPE, policy.clone()).await;
            let before = control_bytes(tmp.path());
            let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, policy.clone())).await);
            // Pre-holding tenure never rewrites the record it observed.
            assert_eq!(control_bytes(tmp.path()), before);
            let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
            assert_eq!(record.enabled, Some(false));
            assert_eq!(record.control_generation, 1);
            assert_eq!(record.policy, policy);
            assert_no_partition(tmp.path());
            drop(reservation);
        }
        // A record whose `enabled` key is absent reads as off and is reserved too.
        let tmp = tempfile::tempdir().unwrap();
        let created = control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Absent,
            WorkspaceIntelligenceControlPatch::default()).await.unwrap();
        assert_eq!(created.record().enabled, None);
        let before = control_bytes(tmp.path());
        let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, None)).await);
        assert_eq!(control(tmp.path()).read(SCOPE).await.unwrap().unwrap().enabled, None);
        assert_eq!(control_bytes(tmp.path()), before);
        assert_no_partition(tmp.path());
        drop(reservation);
    }

    #[tokio::test]
    async fn an_already_enabled_scope_refuses_before_any_lease() {
        for with_policy in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            if with_policy { seed_policy(tmp.path(), SCOPE, bound_policy(HOST_ID)).await; }
            else { seed(tmp.path(), SCOPE, true).await; }
            let before = control_bytes(tmp.path());
            let expected = present(1, if with_policy { Some(bound_policy(HOST_ID)) } else { None });
            // Pins the gate order: an on record reports AlreadyEnabled even when
            // the caller's belief also mismatches, because that is the actionable
            // truth and the caller must not retry a preparation.
            for expectation in [expected, InitialEnableExpectation::Absent] {
                let outcome = reserve(tmp.path(), SCOPE, expectation.clone()).await;
                refused_reservation(outcome, InitialEnableRefusal::AlreadyEnabled);
                assert_no_lease_artifact(tmp.path());
                assert_no_partition(tmp.path());
                assert_eq!(control_bytes(tmp.path()), before);
            }
        }
    }

    #[tokio::test]
    async fn unreadable_or_unrecognized_records_are_errors_without_footprint() {
        for case in ["corrupt", "schema", "directory"] {
            let tmp = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(tmp.path().join("control")).unwrap();
            let path = control_path(tmp.path());
            match case {
                "corrupt" => std::fs::write(&path, b"not a control record").unwrap(),
                "schema" => std::fs::write(&path, serde_json::to_vec(&serde_json::json!({
                    "schema_version": 2, "control_generation": 1, "enabled": false,
                })).unwrap()).unwrap(),
                _ => std::fs::create_dir(&path).unwrap(),
            }
            let error = InitialEnableReservation::reserve(control(tmp.path()),
                tmp.path().join("leases"), SCOPE, InitialEnableExpectation::Absent).await.unwrap_err();
            match case {
                "corrupt" => assert!(matches!(error,
                    WorkspaceIntelligenceClaimError::Control(WorkspaceIntelligenceStoreError::CorruptRecord { .. })), "{error:?}"),
                "schema" => assert!(matches!(error,
                    WorkspaceIntelligenceClaimError::Control(WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion { version: 2, .. })), "{error:?}"),
                _ => assert!(matches!(error, WorkspaceIntelligenceClaimError::Control(_)), "{error:?}"),
            }
            // An unknown or unsupported record is never reset, adopted or reserved over.
            assert_no_lease_artifact(tmp.path());
            assert_no_partition(tmp.path());
        }
    }

    #[tokio::test]
    async fn a_foreign_owner_of_the_scope_lease_yields_standby_without_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let holder = ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap();
        let outcome = reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await;
        assert!(matches!(outcome, InitialEnableAttempt::Standby), "{outcome:?}");
        // Standby stops before the authoritative read, so nothing is created.
        assert!(!tmp.path().join("control").exists());
        assert!(!tmp.path().join("cognition").exists());
        drop(holder);
        let reservation = reserved(reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await);
        drop(reservation);
        assert!(!control_path(tmp.path()).exists());
        assert_no_partition(tmp.path());
    }

    #[tokio::test]
    async fn stating_a_present_record_against_an_absent_scope_is_changed_after_the_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let outcome = reserve(tmp.path(), SCOPE, present(1, None)).await;
        refused_reservation(outcome, InitialEnableRefusal::AuthorityChanged);
        // Only an observed record can refuse before the lease: a missing
        // observation proves nothing, so this refusal legitimately leaves the
        // payload-free scope lease behind and still writes nothing else.
        assert!(!control_path(tmp.path()).exists());
        assert_eq!(std::fs::metadata(lease_path(tmp.path())).unwrap().len(), 0);
        assert_no_partition(tmp.path());
        drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
    }

    #[tokio::test]
    async fn an_expectation_mismatch_refuses_at_the_pre_read_without_footprint() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = bound_policy(HOST_ID);
        seed_disabled(tmp.path(), SCOPE, Some(policy.clone())).await;
        let before = control_bytes(tmp.path());
        let mismatches = [
            InitialEnableExpectation::Absent,
            present(2, Some(policy.clone())),
            present(1, Some(bound_policy(OTHER_HOST_ID))),
            // `None` states "no policy is stored": it never wildcards a policy.
            present(1, None),
        ];
        for expectation in mismatches {
            let outcome = reserve(tmp.path(), SCOPE, expectation.clone()).await;
            refused_reservation(outcome, InitialEnableRefusal::AuthorityChanged);
            assert_no_lease_artifact(tmp.path());
            assert_no_partition(tmp.path());
            assert_eq!(control_bytes(tmp.path()), before);
        }
        // The other direction of the same exact rule: a stored record with no
        // policy is not admitted by a caller who states one.
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, false).await;
        let before = control_bytes(tmp.path());
        let outcome = reserve(tmp.path(), SCOPE, present(1, Some(bound_policy(HOST_ID)))).await;
        refused_reservation(outcome, InitialEnableRefusal::AuthorityChanged);
        assert_no_lease_artifact(tmp.path());
        assert_no_partition(tmp.path());
        assert_eq!(control_bytes(tmp.path()), before);
    }

    #[tokio::test]
    async fn a_whole_policy_change_at_the_same_generation_before_the_lease_refuses_without_footprint() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_disabled(tmp.path(), SCOPE, Some(observed.clone())).await;
        let expectation = present(1, Some(observed.clone()));
        let changed = bound_policy(OTHER_HOST_ID);
        let previous = raw_policy_edit_same_generation(tmp.path(), changed.clone()).await;
        assert_eq!(previous["policy"], observed);
        assert_eq!(previous["control_generation"], serde_json::json!(1));
        let edited = control_bytes(tmp.path());
        let outcome = reserve(tmp.path(), SCOPE, expectation).await;
        refused_reservation(outcome, InitialEnableRefusal::AuthorityChanged);
        // The whole value is compared, so a generation-only check would admit it.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.policy, Some(changed));
        assert_eq!(control_bytes(tmp.path()), edited);
        assert_no_lease_artifact(tmp.path());
        assert_no_partition(tmp.path());
    }

    #[tokio::test]
    async fn a_whole_policy_change_at_the_same_generation_after_the_lease_refuses() {
        let tmp = tempfile::tempdir().unwrap();
        let observed = bound_policy(HOST_ID);
        seed_disabled(tmp.path(), SCOPE, Some(observed.clone())).await;
        let (_registration, mut entered_reservation, release) = register_reservation_pause(tmp.path());
        let base = tmp.path().to_path_buf();
        let expected = observed.clone();
        let task = tokio::spawn(async move { reserve(&base, SCOPE, present(1, Some(expected))).await });
        // Held lease, decision not taken: real-lock evidence, then the change.
        entered(&mut entered_reservation).await;
        assert_contended(&lease_path(tmp.path()));
        let changed = bound_policy(OTHER_HOST_ID);
        let previous = raw_policy_edit_same_generation(tmp.path(), changed.clone()).await;
        assert_eq!(previous["policy"], observed);
        assert_eq!(previous["control_generation"], serde_json::json!(1));
        release.send(()).unwrap();
        let outcome = tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap();
        refused_reservation(outcome, InitialEnableRefusal::AuthorityChanged);
        // The observed projection is re-compared under the guard, so a
        // same-generation whole-policy edit cannot be reserved over.
        let record = control(tmp.path()).read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.enabled, Some(false));
        assert_eq!(record.policy, Some(changed));
        assert_no_partition(tmp.path());
        assert_eq!(std::fs::metadata(lease_path(tmp.path())).unwrap().len(), 0);
        drop(ExclusiveFileLease::try_acquire(&lease_path(tmp.path())).unwrap());
    }

    #[tokio::test]
    async fn one_scope_lease_is_shared_with_the_normal_claim_lifecycle() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, false).await;
        let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, None)).await);
        // The reservation holds the exact `.lock` the claim lifecycle derives.
        assert_eq!(reservation.lease_path(), lease_path(tmp.path()));
        assert!(matches!(reserve(tmp.path(), SCOPE, present(1, None)).await, InitialEnableAttempt::Standby));
        // A foreign scope is a different inode and is not blocked by this tenure.
        let foreign_scope = reserved(reserve(tmp.path(), "claim:beta", InitialEnableExpectation::Absent).await);
        assert_ne!(foreign_scope.lease_path(), reservation.lease_path());
        drop(foreign_scope);
        // The real claim lifecycle contends on the same inode: an already-enabled
        // record still answers Standby while the reservation is held.
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Exactly(1), patch(true)).await.unwrap();
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Standby));
        // Releasing the reservation makes that same path available again.
        let path = reservation.lease_path().to_path_buf();
        drop(reservation);
        drop(ExclusiveFileLease::try_acquire(&path).unwrap());
        assert!(matches!(attempt(tmp.path(), SCOPE).await, ClaimAttempt::Claimed(_)));
    }

    #[tokio::test]
    async fn cancelled_while_waiting_for_the_control_guard_releases_the_lease_and_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, false).await;
        let record = control_path(tmp.path());
        let before = control_bytes(tmp.path());
        let guard = JsonFileStore.acquire_cross_process_lock(&record).await.unwrap();
        let (registration, mut entered_reservation, release) = register_reservation_pause(tmp.path());
        let base = tmp.path().to_path_buf();
        let mut task = tokio::spawn(async move { reserve(&base, SCOPE, present(1, None)).await });
        // The scope lease is already held before the cancellation.
        entered(&mut entered_reservation).await;
        release.send(()).unwrap();
        // Correctness does not depend on how far the detached acquisition got;
        // the assertions below are about the outcome only. Cooperative yields let
        // the attempt reach the real control guard this test holds.
        for _ in 0..64 { tokio::task::yield_now().await; }
        assert!(!task.is_finished());
        assert_contended(&lease_path(tmp.path()));
        task.abort();
        assert!((&mut task).await.unwrap_err().is_cancelled());
        assert!(task.is_finished());
        // A cancelled attempt cannot reach the decision, so it writes nothing.
        assert_eq!(control_bytes(tmp.path()), before);
        assert_no_partition(tmp.path());
        // The pause registry is per control root; this test owns it and retires it
        // before it starts another attempt on the same root.
        drop(registration);
        // Tenure ends with the caller's future rather than with the detached work.
        drop(guard);
        wait_until_free(&lease_path(tmp.path())).await;
        let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, None)).await);
        drop(reservation);
        assert_eq!(control_bytes(tmp.path()), before);
        assert_no_partition(tmp.path());
    }

    #[tokio::test]
    async fn a_reservation_never_makes_a_disabled_scope_claimable() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, false).await;
        let before = control_bytes(tmp.path());
        let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, None)).await);
        // Hard gate: the normal lifecycle still refuses OFF while tenure is held...
        refused_claim(attempt(tmp.path(), SCOPE).await, GovernedClaimRefusal::NotEnabled);
        refused_claim(expecting(tmp.path(), SCOPE, None).await, GovernedClaimRefusal::NotEnabled);
        drop(reservation);
        // ... and after it is released. Pre-holding a lease is not an OFF-to-ON path.
        refused_claim(attempt(tmp.path(), SCOPE).await, GovernedClaimRefusal::NotEnabled);
        assert_no_partition(tmp.path());
        assert_eq!(control_bytes(tmp.path()), before);
    }

    #[tokio::test]
    async fn reservation_debug_is_fully_redacted() {
        let tmp = tempfile::tempdir().unwrap();
        let reservation = reserved(reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await);
        let digest = scope_digest(SCOPE).unwrap();
        let debug = format!("{reservation:?}");
        assert_eq!(debug, "InitialEnableReservation { tenure: \"<redacted>\", .. }");
        for leaked in [SCOPE, digest.as_str(), "leases", "control", "cognition"] {
            assert!(!debug.contains(leaked), "the reservation Debug leaked {leaked}");
        }
        let wrapped = format!("{:?}", InitialEnableAttempt::Reserved(reservation));
        assert_eq!(wrapped, "Reserved(InitialEnableReservation { tenure: \"<redacted>\", .. })");
    }

    #[test]
    fn reservation_surface_is_sealed_and_cannot_write() {
        let source = include_str!("workspace_intelligence_claim.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains("impl std::fmt::Debug for InitialEnableReservation"));
        for forbidden in [
            "#[derive(Debug, Clone)]\npub struct InitialEnableReservation",
            "#[derive(Clone)]\npub struct InitialEnableReservation",
            "impl Clone for InitialEnableReservation",
            "pub fn token",
            "pub fn rebind",
            // No permissive switch, in parameter position or as a field.
            "allow_off:",
            "allow_off =",
            "allow_off,",
            // No raw extraction of tenure, and no path/permission accessor: the
            // held lease, the control root and the verified snapshot stay inside.
            // The pre-existing `ClaimLeaseBinding` crate-internal accessors are a
            // different type and are not matched by these `pub fn` spellings.
            "into_lease",
            "fn into_",
            "pub fn lease_path",
            "pub fn lease(",
            "pub fn control_root",
            "pub fn authority",
            "pub fn snapshot",
            "pub fn verified",
            // The later OFF-to-ON step is not this slice's, in any spelling.
            "fn promote",
            "fn enable(",
            "fn activate(",
        ] {
            assert!(!production.contains(forbidden), "unexpected reservation surface: {forbidden}");
        }
        // Everything from the handle declaration to the end of production is this
        // reservation's own surface: struct, Debug impl and inherent impl.
        let section = production.split("pub struct InitialEnableReservation {").nth(1).unwrap();
        // Private fields and no public constructor: the only mint site is reserve.
        // The private `lease: ExclusiveFileLease` field is required, not banned.
        let fields = section.split('}').next().unwrap();
        assert!(!fields.contains("pub "), "the reservation fields must stay private: {fields}");
        assert!(fields.contains("lease: ExclusiveFileLease"), "the handle must own the lease: {fields}");
        // The verified snapshot is carried, and only crate-internally.
        assert!(fields.contains("authority: VerifiedInitialAuthority"));
        assert!(fields.contains("control_root: PathBuf"));
        assert!(production.contains("pub(crate) enum VerifiedInitialAuthority"));
        assert!(!production.contains("pub enum VerifiedInitialAuthority"));
        // No return type hands out the raw tenure object.
        for forbidden in ["-> ExclusiveFileLease", "-> &ExclusiveFileLease", "-> Arc<ExclusiveFileLease>"] {
            assert!(!section.contains(forbidden), "raw tenure extraction is forbidden: {forbidden}");
        }
        // The test-only path accessor exists exactly once and only under cfg(test).
        // `ClaimLeaseBinding`'s crate-internal accessor is a different type.
        assert_eq!(production.matches("#[cfg(test)]\n    fn lease_path(&self)").count(), 1);
        assert!(production.contains("#[cfg(test)]\n    fn lease_path(&self)"));
        // The reservation path can never write control, cognition or tenure state.
        for forbidden in [".update(", "commit_governed", "advance_incarnation", "advance_cursor", "initialize(", "ControlFieldUpdate"] {
            assert!(!section.contains(forbidden), "the reservation must not write: {forbidden}");
        }
        // The hard gate on the normal lifecycle is untouched: both claim entry
        // points still require an observed enabled-true authority.
        assert_eq!(production.matches("if snapshot.authority().enabled() != Some(true)").count(), 2);
    }

    #[tokio::test]
    async fn the_handle_carries_the_absent_snapshot_it_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let reservation = reserved(reserve(tmp.path(), SCOPE, InitialEnableExpectation::Absent).await);
        // Same-call provenance: scope, control root, lease and snapshot all come
        // from this one `reserve` call.
        assert_eq!(reservation.scope(), SCOPE);
        assert_eq!(reservation.control_root, tmp.path().join("control"));
        assert_eq!(reservation.lease_path(), lease_path(tmp.path()));
        assert_eq!(reservation.authority, VerifiedInitialAuthority::Absent);
        // The snapshot is an observation of this attempt, not proof of absence:
        // no control record was created to make it true.
        assert!(!control_path(tmp.path()).exists());
        drop(reservation);
    }

    #[tokio::test]
    async fn the_handle_carries_the_complete_present_snapshot_it_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let policy = bound_policy(HOST_ID);
        control(tmp.path()).update(SCOPE, ControlGenerationExpectation::Absent,
            WorkspaceIntelligenceControlPatch {
                enabled: ControlFieldUpdate::Set(false),
                model_ref: ControlFieldUpdate::Set("workspace-model-a".to_owned()),
                policy: ControlFieldUpdate::Set(policy.clone()),
                ..Default::default()
            }).await.unwrap();
        let reservation = reserved(reserve(tmp.path(), SCOPE, present(1, Some(policy.clone()))).await);
        let VerifiedInitialAuthority::Present(authority) = &reservation.authority else {
            panic!("a stored record must be carried as a present snapshot: {:?}", reservation.authority);
        };
        // Every projected field is carried, including the two the caller's own
        // expectation never states.
        assert_eq!(authority.control_generation(), 1);
        assert_eq!(authority.schema_version(), Some(1));
        assert_eq!(authority.enabled(), Some(false));
        assert_eq!(authority.model_ref(), Some("workspace-model-a"));
        assert_eq!(authority.policy(), Some(&policy));
        drop(reservation);
    }

    fn cursor_stored(base: &Path, scope: &str) -> Option<String> {
        WorkspaceIntelligenceCognitionStore::new(base.join("cognition"))
            .read(scope).unwrap().unwrap().cursor
    }
    fn refused_cursor(outcome: CursorAttempt, reason: GovernedClaimRefusal) {
        assert!(matches!(outcome, CursorAttempt::Refused(actual) if actual == reason), "{outcome:?}");
    }

    #[tokio::test]
    async fn advance_cursor_writes_the_cursor_under_the_claim() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        let token = stored(tmp.path(), SCOPE);
        assert_eq!(cursor_stored(tmp.path(), SCOPE), None);

        let outcome = claim.advance_cursor(claim.ticket(), None, None, "m-1").await.unwrap();

        let CursorAttempt::Advanced(result) = outcome else { panic!("{outcome:?}") };
        assert_eq!(result.previous, None);
        assert_eq!(result.written, "m-1");
        assert_eq!(cursor_stored(tmp.path(), SCOPE).as_deref(), Some("m-1"));
        assert_eq!(stored(tmp.path(), SCOPE), token, "the tenure marker is untouched");
    }

    #[tokio::test]
    async fn advance_cursor_refuses_a_foreign_ticket_without_a_write() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        // A second claim over another root pairing yields a ticket this claim cannot use.
        let other = tempfile::tempdir().unwrap();
        seed(other.path(), SCOPE, true).await;
        let foreign = acquire(other.path(), SCOPE).await;
        let before_control = control_bytes(tmp.path());
        let before_cognition = cognition_bytes(tmp.path());

        refused_cursor(claim.advance_cursor(foreign.ticket(), None, None, "m-1").await.unwrap(),
            GovernedClaimRefusal::ForeignBinding);

        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), before_cognition, "the partition is untouched");
        assert_eq!(cursor_stored(tmp.path(), SCOPE), None);
    }

    #[tokio::test]
    async fn advance_cursor_refuses_a_different_expected_policy_before_the_fence() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        let before_control = control_bytes(tmp.path());
        let before_cognition = cognition_bytes(tmp.path());

        refused_cursor(claim.advance_cursor(claim.ticket(), Some(&bound_policy(HOST_ID)), None, "m-1").await.unwrap(),
            GovernedClaimRefusal::AuthorityChanged);

        // A caller-belief mismatch is decided from the observation alone: neither the
        // control record nor the partition moved, so the fence never ran.
        assert_eq!(control_bytes(tmp.path()), before_control);
        assert_eq!(cognition_bytes(tmp.path()), before_cognition);
        assert_eq!(cursor_stored(tmp.path(), SCOPE), None);
    }

    #[tokio::test]
    async fn advance_cursor_uses_the_previous_write_as_the_next_expectation() {
        let tmp = tempfile::tempdir().unwrap();
        seed(tmp.path(), SCOPE, true).await;
        let claim = acquire(tmp.path(), SCOPE).await;
        let CursorAttempt::Advanced(first) = claim.advance_cursor(claim.ticket(), None, None, "m-1").await.unwrap()
            else { panic!("the first advance must be accepted") };

        let CursorAttempt::Advanced(second) = claim.advance_cursor(claim.ticket(), None, Some(&first.written), "m-2").await.unwrap()
            else { panic!("the chained advance must be accepted") };

        assert_eq!(second.previous.as_deref(), Some("m-1"));
        assert_eq!(second.written, "m-2");
        assert_eq!(cursor_stored(tmp.path(), SCOPE).as_deref(), Some("m-2"));
        // An expectation that is already stale is a conflict, not an ownership refusal and
        // not a write: the caller re-reads, decides again and retries.
        let before_cognition = cognition_bytes(tmp.path());
        let stale = claim.advance_cursor(claim.ticket(), None, Some(&first.written), "m-3").await.unwrap();
        assert!(matches!(stale, CursorAttempt::Conflict), "{stale:?}");
        assert!(!matches!(stale, CursorAttempt::Refused(_)), "a stale snapshot is not a refusal");
        assert_eq!(cognition_bytes(tmp.path()), before_cognition, "a conflict writes nothing");
        assert_eq!(cursor_stored(tmp.path(), SCOPE).as_deref(), Some("m-2"));
    }

    #[test]
    fn cursor_outcome_and_attempt_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CursorOutcome>();
        assert_send_sync::<CursorAttempt>();
        // A conflict carries no cursor text and no secret, so its debug output is just the
        // variant name.
        assert_eq!(format!("{:?}", CursorAttempt::Conflict), "Conflict");
    }

    #[test]
    fn impossible_cursor_outcomes_are_unexpected_fence_outcomes() {
        // The tenure and verification entry points can never observe a cursor outcome, and
        // their match arms say so by name instead of with a wildcard. This is a source
        // check because those paths are unreachable by construction.
        let source = include_str!("workspace_intelligence_claim.rs");
        let production = source.split("#[cfg(test)]\nmod tests").next().unwrap();
        assert!(production.contains(
            "GovernedFenceOutcome::Verified { .. } | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict =>"
        ));
        assert!(production.contains(
            "GovernedFenceOutcome::Advanced(_) | GovernedFenceOutcome::CursorAdvanced(_) | GovernedFenceOutcome::CursorConflict =>"
        ));
        assert_eq!(
            production.matches("GovernedFenceOutcome::CursorConflict").count(),
            5,
            "four impossible-case arms plus the one real cursor-conflict arm"
        );
    }
}
