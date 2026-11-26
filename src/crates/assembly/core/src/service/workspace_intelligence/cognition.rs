//! Cognition version and invalidation policy for workspace intelligence (WP1.6).
//!
//! This module is pure policy. It reads no file, opens no database, spawns no task, reads no
//! clock and writes no log line. It defines the identities, states, transitions and decisions
//! that the future cognition store and the host reader will share, and nothing else.
//!
//! Deliberate boundaries:
//!
//! - Nothing here names `control_generation`. That generation orders the *control* record, and
//!   a cognition partition is not part of the control plane: borrowing its ordering would make
//!   an unrelated control change look like a cognition fact. [`CognitionEpoch`] is this
//!   partition's own baseline identity.
//! - Partition keys are opaque strings. A workspace path is not a partition identity: two
//!   checkouts of one repository are two partitions, and a repository moved on disk keeps its
//!   partition. Nothing here derives identity from a path.
//! - No user-visible behaviour is delivered here: no surface renders these states, no command
//!   exposes them, and no model prompt consumes them in this slice.
//! - A record this build cannot interpret is retained as [`CognitionState::UnknownRetained`],
//!   never deleted and never reset. Removing it is an explicit user action in the storage
//!   layer, and a compatibility migration points a new record at the old one instead of
//!   reviving it.
//!
//! Two version dimensions stay separate on purpose. [`CognitionRevision`] moves for one record
//! when that record is updated. [`CognitionEpoch`] moves for the whole partition when a fact
//! that changes what an existing snapshot *means* happens: a human withdrawal, a tightened
//! policy, a revoked authorization or a withdrawn source. A consumer holding a snapshot
//! compares the epoch and drops everything when it moved, so a single record's revision can
//! never silently revalidate a snapshot that a sensitive event invalidated.

/// What a cognition record is about.
///
/// The six kinds are the taxonomy the design fixes; they are orthogonal to
/// [`CognitionCategory`] and [`CognitionAuthority`], so no kind implies a category or an
/// authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionKind {
    /// A goal or a constraint the user stated.
    Goal,
    /// Knowledge or a decision.
    Knowledge,
    /// A working relation that spans sessions.
    Relation,
    /// A commitment with a time component.
    Commitment,
    /// A management action or the feedback about one.
    Action,
    /// A recognized gap in what the partition knows.
    Gap,
}

/// Whether a record projects a fact or records an assertion about one.
///
/// The two are never merged: a fact can be re-derived from its source, an assertion carries
/// the authority of whoever asserted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionCategory {
    /// A projection of something the source itself holds.
    Fact,
    /// An inference or statement attributed to its author.
    Asserted,
}

/// Who stands behind a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionAuthority {
    /// A human stated it.
    Human,
    /// This build derived it.
    Derived,
}

/// Stable identity of one cognition record.
///
/// The identifier is never reused: a record that leaves the active set keeps its identity, and
/// a later statement about the same subject is a new record. It is an opaque owner-assigned
/// value, not a path, not a workspace name, and it is never parsed back out of user content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CognitionRecordId(String);

impl CognitionRecordId {
    /// Wraps an owner-assigned identifier, keeping its bytes unchanged.
    pub(crate) fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The identifier exactly as the owner assigned it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Monotonic revision of one record.
///
/// A revision orders the states of a single record. It never orders two records and never
/// orders two partitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CognitionRevision(u64);

impl CognitionRevision {
    /// The first revision of a record.
    pub(crate) const FIRST: Self = Self(1);

    /// Wraps a stored revision value.
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }

    /// The next revision of the same record, strictly greater than `self`.
    ///
    /// The value saturates at [`u64::MAX`] instead of wrapping or panicking: a record that
    /// somehow reached the ceiling keeps the last revision rather than restarting at zero,
    /// because a restart would make an old snapshot look current. A caller must therefore treat
    /// a `next()` that did not move (the result equals `self`) as a refusal and must not write
    /// the same value again; [`CognitionRevision::new`] accepts any stored value on purpose, so
    /// a damaged `u64::MAX` on disk is a refusal at the write site, never a panic here.
    pub(crate) fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Baseline identity of one partition's cognition state.
///
/// Every record in the partition carries the epoch it was written under. When a sensitive
/// event changes the meaning of the whole partition, the epoch advances and every snapshot a
/// consumer holds becomes unusable at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct CognitionEpoch(u64);

impl CognitionEpoch {
    /// The first epoch of a partition.
    pub(crate) const FIRST: Self = Self(1);

    /// Wraps a stored epoch value.
    pub(crate) fn new(value: u64) -> Self {
        Self(value)
    }

    /// The next epoch of the partition, strictly greater than `self`.
    ///
    /// Saturates at [`u64::MAX`] for the same reason as [`CognitionRevision::next`], and the
    /// same write-side obligation applies: a caller must treat a `next()` that did not move as a
    /// refusal instead of writing the same epoch again, and a damaged `u64::MAX` read back by
    /// [`CognitionEpoch::new`] is that caller's refusal, not a panic here.
    pub(crate) fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// Which version dimension an event moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VersionImpact {
    /// Only the record that changed moves forward.
    BumpRevision,
    /// The whole partition rebases: every snapshot taken under the old epoch is stale.
    RebaseEpoch,
}

/// Decides which version dimension one cognition event moves.
///
/// A sensitive event rebases the epoch even when only one record is withdrawn: the point of
/// the epoch is that a consumer which cached *derived* state cannot keep it after the ground
/// under it changed. Every other event touches one record and bumps only its revision.
pub(crate) fn version_impact(event: CognitionEvent) -> VersionImpact {
    use CognitionEvent as E;
    match event {
        E::Withdraw | E::TightenPolicy | E::RevokeAuthorization | E::InvalidateSource => {
            VersionImpact::RebaseEpoch
        }
        E::Validate
        | E::Merge
        | E::DetectConflict
        | E::ResolveConflict
        | E::Supersede
        | E::ValidityElapsed
        | E::RetireUnknown
        | E::Rediscover => VersionImpact::BumpRevision,
    }
}

/// Persistent state of one cognition record.
///
/// Four states are terminal and never revive: [`CognitionState::Superseded`],
/// [`CognitionState::Invalidated`], [`CognitionState::Expired`] and
/// [`CognitionState::Withdrawn`]. [`CognitionState::UnknownRetained`] is not terminal in the
/// storage sense — the record still exists — but no state transition leaves it, because only
/// an explicit user deletion may.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionState {
    /// Observed but not yet validated.
    Pending,
    /// Validated and eligible for injection.
    Active,
    /// Two facts that cannot both hold are recorded; a human must resolve it.
    Conflict,
    /// A newer record replaced this one.
    Superseded,
    /// The source or authorization behind it is gone.
    Invalidated,
    /// Its validity window elapsed.
    Expired,
    /// A human withdrew it.
    Withdrawn,
    /// This build cannot interpret it and retained it untouched.
    UnknownRetained,
}

impl CognitionState {
    /// True for the four states a record never leaves.
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Superseded | Self::Invalidated | Self::Expired | Self::Withdrawn
        )
    }
}

/// One event the cognition store applies to a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionEvent {
    /// A validation pass accepted the record.
    Validate,
    /// A validated update merged into the record.
    Merge,
    /// Two records cannot both hold.
    DetectConflict,
    /// A human resolved a conflict; the merged result is re-validated.
    ResolveConflict,
    /// A newer record replaces this one.
    Supersede,
    /// The source the record projects is gone.
    InvalidateSource,
    /// The authorization that allowed the record was revoked.
    RevokeAuthorization,
    /// A policy tightened underneath the record.
    TightenPolicy,
    /// The record's validity window elapsed.
    ValidityElapsed,
    /// A human withdrew the record.
    Withdraw,
    /// This build could not interpret the record and retained it.
    RetireUnknown,
    /// A source was observed again; a new record references the retained one.
    Rediscover,
}

/// Why a transition was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CognitionTransitionError {
    /// The event is not legal in the current state. Nothing is written when this is returned.
    IllegalTransition {
        /// The state the record was in.
        from: CognitionState,
        /// The event that was refused.
        event: CognitionEvent,
    },
}

/// Applies one event to one state.
///
/// The table is total: every `(state, event)` pair is either a reviewed transition or an
/// [`CognitionTransitionError::IllegalTransition`]. Terminal states accept nothing and
/// [`CognitionState::UnknownRetained`] accepts nothing.
///
/// [`CognitionEvent::Merge`] and [`CognitionEvent::Rediscover`] are content events that never
/// pass through this function: a merge is a validated update of an already-active record, and a
/// rediscovery points a new record at a retained one. Answering them here with
/// [`CognitionTransitionError::IllegalTransition`] is not a verdict on the event itself.
///
/// A conflict leaves only through [`CognitionEvent::InvalidateSource`] into
/// [`CognitionState::Invalidated`], or through [`CognitionEvent::Withdraw`] and
/// [`CognitionEvent::RetireUnknown`]. Revoking an authorization and tightening a policy rebase
/// the partition epoch and do not move a conflicted record's state.
///
/// The arms are grouped per state for readability, but every illegal event of that state is
/// listed by name instead of being caught by a wildcard, so adding a [`CognitionState`] or
/// [`CognitionEvent`] variant fails to compile here — as it does in [`version_impact`],
/// [`forward_invalidation`], [`injection_eligible`] and [`backward_requires_recheck`] — instead
/// of silently turning into a refused transition. The test below pins every listed cell.
pub(crate) fn transition(
    state: CognitionState,
    event: CognitionEvent,
) -> Result<CognitionState, CognitionTransitionError> {
    use CognitionEvent as E;
    use CognitionState as S;

    let next = match state {
        S::Pending => match event {
            E::Validate => S::Active,
            E::DetectConflict => S::Conflict,
            E::InvalidateSource | E::RevokeAuthorization | E::TightenPolicy => S::Invalidated,
            E::ValidityElapsed => S::Expired,
            E::Withdraw => S::Withdrawn,
            E::RetireUnknown => S::UnknownRetained,
            E::Merge | E::ResolveConflict | E::Supersede | E::Rediscover => {
                return Err(illegal(state, event))
            }
        },
        S::Active => match event {
            E::Supersede => S::Superseded,
            E::DetectConflict => S::Conflict,
            E::InvalidateSource | E::RevokeAuthorization | E::TightenPolicy => S::Invalidated,
            E::ValidityElapsed => S::Expired,
            E::Withdraw => S::Withdrawn,
            E::RetireUnknown => S::UnknownRetained,
            E::Validate | E::Merge | E::ResolveConflict | E::Rediscover => {
                return Err(illegal(state, event))
            }
        },
        S::Conflict => match event {
            E::ResolveConflict => S::Pending,
            E::InvalidateSource => S::Invalidated,
            E::Withdraw => S::Withdrawn,
            E::RetireUnknown => S::UnknownRetained,
            E::Validate
            | E::Merge
            | E::DetectConflict
            | E::Supersede
            | E::RevokeAuthorization
            | E::TightenPolicy
            | E::ValidityElapsed
            | E::Rediscover => return Err(illegal(state, event)),
        },
        // A terminal state never revives: reaching it is the end of the record's life, and a
        // later statement about the same subject is a new record with its own identity.
        S::Superseded | S::Invalidated | S::Expired | S::Withdrawn => {
            return Err(illegal(state, event))
        }
        // A retained-unknown record leaves only through an explicit user deletion, which is a
        // storage action, never a transition.
        S::UnknownRetained => return Err(illegal(state, event)),
    };
    Ok(next)
}

fn illegal(from: CognitionState, event: CognitionEvent) -> CognitionTransitionError {
    CognitionTransitionError::IllegalTransition { from, event }
}

/// Whether a record of this state may be injected into a prompt.
///
/// `validity_elapsed` is supplied by the caller: this module reads no clock, so the validity
/// window is a fact the reader passes in rather than one policy derives. Only an active,
/// still-valid record is eligible; a conflicted record is exactly the state a human has to
/// settle first.
pub(crate) fn injection_eligible(state: CognitionState, validity_elapsed: bool) -> bool {
    use CognitionState as S;
    match state {
        S::Active => !validity_elapsed,
        S::Pending
        | S::Conflict
        | S::Superseded
        | S::Invalidated
        | S::Expired
        | S::Withdrawn
        | S::UnknownRetained => false,
    }
}

/// Who may read one cognition record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CognitionVisibility {
    /// Readable inside the partition that owns it and nowhere else.
    Partition,
    /// The owner asked to share the record with a declared scope, under a named
    /// authorization source.
    ExplicitShared {
        /// The scope the owner declared. Opaque here: nothing in this module evaluates it.
        scope: String,
        /// The authorization the owner cited for the share. Opaque here as well.
        authorization_source: String,
    },
}

impl CognitionVisibility {
    /// The declared share scope, when the record is shared at all.
    pub(crate) fn shared_scope(&self) -> Option<&str> {
        match self {
            Self::Partition => None,
            Self::ExplicitShared { scope, .. } => Some(scope),
        }
    }

    /// The authorization source the owner cited, when the record is shared at all.
    pub(crate) fn authorization_source(&self) -> Option<&str> {
        match self {
            Self::Partition => None,
            Self::ExplicitShared {
                authorization_source, ..
            } => Some(authorization_source),
        }
    }
}

/// Whether a reader in `reader_partition` may read a record owned by `record_partition`.
///
/// Both visibilities are answered partition-locally: this build has no cross-partition
/// authorization entry point, so a shared record stays unreadable from another partition
/// instead of becoming silently allowed. That is the conservative answer the design asks for,
/// and [`requires_owner_authorization`] reports the obligation a future reader must satisfy
/// before only the `ExplicitShared` branch may relax.
pub(crate) fn visible_in(
    visibility: &CognitionVisibility,
    reader_partition: &str,
    record_partition: &str,
) -> bool {
    match visibility {
        CognitionVisibility::Partition | CognitionVisibility::ExplicitShared { .. } => {
            reader_partition == record_partition
        }
    }
}

/// Whether reading this record requires the owner-authorization check this build lacks.
pub(crate) fn requires_owner_authorization(visibility: &CognitionVisibility) -> bool {
    match visibility {
        CognitionVisibility::Partition => false,
        CognitionVisibility::ExplicitShared { .. } => true,
    }
}

/// How two records that cannot both hold are reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityOutcome {
    /// They are about different subjects, so both stay.
    Coexist,
    /// The human record survives and the derived one does not.
    KeepHuman,
    /// Both stay, marked as a conflict for a human to settle.
    Conflict,
}

/// Reduces two records by authority.
///
/// Derived state never overrides a human statement in either direction. Two records of the
/// same authority that cannot both hold are never resolved by picking one: the caller records a
/// [`CognitionState::Conflict`] and a human resolves it, because guessing which human statement
/// or which derivation is right is exactly the silent overwrite this contract forbids.
pub(crate) fn resolve_authority_conflict(
    a: CognitionAuthority,
    b: CognitionAuthority,
    mutually_exclusive: bool,
) -> AuthorityOutcome {
    use AuthorityOutcome as O;
    use CognitionAuthority::{Derived, Human};

    if !mutually_exclusive {
        return O::Coexist;
    }
    match (a, b) {
        (Human, Derived) | (Derived, Human) => O::KeepHuman,
        (Human, Human) | (Derived, Derived) => O::Conflict,
    }
}

/// One record's dependence on the exact revision of another.
///
/// The exact upstream revision is part of the fact: a downstream record derived from revision 3
/// says nothing about revision 4, so the pair travels together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CognitionDependency {
    /// The record this one derived from.
    pub(crate) upstream: CognitionRecordId,
    /// The upstream revision this one was derived from.
    pub(crate) upstream_revision: CognitionRevision,
}

/// What an upstream event asks of the records derived from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DownstreamAction {
    /// The derived record is invalid: the ground it stood on is gone.
    Invalidate,
    /// The derived record may still be right but must be rechecked before it is used again.
    MarkForRecheck,
    /// Nothing to do.
    None,
}

/// What an upstream event does to the records derived from it.
///
/// Only events that destroy the upstream's own standing invalidate the downstream records.
/// A supersede is different: the upstream still happened, so the derived record is rechecked
/// rather than thrown away. Everything else is a change inside one record and reaches no
/// dependent.
pub(crate) fn forward_invalidation(upstream_event: CognitionEvent) -> Option<DownstreamAction> {
    use CognitionEvent as E;
    match upstream_event {
        E::InvalidateSource | E::RevokeAuthorization | E::TightenPolicy | E::Withdraw => {
            Some(DownstreamAction::Invalidate)
        }
        E::Supersede => Some(DownstreamAction::MarkForRecheck),
        E::Validate
        | E::Merge
        | E::DetectConflict
        | E::ResolveConflict
        | E::ValidityElapsed
        | E::RetireUnknown
        | E::Rediscover => None,
    }
}

/// Whether a downstream record must be rechecked when its upstream leaves the active set.
///
/// The first version has no event queue, so the reader asks this instead: a record that is
/// still active, still conflicted or still waiting for validation must not keep being injected
/// after an upstream it depends on stopped standing. A record that already left the active set
/// needs nothing, and a retained-unknown record is not ours to reinterpret.
pub(crate) fn backward_requires_recheck(downstream_state: CognitionState) -> bool {
    use CognitionState as S;
    match downstream_state {
        S::Active | S::Conflict | S::Pending => true,
        S::Superseded | S::Invalidated | S::Expired | S::Withdrawn | S::UnknownRetained => false,
    }
}

/// How a record this build cannot interpret is held.
///
/// `kind_known` records whether the record's kind was recognizable at all. Both answers are
/// retained: an unknown kind and a known kind with an unreadable body are the same fact for
/// policy, and neither is deleted, reset or promoted. The flag stays in the signature because a
/// later interpreter needs the distinction for diagnostics, and because a caller must not be
/// able to express "drop it" through this decision. The two values currently agree, so a caller
/// must not infer from this answer whether the body was readable.
pub(crate) fn interpret_unknown(kind_known: bool) -> CognitionState {
    match kind_known {
        // The kind itself is unknown to this build.
        false => CognitionState::UnknownRetained,
        // The kind is known but the body could not be read.
        true => CognitionState::UnknownRetained,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATES: [CognitionState; 8] = [
        CognitionState::Pending,
        CognitionState::Active,
        CognitionState::Conflict,
        CognitionState::Superseded,
        CognitionState::Invalidated,
        CognitionState::Expired,
        CognitionState::Withdrawn,
        CognitionState::UnknownRetained,
    ];

    const EVENTS: [CognitionEvent; 12] = [
        CognitionEvent::Validate,
        CognitionEvent::Merge,
        CognitionEvent::DetectConflict,
        CognitionEvent::ResolveConflict,
        CognitionEvent::Supersede,
        CognitionEvent::InvalidateSource,
        CognitionEvent::RevokeAuthorization,
        CognitionEvent::TightenPolicy,
        CognitionEvent::ValidityElapsed,
        CognitionEvent::Withdraw,
        CognitionEvent::RetireUnknown,
        CognitionEvent::Rediscover,
    ];

    /// The reviewed transition table, written out one legal cell at a time.
    ///
    /// Kept apart from [`transition`] on purpose: the production match is grouped per state,
    /// while this table names every cell the design reviewed, so a table change and a code
    /// change cannot hide behind one edit.
    const LEGAL: &[(CognitionState, CognitionEvent, CognitionState)] = &[
        (CognitionState::Pending, CognitionEvent::Validate, CognitionState::Active),
        (CognitionState::Pending, CognitionEvent::DetectConflict, CognitionState::Conflict),
        (CognitionState::Pending, CognitionEvent::InvalidateSource, CognitionState::Invalidated),
        (
            CognitionState::Pending,
            CognitionEvent::RevokeAuthorization,
            CognitionState::Invalidated,
        ),
        (CognitionState::Pending, CognitionEvent::TightenPolicy, CognitionState::Invalidated),
        (CognitionState::Pending, CognitionEvent::ValidityElapsed, CognitionState::Expired),
        (CognitionState::Pending, CognitionEvent::Withdraw, CognitionState::Withdrawn),
        (CognitionState::Pending, CognitionEvent::RetireUnknown, CognitionState::UnknownRetained),
        (CognitionState::Active, CognitionEvent::Supersede, CognitionState::Superseded),
        (CognitionState::Active, CognitionEvent::DetectConflict, CognitionState::Conflict),
        (CognitionState::Active, CognitionEvent::InvalidateSource, CognitionState::Invalidated),
        (
            CognitionState::Active,
            CognitionEvent::RevokeAuthorization,
            CognitionState::Invalidated,
        ),
        (CognitionState::Active, CognitionEvent::TightenPolicy, CognitionState::Invalidated),
        (CognitionState::Active, CognitionEvent::ValidityElapsed, CognitionState::Expired),
        (CognitionState::Active, CognitionEvent::Withdraw, CognitionState::Withdrawn),
        (CognitionState::Active, CognitionEvent::RetireUnknown, CognitionState::UnknownRetained),
        (CognitionState::Conflict, CognitionEvent::ResolveConflict, CognitionState::Pending),
        (CognitionState::Conflict, CognitionEvent::InvalidateSource, CognitionState::Invalidated),
        (CognitionState::Conflict, CognitionEvent::Withdraw, CognitionState::Withdrawn),
        (CognitionState::Conflict, CognitionEvent::RetireUnknown, CognitionState::UnknownRetained),
    ];

    fn legal_target(
        state: CognitionState,
        event: CognitionEvent,
    ) -> Option<CognitionState> {
        LEGAL
            .iter()
            .find(|(from, candidate, _)| *from == state && *candidate == event)
            .map(|(_, _, target)| *target)
    }

    #[test]
    fn the_transition_table_is_total_over_every_state_and_event() {
        assert_eq!(LEGAL.len(), 20, "the reviewed table has exactly 20 legal cells");
        assert_eq!(STATES.len() * EVENTS.len(), 96, "8 states x 12 events");

        let mut exercised = 0;
        for state in STATES {
            for event in EVENTS {
                match legal_target(state, event) {
                    Some(target) => {
                        exercised += 1;
                        assert_eq!(transition(state, event), Ok(target), "{state:?} + {event:?}");
                    }
                    None => assert_eq!(
                        transition(state, event),
                        Err(CognitionTransitionError::IllegalTransition {
                            from: state,
                            event
                        }),
                        "{state:?} + {event:?}"
                    ),
                }
            }
        }
        assert_eq!(exercised, LEGAL.len(), "every table row was reached");
    }

    #[test]
    fn a_terminal_state_never_revives() {
        for state in [
            CognitionState::Superseded,
            CognitionState::Invalidated,
            CognitionState::Expired,
            CognitionState::Withdrawn,
        ] {
            assert!(state.is_terminal(), "{state:?}");
            for event in EVENTS {
                assert_eq!(
                    transition(state, event),
                    Err(CognitionTransitionError::IllegalTransition { from: state, event }),
                    "{state:?} + {event:?}"
                );
            }
        }
        for state in [
            CognitionState::Pending,
            CognitionState::Active,
            CognitionState::Conflict,
        ] {
            assert!(!state.is_terminal(), "{state:?}");
        }
    }

    #[test]
    fn a_retained_unknown_record_leaves_only_through_an_explicit_delete() {
        // Not terminal in the storage sense: the record still exists. It is unreachable by
        // every event, because deleting it is a storage action a transition must not express.
        assert!(!CognitionState::UnknownRetained.is_terminal());
        for event in EVENTS {
            assert_eq!(
                transition(CognitionState::UnknownRetained, event),
                Err(CognitionTransitionError::IllegalTransition {
                    from: CognitionState::UnknownRetained,
                    event
                }),
                "{event:?}"
            );
        }
    }

    #[test]
    fn a_merge_and_a_rediscovery_are_not_state_transitions() {
        for state in STATES {
            assert_eq!(
                transition(state, CognitionEvent::Merge),
                Err(CognitionTransitionError::IllegalTransition {
                    from: state,
                    event: CognitionEvent::Merge
                }),
                "{state:?}"
            );
            assert_eq!(
                transition(state, CognitionEvent::Rediscover),
                Err(CognitionTransitionError::IllegalTransition {
                    from: state,
                    event: CognitionEvent::Rediscover
                }),
                "{state:?}"
            );
        }
    }

    #[test]
    fn only_an_active_record_with_a_live_validity_window_is_eligible() {
        assert!(injection_eligible(CognitionState::Active, false));
        assert!(!injection_eligible(CognitionState::Active, true));
        for state in STATES {
            if state == CognitionState::Active {
                continue;
            }
            assert!(!injection_eligible(state, false), "{state:?}");
            assert!(!injection_eligible(state, true), "{state:?}");
        }
    }

    #[test]
    fn a_shared_record_stays_inside_its_own_partition() {
        let local = CognitionVisibility::Partition;
        assert!(visible_in(&local, "partition-a", "partition-a"));
        assert!(!visible_in(&local, "partition-a", "partition-b"));
        assert!(!visible_in(&local, "partition-b", "partition-a"));
        assert!(!requires_owner_authorization(&local));
        assert_eq!(local.shared_scope(), None);
        assert_eq!(local.authorization_source(), None);

        let shared = CognitionVisibility::ExplicitShared {
            scope: "team-partition".to_owned(),
            authorization_source: "owner-decision-7".to_owned(),
        };
        assert!(visible_in(&shared, "partition-a", "partition-a"));
        // Cross-partition reads have no authorization entry point in this build, so they stay
        // unsupported instead of silently allowed, even when the declared scope names them.
        assert!(!visible_in(&shared, "team-partition", "partition-a"));
        assert!(!visible_in(&shared, "partition-b", "partition-a"));
        assert!(requires_owner_authorization(&shared));
        assert_eq!(shared.shared_scope(), Some("team-partition"));
        assert_eq!(shared.authorization_source(), Some("owner-decision-7"));
    }

    #[test]
    fn a_derived_record_never_overrides_a_human_one() {
        use AuthorityOutcome as O;
        use CognitionAuthority::{Derived, Human};

        assert_eq!(resolve_authority_conflict(Human, Derived, true), O::KeepHuman);
        assert_eq!(resolve_authority_conflict(Derived, Human, true), O::KeepHuman);
        assert_eq!(resolve_authority_conflict(Human, Human, true), O::Conflict);
        assert_eq!(resolve_authority_conflict(Derived, Derived, true), O::Conflict);
        for (a, b) in [(Human, Human), (Human, Derived), (Derived, Human), (Derived, Derived)] {
            assert_eq!(resolve_authority_conflict(a, b, false), O::Coexist, "{a:?}/{b:?}");
        }
    }

    #[test]
    fn only_a_sensitive_event_rebases_the_partition_epoch() {
        let sensitive = [
            CognitionEvent::Withdraw,
            CognitionEvent::TightenPolicy,
            CognitionEvent::RevokeAuthorization,
            CognitionEvent::InvalidateSource,
        ];
        for event in EVENTS {
            let expected = if sensitive.contains(&event) {
                VersionImpact::RebaseEpoch
            } else {
                VersionImpact::BumpRevision
            };
            assert_eq!(version_impact(event), expected, "{event:?}");
        }
        assert_eq!(
            EVENTS
                .iter()
                .filter(|event| version_impact(**event) == VersionImpact::RebaseEpoch)
                .count(),
            4,
            "the sensitive set is exactly the four listed events"
        );
    }

    #[test]
    fn revisions_and_epochs_only_move_forward() {
        let mut revision = CognitionRevision::FIRST;
        assert_eq!(revision, CognitionRevision::new(1));
        for expected in [2, 3, 4] {
            let previous = revision;
            revision = revision.next();
            assert_eq!(revision, CognitionRevision::new(expected));
            assert!(revision > previous, "revision must strictly increase");
        }

        let mut epoch = CognitionEpoch::FIRST;
        for expected in [2, 3, 4] {
            let previous = epoch;
            epoch = epoch.next();
            assert_eq!(epoch, CognitionEpoch::new(expected));
            assert!(epoch > previous, "epoch must strictly increase");
        }

        // A ceiling keeps the last value instead of wrapping to a value a snapshot could
        // mistake for current.
        let ceiling = CognitionRevision::new(u64::MAX);
        assert_eq!(ceiling.next(), ceiling);
        let ceiling = CognitionEpoch::new(u64::MAX);
        assert_eq!(ceiling.next(), ceiling);
    }

    #[test]
    fn an_upstream_that_stops_standing_reaches_its_dependents() {
        use CognitionEvent as E;
        use DownstreamAction::{Invalidate, MarkForRecheck};

        for event in [E::InvalidateSource, E::RevokeAuthorization, E::TightenPolicy, E::Withdraw] {
            assert_eq!(forward_invalidation(event), Some(Invalidate), "{event:?}");
        }
        assert_eq!(forward_invalidation(E::Supersede), Some(MarkForRecheck));
        // A recheck is a real action, not the "nothing to do" answer.
        assert_ne!(
            forward_invalidation(E::Supersede),
            Some(DownstreamAction::None)
        );
        for event in [
            E::Validate,
            E::Merge,
            E::DetectConflict,
            E::ResolveConflict,
            E::ValidityElapsed,
            E::RetireUnknown,
            E::Rediscover,
        ] {
            assert_eq!(forward_invalidation(event), None, "{event:?}");
        }
    }

    #[test]
    fn a_live_downstream_record_is_rechecked_after_its_upstream_leaves() {
        for state in [
            CognitionState::Active,
            CognitionState::Conflict,
            CognitionState::Pending,
        ] {
            assert!(backward_requires_recheck(state), "{state:?}");
        }
        for state in [
            CognitionState::Superseded,
            CognitionState::Invalidated,
            CognitionState::Expired,
            CognitionState::Withdrawn,
            CognitionState::UnknownRetained,
        ] {
            assert!(!backward_requires_recheck(state), "{state:?}");
        }
    }

    #[test]
    fn an_uninterpretable_record_is_retained_either_way() {
        assert_eq!(interpret_unknown(false), CognitionState::UnknownRetained);
        assert_eq!(interpret_unknown(true), CognitionState::UnknownRetained);
        assert!(!interpret_unknown(false).is_terminal());
    }

    #[test]
    fn the_taxonomy_keeps_its_three_orthogonal_axes() {
        let kinds = [
            CognitionKind::Goal,
            CognitionKind::Knowledge,
            CognitionKind::Relation,
            CognitionKind::Commitment,
            CognitionKind::Action,
            CognitionKind::Gap,
        ];
        assert_eq!(kinds.len(), 6);
        for (index, kind) in kinds.iter().enumerate() {
            // Exhaustive per value: a renamed or dropped kind fails to compile here.
            let named = match kind {
                CognitionKind::Goal => "Goal",
                CognitionKind::Knowledge => "Knowledge",
                CognitionKind::Relation => "Relation",
                CognitionKind::Commitment => "Commitment",
                CognitionKind::Action => "Action",
                CognitionKind::Gap => "Gap",
            };
            assert!(!named.is_empty(), "{index}");
        }

        let categories = [CognitionCategory::Fact, CognitionCategory::Asserted];
        assert_eq!(categories.len(), 2);
        assert_ne!(categories[0], categories[1]);

        let authorities = [CognitionAuthority::Human, CognitionAuthority::Derived];
        assert_eq!(authorities.len(), 2);
        assert_ne!(authorities[0], authorities[1]);
    }

    #[test]
    fn a_dependency_carries_the_exact_upstream_revision() {
        let dependency = CognitionDependency {
            upstream: CognitionRecordId::new("record-7"),
            upstream_revision: CognitionRevision::new(3),
        };
        assert_eq!(dependency.upstream.as_str(), "record-7");
        assert_eq!(dependency.upstream_revision, CognitionRevision::new(3));
        assert_ne!(dependency.upstream_revision, CognitionRevision::new(4));
    }
}
