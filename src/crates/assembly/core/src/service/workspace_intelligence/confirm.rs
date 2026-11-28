//! WP2.4b confirmation surface: the pure decision half of the one confirmed
//! initial enable.
//!
//! # What this module decides
//!
//! The host side of [`super::host::WorkspaceIntelligenceHost::confirm_initial_enable`]
//! takes one durable migration decision and turns it into the single OFF-to-ON
//! transition of a scope. Almost everything that transition must compare is a
//! pure question over facts somebody else already read:
//!
//! - is the recorded decision the same payload as the incoming one, a conflicting
//!   payload, or no decision at all ([`decide`]);
//! - did the legacy source move, or is it unreadable in a way the fingerprint
//!   cannot express ([`source_verdict`]);
//! - what does a fence refusal of the promotion mean for the caller
//!   ([`fence_outcome`]).
//!
//! Both live here, with no IO, no clock, no lock and no logging, so they can be
//! tested without a host and so the host's confirm path reads as the IO sequence
//! it is. The outcome and refusal types are the only vocabulary that crosses back
//! to the host; every variant carries a stable code and nothing else, so no path,
//! scope, model reference or stored payload can leak through a log line.
//!
//! # What this module deliberately does not own
//!
//! It performs no promotion, takes no lease, writes no control record and creates
//! no cognition partition. It also does not validate the decision's own shape
//! ([`super::migration::validate_migration`] owns that) and does not encode the
//! payload it compares; it only reads an already-decoded existing decision and an
//! already-built incoming one.

use openbitfun_services_core::workspace_intelligence_commit::GovernedClaimRefusal;

use super::legacy_preview::PreviewDiagnostic;
use super::migration::{reconcile_existing, MigrationDecision, MigrationOutcome};

/// What one confirmed initial enable produced.
///
/// No `Debug`-hostile content: a generation, one tier fact and one replay marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmOutcome {
    /// The switch is stored ON and the partition was initialized under the same
    /// lease. `intelligent` reports whether the record carried a model reference
    /// the enable preserved, not whether that reference resolves.
    Enabled { generation: u64, intelligent: bool },
    /// The switch is stored ON and the fence refused only because the incarnation
    /// it wanted to advance had already moved, so the partition is not initialized
    /// yet. Nothing is rolled back: the next evaluation pass claims the scope
    /// through the normal ON path and recovers the partition. This is the ONLY
    /// fence refusal that answers this outcome; a fence that reports the record
    /// itself changed is [`ConfirmRefusal::ControlChanged`], because the caller must
    /// re-read rather than wait for a pass.
    EnabledPartitionPending,
    /// The same decision was already confirmed and the switch already reads ON, so
    /// this call wrote nothing.
    AlreadyConfirmed,
}

/// Why one confirmation was refused.
///
/// Every variant carries either nothing or one already-stable code, so a caller can
/// log the reason without exposing a path, a scope, a payload or an error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfirmRefusal {
    /// The host is draining or stopped.
    Stopping,
    /// No live preparation exists for the scope: nothing was prepared, the
    /// preparation was already consumed by another confirmation, or it is no
    /// longer live.
    NotPrepared,
    /// The control record already reads enabled, so this scope needs no initial
    /// enable.
    AlreadyEnabled,
    /// One typed host admission refusal, carried as its stable code.
    Host(&'static str),
    /// The record changed between the preparation and this confirmation.
    ControlChanged,
    /// A decision with this idempotency key is already stored with a different
    /// payload, so storing the incoming one would silently replace it.
    DecisionConflict,
    /// The legacy source no longer matches the fingerprint the decision recorded.
    SourceChanged,
    /// The legacy source cannot be read in the shape this build expects, which the
    /// fingerprint cannot express.
    SourceUnreadable,
    /// The incoming decision itself is invalid, carried as the validation code.
    InvalidDecision(&'static str),
    /// One control-storage or promotion failure, carried as its stable code.
    Control(&'static str),
    /// An outcome this surface never requests. Refused rather than retried.
    Internal,
}

impl ConfirmRefusal {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Stopping => "stopping",
            Self::NotPrepared => "not_prepared",
            Self::AlreadyEnabled => "already_enabled",
            Self::Host(code) => code,
            Self::ControlChanged => "control_changed",
            Self::DecisionConflict => "decision_conflict",
            Self::SourceChanged => "source_changed",
            Self::SourceUnreadable => "source_unreadable",
            Self::InvalidDecision(code) => code,
            Self::Control(code) => code,
            Self::Internal => "internal",
        }
    }
}

/// What the control record says a confirmation should do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reconcile {
    /// Store the incoming decision and open the switch.
    Write,
    /// The same decision is already stored but the switch still reads OFF, so the
    /// enable itself is replayed.
    Replay,
    /// The same decision is stored and the switch already reads ON.
    AlreadyConfirmed,
}

/// Decides what a confirmation must do against the recorded decision.
///
/// `tier_is_off` is the derived `Off` fact of the record, which is exactly "the
/// switch does not read `Some(true)`". It only matters for an identical replay:
/// with the switch still OFF the enable has to be written again, and with it ON the
/// confirmation is already complete.
///
/// An existing payload that does not decode is reported as
/// [`ConfirmRefusal::DecisionConflict`] by the host before this function is called,
/// so a corrupt stored decision is never silently replaced here.
pub(crate) fn decide(
    existing: Option<&MigrationDecision>,
    incoming: &MigrationDecision,
    tier_is_off: bool,
) -> Result<Reconcile, ConfirmRefusal> {
    match reconcile_existing(existing, incoming) {
        MigrationOutcome::Apply => Ok(Reconcile::Write),
        MigrationOutcome::PayloadConflict => Err(ConfirmRefusal::DecisionConflict),
        MigrationOutcome::Unchanged if tier_is_off => Ok(Reconcile::Replay),
        MigrationOutcome::Unchanged => Ok(Reconcile::AlreadyConfirmed),
    }
}

/// Decides whether the legacy source is still the one the decision recorded.
///
/// Two separate checks, on purpose:
///
/// - staleness is the fingerprint comparison, which covers the row set, the
///   column shape this build expects, both file trees and the database's presence;
/// - `SchemaUnsupported` and `ReadFailure` are the diagnostics the fingerprint
///   cannot express, because a source this build cannot read projects the same
///   empty fingerprint as a usable empty one. `DbAbsent` is NOT such a diagnostic:
///   presence is part of the fingerprint, so an absent database is a fresh preview
///   that the staleness check already covers. `NotesDirAbsent` means no notes
///   exist, which is a legitimate empty source.
pub(crate) fn source_verdict(
    stale: bool,
    diagnostics: &[PreviewDiagnostic],
) -> Result<(), ConfirmRefusal> {
    if stale {
        return Err(ConfirmRefusal::SourceChanged);
    }
    let unreadable = diagnostics.iter().any(|diagnostic| match diagnostic {
        // The source cannot be read in the shape this build expects, so nothing the
        // decision recorded can be trusted: the fingerprint it produced is the same
        // empty one a usable empty source produces.
        PreviewDiagnostic::SchemaUnsupported | PreviewDiagnostic::ReadFailure => true,
        // Presence is part of the fingerprint, so an absent database is a legitimate
        // source the staleness check above already covers, and an absent notes
        // directory just means no notes exist.
        PreviewDiagnostic::DbAbsent | PreviewDiagnostic::NotesDirAbsent => false,
    });
    if unreadable {
        return Err(ConfirmRefusal::SourceUnreadable);
    }
    Ok(())
}

/// What one fence refusal of the promotion means for the confirmation.
///
/// The promotion stores the switch before the fence looks at it, so between those
/// two steps another writer can replace the record. Only one refusal is transient:
///
/// - [`GovernedClaimRefusal::StaleIncarnation`] means the incarnation moved, which is
///   exactly what a second owner advancing it looks like. The switch is still ON and
///   the ordinary pass recovers the partition, so this is
///   [`ConfirmOutcome::EnabledPartitionPending`];
/// - every other refusal means the record the fence observed is not the one the
///   confirmation just wrote — it was disabled, replaced or its binding moved. The
///   partition is not initialized and the confirmation can no longer claim the scope
///   is enabled, so the caller must re-read instead of waiting:
///   [`ConfirmRefusal::ControlChanged`].
pub(crate) fn fence_outcome(
    refusal: GovernedClaimRefusal,
) -> Result<ConfirmOutcome, ConfirmRefusal> {
    match refusal {
        GovernedClaimRefusal::StaleIncarnation => Ok(ConfirmOutcome::EnabledPartitionPending),
        GovernedClaimRefusal::ForeignSnapshot
        | GovernedClaimRefusal::ForeignBinding
        | GovernedClaimRefusal::NotObserved
        | GovernedClaimRefusal::NotEnabled
        | GovernedClaimRefusal::AuthorityChanged => Err(ConfirmRefusal::ControlChanged),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::workspace_intelligence::migration::MigrationSourceFingerprint;

    fn source(row_count: u64) -> MigrationSourceFingerprint {
        MigrationSourceFingerprint {
            row_count,
            rows_digest: "digest".to_owned(),
            schema_shape: "shape".to_owned(),
            derived_tree_hash: "derived".to_owned(),
            notes_tree_hash: "notes".to_owned(),
            db_present: true,
        }
    }

    fn decision(key: &str, row_count: u64) -> MigrationDecision {
        MigrationDecision {
            idempotency_key: key.to_owned(),
            decided_at_unix_ms: 1_700_000_000_000,
            source: source(row_count),
            assignments: Vec::new(),
        }
    }

    #[test]
    fn a_first_confirmation_writes_and_a_new_key_writes_again() {
        let incoming = decision("decision-1", 3);
        assert_eq!(decide(None, &incoming, true).unwrap(), Reconcile::Write);
        assert_eq!(decide(None, &incoming, false).unwrap(), Reconcile::Write);
        let other_key = decision("decision-2", 3);
        assert_eq!(
            decide(Some(&incoming), &other_key, false).unwrap(),
            Reconcile::Write
        );
    }

    #[test]
    fn an_identical_replay_replays_only_while_the_switch_is_off() {
        let stored = decision("decision-1", 3);
        let same = decision("decision-1", 3);
        assert_eq!(decide(Some(&stored), &same, true).unwrap(), Reconcile::Replay);
        assert_eq!(
            decide(Some(&stored), &same, false).unwrap(),
            Reconcile::AlreadyConfirmed
        );
    }

    #[test]
    fn the_same_key_with_a_different_payload_is_a_conflict() {
        let stored = decision("decision-1", 3);
        let moved = decision("decision-1", 4);
        for tier_is_off in [true, false] {
            let refusal = decide(Some(&stored), &moved, tier_is_off).unwrap_err();
            assert_eq!(refusal, ConfirmRefusal::DecisionConflict);
            assert_eq!(refusal.code(), "decision_conflict");
        }
    }

    #[test]
    fn staleness_and_unreadable_diagnostics_are_separate_verdicts() {
        assert_eq!(source_verdict(false, &[]), Ok(()));
        assert_eq!(source_verdict(false, &[PreviewDiagnostic::DbAbsent]), Ok(()));
        assert_eq!(source_verdict(false, &[PreviewDiagnostic::NotesDirAbsent]), Ok(()));
        assert_eq!(
            source_verdict(true, &[PreviewDiagnostic::DbAbsent]),
            Err(ConfirmRefusal::SourceChanged)
        );
        assert_eq!(
            source_verdict(false, &[PreviewDiagnostic::SchemaUnsupported]),
            Err(ConfirmRefusal::SourceUnreadable)
        );
        assert_eq!(
            source_verdict(
                false,
                &[PreviewDiagnostic::NotesDirAbsent, PreviewDiagnostic::ReadFailure]
            ),
            Err(ConfirmRefusal::SourceUnreadable)
        );
        // A stale source that is also unreadable reports the movement first: the
        // recorded fingerprint is the stronger, more actionable fact.
        assert_eq!(
            source_verdict(true, &[PreviewDiagnostic::ReadFailure]),
            Err(ConfirmRefusal::SourceChanged)
        );
    }

    #[test]
    fn refusal_codes_are_stable_and_never_carry_content() {
        assert_eq!(ConfirmRefusal::Stopping.code(), "stopping");
        assert_eq!(ConfirmRefusal::NotPrepared.code(), "not_prepared");
        assert_eq!(ConfirmRefusal::AlreadyEnabled.code(), "already_enabled");
        assert_eq!(ConfirmRefusal::Host("anchor_changed").code(), "anchor_changed");
        assert_eq!(ConfirmRefusal::ControlChanged.code(), "control_changed");
        assert_eq!(ConfirmRefusal::SourceChanged.code(), "source_changed");
        assert_eq!(ConfirmRefusal::SourceUnreadable.code(), "source_unreadable");
        assert_eq!(ConfirmRefusal::InvalidDecision("blank_key").code(), "blank_key");
        assert_eq!(
            ConfirmRefusal::Control("control_generation_conflict").code(),
            "control_generation_conflict"
        );
        assert_eq!(ConfirmRefusal::Internal.code(), "internal");
    }

    #[test]
    fn only_a_stale_incarnation_is_a_pending_partition() {
        // The incarnation moved under a switch that is still ON: the ordinary pass
        // owns the recovery, so the confirmation is complete but not yet initialized.
        assert_eq!(
            fence_outcome(GovernedClaimRefusal::StaleIncarnation),
            Ok(ConfirmOutcome::EnabledPartitionPending)
        );
        // Every other fence refusal means the record is no longer the one this
        // confirmation wrote. All six variants are named here, so a new one cannot be
        // folded into the pending outcome by accident.
        for refusal in [
            GovernedClaimRefusal::ForeignSnapshot,
            GovernedClaimRefusal::ForeignBinding,
            GovernedClaimRefusal::NotObserved,
            GovernedClaimRefusal::NotEnabled,
            GovernedClaimRefusal::AuthorityChanged,
        ] {
            assert_eq!(
                fence_outcome(refusal),
                Err(ConfirmRefusal::ControlChanged),
                "{refusal:?}"
            );
        }
    }

    #[test]
    fn outcome_and_refusal_carry_only_numbers_and_codes() {
        let enabled = ConfirmOutcome::Enabled { generation: 2, intelligent: true };
        assert_eq!(format!("{enabled:?}"), "Enabled { generation: 2, intelligent: true }");
        assert_eq!(
            format!("{:?}", ConfirmOutcome::EnabledPartitionPending),
            "EnabledPartitionPending"
        );
        assert_eq!(
            format!("{:?}", ConfirmRefusal::Control("storage")),
            "Control(\"storage\")"
        );
    }
}
