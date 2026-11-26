//! Pure decision layer between one Session snapshot observation and one governed cursor advance.
//!
//! [`super::cursor`] owns the decision contract and [`super::session_source`] owns the
//! observation; this module is the only place that joins them. It reads no file, opens no
//! database, reads no clock and emits no log line: the host performs both reads and the guarded
//! advance, then hands the two facts in.
//!
//! A full reconciliation in this phase only moves the recorded cursor onto the observed marker.
//! No cognition content exists yet, so there is nothing to reconcile against it: the marker is
//! the single durable statement one pass produces.
//!
//! A recorded value that is not this envelope counts as nothing recorded, so the first pass takes
//! the single `cursor` column over by whole replacement. The compare-and-set underneath still
//! compares raw text, so a concurrent writer is never silently overwritten.
//!
//! The gap reason decides nothing here. Every snapshot reconcile means "the marker this source
//! offers is not the recorded one"; the reason travels out for diagnostics and is consumed
//! nowhere else.
//!
//! [`ConsumerAction::Advance`] carries the gap reason rather than the whole gap value. The gap
//! value borrows the recorded marker the decision was made against, and that marker is parsed
//! inside [`decide`] from the caller's raw text, so it cannot outlive the call. Keeping the
//! reason and dropping the borrow leaves a shape the host can read while it holds no parsed
//! marker of its own.

use super::cursor::{
    decide_step, CursorRefusal, GapReason, OfferedStep, SourceId, SourceMarker, StepDecision,
};
use super::cursor_record::RecordedCursor;

/// The source identifier this consumer records for the Session snapshot source.
///
/// It is the same stable code [`super::session_source::SessionSnapshotObservation::code`]
/// declares; the host integration test pins the two together through the recorded envelope.
pub(crate) const SESSION_SNAPSHOT_SOURCE: &str = "session_snapshot";

/// What one pass may do about one scope's cursor.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConsumerAction<'a> {
    /// The offered marker is the recorded one, the observation was incomplete, or the source
    /// offered no step: nothing is written, and that is the correct answer each time.
    Nothing,
    /// The source cannot resume, so the caller reconciles the whole snapshot by advancing the
    /// recorded cursor onto this marker and carrying the gap.
    Advance {
        /// The marker to record.
        to: &'a SourceMarker,
        /// Why the step reconciles instead of resuming. Diagnostics only.
        gap: GapReason,
    },
    /// The source refused to state one step.
    SourceRefused(CursorRefusal),
    /// The recorded envelope names another source, so this source must not touch it.
    SourceMismatch,
}

/// Decides what one pass may do with the step a source offers.
///
/// `recorded` is the cursor the caller decoded for `source`, and `offered` is the step this pass
/// observed. The `Err` case is a marker the caller's envelope carried that
/// [`SourceMarker::parse`] refuses: unreachable after a successful decode of the same envelope,
/// and kept so this layer never panics on a value it did not produce.
pub(crate) fn decide<'a>(
    source: &'a SourceId,
    recorded: RecordedCursor<'a>,
    offered: Option<OfferedStep<'a>>,
) -> Result<ConsumerAction<'a>, CursorRefusal> {
    let Some(offered) = offered else {
        // An incomplete observation offers no marker, and there is nothing to reconcile.
        return Ok(ConsumerAction::Nothing);
    };
    let to = offered.marker;
    match recorded {
        RecordedCursor::Parsed {
            source: recorded_source,
            marker,
        } => {
            if recorded_source != source.as_str() {
                // The envelope is well formed but belongs to another source; the caller's
                // affinity check already refused it, and this layer must not overwrite it.
                return Ok(ConsumerAction::SourceMismatch);
            }
            let parsed = SourceMarker::parse(marker)?;
            decide_against(source, Some(&parsed), offered, to)
        }
        // A foreign value is not this source's progress, so it is treated as nothing recorded
        // and the first pass replaces it wholesale.
        RecordedCursor::Foreign(_) | RecordedCursor::None => {
            decide_against(source, None, offered, to)
        }
    }
}

/// Maps one [`decide_step`] answer onto the action the host performs.
fn decide_against<'a>(
    source: &'a SourceId,
    recorded: Option<&SourceMarker>,
    offered: OfferedStep<'a>,
    to: Option<&'a SourceMarker>,
) -> Result<ConsumerAction<'a>, CursorRefusal> {
    match decide_step(source, recorded, offered) {
        Err(refusal) => Ok(ConsumerAction::SourceRefused(refusal)),
        Ok(StepDecision::Duplicate { .. }) => Ok(ConsumerAction::Nothing),
        Ok(StepDecision::SnapshotReconcile { gap, .. }) => match to {
            Some(marker) => Ok(ConsumerAction::Advance {
                to: marker,
                gap: gap.reason,
            }),
            // A snapshot that carries no marker is not a position this consumer may record.
            None => Ok(ConsumerAction::Nothing),
        },
        // The source declared it cannot replay, so an incremental answer is a contradiction
        // this layer refuses rather than forwards.
        Ok(StepDecision::Incremental { .. }) => Err(CursorRefusal::ContradictoryFacts),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::workspace_intelligence::cursor::{ReplayCapability, ResumeEvidence};

    const SOURCE: &str = SESSION_SNAPSHOT_SOURCE;

    fn source() -> SourceId {
        SourceId::parse(SOURCE).unwrap()
    }

    fn marker(raw: &str) -> SourceMarker {
        SourceMarker::parse(raw).unwrap()
    }

    fn snapshot_step(marker: &SourceMarker) -> OfferedStep<'_> {
        OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker: Some(marker),
            evidence: ResumeEvidence::NotProvided,
        }
    }

    fn parsed<'a>(marker: &'a SourceMarker) -> RecordedCursor<'a> {
        RecordedCursor::Parsed {
            source: SOURCE,
            marker: marker.as_str(),
        }
    }

    #[test]
    fn a_repeated_marker_consumes_nothing() {
        let source = source();
        let marker = marker("s1-usable-1-0-aa");
        let action = decide(&source, parsed(&marker), Some(snapshot_step(&marker))).unwrap();
        assert_eq!(action, ConsumerAction::Nothing);
    }

    #[test]
    fn a_first_sight_reconciles_by_snapshot_without_a_cursor() {
        let source = source();
        let marker = marker("s1-usable-1-0-aa");
        let action = decide(&source, RecordedCursor::None, Some(snapshot_step(&marker))).unwrap();
        assert_eq!(
            action,
            ConsumerAction::Advance {
                to: &marker,
                gap: GapReason::SourceCannotReplay,
            }
        );
    }

    #[test]
    fn a_moved_snapshot_reconciles_onto_the_offered_marker() {
        let source = source();
        let recorded = marker("s1-usable-1-0-aa");
        let offered = marker("s1-usable-2-0-bb");
        let action = decide(&source, parsed(&recorded), Some(snapshot_step(&offered))).unwrap();
        assert_eq!(
            action,
            ConsumerAction::Advance {
                to: &offered,
                gap: GapReason::SourceCannotReplay,
            }
        );
    }

    #[test]
    fn a_foreign_recorded_value_is_replaced_instead_of_matched() {
        let source = source();
        let offered = marker("s1-usable-1-0-aa");
        let action = decide(
            &source,
            RecordedCursor::Foreign("hello"),
            Some(snapshot_step(&offered)),
        )
        .unwrap();
        assert_eq!(
            action,
            ConsumerAction::Advance {
                to: &offered,
                gap: GapReason::SourceCannotReplay,
            }
        );
    }

    #[test]
    fn a_recorded_envelope_of_another_source_is_a_mismatch() {
        let source = source();
        let offered = marker("s1-usable-1-0-aa");
        let other = marker("s1-usable-1-0-aa");
        let action = decide(
            &source,
            RecordedCursor::Parsed {
                source: "other_source",
                marker: other.as_str(),
            },
            Some(snapshot_step(&offered)),
        )
        .unwrap();
        assert_eq!(action, ConsumerAction::SourceMismatch);
    }

    #[test]
    fn an_incomplete_observation_does_nothing() {
        let source = source();
        let action = decide(&source, RecordedCursor::Foreign("hello"), None).unwrap();
        assert_eq!(action, ConsumerAction::Nothing);
    }

    #[test]
    fn a_snapshot_without_its_own_marker_records_no_position() {
        let source = source();
        let offered = OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker: None,
            evidence: ResumeEvidence::NotProvided,
        };
        let action = decide(&source, RecordedCursor::None, Some(offered)).unwrap();
        assert_eq!(action, ConsumerAction::Nothing);
    }

    #[test]
    fn a_capability_that_cannot_be_true_refuses_instead_of_resuming() {
        let source = source();
        let offered = marker("s1-usable-1-0-aa");
        let contradiction = OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker: Some(&offered),
            evidence: ResumeEvidence::RecordedMarkerServed,
        };
        let action = decide(&source, RecordedCursor::None, Some(contradiction)).unwrap();
        assert_eq!(
            action,
            ConsumerAction::SourceRefused(CursorRefusal::ContradictoryFacts)
        );
    }

    #[test]
    fn the_decision_layer_stays_pure_and_crate_internal() {
        let source = include_str!("cursor_consumer.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "std::fs",
            "std::net",
            "tokio::",
            "tracing::",
            "log::",
            "SystemTime",
            "Instant",
            "serde",
            "rusqlite",
        ] {
            assert!(
                !production.contains(forbidden),
                "the decision layer must not reach {forbidden}"
            );
        }
        for line in production.lines() {
            let trimmed = line.trim_start();
            assert!(
                !trimmed.starts_with("pub "),
                "every item stays crate-internal: {trimmed}"
            );
        }
    }
}
