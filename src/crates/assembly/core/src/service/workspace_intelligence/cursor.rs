//! Pure cursor, duplicate and gap decisions for one workspace intelligence source.
//!
//! # P1 cursor slice: WP1.5 first slice
//!
//! This module is the first slice of WP1.5, and it decides one step only: given what a
//! source declares about its own replay capability, what it states about the marker this
//! partition recorded, and the marker it offers now, is that step already consumed, may
//! the caller resume from the recorded marker, or must it reconcile against a full
//! snapshot and surface a gap?
//!
//! The source owns progress and ordering. [`SourceMarker`] derives identity equality and
//! nothing else, so this module cannot order two markers even by accident: every
//! "served", "expired" or "ahead" fact is the source's own statement
//! ([`ResumeEvidence`]), never a comparison made here. Repeating that statement is not a
//! claim that anyone proved it.
//!
//! # What this slice deliberately does not deliver
//!
//! - no IO, filesystem, network, storage handle, clock or async: every function is a pure
//!   function of its arguments and returns the same decision for the same facts;
//! - no persistent write and no write API: the recorded marker is an input. A decision names
//!   the marker a caller records, and the calling persistence owner must apply the source step
//!   and record that marker in the *same* partition transaction as the cognition update the
//!   step produces. Nothing here advances a cursor, acks a step or stores a gap;
//! - no affinity enforcement and no multi-source progress: the cognition `partition_state`
//!   shape holds one opaque `cursor` for the whole partition, not one per source. A
//!   [`SourceId`] names the source of the current decision only and selects no stored row.
//!   The caller must present the marker recorded for that source, and independent progress
//!   for several sources needs a schema and owner change this slice does not make;
//! - no dedup window and no event ledger: with one cursor per partition a duplicate is only
//!   ever the recorded marker itself. Recognising an older marker that arrives again needs
//!   partition state this slice may not add, so a source that cannot present one in-order
//!   cursor must not declare [`ReplayCapability::Resumable`];
//! - no ordering proof, no `Ord`/`PartialOrd` on markers, no sorting and no counting of
//!   markers as progress;
//! - no global replay and no event sourcing: one call answers one step of one source;
//! - no fallback: missing, incoherent or contradictory facts refuse with a stable code
//!   instead of resuming, and every snapshot reconcile carries its gap;
//! - no schema, column, version constant or store change: `COGNITION_SCHEMA_VERSION`
//!   stays 1, and this module never names the store;
//! - no public API: `pub(crate)` only, feature-free, no feature gate, no runtime caller,
//!   no command, registry row, capability or user-visible behavior.
//!
//! # Caller obligations
//!
//! This module decides; it never applies, acks or persists. A caller that consumes a decision
//! must apply the source step and record `Incremental { marker }` in the same partition
//! transaction as the cognition update that step produces, must pass the marker that was
//! recorded for the source it is asking about, and must record the [`Gap`] a snapshot
//! reconcile carries instead of presenting it as an incremental replay.
//!
//! # First sight
//!
//! With no recorded marker there is no position a source can safely resume from. This slice
//! does not assume a source can replay from the beginning of its history and does not invent
//! such a position, so a first sight step answers with a snapshot reconcile that carries
//! [`GapReason::NoCursorRecorded`] — never a replay, an advance or an ack — and any evidence a
//! source offers about a marker the partition never recorded is
//! [`CursorRefusal::ContradictoryFacts`].
//!
//! # Decision precedence
//!
//! The arms below are read in one order, so the same facts always answer the same decision: a
//! capability that contradicts its own evidence is refused first, then a repeated marker is
//! answered as a duplicate (identity needs no ordering fact), then a step with nothing
//! recorded is a first sight, and only then is the source's statement about the recorded
//! marker read. A snapshot-only source is decided before the recorded marker is inspected, so
//! its capability failure is the reason it reports even when no cursor was ever recorded.
//!
//! # Contract status
//!
//! This is a provisional internal contract. [`ReplayCapability`], [`ResumeEvidence`] and the
//! stable codes exist so the first real source adapter can be written against something typed;
//! they may widen once that adapter names its actual sources. Nothing here is a published API,
//! and no compatibility with a later shape is promised.

/// Longest accepted [`SourceId`], in characters.
const MAX_SOURCE_ID_CHARS: usize = 64;

/// Longest accepted [`SourceMarker`], in characters.
///
/// A source must present a token, not a payload: the bound keeps one marker usable as one
/// diagnostic field and as a single boundary token inside a decision. It is a contract of this
/// module, not a limit of the stored `cursor`, which is unbounded `TEXT`.
const MAX_MARKER_CHARS: usize = 256;

/// Opaque identifier of the source a decision is currently about.
///
/// The value is an identity, not a path and not an order: it is matched with equality only,
/// and it is kept verbatim. It names the source of *this* decision; it is not an affinity key
/// and it selects no stored row. The cognition partition holds one `cursor`, so a caller with
/// several sources per partition must keep their independent progress in a shape this module
/// and the current schema do not provide, and must present the marker recorded for `source`.
/// Recognising that a marker came from a different source is a persistence-owner obligation
/// this pure module cannot enforce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceId(String);

impl SourceId {
    /// Parses a source identifier, keeping its bytes unchanged.
    ///
    /// An empty value is refused because absence has no meaning for a source; it is never
    /// read as "all sources" or "no source".
    pub(crate) fn parse(raw: &str) -> Result<Self, CursorRefusal> {
        validate(raw, MAX_SOURCE_ID_CHARS)?;
        Ok(Self(raw.to_owned()))
    }

    /// The identifier exactly as the caller supplied it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque marker a source attached to one step it can serve.
///
/// The marker is the source's own value. It is kept byte for byte — no trimming, no case
/// folding, no re-encoding — and compared with identity equality only. This type
/// deliberately implements no `Ord`/`PartialOrd`: ordering two markers lexically is exactly
/// the claim this module must not make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceMarker(String);

impl SourceMarker {
    /// Parses a marker, keeping its bytes unchanged.
    pub(crate) fn parse(raw: &str) -> Result<Self, CursorRefusal> {
        validate(raw, MAX_MARKER_CHARS)?;
        Ok(Self(raw.to_owned()))
    }

    /// The marker exactly as the source supplied it.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a value or a step was refused.
///
/// Every variant carries a stable code, and no variant is a fallback: a refusal means this
/// module could not decide the step safely, so the caller must not consume anything and
/// must surface the code. There is deliberately no `Display` and no `Error` impl: the
/// human-facing text of a surface belongs to that surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorRefusal {
    /// The value was empty. Absence is expressed by `None`, never by `""`.
    EmptyValue,
    /// The value exceeded the documented bound of its type.
    ValueTooLong,
    /// The value contained a control character, so it could not be used as one
    /// diagnostic field.
    ControlCharacter,
    /// The source gave no statement about the recorded marker, so ordering it would be a
    /// guess.
    OrderingUnproven,
    /// The source's capability and its own evidence cannot both be true.
    ContradictoryFacts,
}

impl CursorRefusal {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::EmptyValue => "empty_value",
            Self::ValueTooLong => "value_too_long",
            Self::ControlCharacter => "control_character",
            Self::OrderingUnproven => "ordering_unproven",
            Self::ContradictoryFacts => "contradictory_facts",
        }
    }
}

/// What a source declares it can replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplayCapability {
    /// The source can serve the step that follows one marker it still holds.
    Resumable,
    /// The source has no resumable position and offers a snapshot instead. A source that
    /// declares this can never be answered as incremental.
    SnapshotOnly,
}

/// The source's own statement about the marker this partition recorded.
///
/// Each variant is a fact the source reports about itself. None of them is derived here,
/// and none of them is a licence to reorder a marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeEvidence {
    /// The source still holds the recorded marker and can serve from it.
    RecordedMarkerServed,
    /// The source no longer holds the recorded marker, so nothing between it and the
    /// source's window can be served.
    RecordedMarkerExpired,
    /// The source states the recorded marker is ahead of the newest marker it holds.
    RecordedMarkerAhead,
    /// The source made no statement about the recorded marker.
    NotProvided,
}

/// What one source offers for the next step, as the source declared it.
///
/// The three facts stay flat instead of being nested per capability, so an adapter declares one
/// value and [`decide_step`] refuses a fact the capability cannot have with
/// [`CursorRefusal::ContradictoryFacts`]. That refusal is deliberate: encoding the same
/// contradiction in the type would move it into the adapter, where it could not produce a coded
/// refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OfferedStep<'a> {
    /// What the source declares it can replay.
    pub(crate) capability: ReplayCapability,
    /// The marker of the step offered now, or `None` when the source offers a snapshot
    /// with no version of its own.
    pub(crate) marker: Option<&'a SourceMarker>,
    /// The source's own statement about the recorded marker.
    pub(crate) evidence: ResumeEvidence,
}

/// Why a decision reconciles by snapshot instead of resuming.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GapReason {
    /// Nothing was ever recorded on this partition.
    NoCursorRecorded,
    /// The source declares it cannot replay from a cursor at all.
    ///
    /// The capability is decided before the recorded marker is inspected, so a snapshot-only
    /// source reports this reason even when no cursor was ever recorded: the capability
    /// failure is the durable cause, and [`GapReason::NoCursorRecorded`] would only describe
    /// the absence.
    SourceCannotReplay,
    /// The source no longer holds the recorded marker.
    RecordedMarkerExpired,
    /// The source reports the recorded marker is ahead of what it can serve.
    RecordedMarkerAhead,
}

impl GapReason {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::NoCursorRecorded => "no_cursor_recorded",
            Self::SourceCannotReplay => "source_cannot_replay",
            Self::RecordedMarkerExpired => "recorded_marker_expired",
            Self::RecordedMarkerAhead => "recorded_marker_ahead",
        }
    }
}

/// The visible gap a snapshot reconcile leaves behind.
///
/// A gap is carried, never dropped: a caller that reconciles without recording the reason
/// it reconciled is the silent regression this slice exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Gap<'a> {
    /// Why the step could not be resumed.
    pub(crate) reason: GapReason,
    /// The recorded marker the gap was measured from, when the partition had one.
    pub(crate) recorded: Option<&'a SourceMarker>,
}

/// What the caller may do with the step the source offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepDecision<'a> {
    /// The offered marker is the recorded marker: the step was already consumed and must
    /// not be applied again. Nothing advances.
    Duplicate {
        /// The source this decision was made for.
        source: &'a SourceId,
        /// The repeated marker.
        marker: &'a SourceMarker,
    },
    /// The source served the recorded marker, so the caller may apply what follows it and must
    /// record the offered marker in the same partition transaction as the cognition update the
    /// step produces. Recording it is the caller's act; this decision acks nothing.
    Incremental {
        /// The source this decision was made for.
        source: &'a SourceId,
        /// The recorded marker the caller resumes from.
        from: &'a SourceMarker,
        /// The marker of the step being applied.
        marker: &'a SourceMarker,
    },
    /// No resumable position exists, so the caller must reconcile against a full snapshot
    /// and carry the gap. This is never presented as an incremental replay.
    SnapshotReconcile {
        /// The source this decision was made for.
        source: &'a SourceId,
        /// The gap the reconcile leaves visible.
        gap: Gap<'a>,
    },
}

impl StepDecision<'_> {
    /// The source this decision was made for.
    pub(crate) fn source(&self) -> &SourceId {
        match self {
            Self::Duplicate { source, .. }
            | Self::Incremental { source, .. }
            | Self::SnapshotReconcile { source, .. } => source,
        }
    }

    /// Stable machine-readable code of the outcome.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Duplicate { .. } => "duplicate",
            Self::Incremental { .. } => "incremental",
            Self::SnapshotReconcile { .. } => "snapshot_reconcile",
        }
    }
}

/// Decides one step for one source against the marker the partition recorded.
///
/// `recorded` is the single marker the partition state holds — one cursor per partition, not
/// one per source — and it is the only progress fact this slice reads. The caller owns the
/// affinity obligation: it must pass the marker that was recorded for `source`, in the
/// partition transaction that applied the matching cognition update. Nothing here can tell
/// that `recorded` belongs to `source`, and nothing here selects between several sources.
///
/// `offered` is the source's own declaration; nothing here verifies it, sorts it or measures
/// two markers against each other.
///
/// With nothing recorded there is no safe resumable position, so the answer is a snapshot
/// reconcile carrying [`GapReason::NoCursorRecorded`] rather than a replay, an advance or an
/// ack; evidence about a marker that was never recorded is
/// [`CursorRefusal::ContradictoryFacts`].
///
/// A repeated marker is answered as a [`StepDecision::Duplicate`] before the evidence is read,
/// because identity needs no ordering fact and consuming nothing is always the safe answer. A
/// snapshot-only source is answered by identity or by a snapshot reconcile with its gap, so it
/// can never be answered as incremental. A resumable source that leaves ordering unproven, and
/// any pair of facts that cannot both be true, refuse instead of resuming.
pub(crate) fn decide_step<'a>(
    source: &'a SourceId,
    recorded: Option<&'a SourceMarker>,
    offered: OfferedStep<'a>,
) -> Result<StepDecision<'a>, CursorRefusal> {
    match offered.capability {
        ReplayCapability::SnapshotOnly => {
            // A source that cannot replay has nothing to say about resuming a marker.
            if offered.evidence != ResumeEvidence::NotProvided {
                return Err(CursorRefusal::ContradictoryFacts);
            }
            let Some(marker) = offered.marker else {
                return Ok(snapshot(source, GapReason::SourceCannotReplay, recorded));
            };
            if recorded == Some(marker) {
                return Ok(StepDecision::Duplicate { source, marker });
            }
            Ok(snapshot(source, GapReason::SourceCannotReplay, recorded))
        }
        ReplayCapability::Resumable => {
            let Some(marker) = offered.marker else {
                // A resumable source that offers no step is neither a resumable step nor a
                // snapshot; answering either way would be the silent fallback this slice
                // refuses.
                return Err(CursorRefusal::ContradictoryFacts);
            };
            let Some(from) = recorded else {
                // Nothing is recorded, so the source can hold no statement about it.
                if offered.evidence != ResumeEvidence::NotProvided {
                    return Err(CursorRefusal::ContradictoryFacts);
                }
                return Ok(snapshot(source, GapReason::NoCursorRecorded, None));
            };
            if from == marker {
                return Ok(StepDecision::Duplicate { source, marker });
            }
            match offered.evidence {
                ResumeEvidence::RecordedMarkerServed => Ok(StepDecision::Incremental {
                    source,
                    from,
                    marker,
                }),
                ResumeEvidence::RecordedMarkerExpired => {
                    Ok(snapshot(source, GapReason::RecordedMarkerExpired, Some(from)))
                }
                ResumeEvidence::RecordedMarkerAhead => {
                    Ok(snapshot(source, GapReason::RecordedMarkerAhead, Some(from)))
                }
                ResumeEvidence::NotProvided => Err(CursorRefusal::OrderingUnproven),
            }
        }
    }
}

/// One snapshot reconcile carrying its reason.
fn snapshot<'a>(
    source: &'a SourceId,
    reason: GapReason,
    recorded: Option<&'a SourceMarker>,
) -> StepDecision<'a> {
    StepDecision::SnapshotReconcile {
        source,
        gap: Gap { reason, recorded },
    }
}

/// Rejects an empty, over-long or control-bearing value, keeping accepted bytes verbatim.
///
/// The precedence is fixed — empty, then length, then control characters — so a refused
/// value always reports the same code.
fn validate(raw: &str, limit: usize) -> Result<(), CursorRefusal> {
    if raw.is_empty() {
        return Err(CursorRefusal::EmptyValue);
    }
    if raw.chars().count() > limit {
        return Err(CursorRefusal::ValueTooLong);
    }
    if raw.chars().any(char::is_control) {
        return Err(CursorRefusal::ControlCharacter);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(raw: &str) -> SourceId {
        SourceId::parse(raw).expect("the test source identifier is valid")
    }

    fn marker(raw: &str) -> SourceMarker {
        SourceMarker::parse(raw).expect("the test marker is valid")
    }

    fn resumable(marker: &SourceMarker, evidence: ResumeEvidence) -> OfferedStep<'_> {
        OfferedStep {
            capability: ReplayCapability::Resumable,
            marker: Some(marker),
            evidence,
        }
    }

    fn snapshot_only(marker: Option<&SourceMarker>) -> OfferedStep<'_> {
        OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker,
            evidence: ResumeEvidence::NotProvided,
        }
    }

    #[test]
    fn a_first_sight_step_reconciles_by_snapshot_and_carries_the_missing_cursor_gap() {
        let owner = source("workspace-catalog");
        let head = marker("m-1");

        let decision = decide_step(&owner, None, resumable(&head, ResumeEvidence::NotProvided))
            .expect("a first sight step is decided, not refused");

        assert_eq!(decision.code(), "snapshot_reconcile");
        assert_eq!(decision.source().as_str(), "workspace-catalog");
        match decision {
            StepDecision::SnapshotReconcile { gap, .. } => {
                assert_eq!(gap.reason, GapReason::NoCursorRecorded);
                assert_eq!(gap.reason.as_str(), "no_cursor_recorded");
                assert_eq!(gap.recorded, None);
            }
            other => panic!("a first sight step must not resume, got {other:?}"),
        }
    }

    #[test]
    fn a_repeated_marker_is_a_duplicate_and_advances_nothing() {
        let owner = source("workspace-catalog");
        let recorded = marker("m-1");
        let same = marker("m-1");

        // Identity is read before the evidence, so even a stale statement from the source
        // cannot turn a repeated marker into a resume.
        for evidence in [
            ResumeEvidence::RecordedMarkerServed,
            ResumeEvidence::RecordedMarkerExpired,
            ResumeEvidence::RecordedMarkerAhead,
            ResumeEvidence::NotProvided,
        ] {
            let decision = decide_step(&owner, Some(&recorded), resumable(&same, evidence))
                .expect("a repeated marker is decided");
            assert_eq!(decision.code(), "duplicate");
            assert_eq!(
                decision,
                StepDecision::Duplicate {
                    source: &owner,
                    marker: &same,
                }
            );
        }
    }

    #[test]
    fn a_snapshot_only_source_never_resumes_and_always_carries_its_gap() {
        let owner = source("workspace-catalog");
        let recorded = marker("m-1");
        let newer = marker("m-2");

        for step in [snapshot_only(None), snapshot_only(Some(&newer))] {
            let decision =
                decide_step(&owner, Some(&recorded), step).expect("a snapshot step is decided");
            assert_eq!(decision.code(), "snapshot_reconcile");
            match decision {
                StepDecision::SnapshotReconcile { gap, .. } => {
                    assert_eq!(gap.reason, GapReason::SourceCannotReplay);
                    assert_eq!(gap.reason.as_str(), "source_cannot_replay");
                    assert_eq!(gap.recorded, Some(&recorded));
                }
                other => panic!("a snapshot-only source must not resume, got {other:?}"),
            }
        }

        // A source without any version still reconciles and still reports its gap. With no
        // recorded cursor the reason stays the capability failure rather than the missing
        // cursor: this pins the documented precedence.
        let first = decide_step(&owner, None, snapshot_only(None)).expect("a snapshot is decided");
        match first {
            StepDecision::SnapshotReconcile { gap, .. } => {
                assert_eq!(gap.reason, GapReason::SourceCannotReplay);
                assert_eq!(gap.reason.as_str(), "source_cannot_replay");
                assert_eq!(gap.recorded, None);
            }
            other => panic!("a snapshot-only source must not resume, got {other:?}"),
        }
    }

    #[test]
    fn an_unchanged_snapshot_version_is_a_duplicate_not_a_reconcile() {
        let owner = source("workspace-catalog");
        let recorded = marker("resource-v7");
        let same = marker("resource-v7");

        let decision = decide_step(&owner, Some(&recorded), snapshot_only(Some(&same)))
            .expect("an unchanged snapshot version is decided");

        assert_eq!(decision.code(), "duplicate");
    }

    #[test]
    fn a_served_recorded_marker_resumes_and_names_both_markers_verbatim() {
        let owner = source("session-log");
        let recorded = marker("m-41");
        let offered = marker("m-42");

        let decision = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::RecordedMarkerServed),
        )
        .expect("a served marker resumes");

        assert_eq!(decision, StepDecision::Incremental {
            source: &owner,
            from: &recorded,
            marker: &offered,
        });
        assert_eq!(decision.code(), "incremental");
    }

    #[test]
    fn missing_ordering_evidence_fails_closed_instead_of_resuming() {
        let owner = source("session-log");
        let recorded = marker("m-41");
        let offered = marker("m-42");

        let refusal = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::NotProvided),
        )
        .expect_err("unevidenced ordering must be refused");

        assert_eq!(refusal, CursorRefusal::OrderingUnproven);
        assert_eq!(refusal.as_str(), "ordering_unproven");
    }

    #[test]
    fn a_recorded_marker_the_source_reports_as_ahead_is_a_gap_and_not_a_rewind() {
        let owner = source("session-log");
        let recorded = marker("m-99");
        let offered = marker("m-7");

        let decision = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::RecordedMarkerAhead),
        )
        .expect("a reported rewind is a decided gap");

        assert_eq!(decision.code(), "snapshot_reconcile");
        match decision {
            StepDecision::SnapshotReconcile { gap, .. } => {
                assert_eq!(gap.reason, GapReason::RecordedMarkerAhead);
                assert_eq!(gap.reason.as_str(), "recorded_marker_ahead");
                assert_eq!(gap.recorded, Some(&recorded));
            }
            other => panic!("a reported rewind must not consume anything, got {other:?}"),
        }
    }

    #[test]
    fn a_recorded_marker_the_source_no_longer_holds_is_a_gap() {
        let owner = source("session-log");
        let recorded = marker("m-41");
        let offered = marker("m-90");

        let decision = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::RecordedMarkerExpired),
        )
        .expect("an expired marker is a decided gap");

        match decision {
            StepDecision::SnapshotReconcile { gap, .. } => {
                assert_eq!(gap.reason, GapReason::RecordedMarkerExpired);
                assert_eq!(gap.reason.as_str(), "recorded_marker_expired");
                assert_eq!(gap.recorded, Some(&recorded));
            }
            other => panic!("an expired marker must not resume, got {other:?}"),
        }
    }

    #[test]
    fn contradictory_capability_facts_are_refused_instead_of_answered() {
        let owner = source("session-log");
        let recorded = marker("m-41");
        let offered = marker("m-42");

        // A source that cannot replay has nothing to say about resuming a marker.
        let step = OfferedStep {
            capability: ReplayCapability::SnapshotOnly,
            marker: Some(&offered),
            evidence: ResumeEvidence::RecordedMarkerServed,
        };
        assert_eq!(
            decide_step(&owner, Some(&recorded), step),
            Err(CursorRefusal::ContradictoryFacts)
        );

        // A resumable source that offers no step is neither resumable nor a snapshot.
        let step = OfferedStep {
            capability: ReplayCapability::Resumable,
            marker: None,
            evidence: ResumeEvidence::RecordedMarkerServed,
        };
        assert_eq!(
            decide_step(&owner, Some(&recorded), step),
            Err(CursorRefusal::ContradictoryFacts)
        );

        // A source cannot hold a statement about a marker this partition never recorded.
        let step = resumable(&offered, ResumeEvidence::RecordedMarkerAhead);
        assert_eq!(
            decide_step(&owner, None, step),
            Err(CursorRefusal::ContradictoryFacts)
        );
    }

    #[test]
    fn markers_are_kept_verbatim_and_never_normalized() {
        let spaced = marker("m-1 ");
        let plain = marker("m-1");
        assert_ne!(spaced, plain, "no marker is trimmed");
        assert_eq!(spaced.as_str(), "m-1 ");
        assert_eq!(marker("m-1").as_str(), "m-1");

        let mixed_case = marker("M-1");
        assert_ne!(mixed_case, plain, "no marker is case folded");
        assert_eq!(mixed_case.as_str(), "M-1");

        let owner = source("session-log");
        assert_eq!(source(" Session-Log ").as_str(), " Session-Log ");
        let decision = decide_step(
            &owner,
            Some(&plain),
            resumable(&spaced, ResumeEvidence::RecordedMarkerServed),
        )
        .expect("two distinct markers resume");
        assert_eq!(decision.code(), "incremental");
    }

    #[test]
    fn empty_over_long_and_control_bearing_values_are_refused_with_their_codes() {
        assert_eq!(SourceId::parse(""), Err(CursorRefusal::EmptyValue));
        assert_eq!(SourceMarker::parse(""), Err(CursorRefusal::EmptyValue));

        let long_id = "i".repeat(MAX_SOURCE_ID_CHARS + 1);
        let long_marker = "m".repeat(MAX_MARKER_CHARS + 1);
        assert_eq!(SourceId::parse(&long_id), Err(CursorRefusal::ValueTooLong));
        assert_eq!(
            SourceMarker::parse(&long_marker),
            Err(CursorRefusal::ValueTooLong)
        );

        assert_eq!(SourceId::parse("a\nb"), Err(CursorRefusal::ControlCharacter));
        assert_eq!(
            SourceMarker::parse("m\u{0}1"),
            Err(CursorRefusal::ControlCharacter)
        );

        // The bounds are inclusive, so a value exactly at them is accepted.
        assert!(SourceId::parse(&"i".repeat(MAX_SOURCE_ID_CHARS)).is_ok());
        assert!(SourceMarker::parse(&"m".repeat(MAX_MARKER_CHARS)).is_ok());
    }

    #[test]
    fn the_same_facts_always_produce_the_same_decision() {
        let owner = source("session-log");
        let recorded = marker("m-41");
        let offered = marker("m-42");

        let first = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::RecordedMarkerServed),
        );
        let second = decide_step(
            &owner,
            Some(&recorded),
            resumable(&offered, ResumeEvidence::RecordedMarkerServed),
        );

        assert_eq!(first, second);
        assert_eq!(first.expect("the step is decided").code(), "incremental");
    }

    #[test]
    fn the_source_id_labels_decisions_but_does_not_enforce_cursor_affinity() {
        let recorded = marker("m-1");
        let head = marker("m-2");
        let left = source("session-log");
        let right = source("workspace-catalog");

        let left_decision = decide_step(
            &left,
            Some(&recorded),
            resumable(&head, ResumeEvidence::RecordedMarkerServed),
        )
        .expect("the left source is decided");
        let right_decision = decide_step(
            &right,
            Some(&recorded),
            resumable(&head, ResumeEvidence::RecordedMarkerServed),
        )
        .expect("the right source is decided");

        // This intentionally supplies the same recorded marker for two different sources. It
        // documents the caller mistake this pure module cannot detect; callers must satisfy
        // the source-affinity obligation above.
        assert_eq!(
            left_decision,
            StepDecision::Incremental {
                source: &left,
                from: &recorded,
                marker: &head,
            }
        );
        assert_eq!(
            right_decision,
            StepDecision::Incremental {
                source: &right,
                from: &recorded,
                marker: &head,
            }
        );
    }

    #[test]
    fn the_value_bound_counts_characters_and_not_bytes() {
        // U+00E9 encodes as two bytes, so a byte-counted bound would refuse this value.
        let at_bound = "\u{e9}".repeat(MAX_MARKER_CHARS);
        assert_eq!(at_bound.chars().count(), MAX_MARKER_CHARS);
        assert_eq!(at_bound.len(), MAX_MARKER_CHARS * 2, "the fixture is multi-byte");
        assert!(SourceMarker::parse(&at_bound).is_ok());

        let over = "\u{e9}".repeat(MAX_MARKER_CHARS + 1);
        assert_eq!(SourceMarker::parse(&over), Err(CursorRefusal::ValueTooLong));
    }

    #[test]
    fn every_refusal_carries_its_stable_code() {
        assert_eq!(CursorRefusal::EmptyValue.as_str(), "empty_value");
        assert_eq!(CursorRefusal::ValueTooLong.as_str(), "value_too_long");
        assert_eq!(CursorRefusal::ControlCharacter.as_str(), "control_character");
        assert_eq!(CursorRefusal::OrderingUnproven.as_str(), "ordering_unproven");
        assert_eq!(
            CursorRefusal::ContradictoryFacts.as_str(),
            "contradictory_facts"
        );
    }
}
