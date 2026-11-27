//! Pure contract of one human cognition entry (WP2.4).
//!
//! This module decides three things and performs no IO: whether a human-supplied
//! entry is acceptable, how a stored entry projects back into the injection shape,
//! and which stable codes name a kind, a state, a visibility and a skip reason.
//!
//! # What it does not do
//!
//! No store call, no filesystem, no clock, no log line and no feature gate. The
//! caller supplies `now_unix_ms`, so validity is decided against a value the test
//! controls instead of the wall clock. The IO half lives in `entries`, which owns
//! validation-free storage and the merged commit transaction.
//!
//! # Stable codes
//!
//! The six kind codes and the eight state codes are a storage contract: the store
//! writes these exact strings and a later reader compares against them, so the
//! mapping functions here are the single source of truth for both directions. A
//! code this module does not know is never guessed: an unknown kind, state or
//! authority keeps the row out of the injected section and reports why.
//!
//! # Injection bounds
//!
//! A section is bounded by [`MAX_INJECTED_ENTRIES`] and
//! [`MAX_INJECTED_TOTAL_CHARS`]. This is the first forgetting layer of one
//! prompt, not a storage policy: an over-limit row stays stored and keeps its
//! revision, it is only left out of this section and reported as
//! [`InjectionSkip::EntryLimitExceeded`]. The two numbers are initial values, and
//! the slice that first measures a real model's context should tune them from
//! that measurement rather than from intuition.

use sha2::{Digest, Sha256};

use super::cognition::{injection_eligible, CognitionKind, CognitionRevision, CognitionState};
use super::scoped_read::ScopedMemoryEntry;

/// Longest accepted statement, counted in characters, not bytes.
pub(crate) const MAX_STATEMENT_CHARS: usize = 2000;

/// Most entries one injected section may carry.
pub(crate) const MAX_INJECTED_ENTRIES: usize = 32;

/// Most characters one injected section may carry in total.
pub(crate) const MAX_INJECTED_TOTAL_CHARS: usize = 12_000;

/// Stored visibility of a record that belongs to its own partition only.
pub(crate) const PARTITION_VISIBILITY: &str = "partition";

/// Stored authority code of a human-entered record.
pub(crate) const AUTHORITY_HUMAN: &str = "human";

/// Stored authority code of a record derived from a source.
pub(crate) const AUTHORITY_DERIVED: &str = "derived";

/// One entry a human asked to create, before validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NewHumanEntry {
    /// Which cognition axis the entry belongs to.
    pub(crate) kind: CognitionKind,
    /// The statement as the human wrote it.
    pub(crate) statement: String,
    /// Optional source resource the statement refers to.
    pub(crate) source_resource: Option<String>,
}

/// One accepted entry, ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedHumanEntry {
    /// Which cognition axis the entry belongs to.
    pub(crate) kind: CognitionKind,
    /// The statement, untrimmed: the stored text is what the human wrote.
    pub(crate) statement: String,
    /// Optional source resource the statement refers to.
    pub(crate) source_resource: Option<String>,
    /// Lowercase-hex SHA-256 of [`Self::statement`], matching the digest the store
    /// derives from the same bytes.
    pub(crate) content_digest: String,
}

/// Why a human-supplied entry is not acceptable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EntryValidationError {
    /// The statement is empty.
    EmptyStatement,
    /// The statement holds only whitespace.
    WhitespaceOnlyStatement,
    /// The statement is longer than [`MAX_STATEMENT_CHARS`] characters.
    StatementTooLong,
}

impl EntryValidationError {
    /// Stable machine-readable code.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::EmptyStatement => "empty_statement",
            Self::WhitespaceOnlyStatement => "whitespace_only_statement",
            Self::StatementTooLong => "statement_too_long",
        }
    }
}

/// Accepts or refuses one human entry.
///
/// The stored statement is never trimmed: a human's own leading and trailing
/// whitespace is part of what they said, and the same bytes feed the content
/// digest the store keeps. Only the emptiness check trims, because a statement of
/// invisible characters carries nothing a reader could act on.
pub(crate) fn validate_human_entry(
    input: &NewHumanEntry,
) -> Result<ValidatedHumanEntry, EntryValidationError> {
    if input.statement.trim().is_empty() {
        return Err(if input.statement.is_empty() {
            EntryValidationError::EmptyStatement
        } else {
            EntryValidationError::WhitespaceOnlyStatement
        });
    }
    if input.statement.chars().count() > MAX_STATEMENT_CHARS {
        return Err(EntryValidationError::StatementTooLong);
    }

    Ok(ValidatedHumanEntry {
        kind: input.kind,
        statement: input.statement.clone(),
        source_resource: input.source_resource.clone(),
        content_digest: content_digest(&input.statement),
    })
}

/// Lowercase-hex SHA-256 of the statement bytes.
fn content_digest(statement: &str) -> String {
    format!("{:x}", Sha256::digest(statement.as_bytes()))
}

/// One stored row projected into the fields the injection decision needs.
///
/// The projection deliberately drops every storage identity: an entry id, a
/// partition key and a record epoch never reach the prompt decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoredEntryProjection {
    /// Stored kind code.
    pub(crate) kind: String,
    /// Stored lifecycle state code.
    pub(crate) state: String,
    /// Stored visibility code.
    pub(crate) visibility: String,
    /// Stored authority code.
    pub(crate) authority: String,
    /// Stored statement text.
    pub(crate) statement: String,
    /// Stored record revision.
    pub(crate) revision: i64,
    /// Stored validity bound in Unix milliseconds.
    pub(crate) valid_until_unix_ms: Option<i64>,
}

/// Why one stored row stayed out of the injected section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InjectionSkip {
    /// The row is not in an injectable lifecycle state.
    Inactive,
    /// The row is not visible inside its own partition.
    NotPartitionVisible,
    /// The row's validity window closed.
    Expired,
    /// A commitment carries no validity bound, so it is never injected.
    CommitmentWithoutValidity,
    /// The stored state code is not one this build knows.
    UnknownState,
    /// The stored kind code is not one this build knows.
    UnknownKind,
    /// The stored authority code is neither human nor derived.
    UnknownAuthority,
    /// The row would exceed this section's entry or character bound.
    EntryLimitExceeded,
}

impl InjectionSkip {
    /// Stable machine-readable code.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Inactive => "inactive",
            Self::NotPartitionVisible => "not_partition_visible",
            Self::Expired => "expired",
            Self::CommitmentWithoutValidity => "commitment_without_validity",
            Self::UnknownState => "unknown_state",
            Self::UnknownKind => "unknown_kind",
            Self::UnknownAuthority => "unknown_authority",
            Self::EntryLimitExceeded => "entry_limit_exceeded",
        }
    }
}

/// Decides which stored rows may enter the scoped memory section.
///
/// A row is injected only when every one of these holds: the kind and the state
/// are known, the authority is human or derived, the visibility is this
/// partition's, the lifecycle state is injectable, the validity bound (when there
/// is one) has not elapsed, and a commitment additionally carries a validity
/// bound. Anything else is skipped with the typed reason, never guessed and never
/// silently dropped.
///
/// The output is then bounded: rows enter in the stored order until
/// [`MAX_INJECTED_ENTRIES`] rows or [`MAX_INJECTED_TOTAL_CHARS`] characters are
/// reached, and every row left out by the bound is reported as
/// [`InjectionSkip::EntryLimitExceeded`]. The bound is applied after the content
/// filter, so an over-limit section never hides a content reason, and it never
/// touches storage: the row stays stored with its revision.
///
/// The output order follows the stored order, and an empty result is a valid
/// answer: it means this partition has content and none of it may be injected
/// today.
pub(crate) fn project_for_injection(
    entries: &[StoredEntryProjection],
    now_unix_ms: i64,
) -> (Vec<ScopedMemoryEntry>, Vec<InjectionSkip>) {
    let mut eligible = Vec::new();
    let mut skipped = Vec::new();

    for entry in entries {
        let Some(kind) = kind_from_code(&entry.kind) else {
            skipped.push(InjectionSkip::UnknownKind);
            continue;
        };
        let Some(state) = state_from_code(&entry.state) else {
            skipped.push(InjectionSkip::UnknownState);
            continue;
        };
        if !matches!(
            entry.authority.as_str(),
            AUTHORITY_HUMAN | AUTHORITY_DERIVED
        ) {
            skipped.push(InjectionSkip::UnknownAuthority);
            continue;
        }
        if entry.visibility != PARTITION_VISIBILITY {
            skipped.push(InjectionSkip::NotPartitionVisible);
            continue;
        }

        let validity_elapsed = entry
            .valid_until_unix_ms
            .is_some_and(|bound| bound <= now_unix_ms);
        if validity_elapsed {
            skipped.push(InjectionSkip::Expired);
            continue;
        }
        if !injection_eligible(state, validity_elapsed) {
            skipped.push(InjectionSkip::Inactive);
            continue;
        }
        if kind == CognitionKind::Commitment && entry.valid_until_unix_ms.is_none() {
            skipped.push(InjectionSkip::CommitmentWithoutValidity);
            continue;
        }

        eligible.push(ScopedMemoryEntry {
            kind,
            text: entry.statement.clone(),
            // A negative stored revision is unreadable storage, not a reason to
            // drop an otherwise eligible row; it reports as the zero revision.
            revision: CognitionRevision::new(u64::try_from(entry.revision).unwrap_or(0)),
        });
    }

    let mut injected = Vec::with_capacity(eligible.len().min(MAX_INJECTED_ENTRIES));
    let mut injected_chars = 0usize;
    for entry in eligible {
        let entry_chars = entry.text.chars().count();
        if injected.len() >= MAX_INJECTED_ENTRIES
            || injected_chars + entry_chars > MAX_INJECTED_TOTAL_CHARS
        {
            skipped.push(InjectionSkip::EntryLimitExceeded);
            continue;
        }
        injected_chars += entry_chars;
        injected.push(entry);
    }

    (injected, skipped)
}

/// Stable code of one cognition kind.
pub(crate) fn kind_code(kind: CognitionKind) -> &'static str {
    match kind {
        CognitionKind::Goal => "goal",
        CognitionKind::Knowledge => "knowledge",
        CognitionKind::Relation => "relation",
        CognitionKind::Commitment => "commitment",
        CognitionKind::Action => "action",
        CognitionKind::Gap => "gap",
    }
}

/// Parses one stored kind code, or reports that this build does not know it.
pub(crate) fn kind_from_code(code: &str) -> Option<CognitionKind> {
    match code {
        "goal" => Some(CognitionKind::Goal),
        "knowledge" => Some(CognitionKind::Knowledge),
        "relation" => Some(CognitionKind::Relation),
        "commitment" => Some(CognitionKind::Commitment),
        "action" => Some(CognitionKind::Action),
        "gap" => Some(CognitionKind::Gap),
        _ => None,
    }
}

/// Stable code of one cognition state.
pub(crate) fn state_code(state: CognitionState) -> &'static str {
    match state {
        CognitionState::Pending => "pending",
        CognitionState::Active => "active",
        CognitionState::Conflict => "conflict",
        CognitionState::Superseded => "superseded",
        CognitionState::Invalidated => "invalidated",
        CognitionState::Expired => "expired",
        CognitionState::Withdrawn => "withdrawn",
        CognitionState::UnknownRetained => "unknown_retained",
    }
}

/// Parses one stored state code, or reports that this build does not know it.
pub(crate) fn state_from_code(code: &str) -> Option<CognitionState> {
    match code {
        "pending" => Some(CognitionState::Pending),
        "active" => Some(CognitionState::Active),
        "conflict" => Some(CognitionState::Conflict),
        "superseded" => Some(CognitionState::Superseded),
        "invalidated" => Some(CognitionState::Invalidated),
        "expired" => Some(CognitionState::Expired),
        "withdrawn" => Some(CognitionState::Withdrawn),
        "unknown_retained" => Some(CognitionState::UnknownRetained),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn human(kind: CognitionKind, statement: &str) -> NewHumanEntry {
        NewHumanEntry {
            kind,
            statement: statement.to_string(),
            source_resource: None,
        }
    }

    fn stored(
        kind: &str,
        state: &str,
        authority: &str,
        visibility: &str,
        valid_until_unix_ms: Option<i64>,
    ) -> StoredEntryProjection {
        StoredEntryProjection {
            kind: kind.to_string(),
            state: state.to_string(),
            visibility: visibility.to_string(),
            authority: authority.to_string(),
            statement: "a statement".to_string(),
            revision: 3,
            valid_until_unix_ms,
        }
    }

    #[test]
    fn an_empty_or_whitespace_only_statement_is_refused() {
        assert_eq!(
            validate_human_entry(&human(CognitionKind::Goal, "")).unwrap_err(),
            EntryValidationError::EmptyStatement
        );
        for blank in [" ", "\t", "\n\n", "  \t \r\n "] {
            assert_eq!(
                validate_human_entry(&human(CognitionKind::Goal, blank)).unwrap_err(),
                EntryValidationError::WhitespaceOnlyStatement,
                "{blank:?}"
            );
        }
    }

    #[test]
    fn a_statement_over_the_limit_is_refused_at_the_limit_it_is_accepted() {
        let longest = "a".repeat(MAX_STATEMENT_CHARS);
        assert!(validate_human_entry(&human(CognitionKind::Knowledge, &longest)).is_ok());

        let too_long = "a".repeat(MAX_STATEMENT_CHARS + 1);
        assert_eq!(
            validate_human_entry(&human(CognitionKind::Knowledge, &too_long)).unwrap_err(),
            EntryValidationError::StatementTooLong
        );

        // Characters, not bytes: a multi-byte statement under the limit is fine.
        let multibyte = "知".repeat(MAX_STATEMENT_CHARS);
        assert!(validate_human_entry(&human(CognitionKind::Knowledge, &multibyte)).is_ok());
    }

    #[test]
    fn an_accepted_entry_keeps_the_statement_verbatim_and_digests_it() {
        let validated = validate_human_entry(&NewHumanEntry {
            kind: CognitionKind::Goal,
            statement: "  keep my spaces  ".to_string(),
            source_resource: Some("session:1".to_string()),
        })
        .expect("the statement is acceptable");

        assert_eq!(validated.kind, CognitionKind::Goal);
        assert_eq!(validated.statement, "  keep my spaces  ");
        assert_eq!(validated.source_resource.as_deref(), Some("session:1"));
        assert_eq!(
            validated.content_digest,
            format!(
                "{:x}",
                Sha256::digest("  keep my spaces  ".as_bytes())
            ),
            "the digest covers the stored bytes, not a trimmed copy"
        );
    }

    #[test]
    fn validation_codes_and_skip_codes_are_stable() {
        for (error, code) in [
            (EntryValidationError::EmptyStatement, "empty_statement"),
            (
                EntryValidationError::WhitespaceOnlyStatement,
                "whitespace_only_statement",
            ),
            (EntryValidationError::StatementTooLong, "statement_too_long"),
        ] {
            assert_eq!(error.as_str(), code);
        }
        for (skip, code) in [
            (InjectionSkip::Inactive, "inactive"),
            (
                InjectionSkip::NotPartitionVisible,
                "not_partition_visible",
            ),
            (InjectionSkip::Expired, "expired"),
            (
                InjectionSkip::CommitmentWithoutValidity,
                "commitment_without_validity",
            ),
            (InjectionSkip::UnknownState, "unknown_state"),
            (InjectionSkip::UnknownKind, "unknown_kind"),
            (InjectionSkip::UnknownAuthority, "unknown_authority"),
            (
                InjectionSkip::EntryLimitExceeded,
                "entry_limit_exceeded",
            ),
        ] {
            assert_eq!(skip.as_str(), code);
        }
    }

    #[test]
    fn every_kind_and_state_code_round_trips() {
        for kind in [
            CognitionKind::Goal,
            CognitionKind::Knowledge,
            CognitionKind::Relation,
            CognitionKind::Commitment,
            CognitionKind::Action,
            CognitionKind::Gap,
        ] {
            assert_eq!(kind_from_code(kind_code(kind)), Some(kind), "{kind:?}");
        }
        for state in [
            CognitionState::Pending,
            CognitionState::Active,
            CognitionState::Conflict,
            CognitionState::Superseded,
            CognitionState::Invalidated,
            CognitionState::Expired,
            CognitionState::Withdrawn,
            CognitionState::UnknownRetained,
        ] {
            assert_eq!(state_from_code(state_code(state)), Some(state), "{state:?}");
        }
        assert_eq!(kind_from_code("GOAL"), None, "codes are case sensitive");
        assert_eq!(kind_from_code(""), None);
        assert_eq!(state_from_code("Active"), None);
        assert_eq!(state_from_code("unknown"), None);
    }

    #[test]
    fn an_active_partition_entry_is_injectable() {
        let entries = vec![stored("goal", "active", "human", "partition", None)];

        let (eligible, skipped) = project_for_injection(&entries, 1_000);

        assert!(skipped.is_empty());
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].kind, CognitionKind::Goal);
        assert_eq!(eligible[0].text, "a statement");
        assert_eq!(eligible[0].revision, CognitionRevision::new(3));
    }

    #[test]
    fn a_derived_entry_is_injectable_too() {
        let entries = vec![stored("knowledge", "active", "derived", "partition", None)];

        let (eligible, skipped) = project_for_injection(&entries, 1_000);

        assert!(skipped.is_empty());
        assert_eq!(eligible.len(), 1);
    }

    #[test]
    fn only_an_active_state_reaches_the_section() {
        for state in [
            "pending",
            "conflict",
            "superseded",
            "invalidated",
            "expired",
            "withdrawn",
            "unknown_retained",
        ] {
            let entries = vec![stored("goal", state, "human", "partition", None)];
            let (eligible, skipped) = project_for_injection(&entries, 1_000);
            assert!(eligible.is_empty(), "{state}");
            assert_eq!(skipped, vec![InjectionSkip::Inactive], "{state}");
        }
    }

    #[test]
    fn an_elapsed_validity_bound_or_another_visibility_is_skipped() {
        let entries = vec![
            stored("goal", "active", "human", "partition", Some(999)),
            stored("goal", "active", "human", "shared", None),
        ];

        let (eligible, skipped) = project_for_injection(&entries, 1_000);

        assert!(eligible.is_empty());
        assert_eq!(
            skipped,
            vec![InjectionSkip::Expired, InjectionSkip::NotPartitionVisible]
        );

        // A bound exactly at the observation instant has elapsed.
        let bound_now = vec![stored("goal", "active", "human", "partition", Some(1_000))];
        assert_eq!(
            project_for_injection(&bound_now, 1_000).1,
            vec![InjectionSkip::Expired]
        );

        // A future bound stays injectable.
        let future = vec![stored("goal", "active", "human", "partition", Some(1_001))];
        assert_eq!(project_for_injection(&future, 1_000).0.len(), 1);
    }

    #[test]
    fn a_commitment_without_a_validity_bound_is_never_injected() {
        let unbound = vec![stored("commitment", "active", "human", "partition", None)];
        let (eligible, skipped) = project_for_injection(&unbound, 1_000);
        assert!(eligible.is_empty());
        assert_eq!(skipped, vec![InjectionSkip::CommitmentWithoutValidity]);

        let bound = vec![stored(
            "commitment",
            "active",
            "human",
            "partition",
            Some(5_000),
        )];
        let (eligible, skipped) = project_for_injection(&bound, 1_000);
        assert_eq!(skipped, Vec::new());
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].kind, CognitionKind::Commitment);
    }

    #[test]
    fn an_unknown_kind_state_or_authority_is_skipped_with_its_reason() {
        let entries = vec![
            stored("forecast", "active", "human", "partition", None),
            stored("goal", "resolved", "human", "partition", None),
            stored("goal", "active", "robot", "partition", None),
        ];

        let (eligible, skipped) = project_for_injection(&entries, 1_000);

        assert!(eligible.is_empty());
        assert_eq!(
            skipped,
            vec![
                InjectionSkip::UnknownKind,
                InjectionSkip::UnknownState,
                InjectionSkip::UnknownAuthority,
            ]
        );
    }

    #[test]
    fn a_negative_stored_revision_reports_the_zero_revision() {
        let mut entry = stored("goal", "active", "human", "partition", None);
        entry.revision = -4;

        let (eligible, _skipped) = project_for_injection(&[entry], 1_000);

        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].revision, CognitionRevision::new(0));
    }

    #[test]
    fn an_empty_input_projects_nothing_and_skips_nothing() {
        assert_eq!(project_for_injection(&[], 1_000), (Vec::new(), Vec::new()));
    }

    #[test]
    fn the_entry_count_limit_truncates_the_tail_and_reports_it() {
        let entries = (0..=MAX_INJECTED_ENTRIES)
            .map(|index| {
                let mut entry = stored("goal", "active", "human", "partition", None);
                entry.statement = format!("entry {index}");
                entry
            })
            .collect::<Vec<_>>();

        let (injected, skipped) = project_for_injection(&entries, 1_000);

        assert_eq!(injected.len(), MAX_INJECTED_ENTRIES);
        assert_eq!(injected[0].text, "entry 0", "the stored order is kept");
        assert_eq!(
            injected[MAX_INJECTED_ENTRIES - 1].text,
            format!("entry {}", MAX_INJECTED_ENTRIES - 1),
            "the first rows win and the tail is dropped"
        );
        assert_eq!(skipped, vec![InjectionSkip::EntryLimitExceeded]);
    }

    #[test]
    fn the_total_character_limit_truncates_the_tail_and_reports_it() {
        // Three rows of 5,000 characters: two fit inside 12,000, the third does not.
        let statement = "x".repeat(5_000);
        let entries = (0..3)
            .map(|_| {
                let mut entry = stored("goal", "active", "human", "partition", None);
                entry.statement = statement.clone();
                entry
            })
            .collect::<Vec<_>>();

        let (injected, skipped) = project_for_injection(&entries, 1_000);

        assert_eq!(injected.len(), 2, "two whole rows fit the character bound");
        assert_eq!(
            injected
                .iter()
                .map(|entry| entry.text.chars().count())
                .sum::<usize>(),
            10_000
        );
        assert!(
            injected
                .iter()
                .all(|entry| entry.text.chars().count() == 5_000),
            "no row is truncated in the middle"
        );
        assert_eq!(skipped, vec![InjectionSkip::EntryLimitExceeded]);
        assert!(
            MAX_INJECTED_TOTAL_CHARS >= 10_000 && MAX_INJECTED_TOTAL_CHARS < 15_000,
            "the fixture assumes the current character bound: {MAX_INJECTED_TOTAL_CHARS}"
        );
    }
}
