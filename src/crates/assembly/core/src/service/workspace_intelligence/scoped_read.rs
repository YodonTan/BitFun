//! Scoped workspace intelligence read contract (WP2.1).
//!
//! This module is the pure half of one decision: given a workspace and its
//! derived tier, may the prompt builder read workspace-scoped cognition content
//! for that workspace, and what does the rendered memory section look like.
//!
//! # What this module is
//!
//! It owns four facts and no behavior beyond them: whether a tier permits the
//! read, the narrow entry shape a read would return, the typed diagnostics of a
//! read that returned nothing, and the rendering of a non-empty entry list.
//!
//! It performs no IO, reads no clock, writes no log line, and touches no store.
//! The IO half lives in `scoped_read_io`, which resolves the persisted host anchor
//! and reads this host's cognition partition; both halves stay apart so the
//! decision can be tested without a filesystem.
//!
//! # What a permitted read returns today
//!
//! Nothing. The v1 cognition partition holds the partition state only (cursor and
//! incarnation token) and no content table has been written yet, so the IO half
//! reports [`ScopedReadDiagnostic::PartitionV1NoContent`] and no entries. An empty
//! read never falls back to the legacy global memory files: a permitted scoped
//! read that finds nothing injects nothing, because mixing another workspace's
//! content into this workspace's prompt is exactly what the scoped read exists to
//! prevent.
//!
//! The global `memories.use_memories` switch still gates the section: a permitted
//! tier is necessary but not sufficient, and this contract never overrides the
//! user's global switch.
//!
//! # Remote scenarios
//!
//! This contract is workspace-local. A remote workspace is out of scope here, and
//! the caller keeps the legacy path for it rather than reading a controller-side
//! directory: the remote decision is made by the existing remote-execution gate,
//! not by this module.

use super::cognition::{CognitionKind, CognitionRevision};
use super::entries_contract::kind_code;
use super::mode::{tier_permits_scoped_read, WorkspaceIntelligenceTier};

/// The scoped read decision of one workspace.
///
/// `workspace_id` is the caller's stable workspace identifier, never a path and
/// never a scope key: the scope is an opaque storage identity derived by the IO
/// half, and it must not travel in a prompt-facing structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedMemoryReadContext {
    /// Stable workspace identifier this read would be scoped to.
    pub(crate) workspace_id: String,
    /// Derived tier the decision was made from.
    pub(crate) tier: WorkspaceIntelligenceTier,
}

impl ScopedMemoryReadContext {
    /// True when this context permits reading scoped cognition content.
    ///
    /// `false` means the caller keeps the legacy path unchanged; it never means
    /// "read the global memory summary instead".
    pub(crate) fn permits_scoped_read(&self) -> bool {
        tier_permits_scoped_read(self.tier)
    }
}

/// One narrow cognition record a scoped read would carry into the prompt.
///
/// It keeps the three fields a prompt needs and nothing else: the record kind,
/// the rendered text and the revision the reader saw. A record identifier stays
/// out on purpose, because the prompt text is not a place to expose storage
/// identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedMemoryEntry {
    /// Which cognition axis this record belongs to.
    pub(crate) kind: CognitionKind,
    /// The record text as the owner stored it.
    pub(crate) text: String,
    /// Revision the reader observed.
    pub(crate) revision: CognitionRevision,
}

/// Why a permitted scoped read produced no entries.
///
/// A diagnostic is an outcome, not an error: the caller injects nothing and says
/// which fact it was missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ScopedReadDiagnostic {
    /// The workspace has no cognition partition record yet.
    PartitionAbsent,
    /// The partition exists but is at the v1 shape, which holds no content.
    PartitionV1NoContent,
    /// The partition exists and holds content, but no entry of it may be injected
    /// right now.
    NoEligibleEntries,
    /// This host could not turn the workspace id into a scope: no persisted
    /// anchor, an unusable host key, or a blank workspace id.
    ScopeUnavailable,
    /// The partition exists but could not be read this time.
    PartitionUnavailable,
}

impl ScopedReadDiagnostic {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PartitionAbsent => "partition_absent",
            Self::PartitionV1NoContent => "partition_v1_no_content",
            Self::NoEligibleEntries => "no_eligible_entries",
            Self::ScopeUnavailable => "scope_unavailable",
            Self::PartitionUnavailable => "partition_unavailable",
        }
    }
}

/// Renders the memory section for a non-empty entry list.
///
/// `None` for an empty list is the whole contract today: a scoped read with no
/// entries injects no section. The text names the workspace so a reader can tell
/// which scope the records belong to, and it states that the records are complete
/// for this workspace so a model does not assume content that is not there.
///
/// The revision travels in the entry but is deliberately not printed: the version
/// is storage metadata, and putting it in a prompt would invite a model to reason
/// about it.
pub(crate) fn render_scoped_memory_reminder(
    entries: &[ScopedMemoryEntry],
    workspace_id: &str,
) -> Option<String> {
    if entries.is_empty() {
        return None;
    }

    let mut rendered = String::from("## Memory\n\n");
    rendered.push_str(&format!(
        "Scoped workspace records for `{workspace_id}`. These records are the complete\
         scoped set for this workspace; do not assume records from other workspaces.\n\n"
    ));
    for entry in entries {
        rendered.push_str(&format!(
            "- [{}] {}\n",
            kind_code(entry.kind),
            entry.text.trim()
        ));
    }

    Some(rendered.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: CognitionKind, text: &str, revision: u64) -> ScopedMemoryEntry {
        ScopedMemoryEntry {
            kind,
            text: text.to_string(),
            revision: CognitionRevision::new(revision),
        }
    }

    #[test]
    fn only_a_switch_on_tier_permits_the_read() {
        let off = ScopedMemoryReadContext {
            workspace_id: "workspace-a".to_string(),
            tier: WorkspaceIntelligenceTier::Off,
        };
        let baseline = ScopedMemoryReadContext {
            workspace_id: "workspace-a".to_string(),
            tier: WorkspaceIntelligenceTier::Baseline,
        };
        let intelligent = ScopedMemoryReadContext {
            workspace_id: "workspace-a".to_string(),
            tier: WorkspaceIntelligenceTier::Intelligent,
        };

        assert!(!off.permits_scoped_read());
        assert!(baseline.permits_scoped_read());
        assert!(intelligent.permits_scoped_read());
    }

    #[test]
    fn an_empty_entry_list_renders_nothing() {
        assert_eq!(render_scoped_memory_reminder(&[], "workspace-a"), None);
    }

    #[test]
    fn a_non_empty_entry_list_names_the_workspace_and_every_entry() {
        let entries = vec![
            entry(CognitionKind::Goal, "ship the scoped read", 3),
            entry(CognitionKind::Knowledge, "the partition is v1", 1),
        ];

        let reminder =
            render_scoped_memory_reminder(&entries, "workspace-a").expect("a section renders");

        assert!(reminder.starts_with("## Memory"));
        assert!(reminder.contains("workspace-a"));
        assert!(reminder.contains("[goal] ship the scoped read"));
        assert!(reminder.contains("[knowledge] the partition is v1"));
        assert!(!reminder.contains("revision"));
        assert!(!reminder.ends_with('\n'));
    }

    #[test]
    fn every_cognition_kind_has_a_stable_code() {
        for (kind, code) in [
            (CognitionKind::Goal, "goal"),
            (CognitionKind::Knowledge, "knowledge"),
            (CognitionKind::Relation, "relation"),
            (CognitionKind::Commitment, "commitment"),
            (CognitionKind::Action, "action"),
            (CognitionKind::Gap, "gap"),
        ] {
            assert_eq!(kind_code(kind), code);
        }
    }

    #[test]
    fn diagnostic_codes_are_stable() {
        assert_eq!(
            ScopedReadDiagnostic::PartitionAbsent.as_str(),
            "partition_absent"
        );
        assert_eq!(
            ScopedReadDiagnostic::PartitionV1NoContent.as_str(),
            "partition_v1_no_content"
        );
        assert_eq!(
            ScopedReadDiagnostic::NoEligibleEntries.as_str(),
            "no_eligible_entries"
        );
        assert_eq!(
            ScopedReadDiagnostic::ScopeUnavailable.as_str(),
            "scope_unavailable"
        );
        assert_eq!(
            ScopedReadDiagnostic::PartitionUnavailable.as_str(),
            "partition_unavailable"
        );
    }
}
