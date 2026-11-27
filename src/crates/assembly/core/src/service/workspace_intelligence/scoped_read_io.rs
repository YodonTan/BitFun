//! IO half of the scoped workspace intelligence read (WP2.1).
//!
//! This module answers two questions about one workspace, and it is the only
//! place in the scoped-read path that touches storage:
//!
//! - does this workspace switch workspace intelligence on, so a caller may read
//!   scoped content at all;
//! - what does this host's cognition partition of that workspace hold right now.
//!
//! # Authority and read-only behavior
//!
//! The host identity comes from the persisted storage anchor through
//! [`read_persisted_host_id`], which never creates, repairs or deletes the anchor. The tier comes from the control record through
//! the same `observe` entry the host facade uses, so this module cannot disagree
//! with the host about what "on" means. The partition is read through the core
//! cognition handle, which is read-only: it creates no root, no record and no
//! schema, and it never resets or deletes anything.
//!
//! A missing anchor, a blank workspace id or an unreadable control record is
//! reported as [`ScopedReadDiagnostic::ScopeUnavailable`] and the caller injects
//! nothing. There is deliberately no default scope, no path-derived scope and no
//! fallback to another workspace's partition.
//!
//! Host tenure is not consulted in this slice: whether this process currently holds
//! the scope's owner lease is not part of the decision, so the read is gated on the
//! derived tier plus the partition content only. The P3 first-enable work must add
//! the tenure gate before a read is treated as proof that this host owns the scope.
//!
//! The global `memories.use_memories` switch still gates the scoped section on the
//! prompt side: a permitted tier is necessary but not sufficient, so an enabled tier
//! never overrides the user's global switch.
//!
//! # Blocking boundary
//!
//! The content read is a blocking SQLite read, so it runs on Tokio's blocking pool
//! and never on a runtime worker. `resolve_scoped_memory_context` still performs its
//! single-row partition observation inside the async context; that is unchanged here
//! and the slice that converges the scoped read (WP2.4) owns moving it onto the same
//! boundary.
//!
//! # What a read returns
//!
//! The content of this workspace's own v2 partition, filtered to what may be
//! injected right now. A v1 partition holds no content table and reports
//! [`ScopedReadDiagnostic::PartitionV1NoContent`]; a v2 partition whose rows are all
//! inactive, expired, shared, self-contradicting or a commitment without a validity
//! bound reports [`ScopedReadDiagnostic::NoEligibleEntries`] and injects nothing.
//! The filter itself is the pure decision of `entries_contract`; this module only
//! projects the stored rows into it and forwards the clock.
//!
//! # Delivery profile
//!
//! Capability delivery is passed as [`CapabilityDelivery::Delivered`] and the
//! model reference is never resolved, because this module consumes the tier only:
//! the derived tier is a function of the control-record switch and the configured
//! reference, and neither depends on the resolution outcome. Not resolving also
//! keeps a prompt build from reaching a model provider.

use log::debug;
use openbitfun_services_core::workspace_intelligence_cognition::{
    StoredCognitionEntry, WorkspaceIntelligenceCognitionError,
};

use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::control::WorkspaceIntelligenceControl;
use crate::service::workspace_intelligence::entries_contract::{
    project_for_injection, StoredEntryProjection,
};
use crate::service::workspace_intelligence::host::read_persisted_host_id;
use crate::service::workspace_intelligence::host_binding::LOCAL_EXECUTION_DOMAIN;
use crate::service::workspace_intelligence::mode::{
    tier_permits_scoped_read, CapabilityDelivery, WorkspaceModelResolution,
};
use crate::service::workspace_intelligence::partition::{
    CognitionError, WorkspaceIntelligenceCognition,
};
use crate::service::workspace_intelligence::scope::{
    HostExecutionDomainKey, WorkspaceControlScope,
};
use crate::service::workspace_intelligence::scoped_read::{
    ScopedMemoryEntry, ScopedMemoryReadContext, ScopedReadDiagnostic,
};

/// Resolves the scoped read decision of one workspace.
///
/// Returns `Some` only when this host's control record for the workspace derives a
/// tier that permits a read. Every other outcome (no anchor, unusable workspace id,
/// unreadable record, `Off`) returns `None`, which means "keep the legacy path",
/// never "read something else".
pub(crate) async fn resolve_scoped_memory_context(
    paths: &PathManager,
    workspace_id: &str,
) -> Option<ScopedMemoryReadContext> {
    let Some(host) = scoped_read_host(paths, workspace_id).await else {
        return None;
    };
    let Some(scope) = WorkspaceControlScope::new(&host, workspace_id) else {
        debug!(
            "Workspace intelligence scoped read skipped: workspace_id={} reason=scope_unavailable",
            workspace_id
        );
        return None;
    };

    let control = WorkspaceIntelligenceControl::for_host(paths, host);
    let observation = match control
        .observe(&scope, CapabilityDelivery::Delivered, |_| {
            WorkspaceModelResolution::Unresolvable
        })
        .await
    {
        Ok(observation) => observation,
        Err(_) => {
            debug!(
                "Workspace intelligence scoped read skipped: workspace_id={} reason=control_unavailable",
                workspace_id
            );
            return None;
        }
    };

    if !tier_permits_scoped_read(observation.mode.tier) {
        return None;
    }

    Some(ScopedMemoryReadContext {
        workspace_id: workspace_id.to_owned(),
        tier: observation.mode.tier,
    })
}

/// Reads the scoped cognition content of one workspace against the current clock.
///
/// The first value is `Some(entries)` only when the partition carried content that
/// may be injected right now. The diagnostics say which fact was missing, and an
/// empty read is never replaced by the legacy global memory files.
pub(crate) async fn read_scoped_memory(
    paths: &PathManager,
    workspace_id: &str,
) -> (Option<Vec<ScopedMemoryEntry>>, Vec<ScopedReadDiagnostic>) {
    read_scoped_memory_at(paths, workspace_id, now_unix_ms()).await
}

/// Reads the scoped cognition content of one workspace at a caller-supplied instant.
///
/// A validity bound is compared against `now_unix_ms`, so a test decides expiry
/// instead of the wall clock. Everything else is identical to
/// [`read_scoped_memory`].
pub(crate) async fn read_scoped_memory_at(
    paths: &PathManager,
    workspace_id: &str,
    now_unix_ms: i64,
) -> (Option<Vec<ScopedMemoryEntry>>, Vec<ScopedReadDiagnostic>) {
    let Some(host) = scoped_read_host(paths, workspace_id).await else {
        return (None, vec![ScopedReadDiagnostic::ScopeUnavailable]);
    };
    let Some(scope) = WorkspaceControlScope::new(&host, workspace_id) else {
        return (None, vec![ScopedReadDiagnostic::ScopeUnavailable]);
    };

    let cognition = WorkspaceIntelligenceCognition::for_host(paths, host);
    let read = match tokio::task::spawn_blocking(move || cognition.read_entries(&scope)).await {
        Ok(read) => read,
        // A cancelled or panicked blocking task is a read that did not happen: the
        // caller injects nothing rather than treating it as empty content.
        Err(_) => return (None, vec![ScopedReadDiagnostic::PartitionUnavailable]),
    };
    match read {
        // No record yet: nothing to read, and nothing was created by this call.
        Ok(None) => (None, vec![ScopedReadDiagnostic::PartitionAbsent]),
        Ok(Some(stored)) => {
            let projected = stored
                .iter()
                .map(project_stored_entry)
                .collect::<Vec<_>>();
            let (entries, skipped) = project_for_injection(&projected, now_unix_ms);
            log_skipped_entries(workspace_id, skipped.as_slice());
            if entries.is_empty() {
                (None, vec![ScopedReadDiagnostic::NoEligibleEntries])
            } else {
                (Some(entries), Vec::new())
            }
        }
        // Defensive: the v2 branch above is the only way a content read succeeds, and
        // 39a guarantees a v2 record always carries both content tables. A record that
        // reports "no content table" therefore reports the v1 shape it was read as.
        Err(CognitionError::Store(
            WorkspaceIntelligenceCognitionError::ContentTableAbsent { .. },
        )) => (None, vec![ScopedReadDiagnostic::PartitionV1NoContent]),
        Err(_) => (None, vec![ScopedReadDiagnostic::PartitionUnavailable]),
    }
}

/// Projects one stored row onto the fields the injection decision reads.
///
/// The projection never carries a record id, a partition key or an epoch: the
/// injection decision and the prompt text have no use for a storage identity.
fn project_stored_entry(entry: &StoredCognitionEntry) -> StoredEntryProjection {
    StoredEntryProjection {
        kind: entry.kind.clone(),
        state: entry.state.clone(),
        visibility: entry.visibility.clone(),
        authority: entry.authority.clone(),
        statement: entry.statement.clone(),
        revision: entry.revision,
        valid_until_unix_ms: entry.valid_until_unix_ms,
    }
}

/// Logs one debug line per skip reason, with the number of rows it removed.
///
/// A skipped row is an outcome, not an error: an empty section stays empty and the
/// reason is only visible to an operator.
fn log_skipped_entries(
    workspace_id: &str,
    skipped: &[crate::service::workspace_intelligence::entries_contract::InjectionSkip],
) {
    if skipped.is_empty() {
        return;
    }
    let mut counts: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();
    for skip in skipped {
        *counts.entry(skip.as_str()).or_default() += 1;
    }
    for (reason, count) in counts {
        debug!(
            "Scoped memory entries skipped: workspace_id={} reason={} count={}",
            workspace_id, reason, count
        );
    }
}

/// The current wall clock in Unix milliseconds.
///
/// A clock before the Unix epoch or a duration that does not fit in `i64` falls
/// back to the nearest representable instant instead of failing a read.
fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Builds this host's key for a workspace, or reports why it cannot.
///
/// The host id is the persisted anchor's, and the execution domain is the local
/// one: a scoped read never speaks for another domain, and no fact about the
/// machine, the device or the process stands in for either value.
async fn scoped_read_host(
    paths: &PathManager,
    workspace_id: &str,
) -> Option<HostExecutionDomainKey> {
    let Some(host_id) = read_persisted_host_id(paths).await else {
        debug!(
            "Workspace intelligence scoped read skipped: workspace_id={} reason=anchor_absent",
            workspace_id
        );
        return None;
    };

    match HostExecutionDomainKey::new(&host_id, LOCAL_EXECUTION_DOMAIN) {
        Some(host) => Some(host),
        None => {
            debug!(
                "Workspace intelligence scoped read skipped: workspace_id={} reason=host_key_unavailable",
                workspace_id
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbitfun_services_core::workspace_intelligence_cognition::{
        NewCognitionEntry, WorkspaceIntelligenceCognitionStore,
    };
    use openbitfun_services_core::workspace_intelligence_host_anchor::{
        HostAnchorEnsure, HostAnchorStore,
    };

    use crate::service::workspace_intelligence::cognition::CognitionKind;
    use crate::service::workspace_intelligence::entries::{
        create_human_entry, partition_key_for_scope, retire_human_entry,
    };
    use crate::service::workspace_intelligence::entries_contract::NewHumanEntry;
    use crate::service::workspace_intelligence::host::WorkspaceIntelligenceHost;
    use crate::service::workspace_intelligence::mode::WorkspaceIntelligenceTier;

    const FIXTURE_WORKSPACE_ID: &str = "workspace-fixture-a";

    fn fixture_paths(user_root: &std::path::Path) -> PathManager {
        PathManager::with_user_root_for_tests(user_root.join("user"))
    }

    async fn mint_anchor(paths: &PathManager) -> String {
        let store =
            HostAnchorStore::new(WorkspaceIntelligenceHost::anchor_root_for_tests(paths));
        match store.ensure().await.expect("the fixture anchor must mint") {
            HostAnchorEnsure::Created(anchor) | HostAnchorEnsure::Existing(anchor) => {
                anchor.host_id().to_owned()
            }
        }
    }

    fn host_key(host_id: &str) -> HostExecutionDomainKey {
        HostExecutionDomainKey::new(host_id, LOCAL_EXECUTION_DOMAIN)
            .expect("the fixture host key is valid")
    }

    #[tokio::test]
    async fn a_missing_anchor_makes_the_scope_unavailable() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());

        let (entries, diagnostics) = read_scoped_memory(&paths, FIXTURE_WORKSPACE_ID).await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::ScopeUnavailable]);
        assert!(resolve_scoped_memory_context(&paths, FIXTURE_WORKSPACE_ID)
            .await
            .is_none());
        assert!(!paths.workspace_intelligence_dir().exists());
    }

    #[tokio::test]
    async fn an_absent_partition_is_reported_and_not_created() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        mint_anchor(&paths).await;

        let (entries, diagnostics) = read_scoped_memory(&paths, FIXTURE_WORKSPACE_ID).await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::PartitionAbsent]);
        assert!(!paths.workspace_intelligence_cognition_dir().exists());
    }

    #[tokio::test]
    async fn a_v1_partition_reports_that_it_holds_no_content() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        owned_scope(&paths).await;

        // Reproduce a record an older build left behind: `partition_state` only, at
        // `user_version = 1`. No writer in this tree produces that shape any more,
        // so the fixture is built at the file-format level.
        let record = std::fs::read_dir(paths.workspace_intelligence_cognition_dir())
            .expect("the cognition root is readable")
            .map(|entry| entry.expect("readable directory entry").path())
            .find(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("sqlite")
            })
            .expect("the fixture record exists");
        rusqlite::Connection::open(&record)
            .expect("the fixture record opens")
            .execute_batch(
                "DROP TABLE cognition_entries;
                 DROP TABLE cognition_dependencies;
                 PRAGMA user_version = 1;",
            )
            .expect("the v1 fixture is created");

        let (entries, diagnostics) = read_scoped_memory(&paths, FIXTURE_WORKSPACE_ID).await;

        assert!(entries.is_none());
        assert_eq!(
            diagnostics,
            vec![ScopedReadDiagnostic::PartitionV1NoContent]
        );
    }

    #[tokio::test]
    async fn a_workspace_without_a_control_record_permits_no_read() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        mint_anchor(&paths).await;

        assert!(resolve_scoped_memory_context(&paths, FIXTURE_WORKSPACE_ID)
            .await
            .is_none());
        assert!(
            !paths.workspace_intelligence_control_dir().exists(),
            "resolving the context must not write a control record or create its root"
        );
    }

    #[tokio::test]
    async fn a_blank_workspace_id_is_refused() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        mint_anchor(&paths).await;

        let (entries, diagnostics) = read_scoped_memory(&paths, "   ").await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::ScopeUnavailable]);
        assert!(resolve_scoped_memory_context(&paths, "   ").await.is_none());
    }

    #[test]
    fn a_permitted_context_carries_the_tier_it_was_derived_from() {
        let context = ScopedMemoryReadContext {
            workspace_id: FIXTURE_WORKSPACE_ID.to_string(),
            tier: WorkspaceIntelligenceTier::Baseline,
        };

        assert!(context.permits_scoped_read());
        assert_eq!(context.workspace_id, FIXTURE_WORKSPACE_ID);
    }

    /// A fixture host whose control record is irrelevant here: these tests read the
    /// partition content only.
    const NOW: i64 = 1_700_000_000_000;

    async fn owned_scope(
        paths: &PathManager,
    ) -> (HostExecutionDomainKey, WorkspaceControlScope) {
        let host_id = mint_anchor(paths).await;
        let host = host_key(&host_id);
        let scope = WorkspaceControlScope::new(&host, FIXTURE_WORKSPACE_ID)
            .expect("the fixture scope is valid");
        WorkspaceIntelligenceCognition::for_host(paths, host.clone())
            .initialize(&scope)
            .expect("the fixture v2 partition must initialize");
        (host, scope)
    }

    fn human_entry(kind: CognitionKind, statement: &str) -> NewHumanEntry {
        NewHumanEntry {
            kind,
            statement: statement.to_string(),
            source_resource: None,
        }
    }

    #[tokio::test]
    async fn a_created_human_entry_is_injected() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        let (host, _scope) = owned_scope(&paths).await;
        create_human_entry(
            &paths,
            &host,
            FIXTURE_WORKSPACE_ID,
            human_entry(CognitionKind::Goal, "ship the scoped read"),
            None,
            NOW,
        )
        .await
        .expect("the entry is created");

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;

        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        let entries = entries.expect("a created entry must be injected");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, CognitionKind::Goal);
        assert_eq!(entries[0].text, "ship the scoped read");
    }

    #[tokio::test]
    async fn an_empty_v2_partition_reports_no_eligible_entries() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        owned_scope(&paths).await;

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::NoEligibleEntries]);
    }

    #[tokio::test]
    async fn a_withdrawn_entry_is_no_longer_injected() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        let (host, _scope) = owned_scope(&paths).await;
        let receipt = create_human_entry(
            &paths,
            &host,
            FIXTURE_WORKSPACE_ID,
            human_entry(CognitionKind::Knowledge, "the partition is v2"),
            None,
            NOW,
        )
        .await
        .expect("the entry is created");

        retire_human_entry(
            &paths,
            &host,
            FIXTURE_WORKSPACE_ID,
            &receipt.entry_id,
            receipt.revision,
            "superseded by a newer decision",
            None,
        )
        .await
        .expect("the entry is withdrawn");

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::NoEligibleEntries]);
    }

    #[tokio::test]
    async fn a_commitment_without_a_validity_bound_is_not_injected() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        let (host, _scope) = owned_scope(&paths).await;
        create_human_entry(
            &paths,
            &host,
            FIXTURE_WORKSPACE_ID,
            human_entry(CognitionKind::Commitment, "promised without a date"),
            None,
            NOW,
        )
        .await
        .expect("the entry is created");

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;

        assert!(entries.is_none());
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::NoEligibleEntries]);
    }

    #[tokio::test]
    async fn only_an_unexpired_validity_bound_is_injected() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = fixture_paths(root.path());
        let (_host, scope) = owned_scope(&paths).await;
        let store = WorkspaceIntelligenceCognitionStore::new(
            paths.workspace_intelligence_cognition_dir(),
        );
        let store_scope = scope.as_str();
        let mut entry = NewCognitionEntry {
            entry_id: "bounded-1".to_string(),
            kind: "goal".to_string(),
            category: "fact".to_string(),
            authority: "human".to_string(),
            state: "active".to_string(),
            statement: "bounded goal".to_string(),
            workspace_partition: partition_key_for_scope(&store_scope),
            visibility: "partition".to_string(),
            shared_scope: None,
            shared_authorization: None,
            source_owner: "human".to_string(),
            source_resource: None,
            source_revision: None,
            observed_at_unix_ms: NOW,
            valid_until_unix_ms: Some(NOW - 1),
            confidence: None,
            revision: 1,
            epoch: 1,
            supersedes: None,
            invalidated_reason: None,
        };
        store
            .commit_entries_with_cursor(&store_scope, None, None, &[entry.clone()], &[])
            .expect("the expired fixture is stored");

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;
        assert!(entries.is_none(), "an elapsed bound is not injected");
        assert_eq!(diagnostics, vec![ScopedReadDiagnostic::NoEligibleEntries]);

        entry.entry_id = "bounded-2".to_string();
        entry.valid_until_unix_ms = Some(NOW + 1);
        store
            .commit_entries_with_cursor(&store_scope, None, None, &[entry], &[])
            .expect("the live fixture is stored");

        let (entries, diagnostics) =
            read_scoped_memory_at(&paths, FIXTURE_WORKSPACE_ID, NOW).await;
        assert!(diagnostics.is_empty(), "{diagnostics:?}");
        assert_eq!(entries.expect("the live bound is injected").len(), 1);
    }
}
