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
//! # What a read returns in this slice
//!
//! No entries. The v1 cognition partition holds the partition state only, so an
//! existing partition is reported as [`ScopedReadDiagnostic::PartitionV1NoContent`]
//! until the slice that writes content tables lands.
//!
//! # Delivery profile
//!
//! Capability delivery is passed as [`CapabilityDelivery::Delivered`] and the
//! model reference is never resolved, because this module consumes the tier only:
//! the derived tier is a function of the control-record switch and the configured
//! reference, and neither depends on the resolution outcome. Not resolving also
//! keeps a prompt build from reaching a model provider.

use log::debug;

use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::control::WorkspaceIntelligenceControl;
use crate::service::workspace_intelligence::host::read_persisted_host_id;
use crate::service::workspace_intelligence::host_binding::LOCAL_EXECUTION_DOMAIN;
use crate::service::workspace_intelligence::mode::{
    tier_permits_scoped_read, CapabilityDelivery, WorkspaceModelResolution,
};
use crate::service::workspace_intelligence::partition::WorkspaceIntelligenceCognition;
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

/// Reads the scoped cognition content of one workspace.
///
/// The first value is `Some(entries)` only when the partition actually carried
/// content; this slice never does. The diagnostics say which fact was missing, and
/// an empty read is never replaced by the legacy global memory files.
pub(crate) async fn read_scoped_memory(
    paths: &PathManager,
    workspace_id: &str,
) -> (Option<Vec<ScopedMemoryEntry>>, Vec<ScopedReadDiagnostic>) {
    let Some(host) = scoped_read_host(paths, workspace_id).await else {
        return (None, vec![ScopedReadDiagnostic::ScopeUnavailable]);
    };
    let Some(scope) = WorkspaceControlScope::new(&host, workspace_id) else {
        return (None, vec![ScopedReadDiagnostic::ScopeUnavailable]);
    };

    let cognition = WorkspaceIntelligenceCognition::for_host(paths, host);
    match cognition.observe(&scope) {
        // No record yet: nothing to read, and nothing was created by this call.
        Ok(None) => (None, vec![ScopedReadDiagnostic::PartitionAbsent]),
        // The v1 partition state is readable, but v1 stores no content rows.
        Ok(Some(_state)) => (None, vec![ScopedReadDiagnostic::PartitionV1NoContent]),
        Err(_) => (None, vec![ScopedReadDiagnostic::PartitionUnavailable]),
    }
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
    use openbitfun_services_core::workspace_intelligence_host_anchor::{
        HostAnchorEnsure, HostAnchorStore,
    };

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
        let host_id = mint_anchor(&paths).await;
        let host = host_key(&host_id);
        let scope = WorkspaceControlScope::new(&host, FIXTURE_WORKSPACE_ID)
            .expect("the fixture scope is valid");

        WorkspaceIntelligenceCognition::for_host(&paths, host)
            .initialize(&scope)
            .expect("the fixture partition must initialize");
        assert!(paths.workspace_intelligence_cognition_dir().exists());

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
}
