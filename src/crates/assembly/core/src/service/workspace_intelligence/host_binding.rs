//! Execution binding: the persisted facts that tie one governed scope to one
//! concrete execution shape of one workspace.
//!
//! The binding lives INSIDE the authoritative control record's opaque `policy`
//! value under `execution_binding`. This module only parses, classifies and
//! compares it:
//!
//! - it never writes a binding, never repairs one, never back-fills an absent one
//!   and never rewrites the control record;
//! - only known fields participate in a comparison. Unknown sub-keys, unknown
//!   nesting and unknown sibling policy content are tolerated on read, never
//!   echoed and never rewritten, so a host never interprets or damages policy
//!   content it does not model;
//! - a known schema version with a malformed body is [`BindingState::Malformed`],
//!   and a well-formed body with an unknown schema version is
//!   [`BindingState::UnsupportedSchema`]. A newer writer's value is never mistaken
//!   for a corrupt one, and neither is resolved by deleting the record.
//!
//! The schema version moved from 1 to 2 when the observed worktree facts joined the
//! comparison. The version check runs before any field is read, so a binding
//! written by the previous build lands in [`BindingState::UnsupportedSchema`] with
//! the observed version instead of comparing equal to a wider body: a scope
//! written before this build cannot be adopted silently, and it is never rewritten.
//!
//! The persisted absence of a binding is itself a state, not a defect to
//! back-fill: an `enabled == true` record with no binding stays enabled, is not
//! rewritten, and is reported as unverified instead of being adopted or claimed.
//!
//! The value is a storage-namespace identity fact. It is never hardware, account,
//! device or machine identity, and nothing derives authorization from it.

use serde_json::{Map, Value};

use crate::service::workspace_intelligence::catalog_readonly::PersistedWorkspace;

/// Key of the binding inside the authoritative control record's `policy` value.
pub(crate) const EXECUTION_BINDING_KEY: &str = "execution_binding";

/// Schema version of the binding body this build writes and understands.
///
/// Version 2 added the observed worktree facts (`worktree_is_main`,
/// `main_repo_path`). A version 1 body is refused as
/// [`BindingState::UnsupportedSchema`] instead of being compared as if it carried
/// them.
pub(crate) const EXECUTION_BINDING_SCHEMA_VERSION: u32 = 2;

/// Execution domain of a local, host-owned workspace.
pub(crate) const LOCAL_EXECUTION_DOMAIN: &str = "local";

/// Known fields of one execution binding.
///
/// Equality over this struct IS comparison over known fields only: an unknown
/// sub-key is dropped at parse time, so it can never make two otherwise equal
/// bindings differ, and it is never written back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutionBinding {
    schema_version: u32,
    host_id: String,
    execution_domain: String,
    workspace_id: String,
    workspace_root: String,
    workspace_kind: String,
    is_worktree_child: bool,
    worktree_parent_id: Option<String>,
    worktree_is_main: Option<bool>,
    main_repo_path: Option<String>,
}

impl ExecutionBinding {
    /// Builds the binding this host observes for one persisted workspace.
    ///
    /// This is the comparison side, not storage: the produced value is never
    /// written into a control record by this slice.
    pub(crate) fn observed(host_id: &str, workspace: &PersistedWorkspace) -> Self {
        Self {
            schema_version: EXECUTION_BINDING_SCHEMA_VERSION,
            host_id: host_id.to_owned(),
            execution_domain: LOCAL_EXECUTION_DOMAIN.to_owned(),
            workspace_id: workspace.id().to_owned(),
            workspace_root: workspace.root().to_owned(),
            workspace_kind: workspace.kind().code().to_owned(),
            is_worktree_child: workspace.is_worktree_child(),
            worktree_parent_id: workspace.worktree_parent_id().map(str::to_owned),
            worktree_is_main: workspace.worktree_is_main(),
            main_repo_path: workspace.main_repo_path().map(str::to_owned),
        }
    }

    pub(crate) fn schema_version(&self) -> u32 {
        self.schema_version
    }

    pub(crate) fn host_id(&self) -> &str {
        &self.host_id
    }

    pub(crate) fn execution_domain(&self) -> &str {
        &self.execution_domain
    }

    pub(crate) fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    pub(crate) fn workspace_root(&self) -> &str {
        &self.workspace_root
    }

    pub(crate) fn workspace_kind(&self) -> &str {
        &self.workspace_kind
    }

    pub(crate) fn is_worktree_child(&self) -> bool {
        self.is_worktree_child
    }

    pub(crate) fn worktree_parent_id(&self) -> Option<&str> {
        self.worktree_parent_id.as_deref()
    }

    /// The stored `worktree.is_main`, `None` when the record has no worktree block.
    pub(crate) fn worktree_is_main(&self) -> Option<bool> {
        self.worktree_is_main
    }

    /// The stored, normalized `worktree.main_repo_path`, when present.
    ///
    /// A comparison fact only: nothing in this crate opens it.
    pub(crate) fn main_repo_path(&self) -> Option<&str> {
        self.main_repo_path.as_deref()
    }

    /// Known-field equality. The caller compares what it observed against what is
    /// stored; there is no "compatible enough" relation and no wildcard.
    pub(crate) fn matches(&self, other: &Self) -> bool {
        self == other
    }
}

/// Classification of the persisted binding of one control record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum BindingState {
    /// No policy, or a policy object without `execution_binding`. This is the
    /// legacy already-enabled shape: it stays enabled, is not rewritten, and is
    /// reported as unverified rather than adopted.
    Absent,
    /// A well-formed binding of a schema version this build understands.
    Present(ExecutionBinding),
    /// A well-formed envelope declaring a schema version this build does not
    /// implement. A newer writer's value is never treated as corrupt.
    UnsupportedSchema { observed: u32 },
    /// `execution_binding` exists but its known fields are not usable.
    Malformed,
}

/// Parses and classifies the binding of one stored `policy` value.
pub(crate) fn classify(policy: Option<&Value>) -> BindingState {
    let Some(policy) = policy else {
        return BindingState::Absent;
    };
    let Value::Object(policy) = policy else {
        // A policy that is not an object cannot carry a binding. It is not the
        // "absent" state: this host cannot prove anything about it.
        return BindingState::Malformed;
    };
    let Some(binding) = policy.get(EXECUTION_BINDING_KEY) else {
        return BindingState::Absent;
    };
    let Value::Object(binding) = binding else {
        return BindingState::Malformed;
    };
    let Some(schema_version) = binding
        .get("schema_version")
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
    else {
        return BindingState::Malformed;
    };
    if schema_version != EXECUTION_BINDING_SCHEMA_VERSION {
        return BindingState::UnsupportedSchema {
            observed: schema_version,
        };
    }
    let (Some(host_id), Some(execution_domain), Some(workspace_id), Some(workspace_root)) = (
        text(binding, "host_id"),
        text(binding, "execution_domain"),
        text(binding, "workspace_id"),
        text(binding, "workspace_root"),
    ) else {
        return BindingState::Malformed;
    };
    let Some(workspace_kind) = binding
        .get("workspace_kind")
        .and_then(Value::as_str)
        .filter(|kind| *kind == "local_workspace" || *kind == "local_worktree_child")
    else {
        return BindingState::Malformed;
    };
    let Some(is_worktree_child) = binding.get("is_worktree_child").and_then(Value::as_bool) else {
        return BindingState::Malformed;
    };
    let worktree_parent_id = match binding.get("worktree_parent_id") {
        None | Some(Value::Null) => None,
        Some(Value::String(parent)) if !parent.trim().is_empty() => Some(parent.clone()),
        Some(_) => return BindingState::Malformed,
    };
    // Both worktree facts belong to the current schema version and are therefore
    // required by it. A body of this version that omits them claims a shape it does
    // not carry, so it is refused instead of being compared with them defaulted.
    //
    // Writer obligation: a future binding writer must emit both keys explicitly,
    // using a JSON null when the fact is absent, and must add a round-trip test
    // that reads its own output back through this function. An omitted key is
    // indistinguishable from a body written by an older build, so it is refused
    // rather than absorbed.
    let worktree_is_main = match binding.get("worktree_is_main") {
        Some(Value::Null) => None,
        Some(Value::Bool(value)) => Some(*value),
        _ => return BindingState::Malformed,
    };
    let main_repo_path = match binding.get("main_repo_path") {
        Some(Value::Null) => None,
        Some(Value::String(path)) if !path.trim().is_empty() => Some(path.clone()),
        _ => return BindingState::Malformed,
    };
    // A child must declare a parent and a non-child must not: a contradictory
    // body is not a binding this build can compare meaningfully.
    if is_worktree_child != worktree_parent_id.is_some() {
        return BindingState::Malformed;
    }
    let is_child_kind = workspace_kind == "local_worktree_child";
    if is_child_kind != is_worktree_child {
        return BindingState::Malformed;
    }
    // The worktree facts must agree with the child flag: a worktree record that is
    // not the main workspace is a child, and a main workspace is never a child.
    if worktree_is_main == Some(false) && !is_worktree_child {
        return BindingState::Malformed;
    }
    if worktree_is_main == Some(true) && is_worktree_child {
        return BindingState::Malformed;
    }
    BindingState::Present(ExecutionBinding {
        schema_version,
        host_id: host_id.to_owned(),
        execution_domain: execution_domain.to_owned(),
        workspace_id: workspace_id.to_owned(),
        workspace_root: workspace_root.to_owned(),
        workspace_kind: workspace_kind.to_owned(),
        is_worktree_child,
        worktree_parent_id,
        worktree_is_main,
        main_repo_path,
    })
}

/// Non-blank string field.
fn text<'a>(binding: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    binding
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::workspace_intelligence::control::{
        ControlMutation, ControlMutationOutcome, WorkspaceIntelligenceControl,
    };
    use crate::service::workspace_intelligence::policy::{ApprovalUpdate, PolicyUpdate};
    use crate::service::workspace_intelligence::scope::{
        HostExecutionDomainKey, WorkspaceControlScope,
    };
    use openbitfun_services_core::workspace_intelligence_store::{
        ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
        WorkspaceIntelligenceStore,
    };

    const HOST_ID: &str = "wi-host-v1:0123456789abcdef0123456789abcdef";

    fn workspace(id: &str) -> PersistedWorkspace {
        // Built through the real classifier so the fixture cannot drift from the
        // persisted-shape contract.
        let record = serde_json::json!({
            "id": id,
            "name": id,
            "rootPath": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
            "workspaceType": "Other",
            "workspaceKind": "normal",
            "status": "Active",
            "languages": [],
            "openedAt": "2026-01-01T00:00:00Z",
            "lastAccessed": "2026-01-01T00:00:00Z",
            "description": null,
            "tags": [],
            "statistics": null,
            "metadata": {},
        });
        let info: openbitfun_services_core::workspace_records::WorkspaceInfo =
            serde_json::from_value(record).unwrap();
        let catalog_entry =
            crate::service::workspace_intelligence::catalog_readonly::classify_record_for_tests(
                &info,
                &Default::default(),
            );
        match catalog_entry {
            crate::service::workspace_intelligence::catalog_readonly::PersistedCatalogEntry::Eligible(
                workspace,
            ) => workspace,
            other => panic!("fixture workspace must be eligible: {other:?}"),
        }
    }

    fn child_workspace(id: &str, parent: &str) -> PersistedWorkspace {
        let record = serde_json::json!({
            "id": id,
            "name": id,
            "rootPath": if cfg!(windows) { "C:\\fixtures\\child" } else { "/fixtures/child" },
            "workspaceType": "Other",
            "workspaceKind": "normal",
            "status": "Active",
            "languages": [],
            "openedAt": "2026-01-01T00:00:00Z",
            "lastAccessed": "2026-01-01T00:00:00Z",
            "description": null,
            "tags": [],
            "statistics": null,
            "metadata": {},
            "worktree": {
                "mainWorkspaceId": parent,
                "path": if cfg!(windows) { "C:\\fixtures\\child" } else { "/fixtures/child" },
                "mainRepoPath": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
                "isMain": false,
            },
        });
        let info: openbitfun_services_core::workspace_records::WorkspaceInfo =
            serde_json::from_value(record).unwrap();
        let parent_info: openbitfun_services_core::workspace_records::WorkspaceInfo =
            serde_json::from_value(serde_json::json!({
                "id": parent,
                "name": parent,
                "rootPath": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
                "workspaceType": "Other",
                "workspaceKind": "normal",
                "status": "Active",
                "languages": [],
                "openedAt": "2026-01-01T00:00:00Z",
                "lastAccessed": "2026-01-01T00:00:00Z",
                "description": null,
                "tags": [],
                "statistics": null,
                "metadata": {},
            }))
            .unwrap();
        let mut records = std::collections::HashMap::new();
        records.insert(parent.to_owned(), parent_info);
        match crate::service::workspace_intelligence::catalog_readonly::classify_record_for_tests(
            &info, &records,
        ) {
            crate::service::workspace_intelligence::catalog_readonly::PersistedCatalogEntry::Eligible(
                workspace,
            ) => workspace,
            other => panic!("fixture child must be eligible: {other:?}"),
        }
    }

    /// Hand-built stored policy: the known binding plus unknown content this
    /// build does not model.
    fn stored_policy(binding: &ExecutionBinding) -> Value {
        serde_json::json!({
            EXECUTION_BINDING_KEY: {
                "schema_version": binding.schema_version(),
                "host_id": binding.host_id(),
                "execution_domain": binding.execution_domain(),
                "workspace_id": binding.workspace_id(),
                "workspace_root": binding.workspace_root(),
                "workspace_kind": binding.workspace_kind(),
                "is_worktree_child": binding.is_worktree_child(),
                "worktree_parent_id": binding.worktree_parent_id(),
                "worktree_is_main": binding.worktree_is_main(),
                "main_repo_path": binding.main_repo_path(),
                "future_note": {"nested": [1, 2, 3], "text": "keep me"},
            },
            "domains": {"memory": {"enabled": true, "unknown_domain_key": "keep"}},
            "future_root_key": ["a", "b"],
        })
    }

    fn bound_policy() -> Value {
        stored_policy(&ExecutionBinding::observed(HOST_ID, &workspace("workspace-a")))
    }

    /// The same workspace record, but with a worktree block that says it is the
    /// main workspace of its group and carries no `mainWorkspaceId`.
    fn main_workspace(id: &str) -> PersistedWorkspace {
        let record = serde_json::json!({
            "id": id,
            "name": id,
            "rootPath": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
            "workspaceType": "Other",
            "workspaceKind": "normal",
            "status": "Active",
            "languages": [],
            "openedAt": "2026-01-01T00:00:00Z",
            "lastAccessed": "2026-01-01T00:00:00Z",
            "description": null,
            "tags": [],
            "statistics": null,
            "metadata": {},
            "worktree": {
                "path": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
                "mainRepoPath": if cfg!(windows) { "C:\\fixtures\\repo" } else { "/fixtures/repo" },
                "isMain": true,
            },
        });
        let info: openbitfun_services_core::workspace_records::WorkspaceInfo =
            serde_json::from_value(record).unwrap();
        match crate::service::workspace_intelligence::catalog_readonly::classify_record_for_tests(
            &info,
            &Default::default(),
        ) {
            crate::service::workspace_intelligence::catalog_readonly::PersistedCatalogEntry::Eligible(
                workspace,
            ) => workspace,
            other => panic!("fixture main workspace must be eligible: {other:?}"),
        }
    }

    #[test]
    fn absent_and_unrelated_policy_is_absent_not_malformed() {
        assert_eq!(classify(None), BindingState::Absent);
        assert_eq!(
            classify(Some(&serde_json::json!({"domains": {}}))),
            BindingState::Absent
        );
    }

    #[test]
    fn a_non_object_policy_is_malformed_rather_than_absent() {
        assert_eq!(
            classify(Some(&serde_json::json!("not-an-object"))),
            BindingState::Malformed
        );
        assert_eq!(
            classify(Some(&serde_json::json!({"execution_binding": 7}))),
            BindingState::Malformed
        );
    }

    #[test]
    fn known_binding_round_trips_through_classification() {
        let observed = ExecutionBinding::observed(HOST_ID, &workspace("workspace-a"));
        let BindingState::Present(stored) = classify(Some(&bound_policy())) else {
            panic!("the hand-built binding must classify as present");
        };
        assert_eq!(stored, observed);
        assert!(stored.matches(&observed));
        assert_eq!(stored.schema_version(), EXECUTION_BINDING_SCHEMA_VERSION);
        assert_eq!(stored.host_id(), HOST_ID);
        assert_eq!(stored.execution_domain(), LOCAL_EXECUTION_DOMAIN);
        assert_eq!(stored.workspace_id(), "workspace-a");
        assert_eq!(stored.workspace_kind(), "local_workspace");
        assert!(!stored.is_worktree_child());
        assert_eq!(stored.worktree_parent_id(), None);
        assert_eq!(stored.worktree_is_main(), None);
        assert_eq!(stored.main_repo_path(), None);
        assert!(!stored.workspace_root().is_empty());
    }

    #[test]
    fn worktree_child_binding_carries_its_resolved_parent() {
        let child = child_workspace("child", "main");
        let observed = ExecutionBinding::observed(HOST_ID, &child);
        assert!(observed.is_worktree_child());
        assert_eq!(observed.worktree_parent_id(), Some("main"));
        assert_eq!(observed.workspace_kind(), "local_worktree_child");
        assert_eq!(observed.worktree_is_main(), Some(false));
        assert!(observed.main_repo_path().is_some());
        let stored = classify(Some(&stored_policy(&observed)));
        assert_eq!(stored, BindingState::Present(observed));
    }

    #[test]
    fn a_worktree_projection_change_is_a_binding_change() {
        // A plain local record and the same workspace re-projected as the main
        // workspace of its group share every older known field: kind, child flag and
        // parent id are identical. Only the observed worktree facts can tell them
        // apart, and the binding must.
        let plain = ExecutionBinding::observed(HOST_ID, &workspace("workspace-a"));
        let main = ExecutionBinding::observed(HOST_ID, &main_workspace("workspace-a"));
        assert_eq!(plain.workspace_kind(), main.workspace_kind());
        assert_eq!(plain.is_worktree_child(), main.is_worktree_child());
        assert_eq!(plain.worktree_parent_id(), main.worktree_parent_id());
        assert_eq!(main.worktree_is_main(), Some(true));
        assert!(main.main_repo_path().is_some());
        assert!(!plain.matches(&main), "the wider binding must see the change");
        assert!(!main.matches(&plain));
    }

    #[test]
    fn unknown_schema_version_is_unsupported_not_malformed() {
        let mut policy = bound_policy();
        policy[EXECUTION_BINDING_KEY]["schema_version"] = serde_json::json!(9);
        assert_eq!(
            classify(Some(&policy)),
            BindingState::UnsupportedSchema { observed: 9 }
        );
    }

    #[test]
    fn a_version_one_body_is_unsupported_instead_of_comparing_equal() {
        // The previous build wrote this exact body. Its known fields happen to be a
        // subset of the current ones, so only the version stands between it and a
        // silent match; the version check runs before any field is read.
        let policy = serde_json::json!({
            EXECUTION_BINDING_KEY: {
                "schema_version": 1,
                "host_id": HOST_ID,
                "execution_domain": LOCAL_EXECUTION_DOMAIN,
                "workspace_id": "workspace-a",
                "workspace_root": if cfg!(windows) { "C:/fixtures/repo" } else { "/fixtures/repo" },
                "workspace_kind": "local_workspace",
                "is_worktree_child": false,
                "worktree_parent_id": null,
            },
        });
        assert_eq!(
            classify(Some(&policy)),
            BindingState::UnsupportedSchema { observed: 1 }
        );
    }

    #[test]
    fn a_current_version_body_without_the_worktree_facts_is_malformed() {
        for missing in ["worktree_is_main", "main_repo_path"] {
            let mut policy = bound_policy();
            policy[EXECUTION_BINDING_KEY]
                .as_object_mut()
                .unwrap()
                .remove(missing);
            assert_eq!(
                classify(Some(&policy)),
                BindingState::Malformed,
                "a {missing}-less body of the current version claims a shape it does not carry"
            );
        }
        // A worktree fact that contradicts the child flag is refused as well: a
        // `is_main: false` worktree record is always a child.
        let mut policy = bound_policy();
        policy[EXECUTION_BINDING_KEY]["worktree_is_main"] = serde_json::json!(false);
        assert_eq!(classify(Some(&policy)), BindingState::Malformed);
    }

    #[test]
    fn malformed_bodies_are_typed_malformed() {
        let cases = [
            serde_json::json!({EXECUTION_BINDING_KEY: {"schema_version": 2}}),
            serde_json::json!({EXECUTION_BINDING_KEY: {"schema_version": "2"}}),
            serde_json::json!({
                EXECUTION_BINDING_KEY: {
                    "schema_version": 2, "host_id": "  ", "execution_domain": "local",
                    "workspace_id": "w", "workspace_root": "/r", "workspace_kind": "local_workspace",
                    "is_worktree_child": false, "worktree_is_main": null, "main_repo_path": null,
                }
            }),
            // A contradiction between the child flag and the parent id.
            serde_json::json!({
                EXECUTION_BINDING_KEY: {
                    "schema_version": 2, "host_id": "h", "execution_domain": "local",
                    "workspace_id": "w", "workspace_root": "/r", "workspace_kind": "local_workspace",
                    "is_worktree_child": true, "worktree_parent_id": "main",
                    "worktree_is_main": null, "main_repo_path": null,
                }
            }),
            // Unknown workspace kind inside a known schema version.
            serde_json::json!({
                EXECUTION_BINDING_KEY: {
                    "schema_version": 2, "host_id": "h", "execution_domain": "local",
                    "workspace_id": "w", "workspace_root": "/r", "workspace_kind": "remote_workspace",
                    "is_worktree_child": false, "worktree_is_main": null, "main_repo_path": null,
                }
            }),
        ];
        for policy in cases {
            assert_eq!(
                classify(Some(&policy)),
                BindingState::Malformed,
                "policy: {policy}"
            );
        }
    }

    #[test]
    fn comparison_uses_known_fields_only() {
        let observed = ExecutionBinding::observed(HOST_ID, &workspace("workspace-a"));
        let mut stored = observed.clone();
        // Unknown content never participates; a known field change always does.
        assert!(stored.matches(&observed));
        stored.workspace_root = "/other".to_owned();
        assert!(!stored.matches(&observed));
    }

    #[test]
    fn a_different_host_or_workspace_id_does_not_match() {
        let observed = ExecutionBinding::observed(HOST_ID, &workspace("workspace-a"));
        for other in [
            ExecutionBinding::observed(
                "wi-host-v1:ffffffffffffffffffffffffffffffff",
                &workspace("workspace-a"),
            ),
            ExecutionBinding::observed(HOST_ID, &workspace("workspace-b")),
            ExecutionBinding::observed(HOST_ID, &child_workspace("child", "main")),
        ] {
            assert!(!observed.matches(&other));
        }
    }

    fn host() -> HostExecutionDomainKey {
        HostExecutionDomainKey::new(HOST_ID, LOCAL_EXECUTION_DOMAIN).unwrap()
    }

    #[tokio::test]
    async fn typed_policy_update_preserves_the_binding_and_unknown_nested_content() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().join("control");
        let host = host();
        let scope = WorkspaceControlScope::new(&host, "workspace-a").unwrap();
        let store = WorkspaceIntelligenceStore::new(root.clone(), vec![1]);
        let policy = bound_policy();
        store
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    policy: ControlFieldUpdate::Set(policy.clone()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let before_record = store.read(&scope.as_str()).await.unwrap().unwrap();
        assert_eq!(before_record.policy.as_ref(), Some(&policy));
        let before_binding = serde_json::to_string(&policy[EXECUTION_BINDING_KEY]).unwrap();

        // The typed policy owner merges the known `approval` block into the stored
        // payload and must leave every unknown part exactly as stored.
        let control = WorkspaceIntelligenceControl::with_root(root.clone(), host);
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(before_record.control_generation),
                ControlMutation::SetPolicy(PolicyUpdate::Approval(ApprovalUpdate::Recommend)),
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ControlMutationOutcome::Applied(_)
        ));

        let after_record = store.read(&scope.as_str()).await.unwrap().unwrap();
        let after = after_record.policy.expect("policy survives the update");
        assert_eq!(
            serde_json::to_string(&after[EXECUTION_BINDING_KEY]).unwrap(),
            before_binding,
            "the execution binding and its unknown nested content must be byte-identical"
        );
        assert_eq!(after["future_root_key"], policy["future_root_key"]);
        assert_eq!(
            after["domains"]["memory"]["unknown_domain_key"], "keep",
            "unknown domain content survives"
        );
        assert_eq!(after["approval"], serde_json::json!({"mode": "recommend"}));
        // The binding still classifies identically after the typed update.
        assert_eq!(
            classify(Some(&after)),
            BindingState::Present(
                ExecutionBinding::observed(HOST_ID, &workspace("workspace-a"))
            )
        );
    }
}
