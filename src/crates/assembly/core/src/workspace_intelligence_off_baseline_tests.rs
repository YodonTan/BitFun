//! OFF differential baseline for the workspace intelligence P0 slice.
//!
//! # What this file is
//!
//! Every test here is a differential baseline for the "OFF" path of the
//! workspace intelligence work: the path where workspace intelligence adds no
//! tool, no reminder, no prompt fragment, no cache identity, and no approval
//! step. Each test observes an existing, real production owner and pins its
//! current output with expectations that were written independently (literal
//! values, or literal structure read from the owner's render/evaluation
//! contract).
//!
//! The file sits at the crate root because its subjects span `agentic`, the
//! Agent Runtime, and the product-domain contracts. It is not a test of the
//! `service::workspace_intelligence` owner and deliberately does not live next
//! to it.
//!
//! Reference values were captured on
//! `d2efc1e7d5dbffc72cbe31f862bcd477ce54881f` with a fixed fixture. At that
//! commit the P0 module had no production consumer, so none of the manifests,
//! reminder orders, prompt texts, cache keys, or permission plans below can
//! have been produced by P0 code.
//!
//! # Owners under observation
//!
//! - product tool manifest and exposure split:
//!   `agentic/tools/product_runtime/catalog.rs`
//! - reminder slot order:
//!   `openbitfun_agent_runtime::prompt::PrependedPromptReminders`
//! - prompt text: `agentic/agents/prompt_builder/prompt_builder_impl.rs`
//! - cache identity: `openbitfun_agent_runtime::prompt_cache`
//! - approval decisions and defaults: `openbitfun_agent_runtime::permission`
//!   plus the product-domain tool permission contract
//!
//! # Evidence boundary
//!
//! Executable proxy metrics, i.e. what these tests really constrain:
//!
//! - the prompt-visible tool names and the direct/deferred exposure for one
//!   fixed context;
//! - the literal order of the prepended reminder slots, both as a pure struct
//!   and through the real prompt builder;
//! - SHA-256 digests plus independent structural assertions of the prompt
//!   builder output, and the literal prompt-cache scope key;
//! - the ordered approval plan for fixed intents, plus the unchanged default
//!   approval strategy and timeout validation.
//!
//! What is deliberately NOT claimed here:
//!
//! - this file does not deliver "governance spawn registration = 0" as runtime
//!   evidence. P0 has no host bootstrap, no governance carrier, and no runtime;
//!   `CoordinationStore` is crate-private to `agentic::coordination`, so any
//!   count taken outside the real registration path is vacuously zero and could
//!   never fail. Runtime spawn-registration metering is explicitly deferred to
//!   P1, after host bootstrap wiring, and process-wide provider metering to the
//!   P2 integration-phase evidence.
//! - this file builds no AI client, session, coordinator, or model resolution.
//!   It therefore says nothing about provider calls in a running process, and
//!   it does not carry the P0 pure-path resolver test; that coverage stays with
//!   the `mode` and `read_contract` unit tests that own those functions.
//! - the tool assertions below are driven by an explicitly supplied
//!   `allowed_tools` filter over the registry snapshot. The resolution does read
//!   that snapshot, but every asserted name comes from the explicit list, so a
//!   tool that some feature set adds to the registry cannot appear in the
//!   asserted result. That filter invariance is the only feature-set property
//!   claimed here. These assertions do not consult the `Standard` agent policy
//!   and do not consult the agent-derived availability catalogs. They were
//!   verified under `--features agent-runtime,git` only, and this file makes no
//!   claim about arbitrary feature combinations, including a narrow set that
//!   removes a baseline tool the assertions rely on. No test here pins the
//!   compiled feature catalog itself, and the `GetToolSpec` answer is not
//!   covered here; the existing `GetToolSpec` owner tests cover it.
//! - nothing here exercises a live desktop, CLI, remote workspace, Peer, or
//!   Detached Dispatch connection, and nothing measures wall-clock behavior.

use std::collections::HashMap;

use openbitfun_agent_runtime::permission::{plan_permission_intents, PermissionIntentPlan};
use openbitfun_agent_runtime::prompt_cache::{
    prompt_cache_scope_key, SystemPromptCacheIdentity, UserContextCacheIdentity,
};
use openbitfun_agent_tools::PermissionIntent;
use openbitfun_product_domains::tool_permissions::{
    PermissionApprovalConfig, PermissionApprovalModelKind, PermissionApprovalOnAsk,
    PermissionApprovalOnError, PermissionApprovalStrategy, PermissionEffect, PermissionGrant,
    PermissionMode, PermissionPolicyConfig, PermissionPolicyPreset,
    PermissionResourceCaseSensitivity, PermissionRule, ResolvedPermissionPolicy,
    ToolPermissionConfig,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::agentic::agents::{
    AgentToolPolicyOverrides, PrependedPromptReminders, PromptBuilder, PromptBuilderContext,
    RemoteExecutionHints, RuntimeContextNeeds, ToolListingSections, UserContextPolicy,
};
use crate::agentic::tools::product_runtime::{
    resolve_product_resolved_tool_manifest, resolve_product_resolved_visible_tools,
};
use crate::agentic::tools::tool_context_runtime::ToolUseContext;
use crate::agentic::tools::ToolRuntimeRestrictions;
use crate::service::workspace::RelatedPath;

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/// Fixture workspace path. Deliberately not a real directory: workspace context
/// rendering is a pure string projection, so no filesystem access is wanted.
const FIXTURE_WORKSPACE_PATH: &str = "/fixtures/wi-p0/workspace";

/// Fixed tool context for the manifest baseline. Pins only the parts this case
/// controls, the production field set carried with no model client, no runtime
/// handles, no custom data, and no workspace or session binding, so the test
/// itself introduces no ambient state.
///
/// The observed owner still reads the process-global registry snapshot, and
/// that is exactly why the assertions only pin the names left after the explicit
/// `allowed_tools` filter.
fn off_baseline_tool_context(agent_type: Option<&str>) -> ToolUseContext {
    ToolUseContext {
        tool_call_id: None,
        agent_type: agent_type.map(str::to_string),
        session_id: None,
        dialog_turn_id: None,
        workspace: None,
        loaded_deferred_tool_specs: Vec::new(),
        model_client: None,
        primary_model_facts: tool_runtime::context::PrimaryModelFacts::default(),
        custom_data: HashMap::new(),
        computer_use_host: None,
        runtime_tool_restrictions: ToolRuntimeRestrictions::default(),
        runtime_handles: openbitfun_runtime_ports::ToolRuntimeHandles::default(),
    }
}

fn sha256_hex(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

fn resolved_policy(rules: Vec<PermissionRule>) -> ResolvedPermissionPolicy {
    ResolvedPermissionPolicy::new(rules, Vec::new())
}

// ---------------------------------------------------------------------------
// Prompt-visible tool manifest and exposure split
// ---------------------------------------------------------------------------

/// Baseline for the prompt-visible tool manifest of a fixed fixture context.
///
/// Owner: `agentic/tools/product_runtime/catalog.rs`
/// (`resolve_product_resolved_tool_manifest`,
/// `resolve_product_resolved_visible_tools`).
///
/// Off means: the same allowed policy produces the same gateways and the same
/// direct/deferred split. No tool is added to the prompt and no deferred
/// listing grows.
///
/// Scope of the assertions: they are driven by the explicitly supplied
/// `allowed_tools` filter applied to the registry snapshot. The resolution does
/// read that snapshot, but every asserted name comes from the explicit list, so
/// a tool that some feature set adds to the registry cannot appear in the
/// asserted result. That is the whole invariance claimed here, and it is a
/// static argument about the filter, not a claim about arbitrary feature sets.
/// This test does not consult the `Standard` agent policy, does not consult the
/// agent-derived availability catalogs, and does not pin the compiled feature
/// catalog itself.
///
/// Verification scope: the assertions were verified under
/// `--features agent-runtime,git` only. This test makes no claim about other
/// feature combinations, and it does not claim to hold for a narrow set that
/// removes a baseline tool such as `Read`, `Write`, or `SessionHistory`, which
/// would fail the assertions because the tool is absent.
///
/// This test does not cover the `GetToolSpec` answer. That behaviour is owned
/// and covered by the existing `GetToolSpec` owner tests, and it is not part of
/// the P0 delivery.
#[tokio::test]
async fn off_baseline_product_tool_manifest_matches_the_pinned_visibility() {
    let context = off_baseline_tool_context(Some("Standard"));
    let overrides = AgentToolPolicyOverrides::default();
    let allowed_tools = vec![
        "Read".to_string(),
        "Write".to_string(),
        "SessionHistory".to_string(),
    ];

    let manifest =
        resolve_product_resolved_tool_manifest(&allowed_tools, &overrides, &context).await;

    // `allowed_tool_names` keeps the caller order and appends the two deferred
    // execution gateways, because `SessionHistory` is deferred by default.
    let allowed_names = manifest
        .allowed_tool_names
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    assert_eq!(
        allowed_names,
        vec!["Read", "Write", "SessionHistory", "GetToolSpec", "CallDeferredTool"]
    );
    assert_eq!(manifest.deferred_tool_names, vec!["SessionHistory".to_string()]);

    // The model-facing definition list is the direct set plus the gateways; the
    // deferred tool contributes no schema until it is loaded.
    let definition_names = manifest
        .tool_definitions
        .iter()
        .map(|definition| definition.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        definition_names,
        vec!["Read", "Write", "GetToolSpec", "CallDeferredTool"]
    );

    // Exposure split from the same owner, independent of the manifest facade.
    let visible =
        resolve_product_resolved_visible_tools(&allowed_tools, &overrides, &context).await;
    let direct_names = visible
        .direct_tools
        .iter()
        .map(|tool| tool.name())
        .collect::<Vec<_>>();
    assert_eq!(
        direct_names,
        vec!["Read", "Write", "GetToolSpec", "CallDeferredTool"]
    );
    let deferred_names = visible
        .deferred_tools
        .iter()
        .map(|tool| tool.name())
        .collect::<Vec<_>>();
    assert_eq!(deferred_names, vec!["SessionHistory"]);
}

// ---------------------------------------------------------------------------
// Prepended reminder order
// ---------------------------------------------------------------------------

/// Baseline for the prepended reminder order.
///
/// Owner: `openbitfun_agent_runtime::prompt::PrependedPromptReminders`
/// (`prompt.rs`, `ordered_reminders`).
///
/// Off means: conversation-start reminders keep their historical slot order, so
/// turning workspace intelligence off cannot reorder or displace an existing
/// reminder.
#[test]
fn off_baseline_prepended_reminder_slot_order_is_pinned() {
    let all_slots = PrependedPromptReminders {
        deferred_tool_listing: Some("slot-deferred_tool_listing".to_string()),
        ptc_tool_calling_guide: Some("slot-ptc_tool_calling_guide".to_string()),
        skill_listing: Some("slot-skill_listing".to_string()),
        agent_listing: Some("slot-agent_listing".to_string()),
        runtime_context: Some("slot-runtime_context".to_string()),
        user_context: Some("slot-user_context".to_string()),
    };
    assert_eq!(
        all_slots.ordered_reminders(),
        vec![
            "slot-deferred_tool_listing",
            "slot-ptc_tool_calling_guide",
            "slot-skill_listing",
            "slot-agent_listing",
            "slot-runtime_context",
            "slot-user_context",
        ]
    );

    // A subset keeps the same relative order and injects nothing.
    let subset = PrependedPromptReminders {
        skill_listing: Some("slot-skill_listing".to_string()),
        user_context: Some("slot-user_context".to_string()),
        ..PrependedPromptReminders::default()
    };
    assert_eq!(
        subset.ordered_reminders(),
        vec!["slot-skill_listing", "slot-user_context"]
    );

    // A single slot carries no separator or decoration of its own.
    let single = PrependedPromptReminders {
        runtime_context: Some("slot-runtime_context".to_string()),
        ..PrependedPromptReminders::default()
    };
    assert_eq!(single.ordered_reminders(), vec!["slot-runtime_context"]);
}

/// The same order observed through the real prompt builder, so the pinned order
/// is not only a property of a hand-built struct.
#[tokio::test]
async fn off_baseline_prompt_builder_emits_reminders_in_the_pinned_order() {
    let tool_sections = ToolListingSections {
        deferred_tool_listing: Some(
            "<deferred_tools>\n- SessionHistory\n</deferred_tools>".to_string(),
        ),
        ptc_tool_calling_guide: Some("# Tool Calling Guide\n\nptc fixture guide".to_string()),
        skill_listing: Some("<available_skills>\n- pdf\n</available_skills>".to_string()),
        agent_listing: Some("<available_agents>\n- Explore\n</available_agents>".to_string()),
        direct_tool_listing: None,
    };
    let context = PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
        .with_tool_listing_sections(tool_sections)
        .with_runtime_context_needs(RuntimeContextNeeds::from_tool_names(["Read"]));
    let reminders = PromptBuilder::new(context)
        .build_prepended_reminders(&UserContextPolicy::empty().with_workspace_context())
        .await;

    let ordered = reminders.ordered_reminders();
    assert_eq!(ordered.len(), 6);
    assert!(
        ordered[0].starts_with("# Tool Calling Guide"),
        "unexpected first reminder: {:?}",
        ordered[0]
    );
    assert_eq!(ordered[1], "# Tool Calling Guide\n\nptc fixture guide");
    assert!(
        ordered[2].starts_with("# Skill Listing"),
        "unexpected third reminder: {:?}",
        ordered[2]
    );
    assert!(
        ordered[3].starts_with("# Agent Listing"),
        "unexpected fourth reminder: {:?}",
        ordered[3]
    );
    assert!(
        ordered[4].starts_with("# Runtime Context"),
        "unexpected fifth reminder: {:?}",
        ordered[4]
    );
    assert!(
        ordered[5].starts_with("# User Context"),
        "unexpected sixth reminder: {:?}",
        ordered[5]
    );
}

// ---------------------------------------------------------------------------
// Prompt text: digests plus independent structure
// ---------------------------------------------------------------------------

/// SHA-256 baseline of the prompt text a fixed fixture produces.
///
/// Owner: `agentic/agents/prompt_builder/prompt_builder_impl.rs`
/// (`get_workspace_context`, `get_project_layout`,
/// `build_runtime_context_reminder`, `build_user_context_reminder`,
/// `build_prompt_from_template`).
///
/// Off means: the system prompt, the user-context reminder, and the runtime
/// context reminder stay byte-identical, so the prompt-cache prefix is not
/// invalidated and no workspace intelligence fragment leaks in.
///
/// Provenance: captured on `d2efc1e7d5dbffc72cbe31f862bcd477ce54881f` with the
/// fixture below. Every input is a literal string, so the text does not depend
/// on the host OS, the workspace on disk, or the user's configuration. Only
/// placeholders with static substitution are used; `{LANGUAGE_PREFERENCE}`,
/// `{PERSONA}`, `{MEMORY_ROOT}`, `{READ_TERMINAL}`, and
/// `{DEEP_RESEARCH_REPORT_LINK}` read external state and are deliberately
/// absent.
#[tokio::test]
async fn off_baseline_prompt_text_digests_are_pinned() {
    let local_context = PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
        .with_related_paths(vec![
            RelatedPath {
                path: "packages/engine".to_string(),
                description: Some("Engine package".to_string()),
            },
            RelatedPath {
                path: "tools/legacy".to_string(),
                description: None,
            },
        ]);
    let local_builder = PromptBuilder::new(local_context);

    let remote_context = PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
        .with_remote_prompt_overlay(
            RemoteExecutionHints {
                connection_display_name: "dev-server".to_string(),
                kernel_name: "Linux".to_string(),
                hostname: "devbox".to_string(),
            },
            Some("\u{2514}\u{2500}\u{2500} src/\n    \u{2514}\u{2500}\u{2500} main.rs".to_string()),
        );
    let remote_builder = PromptBuilder::new(remote_context);

    let runtime_context_builder = PromptBuilder::new(
        PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
            .with_runtime_context_needs(RuntimeContextNeeds::from_tool_names(["Read"])),
    );

    let template_builder = PromptBuilder::new(PromptBuilderContext::new(
        FIXTURE_WORKSPACE_PATH,
        Some("session-pinned".to_string()),
        None,
    ));

    let runtime_context = runtime_context_builder
        .build_runtime_context_reminder()
        .await
        .expect("workspace tools must still produce a runtime context reminder");
    let local_user_context = local_builder
        .build_user_context_reminder(&UserContextPolicy::empty().with_workspace_context())
        .await
        .expect("workspace context must still produce a user context reminder");
    let template_prompt = template_builder
        .build_prompt_from_template(
            "before\n{FILE_REFERENCES}\nmid\n{COMPUTER_USE_GUIDANCE}\nafter\n{SESSION_ID}",
        )
        .await
        .expect("static placeholders must still substitute");

    let samples = [
        ("workspace_context_local", local_builder.get_workspace_context()),
        ("workspace_context_remote", remote_builder.get_workspace_context()),
        ("project_layout_remote", remote_builder.get_project_layout()),
        ("runtime_context", runtime_context),
        ("user_context_workspace_only", local_user_context),
        ("prompt_template", template_prompt),
    ];

    let pinned = [
        // workspace_context_local
        "92864f4af14ad8417217f185d02fa1115b7e0d85c3cc56ad7848afc16a8226f7",
        // workspace_context_remote
        "a38d50e07d77bcd0c01a720b051a3400f959155c4d5b4c245b88c9a2523f5165",
        // project_layout_remote
        "605c26f4d95eb7db617204193aedf96bbe969fad89d047903ed90733c437999f",
        // runtime_context
        "af7262b4a34445b7e30e83dd1c4aab13b699e8be4c315c719c7a1062010f6a5f",
        // user_context_workspace_only
        "9d94d6d3d09f806183144e4956c3190fe1cc8bff9ecc0ebb9aeb952ac5af4916",
        // prompt_template
        "dd5534d266779fbef80304a80c91fdbb51fcbc6850ecfe369e05417636d4427b",
    ];
    assert_eq!(pinned.len(), samples.len());
    for (index, (label, text)) in samples.iter().enumerate() {
        assert_eq!(
            sha256_hex(text),
            pinned[index],
            "prompt text drifted for {label}; captured text: {text:?}"
        );
    }
}

/// SHA-256 baseline of the memory reminder the off path renders from a fixture root.
///
/// Owner: `agentic/agents/prompt_builder/prompt_builder_impl.rs`
/// (`build_user_context_reminder`).
///
/// Off means: the memory section is still built from the legacy memory root and its
/// `memory_summary.md`, byte for byte, and no scoped workspace intelligence content
/// reaches the prompt.
///
/// The fixture root is a temporary directory, so both textual forms of that path are
/// replaced by the literal `{MEMORY_ROOT}` before hashing: the pin covers the
/// reminder text, not the temp path one run happened to receive. That is why this
/// test does mention `{MEMORY_ROOT}` while the prompt-text pin above deliberately
/// avoids it.
#[tokio::test]
async fn off_baseline_memory_reminder_digest_is_pinned() {
    const FIXTURE_SUMMARY: &str = "Off baseline memory summary: one fixed sentence.";

    let root = tempfile::tempdir().expect("temporary root");
    let memory_root = root.path().join("memories");
    std::fs::create_dir_all(&memory_root).expect("create the fixture memory root");
    std::fs::write(memory_root.join("memory_summary.md"), FIXTURE_SUMMARY)
        .expect("write the fixture memory summary");

    let context = PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
        .with_memory_root_for_tests(memory_root.clone())
        .with_memory_enabled_for_tests(true);
    let reminder = PromptBuilder::new(context)
        .build_user_context_reminder(&UserContextPolicy::empty().with_memory_summary())
        .await
        .expect("the memory section must produce a reminder");

    let raw_path = memory_root.to_string_lossy().to_string();
    let normalized = reminder
        .replace(&raw_path.replace('\\', "/"), "{MEMORY_ROOT}")
        .replace(&raw_path, "{MEMORY_ROOT}");

    assert!(
        !normalized.contains(&raw_path) && !normalized.contains(&raw_path.replace('\\', "/")),
        "the fixture root path must not survive normalization"
    );
    assert!(normalized.contains("## Memory"));
    assert!(normalized.contains(FIXTURE_SUMMARY));
    assert_eq!(
        sha256_hex(&normalized),
        "493acd5f3292668db33c51d0415f41da9c296463e9f2b15e73bdb860ea12d4e3"
    );
}

/// Independent structural baseline of the same prompt text: literal section and
/// keyword sequences, so the digest above is not the only expectation.
#[tokio::test]
async fn off_baseline_prompt_structure_matches_the_pinned_sections() {
    let builder = PromptBuilder::new(
        PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None).with_related_paths(vec![
            RelatedPath {
                path: "packages/engine".to_string(),
                description: Some("Engine package".to_string()),
            },
            RelatedPath {
                path: "tools/legacy".to_string(),
                description: None,
            },
        ]),
    );

    let workspace_context = builder.get_workspace_context();
    assert!(
        workspace_context.starts_with(
            "## Workspace Context\n<workspace_context>\n- Current Working Directory: /fixtures/wi-p0/workspace\n"
        ),
        "unexpected workspace context head: {workspace_context:?}"
    );
    let ordered_markers = [
        "- Related directories (user-specified directories related to this workspace):",
        "  - packages/engine \u{2014} Engine package",
        "  - tools/legacy",
        "</workspace_context>",
    ];
    let mut cursor = 0;
    for marker in ordered_markers {
        let found = workspace_context[cursor..].find(marker).unwrap_or_else(|| {
            panic!(
                "workspace context marker {marker:?} missing or out of order: {workspace_context:?}"
            )
        });
        cursor += found + marker.len();
    }
    assert!(workspace_context.ends_with("</workspace_context>\n"));

    let runtime_context = PromptBuilder::new(
        PromptBuilderContext::new(FIXTURE_WORKSPACE_PATH, None, None)
            .with_runtime_context_needs(RuntimeContextNeeds::from_tool_names(["Read"])),
    )
    .build_runtime_context_reminder()
    .await
    .expect("workspace tools must still produce a runtime context reminder");
    assert_eq!(
        runtime_context,
        "# Runtime Context\n\n## Workspace Execution\n- Workspace file and shell tools operate on the local filesystem."
    );
    for absent in [
        "## ExecCommand Shell",
        "## Local Client",
        "ExecCommand shell:",
        "## ExecControl",
    ] {
        assert!(
            !runtime_context.contains(absent),
            "runtime context gained an unexpected section {absent:?}: {runtime_context:?}"
        );
    }

    let user_context = builder
        .build_user_context_reminder(&UserContextPolicy::empty().with_workspace_context())
        .await
        .expect("workspace context must still produce a user context reminder");
    assert!(
        user_context.starts_with(
            "# User Context\nAs you answer the user's questions, you can use the following context.\nNote: this is a snapshot captured at the start of the conversation and may not reflect real-time changes made afterward.\n\n## Workspace Context\n<workspace_context>\n"
        ),
        "unexpected user context head: {user_context:?}"
    );
    assert!(user_context.ends_with("</workspace_context>"));
}

// ---------------------------------------------------------------------------
// Prompt cache identity
// ---------------------------------------------------------------------------

/// Baseline for the prompt-cache scope key.
///
/// Owner: `openbitfun_agent_runtime::prompt_cache::prompt_cache_scope_key`
/// (`prompt_cache.rs`).
///
/// Off means: the composition stays a plain delimiter join of the two identity
/// strings, so a workspace intelligence toggle cannot silently change cache
/// identity for an unchanged scope.
#[test]
fn off_baseline_prompt_cache_scope_key_is_pinned() {
    let system = SystemPromptCacheIdentity::new("system|Standard|fixture");
    let user = UserContextCacheIdentity::new("workspace_context|project_layout");
    assert_eq!(
        prompt_cache_scope_key(&system, &user),
        "system|Standard|fixture||workspace_context|project_layout"
    );

    assert_eq!(
        prompt_cache_scope_key(
            &SystemPromptCacheIdentity::new("a"),
            &UserContextCacheIdentity::new("b")
        ),
        "a||b"
    );
    assert_eq!(
        prompt_cache_scope_key(
            &SystemPromptCacheIdentity::new(""),
            &UserContextCacheIdentity::new("")
        ),
        "||"
    );

    // Identity values are kept verbatim.
    assert_eq!(
        SystemPromptCacheIdentity::new("kept verbatim").scope_key,
        "kept verbatim"
    );
    assert_eq!(
        UserContextCacheIdentity::new("kept verbatim").scope_key,
        "kept verbatim"
    );
}

// ---------------------------------------------------------------------------
// Approval decision sequence and approval defaults
// ---------------------------------------------------------------------------

/// Baseline for the ordered approval decision sequence.
///
/// Owner: `openbitfun_agent_runtime::permission::plan_permission_intents`
/// (`permission.rs`) with the product-domain permission policy contract.
///
/// Off means: the existing static policy plus remembered grants still produce
/// the same plan, `RequiresApproval` still keeps the intent order, and a denial
/// still short-circuits the whole set. Workspace intelligence adds no approval
/// step and closes no existing one.
#[test]
fn off_baseline_permission_plan_sequence_is_pinned() {
    let policy = resolved_policy(vec![
        PermissionRule::new("read", "*", PermissionEffect::Allow),
        PermissionRule::new("write", "*", PermissionEffect::Ask),
        PermissionRule::new("bash", "rm -rf *", PermissionEffect::Deny),
    ]);
    let read_a = PermissionIntent::new("read", vec!["src/a.rs".to_string()]);
    let write_b = PermissionIntent::new("write", vec!["src/b.rs".to_string()]);
    let read_c = PermissionIntent::new("read", vec!["src/c.rs".to_string()]);

    // Ask entries keep their input order.
    let plan = plan_permission_intents(
        vec![read_a.clone(), write_b.clone(), read_c.clone()],
        &policy,
        &[],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    let PermissionIntentPlan::RequiresApproval(approvals) = plan else {
        panic!("an ask intent must still require approval, got {plan:?}");
    };
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].action, "write");
    assert_eq!(approvals[0].resources, vec!["src/b.rs".to_string()]);

    // Two asks stay in input order.
    let write_d = PermissionIntent::new("write", vec!["src/d.rs".to_string()]);
    let plan = plan_permission_intents(
        vec![write_b.clone(), read_a.clone(), write_d.clone()],
        &policy,
        &[],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    let PermissionIntentPlan::RequiresApproval(approvals) = plan else {
        panic!("ask intents must still require approval in order, got {plan:?}");
    };
    assert_eq!(
        approvals
            .iter()
            .map(|intent| (intent.action.as_str(), intent.resources.clone()))
            .collect::<Vec<_>>(),
        vec![
            ("write", vec!["src/b.rs".to_string()]),
            ("write", vec!["src/d.rs".to_string()]),
        ]
    );

    // A denial short-circuits the whole set at the denying intent.
    let deny = PermissionIntent::new("bash", vec!["rm -rf build".to_string()]);
    let plan = plan_permission_intents(
        vec![read_a.clone(), deny.clone(), write_b.clone()],
        &policy,
        &[],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    let PermissionIntentPlan::Denied(denied) = plan else {
        panic!("a deny intent must still short-circuit the set, got {plan:?}");
    };
    assert_eq!(denied.action, "bash");
    assert_eq!(denied.resources, vec!["rm -rf build".to_string()]);

    // Everything allowed stays allowed and creates no approval request.
    let plan = plan_permission_intents(
        vec![read_a.clone(), read_c.clone()],
        &policy,
        &[],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    assert_eq!(plan, PermissionIntentPlan::Allowed);

    // A remembered grant still satisfies an ask intent.
    let grant = PermissionGrant {
        project_id: "fixture-project".to_string(),
        action: "write".to_string(),
        resource: "src/b.rs".to_string(),
        created_at_ms: 0,
    };
    let plan = plan_permission_intents(
        vec![read_a, write_b],
        &policy,
        &[grant],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    assert_eq!(plan, PermissionIntentPlan::Allowed);

    // An intent without resources still fails closed as an approval request.
    let plan = plan_permission_intents(
        vec![PermissionIntent::new("read", Vec::new())],
        &policy,
        &[],
        PermissionResourceCaseSensitivity::Sensitive,
    );
    assert!(matches!(plan, PermissionIntentPlan::RequiresApproval(_)));
}

/// Baseline for the approval configuration that carries the model-approval path.
///
/// Owner: `openbitfun_product_domains::tool_permissions`
/// (`PermissionApprovalConfig`, `PermissionApprovalStrategy`, `PermissionMode`)
/// and `openbitfun_agent_runtime::permission` consumers.
///
/// Off means: the default strategy is still `Interactive` (model approval is not
/// disabled, only off by default), the timeout bounds are unchanged, and a
/// stored approval record still round-trips, so existing sessions keep their
/// approval behavior.
#[test]
fn off_baseline_permission_approval_defaults_stay_interactive() {
    let default = PermissionApprovalConfig::default();
    assert_eq!(default.strategy, PermissionApprovalStrategy::Interactive);
    assert_eq!(default.model_kind, PermissionApprovalModelKind::Chat);
    assert_eq!(default.chat_model_id, "fast");
    assert_eq!(default.timeout_ms, 30_000);
    assert_eq!(default.on_ask, PermissionApprovalOnAsk::User);
    assert_eq!(default.on_error, PermissionApprovalOnError::Ask);
    assert!(PermissionApprovalConfig::is_default(&default));
    assert_eq!(default.validate(), Ok(()));

    // The session/turn mode default is unchanged: a turn without an explicit
    // mode still resolves to `Ask`, and the stored-record projection still maps
    // presets to modes one to one.
    assert_eq!(PermissionMode::default(), PermissionMode::Ask);
    assert_eq!(
        PermissionMode::from_config(&ToolPermissionConfig {
            policy: PermissionPolicyConfig {
                preset: PermissionPolicyPreset::Ask,
                ..PermissionPolicyConfig::default()
            },
            ..ToolPermissionConfig::default()
        }),
        PermissionMode::Ask
    );
    assert_eq!(
        PermissionMode::from_config(&ToolPermissionConfig::default()),
        PermissionMode::FullAccess,
        "the bare stored record still defaults to the FullAccess preset"
    );

    // Timeout validation boundaries are unchanged.
    let with_timeout = |timeout_ms: u64| PermissionApprovalConfig {
        timeout_ms,
        ..PermissionApprovalConfig::default()
    };
    let timeout_error =
        Err("permission approval timeout_ms must be between 1 and 300000".to_string());
    assert_eq!(with_timeout(0).validate(), timeout_error);
    assert_eq!(with_timeout(300_001).validate(), timeout_error);
    assert_eq!(with_timeout(1).validate(), Ok(()));
    assert_eq!(with_timeout(300_000).validate(), Ok(()));

    // Model approval still requires a chat model id when it is selected.
    let selected = PermissionApprovalConfig {
        strategy: PermissionApprovalStrategy::Model,
        ..PermissionApprovalConfig::default()
    };
    assert_eq!(selected.validate(), Ok(()));
    let missing_model = PermissionApprovalConfig {
        chat_model_id: "   ".to_string(),
        ..selected
    };
    assert_eq!(
        missing_model.validate(),
        Err("chat approval strategy requires a chat_model_id".to_string())
    );

    // Persisted approval configuration stays readable in both directions, so an
    // older record keeps its meaning.
    let wire = serde_json::to_value(PermissionApprovalConfig::default())
        .expect("approval configuration must serialize");
    assert_eq!(wire["strategy"], json!("interactive"));
    assert_eq!(wire["timeout_ms"], json!(30_000));
    let round_trip: PermissionApprovalConfig =
        serde_json::from_value(wire).expect("approval configuration must deserialize");
    assert_eq!(round_trip, PermissionApprovalConfig::default());
    let restored: PermissionApprovalConfig = serde_json::from_value(json!({}))
        .expect("a record without the approval section must stay readable");
    assert_eq!(restored, PermissionApprovalConfig::default());
}

// ---------------------------------------------------------------------------
// Layered approval-strategy resolution
// ---------------------------------------------------------------------------

/// Baseline for the four-layer approval-strategy resolution.
///
/// Owner: `agentic/permission_policy.rs::resolve_approval_strategy`, the single
/// resolver the round executor and the workspace-intelligence permission commit
/// point both call. Before this test the four layers lived inline in the round
/// executor and had no coverage.
///
/// Off means: the same four layers in the same order, so a turn keeps the
/// approval strategy it started with and workspace intelligence adds no layer.
#[test]
fn off_baseline_approval_strategy_resolution_is_pinned() {
    fn resolve(
        global: &crate::service::config::types::GlobalConfig,
        context: &[(&str, &str)],
    ) -> PermissionApprovalStrategy {
        let context_vars = context
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect::<HashMap<String, String>>();
        crate::agentic::permission_policy::resolve_approval_strategy(global, &context_vars)
    }

    let strategy_key =
        openbitfun_agent_runtime::permission::PERMISSION_APPROVAL_STRATEGY_CONTEXT_KEY;
    let mode_key = openbitfun_agent_runtime::permission::PERMISSION_MODE_CONTEXT_KEY;

    // The stored configuration alone asks for model approval.
    let mut stored_model = crate::service::config::types::GlobalConfig::default();
    stored_model.tool_permissions.approval.strategy = PermissionApprovalStrategy::Model;
    stored_model.tool_permissions.interaction.auto_approve_ask = false;

    // (a) The submission's own strategy outranks the stored model strategy.
    assert_eq!(
        resolve(&stored_model, &[(strategy_key, "interactive")]),
        PermissionApprovalStrategy::Interactive
    );
    // (b) The immediate-allow layer is reachable from the same key.
    assert_eq!(
        resolve(&stored_model, &[(strategy_key, "immediate_allow")]),
        PermissionApprovalStrategy::ImmediateAllow
    );
    // (c) An explicit model selection is kept verbatim, including case and padding.
    assert_eq!(
        resolve(&stored_model, &[(strategy_key, "  MODEL ")]),
        PermissionApprovalStrategy::Model
    );

    // (d) An AutoApprove permission mode resolves to model approval.
    let mut interactive = crate::service::config::types::GlobalConfig::default();
    interactive.tool_permissions.approval.strategy = PermissionApprovalStrategy::Interactive;
    interactive.tool_permissions.interaction.auto_approve_ask = false;
    assert_eq!(
        resolve(&interactive, &[(mode_key, PermissionMode::AutoApprove.as_str())]),
        PermissionApprovalStrategy::Model
    );
    // A non-AutoApprove mode keeps the stored strategy.
    assert_eq!(
        resolve(&interactive, &[(mode_key, PermissionMode::Ask.as_str())]),
        PermissionApprovalStrategy::Interactive
    );

    // (e) The legacy persisted auto-approve flag still resolves to model approval.
    let mut legacy = interactive.clone();
    legacy.tool_permissions.interaction.auto_approve_ask = true;
    assert_eq!(
        resolve(&legacy, &[]),
        PermissionApprovalStrategy::Model
    );

    // (f) Without any override the stored configuration decides.
    assert_eq!(
        resolve(&stored_model, &[]),
        PermissionApprovalStrategy::Model
    );

    // (g) The empty default resolves to the unchanged interactive default.
    assert_eq!(
        resolve(
            &crate::service::config::types::GlobalConfig::default(),
            &[]
        ),
        PermissionApprovalStrategy::Interactive
    );

    // An unknown strategy value never selects a strategy; it falls through.
    assert_eq!(
        resolve(&interactive, &[(strategy_key, "unheard_of")]),
        PermissionApprovalStrategy::Interactive
    );
}
