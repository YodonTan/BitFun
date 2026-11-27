use crate::service::config::global::GlobalConfigManager;
use crate::service::config::types::{AgentProfileConfig, GlobalConfig};
use crate::util::errors::OpenBitFunResult;
use openbitfun_agent_runtime::permission::{
    AUTO_APPROVE_ASK_CONTEXT_KEY, PERMISSION_MODE_CONTEXT_KEY,
};
use openbitfun_runtime_ports::{
    resolve_child_permission_policy, resolve_permission_policy, ChildPermissionPolicyLayers,
    PermissionApprovalStrategy, PermissionConstraintLayer, PermissionEffect, PermissionMode,
    PermissionPolicyLayers, PermissionRule, PermissionRuntimeCeiling, ResolvedPermissionPolicy,
};

/// Reads the effective mode a submission carried into tool execution.
///
/// The owning surface resolves the layered selection once and writes it to the
/// execution context, so this is a lookup and not a second resolution. The
/// legacy auto-approve flag is still honored for submissions and product
/// surfaces that predate the mode key.
pub(crate) fn permission_mode_from_context(
    global: &GlobalConfig,
    context_vars: &std::collections::HashMap<String, String>,
) -> PermissionMode {
    if let Some(mode) = context_vars
        .get(PERMISSION_MODE_CONTEXT_KEY)
        .map(String::as_str)
        .and_then(PermissionMode::parse)
    {
        return mode;
    }

    let default_mode = PermissionMode::from_config(&global.tool_permissions);
    match context_vars
        .get(AUTO_APPROVE_ASK_CONTEXT_KEY)
        .and_then(|value| value.parse::<bool>().ok())
    {
        // A legacy flag only speaks for the auto-approval half. It must not
        // downgrade a full-access selection that the same turn resolved.
        Some(true) if default_mode != PermissionMode::FullAccess => PermissionMode::AutoApprove,
        Some(false) if default_mode == PermissionMode::AutoApprove => PermissionMode::Ask,
        _ => default_mode,
    }
}

/// Reads the approval strategy a submission explicitly carried into tool
/// execution.
///
/// This is the top layer of the approval resolution: a turn that selected a
/// strategy writes it to the execution context, so a present value outranks
/// every configuration layer below it. An unknown or absent value yields `None`
/// and the lower layers decide.
pub(crate) fn context_approval_strategy(
    context_vars: &std::collections::HashMap<String, String>,
) -> Option<PermissionApprovalStrategy> {
    context_vars
        .get(openbitfun_agent_runtime::permission::PERMISSION_APPROVAL_STRATEGY_CONTEXT_KEY)
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "interactive" => Some(PermissionApprovalStrategy::Interactive),
            "immediate_allow" => Some(PermissionApprovalStrategy::ImmediateAllow),
            "model" => Some(PermissionApprovalStrategy::Model),
            _ => None,
        })
}

/// Resolves one round's approval strategy from the four existing layers.
///
/// Order, unchanged from the round executor that used to inline it: the
/// strategy the submission carried, then an `AutoApprove` permission mode, then
/// the legacy persisted `auto_approve_ask` flag, then the stored approval
/// configuration. It reads no clock, no storage and no workspace intelligence
/// fact, so the OFF path resolves exactly as it always did.
pub(crate) fn resolve_approval_strategy(
    global: &GlobalConfig,
    context_vars: &std::collections::HashMap<String, String>,
) -> PermissionApprovalStrategy {
    let legacy_auto_approval = global.tool_permissions.interaction.auto_approve_ask;
    context_approval_strategy(context_vars)
        .or_else(|| {
            context_vars
                .get(openbitfun_agent_runtime::permission::PERMISSION_MODE_CONTEXT_KEY)
                .and_then(|value| PermissionMode::parse(value))
                .and_then(|mode| {
                    (mode == PermissionMode::AutoApprove)
                        .then_some(PermissionApprovalStrategy::Model)
                })
        })
        .or_else(|| legacy_auto_approval.then_some(PermissionApprovalStrategy::Model))
        .unwrap_or(global.tool_permissions.approval.strategy)
}

/// Resolves the strategy the permission commit point must use.
///
/// The round-start snapshot stays authoritative unless every condition holds:
/// workspace intelligence is on for this workspace (`scoped_permits`), the fresh
/// configuration was readable (`fresh`), and nothing pinned the strategy already
/// (`pinned`, i.e. a CLI `--auto` run or a hook that explicitly asked for user
/// confirmation). A failure at any of those layers keeps the snapshot; none of
/// them rejects the request.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
pub(crate) fn commit_point_approval_strategy(
    scoped_permits: bool,
    pinned: bool,
    fresh: Option<&GlobalConfig>,
    context_vars: &std::collections::HashMap<String, String>,
    snapshot: PermissionApprovalStrategy,
) -> PermissionApprovalStrategy {
    if !scoped_permits || pinned {
        return snapshot;
    }
    match fresh {
        Some(global) => resolve_approval_strategy(global, context_vars),
        None => snapshot,
    }
}

/// Loads the current global configuration, or reports why it is unavailable.
///
/// The permission commit point re-reads the same configuration the round start
/// read, through the same service, so the two cannot disagree about where the
/// configuration lives.
///
/// The failure policy deliberately differs from the round start's: the round
/// start falls back to `GlobalConfig::default()`, while a commit-point failure
/// keeps the round-start snapshot. A round that could not read its configuration
/// already decided with the default, and a later read must not silently replace
/// that decision with a different default.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
pub(crate) async fn load_global_config() -> OpenBitFunResult<GlobalConfig> {
    let service = GlobalConfigManager::get_service().await?;
    service.get_config(None).await
}

pub(crate) fn derive_parent_permission_runtime_ceiling(
    agent_profile: Option<&AgentProfileConfig>,
    agent_definition_constraints: Option<&PermissionConstraintLayer>,
) -> PermissionRuntimeCeiling {
    let mut rules: Vec<PermissionRule> = agent_profile
        .into_iter()
        .flat_map(|profile| profile.tool_permission_rules.iter())
        .filter(|rule| {
            rule.effect == PermissionEffect::Deny
                || (rule.action == "external_directory" && rule.effect == PermissionEffect::Ask)
        })
        .cloned()
        .collect();
    rules.extend(
        agent_definition_constraints
            .into_iter()
            .flat_map(PermissionConstraintLayer::rules)
            .filter(|rule| rule.effect != PermissionEffect::Allow)
            .cloned(),
    );

    PermissionRuntimeCeiling::try_new(rules)
        .expect("parent permission ceiling extraction must exclude allow rules")
}

pub(crate) async fn load_parent_permission_runtime_ceiling(
    agent_type: Option<&str>,
    workspace_id: Option<&str>,
) -> OpenBitFunResult<PermissionRuntimeCeiling> {
    let service = GlobalConfigManager::get_service().await?;
    let global: GlobalConfig = service.get_config(None).await?;
    let profile = agent_type.and_then(|agent_type| {
        let profile_id = crate::agentic::agents::resolve_mode_config_profile_id(agent_type);
        global.ai.agent_profiles.get(profile_id.as_ref())
    });
    let definition_constraints = agent_type.and_then(|agent_type| {
        crate::agentic::agents::get_agent_registry()
            .get_agent(agent_type, workspace_id)
            .map(|agent| agent.permission_constraints().clone())
    });
    Ok(derive_parent_permission_runtime_ceiling(
        profile,
        definition_constraints.as_ref(),
    ))
}

/// Resolves one turn's effective policy.
///
/// `mode` is the already-resolved turn/session/global selection. It only
/// replaces the preset baseline; every later layer (global rules, project,
/// agent, enforced, and the constraint layers appended below) is evaluated
/// afterwards and can still tighten the result.
pub(crate) fn resolve_effective_permission_policy(
    global: &GlobalConfig,
    mode: Option<PermissionMode>,
    project_rules: &[PermissionRule],
    agent_profile: Option<&AgentProfileConfig>,
    agent_definition_constraints: Option<&PermissionConstraintLayer>,
    parent_runtime_ceiling: Option<&PermissionRuntimeCeiling>,
    enforced: &[PermissionRule],
) -> ResolvedPermissionPolicy {
    let agent_rules = agent_profile
        .map(|profile| profile.tool_permission_rules.as_slice())
        .unwrap_or(&[]);

    let resolved = match parent_runtime_ceiling {
        Some(parent_runtime_ceiling) => {
            resolve_child_permission_policy(ChildPermissionPolicyLayers {
                product_defaults: &[],
                global: &global.tool_permissions.policy,
                mode,
                project: project_rules,
                child_agent: agent_rules,
                parent_runtime_ceiling,
                enforced,
            })
        }
        None => resolve_permission_policy(PermissionPolicyLayers {
            product_defaults: &[],
            global: &global.tool_permissions.policy,
            mode,
            project: project_rules,
            agent: agent_rules,
            enforced,
        }),
    };
    let Some(agent_definition_constraints) =
        agent_definition_constraints.filter(|constraints| !constraints.is_empty())
    else {
        return resolved;
    };
    let (rules, mut constraint_layers) = resolved.into_parts();
    constraint_layers.insert(0, agent_definition_constraints.clone());
    ResolvedPermissionPolicy::new(rules, constraint_layers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbitfun_runtime_ports::{PermissionEvaluator, PermissionPolicyPreset};

    fn rule(action: &str, resource: &str, effect: PermissionEffect) -> PermissionRule {
        PermissionRule::new(action, resource, effect)
    }

    #[test]
    fn context_mode_key_outranks_the_legacy_auto_approve_flag() {
        let mut global = GlobalConfig::default();
        global.tool_permissions.policy.preset =
            openbitfun_runtime_ports::PermissionPolicyPreset::Ask;
        global.tool_permissions.interaction.auto_approve_ask = true;
        let mut context_vars = std::collections::HashMap::new();

        assert_eq!(
            permission_mode_from_context(&global, &context_vars),
            PermissionMode::AutoApprove
        );

        context_vars.insert(
            PERMISSION_MODE_CONTEXT_KEY.to_string(),
            "full_access".to_string(),
        );
        context_vars.insert(
            AUTO_APPROVE_ASK_CONTEXT_KEY.to_string(),
            "false".to_string(),
        );
        assert_eq!(
            permission_mode_from_context(&global, &context_vars),
            PermissionMode::FullAccess
        );
    }

    #[test]
    fn legacy_auto_approve_flag_never_downgrades_a_full_access_default() {
        let mut global = GlobalConfig::default();
        global.tool_permissions.policy.preset = PermissionPolicyPreset::FullAccess;
        let mut context_vars = std::collections::HashMap::new();
        context_vars.insert(AUTO_APPROVE_ASK_CONTEXT_KEY.to_string(), "true".to_string());

        assert_eq!(
            permission_mode_from_context(&global, &context_vars),
            PermissionMode::FullAccess
        );
    }

    #[test]
    fn session_full_access_mode_is_still_bounded_by_project_rules() {
        let global = GlobalConfig::default();
        let project = vec![rule("edit", "generated/*", PermissionEffect::Deny)];

        let resolved = resolve_effective_permission_policy(
            &global,
            Some(PermissionMode::FullAccess),
            &project,
            None,
            None,
            None,
            &[],
        );
        let evaluator = PermissionEvaluator::case_sensitive();

        assert_eq!(
            evaluator.evaluate_policy_resource("edit", "src/main.rs", &resolved),
            PermissionEffect::Allow
        );
        assert_eq!(
            evaluator.evaluate_policy_resource("edit", "generated/api.rs", &resolved),
            PermissionEffect::Deny
        );
    }

    #[test]
    fn parent_ceiling_combines_profile_and_agent_constraints_without_allows() {
        let profile = AgentProfileConfig {
            tool_permission_rules: vec![
                rule("read", "*", PermissionEffect::Allow),
                rule("bash", "rm *", PermissionEffect::Deny),
                rule("edit", "src/*", PermissionEffect::Ask),
                rule("external_directory", "*", PermissionEffect::Ask),
                rule("external_directory", "C:/blocked", PermissionEffect::Deny),
                rule("external_directory", "C:/trusted", PermissionEffect::Allow),
            ],
            ..AgentProfileConfig::default()
        };

        let definition_constraints = PermissionConstraintLayer::new(vec![
            rule("bash", "git push *", PermissionEffect::Ask),
            rule("bash", "git status", PermissionEffect::Allow),
            rule("edit", "secrets/*", PermissionEffect::Deny),
        ]);
        let ceiling =
            derive_parent_permission_runtime_ceiling(Some(&profile), Some(&definition_constraints));

        assert_eq!(
            ceiling.rules(),
            [
                rule("bash", "rm *", PermissionEffect::Deny),
                rule("external_directory", "*", PermissionEffect::Ask),
                rule("external_directory", "C:/blocked", PermissionEffect::Deny),
                rule("bash", "git push *", PermissionEffect::Ask),
                rule("edit", "secrets/*", PermissionEffect::Deny),
            ]
        );
        assert!(ceiling
            .rules()
            .iter()
            .all(|rule| rule.effect != PermissionEffect::Allow));
    }

    #[test]
    fn top_level_resolution_keeps_existing_global_project_and_agent_order() {
        let mut global = GlobalConfig::default();
        global.tool_permissions.policy.preset = PermissionPolicyPreset::FullAccess;
        global.tool_permissions.policy.rules = vec![rule("bash", "rm *", PermissionEffect::Ask)];
        let project = vec![rule("edit", "generated/*", PermissionEffect::Deny)];
        let profile = AgentProfileConfig {
            tool_permission_rules: vec![rule(
                "edit",
                "generated/review.md",
                PermissionEffect::Allow,
            )],
            ..AgentProfileConfig::default()
        };

        let resolved = resolve_effective_permission_policy(
            &global,
            None,
            &project,
            Some(&profile),
            None,
            None,
            &[],
        );

        assert_eq!(
            PermissionEvaluator::case_sensitive().evaluate_policy_resource(
                "edit",
                "generated/review.md",
                &resolved,
            ),
            PermissionEffect::Allow
        );
        assert_eq!(
            PermissionEvaluator::case_sensitive().evaluate_policy_resource(
                "edit",
                "generated/api.rs",
                &resolved,
            ),
            PermissionEffect::Deny
        );
    }

    #[test]
    fn child_profile_allow_cannot_loosen_parent_deny_or_external_directory_ask() {
        let mut global = GlobalConfig::default();
        global.tool_permissions.policy.preset = PermissionPolicyPreset::FullAccess;
        let child_profile = AgentProfileConfig {
            tool_permission_rules: vec![
                rule("bash", "rm *", PermissionEffect::Allow),
                rule("external_directory", "*", PermissionEffect::Allow),
            ],
            ..AgentProfileConfig::default()
        };
        let ceiling = PermissionRuntimeCeiling::try_new(vec![
            rule("bash", "rm *", PermissionEffect::Deny),
            rule("external_directory", "*", PermissionEffect::Ask),
        ])
        .expect("test ceiling should be valid");

        let resolved = resolve_effective_permission_policy(
            &global,
            None,
            &[],
            Some(&child_profile),
            None,
            Some(&ceiling),
            &[],
        );
        let evaluator = PermissionEvaluator::case_sensitive();

        assert_eq!(
            evaluator.evaluate_policy_resource("bash", "rm -rf target", &resolved),
            PermissionEffect::Deny
        );
        assert_eq!(
            evaluator.evaluate_policy_resource("external_directory", "C:/outside", &resolved),
            PermissionEffect::Ask
        );
    }

    #[test]
    fn the_layered_approval_resolution_keeps_its_four_layers() {
        let mut global = GlobalConfig::default();
        let mut context_vars = std::collections::HashMap::new();
        let strategy_key =
            openbitfun_agent_runtime::permission::PERMISSION_APPROVAL_STRATEGY_CONTEXT_KEY;

        // Layer one: the strategy the submission itself carried.
        context_vars.insert(strategy_key.to_string(), "immediate_allow".to_string());
        global.tool_permissions.interaction.auto_approve_ask = true;
        global.tool_permissions.approval.strategy = PermissionApprovalStrategy::Interactive;
        assert_eq!(
            resolve_approval_strategy(&global, &context_vars),
            PermissionApprovalStrategy::ImmediateAllow
        );

        // Layer two: an AutoApprove permission mode resolves to model approval.
        context_vars.clear();
        global.tool_permissions.interaction.auto_approve_ask = false;
        context_vars.insert(
            PERMISSION_MODE_CONTEXT_KEY.to_string(),
            PermissionMode::AutoApprove.as_str().to_string(),
        );
        assert_eq!(
            resolve_approval_strategy(&global, &context_vars),
            PermissionApprovalStrategy::Model
        );

        // Layer three: the legacy persisted flag still resolves to model approval.
        context_vars.clear();
        global.tool_permissions.interaction.auto_approve_ask = true;
        assert_eq!(
            resolve_approval_strategy(&global, &context_vars),
            PermissionApprovalStrategy::Model
        );

        // Layer four: the stored configuration decides when nothing else does.
        global.tool_permissions.interaction.auto_approve_ask = false;
        global.tool_permissions.approval.strategy = PermissionApprovalStrategy::ImmediateAllow;
        assert_eq!(
            resolve_approval_strategy(&global, &context_vars),
            PermissionApprovalStrategy::ImmediateAllow
        );
    }

    #[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
    #[test]
    fn the_commit_point_keeps_the_snapshot_unless_the_workspace_is_on() {
        let mut fresh = GlobalConfig::default();
        fresh.tool_permissions.approval.strategy = PermissionApprovalStrategy::Model;
        let context_vars = std::collections::HashMap::new();
        let snapshot = PermissionApprovalStrategy::Interactive;

        // OFF: workspace intelligence is not on for this workspace.
        assert_eq!(
            commit_point_approval_strategy(false, false, Some(&fresh), &context_vars, snapshot),
            snapshot
        );
        // An unreadable configuration keeps the snapshot instead of failing the request.
        assert_eq!(
            commit_point_approval_strategy(true, false, None, &context_vars, snapshot),
            snapshot
        );
        // An invocation-scoped strategy (`--auto`) is never re-read.
        assert_eq!(
            commit_point_approval_strategy(true, true, Some(&fresh), &context_vars, snapshot),
            snapshot
        );
        // ON: the fresh layered resolution decides.
        assert_eq!(
            commit_point_approval_strategy(true, false, Some(&fresh), &context_vars, snapshot),
            PermissionApprovalStrategy::Model
        );
        // ON still honors the submission layer inside the fresh resolution.
        let mut overridden = std::collections::HashMap::new();
        let strategy_key =
            openbitfun_agent_runtime::permission::PERMISSION_APPROVAL_STRATEGY_CONTEXT_KEY;
        overridden.insert(strategy_key.to_string(), "interactive".to_string());
        assert_eq!(
            commit_point_approval_strategy(
                true,
                false,
                Some(&fresh),
                &overridden,
                PermissionApprovalStrategy::Model
            ),
            PermissionApprovalStrategy::Interactive
        );
    }
}
