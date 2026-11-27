//! Tool pipeline type definitions

use crate::agentic::core::{ToolCall, ToolExecutionState};
use crate::agentic::events::SubagentParentInfo as EventSubagentParentInfo;
use crate::agentic::round_preempt::DialogRoundInjectionInterrupt;
use crate::agentic::tools::ToolRuntimeRestrictions;
use crate::agentic::workspace::WorkspaceServices;
use crate::agentic::WorkspaceBinding;
use crate::infrastructure::PathManager;
use openbitfun_agent_tools::{ResolvedToolInvocation, ValidationResult};
use openbitfun_runtime_ports::{
    DelegationPolicy, PermissionApprovalOnAsk, PermissionApprovalOnError,
    PermissionApprovalStrategy, PermissionDelegationContext, RemoteExecPort,
    ResolvedPermissionPolicy, TerminalPort,
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use tokio_util::sync::CancellationToken;
pub use tool_runtime::context::PrimaryModelFacts;
pub use tool_runtime::pipeline::SubagentBatchExecutionPolicy;

/// Tool execution options
#[derive(Debug, Clone)]
pub struct ToolExecutionOptions {
    pub allow_parallel: bool,
    pub subagent_batch_execution_policy: SubagentBatchExecutionPolicy,
    pub max_retries: usize,
    /// Tool execution timeout (seconds), None means infinite waiting
    pub timeout_secs: Option<u64>,
    /// Resolved host policy plus independent restriction layers.
    pub permission_policy: ResolvedPermissionPolicy,
    /// Automatically reply `once` to `ask` requests through the permission manager.
    pub auto_approve_ask: bool,
    /// Approval strategy applied after static policy evaluation. The existing
    /// `auto_approve_ask` flag remains available for invocation-scoped callers
    /// such as CLI `--auto`.
    pub permission_approval_strategy: PermissionApprovalStrategy,
    pub permission_approval_timeout_ms: u64,
    pub permission_approval_on_ask: PermissionApprovalOnAsk,
    pub permission_approval_on_error: PermissionApprovalOnError,
    /// The latest user-authored message for the current model turn, supplied
    /// to model-based permission approval as decision context.
    pub current_user_message: Option<String>,
    /// Whether this execution host can deliver a permission request to a
    /// human mailbox. Headless and detached hosts set this to false so an
    /// interactive fallback cannot wait forever for a controller.
    pub permission_user_input_available: bool,
    /// Optional owner-provided token that latches cancellation before tool
    /// validation and permission preflight have registered pipeline state.
    pub parent_cancellation_token: Option<CancellationToken>,
    /// When `Some`, the permission commit point re-reads the approval strategy
    /// and provider for this workspace instead of trusting the round-start
    /// snapshot. `None` (the default) keeps the snapshot, which is the OFF path.
    pub workspace_intelligence: Option<WorkspaceIntelligenceCommitContext>,
    /// The execution context variables the commit point needs to re-run the
    /// layered approval-strategy resolution. Empty when the caller has none.
    pub approval_context_vars: HashMap<String, String>,
    /// Set when a non-invocation source (a hook's explicit ask) has already
    /// forced `Interactive` for this batch; the commit point must then keep the
    /// round-start snapshot.
    pub approval_strategy_pinned: bool,
    /// Test-only: the fresh approval facts the commit point would otherwise read
    /// from the host. `Some` bypasses the control record and configuration reads
    /// so a test can prove which strategy and provider the commit point uses.
    #[cfg(test)]
    pub fresh_approval_facts: Option<FreshApprovalFacts>,
}

/// Test-only carrier for the facts a permission commit point reads from the host.
#[cfg(test)]
#[derive(Clone)]
pub struct FreshApprovalFacts {
    pub strategy: PermissionApprovalStrategy,
    pub provider: Option<Arc<dyn openbitfun_runtime_ports::PermissionDecisionPort>>,
}

#[cfg(test)]
impl std::fmt::Debug for FreshApprovalFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FreshApprovalFacts")
            .field("strategy", &self.strategy)
            .field("has_provider", &self.provider.is_some())
            .finish()
    }
}

/// The host facts a permission commit point needs to decide whether workspace
/// intelligence is on for one workspace.
///
/// The decision itself stays with the workspace-intelligence owner; this struct
/// only carries the stable workspace id and the executing host's paths so the
/// commit point can ask that owner. It never carries a path-derived identity.
#[derive(Debug, Clone)]
pub struct WorkspaceIntelligenceCommitContext {
    /// Stable workspace id, never a filesystem path.
    pub workspace_id: String,
    /// The executing host's path manager.
    pub paths: Arc<PathManager>,
}

impl Default for ToolExecutionOptions {
    fn default() -> Self {
        Self {
            allow_parallel: true,
            subagent_batch_execution_policy: SubagentBatchExecutionPolicy::default(),
            max_retries: 0,
            timeout_secs: None, // Default no timeout (infinite waiting)
            permission_policy: ResolvedPermissionPolicy::default(),
            auto_approve_ask: false,
            permission_approval_strategy: PermissionApprovalStrategy::Interactive,
            permission_approval_timeout_ms: 30_000,
            permission_approval_on_ask: PermissionApprovalOnAsk::User,
            permission_approval_on_error: PermissionApprovalOnError::Ask,
            current_user_message: None,
            permission_user_input_available: true,
            parent_cancellation_token: None,
            workspace_intelligence: None,
            approval_context_vars: HashMap::new(),
            approval_strategy_pinned: false,
            #[cfg(test)]
            fresh_approval_facts: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SubagentParentInfo {
    pub tool_call_id: String,
    pub session_id: String,
    pub dialog_turn_id: String,
}

impl SubagentParentInfo {
    pub(crate) fn permission_delegation_context(
        &self,
        subagent_type: &str,
    ) -> PermissionDelegationContext {
        PermissionDelegationContext {
            parent_session_id: self.session_id.clone(),
            parent_dialog_turn_id: Some(self.dialog_turn_id.clone()),
            parent_tool_call_id: self.tool_call_id.clone(),
            subagent_type: subagent_type.to_string(),
        }
    }
}

impl From<SubagentParentInfo> for EventSubagentParentInfo {
    fn from(info: SubagentParentInfo) -> Self {
        Self {
            tool_call_id: info.tool_call_id,
            session_id: info.session_id,
            dialog_turn_id: info.dialog_turn_id,
        }
    }
}

/// Tool execution context
#[derive(Debug, Clone)]
pub struct ToolExecutionContext {
    pub session_id: String,
    pub dialog_turn_id: String,
    pub round_id: String,
    pub attempt_id: Option<String>,
    pub attempt_index: Option<u32>,
    pub agent_type: String,
    pub workspace: Option<WorkspaceBinding>,
    pub primary_model_facts: PrimaryModelFacts,
    /// Exact producing client; auxiliary tool review must retain account and
    /// reasoning configuration instead of resolving the model again.
    pub model_client: Option<Arc<crate::infrastructure::ai::AIClient>>,
    pub context_vars: HashMap<String, String>,
    pub subagent_parent_info: Option<SubagentParentInfo>,
    pub permission_delegation: Option<PermissionDelegationContext>,
    pub(crate) delegation_policy: DelegationPolicy,
    pub deferred_tools: Vec<String>,
    pub loaded_deferred_tool_specs: Vec<openbitfun_agent_tools::LoadedDeferredToolSpec>,
    /// Allowed tools list (whitelist)
    /// If empty, allow all registered tools
    /// If not empty, only allow tools in the list to be executed
    pub allowed_tools: Vec<String>,
    pub runtime_tool_restrictions: ToolRuntimeRestrictions,
    /// Optional cooperative interrupt used to stop remaining tool calls when a
    /// round injection is waiting for this turn.
    pub steering_interrupt: Option<DialogRoundInjectionInterrupt>,
    pub workspace_services: Option<WorkspaceServices>,
    pub terminal_port: Option<Arc<dyn TerminalPort>>,
    pub remote_exec_port: Option<Arc<dyn RemoteExecPort>>,
}

/// Tool execution task
#[derive(Debug, Clone)]
pub struct ToolTask {
    pub tool_call: ToolCall,
    /// Position of this call in the model's tool-call array for the current
    /// round. Permission requests inherit this value as their order key.
    pub tool_call_order: u32,
    pub invocation: ResolvedToolInvocation,
    /// Effective arguments before any Native PreToolUse hook rewrite. This
    /// remains immutable so validation and audit can compare both inputs.
    pub original_effective_arguments: serde_json::Value,
    /// A non-relaxable validation rejection found on the original input while
    /// applying a hook rewrite. Final validation still checks rewritten input.
    pub input_rewrite_rejection: Option<ValidationResult>,
    pub invocation_resolution_error: Option<String>,
    pub context: ToolExecutionContext,
    pub options: ToolExecutionOptions,
    pub state: ToolExecutionState,
    pub created_at: SystemTime,
    pub started_at: Option<SystemTime>,
    pub completed_at: Option<SystemTime>,
    /// Tool-owned signal for ending a yieldable call at a round-injection
    /// boundary. This is deliberately distinct from ordinary cancellation.
    pub round_injection_preemption_token: Option<CancellationToken>,
}

impl ToolTask {
    pub fn new(
        tool_call: ToolCall,
        context: ToolExecutionContext,
        options: ToolExecutionOptions,
    ) -> Self {
        let invocation = ResolvedToolInvocation::direct(
            tool_call.tool_name.clone(),
            tool_call.arguments.clone(),
        );
        Self::new_resolved(tool_call, invocation, None, context, options)
    }

    pub fn new_resolved(
        tool_call: ToolCall,
        invocation: ResolvedToolInvocation,
        invocation_resolution_error: Option<String>,
        context: ToolExecutionContext,
        options: ToolExecutionOptions,
    ) -> Self {
        let original_effective_arguments = invocation.effective_arguments.clone();
        Self {
            tool_call,
            tool_call_order: 0,
            invocation,
            original_effective_arguments,
            input_rewrite_rejection: None,
            invocation_resolution_error,
            context,
            options,
            state: ToolExecutionState::Queued { position: 0 },
            created_at: SystemTime::now(),
            started_at: None,
            completed_at: None,
            round_injection_preemption_token: None,
        }
    }

    pub fn effective_tool_name(&self) -> &str {
        &self.invocation.effective_tool_name
    }

    pub fn effective_arguments(&self) -> &serde_json::Value {
        &self.invocation.effective_arguments
    }
}

/// Tool execution result wrapper
#[derive(Debug, Clone)]
pub struct ToolExecutionResult {
    pub tool_id: String,
    /// Provider-facing tool name. For deferred calls this remains CallDeferredTool.
    pub tool_name: String,
    /// Runtime target used for validation, permissions, hooks, and execution.
    pub effective_tool_name: String,
    pub result: crate::agentic::core::ToolResult,
    /// Deferred definitions loaded while executing a PTC gateway call.
    /// These are projected onto the outer RunCode message so a later round
    /// can reuse them without turning the state into a session-global cache.
    pub ptc_loaded_deferred_tool_specs: Vec<openbitfun_agent_tools::LoadedDeferredToolSpec>,
    pub execution_time_ms: u64,
}
