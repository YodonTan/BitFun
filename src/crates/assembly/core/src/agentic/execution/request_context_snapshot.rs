//! Recorded request-context facts for one model request attempt.
//!
//! The registry keeps a bounded, immutable copy of the *actual* prepared send
//! input of recent attempts so a caller can later materialize a single category
//! preview without rebuilding the current context. Numbers (per-category
//! estimates, provider-reported input totals) are persisted on session
//! metadata; message bodies never are.
//!
//! Three invariants drive this module:
//!
//! - provenance comes from the prepared send input, never from message text;
//! - the only full scan of the request runs in a bounded background task, so
//!   `begin_attempt` never delays the send path;
//! - a provider-reported input total is authoritative and an estimate is never
//!   promoted to one.

use super::context_composition::{PreparedSendInput, SendCategory};
use crate::agentic::events::{AgenticEvent, EventPriority, EventQueue};
use crate::agentic::session::SessionManager;
use crate::agentic::WorkspaceBinding;
use crate::util::types::{Message as AIMessage, ToolDefinition};
use crate::util::TokenCounter;
use log::{debug, warn};
use openbitfun_core_types::{
    UsageContextBreakdown, UsageContextCategory, UsageRequestInputSource, UsageRequestRef,
    UsageRequestSnapshot, UsageRequestUsageState, UsageSummaryState,
    REQUEST_CONTEXT_ESTIMATION_VERSION, REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Execution host id used by a workspace that runs on this process.
pub(crate) const LOCAL_EXECUTION_HOST_ID: &str = "local";

/// Retained requests, oldest evicted first.
const MAX_RETAINED_ENTRIES: usize = 8;
/// Retained requests per session; a turn-heavy session cannot evict every other.
const MAX_RETAINED_ENTRIES_PER_SESSION: usize = 4;
/// Retained source bytes for a single request.
const MAX_RETAINED_SOURCE_BYTES: usize = 8 * 1024 * 1024;
/// Retained source bytes across the whole registry.
const MAX_TOTAL_RETAINED_BYTES: usize = 32 * 1024 * 1024;
/// Upper bound for one materialized category preview.
const MAX_PREVIEW_BYTES: usize = 2 * 1024 * 1024;
/// Concurrent background summaries. The send path is never throttled by them.
const MAX_CONCURRENT_SUMMARIES: usize = 2;
/// Remembered evicted identities, only to explain an unavailable preview.
const MAX_REMEMBERED_EVICTIONS: usize = 16;

const PREVIEW_EVICTED_REASON: &str = "source evicted";
const PREVIEW_RESTART_REASON: &str = "preview unavailable after restart";
const PREVIEW_OVERSIZE_REASON: &str = "source exceeded the retained size limit";
const SNAPSHOT_NOT_CAPTURED_REASON: &str = "no captured input for this attempt";
const PREVIEW_TRUNCATED_MARKER: &str = "\n\n[preview truncated]";

/// One explicitly requested category preview of a recorded request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestContextPreview {
    /// Model-visible text of that category, from the retained immutable source.
    Available { content: String, captured_at: u64 },
    /// Explicit degradation: the source is gone, so nothing is reconstructed.
    Unavailable { reason: String },
}

/// Event sink handed to the background summary job.
///
/// The job outlives the round future, so it holds the queue directly instead of
/// borrowing the executor.
#[derive(Clone)]
pub(crate) struct SnapshotEventSink {
    event_queue: Arc<EventQueue>,
}

impl std::fmt::Debug for SnapshotEventSink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SnapshotEventSink").finish()
    }
}

impl SnapshotEventSink {
    pub(crate) fn new(event_queue: Arc<EventQueue>) -> Self {
        Self { event_queue }
    }

    pub(crate) async fn emit(&self, event: AgenticEvent) {
        let _ = self
            .event_queue
            .enqueue(event, Some(EventPriority::Normal))
            .await;
    }
}

/// Where a completed attempt snapshot can be persisted.
#[derive(Clone)]
pub(crate) struct SnapshotActivation {
    sink: SnapshotEventSink,
    session_manager: Option<Arc<SessionManager>>,
}

impl std::fmt::Debug for SnapshotActivation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SnapshotActivation")
            .field("session_manager", &self.session_manager.is_some())
            .finish()
    }
}

impl SnapshotActivation {
    pub(crate) fn new(
        sink: SnapshotEventSink,
        session_manager: Option<Arc<SessionManager>>,
    ) -> Self {
        Self {
            sink,
            session_manager,
        }
    }

    /// Persist through the session owner's CAS merge and publish the result.
    ///
    /// Returns whether the snapshot was applied; an older attempt never
    /// replaces a newer one and a skipped write publishes nothing.
    pub(crate) async fn persist_and_publish(&self, snapshot: UsageRequestSnapshot) -> bool {
        let Some(session_manager) = self.session_manager.as_ref() else {
            debug!(
                "Recorded request snapshot has no persistent session owner: session_id={}, attempt_id={}",
                snapshot.request.session_id, snapshot.request.attempt_id
            );
            return false;
        };
        let applied = session_manager
            .persist_last_recorded_request_snapshot(&snapshot.request.session_id, snapshot.clone())
            .await;
        if !applied {
            return false;
        }
        self.sink
            .emit(AgenticEvent::RequestContextSnapshotUpdated {
                session_id: snapshot.request.session_id.clone(),
                turn_id: snapshot.request.turn_id.clone(),
                snapshot,
            })
            .await;
        true
    }
}

/// Identity fields of a recorded request. `started_at` and `attempt_index` only
/// order attempts and are never identity.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestKey {
    execution_host_id: String,
    workspace_id: Option<String>,
    session_id: String,
    turn_id: String,
    round_id: String,
    attempt_id: String,
}

impl RequestKey {
    fn of(request: &UsageRequestRef) -> Self {
        Self {
            execution_host_id: request.execution_host_id.clone(),
            workspace_id: request.workspace_id.clone(),
            session_id: request.session_id.clone(),
            turn_id: request.turn_id.clone(),
            round_id: request.round_id.clone(),
            attempt_id: request.attempt_id.clone(),
        }
    }
}

/// Progress of the off-send-path category summary for one retained request.
#[derive(Debug, Clone)]
enum SummarySlot {
    /// Registered, no job owns it (for example after a restart-shaped re-entry).
    Pending,
    /// A bounded job is running.
    Running,
    /// Numeric summary available for activation.
    Ready(UsageContextBreakdown),
}

#[derive(Debug)]
struct RetainedRequest {
    request: UsageRequestRef,
    captured_at: u64,
    /// Immutable prepared send input, kept only while it fits the size budget.
    source: Option<Arc<PreparedSendInput>>,
    /// Tool definitions sent with that same input, retained with it or not at all.
    tools: Option<Arc<Vec<ToolDefinition>>>,
    /// Combined retained bytes of messages and tool definitions.
    source_bytes: usize,
    summary: SummarySlot,
    /// Resolved capacity of the attempt, recorded with the snapshot.
    context_window: Option<u64>,
    /// Snapshot produced by `activate_attempt`, so a late summary can upgrade it.
    activated: Option<UsageRequestSnapshot>,
}

impl RetainedRequest {
    fn same_identity(&self, key: &RequestKey) -> bool {
        RequestKey::of(&self.request) == *key
    }

    fn retained_bytes(&self) -> usize {
        self.source.as_ref().map_or(0, |_| self.source_bytes)
    }
}

#[derive(Debug, Default)]
struct SnapshotRegistry {
    /// Oldest first; eviction always removes from the front.
    entries: VecDeque<RetainedRequest>,
    /// Recently evicted identities, bounded, used only for preview reasons.
    evicted: VecDeque<RequestKey>,
    total_bytes: usize,
}

impl SnapshotRegistry {
    fn position(&self, key: &RequestKey) -> Option<usize> {
        self.entries
            .iter()
            .position(|entry| entry.same_identity(key))
    }

    fn evict(&mut self, index: usize) {
        if let Some(entry) = self.entries.remove(index) {
            self.total_bytes = self.total_bytes.saturating_sub(entry.retained_bytes());
            self.remember_eviction(RequestKey::of(&entry.request));
        }
    }

    fn remember_eviction(&mut self, key: RequestKey) {
        if self.evicted.contains(&key) {
            return;
        }
        self.evicted.push_back(key);
        while self.evicted.len() > MAX_REMEMBERED_EVICTIONS {
            self.evicted.pop_front();
        }
    }

    fn enforce_limits(&mut self) {
        while self.entries.len() > MAX_RETAINED_ENTRIES {
            self.evict(0);
        }
        // Evict the oldest request of the most crowded session beyond its share.
        while let Some(session_id) = self.crowded_session() {
            let Some(index) = self
                .entries
                .iter()
                .position(|entry| entry.request.session_id == session_id)
            else {
                break;
            };
            self.evict(index);
        }
        while self.total_bytes > MAX_TOTAL_RETAINED_BYTES && !self.entries.is_empty() {
            self.evict(0);
        }
    }

    fn crowded_session(&self) -> Option<String> {
        let mut sessions: Vec<(String, usize)> = Vec::new();
        for entry in &self.entries {
            match sessions
                .iter_mut()
                .find(|(session_id, _)| session_id == &entry.request.session_id)
            {
                Some((_, count)) => *count += 1,
                None => sessions.push((entry.request.session_id.clone(), 1)),
            }
        }
        sessions
            .into_iter()
            .find(|(_, count)| *count > MAX_RETAINED_ENTRIES_PER_SESSION)
            .map(|(session_id, _)| session_id)
    }
}

fn registry() -> &'static Mutex<SnapshotRegistry> {
    static REGISTRY: OnceLock<Mutex<SnapshotRegistry>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(SnapshotRegistry::default()))
}

fn summary_semaphore() -> &'static Arc<Semaphore> {
    static SEMAPHORE: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEMAPHORE.get_or_init(|| Arc::new(Semaphore::new(MAX_CONCURRENT_SUMMARIES)))
}

/// `std::sync::Mutex` is only ever held for table mutation, never across await.
fn with_registry<T>(action: impl FnOnce(&mut SnapshotRegistry) -> T) -> T {
    match registry().lock() {
        Ok(mut registry) => action(&mut registry),
        Err(poisoned) => action(&mut poisoned.into_inner()),
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Stable execution host identity of the workspace that runs the request.
pub(crate) fn execution_host_id(workspace: Option<&WorkspaceBinding>) -> String {
    let Some(workspace) = workspace else {
        return LOCAL_EXECUTION_HOST_ID.to_string();
    };
    let remote_connection_id = workspace
        .session_identity
        .remote_connection_id
        .clone()
        .or_else(|| match &workspace.backend {
            crate::agentic::WorkspaceBackend::Remote { connection_id, .. } => {
                Some(connection_id.clone())
            }
            crate::agentic::WorkspaceBackend::Local => None,
        });
    match remote_connection_id {
        Some(connection_id) => format!("remote:{connection_id}"),
        None => LOCAL_EXECUTION_HOST_ID.to_string(),
    }
}

/// Facts of one live attempt that identify its recorded request.
pub(crate) struct AttemptRequestIdentity<'a> {
    pub(crate) workspace: Option<&'a WorkspaceBinding>,
    pub(crate) session_id: &'a str,
    pub(crate) turn_id: &'a str,
    pub(crate) round_id: &'a str,
    pub(crate) attempt_id: &'a str,
    pub(crate) attempt_index: u32,
    pub(crate) started_at: i64,
}

impl AttemptRequestIdentity<'_> {
    fn to_request_ref(&self) -> UsageRequestRef {
        UsageRequestRef {
            execution_host_id: execution_host_id(self.workspace),
            workspace_id: self.workspace.and_then(|workspace| {
                workspace
                    .workspace_id
                    .clone()
                    .or_else(|| workspace.project_workspace_id.clone())
            }),
            session_id: self.session_id.to_string(),
            turn_id: self.turn_id.to_string(),
            round_id: self.round_id.to_string(),
            attempt_id: self.attempt_id.to_string(),
            attempt_index: self.attempt_index,
            started_at: self.started_at,
        }
    }
}

pub(crate) fn request_ref(identity: AttemptRequestIdentity<'_>) -> UsageRequestRef {
    identity.to_request_ref()
}

/// Whether a summary job could be admitted for one attempt.
///
/// The permit is taken *before* the entry is registered, so an attempt burst
/// queues no tasks: a rejected attempt stays `Pending` and holds no job.
enum AttemptAdmission {
    /// A permit was taken; the caller spawns exactly one task that owns it.
    Run(OwnedSemaphorePermit),
    /// No permit is free; nothing is spawned and the summary stays `Pending`.
    Deferred,
    /// The attempt already has a running or completed summary.
    AlreadySummarized,
}

/// Register the exact prepared input of one attempt and summarize it off the
/// send path.
///
/// This returns as soon as the source is registered. The single full scan runs
/// in at most [`MAX_CONCURRENT_SUMMARIES`] background tasks for the whole
/// process: a task is spawned only when one of those permits is taken with
/// `try_acquire_owned`, so retries can never queue unbounded work.
pub(crate) fn begin_attempt(
    prepared: Arc<PreparedSendInput>,
    request: UsageRequestRef,
    tools: Option<Arc<Vec<ToolDefinition>>>,
    context_window: Option<u64>,
    activation: SnapshotActivation,
) {
    if !prepared.is_aligned() {
        // Recording a misaligned source would attribute every later message to
        // the wrong category; degrade instead of guessing.
        warn!(
            "Recorded request snapshot skipped: session_id={}, attempt_id={}, messages={}, categories={}",
            request.session_id,
            request.attempt_id,
            prepared.messages.len(),
            prepared.categories.len()
        );
        return;
    }

    let key = RequestKey::of(&request);
    // Messages and tool definitions are one retained unit: the byte bound covers
    // both, so an oversize request retains neither.
    let source_bytes = retained_source_bytes(&prepared.messages)
        .saturating_add(retained_tool_definition_bytes(
            tools.as_deref().map(Vec::as_slice),
        ));
    let retain_source = source_bytes <= MAX_RETAINED_SOURCE_BYTES;
    if !retain_source {
        debug!(
            "Recorded request snapshot source exceeded the retained size limit: session_id={}, attempt_id={}, bytes={}",
            request.session_id, request.attempt_id, source_bytes
        );
    }
    let captured_at = now_ms();

    let needs_summary = with_registry(|registry| match registry.position(&key) {
        Some(index) => matches!(registry.entries[index].summary, SummarySlot::Pending),
        None => true,
    });
    let admission = if !needs_summary {
        AttemptAdmission::AlreadySummarized
    } else {
        // Non-blocking: a burst of attempts never parks a task on a queue.
        match Arc::clone(summary_semaphore()).try_acquire_owned() {
            Ok(permit) => AttemptAdmission::Run(permit),
            Err(_) => AttemptAdmission::Deferred,
        }
    };

    let spawn_summary = with_registry(|registry| {
        let existing = registry
            .position(&key)
            .map(|index| registry.entries[index].summary.clone());
        let (summary, spawn) = match (existing, &admission) {
            (Some(SummarySlot::Running), _) => (SummarySlot::Running, false),
            (Some(SummarySlot::Ready(breakdown)), _) => (SummarySlot::Ready(breakdown), false),
            (_, AttemptAdmission::Run(_)) => (SummarySlot::Running, true),
            (_, AttemptAdmission::Deferred | AttemptAdmission::AlreadySummarized) => {
                (SummarySlot::Pending, false)
            }
        };
        let entry = RetainedRequest {
            request: request.clone(),
            captured_at,
            source: retain_source.then(|| Arc::clone(&prepared)),
            tools: if retain_source { tools.clone() } else { None },
            source_bytes: if retain_source { source_bytes } else { 0 },
            summary,
            context_window,
            activated: None,
        };
        match registry.position(&key) {
            Some(index) => {
                let previous = registry.entries.remove(index).expect("checked index");
                registry.total_bytes = registry
                    .total_bytes
                    .saturating_sub(previous.retained_bytes());
                let mut entry = entry;
                entry.activated = previous.activated;
                // A re-registration without a resolved window keeps the known one.
                entry.context_window = context_window.or(previous.context_window);
                registry.total_bytes = registry
                    .total_bytes
                    .saturating_add(entry.retained_bytes());
                registry.entries.push_back(entry);
            }
            None => {
                registry.total_bytes = registry
                    .total_bytes
                    .saturating_add(entry.retained_bytes());
                registry.entries.push_back(entry);
            }
        }
        registry.enforce_limits();
        spawn
    });

    let permit = match admission {
        AttemptAdmission::Run(permit) if spawn_summary => permit,
        AttemptAdmission::Deferred => {
            debug!(
                "Recorded request snapshot summary skipped by bounded concurrency: session_id={}, attempt_id={}, source_bytes={}",
                request.session_id, request.attempt_id, source_bytes
            );
            return;
        }
        AttemptAdmission::AlreadySummarized | AttemptAdmission::Run(_) => {
            debug!(
                "Recorded request snapshot re-registered without a second summary: session_id={}, attempt_id={}",
                request.session_id, request.attempt_id
            );
            return;
        }
    };

    tokio::spawn(async move {
        let breakdown = summarize_send_input(
            &prepared.messages,
            &prepared.categories,
            tools.as_deref().map(Vec::as_slice),
            context_window,
        );
        complete_summary(request, breakdown, activation).await;
        // The permit covers the whole task, so in-flight summary tasks can never
        // exceed the permits the semaphore has.
        drop(permit);
    });
}

/// Whether a summary job is running, or a summary result is waiting for the
/// attempt to finish. A restarted process has an empty registry and therefore
/// reports `false` for every persisted reference.
pub fn request_context_summary_is_live(request: &UsageRequestRef) -> bool {
    let key = RequestKey::of(request);
    with_registry(|registry| {
        registry
            .entries
            .iter()
            .find(|entry| entry.same_identity(&key))
            .is_some_and(|entry| {
                matches!(
                    entry.summary,
                    SummarySlot::Running | SummarySlot::Ready(_)
                )
            })
    })
}

async fn complete_summary(
    request: UsageRequestRef,
    breakdown: UsageContextBreakdown,
    activation: SnapshotActivation,
) {
    let estimated_total = breakdown_total(&breakdown);
    let key = RequestKey::of(&request);
    // Store the numeric result and fold it into an already activated snapshot in
    // one table mutation. Only the resulting snapshot leaves the lock.
    let publish = with_registry(|registry| {
        let Some(index) = registry.position(&key) else {
            // The source was evicted before the job finished. Nothing is
            // reconstructed and nothing is published.
            debug!(
                "Recorded request snapshot summary dropped after eviction: session_id={}, attempt_id={}",
                request.session_id, request.attempt_id
            );
            return None;
        };
        let entry = &mut registry.entries[index];
        entry.summary = SummarySlot::Ready(breakdown.clone());
        let activated = entry.activated.as_mut()?;
        // The attempt already finished: upgrade the recorded snapshot without
        // downgrading a ready summary or inventing a provider total.
        record_summary_result(activated, breakdown, estimated_total).then(|| activated.clone())
    });

    let Some(snapshot) = publish else {
        // Either no attempt result yet (it reads this result later) or nothing
        // left to upgrade.
        return;
    };
    activation.persist_and_publish(snapshot).await;
}

/// Record the terminal state of one attempt against its captured input.
///
/// The returned snapshot is the value to persist: a provider-reported input
/// total when the adapter normalized one, a same-attempt estimate when only the
/// summary is ready, otherwise an explicit unknown. A reported total is never
/// inferred and a zero is never recorded as a reported total.
pub(crate) fn activate_attempt(
    request: UsageRequestRef,
    usage_prompt_token_count: Option<u64>,
    cached_input_tokens: Option<u64>,
) -> UsageRequestSnapshot {
    let key = RequestKey::of(&request);
    let captured_at = now_ms();
    let (summary, retained, retained_context_window) = with_registry(|registry| {
        let Some(index) = registry.position(&key) else {
            return (None, false, None);
        };
        let entry = &mut registry.entries[index];
        entry.request.started_at = request.started_at;
        entry.request.attempt_index = request.attempt_index;
        let summary = match &entry.summary {
            SummarySlot::Ready(breakdown) => Some(breakdown.clone()),
            SummarySlot::Pending | SummarySlot::Running => None,
        };
        (summary, true, entry.context_window)
    });

    let mut snapshot = UsageRequestSnapshot {
        schema_version: REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
        request,
        captured_at,
        input_source: UsageRequestInputSource::ModelRequest,
        input_total: None,
        context_window: retained_context_window,
        cached_input_tokens: None,
        usage_state: UsageRequestUsageState::Unknown,
        estimated_total: None,
        estimation_version: None,
        summary_state: if retained {
            UsageSummaryState::Pending
        } else {
            UsageSummaryState::Unavailable
        },
        categories: None,
        unavailable_reason: if retained {
            None
        } else {
            Some(SNAPSHOT_NOT_CAPTURED_REASON.to_string())
        },
    };

    if let Some(prompt_token_count) = usage_prompt_token_count.filter(|count| *count > 0) {
        // The adapter already normalized this to the whole request input,
        // including cached tokens.
        snapshot.input_total = Some(prompt_token_count);
        snapshot.cached_input_tokens = cached_input_tokens;
        snapshot.usage_state = UsageRequestUsageState::ProviderReported;
        snapshot.unavailable_reason = None;
    }

    if let Some(breakdown) = summary {
        let estimated_total = breakdown_total(&breakdown);
        record_summary_result(&mut snapshot, breakdown, estimated_total);
    }

    let stored = snapshot.clone();
    with_registry(|registry| {
        if let Some(index) = registry.position(&key) {
            registry.entries[index].activated = Some(stored);
        }
    });
    snapshot
}

/// Merge a completed same-attempt summary into one snapshot.
///
/// A ready summary may upgrade a pending or unavailable one; a ready summary is
/// never downgraded and an estimate never becomes a provider-reported total.
pub(crate) fn record_summary_result(
    snapshot: &mut UsageRequestSnapshot,
    breakdown: UsageContextBreakdown,
    estimated_total: u64,
) -> bool {
    if snapshot.summary_state == UsageSummaryState::Ready {
        return false;
    }
    snapshot.categories = Some(breakdown);
    snapshot.estimated_total = Some(estimated_total);
    snapshot.estimation_version = Some(REQUEST_CONTEXT_ESTIMATION_VERSION);
    snapshot.summary_state = UsageSummaryState::Ready;
    snapshot.unavailable_reason = None;
    if snapshot.usage_state != UsageRequestUsageState::ProviderReported {
        // The category sum is an estimate of this attempt, never a reported
        // total and never a zero filler.
        snapshot.usage_state = UsageRequestUsageState::Estimated;
        snapshot.input_total = None;
    }
    true
}

/// Render exactly one category from the retained source of that reference.
///
/// A preview never substitutes the current context: an evicted source, an
/// earlier process, or a different attempt reports an explicit reason.
pub fn materialize_request_context_preview(
    request: &UsageRequestRef,
    category: UsageContextCategory,
) -> RequestContextPreview {
    let key = RequestKey::of(request);
    let found = with_registry(|registry| {
        registry
            .entries
            .iter()
            .find(|entry| entry.same_identity(&key))
            .map(|entry| (entry.source.clone(), entry.tools.clone(), entry.captured_at))
    });
    match found {
        Some((Some(source), tools, captured_at)) => RequestContextPreview::Available {
            content: render_category_preview(
                &source,
                tools.as_deref().map(Vec::as_slice),
                category,
            ),
            captured_at,
        },
        Some((None, _, _)) => RequestContextPreview::Unavailable {
            reason: PREVIEW_OVERSIZE_REASON.to_string(),
        },
        None => {
            let was_evicted = with_registry(|registry| registry.evicted.contains(&key));
            RequestContextPreview::Unavailable {
                reason: if was_evicted {
                    PREVIEW_EVICTED_REASON
                } else {
                    PREVIEW_RESTART_REASON
                }
                .to_string(),
            }
        }
    }
}

/// Total of the per-category estimates of one attempt.
pub(crate) fn breakdown_total(breakdown: &UsageContextBreakdown) -> u64 {
    breakdown
        .system_prompt
        .saturating_add(breakdown.tool_definitions)
        .saturating_add(breakdown.rules)
        .saturating_add(breakdown.skills)
        .saturating_add(breakdown.mcp_tools)
        .saturating_add(breakdown.subagent_definitions)
        .saturating_add(breakdown.summarized_conversation)
        .saturating_add(breakdown.conversation)
}

fn category_bucket(breakdown: &mut UsageContextBreakdown, category: SendCategory) -> &mut u64 {
    match category {
        SendCategory::SystemPrompt => &mut breakdown.system_prompt,
        SendCategory::ToolDefinitions => &mut breakdown.tool_definitions,
        SendCategory::Rules => &mut breakdown.rules,
        SendCategory::Skills => &mut breakdown.skills,
        SendCategory::McpTools => &mut breakdown.mcp_tools,
        SendCategory::SubagentDefinitions => &mut breakdown.subagent_definitions,
        SendCategory::SummarizedConversation => &mut breakdown.summarized_conversation,
        SendCategory::Conversation => &mut breakdown.conversation,
    }
}

/// The only full scan of a request, always executed by the bounded background job.
fn summarize_send_input(
    messages: &[AIMessage],
    categories: &[SendCategory],
    tools: Option<&[ToolDefinition]>,
    context_window: Option<u64>,
) -> UsageContextBreakdown {
    let mut breakdown = UsageContextBreakdown {
        context_window,
        ..Default::default()
    };
    for (message, category) in messages.iter().zip(categories.iter()) {
        let tokens = TokenCounter::estimate_message_tokens(message) as u64;
        let bucket = category_bucket(&mut breakdown, *category);
        *bucket = bucket.saturating_add(tokens);
    }
    if let Some(tools) = tools.filter(|tools| !tools.is_empty()) {
        breakdown.tool_definitions = breakdown
            .tool_definitions
            .saturating_add(TokenCounter::estimate_tool_definitions_tokens(tools) as u64);
    }
    breakdown
}

fn retained_source_bytes(messages: &[AIMessage]) -> usize {
    messages.iter().map(retained_message_bytes).sum()
}

/// Exact serialized size of the tool definitions sent with one attempt.
///
/// Only bounded metadata is serialized here, never conversation content, and the
/// result is used solely for the retention bound. The identical JSON is what the
/// preview later renders.
fn retained_tool_definition_bytes(tools: Option<&[ToolDefinition]>) -> usize {
    let Some(tools) = tools.filter(|tools| !tools.is_empty()) else {
        return 0;
    };
    match serde_json::to_vec(tools) {
        Ok(bytes) => bytes.len(),
        Err(_) => tools.iter().fold(0usize, |total, tool| {
            total
                .saturating_add(tool.name.len())
                .saturating_add(tool.description.len())
                .saturating_add(json_value_bytes(&tool.parameters))
        }),
    }
}

fn retained_message_bytes(message: &AIMessage) -> usize {
    let mut bytes = message.content.as_ref().map_or(0, String::len);
    bytes = bytes.saturating_add(message.reasoning_content.as_ref().map_or(0, String::len));
    bytes = bytes.saturating_add(message.name.as_ref().map_or(0, String::len));
    bytes = bytes.saturating_add(message.tool_call_id.as_ref().map_or(0, String::len));
    if let Some(tool_calls) = &message.tool_calls {
        for tool_call in tool_calls {
            bytes = bytes.saturating_add(tool_call.name.len());
            bytes = bytes.saturating_add(json_value_bytes(&tool_call.arguments));
        }
    }
    if let Some(images) = &message.tool_image_attachments {
        for image in images {
            bytes = bytes.saturating_add(image.data_base64.len());
        }
    }
    bytes
}

fn json_value_bytes(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(_) => 16,
        serde_json::Value::String(text) => text.len(),
        serde_json::Value::Array(values) => values.iter().map(json_value_bytes).sum(),
        serde_json::Value::Object(map) => map
            .iter()
            .map(|(key, value)| key.len().saturating_add(json_value_bytes(value)))
            .sum(),
    }
}

/// Render exactly one category from the retained source of that reference.
///
/// `ToolDefinitions` is the only category whose content lives outside the
/// prepared messages, so the retained definitions are rendered first and the
/// category's own messages follow.
fn render_category_preview(
    source: &PreparedSendInput,
    tools: Option<&[ToolDefinition]>,
    category: UsageContextCategory,
) -> String {
    let mut content = String::new();
    if category == UsageContextCategory::ToolDefinitions
        && !push_tool_definition_preview(&mut content, tools)
    {
        return content;
    }
    for (message, message_category) in source.messages.iter().zip(source.categories.iter()) {
        if message_category.preview_category() != Some(category) {
            continue;
        }
        let Some(text) = message.content.as_deref().filter(|text| !text.trim().is_empty()) else {
            continue;
        };
        if !content.is_empty() && !push_preview_text(&mut content, "\n\n---\n\n") {
            break;
        }
        if !push_preview_text(&mut content, text) {
            break;
        }
    }
    content
}

/// Append the sent tool schemas of a `ToolDefinitions` preview. Returns false
/// when the preview bound was reached.
fn push_tool_definition_preview(content: &mut String, tools: Option<&[ToolDefinition]>) -> bool {
    let Some(tools) = tools.filter(|tools| !tools.is_empty()) else {
        return true;
    };
    for tool in tools {
        if !content.is_empty() && !push_preview_text(content, "\n\n") {
            return false;
        }
        if !push_preview_text(content, &render_tool_definition_block(tool)) {
            return false;
        }
    }
    true
}

fn render_tool_definition_block(tool: &ToolDefinition) -> String {
    let schema = serde_json::to_string_pretty(&tool.parameters)
        .unwrap_or_else(|_| tool.parameters.to_string());
    let mut block = format!("### `{}`", tool.name);
    let description = tool.description.trim();
    if !description.is_empty() {
        block.push_str("\n\n");
        block.push_str(description);
    }
    block.push_str("\n\n```json\n");
    block.push_str(&schema);
    block.push_str("\n```");
    block
}

/// Append text while keeping the rendered preview bounded. Returns false when
/// the bound was reached, so the caller stops rendering.
fn push_preview_text(content: &mut String, text: &str) -> bool {
    if content.len().saturating_add(text.len()) <= MAX_PREVIEW_BYTES {
        content.push_str(text);
        return true;
    }
    let remaining = MAX_PREVIEW_BYTES
        .saturating_sub(content.len())
        .saturating_sub(PREVIEW_TRUNCATED_MARKER.len());
    let mut take = remaining.min(text.len());
    while take > 0 && !text.is_char_boundary(take) {
        take -= 1;
    }
    content.push_str(&text[..take]);
    content.push_str(PREVIEW_TRUNCATED_MARKER);
    false
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::agentic::core::Message as DomainMessage;

    fn test_request(attempt_id: &str, attempt_index: u32, started_at: i64) -> UsageRequestRef {
        UsageRequestRef {
            execution_host_id: LOCAL_EXECUTION_HOST_ID.to_string(),
            workspace_id: Some("workspace-1".to_string()),
            session_id: "session-1".to_string(),
            turn_id: "turn-1".to_string(),
            round_id: "round-1".to_string(),
            attempt_id: attempt_id.to_string(),
            attempt_index,
            started_at,
        }
    }

    fn session_request(
        session_id: &str,
        attempt_id: &str,
        attempt_index: u32,
        started_at: i64,
    ) -> UsageRequestRef {
        UsageRequestRef {
            session_id: session_id.to_string(),
            ..test_request(attempt_id, attempt_index, started_at)
        }
    }

    fn prepared(
        messages: Vec<AIMessage>,
        categories: Vec<SendCategory>,
    ) -> Arc<PreparedSendInput> {
        Arc::new(PreparedSendInput {
            messages,
            categories,
        })
    }

    fn conversation_input(text: &str) -> Arc<PreparedSendInput> {
        prepared(
            vec![AIMessage::user(text.to_string())],
            vec![SendCategory::Conversation],
        )
    }

    fn sink() -> SnapshotEventSink {
        SnapshotEventSink::new(Arc::new(EventQueue::new(
            openbitfun_agent_runtime::event_queue::EventQueueConfig::default(),
        )))
    }

    fn activation() -> SnapshotActivation {
        SnapshotActivation::new(sink(), None)
    }

    /// Tests share one process-global registry, so they run serially.
    fn test_guard() -> std::sync::MutexGuard<'static, ()> {
        static TEST_LOCK: Mutex<()> = Mutex::new(());
        TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn clear_registry() {
        with_registry(|registry| {
            registry.entries.clear();
            registry.evicted.clear();
            registry.total_bytes = 0;
        });
    }

    fn summary_slot(request: &UsageRequestRef) -> Option<SummarySlot> {
        let key = RequestKey::of(request);
        with_registry(|registry| {
            registry
                .entries
                .iter()
                .find(|entry| entry.same_identity(&key))
                .map(|entry| entry.summary.clone())
        })
    }

    fn force_ready(request: &UsageRequestRef, breakdown: UsageContextBreakdown) {
        with_registry(|registry| {
            let key = RequestKey::of(request);
            let index = registry.position(&key).expect("registered");
            registry.entries[index].summary = SummarySlot::Ready(breakdown);
        });
    }

    fn activated_snapshot(request: &UsageRequestRef) -> Option<UsageRequestSnapshot> {
        let key = RequestKey::of(request);
        with_registry(|registry| {
            registry
                .entries
                .iter()
                .find(|entry| entry.same_identity(&key))
                .and_then(|entry| entry.activated.clone())
        })
    }

    fn summary_ready(request: &UsageRequestRef) -> bool {
        let key = RequestKey::of(request);
        with_registry(|registry| {
            registry
                .entries
                .iter()
                .find(|entry| entry.same_identity(&key))
                .is_some_and(|entry| matches!(entry.summary, SummarySlot::Ready(_)))
        })
    }

    async fn wait_for_summary(request: &UsageRequestRef) {
        for _ in 0..600 {
            if summary_ready(request) {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        panic!("the background summary did not finish");
    }

    #[tokio::test]
    async fn provider_total_is_authoritative_even_with_a_ready_summary() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-u", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hello"),
            request.clone(),
            None,
            Some(200_000),
            activation(),
        );
        let breakdown = UsageContextBreakdown {
            system_prompt: 11,
            conversation: 22,
            ..Default::default()
        };
        let estimated_total = breakdown_total(&breakdown);
        force_ready(&request, breakdown.clone());

        let snapshot = activate_attempt(request.clone(), Some(120_000), Some(4_000));
        assert_eq!(
            snapshot.usage_state,
            UsageRequestUsageState::ProviderReported
        );
        assert_eq!(snapshot.input_source, UsageRequestInputSource::ModelRequest);
        assert_eq!(snapshot.input_total, Some(120_000));
        assert_eq!(snapshot.context_window, Some(200_000));
        assert_eq!(snapshot.cached_input_tokens, Some(4_000));
        assert_eq!(snapshot.summary_state, UsageSummaryState::Ready);
        assert_eq!(snapshot.estimated_total, Some(estimated_total));
        assert_eq!(
            snapshot.estimation_version,
            Some(REQUEST_CONTEXT_ESTIMATION_VERSION)
        );
        assert_eq!(
            snapshot.categories.expect("categories").conversation,
            breakdown.conversation
        );
        clear_registry();
    }

    #[tokio::test]
    async fn estimated_snapshot_has_no_reported_total_and_unknown_has_no_zero() {
        let _guard = test_guard();
        clear_registry();
        let ready = session_request("session-e", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hi"),
            ready.clone(),
            None,
            None,
            activation(),
        );
        force_ready(
            &ready,
            UsageContextBreakdown {
                conversation: 7,
                ..Default::default()
            },
        );
        let estimated = activate_attempt(ready, None, None);
        assert_eq!(estimated.usage_state, UsageRequestUsageState::Estimated);
        assert_eq!(estimated.input_total, None, "an estimate is not a total");
        assert_eq!(estimated.context_window, None);
        assert_eq!(estimated.estimated_total, Some(7));
        assert_eq!(estimated.summary_state, UsageSummaryState::Ready);

        let unknown = session_request("session-unknown", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hi"),
            unknown.clone(),
            None,
            None,
            activation(),
        );
        let snapshot = activate_attempt(unknown, None, None);
        assert_eq!(snapshot.usage_state, UsageRequestUsageState::Unknown);
        assert_eq!(snapshot.input_total, None);
        assert_eq!(snapshot.estimated_total, None);
        assert_eq!(snapshot.estimation_version, None);
        assert_eq!(snapshot.summary_state, UsageSummaryState::Pending);

        let zero_usage = session_request("session-zero", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hi"),
            zero_usage.clone(),
            None,
            None,
            activation(),
        );
        let zero = activate_attempt(zero_usage, Some(0), Some(0));
        assert_eq!(zero.input_total, None, "a zero is never a reported total");
        assert_eq!(zero.usage_state, UsageRequestUsageState::Unknown);

        let missing = activate_attempt(
            session_request("session-never-captured", "round-1:attempt:9", 9, 10),
            None,
            None,
        );
        assert_eq!(missing.usage_state, UsageRequestUsageState::Unknown);
        assert_eq!(missing.input_total, None);
        assert_eq!(missing.summary_state, UsageSummaryState::Unavailable);
        assert_eq!(
            missing.unavailable_reason.as_deref(),
            Some(SNAPSHOT_NOT_CAPTURED_REASON)
        );
        clear_registry();
    }

    #[tokio::test]
    async fn summary_result_never_downgrades_ready_and_never_creates_a_provider_total() {
        let _guard = test_guard();
        let mut snapshot = UsageRequestSnapshot {
            schema_version: REQUEST_CONTEXT_SNAPSHOT_SCHEMA_VERSION,
            request: test_request("round-1:attempt:1", 1, 10),
            captured_at: 10,
            input_source: UsageRequestInputSource::ModelRequest,
            input_total: None,
            context_window: None,
            cached_input_tokens: None,
            usage_state: UsageRequestUsageState::Unknown,
            estimated_total: None,
            estimation_version: None,
            summary_state: UsageSummaryState::Unavailable,
            categories: None,
            unavailable_reason: Some(SNAPSHOT_NOT_CAPTURED_REASON.to_string()),
        };
        let first = UsageContextBreakdown {
            conversation: 5,
            ..Default::default()
        };
        assert!(record_summary_result(&mut snapshot, first, 5));
        assert_eq!(snapshot.summary_state, UsageSummaryState::Ready);
        assert_eq!(snapshot.usage_state, UsageRequestUsageState::Estimated);
        assert_eq!(snapshot.input_total, None);
        assert!(snapshot.unavailable_reason.is_none());

        let second = UsageContextBreakdown {
            conversation: 500,
            ..Default::default()
        };
        assert!(!record_summary_result(&mut snapshot, second, 500));
        assert_eq!(
            snapshot.estimated_total,
            Some(5),
            "a ready summary is never downgraded"
        );

        let mut provider = snapshot.clone();
        provider.usage_state = UsageRequestUsageState::ProviderReported;
        provider.input_total = Some(42);
        provider.summary_state = UsageSummaryState::Pending;
        provider.categories = None;
        provider.estimated_total = None;
        assert!(record_summary_result(
            &mut provider,
            UsageContextBreakdown {
                conversation: 9,
                ..Default::default()
            },
            9
        ));
        assert_eq!(provider.input_total, Some(42));
        assert_eq!(
            provider.usage_state,
            UsageRequestUsageState::ProviderReported
        );
    }

    #[tokio::test]
    async fn begin_attempt_does_not_summarize_inline() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-inline", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("some content"),
            request.clone(),
            None,
            None,
            activation(),
        );
        assert!(request_context_summary_is_live(&request));
        assert!(
            !summary_ready(&request),
            "the summary must not be computed on the caller"
        );
        clear_registry();
    }

    #[tokio::test]
    async fn summary_completed_before_activation_is_merged_into_a_provider_snapshot() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-before", "round-1:attempt:1", 1, 10);
        begin_attempt(
            prepared(
                vec![
                    AIMessage::system("system body".into()),
                    AIMessage::user("user body".into()),
                ],
                vec![SendCategory::SystemPrompt, SendCategory::Conversation],
            ),
            request.clone(),
            None,
            Some(1_000),
            activation(),
        );
        wait_for_summary(&request).await;
        let snapshot = activate_attempt(request.clone(), Some(900), None);
        assert_eq!(
            snapshot.usage_state,
            UsageRequestUsageState::ProviderReported
        );
        assert_eq!(snapshot.input_total, Some(900));
        assert_eq!(snapshot.summary_state, UsageSummaryState::Ready);
        assert!(snapshot.estimated_total.is_some_and(|total| total > 0));
        clear_registry();
    }

    #[tokio::test]
    async fn summary_completed_after_activation_keeps_the_same_provider_total() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-after", "round-1:attempt:2", 2, 20);
        begin_attempt(
            conversation_input("late summary"),
            request.clone(),
            None,
            None,
            activation(),
        );
        let activated = activate_attempt(request.clone(), Some(700), None);
        assert_eq!(activated.summary_state, UsageSummaryState::Pending);
        assert_eq!(activated.input_total, Some(700));
        wait_for_summary(&request).await;
        let upgraded = activated_snapshot(&request).expect("activation recorded");
        assert_eq!(upgraded.summary_state, UsageSummaryState::Ready);
        assert_eq!(
            upgraded.usage_state,
            UsageRequestUsageState::ProviderReported
        );
        assert_eq!(upgraded.input_total, Some(700));
        clear_registry();
    }

    #[tokio::test]
    async fn preview_renders_only_the_requested_category() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-preview", "round-1:attempt:1", 1, 10);
        begin_attempt(
            prepared(
                vec![
                    AIMessage::system("system body".into()),
                    AIMessage::user("conversation body".into()),
                ],
                vec![SendCategory::SystemPrompt, SendCategory::Conversation],
            ),
            request.clone(),
            None,
            None,
            activation(),
        );
        match materialize_request_context_preview(&request, UsageContextCategory::SystemPrompt) {
            RequestContextPreview::Available { content, .. } => assert_eq!(content, "system body"),
            other => panic!("expected an available preview, got {other:?}"),
        }
        // Conversation has no public preview category, so no content leaks
        // through an unrelated request.
        match materialize_request_context_preview(&request, UsageContextCategory::Skills) {
            RequestContextPreview::Available { content, .. } => {
                assert!(content.is_empty(), "only the requested category is rendered")
            }
            other => panic!("expected an empty preview, got {other:?}"),
        }
        assert_eq!(
            materialize_request_context_preview(
                &session_request("session-restart", "round-1:attempt:2", 2, 10),
                UsageContextCategory::SystemPrompt
            ),
            RequestContextPreview::Unavailable {
                reason: PREVIEW_RESTART_REASON.to_string()
            }
        );
        clear_registry();
    }

    #[tokio::test]
    async fn preview_output_is_bounded() {
        let _guard = test_guard();
        let large = "x".repeat(MAX_PREVIEW_BYTES + 4_096);
        let source = prepared(
            vec![AIMessage::user(large)],
            vec![SendCategory::Conversation],
        );
        // Conversation is numeric only, so bound the renderer on a previewable one.
        let source = prepared(
            source.messages.clone(),
            vec![SendCategory::SystemPrompt],
        );
        let content = render_category_preview(&source, None, UsageContextCategory::SystemPrompt);
        assert!(content.len() <= MAX_PREVIEW_BYTES);
        assert!(content.ends_with(PREVIEW_TRUNCATED_MARKER));
    }

    #[tokio::test]
    async fn registry_evicts_oldest_and_reports_evicted_previews() {
        let _guard = test_guard();
        clear_registry();
        let mut requests = Vec::new();
        for index in 0..=MAX_RETAINED_ENTRIES {
            let request = session_request(
                &format!("session-evict-{index}"),
                &format!("round-1:attempt:{index}"),
                index as u32,
                index as i64,
            );
            begin_attempt(
                prepared(
                    vec![AIMessage::system(format!("system-{index}"))],
                    vec![SendCategory::SystemPrompt],
                ),
                request.clone(),
                None,
                None,
                activation(),
            );
            requests.push(request);
        }
        assert_eq!(
            with_registry(|registry| registry.entries.len()),
            MAX_RETAINED_ENTRIES
        );
        assert_eq!(
            materialize_request_context_preview(&requests[0], UsageContextCategory::SystemPrompt),
            RequestContextPreview::Unavailable {
                reason: PREVIEW_EVICTED_REASON.to_string()
            }
        );
        match materialize_request_context_preview(
            &requests[MAX_RETAINED_ENTRIES],
            UsageContextCategory::SystemPrompt,
        ) {
            RequestContextPreview::Available { content, .. } => {
                assert_eq!(content, format!("system-{MAX_RETAINED_ENTRIES}"))
            }
            other => panic!("expected the newest retained source, got {other:?}"),
        }
        clear_registry();
    }

    #[tokio::test]
    async fn registry_keeps_at_most_four_entries_per_session() {
        let _guard = test_guard();
        clear_registry();
        let mut requests = Vec::new();
        for index in 0..=MAX_RETAINED_ENTRIES_PER_SESSION {
            let request = session_request(
                "session-busy",
                &format!("round-1:attempt:{index}"),
                index as u32,
                index as i64,
            );
            begin_attempt(
                prepared(
                    vec![AIMessage::system(format!("system-{index}"))],
                    vec![SendCategory::SystemPrompt],
                ),
                request.clone(),
                None,
                None,
                activation(),
            );
            requests.push(request);
        }
        let session_entries = with_registry(|registry| {
            registry
                .entries
                .iter()
                .filter(|entry| entry.request.session_id == "session-busy")
                .count()
        });
        assert_eq!(session_entries, MAX_RETAINED_ENTRIES_PER_SESSION);
        assert_eq!(
            materialize_request_context_preview(&requests[0], UsageContextCategory::SystemPrompt),
            RequestContextPreview::Unavailable {
                reason: PREVIEW_EVICTED_REASON.to_string()
            }
        );
        clear_registry();
    }

    #[tokio::test]
    async fn sources_over_the_size_limit_are_not_retained() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-large", "round-1:attempt:1", 1, 10);
        let large = "x".repeat(MAX_RETAINED_SOURCE_BYTES + 1);
        begin_attempt(
            prepared(
                vec![AIMessage::system(large)],
                vec![SendCategory::SystemPrompt],
            ),
            request.clone(),
            None,
            None,
            activation(),
        );
        assert_eq!(
            materialize_request_context_preview(&request, UsageContextCategory::SystemPrompt),
            RequestContextPreview::Unavailable {
                reason: PREVIEW_OVERSIZE_REASON.to_string()
            }
        );
        assert!(with_registry(|registry| registry.total_bytes <= MAX_TOTAL_RETAINED_BYTES));
        clear_registry();
    }

    fn tool(name: &str, description: &str) -> ToolDefinition {
        ToolDefinition {
            name: name.to_string(),
            description: description.to_string(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File to read" }
                },
                "required": ["path"]
            }),
        }
    }

    #[tokio::test]
    async fn tool_definitions_preview_renders_the_sent_schemas() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-tools", "round-1:attempt:1", 1, 10);
        let tools = Arc::new(vec![
            tool("read_file", "Read a file from the workspace"),
            tool("write_file", "Write a file in the workspace"),
        ]);
        begin_attempt(
            prepared(
                vec![AIMessage::system("tool calling guide".into())],
                vec![SendCategory::ToolDefinitions],
            ),
            request.clone(),
            Some(tools),
            None,
            activation(),
        );

        let content = match materialize_request_context_preview(
            &request,
            UsageContextCategory::ToolDefinitions,
        ) {
            RequestContextPreview::Available { content, .. } => content,
            other => panic!("expected the sent tool definitions, got {other:?}"),
        };
        for expected in [
            "### `read_file`",
            "Read a file from the workspace",
            "\"required\": [",
            "\"path\"",
            "### `write_file`",
            // The category's own message content still follows the schemas.
            "tool calling guide",
        ] {
            assert!(
                content.contains(expected),
                "preview is missing {expected}: {content}"
            );
        }
        // Another category never renders tool schemas.
        begin_attempt(
            prepared(
                vec![AIMessage::system("system body".into())],
                vec![SendCategory::SystemPrompt],
            ),
            request.clone(),
            Some(Arc::new(vec![tool("read_file", "Read a file")])),
            None,
            activation(),
        );
        match materialize_request_context_preview(&request, UsageContextCategory::SystemPrompt) {
            RequestContextPreview::Available { content, .. } => {
                assert_eq!(content, "system body", "tools belong to one category only")
            }
            other => panic!("expected the system prompt preview, got {other:?}"),
        }

        // The numeric bucket the UI shows stays non-zero for a captured attempt.
        let counted = session_request("session-tools-count", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hello"),
            counted.clone(),
            Some(Arc::new(vec![tool("read_file", "Read a file from the workspace")])),
            None,
            activation(),
        );
        wait_for_summary(&counted).await;
        let snapshot = activate_attempt(counted, None, None);
        let breakdown = snapshot.categories.expect("categories");
        assert!(
            breakdown.tool_definitions > 0,
            "the tool definitions bucket must count the sent schemas"
        );
        assert!(
            breakdown.conversation > 0,
            "the conversation bucket keeps counting messages"
        );
        clear_registry();
    }

    #[tokio::test]
    async fn oversize_tools_drop_messages_and_tools_together() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-tools-large", "round-1:attempt:1", 1, 10);
        let huge = "x".repeat(MAX_RETAINED_SOURCE_BYTES + 1);
        begin_attempt(
            prepared(
                vec![AIMessage::system("small system body".into())],
                vec![SendCategory::SystemPrompt],
            ),
            request.clone(),
            Some(Arc::new(vec![tool("read_file", &huge)])),
            None,
            activation(),
        );
        for category in [
            UsageContextCategory::ToolDefinitions,
            UsageContextCategory::SystemPrompt,
        ] {
            assert_eq!(
                materialize_request_context_preview(&request, category),
                RequestContextPreview::Unavailable {
                    reason: PREVIEW_OVERSIZE_REASON.to_string()
                },
                "an oversize request never falls back to the messages alone"
            );
        }
        assert_eq!(with_registry(|registry| registry.total_bytes), 0);
        clear_registry();
    }

    #[tokio::test]
    async fn summary_admission_is_bounded_and_degrades_to_pending() {
        let _guard = test_guard();
        clear_registry();
        // Drain the global permit pool, then start an attempt: it must not queue
        // a task that would hold its source for an unbounded time.
        let semaphore = Arc::clone(summary_semaphore());
        let mut held = Vec::new();
        for _ in 0..600 {
            if held.len() == MAX_CONCURRENT_SUMMARIES {
                break;
            }
            match semaphore.clone().try_acquire_owned() {
                Ok(permit) => held.push(permit),
                Err(_) => {
                    // A task of an earlier test may still be releasing its permit.
                    held.clear();
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        }
        assert_eq!(
            held.len(),
            MAX_CONCURRENT_SUMMARIES,
            "the summary permits must be drained for this test"
        );

        let burst = session_request("session-burst", "round-1:attempt:1", 1, 10);
        begin_attempt(
            conversation_input("hello"),
            burst.clone(),
            None,
            None,
            activation(),
        );
        assert!(
            matches!(summary_slot(&burst), Some(SummarySlot::Pending)),
            "an attempt without a free permit owns no job"
        );
        assert!(
            !request_context_summary_is_live(&burst),
            "a queued-but-not-running summary is never reported as live"
        );
        // Provider usage is still recorded; only the summary stays pending.
        let pending = activate_attempt(burst.clone(), Some(42), None);
        assert_eq!(pending.summary_state, UsageSummaryState::Pending);
        assert_eq!(pending.usage_state, UsageRequestUsageState::ProviderReported);
        assert_eq!(pending.input_total, Some(42));
        assert!(pending.categories.is_none());
        assert!(pending.estimated_total.is_none());
        assert!(!request_context_summary_is_live(&burst));
        assert!(activated_snapshot(&burst).is_some());

        // Once the pool drains, a later attempt summarizes normally.
        drop(held);
        let later = session_request("session-burst", "round-1:attempt:2", 2, 20);
        begin_attempt(
            conversation_input("hello"),
            later.clone(),
            None,
            None,
            activation(),
        );
        wait_for_summary(&later).await;
        let ready = activate_attempt(later, None, None);
        assert_eq!(ready.summary_state, UsageSummaryState::Ready);
        assert_eq!(ready.usage_state, UsageRequestUsageState::Estimated);
        assert!(ready.estimated_total.is_some());
        clear_registry();
    }

    #[tokio::test]
    async fn retry_attempts_keep_distinct_references_and_sources() {
        let _guard = test_guard();
        clear_registry();
        let first = session_request("session-retry", "round-1:attempt:1", 1, 10);
        let second = session_request("session-retry", "round-1:attempt:2", 2, 20);
        assert_ne!(first, second);
        for (request, body) in [(&first, "first body"), (&second, "second body")] {
            begin_attempt(
                prepared(
                    vec![AIMessage::system(body.to_string())],
                    vec![SendCategory::SystemPrompt],
                ),
                request.clone(),
                None,
                None,
                activation(),
            );
        }
        match materialize_request_context_preview(&first, UsageContextCategory::SystemPrompt) {
            RequestContextPreview::Available { content, .. } => assert_eq!(content, "first body"),
            other => panic!("expected the first attempt's source, got {other:?}"),
        }
        match materialize_request_context_preview(&second, UsageContextCategory::SystemPrompt) {
            RequestContextPreview::Available { content, .. } => assert_eq!(content, "second body"),
            other => panic!("expected the second attempt's source, got {other:?}"),
        }
        clear_registry();
    }

    #[tokio::test]
    async fn misaligned_prepared_input_is_never_recorded() {
        let _guard = test_guard();
        clear_registry();
        let request = session_request("session-misaligned", "round-1:attempt:1", 1, 10);
        begin_attempt(
            prepared(
                vec![AIMessage::user("body".into())],
                vec![SendCategory::Conversation, SendCategory::Conversation],
            ),
            request.clone(),
            None,
            None,
            activation(),
        );
        assert!(!request_context_summary_is_live(&request));
        assert_eq!(
            materialize_request_context_preview(&request, UsageContextCategory::SystemPrompt),
            RequestContextPreview::Unavailable {
                reason: PREVIEW_RESTART_REASON.to_string()
            }
        );
        clear_registry();
    }

    #[tokio::test]
    async fn conversation_and_summary_are_numeric_only_categories() {
        let _guard = test_guard();
        assert_eq!(SendCategory::Conversation.preview_category(), None);
        assert_eq!(SendCategory::SummarizedConversation.preview_category(), None);
        assert_eq!(
            SendCategory::SystemPrompt.preview_category(),
            Some(UsageContextCategory::SystemPrompt)
        );
        let breakdown = summarize_send_input(
            &[
                AIMessage::user("conversation".into()),
                AIMessage::user("summary".into()),
            ],
            &[SendCategory::Conversation, SendCategory::SummarizedConversation],
            None,
            None,
        );
        assert!(breakdown.conversation > 0);
        assert!(breakdown.summarized_conversation > 0);
    }

    #[tokio::test]
    async fn execution_host_identity_is_local_without_a_workspace() {
        let _guard = test_guard();
        assert_eq!(execution_host_id(None), LOCAL_EXECUTION_HOST_ID);
    }

    #[tokio::test]
    async fn summarize_attributes_tokens_to_the_typed_category() {
        let _guard = test_guard();
        let domain = DomainMessage::system("system body".into());
        let ai = AIMessage::from(&domain);
        let tokens = TokenCounter::estimate_message_tokens(&ai) as u64;
        let breakdown = summarize_send_input(
            std::slice::from_ref(&ai),
            &[SendCategory::SystemPrompt],
            Some(&[ToolDefinition {
                name: "Read".into(),
                description: "Read a file".into(),
                parameters: serde_json::json!({"type": "object"}),
            }]),
            Some(128_000),
        );
        assert_eq!(breakdown.system_prompt, tokens);
        assert_eq!(breakdown.conversation, 0);
        assert!(breakdown.tool_definitions > 0);
        assert_eq!(breakdown.context_window, Some(128_000));
        assert!(breakdown_total(&breakdown) > breakdown.system_prompt);
    }
}
