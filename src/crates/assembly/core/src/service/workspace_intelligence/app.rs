//! WP3.1a app-facing facade: the one surface an application drives.
//!
//! # What this module is
//!
//! [`WorkspaceIntelligenceApp`] is a thin, typed projection over one
//! [`WorkspaceIntelligenceHost`] handle. It answers the questions a settings surface
//! asks — what the host looks like, what one workspace's tier is, what the legacy
//! source holds, whether a workspace can be prepared, confirmed or disabled — and every
//! answer is a stable code, never a path, a scope string, a token, a lease or a raw
//! stored payload.
//!
//! # What it deliberately is not
//!
//! - It owns no policy, no storage and no decision: every answer is either a projection
//!   of facts the host already decided, or a call into the host's own crate-internal
//!   entry points. Nothing here enables, disables, prepares or confirms on its own.
//! - It is not a transport. There is no command name, no registry row, no capability and
//!   no UI here; those are later slices that consume this facade.
//! - It does not widen the host: the handle's crate-internal entry points stay
//!   crate-internal, and this module is the only reason any of them is reachable outside
//!   the `host` module.
//!
//! # Availability
//!
//! The facade exists in every build. A build without `workspace-intelligence-host` still
//! constructs one from [`WorkspaceIntelligenceHost::not_compiled`] and gets a
//! [`WorkspaceIntelligenceAppStatus`] that reports the surface as unavailable with the
//! stable code `host_not_compiled`, instead of a compile error or a silent success. The
//! operations then do not exist at all, because there is nothing truthful they could
//! answer.
//!
//! # The one degraded projection
//!
//! The status projection reports delivery and model resolution from the same two sources
//! the scoped read decision uses, and this tree has no model catalogue: a configured
//! workspace model reference is therefore always unresolvable here, so an `intelligent`
//! workspace is projected as degraded (`model_ref_unresolved`) until the resolver slice
//! lands. That is a fact about this tree, not a fallback: no reference is rewritten,
//! dropped or replaced, and the tier itself is unaffected.

use serde::{Deserialize, Serialize};

use super::host::{WorkspaceIntelligenceHost, WorkspaceIntelligenceHostState};
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
use super::confirm::{ConfirmOutcome, ConfirmRefusal};
#[cfg(feature = "workspace-intelligence-host")]
use super::control::{ControlAuthority, ControlObservation};
#[cfg(feature = "workspace-intelligence-host")]
use super::host::{
    InitialEnableRefusal, ScopeDisableOutcome, WorkspaceIntelligenceHostScopeReport,
};
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
use super::legacy_preview::{
    AttributedCandidate, LegacyPreview, LegacySourceFingerprint, PreviewDiagnostic,
    UnattributedItem, UnattributedKind, UnattributedReason,
};
#[cfg(feature = "workspace-intelligence-host")]
use super::mode::{CapabilityDelivery, DerivedMode, WorkspaceIntelligenceTier};
use super::migration::{
    validate_migration, Assignment, MigrationDecision, MigrationSourceFingerprint,
};
#[cfg(feature = "workspace-intelligence-host")]
use super::migration::decode_migration;
#[cfg(feature = "workspace-intelligence-host")]
use openbitfun_services_core::workspace_intelligence_claim::{
    InitialEnableRefusal as ReservationRefusal,
};
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
use std::path::Path;

/// One host-and-scope snapshot as an application renders it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIntelligenceAppStatus {
    /// Stable code of the host state.
    pub host_state: String,
    /// Stable code of the first blocking reason, when the host reports one.
    pub reason: Option<String>,
    /// True when this application may show the workspace intelligence surface.
    ///
    /// It is false for every host state in which this host cannot answer for a workspace
    /// at all (`not_compiled`, `unavailable`, `draining`, `stopped`), and
    /// `unavailability` says which one it is.
    pub surface_available: bool,
    /// Stable code of why the surface is unavailable, when it is.
    pub unavailability: Option<String>,
    /// One row per enumerated scope, in the host's own order.
    pub scopes: Vec<WorkspaceIntelligenceScopeStatus>,
}

/// One workspace's projection.
///
/// The tier and the availability are deliberately two columns: a workspace can be
/// `intelligent` and still be unable to *use* its model right now, and a surface that
/// folded the two together could not tell "off" from "not working yet".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceIntelligenceScopeStatus {
    /// Persisted workspace id this row describes.
    pub workspace_id: String,
    /// Derived tier: `off`, `baseline` or `intelligent`.
    ///
    /// `off` on its own does **not** mean "the workspace is switched off": when
    /// `availability` is `control_unreadable` the record exists but could not be read, so
    /// the tier is unknown and this value is only the fail-closed placeholder. A surface
    /// must decide whether the workspace is operable from `availability` (and
    /// `control_fault`), never from `tier` alone.
    pub tier: String,
    /// Why the tier's model capability can or cannot be used: `available`,
    /// `model_ref_unresolved`, `ai_not_delivered` or `control_unreadable`.
    ///
    /// `control_unreadable` means the stored record could not be read at all, which
    /// includes a record written by a newer build (an unsupported schema version), a
    /// corrupt document and a storage failure. The workspace may well be enabled; this
    /// build simply cannot say.
    pub availability: String,
    /// Stable store-fault code of an unreadable record, when `availability` is
    /// `control_unreadable`. It is a stable code only: no path, no raw document and no
    /// error text.
    pub control_fault: Option<String>,
    /// True when a configured model reference does not resolve. Orthogonal to the tier:
    /// a degraded `intelligent` workspace is still `intelligent`.
    pub degraded: bool,
    /// Stable code of this scope's disposition in the host's last pass.
    pub host_state: Option<String>,
    /// Stable code of the block phase, when the scope is blocked.
    pub block: Option<String>,
    /// Reserved for the slice that reviews an execution binding when a workspace moves.
    /// Always false here: this slice has no binding review surface.
    pub binding_review_required: bool,
    /// The stored migration decision, when this build can decode one.
    pub migration: Option<MigrationReport>,
    /// Observed control generation, when a record was observed.
    pub generation: Option<u64>,
}

/// The stored migration decision, projected.
///
/// Only the identity and the shape are reported: no assignment key, no workspace and no
/// fingerprint travels, because a surface that listed them would become a second,
/// unbounded copy of the stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationReport {
    /// Idempotency key of the stored decision.
    pub idempotency_key: String,
    /// When the decision was taken, in Unix milliseconds.
    pub decided_at_unix_ms: i64,
    /// How many assignments of each kind the decision holds.
    pub assignment_counts: MigrationAssignmentCounts,
}

/// Assignment counts of one migration decision.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationAssignmentCounts {
    /// Assignments that keep the content shared.
    pub keep_shared: usize,
    /// Assignments that move the content to one workspace.
    pub assign_to: usize,
    /// Assignments that defer the recall of the content.
    pub defer_recall: usize,
}

/// One read-only preview of a workspace's legacy Memory source.
///
/// Attribution is filtered to this workspace: `attributed` holds only the candidates
/// whose normalized workspace is the previewed one, while `unattributed` holds every
/// candidate no workspace could claim, which is a fact about the source rather than about
/// one workspace and therefore travels whole.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyPreviewReport {
    /// The fingerprint the preview was built from.
    pub fingerprint: FingerprintDto,
    /// Candidates attributed to this workspace.
    pub attributed: Vec<LegacyAttributedRow>,
    /// Candidates no workspace could claim.
    pub unattributed: Vec<LegacyUnattributedRow>,
    /// Stable codes of the parts of the source this build could not read.
    pub diagnostics: Vec<String>,
}

/// One legacy row attributed to the previewed workspace.
///
/// The content hash travels instead of the content, so a preview can be rendered and
/// compared without carrying memory bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyAttributedRow {
    /// Legacy thread identifier of the row.
    pub thread_id: String,
    /// Source timestamp of the row, in Unix seconds.
    pub source_updated_at: i64,
    /// Hash of the row's content.
    pub content_hash: String,
}

/// One legacy item that no workspace could claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyUnattributedRow {
    /// Stable code of the legacy layer the item came from.
    pub kind: String,
    /// Row identifier, or the slash-normalized relative note path.
    pub key: String,
    /// Stable code of why the item stayed unattributed.
    pub reason: String,
}

/// The stable fingerprint of one legacy source.
///
/// It travels as data because a confirmation must hand back the very fingerprint it
/// previewed, and because a surface that renders it must not re-derive it: the host
/// compares exactly this value against a fresh read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FingerprintDto {
    /// Number of legacy rows the preview saw.
    pub row_count: u64,
    /// Digest over every projected field of every row.
    pub rows_digest: String,
    /// The projected column list this build expects.
    pub schema_shape: String,
    /// Hash over the derived file tree.
    pub derived_tree_hash: String,
    /// Hash over the note file tree.
    pub notes_tree_hash: String,
    /// Whether the database file existed at all.
    pub db_present: bool,
}

/// One migration decision as an application submits it.
///
/// Every field is required. The host re-validates the whole decision before it writes
/// anything, so a caller cannot store a decision this tree could not read back.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MigrationDecisionInput {
    /// Caller-generated idempotency key of this decision.
    pub idempotency_key: String,
    /// When the user took the decision, in Unix milliseconds.
    pub decided_at_unix_ms: i64,
    /// The fingerprint the decision was taken against.
    pub source: FingerprintDto,
    /// What the user assigned.
    pub assignments: Vec<AssignmentInput>,
}

/// One assignment as an application submits it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssignmentInput {
    /// Assignment kind: `keep_shared`, `assign_to` or `defer_recall`.
    pub kind: String,
    /// Legacy row or note the assignment names.
    pub key: String,
    /// Target workspace of an `assign_to` assignment.
    pub workspace: Option<String>,
}

/// What one confirmed enable produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmReport {
    /// `enabled`, `enabled_partition_pending` or `already_confirmed`.
    pub outcome: String,
    /// Control generation after the write, when the switch is on.
    pub generation: Option<u64>,
    /// Whether the enable preserved a configured workspace model reference.
    pub intelligent: Option<bool>,
}

/// What one OFF mutation produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisableReport {
    /// Control generation after the call.
    pub generation: u64,
    /// True when this call wrote the switch off, false when it already read off.
    pub changed: bool,
}

/// Why one app-facing call was refused.
///
/// Every variant carries either nothing or one already-stable code, so a surface can
/// render or log it without exposing a path, a scope, a payload or an error text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppRefusal {
    /// The host is draining or stopped.
    Stopping,
    /// No live preparation exists for this workspace.
    NotPrepared,
    /// The workspace is already enabled.
    AlreadyEnabled,
    /// One typed host refusal, carried as its stable code.
    Host(String),
    /// The record changed between the preparation and this call.
    ControlChanged,
    /// A decision with this idempotency key is already stored with another payload.
    DecisionConflict,
    /// The legacy source moved since the fingerprint the decision recorded.
    SourceChanged,
    /// The legacy source cannot be read in the shape this build expects.
    SourceUnreadable,
    /// The submitted decision is invalid, carried as its validation code.
    InvalidDecision(String),
    /// One control-storage failure, carried as its stable code.
    Control(String),
    /// The caller's expected control generation is no longer current.
    StaleGeneration,
    /// The workspace is not in this host's persisted catalogue.
    WorkspaceNotFound,
    /// An outcome this facade never requests. Refused rather than retried.
    Internal,
}

impl AppRefusal {
    /// Stable machine-readable code for a surface, a log or a test.
    pub fn code(&self) -> &str {
        match self {
            Self::Stopping => "stopping",
            Self::NotPrepared => "not_prepared",
            Self::AlreadyEnabled => "already_enabled",
            Self::Host(code) => code,
            Self::ControlChanged => "control_changed",
            Self::DecisionConflict => "decision_conflict",
            Self::SourceChanged => "source_changed",
            Self::SourceUnreadable => "source_unreadable",
            Self::InvalidDecision(code) => code,
            Self::Control(code) => code,
            Self::StaleGeneration => "stale_generation",
            Self::WorkspaceNotFound => "workspace_not_found",
            Self::Internal => "internal",
        }
    }
}

impl std::fmt::Display for AppRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}

impl std::error::Error for AppRefusal {}

/// What the status projection learned about one scope's control record.
#[cfg(feature = "workspace-intelligence-host")]
enum ScopeRecord {
    /// No scope can be named yet, so no record can exist.
    Absent,
    /// The record was observed in one read.
    Observed(Box<ControlObservation>),
    /// The scope or its record refused the read.
    Unreadable,
}

/// The app-facing facade over one workspace intelligence host handle.
///
/// Cheap to clone in the builds that compile the host: the handle it wraps is one shared
/// owner, not one host per facade.
#[derive(Clone)]
pub struct WorkspaceIntelligenceApp {
    host: WorkspaceIntelligenceHost,
}

impl std::fmt::Debug for WorkspaceIntelligenceApp {
    /// Names the facade only: the handle it wraps holds private identity and paths.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkspaceIntelligenceApp")
    }
}

impl WorkspaceIntelligenceHost {
    /// The app-facing facade of this handle.
    ///
    /// The facade borrows nothing and owns nothing new: it is the same host, answered in
    /// the vocabulary a surface renders.
    pub fn app(&self) -> WorkspaceIntelligenceApp {
        WorkspaceIntelligenceApp {
            host: self.clone(),
        }
    }
}

impl WorkspaceIntelligenceApp {
    /// Current host status, with one projected row per enumerated scope.
    ///
    /// A scope row costs one read of the catalogue, the anchor and the control record,
    /// which is the same read a single [`Self::scope_status`] makes: a host whose pass
    /// enumerated nothing reports no rows rather than inventing them.
    pub async fn status(&self) -> WorkspaceIntelligenceAppStatus {
        let status = self.host.status().await;
        let (surface_available, unavailability) = surface_availability(status.state());
        #[cfg(feature = "workspace-intelligence-host")]
        let scopes = {
            let mut scopes = Vec::with_capacity(status.scopes().len());
            for report in status.scopes() {
                let record = self
                    .scope_record(report.scope())
                    .await
                    .unwrap_or(ScopeRecord::Unreadable);
                let row = scope_projection(report.scope(), Some(report), record);
                scopes.push(row);
            }
            scopes
        };
        // Without the host feature there is no scope to enumerate and no record to read,
        // so the row list is empty rather than absent.
        #[cfg(not(feature = "workspace-intelligence-host"))]
        let scopes: Vec<WorkspaceIntelligenceScopeStatus> = Vec::new();
        WorkspaceIntelligenceAppStatus {
            host_state: status.state().code().to_owned(),
            reason: status.reason().map(|reason| reason.code().to_owned()),
            surface_available,
            unavailability,
            scopes,
        }
    }

    /// One workspace's projection.
    ///
    /// This works even when the host's last pass enumerated no scopes: the catalogue and
    /// the record are read for this workspace alone.
    #[cfg(feature = "workspace-intelligence-host")]
    pub async fn scope_status(
        &self,
        workspace_id: &str,
    ) -> Result<WorkspaceIntelligenceScopeStatus, AppRefusal> {
        let status = self.host.status().await;
        let report = status
            .scopes()
            .iter()
            .find(|report| report.scope() == workspace_id);
        let record = self.scope_record(workspace_id).await?;
        Ok(scope_projection(workspace_id, report, record))
    }

    /// One read-only preview of a workspace's legacy Memory source.
    #[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
    pub async fn preview_legacy(
        &self,
        workspace_id: &str,
    ) -> Result<LegacyPreviewReport, AppRefusal> {
        match self.host.legacy_preview_of(workspace_id).await {
            Ok(Some((root, preview))) => Ok(legacy_report(&root, preview)),
            // The blocking read itself did not complete: a host-side fault, never a
            // statement about the source.
            Ok(None) => Err(AppRefusal::Internal),
            Err(refusal) => Err(app_refusal_of(&refusal)),
        }
    }

    /// Queues one initial-enable preparation of this workspace.
    ///
    /// The queued tenure stays with the host: it is released by the matching
    /// confirmation, by [`Self::cancel_enable`], or by the drain, and never by this call
    /// returning. Nothing is enabled here.
    #[cfg(feature = "workspace-intelligence-host")]
    pub async fn prepare_enable(&self, workspace_id: &str) -> Result<(), AppRefusal> {
        self.host
            .prepare_initial_enable_queued(workspace_id)
            .await
            .map_err(|refusal| app_refusal_of(&refusal))
    }

    /// Revokes the queued preparation of one workspace.
    ///
    /// Answers `false` when nothing was queued for it, which includes a workspace this
    /// host cannot name a scope for yet.
    #[cfg(feature = "workspace-intelligence-host")]
    pub async fn cancel_enable(&self, workspace_id: &str) -> bool {
        self.host.cancel_initial_enable(workspace_id).await
    }

    /// Confirms the one OFF-to-ON transition of one workspace.
    ///
    /// The decision is validated here and then re-read, re-compared and re-validated by
    /// the host before it writes: a source that moved since the preview is
    /// [`AppRefusal::SourceChanged`] and nothing is stored.
    #[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
    pub async fn confirm_enable(
        &self,
        workspace_id: &str,
        input: MigrationDecisionInput,
    ) -> Result<ConfirmReport, AppRefusal> {
        let decision = input.into_decision()?;
        match self.host.confirm_initial_enable(workspace_id, decision).await {
            Ok(outcome) => Ok(confirm_report(outcome)),
            Err(refusal) => {
                if matches!(refusal, ConfirmRefusal::SourceChanged) {
                    // One grep-able line per confirmation refused by a moved source, so a
                    // support session can count them. The workspace id is the persisted
                    // directory id, not the storage scope, and no fingerprint is logged.
                    log::info!(
                        "Workspace intelligence legacy source moved since the preview: \
                         workspace_id={} reason=source_changed",
                        workspace_id
                    );
                }
                Err(app_refusal_of_confirm(refusal))
            }
        }
    }

    /// Stores one workspace OFF under the caller's expected generation.
    ///
    /// Nothing is created and nothing is skipped: a record that moved since the caller
    /// read it is [`AppRefusal::StaleGeneration`], and a workspace without a record is a
    /// typed [`AppRefusal::Control`] answer instead of a freshly written OFF record.
    #[cfg(feature = "workspace-intelligence-host")]
    pub async fn disable(
        &self,
        workspace_id: &str,
        expected_generation: u64,
    ) -> Result<DisableReport, AppRefusal> {
        match self.host.disable_scope(workspace_id, expected_generation).await {
            Ok(ScopeDisableOutcome::Disabled { generation }) => Ok(DisableReport {
                generation,
                changed: true,
            }),
            Ok(ScopeDisableOutcome::AlreadyDisabled { generation }) => Ok(DisableReport {
                generation,
                changed: false,
            }),
            Ok(ScopeDisableOutcome::StaleGeneration) => Err(AppRefusal::StaleGeneration),
            Ok(ScopeDisableOutcome::RecordMissing) => {
                Err(AppRefusal::Control("control_record_missing".to_owned()))
            }
            Ok(ScopeDisableOutcome::Unreadable { fault }) => {
                Err(AppRefusal::Control(fault.to_owned()))
            }
            Ok(ScopeDisableOutcome::Failed { code }) => Err(AppRefusal::Control(code.to_owned())),
            Err(refusal) => Err(app_refusal_of(&refusal)),
        }
    }

    /// Reads one scope's control record for the status projection.
    #[cfg(feature = "workspace-intelligence-host")]
    async fn scope_record(&self, workspace_id: &str) -> Result<ScopeRecord, AppRefusal> {
        match self.host.scope_control_observation(workspace_id).await {
            Ok(Some(observation)) => Ok(ScopeRecord::Observed(Box::new(observation))),
            Ok(None) => Ok(ScopeRecord::Absent),
            Err(refusal) => Err(app_refusal_of(&refusal)),
        }
    }
}

/// The control-record half of one scope's projection.
///
/// Kept apart from the host-disposition fields so the one place that decides "unknown
/// versus off" is the authority match below, not five separate ternaries.
#[cfg(feature = "workspace-intelligence-host")]
struct ProjectedRecord {
    tier: &'static str,
    availability: &'static str,
    control_fault: Option<&'static str>,
    degraded: bool,
    generation: Option<u64>,
    migration: Option<MigrationReport>,
}

/// Projects one scope from its host disposition and its control record.
///
/// The authority decides first, because "no record", "a record I cannot read" and "a
/// record I read" are three different answers:
///
/// - no record at all is a genuine `off`/`available`, and so is a scope with no storage
///   namespace yet;
/// - an existing record this build cannot read — a newer schema version, a corrupt
///   document, a storage fault — is `off` only as a fail-closed placeholder, paired with
///   `availability = control_unreadable` and the store's stable fault code. Projecting it
///   as a healthy `off` would tell a surface that an enabled workspace is switched off;
/// - a record that was read projects its derived tier and its own availability.
#[cfg(feature = "workspace-intelligence-host")]
fn scope_projection(
    workspace_id: &str,
    report: Option<&WorkspaceIntelligenceHostScopeReport>,
    record: ScopeRecord,
) -> WorkspaceIntelligenceScopeStatus {
    let host_state = report.map(|report| report.state().code().to_owned());
    let block = report
        .and_then(|report| report.block())
        .map(|block| block.code().to_owned());
    let projected = match &record {
        ScopeRecord::Absent => ProjectedRecord {
            tier: "off",
            availability: "available",
            control_fault: None,
            degraded: false,
            generation: None,
            migration: None,
        },
        // A scope whose record could not even be observed is unknown, not off: the same
        // fail-closed placeholder and the same availability code the unreadable
        // observation below uses, without a fault code because no store fault was named.
        ScopeRecord::Unreadable => ProjectedRecord {
            tier: "off",
            availability: "control_unreadable",
            control_fault: None,
            degraded: false,
            generation: None,
            migration: None,
        },
        ScopeRecord::Observed(observation) => match observation.authority {
            // The record exists but this read could not decode it. Its own tier is a
            // fail-closed `off` derived from an unobserved read, so it must never be
            // reported as a healthy off state.
            ControlAuthority::Unavailable { fault } => ProjectedRecord {
                tier: "off",
                availability: "control_unreadable",
                control_fault: Some(fault.code()),
                degraded: false,
                generation: None,
                migration: None,
            },
            ControlAuthority::NotObserved => ProjectedRecord {
                tier: tier_code(observation.mode.tier),
                availability: availability_code(&observation.mode),
                control_fault: None,
                degraded: observation.mode.is_degraded(),
                generation: None,
                migration: None,
            },
            ControlAuthority::Observed { generation, .. } => ProjectedRecord {
                tier: tier_code(observation.mode.tier),
                availability: availability_code(&observation.mode),
                control_fault: None,
                degraded: observation.mode.is_degraded(),
                generation: Some(generation),
                migration: observation
                    .migration_payload()
                    .and_then(|payload| decode_migration(payload).ok())
                    .as_ref()
                    .map(migration_report),
            },
        },
    };
    WorkspaceIntelligenceScopeStatus {
        workspace_id: workspace_id.to_owned(),
        tier: projected.tier.to_owned(),
        availability: projected.availability.to_owned(),
        control_fault: projected.control_fault.map(str::to_owned),
        degraded: projected.degraded,
        host_state,
        block,
        // This slice has no binding review surface; the owning slice fills it in.
        binding_review_required: false,
        migration: projected.migration,
        generation: projected.generation,
    }
}

/// Stable code of one derived tier.
#[cfg(feature = "workspace-intelligence-host")]
fn tier_code(tier: WorkspaceIntelligenceTier) -> &'static str {
    match tier {
        WorkspaceIntelligenceTier::Off => "off",
        WorkspaceIntelligenceTier::Baseline => "baseline",
        WorkspaceIntelligenceTier::Intelligent => "intelligent",
    }
}

/// Stable code of one tier's usability, separate from the tier itself.
///
/// Delivery is checked first because a capability the host cannot deliver is the more
/// fundamental fact; a delivered capability with an unresolvable model reference is the
/// degraded case. `off` is never degraded, so it always reads `available`.
#[cfg(feature = "workspace-intelligence-host")]
fn availability_code(mode: &DerivedMode) -> &'static str {
    if matches!(mode.tier, WorkspaceIntelligenceTier::Off) {
        return "available";
    }
    match mode.delivery {
        CapabilityDelivery::Unavailable => "ai_not_delivered",
        CapabilityDelivery::Delivered if mode.is_degraded() => "model_ref_unresolved",
        CapabilityDelivery::Delivered => "available",
    }
}

/// Whether a surface may be shown for one host state, and why not when it may not.
fn surface_availability(state: WorkspaceIntelligenceHostState) -> (bool, Option<String>) {
    match state {
        WorkspaceIntelligenceHostState::Inactive
        | WorkspaceIntelligenceHostState::Active
        | WorkspaceIntelligenceHostState::Degraded => (true, None),
        WorkspaceIntelligenceHostState::NotCompiled => {
            (false, Some("host_not_compiled".to_owned()))
        }
        WorkspaceIntelligenceHostState::Unavailable => (false, Some("host_unavailable".to_owned())),
        WorkspaceIntelligenceHostState::Draining => (false, Some("host_draining".to_owned())),
        WorkspaceIntelligenceHostState::Stopped => (false, Some("host_stopped".to_owned())),
    }
}

/// Projects one stored decision into its report.
#[cfg(feature = "workspace-intelligence-host")]
fn migration_report(decision: &MigrationDecision) -> MigrationReport {
    let mut counts = MigrationAssignmentCounts::default();
    for assignment in &decision.assignments {
        match assignment {
            Assignment::KeepShared { .. } => counts.keep_shared += 1,
            Assignment::AssignTo { .. } => counts.assign_to += 1,
            Assignment::DeferRecall { .. } => counts.defer_recall += 1,
        }
    }
    MigrationReport {
        idempotency_key: decision.idempotency_key.clone(),
        decided_at_unix_ms: decision.decided_at_unix_ms,
        assignment_counts: counts,
    }
}

/// Projects one confirmation outcome into its report.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn confirm_report(outcome: ConfirmOutcome) -> ConfirmReport {
    match outcome {
        ConfirmOutcome::Enabled {
            generation,
            intelligent,
        } => ConfirmReport {
            outcome: "enabled".to_owned(),
            generation: Some(generation),
            intelligent: Some(intelligent),
        },
        ConfirmOutcome::EnabledPartitionPending => ConfirmReport {
            outcome: "enabled_partition_pending".to_owned(),
            generation: None,
            intelligent: None,
        },
        ConfirmOutcome::AlreadyConfirmed => ConfirmReport {
            outcome: "already_confirmed".to_owned(),
            generation: None,
            intelligent: None,
        },
    }
}

/// Maps one enable-path refusal into the facade's vocabulary.
///
/// Exhaustive with no wildcard: a new refusal must be classified here, and nothing but a
/// stable code crosses into the facade.
#[cfg(feature = "workspace-intelligence-host")]
fn app_refusal_of(refusal: &InitialEnableRefusal) -> AppRefusal {
    match refusal {
        InitialEnableRefusal::Stopping => AppRefusal::Stopping,
        InitialEnableRefusal::AlreadyEnabled => AppRefusal::AlreadyEnabled,
        InitialEnableRefusal::ControlChanged => AppRefusal::ControlChanged,
        InitialEnableRefusal::Host(reason) => AppRefusal::Host(reason.code().to_owned()),
        InitialEnableRefusal::UnsupportedScope(scope) => AppRefusal::Host(scope.code().to_owned()),
        // Both reservation refusals are already-decided facts about the record, not a
        // storage fault.
        InitialEnableRefusal::ReserveRefused(reason) => match reason {
            ReservationRefusal::AlreadyEnabled => AppRefusal::AlreadyEnabled,
            ReservationRefusal::AuthorityChanged => AppRefusal::ControlChanged,
        },
        InitialEnableRefusal::WorkspaceNotFound => AppRefusal::WorkspaceNotFound,
        InitialEnableRefusal::UnrenderableWorktreeMainPath => {
            AppRefusal::Host("unrenderable_worktree_main_path".to_owned())
        }
        InitialEnableRefusal::AnchorChanged => AppRefusal::Host("anchor_changed".to_owned()),
        InitialEnableRefusal::ControlSchemaUnsupported => {
            AppRefusal::Host("control_schema_unsupported".to_owned())
        }
        InitialEnableRefusal::ControlPolicyUnreadable => {
            AppRefusal::Host("control_policy_unreadable".to_owned())
        }
        InitialEnableRefusal::AnchorPreparationFailed => {
            AppRefusal::Host("anchor_preparation_failed".to_owned())
        }
        InitialEnableRefusal::AnchorNamespaceBusy => {
            AppRefusal::Host("anchor_namespace_busy".to_owned())
        }
        InitialEnableRefusal::ReserveBusy => AppRefusal::Host("reserve_busy".to_owned()),
        InitialEnableRefusal::ReserveFailed => AppRefusal::Host("reserve_failed".to_owned()),
        InitialEnableRefusal::Abandoned => AppRefusal::Host("abandoned".to_owned()),
    }
}

/// Maps one confirmation refusal into the facade's vocabulary.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn app_refusal_of_confirm(refusal: ConfirmRefusal) -> AppRefusal {
    match refusal {
        ConfirmRefusal::Stopping => AppRefusal::Stopping,
        ConfirmRefusal::NotPrepared => AppRefusal::NotPrepared,
        ConfirmRefusal::AlreadyEnabled => AppRefusal::AlreadyEnabled,
        ConfirmRefusal::Host(code) => AppRefusal::Host(code.to_owned()),
        ConfirmRefusal::ControlChanged => AppRefusal::ControlChanged,
        ConfirmRefusal::DecisionConflict => AppRefusal::DecisionConflict,
        ConfirmRefusal::SourceChanged => AppRefusal::SourceChanged,
        ConfirmRefusal::SourceUnreadable => AppRefusal::SourceUnreadable,
        ConfirmRefusal::InvalidDecision(code) => AppRefusal::InvalidDecision(code.to_owned()),
        ConfirmRefusal::Control(code) => AppRefusal::Control(code.to_owned()),
        ConfirmRefusal::Internal => AppRefusal::Internal,
    }
}

/// Projects one legacy preview into this workspace's report.
///
/// Explicit shared scopes do not exist in this phase, so attribution is a plain
/// comparison against this workspace's own normalized root. That comparison needs the
/// root to normalize, which requires it to exist right now: a root on an offline disk or
/// a workspace deleted since the row was written attributes nothing, and the report says
/// so instead of silently returning an empty list a surface would read as "no legacy
/// content".
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn legacy_report(root: &str, preview: LegacyPreview) -> LegacyPreviewReport {
    // The preview stores each row's *normalized* workspace, so both sides must be
    // normalized the same way. A row the preview itself could not normalize already
    // travels in `unattributed`.
    let normalized_root =
        openbitfun_services_core::workspace_identity::normalize_local_workspace_root_for_stable_id(
            Path::new(root),
        )
        .ok();
    let attributed = preview
        .attributed
        .into_iter()
        .filter(|candidate: &AttributedCandidate| {
            normalized_root
                .as_deref()
                .is_some_and(|root| root == candidate.normalized_workspace)
        })
        .map(|candidate| LegacyAttributedRow {
            thread_id: candidate.thread_id,
            source_updated_at: candidate.source_updated_at,
            content_hash: candidate.content_hash,
        })
        .collect();
    let unattributed = preview
        .unattributed
        .into_iter()
        .map(|item: UnattributedItem| LegacyUnattributedRow {
            kind: unattributed_kind_code(item.kind).to_owned(),
            key: item.key,
            reason: unattributed_reason_code(item.reason).to_owned(),
        })
        .collect();
    let mut diagnostics: Vec<String> = preview
        .diagnostics
        .into_iter()
        .map(|diagnostic: PreviewDiagnostic| diagnostic.as_str().to_owned())
        .collect();
    if normalized_root.is_none() {
        // Not a preview diagnostic: the source itself was read fine. This is a fact about
        // the *workspace root* the attribution needed, and it is appended so an empty
        // `attributed` list is never mistaken for "this workspace has no legacy content".
        diagnostics.push(WORKSPACE_ROOT_UNRESOLVABLE.to_owned());
    }
    LegacyPreviewReport {
        fingerprint: fingerprint_dto(&preview.source),
        attributed,
        unattributed,
        diagnostics,
    }
}

/// Stable code of a workspace root the attribution could not normalize.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
const WORKSPACE_ROOT_UNRESOLVABLE: &str = "workspace_root_unresolvable";

/// Stable code of one unattributed item's legacy layer.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn unattributed_kind_code(kind: UnattributedKind) -> &'static str {
    match kind {
        UnattributedKind::LegacyRow => "legacy_row",
        UnattributedKind::AdHocNote => "ad_hoc_note",
    }
}

/// Stable code of why one item stayed unattributed.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn unattributed_reason_code(reason: UnattributedReason) -> &'static str {
    match reason {
        UnattributedReason::UnnormalizablePath => "unnormalizable_path",
        UnattributedReason::NoWorkspaceField => "no_workspace_field",
    }
}

/// Projects one read fingerprint into its transport shape.
#[cfg(all(feature = "workspace-intelligence-host", feature = "agent-runtime"))]
fn fingerprint_dto(fingerprint: &LegacySourceFingerprint) -> FingerprintDto {
    FingerprintDto {
        row_count: fingerprint.row_count,
        rows_digest: fingerprint.rows_digest.clone(),
        schema_shape: fingerprint.schema_shape.clone(),
        derived_tree_hash: fingerprint.derived_tree_hash.clone(),
        notes_tree_hash: fingerprint.notes_tree_hash.clone(),
        db_present: fingerprint.db_present,
    }
}

impl MigrationDecisionInput {
    /// Turns one submitted decision into the decision the host re-validates.
    ///
    /// The shape is checked here so a malformed submission never reaches the host, and
    /// the host checks it again because nothing a caller sends is trusted for a write. An
    /// `assign_to` assignment without a target workspace is deliberately kept as an empty
    /// workspace, which the shared validation refuses as `blank_workspace`, so the two
    /// layers cannot disagree about that case.
    #[cfg_attr(
        not(all(feature = "workspace-intelligence-host", feature = "agent-runtime")),
        allow(
            dead_code,
            reason = "consumed by the confirmation, which requires the host and agent-runtime"
        )
    )]
    fn into_decision(self) -> Result<MigrationDecision, AppRefusal> {
        let mut assignments = Vec::with_capacity(self.assignments.len());
        for assignment in self.assignments {
            let key = assignment.key;
            let parsed = match assignment.kind.as_str() {
                "keep_shared" => Assignment::KeepShared { key },
                "assign_to" => Assignment::AssignTo {
                    key,
                    workspace: assignment.workspace.unwrap_or_default(),
                },
                "defer_recall" => Assignment::DeferRecall { key },
                _ => {
                    return Err(AppRefusal::InvalidDecision(
                        "unknown_assignment_kind".to_owned(),
                    ))
                }
            };
            assignments.push(parsed);
        }
        let decision = MigrationDecision {
            idempotency_key: self.idempotency_key,
            decided_at_unix_ms: self.decided_at_unix_ms,
            source: MigrationSourceFingerprint {
                row_count: self.source.row_count,
                rows_digest: self.source.rows_digest,
                schema_shape: self.source.schema_shape,
                derived_tree_hash: self.source.derived_tree_hash,
                notes_tree_hash: self.source.notes_tree_hash,
                db_present: self.source.db_present,
            },
            assignments,
        };
        validate_migration(&decision)
            .map_err(|error| AppRefusal::InvalidDecision(error.as_str().to_owned()))?;
        Ok(decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint() -> FingerprintDto {
        FingerprintDto {
            row_count: 3,
            rows_digest: "rows".to_owned(),
            schema_shape: "thread_id,workspace_path".to_owned(),
            derived_tree_hash: "derived".to_owned(),
            notes_tree_hash: "notes".to_owned(),
            db_present: true,
        }
    }

    fn input(kind: &str) -> MigrationDecisionInput {
        MigrationDecisionInput {
            idempotency_key: "decision-1".to_owned(),
            decided_at_unix_ms: 1_700_000_000_000,
            source: fingerprint(),
            assignments: vec![
                AssignmentInput {
                    kind: "keep_shared".to_owned(),
                    key: "thread-1".to_owned(),
                    workspace: None,
                },
                AssignmentInput {
                    kind: kind.to_owned(),
                    key: "thread-2".to_owned(),
                    workspace: Some("workspace-2".to_owned()),
                },
            ],
        }
    }

    #[test]
    fn the_status_report_is_camel_case_and_carries_only_codes() {
        let status = WorkspaceIntelligenceAppStatus {
            host_state: "active".to_owned(),
            reason: None,
            surface_available: true,
            unavailability: None,
            scopes: vec![WorkspaceIntelligenceScopeStatus {
                workspace_id: "workspace-1".to_owned(),
                tier: "baseline".to_owned(),
                availability: "available".to_owned(),
                control_fault: None,
                degraded: false,
                host_state: Some("active".to_owned()),
                block: None,
                binding_review_required: false,
                migration: Some(MigrationReport {
                    idempotency_key: "decision-1".to_owned(),
                    decided_at_unix_ms: 7,
                    assignment_counts: MigrationAssignmentCounts {
                        keep_shared: 1,
                        assign_to: 2,
                        defer_recall: 3,
                    },
                }),
                generation: Some(2),
            }],
        };
        let json = serde_json::to_string(&status).expect("status must serialize");
        assert!(json.contains("\"hostState\":\"active\""), "{json}");
        assert!(json.contains("\"surfaceAvailable\":true"), "{json}");
        assert!(json.contains("\"bindingReviewRequired\":false"), "{json}");
        assert!(json.contains("\"controlFault\":null"), "{json}");
        assert!(json.contains("\"assignmentCounts\":{"), "{json}");
        assert!(json.contains("\"keepShared\":1"), "{json}");
        assert!(json.contains("\"generation\":2"), "{json}");
        // Nothing storage-shaped may leak into a payload a surface renders: no lease, no
        // token, no redacted host marker and no Windows path separator.
        for forbidden in ["lease", "token", "hostMarker", "\\\\"] {
            assert!(!json.contains(forbidden), "{forbidden} in {json}");
        }
    }

    #[test]
    fn a_refusal_renders_as_its_code_and_never_as_content() {
        assert_eq!(AppRefusal::Stopping.code(), "stopping");
        assert_eq!(AppRefusal::NotPrepared.code(), "not_prepared");
        assert_eq!(AppRefusal::AlreadyEnabled.code(), "already_enabled");
        assert_eq!(
            AppRefusal::Host("anchor_changed".to_owned()).code(),
            "anchor_changed"
        );
        assert_eq!(AppRefusal::ControlChanged.code(), "control_changed");
        assert_eq!(AppRefusal::DecisionConflict.code(), "decision_conflict");
        assert_eq!(AppRefusal::SourceChanged.code(), "source_changed");
        assert_eq!(AppRefusal::SourceUnreadable.code(), "source_unreadable");
        assert_eq!(
            AppRefusal::InvalidDecision("blank_key".to_owned()).code(),
            "blank_key"
        );
        assert_eq!(AppRefusal::Control("storage".to_owned()).code(), "storage");
        assert_eq!(AppRefusal::StaleGeneration.code(), "stale_generation");
        assert_eq!(AppRefusal::WorkspaceNotFound.code(), "workspace_not_found");
        assert_eq!(AppRefusal::Internal.code(), "internal");
        assert_eq!(
            format!("{}", AppRefusal::Host("reserve_busy".to_owned())),
            "reserve_busy"
        );
    }

    #[test]
    fn a_submitted_decision_round_trips_into_the_validated_decision() {
        let decision = input("assign_to")
            .into_decision()
            .expect("a well formed decision must pass");
        assert_eq!(decision.idempotency_key, "decision-1");
        assert_eq!(decision.decided_at_unix_ms, 1_700_000_000_000);
        assert_eq!(decision.source.row_count, 3);
        assert!(decision.source.db_present);
        assert_eq!(decision.assignments.len(), 2);
        assert_eq!(decision.assignments[0].kind_code(), "keep_shared");
        assert_eq!(decision.assignments[1].kind_code(), "assign_to");
        assert_eq!(decision.assignments[1].key(), "thread-2");
    }

    #[test]
    fn a_submitted_decision_refuses_an_unknown_kind_and_a_blank_workspace() {
        let unknown = input("retire_everything")
            .into_decision()
            .expect_err("an unknown kind must be refused");
        assert_eq!(
            unknown,
            AppRefusal::InvalidDecision("unknown_assignment_kind".to_owned())
        );
        let mut blank = input("assign_to");
        blank.assignments[1].workspace = None;
        let blank = blank
            .into_decision()
            .expect_err("an assign_to without a workspace must be refused");
        assert_eq!(blank.code(), "blank_workspace");
    }

    #[test]
    fn a_fingerprint_payload_survives_a_json_round_trip() {
        let json = serde_json::to_string(&fingerprint()).expect("fingerprint must serialize");
        assert!(json.contains("\"rowCount\":3"), "{json}");
        assert!(json.contains("\"dbPresent\":true"), "{json}");
        let decoded: FingerprintDto =
            serde_json::from_str(&json).expect("fingerprint must deserialize");
        assert_eq!(decoded, fingerprint());
    }

    #[test]
    fn the_confirmation_and_disable_reports_carry_codes_not_payloads() {
        let enabled = ConfirmReport {
            outcome: "enabled".to_owned(),
            generation: Some(3),
            intelligent: Some(false),
        };
        let json = serde_json::to_string(&enabled).expect("report must serialize");
        assert_eq!(
            json,
            r#"{"outcome":"enabled","generation":3,"intelligent":false}"#
        );
        let pending = serde_json::to_string(&ConfirmReport {
            outcome: "enabled_partition_pending".to_owned(),
            generation: None,
            intelligent: None,
        })
        .expect("report must serialize");
        assert_eq!(
            pending,
            r#"{"outcome":"enabled_partition_pending","generation":null,"intelligent":null}"#
        );
        let disabled = serde_json::to_string(&DisableReport {
            generation: 4,
            changed: true,
        })
        .expect("report must serialize");
        assert_eq!(disabled, r#"{"generation":4,"changed":true}"#);
    }

    #[test]
    fn the_host_state_decides_whether_the_surface_is_available() {
        use WorkspaceIntelligenceHostState as State;
        for state in [State::Inactive, State::Active, State::Degraded] {
            assert_eq!(surface_availability(state), (true, None), "{state:?}");
        }
        assert_eq!(
            surface_availability(State::NotCompiled),
            (false, Some("host_not_compiled".to_owned()))
        );
        assert_eq!(
            surface_availability(State::Unavailable),
            (false, Some("host_unavailable".to_owned()))
        );
        assert_eq!(
            surface_availability(State::Draining),
            (false, Some("host_draining".to_owned()))
        );
        assert_eq!(
            surface_availability(State::Stopped),
            (false, Some("host_stopped".to_owned()))
        );
    }

    #[cfg(feature = "workspace-intelligence-host")]
    #[test]
    fn the_tier_and_the_availability_are_two_columns() {
        use super::super::mode::{derive_mode, ModeFacts};
        use super::super::mode::WorkspaceModelRef;

        let reference = WorkspaceModelRef::parse("model-1").expect("test reference");
        // Off never carries a model reference and is never degraded, whatever the
        // delivery fact says.
        let off = derive_mode(
            ModeFacts {
                enabled: None,
                model_ref: None,
                delivery: CapabilityDelivery::Unavailable,
            },
            |_| unreachable!("off must never resolve a model"),
        );
        assert_eq!(tier_code(off.tier), "off");
        assert_eq!(availability_code(&off), "available");
        assert!(!off.is_degraded());

        let baseline = derive_mode(
            ModeFacts {
                enabled: Some(true),
                model_ref: None,
                delivery: CapabilityDelivery::Delivered,
            },
            |_| unreachable!("baseline must never resolve a model"),
        );
        assert_eq!(tier_code(baseline.tier), "baseline");
        assert_eq!(availability_code(&baseline), "available");

        let intelligent = derive_mode(
            ModeFacts {
                enabled: Some(true),
                model_ref: Some(reference.clone()),
                delivery: CapabilityDelivery::Delivered,
            },
            |_| super::super::mode::WorkspaceModelResolution::Unresolvable,
        );
        assert_eq!(tier_code(intelligent.tier), "intelligent");
        assert_eq!(availability_code(&intelligent), "model_ref_unresolved");
        assert!(intelligent.is_degraded());

        let undelivered = derive_mode(
            ModeFacts {
                enabled: Some(true),
                model_ref: Some(reference),
                delivery: CapabilityDelivery::Unavailable,
            },
            |_| super::super::mode::WorkspaceModelResolution::Unresolvable,
        );
        assert_eq!(tier_code(undelivered.tier), "intelligent");
        assert_eq!(availability_code(&undelivered), "ai_not_delivered");
    }
}
