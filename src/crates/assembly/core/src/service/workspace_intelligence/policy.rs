//! Pure policy projection and merge rules for the workspace intelligence
//! control payload.
//!
//! # P1 core control slice: WP1.1 core assembly + WP1.2a control-vs-control
//!
//! This module is the policy half of the internal P1 core control slice. It is
//! pure: it interprets and edits `serde_json::Value` in memory, performs no IO,
//! keeps no state, and cannot write a control record.
//!
//! Reading fails closed. A payload this reader cannot interpret makes the
//! affected domain or the approval block `Unreadable`; it is never reported as
//! `Off`, which would be an implicit user disable, and never as active. One
//! structural fault produces one diagnostic, while every field that fault
//! governs fails closed with the same code, so `diagnostics()` lists faults
//! rather than restating them per field.
//!
//! Merging edits a clone of the stored payload and touches only the known fields
//! a typed update names. Every unknown root, policy, domain and approval key, and
//! every unknown nested value, stays verbatim, so payload written by a newer
//! build survives a change made by this one. The merged document is the stored
//! payload plus those edits; the typed view is never re-serialized into the
//! output document.

use std::fmt;

use serde_json::{json, Map, Value};

/// Control-record schema version this slice accepts and stamps.
///
/// The store and the control-record projection are given the same list, so the
/// store can never publish a shape the projection rejects.
pub(crate) const CONTROL_SCHEMA_VERSION: u32 = 1;

/// Enhancement domain an intelligent workspace can run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum EnhancementDomain {
    /// Cross-session memory enhancement.
    Memory,
    /// Scheduled-job enhancement.
    Cron,
    /// Collaboration enhancement.
    Collaboration,
}

impl EnhancementDomain {
    /// Every domain this slice models, in stable order.
    pub(crate) const ALL: [Self; 3] = [Self::Memory, Self::Cron, Self::Collaboration];

    /// Stable policy key of the domain.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Memory => "memory",
            Self::Cron => "cron",
            Self::Collaboration => "collaboration",
        }
    }

    /// Static `domains` path of the domain, used by merge errors.
    fn policy_path(self) -> &'static str {
        match self {
            Self::Memory => "domains.memory",
            Self::Cron => "domains.cron",
            Self::Collaboration => "domains.collaboration",
        }
    }
}

/// Autonomy limit a domain may run under.
///
/// The value is an upper bound only: it is never a grant. The real scope,
/// resource and time limits a run must obey are not delivered by this slice, so
/// [`AutonomyLimit::PreauthorizedAuto`] does not authorize anything by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AutonomyLimit {
    /// The domain may only recommend, never act.
    Recommend,
    /// The domain may act on low-risk changes.
    LowRiskAuto,
    /// The domain may act within a preauthorized envelope; the envelope is not
    /// delivered here.
    PreauthorizedAuto,
}

impl AutonomyLimit {
    /// Stable policy key of the limit.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Recommend => "recommend",
            Self::LowRiskAuto => "low_risk_auto",
            Self::PreauthorizedAuto => "preauthorized_auto",
        }
    }

    /// Parses a stored autonomy key. An unknown key is `None`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        match raw {
            "recommend" => Some(Self::Recommend),
            "low_risk_auto" => Some(Self::LowRiskAuto),
            "preauthorized_auto" => Some(Self::PreauthorizedAuto),
            _ => None,
        }
    }
}

/// Typed state of one enhancement domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainPolicy {
    /// The domain is closed. Absent content means off, so an absent domain is
    /// also `Off`.
    Off,
    /// The domain is on under the given autonomy upper bound.
    Active { autonomy: AutonomyLimit },
    /// The domain block cannot be interpreted. It is never active and never an
    /// implicit user disable.
    Unreadable { code: PolicyDiagnosticCode },
}

/// Typed state of the approval block.
///
/// Three levels and no second boolean. `Off` means the approval path does not
/// intervene (不干涉) and the domain is closed. `Recommend` adds no approval step
/// and never auto-allows or auto-denies: for an already pending approval request
/// it only publishes an opinion labelled recommended (allow or deny) with a short
/// reason, evidence and risk, starts no timer and submits nothing. `AutoTimeout`
/// takes effect only after a valid recommendation is ready: at `timeout_ms` the
/// owner adopts that one recommended conclusion exactly once, either allow or
/// deny, and then it is final. This slice stores the configuration only and
/// executes nothing: no new approval runtime, no timer, no second pending store.
/// The timeout unit is milliseconds and exact: `timeout_ms: 0` is legal, no
/// default value is substituted for a missing or malformed timeout, and this slice
/// adds no arbitrary upper limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalPolicy {
    /// Approval does not intervene.
    Off,
    /// For an already pending approval request, approval publishes one opinion
    /// labelled recommended (allow or deny) with a short reason, evidence and
    /// risk. It never auto-allows, never auto-denies, starts no timer and submits
    /// nothing.
    Recommend,
    /// After a valid recommendation is ready, the owner adopts that one
    /// recommended conclusion exactly once at `timeout_ms` milliseconds, either
    /// allow or deny, and then it is final. This slice stores the configuration
    /// only and executes nothing.
    AutoTimeout { timeout_ms: u64 },
    /// The approval block cannot be interpreted. It is never active and never an
    /// implicit user disable.
    Unreadable { code: PolicyDiagnosticCode },
}

/// Stable code of one policy fault.
///
/// Codes are stable and never echo a payload value, so they are safe for logs
/// and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyDiagnosticCode {
    /// The policy payload is present but is not a JSON object.
    PolicyNotObject,
    /// The `domains` container, or one domain inside it, is not a JSON object.
    DomainNotObject,
    /// `enabled` is present but is not a boolean.
    DomainEnabledMalformed,
    /// A domain is enabled but carries no `autonomy` key.
    AutonomyMissing,
    /// `autonomy` names no known limit.
    AutonomyUnknown,
    /// `autonomy` is present but is not a key string.
    AutonomyMalformed,
    /// The `approval` block is present but is not a JSON object.
    ApprovalNotObject,
    /// `mode` is present but is not a key string.
    ApprovalModeMalformed,
    /// `mode` names no known approval mode.
    ApprovalModeUnknown,
    /// An `auto_timeout` approval carries no `timeout_ms`.
    ApprovalTimeoutMissing,
    /// `timeout_ms` is not a non-negative integer that fits `u64`.
    ApprovalTimeoutMalformed,
}

impl PolicyDiagnosticCode {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PolicyNotObject => "policy_not_object",
            Self::DomainNotObject => "domain_not_object",
            Self::DomainEnabledMalformed => "domain_enabled_malformed",
            Self::AutonomyMissing => "autonomy_missing",
            Self::AutonomyUnknown => "autonomy_unknown",
            Self::AutonomyMalformed => "autonomy_malformed",
            Self::ApprovalNotObject => "approval_not_object",
            Self::ApprovalModeMalformed => "approval_mode_malformed",
            Self::ApprovalModeUnknown => "approval_mode_unknown",
            Self::ApprovalTimeoutMissing => "approval_timeout_missing",
            Self::ApprovalTimeoutMalformed => "approval_timeout_malformed",
        }
    }
}

/// One diagnosed policy fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyDiagnostic {
    /// Stable diagnostic code.
    pub(crate) code: PolicyDiagnosticCode,
    /// English detail naming the offending JSON type, path or enum key. A detail
    /// never echoes a payload value.
    pub(crate) detail: String,
}

/// Presence of the policy payload in a control record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyPresence {
    /// The record carries no policy payload: the legacy and closed state.
    Absent,
    /// The record carries a policy payload. The payload is expected to be a JSON
    /// object; a payload of another JSON type is diagnosed `policy_not_object`
    /// and closes every domain and the approval block.
    Object,
}

/// Fail-closed typed projection of a policy payload.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ControlPolicyView {
    /// Whether the record carries a policy payload at all.
    pub(crate) presence: PolicyPresence,
    /// Memory domain state.
    pub(crate) memory: DomainPolicy,
    /// Scheduled-job domain state.
    pub(crate) cron: DomainPolicy,
    /// Collaboration domain state.
    pub(crate) collaboration: DomainPolicy,
    /// Approval state.
    pub(crate) approval: ApprovalPolicy,
    /// Diagnosed faults in detection order.
    pub(crate) diagnostics: Vec<PolicyDiagnostic>,
}

impl ControlPolicyView {
    /// Projects a stored policy payload.
    ///
    /// Parse rules, all fail closed and none of them defaults a typed value:
    ///
    /// - no payload at all -> absent, every domain and approval `Off`, no
    ///   diagnostics;
    /// - a payload that is not a JSON object -> `policy_not_object`, every domain
    ///   and approval `Unreadable`;
    /// - a missing `domains` container, a missing domain, or a missing `enabled`
    ///   field is `Off`: absent means off and is not a fault;
    /// - a non-object `domains` container or a non-object domain, and a malformed
    ///   `enabled`, are `Unreadable`;
    /// - `enabled: false` is `Off` and ignores the domain's autonomy content
    ///   entirely;
    /// - `enabled: true` requires a `autonomy` key naming a known limit, and is
    ///   `Unreadable` when it is missing, malformed or unknown;
    /// - a missing `approval` block or a missing `mode` is `Off`;
    /// - `mode` must name one of the three known modes; `auto_timeout` requires a
    ///   non-negative integer `timeout_ms` that fits `u64`, and `0` is legal.
    pub(crate) fn read(policy: Option<&Value>) -> Self {
        let Some(policy) = policy else {
            return Self::closed(PolicyPresence::Absent);
        };
        let Value::Object(policy_object) = policy else {
            let code = PolicyDiagnosticCode::PolicyNotObject;
            return Self {
                presence: PolicyPresence::Object,
                memory: DomainPolicy::Unreadable { code },
                cron: DomainPolicy::Unreadable { code },
                collaboration: DomainPolicy::Unreadable { code },
                approval: ApprovalPolicy::Unreadable { code },
                diagnostics: vec![PolicyDiagnostic {
                    code,
                    detail: format!(
                        "expected the policy payload to be a JSON object, found {}",
                        json_kind(policy)
                    ),
                }],
            };
        };

        let mut diagnostics = Vec::new();
        let domains = match policy_object.get("domains") {
            None => DomainsContainer::Absent,
            Some(Value::Object(domains)) => DomainsContainer::Object(domains),
            Some(other) => {
                diagnostics.push(PolicyDiagnostic {
                    code: PolicyDiagnosticCode::DomainNotObject,
                    detail: format!(
                        "expected the domains container to be a JSON object, found {}",
                        json_kind(other)
                    ),
                });
                DomainsContainer::Unreadable
            }
        };

        let memory = read_domain(&domains, EnhancementDomain::Memory, &mut diagnostics);
        let cron = read_domain(&domains, EnhancementDomain::Cron, &mut diagnostics);
        let collaboration =
            read_domain(&domains, EnhancementDomain::Collaboration, &mut diagnostics);
        let approval = read_approval(policy_object, &mut diagnostics);

        Self {
            presence: PolicyPresence::Object,
            memory,
            cron,
            collaboration,
            approval,
            diagnostics,
        }
    }

    /// A payload with no active content and no faults.
    fn closed(presence: PolicyPresence) -> Self {
        Self {
            presence,
            memory: DomainPolicy::Off,
            cron: DomainPolicy::Off,
            collaboration: DomainPolicy::Off,
            approval: ApprovalPolicy::Off,
            diagnostics: Vec::new(),
        }
    }

    /// Typed state of one domain.
    pub(crate) fn domain(&self, domain: EnhancementDomain) -> &DomainPolicy {
        match domain {
            EnhancementDomain::Memory => &self.memory,
            EnhancementDomain::Cron => &self.cron,
            EnhancementDomain::Collaboration => &self.collaboration,
        }
    }

    /// Typed state of the approval block.
    pub(crate) fn approval(&self) -> &ApprovalPolicy {
        &self.approval
    }

    /// Diagnosed faults in detection order.
    pub(crate) fn diagnostics(&self) -> &[PolicyDiagnostic] {
        &self.diagnostics
    }

    /// Number of intervention surfaces this view reads as active.
    ///
    /// The count covers all four surfaces: each of the three enhancement domains
    /// whose state is [`DomainPolicy::Active`], plus the approval block when it is
    /// [`ApprovalPolicy::Recommend`] or [`ApprovalPolicy::AutoTimeout`]. An
    /// `Off` surface and an `Unreadable` surface never count.
    ///
    /// A count of `0` alone never proves that everything is closed: an
    /// `Unreadable` domain, an unreadable approval block and a policy diagnostic
    /// are invisible to this count, so a caller that must prove closure combines
    /// it with [`Self::is_closed`] and [`Self::diagnostics`].
    pub(crate) fn active_domain_count(&self) -> usize {
        let domains = EnhancementDomain::ALL
            .iter()
            .filter(|domain| matches!(self.domain(**domain), DomainPolicy::Active { .. }))
            .count();
        let approval = matches!(
            self.approval,
            ApprovalPolicy::Recommend | ApprovalPolicy::AutoTimeout { .. }
        ) as usize;
        domains + approval
    }

    /// True when every domain and the approval path are closed.
    ///
    /// An `Unreadable` domain or approval is not `Off`, so an unreadable payload
    /// is never claimed as closed.
    pub(crate) fn is_closed(&self) -> bool {
        EnhancementDomain::ALL
            .iter()
            .all(|domain| matches!(self.domain(*domain), DomainPolicy::Off))
            && matches!(self.approval, ApprovalPolicy::Off)
    }
}

/// The `domains` container as far as this reader can see.
enum DomainsContainer<'a> {
    /// The policy has no `domains` key.
    Absent,
    /// The container is a JSON object.
    Object(&'a Map<String, Value>),
    /// The container is present but not a JSON object; already diagnosed once.
    Unreadable,
}

/// Reads one domain from the `domains` container.
fn read_domain(
    container: &DomainsContainer<'_>,
    domain: EnhancementDomain,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> DomainPolicy {
    let fields = match container {
        DomainsContainer::Absent => return DomainPolicy::Off,
        DomainsContainer::Unreadable => {
            return DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::DomainNotObject,
            }
        }
        DomainsContainer::Object(domains) => match domains.get(domain.key()) {
            None => return DomainPolicy::Off,
            Some(Value::Object(fields)) => fields,
            Some(other) => {
                diagnostics.push(PolicyDiagnostic {
                    code: PolicyDiagnosticCode::DomainNotObject,
                    detail: format!(
                        "expected domain \"{}\" to be a JSON object, found {}",
                        domain.key(),
                        json_kind(other)
                    ),
                });
                return DomainPolicy::Unreadable {
                    code: PolicyDiagnosticCode::DomainNotObject,
                };
            }
        },
    };

    read_domain_fields(fields, domain, diagnostics)
}

/// Reads the fields of one domain object.
///
/// The merge planner reuses this reader to learn the typed state of the domain
/// it is about to edit and discards the scratch diagnostics; only the typed state
/// decides `Keep`.
fn read_domain_fields(
    fields: &Map<String, Value>,
    domain: EnhancementDomain,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> DomainPolicy {
    match fields.get("enabled") {
        None => DomainPolicy::Off,
        // A disabled domain ignores its autonomy content entirely; a caller that
        // turns the domain off must preserve that content, not reinterpret it.
        Some(Value::Bool(false)) => DomainPolicy::Off,
        Some(Value::Bool(true)) => read_autonomy(fields, domain, diagnostics),
        Some(other) => {
            diagnostics.push(PolicyDiagnostic {
                code: PolicyDiagnosticCode::DomainEnabledMalformed,
                detail: format!(
                    "expected domain \"{}\" enabled to be a boolean, found {}",
                    domain.key(),
                    json_kind(other)
                ),
            });
            DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::DomainEnabledMalformed,
            }
        }
    }
}

/// Reads the autonomy limit of an enabled domain.
fn read_autonomy(
    fields: &Map<String, Value>,
    domain: EnhancementDomain,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> DomainPolicy {
    match fields.get("autonomy") {
        None => {
            diagnostics.push(PolicyDiagnostic {
                code: PolicyDiagnosticCode::AutonomyMissing,
                detail: format!("enabled domain \"{}\" has no autonomy key", domain.key()),
            });
            DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::AutonomyMissing,
            }
        }
        Some(Value::String(autonomy)) => match AutonomyLimit::parse(autonomy) {
            Some(autonomy) => DomainPolicy::Active { autonomy },
            None => {
                diagnostics.push(PolicyDiagnostic {
                    code: PolicyDiagnosticCode::AutonomyUnknown,
                    detail: format!(
                        "domain \"{}\" autonomy key names no known limit",
                        domain.key()
                    ),
                });
                DomainPolicy::Unreadable {
                    code: PolicyDiagnosticCode::AutonomyUnknown,
                }
            }
        },
        Some(other) => {
            diagnostics.push(PolicyDiagnostic {
                code: PolicyDiagnosticCode::AutonomyMalformed,
                detail: format!(
                    "expected domain \"{}\" autonomy to be a key string, found {}",
                    domain.key(),
                    json_kind(other)
                ),
            });
            DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::AutonomyMalformed,
            }
        }
    }
}

/// Reads the approval block of a policy object.
fn read_approval(
    policy_object: &Map<String, Value>,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> ApprovalPolicy {
    let Some(approval) = policy_object.get("approval") else {
        return ApprovalPolicy::Off;
    };
    let Value::Object(fields) = approval else {
        diagnostics.push(PolicyDiagnostic {
            code: PolicyDiagnosticCode::ApprovalNotObject,
            detail: format!(
                "expected the approval block to be a JSON object, found {}",
                json_kind(approval)
            ),
        });
        return ApprovalPolicy::Unreadable {
            code: PolicyDiagnosticCode::ApprovalNotObject,
        };
    };

    read_approval_fields(fields, diagnostics)
}

/// Reads the fields of an approval object.
fn read_approval_fields(
    fields: &Map<String, Value>,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> ApprovalPolicy {
    match fields.get("mode") {
        None => ApprovalPolicy::Off,
        Some(Value::String(mode)) => match mode.as_str() {
            "off" => ApprovalPolicy::Off,
            "recommend" => ApprovalPolicy::Recommend,
            "auto_timeout" => read_approval_timeout(fields, diagnostics),
            _ => {
                diagnostics.push(PolicyDiagnostic {
                    code: PolicyDiagnosticCode::ApprovalModeUnknown,
                    detail: "approval mode names no known mode".to_string(),
                });
                ApprovalPolicy::Unreadable {
                    code: PolicyDiagnosticCode::ApprovalModeUnknown,
                }
            }
        },
        Some(other) => {
            diagnostics.push(PolicyDiagnostic {
                code: PolicyDiagnosticCode::ApprovalModeMalformed,
                detail: format!(
                    "expected the approval mode to be a key string, found {}",
                    json_kind(other)
                ),
            });
            ApprovalPolicy::Unreadable {
                code: PolicyDiagnosticCode::ApprovalModeMalformed,
            }
        }
    }
}

/// Reads the exact millisecond timeout of an `auto_timeout` approval.
fn read_approval_timeout(
    fields: &Map<String, Value>,
    diagnostics: &mut Vec<PolicyDiagnostic>,
) -> ApprovalPolicy {
    match fields.get("timeout_ms") {
        None => {
            diagnostics.push(PolicyDiagnostic {
                code: PolicyDiagnosticCode::ApprovalTimeoutMissing,
                detail: "auto_timeout approval has no timeout_ms".to_string(),
            });
            ApprovalPolicy::Unreadable {
                code: PolicyDiagnosticCode::ApprovalTimeoutMissing,
            }
        }
        Some(value) => match value.as_u64() {
            Some(timeout_ms) => ApprovalPolicy::AutoTimeout { timeout_ms },
            None => {
                diagnostics.push(PolicyDiagnostic {
                    code: PolicyDiagnosticCode::ApprovalTimeoutMalformed,
                    detail: format!(
                        "expected timeout_ms to be a non-negative integer that fits u64, found {}",
                        json_kind(value)
                    ),
                });
                ApprovalPolicy::Unreadable {
                    code: PolicyDiagnosticCode::ApprovalTimeoutMalformed,
                }
            }
        },
    }
}

/// Requested typed state of one enhancement domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DomainUpdate {
    /// The domain is closed. A stored autonomy value stays inert and present.
    Off,
    /// The domain is on under the given autonomy upper bound.
    Active(AutonomyLimit),
}

/// Requested typed state of the approval block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApprovalUpdate {
    /// Approval does not intervene. A stored timeout stays inert and present.
    Off,
    /// For an already pending approval request, publish one opinion labelled
    /// recommended (allow or deny) with a short reason, evidence and risk. It
    /// never auto-allows, never auto-denies, starts no timer and submits nothing.
    Recommend,
    /// After a valid recommendation is ready, adopt that one recommended
    /// conclusion exactly once at `timeout_ms` exact milliseconds and treat it as
    /// final. This slice stores the configuration only and executes nothing.
    AutoTimeout { timeout_ms: u64 },
}

/// One typed policy change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyUpdate {
    /// Change one enhancement domain.
    Domain {
        /// Domain to change.
        domain: EnhancementDomain,
        /// Requested domain state.
        update: DomainUpdate,
    },
    /// Change the approval block.
    Approval(ApprovalUpdate),
}

/// Result of merging a typed change into a stored payload.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum PolicyMerge {
    /// The stored payload already represents the requested state; write nothing.
    Keep,
    /// Replace the stored payload with this document.
    Replace(Value),
}

/// Why a stored payload cannot be merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PolicyMergeError {
    /// The stored policy is present but is not a JSON object.
    UnmergeablePolicyRoot,
    /// A container this update must edit is present but is not a JSON object.
    UnmergeableContainer(&'static str),
}

impl fmt::Display for PolicyMergeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnmergeablePolicyRoot => {
                formatter.write_str("the stored policy payload is not a JSON object")
            }
            Self::UnmergeableContainer(path) => {
                write!(formatter, "the stored policy field {path} is not a JSON object")
            }
        }
    }
}

// The control handle carries this error as a source, so the standard error trait
// is implemented alongside the display and debug rendering.
impl std::error::Error for PolicyMergeError {}

/// Merges one typed policy change into the stored payload.
///
/// The stored payload is cloned and only the known fields the update names are
/// edited: `domains`, the edited domain object, `enabled`, `autonomy`,
/// `approval`, `mode` and `timeout_ms`. Every other root, policy, domain and
/// approval key, and every nested unknown value, stays verbatim.
///
/// `Keep` means the typed state already equals the requested state, including an
/// absent domain with `Off`, `enabled: false` with `Off`, an equal autonomy
/// limit, an equal approval block with an equal timeout, and a missing payload
/// with `Off`/`Off`.
pub(crate) fn merge_policy(
    current: Option<&Value>,
    update: &PolicyUpdate,
) -> Result<PolicyMerge, PolicyMergeError> {
    let mut document = match current {
        None => Map::new(),
        Some(Value::Object(policy)) => policy.clone(),
        Some(_) => return Err(PolicyMergeError::UnmergeablePolicyRoot),
    };

    let keep = match update {
        PolicyUpdate::Domain { domain, update } => merge_domain(&mut document, *domain, *update)?,
        PolicyUpdate::Approval(update) => merge_approval(&mut document, *update)?,
    };

    if keep {
        Ok(PolicyMerge::Keep)
    } else {
        Ok(PolicyMerge::Replace(Value::Object(document)))
    }
}

/// Merges one domain update, returning `true` when the stored state already
/// matches.
fn merge_domain(
    document: &mut Map<String, Value>,
    domain: EnhancementDomain,
    update: DomainUpdate,
) -> Result<bool, PolicyMergeError> {
    let current = match document.get("domains") {
        None => DomainPolicy::Off,
        Some(Value::Object(domains)) => match domains.get(domain.key()) {
            None => DomainPolicy::Off,
            Some(Value::Object(fields)) => {
                // The typed state is what decides `Keep`; the diagnostics of this
                // scratch read are not part of the merged document.
                let mut scratch = Vec::new();
                read_domain_fields(fields, domain, &mut scratch)
            }
            Some(_) => {
                return Err(PolicyMergeError::UnmergeableContainer(domain.policy_path()))
            }
        },
        Some(_) => return Err(PolicyMergeError::UnmergeableContainer("domains")),
    };

    match update {
        DomainUpdate::Off => {
            if matches!(current, DomainPolicy::Off) {
                return Ok(true);
            }
            let fields = domain_fields(document, domain)?;
            fields.insert("enabled".to_string(), Value::Bool(false));
            // A stored autonomy value stays verbatim: it is inert while the domain
            // is off and is never deleted by a close.
            Ok(false)
        }
        DomainUpdate::Active(autonomy) => {
            if matches!(current, DomainPolicy::Active { autonomy: stored } if stored == autonomy) {
                return Ok(true);
            }
            let fields = domain_fields(document, domain)?;
            fields.insert("enabled".to_string(), Value::Bool(true));
            fields.insert(
                "autonomy".to_string(),
                Value::String(autonomy.key().to_string()),
            );
            Ok(false)
        }
    }
}

/// Mutable domain object to edit, creating empty containers when absent.
fn domain_fields<'a>(
    document: &'a mut Map<String, Value>,
    domain: EnhancementDomain,
) -> Result<&'a mut Map<String, Value>, PolicyMergeError> {
    let domains = document
        .entry("domains".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(domains) = domains else {
        return Err(PolicyMergeError::UnmergeableContainer("domains"));
    };

    let fields = domains
        .entry(domain.key().to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    match fields {
        Value::Object(fields) => Ok(fields),
        _ => Err(PolicyMergeError::UnmergeableContainer(domain.policy_path())),
    }
}

/// Merges one approval update, returning `true` when the stored state already
/// matches.
fn merge_approval(
    document: &mut Map<String, Value>,
    update: ApprovalUpdate,
) -> Result<bool, PolicyMergeError> {
    let current = match document.get("approval") {
        None => ApprovalPolicy::Off,
        Some(Value::Object(fields)) => {
            let mut scratch = Vec::new();
            read_approval_fields(fields, &mut scratch)
        }
        Some(_) => return Err(PolicyMergeError::UnmergeableContainer("approval")),
    };

    match update {
        ApprovalUpdate::Off => {
            if matches!(current, ApprovalPolicy::Off) {
                return Ok(true);
            }
            let fields = approval_fields(document)?;
            fields.insert("mode".to_string(), Value::String("off".to_string()));
            // A stored timeout stays verbatim: it is inert while approval is off
            // and is never deleted by a close.
            Ok(false)
        }
        ApprovalUpdate::Recommend => {
            if matches!(current, ApprovalPolicy::Recommend) {
                return Ok(true);
            }
            let fields = approval_fields(document)?;
            fields.insert("mode".to_string(), Value::String("recommend".to_string()));
            Ok(false)
        }
        ApprovalUpdate::AutoTimeout { timeout_ms } => {
            if matches!(
                current,
                ApprovalPolicy::AutoTimeout { timeout_ms: stored } if stored == timeout_ms
            ) {
                return Ok(true);
            }
            let fields = approval_fields(document)?;
            fields.insert(
                "mode".to_string(),
                Value::String("auto_timeout".to_string()),
            );
            fields.insert("timeout_ms".to_string(), json!(timeout_ms));
            Ok(false)
        }
    }
}

/// Mutable approval object to edit, creating it when absent.
fn approval_fields(
    document: &mut Map<String, Value>,
) -> Result<&mut Map<String, Value>, PolicyMergeError> {
    let approval = document
        .entry("approval".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    match approval {
        Value::Object(fields) => Ok(fields),
        _ => Err(PolicyMergeError::UnmergeableContainer("approval")),
    }
}

/// JSON type name for diagnostics, so a detail never echoes a payload value.
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(view: &ControlPolicyView) -> Vec<PolicyDiagnosticCode> {
        view.diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    fn domains(body: Value) -> ControlPolicyView {
        ControlPolicyView::read(Some(&json!({ "domains": body })))
    }

    fn approval(body: Value) -> ControlPolicyView {
        ControlPolicyView::read(Some(&json!({ "approval": body })))
    }

    fn domain_off(domain: EnhancementDomain) -> PolicyUpdate {
        PolicyUpdate::Domain {
            domain,
            update: DomainUpdate::Off,
        }
    }

    #[test]
    fn diagnostic_codes_and_enum_keys_stay_stable() {
        let codes = [
            (PolicyDiagnosticCode::PolicyNotObject, "policy_not_object"),
            (PolicyDiagnosticCode::DomainNotObject, "domain_not_object"),
            (
                PolicyDiagnosticCode::DomainEnabledMalformed,
                "domain_enabled_malformed",
            ),
            (PolicyDiagnosticCode::AutonomyMissing, "autonomy_missing"),
            (PolicyDiagnosticCode::AutonomyUnknown, "autonomy_unknown"),
            (PolicyDiagnosticCode::AutonomyMalformed, "autonomy_malformed"),
            (
                PolicyDiagnosticCode::ApprovalNotObject,
                "approval_not_object",
            ),
            (
                PolicyDiagnosticCode::ApprovalModeMalformed,
                "approval_mode_malformed",
            ),
            (
                PolicyDiagnosticCode::ApprovalModeUnknown,
                "approval_mode_unknown",
            ),
            (
                PolicyDiagnosticCode::ApprovalTimeoutMissing,
                "approval_timeout_missing",
            ),
            (
                PolicyDiagnosticCode::ApprovalTimeoutMalformed,
                "approval_timeout_malformed",
            ),
        ];
        for (code, expected) in codes {
            assert_eq!(code.as_str(), expected);
        }

        assert_eq!(
            EnhancementDomain::ALL.map(EnhancementDomain::key),
            ["memory", "cron", "collaboration"]
        );
        assert_eq!(AutonomyLimit::Recommend.key(), "recommend");
        assert_eq!(AutonomyLimit::LowRiskAuto.key(), "low_risk_auto");
        assert_eq!(AutonomyLimit::PreauthorizedAuto.key(), "preauthorized_auto");
        for limit in [
            AutonomyLimit::Recommend,
            AutonomyLimit::LowRiskAuto,
            AutonomyLimit::PreauthorizedAuto,
        ] {
            assert_eq!(AutonomyLimit::parse(limit.key()), Some(limit));
        }
        assert_eq!(AutonomyLimit::parse(""), None);
        assert_eq!(AutonomyLimit::parse("Recommend"), None);
        assert_eq!(AutonomyLimit::parse("preauthorized_auto_v2"), None);
    }

    #[test]
    fn an_absent_policy_is_closed_without_diagnostics() {
        let view = ControlPolicyView::read(None);

        assert_eq!(view.presence, PolicyPresence::Absent);
        for domain in EnhancementDomain::ALL {
            assert_eq!(view.domain(domain), &DomainPolicy::Off);
        }
        assert_eq!(view.approval(), &ApprovalPolicy::Off);
        assert!(view.diagnostics().is_empty());
        assert_eq!(view.active_domain_count(), 0);
        assert!(view.is_closed());
    }

    #[test]
    fn a_non_object_policy_fails_every_domain_and_approval_closed() {
        for raw in [
            json!("on"),
            json!(1),
            json!(true),
            json!([{ "domains": {} }]),
            json!(null),
        ] {
            let view = ControlPolicyView::read(Some(&raw));

            assert_eq!(view.presence, PolicyPresence::Object);
            assert_eq!(codes(&view), vec![PolicyDiagnosticCode::PolicyNotObject]);
            for domain in EnhancementDomain::ALL {
                assert_eq!(
                    view.domain(domain),
                    &DomainPolicy::Unreadable {
                        code: PolicyDiagnosticCode::PolicyNotObject
                    }
                );
            }
            assert_eq!(
                view.approval(),
                &ApprovalPolicy::Unreadable {
                    code: PolicyDiagnosticCode::PolicyNotObject
                }
            );
            assert_eq!(view.active_domain_count(), 0);
            assert!(!view.is_closed());
        }
    }

    #[test]
    fn a_missing_or_empty_policy_object_is_closed() {
        let view = ControlPolicyView::read(Some(&json!({})));

        assert_eq!(view.presence, PolicyPresence::Object);
        assert!(view.diagnostics().is_empty());
        for domain in EnhancementDomain::ALL {
            assert_eq!(view.domain(domain), &DomainPolicy::Off);
        }
        assert_eq!(view.approval(), &ApprovalPolicy::Off);
        assert!(view.is_closed());
    }

    #[test]
    fn an_absent_domain_is_off_and_a_malformed_domain_is_unreadable() {
        let absent = domains(json!({}));
        for domain in EnhancementDomain::ALL {
            assert_eq!(absent.domain(domain), &DomainPolicy::Off);
        }
        assert!(absent.diagnostics().is_empty());

        let container = domains(json!("memory"));
        assert_eq!(codes(&container), vec![PolicyDiagnosticCode::DomainNotObject]);
        for domain in EnhancementDomain::ALL {
            assert_eq!(
                container.domain(domain),
                &DomainPolicy::Unreadable {
                    code: PolicyDiagnosticCode::DomainNotObject
                }
            );
        }

        let malformed = domains(json!({ "cron": 3 }));
        assert_eq!(codes(&malformed), vec![PolicyDiagnosticCode::DomainNotObject]);
        assert_eq!(malformed.domain(EnhancementDomain::Memory), &DomainPolicy::Off);
        assert_eq!(
            malformed.domain(EnhancementDomain::Cron),
            &DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::DomainNotObject
            }
        );
        assert_eq!(malformed.domain(EnhancementDomain::Collaboration), &DomainPolicy::Off);
        assert!(malformed.diagnostics()[0].detail.contains("cron"));
    }

    #[test]
    fn a_missing_enabled_is_off_and_ignores_autonomy_content() {
        let view = domains(json!({
            "memory": { "autonomy": "preauthorized_auto", "unknown": 1 },
            "cron": {},
        }));

        assert_eq!(view.domain(EnhancementDomain::Memory), &DomainPolicy::Off);
        assert_eq!(view.domain(EnhancementDomain::Cron), &DomainPolicy::Off);
        assert!(view.diagnostics().is_empty());
        assert!(view.is_closed());
    }

    #[test]
    fn a_malformed_enabled_fails_closed_without_reading_autonomy() {
        for enabled in [json!("true"), json!(1), json!(null), json!({}), json!([true])] {
            let view = domains(json!({
                "memory": { "enabled": enabled, "autonomy": "recommend" },
            }));

            assert_eq!(
                view.domain(EnhancementDomain::Memory),
                &DomainPolicy::Unreadable {
                    code: PolicyDiagnosticCode::DomainEnabledMalformed
                }
            );
            assert_eq!(codes(&view), vec![PolicyDiagnosticCode::DomainEnabledMalformed]);
        }
    }

    #[test]
    fn a_disabled_domain_ignores_its_autonomy_content_entirely() {
        for autonomy in [
            json!("future_autonomy_v9"),
            json!(42),
            json!({ "nested": true }),
            json!(null),
        ] {
            let view = domains(json!({
                "memory": { "enabled": false, "autonomy": autonomy },
            }));

            assert_eq!(view.domain(EnhancementDomain::Memory), &DomainPolicy::Off);
            assert!(view.diagnostics().is_empty());
            assert_eq!(view.active_domain_count(), 0);
        }
    }

    #[test]
    fn an_enabled_domain_requires_a_known_autonomy() {
        let missing = domains(json!({ "memory": { "enabled": true } }));
        assert_eq!(
            missing.domain(EnhancementDomain::Memory),
            &DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::AutonomyMissing
            }
        );
        assert_eq!(codes(&missing), vec![PolicyDiagnosticCode::AutonomyMissing]);

        for autonomy in [json!(42), json!(null), json!({}), json!(["recommend"])] {
            let view = domains(json!({ "memory": { "enabled": true, "autonomy": autonomy } }));
            assert_eq!(
                view.domain(EnhancementDomain::Memory),
                &DomainPolicy::Unreadable {
                    code: PolicyDiagnosticCode::AutonomyMalformed
                }
            );
            assert_eq!(codes(&view), vec![PolicyDiagnosticCode::AutonomyMalformed]);
        }

        let unknown = domains(json!({
            "memory": { "enabled": true, "autonomy": "future_autonomy_v9" },
        }));
        assert_eq!(
            unknown.domain(EnhancementDomain::Memory),
            &DomainPolicy::Unreadable {
                code: PolicyDiagnosticCode::AutonomyUnknown
            }
        );
        assert_eq!(codes(&unknown), vec![PolicyDiagnosticCode::AutonomyUnknown]);
        assert!(!unknown.diagnostics()[0].detail.contains("future_autonomy_v9"));

        for (key, limit) in [
            ("recommend", AutonomyLimit::Recommend),
            ("low_risk_auto", AutonomyLimit::LowRiskAuto),
            ("preauthorized_auto", AutonomyLimit::PreauthorizedAuto),
        ] {
            let view = domains(json!({ "memory": { "enabled": true, "autonomy": key } }));
            assert_eq!(
                view.domain(EnhancementDomain::Memory),
                &DomainPolicy::Active { autonomy: limit }
            );
            assert!(view.diagnostics().is_empty());
        }
    }

    #[test]
    fn approval_absence_and_the_three_modes_parse_exactly() {
        let absent = domains(json!({}));
        assert_eq!(absent.approval(), &ApprovalPolicy::Off);

        let not_object = approval(json!("recommend"));
        assert_eq!(
            not_object.approval(),
            &ApprovalPolicy::Unreadable {
                code: PolicyDiagnosticCode::ApprovalNotObject
            }
        );
        assert_eq!(codes(&not_object), vec![PolicyDiagnosticCode::ApprovalNotObject]);

        let no_mode = approval(json!({ "timeout_ms": "not parsed" }));
        assert_eq!(no_mode.approval(), &ApprovalPolicy::Off);
        assert!(no_mode.diagnostics().is_empty());

        for mode in [json!(42), json!(true), json!(null), json!({})] {
            let view = approval(json!({ "mode": mode }));
            assert_eq!(
                view.approval(),
                &ApprovalPolicy::Unreadable {
                    code: PolicyDiagnosticCode::ApprovalModeMalformed
                }
            );
            assert_eq!(codes(&view), vec![PolicyDiagnosticCode::ApprovalModeMalformed]);
        }

        let unknown = approval(json!({ "mode": "auto_always" }));
        assert_eq!(
            unknown.approval(),
            &ApprovalPolicy::Unreadable {
                code: PolicyDiagnosticCode::ApprovalModeUnknown
            }
        );
        assert_eq!(codes(&unknown), vec![PolicyDiagnosticCode::ApprovalModeUnknown]);
        assert!(!unknown.diagnostics()[0].detail.contains("auto_always"));

        let off = approval(json!({ "mode": "off", "timeout_ms": "ignored" }));
        assert_eq!(off.approval(), &ApprovalPolicy::Off);
        assert!(off.diagnostics().is_empty());

        let recommend = approval(json!({ "mode": "recommend" }));
        assert_eq!(recommend.approval(), &ApprovalPolicy::Recommend);
        assert!(recommend.diagnostics().is_empty());
    }

    #[test]
    fn an_auto_timeout_approval_requires_an_exact_millisecond_timeout() {
        let zero = approval(json!({ "mode": "auto_timeout", "timeout_ms": 0 }));
        assert_eq!(zero.approval(), &ApprovalPolicy::AutoTimeout { timeout_ms: 0 });
        assert!(zero.diagnostics().is_empty());

        let largest = approval(json!({ "mode": "auto_timeout", "timeout_ms": u64::MAX }));
        assert_eq!(largest.approval(), &ApprovalPolicy::AutoTimeout { timeout_ms: u64::MAX });

        let missing = approval(json!({ "mode": "auto_timeout" }));
        assert_eq!(
            missing.approval(),
            &ApprovalPolicy::Unreadable {
                code: PolicyDiagnosticCode::ApprovalTimeoutMissing
            }
        );
        assert_eq!(codes(&missing), vec![PolicyDiagnosticCode::ApprovalTimeoutMissing]);

        let overflow = serde_json::from_str::<Value>("18446744073709551616").unwrap();
        for timeout in [
            json!(-1),
            json!(1.5),
            json!("1000"),
            json!(true),
            json!(null),
            overflow,
        ] {
            let view = approval(json!({ "mode": "auto_timeout", "timeout_ms": timeout }));
            assert_eq!(
                view.approval(),
                &ApprovalPolicy::Unreadable {
                    code: PolicyDiagnosticCode::ApprovalTimeoutMalformed
                },
                "timeout {timeout} must fail closed"
            );
            assert_eq!(codes(&view), vec![PolicyDiagnosticCode::ApprovalTimeoutMalformed]);
        }
    }

    #[test]
    fn an_unreadable_field_is_never_active_and_never_a_disable() {
        let view = ControlPolicyView::read(Some(&json!({
            "domains": {
                "memory": { "enabled": true, "autonomy": "recommend" },
                "cron": { "enabled": true, "autonomy": "future_autonomy_v9" },
                "collaboration": { "enabled": "yes" },
            },
            "approval": "not an approval block",
        })));

        assert_eq!(
            codes(&view),
            vec![
                PolicyDiagnosticCode::AutonomyUnknown,
                PolicyDiagnosticCode::DomainEnabledMalformed,
                PolicyDiagnosticCode::ApprovalNotObject,
            ]
        );
        assert_eq!(
            view.domain(EnhancementDomain::Memory),
            &DomainPolicy::Active {
                autonomy: AutonomyLimit::Recommend
            }
        );
        assert!(matches!(
            view.domain(EnhancementDomain::Cron),
            DomainPolicy::Unreadable { .. }
        ));
        assert!(matches!(
            view.domain(EnhancementDomain::Collaboration),
            DomainPolicy::Unreadable { .. }
        ));
        assert!(matches!(view.approval(), ApprovalPolicy::Unreadable { .. }));
        assert_eq!(view.active_domain_count(), 1);
        assert!(!view.is_closed());
    }

    #[test]
    fn the_active_count_covers_approval_without_proving_closure() {
        assert_eq!(
            approval(json!({ "mode": "recommend" })).active_domain_count(),
            1
        );
        assert_eq!(
            approval(json!({ "mode": "auto_timeout", "timeout_ms": 0 })).active_domain_count(),
            1
        );
        assert_eq!(approval(json!({ "mode": "off" })).active_domain_count(), 0);
        assert_eq!(
            approval(json!({ "mode": "auto_always" })).active_domain_count(),
            0,
            "an unreadable approval is never active"
        );

        let domain_and_approval = ControlPolicyView::read(Some(&json!({
            "domains": { "memory": { "enabled": true, "autonomy": "recommend" } },
            "approval": { "mode": "recommend" },
        })));
        assert_eq!(domain_and_approval.active_domain_count(), 2);

        // A count of zero is not proof of closure: an unreadable surface is
        // invisible to the count.
        let unreadable = domains(json!({ "cron": { "enabled": true } }));
        assert_eq!(unreadable.active_domain_count(), 0);
        assert!(!unreadable.is_closed());
        assert!(!unreadable.diagnostics().is_empty());
    }

    #[test]
    fn an_active_domain_update_creates_only_the_named_domain() {
        let merged = merge_policy(
            None,
            &PolicyUpdate::Domain {
                domain: EnhancementDomain::Memory,
                update: DomainUpdate::Active(AutonomyLimit::Recommend),
            },
        )
        .unwrap();

        assert_eq!(
            merged,
            PolicyMerge::Replace(json!({
                "domains": { "memory": { "enabled": true, "autonomy": "recommend" } },
            }))
        );
    }

    #[test]
    fn a_missing_payload_with_a_closed_update_is_keep() {
        assert_eq!(
            merge_policy(None, &domain_off(EnhancementDomain::Memory)).unwrap(),
            PolicyMerge::Keep
        );
        assert_eq!(
            merge_policy(None, &PolicyUpdate::Approval(ApprovalUpdate::Off)).unwrap(),
            PolicyMerge::Keep
        );
    }

    #[test]
    fn equal_typed_state_is_keep() {
        let disabled = json!({ "domains": { "memory": { "enabled": false } } });
        assert_eq!(
            merge_policy(Some(&disabled), &domain_off(EnhancementDomain::Memory)).unwrap(),
            PolicyMerge::Keep
        );

        let active = json!({
            "domains": { "memory": { "enabled": true, "autonomy": "recommend", "kept": 1 } },
        });
        assert_eq!(
            merge_policy(
                Some(&active),
                &PolicyUpdate::Domain {
                    domain: EnhancementDomain::Memory,
                    update: DomainUpdate::Active(AutonomyLimit::Recommend),
                },
            )
            .unwrap(),
            PolicyMerge::Keep
        );

        let approval_off = json!({ "approval": { "mode": "off", "timeout_ms": 3 } });
        assert_eq!(
            merge_policy(Some(&approval_off), &PolicyUpdate::Approval(ApprovalUpdate::Off))
                .unwrap(),
            PolicyMerge::Keep
        );

        let recommendation = json!({ "approval": { "mode": "recommend" } });
        assert_eq!(
            merge_policy(
                Some(&recommendation),
                &PolicyUpdate::Approval(ApprovalUpdate::Recommend),
            )
            .unwrap(),
            PolicyMerge::Keep
        );

        let timeout = json!({ "approval": { "mode": "auto_timeout", "timeout_ms": 7 } });
        assert_eq!(
            merge_policy(
                Some(&timeout),
                &PolicyUpdate::Approval(ApprovalUpdate::AutoTimeout { timeout_ms: 7 }),
            )
            .unwrap(),
            PolicyMerge::Keep
        );
        assert!(matches!(
            merge_policy(
                Some(&timeout),
                &PolicyUpdate::Approval(ApprovalUpdate::AutoTimeout { timeout_ms: 8 }),
            )
            .unwrap(),
            PolicyMerge::Replace(_)
        ));
    }

    #[test]
    fn a_known_change_preserves_every_unknown_key_and_value() {
        let current = json!({
            "unknown_root": { "nested": [1, { "deep": null }], "flag": false },
            "policy_note": "kept",
            "domains": {
                "memory": {
                    "enabled": true,
                    "autonomy": "recommend",
                    "unknown_domain_key": "kept",
                },
                "unknown_domain_key": { "enabled": true, "autonomy": "preauthorized_auto" },
            },
            "approval": {
                "mode": "auto_timeout",
                "timeout_ms": 7,
                "unknown_approval_key": ["kept"],
            },
        });
        let original = current.clone();

        let PolicyMerge::Replace(merged) = merge_policy(
            Some(&current),
            &PolicyUpdate::Domain {
                domain: EnhancementDomain::Memory,
                update: DomainUpdate::Active(AutonomyLimit::LowRiskAuto),
            },
        )
        .unwrap()
        else {
            panic!("a different autonomy limit must replace the payload");
        };

        assert_eq!(merged["unknown_root"], original["unknown_root"]);
        assert_eq!(merged["policy_note"], original["policy_note"]);
        assert_eq!(
            merged["domains"]["unknown_domain_key"],
            original["domains"]["unknown_domain_key"]
        );
        assert_eq!(merged["domains"]["memory"]["unknown_domain_key"], json!("kept"));
        assert_eq!(merged["domains"]["memory"]["autonomy"], json!("low_risk_auto"));
        assert_eq!(merged["domains"]["memory"]["enabled"], json!(true));
        assert_eq!(merged["approval"], original["approval"]);
        assert_eq!(current, original, "the stored payload must stay untouched");

        let PolicyMerge::Replace(approval_merged) = merge_policy(
            Some(&current),
            &PolicyUpdate::Approval(ApprovalUpdate::Recommend),
        )
        .unwrap()
        else {
            panic!("a different approval mode must replace the payload");
        };
        assert_eq!(approval_merged["policy_note"], original["policy_note"]);
        assert_eq!(
            approval_merged["domains"],
            original["domains"],
            "an approval change must not touch a domain"
        );
        assert_eq!(approval_merged["approval"]["mode"], json!("recommend"));
        assert_eq!(approval_merged["approval"]["timeout_ms"], json!(7));
        assert_eq!(approval_merged["approval"]["unknown_approval_key"], json!(["kept"]));
    }

    #[test]
    fn a_close_keeps_the_stored_autonomy_and_timeout_inert() {
        let current = json!({
            "domains": { "memory": { "enabled": true, "autonomy": "preauthorized_auto" } },
            "approval": { "mode": "auto_timeout", "timeout_ms": 9, "unknown": true },
        });

        let PolicyMerge::Replace(merged) =
            merge_policy(Some(&current), &domain_off(EnhancementDomain::Memory)).unwrap()
        else {
            panic!("closing an active domain must replace the payload");
        };
        assert_eq!(merged["domains"]["memory"]["enabled"], json!(false));
        assert_eq!(
            merged["domains"]["memory"]["autonomy"],
            json!("preauthorized_auto"),
            "a close must preserve the stored autonomy value"
        );

        let PolicyMerge::Replace(merged) = merge_policy(
            Some(&current),
            &PolicyUpdate::Approval(ApprovalUpdate::Off),
        )
        .unwrap()
        else {
            panic!("closing an active approval must replace the payload");
        };
        assert_eq!(merged["approval"]["mode"], json!("off"));
        assert_eq!(merged["approval"]["timeout_ms"], json!(9));
        assert_eq!(merged["approval"]["unknown"], json!(true));
    }

    #[test]
    fn unmergeable_shapes_are_reported_with_the_offending_path() {
        assert_eq!(
            merge_policy(Some(&json!("payload")), &domain_off(EnhancementDomain::Memory))
                .unwrap_err(),
            PolicyMergeError::UnmergeablePolicyRoot
        );
        assert_eq!(
            merge_policy(
                Some(&json!({ "domains": [] })),
                &domain_off(EnhancementDomain::Memory),
            )
            .unwrap_err(),
            PolicyMergeError::UnmergeableContainer("domains")
        );
        assert_eq!(
            merge_policy(
                Some(&json!({ "domains": { "memory": 3 } })),
                &domain_off(EnhancementDomain::Memory),
            )
            .unwrap_err(),
            PolicyMergeError::UnmergeableContainer("domains.memory")
        );
        assert_eq!(
            merge_policy(
                Some(&json!({ "approval": true })),
                &PolicyUpdate::Approval(ApprovalUpdate::Off),
            )
            .unwrap_err(),
            PolicyMergeError::UnmergeableContainer("approval")
        );

        assert!(PolicyMergeError::UnmergeablePolicyRoot
            .to_string()
            .contains("JSON object"));
        assert!(PolicyMergeError::UnmergeableContainer("approval")
            .to_string()
            .contains("approval"));
    }
}
