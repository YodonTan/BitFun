//! Internal control handle over the authoritative workspace intelligence
//! control record.
//!
//! # P1 core control slice: WP1.1 core assembly + WP1.2a control-vs-control
//!
//! This module is the internal core assembly of the P1 core control slice. It
//! gives one host-local control handle per (host, execution domain). The handle
//! projects the authoritative control record into the P0 tier derivation and the
//! policy view, and it applies typed control changes through the store's own
//! control generation; there is no second control-generation truth, no cached
//! copy, and no local file protocol.
//!
//! The host and scope value types themselves moved to the feature-free
//! [`super::scope`] module, which the cognition partition slice shares. They are
//! re-exported from here, so the control assembly, its CAS behaviour and the
//! record-file naming contract are unchanged.
//!
//! What this module deliberately does not deliver:
//!
//! - no bootstrap claim, no claim, lease or incarnation of its own, and no
//!   legacy confirmation gate;
//! - no runtime, scheduler, provider, timer, or background task;
//! - no production caller, no product-full assembly, and no UI, command,
//!   registry row or capability;
//! - control-vs-control CAS only, unchanged in behaviour. The governed owner-commit
//!   fence for "close linearized with a governance commit" now lives in
//!   `super::commit` (feature `workspace-intelligence-commit`) over the services
//!   fence; this is not WP1.2b completion.

use std::path::PathBuf;

use openbitfun_services_core::workspace_intelligence_store::{
    ControlFieldUpdate, ControlGenerationExpectation, ControlRecordFault,
    WorkspaceIntelligenceControlPatch, WorkspaceIntelligenceControlWrite,
    WorkspaceIntelligenceStore, WorkspaceIntelligenceStoreError,
};
use serde_json::Value;

use crate::infrastructure::PathManager;

use super::mode::is_idle as tier_is_idle;
use super::{mode::*, policy::*, read_contract::*};

// The host and scope value types live in the feature-free `scope` module so the
// cognition partition slice shares exactly one scope identity and one encoding.
// Re-exported here so every existing `control::HostExecutionDomainKey` and
// `control::WorkspaceControlScope` path keeps resolving.
pub(crate) use super::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// Core assembly of one host-local workspace intelligence control handle.
///
/// The handle is pure: [`WorkspaceIntelligenceControl::for_host`] performs no IO
/// and creates no directory. The store creates the record root only when a real
/// mutation is applied. There is no global singleton, no in-memory mutex, no
/// background task, no claim and no lease.
#[derive(Debug, Clone)]
pub(crate) struct WorkspaceIntelligenceControl {
    store: WorkspaceIntelligenceStore,
    host: HostExecutionDomainKey,
}

impl WorkspaceIntelligenceControl {
    /// Real core assembly entry: the authoritative host-local control handle of
    /// one host, stored under that host's own config root.
    ///
    /// Construction is pure and IO-free: it only composes the store over the
    /// host-local control root and injects the one accepted schema version, which
    /// is the same version the control-record projection accepts.
    pub(crate) fn for_host(paths: &PathManager, host: HostExecutionDomainKey) -> Self {
        Self::with_root(paths.workspace_intelligence_control_dir(), host)
    }

    /// Builds a handle over an explicit host-local root.
    ///
    /// This isolates the storage root only, for tests and for a caller that
    /// already owns a root. It never selects a product configuration path.
    pub(crate) fn with_root(root: PathBuf, host: HostExecutionDomainKey) -> Self {
        Self {
            store: WorkspaceIntelligenceStore::new(root, vec![CONTROL_SCHEMA_VERSION]),
            host,
        }
    }

    /// The host and execution domain this handle owns.
    pub(crate) fn host(&self) -> &HostExecutionDomainKey {
        &self.host
    }

    /// Observes the authoritative control record of `scope`.
    ///
    /// The observation is read-only. It never writes, resets or deletes a record,
    /// and `store.read` never creates the record root:
    ///
    /// - a scope owned by another host is rejected with
    ///   [`ControlError::HostScopeMismatch`] and no store call, so there is no
    ///   local fallback;
    /// - no observed record is `NotObserved`, which derives `Off` and is an
    ///   observation, not an accepted OFF mutation;
    /// - a read failure is `Unavailable` with the mapped store fault and derives
    ///   `Off` from an empty projection; a default is never substituted and
    ///   nothing is written, so a manual close of a record with an unknown schema
    ///   version reports unsupported and leaves the file intact;
    /// - an observed record is projected from that one read, so the generation
    ///   and `read`/`policy` always describe the same snapshot. A legal
    ///   `Intelligent` record stays `Intelligent` even when delivery is
    ///   `Unavailable`, and an unresolvable reference stays `Intelligent` and
    ///   degraded while keeping its reference.
    pub(crate) async fn observe<F>(
        &self,
        scope: &WorkspaceControlScope,
        delivery: CapabilityDelivery,
        resolve: F,
    ) -> Result<ControlObservation, ControlError>
    where
        F: FnOnce(&WorkspaceModelRef) -> WorkspaceModelResolution,
    {
        if !scope.host_matches(&self.host) {
            return Err(ControlError::HostScopeMismatch);
        }

        let observed = self.store.read(&scope.as_str()).await;

        match observed {
            Ok(None) => {
                let read = unobserved_read();
                let policy = ControlPolicyView::read(None);
                let mode = derive_from_read(&read, delivery, resolve);
                Ok(ControlObservation {
                    authority: ControlAuthority::NotObserved,
                    read,
                    mode,
                    policy,
                })
            }
            // A read failure is an unreadable record, not an absent one, and it is
            // never answered with a default or a write.
            Err(error) => {
                let read = unobserved_read();
                let policy = ControlPolicyView::read(None);
                let mode = derive_from_read(&read, delivery, resolve);
                Ok(ControlObservation {
                    authority: ControlAuthority::Unavailable {
                        fault: ControlUnavailableFault::from_store_error(&error),
                    },
                    read,
                    mode,
                    policy,
                })
            }
            Ok(Some(record)) => {
                let read = read_control_record(&record.raw, &[CONTROL_SCHEMA_VERSION]);
                let policy = ControlPolicyView::read(record.policy.as_ref());
                let mode = derive_from_read(&read, delivery, resolve);
                Ok(ControlObservation {
                    authority: ControlAuthority::Observed {
                        generation: record.control_generation,
                        schema_version: record.schema_version,
                    },
                    read,
                    mode,
                    policy,
                })
            }
        }
    }

    /// Reads the stored payload without validating it.
    ///
    /// This is a separate diagnostics-only snapshot, not activation authority: the
    /// payload may be unparsable to [`Self::observe`] or unusable by the tier
    /// derivation, it is never combined with a control generation, and it is never
    /// written back. Activation always passes authority validation.
    pub(crate) async fn preserved_payload(
        &self,
        scope: &WorkspaceControlScope,
    ) -> Result<Option<Value>, ControlError> {
        if !scope.host_matches(&self.host) {
            return Err(ControlError::HostScopeMismatch);
        }
        self.store
            .read_payload(&scope.as_str())
            .await
            .map_err(ControlError::Store)
    }

    /// Applies one typed control change to `scope`.
    ///
    /// A scope owned by another host is rejected before any store call. A read
    /// failure is propagated before any write, so an unreadable record is never
    /// reset or replaced by a default.
    ///
    /// Against a record this handle did not observe, the caller's expectation is
    /// resolved before anything else: `Exactly(n)` is a
    /// [`ControlError::StaleGeneration`] with `actual: Absent` and creates
    /// nothing, whatever the mutation is, because a caller that read no record
    /// cannot tell a first write from a record it failed to observe. Only under
    /// an `Absent` expectation does a semantic no-op (`SetEnabled(false)`,
    /// `SetModelRef(Clear)`, or a policy merge that keeps the stored state)
    /// return [`ControlMutationOutcome::Unchanged`] with `observed: None`,
    /// without calling the store at all, so no root, record or lock file is
    /// created; a real change creates the record at generation `1`.
    ///
    /// Against an observed record, the generation is compared before the values:
    /// a stale expectation is a [`ControlError::StaleGeneration`] even when the
    /// desired state already equals the stored one. A semantic no-op still goes
    /// through `commit`, so the store's own generation comparison re-checks
    /// freshness: the store decides `Unchanged` from its documented lock-free
    /// observation, which is that result's linearization point, and a stale
    /// expectation is still reported as a conflict. Its `Unchanged` result is
    /// reported as [`ControlMutationOutcome::Unchanged`] with the observed
    /// snapshot.
    ///
    /// A patch only ever names the field the mutation changes: closing the switch
    /// never clears the model reference or the policy, and opening it never
    /// synthesizes a model reference.
    pub(crate) async fn apply(
        &self,
        scope: &WorkspaceControlScope,
        expectation: ControlGenerationExpectation,
        mutation: ControlMutation,
    ) -> Result<ControlMutationOutcome, ControlError> {
        if !scope.host_matches(&self.host) {
            return Err(ControlError::HostScopeMismatch);
        }
        if let ControlMutation::SetModelRef(ModelRefUpdate::Set(reference)) = &mutation {
            if reference.trim().is_empty() {
                return Err(ControlError::BlankModelReference);
            }
        }

        let observed = self
            .store
            .read(&scope.as_str())
            .await
            .map_err(ControlError::Store)?;

        let Some(record) = observed else {
            // No record was observed. A caller that expects a specific generation
            // cannot be served, and the mutation must not be turned into a
            // creation or a no-op against an authority this handle never read.
            if let ControlGenerationExpectation::Exactly(expected) = expectation {
                return Err(ControlError::StaleGeneration {
                    expected: ControlGenerationExpectation::Exactly(expected),
                    actual: ControlGenerationExpectation::Absent,
                });
            }
            let Some(patch) = plan_mutation(&mutation, StoredAuthority::Missing)? else {
                return Ok(ControlMutationOutcome::Unchanged { observed: None });
            };
            return self
                .commit(scope, ControlGenerationExpectation::Absent, patch)
                .await;
        };

        match expectation {
            ControlGenerationExpectation::Absent => {
                return Err(ControlError::UnexpectedRecord {
                    actual_generation: record.control_generation,
                })
            }
            ControlGenerationExpectation::Exactly(expected)
                if record.control_generation != expected =>
            {
                return Err(ControlError::StaleGeneration {
                    expected: ControlGenerationExpectation::Exactly(expected),
                    actual: ControlGenerationExpectation::Exactly(record.control_generation),
                })
            }
            ControlGenerationExpectation::Exactly(_) => {}
        }

        let authority = StoredAuthority::Present {
            enabled: record.enabled,
            model_ref: record.model_ref.as_deref(),
            policy: record.policy.as_ref(),
        };
        let patch = match plan_mutation(&mutation, authority)? {
            Some(patch) => patch,
            // A semantic no-op still goes through `commit`, so the store's own
            // generation comparison re-checks freshness. The store decides
            // `Unchanged` from its documented lock-free observation, which is that
            // result's linearization point; no lock is taken on this path.
            None => WorkspaceIntelligenceControlPatch::default(),
        };

        self.commit(
            scope,
            ControlGenerationExpectation::Exactly(record.control_generation),
            patch,
        )
        .await
    }

    /// Runs one store mutation and maps its result.
    async fn commit(
        &self,
        scope: &WorkspaceControlScope,
        expectation: ControlGenerationExpectation,
        patch: WorkspaceIntelligenceControlPatch,
    ) -> Result<ControlMutationOutcome, ControlError> {
        match self.store.update(&scope.as_str(), expectation, patch).await {
            Ok(WorkspaceIntelligenceControlWrite::Applied(record)) => {
                Ok(ControlMutationOutcome::Applied(snapshot_of(
                    record.control_generation,
                    record.schema_version,
                    &record.raw,
                    record.policy.as_ref(),
                )))
            }
            Ok(WorkspaceIntelligenceControlWrite::Unchanged(record)) => {
                Ok(ControlMutationOutcome::Unchanged {
                    observed: Some(snapshot_of(
                        record.control_generation,
                        record.schema_version,
                        &record.raw,
                        record.policy.as_ref(),
                    )),
                })
            }
            Err(WorkspaceIntelligenceStoreError::ControlGenerationConflict {
                expected,
                actual,
            }) => Err(ControlError::StaleGeneration { expected, actual }),
            Err(error) => Err(ControlError::Store(error)),
        }
    }
}

/// Stored authority one mutation is planned against.
#[derive(Debug, Clone, Copy)]
enum StoredAuthority<'a> {
    /// No record was observed. Missing counts as off, no reference and no policy.
    Missing,
    /// The record this handle just read.
    Present {
        /// Stored switch; an absent field reads as off.
        enabled: Option<bool>,
        /// Stored reference, kept verbatim.
        model_ref: Option<&'a str>,
        /// Stored opaque policy payload.
        policy: Option<&'a Value>,
    },
}

/// Plans the patch of one mutation.
///
/// `Ok(None)` is a semantic no-op: the stored authority already holds the
/// requested state. A returned patch names only the fields the mutation changes.
fn plan_mutation(
    mutation: &ControlMutation,
    authority: StoredAuthority<'_>,
) -> Result<Option<WorkspaceIntelligenceControlPatch>, ControlError> {
    match mutation {
        ControlMutation::SetEnabled(enabled) => {
            let stored = match authority {
                StoredAuthority::Missing => false,
                StoredAuthority::Present { enabled, .. } => enabled.unwrap_or(false),
            };
            if stored == *enabled {
                return Ok(None);
            }
            Ok(Some(WorkspaceIntelligenceControlPatch {
                enabled: ControlFieldUpdate::Set(*enabled),
                ..Default::default()
            }))
        }
        ControlMutation::SetModelRef(update) => match update {
            ModelRefUpdate::Set(reference) => {
                let stored = match authority {
                    StoredAuthority::Missing => None,
                    StoredAuthority::Present { model_ref, .. } => model_ref,
                };
                if stored == Some(reference.as_str()) {
                    return Ok(None);
                }
                Ok(Some(WorkspaceIntelligenceControlPatch {
                    model_ref: ControlFieldUpdate::Set(reference.clone()),
                    ..Default::default()
                }))
            }
            ModelRefUpdate::Clear => {
                let stored = match authority {
                    StoredAuthority::Missing => None,
                    StoredAuthority::Present { model_ref, .. } => model_ref,
                };
                if stored.is_none() {
                    return Ok(None);
                }
                Ok(Some(WorkspaceIntelligenceControlPatch {
                    model_ref: ControlFieldUpdate::Clear,
                    ..Default::default()
                }))
            }
        },
        ControlMutation::SetPolicy(update) => {
            let stored = match authority {
                StoredAuthority::Missing => None,
                StoredAuthority::Present { policy, .. } => policy,
            };
            match merge_policy(stored, update)? {
                PolicyMerge::Keep => Ok(None),
                PolicyMerge::Replace(value) => Ok(Some(WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(value),
                    ..Default::default()
                })),
            }
        }
    }
}

/// Projection of a control record this handle did not observe.
///
/// No document was read, so there is no payload to preserve: `preserved` is JSON
/// `null`, which is diagnostics input only and must never be written back.
fn unobserved_read() -> ControlRecordRead {
    ControlRecordRead {
        enabled: None,
        model_ref: None,
        diagnostics: Vec::new(),
        preserved: Value::Null,
    }
}

/// Snapshot of one store read.
///
/// The generation and the raw payload always come from the same store read; the
/// typed projection and the policy view are derived from that same payload.
fn snapshot_of(
    generation: u64,
    schema_version: Option<u32>,
    raw: &Value,
    policy: Option<&Value>,
) -> ControlRecordSnapshot {
    ControlRecordSnapshot {
        generation,
        schema_version,
        read: read_control_record(raw, &[CONTROL_SCHEMA_VERSION]),
        policy: ControlPolicyView::read(policy),
    }
}

/// Control-record snapshot of one store read.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ControlRecordSnapshot {
    /// Control generation of the observed record.
    pub(crate) generation: u64,
    /// Declared schema version; `None` is a legacy record.
    pub(crate) schema_version: Option<u32>,
    /// Projected control-record read, including the preserved payload.
    pub(crate) read: ControlRecordRead,
    /// Fail-closed policy view of the same record.
    pub(crate) policy: ControlPolicyView,
}

impl ControlRecordSnapshot {
    /// The stored payload, with JSON `Value` semantics, from the same read as
    /// `generation`.
    pub(crate) fn raw(&self) -> &Value {
        &self.read.preserved
    }
}

/// Authority of one observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlAuthority {
    /// No record was observed. This carries no generation, because a missing
    /// observation is not an authoritative "off" state and no generation may be
    /// faked for it.
    NotObserved,
    /// The record could not be read; the stored bytes are untouched.
    Unavailable { fault: ControlUnavailableFault },
    /// The record was observed and projected from one read.
    Observed {
        /// Observed control generation.
        generation: u64,
        /// Declared schema version; `None` is a legacy record.
        schema_version: Option<u32>,
    },
}

/// Why an authoritative control record was unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlUnavailableFault {
    /// The stored document is not valid JSON.
    Corrupt,
    /// The stored document is structurally invalid.
    Invalid(ControlRecordFault),
    /// The stored document declares a schema version this slice does not accept.
    UnsupportedSchemaVersion(u32),
    /// The record could not be read or written at the storage layer.
    Storage,
    /// The control transaction task failed.
    Transaction,
}

impl ControlUnavailableFault {
    /// Stable machine-readable store-fault code.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt_record",
            Self::Invalid(fault) => fault.as_str(),
            Self::UnsupportedSchemaVersion(_) => "schema_version_unsupported",
            Self::Storage => "storage",
            Self::Transaction => "transaction",
        }
    }

    /// Maps a store read failure. A failure a read cannot produce is reported as
    /// a storage fault rather than as an absent record.
    fn from_store_error(error: &WorkspaceIntelligenceStoreError) -> Self {
        match error {
            WorkspaceIntelligenceStoreError::CorruptRecord { .. } => Self::Corrupt,
            WorkspaceIntelligenceStoreError::InvalidRecord { fault, .. } => Self::Invalid(*fault),
            WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion { version, .. } => {
                Self::UnsupportedSchemaVersion(*version)
            }
            WorkspaceIntelligenceStoreError::Storage(_) => Self::Storage,
            WorkspaceIntelligenceStoreError::Transaction(_) => Self::Transaction,
            WorkspaceIntelligenceStoreError::EmptyScope
            | WorkspaceIntelligenceStoreError::ControlGenerationConflict { .. }
            | WorkspaceIntelligenceStoreError::ControlGenerationOverflow { .. }
            | WorkspaceIntelligenceStoreError::BlankModelReference => Self::Storage,
        }
    }
}

/// Read-only observation of one workspace control scope.
#[derive(Debug, Clone)]
pub(crate) struct ControlObservation {
    /// Authority of this observation.
    pub(crate) authority: ControlAuthority,
    /// Fail-closed control-record projection of the same read.
    pub(crate) read: ControlRecordRead,
    /// Derived tier and its orthogonal facts.
    pub(crate) mode: DerivedMode,
    /// Fail-closed policy view of the same read.
    pub(crate) policy: ControlPolicyView,
}

impl ControlObservation {
    /// True when this observation is a healthy, idle intelligent workspace.
    ///
    /// Idle requires all of the following: the derived tier is `Intelligent`, the
    /// configured workspace model is usable (a degraded model is a separate
    /// state, so a degraded `Intelligent` workspace is never idle), every
    /// intervention surface is closed, and the policy carries no diagnostic. A
    /// diagnostic or an `Unreadable` field must never surface as a normal idle,
    /// which is why this helper never relies on the active count alone. Delivery
    /// stays orthogonal: it never changes the tier, so it is not consulted here.
    pub(crate) fn is_idle(&self) -> bool {
        tier_is_idle(self.mode.tier, self.policy.active_domain_count())
            && !self.mode.is_degraded()
            && self.policy.is_closed()
            && self.policy.diagnostics().is_empty()
    }
}

/// One typed control change.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ControlMutation {
    /// Set the control switch.
    SetEnabled(bool),
    /// Set or clear the workspace model reference.
    SetModelRef(ModelRefUpdate),
    /// Change the policy payload.
    SetPolicy(PolicyUpdate),
}

/// Explicit model-reference update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ModelRefUpdate {
    /// Store the supplied reference verbatim. A blank reference is rejected.
    Set(String),
    /// Remove the stored reference.
    Clear,
}

/// Result of one control mutation.
#[derive(Debug)]
pub(crate) enum ControlMutationOutcome {
    /// The mutation changed the record; the generation advanced by one.
    Applied(ControlRecordSnapshot),
    /// The stored record already held the requested state and was not rewritten.
    ///
    /// `observed: None` is the missing-case semantic no-op under an `Absent`
    /// expectation: no record, no generation, and nothing was created. A specific
    /// `Exactly(n)` expectation never receives this outcome against a missing
    /// record; it receives [`ControlError::StaleGeneration`] instead.
    Unchanged {
        /// Snapshot of the record after the store call, when one was observed.
        observed: Option<ControlRecordSnapshot>,
    },
}

/// Failures of the workspace intelligence control handle.
///
/// Every variant fails closed: there is no silent fallback, no default record and
/// no local state that could answer a control change.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlError {
    /// The scope belongs to a different host and execution domain.
    #[error("the scope is owned by a different host and execution domain")]
    HostScopeMismatch,
    /// The caller's expectation is stale.
    #[error("control generation conflict: expected {expected}, observed {actual}")]
    StaleGeneration {
        /// Generation the caller expected.
        expected: ControlGenerationExpectation,
        /// Generation the store observed.
        actual: ControlGenerationExpectation,
    },
    /// The caller expected no record, but the authoritative record exists.
    #[error("the control record already exists at generation {actual_generation}")]
    UnexpectedRecord {
        /// Generation of the existing record.
        actual_generation: u64,
    },
    /// A blank workspace model reference is not a binding.
    #[error("workspace model reference must not be empty or blank")]
    BlankModelReference,
    /// The stored policy payload cannot be merged.
    #[error(transparent)]
    UnmergeablePolicy(#[from] PolicyMergeError),
    /// The authoritative control store failed.
    #[error(transparent)]
    Store(#[from] WorkspaceIntelligenceStoreError),
}

/// Tests of the P1 core control slice: WP1.1 core assembly + WP1.2a
/// control-vs-control.
#[cfg(test)]
mod tests {
    use super::*;

    fn host(host_id: &str, execution_domain: &str) -> HostExecutionDomainKey {
        HostExecutionDomainKey::new(host_id, execution_domain)
            .expect("test host key must be non-blank")
    }

    fn scope_of(host: &HostExecutionDomainKey, workspace_id: &str) -> WorkspaceControlScope {
        WorkspaceControlScope::new(host, workspace_id).expect("test scope must be non-blank")
    }

    fn handle(
        root: &std::path::Path,
        host: HostExecutionDomainKey,
    ) -> WorkspaceIntelligenceControl {
        WorkspaceIntelligenceControl::with_root(root.to_path_buf(), host)
    }

    fn resolved(_: &WorkspaceModelRef) -> WorkspaceModelResolution {
        WorkspaceModelResolution::Resolved
    }

    fn panic_resolver(_: &WorkspaceModelRef) -> WorkspaceModelResolution {
        panic!("this observation must not resolve a workspace model reference")
    }

    /// The single control record file under a root, as the store named it.
    fn single_record_path(root: &std::path::Path) -> PathBuf {
        let mut records: Vec<PathBuf> = std::fs::read_dir(root)
            .expect("the control root must exist after a real mutation")
            .map(|entry| entry.expect("readable directory entry").path())
            .filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("json")
            })
            .collect();
        records.sort();
        assert_eq!(records.len(), 1, "expected exactly one control record");
        records.into_iter().next().expect("one record path")
    }

    #[test]
    fn host_keys_and_scopes_reject_blank_identifiers() {
        assert!(HostExecutionDomainKey::new("", "local").is_none());
        assert!(HostExecutionDomainKey::new("host-1", "   ").is_none());
        assert!(HostExecutionDomainKey::new("\t", "local").is_none());

        let host = host("host-1", "local");
        assert!(WorkspaceControlScope::new(&host, "").is_none());
        assert!(WorkspaceControlScope::new(&host, "  ").is_none());
    }

    #[test]
    fn scope_encoding_distinguishes_tuples_a_plain_join_would_collide_on() {
        let plain = host("host-1", "local");
        let shifted = host("host-1", "local|a");

        let left = scope_of(&plain, "a|b");
        let right = scope_of(&shifted, "b");
        assert_eq!(
            format!("{}|{}|{}", plain.host_id(), plain.execution_domain(), "a|b"),
            format!(
                "{}|{}|{}",
                shifted.host_id(),
                shifted.execution_domain(),
                "b"
            ),
            "the fixture must collide under a plain join"
        );
        assert_ne!(left.as_str(), right.as_str());
        assert!(left.as_str().starts_with("[\"wi-scope-v1\""));

        assert_ne!(
            scope_of(&plain, "/remote/repo").as_str(),
            scope_of(&plain, "\\remote\\repo").as_str()
        );
        assert_ne!(scope_of(&plain, "workspace").as_str(), scope_of(&plain, "wörkspace").as_str());
    }

    #[tokio::test]
    async fn the_core_assembly_derives_three_tiers_from_one_authoritative_record() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let paths = PathManager::with_user_root_for_tests(fixture.path().join("user"));
        let control = WorkspaceIntelligenceControl::for_host(&paths, host("host-1", "local"));
        let scope = scope_of(control.host(), "workspace-a");
        let control_root = paths.workspace_intelligence_control_dir();

        // NotObserved: no record, so the tier is Off and nothing is created.
        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("a missing record is an observation");
        assert_eq!(observation.authority, ControlAuthority::NotObserved);
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Off);
        assert_eq!(observation.policy.presence, PolicyPresence::Absent);
        assert!(observation.policy.is_closed());
        assert!(!control_root.exists(), "an observation must not create the control root");

        // Baseline: switched on without a workspace model reference.
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");
        let ControlMutationOutcome::Applied(snapshot) = outcome else {
            panic!("a real creation must be applied: {outcome:?}");
        };
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.schema_version, Some(CONTROL_SCHEMA_VERSION));

        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("the record must be observable");
        assert_eq!(
            observation.authority,
            ControlAuthority::Observed {
                generation: 1,
                schema_version: Some(CONTROL_SCHEMA_VERSION),
            }
        );
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Baseline);
        assert!(!observation.mode.is_degraded());
        assert!(observation.policy.is_closed());

        // Intelligent: an enabled record with a resolvable reference.
        control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                ControlMutation::SetModelRef(ModelRefUpdate::Set("workspace-model-a".to_string())),
            )
            .await
            .expect("setting the reference must succeed");

        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, resolved)
            .await
            .expect("the record must be observable");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Intelligent);
        assert!(!observation.mode.is_degraded());
        assert_eq!(
            observation.mode.model_ref.as_ref().map(WorkspaceModelRef::as_str),
            Some("workspace-model-a")
        );

        // Intelligent-degraded: unavailable delivery and an unresolvable
        // reference degrade orthogonally and keep the reference.
        let observation = control
            .observe(&scope, CapabilityDelivery::Unavailable, |_| {
                WorkspaceModelResolution::Unresolvable
            })
            .await
            .expect("the record must be observable");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Intelligent);
        assert!(observation.mode.is_degraded());
        assert_eq!(observation.mode.delivery, CapabilityDelivery::Unavailable);
        assert_eq!(
            observation.mode.model_ref.as_ref().map(WorkspaceModelRef::as_str),
            Some("workspace-model-a")
        );

        // Back to Baseline: clearing the reference keeps the switch on.
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(2),
                ControlMutation::SetModelRef(ModelRefUpdate::Clear),
            )
            .await
            .expect("clearing the reference must succeed");
        let ControlMutationOutcome::Applied(snapshot) = outcome else {
            panic!("a real change must be applied: {outcome:?}");
        };
        assert_eq!(snapshot.generation, 3);

        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("the record must be observable");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Baseline);
        assert!(observation.policy.is_closed());
    }

    #[tokio::test]
    async fn a_semantic_no_op_keeps_the_stored_bytes_and_the_generation() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");
        let record_path = single_record_path(&root);
        let before = std::fs::read(&record_path).expect("the record must be readable");

        // Repeating the switch state is a semantic no-op: the handle still calls
        // the store's own compare-and-swap, which answers Unchanged.
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("a no-op must succeed");
        let ControlMutationOutcome::Unchanged {
            observed: Some(snapshot),
        } = outcome
        else {
            panic!("a no-op must report the observed snapshot: {outcome:?}");
        };
        assert_eq!(snapshot.generation, 1);
        assert_eq!(
            std::fs::read(&record_path).expect("the record must be readable"),
            before,
            "an unchanged record must not be rewritten"
        );

        // Clearing a reference that is not stored is the same no-op.
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                ControlMutation::SetModelRef(ModelRefUpdate::Clear),
            )
            .await
            .expect("a no-op must succeed");
        assert!(
            matches!(
                outcome,
                ControlMutationOutcome::Unchanged {
                    observed: Some(ControlRecordSnapshot { generation: 1, .. })
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(std::fs::read(&record_path).expect("the record must be readable"), before);
    }

    #[tokio::test]
    async fn a_closed_no_op_against_a_missing_record_creates_nothing() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        let closed_mutations = [
            ControlMutation::SetEnabled(false),
            ControlMutation::SetModelRef(ModelRefUpdate::Clear),
            ControlMutation::SetPolicy(PolicyUpdate::Domain {
                domain: EnhancementDomain::Memory,
                update: DomainUpdate::Off,
            }),
            ControlMutation::SetPolicy(PolicyUpdate::Approval(ApprovalUpdate::Off)),
        ];
        for mutation in closed_mutations {
            let outcome = control
                .apply(
                    &scope,
                    ControlGenerationExpectation::Absent,
                    mutation.clone(),
                )
                .await
                .expect("a missing-case no-op must succeed");
            assert!(
                matches!(
                    outcome,
                    ControlMutationOutcome::Unchanged { observed: None }
                ),
                "{mutation:?}: {outcome:?}"
            );
            assert!(
                !root.exists(),
                "{mutation:?} must not create the control root, a record or a lock file"
            );
        }
    }

    #[tokio::test]
    async fn a_specific_expectation_against_a_missing_record_is_never_a_false_success() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        let mutations = [
            ControlMutation::SetEnabled(true),
            ControlMutation::SetEnabled(false),
            ControlMutation::SetModelRef(ModelRefUpdate::Clear),
            ControlMutation::SetPolicy(PolicyUpdate::Domain {
                domain: EnhancementDomain::Memory,
                update: DomainUpdate::Off,
            }),
            ControlMutation::SetPolicy(PolicyUpdate::Approval(ApprovalUpdate::Off)),
        ];

        // A caller that observed no record cannot tell a first write from a record
        // it failed to observe, so a specific generation must never be answered
        // with a creation or with a missing-case no-op.
        for generation in [0_u64, 5] {
            for mutation in &mutations {
                let error = control
                    .apply(
                        &scope,
                        ControlGenerationExpectation::Exactly(generation),
                        mutation.clone(),
                    )
                    .await
                    .expect_err("a specific expectation against a missing record must fail");
                assert!(
                    matches!(
                        error,
                        ControlError::StaleGeneration {
                            expected: ControlGenerationExpectation::Exactly(expected),
                            actual: ControlGenerationExpectation::Absent,
                        } if expected == generation
                    ),
                    "generation {generation}, mutation {mutation:?}: {error}"
                );
                assert!(
                    !root.exists(),
                    "generation {generation}, mutation {mutation:?} must not create anything"
                );
            }
        }

        // The `Absent` expectation keeps its two documented outcomes.
        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(false),
            )
            .await
            .expect("an absent expectation with a closed no-op must succeed");
        assert!(
            matches!(
                outcome,
                ControlMutationOutcome::Unchanged { observed: None }
            ),
            "{outcome:?}"
        );
        assert!(!root.exists());

        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("an absent expectation with a real change must create the record");
        let ControlMutationOutcome::Applied(snapshot) = outcome else {
            panic!("a real change must be applied: {outcome:?}");
        };
        assert_eq!(snapshot.generation, 1);
        assert!(root.exists());
    }

    #[tokio::test]
    async fn a_known_policy_change_preserves_unknown_content_verbatim() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");
        let store = WorkspaceIntelligenceStore::new(root.clone(), vec![CONTROL_SCHEMA_VERSION]);

        let stored_policy = serde_json::json!({
            "unknown_policy_key": { "nested": [1, { "deep": null }] },
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
        store
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Keep,
                    policy: ControlFieldUpdate::Set(stored_policy.clone()),
                },
            )
            .await
            .expect("seeding the record must succeed");

        // Add an unknown root key the typed patch model does not know about.
        let record_path = single_record_path(&root);
        let mut document: Value = serde_json::from_slice(
            &std::fs::read(&record_path).expect("the record must be readable"),
        )
        .expect("the record must be valid JSON");
        document["unknown_root_key"] =
            serde_json::json!({ "nested": [1, 2, { "deep": null }], "flag": false });
        std::fs::write(
            &record_path,
            serde_json::to_vec(&document).expect("the fixture must serialize"),
        )
        .expect("the fixture must be writable");

        let outcome = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                ControlMutation::SetPolicy(PolicyUpdate::Approval(ApprovalUpdate::Recommend)),
            )
            .await
            .expect("a known policy change must succeed");
        assert!(matches!(outcome, ControlMutationOutcome::Applied(_)), "{outcome:?}");

        let stored: Value = serde_json::from_slice(
            &std::fs::read(&record_path).expect("the record must be readable"),
        )
        .expect("the record must be valid JSON");
        assert_eq!(
            stored["unknown_root_key"],
            serde_json::json!({ "nested": [1, 2, { "deep": null }], "flag": false })
        );
        assert_eq!(stored["control_generation"], serde_json::json!(2));
        assert_eq!(stored["policy"]["unknown_policy_key"], stored_policy["unknown_policy_key"]);
        assert_eq!(stored["policy"]["domains"]["memory"], stored_policy["domains"]["memory"]);
        assert_eq!(
            stored["policy"]["domains"]["unknown_domain_key"],
            stored_policy["domains"]["unknown_domain_key"]
        );
        assert_eq!(stored["policy"]["approval"]["mode"], serde_json::json!("recommend"));
        assert_eq!(stored["policy"]["approval"]["timeout_ms"], serde_json::json!(7));
        assert_eq!(
            stored["policy"]["approval"]["unknown_approval_key"],
            serde_json::json!(["kept"])
        );
    }

    #[tokio::test]
    async fn unreadable_records_are_rejected_without_rewrite() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");
        let record_path = single_record_path(&root);

        let cases: [(&[u8], ControlUnavailableFault); 3] = [
            (b"not json", ControlUnavailableFault::Corrupt),
            (
                br#"{"enabled": "yes"}"#,
                ControlUnavailableFault::Invalid(ControlRecordFault::EnabledMalformed),
            ),
            (
                br#"{"schema_version": 999, "control_generation": 1, "enabled": true}"#,
                ControlUnavailableFault::UnsupportedSchemaVersion(999),
            ),
        ];
        for (bytes, fault) in cases {
            std::fs::write(&record_path, bytes).expect("the fixture must be writable");

            let observation = control
                .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
                .await
                .expect("an unreadable record is an observation");
            assert_eq!(
                observation.authority,
                ControlAuthority::Unavailable { fault },
                "fault {fault:?}"
            );
            assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Off);
            assert!(!observation.mode.is_degraded());
            assert_eq!(observation.policy.presence, PolicyPresence::Absent);
            assert_eq!(
                std::fs::read(&record_path)
                    .expect("the record must be readable")
                    .as_slice(),
                bytes,
                "an observation must not rewrite an unreadable record"
            );

            let error = control
                .apply(
                    &scope,
                    ControlGenerationExpectation::Exactly(1),
                    ControlMutation::SetEnabled(false),
                )
                .await
                .expect_err("an unreadable record must reject a mutation");
            assert!(matches!(error, ControlError::Store(_)), "{error}");
            assert_eq!(
                std::fs::read(&record_path)
                    .expect("the record must be readable")
                    .as_slice(),
                bytes,
                "a failed mutation must not rewrite an unreadable record"
            );
        }

        // A legacy record without a schema version or a control generation stays
        // readable and untouched: it is not a fault, and this slice never
        // rewrites or upgrades it.
        let legacy = br#"{"enabled": true, "policy": {"unknown_key": "kept"}}"#;
        std::fs::write(&record_path, legacy).expect("the fixture must be writable");
        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("a legacy record is an observation");
        assert_eq!(
            observation.authority,
            ControlAuthority::Observed {
                generation: 0,
                schema_version: None,
            }
        );
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Baseline);
        assert_eq!(observation.policy.presence, PolicyPresence::Object);
        assert!(observation.policy.is_closed());
        assert_eq!(
            std::fs::read(&record_path)
                .expect("the record must be readable")
                .as_slice(),
            legacy,
            "an observation must not rewrite a legacy record"
        );
    }

    #[tokio::test]
    async fn two_control_handles_serialize_on_the_control_generation() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let scope = scope_of(&host, "workspace-a");
        let setup = handle(&root, host.clone());

        setup
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");

        let first = handle(&root, host.clone());
        let second = handle(&root, host.clone());
        let mutation =
            ControlMutation::SetModelRef(ModelRefUpdate::Set("workspace-model-a".to_string()));
        let (first, second) = tokio::join!(
            first.apply(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                mutation.clone(),
            ),
            second.apply(&scope, ControlGenerationExpectation::Exactly(1), mutation),
        );

        let mut applied = 0;
        let mut stale = 0;
        for result in [first, second] {
            match result {
                Ok(ControlMutationOutcome::Applied(snapshot)) => {
                    applied += 1;
                    assert_eq!(snapshot.generation, 2);
                }
                Err(ControlError::StaleGeneration { expected, actual }) => {
                    stale += 1;
                    assert_eq!(expected, ControlGenerationExpectation::Exactly(1));
                    assert_eq!(actual, ControlGenerationExpectation::Exactly(2));
                }
                other => panic!("unexpected control result: {other:?}"),
            }
        }
        assert_eq!((applied, stale), (1, 1));
    }

    #[tokio::test]
    async fn a_stale_expectation_conflicts_even_when_the_desired_state_is_current() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");

        let error = control
            .apply(
                &scope,
                ControlGenerationExpectation::Exactly(4),
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect_err("a stale caller must never be answered with success");
        let ControlError::StaleGeneration { expected, actual } = error else {
            panic!("a stale expectation must be a conflict: {error}");
        };
        assert_eq!(expected, ControlGenerationExpectation::Exactly(4));
        assert_eq!(actual, ControlGenerationExpectation::Exactly(1));

        // The same holds when the caller expects no record but one exists.
        let error = control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect_err("an existing record must reject a creation intent");
        assert!(
            matches!(
                error,
                ControlError::UnexpectedRecord {
                    actual_generation: 1
                }
            ),
            "{error}"
        );

        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("the record must be observable");
        assert_eq!(
            observation.authority,
            ControlAuthority::Observed {
                generation: 1,
                schema_version: Some(CONTROL_SCHEMA_VERSION),
            }
        );
    }

    #[tokio::test]
    async fn a_foreign_scope_is_rejected_without_any_local_fallback() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let owner = host("host-1", "local");
        let foreign = host("host-2", "local");
        let control = handle(&root, owner);
        let foreign_scope = scope_of(&foreign, "workspace-a");

        let error = control
            .observe(&foreign_scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect_err("a foreign scope must be rejected");
        assert!(matches!(error, ControlError::HostScopeMismatch));

        let error = control
            .apply(
                &foreign_scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect_err("a foreign scope must be rejected");
        assert!(matches!(error, ControlError::HostScopeMismatch));

        let error = control
            .preserved_payload(&foreign_scope)
            .await
            .expect_err("a foreign scope must be rejected");
        assert!(matches!(error, ControlError::HostScopeMismatch));

        // A scope that differs only in the execution domain is foreign too.
        let other_domain = scope_of(&host("host-1", "sandbox"), "workspace-a");
        let error = control
            .observe(&other_domain, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect_err("a different execution domain must be rejected");
        assert!(matches!(error, ControlError::HostScopeMismatch));

        assert!(!root.exists(), "a mismatched scope must not reach the store at all");
    }

    #[tokio::test]
    async fn an_off_observation_never_resolves_and_a_closed_intelligent_record_is_idle() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let scope = scope_of(&host, "workspace-a");

        // NotObserved resolves nothing and writes nothing.
        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("a missing record is an observation");
        assert_eq!(observation.authority, ControlAuthority::NotObserved);
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Off);
        assert!(!root.exists());

        // Unavailable resolves nothing and writes nothing either.
        control
            .apply(
                &scope,
                ControlGenerationExpectation::Absent,
                ControlMutation::SetEnabled(true),
            )
            .await
            .expect("creating the record must succeed");
        let record_path = single_record_path(&root);
        let unreadable = br#"{"enabled": 1}"#;
        std::fs::write(&record_path, unreadable).expect("the fixture must be writable");
        let observation = control
            .observe(&scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("an unreadable record is an observation");
        assert!(matches!(
            observation.authority,
            ControlAuthority::Unavailable { .. }
        ));
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Off);
        assert_eq!(
            std::fs::read(&record_path)
                .expect("the record must be readable")
                .as_slice(),
            unreadable
        );

        // A legal Intelligent record whose domains are all off is idle.
        let idle_scope = scope_of(&host, "workspace-b");
        let store = WorkspaceIntelligenceStore::new(root.clone(), vec![CONTROL_SCHEMA_VERSION]);
        store
            .update(
                &idle_scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Set("workspace-model-a".to_string()),
                    policy: ControlFieldUpdate::Set(serde_json::json!({
                        "domains": {
                            "memory": { "enabled": false },
                            "cron": { "enabled": false },
                            "collaboration": { "enabled": false },
                        },
                    })),
                },
            )
            .await
            .expect("seeding the idle record must succeed");

        let observation = control
            .observe(&idle_scope, CapabilityDelivery::Delivered, resolved)
            .await
            .expect("the idle record must be observable");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(observation.policy.active_domain_count(), 0);
        assert!(observation.policy.is_closed());
        assert!(observation.policy.diagnostics().is_empty());
        assert!(observation.is_idle());
    }

    /// Seeds one record and observes it with the caller's resolver.
    async fn seeded_observation(
        control: &WorkspaceIntelligenceControl,
        store: &WorkspaceIntelligenceStore,
        scope: &WorkspaceControlScope,
        policy: Value,
        resolve: fn(&WorkspaceModelRef) -> WorkspaceModelResolution,
    ) -> ControlObservation {
        store
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Set("workspace-model-a".to_string()),
                    policy: ControlFieldUpdate::Set(policy),
                },
            )
            .await
            .expect("seeding the record must succeed");
        control
            .observe(scope, CapabilityDelivery::Delivered, resolve)
            .await
            .expect("the seeded record must be observable")
    }

    #[tokio::test]
    async fn idle_requires_a_healthy_intelligent_workspace_with_every_surface_closed() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("control");
        let host = host("host-1", "local");
        let control = handle(&root, host.clone());
        let store = WorkspaceIntelligenceStore::new(root.clone(), vec![CONTROL_SCHEMA_VERSION]);

        let closed_policy = || {
            serde_json::json!({
                "domains": {
                    "memory": { "enabled": false },
                    "cron": { "enabled": false },
                    "collaboration": { "enabled": false },
                },
                "approval": { "mode": "off" },
            })
        };

        // Approval is an intervention surface too: a workspace whose only pending
        // surface is approval is not idle.
        let recommend_scope = scope_of(&host, "approval-recommend");
        let observation = seeded_observation(
            &control,
            &store,
            &recommend_scope,
            serde_json::json!({ "approval": { "mode": "recommend" } }),
            resolved,
        )
        .await;
        assert_eq!(observation.policy.approval(), &ApprovalPolicy::Recommend);
        assert_eq!(observation.policy.active_domain_count(), 1);
        assert!(!observation.is_idle());

        let timeout_scope = scope_of(&host, "approval-timeout");
        let observation = seeded_observation(
            &control,
            &store,
            &timeout_scope,
            serde_json::json!({ "approval": { "mode": "auto_timeout", "timeout_ms": 0 } }),
            resolved,
        )
        .await;
        assert_eq!(
            observation.policy.approval(),
            &ApprovalPolicy::AutoTimeout { timeout_ms: 0 }
        );
        assert_eq!(observation.policy.active_domain_count(), 1);
        assert!(!observation.is_idle());

        // An unknown shape is not a closed surface: it must never surface as idle.
        let unknown_mode_scope = scope_of(&host, "approval-unknown");
        let observation = seeded_observation(
            &control,
            &store,
            &unknown_mode_scope,
            serde_json::json!({ "approval": { "mode": "auto_always" } }),
            resolved,
        )
        .await;
        assert_eq!(observation.policy.active_domain_count(), 0);
        assert!(!observation.policy.is_closed());
        assert!(!observation.is_idle());

        let unknown_autonomy_scope = scope_of(&host, "autonomy-unknown");
        let observation = seeded_observation(
            &control,
            &store,
            &unknown_autonomy_scope,
            serde_json::json!({
                "domains": { "memory": { "enabled": true, "autonomy": "future_autonomy_v9" } },
            }),
            resolved,
        )
        .await;
        assert_eq!(observation.policy.active_domain_count(), 0);
        assert!(!observation.policy.is_closed());
        assert!(!observation.is_idle());

        // Every surface off with a usable model is idle.
        let closed_scope = scope_of(&host, "all-off");
        let observation =
            seeded_observation(&control, &store, &closed_scope, closed_policy(), resolved).await;
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Intelligent);
        assert_eq!(observation.policy.active_domain_count(), 0);
        assert!(observation.policy.is_closed());
        assert!(observation.policy.diagnostics().is_empty());
        assert!(observation.is_idle());

        // A degraded model is a separate state: an intelligent workspace with an
        // unresolvable reference is never idle, and the reference is still kept.
        let degraded_scope = scope_of(&host, "all-off-degraded");
        let observation = seeded_observation(
            &control,
            &store,
            &degraded_scope,
            closed_policy(),
            |_| WorkspaceModelResolution::Unresolvable,
        )
        .await;
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Intelligent);
        assert!(observation.mode.is_degraded());
        assert_eq!(
            observation.mode.model_ref.as_ref().map(WorkspaceModelRef::as_str),
            Some("workspace-model-a")
        );
        assert!(!observation.is_idle());

        // Off and Baseline are never idle, whatever their policy says.
        let never_observed = scope_of(&host, "never-observed");
        let observation = control
            .observe(&never_observed, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("a missing record is an observation");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Off);
        assert!(observation.policy.is_closed());
        assert!(!observation.is_idle());

        let baseline_scope = scope_of(&host, "baseline");
        store
            .update(
                &baseline_scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    model_ref: ControlFieldUpdate::Keep,
                    policy: ControlFieldUpdate::Set(closed_policy()),
                },
            )
            .await
            .expect("seeding the baseline record must succeed");
        let observation = control
            .observe(&baseline_scope, CapabilityDelivery::Delivered, panic_resolver)
            .await
            .expect("the baseline record must be observable");
        assert_eq!(observation.mode.tier, WorkspaceIntelligenceTier::Baseline);
        assert!(observation.policy.is_closed());
        assert!(!observation.is_idle());
    }
}
