//! Workspace intelligence host bootstrap: anchor, scope enumeration, gates,
//! owner tenure, standby and drain.
//!
//! This module is the narrow app-facing surface of the internal host slice. It
//! answers three questions and nothing else: start (bootstrap), `status()`, and
//! `shutdown()`. The returned handle never exposes a claim, an origin ticket, a
//! token, a lease path, a control root, or the raw anchor value.
//!
//! ## Visibility
//!
//! `bootstrap`, `status`, `shutdown` and the plain-data result types are `pub`, and
//! an opaque handle is the only way to reach this slice. Tenure, tickets, tokens,
//! lease paths, control and cognition roots, the raw anchor and the full host id
//! are deliberately not part of that surface.
//!
//! ## Authority
//!
//! Fresh authority comes from disk, never from memory:
//!
//! - the anchor is read through the storage-namespace anchor owner
//!   (`HostAnchorStore::read_strict`), which never creates, repairs or deletes it.
//!   The document is `user_data/workspace-intelligence/host-anchor.json`, and its
//!   directory comes from `PathManager::workspace_intelligence_dir` — the shared
//!   parent of the control, cognition and lease roots — rather than from a
//!   subdirectory this host infers. No build has ever written it anywhere else, so
//!   there is no earlier location to migrate from;
//! - the workspace catalog is read through the read-only persisted registry
//!   reader in `service::workspace_intelligence::catalog_readonly`, not from the
//!   in-memory catalog snapshot. That source is supplied by the composition as a
//!   [`WorkspaceCatalogSource`] (a path plus an optional revision hint), never as
//!   the workspace service itself, so this host is not a workspace runtime
//!   consumer;
//! - the control record is read once per scope, and the WHOLE observed raw
//!   `policy` value is handed to `GovernedClaim::claim_expecting` so a
//!   same-generation change that lands after the read is rejected inside the
//!   owner's own lock;
//! - the optional catalog revision hint the composition supplies (the workspace
//!   owner's own `subscribe_catalog_changes` receiver) is a wake-up hint only.
//!   Another host process can rewrite the registry with no local event, so the
//!   hint short-circuits a sleep and never decides anything.
//!
//! ## Footprint
//!
//! An unsupported delivery profile, a missing anchor with no control records, and
//! a catalog with nothing enabled all produce zero writes: no task, no lease, no
//! cognition partition, no control write and no anchor mint. A missing anchor next
//! to a non-empty control directory is a bounded existence probe only: the foreign
//! files are never opened, parsed or guessed from, and every byte is preserved.
//!
//! ## Naming
//!
//! "Host" here is a persistent storage/user-data namespace anchor. It is never the
//! machine running the process, never hardware, never an account, and nothing may
//! derive device identity from it. `DeviceIdentity` and every device/account
//! identity API are deliberately never called on any path of this module.
//!
//! ## Change detection
//!
//! Only observed changes are detected. This module does not claim system-wide
//! atomic linearization, adds no second store, no transaction and no CAS in the
//! catalog owner, and re-reads the persisted registry before a claim, after the
//! owner commit and before publish, and on a coarse periodic fallback. When the
//! observed binding stops matching, new claims, commits and publishes are refused,
//! the persisted enabled record is left untouched, and the scope reports
//! `BindingChanged`.
//!
//! ## Recovery requires a new authority
//!
//! A scope refused for a binding reason stays refused until an explicit new
//! control authority arrives. The first time an enabled scope is classified
//! `Unverified`, `BindingSchemaUnsupported`, `BindingMalformed` or
//! `BindingChanged`, this host latches `scope -> control_generation` (plus the
//! reason, so a reverted record still has something truthful to report) and
//! reports the row as [`WorkspaceIntelligenceHostBlock::AwaitingNewAuthority`].
//! Every later pass consults the latch before any claim or tenure path: while the
//! generation has not strictly advanced, the scope claims nothing, takes no lease,
//! commits nothing and publishes nothing, even if the live catalog reverts to the
//! stored shape or a binding is patched into the same generation. A scope whose
//! catalog record becomes ineligible keeps its latch too, and keeps reporting the
//! reason it was latched for: an eligibility change is a catalog write that does
//! not advance the control generation, so it is not a new authority either.
//!
//! A latch is dropped in exactly three cases: the record is OFF or absent, the
//! scope stops appearing in the catalog at all, or the generation strictly
//! advanced AND the stored binding at that new generation matches the live facts.
//! Nothing else clears it.
//!
//! The latch is this host's own admission observation and is volatile by
//! construction: it lives in memory beside the published tenure, is never written
//! to any file, and cannot remember an observation across a process restart. A
//! restarted host starts from the persisted facts alone, exactly as the first
//! build to see them would.
//!
//! ## Configuration
//!
//! Exactly one of the two handle bodies below is compiled, and the pair is
//! asymmetric on purpose. With `workspace-intelligence-host` the handle owns an
//! `Arc<HostCore>` behind private fields, `bootstrap` is its only constructor, and
//! it deliberately implements no `Debug`: it owns the anchor value and the
//! control, cognition and lease roots, and a derived `Debug` would make all of
//! them one `{:?}` away from a log line. Without the feature the handle is a unit
//! struct with `Debug` and `Clone`, `not_compiled` is its only constructor, and it
//! holds nothing at all, so printing it is safe by construction. `bootstrap`,
//! `bootstrap_with_options` and the drain machinery exist only in the compiled
//! configuration; `status` and `shutdown` exist in both and share their names,
//! signatures and return types, so a caller reads the same two methods either way.
//! The CONSTRUCTOR is the one member that does not share a signature: it is
//! `cfg`-selected, `bootstrap` in the compiled build and `not_compiled` in the
//! build without the feature, and the composition root picks the one its own
//! feature `cfg` selects.
//!
//! ## Shutdown
//!
//! `Active -> Draining -> Stopped`. Once draining, no new hand-off, claim attempt
//! or publish is accepted: a pass whose claim attempt comes after the drain began
//! takes no lease at all. A claim that was already in flight keeps its lease and
//! its committed incarnation, and is dropped at publish instead of being handed off.
//! [`DRAIN_BUDGET`] is a wait budget, NOT a hard upper bound on a blocking owner
//! commit: the cognition store's SQLite busy timeout is 10 s and the owner guard
//! can outlive it, so in-flight blocking owner work keeps its locks until its
//! transaction ends. On timeout the result is
//! `DrainTimedOut { outstanding }` and the state remains `Draining` (incomplete),
//! never `Stopped`. The honest statements are "stopped waiting" and "no new
//! hand-off"; a drain never claims that a lease was released (only process exit
//! releases it) and never claims a rollback.

use std::time::Duration;

/// Overall state of one workspace intelligence host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostState {
    /// The host feature is not compiled into this build. Answerable without it.
    NotCompiled,
    /// Nothing is enabled on this host and nothing is running.
    Inactive,
    /// At least one scope is owned by this process and nothing blocks.
    Active,
    /// At least one scope is owned, but something else is blocked or only standby
    /// tenure was obtained.
    Degraded,
    /// No scope is owned by this process and a typed reason explains why. A pass
    /// that cannot enumerate the scopes releases the tenure it held, so this state
    /// never coexists with a held owner claim.
    Unavailable,
    /// Shutdown started: no new hand-off, claim attempt or publish is accepted. A
    /// claim already in flight keeps its lease and incarnation and is dropped at
    /// publish.
    Draining,
    /// Shutdown completed and the host stopped.
    Stopped,
}

impl WorkspaceIntelligenceHostState {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotCompiled => "not_compiled",
            Self::Inactive => "inactive",
            Self::Active => "active",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
        }
    }
}

/// Why a delivery profile cannot host workspace intelligence in this wave.
///
/// These are typed delivery decisions, not UI copy: a surface such as the CLI
/// renders its own Install/Skip wording from [`Self::code`], so no product string
/// is invented here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostUnsupportedProfile {
    /// A background daemon delivery, even when its surface looks interactive.
    Daemon,
    /// A shared Agent Runtime owns the workspace; that deployment has not drained.
    SharedRuntime,
    /// A server stdio delivery has no local interactive host.
    ServerStdio,
    /// A detached dispatch target runs headless with no guaranteed submitter.
    DetachedDispatch,
    /// A management-only delivery.
    Management,
    /// An ACP host app.
    Acp,
    /// An SDK host app.
    SdkHostApp,
    /// A peer-device controller: product commands are proxied to the peer.
    PeerController,
}

impl WorkspaceIntelligenceHostUnsupportedProfile {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::Daemon => "profile_daemon",
            Self::SharedRuntime => "profile_shared_runtime",
            Self::ServerStdio => "profile_server_stdio",
            Self::DetachedDispatch => "profile_detached_dispatch",
            Self::Management => "profile_management",
            Self::Acp => "profile_acp",
            Self::SdkHostApp => "profile_sdk_host_app",
            Self::PeerController => "profile_peer_controller",
        }
    }
}

/// Why a persisted workspace record can never hold a governed scope here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostUnsupportedScope {
    /// A remote/SSH workspace. Every remote execution scope is unsupported.
    RemoteScope,
    /// An assistant workspace is not a governance target.
    AssistantWorkspace,
    /// A worktree record the startup path would upgrade in memory only.
    LegacyWorktreeReference,
    /// A worktree child whose parent does not resolve in the same snapshot.
    UnresolvedWorktreeParent,
    /// A local root this build cannot render exactly (not valid UTF-8).
    NonUtf8Root,
    /// A record that fails structural validation.
    MalformedRecord,
}

impl WorkspaceIntelligenceHostUnsupportedScope {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::RemoteScope => "remote_scope",
            Self::AssistantWorkspace => "assistant_workspace",
            Self::LegacyWorktreeReference => "legacy_worktree_reference",
            Self::UnresolvedWorktreeParent => "unresolved_worktree_parent",
            Self::NonUtf8Root => "non_utf8_root",
            Self::MalformedRecord => "malformed_record",
        }
    }
}

/// Typed reason attached to a host state or to one scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostReason {
    /// The host feature is not compiled into this build.
    NotCompiled,
    /// No anchor and no control records: nothing to do and nothing written.
    NoRecords,
    /// The catalog was read and holds no enabled scope.
    NoEnabledScope,
    /// The anchor is missing while the control directory holds records.
    AnchorMissingWithRecords,
    /// The anchor document exists but could not be read or validated.
    AnchorUnreadable,
    /// The persisted workspace registry could not be read, decoded or validated.
    CatalogUnreadable,
    /// A persisted control record could not be read or decoded.
    ControlUnreadable,
    /// An enabled record stores no execution binding. It stays enabled and is not
    /// claimed, rewritten or back-filled.
    Unverified,
    /// The observed execution binding no longer matches the stored one.
    BindingChanged,
    /// The stored execution binding declares an unknown schema version.
    BindingSchemaUnsupported,
    /// The stored execution binding is present but not usable.
    BindingMalformed,
    /// The control authority changed between this host's read and the claim.
    AuthorityChanged,
    /// The owner claim was refused for a reason without a narrower mapping.
    ClaimRefused,
    /// The owner claim could not be attempted at all.
    ClaimFailed,
    /// Only standby tenure was obtained: another process owns the scope.
    Standby,
    /// The delivery profile cannot host workspace intelligence.
    ProfileUnsupported(WorkspaceIntelligenceHostUnsupportedProfile),
}

impl WorkspaceIntelligenceHostReason {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::NotCompiled => "not_compiled",
            Self::NoRecords => "no_records",
            Self::NoEnabledScope => "no_enabled_scope",
            Self::AnchorMissingWithRecords => "anchor_missing_with_records",
            Self::AnchorUnreadable => "anchor_unreadable",
            Self::CatalogUnreadable => "catalog_unreadable",
            Self::ControlUnreadable => "control_unreadable",
            Self::Unverified => "unverified",
            Self::BindingChanged => "binding_changed",
            Self::BindingSchemaUnsupported => "binding_schema_unsupported",
            Self::BindingMalformed => "binding_malformed",
            Self::AuthorityChanged => "authority_changed",
            Self::ClaimRefused => "claim_refused",
            Self::ClaimFailed => "claim_failed",
            Self::Standby => "standby",
            Self::ProfileUnsupported(profile) => profile.code(),
        }
    }
}

/// Disposition of one enumerated scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostScopeState {
    /// This process holds the scope's owner tenure.
    Active,
    /// Another process holds it; this process is a candidate for takeover.
    Standby,
    /// The record is off, or there is no record. Nothing is claimed.
    Disabled,
    /// Enabled but blocked by a typed authority, binding or storage reason.
    Blocked(WorkspaceIntelligenceHostReason),
    /// Never eligible on this host.
    Unsupported(WorkspaceIntelligenceHostUnsupportedScope),
}

impl WorkspaceIntelligenceHostScopeState {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Standby => "standby",
            Self::Disabled => "disabled",
            Self::Blocked(reason) => reason.code(),
            Self::Unsupported(reason) => reason.code(),
        }
    }
}

/// Whether a blocked scope may claim again on a later pass, or is waiting for an
/// explicit new authority.
///
/// A binding block is latched at the control generation where this host first
/// observed it, so the same reasons can mean two different things: a block that
/// this pass merely observed (`Transient`), and one that only a control write
/// advancing the generation can clear (`AwaitingNewAuthority`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostBlock {
    /// Blocked by this pass's own observation. A later pass may claim.
    Transient,
    /// Latched at a control generation. Only a strictly newer generation that
    /// carries a matching stored binding recovers the scope, even if the live
    /// facts revert in between.
    AwaitingNewAuthority,
}

impl WorkspaceIntelligenceHostBlock {
    /// Stable machine-readable code for status data and logs.
    pub fn code(self) -> &'static str {
        match self {
            Self::Transient => "transient",
            Self::AwaitingNewAuthority => "awaiting_new_authority",
        }
    }
}

/// Plain-data report of one enumerated scope, keyed by the persisted workspace id.
///
/// The workspace id is the only scope-shaped value that leaves this module: the
/// control scope string embeds the full storage-namespace host id, so it stays an
/// internal storage key and is never projected into status data or a log field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIntelligenceHostScopeReport {
    workspace_id: String,
    state: WorkspaceIntelligenceHostScopeState,
    block: Option<WorkspaceIntelligenceHostBlock>,
}

impl WorkspaceIntelligenceHostScopeReport {
    /// Persisted workspace id of this scope.
    pub fn scope(&self) -> &str {
        &self.workspace_id
    }

    pub fn state(&self) -> WorkspaceIntelligenceHostScopeState {
        self.state
    }

    /// Latch phase of a blocked row: `None` when the row is not blocked, and the
    /// typed phase otherwise. The generation itself stays host-internal.
    pub fn block(&self) -> Option<WorkspaceIntelligenceHostBlock> {
        self.block
    }
}

/// Counts of the four scope buckets the host reports.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WorkspaceIntelligenceHostCounts {
    active: usize,
    standby: usize,
    invalid: usize,
    unsupported: usize,
}

impl WorkspaceIntelligenceHostCounts {
    pub fn active(&self) -> usize {
        self.active
    }

    pub fn standby(&self) -> usize {
        self.standby
    }

    pub fn invalid(&self) -> usize {
        self.invalid
    }

    pub fn unsupported(&self) -> usize {
        self.unsupported
    }
}

/// Plain-data status of one host handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceIntelligenceHostStatus {
    state: WorkspaceIntelligenceHostState,
    reason: Option<WorkspaceIntelligenceHostReason>,
    counts: WorkspaceIntelligenceHostCounts,
    anchor_present: bool,
    host_marker: Option<String>,
    scopes: Vec<WorkspaceIntelligenceHostScopeReport>,
}

impl WorkspaceIntelligenceHostStatus {
    /// Overall state.
    pub fn state(&self) -> WorkspaceIntelligenceHostState {
        self.state
    }

    /// First blocking typed reason, if any.
    pub fn reason(&self) -> Option<WorkspaceIntelligenceHostReason> {
        self.reason
    }

    /// Scope counts.
    pub fn counts(&self) -> WorkspaceIntelligenceHostCounts {
        self.counts
    }

    /// True when a validated storage-namespace anchor is available.
    pub fn anchor_present(&self) -> bool {
        self.anchor_present
    }

    /// Redacted marker of the storage-namespace anchor. Never the full host id.
    pub fn host_marker(&self) -> Option<&str> {
        self.host_marker.as_deref()
    }

    /// Per-scope dispositions, sorted by persisted workspace id.
    pub fn scopes(&self) -> &[WorkspaceIntelligenceHostScopeReport] {
        &self.scopes
    }

    /// Disposition of one workspace, if this snapshot enumerated it.
    pub fn scope_state(
        &self,
        workspace_id: &str,
    ) -> Option<WorkspaceIntelligenceHostScopeState> {
        self.scopes
            .iter()
            .find(|report| report.workspace_id == workspace_id)
            .map(|report| report.state)
    }
}

/// Outcome of draining one host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostDrain {
    /// The host stopped waiting with no outstanding owner work.
    Drained,
    /// The drain budget expired while owner work was still in flight. The state
    /// stays `Draining`; nothing is rolled back and nothing new is handed off.
    DrainTimedOut { outstanding: usize },
}

/// Result of one shutdown call: the drain outcome and the state it left behind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceIntelligenceHostShutdown {
    drain: WorkspaceIntelligenceHostDrain,
    state: WorkspaceIntelligenceHostState,
}

impl WorkspaceIntelligenceHostShutdown {
    /// Drain outcome.
    pub fn drain(&self) -> WorkspaceIntelligenceHostDrain {
        self.drain
    }

    /// State after the drain attempt.
    pub fn state(&self) -> WorkspaceIntelligenceHostState {
        self.state
    }

    pub(super) fn new(
        drain: WorkspaceIntelligenceHostDrain,
        state: WorkspaceIntelligenceHostState,
    ) -> Self {
        Self { drain, state }
    }
}

/// Delivery surface a host bootstrap runs on.
///
/// The surface alone is not enough: a CLI daemon and an interactive CLI share
/// a surface shape, so bootstrap also carries the real `RuntimeDeployment`.
///
/// It is declared unconditionally so a build without the host feature can still
/// name the same surface type when it asks for the typed `NotCompiled` answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceIntelligenceHostSurface {
    Desktop,
    CliInteractive,
    CliExecution,
    ServerLoopback,
    ServerStdio,
    Daemon,
    DetachedDispatch,
    Management,
    SharedRuntime,
    Acp,
    SdkHostApp,
    PeerController,
}

/// Drain wait budget.
///
/// This is a named constant rather than a magic number because it is a *wait*
/// budget, not a hard upper bound on a blocking owner commit: the cognition
/// store's SQLite busy timeout is 10 s and the owner guard can outlive it.
// Only a build that compiles the host can drain anything.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "no host body exists to spend a drain budget")
)]
pub(crate) const DRAIN_BUDGET: Duration = Duration::from_secs(12);

#[cfg(not(feature = "workspace-intelligence-host"))]
mod not_compiled {
    use super::{
        WorkspaceIntelligenceHostCounts, WorkspaceIntelligenceHostDrain,
        WorkspaceIntelligenceHostReason, WorkspaceIntelligenceHostShutdown,
        WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostStatus,
    };

    /// Feature-off host handle.
    ///
    /// Without the feature there is no bootstrap dependency to read, so this
    /// handle performs no IO, spawns no task, takes no lease and writes nothing.
    /// It exists so a caller can ask about workspace intelligence in a build that
    /// does not compile it and get a typed answer instead of an absence.
    #[derive(Debug, Clone)]
    pub struct WorkspaceIntelligenceHost;

    impl WorkspaceIntelligenceHost {
        /// The only constructor of a build without the host feature.
        ///
        /// A build that does not compile the host cannot read the anchor or the
        /// persisted registry, so this handle performs no IO and its `status()` is
        /// always `NotCompiled`. A build with the feature obtains a handle only
        /// through [`bootstrap`](super::compiled::WorkspaceIntelligenceHost::bootstrap),
        /// and a composition root picks between the two with the same feature `cfg`
        /// it already uses. Neither path accepts a host id or an anchor value from
        /// the caller: the anchor is always read from the caller's own user-data
        /// root.
        pub fn not_compiled() -> Self {
            Self
        }

        /// Typed `NotCompiled` answer.
        pub async fn status(&self) -> WorkspaceIntelligenceHostStatus {
            WorkspaceIntelligenceHostStatus {
                state: WorkspaceIntelligenceHostState::NotCompiled,
                reason: Some(WorkspaceIntelligenceHostReason::NotCompiled),
                counts: WorkspaceIntelligenceHostCounts::default(),
                anchor_present: false,
                host_marker: None,
                scopes: Vec::new(),
            }
        }

        /// Nothing runs without the feature, so nothing is left to drain.
        pub async fn shutdown(&self) -> WorkspaceIntelligenceHostShutdown {
            WorkspaceIntelligenceHostShutdown::new(
                WorkspaceIntelligenceHostDrain::Drained,
                WorkspaceIntelligenceHostState::NotCompiled,
            )
        }
    }
}

#[cfg(feature = "workspace-intelligence-host")]
mod compiled {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use log::{info, warn};
    use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
    use openbitfun_services_core::workspace_intelligence_claim::{
        ClaimAttempt, ClaimVerification, GovernedClaim, WorkspaceIntelligenceClaimError,
    };
    use openbitfun_services_core::workspace_intelligence_commit::{
        GovernedClaimRefusal, WorkspaceIntelligenceCommitError,
    };
    use openbitfun_services_core::workspace_intelligence_host_anchor::{
        HostAnchorError, HostAnchorState, HostAnchorStore, HOST_ID_PREFIX,
    };
    use openbitfun_services_core::workspace_intelligence_store::{
        WorkspaceIntelligenceStore, WorkspaceIntelligenceStoreError,
    };
    use tokio::sync::{watch, Mutex};

    use crate::infrastructure::PathManager;
    use crate::service::workspace_intelligence::catalog_readonly::{
        self, PersistedCatalog, PersistedCatalogEntry, PersistedCatalogUnsupported,
        PersistedWorkspace,
    };
    use crate::service::workspace_intelligence::host_binding::{
        self, BindingState, ExecutionBinding, LOCAL_EXECUTION_DOMAIN,
    };
    use crate::service::workspace_intelligence::host_standby::{
        StandbyWorker, STANDBY_BASE_DELAY, STANDBY_MAX_DELAY,
    };
    use crate::service::workspace_intelligence::policy::{ControlPolicyView, CONTROL_SCHEMA_VERSION};
    use crate::service::workspace_intelligence::scope::{
        HostExecutionDomainKey, WorkspaceControlScope,
    };

    use super::{
        WorkspaceIntelligenceHostBlock, WorkspaceIntelligenceHostCounts,
        WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostReason,
        WorkspaceIntelligenceHostScopeReport, WorkspaceIntelligenceHostScopeState,
        WorkspaceIntelligenceHostShutdown, WorkspaceIntelligenceHostState,
        WorkspaceIntelligenceHostStatus, WorkspaceIntelligenceHostSurface,
        WorkspaceIntelligenceHostUnsupportedProfile, WorkspaceIntelligenceHostUnsupportedScope,
        DRAIN_BUDGET,
    };

    /// Exhaustive delivery gate.
    ///
    /// There is deliberately no wildcard arm: a new surface or a new
    /// [`RuntimeDeployment`] variant fails to compile here instead of silently
    /// inheriting an answer. Mapped variants: `RuntimeDeployment::Embedded` (an
    /// embedded runtime owns the workspace) and `RuntimeDeployment::Shared` (a
    /// shared runtime owns it and has not drained), which no surface may admit.
    pub(crate) fn profile_support(
        surface: WorkspaceIntelligenceHostSurface,
        deployment: RuntimeDeployment,
    ) -> Result<(), WorkspaceIntelligenceHostUnsupportedProfile> {
        use RuntimeDeployment::{Embedded, Shared};
        use WorkspaceIntelligenceHostSurface as Surface;
        use WorkspaceIntelligenceHostUnsupportedProfile as Unsupported;
        match (surface, deployment) {
            (Surface::Desktop, Embedded) => Ok(()),
            // A shared runtime owns the workspace and has not drained it: that is
            // exactly the tenure this host must not admit, on every surface.
            (Surface::Desktop, Shared) => Err(Unsupported::SharedRuntime),
            (Surface::CliInteractive, Embedded) => Ok(()),
            // Same rule on every surface: a shared deployment is refused as such
            // whenever the surface itself would have been admitted.
            (Surface::CliInteractive, Shared) => Err(Unsupported::SharedRuntime),
            (Surface::CliExecution, Embedded) => Ok(()),
            (Surface::CliExecution, Shared) => Err(Unsupported::SharedRuntime),
            (Surface::ServerLoopback, Embedded) => Ok(()),
            (Surface::ServerLoopback, Shared) => Err(Unsupported::SharedRuntime),
            (Surface::ServerStdio, Embedded) => Err(Unsupported::ServerStdio),
            (Surface::ServerStdio, Shared) => Err(Unsupported::ServerStdio),
            (Surface::Daemon, Embedded) => Err(Unsupported::Daemon),
            (Surface::Daemon, Shared) => Err(Unsupported::Daemon),
            (Surface::DetachedDispatch, Embedded) => Err(Unsupported::DetachedDispatch),
            (Surface::DetachedDispatch, Shared) => Err(Unsupported::DetachedDispatch),
            (Surface::Management, Embedded) => Err(Unsupported::Management),
            (Surface::Management, Shared) => Err(Unsupported::Management),
            (Surface::SharedRuntime, Embedded) => Err(Unsupported::SharedRuntime),
            (Surface::SharedRuntime, Shared) => Err(Unsupported::SharedRuntime),
            (Surface::Acp, Embedded) => Err(Unsupported::Acp),
            (Surface::Acp, Shared) => Err(Unsupported::Acp),
            (Surface::SdkHostApp, Embedded) => Err(Unsupported::SdkHostApp),
            (Surface::SdkHostApp, Shared) => Err(Unsupported::SdkHostApp),
            (Surface::PeerController, Embedded) => Err(Unsupported::PeerController),
            (Surface::PeerController, Shared) => Err(Unsupported::PeerController),
        }
    }

    /// Bootstrap timings. [`bootstrap`](compiled::WorkspaceIntelligenceHost::bootstrap)
    /// always uses [`HostTiming::default`]; fixtures inject a short standby delay and
    /// a short drain budget so tests stay fast.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct HostTiming {
        standby_base: Duration,
        standby_cap: Duration,
        drain_budget: Duration,
    }

    impl HostTiming {
        // Fixtures compress the schedule; production uses the defaults below.
        #[cfg(test)]
        pub(crate) fn new(standby_base: Duration, standby_cap: Duration, drain_budget: Duration) -> Self {
            Self {
                standby_base,
                standby_cap,
                drain_budget,
            }
        }
    }

    impl Default for HostTiming {
        fn default() -> Self {
            Self {
                standby_base: STANDBY_BASE_DELAY,
                standby_cap: STANDBY_MAX_DELAY,
                drain_budget: DRAIN_BUDGET,
            }
        }
    }

    /// One read-only observation for the future confirmed preparation owner.
    /// No `Debug`: the observations carry private identity, paths and raw policy.
    #[allow(dead_code, reason = "only the future confirmed enable owner consumes these facts")]
    pub(super) enum InitialEnableAdmission {
        NeedsAnchor {
            workspace: PersistedWorkspace,
        },
        Anchored {
            scope: WorkspaceControlScope,
            binding: ExecutionBinding,
            control: InitialEnableControl,
        },
    }

    #[allow(dead_code, reason = "only the future confirmed enable owner consumes this snapshot")]
    pub(super) enum InitialEnableControl {
        Absent,
        Disabled {
            generation: u64,
            raw_policy: Option<serde_json::Value>,
        },
    }

    /// Only typed reasons leave the admission check, never the underlying errors.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum InitialEnableRefusal {
        Stopping,
        Host(WorkspaceIntelligenceHostReason),
        WorkspaceNotFound,
        UnsupportedScope(WorkspaceIntelligenceHostUnsupportedScope),
        UnrenderableWorktreeMainPath,
        AnchorChanged,
        AlreadyEnabled,
        ControlSchemaUnsupported,
        ControlPolicyUnreadable,
    }

    /// Validated storage-namespace tenancy of this host.
    struct Tenancy {
        host: HostExecutionDomainKey,
        marker: String,
    }

    /// The persisted-registry source one host is handed by its composition.
    ///
    /// The host needs exactly one thing from the workspace owner: an optional
    /// wake-up hint that the persisted registry changed. It deliberately does NOT
    /// take a `WorkspaceService`. That type lives behind the `workspace-runtime`
    /// feature, so holding one — or calling `subscribe_catalog_changes()` through
    /// it — would make this host a workspace runtime consumer and drag the
    /// workspace runtime's process, filesystem and terminal owners into a build
    /// that only needs to read a persisted registry location. Because
    /// `WorkspaceService::subscribe_catalog_changes()` is an associated function
    /// with no receiver, the composition obtains the receiver itself and hands it
    /// over here; this module never names that type.
    ///
    /// The registry LOCATION is not part of this value, on purpose. It is derived
    /// from the host's own [`PathManager`] by `catalog_readonly`, so no assembled
    /// caller can point a host at another profile's user-data root: the strongest
    /// form of the same-user-data-root requirement is that the value cannot exist.
    pub(crate) struct WorkspaceCatalogSource {
        revision: Option<watch::Receiver<u64>>,
    }

    impl WorkspaceCatalogSource {
        /// Source with no hint: the coarse fallback timer is the only wake-up.
        ///
        /// Production reaches this through `from_hint(None)`; the name exists so a
        /// fixture states that it deliberately exercises the no-watch path.
        #[cfg(test)]
        pub(crate) fn without_hint() -> Self {
            Self { revision: None }
        }

        /// Source built from the optional hint a public caller supplies.
        fn from_hint(revision: Option<watch::Receiver<u64>>) -> Self {
            Self { revision }
        }

        /// Source with a real revision hint, for fixtures that must prove the
        /// hint itself wakes a pass.
        ///
        /// Production reaches the same value through `from_hint`; this name exists
        /// so a fixture states that the hint is the only wake-up it leaves enabled.
        #[cfg(test)]
        pub(crate) fn from_hint_for_tests(revision: watch::Receiver<u64>) -> Self {
            Self {
                revision: Some(revision),
            }
        }

        fn revision(&self) -> Option<watch::Receiver<u64>> {
            self.revision.clone()
        }
    }

    /// One volatile admission latch: the control generation at which this host
    /// first refused to claim a still-enabled scope, and the reason it refused for.
    ///
    /// The reason is kept beside the generation because the live facts may revert
    /// afterwards, and a reverted record no longer carries the fact that was
    /// refused: the row would otherwise have nothing truthful left to report.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct BlockedScope {
        generation: u64,
        reason: WorkspaceIntelligenceHostReason,
    }

    /// Mutable book of one host. Never held across an owner await except for the
    /// short, fully synchronous sections below.
    struct Book {
        state: WorkspaceIntelligenceHostState,
        reason: Option<WorkspaceIntelligenceHostReason>,
        fatal: Option<WorkspaceIntelligenceHostReason>,
        scopes: Vec<WorkspaceIntelligenceHostScopeReport>,
        claims: BTreeMap<String, GovernedClaim>,
        /// Volatile per-scope admission latch. Deliberately not persisted: it holds
        /// one host's own observation, and a restart starts from fresh facts.
        blocked_generation: BTreeMap<String, BlockedScope>,
        worker: Option<StandbyWorker>,
    }

    impl Book {
        fn new() -> Self {
            Self {
                state: WorkspaceIntelligenceHostState::Inactive,
                reason: Some(WorkspaceIntelligenceHostReason::NoRecords),
                fatal: None,
                scopes: Vec::new(),
                claims: BTreeMap::new(),
                blocked_generation: BTreeMap::new(),
                worker: None,
            }
        }

        /// Counts one bucket per enumerated scope.
        fn counts(&self) -> WorkspaceIntelligenceHostCounts {
            let mut counts = WorkspaceIntelligenceHostCounts::default();
            for report in &self.scopes {
                match report.state {
                    WorkspaceIntelligenceHostScopeState::Active => counts.active += 1,
                    WorkspaceIntelligenceHostScopeState::Standby => counts.standby += 1,
                    WorkspaceIntelligenceHostScopeState::Blocked(_) => counts.invalid += 1,
                    WorkspaceIntelligenceHostScopeState::Unsupported(_) => counts.unsupported += 1,
                    WorkspaceIntelligenceHostScopeState::Disabled => {}
                }
            }
            counts
        }

        /// Derives the overall state from the enumerated scopes.
        ///
        /// A teardown state always wins: nothing may resurrect a host that is
        /// draining or stopped.
        fn settle(&mut self) {
            if matches!(
                self.state,
                WorkspaceIntelligenceHostState::Draining | WorkspaceIntelligenceHostState::Stopped
            ) {
                return;
            }
            if let Some(fatal) = self.fatal {
                self.state = WorkspaceIntelligenceHostState::Unavailable;
                self.reason = Some(fatal);
                return;
            }
            let counts = self.counts();
            let first_blocked = self.scopes.iter().find_map(|report| match report.state {
                WorkspaceIntelligenceHostScopeState::Blocked(reason) => Some(reason),
                _ => None,
            });
            if counts.active > 0 {
                self.state = if first_blocked.is_some() {
                    WorkspaceIntelligenceHostState::Degraded
                } else {
                    WorkspaceIntelligenceHostState::Active
                };
                self.reason = first_blocked;
            } else if let Some(reason) = first_blocked {
                self.state = WorkspaceIntelligenceHostState::Unavailable;
                self.reason = Some(reason);
            } else if counts.standby > 0 {
                self.state = WorkspaceIntelligenceHostState::Degraded;
                self.reason = Some(WorkspaceIntelligenceHostReason::Standby);
            } else {
                self.state = WorkspaceIntelligenceHostState::Inactive;
                self.reason = Some(WorkspaceIntelligenceHostReason::NoEnabledScope);
            }
        }
    }

    /// In-flight accounting for one evaluation pass.
    struct InFlight(Arc<HostCore>);

    impl InFlight {
        fn enter(core: Arc<HostCore>) -> Self {
            core.in_flight.fetch_add(1, Ordering::SeqCst);
            Self(core)
        }
    }

    impl Drop for InFlight {
        fn drop(&mut self) {
            if self.0.in_flight.fetch_sub(1, Ordering::SeqCst) == 1 {
                self.0.idle.notify_waiters();
            }
        }
    }

    /// Shared state of one host handle.
    struct HostCore {
        paths: Arc<PathManager>,
        catalog: WorkspaceCatalogSource,
        timing: HostTiming,
        tenancy: Option<Tenancy>,
        control: WorkspaceIntelligenceStore,
        cognition_root: PathBuf,
        lease_root: PathBuf,
        book: Mutex<Book>,
        pass: Mutex<()>,
        stop: watch::Sender<bool>,
        in_flight: AtomicUsize,
        idle: tokio::sync::Notify,
        #[cfg(test)]
        pause: Option<HostPause>,
        #[cfg(test)]
        after_claim: Option<HostPause>,
        #[cfg(test)]
        before_book: Option<HostPause>,
        #[cfg(test)]
        at_book_lock: Option<HostPause>,
        #[cfg(test)]
        drain_window: Option<HostPause>,
    }

    impl HostCore {
        fn new(
            paths: Arc<PathManager>,
            catalog: WorkspaceCatalogSource,
            timing: HostTiming,
            tenancy: Option<Tenancy>,
        ) -> Self {
            let control = WorkspaceIntelligenceStore::new(
                paths.workspace_intelligence_control_dir(),
                vec![CONTROL_SCHEMA_VERSION],
            );
            let (stop, _) = watch::channel(false);
            #[cfg(test)]
            let pause = super::pauses::for_user_root_of(&paths, super::pauses::PausePoint::BeforeClaim);
            #[cfg(test)]
            let after_claim =
                super::pauses::for_user_root_of(&paths, super::pauses::PausePoint::AfterClaim);
            #[cfg(test)]
            let before_book =
                super::pauses::for_user_root_of(&paths, super::pauses::PausePoint::BeforeBook);
            #[cfg(test)]
            let at_book_lock =
                super::pauses::for_user_root_of(&paths, super::pauses::PausePoint::AtBookLock);
            #[cfg(test)]
            let drain_window =
                super::pauses::for_user_root_of(&paths, super::pauses::PausePoint::DrainWait);
            Self {
                cognition_root: paths.workspace_intelligence_cognition_dir(),
                lease_root: paths.workspace_intelligence_lease_dir(),
                control,
                stop,
                in_flight: AtomicUsize::new(0),
                idle: tokio::sync::Notify::new(),
                pass: Mutex::new(()),
                book: Mutex::new(Book::new()),
                timing,
                tenancy,
                catalog,
                paths,
                #[cfg(test)]
                pause,
                #[cfg(test)]
                after_claim,
                #[cfg(test)]
                before_book,
                #[cfg(test)]
                at_book_lock,
                #[cfg(test)]
                drain_window,
            }
        }

        fn shutdown_requested(&self) -> bool {
            *self.stop.borrow()
        }

        /// Sets a terminal state without evaluating anything.
        async fn mark(
            &self,
            state: WorkspaceIntelligenceHostState,
            reason: WorkspaceIntelligenceHostReason,
        ) {
            let mut book = self.book.lock().await;
            book.state = state;
            book.reason = Some(reason);
            book.fatal = Some(reason);
            book.scopes.clear();
            book.claims.clear();
        }

        /// Reads the persisted workspace registry through the read-only reader.
        ///
        /// The reader resolves the location from `self.paths`, the same user-data
        /// root this host anchors on, so the registry this pass enumerates is the
        /// one the host's own profile owns.
        async fn read_catalog(&self) -> Result<PersistedCatalog, catalog_readonly::CatalogReadError> {
            catalog_readonly::read_persisted_catalog(&self.paths).await
        }

        async fn check_initial_enable_gate(&self) -> Result<(), InitialEnableRefusal> {
            let book = self.book.lock().await;
            if self.shutdown_requested()
                || matches!(
                    book.state,
                    WorkspaceIntelligenceHostState::Draining
                        | WorkspaceIntelligenceHostState::Stopped
                )
            {
                return Err(InitialEnableRefusal::Stopping);
            }
            // Bootstrap records the exhaustive profile gate in `fatal`. The only
            // exception is a supported host that started with no records: that
            // is exactly where first-enable preflight must be possible.
            match (book.state, book.fatal) {
                // A supported host that started with no records is exactly the
                // first-enable shape, so it may preflight.
                (
                    WorkspaceIntelligenceHostState::Inactive,
                    Some(WorkspaceIntelligenceHostReason::NoRecords),
                )
                | (_, None) => Ok(()),
                (_, Some(reason)) => Err(InitialEnableRefusal::Host(reason)),
            }
        }

        async fn observe_initial_enable(
            &self,
            workspace_id: &str,
        ) -> Result<InitialEnableAdmission, InitialEnableRefusal> {
            use InitialEnableRefusal as Refusal;
            use WorkspaceIntelligenceHostReason as Reason;

            let catalog = self
                .read_catalog()
                .await
                .map_err(|_| Refusal::Host(Reason::CatalogUnreadable))?;
            let workspace = match catalog.entries().iter().find(|(id, _)| id == workspace_id) {
                Some((_, PersistedCatalogEntry::Eligible(workspace))) => workspace,
                Some((_, PersistedCatalogEntry::Unsupported(reason))) => {
                    return Err(Refusal::UnsupportedScope(unscoped_unsupported(*reason)));
                }
                None => return Err(Refusal::WorkspaceNotFound),
            };
            // The legacy reader projects an unrenderable main path as absent for
            // startup comparison. Do not use that lossy fact for a new binding.
            if workspace.worktree_is_main().is_some() && workspace.main_repo_path().is_none() {
                return Err(Refusal::UnrenderableWorktreeMainPath);
            }

            let anchor = HostAnchorStore::new(anchor_root(&self.paths))
                .read_strict()
                .await
                .map_err(|_| Refusal::Host(Reason::AnchorUnreadable))?;
            let host = match anchor {
                HostAnchorState::Absent => {
                    if self.tenancy.is_some() {
                        return Err(Refusal::AnchorChanged);
                    }
                    if !control_directory_is_vacant(&self.paths).await {
                        return Err(Refusal::Host(Reason::AnchorMissingWithRecords));
                    }
                    return Ok(InitialEnableAdmission::NeedsAnchor {
                        workspace: workspace.clone(),
                    });
                }
                HostAnchorState::Present(anchor) => {
                    HostExecutionDomainKey::new(anchor.host_id(), LOCAL_EXECUTION_DOMAIN)
                        .expect("a validated anchor id is never blank")
                }
            };
            if self.tenancy.as_ref().is_some_and(|tenancy| tenancy.host != host) {
                return Err(Refusal::AnchorChanged);
            }
            // Observing a valid anchor does not adopt it into the running host.
            let scope = WorkspaceControlScope::new(&host, workspace.id())
                .expect("an eligible workspace id is never blank");
            // `as_str` renders the storage key; it is not a borrow of the scope.
            let scope_key = scope.as_str();
            let binding = ExecutionBinding::observed(host.host_id(), workspace);
            let record = self
                .control
                .read(&scope_key)
                .await
                .map_err(|error| match error {
                    WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion { .. } => {
                        Refusal::ControlSchemaUnsupported
                    }
                    _ => Refusal::Host(Reason::ControlUnreadable),
                })?;
            let control = match record {
                None => InitialEnableControl::Absent,
                Some(record) => {
                    if record.enabled == Some(true) {
                        return Err(Refusal::AlreadyEnabled);
                    }
                    match host_binding::classify(record.policy.as_ref()) {
                        BindingState::Absent => {}
                        BindingState::Present(stored) if stored.matches(&binding) => {}
                        BindingState::Present(_) => {
                            return Err(Refusal::Host(Reason::BindingChanged))
                        }
                        BindingState::Malformed => {
                            return Err(Refusal::Host(Reason::BindingMalformed))
                        }
                        BindingState::UnsupportedSchema { .. } => {
                            return Err(Refusal::Host(Reason::BindingSchemaUnsupported));
                        }
                    }
                    if !ControlPolicyView::read(record.policy.as_ref()).diagnostics().is_empty() {
                        return Err(Refusal::ControlPolicyUnreadable);
                    }
                    InitialEnableControl::Disabled {
                        generation: record.control_generation,
                        raw_policy: record.policy,
                    }
                }
            };
            Ok(InitialEnableAdmission::Anchored { scope, binding, control })
        }

        /// One full re-evaluation pass over the persisted facts.
        ///
        /// Never called concurrently with itself: a second call returns
        /// immediately instead of queueing a second pass.
        async fn evaluate(self: &Arc<Self>) {
            let _in_flight = InFlight::enter(Arc::clone(self));
            let Ok(_pass) = self.pass.try_lock() else {
                return;
            };
            if self.shutdown_requested() {
                return;
            }
            let Some(tenancy) = self.tenancy.as_ref() else {
                return;
            };
            let catalog = match self.read_catalog().await {
                Ok(catalog) => catalog,
                Err(error) => {
                    warn!(
                        "Workspace intelligence host could not read the persisted workspace registry: code={}",
                        error.code()
                    );
                    let mut book = self.book.lock().await;
                    // The tenure published by the previous pass is released here
                    // rather than kept: with no readable authority this host cannot
                    // prove it still holds a scope, so it must not settle
                    // `Unavailable` — documented as "no scope is owned" — while
                    // still holding one. The leases release on drop, and a later
                    // pass re-claims from fresh persisted facts.
                    book.claims.clear();
                    book.fatal = Some(WorkspaceIntelligenceHostReason::CatalogUnreadable);
                    book.scopes.clear();
                    book.settle();
                    return;
                }
            };

            let (mut owned, latched, retry_earned): (
                BTreeMap<String, GovernedClaim>,
                BTreeMap<String, BlockedScope>,
                bool,
            ) = {
                let mut book = self.book.lock().await;
                // Retry is earned by evidence this host already observed, never by an
                // unreadable record: a worker in place, tenure this host still holds, or
                // a latch all presuppose a scope that was read as enabled at some
                // generation. Read under the same lock as the two maps it is taken with,
                // so the three facts describe one state of the book.
                let retry_earned = book.worker.is_some()
                    || !book.claims.is_empty()
                    || !book.blocked_generation.is_empty();
                (
                    std::mem::take(&mut book.claims),
                    std::mem::take(&mut book.blocked_generation),
                    retry_earned,
                )
            };
            // Rebuilt from the scopes this pass actually enumerates, so a scope that
            // leaves the catalog or goes OFF drops its latch without a second sweep.
            let mut next_latched: BTreeMap<String, BlockedScope> = BTreeMap::new();
            let mut reports: Vec<WorkspaceIntelligenceHostScopeReport> = Vec::new();
            let mut published: BTreeMap<String, GovernedClaim> = BTreeMap::new();
            // `(scope_id, observed_binding, observed_control_generation,
            //   raw_expected_policy, claim)`. The control facts are the ones this
            // pass observed when it made the claim, so the publish step can prove the
            // authority it committed under is still the authority in force. The
            // policy is the exact raw value handed to `claim_expecting`, not a
            // re-serialization and not a merge.
            let mut pending: Vec<(
                String,
                ExecutionBinding,
                u64,
                Option<serde_json::Value>,
                GovernedClaim,
            )> = Vec::new();
            let mut has_enabled = false;

            for (id, entry) in catalog.entries() {
                let workspace = match entry {
                    PersistedCatalogEntry::Eligible(workspace) => workspace,
                    PersistedCatalogEntry::Unsupported(reason) => {
                        // An eligibility change is a catalog write and does not advance
                        // the control generation, so it is not a new authority: a
                        // latched scope that merely became ineligible here keeps its
                        // latch, or the blip would be a way to reach a claim at the
                        // old generation once the record becomes eligible again.
                        let latched_scope = WorkspaceControlScope::new(&tenancy.host, id);
                        if let Some(scope) = latched_scope.as_ref() {
                            let ineligible_scope_id = scope.as_str();
                            if let Some(existing) = latched.get(&ineligible_scope_id).copied() {
                                next_latched.insert(ineligible_scope_id, existing);
                                reports.push(awaiting_authority(id, existing.reason));
                                continue;
                            }
                        }
                        // No scope is ever minted for this record, so the report
                        // carries the persisted workspace id instead of a scope id.
                        reports.push(unsupported_report(id, unscoped_unsupported(*reason)));
                        continue;
                    }
                };
                // Outward label of this scope. It is the persisted workspace id,
                // never the internal scope key: `WorkspaceControlScope::as_str`
                // embeds the full storage-namespace anchor, and status rows, their
                // derived `Debug` and every log field are outward data.
                let label = workspace.id();
                let Some(scope) = WorkspaceControlScope::new(&tenancy.host, workspace.id()) else {
                    continue;
                };
                let scope_id = scope.as_str();
                let record = match self.control.read(&scope_id).await {
                    Ok(record) => record,
                    Err(error) => {
                        warn!(
                            "Workspace intelligence host could not read a control record: workspace={} code={}",
                            label,
                            control_error_code(&error)
                        );
                        // A transient read failure is not evidence that the authority
                        // changed, so an existing latch is carried across it: a read
                        // error must never be a way to re-open a latched scope.
                        if let Some(existing) = latched.get(scope_id.as_str()) {
                            next_latched.insert(scope_id.clone(), *existing);
                        }
                        reports.push(blocked(label, WorkspaceIntelligenceHostReason::ControlUnreadable));
                        // A control read can fail transiently, and an already-earned
                        // recovery timer must survive it. A pass that has never confirmed
                        // an enabled scope must not invent one from an unreadable record:
                        // with no ON evidence there is nothing to retry and no worker is
                        // created, exactly as a missing anchor starts no task. Note
                        // `has_enabled` here means a scope of THIS pass was really read as
                        // enabled, `latched`/`owned` only hold scopes that were once read
                        // as enabled, and `retry_earned` covers a worker, tenure or latch
                        // this host already holds from an earlier pass.
                        let proven_on = retry_earned
                            || has_enabled
                            || latched.contains_key(scope_id.as_str())
                            || owned.contains_key(scope_id.as_str());
                        if proven_on {
                            has_enabled = true;
                        }
                        continue;
                    }
                };
                let Some(record) = record else {
                    reports.push(disabled(label));
                    continue;
                };
                if record.enabled != Some(true) {
                    reports.push(disabled(label));
                    continue;
                }
                has_enabled = true;
                let observed = ExecutionBinding::observed(tenancy.host.host_id(), workspace);

                // The latch is consulted before ANY claim or tenure path: an existing
                // entry and a generation that did not strictly advance means this scope
                // must not claim, must not take a lease, must not commit and must not
                // publish, whatever the live facts now say. That is what makes a
                // revert of the live catalog, or a binding hand-patched into the same
                // generation, unable to re-open a scope that this host already
                // refused: only an explicit new authority can.
                if let Some(existing) = latched.get(scope_id.as_str()).copied() {
                    if record.control_generation <= existing.generation {
                        // Tenure is not carried over a latched block, exactly as it is
                        // not carried over a detected change.
                        owned.remove(scope_id.as_str());
                        next_latched.insert(scope_id.clone(), existing);
                        reports.push(awaiting_authority(label, existing.reason));
                        continue;
                    }
                }
                // A strictly newer generation is necessary but not sufficient: the
                // stored binding at that generation must also match the live facts,
                // which the classification below decides. Reaching a claim therefore
                // clears the latch by never re-inserting it.
                let latch_at_first_block = |reason: WorkspaceIntelligenceHostReason| {
                    // Never overwrite: the latch records the generation at which the
                    // block was FIRST observed, so an unrelated later read cannot
                    // raise the bar for this scope.
                    latched
                        .get(scope_id.as_str())
                        .copied()
                        .unwrap_or(BlockedScope {
                            generation: record.control_generation,
                            reason,
                        })
                };

                match host_binding::classify(record.policy.as_ref()) {
                    BindingState::Absent => {
                        next_latched.insert(
                            scope_id.clone(),
                            latch_at_first_block(WorkspaceIntelligenceHostReason::Unverified),
                        );
                        owned.remove(scope_id.as_str());
                        reports.push(awaiting_authority(
                            label,
                            WorkspaceIntelligenceHostReason::Unverified,
                        ));
                        continue;
                    }
                    BindingState::UnsupportedSchema { observed } => {
                        warn!(
                            "Workspace intelligence host refuses an unknown execution binding schema: workspace={} observed={}",
                            label, observed
                        );
                        next_latched.insert(
                            scope_id.clone(),
                            latch_at_first_block(
                                WorkspaceIntelligenceHostReason::BindingSchemaUnsupported,
                            ),
                        );
                        owned.remove(scope_id.as_str());
                        reports.push(awaiting_authority(
                            label,
                            WorkspaceIntelligenceHostReason::BindingSchemaUnsupported,
                        ));
                        continue;
                    }
                    BindingState::Malformed => {
                        next_latched.insert(
                            scope_id.clone(),
                            latch_at_first_block(
                                WorkspaceIntelligenceHostReason::BindingMalformed,
                            ),
                        );
                        owned.remove(scope_id.as_str());
                        reports.push(awaiting_authority(
                            label,
                            WorkspaceIntelligenceHostReason::BindingMalformed,
                        ));
                        continue;
                    }
                    BindingState::Present(stored) if !stored.matches(&observed) => {
                        // Tenure is not carried over a changed binding.
                        owned.remove(scope_id.as_str());
                        next_latched.insert(
                            scope_id.clone(),
                            latch_at_first_block(WorkspaceIntelligenceHostReason::BindingChanged),
                        );
                        reports.push(awaiting_authority(
                            label,
                            WorkspaceIntelligenceHostReason::BindingChanged,
                        ));
                        continue;
                    }
                    BindingState::Present(_) => {}
                }

                #[cfg(test)]
                if let Some(pause) = self.pause.as_ref() {
                    // Test-only: the control record has been read and nothing has
                    // been claimed yet.
                    pause.wait().await;
                }

                if let Some(claim) = owned.remove(scope_id.as_str()) {
                    // Already owned: verify tenure read-only instead of claiming a
                    // second time, which would only report standby against
                    // ourselves. This is also the read-only control-generation
                    // check that keeps a control change observable without a
                    // catalog event.
                    match claim.verify_expecting(claim.ticket(), record.policy.as_ref()).await {
                        Ok(ClaimVerification::Verified { .. }) => {
                            // The verification awaited, so the drain may have
                            // started while it ran. Tenure is not published after
                            // that point: an already-owned claim must obey the same
                            // drop rule as a fresh one, otherwise a `Draining` host
                            // would report an owned scope it had just re-published.
                            if self.shutdown_requested() {
                                drop(claim);
                                info!(
                                    "Workspace intelligence host dropped a verified claim because shutdown started: workspace={}",
                                    label
                                );
                                reports.push(blocked(
                                    label,
                                    WorkspaceIntelligenceHostReason::ClaimRefused,
                                ));
                            } else {
                                published.insert(scope_id.clone(), claim);
                                reports.push(active(label));
                            }
                        }
                        Ok(ClaimVerification::Refused(refusal)) => {
                            drop(claim);
                            reports.push(refusal_report(label, refusal));
                        }
                        Err(error) => {
                            drop(claim);
                            warn!(
                                "Workspace intelligence host tenure verification failed: workspace={} code={}",
                                label,
                                claim_error_code(&error)
                            );
                            reports.push(blocked(label, WorkspaceIntelligenceHostReason::ClaimFailed));
                        }
                    }
                    continue;
                }

                if self.shutdown_requested() {
                    // The drain contract: once draining, no NEW hand-off starts. A
                    // pass that only reaches its attempt now must not take a lease,
                    // commit an incarnation or open a cognition partition at all,
                    // which is what makes "no new claim while draining" true rather
                    // than merely "no published claim".
                    info!(
                        "Workspace intelligence host refused a new claim because shutdown started: workspace={}",
                        label
                    );
                    reports.push(blocked(label, WorkspaceIntelligenceHostReason::ClaimRefused));
                    continue;
                }

                // The exact raw `policy` of the record this claim is made under, and
                // the generation that carried it. Both are carried to the publish
                // step unchanged.
                let expected_policy = record.policy.clone();
                let observed_control_generation = record.control_generation;
                match GovernedClaim::claim_expecting(
                    self.control.clone(),
                    self.cognition_root.clone(),
                    self.lease_root.clone(),
                    &scope_id,
                    expected_policy.as_ref(),
                )
                .await
                {
                    Ok(ClaimAttempt::Claimed(claim)) => pending.push((
                        scope_id,
                        observed,
                        observed_control_generation,
                        expected_policy,
                        claim,
                    )),
                    Ok(ClaimAttempt::Standby) => reports.push(standby(label)),
                    Ok(ClaimAttempt::Refused(refusal)) => {
                        reports.push(refusal_report(label, refusal))
                    }
                    Err(error) => {
                        warn!(
                            "Workspace intelligence host could not attempt an owner claim: workspace={} code={}",
                            label,
                            claim_error_code(&error)
                        );
                        reports.push(blocked(label, WorkspaceIntelligenceHostReason::ClaimFailed));
                    }
                }
            }
            drop(owned);

            #[cfg(test)]
            if let Some(pause) = self.after_claim.as_ref() {
                if !pending.is_empty() {
                    // Test-only: a candidate claim of this pass has already committed
                    // and nothing has been published yet.
                    pause.wait().await;
                }
            }

            // Publish step. A claim is only handed off when shutdown has not
            // started AND the persisted registry still binds the same shape AND the
            // control authority it committed under is still in force. Once the drain
            // began the whole phase is skipped: there is no hand-off, so the
            // registry is not even re-read and every candidate claim is dropped (its
            // lease releases on drop) instead of being published.
            if !pending.is_empty() {
                if self.shutdown_requested() {
                    for (_, observed, _, _, claim) in pending {
                        drop(claim);
                        info!(
                            "Workspace intelligence host dropped a claim because shutdown started: workspace={}",
                            observed.workspace_id()
                        );
                        reports.push(blocked(
                            observed.workspace_id(),
                            WorkspaceIntelligenceHostReason::ClaimRefused,
                        ));
                    }
                } else {
                    let after = self.read_catalog().await;
                    for (
                        scope_id,
                        observed,
                        observed_control_generation,
                        expected_policy,
                        claim,
                    ) in pending
                    {
                        let catalog_outcome = match &after {
                            Err(error) => {
                                warn!(
                                    "Workspace intelligence host could not re-read the registry before publish: code={}",
                                    error.code()
                                );
                                Err(WorkspaceIntelligenceHostReason::CatalogUnreadable)
                            }
                            Ok(catalog) => match catalog.workspace(observed.workspace_id()) {
                                Some(workspace)
                                    if ExecutionBinding::observed(
                                        tenancy.host.host_id(),
                                        workspace,
                                    )
                                    .matches(&observed) =>
                                {
                                    Ok(())
                                }
                                _ => Err(WorkspaceIntelligenceHostReason::BindingChanged),
                            },
                        };
                        // The catalog decides the workspace fact and the control
                        // record decides the authority, so a claim committed under
                        // one authority is never published under another. Generation
                        // equality is what makes a close, a model change or a policy
                        // change after the commit observable: a model change leaves
                        // the raw policy equal, so only the generation can reveal it.
                        // The whole raw policy is compared, so unknown nested keys
                        // still participate exactly as stored. Verification is
                        // read-only and rollback-only, and it re-runs the
                        // same-transaction double-token check.
                        let control_outcome = match claim
                            .verify_expecting(claim.ticket(), expected_policy.as_ref())
                            .await
                        {
                            Ok(ClaimVerification::Verified { control_generation })
                                if control_generation == observed_control_generation =>
                            {
                                Ok(())
                            }
                            Ok(ClaimVerification::Verified { .. }) => {
                                Err(WorkspaceIntelligenceHostReason::AuthorityChanged)
                            }
                            Ok(ClaimVerification::Refused(refusal)) => {
                                Err(claim_refusal_reason(refusal))
                            }
                            Err(error) => {
                                warn!(
                                    "Workspace intelligence host could not verify the control authority before publish: workspace={} code={}",
                                    observed.workspace_id(),
                                    claim_error_code(&error)
                                );
                                Err(WorkspaceIntelligenceHostReason::ClaimFailed)
                            }
                        };
                        match (catalog_outcome, control_outcome) {
                            (Ok(()), Ok(())) => {
                                published.insert(scope_id, claim);
                                reports.push(active(observed.workspace_id()));
                            }
                            (Err(reason), _) | (_, Err(reason)) => {
                                // The claim is dropped, so its lease releases. No
                                // persisted record is rewritten or deleted and no
                                // cognition partition is removed: the host only
                                // stops claiming.
                                drop(claim);
                                reports.push(blocked(observed.workspace_id(), reason));
                            }
                        }
                    }
                }
            }

            #[cfg(test)]
            if let Some(book_pause) = self.before_book.as_ref() {
                // Test-only: every claim of this pass is committed and the book has
                // not been written yet, which is the exact window a drain can race.
                book_pause.wait().await;
            }

            // A pass that raced the drain start never publishes tenure. The decision
            // is taken INSIDE the book lock, because `shutdown()` sets the stop flag
            // and the `Draining` state while holding that same lock: an in-lock read
            // of both is consistent by construction, while a read outside it would
            // let this pass observe `false`, lose the lock race and then store a
            // non-empty `published`, which `settle()` could no longer fix because a
            // teardown state always wins. This governs a claim that was just
            // published by this pass, not only one that was already held. Every claim
            // cleared here is released, and no row may keep claiming `active`.
            reports.sort_by(|left, right| left.workspace_id.cmp(&right.workspace_id));
            let spawn_worker = {
                #[cfg(test)]
                if let Some(lock_pause) = self.at_book_lock.as_ref() {
                    // Test-only: nothing between here and the lock below, so a drain
                    // started now is invisible to any snapshot of the stop flag taken
                    // above this point.
                    lock_pause.wait().await;
                }
                let mut book = self.book.lock().await;
                let tearing_down = self.shutdown_requested()
                    || matches!(
                        book.state,
                        WorkspaceIntelligenceHostState::Draining
                            | WorkspaceIntelligenceHostState::Stopped
                    );
                if tearing_down {
                    published.clear();
                    demote_active_reports(&mut reports);
                }
                book.claims = published;
                book.scopes = reports;
                // The rebuilt latch replaces the previous one wholesale, so a scope
                // that left the catalog or went OFF is no longer latched.
                book.blocked_generation = next_latched;
                book.fatal = None;
                // The worker decision comes from the same in-lock read, so a drain
                // can never leave a fresh wake-up task behind for a host that is
                // already tearing down.
                let spawn_worker = !tearing_down && has_enabled && book.worker.is_none();
                book.settle();
                // Keep the fallback alive while ANY scope is enabled: an unverified
                // or binding-changed scope is still genuinely on, and a standby
                // scope needs the timer to notice an owner release. With no enabled
                // scope there is nothing to re-read, so no task exists at all.
                if !has_enabled && book.worker.take().is_some() {
                    info!("Workspace intelligence host stopped its standby worker: no enabled scope remains");
                }
                spawn_worker && book.worker.is_none()
            };
            if spawn_worker {
                let worker = self.spawn_worker();
                // The task is spawned outside the lock, so the slot is re-checked
                // under it: a drain that started in between must not be left with a
                // live wake-up task. Dropping the handle aborts it, so the fallback
                // never outlives the drain.
                let mut book = self.book.lock().await;
                if self.shutdown_requested() || book.worker.is_some() {
                    drop(book);
                    drop(worker);
                } else {
                    book.worker = Some(worker);
                }
            }
        }

        /// Starts the single bounded standby worker of this host.
        fn spawn_worker(self: &Arc<Self>) -> StandbyWorker {
            let weak = Arc::downgrade(self);
            info!(
                "Workspace intelligence host started its standby worker: base_ms={} cap_ms={}",
                self.timing.standby_base.as_millis(),
                self.timing.standby_cap.as_millis()
            );
            StandbyWorker::spawn(
                self.timing.standby_base,
                self.timing.standby_cap,
                self.catalog.revision(),
                self.stop.subscribe(),
                move || {
                    let weak = weak.clone();
                    async move {
                        if let Some(core) = weak.upgrade() {
                            core.evaluate().await;
                        }
                    }
                },
            )
        }

        async fn status(&self) -> WorkspaceIntelligenceHostStatus {
            let book = self.book.lock().await;
            WorkspaceIntelligenceHostStatus {
                state: book.state,
                reason: book.reason,
                counts: book.counts(),
                anchor_present: self.tenancy.is_some(),
                host_marker: self.tenancy.as_ref().map(|tenancy| tenancy.marker.clone()),
                scopes: book.scopes.clone(),
            }
        }

        async fn shutdown(&self) -> WorkspaceIntelligenceHostShutdown {
            let deadline = tokio::time::Instant::now() + self.timing.drain_budget;
            {
                let mut book = self.book.lock().await;
                if matches!(book.state, WorkspaceIntelligenceHostState::Stopped) {
                    return WorkspaceIntelligenceHostShutdown::new(
                        WorkspaceIntelligenceHostDrain::Drained,
                        book.state,
                    );
                }
                let _ = self.stop.send_replace(true);
                book.state = WorkspaceIntelligenceHostState::Draining;
                info!(
                    "Workspace intelligence host is draining: budget_ms={}",
                    self.timing.drain_budget.as_millis()
                );
            }

            // Stop the wake-up source first: no new pass may start.
            let worker = {
                let mut book = self.book.lock().await;
                book.worker.take()
            };
            if let Some(worker) = worker {
                let _ = tokio::time::timeout_at(deadline, worker.join()).await;
            }

            let drained = tokio::time::timeout_at(deadline, async {
                loop {
                    // The wake-up interest is created — and enabled — BEFORE the
                    // counter is read. A `Notified` future captures the
                    // `notify_waiters` epoch at creation and `notify_waiters` stores
                    // no permit, so a 1 -> 0 drop inside this window would be lost
                    // if the interest were created afterwards: the loop would then
                    // sit until the deadline and report a timeout with nothing
                    // outstanding.
                    let notified = self.idle.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();
                    if self.in_flight.load(Ordering::SeqCst) == 0 {
                        return;
                    }
                    #[cfg(test)]
                    if let Some(window) = self.drain_window.as_ref() {
                        // Test-only: in-flight work is dropped in this exact
                        // window, which is the only place a lost wake-up can hurt.
                        window.wait().await;
                    }
                    notified.await;
                }
            })
            .await
            .is_ok();
            let outstanding = self.in_flight.load(Ordering::SeqCst);

            let mut book = self.book.lock().await;
            if drained || outstanding == 0 {
                // Tenure handles are dropped here. This is not a rollback and is
                // not reported as one: the persisted control record, the cognition
                // partition and the owner's own writes are untouched.
                book.claims.clear();
                // No scope is owned any more, so the per-scope snapshot is cleared
                // instead of leaving stale `active` rows behind.
                book.scopes.clear();
                book.state = WorkspaceIntelligenceHostState::Stopped;
                info!("Workspace intelligence host stopped: drain=stopped");
                WorkspaceIntelligenceHostShutdown::new(
                    WorkspaceIntelligenceHostDrain::Drained,
                    book.state,
                )
            } else {
                book.settle_state_after_timeout();
                warn!(
                    "Workspace intelligence host stopped waiting for owner work: outstanding={}",
                    outstanding
                );
                WorkspaceIntelligenceHostShutdown::new(
                    WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding },
                    book.state,
                )
            }
        }
    }

    impl Book {
        /// After a timeout the host stays `Draining`. It is never promoted to
        /// `Stopped` and never claims that in-flight work ended.
        fn settle_state_after_timeout(&mut self) {
            self.state = WorkspaceIntelligenceHostState::Draining;
        }
    }

    fn active(workspace_id: &str) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Active,
            block: None,
        }
    }

    fn standby(workspace_id: &str) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Standby,
            block: None,
        }
    }

    fn disabled(workspace_id: &str) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Disabled,
            block: None,
        }
    }

    fn blocked(
        workspace_id: &str,
        reason: WorkspaceIntelligenceHostReason,
    ) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Blocked(reason),
            block: Some(WorkspaceIntelligenceHostBlock::Transient),
        }
    }

    /// A blocked row whose scope is latched: no later pass may claim it until an
    /// explicit new control authority advances the generation.
    fn awaiting_authority(
        workspace_id: &str,
        reason: WorkspaceIntelligenceHostReason,
    ) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Blocked(reason),
            block: Some(WorkspaceIntelligenceHostBlock::AwaitingNewAuthority),
        }
    }

    fn unsupported_report(
        workspace_id: &str,
        reason: WorkspaceIntelligenceHostUnsupportedScope,
    ) -> WorkspaceIntelligenceHostScopeReport {
        WorkspaceIntelligenceHostScopeReport {
            workspace_id: workspace_id.to_owned(),
            state: WorkspaceIntelligenceHostScopeState::Unsupported(reason),
            block: None,
        }
    }

    /// Removes every `active` row from a pass that raced the drain start.
    ///
    /// A draining host holds no published tenure, so a row that still claimed
    /// ownership would be the one place contradicting both the state and the
    /// counts. The row is reported as a refused hand-off instead. Its block phase
    /// is `Transient`: nothing is latched, because the next pass of a live host may
    /// publish again; this pass simply could not.
    fn demote_active_reports(reports: &mut [WorkspaceIntelligenceHostScopeReport]) {
        for report in reports.iter_mut() {
            if report.state == WorkspaceIntelligenceHostScopeState::Active {
                report.state = WorkspaceIntelligenceHostScopeState::Blocked(
                    WorkspaceIntelligenceHostReason::ClaimRefused,
                );
                report.block = Some(WorkspaceIntelligenceHostBlock::Transient);
            }
        }
    }

    /// Stable machine-readable code of a control-store failure.
    ///
    /// The `Display` form of the store error carries the record path, so no log may
    /// print it: the control root is private storage, not a diagnostic detail.
    fn control_error_code(error: &WorkspaceIntelligenceStoreError) -> &'static str {
        match error {
            WorkspaceIntelligenceStoreError::EmptyScope => "empty_scope",
            WorkspaceIntelligenceStoreError::CorruptRecord { .. } => "corrupt_record",
            WorkspaceIntelligenceStoreError::InvalidRecord { .. } => "invalid_record",
            WorkspaceIntelligenceStoreError::UnsupportedSchemaVersion { .. } => {
                "unsupported_schema_version"
            }
            WorkspaceIntelligenceStoreError::ControlGenerationConflict { .. } => {
                "control_generation_conflict"
            }
            WorkspaceIntelligenceStoreError::ControlGenerationOverflow { .. } => {
                "control_generation_overflow"
            }
            WorkspaceIntelligenceStoreError::BlankModelReference => "blank_model_reference",
            WorkspaceIntelligenceStoreError::Storage(_) => "storage",
            WorkspaceIntelligenceStoreError::Transaction(_) => "transaction",
        }
    }

    /// Stable machine-readable code of one owner-commit failure.
    fn commit_error_code(error: &WorkspaceIntelligenceCommitError) -> &'static str {
        match error {
            WorkspaceIntelligenceCommitError::Control(inner) => control_error_code(inner),
            WorkspaceIntelligenceCommitError::Cognition(inner) => inner.code(),
            WorkspaceIntelligenceCommitError::OwnerTask(_) => "owner_task",
        }
    }

    /// Stable machine-readable code of one owner-claim failure.
    ///
    /// Exhaustive with no wildcard: a new owner failure must be classified here,
    /// and nothing but a code may reach a log or a status payload.
    fn claim_error_code(error: &WorkspaceIntelligenceClaimError) -> &'static str {
        match error {
            WorkspaceIntelligenceClaimError::Lease(_) => "claim_lease",
            WorkspaceIntelligenceClaimError::Control(inner) => control_error_code(inner),
            WorkspaceIntelligenceClaimError::Fence(inner) => commit_error_code(inner),
            WorkspaceIntelligenceClaimError::UnexpectedFenceOutcome { .. } => {
                "claim_unexpected_fence_outcome"
            }
        }
    }

    fn unscoped_unsupported(
        reason: PersistedCatalogUnsupported,
    ) -> WorkspaceIntelligenceHostUnsupportedScope {
        match reason {
            PersistedCatalogUnsupported::RemoteScope => {
                WorkspaceIntelligenceHostUnsupportedScope::RemoteScope
            }
            PersistedCatalogUnsupported::AssistantWorkspace => {
                WorkspaceIntelligenceHostUnsupportedScope::AssistantWorkspace
            }
            PersistedCatalogUnsupported::LegacyWorktreeReference => {
                WorkspaceIntelligenceHostUnsupportedScope::LegacyWorktreeReference
            }
            PersistedCatalogUnsupported::UnresolvedWorktreeParent => {
                WorkspaceIntelligenceHostUnsupportedScope::UnresolvedWorktreeParent
            }
            PersistedCatalogUnsupported::NonUtf8Root => {
                WorkspaceIntelligenceHostUnsupportedScope::NonUtf8Root
            }
            PersistedCatalogUnsupported::MalformedRecord => {
                WorkspaceIntelligenceHostUnsupportedScope::MalformedRecord
            }
        }
    }

    /// Exhaustive mapping of an owner claim refusal. No wildcard arm: a new
    /// refusal variant must be classified here.
    fn claim_refusal_reason(refusal: GovernedClaimRefusal) -> WorkspaceIntelligenceHostReason {
        match refusal {
            GovernedClaimRefusal::AuthorityChanged => {
                WorkspaceIntelligenceHostReason::AuthorityChanged
            }
            GovernedClaimRefusal::NotEnabled => WorkspaceIntelligenceHostReason::ClaimRefused,
            GovernedClaimRefusal::NotObserved => WorkspaceIntelligenceHostReason::ClaimRefused,
            GovernedClaimRefusal::ForeignSnapshot => WorkspaceIntelligenceHostReason::ClaimRefused,
            GovernedClaimRefusal::ForeignBinding => WorkspaceIntelligenceHostReason::ClaimRefused,
            GovernedClaimRefusal::StaleIncarnation => WorkspaceIntelligenceHostReason::ClaimRefused,
        }
    }

    fn refusal_report(
        workspace_id: &str,
        refusal: GovernedClaimRefusal,
    ) -> WorkspaceIntelligenceHostScopeReport {
        match refusal {
            // A concurrently closed record is off, not blocked.
            GovernedClaimRefusal::NotEnabled | GovernedClaimRefusal::NotObserved => {
                disabled(workspace_id)
            }
            other => blocked(workspace_id, claim_refusal_reason(other)),
        }
    }

    /// Storage-namespace root the host anchor document lives in.
    ///
    /// [`PathManager::workspace_intelligence_dir`] is the single owner of this
    /// location: it is the shared parent of the control, cognition and lease roots
    /// and the directory the anchor document is written into, so this module neither
    /// infers the parent from a sibling root nor adds a subdirectory of its own. The
    /// resulting document is
    /// `user_data/workspace-intelligence/host-anchor.json`.
    ///
    /// There is no earlier location to migrate from: this feature has no production
    /// caller, so no build has ever written the document anywhere else and no
    /// compatibility path is needed.
    fn anchor_root(paths: &PathManager) -> PathBuf {
        paths.workspace_intelligence_dir()
    }

    /// Bounded existence probe of the control directory.
    ///
    /// At most one entry is taken, nothing is opened, parsed or inferred from a
    /// file name, and an unreadable directory fails closed as "not empty".
    fn control_directory_has_entries(paths: &PathManager) -> bool {
        let root = paths.workspace_intelligence_control_dir();
        match std::fs::read_dir(&root) {
            Ok(mut entries) => entries.next().is_some(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(_) => true,
        }
    }

    /// True when the metadata describes a directory entry that is itself a link.
    ///
    /// A Windows junction is a reparse point but not a symlink, so the attribute
    /// is checked too instead of trusting the file type alone.
    fn directory_entry_is_linked(metadata: &std::fs::Metadata) -> bool {
        if metadata.file_type().is_symlink() {
            return true;
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return true;
            }
        }
        false
    }

    /// A missing anchor only permits preflight if the namespace and control
    /// directories are observed absent or empty. Do not let a linked or
    /// unreadable directory masquerade as absent. Every entry is probed, so an
    /// absent namespace never skips the control check. This stricter probe is
    /// not used by startup.
    async fn control_directory_is_vacant(paths: &PathManager) -> bool {
        let control = paths.workspace_intelligence_control_dir();
        for path in [anchor_root(paths), control.clone()] {
            let metadata = match tokio::fs::symlink_metadata(&path).await {
                Ok(metadata) => metadata,
                // An absent entry is vacant; the remaining entry is still probed.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return false,
            };
            if !metadata.is_dir() || directory_entry_is_linked(&metadata) {
                return false;
            }
        }
        // An absent control directory is vacant; an unreadable one is not.
        match tokio::fs::read_dir(&control).await {
            Ok(mut entries) => matches!(entries.next_entry().await, Ok(None)),
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
    }

    /// Redacted marker of the storage-namespace anchor: a prefix marker only.
    fn redacted_marker(host_id: &str) -> String {
        let suffix = host_id.strip_prefix(HOST_ID_PREFIX).unwrap_or(host_id);
        let prefix: String = suffix.chars().take(4).collect();
        format!("{HOST_ID_PREFIX}{prefix}...")
    }

    fn anchor_error_code(error: &HostAnchorError) -> &'static str {
        error.code()
    }

    /// Internal bootstrap options. The public
    /// [`WorkspaceIntelligenceHost::bootstrap`] never needs this type.
    #[derive(Debug, Clone, Copy, Default)]
    pub(crate) struct WorkspaceIntelligenceHostOptions {
        timing: Option<HostTiming>,
    }

    impl WorkspaceIntelligenceHostOptions {
        // Fixtures compress the schedule; production takes `default()`.
        #[cfg(test)]
        pub(crate) fn with_timing(timing: HostTiming) -> Self {
            Self {
                timing: Some(timing),
            }
        }
    }

    /// One workspace intelligence host handle.
    ///
    /// It exposes bootstrap, `status()` and `shutdown()` only. Tenure handles,
    /// tickets, tokens, lease paths, control roots and the raw anchor value stay
    /// private.
    #[derive(Clone)]
    pub struct WorkspaceIntelligenceHost {
        core: Arc<HostCore>,
    }

    impl WorkspaceIntelligenceHost {
        /// Bootstraps the host of one delivery surface.
        ///
        /// This is the only constructor of a build that compiles the host feature; a
        /// build without it has no anchor or registry reader and reports
        /// `NotCompiled` through `not_compiled()` instead. A composition root chooses
        /// between the two with the same feature `cfg` it already uses, and neither
        /// path accepts a host id or an anchor value from the caller: the anchor is
        /// always read from `paths`, the caller's own user-data root.
        ///
        /// `paths` owns the user-data root this host anchors on and whose persisted
        /// registry it enumerates: it is the only way the host learns where to read,
        /// so a composition cannot point two authorities at two roots.
        /// `catalog_revision` is the optional wake-up hint of the workspace owner's
        /// own catalog revision; `None` is fully supported and only changes how
        /// quickly the next pass starts. The hint is a hint only: another host
        /// process can rewrite the registry with no local event, so the coarse
        /// fallback timer is what makes the pass happen at all.
        pub async fn bootstrap(
            paths: Arc<PathManager>,
            catalog_revision: Option<watch::Receiver<u64>>,
            surface: WorkspaceIntelligenceHostSurface,
            deployment: RuntimeDeployment,
        ) -> Self {
            Self::bootstrap_with_options(
                paths,
                WorkspaceCatalogSource::from_hint(catalog_revision),
                surface,
                deployment,
                WorkspaceIntelligenceHostOptions::default(),
            )
            .await
        }

        /// Bootstrap with explicit internal timings.
        pub(crate) async fn bootstrap_with_options(
            paths: Arc<PathManager>,
            catalog: WorkspaceCatalogSource,
            surface: WorkspaceIntelligenceHostSurface,
            deployment: RuntimeDeployment,
            options: WorkspaceIntelligenceHostOptions,
        ) -> Self {
            let timing = options.timing.unwrap_or_default();
            if let Err(profile) = profile_support(surface, deployment) {
                // Zero footprint: no anchor read, no catalog read, no task.
                let core = Arc::new(HostCore::new(paths, catalog, timing, None));
                core.mark(
                    WorkspaceIntelligenceHostState::Unavailable,
                    WorkspaceIntelligenceHostReason::ProfileUnsupported(profile),
                )
                .await;
                info!(
                    "Workspace intelligence host is unavailable on this delivery profile: reason={}",
                    profile.code()
                );
                return Self { core };
            }

            let anchor = HostAnchorStore::new(anchor_root(&paths)).read_strict().await;
            let host_id = match anchor {
                Ok(HostAnchorState::Present(anchor)) => anchor.host_id().to_owned(),
                Ok(HostAnchorState::Absent) => {
                    let core = Arc::new(HostCore::new(paths, catalog, timing, None));
                    let reason = if control_directory_has_entries(&core.paths) {
                        WorkspaceIntelligenceHostReason::AnchorMissingWithRecords
                    } else {
                        WorkspaceIntelligenceHostReason::NoRecords
                    };
                    let state = if reason == WorkspaceIntelligenceHostReason::NoRecords {
                        WorkspaceIntelligenceHostState::Inactive
                    } else {
                        WorkspaceIntelligenceHostState::Unavailable
                    };
                    if state == WorkspaceIntelligenceHostState::Unavailable {
                        warn!(
                            "Workspace intelligence host has control records but no storage anchor: reason={}",
                            reason.code()
                        );
                    } else {
                        info!(
                            "Workspace intelligence host is inactive: reason={}",
                            reason.code()
                        );
                    }
                    core.mark(state, reason).await;
                    return Self { core };
                }
                Err(error) => {
                    let core = Arc::new(HostCore::new(paths, catalog, timing, None));
                    warn!(
                        "Workspace intelligence host could not read the storage anchor: code={}",
                        anchor_error_code(&error)
                    );
                    core.mark(
                        WorkspaceIntelligenceHostState::Unavailable,
                        WorkspaceIntelligenceHostReason::AnchorUnreadable,
                    )
                    .await;
                    return Self { core };
                }
            };
            let host = HostExecutionDomainKey::new(&host_id, LOCAL_EXECUTION_DOMAIN)
                .expect("a validated anchor id is never blank");
            let tenancy = Tenancy {
                marker: redacted_marker(&host_id),
                host,
            };
            let core = Arc::new(HostCore::new(paths, catalog, timing, Some(tenancy)));
            #[cfg(test)]
            if super::pauses::first_pass_is_deferred(&core.paths) {
                // Test-only: the fixture drives the first pass itself, so it can park
                // that pass in its publish window while already holding the handle.
                return Self { core };
            }
            core.evaluate().await;
            Self { core }
        }

        /// Preflight for the sole confirmed initial-enable preparation owner.
        /// This does not mint, adopt, reserve or authorize anything. Preparation
        /// must revalidate the live facts and stop state at its own commit gate.
        #[allow(dead_code, reason = "the confirmed enable preparation owner is not wired yet")]
        pub(super) async fn initial_enable_admission(
            &self,
            workspace_id: &str,
        ) -> Result<InitialEnableAdmission, InitialEnableRefusal> {
            self.core.check_initial_enable_gate().await?;
            let observed = self.core.observe_initial_enable(workspace_id).await;
            #[cfg(test)]
            if let Some(pause) = super::pauses::for_user_root_of(
                &self.core.paths,
                super::pauses::PausePoint::AfterInitialEnableObservation,
            ) {
                pause.wait().await;
            }
            self.core.check_initial_enable_gate().await?;
            observed
        }

        /// Current typed status.
        pub async fn status(&self) -> WorkspaceIntelligenceHostStatus {
            self.core.status().await
        }

        /// Stops the host and reports the drain result.
        pub async fn shutdown(&self) -> WorkspaceIntelligenceHostShutdown {
            self.core.shutdown().await
        }
    }

    /// Test-only pause the `pauses` registry can install at a named point.
    ///
    /// It fires once: the first `wait()` blocks until the fixture releases it, and
    /// every later call returns immediately.
    #[cfg(test)]
    #[derive(Clone)]
    pub(crate) struct HostPause {
        entered: tokio::sync::mpsc::UnboundedSender<()>,
        gate: Arc<tokio::sync::Semaphore>,
        armed: Arc<std::sync::atomic::AtomicBool>,
    }

    #[cfg(test)]
    impl HostPause {
        pub(crate) fn new() -> (Self, tokio::sync::mpsc::UnboundedReceiver<()>) {
            let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
            (
                Self {
                    entered,
                    gate: Arc::new(tokio::sync::Semaphore::new(0)),
                    armed: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                },
                receiver,
            )
        }

        pub(crate) fn release(&self) {
            self.gate.add_permits(1);
        }

        async fn wait(&self) {
            if !self
                .armed
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return;
            }
            let _ = self.entered.send(());
            let _ = self.gate.acquire().await;
        }
    }

    #[cfg(test)]
    impl WorkspaceIntelligenceHost {
        /// Anchor root the production bootstrap uses, so fixtures cannot drift.
        pub(crate) fn anchor_root_for_tests(paths: &PathManager) -> PathBuf {
            anchor_root(paths)
        }

        /// In-flight evaluation passes, so a fixture can synchronize on a blocked
        /// owner instead of sleeping.
        pub(crate) async fn in_flight_for_tests(&self) -> usize {
            self.core.in_flight.load(Ordering::SeqCst)
        }

        /// True while the bounded standby worker exists.
        pub(crate) async fn has_standby_worker_for_tests(&self) -> bool {
            self.core.book.lock().await.worker.is_some()
        }

        /// One explicit evaluation pass, for fixtures that must not wait for the
        /// coarse fallback.
        pub(crate) async fn evaluate_for_tests(&self) {
            self.core.evaluate().await;
        }
    }

    #[cfg(test)]
    mod timing_defaults {
        use super::HostTiming;
        use std::time::Duration;

        /// The production timing literal set, kept where the private fields can be
        /// read so a silent retune of the real schedule fails a test.
        #[test]
        fn the_production_timing_defaults_are_the_reviewed_literals() {
            let timing = HostTiming::default();
            assert_eq!(timing.standby_base, Duration::from_millis(250));
            assert_eq!(timing.standby_cap, Duration::from_secs(30));
            assert_eq!(timing.drain_budget, Duration::from_secs(12));
        }
    }
}

// Exactly one host handle per build: the feature decides which body it has.
// Both names are the same type as far as a caller is concerned, so the public
// surface does not change shape with the feature.
#[cfg(not(feature = "workspace-intelligence-host"))]
pub use not_compiled::WorkspaceIntelligenceHost;
#[cfg(feature = "workspace-intelligence-host")]
pub use compiled::WorkspaceIntelligenceHost;

#[allow(unused_imports)]
#[cfg(all(test, feature = "workspace-intelligence-host"))]
pub(crate) use compiled::HostPause;

/// Test-only pause registry keyed by user root and pause point.
///
/// The pause must be installed before the first bootstrap pass runs, so it cannot
/// be a field a caller sets afterwards.
#[cfg(all(test, feature = "workspace-intelligence-host"))]
mod pauses {
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;

    use super::HostPause;

    /// Where a fixture may park a host.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum PausePoint {
        /// After the control record was read and before any claim attempt.
        BeforeClaim,
        /// After the owner claim of a pass committed and strictly before the pass
        /// publishes tenure. The claim's lease is held and its incarnation advance
        /// is committed here, so a rewrite that lands now is the
        /// commit-versus-publish window.
        AfterClaim,
        /// After the whole publish phase of a pass and strictly before the pass takes
        /// the book lock. The pass has already decided which claims it wants to keep,
        /// so a drain that starts here is the last window in which a stale decision
        /// could be written into the book.
        BeforeBook,
        /// The last point at which a drain can start before the pass reads the stop
        /// flag under the book lock. Placed immediately before that lock, so any
        /// pre-lock snapshot of the flag is older than a drain started here.
        AtBookLock,
        /// After initial-enable reads, before checking the owner gate again.
        AfterInitialEnableObservation,
        /// In the drain loop, between the in-flight check and the wait.
        DrainWait,
    }

    static PAUSES: Mutex<Vec<(PathBuf, PausePoint, HostPause)>> = Mutex::new(Vec::new());

    /// Removes the registration when dropped, so fixtures do not leak into each
    /// other.
    pub(super) struct Registration(PathBuf, PausePoint);

    impl Drop for Registration {
        fn drop(&mut self) {
            PAUSES
                .lock()
                .expect("pause registry lock")
                .retain(|(root, point, _)| !(root == &self.0 && *point == self.1));
        }
    }

    pub(super) fn register(
        user_root: &Path,
        point: PausePoint,
        pause: HostPause,
    ) -> Registration {
        PAUSES
            .lock()
            .expect("pause registry lock")
            .push((user_root.to_path_buf(), point, pause));
        Registration(user_root.to_path_buf(), point)
    }

    static DEFERRED_FIRST_PASS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

    /// Removes the deferral when dropped, so fixtures do not leak into each other.
    pub(super) struct FirstPassDeferral(PathBuf);

    impl Drop for FirstPassDeferral {
        fn drop(&mut self) {
            DEFERRED_FIRST_PASS
                .lock()
                .expect("pause registry lock")
                .retain(|root| root != &self.0);
        }
    }

    /// Leaves the bootstrap's first evaluation pass to the fixture.
    ///
    /// A pass that must be parked in its publish window while the fixture holds the
    /// host handle cannot be the bootstrap pass: the handle only exists once
    /// bootstrap returned. Deferring that pass is what makes the interleaving
    /// reachable without a second constructor or a production seam.
    pub(super) fn defer_first_pass(user_root: &Path) -> FirstPassDeferral {
        DEFERRED_FIRST_PASS
            .lock()
            .expect("pause registry lock")
            .push(user_root.to_path_buf());
        FirstPassDeferral(user_root.to_path_buf())
    }

    #[cfg(feature = "workspace-intelligence-host")]
    pub(super) fn first_pass_is_deferred(paths: &crate::infrastructure::PathManager) -> bool {
        DEFERRED_FIRST_PASS
            .lock()
            .expect("pause registry lock")
            .iter()
            .any(|root| root == paths.user_root_dir())
    }

    fn pause_for(user_root: &Path, point: PausePoint) -> Option<HostPause> {
        PAUSES
            .lock()
            .expect("pause registry lock")
            .iter()
            .find(|(root, candidate, _)| root == user_root && *candidate == point)
            .map(|(_, _, pause)| pause.clone())
    }

    #[cfg(feature = "workspace-intelligence-host")]
    pub(super) fn for_user_root_of(
        paths: &crate::infrastructure::PathManager,
        point: PausePoint,
    ) -> Option<HostPause> {
        pause_for(paths.user_root_dir(), point)
    }
}

/// Feature-off answer. A build without the host feature must still answer with a
/// typed `NotCompiled` state, without IO and without a task.
#[cfg(all(test, not(feature = "workspace-intelligence-host")))]
mod feature_off_tests {
    use super::not_compiled::WorkspaceIntelligenceHost;
    use super::*;
    use crate::infrastructure::PathManager;
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;

    /// Recursive content hash of one directory tree, so "no byte changed" is a
    /// property of the whole user root rather than of one known file.
    fn tree_hash(root: &Path) -> String {
        fn walk(root: &Path, dir: &Path, hasher: &mut Sha256) {
            let mut entries: Vec<_> = match std::fs::read_dir(dir) {
                Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
                Err(_) => return,
            };
            entries.sort();
            for path in entries {
                hasher.update(path.strip_prefix(root).unwrap().to_string_lossy().as_bytes());
                if path.is_dir() {
                    hasher.update(b"dir");
                    walk(root, &path, hasher);
                } else {
                    hasher.update(b"file");
                    if let Ok(bytes) = std::fs::read(&path) {
                        hasher.update(&bytes);
                    }
                }
            }
        }
        let mut hasher = Sha256::new();
        walk(root, root, &mut hasher);
        format!("{:x}", hasher.finalize())
    }

    #[tokio::test]
    async fn a_build_without_the_host_feature_answers_not_compiled() {
        // A real user root, so "no IO" is measurable: the handle is built from
        // nothing and must leave this tree byte-identical.
        let fixture = tempfile::tempdir().unwrap();
        let paths = Arc::new(PathManager::with_user_root_for_tests(fixture.path().join("user")));
        std::fs::create_dir_all(paths.user_data_dir()).unwrap();
        std::fs::write(paths.user_data_dir().join("keep.txt"), b"keep").unwrap();
        let before = tree_hash(fixture.path());
        let roots: Vec<PathBuf> = vec![
            paths.workspace_intelligence_control_dir(),
            paths.workspace_intelligence_cognition_dir(),
            paths.workspace_intelligence_lease_dir(),
        ];

        let host = WorkspaceIntelligenceHost::not_compiled();
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::NotCompiled);
        assert_eq!(status.reason(), Some(WorkspaceIntelligenceHostReason::NotCompiled));
        assert_eq!(status.counts(), WorkspaceIntelligenceHostCounts::default());
        assert!(!status.anchor_present());
        assert_eq!(status.host_marker(), None);
        assert!(status.scopes().is_empty());
        let shutdown = host.shutdown().await;
        assert_eq!(shutdown.drain(), WorkspaceIntelligenceHostDrain::Drained);
        assert_eq!(shutdown.state(), WorkspaceIntelligenceHostState::NotCompiled);

        assert_eq!(tree_hash(fixture.path()), before, "the user root must be untouched");
        for root in roots {
            assert!(!root.exists(), "a feature-off handle creates no root: {}", root.display());
        }
    }
}

#[cfg(all(test, feature = "workspace-intelligence-host"))]
mod tests {
    use super::compiled::{
        profile_support, HostTiming, WorkspaceCatalogSource, WorkspaceIntelligenceHost,
        WorkspaceIntelligenceHostOptions,
    };
    use super::{
        HostPause, WorkspaceIntelligenceHostBlock, WorkspaceIntelligenceHostDrain,
        WorkspaceIntelligenceHostReason, WorkspaceIntelligenceHostScopeState,
        WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostSurface,
        WorkspaceIntelligenceHostUnsupportedProfile,
        WorkspaceIntelligenceHostUnsupportedScope,
    };
    use crate::infrastructure::PathManager;
    use crate::service::workspace_intelligence::catalog_readonly;
    use crate::service::workspace_intelligence::host_binding::{
        classify, BindingState, ExecutionBinding, EXECUTION_BINDING_SCHEMA_VERSION,
        LOCAL_EXECUTION_DOMAIN,
    };
    use crate::service::workspace_intelligence::scope::{
        HostExecutionDomainKey, WorkspaceControlScope,
    };
    use openbitfun_core_types::product_identity::product_id;
    use openbitfun_services_core::json_store::JsonFileStore;
    use openbitfun_services_core::persistence::{PersistenceService, StorageOptions};
    use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
    use openbitfun_services_core::workspace_intelligence_cognition::WorkspaceIntelligenceCognitionStore;
    use openbitfun_services_core::workspace_intelligence_commit::{
        GovernedClaimRefusal, GovernedCommitOutcome, GovernedCommitRefusal,
    };
    use openbitfun_services_core::workspace_intelligence_host_anchor::{
        HostAnchorEnsure, HostAnchorStore, HOST_ANCHOR_FILE_NAME, HOST_ID_PREFIX,
    };
    use openbitfun_services_core::workspace_intelligence_store::{
        ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
        WorkspaceIntelligenceStore,
    };
    use openbitfun_services_core::workspace_persistence::{
        WorkspacePersistenceData, WORKSPACE_PERSISTENCE_FORMAT_VERSION,
    };
    use openbitfun_services_core::workspace_records::WorkspaceInfo;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::time::Duration;

    const DEADLINE: Duration = Duration::from_secs(30);
    const SETTLE: Duration = Duration::from_millis(300);

    /// Fast standby timing: a fixture must never wait for the 250 ms default.
    fn fast() -> HostTiming {
        HostTiming::new(Duration::from_millis(5), Duration::from_millis(20), Duration::from_secs(2))
    }

    /// Standby timing that never ticks, for fixtures that drive passes explicitly.
    fn sleeping() -> HostTiming {
        HostTiming::new(Duration::from_secs(3600), Duration::from_secs(3600), Duration::from_secs(2))
    }

    fn options(timing: HostTiming) -> WorkspaceIntelligenceHostOptions {
        WorkspaceIntelligenceHostOptions::with_timing(timing)
    }

    /// The composition source a fixture hands over: no hint, so only the coarse
    /// fallback wakes the host. `WorkspaceCatalogSource` carries nothing else.
    fn source() -> WorkspaceCatalogSource {
        WorkspaceCatalogSource::without_hint()
    }

    /// The anchor payload without its prefix: the string that must never reach
    /// status data or a log line.
    fn anchor_suffix(host_id: &str) -> &str {
        host_id.strip_prefix(HOST_ID_PREFIX).unwrap_or(host_id)
    }

    /// One isolated user root plus the persisted-registry writer over it.
    ///
    /// The fixture writes the registry through the same persistence owner the
    /// workspace service uses (`workspace_data` under the user-data root), so the
    /// bytes the host reads are the production shape. It holds no workspace
    /// runtime on purpose: the host feature must not compile one, and neither does
    /// its test fixture.
    struct Fixture {
        dir: tempfile::TempDir,
        paths: Arc<PathManager>,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Arc::new(PathManager::with_user_root_for_tests(dir.path().join("user")));
            Self { dir, paths }
        }

        fn control_dir(&self) -> PathBuf {
            self.paths.workspace_intelligence_control_dir()
        }

        fn lease_dir(&self) -> PathBuf {
            self.paths.workspace_intelligence_lease_dir()
        }

        fn cognition_dir(&self) -> PathBuf {
            self.paths.workspace_intelligence_cognition_dir()
        }

        /// The registry file the reader and the owner both address.
        fn registry_path(&self) -> PathBuf {
            catalog_readonly::catalog_path(&self.paths)
        }

        fn control(&self) -> WorkspaceIntelligenceStore {
            WorkspaceIntelligenceStore::new(self.control_dir(), vec![1])
        }

        fn scope(&self, host_id: &str, workspace_id: &str) -> String {
            let host = HostExecutionDomainKey::new(host_id, LOCAL_EXECUTION_DOMAIN).unwrap();
            WorkspaceControlScope::new(&host, workspace_id).unwrap().as_str()
        }

        /// Publishes the registry through the persistence owner under the same key
        /// the workspace service writes, so the fixture cannot drift from the
        /// persisted shape the host reads.
        async fn publish(&self, records: Vec<Value>) {
            save_registry(&self.paths, records).await;
        }

        /// Mints the storage-namespace anchor once and returns its host id.
        async fn anchor(&self) -> String {
            let store = HostAnchorStore::new(WorkspaceIntelligenceHost::anchor_root_for_tests(
                &self.paths,
            ));
            match store.ensure().await.unwrap() {
                HostAnchorEnsure::Created(anchor) | HostAnchorEnsure::Existing(anchor) => {
                    anchor.host_id().to_owned()
                }
            }
        }

        fn anchor_bytes(&self) -> Vec<u8> {
            std::fs::read(
                WorkspaceIntelligenceHost::anchor_root_for_tests(&self.paths)
                    .join(HOST_ANCHOR_FILE_NAME),
            )
            .unwrap()
        }

        /// Observed binding the host should compare against.
        async fn binding(&self, host_id: &str, workspace_id: &str) -> ExecutionBinding {
            let catalog = catalog_readonly::read_persisted_catalog(&self.paths)
                .await
                .unwrap();
            ExecutionBinding::observed(host_id, catalog.workspace(workspace_id).unwrap())
        }

        fn bound_policy(binding: &ExecutionBinding) -> Value {
            json!({
                "execution_binding": {
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
                },
                "domains": {"memory": {"enabled": true}},
            })
        }

        /// The complete local-shaped binding fence for one arbitrary workspace id
        /// and root.
        ///
        /// [`Fixture::bound_policy`] serializes the binding this host OBSERVES, which
        /// only exists for an eligible record. A record this host classifies as
        /// unsupported never reaches an observation, so a fixture that wants to show
        /// "even a well-formed ON record is refused" has to state the fence the host
        /// would demand of a local record at that id and root: schema version, the
        /// host/domain/id/root identity and all five worktree fields.
        fn local_shaped_policy(host_id: &str, workspace_id: &str, workspace_root: &str) -> Value {
            json!({
                "execution_binding": {
                    "schema_version": EXECUTION_BINDING_SCHEMA_VERSION,
                    "host_id": host_id,
                    "execution_domain": LOCAL_EXECUTION_DOMAIN,
                    "workspace_id": workspace_id,
                    "workspace_root": workspace_root,
                    "workspace_kind": "local_workspace",
                    "is_worktree_child": false,
                    "worktree_parent_id": Value::Null,
                    "worktree_is_main": Value::Null,
                    "main_repo_path": Value::Null,
                },
                "domains": {"memory": {"enabled": true}},
            })
        }

        /// Hand-patches the persisted `policy` of the single control record while
        /// leaving `control_generation` exactly as stored.
        ///
        /// This models a writer that mutates the document behind the store's CAS,
        /// which the store itself never does. It is the only way to build the
        /// same-generation shape the latch has to refuse, and it deliberately
        /// bypasses the owner so the test cannot pass by having the owner renumber.
        fn patch_policy_same_generation(&self, policy: Value) {
            let path = {
                let mut files: Vec<PathBuf> = std::fs::read_dir(self.control_dir())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                    .collect();
                files.sort();
                assert_eq!(files.len(), 1, "exactly one control record");
                files.pop().unwrap()
            };
            let text = std::fs::read_to_string(&path).unwrap();
            let mut document: Value = serde_json::from_str(&text).unwrap();
            let generation = document["control_generation"].clone();
            document["policy"] = policy;
            assert_eq!(
                document["control_generation"], generation,
                "the hand patch must not touch the generation"
            );
            std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
        }

        async fn seed_control(&self, scope: &str, enabled: bool, policy: Option<Value>) {
            self.control()
                .update(
                    scope,
                    ControlGenerationExpectation::Absent,
                    WorkspaceIntelligenceControlPatch {
                        enabled: ControlFieldUpdate::Set(enabled),
                        policy: policy
                            .map(ControlFieldUpdate::Set)
                            .unwrap_or(ControlFieldUpdate::Keep),
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }

        fn control_bytes(&self) -> Vec<u8> {
            let mut files: Vec<PathBuf> = std::fs::read_dir(self.control_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                .collect();
            files.sort();
            assert_eq!(files.len(), 1, "exactly one control record");
            std::fs::read(&files[0]).unwrap()
        }

        /// Bytes of every persisted control record, keyed by file name.
        ///
        /// A fixture that seeds one record per scope needs the whole set: "no pass
        /// rewrote a control record" is then a property of all of them, not of one
        /// hand-picked file.
        fn control_records(&self) -> Vec<(PathBuf, Vec<u8>)> {
            let mut files: Vec<PathBuf> = std::fs::read_dir(self.control_dir())
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                .collect();
            files.sort();
            files
                .into_iter()
                .map(|path| {
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect()
        }

        fn token(&self, scope: &str) -> Option<String> {
            WorkspaceIntelligenceCognitionStore::new(self.cognition_dir())
                .read(scope)
                .unwrap()
                .and_then(|state| state.incarnation_token)
        }

        /// Overwrites the single persisted control record with the given bytes and
        /// returns them.
        ///
        /// This is the only way a fixture can make the authoritative owner's own read
        /// fail on real storage: the bytes are written in place, so the record still
        /// exists and is still the only `.json` under the control root. Every
        /// intermediate state of a truncated JSON document is a decode error, so an
        /// in-place write can never be mistaken for a missing record. The same helper
        /// restores the saved bytes afterwards.
        fn overwrite_control_record(&self, bytes: &[u8]) -> Vec<u8> {
            let path = {
                let mut files: Vec<PathBuf> = std::fs::read_dir(self.control_dir())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
                    .collect();
                files.sort();
                assert_eq!(files.len(), 1, "exactly one control record");
                files.pop().unwrap()
            };
            std::fs::write(&path, bytes).unwrap();
            bytes.to_vec()
        }

        /// Every `.lock` under the single lease root. Owner tenure is the only thing
        /// this host may create there, so an empty result is the zero-tenure claim.
        /// Fixture-side control and anchor writes hold their own JSON guards and are
        /// deliberately not counted here.
        fn lock_files(&self) -> Vec<PathBuf> {
            fn walk(root: &Path, found: &mut Vec<PathBuf>) {
                let Ok(entries) = std::fs::read_dir(root) else {
                    return;
                };
                for entry in entries {
                    let path = entry.unwrap().path();
                    if path.is_dir() {
                        walk(&path, found);
                    } else if path.extension().and_then(|value| value.to_str()) == Some("lock") {
                        found.push(path);
                    }
                }
            }
            let mut found = Vec::new();
            walk(&self.lease_dir(), &mut found);
            found.sort();
            found
        }

        /// True when the lease root exists at all.
        fn lease_root_exists(&self) -> bool {
            self.lease_dir().exists()
        }

        fn sqlite_files(&self) -> Vec<PathBuf> {
            let mut files: Vec<PathBuf> = match std::fs::read_dir(self.cognition_dir()) {
                Ok(entries) => entries
                    .map(|entry| entry.unwrap().path())
                    .filter(|path| path.extension().and_then(|v| v.to_str()) == Some("sqlite"))
                    .collect(),
                Err(_) => Vec::new(),
            };
            files.sort();
            files
        }

        /// The control generation currently stored for this scope.
        async fn control_generation(&self, scope: &str) -> u64 {
            self.control()
                .read(scope)
                .await
                .unwrap()
                .expect("the scope has a control record")
                .control_generation
        }

        /// True while some holder still owns the scope's exclusive owner lease.
        ///
        /// `ExclusiveFileLease` keeps an in-process registry next to the OS lock, so
        /// a second acquire answers `InUse` for the same process as well as for
        /// another one. This is therefore the fixture-side proof that a dropped claim
        /// released its tenure, and it writes nothing.
        fn lease_is_held(&self, scope: &str) -> bool {
            let mut hasher = Sha256::new();
            hasher.update(scope.as_bytes());
            let lease_path = self.lease_dir().join(format!("{:x}.lock", hasher.finalize()));
            match openbitfun_services_core::exclusive_file_lease::ExclusiveFileLease::try_acquire(
                &lease_path,
            ) {
                Ok(lease) => {
                    drop(lease);
                    false
                }
                Err(openbitfun_services_core::exclusive_file_lease::ExclusiveFileLeaseError::InUse) => true,
                Err(error) => panic!("unexpected lease probe error: {error:?}"),
            }
        }

        /// Bytes of every cognition partition, so a refused publish can be shown to
        /// have written nothing into the owner's own database.
        fn sqlite_bytes(&self) -> Vec<(PathBuf, Vec<u8>)> {
            self.sqlite_files()
                .into_iter()
                .map(|path| {
                    let bytes = std::fs::read(&path).unwrap();
                    (path, bytes)
                })
                .collect()
        }

        fn tree_hash(&self) -> String {
            fn walk(root: &Path, dir: &Path, hasher: &mut Sha256) {
                let mut entries: Vec<_> = match std::fs::read_dir(dir) {
                    Ok(entries) => entries.map(|entry| entry.unwrap().path()).collect(),
                    Err(_) => return,
                };
                entries.sort();
                for path in entries {
                    hasher.update(path.strip_prefix(root).unwrap().to_string_lossy().as_bytes());
                    if path.is_dir() {
                        hasher.update(b"dir");
                        walk(root, &path, hasher);
                    } else {
                        hasher.update(b"file");
                        if let Ok(bytes) = std::fs::read(&path) {
                            hasher.update(&bytes);
                        }
                    }
                }
            }
            let mut hasher = Sha256::new();
            walk(self.dir.path(), self.dir.path(), &mut hasher);
            format!("{:x}", hasher.finalize())
        }
    }

    /// Writes the persisted workspace registry through the persistence owner.
    ///
    /// Shared by the in-process fixtures and by the cross-process child, so a
    /// rewrite from another process goes through exactly the owner path the
    /// workspace service uses: the same `workspace_data` key, the same product
    /// identity and typed [`WorkspaceInfo`] records. Nothing here hand-writes or
    /// hand-parses the registry document.
    async fn save_registry(paths: &PathManager, records: Vec<Value>) {
        let mut workspaces = std::collections::HashMap::new();
        let mut ids = Vec::new();
        for record in records {
            let info: WorkspaceInfo = serde_json::from_value(record).unwrap();
            ids.push(info.id.clone());
            workspaces.insert(info.id.clone(), info);
        }
        let data = WorkspacePersistenceData {
            format_version: WORKSPACE_PERSISTENCE_FORMAT_VERSION,
            product_id: product_id().to_owned(),
            workspaces,
            opened_workspace_ids: ids,
            current_workspace_id: None,
            recent_workspaces: Vec::new(),
            recent_assistant_workspaces: Vec::new(),
            primary_assistant_key: None,
            assistant_name_sequence: 0,
            saved_at: chrono::Utc::now(),
        };
        PersistenceService::from_base_dir(paths.user_data_dir())
            .save_json(
                catalog_readonly::WORKSPACE_CATALOG_KEY,
                &data,
                StorageOptions {
                    create_backup: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }

    /// Waits for a cross-process marker file and returns its text.
    async fn await_marker(path: &Path) -> String {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                return text;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "marker deadline: {}",
                path.display()
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    fn local_record(fixture: &Fixture, id: &str, name: &str) -> Value {
        local_record_at(fixture.dir.path(), id, name)
    }

    fn local_record_at(base: &Path, id: &str, name: &str) -> Value {
        let root = base.join(name);
        std::fs::create_dir_all(&root).unwrap();
        json!({
            "id": id,
            "name": id,
            "rootPath": root.to_string_lossy().to_string(),
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
        })
    }

    fn child_record(fixture: &Fixture, id: &str, parent: &str, name: &str) -> Value {
        child_record_at(fixture.dir.path(), id, parent, name)
    }

    /// The same local record as [`local_record`], with a worktree block that says it
    /// is the main workspace of its group and therefore carries no
    /// `mainWorkspaceId`.
    fn main_record(fixture: &Fixture, id: &str, name: &str) -> Value {
        let root = fixture.dir.path().join(name);
        std::fs::create_dir_all(&root).unwrap();
        let root = root.to_string_lossy().to_string();
        json!({
            "id": id,
            "name": id,
            "rootPath": root,
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
                "path": root,
                "mainRepoPath": root,
                "isMain": true,
            },
        })
    }

    fn child_record_at(base: &Path, id: &str, parent: &str, name: &str) -> Value {
        let root = base.join(name);
        std::fs::create_dir_all(&root).unwrap();
        json!({
            "id": id,
            "name": id,
            "rootPath": root.to_string_lossy().to_string(),
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
                "path": root.to_string_lossy().to_string(),
                "mainRepoPath": base.join("main-repo").to_string_lossy().to_string(),
                "isMain": false,
            },
        })
    }

    async fn wait_for_in_flight(host: &WorkspaceIntelligenceHost, expected: usize) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while host.in_flight_for_tests().await < expected {
            assert!(tokio::time::Instant::now() < deadline, "in-flight deadline");
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    /// Waits until the in-flight pass holds the scope's owner lease.
    ///
    /// A pass that has taken the lease has passed the pre-claim gate and is inside
    /// the owner claim, which is the only state in which a drain can genuinely be
    /// blocked by owner work. Waiting for the in-flight counter alone would also
    /// match a pass that is still reading the catalog and would then refuse the
    /// claim outright.
    async fn wait_for_owner_lease(fixture: &Fixture) {
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while fixture.lock_files().is_empty() {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the pass must reach the owner claim"
            );
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    }

    mod initial_enable_admission {
        use super::super::compiled::{
            InitialEnableAdmission, InitialEnableControl, InitialEnableRefusal,
        };
        use super::*;
        use InitialEnableRefusal as Refusal;
        use WorkspaceIntelligenceHostReason as Reason;
        use WorkspaceIntelligenceHostUnsupportedScope as Unsupported;

        const ID: &str = "  persisted:workspace/a  ";

        async fn bootstrap(fixture: &Fixture) -> WorkspaceIntelligenceHost {
            WorkspaceIntelligenceHost::bootstrap_with_options(
                Arc::clone(&fixture.paths),
                source(),
                WorkspaceIntelligenceHostSurface::Desktop,
                RuntimeDeployment::Embedded,
                options(sleeping()),
            )
            .await
        }

        async fn refuse(host: &WorkspaceIntelligenceHost, id: &str, expected: Refusal) {
            match host.initial_enable_admission(id).await {
                Ok(_) => panic!("expected admission refusal: {expected:?}"),
                Err(actual) => assert_eq!(actual, expected),
            }
        }

        #[tokio::test]
        async fn vacant_root_needs_anchor_and_uses_the_live_exact_id() {
            let fixture = Fixture::new().await;
            let host = bootstrap(&fixture).await;
            assert_eq!(host.status().await.reason(), Some(Reason::NoRecords));
            let empty = fixture.tree_hash();
            refuse(&host, ID, Refusal::WorkspaceNotFound).await;
            assert_eq!(fixture.tree_hash(), empty);

            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let before = fixture.tree_hash();
            refuse(&host, ID.trim(), Refusal::WorkspaceNotFound).await;
            let Ok(InitialEnableAdmission::NeedsAnchor { workspace }) =
                host.initial_enable_admission(ID).await
            else {
                panic!("supported host with no records needs an anchor");
            };
            assert!(workspace.id() == ID);
            assert_eq!(fixture.tree_hash(), before);
            assert!(!fixture.paths.workspace_intelligence_dir().exists());
            assert!(!host.has_standby_worker_for_tests().await);

            std::fs::create_dir_all(fixture.control_dir()).unwrap();
            let before = fixture.tree_hash();
            assert!(matches!(host.initial_enable_admission(ID).await,
                Ok(InitialEnableAdmission::NeedsAnchor { .. })));
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn shared_and_unsupported_surfaces_refuse_before_reading_catalog() {
            use WorkspaceIntelligenceHostSurface as Surface;
            use WorkspaceIntelligenceHostUnsupportedProfile as Profile;
            let fixture = Fixture::new().await;
            std::fs::create_dir_all(fixture.paths.user_data_dir()).unwrap();
            std::fs::write(fixture.registry_path(), b"invalid catalog").unwrap();
            let before = fixture.tree_hash();
            for (surface, deployment, profile) in [
                (Surface::Desktop, RuntimeDeployment::Shared, Profile::SharedRuntime),
                (Surface::PeerController, RuntimeDeployment::Embedded, Profile::PeerController),
                (Surface::DetachedDispatch, RuntimeDeployment::Embedded, Profile::DetachedDispatch),
                (Surface::ServerStdio, RuntimeDeployment::Embedded, Profile::ServerStdio),
            ] {
                let host = WorkspaceIntelligenceHost::bootstrap(
                    Arc::clone(&fixture.paths), None, surface, deployment,
                ).await;
                refuse(&host, ID, Refusal::Host(Reason::ProfileUnsupported(profile))).await;
            }
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn an_unreadable_catalog_is_refused_instead_of_reading_as_empty() {
            let fixture = Fixture::new().await;
            let host = bootstrap(&fixture).await;
            std::fs::create_dir_all(fixture.paths.user_data_dir()).unwrap();
            std::fs::write(fixture.registry_path(), b"invalid catalog").unwrap();
            let before = fixture.tree_hash();
            // The catalog is read before any anchor or control probe, and an
            // unreadable one is not "no such workspace": it never falls through
            // to a mintable `NeedsAnchor` answer.
            refuse(&host, ID, Refusal::Host(Reason::CatalogUnreadable)).await;
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn workspace_kind_and_worktree_refusals_leave_the_tree_untouched() {
            let fixture = Fixture::new().await;
            let host = bootstrap(&fixture).await;
            let mut remote = local_record(&fixture, "remote", "remote-decoy");
            remote["workspaceKind"] = json!("remote");
            remote["rootPath"] = json!("/srv/posix/remote");
            remote["metadata"] = json!({"connectionId": "offline"});
            let mut assistant = local_record(&fixture, "assistant", "assistant");
            assistant["workspaceKind"] = json!("assistant");
            assistant["assistantId"] = json!("helper");
            let mut legacy = child_record(&fixture, "legacy", "main", "legacy");
            legacy["worktree"].as_object_mut().unwrap().remove("mainWorkspaceId");
            let unresolved = child_record(&fixture, "unresolved", "missing", "unresolved");
            let mut main = main_record(&fixture, "main", "main");
            main["worktree"]["mainRepoPath"] = json!("relative/main");
            let mut child = child_record(&fixture, "child", "main", "child");
            child["worktree"]["mainRepoPath"] = json!("");
            fixture.publish(vec![remote, assistant, legacy, unresolved, main, child]).await;
            let before = fixture.tree_hash();
            for (id, reason) in [
                ("remote", Unsupported::RemoteScope),
                ("assistant", Unsupported::AssistantWorkspace),
                ("legacy", Unsupported::LegacyWorktreeReference),
                ("unresolved", Unsupported::UnresolvedWorktreeParent),
            ] {
                refuse(&host, id, Refusal::UnsupportedScope(reason)).await;
            }
            for id in ["main", "child"] {
                refuse(&host, id, Refusal::UnrenderableWorktreeMainPath).await;
            }
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn missing_anchor_never_mints_over_unknown_control_storage() {
            let fixture = Fixture::new().await;
            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let host = bootstrap(&fixture).await;
            std::fs::create_dir_all(fixture.control_dir().parent().unwrap()).unwrap();
            std::fs::write(fixture.control_dir(), b"not a directory").unwrap();
            let before = fixture.tree_hash();
            refuse(&host, ID, Refusal::Host(Reason::AnchorMissingWithRecords)).await;
            assert_eq!(fixture.tree_hash(), before);

            std::fs::rename(fixture.control_dir(), fixture.dir.path().join("moved")).unwrap();
            std::fs::create_dir(fixture.control_dir()).unwrap();
            std::fs::write(fixture.control_dir().join("unknown"), b"keep").unwrap();
            let before = fixture.tree_hash();
            refuse(&host, ID, Refusal::Host(Reason::AnchorMissingWithRecords)).await;
            let restarted = bootstrap(&fixture).await;
            refuse(&restarted, ID, Refusal::Host(Reason::AnchorMissingWithRecords)).await;
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn strict_anchor_read_refuses_invalid_loss_or_replacement() {
            let fixture = Fixture::new().await;
            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let unanchored = bootstrap(&fixture).await;
            let host_id = fixture.anchor().await;
            let anchored = bootstrap(&fixture).await;
            let path = fixture.paths.workspace_intelligence_dir().join(HOST_ANCHOR_FILE_NAME);
            let mut replacement: Value = serde_json::from_slice(&fixture.anchor_bytes()).unwrap();
            std::fs::rename(&path, fixture.dir.path().join("original-anchor")).unwrap();
            let before = fixture.tree_hash();
            refuse(&anchored, ID, Refusal::AnchorChanged).await;
            assert_eq!(fixture.tree_hash(), before);

            let other = if anchor_suffix(&host_id).starts_with('0') { '1' } else { '0' };
            replacement["anchor"] = json!(other.to_string().repeat(32));
            std::fs::write(&path, serde_json::to_vec(&replacement).unwrap()).unwrap();
            let before = fixture.tree_hash();
            refuse(&anchored, ID, Refusal::AnchorChanged).await;
            assert_eq!(fixture.tree_hash(), before);

            std::fs::write(&path, b"invalid anchor").unwrap();
            let before = fixture.tree_hash();
            refuse(&unanchored, ID, Refusal::Host(Reason::AnchorUnreadable)).await;
            let invalid_at_boot = bootstrap(&fixture).await;
            refuse(&invalid_at_boot, ID, Refusal::Host(Reason::AnchorUnreadable)).await;
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn present_anchor_snapshots_control_without_adopting_or_rewriting() {
            let fixture = Fixture::new().await;
            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let host = bootstrap(&fixture).await;
            let host_id = fixture.anchor().await;
            let scope_key = fixture.scope(&host_id, ID);
            let before = fixture.tree_hash();
            let Ok(InitialEnableAdmission::Anchored {
                scope,
                binding,
                control: InitialEnableControl::Absent,
            }) = host.initial_enable_admission(ID).await
            else {
                panic!("a newly observed anchor has no control record");
            };
            assert!(scope.as_str() == scope_key);
            assert!(binding.host_id() == host_id && binding.workspace_id() == ID);
            assert!(!host.status().await.anchor_present(), "preflight must not adopt tenancy");
            assert_eq!(fixture.tree_hash(), before);

            let mut policy = Fixture::bound_policy(&binding);
            policy["domains"]["memory"]["enabled"] = json!(false);
            policy["future"] = json!({"nested": [true, 1, null]});
            fixture.seed_control(&scope_key, false, Some(policy.clone())).await;
            let before = fixture.tree_hash();
            let Ok(InitialEnableAdmission::Anchored {
                control: InitialEnableControl::Disabled { generation, raw_policy }, ..
            }) = host.initial_enable_admission(ID).await else {
                panic!("a matching disabled record is a usable snapshot");
            };
            assert_eq!(generation, 1);
            assert!(raw_policy.as_ref() == Some(&policy), "the whole raw policy must survive");
            assert_eq!(fixture.tree_hash(), before);

            // Old records without schema, generation, switch or binding still read as OFF.
            fixture.overwrite_control_record(br#"{"policy":{"future":[1,2]}}"#);
            let before = fixture.tree_hash();
            let Ok(InitialEnableAdmission::Anchored {
                control: InitialEnableControl::Disabled { generation, raw_policy },
                ..
            }) = host.initial_enable_admission(ID).await
            else {
                panic!("a record without a schema version still reads as an OFF snapshot");
            };
            assert_eq!(generation, 0);
            assert!(raw_policy.as_ref() == Some(&json!({"future": [1, 2]})));
            assert_eq!(fixture.tree_hash(), before);
        }

        #[tokio::test]
        async fn enabled_and_unusable_control_records_are_refused_without_writes() {
            let fixture = Fixture::new().await;
            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let host_id = fixture.anchor().await;
            let scope = fixture.scope(&host_id, ID);
            fixture.seed_control(&scope, false, None).await;
            let host = bootstrap(&fixture).await;
            let mut changed = Fixture::bound_policy(&fixture.binding(&host_id, ID).await);
            changed["execution_binding"]["workspace_root"] = json!("different");
            for (record, refusal) in [
                (json!({"enabled": true}), Refusal::AlreadyEnabled),
                (
                    json!({"enabled": "false"}),
                    Refusal::Host(Reason::ControlUnreadable),
                ),
                (
                    json!({"schema_version": 99}),
                    Refusal::ControlSchemaUnsupported,
                ),
                (
                    json!({"policy": {"execution_binding": null}}),
                    Refusal::Host(Reason::BindingMalformed),
                ),
                (
                    json!({"policy": {"execution_binding": {"schema_version": 1}}}),
                    Refusal::Host(Reason::BindingSchemaUnsupported),
                ),
                (json!({"policy": changed}), Refusal::Host(Reason::BindingChanged)),
                (
                    json!({"policy": {"approval": {"mode": "unknown"}}}),
                    Refusal::ControlPolicyUnreadable,
                ),
            ] {
                fixture.overwrite_control_record(&serde_json::to_vec(&record).unwrap());
                let before = fixture.tree_hash();
                refuse(&host, ID, refusal).await;
                assert_eq!(fixture.tree_hash(), before);
            }
            fixture.overwrite_control_record(b"{");
            let before = fixture.tree_hash();
            refuse(&host, ID, Refusal::Host(Reason::ControlUnreadable)).await;
            assert_eq!(fixture.tree_hash(), before);
            assert!(!host.has_standby_worker_for_tests().await);
        }

        #[tokio::test]
        async fn shutdown_after_reads_rejects_the_observation_and_stays_closed() {
            let fixture = Fixture::new().await;
            fixture.publish(vec![local_record(&fixture, ID, "local")]).await;
            let host = bootstrap(&fixture).await;
            let (pause, mut entered) = HostPause::new();
            let _registration = super::super::pauses::register(
                fixture.paths.user_root_dir(),
                super::super::pauses::PausePoint::AfterInitialEnableObservation,
                pause.clone(),
            );
            let before = fixture.tree_hash();
            let preflight = tokio::spawn({
                let host = host.clone();
                async move { host.initial_enable_admission(ID).await }
            });
            tokio::time::timeout(DEADLINE, entered.recv()).await.unwrap().unwrap();
            assert_eq!(host.shutdown().await.state(), WorkspaceIntelligenceHostState::Stopped);
            pause.release();
            assert!(matches!(preflight.await.unwrap(), Err(Refusal::Stopping)));
            refuse(&host, ID, Refusal::Stopping).await;
            assert_eq!(fixture.tree_hash(), before);
        }
    }

    // 1
    #[tokio::test]
    async fn no_anchor_and_no_control_records_is_inactive_and_leaves_the_user_root_byte_identical() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let before = fixture.tree_hash();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Inactive);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::NoRecords)
        );
        assert!(!status.anchor_present());
        assert_eq!(status.counts().active(), 0);
        assert!(
            !host.has_standby_worker_for_tests().await,
            "no enabled scope must mean no task"
        );
        assert!(fixture.lock_files().is_empty(), "no .lock may be created");
        assert!(!fixture.lease_root_exists(), "no lease root");
        assert!(!fixture.cognition_dir().exists(), "no cognition root");
        assert!(!fixture.control_dir().exists(), "no control root");
        assert_eq!(fixture.tree_hash(), before, "the user root must be untouched");
    }

    // 2
    #[tokio::test]
    async fn restart_on_the_same_host_reuses_the_same_anchor_and_claims_once() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let anchor_before = fixture.anchor_bytes();

        let first = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let first_status = first.status().await;
        assert_eq!(first_status.state(), WorkspaceIntelligenceHostState::Active);
        assert_eq!(first_status.counts().active(), 1);
        assert!(first_status.anchor_present());
        let marker = first_status.host_marker().unwrap().to_owned();
        assert!(marker.contains("..."), "the marker must be redacted");
        assert!(
            !marker.contains(anchor_suffix(&host_id)),
            "the marker must not carry the anchor value"
        );

        // H1: the internal control scope embeds the full storage-namespace host id.
        // None of it may leave this module: not a report key, not a `Debug` field.
        let suffix = anchor_suffix(&host_id);
        let debug = format!("{first_status:?}");
        for report in first_status.scopes() {
            assert_eq!(
                report.scope(),
                "workspace-a",
                "the outward key of a scope is the persisted workspace id"
            );
            assert!(
                !report.scope().contains(HOST_ID_PREFIX) && !report.scope().contains(suffix),
                "no report key may carry the anchor: {}",
                report.scope()
            );
        }
        assert!(
            !debug.contains(suffix),
            "status data must not publish the anchor: {debug}"
        );
        assert!(
            !debug.contains(&scope),
            "the internal scope key must not be published: {debug}"
        );
        assert_eq!(
            debug.matches(HOST_ID_PREFIX).count(),
            1,
            "the redacted marker is the only host-derived string in status data: {debug}"
        );
        assert!(debug.contains(&marker), "the marker itself stays: {debug}");
        assert!(fixture.token(&scope).is_some(), "the first bootstrap claims");
        let token = fixture.token(&scope);

        let second = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let second_status = second.status().await;
        assert_eq!(
            second_status.host_marker(),
            Some(marker.as_str()),
            "the same storage root must report the same redacted anchor marker"
        );
        assert_eq!(second_status.counts().active(), 0);
        assert_eq!(second_status.counts().standby(), 1);
        let second_debug = format!("{second_status:?}");
        assert!(
            !second_debug.contains(suffix),
            "a standby-only snapshot must not publish the anchor either: {second_debug}"
        );
        assert_eq!(
            second_debug.matches(HOST_ID_PREFIX).count(),
            1,
            "the redacted marker is the only host-derived string in status data: {second_debug}"
        );
        assert_eq!(
            fixture.token(&scope),
            token,
            "a second bootstrap must not mint a second claim"
        );
        assert_eq!(fixture.anchor_bytes(), anchor_before, "the anchor is never rewritten");
    }

    // The anchor document sits directly in the workspace intelligence namespace
    // root, which `PathManager::workspace_intelligence_dir` owns, and never in an
    // inferred subdirectory beside the record roots.
    #[tokio::test]
    async fn the_anchor_document_lives_in_the_namespace_root_and_never_in_a_subdirectory() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        // Minted through the anchor owner, so the location under test is the one a
        // real mint uses and not a fixture-local path.
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;

        let namespace = fixture.paths.workspace_intelligence_dir();
        let document = namespace.join(HOST_ANCHOR_FILE_NAME);
        assert_eq!(
            document,
            fixture
                .paths
                .user_data_dir()
                .join("workspace-intelligence")
                .join("host-anchor.json"),
            "the reviewed location is one level below the user-data root"
        );
        assert!(
            document.is_file(),
            "the host reads its anchor from the namespace root: {document:?}"
        );
        assert_eq!(
            document,
            WorkspaceIntelligenceHost::anchor_root_for_tests(&fixture.paths)
                .join(HOST_ANCHOR_FILE_NAME),
            "the production root and the fixture root are the same function"
        );
        assert_eq!(
            std::fs::read(&document).unwrap(),
            fixture.anchor_bytes(),
            "the host consults exactly this document"
        );
        assert!(
            !namespace.join("anchor").exists(),
            "no anchor subdirectory is created or consulted"
        );
        assert!(
            status.anchor_present(),
            "the anchor is present in the reviewed location: {status:?}"
        );
        assert_eq!(status.counts().active(), 1, "the scope is owned: {status:?}");
    }

    // 3
    #[tokio::test]
    async fn anchor_missing_with_control_records_is_unavailable_and_preserves_bytes() {
        let fixture = Fixture::new().await;
        std::fs::create_dir_all(fixture.control_dir()).unwrap();
        // A foreign file whose name looks like a control record and whose content
        // is not JSON: it must be neither opened nor parsed.
        let digest = "a".repeat(64);
        let foreign = fixture.control_dir().join(format!("{digest}.json"));
        std::fs::write(&foreign, b"this is not json at all").unwrap();
        let bytes = std::fs::read(&foreign).unwrap();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::AnchorMissingWithRecords)
        );
        assert!(!status.anchor_present());
        assert_eq!(std::fs::read(&foreign).unwrap(), bytes, "preserve every byte");
        assert_eq!(std::fs::read_dir(fixture.control_dir()).unwrap().count(), 1);
        assert!(
            !WorkspaceIntelligenceHost::anchor_root_for_tests(&fixture.paths)
                .join(HOST_ANCHOR_FILE_NAME)
                .exists(),
            "the anchor document is never minted by a bootstrap"
        );
        assert!(!host.has_standby_worker_for_tests().await);
    }

    // 4
    #[tokio::test]
    async fn legacy_enabled_without_binding_is_unverified_and_stays_on() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        fixture.seed_control(&scope, true, None).await;
        let bytes = fixture.control_bytes();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::Unverified)
        );
        assert_eq!(
            status.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::Unverified
            ))
        );
        assert_eq!(fixture.control_bytes(), bytes, "the enabled record is untouched");
        assert!(fixture.lock_files().is_empty(), "no lease may be taken");
        assert!(!fixture.cognition_dir().exists(), "no cognition partition");
        assert!(fixture.token(&scope).is_none());
    }

    // 5
    #[tokio::test]
    async fn binding_kind_change_is_detected_before_claim() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        assert_eq!(host.status().await.state(), WorkspaceIntelligenceHostState::Active);
        let bytes = fixture.control_bytes();

        // Rewrite the persisted registry for the same workspace id through the
        // real owner: the record becomes a worktree child.
        fixture
            .publish(vec![
                local_record(&fixture, "parent-workspace", "parent"),
                child_record(&fixture, "workspace-a", "parent-workspace", "child"),
            ])
            .await;
        host.evaluate_for_tests().await;
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged)
        );
        assert_eq!(status.counts().active(), 0, "no new claim is published");
        assert_eq!(fixture.control_bytes(), bytes, "the control record is untouched");
    }

    // R2: the observed worktree projection is part of the binding. A record that
    // gains or loses the stored `is_main` fact keeps every previously known field
    // identical — same kind, same absent parent — so only the wider binding can see
    // the change, in either direction.
    #[tokio::test]
    async fn a_worktree_projection_change_between_passes_is_detected_and_refused() {
        for rewrite_to_main in [true, false] {
            let fixture = Fixture::new().await;
            let (stored, rewritten) = if rewrite_to_main {
                (
                    local_record(&fixture, "workspace-a", "a"),
                    main_record(&fixture, "workspace-a", "a"),
                )
            } else {
                (
                    main_record(&fixture, "workspace-a", "a"),
                    local_record(&fixture, "workspace-a", "a"),
                )
            };
            fixture.publish(vec![stored]).await;
            let host_id = fixture.anchor().await;
            let scope = fixture.scope(&host_id, "workspace-a");
            let binding = fixture.binding(&host_id, "workspace-a").await;
            assert_eq!(
                binding.worktree_is_main(),
                if rewrite_to_main { None } else { Some(true) },
                "the seeded binding carries the projection it was minted from"
            );
            fixture
                .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
                .await;

            let host = WorkspaceIntelligenceHost::bootstrap_with_options(
                Arc::clone(&fixture.paths),
                source(),
                WorkspaceIntelligenceHostSurface::Desktop,
                RuntimeDeployment::Embedded,
                options(sleeping()),
            )
            .await;
            assert_eq!(
                host.status().await.state(),
                WorkspaceIntelligenceHostState::Active,
                "the seeded projection is claimed"
            );
            let bytes = fixture.control_bytes();
            let partitions = fixture.sqlite_files();

            // Rewrite the persisted record through the real owner path: same id,
            // same root, same kind, same absent parent, different worktree facts.
            fixture.publish(vec![rewritten]).await;
            let persisted = catalog_readonly::read_persisted_catalog(&fixture.paths)
                .await
                .unwrap();
            let workspace = persisted.workspace("workspace-a").expect("still eligible");
            assert_eq!(
                workspace.worktree_is_main(),
                if rewrite_to_main { Some(true) } else { None },
                "the owner write really changed the persisted registry"
            );

            host.evaluate_for_tests().await;
            let status = host.status().await;
            assert_eq!(
                status.reason(),
                Some(WorkspaceIntelligenceHostReason::BindingChanged),
                "the wider binding must see the projection change (to_main={rewrite_to_main})"
            );
            assert_eq!(
                status.counts().active(),
                0,
                "no claim survives a projection change"
            );
            assert_eq!(fixture.control_bytes(), bytes, "the ON record is untouched");
            assert_eq!(
                fixture.sqlite_files(),
                partitions,
                "a refused publish adds no cognition partition"
            );
        }
    }

    // 6
    #[tokio::test]
    async fn same_generation_policy_change_after_the_host_read_is_rejected() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let (pause, mut entered) = HostPause::new();
        let _registration = super::pauses::register(
            fixture.paths.user_root_dir(),
            super::pauses::PausePoint::BeforeClaim,
            pause.clone(),
        );
        let paths = Arc::clone(&fixture.paths);
        let bootstrap = tokio::spawn(async move {
            WorkspaceIntelligenceHost::bootstrap_with_options(
                paths,
                source(),
                WorkspaceIntelligenceHostSurface::Desktop,
                RuntimeDeployment::Embedded,
                options(sleeping()),
            )
            .await
        });
        tokio::time::timeout(DEADLINE, entered.recv())
            .await
            .expect("the host must reach the pause point")
            .expect("the pause channel stays open");

        // Mutate the policy through the owner while the host is between its read
        // and its claim. The generation advances, but the claim carries the exact
        // raw value it read, so the owner refuses it.
        let mut changed = Fixture::bound_policy(&binding);
        changed["domains"]["memory"]["enabled"] = json!(false);
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(changed),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        pause.release();

        let host = tokio::time::timeout(DEADLINE, bootstrap)
            .await
            .expect("bootstrap completes")
            .unwrap();
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::AuthorityChanged)
        );
        assert_eq!(status.counts().active(), 0);
        assert!(
            !fixture.cognition_dir().exists(),
            "a refused claim publishes nothing"
        );
    }

    // 7
    #[tokio::test]
    async fn remote_and_assistant_workspaces_are_typed_unsupported_and_never_claimed() {
        let fixture = Fixture::new().await;
        let assistant_root = fixture.dir.path().join("assistant");
        std::fs::create_dir_all(&assistant_root).unwrap();
        let assistant_root = assistant_root.to_string_lossy().to_string();
        fixture
            .publish(vec![
                json!({
                    "id": "remote-workspace",
                    "name": "remote",
                    "rootPath": "/srv/apps/remote",
                    "workspaceType": "Other",
                    "workspaceKind": "remote",
                    "status": "Inactive",
                    "languages": [],
                    "openedAt": "2026-01-01T00:00:00Z",
                    "lastAccessed": "2026-01-01T00:00:00Z",
                    "description": null,
                    "tags": [],
                    "statistics": null,
                    "metadata": {"connectionId": "ssh-1", "sshHost": "example"},
                }),
                json!({
                    "id": "assistant-workspace",
                    "name": "assistant",
                    "rootPath": assistant_root,
                    "workspaceType": "Other",
                    "workspaceKind": "assistant",
                    "assistantId": "helper",
                    "status": "Active",
                    "languages": [],
                    "openedAt": "2026-01-01T00:00:00Z",
                    "lastAccessed": "2026-01-01T00:00:00Z",
                    "description": null,
                    "tags": [],
                    "statistics": null,
                    "metadata": {},
                }),
            ])
            .await;
        let host_id = fixture.anchor().await;

        // Each unsupported record carries a REAL enabled control record written
        // through the authoritative owner's own compare-and-swap: the complete
        // local-shaped execution-binding fence this host demands of an eligible
        // scope (identity, domain, id, root and all five worktree fields) plus the ON
        // switch. The seeded body therefore differs from a claimable local scope in
        // exactly one persisted fact: the workspace kind the record declares. That is
        // what makes the typed refusal below meaningful instead of vacuous.
        for (workspace_id, workspace_root) in [
            ("remote-workspace", "/srv/apps/remote"),
            ("assistant-workspace", assistant_root.as_str()),
        ] {
            let policy = Fixture::local_shaped_policy(&host_id, workspace_id, workspace_root);
            let BindingState::Present(seeded) = classify(Some(&policy)) else {
                panic!("the seeded policy must be a complete binding, got {policy}");
            };
            assert_eq!(seeded.schema_version(), EXECUTION_BINDING_SCHEMA_VERSION);
            assert_eq!(seeded.host_id(), host_id.as_str());
            assert_eq!(seeded.execution_domain(), LOCAL_EXECUTION_DOMAIN);
            assert_eq!(seeded.workspace_id(), workspace_id);
            assert_eq!(seeded.workspace_root(), workspace_root);
            assert_eq!(seeded.workspace_kind(), "local_workspace");
            assert!(!seeded.is_worktree_child());
            assert_eq!(seeded.worktree_parent_id(), None);
            assert_eq!(seeded.worktree_is_main(), None);
            assert_eq!(seeded.main_repo_path(), None);
            fixture
                .seed_control(&fixture.scope(&host_id, workspace_id), true, Some(policy))
                .await;
        }
        let control_records = fixture.control_records();
        assert_eq!(control_records.len(), 2, "one enabled record per unsupported scope");
        for (path, bytes) in &control_records {
            let document: Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(document["enabled"], json!(true), "{} is an ON record", path.display());
            assert_eq!(
                document["control_generation"],
                json!(1),
                "{} is a first-generation record",
                path.display()
            );
        }
        let registry = fixture.registry_path();
        let registry_bytes = std::fs::read(&registry).unwrap();
        let before = fixture.tree_hash();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        // `unsupported` is derived from the persisted record shape alone, so this
        // count is structurally independent of the control records seeded above and
        // proves nothing about them. The real evidence of F4 is further down: no
        // lease, no cognition partition, byte-identical ON control records, an
        // untouched registry and an unchanged user-root tree hash.
        assert_eq!(status.counts().unsupported(), 2);
        assert_eq!(status.counts().active(), 0);
        assert_eq!(status.counts().standby(), 0);
        assert_eq!(
            status.scope_state("remote-workspace"),
            Some(WorkspaceIntelligenceHostScopeState::Unsupported(
                WorkspaceIntelligenceHostUnsupportedScope::RemoteScope
            ))
        );
        assert_eq!(
            status.scope_state("assistant-workspace"),
            Some(WorkspaceIntelligenceHostScopeState::Unsupported(
                WorkspaceIntelligenceHostUnsupportedScope::AssistantWorkspace
            ))
        );
        // A remote record stays a record: it is never projected into a
        // `remote:<connection>` execution domain, so no scope, no lease, no control
        // write and no cognition partition can exist for it — the seeded ON record
        // included.
        let debug = format!("{status:?}");
        assert!(
            !debug.contains("remote:"),
            "a remote record must not become a remote execution domain: {debug}"
        );
        assert!(
            !debug.contains("ssh-1"),
            "the connection id is not an execution domain: {debug}"
        );
        for report in status.scopes() {
            assert!(
                report.scope() == "remote-workspace" || report.scope() == "assistant-workspace",
                "the outward key is the persisted id, got {}",
                report.scope()
            );
        }
        assert!(fixture.lock_files().is_empty(), "no lease may be created");
        assert!(fixture.sqlite_files().is_empty(), "no cognition partition");
        assert_eq!(
            fixture.control_records(),
            control_records,
            "not one byte of the enabled control records may be rewritten"
        );
        assert_eq!(
            std::fs::read(&registry).unwrap(),
            registry_bytes,
            "the persisted registry is never rewritten"
        );
        assert_eq!(fixture.tree_hash(), before, "the user root is untouched");
    }

    // 7b: the catalog revision hint is a real wake-up source, not a decoration. The
    // fallback delay is an hour, so a pass can only start because the hint fired.
    #[tokio::test]
    async fn a_catalog_hint_wakes_a_real_pass_and_a_repeated_hint_adds_no_tenure() {
        let fixture = Fixture::new().await;
        // Two local workspaces. Only the first is enabled before bootstrap, so the
        // bootstrap pass owns something and therefore spawns the standby worker that
        // holds the hint receiver.
        fixture
            .publish(vec![
                local_record(&fixture, "workspace-a", "a"),
                local_record(&fixture, "workspace-b", "b"),
            ])
            .await;
        let host_id = fixture.anchor().await;
        let scope_a = fixture.scope(&host_id, "workspace-a");
        let binding_a = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope_a, true, Some(Fixture::bound_policy(&binding_a)))
            .await;

        let (revision, revision_rx) = tokio::sync::watch::channel(0u64);
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            WorkspaceCatalogSource::from_hint_for_tests(revision_rx),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.counts().active(), 1, "the bootstrap pass owns workspace-a");
        assert_eq!(
            status.scope_state("workspace-b"),
            Some(WorkspaceIntelligenceHostScopeState::Disabled),
            "workspace-b has no control record yet: {status:?}"
        );
        assert!(
            host.has_standby_worker_for_tests().await,
            "an enabled scope keeps the hint receiver alive"
        );
        let token_a = fixture
            .token(&scope_a)
            .expect("the bootstrap pass committed a cognition incarnation");
        let scope_b = fixture.scope(&host_id, "workspace-b");
        assert!(
            fixture.token(&scope_b).is_none(),
            "no pass has read workspace-b yet"
        );
        let leases_before_hint = fixture.lock_files();
        assert_eq!(leases_before_hint.len(), 1, "one lease for the one owned scope");

        // Workspace-b becomes enabled ON DISK only. Nothing in this process reports
        // it, so the only thing that can make a pass read it is the hint.
        let binding_b = fixture.binding(&host_id, "workspace-b").await;
        fixture
            .seed_control(&scope_b, true, Some(Fixture::bound_policy(&binding_b)))
            .await;
        let control_records = fixture.control_records();
        assert_eq!(control_records.len(), 2, "one enabled record per scope");

        // (a) One hint event must start a pass that owns the newly enabled scope.
        revision.send(1).unwrap();
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let status = host.status().await;
            if status.scope_state("workspace-b")
                == Some(WorkspaceIntelligenceHostScopeState::Active)
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the hint must wake a pass: {status:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let status = host.status().await;
        assert_eq!(status.counts().active(), 2, "the hinted pass owns both scopes");
        assert_eq!(status.counts().standby(), 0);
        let token_b = fixture
            .token(&scope_b)
            .expect("the hinted pass committed a cognition incarnation for workspace-b");
        let leases_after_hint = fixture.lock_files();
        assert_eq!(leases_after_hint.len(), 2, "one lease per owned scope");
        assert_eq!(fixture.token(&scope_a).as_deref(), Some(token_a.as_str()));
        assert_eq!(
            fixture.control_records(),
            control_records,
            "a pass never rewrites a control record"
        );
        let partitions = fixture.sqlite_bytes();

        // (b) A second hint with nothing changed on disk must re-read the same facts
        // and add no tenure: no second lease, no token rotation, no control write and
        // no cognition write.
        //
        // The pass is observed rather than assumed. `in_flight` is raised at the top
        // of every evaluation pass, this runtime is single-threaded, and the fallback
        // is an hour away, so a pass that starts now can only be the hint's.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while host.in_flight_for_tests().await > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the hinted pass must finish before the next hint"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        revision.send(2).unwrap();
        let deadline = tokio::time::Instant::now() + DEADLINE;
        // `observed` means a pass was seen pending at least once: `in_flight` is
        // raised at pass entry and lowered on drop, so the poll below witnesses the
        // hint-started pass itself, not a later state of it.
        let mut observed = false;
        while tokio::time::Instant::now() < deadline {
            if host.in_flight_for_tests().await > 0 {
                observed = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        assert!(observed, "the second hint must start a pass");
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while host.in_flight_for_tests().await > 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "the second hinted pass must finish"
            );
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        assert_eq!(
            fixture.lock_files(),
            leases_after_hint,
            "an empty pass takes no second lease"
        );
        assert_eq!(
            fixture.token(&scope_a).as_deref(),
            Some(token_a.as_str()),
            "workspace-a keeps its incarnation"
        );
        assert_eq!(
            fixture.token(&scope_b).as_deref(),
            Some(token_b.as_str()),
            "workspace-b keeps its incarnation"
        );
        assert_eq!(
            fixture.control_records(),
            control_records,
            "an empty pass writes no control record"
        );
        assert_eq!(
            fixture.sqlite_bytes(),
            partitions,
            "an empty pass writes no cognition partition"
        );
        let status = host.status().await;
        assert_eq!(status.counts().active(), 2, "the same tenure is still reported");
        host.shutdown().await;
    }

    // 8
    #[tokio::test]
    async fn standby_takes_over_after_the_owner_releases() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let owner = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(fast()),
        )
        .await;
        assert_eq!(owner.status().await.state(), WorkspaceIntelligenceHostState::Active);
        let first_token = fixture.token(&scope).expect("owner token");

        let standby = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(fast()),
        )
        .await;
        let standby_status = standby.status().await;
        assert_eq!(standby_status.counts().active(), 0);
        assert_eq!(standby_status.counts().standby(), 1);
        assert!(standby.has_standby_worker_for_tests().await);
        assert_eq!(fixture.token(&scope), Some(first_token.clone()));

        let shutdown = owner.shutdown().await;
        assert_eq!(shutdown.drain(), WorkspaceIntelligenceHostDrain::Drained);
        assert_eq!(shutdown.state(), WorkspaceIntelligenceHostState::Stopped);
        assert_eq!(owner.status().await.counts().active(), 0);

        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            if standby.status().await.counts().active() == 1 {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "takeover deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let takeover_token = fixture.token(&scope).expect("takeover token");
        assert_ne!(takeover_token, first_token, "the token must advance");

        // Exactly one takeover: the standby host keeps its claim instead of
        // re-claiming on every fallback tick.
        tokio::time::sleep(SETTLE).await;
        assert_eq!(standby.status().await.counts().active(), 1);
        assert_eq!(fixture.token(&scope), Some(takeover_token));
    }

    // 9
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn drain_timeout_stays_draining_and_never_publishes_late() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;

        // Bootstrap with no control record: nothing is enabled and nothing runs.
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(HostTiming::new(
                Duration::from_secs(3600),
                Duration::from_secs(3600),
                Duration::from_millis(200),
            )),
        )
        .await;
        assert_eq!(host.status().await.state(), WorkspaceIntelligenceHostState::Inactive);

        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        // Hold the control guard so the owner claim blocks after taking its lease.
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(scope.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let record_path = fixture.control_dir().join(format!("{digest}.json"));
        let guard = JsonFileStore
            .acquire_cross_process_lock(&record_path)
            .await
            .expect("fixture holds the control guard");

        let evaluation = tokio::spawn({
            let host = host.clone();
            async move { host.evaluate_for_tests().await }
        });
        // The pass must be inside the owner claim when the drain starts. A pass that
        // is still reading now refuses the claim before taking a lease, which is the
        // correct behaviour but not the blocked-owner condition this test pins.
        wait_for_owner_lease(&fixture).await;

        let shutdown = host.shutdown().await;
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding: 1 },
            "the blocking owner must be reported, not hidden"
        );
        assert_eq!(
            shutdown.state(),
            WorkspaceIntelligenceHostState::Draining,
            "a timed-out drain stays incomplete, never stopped"
        );

        drop(guard);
        tokio::time::timeout(DEADLINE, evaluation)
            .await
            .expect("the blocked owner finishes once the guard is released")
            .unwrap();

        let status = host.status().await;
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Draining,
            "the host must not promote itself to stopped after the fact"
        );
        assert_eq!(status.counts().active(), 0);
        assert_eq!(
            status.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::ClaimRefused
            )),
            "a claim completing after the drain started must not be published"
        );
        // No assertion about a rollback: the owner's own writes are untouched.
    }

    // M2: an already-owned claim must obey the same drop rule as a fresh one.
    #[tokio::test]
    async fn an_owned_claim_finishing_after_the_drain_started_is_not_republished() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(HostTiming::new(
                Duration::from_secs(3600),
                Duration::from_secs(3600),
                Duration::from_millis(200),
            )),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.counts().active(), 1, "the first pass owns the scope");

        // Park the second pass inside the lock-backed owner read, which is the
        // re-verification path of the tenure this host already holds.
        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(scope.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let record_path = fixture.control_dir().join(format!("{digest}.json"));
        let guard = JsonFileStore
            .acquire_cross_process_lock(&record_path)
            .await
            .expect("fixture holds the control guard");

        let evaluation = tokio::spawn({
            let host = host.clone();
            async move { host.evaluate_for_tests().await }
        });
        wait_for_in_flight(&host, 1).await;

        let shutdown = host.shutdown().await;
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding: 1 }
        );
        assert_eq!(shutdown.state(), WorkspaceIntelligenceHostState::Draining);

        drop(guard);
        tokio::time::timeout(DEADLINE, evaluation)
            .await
            .expect("the parked pass finishes once the guard is released")
            .unwrap();

        let status = host.status().await;
        assert_eq!(
            status.counts().active(),
            0,
            "an owned claim re-verified after the drain started must not be counted active"
        );
        // The fixture does not pin which lock-backed owner call parks the pass, so
        // the exact blocked reason is not asserted. What is asserted is the rule:
        // no path may report `active` tenure once the drain has started.
        assert_ne!(
            status.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Active),
            "a tenure that outlived the drain start is never re-published"
        );
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Draining,
            "the timed-out drain stays incomplete"
        );
        // No assertion on the `.lock` inode: the owner never deletes it, so its
        // existence cannot tell held tenure from released tenure.
    }

    // M3: a 1 -> 0 in-flight drop between the check and the wait must not be lost.
    #[tokio::test]
    async fn an_in_flight_drop_between_the_check_and_the_wait_still_drains() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        // The pause must be registered before the first bootstrap pass, because the
        // host resolves its pause points once, at construction. It parks the drain
        // loop exactly between its in-flight check and its wait, which is the only
        // window where a notification can be lost.
        let (pause, mut entered) = HostPause::new();
        let _registration = super::pauses::register(
            fixture.paths.user_root_dir(),
            super::pauses::PausePoint::DrainWait,
            pause.clone(),
        );

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(HostTiming::new(
                Duration::from_secs(3600),
                Duration::from_secs(3600),
                // Far longer than the outer `DEADLINE` on purpose: if the 1 -> 0
                // notification were lost, the drain loop could only exit by
                // reaching its own budget, so the outer guard — not an elapsed-time
                // assertion — is what proves the wake-up arrived.
                Duration::from_secs(3600),
            )),
        )
        .await;

        let digest = {
            let mut hasher = Sha256::new();
            hasher.update(scope.as_bytes());
            format!("{:x}", hasher.finalize())
        };
        let record_path = fixture.control_dir().join(format!("{digest}.json"));
        let guard = JsonFileStore
            .acquire_cross_process_lock(&record_path)
            .await
            .expect("fixture holds the control guard");

        let evaluation = tokio::spawn({
            let host = host.clone();
            async move { host.evaluate_for_tests().await }
        });
        wait_for_in_flight(&host, 1).await;

        let draining = tokio::spawn({
            let host = host.clone();
            async move { host.shutdown().await }
        });
        tokio::time::timeout(DEADLINE, entered.recv())
            .await
            .expect("the drain loop must reach the in-flight window")
            .expect("the pause channel stays open");

        // The only in-flight pass finishes while the drain loop is parked: its
        // 1 -> 0 drop notifies an interest that must already be registered.
        drop(guard);
        tokio::time::timeout(DEADLINE, evaluation)
            .await
            .expect("the parked pass finishes once the guard is released")
            .unwrap();
        assert_eq!(host.in_flight_for_tests().await, 0);
        pause.release();

        let shutdown = tokio::time::timeout(DEADLINE, draining)
            .await
            .expect("the drain must not wait for its full budget")
            .unwrap();
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::Drained,
            "a notification that arrives inside the window must still be observed"
        );
        assert_eq!(shutdown.state(), WorkspaceIntelligenceHostState::Stopped);
    }

    // M1: an unreadable catalog must not leave held tenure behind. `Unavailable`
    // is documented as "no scope is owned", so the pass that cannot enumerate the
    // scopes releases its own claims instead of settling while still holding them.
    #[tokio::test]
    async fn a_catalog_read_error_releases_held_tenure_and_reports_unavailable() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        assert_eq!(host.status().await.counts().active(), 1, "the first pass owns it");
        assert_eq!(host.status().await.scopes().len(), 1);

        // Replace the registry the host must decode with an undecodable document:
        // the next pass has no authority to prove tenure over.
        let valid = std::fs::read(fixture.registry_path()).unwrap();
        std::fs::write(fixture.registry_path(), b"{ \"workspaces\": ").unwrap();
        host.evaluate_for_tests().await;

        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::CatalogUnreadable)
        );
        assert_eq!(
            status.counts().active(),
            0,
            "the tenure the previous pass held is released, not reported as owned"
        );
        assert_eq!(status.counts().standby(), 0);
        assert!(
            status.scopes().is_empty(),
            "a pass with no authority reports no scope"
        );

        // The OS lease is the load-bearing part: once the registry is readable
        // again another host must be able to claim the scope. If the unreadable
        // pass had kept `book.claims`, this host would still hold the lease and
        // the second host would only ever be standby.
        std::fs::write(fixture.registry_path(), &valid).unwrap();
        let second = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let second_status = second.status().await;
        assert_eq!(
            second_status.counts().active(),
            1,
            "the released tenure is free for the next host: {second_status:?}"
        );
        assert_eq!(second_status.counts().standby(), 0);
    }

    // M2: a fresh host that has never confirmed an enabled scope must not mint a
    // wake-up worker out of an unreadable control record.
    //
    // This is the same baseline as "no anchor starts no task": the host has no ON
    // evidence at all, so there is nothing to retry, and the retry pass it is not
    // given must not earn one for itself either. The control record really exists on
    // disk — it is just undecodable — so the only fact under test is readability.
    #[tokio::test]
    async fn a_fresh_host_with_only_an_unreadable_control_record_starts_no_worker() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        // A real, valid, enabled record first: if the host could read it, it would
        // claim. Only the overwrite below makes it unreadable.
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let record: Value = serde_json::from_slice(&fixture.control_bytes()).unwrap();
        assert_eq!(record["enabled"], json!(true), "the seeded record really is ON");

        let corrupt = fixture.overwrite_control_record(b"this is not a control record");
        let preserved = fixture.control_records();
        assert_eq!(preserved.len(), 1, "the record still exists under the control root");
        assert_eq!(preserved[0].1, corrupt, "the bytes are exactly the corrupt ones");
        let before = fixture.tree_hash();
        let registry_bytes = std::fs::read(fixture.registry_path()).unwrap();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Unavailable,
            "an unreadable authority leaves nothing provable: {status:?}"
        );
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::ControlUnreadable)
        );
        assert_eq!(status.counts().active(), 0);
        assert_eq!(status.counts().standby(), 0);
        // `invalid` is the bucket of BLOCKED rows, so the honest count for one
        // unreadable scope is one blocked row and nothing owned. The zero-tenure
        // claim is the lease/sqlite assertions below, not this count.
        assert_eq!(status.counts().invalid(), 1, "one blocked row, nothing owned");
        assert_eq!(
            status.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::ControlUnreadable
            ))
        );
        assert!(
            !host.has_standby_worker_for_tests().await,
            "a host with no ON evidence spawns no wake-up task: {status:?}"
        );
        assert!(fixture.lock_files().is_empty(), "no lease is attempted");
        assert!(fixture.sqlite_files().is_empty(), "no cognition partition");
        assert_eq!(
            fixture.control_records(),
            preserved,
            "the unreadable record is preserved, never repaired or deleted"
        );
        assert_eq!(
            std::fs::read(fixture.registry_path()).unwrap(),
            registry_bytes,
            "the persisted registry is never rewritten"
        );
        assert_eq!(fixture.tree_hash(), before, "the user root is untouched");

        // The retry path itself must not earn a worker. If one unreadable pass could
        // set the flag, the second pass below would already have a worker in place
        // and would keep the fallback alive forever on nothing.
        for _ in 0..2 {
            host.evaluate_for_tests().await;
            assert!(
                !host.has_standby_worker_for_tests().await,
                "a repeated unreadable pass still has no ON evidence to retry"
            );
            assert_eq!(
                fixture.control_records(),
                preserved,
                "no pass rewrites the unreadable record"
            );
        }
        let status = host.status().await;
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Unavailable,
            "the retried pass reaches the same typed state: {status:?}"
        );
        assert_eq!(fixture.tree_hash(), before, "the user root is untouched");
    }

    // L1: an already-earned ON recovery must survive a control read error. The
    // worker is not a permanent flag — it lives only in this process and only for a
    // scope this host really read as enabled — but a single unreadable read must not
    // kill it, or the transient fault would become permanent.
    #[tokio::test]
    async fn an_enabled_host_keeps_its_recovery_worker_across_a_control_read_error() {
        let poll = Duration::from_millis(1);
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let original = fixture.control_bytes();

        // `fast()` timing, so the worker really is the thing that retries on its own.
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(fast()),
        )
        .await;
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let status = host.status().await;
            if status.scope_state("workspace-a") == Some(WorkspaceIntelligenceHostScopeState::Active)
                && host.has_standby_worker_for_tests().await
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the enabled scope must be owned by a host with a worker: {status:?}"
            );
            tokio::time::sleep(poll).await;
        }
        let owned = host.status().await;
        assert_eq!(owned.counts().active(), 1, "the enabled scope is owned first");
        assert_eq!(fixture.control_bytes(), original, "the host never wrote control");

        // One truncated document: the record is still there, but the owner cannot
        // decode it, so the pass must report the scope as blocked.
        let corrupt = fixture.overwrite_control_record(b"{\"enabled\":");
        let preserved = fixture.control_records();
        assert_eq!(preserved.len(), 1);
        assert_eq!(preserved[0].1, corrupt, "the bytes are exactly the truncated JSON");
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let status = host.status().await;
            if status.scope_state("workspace-a")
                == Some(WorkspaceIntelligenceHostScopeState::Blocked(
                    WorkspaceIntelligenceHostReason::ControlUnreadable,
                ))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the worker must retry into the unreadable record: {status:?}"
            );
            tokio::time::sleep(poll).await;
        }
        assert_eq!(
            fixture.control_records(),
            preserved,
            "the unreadable record is preserved"
        );
        // The load-bearing assertion of this test: the earned recovery outlived the
        // error instead of being killed by it.
        assert!(
            host.has_standby_worker_for_tests().await,
            "an earned ON recovery must survive a control read error"
        );

        // Restoring the valid bytes must be enough: the worker retries into a readable
        // ON record again and the scope is owned once more.
        fixture.overwrite_control_record(&original);
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let status = host.status().await;
            if status.scope_state("workspace-a") == Some(WorkspaceIntelligenceHostScopeState::Active)
                && status.counts().active() == 1
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the kept worker must recover the scope: {status:?}"
            );
            tokio::time::sleep(poll).await;
        }
        let recovered = host.status().await;
        assert_eq!(recovered.counts().active(), 1);
        assert_eq!(recovered.counts().standby(), 0);
        assert_ne!(
            recovered.state(),
            WorkspaceIntelligenceHostState::Unavailable,
            "a recovered host is not Unavailable: {recovered:?}"
        );
        assert_eq!(
            fixture.control_bytes(),
            original,
            "the host never rewrote the control record"
        );
        assert!(
            host.has_standby_worker_for_tests().await,
            "the recovered host keeps its worker"
        );
        // The error pass released the tenure it could no longer prove (the OS lease is
        // dropped; the lease file and the persisted incarnation stay), so recovery
        // re-acquires the lease and mints a NEW incarnation. Only "a token exists" is
        // asserted here on purpose: asserting equality would pin the opposite of what
        // was measured.
        assert!(
            fixture.token(&scope).is_some(),
            "the recovered scope has a cognition incarnation"
        );
    }

    // T-B: the commit-versus-publish window. The owner claim commits, then the
    // persisted binding changes before the pass publishes tenure, so the claim
    // must be dropped instead of handed off.
    #[tokio::test]
    async fn a_binding_change_between_the_owner_commit_and_publish_is_not_published() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let control = fixture.control_bytes();

        let (pause, mut entered) = HostPause::new();
        let _registration = super::pauses::register(
            fixture.paths.user_root_dir(),
            super::pauses::PausePoint::AfterClaim,
            pause.clone(),
        );
        let paths = Arc::clone(&fixture.paths);
        let bootstrap = tokio::spawn(async move {
            WorkspaceIntelligenceHost::bootstrap_with_options(
                paths,
                source(),
                WorkspaceIntelligenceHostSurface::Desktop,
                RuntimeDeployment::Embedded,
                options(sleeping()),
            )
            .await
        });
        tokio::time::timeout(DEADLINE, entered.recv())
            .await
            .expect("the host must reach the post-claim pause")
            .expect("the pause channel stays open");

        // Strictly after the owner claim: the incarnation advance is committed (so
        // the partition already carries this claim's token) and the lease is held,
        // while nothing has been published.
        let token = fixture
            .token(&scope)
            .expect("the owner claim committed before the pause");
        let partitions = fixture.sqlite_files();
        assert!(
            !partitions.is_empty(),
            "the claim initialized the cognition partition"
        );

        // The persisted binding changes while the claim is committed and
        // unpublished: same workspace id, now a worktree child, written through the
        // real owner.
        fixture
            .publish(vec![
                local_record(&fixture, "parent-workspace", "parent"),
                child_record(&fixture, "workspace-a", "parent-workspace", "child"),
            ])
            .await;
        pause.release();

        let host = tokio::time::timeout(DEADLINE, bootstrap)
            .await
            .expect("bootstrap completes")
            .unwrap();
        let status = host.status().await;
        assert_eq!(
            status.counts().active(),
            0,
            "a claim whose binding changed before publish is never handed off: {status:?}"
        );
        assert_ne!(status.state(), WorkspaceIntelligenceHostState::Active);
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged)
        );
        assert_eq!(
            status.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::BindingChanged
            ))
        );
        let debug = format!("{status:?}");
        assert!(
            !debug.contains(&scope),
            "status is keyed by the workspace id, never the scope string: {debug}"
        );
        assert!(
            !debug.contains(&token),
            "the unpublished claim token never reaches status data: {debug}"
        );
        assert_eq!(fixture.control_bytes(), control, "the ON record is byte-identical");
        // The refused publish writes no revision: the partition keeps exactly the
        // state the claim itself committed and gains no second one.
        assert_eq!(fixture.token(&scope).as_deref(), Some(token.as_str()));
        assert_eq!(fixture.sqlite_files(), partitions, "no new cognition partition");
    }

    /// One parked pass in the exact window where its owner claim has committed and
    /// nothing has been published yet.
    ///
    /// Shared by the control-authority tests below, which all need that window to
    /// change the persisted authority between the commit and the publish.
    struct ClaimWindow {
        host: WorkspaceIntelligenceHost,
        evaluation: Option<tokio::task::JoinHandle<()>>,
        pause: HostPause,
        scope: String,
    }

    impl ClaimWindow {
        /// Bootstraps over `fixture` and parks its first pass after the owner claim.
        async fn open(fixture: &Fixture) -> Self {
            fixture.publish(vec![local_record(fixture, "workspace-a", "a")]).await;
            let host_id = fixture.anchor().await;
            let scope = fixture.scope(&host_id, "workspace-a");
            let binding = fixture.binding(&host_id, "workspace-a").await;
            fixture
                .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
                .await;

            let (pause, mut entered) = HostPause::new();
            let _registration = super::pauses::register(
                fixture.paths.user_root_dir(),
                super::pauses::PausePoint::AfterClaim,
                pause.clone(),
            );
            let _deferred = super::pauses::defer_first_pass(fixture.paths.user_root_dir());
            let host = WorkspaceIntelligenceHost::bootstrap_with_options(
                Arc::clone(&fixture.paths),
                source(),
                WorkspaceIntelligenceHostSurface::Desktop,
                RuntimeDeployment::Embedded,
                options(sleeping()),
            )
            .await;
            let evaluation = tokio::spawn({
                let host = host.clone();
                async move { host.evaluate_for_tests().await }
            });
            tokio::time::timeout(DEADLINE, entered.recv())
                .await
                .expect("the pass must reach the post-claim pause")
                .expect("the pause channel stays open");
            Self {
                host,
                evaluation: Some(evaluation),
                pause,
                scope,
            }
        }

        /// Releases the parked pass and waits for it to finish.
        async fn finish(&mut self) {
            self.pause.release();
            let evaluation = self.evaluation.take().expect("one parked pass");
            tokio::time::timeout(DEADLINE, evaluation)
                .await
                .expect("the parked pass finishes once released")
                .unwrap();
        }
    }

    // A control close after the owner claim committed must not be published: the
    // authority the claim was made under is no longer in force.
    #[tokio::test]
    async fn control_close_after_the_claim_commit_is_never_published() {
        let fixture = Fixture::new().await;
        let mut window = ClaimWindow::open(&fixture).await;
        let scope = window.scope.clone();
        // The claim really is committed and unpublished at this point.
        assert!(fixture.token(&scope).is_some(), "the claim committed before the pause");
        assert!(fixture.lease_is_held(&scope), "the committed claim holds its lease");
        let partitions_at_pause = fixture.sqlite_bytes();
        assert!(!partitions_at_pause.is_empty(), "the claim opened a cognition partition");
        let generation = fixture.control_generation(&scope).await;

        // The real persisted close, through the store's own compare-and-swap.
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(generation),
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(false),
                    ..Default::default()
                },
            )
            .await
            .expect("the close is applied");

        window.finish().await;

        let status = window.host.status().await;
        assert_eq!(
            status.counts().active(),
            0,
            "a claim committed under an authority that has since closed is never published: {status:?}"
        );
        assert!(
            !matches!(
                status.scope_state("workspace-a"),
                Some(WorkspaceIntelligenceHostScopeState::Active)
                    | Some(WorkspaceIntelligenceHostScopeState::Standby)
            ),
            "the refused scope is neither owned nor pending: {status:?}"
        );
        assert!(
            !fixture.lease_is_held(&scope),
            "the dropped claim released its lease, so no tenure survives the refusal"
        );
        assert_eq!(window.host.in_flight_for_tests().await, 0);
        // The host neither rewrote nor deleted the record the owner closed, and it
        // did not touch the owner's own database.
        let record = fixture.control().read(&scope).await.unwrap().unwrap();
        assert_eq!(record.enabled, Some(false), "the host did not reopen the record");
        assert_eq!(record.control_generation, generation + 1, "the close is the only write");
        assert_eq!(
            fixture.sqlite_bytes(),
            partitions_at_pause,
            "the refused publish wrote nothing into the cognition partition"
        );
    }

    // A policy advance after the owner claim committed must not be published: the
    // record stays ON, but the claim was made under the previous policy.
    #[tokio::test]
    async fn policy_generation_advance_after_the_claim_commit_is_never_published() {
        let fixture = Fixture::new().await;
        let mut window = ClaimWindow::open(&fixture).await;
        let scope = window.scope.clone();
        assert!(fixture.token(&scope).is_some(), "the claim committed before the pause");
        assert!(fixture.lease_is_held(&scope), "the committed claim holds its lease");
        let partitions_at_pause = fixture.sqlite_bytes();
        let generation = fixture.control_generation(&scope).await;
        let stored = fixture
            .control()
            .read(&scope)
            .await
            .unwrap()
            .expect("the scope has a control record");
        let mut advanced_policy = stored.policy.clone().expect("the seeded policy is stored");
        advanced_policy["policy_generation_advance"] = json!(1);

        // A real policy advance: the record stays enabled and carries the new value.
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(generation),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(advanced_policy.clone()),
                    ..Default::default()
                },
            )
            .await
            .expect("the policy advance is applied");

        window.finish().await;

        let status = window.host.status().await;
        assert_eq!(
            status.counts().active(),
            0,
            "a claim is never published under a policy it was not made under: {status:?}"
        );
        assert!(
            !matches!(
                status.scope_state("workspace-a"),
                Some(WorkspaceIntelligenceHostScopeState::Active)
                    | Some(WorkspaceIntelligenceHostScopeState::Standby)
            ),
            "the refused scope is neither owned nor pending: {status:?}"
        );
        assert!(
            !fixture.lease_is_held(&scope),
            "the dropped claim released its lease, so no tenure survives the refusal"
        );
        assert_eq!(window.host.in_flight_for_tests().await, 0);
        // The new authority stays exactly as the owner wrote it.
        let record = fixture.control().read(&scope).await.unwrap().unwrap();
        assert_eq!(record.enabled, Some(true), "the record is still on");
        assert_eq!(
            record.policy,
            Some(advanced_policy),
            "the host did not rewrite the advanced policy back"
        );
        assert_eq!(record.control_generation, generation + 1);
        assert_eq!(
            fixture.sqlite_bytes(),
            partitions_at_pause,
            "the refused publish wrote nothing into the cognition partition"
        );
    }

    // A model change alone leaves the raw policy identical, so only the control
    // generation can reveal that the claim was made under an older authority.
    #[tokio::test]
    async fn model_change_after_the_claim_commit_is_never_published() {
        let fixture = Fixture::new().await;
        let mut window = ClaimWindow::open(&fixture).await;
        let scope = window.scope.clone();
        assert!(fixture.token(&scope).is_some(), "the claim committed before the pause");
        let partitions_at_pause = fixture.sqlite_bytes();
        let generation = fixture.control_generation(&scope).await;
        let policy_before = fixture
            .control()
            .read(&scope)
            .await
            .unwrap()
            .expect("the scope has a control record")
            .policy;

        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(generation),
                WorkspaceIntelligenceControlPatch {
                    model_ref: ControlFieldUpdate::Set("model-after-claim".to_owned()),
                    ..Default::default()
                },
            )
            .await
            .expect("the model change is applied");

        window.finish().await;

        let status = window.host.status().await;
        assert_eq!(
            status.counts().active(),
            0,
            "a generation advance with an unchanged policy is still an authority change: {status:?}"
        );
        assert!(
            !fixture.lease_is_held(&scope),
            "the dropped claim released its lease"
        );
        let record = fixture.control().read(&scope).await.unwrap().unwrap();
        assert_eq!(record.policy, policy_before, "the policy is untouched by a model change");
        assert_eq!(record.model_ref.as_deref(), Some("model-after-claim"));
        assert_eq!(
            fixture.sqlite_bytes(),
            partitions_at_pause,
            "the refused publish wrote nothing into the cognition partition"
        );
    }

    // C6+C8: a pass that verified its claims before the drain started must not
    // publish tenure after it. The decision is taken inside the book lock, so the
    // pass can never store a non-empty tenure set that `settle()` may no longer fix.
    #[tokio::test]
    async fn a_pass_that_raced_the_drain_start_never_publishes_tenure() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let control = fixture.control_bytes();

        let (pause, mut entered) = HostPause::new();
        let _registration = super::pauses::register(
            fixture.paths.user_root_dir(),
            super::pauses::PausePoint::BeforeBook,
            pause.clone(),
        );
        // The fixture drives the first pass itself: the handle has to exist while
        // that pass is parked in its publish window, and the bootstrap pass only
        // returns the handle once it finished.
        let _deferred = super::pauses::defer_first_pass(fixture.paths.user_root_dir());
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            // A short drain budget, so the parked pass is reported as a real
            // timeout instead of the fixture waiting the production 12 s.
            options(HostTiming::new(
                Duration::from_millis(5),
                Duration::from_millis(20),
                Duration::from_millis(400),
            )),
        )
        .await;

        let evaluation = tokio::spawn({
            let host = host.clone();
            async move { host.evaluate_for_tests().await }
        });
        tokio::time::timeout(DEADLINE, entered.recv())
            .await
            .expect("the pass must reach the pre-book pause")
            .expect("the pause channel stays open");
        // The pass is parked with a committed claim and an unwritten book, which is
        // exactly the window a drain can race.
        let token = fixture
            .token(&scope)
            .expect("the owner claim committed before the pause");
        let partitions_before = fixture.sqlite_files();

        let shutdown = host.shutdown().await;
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding: 1 },
            "the parked pass is the outstanding owner work"
        );
        // No status assertion here: this fixture never lets a pass write the book
        // before the pause, so `active() == 0` above the release holds even with the
        // teardown logic removed. The load-bearing assertions are the post-release
        // ones below, where the pass has actually run its book write.

        pause.release();
        tokio::time::timeout(DEADLINE, evaluation)
            .await
            .expect("the parked pass finishes once released")
            .unwrap();

        let after = host.status().await;
        assert!(!host.has_standby_worker_for_tests().await,
            "the pass that released its tenure must not have spawned a wake-up task: {after:?}");
        assert_eq!(after.state(), WorkspaceIntelligenceHostState::Draining);
        assert_eq!(
            after.counts().active(),
            0,
            "the raced claim is not retained in the DrainTimedOut branch: {after:?}"
        );
        assert!(
            after
                .scopes()
                .iter()
                .all(|report| report.state()
                    != WorkspaceIntelligenceHostScopeState::Active),
            "no scope row may keep claiming active: {after:?}"
        );
        assert_eq!(host.in_flight_for_tests().await, 0);
        assert_eq!(fixture.control_bytes(), control, "the ON record is byte-identical");
        assert_eq!(
            fixture.token(&scope).as_deref(),
            Some(token.as_str()),
            "the committed incarnation is never rolled back"
        );
        assert_eq!(fixture.sqlite_files(), partitions_before, "no new cognition partition");
    }

    // C8: a claim this pass has just published is dropped when a drain starts before
    // the book write. The pass is parked at the last statement before that lock, so
    // the publish decision above the lock is not the authority and any snapshot of
    // the stop flag taken there is stale by construction: the in-lock read is what
    // clears the tenure, demotes the row, releases the lease and leaves no wake-up
    // task behind.
    #[tokio::test]
    async fn a_drain_starting_before_the_book_write_never_publishes_that_claim() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let control = fixture.control_bytes();

        let (pause, mut entered) = HostPause::new();
        let _registration = super::pauses::register(
            fixture.paths.user_root_dir(),
            super::pauses::PausePoint::AtBookLock,
            pause.clone(),
        );
        let _deferred = super::pauses::defer_first_pass(fixture.paths.user_root_dir());
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            // A short drain budget, so the parked pass is reported as a real timeout
            // instead of the fixture waiting the production 12 s.
            options(HostTiming::new(
                Duration::from_millis(5),
                Duration::from_millis(20),
                Duration::from_millis(300),
            )),
        )
        .await;

        let evaluation = tokio::spawn({
            let host = host.clone();
            async move { host.evaluate_for_tests().await }
        });
        tokio::time::timeout(DEADLINE, entered.recv())
            .await
            .expect("the pass must reach the pre-lock pause")
            .expect("the pause channel stays open");
        // Above the lock the pass has already accepted this claim: it passed the
        // catalog re-read and the control recheck, so only the in-lock read can still
        // drop it. That is exactly the case under test.
        let token = fixture
            .token(&scope)
            .expect("the owner claim committed before the pause");
        assert!(fixture.lease_is_held(&scope), "the accepted claim holds its lease");
        let partitions_before = fixture.sqlite_bytes();

        // The drain runs to its own budget while the pass is parked, so the reported
        // outcome is a timeout with real outstanding owner work, not a fabricated one.
        let shutdown = host.shutdown().await;
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding: 1 },
            "the parked pass is the outstanding owner work"
        );
        assert_eq!(
            shutdown.state(),
            WorkspaceIntelligenceHostState::Draining,
            "a timed-out drain stays incomplete, never stopped"
        );

        pause.release();
        tokio::time::timeout(DEADLINE, evaluation)
            .await
            .expect("the parked pass finishes once released")
            .unwrap();

        let after = host.status().await;
        assert_eq!(
            after.counts().active(),
            0,
            "the claim published just before the drain is not retained: {after:?}"
        );
        // The row exists and is demoted, which is what proves the pass reached the
        // lock holding an `active` row: a stale snapshot would have left it `Active`.
        assert_eq!(
            after.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::ClaimRefused
            )),
            "the parked pass demoted its own tenure instead of publishing it: {after:?}"
        );
        assert_eq!(
            after.state(),
            WorkspaceIntelligenceHostState::Draining,
            "the teardown state always wins and is never promoted to stopped here"
        );
        // A demoted row is a blocked row, so its typed block phase must agree with
        // its state: a consumer switching on `block()` would otherwise read this
        // blocked row as unblocked.
        assert_eq!(
            after
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            Some(WorkspaceIntelligenceHostBlock::Transient),
            "the demoted row reports a transient block, never `None`: {after:?}"
        );
        assert!(
            !host.has_standby_worker_for_tests().await,
            "no wake-up task is created for a draining host: {after:?}"
        );
        assert_eq!(host.in_flight_for_tests().await, 0);
        // The cleared claim released its own lease. Nothing was rolled back: the
        // owner's record, incarnation and database are exactly as they were.
        assert!(
            !fixture.lease_is_held(&scope),
            "the dropped claim released its lease"
        );
        assert_eq!(fixture.control_bytes(), control, "the ON record is byte-identical");
        assert_eq!(
            fixture.token(&scope).as_deref(),
            Some(token.as_str()),
            "the committed incarnation is never rolled back"
        );
        assert_eq!(
            fixture.sqlite_bytes(),
            partitions_before,
            "the dropped publish wrote nothing into the cognition partition"
        );
    }
    // R5: the latch must not be defeated by the live facts reverting. A detected
    // binding change is latched at the generation it was detected under, so the
    // scope stays refused even once the persisted projection is restored and the
    // live catalog matches the stored binding again.
    #[tokio::test]
    async fn a_detected_binding_change_stays_blocked_after_the_live_catalog_reverts_at_the_same_generation(
    ) {
        let fixture = Fixture::new().await;
        let original = local_record(&fixture, "workspace-a", "a");
        fixture.publish(vec![original.clone()]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let generation = fixture.control_generation(&scope).await;
        let control = fixture.control_bytes();

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        assert_eq!(
            host.status().await.state(),
            WorkspaceIntelligenceHostState::Active,
            "the seeded projection is claimed"
        );

        // 1. A real owner write changes the persisted worktree projection.
        fixture
            .publish(vec![main_record(&fixture, "workspace-a", "a")])
            .await;
        host.evaluate_for_tests().await;
        let changed = host.status().await;
        assert_eq!(
            changed.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "the projection change is detected: {changed:?}"
        );
        assert_eq!(changed.counts().active(), 0, "no tenure over a changed binding");
        assert_eq!(
            changed.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::BindingChanged
            )),
            "the row keeps the reason it was refused for"
        );
        assert_eq!(
            changed
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            Some(WorkspaceIntelligenceHostBlock::AwaitingNewAuthority),
            "the row is latched, not merely blocked for this pass"
        );
        let latched_leases = fixture.lock_files();

        // 2. The same owner path restores the original projection. The control
        //    generation is untouched, so no new authority was written.
        fixture.publish(vec![original]).await;
        let restored = catalog_readonly::read_persisted_catalog(&fixture.paths)
            .await
            .unwrap();
        assert_eq!(
            restored
                .workspace("workspace-a")
                .expect("still eligible")
                .worktree_is_main(),
            None,
            "the owner write really restored the persisted projection"
        );
        assert_eq!(
            fixture.control_generation(&scope).await,
            generation,
            "the revert did not advance the generation"
        );

        for pass in 0..3 {
            host.evaluate_for_tests().await;
            let status = host.status().await;
            assert_eq!(
                status.reason(),
                Some(WorkspaceIntelligenceHostReason::BindingChanged),
                "pass {pass}: the latch survives the revert: {status:?}"
            );
            assert_eq!(
                status.counts().active(),
                0,
                "pass {pass}: a reverted catalog never re-opens a latched scope"
            );
            assert_eq!(
                status.scope_state("workspace-a"),
                Some(WorkspaceIntelligenceHostScopeState::Blocked(
                    WorkspaceIntelligenceHostReason::BindingChanged
                )),
                "pass {pass}: the row stays blocked"
            );
        }
        assert_eq!(
            fixture.lock_files(),
            latched_leases,
            "no new lease is taken while latched"
        );
        assert_eq!(
            fixture.control_bytes(),
            control,
            "the persisted ON record is never rewritten"
        );
    }

    // R5: the latched scope recovers only through an explicit new authority whose
    // stored binding matches the live facts.
    #[tokio::test]
    async fn an_explicit_new_binding_at_a_new_generation_recovers_the_scope() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        assert_eq!(host.status().await.state(), WorkspaceIntelligenceHostState::Active);

        // The owner as an explicit new authority is the writer that mints the
        // binding, so this is the exact shape a recovered scope must have.
        fixture
            .publish(vec![main_record(&fixture, "workspace-a", "a")])
            .await;
        host.evaluate_for_tests().await;
        let latched = host.status().await;
        assert_eq!(
            latched.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "the change is latched: {latched:?}"
        );
        let latched_generation = fixture.control_generation(&scope).await;

        // A revert of the live facts at the same generation leaves the scope
        // blocked: without that, this test would pass on a host with no latch at
        // all, because the mismatching catalog alone explains the block.
        fixture
            .publish(vec![local_record(&fixture, "workspace-a", "a")])
            .await;
        host.evaluate_for_tests().await;
        assert_eq!(
            host.status().await.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "the reverted live facts do not clear the latch"
        );
        assert_eq!(host.status().await.counts().active(), 0);

        // A generation advance that still does not match must NOT clear the latch.
        // The payload really differs from the stored one, so this write advances the
        // generation; only the binding it carries is wrong, and generation equality
        // is not what recovers a scope.
        let mut stale = Fixture::bound_policy(&binding);
        stale["execution_binding"]["worktree_is_main"] = json!(true);
        stale["domains"]["memory"]["enabled"] = json!(false);
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(latched_generation),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(stale),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            fixture.control_generation(&scope).await > latched_generation,
            "the stale write still advanced the generation"
        );
        host.evaluate_for_tests().await;
        assert_eq!(
            host.status().await.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "a newer generation alone does not recover a still-mismatching binding"
        );
        assert_eq!(host.status().await.counts().active(), 0);

        // The real explicit new authority: a generation advance carrying the
        // binding that matches the live facts.
        let current = fixture.binding(&host_id, "workspace-a").await;
        let advanced = fixture.control_generation(&scope).await;
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(advanced),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(Fixture::bound_policy(&current)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(
            fixture.control_generation(&scope).await > latched_generation,
            "the explicit write advanced the generation: latched={latched_generation} now={}",
            fixture.control_generation(&scope).await
        );

        host.evaluate_for_tests().await;
        let recovered = host.status().await;
        assert_eq!(
            recovered.state(),
            WorkspaceIntelligenceHostState::Active,
            "the new authority recovers the scope: {recovered:?}"
        );
        assert_eq!(recovered.counts().active(), 1);
        assert_eq!(
            recovered
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            None,
            "a recovered row is no longer latched"
        );
        assert_eq!(
            recovered.reason(),
            None,
            "nothing is blocked once the scope recovered"
        );
    }

    // R5: a binding hand-patched into the SAME generation is not an authority
    // write, so it never auto-adopts an unverified scope.
    #[tokio::test]
    async fn a_same_generation_binding_patch_never_auto_adopts_an_unverified_scope() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        fixture.seed_control(&scope, true, None).await;
        let generation = fixture.control_generation(&scope).await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let unverified = host.status().await;
        assert_eq!(
            unverified.reason(),
            Some(WorkspaceIntelligenceHostReason::Unverified),
            "an enabled record with no binding is unverified: {unverified:?}"
        );
        assert_eq!(
            unverified
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            Some(WorkspaceIntelligenceHostBlock::AwaitingNewAuthority),
            "the unverified scope is latched"
        );

        // Hand-patch a matching binding into the SAME generation: no CAS write,
        // no generation advance, so it is not an authoritative statement.
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture.patch_policy_same_generation(Fixture::bound_policy(&binding));
        assert_eq!(
            fixture.control_generation(&scope).await,
            generation,
            "the hand patch left the generation untouched"
        );

        for pass in 0..3 {
            host.evaluate_for_tests().await;
            let status = host.status().await;
            assert_eq!(
                status.reason(),
                Some(WorkspaceIntelligenceHostReason::Unverified),
                "pass {pass}: a same-generation patch never adopts the scope: {status:?}"
            );
            assert_eq!(
                status.counts().active(),
                0,
                "pass {pass}: the scope is never claimed"
            );
            assert!(fixture.token(&scope).is_none(), "pass {pass}: no incarnation");
            assert!(
                fixture.lock_files().is_empty(),
                "pass {pass}: no lease is ever taken"
            );
        }

        // The same binding at a NEW generation is the explicit authority that does
        // recover it, which proves the latch was waiting for that and nothing else.
        // The binding value is already stored, so the advance is carried by the
        // model reference: a `Set` of an identical policy is a no-op and would leave
        // the generation untouched.
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(generation),
                WorkspaceIntelligenceControlPatch {
                    model_ref: ControlFieldUpdate::Set("wi-explicit-authority".to_owned()),
                    policy: ControlFieldUpdate::Set(Fixture::bound_policy(&binding)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(fixture.control_generation(&scope).await > generation);

        host.evaluate_for_tests().await;
        let recovered = host.status().await;
        assert_eq!(
            recovered.state(),
            WorkspaceIntelligenceHostState::Active,
            "the generation advance recovers the scope: {recovered:?}"
        );
        assert_eq!(recovered.counts().active(), 1);
    }

    // R5: an eligibility blip is a catalog write that does not advance the control
    // generation, so it is not a new authority. A latched scope that drops out of
    // the eligible set and comes back must stay latched; otherwise the blip would
    // be a way to reach a claim at the generation the latch was set under.
    #[tokio::test]
    async fn a_latched_scope_keeps_its_latch_across_an_eligibility_blip() {
        let fixture = Fixture::new().await;
        let parent = main_record(&fixture, "workspace-p", "p");
        let child = child_record(&fixture, "workspace-a", "workspace-p", "a");
        fixture
            .publish(vec![parent.clone(), child.clone()])
            .await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        assert_eq!(
            binding.worktree_is_main(),
            Some(false),
            "the seeded child carries its observed worktree facts"
        );
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let generation = fixture.control_generation(&scope).await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        assert_eq!(
            host.status().await.scope_state("workspace-a"),
            Some(WorkspaceIntelligenceHostScopeState::Active),
            "the seeded child is claimed"
        );

        // Latch it: a real owner write changes one observed worktree fact while the
        // record stays an eligible child.
        let mut changed = child.clone();
        changed["worktree"]["mainRepoPath"] = json!(
            fixture
                .dir
                .path()
                .join("other-main-repo")
                .to_string_lossy()
                .to_string()
        );
        fixture.publish(vec![parent.clone(), changed]).await;
        host.evaluate_for_tests().await;
        let latched = host.status().await;
        assert_eq!(
            latched.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "the child is latched: {latched:?}"
        );
        assert_eq!(
            latched
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            Some(WorkspaceIntelligenceHostBlock::AwaitingNewAuthority)
        );
        // The incarnation the legitimate first claim committed stays as it is: a
        // block is not a rollback. It is therefore the baseline for proving that no
        // LATER claim commits a new one.
        let token_after_latch = fixture.token(&scope);
        assert!(
            token_after_latch.is_some(),
            "the earlier granted claim left its incarnation in place"
        );

        // The blip: the parent record disappears, so the child becomes
        // `UnresolvedWorktreeParent` and is no longer eligible. The control record is
        // untouched, so this is not a new authority.
        fixture.publish(vec![child.clone()]).await;
        host.evaluate_for_tests().await;
        assert_eq!(
            fixture.control_generation(&scope).await,
            generation,
            "the blip did not advance the generation"
        );
        let during_blip = host.status().await;
        assert_eq!(
            during_blip.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged),
            "the ineligible scope still reports the reason it was latched for: {during_blip:?}"
        );
        assert_eq!(
            during_blip
                .scopes()
                .iter()
                .find(|report| report.scope() == "workspace-a")
                .and_then(|report| report.block()),
            Some(WorkspaceIntelligenceHostBlock::AwaitingNewAuthority),
            "the blip does not present the scope as plainly unsupported: {during_blip:?}"
        );

        // The parent returns and the live facts are reverted to exactly the stored
        // binding, still at the same generation. Without a carried latch this is the
        // pass that reaches `Present(_) => {}` and claims at the latched generation.
        fixture.publish(vec![parent, child]).await;
        let restored = catalog_readonly::read_persisted_catalog(&fixture.paths)
            .await
            .unwrap();
        assert_eq!(
            restored
                .workspace("workspace-a")
                .expect("eligible again")
                .main_repo_path(),
            binding.main_repo_path(),
            "the restored record matches the stored binding exactly"
        );

        // A lease file left by the earlier claim stays on disk; what matters is that
        // no tenure is HELD and no further lease file appears.
        assert!(
            !fixture.lease_is_held(&scope),
            "the latched scope holds no owner tenure"
        );
        let lease_files_after_latch = fixture.lock_files();

        for pass in 0..3 {
            host.evaluate_for_tests().await;
            let status = host.status().await;
            assert_eq!(
                status.scope_state("workspace-a"),
                Some(WorkspaceIntelligenceHostScopeState::Blocked(
                    WorkspaceIntelligenceHostReason::BindingChanged
                )),
                "pass {pass}: the carried latch still refuses the scope: {status:?}"
            );
            assert_eq!(
                status.counts().active(),
                0,
                "pass {pass}: no claim is made at the latched generation"
            );
            assert!(
                fixture.token(&scope) == token_after_latch,
                "pass {pass}: no new incarnation is committed"
            );
            assert!(
                !fixture.lease_is_held(&scope),
                "pass {pass}: no lease is taken"
            );
            assert_eq!(
                fixture.lock_files(),
                lease_files_after_latch,
                "pass {pass}: no lease file appears"
            );
        }
    }


    // Liveness: an unverified scope is never auto-adopted, but an explicit new
    // authority written with no catalog event must still be observed.
    #[tokio::test]
    async fn an_unverified_scope_is_re_evaluated_after_an_explicit_binding_write() {
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        fixture.seed_control(&scope, true, None).await;

        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(fast()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::Unverified)
        );
        assert_eq!(status.counts().active(), 0, "absence of a binding is not adopted");
        assert!(
            host.has_standby_worker_for_tests().await,
            "an enabled scope keeps the bounded fallback alive"
        );

        // No catalog event happens here: only the control generation advances.
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .control()
            .update(
                &scope,
                ControlGenerationExpectation::Exactly(1),
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(Fixture::bound_policy(&binding)),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            if host.status().await.counts().active() == 1 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the fallback must re-read the control generation"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(fixture.token(&scope).is_some(), "the explicit binding is claimed");
    }

    // 10
    #[tokio::test]
    async fn profile_gates_are_exhaustive_and_typed() {
        use WorkspaceIntelligenceHostSurface as Surface;
        use WorkspaceIntelligenceHostUnsupportedProfile as Unsupported;

        let surfaces = [
            Surface::Desktop,
            Surface::CliInteractive,
            Surface::CliExecution,
            Surface::ServerLoopback,
            Surface::ServerStdio,
            Surface::Daemon,
            Surface::DetachedDispatch,
            Surface::Management,
            Surface::SharedRuntime,
            Surface::Acp,
            Surface::SdkHostApp,
            Surface::PeerController,
        ];
        let deployments = [RuntimeDeployment::Embedded, RuntimeDeployment::Shared];
        let mut allowed = Vec::new();
        for surface in surfaces {
            for deployment in deployments {
                if profile_support(surface, deployment).is_ok() {
                    allowed.push((surface, deployment));
                }
            }
        }
        assert_eq!(
            allowed,
            vec![
                (Surface::Desktop, RuntimeDeployment::Embedded),
                (Surface::CliInteractive, RuntimeDeployment::Embedded),
                (Surface::CliExecution, RuntimeDeployment::Embedded),
                (Surface::ServerLoopback, RuntimeDeployment::Embedded),
            ]
        );
        // `Shared` means a shared runtime owns the scope and has not drained it.
        // No surface may admit such a scope, so the refusal is total; the reason is
        // the deployment's own unless the surface is refused for a stronger,
        // surface-specific delivery reason.
        for surface in surfaces {
            let outcome = profile_support(surface, RuntimeDeployment::Shared);
            assert!(
                outcome.is_err(),
                "{surface:?} must reject a shared deployment"
            );
            if profile_support(surface, RuntimeDeployment::Embedded).is_ok() {
                assert_eq!(
                    outcome,
                    Err(Unsupported::SharedRuntime),
                    "{surface:?} admits an embedded runtime, so its shared refusal is the deployment"
                );
            }
        }
        // `Daemon` is refused by its delivery, not by the deployment: the typed
        // reason is what the CLI renders as Install/Skip, never UI copy here.
        assert_eq!(
            profile_support(Surface::Daemon, RuntimeDeployment::Embedded),
            Err(Unsupported::Daemon)
        );
        assert_eq!(
            profile_support(Surface::SharedRuntime, RuntimeDeployment::Embedded),
            Err(Unsupported::SharedRuntime)
        );
        assert_eq!(
            profile_support(Surface::ServerStdio, RuntimeDeployment::Embedded),
            Err(Unsupported::ServerStdio)
        );

        // An unsupported profile bootstraps nothing at all.
        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let before = fixture.tree_hash();
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            Surface::Daemon,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::ProfileUnsupported(
                Unsupported::Daemon
            ))
        );
        assert!(!status.anchor_present());
        assert!(!host.has_standby_worker_for_tests().await);
        assert!(fixture.lock_files().is_empty());
        assert!(!fixture.cognition_dir().exists());
        assert_eq!(fixture.tree_hash(), before, "an unsupported profile writes nothing");
    }

    // 11
    #[tokio::test]
    async fn two_processes_have_exactly_one_active_and_one_standby() {
        const CHILD_USER_ROOT: &str = "OPENBITFUN_WI_HOST_CHILD_USER_ROOT";
        const CHILD_SYNC: &str = "OPENBITFUN_WI_HOST_CHILD_SYNC";
        const CHILD_ROLE: &str = "OPENBITFUN_WI_HOST_CHILD_ROLE";

        struct Child(std::process::Child);

        impl Drop for Child {
            fn drop(&mut self) {
                // Kills only this fixture's own children.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        fn spawn_child(user_root: &Path, sync: &Path, role: &str) -> Child {
            let mut command =
                openbitfun_services_core::process_manager::create_command(std::env::current_exe().unwrap());
            Child(
                command
                    .args([
                        "--exact",
                        "service::workspace_intelligence::host::tests::host_process_fixture",
                        "--nocapture",
                    ])
                    .env(CHILD_USER_ROOT, user_root)
                    .env(CHILD_SYNC, sync)
                    .env(CHILD_ROLE, role)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        async fn wait_marker(path: &Path) -> String {
            let deadline = tokio::time::Instant::now() + DEADLINE;
            loop {
                if let Ok(text) = tokio::fs::read_to_string(path).await {
                    return text;
                }
                assert!(tokio::time::Instant::now() < deadline, "marker deadline: {}", path.display());
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let anchor_before = fixture.anchor_bytes();

        let sync = fixture.dir.path().join("sync");
        std::fs::create_dir_all(&sync).unwrap();
        let user_root = fixture.paths.user_root_dir().to_path_buf();
        let mut children = [
            spawn_child(&user_root, &sync, "a"),
            spawn_child(&user_root, &sync, "b"),
        ];
        wait_marker(&sync.join("a.ready")).await;
        wait_marker(&sync.join("b.ready")).await;
        tokio::fs::write(sync.join("start.ready"), b"start").await.unwrap();
        let outcomes = [wait_marker(&sync.join("a.outcome")).await, wait_marker(&sync.join("b.outcome")).await];
        assert_eq!(
            outcomes.iter().filter(|outcome| *outcome == "active").count(),
            1,
            "exactly one process owns the scope: {outcomes:?}"
        );
        assert_eq!(
            outcomes.iter().filter(|outcome| *outcome == "standby").count(),
            1,
            "exactly one process is standby: {outcomes:?}"
        );
        assert_eq!(fixture.anchor_bytes(), anchor_before, "children never rewrite the anchor");
        assert!(fixture.token(&scope).is_some(), "the winner minted one claim");

        tokio::fs::write(sync.join("release.ready"), b"release").await.unwrap();
        let deadline = tokio::time::Instant::now() + DEADLINE;
        for child in &mut children {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(tokio::time::Instant::now() < deadline, "child exit deadline");
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
    }

    /// Child process body of [`two_processes_have_exactly_one_active_and_one_standby`].
    #[tokio::test]
    async fn host_process_fixture() {
        const CHILD_USER_ROOT: &str = "OPENBITFUN_WI_HOST_CHILD_USER_ROOT";
        const CHILD_SYNC: &str = "OPENBITFUN_WI_HOST_CHILD_SYNC";
        const CHILD_ROLE: &str = "OPENBITFUN_WI_HOST_CHILD_ROLE";
        let Some(user_root) = std::env::var_os(CHILD_USER_ROOT) else {
            return;
        };
        let sync = PathBuf::from(std::env::var_os(CHILD_SYNC).unwrap());
        let role = std::env::var(CHILD_ROLE).unwrap();
        let paths = Arc::new(PathManager::with_user_root_for_tests(PathBuf::from(user_root)));
        tokio::fs::write(sync.join(format!("{role}.ready")), b"ready").await.unwrap();
        let deadline = tokio::time::Instant::now() + DEADLINE;
        while !sync.join("start.ready").exists() {
            assert!(tokio::time::Instant::now() < deadline, "start deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            paths,
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(sleeping()),
        )
        .await;
        let status = host.status().await;
        tokio::fs::write(
            sync.join(format!("{role}.outcome")),
            if status.counts().active() > 0 {
                "active"
            } else if status.counts().standby() > 0 {
                "standby"
            } else {
                status.state().code()
            },
        )
        .await
        .unwrap();
        while !sync.join("release.ready").exists() {
            assert!(tokio::time::Instant::now() < deadline, "release deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        host.shutdown().await;
    }

    // T-A: another process rewrites the persisted registry and this host, which has
    // no watch hint at all, must still refuse the stale tenure.
    #[tokio::test]
    async fn a_cross_process_registry_rewrite_is_detected_without_any_watch_hint() {
        const CHILD_BASE: &str = "OPENBITFUN_WI_HOST_REWRITE_BASE";
        const CHILD_SYNC: &str = "OPENBITFUN_WI_HOST_REWRITE_SYNC";

        struct Child(std::process::Child);

        impl Drop for Child {
            fn drop(&mut self) {
                // Kills only this fixture's own child.
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        let fixture = Fixture::new().await;
        fixture.publish(vec![local_record(&fixture, "workspace-a", "a")]).await;
        let host_id = fixture.anchor().await;
        let scope = fixture.scope(&host_id, "workspace-a");
        let binding = fixture.binding(&host_id, "workspace-a").await;
        fixture
            .seed_control(&scope, true, Some(Fixture::bound_policy(&binding)))
            .await;
        let control = fixture.control_bytes();
        let registry_before = std::fs::read(fixture.registry_path()).unwrap();

        // `source()` carries NO revision hint, so no watch event can exist for this
        // rewrite, and `fast()` timing makes the coarse fallback the thing that
        // notices it.
        let host = WorkspaceIntelligenceHost::bootstrap_with_options(
            Arc::clone(&fixture.paths),
            source(),
            WorkspaceIntelligenceHostSurface::Desktop,
            RuntimeDeployment::Embedded,
            options(fast()),
        )
        .await;
        let status = host.status().await;
        assert_eq!(status.counts().active(), 1, "this host owns the scope first");
        let leases = fixture.lock_files();
        let partitions = fixture.sqlite_files();
        assert_eq!(leases.len(), 1, "one lease for the one owned scope");
        assert!(!partitions.is_empty(), "an owned scope has a cognition partition");

        let sync = fixture.dir.path().join("rewrite-sync");
        std::fs::create_dir_all(&sync).unwrap();
        let mut child = Child(
            openbitfun_services_core::process_manager::create_command(
                std::env::current_exe().unwrap(),
            )
            .args([
                "--exact",
                "service::workspace_intelligence::host::tests::host_registry_rewrite_fixture",
                "--nocapture",
            ])
            .env(CHILD_BASE, fixture.dir.path())
            .env(CHILD_SYNC, &sync)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap(),
        );
        assert_eq!(await_marker(&sync.join("rewritten")).await, "rewritten");

        // The negative that matters: the child really changed the registry on disk.
        // The parent re-reads it through the owner decoder and sees the new facts.
        let rewritten = catalog_readonly::read_persisted_catalog(&fixture.paths)
            .await
            .unwrap();
        let workspace = rewritten
            .workspace("workspace-a")
            .expect("the rewritten record stays eligible");
        assert!(
            workspace.is_worktree_child(),
            "the child process rewrote the persisted workspace facts"
        );
        assert_eq!(workspace.worktree_parent_id(), Some("parent-workspace"));
        assert_ne!(
            std::fs::read(fixture.registry_path()).unwrap(),
            registry_before,
            "the registry bytes on disk really changed"
        );

        // No explicit pass and no hint: the bounded fallback must re-read the
        // registry and refuse the tenure it can no longer prove.
        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            let status = host.status().await;
            if status.scope_state("workspace-a")
                == Some(WorkspaceIntelligenceHostScopeState::Blocked(
                    WorkspaceIntelligenceHostReason::BindingChanged,
                ))
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the fallback must re-read the registry with no hint: {status:?}"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let status = host.status().await;
        assert_eq!(status.counts().active(), 0, "the stale tenure is not counted active");
        assert_eq!(status.counts().standby(), 0, "no new claim is attempted");
        assert_eq!(status.state(), WorkspaceIntelligenceHostState::Unavailable);
        assert_eq!(
            status.reason(),
            Some(WorkspaceIntelligenceHostReason::BindingChanged)
        );
        let debug = format!("{status:?}");
        assert!(
            !debug.contains(&scope),
            "status is keyed by the workspace id, never the scope string: {debug}"
        );
        assert!(
            !debug.contains(anchor_suffix(&host_id)),
            "no anchor suffix in status data either: {debug}"
        );
        assert_eq!(
            fixture.control_bytes(),
            control,
            "the persisted ON record is byte-for-byte untouched"
        );
        assert_eq!(fixture.lock_files(), leases, "no new lease file appears");
        assert_eq!(
            fixture.sqlite_files(),
            partitions,
            "no new cognition partition appears"
        );

        let deadline = tokio::time::Instant::now() + DEADLINE;
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "the child process wrote the registry and exited");
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "child exit deadline");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        host.shutdown().await;
    }

    /// Child process body of [`a_cross_process_registry_rewrite_is_detected_without_any_watch_hint`].
    ///
    /// It rewrites the shared user root's persisted registry through the real
    /// persistence owner: same key, same product identity, typed records.
    #[tokio::test]
    async fn host_registry_rewrite_fixture() {
        const CHILD_BASE: &str = "OPENBITFUN_WI_HOST_REWRITE_BASE";
        const CHILD_SYNC: &str = "OPENBITFUN_WI_HOST_REWRITE_SYNC";
        let Some(base) = std::env::var_os(CHILD_BASE) else {
            return;
        };
        let base = PathBuf::from(base);
        let sync = PathBuf::from(std::env::var_os(CHILD_SYNC).unwrap());
        let paths = PathManager::with_user_root_for_tests(base.join("user"));
        save_registry(
            &paths,
            vec![
                local_record_at(&base, "parent-workspace", "parent"),
                child_record_at(&base, "workspace-a", "parent-workspace", "child"),
            ],
        )
        .await;
        tokio::fs::write(sync.join("rewritten"), b"rewritten").await.unwrap();
    }

    // 12
    #[test]
    fn frozen_governed_enums_are_symbol_stable() {
        // Compile-checked exhaustive matches with no wildcard arm: a new variant
        // in the services owner fails here instead of silently changing a code.
        fn claim_refusal_code(refusal: &GovernedClaimRefusal) -> &'static str {
            match refusal {
                GovernedClaimRefusal::ForeignSnapshot => "foreign_snapshot",
                GovernedClaimRefusal::ForeignBinding => "foreign_binding",
                GovernedClaimRefusal::NotObserved => "not_observed",
                GovernedClaimRefusal::NotEnabled => "not_enabled",
                GovernedClaimRefusal::AuthorityChanged => "authority_changed",
                GovernedClaimRefusal::StaleIncarnation => "stale_incarnation",
            }
        }
        fn commit_refusal_code(refusal: &GovernedCommitRefusal) -> &'static str {
            match refusal {
                GovernedCommitRefusal::ForeignSnapshot => "foreign_snapshot",
                GovernedCommitRefusal::NotObserved => "not_observed",
                GovernedCommitRefusal::AuthorityChanged => "authority_changed",
                GovernedCommitRefusal::NotEnabled => "not_enabled",
            }
        }
        fn outcome_name(outcome: &GovernedCommitOutcome) -> &'static str {
            match outcome {
                GovernedCommitOutcome::Committed { .. } => "committed",
                GovernedCommitOutcome::Refused(_) => "refused",
            }
        }

        let claim_refusals = [
            GovernedClaimRefusal::ForeignSnapshot,
            GovernedClaimRefusal::ForeignBinding,
            GovernedClaimRefusal::NotObserved,
            GovernedClaimRefusal::NotEnabled,
            GovernedClaimRefusal::AuthorityChanged,
            GovernedClaimRefusal::StaleIncarnation,
        ];
        let mut claim_codes: Vec<String> = claim_refusals
            .iter()
            .map(|refusal| {
                assert_eq!(refusal.code(), claim_refusal_code(refusal));
                refusal.code().to_owned()
            })
            .collect();
        claim_codes.sort();
        assert_eq!(
            claim_codes,
            vec![
                "authority_changed",
                "foreign_binding",
                "foreign_snapshot",
                "not_enabled",
                "not_observed",
                "stale_incarnation",
            ]
        );

        let commit_refusals = [
            GovernedCommitRefusal::ForeignSnapshot,
            GovernedCommitRefusal::NotObserved,
            GovernedCommitRefusal::AuthorityChanged,
            GovernedCommitRefusal::NotEnabled,
        ];
        let mut commit_codes: Vec<String> = commit_refusals
            .iter()
            .map(|refusal| {
                assert_eq!(refusal.code(), commit_refusal_code(refusal));
                refusal.code().to_owned()
            })
            .collect();
        commit_codes.sort();
        assert_eq!(
            commit_codes,
            vec![
                "authority_changed",
                "foreign_snapshot",
                "not_enabled",
                "not_observed",
            ]
        );

        let refused = GovernedCommitOutcome::Refused(GovernedCommitRefusal::NotEnabled);
        assert_eq!(outcome_name(&refused), "refused");
        // `Committed` needs owner results a fixture must not fabricate; the
        // exhaustive match above already pins both variant names at compile time.
    }
}
