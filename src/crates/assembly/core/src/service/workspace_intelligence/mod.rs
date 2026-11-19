//! Workspace intelligence tier derivation (P0) and internal control assembly
//! (P1 core control slice: WP1.1 core assembly + WP1.2a control-vs-control).
//!
//! Phase 0 holds the pure, side-effect-free parts of the workspace intelligence
//! control contract: `mode` derives the tier from control facts, and
//! `read_contract` projects a persisted control record without writing,
//! repairing, or reorganizing it. No storage, IO, background work, or model
//! resolution lives here.
//!
//! The feature-free `scope` module holds the host and workspace scope value types
//! and their single injective storage encoding. The `policy` module adds the pure,
//! fail-closed policy projection and merge rules. The feature-gated `control`
//! module adds the internal control handle over the authoritative store's own
//! compare-and-swap. The feature-gated `partition` module adds the internal
//! cognition partition handle over the authoritative per-scope partition store.
//!
//! The P0/P1 control and cognition slices are internal and have no production
//! caller, no app entry point of their own, no legacy confirmation gate, UI,
//! command, registry or capability. The gated `host` facade re-exported at the end
//! of this module is the only app-facing entry point, and no in-tree composition
//! root calls it yet. A real enable
//! later must pass the P2.4/P3 gate; nothing here turns workspace intelligence
//! on, and no product feature selects `workspace-intelligence-control`.
//!
//! The `partition` slice itself adds no claim, cursor consumption or policy.
//! It persists only the partition root and the
//! `partition_state` shape, it is not selected by `default`, `product-full` or
//! `agent-runtime`, and a future real narrow consumer must select
//! `workspace-intelligence-cognition` explicitly in its own manifest.
//!
//! The gated `commit` module adds the internal governed owner-commit wrapper over
//! the services fence. It recovers the cognition partition of an already-enabled
//! scope only: no bootstrap/claim, no OFF-to-ON enabling path, and no model
//! resolution. It is not selected by `default`, `product-full` or `agent-runtime`.
//!
//! The gated `claim` module wraps the services owner-claim lifecycle for an
//! already-enabled scope: one OS lease per scope, a transactional incarnation
//! marker, and read-only tenure verification. It is NOT a WP1.4 exit and NOT a
//! P1 exit. There is still no app bootstrap, first enable, `allow_off`, host
//! identity source, execution-binding change detection, Shared-profile gate,
//! pending cursor, revision/epoch, model run, background task or registry.
//! It is not selected by `default`, `product-full` or `agent-runtime`.
//!
//! The unconditional `host` module is the workspace intelligence host handle:
//! bootstrap over one owner-decoded persisted catalog, per-scope lease tenure, a
//! typed status snapshot and a bounded shutdown. It is unconditional so
//! that a build without the feature can answer `NotCompiled` instead of
//! failing to link or silently reporting success. Its handle, its three entry
//! points and the plain status data around them are re-exported at the end of
//! this module as the one app-facing surface of this tree; every other type here
//! stays crate-internal. The `catalog_readonly` module
//! (read-only persisted registry snapshot), the `host_binding` module (execution
//! binding resolution) and the `host_standby` module (bounded fallback wake-up)
//! are gated on `workspace-intelligence-host` together with the rest of the host
//! slice.
//!
//! This is neither a WP1.4 nor a P1 exit: it adds no first enable, no
//! `allow_off`, no pending cursor, no content mutation, no model run, no Tauri
//! command, no Product Operation Registry row and no UI. `bootstrap` returns a
//! handle nobody promotes yet; a real enable later must pass the P2.4/P3 gate.
//! Nothing here is selected by `default`, `product-full` or `agent-runtime`.
//!
//! The `test-support`-gated `host_fixture` module is a test-only writer that
//! publishes one real enabled scope through those same owners, for a test that
//! needs that persisted shape and cannot obtain it from a production entry point.
//! Outside `#[cfg(test)]` fixtures it is the only mint site of a host anchor in
//! this crate, and no production caller names it.

// Crate-internal modules: reachable inside the crate. Only the facade re-exported at
// the end of this module and the `test-support`-gated `host_fixture` below are public
// API; `host` itself stays crate-private.
// Nothing in this tree has a production consumer yet. The allowances are per module
// so each one disappears with the change that gives that module its caller.
#[allow(dead_code)]
pub(crate) mod scope;
#[allow(dead_code)]
pub(crate) mod mode;
#[allow(dead_code)]
pub(crate) mod policy;
#[allow(dead_code)]
pub(crate) mod read_contract;
// Unconditional: a feature-off build must be able to answer `NotCompiled`.
pub(crate) mod host;
#[allow(dead_code)] // Internal to the host slice; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod catalog_readonly;
#[allow(dead_code)] // Internal to the host slice; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod host_binding;
#[allow(dead_code)] // Internal to the host slice; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod host_standby;
#[allow(dead_code)]
#[cfg(feature = "workspace-intelligence-control")]
pub(crate) mod control;
#[allow(dead_code)]
#[cfg(feature = "workspace-intelligence-cognition")]
pub(crate) mod partition;
#[allow(dead_code)]
#[cfg(feature = "workspace-intelligence-commit")]
pub(crate) mod commit;
#[allow(dead_code)]
#[cfg(feature = "workspace-intelligence-claim")]
pub(crate) mod claim;
// Test-only, and behind both features: it publishes an enabled scope for a test
// that must have one, while the production enable gate stays outside this tree.
// Nothing a `test-support` build produces is part of a product assembly.
#[cfg(all(feature = "test-support", feature = "workspace-intelligence-host"))]
pub mod host_fixture;

// The application-facing surface of this tree. A host handle is opaque and is
// obtained only through `bootstrap` (host feature compiled) or `not_compiled`
// (host feature absent); the rest is plain status data an app renders or logs.
// Tenure, tickets, tokens, lease paths, control/cognition roots and the raw
// anchor stay crate-internal, as does every type of `host_binding`,
// `host_standby` and `catalog_readonly`.
pub use host::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostBlock, WorkspaceIntelligenceHostCounts,
    WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostReason,
    WorkspaceIntelligenceHostScopeReport, WorkspaceIntelligenceHostScopeState,
    WorkspaceIntelligenceHostShutdown, WorkspaceIntelligenceHostState,
    WorkspaceIntelligenceHostStatus, WorkspaceIntelligenceHostSurface,
    WorkspaceIntelligenceHostUnsupportedProfile, WorkspaceIntelligenceHostUnsupportedScope,
};
