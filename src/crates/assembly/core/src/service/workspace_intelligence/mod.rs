//! Workspace intelligence tier derivation, internal control assembly and the
//! app-facing host facade.
//!
//! The pure, side-effect-free parts of the workspace intelligence control
//! contract live here: `mode` derives the tier from control facts, and
//! `read_contract` projects a persisted control record without writing,
//! repairing, or reorganizing it. No storage, IO, background work, or model
//! resolution lives in them.
//!
//! The feature-free `scope` module holds the host and workspace scope value types
//! and their single injective storage encoding. The `policy` module adds the pure,
//! fail-closed policy projection and merge rules. The feature-gated `control`
//! module adds the internal control handle over the authoritative store's own
//! compare-and-swap. The feature-gated `partition` module adds the internal
//! cognition partition handle over the authoritative per-scope partition store.
//!
//! The feature-free `cursor` module is the first slice of WP1.5: it decides one step
//! per source — duplicate, incremental from the marker the partition recorded, or a
//! snapshot reconcile that carries its gap — and refuses when the source's own facts
//! are missing or contradict each other. It orders no marker, proves no ordering,
//! writes no cursor, keeps no dedup window, adds no schema or store change and has no
//! caller in this tree. The partition holds one cursor, not one per source, so the
//! module names the source of each decision while marker affinity and multi-source
//! progress stay obligations of the persistence owner this tree does not provide.
//!
//! The `workspace-intelligence-host`-gated `session_source` module is the first real
//! source of WP1.5-b: it observes one already resolved Session storage root read-only
//! and derives a deterministic snapshot marker over the sessions it can see, with an
//! explicit incomplete state or typed read error instead of partial data. It writes
//! nothing, takes no index lock, creates no directory, keeps no state and reads no
//! clock. It always declares `SnapshotOnly`, so a reconcile carries its gap; it has
//! no consumer, writes no cursor and persists nothing. Its caller passes the Session
//! root: deriving that root from a workspace, and remote or assistant support, belong
//! to a later host wiring slice.
//!
//! The control and cognition modules are internal and have no production caller
//! outside the host facade, plus no entry point of their own, no legacy
//! confirmation gate, UI, command, registry or capability. The gated `host`
//! facade re-exported at the end of this module is the only app-facing entry
//! point, and the composition roots that call `bootstrap` are the app surfaces
//! that select this feature deliberately: in this tree the CLI interactive and
//! execution modes are such callers. A surface that does not select it answers
//! `NotCompiled` instead of silently reporting success. A real enable later must
//! pass a separately reviewed enable gate outside this tree; nothing here turns
//! workspace intelligence on, and no product feature selects
//! `workspace-intelligence-control`.
//!
//! The `partition` module itself adds no claim, cursor consumption or policy.
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
//! marker, and read-only tenure verification. The module itself adds no first
//! enable, no `allow_off`, no device or account identity source, no pending
//! cursor, no revision/epoch, no model run, no background worker and no registry;
//! the delivery-profile admission and the execution-binding change detection
//! that drive it live in the `host` facade. It is not selected by `default`,
//! `product-full` or `agent-runtime`.
//!
//! The unconditional `host` module is the workspace intelligence host handle:
//! bootstrap over one owner-decoded persisted catalog, per-scope lease tenure, a
//! typed status snapshot and a bounded shutdown. It is unconditional so
//! that a build without the feature can answer `NotCompiled` instead of
//! failing to link or silently reporting success. Its handle, its three app-facing
//! entry points and the plain status data around them are re-exported at the end of
//! this module as the one app-facing surface of this tree; every other type here
//! stays crate-internal. The handle additionally carries two crate-internal
//! preparation entry points (`pub(super)`, no app caller, no command and no registry
//! row): the anchor step can mint or adopt this host's storage anchor, and the
//! complete preparation composes it with a scope reservation and hands back a
//! queued, revocable permit that authorizes nothing. Neither entry point ever
//! enables a scope. The `catalog_readonly` module
//! (read-only persisted registry snapshot), the `host_binding` module (execution
//! binding resolution) and the `host_standby` module (bounded fallback wake-up)
//! are gated on `workspace-intelligence-host` together with the rest of the host
//! feature.
//!
//! This tree still adds no first enable, no `allow_off`, no pending cursor, no
//! content mutation, no model run, no Tauri command, no Product Operation
//! Registry row and no UI, so a real first enable still has to pass the enable
//! gate this tree does not provide. Nothing here is selected by `default`,
//! `product-full` or `agent-runtime`.
//!
//! The `test-support`-gated `host_fixture` module is a test-only writer, compiled
//! only when `test-support` and `workspace-intelligence-host` are selected
//! together and reached only from a `[dev-dependencies]` edge: it publishes one
//! real enabled scope through those same owners, for a test that needs that
//! persisted shape and cannot obtain it from a production entry point. Outside
//! `#[cfg(test)]` fixtures, the crate-internal preparation paths of the `host`
//! module are the only anchor mint site in this crate: they are `pub(super)`, no app
//! caller names them, and the test-support writer above stays test-only.

// Crate-internal modules: reachable inside the crate. Only the facade re-exported at
// the end of this module and the `test-support`-gated `host_fixture` below are public
// API; `host` itself stays crate-private.
// Each allowance is per module: it covers the internal modules that only the
// app-facing facade consumes, and disappears with the change that gives that module
// its own caller.
#[allow(dead_code)]
pub(crate) mod scope;
#[allow(dead_code)]
pub(crate) mod mode;
#[allow(dead_code)]
pub(crate) mod policy;
#[allow(dead_code)]
pub(crate) mod read_contract;
// No consumer in this tree: nothing reads a cursor yet, so the WP1.5 decision contract
// stays a feature-free internal module until the persistence slice names it.
#[allow(dead_code)]
pub(crate) mod cursor;
// Unconditional: a feature-off build must be able to answer `NotCompiled`.
pub(crate) mod host;
#[allow(dead_code)] // Internal to the host feature; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod catalog_readonly;
#[allow(dead_code)] // Internal to the host feature; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod host_binding;
#[allow(dead_code)] // Internal to the host feature; consumed only by `host`.
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod host_standby;
// First real source of WP1.5-b: read-only Session snapshot observation. No consumer yet,
// and nothing here writes a cursor or the observed root.
#[allow(dead_code)]
#[cfg(feature = "workspace-intelligence-host")]
pub(crate) mod session_source;
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
// `host_standby` and `catalog_readonly`. The crate-internal preparation entry
// points and the queued permit they hand back are deliberately not part of this
// re-export and have no app caller.
pub use host::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostBlock, WorkspaceIntelligenceHostCounts,
    WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostReason,
    WorkspaceIntelligenceHostScopeReport, WorkspaceIntelligenceHostScopeState,
    WorkspaceIntelligenceHostShutdown, WorkspaceIntelligenceHostState,
    WorkspaceIntelligenceHostStatus, WorkspaceIntelligenceHostSurface,
    WorkspaceIntelligenceHostUnsupportedProfile, WorkspaceIntelligenceHostUnsupportedScope,
};
