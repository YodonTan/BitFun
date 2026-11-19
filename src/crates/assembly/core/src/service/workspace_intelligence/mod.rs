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
//! These slices are internal and have no production caller, app bootstrap,
//! legacy confirmation gate, UI, command, registry or capability. A real enable
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

#![allow(dead_code)] // P0 has no production consumer yet; remove once a later phase wires it in.

// Crate-internal modules for P1+ consumers: reachable inside the crate, never a public API.
pub(crate) mod scope;
pub(crate) mod mode;
pub(crate) mod policy;
pub(crate) mod read_contract;
#[cfg(feature = "workspace-intelligence-control")]
pub(crate) mod control;
#[cfg(feature = "workspace-intelligence-cognition")]
pub(crate) mod partition;
#[cfg(feature = "workspace-intelligence-commit")]
pub(crate) mod commit;
#[cfg(feature = "workspace-intelligence-claim")]
pub(crate) mod claim;
