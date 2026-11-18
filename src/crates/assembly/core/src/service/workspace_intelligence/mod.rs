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
//! This slice is internal: it has no production caller, no bootstrap and no
//! claim, no legacy confirmation gate, and no UI, command, registry or
//! capability. A real enable later must pass the P2.4/P3 gate; nothing here
//! turns workspace intelligence on, and no product feature selects
//! `workspace-intelligence-control`.
//!
//! The cognition partition slice is internal in the same way: no claim, no cursor
//! consumption and no policy. It persists only the partition root and the
//! `partition_state` shape, it is not selected by `default`, `product-full` or
//! `agent-runtime`, and a future real narrow consumer must select
//! `workspace-intelligence-cognition` explicitly in its own manifest.
//!
//! The gated `commit` module adds the internal governed owner-commit wrapper over
//! the services fence. It recovers the cognition partition of an already-enabled
//! scope only: no bootstrap/claim, no OFF-to-ON enabling path, and no model
//! resolution. It is not selected by `default`, `product-full` or `agent-runtime`.

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
