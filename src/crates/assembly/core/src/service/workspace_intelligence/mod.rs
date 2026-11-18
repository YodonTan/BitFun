//! Workspace intelligence tier derivation (P0) and internal control assembly
//! (P1 core control slice: WP1.1 core assembly + WP1.2a control-vs-control).
//!
//! Phase 0 holds the pure, side-effect-free parts of the workspace
//! intelligence control contract: `mode` derives the tier from control facts,
//! and `read_contract` projects a persisted control record without writing,
//! repairing, or reorganizing it. No storage, IO, background work, or model
//! resolution lives here.
//!
//! The `policy` module adds the pure, fail-closed policy projection and merge
//! rules. The feature-gated `control` module adds the internal control handle
//! over the authoritative store's own compare-and-swap.
//!
//! This slice is internal: it has no production caller, no bootstrap and no
//! claim, no legacy confirmation gate, and no UI, command, registry or
//! capability. A real enable later must pass the P2.4/P3 gate; nothing here
//! turns workspace intelligence on, and no product feature selects
//! `workspace-intelligence-control`.

#![allow(dead_code)] // P0 has no production consumer yet; remove once a later phase wires it in.

// Crate-internal modules for P1+ consumers: reachable inside the crate, never a public API.
pub(crate) mod mode;
pub(crate) mod policy;
pub(crate) mod read_contract;
#[cfg(feature = "workspace-intelligence-control")]
pub(crate) mod control;
