//! Workspace intelligence tier derivation (P0).
//!
//! Phase 0 holds the pure, side-effect-free parts of the workspace
//! intelligence control contract: `mode` derives the tier from control facts,
//! and `read_contract` projects a persisted control record without writing,
//! repairing, or reorganizing it. No storage, IO, background work, or model
//! resolution lives here.

#![allow(dead_code)] // P0 has no production consumer yet; remove once a later phase wires it in.

// Crate-internal modules for P1+ consumers: reachable inside the crate, never a public API.
pub(crate) mod mode;
pub(crate) mod read_contract;
