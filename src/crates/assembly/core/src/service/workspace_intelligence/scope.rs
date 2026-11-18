//! Pure workspace scope identity shared by the workspace intelligence slices.
//!
//! This module is feature-free and holds value types only: no IO, no
//! `PathManager`, no feature gate and no store. It exists so the control slice and
//! the cognition partition slice share one host and scope identity instead of
//! duplicating it, and so a cognition handle can reject a foreign host before it
//! touches any storage.
//!
//! [`WorkspaceControlScope::as_str`] is a storage contract, not a formatting
//! detail: the control record file names and the cognition partition keys are
//! derived from its exact bytes, so the encoding below must not change. There is
//! deliberately no second scope encoding, no path-to-scope helper and no default
//! scope in this module.

/// Host and execution domain that own a control record.
///
/// The key is a pure pair of caller-supplied identifiers. It is never derived
/// from a device identity, a connection id, a PID, a hostname probe, or the
/// current machine, so two different hosts can never be merged by an ambient
/// discovery step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostExecutionDomainKey {
    host_id: String,
    execution_domain: String,
}

impl HostExecutionDomainKey {
    /// Builds the key, rejecting a blank host id or execution domain.
    pub(crate) fn new(host_id: &str, execution_domain: &str) -> Option<Self> {
        if host_id.trim().is_empty() || execution_domain.trim().is_empty() {
            return None;
        }
        Some(Self {
            host_id: host_id.to_owned(),
            execution_domain: execution_domain.to_owned(),
        })
    }

    /// Caller-supplied host identifier.
    pub(crate) fn host_id(&self) -> &str {
        &self.host_id
    }

    /// Caller-supplied execution domain inside that host.
    pub(crate) fn execution_domain(&self) -> &str {
        &self.execution_domain
    }
}

/// Stable workspace scope of one control record.
///
/// The scope is the owning host plus the caller's stable workspace identifier.
/// [`WorkspaceControlScope::as_str`] renders one injective, versioned encoding of
/// that tuple: JSON tuple encoding escapes delimiters, Unicode and path
/// separators, so two different tuples never share a string.
///
/// Scope derivation is not delivered by this slice. There is deliberately no
/// path-to-scope helper: deriving a scope from a local workspace root, or from a
/// remote workspace, is out of scope here and remote workspaces are unsupported
/// by this slice. A remote POSIX path must never be split or reinterpreted with
/// local path semantics.
///
/// A scope key is an opaque storage identity. It must never be reused to derive a
/// grant key, a project id, or any other authority-bearing identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WorkspaceControlScope {
    host: HostExecutionDomainKey,
    stable_workspace_id: String,
}

impl WorkspaceControlScope {
    /// Builds a scope from the owning host and a caller-supplied stable workspace
    /// identifier, rejecting a blank identifier.
    pub(crate) fn new(host: &HostExecutionDomainKey, stable_workspace_id: &str) -> Option<Self> {
        if stable_workspace_id.trim().is_empty() {
            return None;
        }
        Some(Self {
            host: host.clone(),
            stable_workspace_id: stable_workspace_id.to_owned(),
        })
    }

    /// Injective version-prefixed storage key of this scope.
    ///
    /// The tuple is serialized as JSON, so the encoding cannot be confused by a
    /// delimiter, a path separator or a Unicode payload that a plain join of the
    /// fields would collide on.
    pub(crate) fn as_str(&self) -> String {
        serde_json::to_string(&(
            "wi-scope-v1",
            self.host.host_id(),
            self.host.execution_domain(),
            self.stable_workspace_id.as_str(),
        ))
        .expect("a JSON tuple of borrowed strings cannot fail to serialize")
    }

    /// True when `host` is the host this scope was built for.
    pub(crate) fn host_matches(&self, host: &HostExecutionDomainKey) -> bool {
        self.host == *host
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen storage encoding of one scope, written out by hand.
    ///
    /// Existing control records and cognition partitions are named from these exact
    /// bytes, so this literal is an independent pin: it is not produced by the
    /// encoder under test and therefore cannot agree with a bug inside it.
    ///
    /// Deliberately no hash pin here: this module is feature-free and must not gain
    /// a hashing dependency. The store's own hostile-scope test already asserts its
    /// 64-character lowercase-hex record stems against its real hash implementation.
    const FROZEN_SCOPE_ENCODING: &str = r#"["wi-scope-v1","host-1","local","workspace-a"]"#;

    #[test]
    fn the_scope_encoding_stays_byte_identical_to_the_frozen_tuple() {
        let host = HostExecutionDomainKey::new("host-1", "local").expect("host is not blank");
        let scope = WorkspaceControlScope::new(&host, "workspace-a").expect("scope is not blank");
        let encoded = scope.as_str();
        assert_eq!(encoded, FROZEN_SCOPE_ENCODING);
        assert_eq!(encoded.as_bytes(), FROZEN_SCOPE_ENCODING.as_bytes());
    }
}
