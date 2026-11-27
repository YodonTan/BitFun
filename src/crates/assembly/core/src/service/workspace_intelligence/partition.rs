//! Internal cognition partition handle over the authoritative per-scope store.
//!
//! # P1 cognition partition root: WP1.3 core assembly
//!
//! This module is the internal core assembly of the P1 cognition partition root.
//! It gives one host-local cognition handle per (host, execution domain). The
//! handle composes the authoritative cognition partition store over the
//! host-local cognition root, rejects a scope owned by another host before it
//! touches storage, and otherwise forwards the caller's own scope key to the
//! store unchanged.
//!
//! What this slice persists: the partition root and the `partition_state` shape
//! only. `cursor` and `incarnation_token` are shape-only values here; consuming a
//! cursor or advancing an incarnation is WP1.4/WP1.5 work and is not delivered by
//! this module.
//!
//! What this module deliberately does not deliver:
//!
//! - no claim, lease, incarnation token advancement or cursor/gap consumption;
//! - no control generation, no policy projection and no second control truth;
//! - no runtime, scheduler, provider, timer, or background task;
//! - no production caller, no product-full assembly, and no UI, command,
//!   registry row or capability;
//! - no scope derivation: no path-to-scope helper, no default scope and no
//!   session/model fallback. The caller owns the scope identity, and a foreign
//!   scope is never answered from this host's storage.
//!
//! # Blocking boundary
//!
//! The handle is synchronous on purpose, matching the store: no `tokio`, no async
//! signature and no runtime handle. A future async runtime caller must cross a
//! blocking boundary (for example `spawn_blocking`) before calling
//! [`WorkspaceIntelligenceCognition::initialize`] or
//! [`WorkspaceIntelligenceCognition::observe`]. No runtime caller exists in this
//! slice.

use std::path::PathBuf;

use openbitfun_services_core::workspace_intelligence_cognition::{
    CognitionInitialization, CognitionPartitionState, StoredCognitionEntry,
    WorkspaceIntelligenceCognitionError, WorkspaceIntelligenceCognitionStore,
};

use crate::infrastructure::PathManager;

use super::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// Core assembly of one host-local cognition partition handle.
///
/// The handle is pure: [`WorkspaceIntelligenceCognition::for_host`] performs no
/// IO and creates no directory. The store creates the partition root only when a
/// real initialization is applied. There is no global singleton, no in-memory
/// mutex, no background task, no claim and no lease.
#[derive(Debug)]
pub(crate) struct WorkspaceIntelligenceCognition {
    store: WorkspaceIntelligenceCognitionStore,
    host: HostExecutionDomainKey,
}

impl WorkspaceIntelligenceCognition {
    /// Real core assembly entry: the authoritative host-local cognition handle of
    /// one host, stored under that host's own cognition root.
    ///
    /// Construction is pure and IO-free: it only composes the store over the
    /// host-local cognition root.
    pub(crate) fn for_host(paths: &PathManager, host: HostExecutionDomainKey) -> Self {
        Self::with_root(paths.workspace_intelligence_cognition_dir(), host)
    }

    /// Builds a handle over an explicit host-local root.
    ///
    /// This isolates the storage root only, for tests and for a caller that
    /// already owns a root. It never selects a product configuration path.
    pub(crate) fn with_root(root: PathBuf, host: HostExecutionDomainKey) -> Self {
        Self {
            store: WorkspaceIntelligenceCognitionStore::new(root),
            host,
        }
    }

    /// The host and execution domain this handle owns.
    pub(crate) fn host(&self) -> &HostExecutionDomainKey {
        &self.host
    }

    /// Creates the v1 cognition partition of `scope` if it does not exist yet.
    ///
    /// A scope owned by another host is rejected with
    /// [`CognitionError::HostScopeMismatch`] before any store call, so a foreign
    /// scope is never answered from this host's storage.
    ///
    /// The scope key handed to the store is [`WorkspaceControlScope::as_str`], the
    /// same single encoding the control slice uses. Nothing is derived from a
    /// path, and no default or fallback scope exists.
    ///
    /// This call persists the partition root and the `partition_state` shape only.
    /// It assigns no cursor and no incarnation token: cursor consumption is
    /// WP1.5 and incarnation advancement is WP1.4.
    pub(crate) fn initialize(
        &self,
        scope: &WorkspaceControlScope,
    ) -> Result<CognitionInitialization, CognitionError> {
        if !scope.host_matches(&self.host) {
            return Err(CognitionError::HostScopeMismatch);
        }
        self.store
            .initialize(&scope.as_str())
            .map_err(CognitionError::Store)
    }

    /// Observes the cognition partition of `scope`.
    ///
    /// The observation is read-only: it never creates the root, the record or a
    /// schema, and it never resets or deletes anything.
    ///
    /// - a scope owned by another host is rejected with
    ///   [`CognitionError::HostScopeMismatch`] and no store call, so there is no
    ///   local fallback;
    /// - `Ok(None)` is an observation that this call did not see a record, never
    ///   proof of an accepted close, reset or delete, and not evidence about a
    ///   record another process is about to publish;
    /// - an unreadable, uninitialized, unsupported or scope-mismatched record is
    ///   an explicit [`CognitionError::Store`], never `Ok(None)`.
    pub(crate) fn observe(
        &self,
        scope: &WorkspaceControlScope,
    ) -> Result<Option<CognitionPartitionState>, CognitionError> {
        if !scope.host_matches(&self.host) {
            return Err(CognitionError::HostScopeMismatch);
        }
        self.store.read(&scope.as_str()).map_err(CognitionError::Store)
    }

    /// Observes the stored content entries of `scope`.
    ///
    /// This is a forward of the store's own read-only content read, so the same
    /// guarantees hold: it never creates the root, the record or a schema, it never
    /// upgrades a v1 record, and it never resets or deletes anything.
    ///
    /// - a scope owned by another host is rejected with
    ///   [`CognitionError::HostScopeMismatch`] before any store call;
    /// - `Ok(None)` is an observation that this call did not see a record;
    /// - a v1 record answers [`WorkspaceIntelligenceCognitionError::ContentTableAbsent`]
    ///   through [`CognitionError::Store`], because a v1 record holds no content;
    /// - rows come back in the store's own order, for this partition only.
    pub(crate) fn read_entries(
        &self,
        scope: &WorkspaceControlScope,
    ) -> Result<Option<Vec<StoredCognitionEntry>>, CognitionError> {
        if !scope.host_matches(&self.host) {
            return Err(CognitionError::HostScopeMismatch);
        }
        self.store
            .read_entries(&scope.as_str())
            .map_err(CognitionError::Store)
    }
}

/// Failures of the workspace intelligence cognition handle.
///
/// Every variant fails closed: there is no silent fallback, no default scope and
/// no local state that could answer a foreign scope.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CognitionError {
    /// The scope belongs to a different host and execution domain.
    #[error("the scope is owned by a different host and execution domain")]
    HostScopeMismatch,
    /// The authoritative cognition partition store failed.
    #[error(transparent)]
    Store(#[from] WorkspaceIntelligenceCognitionError),
}

/// Tests of the P1 cognition partition root: WP1.3 core assembly.
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
    ) -> WorkspaceIntelligenceCognition {
        WorkspaceIntelligenceCognition::with_root(root.to_path_buf(), host)
    }

    /// The partition databases directly inside a root, sorted.
    fn database_files(root: &std::path::Path) -> Vec<PathBuf> {
        let mut files = std::fs::read_dir(root)
            .expect("the cognition root must exist after an initialization")
            .map(|entry| entry.expect("readable directory entry").path())
            .filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("sqlite")
            })
            .collect::<Vec<_>>();
        files.sort();
        files
    }

    /// Initializes `scope` and returns the one database file it added.
    fn initialize_and_capture_file(
        cognition: &WorkspaceIntelligenceCognition,
        root: &std::path::Path,
        scope: &WorkspaceControlScope,
    ) -> PathBuf {
        let before = if root.exists() {
            database_files(root)
        } else {
            Vec::new()
        };
        cognition
            .initialize(scope)
            .expect("initializing a host-owned scope must succeed");
        let after = database_files(root);
        assert_eq!(
            after.len(),
            before.len() + 1,
            "an initialization must add exactly one database file"
        );
        let added = after
            .into_iter()
            .filter(|path| !before.contains(path))
            .collect::<Vec<_>>();
        assert_eq!(added.len(), 1);
        added.into_iter().next().expect("one added database file")
    }

    #[test]
    fn for_host_is_pure_and_uses_the_cognition_root() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let paths = PathManager::with_user_root_for_tests(fixture.path().join("user"));
        let cognition_root = paths.workspace_intelligence_cognition_dir();
        let control_root = paths.workspace_intelligence_control_dir();

        let cognition = WorkspaceIntelligenceCognition::for_host(&paths, host("host-1", "local"));
        assert_eq!(cognition.host(), &host("host-1", "local"));

        // Construction is IO-free: no user data root, no cognition root, no control
        // root, no database, no lock file.
        assert!(
            !paths.user_data_dir().exists(),
            "constructing the handle must not create the user data root"
        );
        assert!(!cognition_root.exists());
        assert!(!control_root.exists());

        // The composed store root is the cognition root: the first initialization
        // publishes exactly one database directly inside it and leaves the control
        // root untouched.
        let scope = scope_of(cognition.host(), "workspace-a");
        let database = initialize_and_capture_file(&cognition, &cognition_root, &scope);
        assert_eq!(database.parent(), Some(cognition_root.as_path()));
        assert!(!control_root.exists(), "the cognition slice owns no control root");
    }

    #[test]
    fn host_scope_mismatch_takes_no_local_fallback() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("cognition");
        let cognition = handle(&root, host("host-1", "local"));

        let foreign_scopes = [
            // Another host id.
            scope_of(&host("host-2", "local"), "workspace-a"),
            // Same host id, different execution domain.
            scope_of(&host("host-1", "sandbox"), "workspace-a"),
        ];

        for foreign_scope in &foreign_scopes {
            let error = cognition
                .initialize(foreign_scope)
                .expect_err("a foreign scope must not be initialized here");
            assert!(matches!(error, CognitionError::HostScopeMismatch), "{error}");
            let error = cognition
                .observe(foreign_scope)
                .expect_err("a foreign scope must not be observed here");
            assert!(matches!(error, CognitionError::HostScopeMismatch), "{error}");
        }

        assert!(
            !root.exists(),
            "a mismatched scope must not reach the store at all"
        );

        // The same handle still works for its own scope, so the rejection is about
        // the foreign scope and not a broken handle.
        let own_scope = scope_of(cognition.host(), "workspace-a");
        cognition
            .initialize(&own_scope)
            .expect("a host-owned scope must be initialized");
        assert_eq!(database_files(&root).len(), 1);
    }

    #[test]
    fn initialize_then_observe_round_trips_across_handles() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("cognition");
        let host = host("host-1", "local");
        let scope = scope_of(&host, "workspace-a");

        let first = handle(&root, host.clone());
        let initialization = first
            .initialize(&scope)
            .expect("the first initialization must succeed");
        assert!(initialization.is_initialized());
        assert_eq!(
            initialization.state(),
            &CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            }
        );
        let database = database_files(&root)
            .into_iter()
            .next()
            .expect("one database file");
        let bytes = std::fs::read(&database).expect("the record must be readable");
        drop(first);

        // A fresh handle over the same root observes the same state, as a process
        // restart would.
        let reopened = handle(&root, host.clone());
        assert_eq!(
            reopened
                .observe(&scope)
                .expect("the record must be observable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
        assert_eq!(
            std::fs::read(&database).expect("the record must be readable"),
            bytes,
            "an observation must not rewrite the record"
        );

        // Re-initializing reports the existing partition and writes no user field.
        let existing = reopened
            .initialize(&scope)
            .expect("re-initializing reports the existing partition");
        assert!(!existing.is_initialized());
        assert_eq!(
            std::fs::read(&database).expect("the record must be readable"),
            bytes,
            "an existing partition is not rewritten"
        );
    }

    #[test]
    fn missing_partition_observe_does_not_create_the_root() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("cognition");
        let cognition = handle(&root, host("host-1", "local"));
        let scope = scope_of(cognition.host(), "workspace-a");

        assert_eq!(
            cognition
                .observe(&scope)
                .expect("a missing partition is an observation"),
            None
        );
        assert!(
            !root.exists(),
            "an observation must not create the root directory or a record"
        );
        assert_eq!(
            std::fs::read_dir(fixture.path())
                .expect("the fixture root is readable")
                .count(),
            0
        );
    }

    #[test]
    fn two_scopes_get_distinct_database_files() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("cognition");
        let cognition = handle(&root, host("host-1", "local"));
        let first_scope = scope_of(cognition.host(), "workspace-a");
        let second_scope = scope_of(cognition.host(), "workspace-b");

        let first_database = initialize_and_capture_file(&cognition, &root, &first_scope);
        let second_database = initialize_and_capture_file(&cognition, &root, &second_scope);
        assert_ne!(first_database, second_database);
        assert!(first_database.is_file());
        assert!(second_database.is_file());
        assert_eq!(database_files(&root).len(), 2);
        assert_eq!(first_database.parent(), Some(root.as_path()));
        assert_eq!(second_database.parent(), Some(root.as_path()));

        let expected = CognitionPartitionState {
            cursor: None,
            incarnation_token: None,
        };
        assert_eq!(
            cognition.observe(&first_scope).expect("first scope is readable"),
            Some(expected.clone())
        );
        assert_eq!(
            cognition.observe(&second_scope).expect("second scope is readable"),
            Some(expected)
        );
    }

    #[test]
    fn store_scope_mismatch_is_surfaced_not_masked() {
        let fixture = tempfile::tempdir().expect("temp dir");
        let root = fixture.path().join("cognition");
        let cognition = handle(&root, host("host-1", "local"));
        let source_scope = scope_of(cognition.host(), "workspace-a");
        let copied_scope = scope_of(cognition.host(), "workspace-b");

        let source_database = initialize_and_capture_file(&cognition, &root, &source_scope);
        let copied_database = initialize_and_capture_file(&cognition, &root, &copied_scope);
        assert_ne!(source_database, copied_database);

        // Copy one scope's database onto the other scope's file name, as a
        // mis-restored backup or a mistaken file move would.
        std::fs::copy(&source_database, &copied_database).expect("the record is copied");
        let copied_bytes = std::fs::read(&copied_database).expect("the record must be readable");
        assert_eq!(copied_bytes, std::fs::read(&source_database).expect("source is readable"));

        let error = cognition
            .observe(&copied_scope)
            .expect_err("a foreign partition key is never accepted");
        let CognitionError::Store(store_error) = &error else {
            panic!("a store failure must not be masked: {error}");
        };
        assert_eq!(store_error.code(), "partition_scope_mismatch");
        assert!(store_error.is_scope_mismatch());
        assert!(!store_error.is_invalid_shape());
        assert_eq!(store_error.shape_fault_code(), None);

        // The copied record is not rewritten, and the source scope still reads.
        assert_eq!(
            std::fs::read(&copied_database).expect("the record must be readable"),
            copied_bytes,
            "a mismatched record is not rewritten"
        );
        assert_eq!(
            cognition
                .observe(&source_scope)
                .expect("the source scope is still readable"),
            Some(CognitionPartitionState {
                cursor: None,
                incarnation_token: None,
            })
        );
    }
}
