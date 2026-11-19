//! Test-only fixture that publishes one real, on-disk enabled scope.
//!
//! Workspace intelligence tests that must exercise a host with an enabled
//! workspace need a persisted shape that no production writer produces yet: an
//! `enabled == true` control record whose policy carries an execution binding of
//! the current schema version. A real enable is a product decision that must pass
//! the P2.4/P3 gate, and this crate deliberately has no enable path, so no
//! production entry point reaches that shape and a test must not re-derive the
//! anchor, the scope encoding and the merge rules by hand. This module is the
//! explicit, test-only writer for it. It adds no production enable: it is
//! compiled only when both `test-support` and `workspace-intelligence-host` are
//! selected, `test-support` is the feature this crate's manifest documents for
//! `[dev-dependencies]` use only, and no production caller names it.
//!
//! # Why it is not a second source of truth
//!
//! Every document it publishes is written by the owner that already owns that
//! document, under that owner's own key, format and transaction:
//!
//! - the workspace record goes through the workspace persistence owner under the
//!   same `workspace_data` key and the same `WorkspacePersistenceData` shape the
//!   workspace service writes, so the catalog a host reads from this fixture is
//!   the document a real process reads;
//! - the control record goes through the authoritative control store's own
//!   compare-and-swap, so a record this fixture publishes is a record the host's
//!   resolver accepts;
//! - the host anchor is minted by the anchor owner's own `ensure`, the same call
//!   a first enable would make; outside `#[cfg(test)]` fixtures, this module is
//!   the only mint site in this crate;
//! - the execution binding is not a new format: the stored policy is merged in
//!   memory, the known binding fields are written explicitly, every unknown
//!   sibling key and every unknown nested sub-key survives verbatim, and the
//!   merged value is classified with the same resolver the host uses before it is
//!   committed.
//!
//! # Roots
//!
//! Nothing here reads an environment variable, and no entry point has a default
//! or implicit root: the caller passes the [`PathManager`] to use, and a seed
//! also passes the workspace directory. [`test_path_manager`] derives the
//! isolated user-data root core's own tests use without touching the filesystem;
//! the caller must still supply a temporary root, because an explicit root is
//! honoured verbatim.
//!
//! # Public surface
//!
//! The whole public surface of this module is exactly: [`SeededWorkspace`] with
//! its two read-only accessors, [`SeedError`] with its single `code()` and no
//! `Display`, [`test_path_manager`], [`seed_local_workspace`] and
//! [`enable_workspace`]. It is compiled only while `test-support` and
//! `workspace-intelligence-host` are selected together; `test-support` is selected
//! only from `[dev-dependencies]`, and no product assembly selects it, so a normal
//! product build can neither name nor call anything here. None of these items is a
//! product API, and none of them is an enable gate.
//!
//! # Stored records written by an older schema
//!
//! A stored binding that declares an older schema version cannot be compared by
//! the current resolver at all. [`enable_workspace`] then replaces the known
//! binding fields in place with the facts it observes, which advances the control
//! generation. That is an explicit test write and not a production back-fill: no
//! production path upgrades a stored binding on its own.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::Utc;
use openbitfun_services_core::persistence::{PersistenceService, StorageOptions};
use openbitfun_services_core::workspace_intelligence_host_anchor::{
    HostAnchorEnsure, HostAnchorStore,
};
use openbitfun_services_core::workspace_intelligence_store::{
    ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch,
    WorkspaceIntelligenceStore,
};
use openbitfun_services_core::workspace_persistence::{
    WorkspacePersistenceData, WORKSPACE_PERSISTENCE_FORMAT_VERSION,
};
use openbitfun_services_core::workspace_records::{
    WorkspaceInfo, WorkspaceKind, WorkspaceStatus, WorkspaceType,
};
use serde_json::{json, Map, Value};

use crate::infrastructure::PathManager;
use crate::service::workspace_intelligence::catalog_readonly::{
    self, PersistedCatalogEntry,
};
use crate::service::workspace_intelligence::host_binding::{
    self, BindingState, ExecutionBinding, EXECUTION_BINDING_KEY, LOCAL_EXECUTION_DOMAIN,
};
use crate::service::workspace_intelligence::policy::CONTROL_SCHEMA_VERSION;
use crate::service::workspace_intelligence::scope::{
    HostExecutionDomainKey, WorkspaceControlScope,
};

/// One workspace whose scope [`enable_workspace`] has enabled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeededWorkspace {
    workspace_id: String,
    generation: u64,
}

impl SeededWorkspace {
    /// The persisted workspace id this fixture enabled, verbatim.
    pub fn workspace_id(&self) -> &str {
        &self.workspace_id
    }

    /// Control generation of the enabled record after the enable returned.
    pub fn generation(&self) -> u64 {
        self.generation
    }
}

/// Why a fixture seed or enable refused.
///
/// Every variant is a refusal: none is resolved by deleting, resetting or
/// rewriting a stored document, and none carries a path, a stored payload, a
/// document text or another owner's error message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedError {
    /// A blank workspace id, or a workspace root without a UTF-8 rendering.
    InvalidInput,
    /// The persisted catalog could not be read. The payload is the catalog
    /// reader's own stable code, or this fixture's own stable load code.
    CatalogRead(&'static str),
    /// The persisted catalog or the workspace directory could not be written.
    CatalogWrite,
    /// The seeded record does not come back as an eligible scope candidate.
    CatalogUnsupported,
    /// The host anchor could not be read or published. The payload is the anchor
    /// owner's own stable code.
    Anchor(&'static str),
    /// The control record could not be read. The payload is a stable fixture code.
    ControlRead(&'static str),
    /// The control record could not be written. The payload is a stable fixture
    /// code that keeps a generation conflict distinct from any other failure.
    ControlWrite(&'static str),
    /// The stored policy, or its `execution_binding` value, is not a JSON object.
    PolicyNotObject,
    /// The merged policy does not resolve to the binding this fixture observed.
    BindingRefused,
}

impl SeedError {
    /// Stable code for a test assertion or a log line. There is deliberately no
    /// `Display`: every diagnostic detail a lower owner carries (paths, payload
    /// bytes, document text) stays out of this type.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidInput => "invalid_input",
            Self::CatalogRead(code) => *code,
            Self::CatalogWrite => "catalog_write",
            Self::CatalogUnsupported => "catalog_unsupported",
            Self::Anchor(code) => *code,
            Self::ControlRead(code) => *code,
            Self::ControlWrite(code) => *code,
            Self::PolicyNotObject => "policy_not_object",
            Self::BindingRefused => "binding_refused",
        }
    }
}

/// The isolated user-data root core's own tests use, for a caller that must
/// point the host and this fixture at the same temporary root. No IO, creates
/// nothing.
pub fn test_path_manager(user_root: &Path) -> Arc<PathManager> {
    Arc::new(PathManager::with_user_root_for_tests(user_root.to_path_buf()))
}

/// Adds one local workspace record through the persistence owner's own key.
/// Creates the workspace directory. Writes no anchor, no control record and no
/// cognition/lease root.
pub async fn seed_local_workspace(
    paths: &PathManager,
    workspace_id: &str,
    root: &Path,
) -> Result<(), SeedError> {
    if workspace_id.trim().is_empty() {
        return Err(SeedError::InvalidInput);
    }
    // The root is a binding comparison fact, so it must be rendered exactly or
    // not at all: a lossy rendering would alias two different roots onto one.
    let Some(root_text) = root.to_str() else {
        return Err(SeedError::InvalidInput);
    };
    // The seed write step is the workspace directory plus the registry document;
    // a failure of either is one refusal.
    std::fs::create_dir_all(root).map_err(|_| SeedError::CatalogWrite)?;

    let store = PersistenceService::from_base_dir(paths.user_data_dir());
    let mut data = match store.load_json(catalog_readonly::WORKSPACE_CATALOG_KEY).await {
        Ok(Some(data)) => data,
        Ok(None) => WorkspacePersistenceData {
            format_version: WORKSPACE_PERSISTENCE_FORMAT_VERSION,
            product_id: catalog_readonly::expected_product_identity().to_owned(),
            workspaces: HashMap::new(),
            opened_workspace_ids: Vec::new(),
            current_workspace_id: None,
            recent_workspaces: Vec::new(),
            recent_assistant_workspaces: Vec::new(),
            primary_assistant_key: None,
            assistant_name_sequence: 0,
            saved_at: Utc::now(),
        },
        // The persistence owner's load error carries no code of its own, so this
        // fixture reports its own stable code instead of a message or a path.
        Err(_) => return Err(SeedError::CatalogRead("catalog_read_failed")),
    };
    let now = Utc::now();
    data.workspaces.insert(
        workspace_id.to_owned(),
        WorkspaceInfo {
            id: workspace_id.to_owned(),
            name: workspace_id.to_owned(),
            root_path: PathBuf::from(root_text),
            workspace_type: WorkspaceType::Other,
            workspace_kind: WorkspaceKind::Normal,
            assistant_id: None,
            status: WorkspaceStatus::Active,
            languages: Vec::new(),
            opened_at: now,
            last_accessed: now,
            description: None,
            tags: Vec::new(),
            statistics: None,
            identity: None,
            worktree: None,
            related_paths: Vec::new(),
            metadata: HashMap::new(),
        },
    );
    data.saved_at = Utc::now();
    // No backup and no compression: a fixture must not leave a second copy of the
    // registry behind, and an assertion then reads exactly the document the write
    // produced.
    store
        .save_json(
            catalog_readonly::WORKSPACE_CATALOG_KEY,
            &data,
            StorageOptions {
                create_backup: false,
                backup_count: 0,
                compress: false,
            },
        )
        .await
        .map_err(|_| SeedError::CatalogWrite)?;

    // A silent no-op would let a test drift from the catalog it seeds for, so the
    // record must come back as the eligible projection this fixture promised.
    let catalog = catalog_readonly::read_persisted_catalog(paths)
        .await
        .map_err(|error| SeedError::CatalogRead(error.code()))?;
    match catalog
        .entries()
        .iter()
        .find(|(entry_id, _)| entry_id == workspace_id)
        .map(|(_, entry)| entry)
    {
        Some(PersistedCatalogEntry::Eligible(_)) => Ok(()),
        Some(PersistedCatalogEntry::Unsupported(_)) | None => Err(SeedError::CatalogUnsupported),
    }
}

/// Explicitly enables one already-seeded local workspace: mints the anchor only
/// if absent (outside `#[cfg(test)]` fixtures, the only mint site in this tree),
/// writes the observed execution binding into the stored policy with unknown
/// content preserved, and sets `enabled` true with one compare-and-swap.
///
/// The order is: read the persisted catalog, `ensure()` the anchor (which returns
/// the stored one or publishes the mint), read the control record, merge the
/// observed binding in memory, commit one compare-and-swap, then read the record
/// back. The control scope key is derived from the anchor's host id, so the anchor
/// must exist before any scope can be named, and the mint therefore comes first.
/// Every refusal after the catalog read — `PolicyNotObject`, `BindingRefused`,
/// `ControlRead` or `ControlWrite` — leaves a published anchor behind. That
/// residue is not a defect: the anchor owner's `ensure` is write-once and
/// idempotent, it is the same call a real first enable makes, a retry reuses the
/// same host id, and the mint publishes the anchor document with the owner's own
/// lock file and nothing else — no control record, no lease and no cognition
/// record. Only the catalog refusal guarantees that no root was created.
pub async fn enable_workspace(
    paths: &PathManager,
    workspace_id: &str,
) -> Result<SeededWorkspace, SeedError> {
    // The catalog is read first: an id this user-data root does not hold as an
    // eligible record refuses before this fixture creates any root.
    let catalog = catalog_readonly::read_persisted_catalog(paths)
        .await
        .map_err(|error| SeedError::CatalogRead(error.code()))?;
    let Some(workspace) = catalog.workspace(workspace_id) else {
        return Err(SeedError::CatalogUnsupported);
    };

    let anchor = HostAnchorStore::new(paths.workspace_intelligence_dir())
        .ensure()
        .await
        .map_err(|error| SeedError::Anchor(error.code()))?;
    let host_id = match anchor {
        HostAnchorEnsure::Created(anchor) | HostAnchorEnsure::Existing(anchor) => {
            anchor.host_id().to_owned()
        }
    };

    let key = HostExecutionDomainKey::new(&host_id, LOCAL_EXECUTION_DOMAIN)
        .ok_or(SeedError::InvalidInput)?;
    let scope = WorkspaceControlScope::new(&key, workspace_id).ok_or(SeedError::InvalidInput)?;
    let store = control_store(paths);

    let stored = store
        .read(&scope.as_str())
        .await
        .map_err(|_| SeedError::ControlRead("control_read_failed"))?;
    let (expectation, base) = match &stored {
        Some(record) => (
            ControlGenerationExpectation::Exactly(record.control_generation),
            record.policy.as_ref(),
        ),
        None => (ControlGenerationExpectation::Absent, None),
    };

    let observed = ExecutionBinding::observed(&host_id, workspace);
    let merged = merge_observed_binding(base, &observed)?;

    let write = store
        .update(
            &scope.as_str(),
            expectation,
            WorkspaceIntelligenceControlPatch {
                enabled: ControlFieldUpdate::Set(true),
                policy: ControlFieldUpdate::Set(merged.clone()),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| {
            // The store reports no code of its own and the fixture never puts its
            // message or a path on the wire: only the conflict fact is reported.
            SeedError::ControlWrite(if error.is_conflict() {
                "control_generation_conflict"
            } else {
                "control_write_failed"
            })
        })?;

    let readback = store
        .read(&scope.as_str())
        .await
        .map_err(|_| SeedError::ControlRead("control_read_failed"))?;
    // The published record must be the record this fixture promised, otherwise a
    // test would be enabled by a write the fixture cannot verify.
    match readback {
        Some(record)
            if record.enabled == Some(true) && record.policy.as_ref() == Some(&merged) => {}
        _ => return Err(SeedError::ControlWrite("readback_mismatch")),
    }

    Ok(SeededWorkspace {
        workspace_id: workspace_id.to_owned(),
        generation: write.record().control_generation,
    })
}

/// The authoritative control store over this host's own control root.
fn control_store(paths: &PathManager) -> WorkspaceIntelligenceStore {
    WorkspaceIntelligenceStore::new(
        paths.workspace_intelligence_control_dir(),
        vec![CONTROL_SCHEMA_VERSION],
    )
}

/// Merges the observed binding into the stored opaque policy.
///
/// The stored policy is cloned, never rebuilt: every unknown sibling key and
/// every unknown key inside `execution_binding` survives verbatim, and only the
/// known binding fields are written. A policy or an `execution_binding` value
/// that is not an object is refused before anything is written, so a document
/// this fixture cannot merge stays exactly as stored.
fn merge_observed_binding(
    base: Option<&Value>,
    observed: &ExecutionBinding,
) -> Result<Value, SeedError> {
    let mut policy = match base {
        None => Map::new(),
        Some(Value::Object(policy)) => policy.clone(),
        Some(_) => return Err(SeedError::PolicyNotObject),
    };
    let mut binding = match policy.get(EXECUTION_BINDING_KEY) {
        None => Map::new(),
        Some(Value::Object(binding)) => binding.clone(),
        Some(_) => return Err(SeedError::PolicyNotObject),
    };
    // Every known key is written explicitly, and every absent fact is written as
    // a JSON null: an omitted key is indistinguishable from a body an older build
    // wrote, and the resolver refuses such a body instead of comparing it.
    binding.insert("schema_version".to_owned(), json!(observed.schema_version()));
    binding.insert("host_id".to_owned(), json!(observed.host_id()));
    binding.insert(
        "execution_domain".to_owned(),
        json!(observed.execution_domain()),
    );
    binding.insert("workspace_id".to_owned(), json!(observed.workspace_id()));
    binding.insert(
        "workspace_root".to_owned(),
        json!(observed.workspace_root()),
    );
    binding.insert(
        "workspace_kind".to_owned(),
        json!(observed.workspace_kind()),
    );
    binding.insert(
        "is_worktree_child".to_owned(),
        json!(observed.is_worktree_child()),
    );
    binding.insert(
        "worktree_parent_id".to_owned(),
        optional_text(observed.worktree_parent_id()),
    );
    binding.insert(
        "worktree_is_main".to_owned(),
        optional_flag(observed.worktree_is_main()),
    );
    binding.insert(
        "main_repo_path".to_owned(),
        optional_text(observed.main_repo_path()),
    );
    policy.insert(EXECUTION_BINDING_KEY.to_owned(), Value::Object(binding));

    let merged = Value::Object(policy);
    if host_binding::classify(Some(&merged)) != BindingState::Present(observed.clone()) {
        // A policy the host's own resolver cannot resolve to the observed binding
        // must never be committed: it would enable a scope the host refuses.
        return Err(SeedError::BindingRefused);
    }
    Ok(merged)
}

/// JSON null for an absent optional text fact.
fn optional_text(value: Option<&str>) -> Value {
    match value {
        Some(value) => Value::String(value.to_owned()),
        None => Value::Null,
    }
}

/// JSON null for an absent optional flag.
fn optional_flag(value: Option<bool>) -> Value {
    match value {
        Some(value) => Value::Bool(value),
        None => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbitfun_services_core::workspace_intelligence_host_anchor::{
        HostAnchorError, HOST_ANCHOR_FILE_NAME,
    };
    use openbitfun_services_core::workspace_intelligence_store::WorkspaceIntelligenceControlRecord;

    use crate::service::workspace_intelligence::catalog_readonly::CatalogReadError;
    use crate::service::workspace_intelligence::host_binding::EXECUTION_BINDING_SCHEMA_VERSION;

    /// One isolated user root and the workspace directories under the same temp
    /// root, so these tests run on a temporary root.
    struct Fixture {
        temp: tempfile::TempDir,
        paths: Arc<PathManager>,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("a temp root");
            let paths = test_path_manager(&temp.path().join("user"));
            Self { temp, paths }
        }

        fn workspace_root(&self, name: &str) -> PathBuf {
            self.temp.path().join(name).join("workspace")
        }
    }

    /// The normalized root the catalog reader reports for one local path.
    ///
    /// Mirrors the reader's documented platform rule instead of re-deriving it
    /// from the reader itself, so this fixture cannot agree with a bug inside it.
    fn expected_root(root: &Path) -> String {
        #[cfg(windows)]
        {
            root.to_string_lossy().replace('\\', "/")
        }
        #[cfg(not(windows))]
        {
            root.to_string_lossy().into_owned()
        }
    }

    /// Mints the anchor through the anchor owner and returns the host id a
    /// control scope is keyed on.
    async fn minted_host_id(paths: &PathManager) -> String {
        match HostAnchorStore::new(paths.workspace_intelligence_dir())
            .ensure()
            .await
            .expect("the anchor is mintable in a temp root")
        {
            HostAnchorEnsure::Created(anchor) | HostAnchorEnsure::Existing(anchor) => {
                anchor.host_id().to_owned()
            }
        }
    }

    fn scope_of(host_id: &str, workspace_id: &str) -> WorkspaceControlScope {
        let key = HostExecutionDomainKey::new(host_id, LOCAL_EXECUTION_DOMAIN)
            .expect("a minted host id is not blank");
        WorkspaceControlScope::new(&key, workspace_id).expect("the fixture ids are not blank")
    }

    async fn read_record(
        paths: &PathManager,
        host_id: &str,
        workspace_id: &str,
    ) -> WorkspaceIntelligenceControlRecord {
        control_store(paths)
            .read(&scope_of(host_id, workspace_id).as_str())
            .await
            .expect("the control record is readable")
            .expect("the control record exists")
    }

    /// The observed binding of one seeded workspace, read back through the same
    /// persisted catalog this fixture writes.
    async fn observed_binding(
        paths: &PathManager,
        host_id: &str,
        workspace_id: &str,
    ) -> ExecutionBinding {
        let catalog = catalog_readonly::read_persisted_catalog(paths)
            .await
            .expect("the seeded catalog is readable");
        let workspace = catalog
            .workspace(workspace_id)
            .expect("the seeded workspace is eligible");
        ExecutionBinding::observed(host_id, workspace)
    }

    /// The single control record file of a root that holds exactly one scope.
    fn control_record_path(paths: &PathManager) -> PathBuf {
        let mut files: Vec<PathBuf> = std::fs::read_dir(paths.workspace_intelligence_control_dir())
            .expect("the control root exists")
            .map(|entry| entry.expect("a control entry").path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "json"))
            .collect();
        files.sort();
        assert_eq!(
            files.len(),
            1,
            "the fixture root holds one control record: {files:?}"
        );
        files.remove(0)
    }

    fn user_data_entries(paths: &PathManager) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(paths.user_data_dir())
            .expect("the user data root exists")
            .map(|entry| {
                entry
                    .expect("a user data entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    /// Hand-built binding object with the ten known keys: written as a JSON
    /// literal here rather than through the merge under test, so the two cannot
    /// agree through a shared encoder bug.
    fn stored_binding_object(observed: &ExecutionBinding) -> Map<String, Value> {
        json!({
            "schema_version": observed.schema_version(),
            "host_id": observed.host_id(),
            "execution_domain": observed.execution_domain(),
            "workspace_id": observed.workspace_id(),
            "workspace_root": observed.workspace_root(),
            "workspace_kind": observed.workspace_kind(),
            "is_worktree_child": observed.is_worktree_child(),
            "worktree_parent_id": observed.worktree_parent_id(),
            "worktree_is_main": observed.worktree_is_main(),
            "main_repo_path": observed.main_repo_path(),
        })
        .as_object()
        .expect("a JSON object literal")
        .clone()
    }

    #[test]
    fn the_test_path_manager_derives_the_isolated_root_and_writes_nothing() {
        let temp = tempfile::tempdir().expect("a temp root");
        let user_root = temp.path().join("user");
        let paths = test_path_manager(&user_root);

        assert_eq!(paths.user_root_dir(), user_root.as_path());
        assert_eq!(paths.user_data_dir(), user_root.join("data"));
        assert!(
            !user_root.exists(),
            "the fixture root is derived, not created"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("the caller's root")
                .count(),
            0,
            "no directory is created under the caller's root"
        );
    }

    #[tokio::test]
    async fn seeded_records_round_trip_verbatim_through_the_persisted_catalog() {
        let fixture = Fixture::new();
        let first_root = fixture.workspace_root("first");
        seed_local_workspace(&fixture.paths, "fixture-ws-1", &first_root)
            .await
            .expect("the first seed");
        // A second id carrying separators must survive verbatim and must not
        // replace the first record.
        let second_root = fixture.workspace_root("second");
        seed_local_workspace(&fixture.paths, "  fixture:separator/id  ", &second_root)
            .await
            .expect("the second seed");

        let catalog = catalog_readonly::read_persisted_catalog(&fixture.paths)
            .await
            .expect("the seeded catalog is readable");
        let first = catalog
            .workspace("fixture-ws-1")
            .expect("the first record survives the second seed");
        assert_eq!(first.id(), "fixture-ws-1");
        assert_eq!(
            first.kind(),
            catalog_readonly::PersistedWorkspaceKind::LocalWorkspace
        );
        assert_eq!(first.root(), expected_root(&first_root));
        assert!(
            first_root.is_dir(),
            "the seed creates the workspace directory"
        );
        let second = catalog
            .workspace("  fixture:separator/id  ")
            .expect("the second record is eligible");
        assert_eq!(second.id(), "  fixture:separator/id  ");
        assert_eq!(second.root(), expected_root(&second_root));
        // The second seed reuses an existing registry, which is the only case in
        // which the persistence owner would write a backup: a single seed over a
        // fresh root cannot catch `create_backup` turning back on.
        assert_eq!(
            user_data_entries(&fixture.paths),
            vec!["workspace_data.json".to_owned()]
        );
    }

    #[tokio::test]
    async fn seeding_alone_touches_no_workspace_intelligence_root() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "seed-only",
            &fixture.workspace_root("seed-only"),
        )
        .await
        .expect("the seed");

        assert!(
            !fixture.paths.workspace_intelligence_dir().exists(),
            "a seed writes no anchor, no control record and no cognition root"
        );
        assert!(!fixture.paths.workspace_intelligence_control_dir().exists());
        assert_eq!(
            user_data_entries(&fixture.paths),
            vec!["workspace_data.json".to_owned()]
        );
    }

    #[tokio::test]
    async fn enabling_mints_the_anchor_and_publishes_the_observed_binding_once() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "enable-ws",
            &fixture.workspace_root("enable-ws"),
        )
        .await
        .expect("the seed");

        let seeded = enable_workspace(&fixture.paths, "enable-ws")
            .await
            .expect("the enable");
        assert_eq!(seeded.workspace_id(), "enable-ws");
        assert_eq!(seeded.generation(), 1, "a first enable creates generation one");

        assert!(
            fixture
                .paths
                .workspace_intelligence_dir()
                .join(HOST_ANCHOR_FILE_NAME)
                .is_file(),
            "the enable mints the anchor through the anchor owner"
        );
        let host_id = minted_host_id(&fixture.paths).await;
        let record = read_record(&fixture.paths, &host_id, "enable-ws").await;
        assert_eq!(record.enabled, Some(true));
        assert_eq!(record.control_generation, 1);
        assert_eq!(record.schema_version, Some(CONTROL_SCHEMA_VERSION));
        let observed = observed_binding(&fixture.paths, &host_id, "enable-ws").await;
        assert_eq!(
            host_binding::classify(record.policy.as_ref()),
            BindingState::Present(observed)
        );
    }

    #[tokio::test]
    async fn enabling_twice_leaves_the_control_record_byte_identical() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "idempotent-ws",
            &fixture.workspace_root("idempotent-ws"),
        )
        .await
        .expect("the seed");
        enable_workspace(&fixture.paths, "idempotent-ws")
            .await
            .expect("the first enable");
        let record_path = control_record_path(&fixture.paths);
        let before = std::fs::read(&record_path).expect("the published record");

        let second = enable_workspace(&fixture.paths, "idempotent-ws")
            .await
            .expect("the second enable");
        assert_eq!(
            second.generation(),
            1,
            "an identical enable does not advance the generation"
        );
        assert_eq!(
            std::fs::read(&record_path).expect("the record"),
            before,
            "an identical enable leaves the stored bytes untouched"
        );
        let host_id = minted_host_id(&fixture.paths).await;
        let record = read_record(&fixture.paths, &host_id, "idempotent-ws").await;
        let observed = observed_binding(&fixture.paths, &host_id, "idempotent-ws").await;
        assert_eq!(
            host_binding::classify(record.policy.as_ref()),
            BindingState::Present(observed)
        );
    }

    #[tokio::test]
    async fn an_enable_preserves_unknown_sibling_and_nested_policy_content() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "unknown-ws",
            &fixture.workspace_root("unknown-ws"),
        )
        .await
        .expect("the seed");
        let host_id = minted_host_id(&fixture.paths).await;
        let scope = scope_of(&host_id, "unknown-ws");
        let observed = observed_binding(&fixture.paths, &host_id, "unknown-ws").await;

        let mut binding = stored_binding_object(&observed);
        binding.insert(
            "future_note".to_owned(),
            json!({"nested": [1, 2, 3], "text": "keep me"}),
        );
        let policy = json!({
            EXECUTION_BINDING_KEY: Value::Object(binding),
            "domains": {"memory": {"enabled": true, "unknown_domain_key": "keep"}},
            "future_root_key": ["a", "b"],
        });
        // The hand-built policy must be a policy the host resolver accepts, so
        // the preservation assertion below compares two resolvable documents.
        assert_eq!(
            host_binding::classify(Some(&policy)),
            BindingState::Present(observed.clone())
        );
        control_store(&fixture.paths)
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(policy),
                    ..Default::default()
                },
            )
            .await
            .expect("the stored policy");

        let seeded = enable_workspace(&fixture.paths, "unknown-ws")
            .await
            .expect("the enable");
        assert_eq!(
            seeded.generation(),
            2,
            "the enable advanced the stored generation once"
        );
        let record = read_record(&fixture.paths, &host_id, "unknown-ws").await;
        let merged = record.policy.expect("the merged policy");
        assert_eq!(merged["future_root_key"], json!(["a", "b"]));
        assert_eq!(merged["domains"]["memory"]["unknown_domain_key"], json!("keep"));
        assert_eq!(
            merged[EXECUTION_BINDING_KEY]["future_note"]["text"],
            json!("keep me")
        );
        assert_eq!(
            merged[EXECUTION_BINDING_KEY]["future_note"]["nested"],
            json!([1, 2, 3])
        );
        assert_eq!(
            host_binding::classify(Some(&merged)),
            BindingState::Present(observed)
        );
    }

    #[tokio::test]
    async fn a_non_object_policy_refuses_without_rewriting_the_record() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "not-object",
            &fixture.workspace_root("not-object"),
        )
        .await
        .expect("the seed");
        let host_id = minted_host_id(&fixture.paths).await;
        let scope = scope_of(&host_id, "not-object");
        control_store(&fixture.paths)
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(json!("text")),
                    ..Default::default()
                },
            )
            .await
            .expect("the stored non-object policy");
        let record_path = control_record_path(&fixture.paths);
        let before = std::fs::read(&record_path).expect("the stored record");

        let error = enable_workspace(&fixture.paths, "not-object")
            .await
            .expect_err("a non-object policy cannot carry an execution binding");
        assert_eq!(error, SeedError::PolicyNotObject);
        assert_eq!(error.code(), "policy_not_object");
        assert_eq!(
            std::fs::read(&record_path).expect("the record"),
            before,
            "a refused merge never rewrites the stored record"
        );
    }

    #[tokio::test]
    async fn a_non_object_binding_refuses_without_rewriting_the_record() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "not-object-binding",
            &fixture.workspace_root("not-object-binding"),
        )
        .await
        .expect("the seed");
        let host_id = minted_host_id(&fixture.paths).await;
        let scope = scope_of(&host_id, "not-object-binding");
        control_store(&fixture.paths)
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    policy: ControlFieldUpdate::Set(json!({EXECUTION_BINDING_KEY: 7})),
                    ..Default::default()
                },
            )
            .await
            .expect("the stored non-object binding");
        let record_path = control_record_path(&fixture.paths);
        let before = std::fs::read(&record_path).expect("the stored record");

        let error = enable_workspace(&fixture.paths, "not-object-binding")
            .await
            .expect_err("a non-object binding cannot be merged");
        assert_eq!(error, SeedError::PolicyNotObject);
        assert_eq!(error.code(), "policy_not_object");
        assert_eq!(std::fs::read(&record_path).expect("the record"), before);
    }

    #[tokio::test]
    async fn an_existing_version_one_binding_is_replaced_by_the_observed_one() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "upgrade-ws",
            &fixture.workspace_root("upgrade-ws"),
        )
        .await
        .expect("the seed");
        let host_id = minted_host_id(&fixture.paths).await;
        let scope = scope_of(&host_id, "upgrade-ws");
        let observed = observed_binding(&fixture.paths, &host_id, "upgrade-ws").await;

        // The body the previous build wrote: no worktree facts, an unknown sub-key
        // and an unknown sibling key, on a record that is already enabled.
        let previous = json!({
            EXECUTION_BINDING_KEY: {
                "schema_version": 1,
                "host_id": host_id,
                "execution_domain": LOCAL_EXECUTION_DOMAIN,
                "workspace_id": "upgrade-ws",
                "workspace_root": observed.workspace_root(),
                "workspace_kind": "local_workspace",
                "is_worktree_child": false,
                "worktree_parent_id": null,
                "unknown_previous_key": {"keep": true},
            },
            "unknown_sibling": {"keep": "yes"},
        });
        assert_eq!(
            host_binding::classify(Some(&previous)),
            BindingState::UnsupportedSchema { observed: 1 },
            "a stored binding of the previous schema cannot be compared"
        );
        control_store(&fixture.paths)
            .update(
                &scope.as_str(),
                ControlGenerationExpectation::Absent,
                WorkspaceIntelligenceControlPatch {
                    enabled: ControlFieldUpdate::Set(true),
                    policy: ControlFieldUpdate::Set(previous),
                    ..Default::default()
                },
            )
            .await
            .expect("the stored previous-schema record");

        let seeded = enable_workspace(&fixture.paths, "upgrade-ws")
            .await
            .expect("the enable");
        assert_eq!(
            seeded.generation(),
            2,
            "replacing the known binding keys advances the generation"
        );
        let record = read_record(&fixture.paths, &host_id, "upgrade-ws").await;
        assert_eq!(record.enabled, Some(true));
        let merged = record.policy.expect("the merged policy");
        assert_eq!(
            merged[EXECUTION_BINDING_KEY]["schema_version"],
            json!(EXECUTION_BINDING_SCHEMA_VERSION)
        );
        assert_eq!(
            host_binding::classify(Some(&merged)),
            BindingState::Present(observed)
        );
        // The replacement is surgical: only the known binding keys change, so an
        // unknown sub-key and an unknown sibling key stay as stored.
        assert_eq!(
            merged[EXECUTION_BINDING_KEY]["unknown_previous_key"]["keep"],
            json!(true)
        );
        assert_eq!(merged["unknown_sibling"]["keep"], json!("yes"));
    }

    #[tokio::test]
    async fn enabling_an_unseeded_id_reads_the_catalog_before_creating_anything() {
        let fixture = Fixture::new();
        seed_local_workspace(
            &fixture.paths,
            "seeded",
            &fixture.workspace_root("seeded"),
        )
        .await
        .expect("the seed");

        let error = enable_workspace(&fixture.paths, "not-seeded")
            .await
            .expect_err("an id this catalog does not hold cannot be enabled");
        assert_eq!(error, SeedError::CatalogUnsupported);
        assert_eq!(error.code(), "catalog_unsupported");
        assert!(
            !fixture.paths.workspace_intelligence_dir().exists(),
            "a refused id creates no anchor and no control root"
        );
        assert!(!fixture.paths.workspace_intelligence_control_dir().exists());

        // The same holds for a user-data root that holds no registry at all.
        let empty = Fixture::new();
        let error = enable_workspace(&empty.paths, "absent")
            .await
            .expect_err("an empty catalog cannot be enabled");
        assert_eq!(error, SeedError::CatalogUnsupported);
        assert!(!empty.paths.workspace_intelligence_dir().exists());
    }

    /// A non-UTF-8 root cannot be rendered as a binding fact, so the seed refuses
    /// before it writes anything.
    ///
    /// This branch is covered by the pinned reader contract, but it is not
    /// compiled or executed on this Windows host; it exists so a Unix host runs
    /// it. No synthetic path stands in for it here.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_non_utf8_workspace_root_is_refused_instead_of_being_aliased() {
        use std::ffi::OsString;
        use std::os::unix::ffi::{OsStrExt, OsStringExt};

        let fixture = Fixture::new();
        let mut bytes = fixture.temp.path().as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"/repo-\xff");
        let root = PathBuf::from(OsString::from_vec(bytes));
        assert!(root.to_str().is_none(), "the fixture path is not UTF-8");

        let error = seed_local_workspace(&fixture.paths, "non-utf8", &root)
            .await
            .expect_err("a non-UTF-8 root cannot be a binding fact");
        assert_eq!(error, SeedError::InvalidInput);
        assert_eq!(error.code(), "invalid_input");
        assert!(
            !fixture.paths.user_data_dir().exists(),
            "the refusal happens before any write"
        );
    }

    #[test]
    fn seed_error_codes_are_stable_and_never_carry_a_path() {
        let cases = [
            (SeedError::InvalidInput, "invalid_input"),
            (
                SeedError::CatalogRead("catalog_unreadable"),
                "catalog_unreadable",
            ),
            (
                SeedError::CatalogRead("catalog_read_failed"),
                "catalog_read_failed",
            ),
            (SeedError::CatalogWrite, "catalog_write"),
            (SeedError::CatalogUnsupported, "catalog_unsupported"),
            (SeedError::Anchor("host_anchor_corrupt"), "host_anchor_corrupt"),
            (
                SeedError::ControlRead("control_read_failed"),
                "control_read_failed",
            ),
            (
                SeedError::ControlWrite("control_generation_conflict"),
                "control_generation_conflict",
            ),
            (
                SeedError::ControlWrite("control_write_failed"),
                "control_write_failed",
            ),
            (
                SeedError::ControlWrite("readback_mismatch"),
                "readback_mismatch",
            ),
            (SeedError::PolicyNotObject, "policy_not_object"),
            (SeedError::BindingRefused, "binding_refused"),
        ];
        for (error, expected) in cases {
            assert_eq!(error.code(), expected);
            assert!(!error.code().contains('\\'), "{expected}");
            assert!(!error.code().contains('/'), "{expected}");
        }

        // The retyped variants keep the lower owner's own code, so a code a test
        // asserts on is the code that owner reports.
        let unreadable = CatalogReadError::Unreadable {
            observed: "a bounded summary".to_owned(),
        };
        assert_eq!(
            SeedError::CatalogRead(unreadable.code()).code(),
            "catalog_unreadable"
        );
        assert_eq!(
            SeedError::Anchor(HostAnchorError::Corrupt.code()).code(),
            "host_anchor_corrupt"
        );
        assert_eq!(
            SeedError::Anchor(HostAnchorError::Symlink.code()).code(),
            "host_anchor_symlink"
        );
    }
}
