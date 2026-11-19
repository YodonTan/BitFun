//! Read-only snapshot of the persisted workspace registry.
//!
//! Workspace intelligence host bootstrap needs one thing from the workspace
//! catalog: which persisted records exist, and their stable structural facts.
//! That answer must come from disk, not from the process-local catalog snapshot:
//! another host process can rewrite the registry with no local event, so an
//! in-memory list (even `WorkspaceService::list_workspace_infos`) cannot be a
//! source of authority for an owner claim.
//!
//! This reader belongs to the workspace intelligence host slice
//! (`workspace-intelligence-host`), not to the workspace runtime: the host needs
//! the persisted registry without compiling a workspace runtime, so this module
//! depends only on the services persistence/registry owners and never names
//! `WorkspaceService` in any code path.
//!
//! It decodes the registry through the SAME persistence owner the workspace
//! service uses at startup: the `workspace_data` document under the user-data
//! root this host's [`PathManager`] resolves, decoded as
//! [`WorkspacePersistenceData`] and validated with
//! [`validate_workspace_persistence_data`], and nothing else. The root is never a
//! caller-supplied parameter, so this reader cannot be pointed at another
//! profile's registry. It is a read-only reader:
//!
//! - it performs no startup, no reset, no refresh, no catalog save, no migration
//!   write, no SSH activation, no network access, and never creates a directory;
//! - a missing registry file is an empty catalog, not an error and not a write;
//! - an unreadable, undecodable, wrong-product, wrong-version or structurally
//!   invalid registry is a typed error. There is deliberately no fallback to an
//!   in-memory catalog, because a stale list would admit an owner claim for a
//!   workspace this host no longer has;
//! - the startup path's in-memory-only legacy upgrade
//!   `WorkspaceService::load_workspace_history_only` ->
//!   `legacy_compat::upgrade_legacy_worktree_references`
//!   (`workspace/service.rs:2100-2104`) is NOT invoked here, and
//!   `legacy_compat::pin_legacy_port_scoped_identities` (called at
//!   `workspace/service.rs:2117`) is NOT invoked either. A record the worktree
//!   upgrade would have turned into a child is reported as
//!   [`PersistedCatalogUnsupported::LegacyWorktreeReference`] instead of being
//!   silently accepted or rewritten. A stored main-workspace record is not such a
//!   case: it is already the parent of its group, so it stays eligible without a
//!   parent id.
//!
//! ## Why not running the port-scoped pin is safe here
//!
//! `legacy_compat::pin_legacy_port_scoped_identities` cannot change the
//! classification of anything this reader reports, because it returns early for
//! every record that is not `WorkspaceKind::Remote`
//! (`workspace/legacy_compat.rs:99-102`:
//! `if record.workspace_kind != WorkspaceKind::Remote { continue; }`), and every
//! `Remote` record is already reported as
//! [`PersistedCatalogUnsupported::RemoteScope`] — classified on
//! `workspace_kind` before its root path or metadata is inspected. This reader
//! therefore makes no claim about pinning: it only guarantees that no
//! classification it produces would have differed had the pin run.
//!
//! ## Identity
//!
//! [`PersistedWorkspace::id`] is the persisted `WorkspaceInfo.id` verbatim. This
//! module never recomputes `local_workspace_stable_storage_id` and never compares
//! the persisted id against a recomputed one: a relocated data root and a legacy
//! record legitimately disagree, and filtering on that would refuse valid records.
//!
//! ## Paths
//!
//! The registry location is derived from the caller's [`PathManager`] and from
//! nothing else: [`catalog_path`] is the same `user_data_dir()` base directory
//! and the same `workspace_data` key the persistence owner resolves in
//! `PersistenceService::new_user_level`
//! (`infrastructure/storage/persistence.rs:28`), so one `PathManager` yields one
//! control root, one cognition root, one lease root and one registry. There is
//! deliberately no `base_dir` parameter and no free `PathBuf`: a mis-assembly
//! cannot point this reader at a different user-data root than the roots the same
//! host claims tenure over.
//!
//! A `Remote` record is classified before its root path is inspected, so a POSIX
//! remote path is never split or reinterpreted with local path semantics. The
//! normalized root of an eligible record is a purely lexical rendering of the
//! persisted path (separators unified, trailing separator dropped); it is an
//! execution-binding fact, not a canonicalized filesystem answer, and it never
//! performs IO on the workspace root.

use std::path::{Path, PathBuf};

use openbitfun_core_types::product_identity::product_id;
use openbitfun_services_core::persistence::PersistenceService;
use openbitfun_services_core::workspace_persistence::{
    validate_workspace_persistence_data, WorkspacePersistenceData,
    WORKSPACE_PERSISTENCE_FORMAT_VERSION,
};
use openbitfun_services_core::workspace_records::{WorkspaceInfo, WorkspaceKind};

use crate::infrastructure::PathManager;

/// Persistence key of the workspace registry. Owned by the workspace service.
pub(crate) const WORKSPACE_CATALOG_KEY: &str = "workspace_data";

/// Structural kind of one eligible local workspace record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistedWorkspaceKind {
    /// A normal local workspace record that is not a worktree child.
    LocalWorkspace,
    /// A local worktree child record whose parent resolves in this snapshot.
    LocalWorktreeChild,
}

impl PersistedWorkspaceKind {
    /// Stable machine-readable code used by the execution binding and by logs.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::LocalWorkspace => "local_workspace",
            Self::LocalWorktreeChild => "local_worktree_child",
        }
    }
}

/// One eligible local workspace projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistedWorkspace {
    id: String,
    root: String,
    kind: PersistedWorkspaceKind,
    worktree_parent_id: Option<String>,
    worktree_is_main: Option<bool>,
    main_repo_path: Option<String>,
}

impl PersistedWorkspace {
    /// The persisted workspace id, verbatim and opaque.
    pub(crate) fn id(&self) -> &str {
        &self.id
    }

    /// Lexically normalized workspace root, used only as a binding fact.
    pub(crate) fn root(&self) -> &str {
        &self.root
    }

    /// Structural kind of this record.
    pub(crate) fn kind(&self) -> PersistedWorkspaceKind {
        self.kind
    }

    /// True when this record is a worktree child.
    pub(crate) fn is_worktree_child(&self) -> bool {
        self.kind == PersistedWorkspaceKind::LocalWorktreeChild
    }

    /// Resolved parent workspace id of a worktree child.
    pub(crate) fn worktree_parent_id(&self) -> Option<&str> {
        self.worktree_parent_id.as_deref()
    }

    /// The stored `worktree.is_main`, or `None` when the record carries no
    /// worktree block.
    ///
    /// This is an observed binding fact and nothing else. `is_main == true` and
    /// "no worktree block at all" project onto the same kind and the same absent
    /// parent id, so without this fact a persisted projection changing from one to
    /// the other would be invisible to a binding comparison.
    pub(crate) fn worktree_is_main(&self) -> Option<bool> {
        self.worktree_is_main
    }

    /// The stored `worktree.main_repo_path`, normalized like the workspace root,
    /// or `None` when the record carries no worktree block or the stored value is
    /// not a usable local absolute path.
    ///
    /// A binding comparison fact only: it is never an IO path and never an
    /// eligibility filter.
    pub(crate) fn main_repo_path(&self) -> Option<&str> {
        self.main_repo_path.as_deref()
    }
}

/// Why a persisted record can never hold a governed scope on this host.
///
/// These are structural or product refusals, not control faults: nothing is
/// enabled, claimed, rewritten or deleted for such a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistedCatalogUnsupported {
    /// A remote/SSH workspace. Remote execution domains are not supported by this
    /// wave, so no `remote:<connection>` scope is ever minted.
    RemoteScope,
    /// An assistant workspace is not a governance target.
    AssistantWorkspace,
    /// A worktree record without `main_workspace_id`: the startup path would fill
    /// it in memory, and this reader refuses to guess or rewrite it.
    LegacyWorktreeReference,
    /// A worktree child whose `main_workspace_id` does not resolve in this
    /// snapshot. Never substituted with the parent path or a parent id.
    UnresolvedWorktreeParent,
    /// A local record whose root is not valid UTF-8. The root is a binding
    /// comparison fact, so it is rendered exactly or not at all: substituting
    /// replacement characters would let two different roots compare equal.
    NonUtf8Root,
    /// A local record that fails structural validation (blank id, non-absolute or
    /// empty root).
    MalformedRecord,
}

impl PersistedCatalogUnsupported {
    /// Stable machine-readable code used by status data and logs.
    pub(crate) fn code(self) -> &'static str {
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

/// Classification of one persisted workspace id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PersistedCatalogEntry {
    /// Structurally eligible to hold a governed scope.
    Eligible(PersistedWorkspace),
    /// Never eligible on this host.
    Unsupported(PersistedCatalogUnsupported),
}

/// One read of the persisted registry.
///
/// Entries are sorted by persisted id so every consumer observes a deterministic
/// order, and ids are reported verbatim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PersistedCatalog {
    entries: Vec<(String, PersistedCatalogEntry)>,
}

impl PersistedCatalog {
    /// Every persisted workspace id with its classification, sorted by id.
    pub(crate) fn entries(&self) -> &[(String, PersistedCatalogEntry)] {
        &self.entries
    }

    /// Every structurally eligible local workspace.
    pub(crate) fn eligible(&self) -> impl Iterator<Item = &PersistedWorkspace> {
        self.entries.iter().filter_map(|(_, entry)| match entry {
            PersistedCatalogEntry::Eligible(workspace) => Some(workspace),
            PersistedCatalogEntry::Unsupported(_) => None,
        })
    }

    /// The eligible projection of `id`, if this snapshot still has one.
    pub(crate) fn workspace(&self, id: &str) -> Option<&PersistedWorkspace> {
        self.entries
            .iter()
            .find(|(entry_id, _)| entry_id == id)
            .and_then(|(_, entry)| match entry {
                PersistedCatalogEntry::Eligible(workspace) => Some(workspace),
                PersistedCatalogEntry::Unsupported(_) => None,
            })
    }

    /// Number of entries that can never hold a scope.
    pub(crate) fn unsupported_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|(_, entry)| matches!(entry, PersistedCatalogEntry::Unsupported(_)))
            .count()
    }
}

/// Typed failure of one read-only registry snapshot.
///
/// Every variant is a refusal. No variant carries a fallback catalog, and no
/// variant is resolved by rewriting or deleting the persisted registry.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CatalogReadError {
    /// The registry exists but could not be read or decoded as the current
    /// persistence shape.
    #[error("the persisted workspace registry is unreadable: {observed}")]
    Unreadable { observed: String },
    /// The registry was written by a different product identity.
    #[error("the persisted workspace registry belongs to another product: {observed}")]
    UnsupportedProduct { observed: String },
    /// The registry declares a format version this build does not implement.
    #[error("the persisted workspace registry declares unsupported format version {observed}")]
    UnsupportedFormat { observed: u32 },
    /// The registry decodes but fails the owner's structural validation.
    #[error("the persisted workspace registry is invalid: {observed}")]
    InvalidPersistence { observed: String },
}

impl CatalogReadError {
    /// Stable machine-readable code for status data and logs.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "catalog_unreadable",
            Self::UnsupportedProduct { .. } => "catalog_unsupported_product",
            Self::UnsupportedFormat { .. } => "catalog_unsupported_format",
            Self::InvalidPersistence { .. } => "catalog_invalid_persistence",
        }
    }
}

/// Bounded, printable-ASCII summary of a diagnostic detail.
///
/// Raw filesystem paths, persisted payloads and non-ASCII document text never
/// reach `Display` unbounded or verbatim.
fn observed_summary(detail: &str) -> String {
    const LIMIT: usize = 96;
    let mut summary = String::new();
    let mut truncated = false;
    for character in detail.chars() {
        if summary.chars().count() >= LIMIT {
            truncated = true;
            break;
        }
        if character.is_ascii_graphic() || character == ' ' {
            summary.push(character);
        } else {
            truncated = true;
        }
    }
    if truncated {
        summary.push_str("...");
    }
    summary
}

/// Reads the persisted workspace registry of the user-data root this host owns.
///
/// The base directory, the MiniApp root and the expected product identity are all
/// derived from `paths` and never supplied by a caller. The registry is
/// [`catalog_path`]: `workspace_data.json` under
/// [`PathManager::user_data_dir`], which is exactly the base directory the
/// workspace owner's own `PersistenceService::new_user_level` receives and exactly
/// the key its `save_json("workspace_data", ..)` writes. There is deliberately no
/// `base_dir` parameter: a caller cannot point this reader at another profile's
/// user-data root, so a mis-assembled host cannot enumerate — and therefore cannot
/// later claim — a registry it does not own.
///
/// The call is read-only: it never creates the base directory, a record, a lock
/// file or a backup, and it never rewrites the persisted bytes.
pub(crate) async fn read_persisted_catalog(
    paths: &PathManager,
) -> Result<PersistedCatalog, CatalogReadError> {
    // `from_base_dir` is the pure constructor: unlike `new`, it performs no IO
    // and cannot create the base directory. The owner-derived path keeps this
    // reader on the same keyed file the workspace owner reads and writes.
    let store = PersistenceService::from_base_dir(paths.user_data_dir());
    let data: Option<WorkspacePersistenceData> = store
        .load_json(WORKSPACE_CATALOG_KEY)
        .await
        .map_err(|error| CatalogReadError::Unreadable {
            observed: observed_summary(&error),
        })?;
    let Some(data) = data else {
        // No persisted registry is an empty catalog. It is not an error and it is
        // not a reason to create one.
        return Ok(PersistedCatalog::default());
    };

    if data.format_version != WORKSPACE_PERSISTENCE_FORMAT_VERSION {
        return Err(CatalogReadError::UnsupportedFormat {
            observed: data.format_version,
        });
    }
    let product_identity = expected_product_identity();
    if data.product_id != product_identity {
        return Err(CatalogReadError::UnsupportedProduct {
            observed: observed_summary(&data.product_id),
        });
    }
    // The owner's validator is the authority for every structural rule of the
    // registry shape. It also pins the compiled product identity, so the identity
    // compared above is the same one the validation enforces.
    validate_workspace_persistence_data(&data, &paths.miniapps_dir()).map_err(|error| {
        CatalogReadError::InvalidPersistence {
            observed: observed_summary(&error.to_string()),
        }
    })?;

    Ok(classify(&data))
}

/// Classifies every persisted record of one validated registry.
fn classify(data: &WorkspacePersistenceData) -> PersistedCatalog {
    let mut entries: Vec<(String, PersistedCatalogEntry)> = data
        .workspaces
        .values()
        .map(|record| {
            let id = record.id.clone();
            (id, classify_record(record, &data.workspaces))
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    PersistedCatalog { entries }
}

/// Structurally classifies one record without IO.
///
/// Order matters twice. The record kind is decided before the root path is
/// inspected, because a remote root is a POSIX-remote or opaque location that must
/// never be given local path semantics. Inside a worktree record, the stored
/// `is_main` is decided before the parent id is required, because a main workspace
/// is the parent of its group and not a child.
fn classify_record(
    record: &WorkspaceInfo,
    records: &std::collections::HashMap<String, WorkspaceInfo>,
) -> PersistedCatalogEntry {
    let unsupported = match record.workspace_kind {
        WorkspaceKind::Remote => Some(PersistedCatalogUnsupported::RemoteScope),
        WorkspaceKind::Assistant => Some(PersistedCatalogUnsupported::AssistantWorkspace),
        WorkspaceKind::Normal => None,
    };
    if let Some(reason) = unsupported {
        return PersistedCatalogEntry::Unsupported(reason);
    }
    if record.id.trim().is_empty() {
        return PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::MalformedRecord);
    }
    let root = match normalize_local_root(&record.root_path) {
        Ok(root) => root,
        Err(reason) => return PersistedCatalogEntry::Unsupported(reason),
    };
    let Some(worktree) = record.worktree.as_ref() else {
        return PersistedCatalogEntry::Eligible(PersistedWorkspace {
            id: record.id.clone(),
            root,
            kind: PersistedWorkspaceKind::LocalWorkspace,
            worktree_parent_id: None,
            worktree_is_main: None,
            main_repo_path: None,
        });
    };
    // The stored main-repository path is an observed fact of this record, never an
    // IO path this reader opens, and it is never an eligibility filter: eligibility
    // is decided by the record kind, the normalized root and the worktree
    // relationship alone. Because this value selects nothing, an unrenderable one
    // is recorded as absent rather than refused, and the alias cannot merge two
    // records into one scope or point this reader at a file. The residual is that
    // two distinct unrenderable values are indistinguishable in the binding, so a
    // change between them alone is not observable; every comparable change of this
    // fact is.
    let main_repo_path = normalize_local_root(Path::new(&worktree.main_repo_path)).ok();
    if worktree.is_main {
        // The main workspace of its own worktree group: it is the group's parent
        // and not a child, so it needs no `main_workspace_id`. Requiring one here
        // would mis-reject a legitimate persisted main record as a legacy
        // reference.
        return PersistedCatalogEntry::Eligible(PersistedWorkspace {
            id: record.id.clone(),
            root,
            kind: PersistedWorkspaceKind::LocalWorkspace,
            worktree_parent_id: None,
            worktree_is_main: Some(true),
            main_repo_path,
        });
    }
    let Some(parent_id) = worktree
        .main_workspace_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
    else {
        // The startup path fills this in memory and then saves the registry. This
        // reader does not run that upgrade and does not accept a guessed parent.
        return PersistedCatalogEntry::Unsupported(
            PersistedCatalogUnsupported::LegacyWorktreeReference,
        );
    };
    match records.get(parent_id) {
        Some(parent) if parent.workspace_kind == WorkspaceKind::Normal => {}
        _ => {
            return PersistedCatalogEntry::Unsupported(
                PersistedCatalogUnsupported::UnresolvedWorktreeParent,
            )
        }
    }
    PersistedCatalogEntry::Eligible(PersistedWorkspace {
        id: record.id.clone(),
        root,
        kind: PersistedWorkspaceKind::LocalWorktreeChild,
        worktree_parent_id: Some(parent_id.to_owned()),
        worktree_is_main: Some(false),
        main_repo_path,
    })
}

/// Injective, OS-native rendering of a persisted local root.
///
/// The root is a binding comparison fact, not a scope id, so it must render the
/// stored value exactly once: two different roots may never produce one string.
///
/// - A root that is not valid UTF-8 is refused instead of being rendered with
///   replacement characters, because the replacement would alias it onto a
///   different root.
/// - Separators are unified only on Windows, where `\` and `/` name the same
///   directory. On every other platform the stored string is kept as it is: a
///   backslash is a legal file-name byte there, so rewriting it would alias two
///   distinct roots. Only the trailing-separator rule applies, and a root that is
///   exactly `/` keeps exactly one separator.
/// - A Windows drive or filesystem root keeps exactly one separator too.
///
/// Nothing here touches the filesystem, so a workspace whose folder is currently
/// offline stays eligible.
fn normalize_local_root(root: &Path) -> Result<String, PersistedCatalogUnsupported> {
    let Some(text) = root.to_str() else {
        return Err(PersistedCatalogUnsupported::NonUtf8Root);
    };
    if text.trim().is_empty() || !root.is_absolute() {
        return Err(PersistedCatalogUnsupported::MalformedRecord);
    }
    #[cfg(windows)]
    let text = text.replace('\\', "/");
    #[cfg(not(windows))]
    let text = text.to_owned();
    let normalized = if text == "/" {
        // A filesystem root keeps exactly one separator; trimming it would turn an
        // absolute root into an empty string.
        "/".to_owned()
    } else {
        let without_trailing = text.trim_end_matches('/');
        if without_trailing.is_empty() {
            // Only separators were stored: keep the stored spelling instead of
            // collapsing distinct roots onto one string.
            text.clone()
        } else if without_trailing.ends_with(':') {
            // A Windows drive root keeps exactly one separator.
            format!("{without_trailing}/")
        } else {
            without_trailing.to_owned()
        }
    };
    Ok(normalized)
}

/// The product identity this build writes into a new registry.
pub(crate) fn expected_product_identity() -> &'static str {
    product_id()
}

/// Structural classification of one record against an explicit record set.
///
/// Fixtures use this so a test workspace cannot drift from the classification the
/// production reader applies to the same persisted bytes.
#[cfg(test)]
pub(crate) fn classify_record_for_tests(
    record: &WorkspaceInfo,
    records: &std::collections::HashMap<String, WorkspaceInfo>,
) -> PersistedCatalogEntry {
    classify_record(record, records)
}

/// Path of the registry file this host's user-data root stores.
///
/// Derived from the owner and therefore the single location both this reader and
/// the workspace owner address: `<user_data_dir>/workspace_data.json`.
pub(crate) fn catalog_path(paths: &PathManager) -> PathBuf {
    paths
        .user_data_dir()
        .join(format!("{WORKSPACE_CATALOG_KEY}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use openbitfun_services_core::persistence::StorageOptions;
    use sha2::{Digest, Sha256};

    /// One isolated user root.
    ///
    /// The reader derives the registry location from the [`PathManager`], so a
    /// fixture needs a real user root rather than a bare directory: it builds one
    /// through the test-only `PathManager::with_user_root_for_tests`. Passing a
    /// loose path is impossible by construction, which is exactly the property
    /// this suite relies on.
    struct Root {
        fixture: tempfile::TempDir,
        paths: PathManager,
    }

    impl Root {
        fn new() -> Self {
            let fixture = tempfile::tempdir().unwrap();
            let paths = PathManager::with_user_root_for_tests(fixture.path().join("user"));
            Self { fixture, paths }
        }

        /// Absolute-under-temp path, so fixtures never point at real user data.
        fn temp(&self) -> &Path {
            self.fixture.path()
        }

        fn data_dir(&self) -> PathBuf {
            self.paths.user_data_dir()
        }

        fn catalog_path(&self) -> PathBuf {
            catalog_path(&self.paths)
        }

        fn write(&self, document: &serde_json::Value) {
            std::fs::create_dir_all(self.data_dir()).unwrap();
            std::fs::write(self.catalog_path(), serde_json::to_vec_pretty(document).unwrap())
                .unwrap();
        }

        async fn read(&self) -> Result<PersistedCatalog, CatalogReadError> {
            read_persisted_catalog(&self.paths).await
        }

        /// Recursive content hash of the whole user root, so "no byte changed" is a
        /// property of the tree rather than of one known file.
        fn tree_hash(&self) -> String {
            tree_hash(self.temp())
        }
    }

    /// Structural classification of one fixture registry entry.
    fn record(id: &str, root: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut record = serde_json::json!({
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
        });
        if let (Some(record), Some(extra)) = (record.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                record.insert(key.clone(), value.clone());
            }
        }
        record
    }

    /// A registry document shaped exactly like the persistence owner writes it.
    fn document(records: Vec<serde_json::Value>) -> serde_json::Value {
        let mut workspaces = serde_json::Map::new();
        let mut ids = Vec::new();
        for record in records {
            let id = record["id"].as_str().expect("fixture id").to_owned();
            ids.push(id.clone());
            workspaces.insert(id, record);
        }
        serde_json::json!({
            "format_version": WORKSPACE_PERSISTENCE_FORMAT_VERSION,
            "product_id": expected_product_identity(),
            "workspaces": workspaces,
            "opened_workspace_ids": ids,
            "current_workspace_id": null,
            "recent_workspaces": [],
            "recent_assistant_workspaces": [],
            "primary_assistant_key": null,
            "assistant_name_sequence": 0,
            "saved_at": "2026-01-01T00:00:00Z",
        })
    }

    /// Absolute-under-temp local root, so fixtures never point at real user data.
    fn local_root(root: &Root, name: &str) -> String {
        root.temp().join(name).to_string_lossy().to_string()
    }

    /// Recursive content hash of one directory tree, so "no byte changed" is a
    /// property of the whole tree rather than of one known file.
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

    #[test]
    fn the_registry_location_is_the_workspace_owner_key_under_the_user_data_root() {
        let root = Root::new();
        // The literal the workspace owner writes (`save_json("workspace_data", ..)`)
        // rather than this module's own constant, so a renamed key cannot pass by
        // re-deriving the same wrong value.
        assert_eq!(root.catalog_path(), root.data_dir().join("workspace_data.json"));
        assert_eq!(WORKSPACE_CATALOG_KEY, "workspace_data");
        assert!(root.catalog_path().starts_with(root.paths.user_root_dir()));
    }

    #[tokio::test]
    async fn a_registry_written_by_the_owner_is_read_back_by_this_reader() {
        // The strongest form of the same property: the owner writes through its own
        // `PersistenceService`, and this reader must find and decode exactly that
        // file with no location hint of its own.
        let root = Root::new();
        std::fs::create_dir_all(root.data_dir()).unwrap();
        let document = document(vec![record(
            "owner-written",
            &local_root(&root, "owner"),
            serde_json::json!({}),
        )]);
        let data: WorkspacePersistenceData = serde_json::from_value(document).unwrap();
        PersistenceService::from_base_dir(root.data_dir())
            .save_json(
                "workspace_data",
                &data,
                StorageOptions {
                    create_backup: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(root.data_dir().join("workspace_data.json").is_file());

        let catalog = root.read().await.unwrap();
        assert_eq!(
            catalog.workspace("owner-written").map(|w| w.id()),
            Some("owner-written"),
            "the reader must see the registry the owner wrote"
        );
    }

    #[tokio::test]
    async fn valid_snapshot_round_trips_persisted_ids_verbatim() {
        let root = Root::new();
        let odd_id = "  legacy:id/with/separators  ";
        root.write(&document(vec![
            record(odd_id, &local_root(&root, "a"), serde_json::json!({})),
            record("plain-id", &local_root(&root, "b"), serde_json::json!({})),
        ]));

        let catalog = root.read().await.unwrap();
        let ids: Vec<_> = catalog
            .entries()
            .iter()
            .map(|(id, _)| id.as_str())
            .collect();
        assert_eq!(ids, vec!["  legacy:id/with/separators  ", "plain-id"]);
        // The id is reported verbatim: no trimming, hashing or re-derivation.
        let workspace = catalog.workspace("  legacy:id/with/separators  ").unwrap();
        assert_eq!(workspace.id(), "  legacy:id/with/separators  ");
        assert_eq!(workspace.kind(), PersistedWorkspaceKind::LocalWorkspace);
        assert!(!workspace.is_worktree_child());
        assert_eq!(workspace.worktree_parent_id(), None);
        assert_eq!(catalog.unsupported_count(), 0);
    }

    #[tokio::test]
    async fn relocated_root_with_mismatched_persisted_id_is_still_eligible() {
        let root = Root::new();
        // The persisted id cannot be the id this root would derive: a recompute
        // filter would refuse this record, and that refusal would be wrong.
        root.write(&document(vec![record(
            "moved-storage-id",
            &local_root(&root, "relocated"),
            serde_json::json!({}),
        )]));
        let catalog = root.read().await.unwrap();
        let workspace = catalog.workspace("moved-storage-id").unwrap();
        assert_eq!(workspace.id(), "moved-storage-id");
        assert_eq!(
            workspace.root(),
            local_root(&root, "relocated").replace('\\', "/")
        );
    }

    #[tokio::test]
    async fn worktree_child_without_a_resolvable_parent_is_typed_unsupported() {
        let root = Root::new();
        root.write(&document(vec![record(
            "child",
            &local_root(&root, "child"),
            serde_json::json!({
                "worktree": {
                    "mainWorkspaceId": "missing-parent",
                    "path": local_root(&root, "child"),
                    "mainRepoPath": local_root(&root, "main"),
                    "isMain": false,
                }
            }),
        )]));
        let catalog = root.read().await.unwrap();
        assert_eq!(
            catalog.entries()[0].1,
            PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::UnresolvedWorktreeParent)
        );
        assert!(catalog.workspace("child").is_none());
        assert_eq!(catalog.unsupported_count(), 1);
    }

    #[tokio::test]
    async fn resolvable_worktree_child_reports_its_resolved_parent() {
        let root = Root::new();
        root.write(&document(vec![
            record(
                "main",
                &local_root(&root, "main"),
                serde_json::json!({
                    "worktree": {
                        "mainWorkspaceId": "main",
                        "path": local_root(&root, "main"),
                        "mainRepoPath": local_root(&root, "main"),
                        "isMain": true,
                    }
                }),
            ),
            record(
                "child",
                &local_root(&root, "child"),
                serde_json::json!({
                    "worktree": {
                        "mainWorkspaceId": "main",
                        "path": local_root(&root, "child"),
                        "mainRepoPath": local_root(&root, "main"),
                        "isMain": false,
                    }
                }),
            ),
        ]));
        let catalog = root.read().await.unwrap();
        let child = catalog.workspace("child").expect("resolved child");
        assert!(child.is_worktree_child());
        assert_eq!(child.kind(), PersistedWorkspaceKind::LocalWorktreeChild);
        assert_eq!(child.worktree_parent_id(), Some("main"));
        assert_eq!(child.worktree_is_main(), Some(false));
        let expected_main_repo = normalize_local_root(&root.temp().join("main")).unwrap();
        assert_eq!(
            child.main_repo_path(),
            Some(expected_main_repo.as_str()),
            "the stored main-repository path is an observed binding fact"
        );
        let main = catalog.workspace("main").expect("main workspace");
        assert!(!main.is_worktree_child());
        assert_eq!(main.worktree_parent_id(), None);
        assert_eq!(main.worktree_is_main(), Some(true));
    }

    #[tokio::test]
    async fn a_main_workspace_without_a_parent_id_is_eligible() {
        let root = Root::new();
        // A persisted main record carries `is_main: true` and no
        // `main_workspace_id`: it is the parent of its group, not a child, so
        // requiring a parent here would mis-reject it as a legacy reference.
        root.write(&document(vec![record(
            "main",
            &local_root(&root, "main"),
            serde_json::json!({
                "worktree": {
                    "path": local_root(&root, "main"),
                    "mainRepoPath": local_root(&root, "main"),
                    "isMain": true,
                }
            }),
        )]));
        let catalog = root.read().await.unwrap();
        let main = catalog.workspace("main").expect("a main record is eligible");
        assert_eq!(main.kind(), PersistedWorkspaceKind::LocalWorkspace);
        assert!(!main.is_worktree_child());
        assert_eq!(main.worktree_parent_id(), None);
        assert_eq!(main.worktree_is_main(), Some(true));
        assert!(main.main_repo_path().is_some());
        assert_eq!(catalog.unsupported_count(), 0);
    }

    #[tokio::test]
    async fn a_record_without_a_worktree_block_carries_no_worktree_facts() {
        let root = Root::new();
        root.write(&document(vec![record(
            "plain",
            &local_root(&root, "plain"),
            serde_json::json!({}),
        )]));
        let catalog = root.read().await.unwrap();
        let plain = catalog.workspace("plain").expect("eligible");
        assert_eq!(plain.worktree_is_main(), None);
        assert_eq!(plain.main_repo_path(), None);
    }

    #[tokio::test]
    async fn legacy_worktree_record_is_unsupported_and_never_upgraded() {
        let root = Root::new();
        root.write(&document(vec![record(
            "legacy-child",
            &local_root(&root, "child"),
            serde_json::json!({
                "worktree": {
                    "path": local_root(&root, "child"),
                    "mainRepoPath": local_root(&root, "main"),
                    "isMain": false,
                }
            }),
        )]));
        let before = root.tree_hash();
        let catalog = root.read().await.unwrap();
        assert_eq!(
            catalog.entries()[0].1,
            PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::LegacyWorktreeReference)
        );
        assert_eq!(root.tree_hash(), before);
    }

    #[tokio::test]
    async fn remote_and_assistant_records_are_typed_unsupported_without_path_semantics() {
        let root = Root::new();
        root.write(&document(vec![
            record(
                "remote",
                "/srv/posix/remote",
                serde_json::json!({
                    "workspaceKind": "remote",
                    "metadata": {"connectionId": "ssh-1", "sshHost": "host"},
                }),
            ),
            record(
                "assistant",
                &local_root(&root, "assistant"),
                serde_json::json!({
                    "workspaceKind": "assistant",
                    "assistantId": "helper",
                }),
            ),
        ]));
        let catalog = root.read().await.unwrap();
        assert_eq!(
            catalog.entries()[0].1,
            PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::AssistantWorkspace)
        );
        assert_eq!(
            catalog.entries()[1].1,
            PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::RemoteScope)
        );
        assert_eq!(catalog.eligible().count(), 0);
        // A remote record keeps its persisted id and gains no connection id: the
        // kind is decided before the path or the SSH metadata is read, so no
        // remote scope can be derived from this snapshot.
        assert_eq!(catalog.entries()[1].0, "remote");
    }

    #[tokio::test]
    async fn corrupt_registry_is_a_typed_error_with_no_in_memory_fallback() {
        let root = Root::new();
        std::fs::create_dir_all(root.data_dir()).unwrap();
        std::fs::write(root.catalog_path(), b"{ \"workspaces\": ").unwrap();
        let before = root.tree_hash();
        let error = root.read().await.unwrap_err();
        assert_eq!(error.code(), "catalog_unreadable");
        assert_eq!(root.tree_hash(), before);
    }

    #[tokio::test]
    async fn unreadable_registry_is_a_typed_error_with_no_write() {
        let root = Root::new();
        // A directory where the registry file belongs: every read fails, and no
        // code path may reset or replace it.
        std::fs::create_dir_all(root.catalog_path()).unwrap();
        let before = root.tree_hash();
        let error = root.read().await.unwrap_err();
        assert_eq!(error.code(), "catalog_unreadable");
        assert_eq!(root.tree_hash(), before);
    }

    #[tokio::test]
    async fn wrong_product_and_wrong_version_are_refused() {
        let root = Root::new();

        let mut foreign_product = document(Vec::new());
        foreign_product["product_id"] = serde_json::json!("another-product");
        root.write(&foreign_product);
        assert_eq!(
            root.read().await.unwrap_err().code(),
            "catalog_unsupported_product"
        );

        let mut foreign_version = document(Vec::new());
        foreign_version["format_version"] = serde_json::json!(7);
        root.write(&foreign_version);
        assert_eq!(
            root.read().await.unwrap_err().code(),
            "catalog_unsupported_format"
        );
    }

    #[tokio::test]
    async fn relative_or_empty_local_root_is_typed_malformed() {
        let root = Root::new();
        root.write(&document(vec![
            record("relative", "relative/path", serde_json::json!({})),
            record("empty", "", serde_json::json!({})),
        ]));
        let catalog = root.read().await.unwrap();
        assert_eq!(catalog.eligible().count(), 0);
        for (_, entry) in catalog.entries() {
            assert_eq!(
                entry,
                &PersistedCatalogEntry::Unsupported(PersistedCatalogUnsupported::MalformedRecord)
            );
        }
    }

    #[tokio::test]
    async fn reading_a_missing_registry_creates_no_file_and_changes_no_byte() {
        let root = Root::new();
        std::fs::create_dir_all(root.data_dir()).unwrap();
        std::fs::write(root.data_dir().join("unrelated.txt"), b"keep").unwrap();
        let before = root.tree_hash();
        let catalog = root.read().await.unwrap();
        assert!(catalog.entries().is_empty());
        assert_eq!(root.tree_hash(), before);

        // An absent user-data root is also not created by a read.
        let absent = Root::new();
        let catalog = absent.read().await.unwrap();
        assert!(catalog.entries().is_empty());
        assert!(!absent.data_dir().exists());
    }

    #[test]
    fn a_relative_or_empty_root_is_typed_malformed() {
        assert_eq!(
            normalize_local_root(Path::new("relative")),
            Err(PersistedCatalogUnsupported::MalformedRecord),
            "a relative root is structurally unusable"
        );
        assert_eq!(
            normalize_local_root(Path::new("")),
            Err(PersistedCatalogUnsupported::MalformedRecord)
        );
    }

    #[cfg(windows)]
    #[test]
    fn local_root_normalization_unifies_windows_separators_only() {
        assert_eq!(
            normalize_local_root(Path::new(r"C:\data\repo\")),
            Ok("C:/data/repo".to_owned())
        );
        assert_eq!(
            normalize_local_root(Path::new(r"C:\")),
            Ok("C:/".to_owned()),
            "a drive root keeps exactly one separator"
        );
        assert_eq!(
            normalize_local_root(Path::new(r"\\server\share\repo")),
            Ok("//server/share/repo".to_owned()),
            "a UNC root is unified without losing its leading separators"
        );
    }

    // The two Unix cases below are not executable on a Windows host; they exist so
    // the injective rendering is pinned where a backslash is a legal name byte.
    #[cfg(unix)]
    #[test]
    fn a_stored_backslash_is_a_file_name_byte_and_never_a_separator() {
        let literal = normalize_local_root(Path::new("/data/a\\b")).unwrap();
        let separator = normalize_local_root(Path::new("/data/a/b")).unwrap();
        // A POSIX file name may contain a backslash, so unifying it with `/` would
        // alias two different roots onto one comparison fact.
        assert_eq!(literal, "/data/a\\b");
        assert_eq!(separator, "/data/a/b");
        assert_ne!(literal, separator);
    }

    #[cfg(unix)]
    #[test]
    fn the_unix_filesystem_root_keeps_exactly_one_separator() {
        assert_eq!(normalize_local_root(Path::new("/")), Ok("/".to_owned()));
        assert_eq!(
            normalize_local_root(Path::new("/data/repo///")),
            Ok("/data/repo".to_owned())
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_root_is_typed_unsupported_instead_of_aliased() {
        use std::os::unix::ffi::OsStrExt;
        let root = Path::new(std::ffi::OsStr::from_bytes(b"/data/\xff"));
        assert_eq!(
            normalize_local_root(root),
            Err(PersistedCatalogUnsupported::NonUtf8Root),
            "a lossy rendering would alias this root onto another one"
        );
        assert_eq!(
            PersistedCatalogUnsupported::NonUtf8Root.code(),
            "non_utf8_root"
        );
    }
}
