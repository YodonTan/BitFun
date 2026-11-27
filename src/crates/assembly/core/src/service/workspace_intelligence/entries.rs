//! IO half of a human cognition entry (WP2.4).
//!
//! This is the only writer of human-entered cognition content in the tree. It
//! validates through the pure contract, turns one workspace into its storage
//! scope, and commits the entry with the merged entries-plus-cursor transaction the
//! services store already owns. A retirement withdraws one entry under an exact
//! revision expectation.
//!
//! # One scope encoder, one partition key
//!
//! The store names a record and filters stored rows by the lowercase-hex SHA-256 of
//! [`WorkspaceControlScope::as_str`]. That digest helper is crate-private in the
//! services store, so [`partition_key_for_scope`] reproduces the same digest over
//! the same bytes. The two must stay in step: a change on either side is a storage
//! format change, and the round-trip test below pins the agreement.
//!
//! # Storage root
//!
//! The store root is [`PathManager::workspace_intelligence_cognition_dir`], the
//! same root [`crate::service::workspace_intelligence::partition::WorkspaceIntelligenceCognition::for_host`]
//! composes, so a row written here is the row that handle reads back.
//!
//! # What this module never does
//!
//! It never creates a partition: a scope with no v2 partition answers
//! [`EntryWriteError::PartitionUnavailable`] and stays absent. It never upgrades a
//! v1 partition, never writes a shared or global record, never derives a scope from
//! a path, and never resolves a model. Blocking store calls cross
//! `tokio::task::spawn_blocking`, so an async caller never blocks its worker.
//!
//! A commitment created here always stores `valid_until_unix_ms = None`, so the
//! injection filter never injects it
//! ([`super::entries_contract::InjectionSkip::CommitmentWithoutValidity`]) until a
//! slice adds a path that writes a time bound.

use log::debug;
use openbitfun_services_core::workspace_intelligence_cognition::{
    EntryRetirement, NewCognitionEntry, StoredCognitionEntry,
    WorkspaceIntelligenceCognitionError, WorkspaceIntelligenceCognitionStore,
};
use sha2::{Digest, Sha256};

use crate::infrastructure::PathManager;

use super::cognition::CognitionState;
use super::entries_contract::{
    kind_code, state_code, validate_human_entry, EntryValidationError, NewHumanEntry,
    ValidatedHumanEntry, AUTHORITY_HUMAN, PARTITION_VISIBILITY,
};
use super::scope::{HostExecutionDomainKey, WorkspaceControlScope};

/// What one accepted creation stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HumanEntryReceipt {
    /// Stable identity of the stored record.
    pub(crate) entry_id: String,
    /// Revision the record was stored with.
    pub(crate) revision: i64,
}

/// Why a human entry write was refused.
///
/// `Storage` carries a stable error code and never a path or a stored value, so a
/// caller can log it as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntryWriteError {
    /// The entry itself is not acceptable.
    Validation(EntryValidationError),
    /// The workspace id or the host key could not form a scope.
    ScopeUnavailable,
    /// This scope has no v2 partition this call may write to.
    PartitionUnavailable,
    /// The stored cursor is not the one the caller observed.
    CursorConflict,
    /// The entry id already exists in this partition.
    DuplicateEntry { entry_id: String },
    /// The stored revision is not the one the caller observed.
    RevisionConflict { entry_id: String },
    /// This partition holds no entry with that id.
    NotFound { entry_id: String },
    /// The entry exists but is not a human-entered record.
    NotHumanEntry { entry_id: String },
    /// The entry is already in a state a withdrawal cannot leave.
    AlreadyTerminal { entry_id: String },
    /// The store failed with a stable code.
    Storage(&'static str),
}

impl EntryWriteError {
    /// Stable machine-readable code.
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Validation(error) => error.as_str(),
            Self::ScopeUnavailable => "scope_unavailable",
            Self::PartitionUnavailable => "partition_unavailable",
            Self::CursorConflict => "cursor_conflict",
            Self::DuplicateEntry { .. } => "duplicate_entry",
            Self::RevisionConflict { .. } => "revision_conflict",
            Self::NotFound { .. } => "not_found",
            Self::NotHumanEntry { .. } => "not_human_entry",
            Self::AlreadyTerminal { .. } => "already_terminal",
            Self::Storage(_) => "storage",
        }
    }

    /// Stable failure code, including the store's own code for [`Self::Storage`].
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Storage(code) => code,
            other => other.as_str(),
        }
    }
}

/// Creates one human-entered record in the workspace's own partition.
///
/// The entry is validated first, so a refused statement never reaches storage. The
/// stored record is partition-visible, human-authored, a fact projection of the
/// statement and active, with revision `1` and epoch baseline `1`. The statement is
/// stored verbatim and its digest is derived by the store from those exact bytes.
///
/// `expected_cursor` is compared with the stored cursor exactly, with the same
/// semantics as the store's own cursor advance: a mismatch writes nothing and
/// answers [`EntryWriteError::CursorConflict`].
pub(crate) async fn create_human_entry(
    paths: &PathManager,
    host: &HostExecutionDomainKey,
    workspace_id: &str,
    input: NewHumanEntry,
    expected_cursor: Option<&str>,
    now_unix_ms: i64,
) -> Result<HumanEntryReceipt, EntryWriteError> {
    let entry_id = uuid::Uuid::new_v4().to_string();
    create_human_entry_with_id(
        paths,
        host,
        workspace_id,
        input,
        expected_cursor,
        now_unix_ms,
        entry_id,
    )
    .await
}

/// Creates one human-entered record with a caller-supplied entry id.
///
/// This is the shared body of [`create_human_entry`] and the only way a test can
/// name a record before it exists. Production callers never choose an id.
async fn create_human_entry_with_id(
    paths: &PathManager,
    host: &HostExecutionDomainKey,
    workspace_id: &str,
    input: NewHumanEntry,
    expected_cursor: Option<&str>,
    now_unix_ms: i64,
    entry_id: String,
) -> Result<HumanEntryReceipt, EntryWriteError> {
    let validated = validate_human_entry(&input).map_err(EntryWriteError::Validation)?;
    let scope = WorkspaceControlScope::new(host, workspace_id)
        .ok_or(EntryWriteError::ScopeUnavailable)?;
    let entry = new_cognition_entry(&validated, now_unix_ms, entry_id);
    let receipt = write_entry(
        paths,
        scope.as_str(),
        expected_cursor.map(str::to_owned),
        entry,
    )
    .await?;

    debug!(
        "Workspace intelligence human entry created: workspace_id={} entry_id={} revision={}",
        workspace_id, receipt.entry_id, receipt.revision
    );
    Ok(receipt)
}

/// Withdraws one human-entered record under an exact revision expectation.
///
/// The record must exist, be human-authored, and still be in a state a withdrawal
/// may leave (`active`, `pending` or `conflict`). The withdrawal stores
/// `withdrawn` and the caller's reason, increments the revision, and rejects a
/// stored revision that is not the expected one, so two callers cannot both
/// withdraw the same observed revision.
///
/// Concurrency safety rests on the second transaction's `expected_revision`
/// compare-and-set, not on the read above it: every writer that changes a record's
/// state bumps its revision, and both the merged commit primitive and this module
/// do, so the checks above can only ever be stale advice. A writer that changed a
/// state without bumping the revision would break that premise.
pub(crate) async fn retire_human_entry(
    paths: &PathManager,
    host: &HostExecutionDomainKey,
    workspace_id: &str,
    entry_id: &str,
    expected_revision: i64,
    reason: &str,
    expected_cursor: Option<&str>,
) -> Result<(), EntryWriteError> {
    let scope = WorkspaceControlScope::new(host, workspace_id)
        .ok_or(EntryWriteError::ScopeUnavailable)?;
    let store_scope = scope.as_str();

    let stored = read_entries(paths, store_scope.clone()).await?;
    let stored = stored.ok_or(EntryWriteError::PartitionUnavailable)?;
    let target = stored
        .iter()
        .find(|entry| entry.entry_id == entry_id)
        .ok_or_else(|| EntryWriteError::NotFound {
            entry_id: entry_id.to_string(),
        })?;
    if target.authority != AUTHORITY_HUMAN {
        return Err(EntryWriteError::NotHumanEntry {
            entry_id: entry_id.to_string(),
        });
    }
    if !matches!(
        target.state.as_str(),
        "active" | "pending" | "conflict"
    ) {
        return Err(EntryWriteError::AlreadyTerminal {
            entry_id: entry_id.to_string(),
        });
    }

    let retirement = EntryRetirement {
        entry_id: entry_id.to_string(),
        expected_revision,
        new_state: state_code(CognitionState::Withdrawn).to_string(),
        reason: Some(reason.to_string()),
    };
    withdraw_entry(
        paths,
        store_scope,
        expected_cursor.map(str::to_owned),
        retirement,
    )
    .await?;

    debug!(
        "Workspace intelligence human entry withdrawn: workspace_id={} entry_id={}",
        workspace_id, entry_id
    );
    Ok(())
}

/// The stored record one validated entry becomes.
///
/// It is a fact projection of a human statement, so the category is `fact` and the
/// authority is `human`; the visibility is this partition's own, so no shared scope
/// or authorization is stored. A later slice owns derived records, shared
/// visibility and any validity bound.
fn new_cognition_entry(
    validated: &ValidatedHumanEntry,
    now_unix_ms: i64,
    entry_id: String,
) -> NewCognitionEntry {
    NewCognitionEntry {
        entry_id,
        kind: kind_code(validated.kind).to_string(),
        category: "fact".to_string(),
        authority: AUTHORITY_HUMAN.to_string(),
        state: state_code(CognitionState::Active).to_string(),
        statement: validated.statement.clone(),
        workspace_partition: String::new(),
        visibility: PARTITION_VISIBILITY.to_string(),
        shared_scope: None,
        shared_authorization: None,
        source_owner: AUTHORITY_HUMAN.to_string(),
        source_resource: validated.source_resource.clone(),
        source_revision: None,
        observed_at_unix_ms: now_unix_ms,
        valid_until_unix_ms: None,
        confidence: None,
        revision: 1,
        epoch: 1,
        supersedes: None,
        invalidated_reason: None,
    }
}

/// Commits one new entry through the store's merged transaction.
async fn write_entry(
    paths: &PathManager,
    store_scope: String,
    expected_cursor: Option<String>,
    mut entry: NewCognitionEntry,
) -> Result<HumanEntryReceipt, EntryWriteError> {
    entry.workspace_partition = partition_key_for_scope(&store_scope);
    let entry_id = entry.entry_id.clone();
    let store = cognition_store(paths);
    let committed = tokio::task::spawn_blocking(move || {
        store.commit_entries_with_cursor(
            &store_scope,
            expected_cursor.as_deref(),
            None,
            &[entry],
            &[],
        )
    })
    .await
    .map_err(|_| EntryWriteError::Storage("blocking_task_failed"))?
    .map_err(|error| map_store_error(error, &entry_id))?;

    debug_assert_eq!(
        committed.committed_entry_ids,
        vec![entry_id.clone()],
        "one committed entry must report the id it was asked to commit"
    );
    Ok(HumanEntryReceipt {
        entry_id,
        revision: 1,
    })
}

/// Commits one withdrawal through the store's merged transaction.
async fn withdraw_entry(
    paths: &PathManager,
    store_scope: String,
    expected_cursor: Option<String>,
    retirement: EntryRetirement,
) -> Result<(), EntryWriteError> {
    let entry_id = retirement.entry_id.clone();
    let store = cognition_store(paths);
    tokio::task::spawn_blocking(move || {
        store.commit_entries_with_cursor(
            &store_scope,
            expected_cursor.as_deref(),
            None,
            &[],
            &[retirement],
        )
    })
    .await
    .map_err(|_| EntryWriteError::Storage("blocking_task_failed"))?
    .map_err(|error| map_store_error(error, &entry_id))?;
    Ok(())
}

/// Reads the stored entries of one scope.
async fn read_entries(
    paths: &PathManager,
    store_scope: String,
) -> Result<Option<Vec<StoredCognitionEntry>>, EntryWriteError> {
    let store = cognition_store(paths);
    tokio::task::spawn_blocking(move || store.read_entries(&store_scope))
        .await
        .map_err(|_| EntryWriteError::Storage("blocking_task_failed"))?
        .map_err(|error| match error {
            WorkspaceIntelligenceCognitionError::ContentTableAbsent { .. }
            | WorkspaceIntelligenceCognitionError::UninitializedDatabase { .. }
            | WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { .. } => {
                EntryWriteError::PartitionUnavailable
            }
            other => EntryWriteError::Storage(other.code()),
        })
}

/// The cognition store over this host's cognition root.
///
/// The root is the one the core cognition handle composes, so a write here and a
/// read through that handle observe the same record.
fn cognition_store(paths: &PathManager) -> WorkspaceIntelligenceCognitionStore {
    WorkspaceIntelligenceCognitionStore::new(paths.workspace_intelligence_cognition_dir())
}

/// The stored `workspace_partition` value of one scope string.
///
/// This must equal the digest the store derives from the same scope bytes: the
/// store selects rows by that value, so a different digest would store a row no
/// reader ever sees. The digest is lowercase hex SHA-256 of
/// [`WorkspaceControlScope::as_str`], exactly as the store computes it.
pub(crate) fn partition_key_for_scope(store_scope: &str) -> String {
    format!("{:x}", Sha256::digest(store_scope.as_bytes()))
}

/// Maps one store failure onto the typed entry write error.
fn map_store_error(
    error: WorkspaceIntelligenceCognitionError,
    entry_id: &str,
) -> EntryWriteError {
    match error {
        WorkspaceIntelligenceCognitionError::CursorPartitionUnavailable { .. } => {
            EntryWriteError::PartitionUnavailable
        }
        // Unreachable on the commit path: `commit_entries_with_cursor` answers
        // `CursorPartitionUnavailable` for a v1 record, so a commit never reports a
        // missing content table. It stays mapped so this match remains total.
        WorkspaceIntelligenceCognitionError::ContentTableAbsent { .. } => {
            EntryWriteError::PartitionUnavailable
        }
        WorkspaceIntelligenceCognitionError::UninitializedDatabase { .. } => {
            EntryWriteError::PartitionUnavailable
        }
        WorkspaceIntelligenceCognitionError::UnsupportedSchemaVersion { .. } => {
            EntryWriteError::PartitionUnavailable
        }
        WorkspaceIntelligenceCognitionError::CursorConflict { .. } => {
            EntryWriteError::CursorConflict
        }
        WorkspaceIntelligenceCognitionError::EntryDuplicate { .. } => {
            EntryWriteError::DuplicateEntry {
                entry_id: entry_id.to_string(),
            }
        }
        WorkspaceIntelligenceCognitionError::EntryRevisionConflict { .. } => {
            EntryWriteError::RevisionConflict {
                entry_id: entry_id.to_string(),
            }
        }
        other => EntryWriteError::Storage(other.code()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openbitfun_services_core::workspace_intelligence_cognition::StoredCognitionEntry;

    use crate::service::workspace_intelligence::cognition::CognitionKind;

    const WORKSPACE_ID: &str = "workspace-entries-a";
    const NOW: i64 = 1_700_000_000_000;

    fn human(statement: &str) -> NewHumanEntry {
        NewHumanEntry {
            kind: CognitionKind::Goal,
            statement: statement.to_string(),
            source_resource: None,
        }
    }

    fn host() -> HostExecutionDomainKey {
        HostExecutionDomainKey::new("host-entries-fixture", "local").expect("the fixture host is valid")
    }

    fn paths(root: &std::path::Path) -> PathManager {
        PathManager::with_user_root_for_tests(root.join("user"))
    }

    /// A scope string for the fixture host.
    fn scope_str(workspace_id: &str) -> String {
        WorkspaceControlScope::new(&host(), workspace_id)
            .expect("the fixture scope is valid")
            .as_str()
    }

    /// Creates the v2 partition a write needs and returns the store over it.
    fn partition(paths: &PathManager, workspace_id: &str) -> WorkspaceIntelligenceCognitionStore {
        let store = cognition_store(paths);
        store
            .initialize(&scope_str(workspace_id))
            .expect("the fixture partition must initialize");
        store
    }

    fn stored_entries(
        paths: &PathManager,
        workspace_id: &str,
    ) -> Vec<StoredCognitionEntry> {
        cognition_store(paths)
            .read_entries(&scope_str(workspace_id))
            .expect("the fixture partition is readable")
            .expect("the fixture partition exists")
    }

    async fn create(
        paths: &PathManager,
        statement: &str,
        expected_cursor: Option<&str>,
        entry_id: &str,
    ) -> Result<HumanEntryReceipt, EntryWriteError> {
        create_human_entry_with_id(
            paths,
            &host(),
            WORKSPACE_ID,
            human(statement),
            expected_cursor,
            NOW,
            entry_id.to_string(),
        )
        .await
    }

    #[tokio::test]
    async fn a_created_entry_is_readable_through_the_store() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);

        let receipt = create(&paths, "ship the scoped read", None, "entry-1")
            .await
            .expect("the entry is created");

        assert_eq!(receipt.entry_id, "entry-1");
        assert_eq!(receipt.revision, 1);
        let stored = stored_entries(&paths, WORKSPACE_ID);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].entry_id, "entry-1");
        assert_eq!(stored[0].kind, "goal");
        assert_eq!(stored[0].category, "fact");
        assert_eq!(stored[0].authority, "human");
        assert_eq!(stored[0].state, "active");
        assert_eq!(stored[0].visibility, "partition");
        assert_eq!(stored[0].statement, "ship the scoped read");
        assert_eq!(stored[0].revision, 1);
        assert_eq!(stored[0].epoch, 1);
        assert_eq!(stored[0].observed_at_unix_ms, NOW);
        assert_eq!(stored[0].shared_scope, None);
        // Reading one row back through the store is itself the evidence that the
        // partition key core wrote equals the digest the store selects by: a
        // different key would have stored a row this read cannot see.
        let validated = validate_human_entry(&human("ship the scoped read"))
            .expect("the fixture statement is acceptable");
        assert_eq!(
            stored[0].content_digest, validated.content_digest,
            "the digest the contract derived equals the digest the store stored"
        );
    }

    #[tokio::test]
    async fn a_duplicate_entry_id_is_refused_and_changes_nothing() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);
        create(&paths, "first", None, "entry-1")
            .await
            .expect("the first entry is created");

        let error = create(&paths, "second", None, "entry-1")
            .await
            .expect_err("a duplicate id is refused");

        assert_eq!(error.code(), "duplicate_entry");
        assert_eq!(
            error,
            EntryWriteError::DuplicateEntry {
                entry_id: "entry-1".to_string()
            }
        );
        let stored = stored_entries(&paths, WORKSPACE_ID);
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].statement, "first", "the first row is untouched");
    }

    #[tokio::test]
    async fn a_cursor_mismatch_writes_no_entry() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);

        let error = create(&paths, "first", Some("wrong"), "entry-1")
            .await
            .expect_err("the observed cursor does not match");

        assert_eq!(error.code(), "cursor_conflict");
        assert!(stored_entries(&paths, WORKSPACE_ID).is_empty());
    }

    #[tokio::test]
    async fn a_workspace_without_a_partition_is_never_created() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());

        let error = create(&paths, "first", None, "entry-1")
            .await
            .expect_err("a missing partition is not created");

        assert_eq!(error.code(), "partition_unavailable");
        assert!(
            !paths.workspace_intelligence_cognition_dir().exists(),
            "a refused write must not create the cognition root or a record"
        );
    }

    #[tokio::test]
    async fn a_refused_statement_never_reaches_storage() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);

        for (statement, code) in [
            ("", "empty_statement"),
            ("   \t\n ", "whitespace_only_statement"),
        ] {
            let error = create(&paths, statement, None, "entry-1")
                .await
                .expect_err("a blank statement is refused");
            assert_eq!(error.code(), code);
            assert!(matches!(error, EntryWriteError::Validation(_)));
        }

        let too_long = "a".repeat(2001);
        let error = create(&paths, &too_long, None, "entry-2")
            .await
            .expect_err("an over-long statement is refused");
        assert_eq!(error.code(), "statement_too_long");
        assert!(stored_entries(&paths, WORKSPACE_ID).is_empty());
    }

    #[tokio::test]
    async fn a_blank_workspace_id_has_no_scope() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());

        let error = create_human_entry(
            &paths,
            &host(),
            "   ",
            human("text"),
            None,
            NOW,
        )
        .await
        .expect_err("a blank workspace id has no scope");

        assert_eq!(error, EntryWriteError::ScopeUnavailable);
        assert!(!paths.workspace_intelligence_cognition_dir().exists());
    }

    #[tokio::test]
    async fn retiring_a_human_entry_withdraws_it_and_bumps_the_revision() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);
        create(&paths, "first", None, "entry-1")
            .await
            .expect("the entry is created");

        retire_human_entry(
            &paths,
            &host(),
            WORKSPACE_ID,
            "entry-1",
            1,
            "no longer true",
            None,
        )
        .await
        .expect("the withdrawal succeeds");

        let stored = stored_entries(&paths, WORKSPACE_ID);
        assert_eq!(stored[0].state, "withdrawn");
        assert_eq!(stored[0].revision, 2);
        assert_eq!(
            stored[0].invalidated_reason.as_deref(),
            Some("no longer true")
        );
        assert_eq!(stored[0].statement, "first", "the statement is untouched");
    }

    #[tokio::test]
    async fn a_derived_entry_is_never_withdrawn_as_a_human_one() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        let store = partition(&paths, WORKSPACE_ID);
        let scope = scope_str(WORKSPACE_ID);
        let derived = NewCognitionEntry {
            entry_id: "derived-1".to_string(),
            kind: "knowledge".to_string(),
            category: "fact".to_string(),
            authority: "derived".to_string(),
            state: "active".to_string(),
            statement: "derived text".to_string(),
            workspace_partition: partition_key_for_scope(&scope),
            visibility: "partition".to_string(),
            shared_scope: None,
            shared_authorization: None,
            source_owner: "session".to_string(),
            source_resource: None,
            source_revision: None,
            observed_at_unix_ms: NOW,
            valid_until_unix_ms: None,
            confidence: None,
            revision: 1,
            epoch: 1,
            supersedes: None,
            invalidated_reason: None,
        };
        store
            .commit_entries_with_cursor(&scope, None, None, &[derived], &[])
            .expect("the derived fixture is stored");

        let error = retire_human_entry(&paths, &host(), WORKSPACE_ID, "derived-1", 1, "why", None)
            .await
            .expect_err("a derived entry is not a human entry");

        assert_eq!(error, EntryWriteError::NotHumanEntry {
            entry_id: "derived-1".to_string()
        });
        assert_eq!(stored_entries(&paths, WORKSPACE_ID)[0].state, "active");
    }

    #[tokio::test]
    async fn an_already_withdrawn_entry_is_not_withdrawn_again() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);
        create(&paths, "first", None, "entry-1")
            .await
            .expect("the entry is created");
        retire_human_entry(&paths, &host(), WORKSPACE_ID, "entry-1", 1, "once", None)
            .await
            .expect("the first withdrawal succeeds");

        let error = retire_human_entry(&paths, &host(), WORKSPACE_ID, "entry-1", 2, "twice", None)
            .await
            .expect_err("a withdrawn entry is terminal");

        assert_eq!(error, EntryWriteError::AlreadyTerminal {
            entry_id: "entry-1".to_string()
        });
    }

    #[tokio::test]
    async fn a_stale_revision_is_refused_and_the_entry_survives() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);
        create(&paths, "first", None, "entry-1")
            .await
            .expect("the entry is created");

        let error = retire_human_entry(&paths, &host(), WORKSPACE_ID, "entry-1", 7, "why", None)
            .await
            .expect_err("the observed revision is not the stored one");

        assert_eq!(error, EntryWriteError::RevisionConflict {
            entry_id: "entry-1".to_string()
        });
        let stored = stored_entries(&paths, WORKSPACE_ID);
        assert_eq!(stored[0].state, "active");
        assert_eq!(stored[0].revision, 1);
    }

    #[tokio::test]
    async fn an_unknown_entry_id_is_reported_as_missing() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);

        let error = retire_human_entry(&paths, &host(), WORKSPACE_ID, "absent", 1, "why", None)
            .await
            .expect_err("the entry does not exist");

        assert_eq!(error, EntryWriteError::NotFound {
            entry_id: "absent".to_string()
        });
    }

    #[tokio::test]
    async fn two_workspaces_never_see_each_others_entries() {
        let root = tempfile::tempdir().expect("temporary root");
        let paths = paths(root.path());
        partition(&paths, WORKSPACE_ID);
        partition(&paths, "workspace-entries-b");
        create(&paths, "mine", None, "entry-1")
            .await
            .expect("the entry is created");

        assert!(stored_entries(&paths, "workspace-entries-b").is_empty());
        let error = retire_human_entry(
            &paths,
            &host(),
            "workspace-entries-b",
            "entry-1",
            1,
            "why",
            None,
        )
        .await
        .expect_err("another workspace cannot retire this entry");
        assert_eq!(error, EntryWriteError::NotFound {
            entry_id: "entry-1".to_string()
        });
    }

    #[test]
    fn storage_error_codes_are_stable_without_a_path() {
        assert_eq!(
            EntryWriteError::Storage("corrupt_database").code(),
            "corrupt_database"
        );
        assert_eq!(
            EntryWriteError::Storage("corrupt_database").as_str(),
            "storage"
        );
        assert_eq!(
            EntryWriteError::Validation(EntryValidationError::EmptyStatement).code(),
            "empty_statement"
        );
        assert_eq!(
            EntryWriteError::PartitionUnavailable.code(),
            "partition_unavailable"
        );
        assert_eq!(EntryWriteError::CursorConflict.code(), "cursor_conflict");
    }
}
