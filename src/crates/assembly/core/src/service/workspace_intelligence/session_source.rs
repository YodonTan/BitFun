//! Read-only Session directory snapshot source for workspace intelligence.
//!
//! # P1 source slice: WP1.5-b first slice
//!
//! This module is the first real source of WP1.5 and it is a pure reader. It takes an
//! already resolved Session storage root and produces one deterministic snapshot marker over
//! the bytes it read: the index's session set, the valid and invalid counts, and a
//! per-session digest of the raw `metadata.json` bytes plus the `turn-catalog.json` revision.
//!
//! # What this slice deliberately does not deliver
//!
//! - no write of any kind: no file, no directory, no lock and no cursor. It never calls the
//!   owner's index snapshot read, because that path takes an exclusive `.index.lock` and
//!   rebuilds a missing or unparseable index by writing `index.json`. This module reads
//!   `index.json`, every `metadata.json` and every `turn-catalog.json` itself, with lock-free
//!   read-only calls;
//! - no persistence and no decision: it produces an observation and, when that observation is
//!   complete, an [`OfferedStep`] for `cursor::decide_step`. Recording the marker and calling
//!   the decision belong to the next slice;
//! - no repair: a missing, unreadable or self-inconsistent `index.json` is never rebuilt here.
//!   The Sessions it cannot attribute are reported as invalid instead, which is what an
//!   operator already sees today when that file is damaged. A later capability may offer an
//!   explicit repair; this slice does not;
//! - no workspace-root derivation: the caller passes the Session storage root explicitly.
//!   Deriving it from a workspace root would go through `PathManager::project_runtime_root`,
//!   which migrates legacy project runtime state and is not supported for remote or assistant
//!   workspaces. The real assembly (workspace id to Session root) belongs to the later host
//!   wiring slice, and no consumer calls this module yet;
//! - no public API (`pub(crate)`), no feature of its own and no product behavior. The module is
//!   gated on `workspace-intelligence-host` only because the Session storage layout and the
//!   metadata types it reads belong to the `local-storage` capability that host feature
//!   already selects.
//!
//! # What the marker is, and what it is not
//!
//! - The marker is a deterministic function of the bytes this observation read. Two
//!   observations of one directory agree, and the enumeration order does not matter, because
//!   the digest is built over sorted lines.
//! - It is not an atomic snapshot across Sessions: a concurrent writer can leave a byte
//!   combination that never existed on disk as a whole. Equal markers therefore mean "the same
//!   bytes were read", not "the tree was consistent at one instant".
//! - It cannot see an ABA sequence: a value that changes and changes back produces the same
//!   marker as the untouched tree.
//! - The index is only the set authority. Its `updatedAt`, `schemaVersion` and file bytes are
//!   deliberately excluded, so a rewrite that keeps the same session set does not move the
//!   marker. `metadata.json` is hashed by content, which is what detects a same-length
//!   replacement that a file revision would miss.
//! - An observation that hit a documented bound is marked `incomplete` and its marker is only
//!   a bounded prefix digest. [`offered_step`] returns `None` for it: a truncated digest can
//!   coincide with a complete one, which would let a caller answer "duplicate" for a tree it
//!   never fully read.
//!
//! # Session sets on the two paths
//!
//! - A usable index is the session-set authority: its `sessions[]` entries are inspected, and
//!   no additional filtering is applied here because the owner only indexes Sessions it shows
//!   to the user.
//! - A missing, unreadable or inconsistent index falls back to enumerating the entries of the
//!   Session root. Every entry counts, without filtering hidden or subagent directories, and
//!   every one of them is invalid for this observation with reason `index_unavailable` unless a
//!   more specific entry-level reason applies. Counting everything is deliberate: in this state
//!   the adapter cannot tell which entries are Sessions.
//!
//! The scope of that fallback is the entry set, and only the entry set. In this state only entry
//! names, entry kinds and entry-level reasons reach the marker: no `metadata.json` and no
//! `turn-catalog.json` is read, because the adapter cannot attribute a directory to a Session.
//! A content-only change inside an existing Session directory therefore does not move the marker
//! while the index is unusable. That is the accepted trade-off of this slice: reading content it
//! cannot attribute would turn one damaged `index.json` into a partial read of arbitrary
//! directories. The weaker guarantee is bounded and explicit: an added, removed or renamed entry
//! always moves the marker, and a content-only change is caught by the reconcile that follows the
//! index becoming usable again.
//!
//! A single invalid Session never fails the observation; only an absent, non-directory or
//! unreadable Session root is a typed [`SourceReadError`]. An entry that is neither a directory
//! nor a link is `entry_not_directory`; only a real symlink, junction or reparse point is
//! `linked_entry`. Neither kind is ever followed.
//!
//! # Calling
//!
//! Every read here is synchronous, bounded and lock-free. A future asynchronous host caller must
//! run one observation on a blocking thread, for example through `spawn_blocking`, instead of
//! awaiting it on a runtime worker.

use std::path::Path;

use openbitfun_services_core::session::types::StoredSessionMetadataFile;
use openbitfun_services_core::session::SessionStorageLayout;
use sha2::{Digest, Sha256};

use super::cursor::{OfferedStep, ReplayCapability, ResumeEvidence, SourceMarker};

/// Largest number of Session entries one observation considers.
///
/// The bound keeps one observation's work and diagnostic footprint finite. An index or a
/// directory that holds more entries is reported as an incomplete observation rather than being
/// silently truncated into a usable marker.
pub(crate) const MAX_SESSIONS: usize = 10_000;

/// Largest single file one observation reads, in bytes.
///
/// Session metadata is a small document; a file above this bound is reported as an incomplete
/// observation instead of being read into memory or hashed partially.
pub(crate) const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Longest catalog revision accepted into a per-session digest.
const MAX_CATALOG_REVISION_CHARS: usize = 256;

/// Version prefix of the marker shape. A later shape change must change it.
const MARKER_PREFIX: &str = "s1";

/// Set authority the observation was built from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionIndexState {
    /// The Session storage root does not exist, which is a legitimate empty observation.
    RootAbsent,
    /// `index.json` was readable and consistent, so its session set was used.
    Usable,
    /// The root exists but `index.json` does not.
    IndexMissing,
    /// `index.json` is not readable, not JSON, or not the index shape this module reads.
    IndexUnreadable,
    /// `index.json` lists fewer metadata files than sessions, so it cannot be trusted.
    IndexInconsistent,
}

impl SessionIndexState {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RootAbsent => "root_absent",
            Self::Usable => "usable",
            Self::IndexMissing => "index_missing",
            Self::IndexUnreadable => "index_unreadable",
            Self::IndexInconsistent => "index_inconsistent",
        }
    }
}

/// Why an observation is not a complete view of the Session directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IncompleteReason {
    /// More Session entries exist than [`MAX_SESSIONS`] allows one observation to consider.
    SessionLimitExceeded,
    /// At least one file is larger than [`MAX_FILE_BYTES`].
    FileLimitExceeded,
}

impl IncompleteReason {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::SessionLimitExceeded => "session_limit_exceeded",
            Self::FileLimitExceeded => "file_limit_exceeded",
        }
    }
}

/// Why one Session entry is not a valid source contribution.
///
/// The codes are stable and carry no path, no session identifier and no user content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InvalidSessionReason {
    /// The entry is a link: a symlink, a Windows junction or another reparse point. The link is
    /// never followed, so no file behind it is read.
    LinkedEntry,
    /// The entry is neither a directory nor a link, so it cannot be a Session directory. A plain
    /// file in the Session root, such as `index.json` or an SQLite sidecar, is reported this way
    /// instead of being called a link.
    EntryNotDirectory,
    /// The name is not a usable session identifier.
    SessionIdInvalid,
    /// No usable index exists, so Session entries cannot be attributed.
    IndexUnavailable,
    /// `metadata.json` is absent.
    MetadataMissing,
    /// `metadata.json` is itself a link.
    MetadataLinked,
    /// `metadata.json` exists but could not be read inside the documented bound.
    MetadataUnreadable,
    /// `metadata.json` is not a Session metadata document.
    MetadataInvalid,
    /// `metadata.json` names a different session than the entry it was read from.
    SessionIdMismatch,
}

impl InvalidSessionReason {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LinkedEntry => "linked_entry",
            Self::EntryNotDirectory => "entry_not_directory",
            Self::SessionIdInvalid => "session_id_invalid",
            Self::IndexUnavailable => "index_unavailable",
            Self::MetadataMissing => "metadata_missing",
            Self::MetadataLinked => "metadata_linked",
            Self::MetadataUnreadable => "metadata_unreadable",
            Self::MetadataInvalid => "metadata_invalid",
            Self::SessionIdMismatch => "session_id_mismatch",
        }
    }
}

/// One deterministic read of one Session storage root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionSnapshotObservation {
    marker: SourceMarker,
    index_state: SessionIndexState,
    sessions: usize,
    invalid_reasons: Vec<InvalidSessionReason>,
    incomplete: Option<IncompleteReason>,
}

impl SessionSnapshotObservation {
    /// Marker over the bytes this observation read.
    pub(crate) fn marker(&self) -> &SourceMarker {
        &self.marker
    }

    /// Which set authority the observation was built from.
    pub(crate) fn index_state(&self) -> SessionIndexState {
        self.index_state
    }

    /// Number of valid Sessions this observation read.
    pub(crate) fn sessions(&self) -> usize {
        self.sessions
    }

    /// Number of entries that were counted but are not valid source contributions.
    pub(crate) fn invalid_sessions(&self) -> usize {
        self.invalid_reasons.len()
    }

    /// One stable reason per invalid entry, ordered by entry key.
    ///
    /// The reasons travel without the entry keys, so a caller can log or count them without
    /// echoing a Session identifier.
    pub(crate) fn invalid_reasons(&self) -> &[InvalidSessionReason] {
        &self.invalid_reasons
    }

    /// Why this observation is not a complete view, when a bound was reached.
    pub(crate) fn incomplete(&self) -> Option<IncompleteReason> {
        self.incomplete
    }

    /// Stable code of this source kind.
    pub(crate) fn code(&self) -> &'static str {
        "session_snapshot"
    }
}

/// Why a Session root could not be observed at all.
///
/// A single invalid Session entry is never one of these; only the root itself can fail this
/// way. Neither variant carries a path or any user content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SourceReadError {
    /// The root exists but is not a directory this module may enumerate: a plain file, a
    /// symlink, a junction or a reparse point.
    RootNotDirectory,
    /// The root exists and is a directory, but it could not be enumerated.
    RootUnreadable,
}

impl SourceReadError {
    /// Stable machine-readable code for logs and diagnostics.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::RootNotDirectory => "root_not_directory",
            Self::RootUnreadable => "root_unreadable",
        }
    }
}

/// Observes one Session storage root without writing anything.
///
/// The caller passes the resolved Session storage root; this module never derives it from a
/// workspace root. The returned marker is deterministic for the bytes that were read.
pub(crate) fn observe_sessions_snapshot(
    sessions_root: &Path,
) -> Result<SessionSnapshotObservation, SourceReadError> {
    observe_with_limits(sessions_root, MAX_SESSIONS, MAX_FILE_BYTES)
}

/// The step this observation offers to the cursor contract, or `None` when it is incomplete.
///
/// A complete observation always declares [`ReplayCapability::SnapshotOnly`]: a Session
/// directory is reconciled by comparing snapshots, and the module never has a resumable
/// position of its own. An incomplete observation offers nothing, because a bounded prefix
/// digest could coincide with a complete one and be mistaken for a duplicate.
pub(crate) fn offered_step(
    observation: &SessionSnapshotObservation,
) -> Option<OfferedStep<'_>> {
    if observation.incomplete.is_some() {
        return None;
    }
    Some(OfferedStep {
        capability: ReplayCapability::SnapshotOnly,
        marker: Some(&observation.marker),
        evidence: ResumeEvidence::NotProvided,
    })
}

/// One entry the observation will inspect.
struct Candidate {
    key: String,
    /// The name is valid UTF-8, so it can be a session identifier at all.
    utf8: bool,
    /// The entry came from a usable index rather than from a directory enumeration.
    indexed: bool,
}

/// What one Session entry contributed to the digest.
struct SessionInspection {
    /// Digest field of the metadata document: `hash:<hex>`, `absent`, `linked`, `oversize`,
    /// `unreadable`, or `unread` when the entry was never read.
    metadata_field: String,
    /// Digest field of the turn catalog: `rev:<hex>`, `absent`, `unusable`, or `unread`.
    catalog_field: String,
    /// Why the entry is not a valid contribution, when it is not.
    reason: Option<InvalidSessionReason>,
}

impl SessionInspection {
    /// An entry this observation did not read at all.
    fn unread(reason: InvalidSessionReason) -> Self {
        Self {
            metadata_field: "unread".to_owned(),
            catalog_field: "unread".to_owned(),
            reason: Some(reason),
        }
    }

    /// One digest line: the entry key only appears as its hash.
    fn digest_line(&self, key: &str) -> String {
        let validity = match self.reason {
            None => "valid".to_owned(),
            Some(reason) => format!("invalid:{}", reason.as_str()),
        };
        format!(
            "{}|{}|{}|{}",
            hex_digest(key.as_bytes()),
            validity,
            self.metadata_field,
            self.catalog_field
        )
    }
}

/// One read result, bounded before and after the read itself.
enum FileRead {
    Bytes(Vec<u8>),
    Absent,
    Linked,
    TooLarge,
    Unreadable,
}

fn observe_with_limits(
    sessions_root: &Path,
    max_sessions: usize,
    max_file_bytes: u64,
) -> Result<SessionSnapshotObservation, SourceReadError> {
    let root_metadata = match std::fs::symlink_metadata(sessions_root) {
        Ok(metadata) => metadata,
        // A Session root that was never created is a legitimate empty observation: no
        // directory is created here, and the marker still names the state.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(build_observation(
                SessionIndexState::RootAbsent,
                0,
                Vec::new(),
                &[],
                None,
            ))
        }
        Err(_) => return Err(SourceReadError::RootUnreadable),
    };
    if !root_metadata.is_dir() || entry_is_linked(&root_metadata) {
        return Err(SourceReadError::RootNotDirectory);
    }

    let layout = SessionStorageLayout::new(sessions_root);
    let mut incomplete = None;
    let (index_state, indexed_keys) = read_index(&layout, max_file_bytes, &mut incomplete);

    let mut candidates: Vec<Candidate> = match indexed_keys {
        Some(keys) => keys
            .into_iter()
            .map(|key| Candidate {
                key,
                utf8: true,
                indexed: true,
            })
            .collect(),
        None => enumerate_entries(sessions_root)?,
    };
    candidates.sort_by(|left, right| left.key.cmp(&right.key));
    if candidates.len() > max_sessions {
        // The first bound reached is the one reported; trimming keeps the digest bounded.
        incomplete.get_or_insert(IncompleteReason::SessionLimitExceeded);
        candidates.truncate(max_sessions);
    }

    let mut sessions = 0usize;
    let mut invalid_reasons = Vec::new();
    let mut lines = Vec::with_capacity(candidates.len());
    for candidate in &candidates {
        let inspection = if candidate.indexed {
            inspect_indexed_entry(&layout, &candidate.key, max_file_bytes, &mut incomplete)
        } else {
            inspect_unlisted_entry(sessions_root, candidate)
        };
        match inspection.reason {
            None => sessions += 1,
            Some(reason) => invalid_reasons.push(reason),
        }
        lines.push(inspection.digest_line(&candidate.key));
    }
    lines.sort();

    Ok(build_observation(
        index_state,
        sessions,
        invalid_reasons,
        &lines,
        incomplete,
    ))
}

/// Builds the observation and its marker from the digested lines.
///
/// The marker names the set authority, both counts and the digest of the sorted lines, so two
/// observations agree exactly when they read the same bytes for the same entries.
fn build_observation(
    index_state: SessionIndexState,
    sessions: usize,
    invalid_reasons: Vec<InvalidSessionReason>,
    lines: &[String],
    incomplete: Option<IncompleteReason>,
) -> SessionSnapshotObservation {
    let digest = hex_digest(lines.join("\n").as_bytes());
    let marker = format!(
        "{MARKER_PREFIX}-{}-{sessions}-{}-{digest}",
        index_state.as_str(),
        invalid_reasons.len()
    );
    SessionSnapshotObservation {
        marker: SourceMarker::parse(&marker)
            .expect("the marker shape is fixed by this module and within the marker bound"),
        index_state,
        sessions,
        invalid_reasons,
        incomplete,
    }
}

/// Reads the index document read-only and returns the session set it names.
fn read_index(
    layout: &SessionStorageLayout,
    max_file_bytes: u64,
    incomplete: &mut Option<IncompleteReason>,
) -> (SessionIndexState, Option<Vec<String>>) {
    let bytes = match read_capped(&layout.index_path(), max_file_bytes) {
        FileRead::Absent => return (SessionIndexState::IndexMissing, None),
        FileRead::Bytes(bytes) => bytes,
        FileRead::TooLarge => {
            incomplete.get_or_insert(IncompleteReason::FileLimitExceeded);
            return (SessionIndexState::IndexUnreadable, None);
        }
        FileRead::Linked | FileRead::Unreadable => {
            return (SessionIndexState::IndexUnreadable, None)
        }
    };
    let document: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(document) => document,
        Err(_) => return (SessionIndexState::IndexUnreadable, None),
    };
    let Some(object) = document.as_object() else {
        return (SessionIndexState::IndexUnreadable, None);
    };
    let Some(sessions) = object.get("sessions").and_then(|value| value.as_array()) else {
        return (SessionIndexState::IndexUnreadable, None);
    };
    let mut keys = Vec::with_capacity(sessions.len());
    for entry in sessions {
        let Some(entry) = entry.as_object() else {
            return (SessionIndexState::IndexUnreadable, None);
        };
        // The owner type accepts both spellings, so the set authority read does too.
        let Some(identifier) = entry
            .get("sessionId")
            .or_else(|| entry.get("session_id"))
            .and_then(|value| value.as_str())
        else {
            return (SessionIndexState::IndexUnreadable, None);
        };
        keys.push(identifier.to_owned());
    }
    // The owner's own completeness rule: fewer metadata files than sessions means the index
    // cannot be trusted as a set authority.
    let metadata_file_count = object
        .get("metadataFileCount")
        .or_else(|| object.get("metadata_file_count"))
        .and_then(|value| value.as_u64())
        .unwrap_or(0);
    if metadata_file_count < keys.len() as u64 {
        return (SessionIndexState::IndexInconsistent, None);
    }
    (SessionIndexState::Usable, Some(keys))
}

/// Enumerates every entry of the Session root without following any of them.
fn enumerate_entries(sessions_root: &Path) -> Result<Vec<Candidate>, SourceReadError> {
    let entries = match std::fs::read_dir(sessions_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(SourceReadError::RootUnreadable),
    };
    let mut candidates = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return Err(SourceReadError::RootUnreadable),
        };
        let name = entry.file_name();
        candidates.push(Candidate {
            key: name.to_string_lossy().into_owned(),
            utf8: name.to_str().is_some(),
            indexed: false,
        });
    }
    Ok(candidates)
}

/// Inspects one Session the index named.
fn inspect_indexed_entry(
    layout: &SessionStorageLayout,
    key: &str,
    max_file_bytes: u64,
    incomplete: &mut Option<IncompleteReason>,
) -> SessionInspection {
    if openbitfun_core_types::validate_session_id(key).is_err() {
        return SessionInspection::unread(InvalidSessionReason::SessionIdInvalid);
    }
    match std::fs::symlink_metadata(layout.session_dir(key)) {
        Ok(metadata) if entry_is_linked(&metadata) => {
            return SessionInspection::unread(InvalidSessionReason::LinkedEntry)
        }
        Ok(metadata) if !metadata.is_dir() => {
            return SessionInspection::unread(InvalidSessionReason::EntryNotDirectory)
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return SessionInspection::unread(InvalidSessionReason::MetadataMissing)
        }
        Err(_) => return SessionInspection::unread(InvalidSessionReason::MetadataUnreadable),
    }
    let (metadata_field, reason) = inspect_metadata(layout, key, max_file_bytes, incomplete);
    let catalog_field = inspect_catalog(layout, key, max_file_bytes, incomplete);
    SessionInspection {
        metadata_field,
        catalog_field,
        reason,
    }
}

/// Inspects one entry of the unindexed enumeration.
fn inspect_unlisted_entry(sessions_root: &Path, candidate: &Candidate) -> SessionInspection {
    if !candidate.utf8 {
        return SessionInspection::unread(InvalidSessionReason::SessionIdInvalid);
    }
    let reason = match std::fs::symlink_metadata(sessions_root.join(&candidate.key)) {
        // Only a real link is a link: a junction, a symlink or another reparse point.
        Ok(metadata) if entry_is_linked(&metadata) => InvalidSessionReason::LinkedEntry,
        Ok(metadata) if !metadata.is_dir() => InvalidSessionReason::EntryNotDirectory,
        Ok(_) if openbitfun_core_types::validate_session_id(&candidate.key).is_err() => {
            InvalidSessionReason::SessionIdInvalid
        }
        // A directory that looks like a Session is still not attributable without an index.
        Ok(_) | Err(_) => InvalidSessionReason::IndexUnavailable,
    };
    SessionInspection::unread(reason)
}

/// Reads one `metadata.json` and decides whether the entry is a valid contribution.
fn inspect_metadata(
    layout: &SessionStorageLayout,
    key: &str,
    max_file_bytes: u64,
    incomplete: &mut Option<IncompleteReason>,
) -> (String, Option<InvalidSessionReason>) {
    match read_capped(&layout.metadata_path(key), max_file_bytes) {
        FileRead::Absent => (
            "absent".to_owned(),
            Some(InvalidSessionReason::MetadataMissing),
        ),
        FileRead::Linked => (
            "linked".to_owned(),
            Some(InvalidSessionReason::MetadataLinked),
        ),
        FileRead::TooLarge => {
            incomplete.get_or_insert(IncompleteReason::FileLimitExceeded);
            (
                "oversize".to_owned(),
                Some(InvalidSessionReason::MetadataUnreadable),
            )
        }
        FileRead::Unreadable => (
            "unreadable".to_owned(),
            Some(InvalidSessionReason::MetadataUnreadable),
        ),
        FileRead::Bytes(bytes) => {
            // The raw bytes are hashed before the document is judged, so an invalid or
            // mismatched document still moves the marker when its bytes move.
            let field = format!("hash:{}", hex_digest(&bytes));
            let stored: StoredSessionMetadataFile = match serde_json::from_slice(&bytes) {
                Ok(stored) => stored,
                Err(_) => return (field, Some(InvalidSessionReason::MetadataInvalid)),
            };
            if stored.metadata.session_id != key {
                return (field, Some(InvalidSessionReason::SessionIdMismatch));
            }
            (field, None)
        }
    }
}

/// Reads one `turn-catalog.json` and folds its revision into the digest.
///
/// An unusable catalog does not invalidate the Session: it is a digest input that says the
/// catalog could not be trusted, which is why it is a distinct field rather than an empty
/// revision.
fn inspect_catalog(
    layout: &SessionStorageLayout,
    key: &str,
    max_file_bytes: u64,
    incomplete: &mut Option<IncompleteReason>,
) -> String {
    match read_capped(&layout.turn_catalog_path(key), max_file_bytes) {
        FileRead::Absent => "absent".to_owned(),
        FileRead::Bytes(bytes) => match catalog_revision(&bytes) {
            Some(revision) => format!("rev:{}", hex_digest(revision.as_bytes())),
            None => "unusable".to_owned(),
        },
        FileRead::TooLarge => {
            incomplete.get_or_insert(IncompleteReason::FileLimitExceeded);
            "unusable".to_owned()
        }
        FileRead::Linked | FileRead::Unreadable => "unusable".to_owned(),
    }
}

/// The revision string of one catalog document, when it is usable.
fn catalog_revision(bytes: &[u8]) -> Option<String> {
    let document: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let revision = document.get("revision")?.as_str()?;
    if revision.is_empty()
        || revision.chars().count() > MAX_CATALOG_REVISION_CHARS
        || revision.chars().any(char::is_control)
    {
        return None;
    }
    Some(revision.to_owned())
}

/// Reads one file without following a link and without exceeding the documented bound.
fn read_capped(path: &Path, max_file_bytes: u64) -> FileRead {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return FileRead::Absent,
        Err(_) => return FileRead::Unreadable,
    };
    if entry_is_linked(&metadata) {
        return FileRead::Linked;
    }
    if !metadata.is_file() {
        return FileRead::Unreadable;
    }
    if metadata.len() > max_file_bytes {
        return FileRead::TooLarge;
    }
    match std::fs::read(path) {
        // The length is checked again after the read, so a file that grew between the two
        // calls is still reported instead of being accepted.
        Ok(bytes) if bytes.len() as u64 > max_file_bytes => FileRead::TooLarge,
        Ok(bytes) => FileRead::Bytes(bytes),
        Err(_) => FileRead::Unreadable,
    }
}

/// True when the metadata describes a directory entry that is itself a link.
///
/// A Windows junction is a reparse point but not a symlink, so the attribute is checked too
/// instead of trusting the file type alone.
fn entry_is_linked(metadata: &std::fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return true;
        }
    }
    false
}

/// Lowercase hex SHA-256 of the given bytes.
fn hex_digest(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use openbitfun_services_core::session::types::SessionMetadata;
    use openbitfun_services_core::session::SessionMetadataStore;

    use crate::service::workspace_intelligence::cursor::{
        decide_step, GapReason, ReplayCapability, ResumeEvidence, StepDecision,
    };

    /// One `metadata.json` document the owner type can read back.
    fn metadata_document(session_id: &str, last_active_at: u64) -> Vec<u8> {
        let mut metadata = SessionMetadata::new(
            session_id.to_owned(),
            format!("Session {session_id}"),
            "Standard".to_owned(),
            "model".to_owned(),
        );
        metadata.last_active_at = last_active_at;
        serde_json::to_vec(&StoredSessionMetadataFile::new(metadata))
            .expect("the fixture metadata serializes")
    }

    fn write_session(root: &Path, session_id: &str, last_active_at: u64) {
        let directory = root.join(session_id);
        std::fs::create_dir_all(&directory).expect("create a session directory");
        std::fs::write(
            directory.join("metadata.json"),
            metadata_document(session_id, last_active_at),
        )
        .expect("write the fixture metadata");
    }

    fn write_catalog(root: &Path, session_id: &str, revision: &str) {
        let document = serde_json::json!({ "revision": revision });
        std::fs::write(
            root.join(session_id).join("turn-catalog.json"),
            serde_json::to_vec(&document).expect("the fixture catalog serializes"),
        )
        .expect("write the fixture catalog");
    }

    fn write_index(root: &Path, session_ids: &[&str], metadata_file_count: usize) {
        let sessions: Vec<serde_json::Value> = session_ids
            .iter()
            .map(|session_id| serde_json::json!({ "sessionId": session_id }))
            .collect();
        let document = serde_json::json!({
            "schemaVersion": 1,
            "updatedAt": 1,
            "metadataFileCount": metadata_file_count,
            "sessions": sessions,
        });
        std::fs::write(
            root.join("index.json"),
            serde_json::to_vec(&document).expect("the fixture index serializes"),
        )
        .expect("write the fixture index");
    }

    /// Every path under the root with the hash of its bytes, sorted.
    fn tree_fingerprint(root: &Path) -> Vec<(String, String)> {
        fn walk(root: &Path, directory: &Path, out: &mut Vec<(String, String)>) {
            let Ok(entries) = std::fs::read_dir(directory) else {
                return;
            };
            for entry in entries {
                let entry = entry.expect("a readable directory entry");
                let path = entry.path();
                let relative = path
                    .strip_prefix(root)
                    .expect("every entry is under the root")
                    .to_string_lossy()
                    .into_owned();
                let metadata = std::fs::symlink_metadata(&path).expect("entry metadata");
                if metadata.is_dir() && !entry_is_linked(&metadata) {
                    walk(root, &path, out);
                } else {
                    let bytes = std::fs::read(&path).unwrap_or_default();
                    out.push((relative, hex_digest(&bytes)));
                }
            }
        }
        let mut out = Vec::new();
        walk(root, root, &mut out);
        out.sort();
        out
    }

    fn observation(root: &Path) -> SessionSnapshotObservation {
        observe_sessions_snapshot(root).expect("the fixture root is observable")
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().expect("a temporary directory")
    }

    fn root_path(temp: &tempfile::TempDir) -> PathBuf {
        temp.path().to_path_buf()
    }

    #[test]
    fn a_production_shaped_root_is_observed_without_writing() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_session(&root, "session-b", 20);
        write_index(&root, &["session-a", "session-b"], 2);
        // A production root has no lock file until the owner takes one; this observation must
        // not create it.
        assert!(!root.join(".index.lock").exists(), "the fixture has no lock file");
        let before = tree_fingerprint(&root);

        let observed = observation(&root);

        assert_eq!(observed.index_state(), SessionIndexState::Usable);
        assert_eq!(observed.index_state().as_str(), "usable");
        assert_eq!(observed.sessions(), 2);
        assert_eq!(observed.invalid_sessions(), 0);
        assert_eq!(observed.incomplete(), None);
        assert_eq!(observed.code(), "session_snapshot");
        assert!(!root.join(".index.lock").exists(), "no lock file may appear");
        assert_eq!(tree_fingerprint(&root), before, "the observation wrote nothing");
    }

    #[test]
    fn a_real_owner_written_root_reads_as_usable() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime");
        let temp = temp_root();
        let root = root_path(&temp);
        let store = SessionMetadataStore::new(&root);
        runtime.block_on(async {
            for (session_id, last_active_at) in [("session-a", 10u64), ("session-b", 20u64)] {
                let mut metadata = SessionMetadata::new(
                    session_id.to_owned(),
                    format!("Session {session_id}"),
                    "Standard".to_owned(),
                    "model".to_owned(),
                );
                metadata.last_active_at = last_active_at;
                store
                    .save_metadata(&metadata)
                    .await
                    .expect("the owner writes the fixture");
            }
        });
        let before = tree_fingerprint(&root);

        let observed = observation(&root);

        assert_eq!(observed.index_state(), SessionIndexState::Usable);
        assert_eq!(observed.sessions(), 2);
        assert_eq!(observed.invalid_sessions(), 0);
        assert_eq!(tree_fingerprint(&root), before, "the observation wrote nothing");
    }

    #[test]
    fn a_missing_root_is_an_empty_observation_that_creates_nothing() {
        let temp = temp_root();
        let root = root_path(&temp).join("sessions");

        let observed = observation(&root);

        assert_eq!(observed.index_state(), SessionIndexState::RootAbsent);
        assert_eq!(observed.index_state().as_str(), "root_absent");
        assert_eq!(observed.sessions(), 0);
        assert_eq!(observed.invalid_sessions(), 0);
        assert_eq!(observed.incomplete(), None);
        assert!(!root.exists(), "the observation must not create the root");
    }

    #[test]
    fn two_observations_of_one_root_agree() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-b", 20);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-b", "session-a"], 2);

        assert_eq!(observation(&root).marker(), observation(&root).marker());
    }

    #[test]
    fn adding_a_session_moves_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let before = observation(&root).marker().clone();

        write_session(&root, "session-b", 20);
        write_index(&root, &["session-a", "session-b"], 2);

        let after = observation(&root);
        assert_eq!(after.sessions(), 2);
        assert_ne!(*after.marker(), before);
    }

    #[test]
    fn changing_last_active_moves_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let before = observation(&root).marker().clone();

        write_session(&root, "session-a", 11);

        assert_ne!(*observation(&root).marker(), before);
    }

    #[test]
    fn a_same_length_replacement_with_a_restored_mtime_moves_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let metadata_path = root.join("session-a").join("metadata.json");
        let original = std::fs::read(&metadata_path).expect("the fixture metadata is readable");
        let original_modified = std::fs::metadata(&metadata_path)
            .expect("fixture metadata")
            .modified()
            .expect("the fixture has a modified time");
        let before = observation(&root).marker().clone();

        // Replace one byte inside the session name and keep the length identical.
        let mut replaced = original.clone();
        let position = original
            .windows(b"Session ".len())
            .position(|window| window == b"Session ")
            .expect("the fixture names the session")
            + b"Session ".len();
        replaced[position] = b'X';
        assert_eq!(replaced.len(), original.len(), "the replacement is length preserving");
        std::fs::write(&metadata_path, &replaced).expect("rewrite the fixture metadata");
        let file = std::fs::File::options()
            .write(true)
            .open(&metadata_path)
            .expect("the rewritten metadata opens");
        file.set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .expect("the fixture modified time is restored");
        drop(file);
        assert_eq!(
            std::fs::metadata(&metadata_path)
                .expect("fixture metadata")
                .modified()
                .expect("modified time"),
            original_modified,
            "the file revision signal is unchanged"
        );

        assert_ne!(*observation(&root).marker(), before, "content hash detects the change");
    }

    #[test]
    fn removing_a_session_moves_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_session(&root, "session-b", 20);
        write_index(&root, &["session-a", "session-b"], 2);
        let before = observation(&root).marker().clone();

        std::fs::remove_dir_all(root.join("session-b")).expect("remove the fixture session");
        write_index(&root, &["session-a"], 1);

        let after = observation(&root);
        assert_eq!(after.sessions(), 1);
        assert_ne!(*after.marker(), before);
    }

    #[test]
    fn a_catalog_revision_moves_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let absent = observation(&root).marker().clone();

        write_catalog(&root, "session-a", "rev-1");
        let present = observation(&root).marker().clone();
        assert_ne!(present, absent, "a catalog appearing moves the marker");

        write_catalog(&root, "session-a", "rev-2");
        assert_ne!(
            *observation(&root).marker(),
            present,
            "a catalog revision moves the marker"
        );
    }

    #[test]
    fn an_unusable_index_degrades_to_invalid_sessions_without_a_write() {
        for (label, index_writer, expected_state) in [
            (
                "missing",
                Box::new(|root: &Path| {
                    std::fs::remove_file(root.join("index.json")).expect("drop the index");
                }) as Box<dyn Fn(&Path)>,
                SessionIndexState::IndexMissing,
            ),
            (
                "corrupt",
                Box::new(|root: &Path| {
                    std::fs::write(root.join("index.json"), b"{ not json").expect("corrupt index");
                }) as Box<dyn Fn(&Path)>,
                SessionIndexState::IndexUnreadable,
            ),
            (
                "sessions-not-array",
                Box::new(|root: &Path| {
                    let document = serde_json::json!({ "sessions": 7, "metadataFileCount": 0 });
                    std::fs::write(root.join("index.json"), serde_json::to_vec(&document).unwrap())
                        .expect("write a malformed index");
                }) as Box<dyn Fn(&Path)>,
                SessionIndexState::IndexUnreadable,
            ),
            (
                "inconsistent",
                Box::new(|root: &Path| {
                    write_index(root, &["session-a"], 0);
                }) as Box<dyn Fn(&Path)>,
                SessionIndexState::IndexInconsistent,
            ),
        ] {
            let temp = temp_root();
            let root = root_path(&temp);
            write_session(&root, "session-a", 10);
            write_session(&root, "session-b", 20);
            // Start from a usable index so each case is a real degradation of one.
            write_index(&root, &["session-a", "session-b"], 2);
            index_writer(&root);
            let before = tree_fingerprint(&root);

            let observed = observation(&root);

            assert_eq!(observed.index_state(), expected_state, "{label}");
            assert_eq!(observed.sessions(), 0, "{label}");
            // Both session directories plus index.json when the fixture keeps one.
            let expected_invalid = std::fs::read_dir(&root)
                .expect("the fixture root is readable")
                .count();
            assert_eq!(observed.invalid_sessions(), expected_invalid, "{label}");
            assert_eq!(
                observed
                    .invalid_reasons()
                    .iter()
                    .filter(|reason| **reason == InvalidSessionReason::IndexUnavailable)
                    .count(),
                2,
                "{label}"
            );
            assert_eq!(tree_fingerprint(&root), before, "{label}: no write");

            // Repairing the index moves the marker, so the degraded state is not sticky.
            let degraded = observed.marker().clone();
            write_index(&root, &["session-a", "session-b"], 2);
            let repaired = observation(&root);
            assert_eq!(repaired.index_state(), SessionIndexState::Usable, "{label}");
            assert_eq!(repaired.sessions(), 2, "{label}");
            assert_ne!(*repaired.marker(), degraded, "{label}");
        }
    }

    #[test]
    fn one_invalid_session_does_not_fail_the_observation() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_session(&root, "session-b", 20);
        write_session(&root, "session-c", 30);
        write_index(&root, &["session-a", "session-b", "session-c"], 3);
        std::fs::remove_file(root.join("session-b").join("metadata.json"))
            .expect("drop one metadata document");
        std::fs::write(root.join("session-c").join("metadata.json"), b"{ not json")
            .expect("corrupt one metadata document");

        let observed = observation(&root);

        assert_eq!(observed.index_state(), SessionIndexState::Usable);
        assert_eq!(observed.sessions(), 1);
        assert_eq!(observed.invalid_sessions(), 2);
        assert_eq!(
            observed.invalid_reasons(),
            &[
                InvalidSessionReason::MetadataMissing,
                InvalidSessionReason::MetadataInvalid
            ]
        );
        assert_eq!(
            InvalidSessionReason::MetadataMissing.as_str(),
            "metadata_missing"
        );
        assert_eq!(
            InvalidSessionReason::MetadataInvalid.as_str(),
            "metadata_invalid"
        );
    }

    #[test]
    fn a_mismatched_session_id_is_invalid_but_still_hashed() {
        let temp = temp_root();
        let root = root_path(&temp);
        std::fs::create_dir_all(root.join("session-a")).expect("create the session directory");
        std::fs::write(
            root.join("session-a").join("metadata.json"),
            metadata_document("session-other", 10),
        )
        .expect("write a mismatched metadata document");
        write_index(&root, &["session-a"], 1);

        let observed = observation(&root);
        assert_eq!(observed.sessions(), 0);
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::SessionIdMismatch]
        );
        assert_eq!(
            InvalidSessionReason::SessionIdMismatch.as_str(),
            "session_id_mismatch"
        );
        let before = observed.marker().clone();

        std::fs::write(
            root.join("session-a").join("metadata.json"),
            metadata_document("session-other", 11),
        )
        .expect("rewrite the mismatched metadata document");
        assert_ne!(*observation(&root).marker(), before);
    }

    #[test]
    fn a_linked_entry_is_reported_and_never_followed() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        // The link target lives outside the observed root and holds a Session the owner type
        // could read, so a followed link would count as a valid contribution.
        let outside_temp = temp_root();
        let outside = outside_temp.path().join("outside");
        std::fs::create_dir_all(&outside).expect("create the outside directory");
        std::fs::write(
            outside.join("metadata.json"),
            metadata_document("session-link", 10),
        )
        .expect("write the outside metadata");

        assert!(
            link_directory(&outside, &root.join("session-link")),
            "this machine cannot create a directory link without elevation, so the linked-entry \
             path was not evaluated: the precondition of this test does not hold"
        );
        write_index(&root, &["session-a", "session-link"], 2);

        let observed = observation(&root);

        assert_eq!(observed.sessions(), 1);
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::LinkedEntry],
            "a linked Session entry is reported and never followed"
        );
        assert_eq!(InvalidSessionReason::LinkedEntry.as_str(), "linked_entry");
    }

    #[test]
    fn a_plain_file_entry_is_not_reported_as_a_link() {
        // A file in the Session root is a different kind from a link, so it gets its own code.
        let degraded_root = temp_root();
        let degraded = degraded_root.path().join("sessions");
        std::fs::create_dir_all(&degraded).expect("create the degraded root");
        std::fs::write(degraded.join("stray-file"), b"x").expect("write a stray file");
        std::fs::write(degraded.join("index.json"), b"{ not json").expect("write a stray index");
        std::fs::write(degraded.join("product-search-v1.sqlite"), b"x").expect("write a sidecar");

        let observed = observation(&degraded);

        assert_eq!(observed.index_state(), SessionIndexState::IndexUnreadable);
        assert_eq!(observed.sessions(), 0);
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::EntryNotDirectory; 3],
            "plain files are never reported as links and never treated as Sessions"
        );
        assert_eq!(
            InvalidSessionReason::EntryNotDirectory.as_str(),
            "entry_not_directory"
        );

        // The same entry through a usable index: the index names it, the entry is a plain file.
        let indexed_root = temp_root();
        let root = indexed_root.path().join("sessions");
        std::fs::create_dir_all(&root).expect("create the indexed root");
        std::fs::write(root.join("session-a"), b"x").expect("write a plain file entry");
        write_index(&root, &["session-a"], 1);

        let indexed = observation(&root);

        assert_eq!(indexed.sessions(), 0);
        assert_eq!(
            indexed.invalid_reasons(),
            &[InvalidSessionReason::EntryNotDirectory],
            "a named entry that is a plain file is not a link either"
        );
    }

    #[test]
    fn an_index_identifier_that_escapes_the_root_is_never_joined() {
        let parent = temp_root();
        let root = parent.path().join("sessions");
        std::fs::create_dir_all(&root).expect("create the sessions root");
        // A file above the documented bound sits next to the root, behind the escaping
        // identifier. Reading it would have reported the file limit, so the assertions below
        // prove that no such read happened either.
        let outside = parent.path().join("outside");
        std::fs::create_dir_all(&outside).expect("create the outside directory");
        let outside_metadata = outside.join("metadata.json");
        std::fs::File::create(&outside_metadata)
            .expect("create the outside metadata")
            .set_len(MAX_FILE_BYTES + 1)
            .expect("grow the outside metadata past the bound");
        write_index(&root, &["..", "../outside", "a/b", "C:evil"], 4);
        let before = tree_fingerprint(&root);

        let observed = observation(&root);

        assert_eq!(observed.index_state(), SessionIndexState::Usable);
        assert_eq!(observed.sessions(), 0);
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::SessionIdInvalid; 4],
            "every identifier that could leave the root is refused before any join"
        );
        assert_eq!(
            observed.incomplete(),
            None,
            "no out-of-root file was read, so no bound was reached"
        );
        assert_eq!(
            std::fs::metadata(&outside_metadata)
                .expect("the outside metadata still exists")
                .len(),
            MAX_FILE_BYTES + 1,
            "the file behind the escaping identifier was neither read nor changed"
        );
        assert_eq!(
            tree_fingerprint(&root),
            before,
            "the observed root was not written"
        );
    }

    #[test]
    fn an_index_rewrite_with_the_same_session_set_keeps_the_marker() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let before = observation(&root).marker().clone();

        // The same session set written by a different owner version: new bytes and new revision
        // fields, same set. The index is only the set authority, so the marker stays.
        let rewritten = serde_json::json!({
            "schemaVersion": 7,
            "updatedAt": 9_999,
            "metadataFileCount": 1,
            "sessions": [{ "sessionId": "session-a" }],
        });
        std::fs::write(
            root.join("index.json"),
            serde_json::to_vec(&rewritten).expect("the rewritten index serializes"),
        )
        .expect("rewrite the fixture index");

        let after = observation(&root);

        assert_eq!(after.index_state(), SessionIndexState::Usable);
        assert_eq!(after.sessions(), 1);
        assert_eq!(
            *after.marker(),
            before,
            "index bytes and revision fields alone do not move the marker"
        );
    }

    #[test]
    fn an_index_that_is_a_directory_and_an_unusable_catalog_are_reported() {
        // An index path that is not a file is not the index shape, so the set falls back to the
        // degraded enumeration instead of being read.
        let index_temp = temp_root();
        let index_root = index_temp.path().join("sessions");
        std::fs::create_dir_all(index_root.join("index.json")).expect("create an index directory");

        let observed = observation(&index_root);

        assert_eq!(observed.index_state(), SessionIndexState::IndexUnreadable);
        assert_eq!(
            observed.index_state().as_str(),
            "index_unreadable",
            "a directory at the index path is unreadable, not missing"
        );
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::IndexUnavailable],
            "a directory at the index path is not attributable as a Session either"
        );

        // A catalog that is not JSON keeps its Session valid and is reported as an unusable
        // revision rather than as an absent one.
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let absent = observation(&root).marker().clone();
        std::fs::write(
            root.join("session-a").join("turn-catalog.json"),
            b"{ not json",
        )
        .expect("write an unusable catalog");
        let unusable = observation(&root);

        assert_eq!(unusable.sessions(), 1);
        assert_eq!(unusable.incomplete(), None);
        assert_ne!(
            *unusable.marker(),
            absent,
            "an unusable catalog is not the same input as an absent one"
        );

        // A catalog above the bound is a file limit, not a silently unusable revision.
        std::fs::File::create(root.join("session-a").join("turn-catalog.json"))
            .expect("create an oversized catalog")
            .set_len(MAX_FILE_BYTES + 1)
            .expect("grow the catalog past the bound");
        let oversized = observation(&root);

        assert_eq!(
            oversized.incomplete(),
            Some(IncompleteReason::FileLimitExceeded)
        );
        assert!(offered_step(&oversized).is_none());
    }

    #[cfg(windows)]
    fn link_directory(target: &Path, link: &Path) -> bool {
        // The output is captured so the fixture command cannot print into the test log.
        let output = crate::util::create_test_command("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output();
        matches!(output, Ok(output) if output.status.success()) && link.exists()
    }

    #[cfg(unix)]
    fn link_directory(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).is_ok()
    }

    #[test]
    fn the_session_limit_is_reported_as_incomplete() {
        let temp = temp_root();
        let root = root_path(&temp);
        for session_id in ["session-a", "session-b", "session-c"] {
            write_session(&root, session_id, 10);
        }
        write_index(&root, &["session-a", "session-b", "session-c"], 3);

        let observed = observe_with_limits(&root, 2, MAX_FILE_BYTES)
            .expect("a bounded observation is still a value");

        assert_eq!(observed.incomplete(), Some(IncompleteReason::SessionLimitExceeded));
        assert_eq!(
            observed.incomplete().map(IncompleteReason::as_str),
            Some("session_limit_exceeded")
        );
        assert!(
            offered_step(&observed).is_none(),
            "an incomplete observation must not offer a marker"
        );
        assert_eq!(MAX_SESSIONS, 10_000);
        assert_eq!(MAX_FILE_BYTES, 8 * 1024 * 1024);
    }

    #[test]
    fn the_file_limit_is_reported_as_incomplete() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        // The bound still admits the index and refuses the larger metadata document, so the
        // reported limit is about that document rather than about the index.
        let index_bytes = std::fs::metadata(root.join("index.json"))
            .expect("the fixture index is present")
            .len();
        let metadata_bytes = std::fs::metadata(root.join("session-a").join("metadata.json"))
            .expect("the fixture metadata is present")
            .len();
        assert!(
            metadata_bytes > index_bytes,
            "the fixture makes the bound meaningful"
        );

        let observed = observe_with_limits(&root, MAX_SESSIONS, index_bytes)
            .expect("a bounded observation is still a value");

        assert_eq!(
            observed.incomplete(),
            Some(IncompleteReason::FileLimitExceeded)
        );
        assert_eq!(
            observed.incomplete().map(IncompleteReason::as_str),
            Some("file_limit_exceeded")
        );
        assert_eq!(observed.index_state(), SessionIndexState::Usable);
        assert_eq!(
            observed.invalid_reasons(),
            &[InvalidSessionReason::MetadataUnreadable]
        );
        assert!(
            offered_step(&observed).is_none(),
            "an incomplete observation must not offer a marker"
        );
    }

    #[test]
    fn a_file_root_is_refused() {
        let temp = temp_root();
        let root = root_path(&temp).join("sessions");
        std::fs::write(&root, b"not a directory").expect("write a file root");

        let error = observe_sessions_snapshot(&root).expect_err("a file root is refused");

        assert_eq!(error, SourceReadError::RootNotDirectory);
        assert_eq!(error.as_str(), "root_not_directory");
    }

    #[test]
    fn the_observation_feeds_the_cursor_contract() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);
        let observed = observation(&root);
        let step = offered_step(&observed).expect("a complete observation offers a step");
        assert_eq!(step.capability, ReplayCapability::SnapshotOnly);
        assert_eq!(step.evidence, ResumeEvidence::NotProvided);

        let source = observed_source_id();
        let first =
            decide_step(&source, None, step).expect("a first sight step is decided");
        match first {
            StepDecision::SnapshotReconcile { gap, .. } => {
                // This source declares `SnapshotOnly`, so the capability failure is the durable
                // cause and outranks "nothing recorded": the answer is a reconcile with an
                // explicit gap, never a replay, an advance or an ack.
                assert_eq!(gap.reason, GapReason::SourceCannotReplay);
                assert!(gap.recorded.is_none(), "nothing was recorded for this source");
            }
            other => panic!("a first sight observation must not resume, got {other:?}"),
        }

        let recorded = observed.marker().clone();
        let repeated = decide_step(&source, Some(&recorded), step)
            .expect("a repeated marker is decided");
        assert_eq!(repeated.code(), "duplicate");
    }

    fn observed_source_id() -> super::super::cursor::SourceId {
        super::super::cursor::SourceId::parse("session-directory")
            .expect("the source identifier is valid")
    }

    #[test]
    fn the_marker_is_bounded_and_uses_a_clean_alphabet() {
        let temp = temp_root();
        let root = root_path(&temp);
        write_session(&root, "session-a", 10);
        write_index(&root, &["session-a"], 1);

        let marker = observation(&root).marker().clone();
        let text = marker.as_str();
        assert!(text.len() <= 256, "the marker is bounded, got {text}");
        assert!(
            text.chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-'),
            "the marker alphabet is clean, got {text}"
        );
        assert!(text.starts_with("s1-usable-1-0-"), "got {text}");
    }

    #[test]
    fn the_source_never_names_a_write_api() {
        let source = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/service/workspace_intelligence/session_source.rs"
        ))
        .expect("the module source is readable");
        // Only the production part is scanned: the test module writes its own fixtures.
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the production part precedes the test module");
        let code: String = production
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        for token in [
            "fs::write",
            "create_dir",
            "OpenOptions",
            "remove_file",
            "FileLock",
            "indexed_metadata_snapshot",
            "tokio::spawn",
            "SystemTime::now",
        ] {
            assert!(
                !code.contains(token),
                "the read-only source must not name `{token}`"
            );
        }
    }
}
