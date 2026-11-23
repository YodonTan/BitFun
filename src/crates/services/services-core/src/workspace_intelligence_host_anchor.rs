//! Write-once host anchor for workspace intelligence local storage.
//!
//! The anchor is a **storage/user-data namespace** identifier: it labels which
//! local storage tree a workspace-intelligence root belongs to. "Host" in these
//! names means that storage namespace, never the machine running the process. It
//! is not hardware identity, not an account, not `device_id`, and not a machine
//! fingerprint, and nothing may derive any of those facts from it.
//!
//! The value is a UUID v4 rendered with `simple()`: 32 lowercase hex characters,
//! 128 bits of which only 122 are random because the version and variant bits are
//! fixed. This module does not claim full 16-byte CSPRNG randomness. The value is
//! opaque and NOT a secret, which is why it is neither hashed nor given any
//! privacy guarantee.
//!
//! No production caller of the writing path exists in this tree yet: the core
//! host bootstrap reads the anchor through `read_strict`, and the only
//! production `ensure_for_initial_enable` caller arrives at first
//! workspace-intelligence enable.
//! The protected first-enable entry point is
//! [`HostAnchorStore::ensure_for_initial_enable`], which additionally proves the
//! same-namespace control root vacant before it may mint. This module supplies
//! no bootstrap sequencing, policy, runtime, process, network, or UI behavior.
//!
//! `read_strict` never creates the root, a directory, a file, or a `.lock`, never
//! takes a lock, and never deletes or resets anything. `ensure` and the
//! protected [`ensure_for_initial_enable`](HostAnchorStore::ensure_for_initial_enable)
//! are the only writers: each runs the mint as an owned task, re-reads under the
//! JSON cross-process guard, and publishes the minted document with a strict
//! create-new atomic write that fails with `AlreadyExists` instead of replacing a
//! racing writer. No stored variant is ever repaired, overwritten, or adopted.
//!
//! Caller cancellation cannot interrupt a mint that already started, because the
//! mint is an owned task and the caller can lose only the result. A runtime
//! shutdown during first enable can still drop that owned task at its next await,
//! so a `.tmp` may persist and no anchor is published; that only affects the
//! first-enable mint (P2/P3), never a read.
//!
//! # Filesystems
//!
//! The atomic publish relies on a hard link inside the same directory. On
//! FAT/exFAT volumes or some SMB/OneDrive mounts without working hard links,
//! `ensure` fails closed with `host_anchor_io`: no anchor is published and
//! nothing is replaced. The read path is unaffected.
//!
//! # Unix open semantics
//!
//! On non-Windows platforms the entry is pre-statted, then opened with
//! `O_NOFOLLOW | O_NONBLOCK`, then re-statted and identity-checked against the
//! opened handle. The two flags do two separate jobs: `O_NOFOLLOW` refuses a
//! final-component symlink with `ELOOP` instead of following it, and
//! `O_NONBLOCK` stops `open(2)` blocking when a FIFO was substituted for the
//! statted regular file, which then fails the handle `is_file()` check as
//! `NotRegularFile`. The post-open `(dev, ino)` re-stat is retained as the
//! same-name replace detector. A substituted *regular* file stays
//! indistinguishable, because the anchor directory is the trust boundary: such a
//! file still has to parse as a valid v1 document. This Unix path is present for
//! review only on this host: `x86_64-pc-windows-msvc` is the only installed
//! target, so it has not been compiled or executed for Unix here. Windows has no
//! equivalent window: a reparse point is opened as itself and the handle metadata
//! is what gets validated.

use crate::bounded_fs::{is_symlink_or_reparse, BoundedTextRead};
use crate::json_store::{JsonFileStore, JsonFileStoreError};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

/// File name of the anchor document inside the caller-selected root.
pub const HOST_ANCHOR_FILE_NAME: &str = "host-anchor.json";
/// On-disk format discriminator of this schema version.
pub const HOST_ANCHOR_FORMAT: &str = "wi-host-anchor-v1";
/// On-disk schema version of the anchor document.
pub const HOST_ANCHOR_SCHEMA_VERSION: u32 = 1;
/// Maximum accepted size of the anchor document.
pub const HOST_ANCHOR_MAX_BYTES: usize = 4096;
/// Version prefix of the public host id derived from the stored anchor.
pub const HOST_ID_PREFIX: &str = "wi-host-v1:";

/// Read-only view of the anchor document's state.
#[derive(Debug, Clone)]
pub enum HostAnchorState {
    /// The anchor file does not exist. This is the only adoption-eligible state.
    ///
    /// On Windows, `ERROR_BAD_NETPATH` and `ERROR_BAD_NET_NAME` decode to
    /// `NotFound`, so an offline network home also reports `Absent`; `ensure`
    /// and `ensure_for_initial_enable` would then attempt to mint there, which
    /// is why only an explicit first-enable path may call either.
    Absent,
    /// The anchor file exists and passed strict validation.
    Present(HostAnchor),
}

/// Outcome of an [`HostAnchorStore::ensure`] or
/// [`HostAnchorStore::ensure_for_initial_enable`] call.
#[derive(Debug, Clone)]
pub enum HostAnchorEnsure {
    /// This call published the anchor.
    Created(HostAnchor),
    /// A previously published anchor was returned unchanged.
    Existing(HostAnchor),
}

/// Validated anchor value. The single field is the version-prefixed anchor; the
/// anchor content is its 32-hex suffix and nothing else, so no schema, format,
/// timestamp, or counter can become part of the identity.
#[derive(Clone)]
pub struct HostAnchor {
    host_id: String,
}

impl std::fmt::Debug for HostAnchor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("HostAnchor(<redacted>)")
    }
}

impl HostAnchor {
    fn from_anchor(anchor: &str) -> Self {
        Self {
            host_id: format!("{HOST_ID_PREFIX}{anchor}"),
        }
    }

    /// The full anchor id: [`HOST_ID_PREFIX`] plus all 32 hex characters. The
    /// suffix is the stored anchor exactly; it is never hashed or truncated, and
    /// there is deliberately no raw-anchor accessor beyond module need.
    pub fn host_id(&self) -> &str {
        &self.host_id
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HostAnchorError {
    #[error("Host anchor path is a symlink or reparse point")]
    Symlink,
    #[error("Host anchor path is not a regular file")]
    NotRegularFile,
    #[error("Host anchor document exceeds the byte limit")]
    TooLarge,
    #[error("Host anchor document is corrupt")]
    Corrupt,
    #[error("Host anchor document declares unsupported schema version {observed}")]
    UnsupportedSchema { observed: u32 },
    /// `observed` is a bounded, printable-ASCII-only summary of the document
    /// value; raw document text never reaches `Display` or logs.
    #[error("Host anchor document declares unsupported format {observed}")]
    UnsupportedFormat { observed: String },
    #[error("Host anchor mint raced an external writer and the target stayed absent")]
    MintRaced,
    /// A protected initial-enable mint was refused because its control root is
    /// not a plain direct child of this store's anchor root.
    #[error("Host anchor initial-enable control root is out of scope for this anchor root")]
    InitialEnableControlOutOfScope,
    /// A protected initial-enable mint was refused because the namespace root is
    /// a symlink or reparse point.
    #[error("Host anchor root is a symlink or reparse point")]
    InitialEnableRootReparse,
    /// A protected initial-enable mint was refused because the namespace root
    /// exists but is not a directory.
    #[error("Host anchor root is not a directory")]
    InitialEnableRootNotDirectory,
    /// A protected initial-enable mint was refused because the namespace root
    /// could not be inspected.
    #[error("Host anchor root could not be inspected: {0}")]
    InitialEnableRootUnreadable(#[source] std::io::Error),
    /// A protected initial-enable mint was refused because the control root is a
    /// symlink or reparse point.
    #[error("Host anchor initial-enable control root is a symlink or reparse point")]
    InitialEnableControlReparse,
    /// A protected initial-enable mint was refused because the control root
    /// exists but is not a directory.
    #[error("Host anchor initial-enable control root is not a directory")]
    InitialEnableControlNotDirectory,
    /// A protected initial-enable mint was refused because the control root
    /// could not be proven empty.
    #[error("Host anchor initial-enable control root could not be read: {0}")]
    InitialEnableControlUnreadable(#[source] std::io::Error),
    /// A protected initial-enable mint was refused because the control root
    /// holds at least one entry.
    #[error("Host anchor initial-enable control root holds entries")]
    InitialEnableControlOccupied,
    #[error("Host anchor lock failed: {0}")]
    Lock(#[from] JsonFileStoreError),
    #[error("Host anchor IO failed: {0}")]
    Io(#[source] std::io::Error),
}

impl HostAnchorError {
    /// Stable machine-readable code. No variant is resolved by deleting or
    /// rewriting the anchor file.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Symlink => "host_anchor_symlink",
            Self::NotRegularFile => "host_anchor_not_regular_file",
            Self::TooLarge => "host_anchor_too_large",
            Self::Corrupt => "host_anchor_corrupt",
            Self::UnsupportedSchema { .. } => "host_anchor_unsupported_schema",
            Self::UnsupportedFormat { .. } => "host_anchor_unsupported_format",
            Self::MintRaced => "host_anchor_mint_raced",
            Self::InitialEnableControlOutOfScope => {
                "host_anchor_initial_enable_control_out_of_scope"
            }
            Self::InitialEnableRootReparse => "host_anchor_initial_enable_root_reparse",
            Self::InitialEnableRootNotDirectory => "host_anchor_initial_enable_root_not_directory",
            Self::InitialEnableRootUnreadable(_) => "host_anchor_initial_enable_root_unreadable",
            Self::InitialEnableControlReparse => "host_anchor_initial_enable_control_reparse",
            Self::InitialEnableControlNotDirectory => {
                "host_anchor_initial_enable_control_not_directory"
            }
            Self::InitialEnableControlUnreadable(_) => {
                "host_anchor_initial_enable_control_unreadable"
            }
            Self::InitialEnableControlOccupied => "host_anchor_initial_enable_control_occupied",
            Self::Lock(_) => "host_anchor_lock",
            Self::Io(_) => "host_anchor_io",
        }
    }
}

/// Bounded, printable-ASCII-only rendering of a document-controlled field: at
/// most 48 filtered bytes plus `...` when anything was dropped or truncated.
/// Raw document text (newlines, escape sequences, non-ASCII, or kilobytes of
/// noise) never reaches `Display` or logs.
fn observed_summary(observed: &str) -> String {
    const LIMIT: usize = 48;
    let mut summary = String::new();
    let mut truncated = false;
    for byte in observed.bytes() {
        if summary.len() >= LIMIT {
            truncated = true;
            break;
        }
        if (0x20..=0x7e).contains(&byte) {
            summary.push(char::from(byte));
        } else {
            truncated = true;
        }
    }
    if truncated {
        summary.push_str("...");
    }
    summary
}

#[derive(serde::Serialize)]
struct HostAnchorDocument<'a> {
    schema_version: u32,
    format: &'a str,
    anchor: &'a str,
}

fn is_lower_hex_anchor(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

/// Compact JSON with exactly the schema version, format discriminator, and
/// anchor keys. Unknown extra keys are tolerated on read and never rewritten.
fn serialize_document(anchor: &str) -> Result<String, HostAnchorError> {
    serde_json::to_string(&HostAnchorDocument {
        schema_version: HOST_ANCHOR_SCHEMA_VERSION,
        format: HOST_ANCHOR_FORMAT,
        anchor,
    })
    .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))
}

/// Strict validation of a document that was already bounded and UTF-8 decoded.
/// A missing or ill-typed field is `Corrupt`; a well-typed schema version or
/// format that this module does not implement is reported as unsupported so a
/// newer writer's value is never mistaken for a corrupt one.
fn document_anchor(text: &str) -> Result<HostAnchor, HostAnchorError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| HostAnchorError::Corrupt)?;
    let Some(object) = value.as_object() else {
        return Err(HostAnchorError::Corrupt);
    };
    let schema_version = object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .filter(|version| *version <= u64::from(u32::MAX))
        .ok_or(HostAnchorError::Corrupt)?;
    let schema_version = u32::try_from(schema_version).map_err(|_| HostAnchorError::Corrupt)?;
    if schema_version != HOST_ANCHOR_SCHEMA_VERSION {
        return Err(HostAnchorError::UnsupportedSchema {
            observed: schema_version,
        });
    }
    let Some(format) = object.get("format").and_then(serde_json::Value::as_str) else {
        return Err(HostAnchorError::Corrupt);
    };
    if format != HOST_ANCHOR_FORMAT {
        return Err(HostAnchorError::UnsupportedFormat {
            observed: observed_summary(format),
        });
    }
    let anchor = object
        .get("anchor")
        .and_then(serde_json::Value::as_str)
        .filter(|anchor| is_lower_hex_anchor(anchor))
        .ok_or(HostAnchorError::Corrupt)?;
    Ok(HostAnchor::from_anchor(anchor))
}

/// Read-only handle for one caller-selected anchor root.
pub struct HostAnchorStore {
    root: PathBuf,
}

impl HostAnchorStore {
    /// Binds a root without any IO. The root is caller-selected storage; it is
    /// not hardware, account, or machine identity.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn anchor_path(&self) -> PathBuf {
        self.root.join(HOST_ANCHOR_FILE_NAME)
    }

    /// Strict read. Missing is the only adoption-eligible state; every other
    /// outcome is a typed error and nothing is ever created, locked, repaired,
    /// deleted, or reset here.
    ///
    /// The whole stat/open/bounded-read/parse body runs on a blocking worker:
    /// the anchor can sit on a redirected user-data directory, and a bootstrap
    /// caller must not stall an async worker on filesystem IO.
    pub async fn read_strict(&self) -> Result<HostAnchorState, HostAnchorError> {
        let path = self.anchor_path();
        tokio::task::spawn_blocking(move || read_strict_blocking(&path))
            .await
            .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))?
    }

    /// Publish the anchor exactly once. An existing anchor of any shape is
    /// returned or reported unchanged; this call never overwrites, adopts, or
    /// deletes stored data.
    ///
    /// This is the unprotected primitive: an explicit first-enable caller must
    /// use [`ensure_for_initial_enable`](Self::ensure_for_initial_enable)
    /// instead, which additionally proves the same-namespace control root
    /// vacant before it may mint.
    pub async fn ensure(&self) -> Result<HostAnchorEnsure, HostAnchorError> {
        match self.read_strict().await? {
            HostAnchorState::Present(anchor) => Ok(HostAnchorEnsure::Existing(anchor)),
            HostAnchorState::Absent => {
                // The mint is an owned task, so caller cancellation can lose only
                // the result and the mint itself still completes. A runtime
                // shutdown during first enable can drop the owned task at its
                // next await, which may leave a `.tmp` and publishes no anchor;
                // this affects only the first-enable mint, never a read.
                let root = self.root.clone();
                tokio::spawn(async move { mint_anchor(root).await })
                    .await
                    .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))?
            }
        }
    }

    /// Protected write-once mint for the explicit first workspace-intelligence
    /// enable.
    ///
    /// This is the mint entry point a first-enable flow may consume, and it is
    /// deliberately stricter than [`ensure`](Self::ensure):
    ///
    /// 1. `control_root` must be the same-namespace control directory: a plain
    ///    direct child of this store's anchor root, built by the `PathManager`
    ///    owner from that same root. `..` segments, deeper descendants, the
    ///    anchor root itself, and sibling namespaces are refused with
    ///    [`HostAnchorError::InitialEnableControlOutOfScope`] before any IO. The
    ///    directory *name* is never duplicated or inferred here, and spellings
    ///    that normalize to the same direct child (interior `.` segments,
    ///    repeated separators) are accepted as that child.
    /// 2. An existing anchor is returned unchanged whatever the control state;
    ///    nothing is overwritten, adopted, repaired, or deleted.
    /// 3. Only an anchor that is strictly `Absent` and a control root that is
    ///    proven vacant may mint. Occupied, unreadable, linked/reparse, and
    ///    non-directory roots, and every unknown entry (including `.lock` and
    ///    `_tmp`/`*.tmp` residue), refuse with a typed error.
    /// 4. The vacancy pre-check runs before the anchor guard is acquired, so a
    ///    refusal leaves no directory, no lock, and no `.tmp` behind.
    /// 5. The mint is the same owned task shape as [`ensure`](Self::ensure):
    ///    under the anchor's cross-process OS guard it re-reads the anchor
    ///    strictly, re-proves control vacancy immediately before publishing, and
    ///    publishes with a strict create-new write that fails with
    ///    `AlreadyExists` instead of replacing a racing writer.
    ///
    /// # Trust and residual races
    ///
    /// The parent of the anchor root is trusted: the `PathManager` owner selects
    /// it, and this module cannot defend against a hostile parent, a renamed
    /// namespace, or a path swapped for a link between a check and the publish.
    /// The control root is only probed, never opened, locked, created, or
    /// modified, and proving vacancy is a conservative refusal gate, not a
    /// cross-store transaction: a control record that appears after the in-lock
    /// vacancy re-check cannot be detected here, so every cooperative control
    /// writer must be anchor-first and must not create a control record for a
    /// namespace whose anchor it has not obtained first. A refusal inside the
    /// lock can leave the anchor root and the inert `host-anchor.json.lock`
    /// behind; that lock is not a tenancy marker and no read path ever cleans it
    /// up. On Windows, `ERROR_BAD_NETPATH` and `ERROR_BAD_NET_NAME` decode to
    /// `NotFound`, so an offline redirected home can appear anchor-absent and
    /// control-vacant and reach the mint, which then fails closed on the first
    /// real write.
    ///
    /// Like [`ensure`](Self::ensure), this method belongs only to the explicit
    /// first-enable path, never to startup, bootstrap, or any automatic retry.
    pub async fn ensure_for_initial_enable(
        &self,
        control_root: &Path,
    ) -> Result<HostAnchorEnsure, HostAnchorError> {
        let control_root = initial_enable_control_root(&self.root, control_root)?;
        if let HostAnchorState::Present(anchor) = self.read_strict().await? {
            return Ok(HostAnchorEnsure::Existing(anchor));
        }
        // Pre-check vacancy without taking the guard: an occupied control root
        // refuses here, before the anchor root or a lock file is created.
        let precheck_root = self.root.clone();
        let precheck_control = control_root.clone();
        tokio::task::spawn_blocking(move || {
            prove_initial_enable_vacancy(&precheck_root, &precheck_control)
        })
        .await
        .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))??;
        // As in `ensure`, the mint is an owned task, so caller cancellation can
        // lose only the result and the guarded re-check plus publish still
        // complete.
        let root = self.root.clone();
        tokio::spawn(async move { mint_anchor_for_initial_enable(root, control_root).await })
            .await
            .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))?
    }
}

/// Strict read body. Runs on a blocking worker (see
/// [`HostAnchorStore::read_strict`]).
///
/// The anchor entry is opened exactly once and never followed: on Windows a
/// reparse point is opened as itself, and elsewhere the entry is re-statted after
/// the open and must still be the same non-symlink file.
fn read_strict_blocking(path: &Path) -> Result<HostAnchorState, HostAnchorError> {
    let Some(file) = open_anchor_handle(path)? else {
        return Ok(HostAnchorState::Absent);
    };
    let metadata = file.metadata().map_err(HostAnchorError::Io)?;
    if is_symlink_or_reparse(&metadata) {
        // Fail closed rather than reading a linked target.
        return Err(HostAnchorError::Symlink);
    }
    if !metadata.is_file() {
        return Err(HostAnchorError::NotRegularFile);
    }
    match read_bounded_from_handle(&file, HOST_ANCHOR_MAX_BYTES) {
        Ok(BoundedTextRead::Content(text)) => {
            Ok(HostAnchorState::Present(document_anchor(&text)?))
        }
        Ok(BoundedTextRead::TooLarge) => Err(HostAnchorError::TooLarge),
        Ok(BoundedTextRead::InvalidUtf8) => Err(HostAnchorError::Corrupt),
        Err(error) => Err(HostAnchorError::Io(error)),
    }
}

/// Opens the anchor entry itself, never a followed target. `None` is the absent
/// state; a broken symlink or junction is refused as its own state and can never
/// be mistaken for absent.
#[cfg(windows)]
fn open_anchor_handle(path: &Path) -> Result<Option<std::fs::File>, HostAnchorError> {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_FLAG_OPEN_REPARSE_POINT opens a reparse point as itself instead of
    // following it, so a same-directory swap cannot redirect this read.
    // FILE_FLAG_BACKUP_SEMANTICS is what lets a directory entry open at all, so a
    // directory is reported as `NotRegularFile` instead of an access error.
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(HostAnchorError::Io(error)),
    }
}

#[cfg(not(windows))]
fn open_anchor_handle(path: &Path) -> Result<Option<std::fs::File>, HostAnchorError> {
    use std::os::unix::fs::OpenOptionsExt;
    let entry = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(HostAnchorError::Io(error)),
    };
    if is_symlink_or_reparse(&entry) {
        return Err(HostAnchorError::Symlink);
    }
    if !entry.is_file() {
        return Err(HostAnchorError::NotRegularFile);
    }
    // Test-only barrier strictly between the pre-stat and the open, so a
    // substitution in that window is exercised deterministically.
    #[cfg(test)]
    if let Some(pause) = test_pauses::anchor_pauses_for(path).before_open_pause.as_ref() {
        test_pauses::wait_pause_blocking(pause);
    }
    // The open is atomic about both hazards of the pre-stat/open window:
    // `O_NOFOLLOW` refuses a final-component symlink with `ELOOP` instead of
    // following it, and `O_NONBLOCK` keeps `open(2)` from blocking when a FIFO
    // was substituted for the statted regular file.
    let file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(HostAnchorError::Symlink)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(HostAnchorError::Io(error)),
    };
    // A symlink is already refused by `O_NOFOLLOW` above, so this post-open
    // re-stat and `(dev, ino)` comparison is the same-name replace detector: it
    // requires the opened handle to be exactly the entry that is there now. An
    // identity that cannot be proven fails closed as `Symlink`, with no retry.
    let current = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return Err(HostAnchorError::Symlink),
    };
    if is_symlink_or_reparse(&current) {
        return Err(HostAnchorError::Symlink);
    }
    let opened = file.metadata().map_err(HostAnchorError::Io)?;
    use std::os::unix::fs::MetadataExt;
    if (current.dev(), current.ino()) != (opened.dev(), opened.ino()) {
        return Err(HostAnchorError::Symlink);
    }
    Ok(Some(file))
}

/// Bounded read over the already-open handle. The bounded read must consume the
/// same handle that was validated, because a path-based helper re-opens the path
/// and re-introduces the swap window between validation and read. It mirrors
/// `bounded_fs::read_bounded_file` exactly (capacity `min(max, 64 KiB) + 1`, at
/// most `max + 1` bytes read, `TooLarge` beyond) so both stay behaviourally
/// identical.
fn read_bounded_from_handle(
    file: &std::fs::File,
    max_bytes: usize,
) -> std::io::Result<BoundedTextRead> {
    let read_limit = max_bytes.saturating_add(1) as u64;
    let mut bytes = Vec::with_capacity(max_bytes.min(64 * 1024).saturating_add(1));
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Ok(BoundedTextRead::TooLarge);
    }
    Ok(match String::from_utf8(bytes) {
        Ok(content) => BoundedTextRead::Content(content),
        Err(_) => BoundedTextRead::InvalidUtf8,
    })
}

/// Post-publish resolution for the create-new mint.
#[derive(Debug)]
enum AnchorPublish {
    /// The create-new publish succeeded and must still be verified by re-reading.
    Published,
    /// An external writer already published a complete anchor.
    Existing(HostAnchor),
}

/// Maps the create-new publish result plus the re-read that follows it.
/// `re_read` is consulted only for the exact `AlreadyExists` publish outcome:
/// every other publish result keeps its own typed mapping and is never retried,
/// and a target that is still absent is the single `MintRaced` case.
async fn resolve_create_new_publish(
    publish: Result<(), JsonFileStoreError>,
    re_read: impl std::future::Future<Output = Result<HostAnchorState, HostAnchorError>>,
) -> Result<AnchorPublish, HostAnchorError> {
    match publish {
        Ok(()) => Ok(AnchorPublish::Published),
        Err(error) if error.is_already_exists() => match re_read.await? {
            HostAnchorState::Present(anchor) => Ok(AnchorPublish::Existing(anchor)),
            HostAnchorState::Absent => Err(HostAnchorError::MintRaced),
        },
        Err(error) => Err(HostAnchorError::Io(std::io::Error::other(error))),
    }
}

async fn mint_anchor(root: PathBuf) -> Result<HostAnchorEnsure, HostAnchorError> {
    let store = HostAnchorStore::new(root);
    let path = store.anchor_path();
    #[cfg(test)]
    let pauses = test_pauses::anchor_pauses_for(&path);
    // Test-only completion signal. It fires when this future leaves its body, so
    // the cancellation test can await real completion instead of directory shape.
    #[cfg(test)]
    let _finished = test_pauses::MintFinishedGuard(pauses.finished.clone());
    // The mint path is the only place that may bring up the caller-selected root.
    // The lock helper and the atomic write below both create it idempotently
    // (`create_dir_all`); no read path ever does.
    let _lock = JsonFileStore.acquire_cross_process_lock(&path).await?;
    // Same-winner read: another process may have published while we queued here.
    if let HostAnchorState::Present(anchor) = store.read_strict().await? {
        return Ok(HostAnchorEnsure::Existing(anchor));
    }
    // Test-only barrier: the guard is held and the fresh read confirmed the anchor
    // is still absent, so nothing has been minted or published yet.
    #[cfg(test)]
    if let Some(pause) = pauses.guard_pause.as_ref() {
        test_pauses::wait_pause(pause).await;
    }
    let anchor = uuid::Uuid::new_v4().simple().to_string();
    let text = serialize_document(&anchor)?;
    let publish = JsonFileStore.write_text_atomic_create_new(&path, &text).await;
    match resolve_create_new_publish(publish, store.read_strict()).await? {
        AnchorPublish::Existing(anchor) => return Ok(HostAnchorEnsure::Existing(anchor)),
        AnchorPublish::Published => {}
    }
    // Test-only barrier: the anchor is published, the final re-read is still ahead.
    #[cfg(test)]
    if let Some(pause) = pauses.published_pause.as_ref() {
        test_pauses::wait_pause(pause).await;
    }
    // The published document must round-trip to the minted value; anything else
    // is corrupt storage and is reported, never overwritten.
    let expected = format!("{HOST_ID_PREFIX}{anchor}");
    match store.read_strict().await? {
        HostAnchorState::Present(anchor) if anchor.host_id() == expected => {
            Ok(HostAnchorEnsure::Created(anchor))
        }
        HostAnchorState::Present(_) | HostAnchorState::Absent => Err(HostAnchorError::Corrupt),
    }
}

/// Mint body for [`HostAnchorStore::ensure_for_initial_enable`].
///
/// Twin of [`mint_anchor`], with the control-vacancy gate added at the last
/// possible check point: after the guard is held and the anchor was strictly
/// re-read as absent, and immediately before the create-new publish. The
/// publish, race mapping, and round-trip verification are the same reviewed
/// steps `ensure` uses.
async fn mint_anchor_for_initial_enable(
    root: PathBuf,
    control_root: PathBuf,
) -> Result<HostAnchorEnsure, HostAnchorError> {
    let probe_root = root.clone();
    let store = HostAnchorStore::new(root);
    let path = store.anchor_path();
    #[cfg(test)]
    let pauses = test_pauses::anchor_pauses_for(&path);
    // The mint path is the only place that may bring up the caller-selected root.
    // The lock helper and the atomic write below both create it idempotently
    // (`create_dir_all`); no read path ever does.
    let _lock = JsonFileStore.acquire_cross_process_lock(&path).await?;
    // Same-winner read: another process may have published while we queued here.
    if let HostAnchorState::Present(anchor) = store.read_strict().await? {
        return Ok(HostAnchorEnsure::Existing(anchor));
    }
    // Test-only check point: the guard is held and the anchor was just re-read
    // as absent. A record that lands while this pause is open must be refused by
    // the vacancy re-check below instead of being minted over.
    #[cfg(test)]
    if let Some(pause) = pauses.guard_pause.as_ref() {
        test_pauses::wait_pause(pause).await;
    }
    // Re-prove vacancy under the same anchor guard, immediately before minting.
    // This refuses a record that arrived after the caller-side pre-check; no
    // atomicity beyond this check point is claimed.
    tokio::task::spawn_blocking(move || prove_initial_enable_vacancy(&probe_root, &control_root))
        .await
        .map_err(|error| HostAnchorError::Io(std::io::Error::other(error)))??;
    let anchor = uuid::Uuid::new_v4().simple().to_string();
    let text = serialize_document(&anchor)?;
    let publish = JsonFileStore.write_text_atomic_create_new(&path, &text).await;
    match resolve_create_new_publish(publish, store.read_strict()).await? {
        AnchorPublish::Existing(anchor) => return Ok(HostAnchorEnsure::Existing(anchor)),
        AnchorPublish::Published => {}
    }
    // The published document must round-trip to the minted value; anything else
    // is corrupt storage and is reported, never overwritten.
    let expected = format!("{HOST_ID_PREFIX}{anchor}");
    match store.read_strict().await? {
        HostAnchorState::Present(anchor) if anchor.host_id() == expected => {
            Ok(HostAnchorEnsure::Created(anchor))
        }
        HostAnchorState::Present(_) | HostAnchorState::Absent => Err(HostAnchorError::Corrupt),
    }
}

/// Pure structural check of the caller-supplied initial-enable control root.
///
/// The root must resolve to a direct child of the anchor root, built by the owner
/// that selected it (`PathManager`) from that same root. This module deliberately
/// does not know or reproduce the directory *name*; it only verifies the
/// namespace position, because that position is what makes the vacancy proof
/// same-namespace. `Path::parent` is lexical and never normalizes `..`, so an
/// escaping path such as `root/../control` keeps a parent outside the root and is
/// refused, and `..`/leading `.` components are rejected explicitly as well.
/// Interior `.` segments and repeated separators are filesystem no-ops that
/// resolve to the same direct child, so they are accepted as that child.
fn initial_enable_control_root(
    root: &Path,
    control_root: &Path,
) -> Result<PathBuf, HostAnchorError> {
    if control_root.parent() != Some(root)
        || control_root.file_name().is_none()
        || control_root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(HostAnchorError::InitialEnableControlOutOfScope);
    }
    Ok(control_root.to_path_buf())
}

/// Proves that the namespace cannot hide control records. Runs on a blocking
/// worker (see [`HostAnchorStore::ensure_for_initial_enable`]).
///
/// "Vacant" means the control root is absent, or a real (non-linked) directory
/// with no entry at all. Anything else refuses: a link or reparse point, a
/// non-directory, an unreadable entry, and every entry whatever its name or type
/// — scoped records, `.lock` files, `_tmp`/`*.tmp` residue, unknown names. The
/// directory is never opened for writing, locked, created, or modified, and
/// nothing found here is deleted, filtered, or repaired. The anchor root is
/// checked in the same pass so a linked or replaced namespace root cannot host a
/// mint.
fn prove_initial_enable_vacancy(
    anchor_root: &Path,
    control_root: &Path,
) -> Result<(), HostAnchorError> {
    match std::fs::symlink_metadata(anchor_root) {
        Ok(metadata) if is_symlink_or_reparse(&metadata) => {
            return Err(HostAnchorError::InitialEnableRootReparse);
        }
        Ok(metadata) if !metadata.is_dir() => {
            return Err(HostAnchorError::InitialEnableRootNotDirectory);
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(HostAnchorError::InitialEnableRootUnreadable(error)),
    }
    let control = match std::fs::symlink_metadata(control_root) {
        Ok(metadata) => metadata,
        // An absent control root cannot hold records: the control store keeps
        // them inside this directory only.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(HostAnchorError::InitialEnableControlUnreadable(error)),
    };
    if is_symlink_or_reparse(&control) {
        return Err(HostAnchorError::InitialEnableControlReparse);
    }
    if !control.is_dir() {
        return Err(HostAnchorError::InitialEnableControlNotDirectory);
    }
    // One bounded take, no name or type filter. One entry of any kind refuses the
    // mint, and an enumeration failure is not "empty".
    let mut entries = match std::fs::read_dir(control_root) {
        Ok(entries) => entries,
        Err(error) => return Err(HostAnchorError::InitialEnableControlUnreadable(error)),
    };
    match entries.next() {
        None => Ok(()),
        Some(Ok(_)) => Err(HostAnchorError::InitialEnableControlOccupied),
        Some(Err(error)) => Err(HostAnchorError::InitialEnableControlUnreadable(error)),
    }
}

/// Test-only pause and completion registry keyed by anchor path.
///
/// The commit owner's `TestPause` is unreachable here: this feature deliberately
/// does not compose `workspace-intelligence-commit`, so the twin below keeps the
/// identical shape and waiter semantics without adding a public item.
#[cfg(test)]
mod test_pauses {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    pub(super) type TestPause = (
        tokio::sync::mpsc::UnboundedSender<()>,
        Arc<Mutex<std::sync::mpsc::Receiver<()>>>,
    );

    /// Test-only pause points and the completion notification for one anchor.
    #[derive(Clone, Default)]
    pub(super) struct AnchorPauses {
        /// Fires on the read path, strictly between the pre-stat and the open.
        #[cfg(unix)]
        pub(super) before_open_pause: Option<TestPause>,
        /// Fires with the cross-process guard held, after the fresh read
        /// confirmed still-absent and before anything is minted or published.
        /// For the protected initial-enable mint it fires at the vacancy check
        /// point: a record that lands while the pause is open must be refused by
        /// the re-check that follows, never minted over.
        pub(super) guard_pause: Option<TestPause>,
        /// Fires after the create-new publish succeeded, before the final read.
        pub(super) published_pause: Option<TestPause>,
        /// Signals that the owned mint future finished, whatever its outcome.
        pub(super) finished: Option<tokio::sync::mpsc::UnboundedSender<()>>,
    }

    static ANCHOR_PAUSES: Mutex<Vec<(PathBuf, AnchorPauses)>> = Mutex::new(Vec::new());

    pub(super) struct AnchorPauseRegistration(PathBuf);

    impl Drop for AnchorPauseRegistration {
        fn drop(&mut self) {
            ANCHOR_PAUSES
                .lock()
                .unwrap()
                .retain(|entry| entry.0.as_os_str() != self.0.as_os_str());
        }
    }

    pub(super) fn register_anchor_pauses(
        path: &Path,
        pauses: AnchorPauses,
    ) -> AnchorPauseRegistration {
        ANCHOR_PAUSES
            .lock()
            .unwrap()
            .push((path.to_path_buf(), pauses));
        AnchorPauseRegistration(path.to_path_buf())
    }

    pub(super) fn anchor_pauses_for(path: &Path) -> AnchorPauses {
        ANCHOR_PAUSES
            .lock()
            .unwrap()
            .iter()
            .find(|entry| entry.0.as_os_str() == path.as_os_str())
            .map(|entry| entry.1.clone())
            .unwrap_or_default()
    }

    /// Announces entry, then yields until released or the release sender drops.
    /// Mirrors the commit owner's async waiter.
    pub(super) async fn wait_pause(pause: &TestPause) {
        pause.0.send(()).unwrap();
        loop {
            let released = pause.1.lock().unwrap().try_recv();
            match released {
                Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
            }
        }
    }

    /// Blocking twin of [`wait_pause`] for pause points that run on a blocking
    /// worker, mirroring the commit owner's blocking waiter.
    #[cfg(unix)]
    pub(super) fn wait_pause_blocking(pause: &TestPause) {
        pause.0.send(()).unwrap();
        let _ = pause.1.lock().unwrap().recv();
    }

    /// Sends the completion notification when the owned mint future leaves its
    /// body, including every early-return path.
    pub(super) struct MintFinishedGuard(
        pub(super) Option<tokio::sync::mpsc::UnboundedSender<()>>,
    );

    impl Drop for MintFinishedGuard {
        fn drop(&mut self) {
            if let Some(finished) = self.0.take() {
                let _ = finished.send(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    const DEADLINE: Duration = Duration::from_secs(30);
    const ANCHOR: &str = "0123456789abcdef0123456789abcdef";

    fn anchor_document(anchor: &str) -> String {
        format!(
            "{{\"schema_version\":{HOST_ANCHOR_SCHEMA_VERSION},\"format\":\"{HOST_ANCHOR_FORMAT}\",\"anchor\":\"{anchor}\"}}"
        )
    }

    fn present(state: HostAnchorState) -> HostAnchor {
        match state {
            HostAnchorState::Present(anchor) => anchor,
            other => panic!("expected a present anchor, got {other:?}"),
        }
    }

    fn created(outcome: HostAnchorEnsure) -> HostAnchor {
        match outcome {
            HostAnchorEnsure::Created(anchor) => anchor,
            other => panic!("expected a created anchor, got {other:?}"),
        }
    }

    fn existing(outcome: HostAnchorEnsure) -> HostAnchor {
        match outcome {
            HostAnchorEnsure::Existing(anchor) => anchor,
            other => panic!("expected an existing anchor, got {other:?}"),
        }
    }

    fn entry_names(root: &Path) -> Vec<String> {
        let mut names = std::fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn copy_tree(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    fn is_symlink_privilege_error(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::PermissionDenied
            || error.raw_os_error() == Some(1314)
    }

    #[cfg(unix)]
    fn symlink_anchor(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn symlink_anchor(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_file(target, link)
    }

    #[tokio::test]
    async fn read_strict_on_missing_root_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("missing");
        let store = HostAnchorStore::new(root.clone());
        assert!(matches!(
            store.read_strict().await.unwrap(),
            HostAnchorState::Absent
        ));
        assert!(!root.exists());
        assert!(!store.anchor_path().exists());
        assert_eq!(entry_names(tmp.path()), Vec::<String>::new());
    }

    #[tokio::test]
    async fn read_strict_returns_present_and_never_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        std::fs::write(store.anchor_path(), anchor_document(ANCHOR)).unwrap();
        let before = std::fs::read(store.anchor_path()).unwrap();

        let first = present(store.read_strict().await.unwrap());
        let second = present(store.read_strict().await.unwrap());
        assert_eq!(first.host_id(), format!("{HOST_ID_PREFIX}{ANCHOR}"));
        assert_eq!(second.host_id(), first.host_id());
        let suffix = first.host_id().strip_prefix(HOST_ID_PREFIX).unwrap();
        assert_eq!(suffix.len(), 32);
        assert!(suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(std::fs::read(store.anchor_path()).unwrap(), before);
        assert_eq!(entry_names(&root), vec![HOST_ANCHOR_FILE_NAME.to_owned()]);
    }

    #[tokio::test]
    async fn read_strict_keeps_unknown_corrupt_and_unsupported_bytes_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let cases: [(&str, String); 4] = [
            (
                "unknown-extra-key",
                format!(
                    "{{\"schema_version\":{HOST_ANCHOR_SCHEMA_VERSION},\"format\":\"{HOST_ANCHOR_FORMAT}\",\"anchor\":\"{ANCHOR}\",\"future_field\":[1,2,3]}}"
                ),
            ),
            ("truncated-json", "{\"schema_version\":1,".to_owned()),
            (
                "unsupported-schema",
                format!(
                    "{{\"schema_version\":2,\"format\":\"{HOST_ANCHOR_FORMAT}\",\"anchor\":\"{ANCHOR}\"}}"
                ),
            ),
            (
                "unsupported-format",
                format!(
                    "{{\"schema_version\":{HOST_ANCHOR_SCHEMA_VERSION},\"format\":\"wi-host-anchor-v2\",\"anchor\":\"{ANCHOR}\"}}"
                ),
            ),
        ];
        for (name, text) in cases {
            std::fs::write(store.anchor_path(), &text).unwrap();
            let before = std::fs::read(store.anchor_path()).unwrap();
            let state = store.read_strict().await;
            match name {
                "unknown-extra-key" => assert_eq!(
                    present(state.unwrap()).host_id(),
                    format!("{HOST_ID_PREFIX}{ANCHOR}"),
                    "{name}"
                ),
                "truncated-json" => {
                    assert_eq!(state.unwrap_err().code(), "host_anchor_corrupt", "{name}");
                }
                "unsupported-schema" => {
                    let error = state.unwrap_err();
                    assert_eq!(error.code(), "host_anchor_unsupported_schema", "{name}");
                    assert!(
                        matches!(error, HostAnchorError::UnsupportedSchema { observed: 2 }),
                        "{name}"
                    );
                }
                _ => {
                    let error = state.unwrap_err();
                    assert_eq!(error.code(), "host_anchor_unsupported_format", "{name}");
                    assert!(
                        matches!(error, HostAnchorError::UnsupportedFormat { observed } if observed == "wi-host-anchor-v2"),
                        "{name}"
                    );
                }
            }
            assert_eq!(std::fs::read(store.anchor_path()).unwrap(), before, "{name}");
        }
    }

    #[tokio::test]
    async fn read_strict_rejects_directory_oversize_and_symlink() {
        let tmp = tempfile::tempdir().unwrap();

        // (a) A directory at the anchor path is not a regular file.
        let directory_root = tmp.path().join("directory");
        std::fs::create_dir_all(directory_root.join(HOST_ANCHOR_FILE_NAME)).unwrap();
        let store = HostAnchorStore::new(directory_root);
        let error = store.read_strict().await.unwrap_err();
        assert_eq!(error.code(), "host_anchor_not_regular_file");

        // (b) One byte over the limit is refused without touching the file.
        let oversize_root = tmp.path().join("oversize");
        std::fs::create_dir_all(&oversize_root).unwrap();
        let store = HostAnchorStore::new(oversize_root);
        std::fs::write(store.anchor_path(), vec![b'x'; HOST_ANCHOR_MAX_BYTES + 1]).unwrap();
        let before = std::fs::read(store.anchor_path()).unwrap();
        let error = store.read_strict().await.unwrap_err();
        assert_eq!(error.code(), "host_anchor_too_large");
        assert_eq!(std::fs::read(store.anchor_path()).unwrap(), before);

        // (c) A symlink to a valid anchor is refused, never followed.
        let symlink_root = tmp.path().join("symlink");
        std::fs::create_dir_all(&symlink_root).unwrap();
        let valid = symlink_root.join("valid.json");
        std::fs::write(&valid, anchor_document(ANCHOR)).unwrap();
        let link = symlink_root.join(HOST_ANCHOR_FILE_NAME);
        match symlink_anchor(&valid, &link) {
            Ok(()) => {
                let store = HostAnchorStore::new(symlink_root);
                let error = store.read_strict().await.unwrap_err();
                assert_eq!(error.code(), "host_anchor_symlink");
            }
            Err(error) if is_symlink_privilege_error(&error) => {
                // Windows without SeCreateSymbolicLinkPrivilege (or developer
                // mode) cannot create a file symlink. Only this sub-assertion is
                // skipped; the directory and oversize cases above still run, and
                // `reparse_point_at_anchor_path_is_refused` covers the reparse
                // branch without any privilege.
            }
            Err(error) => panic!("unexpected symlink creation failure: {error}"),
        }
    }

    #[tokio::test]
    async fn ensure_creates_once_and_never_rewrites() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        let store = HostAnchorStore::new(root.clone());
        let created = created(store.ensure().await.unwrap());
        let path = store.anchor_path();
        let bytes = std::fs::read(&path).unwrap();
        let suffix = created.host_id().strip_prefix(HOST_ID_PREFIX).unwrap();
        // Compact JSON with exactly the reviewed keys, in order.
        assert_eq!(
            String::from_utf8(bytes.clone()).unwrap(),
            anchor_document(suffix)
        );

        let existing = existing(store.ensure().await.unwrap());
        assert_eq!(existing.host_id(), created.host_id());
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            entry_names(&root),
            vec![
                HOST_ANCHOR_FILE_NAME.to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );
    }

    const CHILD_ROOT: &str = "OPENBITFUN_WI_HOST_ANCHOR_CHILD_ROOT";
    const CHILD_ROLE: &str = "OPENBITFUN_WI_HOST_ANCHOR_CHILD_ROLE";

    /// Kills and reaps only the children this test spawned to start a race.
    struct Child(std::process::Child);

    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn child(root: &Path, role: &str) -> Child {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        Child(
            command
                .args([
                    "--exact",
                    "workspace_intelligence_host_anchor::tests::anchor_process_fixture",
                    "--nocapture",
                ])
                .env(CHILD_ROOT, root)
                .env(CHILD_ROLE, role)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        )
    }

    async fn marker(path: &Path) -> String {
        let deadline = Instant::now() + DEADLINE;
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await {
                return text;
            }
            assert!(Instant::now() < deadline, "marker deadline: {}", path.display());
            tokio::task::yield_now().await;
        }
    }

    async fn write_marker(path: &Path, text: &str) {
        JsonFileStore.write_text_atomic_strict(path, text).await.unwrap();
    }

    #[tokio::test]
    async fn ensure_concurrent_processes_have_exactly_one_winner() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        let mut children = [child(&root, "a"), child(&root, "b")];
        let outcomes = [
            marker(&root.join("a.outcome")).await,
            marker(&root.join("b.outcome")).await,
        ];
        assert_eq!(
            outcomes
                .iter()
                .filter(|text| text.starts_with("created "))
                .count(),
            1,
            "{outcomes:?}"
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|text| text.starts_with("existing "))
                .count(),
            1,
            "{outcomes:?}"
        );
        let created_id = outcomes
            .iter()
            .find_map(|text| text.strip_prefix("created "))
            .unwrap();
        let existing_id = outcomes
            .iter()
            .find_map(|text| text.strip_prefix("existing "))
            .unwrap();
        assert_eq!(created_id, existing_id);
        assert!(created_id.starts_with(HOST_ID_PREFIX));
        // Exactly one anchor file, its lock, and the two outcome markers: no temp
        // or partial residue from either racer.
        assert_eq!(
            entry_names(&root),
            vec![
                "a.outcome".to_owned(),
                "b.outcome".to_owned(),
                HOST_ANCHOR_FILE_NAME.to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );
        let store = HostAnchorStore::new(root.clone());
        assert_eq!(present(store.read_strict().await.unwrap()).host_id(), created_id);
        let deadline = Instant::now() + DEADLINE;
        for child in &mut children {
            loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                assert!(Instant::now() < deadline, "child exit deadline");
                tokio::task::yield_now().await;
            }
        }
    }

    /// Test-only release handle: sending releases the pause, and dropping releases
    /// it too, so a panicking assertion cannot leave the owned task parked.
    struct ReleasePause(std::sync::mpsc::Sender<()>);

    impl ReleasePause {
        fn send(&self, value: ()) -> Result<(), std::sync::mpsc::SendError<()>> {
            self.0.send(value)
        }
    }

    impl Drop for ReleasePause {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    fn pause() -> (
        test_pauses::TestPause,
        tokio::sync::mpsc::UnboundedReceiver<()>,
        ReleasePause,
    ) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        (
            (entered, Arc::new(std::sync::Mutex::new(wait))),
            receiver,
            ReleasePause(release),
        )
    }

    async fn entered(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
        tokio::time::timeout(DEADLINE, receiver.recv())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn ensure_cancelled_caller_still_publishes_exactly_one_complete_anchor() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        let store = HostAnchorStore::new(root.clone());
        // A timed poll cannot tell "the abort landed before the owned mint
        // started" apart from "the abort landed after it published", so such a
        // test would be vacuous. These test-only barriers make both facts
        // deterministic: `guard_pause` fires with the cross-process guard held and
        // nothing published, and the completion channel reports the real end of
        // the owned task instead of inferring it from directory shape.
        let (guard_pause, mut guard_entered, release_guard) = pause();
        let (published_pause, mut published_entered, release_published) = pause();
        let (finished, mut finished_receiver) = tokio::sync::mpsc::unbounded_channel();
        let _registration = test_pauses::register_anchor_pauses(
            &store.anchor_path(),
            test_pauses::AnchorPauses {
                guard_pause: Some(guard_pause),
                published_pause: Some(published_pause),
                finished: Some(finished),
                ..Default::default()
            },
        );

        let caller_store = HostAnchorStore::new(root.clone());
        let caller = tokio::spawn(async move { caller_store.ensure().await });
        entered(&mut guard_entered).await;
        // The owned task is parked before the mint and has published nothing.
        assert!(!store.anchor_path().exists());

        // Abort cancels only the caller's future; the owned mint task it spawned
        // is what completes the publish.
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        // Proof that the abort landed pre-publish: still nothing on disk.
        assert!(!store.anchor_path().exists());

        release_guard.send(()).unwrap();
        entered(&mut published_entered).await;
        assert!(
            store.anchor_path().is_file(),
            "the cancelled caller's owned task must still publish"
        );
        release_published.send(()).unwrap();

        // Real completion of the owned task, not a directory-shape inference.
        tokio::time::timeout(DEADLINE, finished_receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            entry_names(&root),
            vec![
                HOST_ANCHOR_FILE_NAME.to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.anchor_path()).unwrap()).unwrap();
        assert_eq!(
            document["schema_version"].as_u64(),
            Some(u64::from(HOST_ANCHOR_SCHEMA_VERSION))
        );
        assert_eq!(document["format"].as_str(), Some(HOST_ANCHOR_FORMAT));
        let anchor = present(store.read_strict().await.unwrap());
        assert_eq!(
            document["anchor"].as_str().unwrap(),
            anchor.host_id().strip_prefix(HOST_ID_PREFIX).unwrap()
        );
    }

    /// Links a directory for tests: a junction on Windows, a symlink elsewhere.
    #[cfg(windows)]
    fn link_directory(target: &Path, link: &Path) -> std::io::Result<()> {
        use std::os::windows::process::CommandExt;
        // A directory junction is a reparse point that needs no
        // SeCreateSymbolicLinkPrivilege, and CREATE_NO_WINDOW keeps the fixture
        // from flashing a console window.
        let status = std::process::Command::new(
            std::env::var_os("ComSpec").unwrap_or_else(|| "cmd".into()),
        )
        .creation_flags(0x0800_0000)
        .args(["/d", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "mklink /J failed with {status}"
            )))
        }
    }

    #[cfg(unix)]
    fn link_directory(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    /// A same-root direct-child control name the platform refuses to inspect.
    fn unreadable_control_name(root: &Path) -> PathBuf {
        #[cfg(windows)]
        {
            // Win32 rejects `?` with ERROR_INVALID_NAME, which is not `NotFound`
            // and therefore cannot masquerade as a vacant directory.
            root.join("control?bad")
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            // An interior NUL is refused by the path conversion itself.
            root.join(std::ffi::OsStr::from_bytes(b"control\0bad"))
        }
    }

    #[tokio::test]
    async fn initial_enable_mints_once_on_vacant_control_roots() {
        let tmp = tempfile::tempdir().unwrap();

        // (a) A fresh namespace: neither the anchor root nor the control root
        // exists, so the control store cannot hold any record.
        let absent_root = tmp.path().join("absent-namespace");
        let absent_control = absent_root.join("control");
        let absent_store = HostAnchorStore::new(absent_root.clone());
        let minted = created(
            absent_store
                .ensure_for_initial_enable(&absent_control)
                .await
                .unwrap(),
        );
        let suffix = minted.host_id().strip_prefix(HOST_ID_PREFIX).unwrap();
        assert_eq!(
            String::from_utf8(std::fs::read(absent_store.anchor_path()).unwrap()).unwrap(),
            anchor_document(suffix)
        );
        // Proving vacancy is read-only: the control root is never created.
        assert!(!absent_control.exists());

        // The same anchor is reused by every later first-enable attempt.
        let reused = existing(
            absent_store
                .ensure_for_initial_enable(&absent_control)
                .await
                .unwrap(),
        );
        assert_eq!(reused.host_id(), minted.host_id());
        assert_eq!(
            entry_names(&absent_root),
            vec![
                HOST_ANCHOR_FILE_NAME.to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );

        // (b) An existing but empty control root is proven vacant too.
        let empty_root = tmp.path().join("empty-namespace");
        let empty_control = empty_root.join("control");
        std::fs::create_dir_all(&empty_control).unwrap();
        let empty_store = HostAnchorStore::new(empty_root.clone());
        let minted = created(
            empty_store
                .ensure_for_initial_enable(&empty_control)
                .await
                .unwrap(),
        );
        let reused = existing(
            empty_store
                .ensure_for_initial_enable(&empty_control)
                .await
                .unwrap(),
        );
        assert_eq!(reused.host_id(), minted.host_id());
        assert!(entry_names(&empty_control).is_empty());
        assert_eq!(
            entry_names(&empty_root),
            vec![
                "control".to_owned(),
                HOST_ANCHOR_FILE_NAME.to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );
    }

    #[tokio::test]
    async fn initial_enable_returns_an_existing_anchor_untouched_even_with_control_records() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("namespace");
        let control = root.join("control");
        std::fs::create_dir_all(&control).unwrap();
        let store = HostAnchorStore::new(root.clone());
        std::fs::write(store.anchor_path(), anchor_document(ANCHOR)).unwrap();
        // A record that would refuse a mint must not affect an existing anchor.
        let record = control.join("scope.json");
        std::fs::write(&record, b"existing control record").unwrap();
        let anchor_before = std::fs::read(store.anchor_path()).unwrap();
        let record_before = std::fs::read(&record).unwrap();

        let anchor = existing(store.ensure_for_initial_enable(&control).await.unwrap());
        assert_eq!(anchor.host_id(), format!("{HOST_ID_PREFIX}{ANCHOR}"));
        // Nothing was written, locked, adopted, or repaired.
        assert_eq!(std::fs::read(store.anchor_path()).unwrap(), anchor_before);
        assert_eq!(std::fs::read(&record).unwrap(), record_before);
        assert_eq!(
            entry_names(&root),
            vec!["control".to_owned(), HOST_ANCHOR_FILE_NAME.to_owned()]
        );
    }

    #[tokio::test]
    async fn initial_enable_refuses_occupied_control_roots_without_touching_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        // Every entry counts, with no name or type filter: a scoped record, a
        // lock, temp residue, and an unknown name.
        for entry in [
            "scope.json",
            ".scope.json.lock",
            ".scope.json.1234.5678.0.tmp",
            "unknown-entry",
        ] {
            let root = tmp.path().join(entry);
            let control = root.join("control");
            std::fs::create_dir_all(&control).unwrap();
            let entry_path = control.join(entry);
            std::fs::write(&entry_path, b"control record bytes").unwrap();
            let before = std::fs::read(&entry_path).unwrap();
            let store = HostAnchorStore::new(root.clone());

            let error = store
                .ensure_for_initial_enable(&control)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                "host_anchor_initial_enable_control_occupied",
                "{entry}"
            );
            // The pre-check refuses before the guard: no anchor, no lock, no temp.
            assert!(!store.anchor_path().exists(), "{entry}");
            assert_eq!(entry_names(&root), vec!["control".to_owned()], "{entry}");
            assert_eq!(entry_names(&control), vec![entry.to_owned()], "{entry}");
            assert_eq!(std::fs::read(&entry_path).unwrap(), before, "{entry}");
        }

        // A nested directory is an entry too.
        let root = tmp.path().join("nested-directory");
        let control = root.join("control");
        std::fs::create_dir_all(control.join("nested")).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let error = store
            .ensure_for_initial_enable(&control)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_control_occupied");
        assert!(!store.anchor_path().exists());
        assert_eq!(entry_names(&root), vec!["control".to_owned()]);
        assert_eq!(entry_names(&control), vec!["nested".to_owned()]);
    }

    #[tokio::test]
    async fn initial_enable_refuses_control_roots_outside_the_anchor_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("namespace");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        for control in [
            tmp.path().join("sibling"),
            root.join(".."),
            root.join("..").join("control"),
            root.join("nested").join("control"),
            root.clone(),
        ] {
            let error = store
                .ensure_for_initial_enable(&control)
                .await
                .unwrap_err();
            assert_eq!(
                error.code(),
                "host_anchor_initial_enable_control_out_of_scope",
                "{}",
                control.display()
            );
        }
        // Every refusal is decided before any IO: the namespace root stays empty.
        assert_eq!(entry_names(&root), Vec::<String>::new());
    }

    #[tokio::test]
    async fn initial_enable_refuses_malformed_or_unreadable_control_roots() {
        let tmp = tempfile::tempdir().unwrap();

        // (a) A plain file where the control directory should be.
        let root = tmp.path().join("file-shaped");
        let control = root.join("control");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(&control, b"not a directory").unwrap();
        let before = std::fs::read(&control).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let error = store
            .ensure_for_initial_enable(&control)
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "host_anchor_initial_enable_control_not_directory"
        );
        assert!(!store.anchor_path().exists());
        assert_eq!(std::fs::read(&control).unwrap(), before);
        assert_eq!(entry_names(&root), vec!["control".to_owned()]);

        // (b) A linked control root is never traversed to "prove" vacancy.
        let root = tmp.path().join("linked-shaped");
        let target = tmp.path().join("linked-target");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        let control = root.join("control");
        link_directory(&target, &control).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let error = store
            .ensure_for_initial_enable(&control)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_control_reparse");
        assert!(!store.anchor_path().exists());
        assert_eq!(entry_names(&root), vec!["control".to_owned()]);
        assert!(entry_names(&target).is_empty());

        // (c) A control name the filesystem refuses to inspect is a typed
        // refusal, not a vacant directory.
        let root = tmp.path().join("unreadable-name");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let error = store
            .ensure_for_initial_enable(&unreadable_control_name(&root))
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            "host_anchor_initial_enable_control_unreadable"
        );
        assert!(!store.anchor_path().exists());
        assert!(entry_names(&root).is_empty());

        // (d) A plain file where the anchor root should be is refused by the
        // vacancy probe itself.
        let root = tmp.path().join("file-root");
        std::fs::write(&root, b"not a directory").unwrap();
        let error = prove_initial_enable_vacancy(&root, &root.join("control")).unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_root_not_directory");
        assert_eq!(std::fs::read(&root).unwrap(), b"not a directory".to_vec());
    }

    #[tokio::test]
    async fn initial_enable_refuses_a_linked_anchor_root() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("namespace-target");
        std::fs::create_dir_all(&target).unwrap();
        let root = tmp.path().join("namespace");
        link_directory(&target, &root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let error = store
            .ensure_for_initial_enable(&root.join("control"))
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_root_reparse");
        // Neither the linked root nor its target received anything.
        assert!(entry_names(&target).is_empty());
        assert!(!store.anchor_path().exists());
    }

    #[tokio::test]
    async fn initial_enable_late_control_record_is_refused_at_the_check_point() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("namespace");
        let control = root.join("control");
        let store = HostAnchorStore::new(root.clone());
        // The pre-check sees a vacant namespace, so the caller proceeds to the
        // guard; the barrier then holds exactly at the in-lock check point.
        let (guard_pause, mut guard_entered, release_guard) = pause();
        let registration = test_pauses::register_anchor_pauses(
            &store.anchor_path(),
            test_pauses::AnchorPauses {
                guard_pause: Some(guard_pause),
                ..Default::default()
            },
        );

        let caller_store = HostAnchorStore::new(root.clone());
        let caller_control = control.clone();
        let caller = tokio::spawn(async move {
            caller_store.ensure_for_initial_enable(&caller_control).await
        });
        entered(&mut guard_entered).await;
        // The guard is held, the anchor is still absent, and nothing is published.
        assert!(!store.anchor_path().exists());

        // The record arrives after the caller-side pre-check and before the
        // in-lock vacancy re-check: the mint must refuse it, not mint over it.
        std::fs::create_dir_all(&control).unwrap();
        let record = control.join("scope.json");
        std::fs::write(&record, b"late control record").unwrap();
        release_guard.send(()).unwrap();
        // Never park a later firing: release and disconnect the pause.
        drop(release_guard);

        let error = caller.await.unwrap().unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_control_occupied");
        assert!(
            !store.anchor_path().exists(),
            "a late record is never minted over"
        );
        assert_eq!(std::fs::read(&record).unwrap(), b"late control record".to_vec());
        // Residual inert guard file only: the control record is untouched, and
        // the in-lock refusal never repairs or deletes anything.
        assert_eq!(
            entry_names(&root),
            vec![
                "control".to_owned(),
                format!("{HOST_ANCHOR_FILE_NAME}.lock"),
            ]
        );

        // The refusal is stable: a second attempt stays refused, barrier gone.
        drop(registration);
        let error = store
            .ensure_for_initial_enable(&control)
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_initial_enable_control_occupied");
        assert!(!store.anchor_path().exists());
    }

    /// Creates a FIFO at `path`, failing the test with the OS error otherwise.
    #[cfg(unix)]
    fn mkfifo(path: &Path) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .expect("temp paths never contain NUL");
        // SAFETY: `c_path` is a valid NUL-terminated path owned by this scope.
        let result = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Bounds the three Unix open tests: a regression must fail loudly instead of
    /// hanging the suite. This timeout is a regression tripwire, not the
    /// mechanism the tests rely on.
    #[cfg(unix)]
    const OPEN_TRIPWIRE: Duration = Duration::from_secs(10);

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_substituted_after_the_pre_stat_is_refused_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(HOST_ANCHOR_FILE_NAME);
        std::fs::write(&path, anchor_document(ANCHOR)).unwrap();

        let (open_pause, mut open_entered, release_open) = pause();
        let _registration = test_pauses::register_anchor_pauses(
            &path,
            test_pauses::AnchorPauses {
                before_open_pause: Some(open_pause),
                ..Default::default()
            },
        );

        let reader_store = HostAnchorStore::new(root.clone());
        let reader = tokio::spawn(async move { reader_store.read_strict().await });
        entered(&mut open_entered).await;
        // Substitute a FIFO inside the pre-stat/open window. Without `O_NONBLOCK`
        // the open would park here forever.
        std::fs::remove_file(&path).unwrap();
        mkfifo(&path).expect("mkfifo must create the substituted FIFO");
        release_open.send(()).unwrap();

        let error = tokio::time::timeout(OPEN_TRIPWIRE, reader)
            .await
            .expect("a regression must fail loudly; this timeout is a tripwire, not the mechanism")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_not_regular_file");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_substituted_after_the_pre_stat_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join(HOST_ANCHOR_FILE_NAME);
        std::fs::write(&path, anchor_document(ANCHOR)).unwrap();
        // The link target is a FIFO, so following the link would block instead of
        // merely reading a different file.
        let fifo = tmp.path().join("fifo-target");
        mkfifo(&fifo).expect("mkfifo must create the link target");

        let (open_pause, mut open_entered, release_open) = pause();
        let _registration = test_pauses::register_anchor_pauses(
            &path,
            test_pauses::AnchorPauses {
                before_open_pause: Some(open_pause),
                ..Default::default()
            },
        );

        let reader_store = HostAnchorStore::new(root.clone());
        let reader = tokio::spawn(async move { reader_store.read_strict().await });
        entered(&mut open_entered).await;
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&fifo, &path).expect("symlink must replace the anchor");
        release_open.send(()).unwrap();

        let error = tokio::time::timeout(OPEN_TRIPWIRE, reader)
            .await
            .expect("a regression must fail loudly; this timeout is a tripwire, not the mechanism")
            .unwrap()
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_symlink");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn fifo_already_at_the_anchor_path_is_refused_by_the_pre_stat() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root.clone());
        mkfifo(&store.anchor_path()).expect("mkfifo must create the FIFO");

        let error = tokio::time::timeout(OPEN_TRIPWIRE, store.read_strict())
            .await
            .expect("the pre-stat must refuse the FIFO without opening it")
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_not_regular_file");
    }

    #[tokio::test]
    async fn ensure_refuses_to_adopt_unknown_or_corrupt_content() {
        let tmp = tempfile::tempdir().unwrap();
        let cases: [(&str, String, &str); 2] = [
            (
                "unsupported-schema",
                format!(
                    "{{\"schema_version\":2,\"format\":\"{HOST_ANCHOR_FORMAT}\",\"anchor\":\"{ANCHOR}\"}}"
                ),
                "host_anchor_unsupported_schema",
            ),
            ("corrupt", "not a host anchor document".to_owned(), "host_anchor_corrupt"),
        ];
        for (name, text, code) in cases {
            let root = tmp.path().join(name);
            std::fs::create_dir_all(&root).unwrap();
            let store = HostAnchorStore::new(root.clone());
            std::fs::write(store.anchor_path(), &text).unwrap();
            let before = std::fs::read(store.anchor_path()).unwrap();
            let error = store.ensure().await.unwrap_err();
            assert_eq!(error.code(), code, "{name}");
            assert_eq!(std::fs::read(store.anchor_path()).unwrap(), before, "{name}");
            assert_eq!(
                entry_names(&root),
                vec![HOST_ANCHOR_FILE_NAME.to_owned()],
                "{name}"
            );
        }
    }

    #[tokio::test]
    async fn ensure_failure_leaves_no_partial_target() {
        let tmp = tempfile::tempdir().unwrap();

        // A directory at the anchor path fails closed before any lock or write.
        let directory_root = tmp.path().join("directory-target");
        std::fs::create_dir_all(directory_root.join(HOST_ANCHOR_FILE_NAME)).unwrap();
        let store = HostAnchorStore::new(directory_root.clone());
        let error = store.ensure().await.unwrap_err();
        assert_eq!(error.code(), "host_anchor_not_regular_file");
        assert_eq!(
            entry_names(&directory_root),
            vec![HOST_ANCHOR_FILE_NAME.to_owned()]
        );

        // A symlink at the anchor path fails closed too, and leaves no temp file.
        let symlink_root = tmp.path().join("symlink-target");
        std::fs::create_dir_all(&symlink_root).unwrap();
        let valid = symlink_root.join("valid.json");
        std::fs::write(&valid, anchor_document(ANCHOR)).unwrap();
        let link = symlink_root.join(HOST_ANCHOR_FILE_NAME);
        match symlink_anchor(&valid, &link) {
            Ok(()) => {
                let store = HostAnchorStore::new(symlink_root.clone());
                let error = store.ensure().await.unwrap_err();
                assert_eq!(error.code(), "host_anchor_symlink");
                let names = entry_names(&symlink_root);
                assert!(names.iter().all(|name| !name.ends_with(".tmp")), "{names:?}");
                assert_eq!(
                    names,
                    vec!["host-anchor.json".to_owned(), "valid.json".to_owned()]
                );
            }
            Err(error) if is_symlink_privilege_error(&error) => {
                // Windows without SeCreateSymbolicLinkPrivilege (or developer
                // mode) cannot create a file symlink. Only this sub-assertion is
                // skipped; the directory case above still runs, and
                // `reparse_point_at_anchor_path_is_refused` covers the reparse
                // branch without any privilege.
            }
            Err(error) => panic!("unexpected symlink creation failure: {error}"),
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn reparse_point_at_anchor_path_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let junction_target = tmp.path().join("junction-target");
        std::fs::create_dir_all(&junction_target).unwrap();
        let anchor_path = root.join(HOST_ANCHOR_FILE_NAME);
        // A directory junction is a reparse point that needs no
        // SeCreateSymbolicLinkPrivilege, so this exercises the Windows
        // FILE_ATTRIBUTE_REPARSE_POINT branch on hosts where file symlinks are
        // unavailable.
        let mut command = std::process::Command::new(
            std::env::var_os("ComSpec").unwrap_or_else(|| "cmd".into()),
        );
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let status = command
            .args(["/d", "/c", "mklink", "/J"])
            .arg(&anchor_path)
            .arg(&junction_target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "mklink /J failed with {status}");

        let store = HostAnchorStore::new(root.clone());
        assert_eq!(
            store.read_strict().await.unwrap_err().code(),
            "host_anchor_symlink"
        );
        assert_eq!(store.ensure().await.unwrap_err().code(), "host_anchor_symlink");
        // No label was placed on the junction target, no lock and no temp file
        // were created, and the refusable entry is still exactly what it was.
        assert_eq!(entry_names(&root), vec![HOST_ANCHOR_FILE_NAME.to_owned()]);
        assert!(entry_names(&junction_target).is_empty());
        let metadata = std::fs::symlink_metadata(&anchor_path).unwrap();
        assert!(is_symlink_or_reparse(&metadata));
        assert!(!metadata.is_file());
    }

    #[tokio::test]
    async fn data_root_migration_preserves_the_anchor_value() {
        let tmp = tempfile::tempdir().unwrap();
        let source_root = tmp.path().join("root-a");
        let destination_root = tmp.path().join("root-b");
        let created = created(HostAnchorStore::new(source_root.clone()).ensure().await.unwrap());
        copy_tree(&source_root, &destination_root);
        let migrated =
            present(HostAnchorStore::new(destination_root).read_strict().await.unwrap());
        assert_eq!(migrated.host_id(), created.host_id());
    }

    #[tokio::test]
    async fn host_id_is_prefix_plus_full_anchor_without_hashing() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        let store = HostAnchorStore::new(root.clone());
        let created = created(store.ensure().await.unwrap());
        let document: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(store.anchor_path()).unwrap()).unwrap();
        let stored = document["anchor"].as_str().unwrap();
        let suffix = created.host_id().strip_prefix(HOST_ID_PREFIX).unwrap();
        // The suffix is the stored value itself, not a hash or truncation of it.
        assert_eq!(suffix, stored);
        assert_eq!(suffix.len(), 32);
        let debug = format!("{created:?}");
        assert_eq!(debug, "HostAnchor(<redacted>)");
        assert!(!debug.contains(stored));
    }

    #[test]
    fn unsupported_format_display_stays_bounded_and_printable() {
        let noisy = format!("{}\n\u{1b}[0m\u{4f60}\u{597d}", "A".repeat(200));
        let text = format!(
            "{{\"schema_version\":{HOST_ANCHOR_SCHEMA_VERSION},\"format\":{},\"anchor\":\"{ANCHOR}\"}}",
            serde_json::to_string(&noisy).unwrap()
        );
        let error = document_anchor(&text).unwrap_err();
        assert_eq!(error.code(), "host_anchor_unsupported_format");
        let HostAnchorError::UnsupportedFormat { observed } = &error else {
            panic!("expected an unsupported format error, got {error:?}");
        };
        // At most 48 filtered printable ASCII bytes plus the truncation marker,
        // and no raw document text in `Display`.
        assert!(observed.len() <= 48 + 3, "{observed}");
        assert!(observed.ends_with("..."), "{observed}");
        assert!(
            observed.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "{observed}"
        );
        let display = error.to_string();
        assert_eq!(
            display,
            format!("Host anchor document declares unsupported format {observed}")
        );
        assert!(!display.contains('\n'));
        assert!(!display.contains('\u{1b}'));
    }

    async fn raced_publish(path: &Path) -> Result<(), JsonFileStoreError> {
        let publish =
            JsonFileStore.write_text_atomic_create_new(path, &anchor_document(ANCHOR)).await;
        assert!(publish.as_ref().unwrap_err().is_already_exists());
        publish
    }

    async fn unreachable_read() -> Result<HostAnchorState, HostAnchorError> {
        panic!("a non-AlreadyExists publish outcome must not consult the re-read")
    }

    fn existing_from(outcome: AnchorPublish) -> HostAnchor {
        match outcome {
            AnchorPublish::Existing(anchor) => anchor,
            other => panic!("expected an existing publish outcome, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn raced_create_new_publish_maps_to_the_external_outcome() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("data");
        std::fs::create_dir_all(&root).unwrap();
        let store = HostAnchorStore::new(root);
        let path = store.anchor_path();
        JsonFileStore
            .write_text_atomic_create_new(&path, &anchor_document(ANCHOR))
            .await
            .unwrap();

        // (AlreadyExists, Present) -> Existing with the stored value.
        let publish = raced_publish(&path).await;
        let existing = existing_from(
            resolve_create_new_publish(publish, store.read_strict())
                .await
                .unwrap(),
        );
        assert_eq!(existing.host_id(), format!("{HOST_ID_PREFIX}{ANCHOR}"));

        // (AlreadyExists, Absent) -> MintRaced: the racer's file vanished again.
        let publish = raced_publish(&path).await;
        std::fs::remove_file(&path).unwrap();
        let error = resolve_create_new_publish(publish, store.read_strict())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_mint_raced");

        // (AlreadyExists, Corrupt) -> Corrupt: the typed read failure is kept.
        std::fs::write(&path, &anchor_document(ANCHOR)).unwrap();
        let publish = raced_publish(&path).await;
        std::fs::write(&path, "not a host anchor document").unwrap();
        let error = resolve_create_new_publish(publish, store.read_strict())
            .await
            .unwrap_err();
        assert_eq!(error.code(), "host_anchor_corrupt");

        // A successful publish is `Published`, and a publish failure that is not
        // `AlreadyExists` keeps its own mapping; neither consults the re-read.
        let published = resolve_create_new_publish(Ok(()), unreachable_read())
            .await
            .unwrap();
        assert!(matches!(published, AnchorPublish::Published));
        let error = resolve_create_new_publish(
            Err(JsonFileStoreError::Replace {
                source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
            }),
            unreachable_read(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "host_anchor_io");
    }

    #[tokio::test]
    async fn anchor_process_fixture() {
        let Some(root) = std::env::var_os(CHILD_ROOT) else {
            return;
        };
        let root = PathBuf::from(root);
        let role = std::env::var(CHILD_ROLE).unwrap();
        let store = HostAnchorStore::new(root.clone());
        let text = match store.ensure().await {
            Ok(HostAnchorEnsure::Created(anchor)) => format!("created {}", anchor.host_id()),
            Ok(HostAnchorEnsure::Existing(anchor)) => format!("existing {}", anchor.host_id()),
            Err(error) => format!("error {} {error}", error.code()),
        };
        write_marker(&root.join(format!("{role}.outcome")), &text).await;
    }
}
