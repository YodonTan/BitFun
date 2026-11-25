//! Real ON end-to-end evidence for the CLI's workspace-intelligence skip sites.
//!
//! Six command sites place `CliHostPlacement::Skip` and never admit the host:
//! `usage`, `doctor`, `health`, `server`, the session report site (`sessions
//! list|show|delete|fork`) and ACP. The process-level placement probes already prove
//! a skip decides before a root, a deployment or a slot is read; this file proves the
//! *shipped binary* really reaches each site on a workspace a real host has already
//! published, and that a skip leaves that workspace exactly as it was.
//!
//! One isolated root carries the whole scenario, because a baseline and a treated run
//! must be compared on the same paths:
//!
//! 1. the fixture seeds the workspace record for the CLI's own working directory, so
//!    the ON scope is the directory the command actually runs in;
//! 2. the OFF baseline runs the same binary with the same arguments before the scope
//!    is enabled, and proves the run creates no host namespace at all;
//! 3. the fixture enables the seeded scope in one control generation, and a real
//!    `WorkspaceIntelligenceHost` bootstrap publishes the ON state: it owns the
//!    scope, advances its incarnation token into a non-empty cognition partition and
//!    writes its lease, then drains and releases the lease;
//! 4. the treated command runs cold: no owner is alive and no durable byte of the host
//!    namespace may change;
//! 5. the treated command runs warm: this process holds a live `Active` host on that
//!    scope, so the incarnation token and the lease are certainly held, and the run
//!    must leave the owner, the lease and the whole tree intact;
//! 6. after the last snapshot the process bootstraps once more to prove the scope is
//!    takeable again, which is only possible if the earlier owner drained.
//!
//! The evidence for "the command reached the site" is the site's own placement line.
//! These commands log to stderr only with `--verbose` (the default level is `ERROR`),
//! and a skip reports `host_placement=<skip code>` from the placement code itself, so
//! every invocation here that is asked for that line passes `--verbose` and asserts it. A
//! command that failed while parsing arguments or while starting up cannot produce it, so an
//! early failure cannot stand in for reaching the site. The same level rule decides what a
//! drain assertion can be made on: `host_drain=` is an `INFO` record, so it exists only on a
//! `--verbose` run. A plain run filters it out with every other non-error record, and no
//! assertion here is taken from that run's stderr.
//!
//! The two protocol sites answer a real `initialize` on stdout, so their stdout is
//! asserted line by line as JSON and compared as a stable business projection. Those
//! payloads are deterministic — the app server advertises a fixed identity, fixed transport
//! limits and a fixed capability list, and ACP advertises a fixed protocol version and agent
//! identity — so nothing is removed from either comparison.
//!
//! Each stdio site is driven the way the shipped command is measured to behave, which is not
//! the same for both:
//!
//! - the app server leaves through `std::process::exit` inside its own body. On an isolated
//!   root with the repository's model catalog selected, the recorded `--verbose` `app/health`
//!   probe received no response within 30 s. Its trace records the request, dispatch and a
//!   model-catalog-updated event, but no response or `models.dev` line. The cause is not
//!   isolated by this slice, so this measurement is not a product defect diagnosis and no code
//!   in the product
//!   is changed for it. The site is therefore proven by two runs of the same shipped command
//!   on the same root: a `--verbose` run that closes stdin at once for the placement line and
//!   the absence of a drain, and a plain run for the protocol exchange;
//! - ACP answers with the `--verbose` channel open, so one run carries both its placement line
//!   and its protocol answer. The shipped transport is a long-lived server that serves while a
//!   client is connected (`acp_stdio_cli.rs` waits for it the same way and then stops it), so
//!   this slice does not measure natural EOF exit for it: the test cancels the session itself
//!   once the answer has been observed and asserted, and claims nothing about a drain or about
//!   a normal exit status for that command.
//!
//! stderr is the `--verbose` tracing channel, not command output: its lines carry their
//! own timestamps and the run's own trace volume. This file therefore never compares
//! stderr across runs. What it takes from that channel is asserted per run instead: the
//! site's own `host_placement=` line, the `host_drain=` line the command's real exit path
//! can produce, and the command's own plain diagnostic lines, recognised by not being a
//! timestamped tracing record. stdout and the exit status are the comparison surface and stay
//! strict.
//!
//! The snapshot compares what is durable on disk, byte for byte, and does not claim that a
//! command performed no IO at all: a transient claim that leaves a file's durable bytes and
//! length unchanged is invisible to it. Those bytes are the anchor document, the control
//! record with its generation, the cognition partition with the incarnation token and the
//! lease files. The transient side of the lease is covered separately, by asserting across the
//! run that the live owner still holds it; and the reason no admission can be hiding behind
//! that limit is the skip path itself, which refuses before any root, catalog, deployment or
//! slot is read. The one file a snapshot cannot read is the lease a live owner holds, which the
//! OS refuses with a byte-range lock; that entry is compared by name, kind and length instead.
//!
//! Every child is started through `process_manager`, so no test here creates a console
//! window, and every child is killed and reaped on an error or timeout path instead of
//! being left orphaned. Every root is isolated, and the model catalog is read from the copy
//! already in the repository, which avoids the shipped default's `models.dev` fetch. Nothing
//! here uses the user's own data, a daemon, or a model; this suite performs no socket audit,
//! so it does not claim that no other connection exists.

#[path = "../support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use openbitfun_core::infrastructure::PathManager;
use openbitfun_core::service::workspace_intelligence::host_fixture;
use openbitfun_core::service::workspace_intelligence::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostScopeState,
    WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostSurface,
};
use openbitfun_services_core::exclusive_file_lease::ExclusiveFileLease;
use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
use serde_json::{json, Value};
use support::{command_output_with_timeout, CliTestEnvironment};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Persisted workspace id of the scope every scenario enables.
pub(crate) const WORKSPACE_ID: &str = "cli-skip-e2e-workspace";

/// A session id that passes the owner's own id validation and exists nowhere.
const MISSING_SESSION_ID: &str = "cli-skip-e2e-missing-session";

/// Field a placement decision is logged with, and the field a drain is logged with.
const PLACEMENT_FIELD: &str = "host_placement=";
const DRAIN_FIELD: &str = "host_drain=";

/// The member root of the host namespace a live owner holds a byte-range lock in.
const LEASE_ROOT: &str = "lease";

/// Value code of a drain that found no admitted host.
pub(crate) const NOT_INSTALLED_CODE: &str = "not_installed";

/// Value code of a drain that stopped a live host with nothing outstanding.
const DRAINED_CODE: &str = "drained";

/// Stable placement codes of the sites this file covers.
const MANAGEMENT_SKIP_CODE: &str = "host_skip_management";
const STDIO_SKIP_CODE: &str = "host_skip_stdio_server";
const ACP_SKIP_CODE: &str = "host_skip_acp";

/// The model catalog the product already ships inside the repository.
///
/// The shipped default refreshes the models.dev catalog over the network. The documented
/// development and testing source (`OPENBITFUN_MODELS_DEV_PATH`) selects this copy instead, so
/// the child reads a catalog from disk and the models.dev fetch is not attempted; the child
/// keeps its own default models either way.
pub(crate) const REPOSITORY_MODEL_CATALOG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../crates/services/services-integrations/assets/models-dev.json"
);

/// How long one one-shot command may take before it is killed and failed.
///
/// A one-shot command here only assembles core services and prints a report; it runs no
/// turn and reaches no model. The budget is therefore generous against a loaded machine
/// rather than sized for the work, and a command that exceeds it fails instead of passing.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

/// Absolute deadline of one stdio protocol session, measured from its spawn.
///
/// It is one budget for the whole exchange rather than a per-line timeout, so a child
/// that answers slowly but forever cannot extend it. The exchange is one `initialize`
/// (and, for the app server, one `app/health`) on an isolated root, and the measured cost of
/// each of those sessions is a few seconds, so the budget is again generous rather than sized
/// for the work.
const STDIO_DEADLINE: Duration = Duration::from_secs(120);

/// The window in which the live owner must leave its own namespace untouched.
///
/// The treated run's evidence is only attributable if the live owner is quiescent on its
/// own, so this window proves that before the command runs. An already-owned scope is
/// verified read-only: `host.rs` takes the owned-claim branch and calls
/// `verify_expecting`, whose contract is a rolled-back, token-preserving verification
/// (`workspace_intelligence_claim.rs`), so a quiet window is what the owner's steady
/// state is expected to be. The window is asserted, never skipped: a change inside it
/// fails the test rather than narrowing what is compared. 900 ms is long enough that a
/// writer on a short period would be caught and short enough to keep the scenario cheap.
const OWNER_QUIESCENCE_WINDOW: Duration = Duration::from_millis(900);

/// One invocation's own isolated CLI root with one seeded workspace.
pub(crate) struct OnRoot {
    pub(crate) environment: CliTestEnvironment,
    pub(crate) paths: Arc<PathManager>,
}

impl OnRoot {
    /// Creates the isolated root the CLI composes its own user-data root from.
    pub(crate) fn new() -> Self {
        let environment = CliTestEnvironment::new();
        let paths = host_fixture::test_path_manager(environment.user_root());
        Self { environment, paths }
    }

    /// Seeds the workspace record for the directory the CLI runs in.
    ///
    /// The scope is the CLI's real `cwd`, resolved from `current_dir` exactly as
    /// `usage`, `doctor`, `health`, the session reports and both protocol hosts do, so
    /// nothing here moves the scope into an unrelated directory. Seeding writes the
    /// catalog record only: no anchor, no control record and no host namespace.
    pub(crate) async fn seed_workspace_record(&self) {
        host_fixture::seed_local_workspace(
            self.paths.as_ref(),
            WORKSPACE_ID,
            self.environment.workspace(),
        )
        .await
        .expect("seed the workspace record for the CLI working directory");
        assert!(
            !self.paths.workspace_intelligence_dir().exists(),
            "seeding a workspace record must not create the host namespace"
        );
    }

    /// Enables the seeded scope in the fixture's one control generation.
    async fn enable_seeded_scope(&self) {
        let seeded = host_fixture::enable_workspace(self.paths.as_ref(), WORKSPACE_ID)
            .await
            .expect("enable the seeded workspace");
        assert_eq!(seeded.workspace_id(), WORKSPACE_ID);
        assert_eq!(
            seeded.generation(),
            1,
            "the fixture enables the seeded scope in one control generation"
        );
    }

    /// The CLI working directory, which is the ON scope of every scenario here.
    fn cwd(&self) -> String {
        self.environment
            .workspace()
            .to_string_lossy()
            .into_owned()
    }

    /// Runs one shipped command to completion inside this root.
    pub(crate) fn run(&self, args: &[&str]) -> Output {
        let mut command = self.environment.std_command();
        command.args(args);
        command.env("OPENBITFUN_MODELS_DEV_PATH", REPOSITORY_MODEL_CATALOG);
        command_output_with_timeout(&mut command, COMMAND_TIMEOUT)
    }

    /// The `.lock` files inside the host's own lease root.
    fn lease_files(&self) -> Vec<PathBuf> {
        let root = self.paths.workspace_intelligence_lease_dir();
        let Ok(entries) = std::fs::read_dir(&root) else {
            return Vec::new();
        };
        let mut locks: Vec<PathBuf> = entries
            .map(|entry| entry.expect("read a lease directory entry").path())
            .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("lock"))
            .collect();
        locks.sort();
        locks
    }

    /// The one lease file the enabled scope owns, after asserting there is exactly one.
    pub(crate) fn single_lease_file(&self, label: &str) -> PathBuf {
        let mut locks = self.lease_files();
        assert_eq!(
            locks.len(),
            1,
            "{label}: one enabled scope takes exactly one lease file: {locks:?}"
        );
        locks.remove(0)
    }
}

/// A host this test process bootstrapped on the isolated root, kept alive on purpose.
///
/// The live owner is what makes the warm run meaningful: while it is alive it holds the
/// scope's lease and its incarnation token is stored, so a treated command that really
/// tried to admit a host would either be refused by the lease or rewrite the tree. The
/// handle is dropped through [`LiveOwner::stop`] on every normal path, and `Drop` starts
/// a best-effort drain on a failing path, so no owner outlives its test without
/// attempting the same shutdown.
pub(crate) struct LiveOwner {
    host: Option<WorkspaceIntelligenceHost>,
}

impl LiveOwner {
    /// Bootstraps the host this process owns the enabled scope with.
    pub(crate) async fn bootstrap(paths: &Arc<PathManager>, label: &str) -> Self {
        Self::bootstrap_for_scope(paths, WORKSPACE_ID, label).await
    }

    /// Bootstraps the host for one enabled scope id.
    ///
    /// The scope id must be the record the production catalog lookup resolves for the
    /// scope root. The scenarios in `host_skip_lifecycle_cli.rs` use one fixed record
    /// because they own the directory they seed; a scenario whose scope root is composed by
    /// the command itself has to pass the id production derives for that root, or it would
    /// be proving a scope no real run names.
    pub(crate) async fn bootstrap_for_scope(
        paths: &Arc<PathManager>,
        scope_id: &str,
        label: &str,
    ) -> Self {
        let host = WorkspaceIntelligenceHost::bootstrap(
            Arc::clone(paths),
            None,
            WorkspaceIntelligenceHostSurface::CliInteractive,
            RuntimeDeployment::Embedded,
        )
        .await;
        let status = host.status().await;
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Active,
            "{label}: the real host must own the enabled scope: {status:?}"
        );
        assert_eq!(
            status.scope_state(scope_id),
            Some(WorkspaceIntelligenceHostScopeState::Active),
            "{label}: the enabled workspace must be the scope this process owns"
        );
        assert_eq!(
            status.counts().active(),
            1,
            "{label}: exactly the seeded scope is owned"
        );
        Self { host: Some(host) }
    }

    pub(crate) fn handle(&self) -> &WorkspaceIntelligenceHost {
        self.host
            .as_ref()
            .expect("a live owner handle is present while the owner is alive")
    }

    /// Drains the owner explicitly and asserts the drain it reported.
    pub(crate) async fn stop(&mut self, label: &str) {
        let host = self
            .host
            .take()
            .expect("a live owner is stopped exactly once");
        let shutdown = host.shutdown().await;
        assert_eq!(
            shutdown.drain(),
            WorkspaceIntelligenceHostDrain::Drained,
            "{label}: the owner must drain with no outstanding work"
        );
        assert_eq!(
            shutdown.state(),
            WorkspaceIntelligenceHostState::Stopped,
            "{label}: a drained owner is stopped"
        );
    }
}

impl Drop for LiveOwner {
    fn drop(&mut self) {
        // A failing assertion or a panic can reach this without an explicit stop. Nothing can be
        // awaited from a synchronous drop, so this only queues the same shutdown on the runtime
        // and does not check its result: it is best effort, and it cannot promise that the owner
        // drained or released its lease before the test runtime goes away. The owned paths above
        // do the checked shutdown.
        let Some(host) = self.host.take() else {
            return;
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = host.shutdown().await;
            });
        }
    }
}

/// One entry of the host's own namespace.
///
/// A directory is an entry without bytes, so a new empty member root counts as a
/// change; a file carries its exact bytes, which is the strongest statement a refusal
/// can make about the anchor document, the control record with its generation, the
/// cognition partition with the incarnation token and every lease file the owner wrote.
/// What a snapshot sees is what is durable on disk, so a transient claim that leaves a
/// file's bytes and length unchanged is not part of this comparison; the live-owner lease is
/// covered by its own assertion instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TreeEntry {
    relative: String,
    content: TreeContent,
}

/// What the snapshot could observe about one entry of the host namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TreeContent {
    /// A directory: an entry without bytes, so a new empty member root is a change.
    Directory,
    /// A file read in full: every byte is in the comparison.
    Bytes(Vec<u8>),
    /// A file the OS refused to read because its live holder keeps a byte-range lock on it.
    ///
    /// Only the lease root qualifies, because that is the one place an owner is measured to
    /// hold such a lock: Windows answers `fs::read` of the live owner's own lease file with
    /// `ERROR_LOCK_VIOLATION`, and no share mode gets around a byte-range lock. Those bytes
    /// therefore cannot be read by any process — which is also why no other process can
    /// rewrite them while the holder stays. The entry is still in the comparison by name, kind
    /// and size, and the holder is the same at both snapshots. Every other entry, the anchor
    /// and control documents and the cognition partition included, is read in full, and a
    /// refusal there is a hard failure.
    ///
    /// A lease this lock hides is exactly why the durable comparison alone is not the whole
    /// statement about the lease: `assert_live_owner_intact` and `assert_lease_released` hold
    /// and release the same lease from this process, so a claim taken and dropped during the
    /// treated run cannot pass unseen as "no lessee ever existed".
    LockedWhileOwned { len: u64 },
}

/// Whether a read failed because a holder keeps a byte-range lock on the file.
///
/// `ERROR_LOCK_VIOLATION` (33) is the byte-range lock Windows reports for a locked region;
/// `ERROR_SHARING_VIOLATION` (32) is the same outcome under an exclusive share mode.
fn is_lock_or_share_violation(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(32) | Some(33))
}

/// How long a file outside the owner's locked lease root may stay unreadable.
///
/// Such a file is not held by a drained owner, so a refusal there is another process holding
/// it for a moment. The bytes are retried for this long and a still-refused read is then a
/// hard failure, so a real byte comparison is never silently replaced by a weaker one.
const UNEXPECTED_LOCK_BUDGET: Duration = Duration::from_secs(5);

/// Whether a namespace-relative path is inside the one root a live owner locks.
///
/// Only the lease root qualifies, and that is measured rather than assumed: while an owner is
/// alive its lease file answers `fs::read` with `ERROR_LOCK_VIOLATION`. Every other file,
/// including the cognition partition and the anchor and control documents, is read in full in
/// every snapshot, so those bytes are always compared exactly.
fn is_owner_held_root(relative: &str) -> bool {
    relative == LEASE_ROOT
        || relative.starts_with(&format!("{LEASE_ROOT}{}", std::path::MAIN_SEPARATOR))
}

/// Reads one namespace file in full, or records the owner's own byte-range lock on it.
fn snapshot_file(path: &Path, relative: &str) -> TreeContent {
    let len = std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("stat the host namespace file {path:?}: {error}"))
        .len();
    let owner_held = is_owner_held_root(relative);
    let deadline = Instant::now() + UNEXPECTED_LOCK_BUDGET;
    loop {
        match std::fs::read(path) {
            Ok(bytes) => return TreeContent::Bytes(bytes),
            Err(error) if is_lock_or_share_violation(&error) => {
                if owner_held {
                    return TreeContent::LockedWhileOwned { len };
                }
                assert!(
                    Instant::now() < deadline,
                    "{relative}: nothing may hold this namespace file open while no owner of it \
                     is alive; it stayed unreadable ({} bytes) for {UNEXPECTED_LOCK_BUDGET:?}: \
                     {error}",
                    len
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => panic!("read the host namespace file {path:?}: {error}"),
        }
    }
}

/// Every entry under the host's own namespace, sorted by relative path.
///
/// The namespace must exist and every directory under it must be readable: a snapshot
/// that silently became empty because a root was missing or unreadable would make two
/// states compare equal without observing anything, so both are hard failures here.
pub(crate) fn wi_tree_snapshot(root: &Path) -> Vec<TreeEntry> {
    fn walk(root: &Path, directory: &Path, entries: &mut Vec<TreeEntry>) {
        let dir_entries = std::fs::read_dir(directory).unwrap_or_else(|error| {
            panic!("read the host namespace directory {directory:?}: {error}")
        });
        for entry in dir_entries {
            let entry = entry.expect("read a host namespace entry");
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .expect("a host namespace entry stays under its root")
                .to_string_lossy()
                .into_owned();
            if entry
                .file_type()
                .expect("read a host namespace entry type")
                .is_dir()
            {
                entries.push(TreeEntry {
                    relative,
                    content: TreeContent::Directory,
                });
                walk(root, &path, entries);
            } else {
                let content = snapshot_file(&path, &relative);
                entries.push(TreeEntry { relative, content });
            }
        }
    }

    assert!(
        root.is_dir(),
        "the host namespace {root:?} must exist before it can be snapshotted"
    );
    let mut entries = Vec::new();
    walk(root, root, &mut entries);
    assert!(
        !entries.is_empty(),
        "a snapshotted host namespace {root:?} must hold at least its own member roots"
    );
    entries.sort_by(|left, right| left.relative.cmp(&right.relative));
    entries
}

/// The changed entries as a readable list, so a failure names what moved.
fn describe_tree_change(before: &[TreeEntry], after: &[TreeEntry]) -> String {
    let before: BTreeMap<&str, &TreeContent> = before
        .iter()
        .map(|entry| (entry.relative.as_str(), &entry.content))
        .collect();
    let after: BTreeMap<&str, &TreeContent> = after
        .iter()
        .map(|entry| (entry.relative.as_str(), &entry.content))
        .collect();

    let mut changed = Vec::new();
    for (path, content) in &after {
        match before.get(path) {
            None => changed.push(format!("added {path}")),
            Some(previous) if *previous != *content => changed.push(format!("rewritten {path}")),
            Some(_) => {}
        }
    }
    for path in before.keys() {
        if !after.contains_key(path) {
            changed.push(format!("removed {path}"));
        }
    }
    if changed.is_empty() {
        "no entry differs".to_string()
    } else {
        changed.join(", ")
    }
}

/// Asserts the host namespace under `root` is byte-identical to `before`.
pub(crate) fn assert_tree_unchanged(before: &[TreeEntry], root: &Path, label: &str) {
    let after = wi_tree_snapshot(root);
    assert_eq!(
        describe_tree_change(before, &after),
        "no entry differs",
        "{label}: the command must not create, rewrite or re-stamp one byte of the enabled \
         host namespace under {root:?}"
    );
}

/// Asserts the live owner is quiet, and returns the state the treated run is compared to.
///
/// An already-owned scope is verified read-only by the owner's own contract
/// (`verify_expecting` is rolled-back and mints no token), so a window in which nothing
/// under the namespace changes is the owner's steady state. It is asserted once, with no
/// retry: a change inside the window is a real writer and must fail rather than be slept
/// away, because the same writer would make the treated run's evidence unattributable.
async fn assert_owner_quiescent(root: &OnRoot, label: &str) -> Vec<TreeEntry> {
    let namespace = root.paths.workspace_intelligence_dir();
    let before = wi_tree_snapshot(&namespace);
    tokio::time::sleep(OWNER_QUIESCENCE_WINDOW).await;
    let after = wi_tree_snapshot(&namespace);
    assert_eq!(
        describe_tree_change(&before, &after),
        "no entry differs",
        "{label}: the live owner must be quiescent for {OWNER_QUIESCENCE_WINDOW:?} before the \
         treated run, otherwise a change seen after it is not attributable to the command"
    );
    after
}

/// Every regular file under `root` with its length, sorted.
fn files_under(root: &Path) -> Vec<(PathBuf, usize)> {
    fn walk(dir: &Path, files: &mut Vec<(PathBuf, usize)>) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|error| panic!("read the owner root directory {dir:?}: {error}"));
        for entry in entries {
            let entry = entry.expect("read an owner root entry");
            let path = entry.path();
            if entry
                .file_type()
                .expect("read an owner root entry type")
                .is_dir()
            {
                walk(&path, files);
                continue;
            }
            let len = entry
                .metadata()
                .expect("read an owner root file length")
                .len() as usize;
            files.push((path, len));
        }
    }

    let mut files = Vec::new();
    walk(root, &mut files);
    files.sort();
    files
}

/// Asserts the enabled scope published a real owner's own state, not an empty database.
///
/// The anchor document and the cognition partition are named by what they are, not by
/// how they are stored: the anchor is the one document the owner writes outside its
/// member roots, and the cognition partition only has to be a non-empty file, because
/// the incarnation token lives inside it and is opaque to this test.
pub(crate) fn assert_owner_published_state(tree: &[TreeEntry], root: &OnRoot, label: &str) {
    let cognition = files_under(&root.paths.workspace_intelligence_cognition_dir());
    assert!(
        cognition.iter().any(|(_, length)| *length > 0),
        "{label}: a real ON owner must leave a non-empty cognition partition carrying the \
         incarnation token, not an empty database: {cognition:?}"
    );
    assert!(
        std::fs::read_dir(root.paths.workspace_intelligence_control_dir())
            .expect("read the control root")
            .next()
            .is_some(),
        "{label}: the enabled scope keeps its control record"
    );
    let anchor_documents: Vec<&str> = tree
        .iter()
        .filter(|entry| !matches!(entry.content, TreeContent::Directory))
        .map(|entry| entry.relative.as_str())
        .filter(|relative| {
            !relative.starts_with("control")
                && !relative.starts_with("cognition")
                && !relative.starts_with("lease")
        })
        .collect();
    assert!(
        !anchor_documents.is_empty(),
        "{label}: the owner must publish its storage anchor document inside its namespace: {:?}",
        tree.iter().map(|entry| &entry.relative).collect::<Vec<_>>()
    );
}

/// Whether `text` names `path`, tolerating the platform's own path casing.
///
/// The CLI prints the directory `current_dir` reported, and Windows can resolve the same
/// directory with its own casing, so this compares case-insensitively rather than
/// byte-comparing two renderings the test does not control.
fn names_path(text: &str, path: &str) -> bool {
    text.to_lowercase().contains(&path.to_lowercase())
}

/// Lines of `text` that carry `needle`.
fn lines_with<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines().filter(|line| line.contains(needle)).collect()
}

/// The lines a command printed itself, with the `--verbose` tracing records removed.
///
/// A `tracing` record always starts with its own RFC 3339 timestamp, so the command's own
/// `println!`/`eprintln!` lines are exactly the ones that do not. This is used only where a
/// command's plain diagnostics are the subject; the tracing channel is never mined for them.
/// The shape test is structural rather than a substring search, so a record cannot pass as a
/// diagnostic by merely containing a date somewhere.
pub(crate) fn plain_diagnostics(stderr: &str) -> Vec<&str> {
    stderr
        .lines()
        .filter(|line| !is_tracing_record(line))
        .filter(|line| !line.trim().is_empty())
        .collect()
}

/// Whether `line` is one `tracing` record, recognized by its leading timestamp.
fn is_tracing_record(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[8..10].iter().all(u8::is_ascii_digit)
}

/// Every value `text` records for the structured field `field` (`"host_drain="`).
///
/// The tracing formatter renders a `&str` field with `Debug`, so the record carries
/// `host_drain="not_installed"`. The value is compared after one matching surrounding
/// quote pair is removed, which keeps the comparison exact in both directions: no code
/// is accepted because it is a substring of a longer one, and the assertion never depends
/// on whether the field was recorded as a quoted or a bare value.
fn field_values<'a>(text: &'a str, field: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    for line in lines_with(text, field) {
        let mut rest = line.splitn(2, field).nth(1).unwrap_or_default().trim_start();
        if let Some(unquoted) = rest.strip_prefix('"') {
            rest = unquoted;
        }
        let rest = match rest.find('"') {
            Some(end) => &rest[..end],
            None => rest,
        };
        values.push(rest.trim_end_matches([',', ' ']));
    }
    values
}

/// Asserts the invocation reached its own skip site and admitted nothing.
///
/// One placement line naming exactly this site's code is the whole evidence: the
/// placement code writes it from `refuse()` before any root, catalog, deployment or slot
/// is read, so a command that failed while parsing arguments or while starting up cannot
/// produce it, and a command that admitted a host would report `install`.
pub(crate) fn assert_skip_site(stderr: &str, skip_code: &str, label: &str) {
    let placements = field_values(stderr, PLACEMENT_FIELD);
    assert_eq!(
        placements.len(),
        1,
        "{label}: the command must report exactly one placement decision: {stderr}"
    );
    // An exact comparison of the reported code, not a substring search: a command that
    // admitted its host would report `install` here and fail, and no code can pass by
    // being contained in a longer one.
    assert_eq!(
        placements[0], skip_code,
        "{label}: the site must report its own skip code exactly: {stderr}"
    );
}

/// How a site's own command body leaves the process, which decides the drain it can report.
///
/// `main` awaits [`workspace_intelligence::drain`] after `run_cli` returns, so a command
/// whose body returns always reports the drain of the slot it left empty. A body that
/// calls `std::process::exit` itself never reaches that drain, and a test that expected
/// one there would be asserting a line the shipped command cannot print. The variants
/// name the real exit shape of each site instead of forcing one outcome on all of them.
///
/// Every assertion taken from these variants needs a `--verbose` run: `host_drain=` is an
/// `INFO` record, so an `ERROR`-level run cannot show one. ACP is not described here: this
/// file cancels that session itself, and claims no drain for it.
#[derive(Debug, Clone, Copy)]
enum DrainPath {
    /// The body returns to `main` on every outcome (`usage`, `health` and the session
    /// reports): exactly one `not_installed` drain, and never a `drained` one.
    ReturnsThroughCli,
    /// The body returns only when its own checks pass; `doctor` calls
    /// `std::process::exit(1)` when they fail, and that path bypasses the drain.
    ReturnsWhenTheChecksPass,
    /// The body always leaves through `std::process::exit` (`server`): no drain line at
    /// all, on either outcome.
    ExitsInTheBody,
}

impl DrainPath {
    /// Asserts this one invocation reported exactly the drain its own exit path allows.
    fn assert_reported(self, succeeded: bool, stderr: &str, label: &str) {
        match self {
            Self::ReturnsThroughCli => assert_drained_empty_slot(stderr, label),
            Self::ReturnsWhenTheChecksPass => {
                if succeeded {
                    assert_drained_empty_slot(stderr, label);
                } else {
                    assert_no_drain(stderr, label);
                }
            }
            Self::ExitsInTheBody => assert_no_drain(stderr, label),
        }
    }
}

/// Asserts the invocation drained the host slot through the process exit path.
///
/// The bounded drain is awaited on every `run_cli` return path, so a command that
/// returns normally reports one `not_installed` drain: it admitted nothing, so there was
/// nothing to stop.
pub(crate) fn assert_drained_empty_slot(stderr: &str, label: &str) {
    let drains = field_values(stderr, DRAIN_FIELD);
    assert_eq!(
        drains.len(),
        1,
        "{label}: a command that returns through the CLI must drain the empty host slot: {stderr}"
    );
    assert_eq!(
        drains[0], NOT_INSTALLED_CODE,
        "{label}: a skip command admits nothing, so the drain finds no host: {stderr}"
    );
}

/// Asserts the invocation never reported a drain at all.
///
/// A body that exits inside itself bypasses the CLI's bounded drain, so the only drain
/// fact available is its absence. Asserting the absence of every drain field keeps the
/// stronger claim honest: the command neither stopped a host nor answered for an empty
/// slot, because it never reached the shutdown path.
///
/// This is only meaningful on a `--verbose` run: `host_drain=` is an `INFO` record, so a run
/// whose level is `ERROR` would look drain-free no matter what it did, and asserting this on
/// such a run would pass without observing anything.
fn assert_no_drain(stderr: &str, label: &str) {
    assert!(
        lines_with(stderr, DRAIN_FIELD).is_empty(),
        "{label}: this body exits inside itself, so it never reports a drain: {stderr}"
    );
}

/// Asserts no drain reported stopping an admitted host before the test cancelled the session.
///
/// This checks only the absence of a `drained` record on the verbose run's `INFO` channel.
/// It does not assert the absence of `not_installed` or prove that the whole shutdown path
/// was never reached; natural EOF exit and its drain remain outside this scenario.
fn assert_no_host_stopped_by_drain(stderr: &str, label: &str) {
    let drains = field_values(stderr, DRAIN_FIELD);
    assert!(
        drains.iter().all(|code| *code != DRAINED_CODE),
        "{label}: a cancelled session must not have drained an admitted host: {stderr}"
    );
}

/// Asserts one one-shot invocation's stdout and exit status keep the baseline contract.
fn assert_same_stdout_and_exit(run: &Output, baseline: &Output, label: &str) {
    assert_eq!(
        run.status.code(),
        baseline.status.code(),
        "{label}: enabling the scope must not change the exit status; stderr: {}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        run.stdout, baseline.stdout,
        "{label}: enabling the scope must not add one stdout byte; baseline: {}\nstderr: {}",
        String::from_utf8_lossy(&baseline.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

/// Asserts a drained owner released the scope lease while this process stayed alive.
///
/// The process that took the lease is still running here, so an acquirable lease proves
/// the owner's own drain released it rather than the OS releasing it at process exit.
pub(crate) fn assert_lease_released(lease: &Path, label: &str) {
    let released = ExclusiveFileLease::try_acquire(lease).unwrap_or_else(|error| {
        panic!("{label}: the explicit drain must release the scope lease, not the process exit: {error:?}")
    });
    drop(released);
}

/// Enables the seeded scope and lets one real owner publish the state it leaves behind.
///
/// Returns the scope's lease file and the snapshot taken after that owner drained. The
/// snapshot is the pre-command state every treated run is compared against, and the
/// assertions inside prove it is a real owner's state rather than an empty database: the
/// incarnation token is stored in the cognition partition and the lease exists.
async fn publish_owner_state(root: &OnRoot, label: &str) -> (PathBuf, Vec<TreeEntry>) {
    let namespace = root.paths.workspace_intelligence_dir();
    root.enable_seeded_scope().await;
    let after_enable = wi_tree_snapshot(&namespace);

    let mut publisher = LiveOwner::bootstrap(&root.paths, &format!("{label}/publisher")).await;
    publisher.stop(&format!("{label}/publisher")).await;
    drop(publisher);

    let lease = root.single_lease_file(label);
    assert_lease_released(&lease, &format!("{label}/publisher"));
    let after_owner = wi_tree_snapshot(&namespace);
    assert_ne!(
        after_owner, after_enable,
        "{label}: the real owner must publish its own state on top of the enable"
    );
    assert_owner_published_state(&after_owner, root, label);
    (lease, after_owner)
}

/// Takes the scope with a live owner and returns it with the quiet state to compare to.
///
/// While this owner is alive the scope's lease is held and its incarnation token is
/// stored, so the warm run is measured against a workspace another live process really
/// owns rather than against a database the test only believes is populated.
pub(crate) async fn start_live_owner(root: &OnRoot, lease: &Path, label: &str) -> (LiveOwner, Vec<TreeEntry>) {
    start_live_owner_for_scope(root, lease, WORKSPACE_ID, label).await
}

/// [`start_live_owner`] for a scope whose record id the test does not choose itself.
pub(crate) async fn start_live_owner_for_scope(
    root: &OnRoot,
    lease: &Path,
    scope_id: &str,
    label: &str,
) -> (LiveOwner, Vec<TreeEntry>) {
    let owner = LiveOwner::bootstrap_for_scope(&root.paths, scope_id, label).await;
    assert!(
        ExclusiveFileLease::try_acquire(lease).is_err(),
        "{label}: the live owner must hold the scope lease while it runs"
    );
    let steady = assert_owner_quiescent(root, label).await;
    (owner, steady)
}

/// Asserts the treated command left the live owner owning exactly the one scope.
pub(crate) async fn assert_live_owner_intact(owner: &LiveOwner, lease: &Path, label: &str) {
    let status = owner.handle().status().await;
    assert_eq!(
        status.state(),
        WorkspaceIntelligenceHostState::Active,
        "{label}: the treated command must leave the live owner active"
    );
    assert_eq!(
        status.counts().active(),
        1,
        "{label}: the treated command must not take or drop the scope"
    );
    assert!(
        ExclusiveFileLease::try_acquire(lease).is_err(),
        "{label}: the treated command must not touch the lease the owner holds"
    );
}

/// Drains the warm owner explicitly and asserts its lease really came back.
pub(crate) async fn stop_live_owner(mut owner: LiveOwner, lease: &Path, label: &str) {
    owner.stop(label).await;
    drop(owner);
    assert_lease_released(lease, label);
}

/// Proves the scope is still takeable after the last snapshot.
///
/// This bootstrap advances the incarnation token like any other owner start, so it is
/// deliberately kept out of the skip-command snapshots above. It is the evidence that the
/// earlier owners released their leases explicitly instead of leaving them to process
/// exit.
pub(crate) async fn assert_scope_takeable(root: &OnRoot, label: &str) {
    assert_scope_takeable_for_scope(root, WORKSPACE_ID, label).await
}

/// [`assert_scope_takeable`] for a scope whose record id the test does not choose itself.
pub(crate) async fn assert_scope_takeable_for_scope(root: &OnRoot, scope_id: &str, label: &str) {
    let mut takeover = LiveOwner::bootstrap_for_scope(&root.paths, scope_id, label).await;
    takeover.stop(label).await;
    drop(takeover);
}

/// What one management site's three invocations produced on one isolated root.
struct SiteRuns {
    cwd: String,
    baseline: Output,
    cold: Output,
    warm: Output,
}

impl SiteRuns {
    /// Asserts the treated runs kept the baseline's stdout bytes and exit status exactly.
    ///
    /// A management command owns no workspace, so enabling the scope must not change one
    /// stdout byte or the status it reports. Those are the command's product and are
    /// deterministic in this isolated root: the commands print paths from the root they
    /// were given and counts from a catalog this test seeded. stderr is not compared
    /// across runs: with `--verbose` it is the tracing stream, whose lines carry their own
    /// timestamps and the run's own trace volume, so each run's placement, drain and body
    /// assertions are the evidence taken from that channel instead.
    fn assert_management_contract(&self, label: &str) {
        for (run, phase) in [(&self.cold, "cold"), (&self.warm, "warm")] {
            assert_same_stdout_and_exit(run, &self.baseline, &format!("{label}/{phase}"));
        }
    }
}

/// Runs one management site through the whole ON scenario on one isolated root.
async fn exercise_management_site(
    args: &[&str],
    skip_code: &str,
    drain: DrainPath,
    label: &str,
) -> SiteRuns {
    let root = OnRoot::new();
    root.seed_workspace_record().await;

    // OFF baseline: the same binary, the same arguments and the same working directory,
    // before the scope is enabled. The placement is decided statically, so the site is
    // reached here too and must report the same skip code without any host state.
    let baseline = root.run(args);
    assert_skip_site(
        &String::from_utf8_lossy(&baseline.stderr),
        skip_code,
        &format!("{label}/baseline"),
    );
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "{label}: an invocation with no enabled scope must not create the host namespace; \
         stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    // ON: the fixture enables the seeded scope and a real host publishes the state a real
    // owner leaves behind, including the incarnation token in its partition.
    let (lease, after_owner) = publish_owner_state(&root, label).await;

    // Cold run: the owner is gone, the tree is the owner's own state, and a skip must not
    // change it.
    let cold = root.run(args);
    assert_skip_site(
        &String::from_utf8_lossy(&cold.stderr),
        skip_code,
        &format!("{label}/cold"),
    );
    drain.assert_reported(
        cold.status.success(),
        &String::from_utf8_lossy(&cold.stderr),
        &format!("{label}/cold"),
    );
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        &format!("{label}/cold"),
    );

    // Warm run: this process really owns the scope while the command runs, so the lease is
    // held and the token is stored rather than inferred.
    let (owner, steady) = start_live_owner(&root, &lease, &format!("{label}/warm")).await;
    let warm = root.run(args);
    assert_skip_site(
        &String::from_utf8_lossy(&warm.stderr),
        skip_code,
        &format!("{label}/warm"),
    );
    drain.assert_reported(
        warm.status.success(),
        &String::from_utf8_lossy(&warm.stderr),
        &format!("{label}/warm"),
    );
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        &format!("{label}/warm"),
    );
    assert_live_owner_intact(&owner, &lease, &format!("{label}/warm")).await;
    stop_live_owner(owner, &lease, &format!("{label}/warm")).await;
    assert_scope_takeable(&root, &format!("{label}/takeover")).await;

    SiteRuns {
        cwd: root.cwd(),
        baseline,
        cold,
        warm,
    }
}

/// One stdio protocol child with an absolute deadline and a continuously drained stderr.
///
/// The child is spawned through `process_manager`, killed and reaped on any timeout or
/// failure path, and `kill_on_drop` backs that up if an assertion unwinds first. stderr is
/// read for the whole session by a task that appends to a shared buffer, so the child can
/// never block on a full stderr pipe while it serves its protocol on stdout, and a failing
/// assertion can still report what the child logged.
struct StdioSession {
    label: &'static str,
    child: Option<tokio::process::Child>,
    stdin: Option<tokio::process::ChildStdin>,
    stdout: Option<BufReader<tokio::process::ChildStdout>>,
    stderr_reader: Option<tokio::task::JoinHandle<()>>,
    stderr_text: Arc<Mutex<String>>,
    deadline: Instant,
    stdout_lines: Vec<String>,
}

impl StdioSession {
    /// Starts one protocol command in `environment`'s own root.
    fn spawn(environment: &CliTestEnvironment, args: &[&str], label: &'static str) -> Self {
        let mut command = openbitfun_services_core::process_manager::create_tokio_command(env!(
            "CARGO_BIN_EXE_openbitfun"
        ));
        command
            .args(args)
            .env("OPENBITFUN_MODELS_DEV_PATH", REPOSITORY_MODEL_CATALOG)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        environment.apply_tokio_environment(&mut command);

        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{label}: start the CLI child: {error}"));
        let stdin = child.stdin.take().expect("the child stdin pipe");
        let stdout = BufReader::new(child.stdout.take().expect("the child stdout pipe"));
        let stderr = child.stderr.take().expect("the child stderr pipe");
        let stderr_text = Arc::new(Mutex::new(String::new()));
        let captured = Arc::clone(&stderr_text);
        let stderr_reader = tokio::spawn(async move {
            let mut stderr = BufReader::new(stderr);
            loop {
                let mut line = String::new();
                match stderr.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => captured
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push_str(&line),
                }
            }
        });

        Self {
            label,
            child: Some(child),
            stdin: Some(stdin),
            stdout: Some(stdout),
            stderr_reader: Some(stderr_reader),
            stderr_text,
            deadline: Instant::now() + STDIO_DEADLINE,
            stdout_lines: Vec::new(),
        }
    }

    /// Everything the child has logged so far.
    fn stderr_so_far(&self) -> String {
        self.stderr_text
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// The budget left for `step`.
    fn budget(&self, step: &str) -> Duration {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "{}: {step} exceeded the absolute deadline {STDIO_DEADLINE:?}; stdout lines: {:?}; \
             stderr: {}",
            self.label,
            self.stdout_lines,
            self.stderr_so_far()
        );
        remaining
    }

    /// Stops the child on a failing path, makes one bounded reap attempt, and reports both.
    ///
    /// This path is already failing, so the cleanup is reported in the panic message instead of
    /// asserted: the message states exactly how far the bounded attempt got and never claims a
    /// guaranteed reap.
    fn fail(&mut self, reason: &str) -> ! {
        let mut cleanup = Vec::new();
        if let Some(child) = self.child.as_mut() {
            match child.start_kill() {
                Ok(()) => cleanup.push("kill signal sent".to_owned()),
                Err(error) => cleanup.push(format!("kill failed: {error}")),
            }
        }
        if let Some(mut child) = self.child.take() {
            // Bounded: the process was just killed, and this path ends in a panic anyway.
            let deadline = Instant::now() + Duration::from_secs(10);
            cleanup.push(loop {
                match child.try_wait() {
                    Ok(Some(status)) => break format!("child exited with {status}"),
                    Err(error) => break format!("reap failed: {error}"),
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Ok(None) => break "child still running after the bounded reap attempt".to_owned(),
                }
            });
        }
        panic!(
            "{}: {reason}\ncleanup: {}\nstdout lines:\n{}\nstderr:\n{}",
            self.label,
            cleanup.join("; "),
            self.stdout_lines.join("\n"),
            self.stderr_so_far()
        )
    }

    /// Sends one JSON-RPC request and returns the response with the same id.
    async fn request(&mut self, request: Value, id: i64, step: &str) -> Value {
        let mut line = serde_json::to_vec(&request).expect("serialize a protocol request");
        line.push(b'\n');
        let budget = self.budget(step);
        let mut stdin = self.stdin.take().expect("the child stdin stays open");
        let written = tokio::time::timeout(budget, async {
            stdin.write_all(&line).await?;
            stdin.flush().await
        })
        .await;
        self.stdin = Some(stdin);
        match written {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("{}: write the {step} request: {error}", self.label),
            Err(_) => self.fail(&format!("writing the {step} request timed out")),
        }

        loop {
            let budget = self.budget(step);
            let mut stdout = self.stdout.take().expect("the child stdout stays open");
            let mut response = String::new();
            let read = tokio::time::timeout(budget, stdout.read_line(&mut response)).await;
            self.stdout = Some(stdout);
            match read {
                Ok(Ok(0)) => self.fail(&format!("stdout closed while waiting for {step}")),
                Ok(Ok(_)) => {}
                Ok(Err(error)) => panic!("{}: read the {step} response: {error}", self.label),
                Err(_) => self.fail(&format!("reading the {step} response timed out")),
            }

            let response = response.trim_end().to_owned();
            self.stdout_lines.push(response.clone());
            let message: Value = serde_json::from_str(&response).unwrap_or_else(|error| {
                panic!(
                    "{}: protocol stdout must be one JSON object per line: {error}: {response}",
                    self.label
                )
            });
            if message.get("id").and_then(Value::as_i64) == Some(id) {
                return message;
            }
            assert!(
                message.get("method").is_some(),
                "{}: unexpected protocol message while waiting for {step}: {message}",
                self.label
            );
        }
    }

    /// Ends this session in `mode` and returns the status that end produced.
    ///
    /// stdout is drained by a task for the whole wait, so a child with output still to write
    /// can never be held back by a full pipe and a timeout means the child really did not end.
    /// Every line that task reads is kept and validated as one JSON object afterwards:
    /// draining the pipe narrows nothing that is compared. A timed-out end is a failure, never
    /// a pass: the child is killed, its reap is checked, and the assertion fails.
    async fn await_end(&mut self, step: &str, mode: EndMode) -> ExitStatus {
        let residual = Arc::new(Mutex::new(Vec::<String>::new()));
        let stdout_reader = self.stdout.take().map(|mut stdout| {
            let collected = Arc::clone(&residual);
            tokio::spawn(async move {
                loop {
                    let mut line = String::new();
                    match stdout.read_line(&mut line).await {
                        Ok(0) => return None,
                        Ok(_) => collected
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .push(line),
                        Err(error) => return Some(error),
                    }
                }
            })
        });

        let mut child = self.child.take().expect("the child handle stays present");
        let budget = self.budget(step);
        let status = match mode {
            EndMode::NaturalExit => {
                drop(self.stdin.take());
                match tokio::time::timeout(budget, child.wait()).await {
                    Ok(Ok(status)) => status,
                    Ok(Err(error)) => panic!("{}: wait for the CLI child: {error}", self.label),
                    Err(_) => {
                        self.kill_and_report(&mut child, step).await;
                        panic!(
                            "{}: the CLI child did not exit within {budget:?} after {step}; a \
                             timeout is a failure, not a pass{}",
                            self.label,
                            self.tail_for_failure()
                        )
                    }
                }
            }
            EndMode::CancelNow => {
                // The command is alive and serving with its stdin still open; that state is
                // what makes this a cancellation by the test rather than an observed exit.
                assert!(
                    self.stdin.is_some(),
                    "{}: the session keeps its stdin open until it is cancelled",
                    self.label
                );
                match child.try_wait() {
                    Ok(None) => {}
                    Ok(Some(status)) => panic!(
                        "{}: the command left on its own ({status}) before the test cancelled it \
                         after {step}; this file only observes a session it stops itself{}",
                        self.label,
                        self.tail_for_failure()
                    ),
                    Err(error) => panic!(
                        "{}: ask whether the CLI child still serves after {step}: {error}",
                        self.label
                    ),
                }
                if let Err(error) = child.start_kill() {
                    panic!(
                        "{}: cancel the CLI child after {step}: {error}{}",
                        self.label,
                        self.tail_for_failure()
                    );
                }
                match tokio::time::timeout(budget, child.wait()).await {
                    Ok(Ok(status)) => status,
                    Ok(Err(error)) => panic!(
                        "{}: wait for the cancelled CLI child after {step}: {error}{}",
                        self.label,
                        self.tail_for_failure()
                    ),
                    Err(_) => {
                        self.kill_and_report(&mut child, step).await;
                        panic!(
                            "{}: the cancelled CLI child did not exit within {budget:?} after \
                             {step}; a timeout is a failure, not a pass{}",
                            self.label,
                            self.tail_for_failure()
                        )
                    }
                }
            }
        };

        if let Some(reader) = stdout_reader {
            let budget = self.budget(step);
            match tokio::time::timeout(budget, reader).await {
                Ok(Ok(None)) => {}
                Ok(Ok(Some(error))) => panic!(
                    "{}: read the residual stdout after {step}: {error}",
                    self.label
                ),
                Ok(Err(error)) => panic!("{}: join the stdout reader: {error}", self.label),
                Err(_) => panic!(
                    "{}: the stdout reader did not finish within {budget:?} after the child \
                     ended",
                    self.label
                ),
            }
        }
        // The protocol owns stdout, so nothing may follow the last response there. Any
        // remaining line must still be one JSON object: an unparsable line is a failure, not
        // the end of the output.
        let residual = std::mem::take(
            &mut *residual
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for line in residual {
            let line = line.trim_end().to_owned();
            assert!(
                serde_json::from_str::<Value>(&line).is_ok(),
                "{}: every stdout line must be one JSON object: {line}",
                self.label
            );
            self.stdout_lines.push(line);
        }

        if let Some(reader) = self.stderr_reader.take() {
            let budget = self.budget(step);
            match tokio::time::timeout(budget, reader).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => panic!("{}: join the stderr reader: {error}", self.label),
                Err(_) => panic!(
                    "{}: the stderr reader did not finish within {budget:?} after the child \
                     ended",
                    self.label
                ),
            }
        }
        status
    }

    /// Kills `child` and reports, rather than assumes, how the reap went on a failing path.
    ///
    /// This runs only where an assertion is already failing, so it cannot turn a failure into
    /// a pass; it exists so a killed child is not left behind and so a reap that did not
    /// happen is visible in the message instead of being dropped.
    async fn kill_and_report(&self, child: &mut tokio::process::Child, step: &str) {
        if let Err(error) = child.start_kill() {
            panic!("{}: kill the CLI child after {step}: {error}", self.label);
        }
        match tokio::time::timeout(Duration::from_secs(10), child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => panic!(
                "{}: the killed CLI child could not be reaped after {step}: {error}",
                self.label
            ),
            Err(_) => panic!(
                "{}: the killed CLI child still had not exited 10s after {step}",
                self.label
            ),
        }
    }

    /// The stdout/stderr collected so far, rendered for a failure message.
    fn tail_for_failure(&self) -> String {
        format!(
            "\nstdout lines:\n{}\nstderr:\n{}",
            self.stdout_lines.join("\n"),
            self.stderr_so_far()
        )
    }

    /// Closes stdin and requires the command to leave on its own inside the deadline.
    async fn finish(mut self, step: &str) -> (ExitStatus, String) {
        let status = self.await_end(step, EndMode::NaturalExit).await;
        (status, self.stderr_so_far())
    }

    /// Stops a session the test itself ends, and reports that ending explicitly.
    ///
    /// ACP is a long-lived server, so this slice observes its answer and then cancels it
    /// while it is still serving; the returned [`SessionEnd`] says so instead of presenting a
    /// cancellation as a natural exit.
    async fn cancel_after_observation(mut self, step: &str) -> (SessionEnd, String) {
        let status = self.await_end(step, EndMode::CancelNow).await;
        (SessionEnd::CancelledByTest { status }, self.stderr_so_far())
    }
}

impl Drop for StdioSession {
    fn drop(&mut self) {
        // A failed assertion unwinds before `finish` or `cancel_after_observation`, so this
        // asks the child to stop and hands the wait to the runtime; `kill_on_drop` also
        // terminates it when the handle goes. Nothing can be awaited from a synchronous drop,
        // so this is a best-effort stop: it cannot promise that the child was reaped. The
        // owned paths above do the bounded, checked kill and wait.
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.start_kill();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                let _ = child.wait().await;
            });
        }
    }
}

/// The protocol payload two runs are compared on.
///
/// It is the response result verbatim. Both protocol hosts this file drives answer
/// deterministically (fixed identities, fixed limits, fixed capability lists), so no field is
/// removed to make two runs equal: a payload that started carrying a random value would fail
/// here instead of being silently ignored. The exit status is compared separately, and only
/// where the command really reports its own exit; a cancelled session contributes none.
fn protocol_result(response: &Value) -> Value {
    response
        .get("result")
        .cloned()
        .unwrap_or_else(|| panic!("the response must carry a result: {response}"))
}

/// How a stdio session is ended by this file.
#[derive(Debug, Clone, Copy)]
enum EndMode {
    /// The client closes stdin and the shipped command must leave by itself.
    NaturalExit,
    /// The test stops the command while it is still alive with stdin open.
    CancelNow,
}

/// How a long-lived protocol session ended.
///
/// There is one variant on purpose: this file cancels ACP itself, so no other ending is
/// observed, and a session that ends some other way fails inside `await_end`.
#[derive(Debug)]
enum SessionEnd {
    /// The test stopped the live command with stdin open, after the answer was observed.
    ///
    /// `status` is the status of that cancellation. It is not a product exit code, it is never
    /// compared with one, and no drain of the command is claimed from it.
    CancelledByTest { status: ExitStatus },
}

impl SessionEnd {
    /// Asserts the cancellation really took effect, and that no host was drained before it.
    ///
    /// A killed session must not report a clean exit: a success status here would mean the
    /// command left on its own and the observation window was not the one this slice claims.
    fn assert_cancelled_by_test(self, stderr: &str, label: &str) {
        let Self::CancelledByTest { status } = self;
        assert!(
            !status.success(),
            "{label}: a session the test cancelled does not report a clean exit: {status}"
        );
        assert_no_host_stopped_by_drain(stderr, label);
    }
}

/// Runs one app-server exchange without the `--verbose` channel: `app/initialize` then
/// `app/health`, then stdin EOF.
///
/// On an isolated root with the repository's model catalog selected, the recorded `--verbose`
/// `app/health` probe received no response within 30 s. Its trace records the request, dispatch
/// and a model-catalog-updated event, but no response or `models.dev` line. The cause is not
/// isolated by this slice, so this is a measurement rather than a product defect diagnosis.
/// The site is therefore proven
/// by its own `--verbose` run ([`assert_stdio_placement_site`]) and the protocol by this plain
/// run, both of the same shipped command in the same phase on the same isolated root. This run
/// prints nothing at `INFO`, so no drain observation is taken from its stderr at all.
async fn exchange_app_server(
    environment: &CliTestEnvironment,
    initialize: &Value,
    health: &Value,
    label: &'static str,
) -> (Value, Value, ExitStatus, String) {
    let mut server = StdioSession::spawn(environment, &["server"], label);
    let initialized = server.request(initialize.clone(), 1, "app/initialize").await;
    let health = server.request(health.clone(), 2, "app/health").await;
    let (status, stderr) = server.finish("stdin EOF").await;
    (initialized, health, status, stderr)
}

/// Proves the stdio site is reached by the shipped command's own placement line.
///
/// This is the `--verbose` run of the same command: it opens the trace channel, decides the
/// placement, and closes stdin at once, so the command leaves through its own body without
/// serving a request. Neither a parsed-argument failure nor a startup failure can print a
/// placement line, so this run is the site evidence the protocol run cannot carry. It is also
/// the only run of this site whose stderr carries `INFO`, so the absence of a drain is
/// asserted here and nowhere else.
async fn assert_stdio_placement_site(
    environment: &CliTestEnvironment,
    command: &str,
    skip_code: &str,
    label: &'static str,
) -> ExitStatus {
    let args = ["--verbose", command];
    let session = StdioSession::spawn(environment, &args, label);
    let (status, stderr) = session.finish("stdin EOF").await;
    assert_skip_site(&stderr, skip_code, label);
    DrainPath::ExitsInTheBody.assert_reported(status.success(), &stderr, label);
    status
}

/// Runs one ACP exchange: `initialize` on the `--verbose` channel, then a cancellation by the
/// test.
///
/// The ACP transport answers with this channel open, so one run carries both the placement
/// line and the protocol answer. The shipped transport is a long-lived server: the existing
/// `tests/acp_stdio_cli.rs` shutdown helper (`:123`-`:135`) already has to kill it after a
/// bounded wait rather than rely on a natural exit, and this slice does not attempt to fix or
/// observe that EOF behavior. It therefore does not observe a natural EOF exit for this
/// command, which means its natural exit code and any drain after EOF are unverified here. The
/// session is cancelled while stdin is still open and the server still serves, and
/// [`SessionEnd`] reports that explicitly.
async fn exchange_acp(
    environment: &CliTestEnvironment,
    initialize: &Value,
    label: &'static str,
) -> (Value, SessionEnd, String) {
    let mut acp = StdioSession::spawn(environment, &["--verbose", "acp"], label);
    let initialized = acp.request(initialize.clone(), 1, "initialize").await;
    let (end, stderr) = acp.cancel_after_observation("cancelled by the test").await;
    (initialized, end, stderr)
}

#[tokio::test]
async fn a_real_cli_usage_skip_reports_its_placement_and_leaves_the_enabled_scope_untouched() {
    let runs = exercise_management_site(
        &["--verbose", "usage"],
        MANAGEMENT_SKIP_CODE,
        DrainPath::ReturnsThroughCli,
        "usage",
    )
    .await;
    runs.assert_management_contract("usage");

    // The usage report owns no workspace and this root has no session, so the command's
    // own body fails after the placement with the owner's message. That failure is the
    // site's body, not a startup failure: it is produced after the runtime was assembled
    // and after the placement was decided.
    let stderr = String::from_utf8_lossy(&runs.cold.stderr);
    assert!(
        stderr.contains("No history sessions for current project"),
        "usage must report the owner's own empty-session failure: {stderr}"
    );
    assert!(
        runs.cold.stdout.is_empty(),
        "a usage report with no session prints no report: {}",
        String::from_utf8_lossy(&runs.cold.stdout)
    );
    assert!(
        !runs.cold.status.success(),
        "a usage report with no session reports failure"
    );
}

#[tokio::test]
async fn a_real_cli_doctor_skip_reports_its_placement_and_leaves_the_enabled_scope_untouched() {
    let runs = exercise_management_site(
        &["--verbose", "doctor"],
        MANAGEMENT_SKIP_CODE,
        // `doctor` calls `std::process::exit(1)` when its own checks fail, which skips the
        // CLI's bounded drain; a passing doctor returns through the CLI and drains the
        // empty slot. The drain assertion therefore follows the run's own exit path.
        DrainPath::ReturnsWhenTheChecksPass,
        "doctor",
    )
    .await;
    runs.assert_management_contract("doctor");

    let stdout = String::from_utf8_lossy(&runs.cold.stdout).into_owned();
    assert!(
        stdout.contains("OpenBitFun CLI doctor"),
        "the doctor must print its own title: {stdout}"
    );
    assert!(
        names_path(&stdout, &format!("[ok] Workspace: {}", runs.cwd)),
        "the doctor must inspect the CLI's own working directory: {stdout}"
    );
    assert!(
        stdout.contains("Runtime capability registrations: complete"),
        "the doctor must report the assembled runtime it diagnoses: {stdout}"
    );
    // One of these four lines is the doctor's own verdict; finding none would mean the run
    // stopped before the body it is supposed to have reached.
    assert!(
        stdout.contains("Doctor checks passed.")
            || stdout.contains("Doctor checks completed with plugin warnings.")
            || stdout.contains("Doctor checks completed with an external agent source warning.")
            || stdout.contains("Doctor checks found plugin source errors."),
        "the doctor must print its own verdict: {stdout}"
    );
}

#[tokio::test]
async fn a_real_cli_health_skip_reports_its_placement_and_leaves_the_enabled_scope_untouched() {
    let runs = exercise_management_site(
        &["--verbose", "health"],
        MANAGEMENT_SKIP_CODE,
        DrainPath::ReturnsThroughCli,
        "health",
    )
    .await;
    runs.assert_management_contract("health");

    let stdout = String::from_utf8_lossy(&runs.cold.stdout).into_owned();
    assert!(
        stdout.contains("OpenBitFun CLI health"),
        "the health report must print its own title: {stdout}"
    );
    assert!(
        stdout.contains("Runtime capability registrations: complete"),
        "the health report must state the assembled capability set: {stdout}"
    );
    assert!(
        runs.cold.status.success(),
        "a health report completes: {}",
        String::from_utf8_lossy(&runs.cold.stderr)
    );
}

#[tokio::test]
async fn a_real_cli_session_report_skip_reports_its_placement_and_leaves_the_scope_untouched() {
    let root = OnRoot::new();
    root.seed_workspace_record().await;

    // The one session placement site serves four report actions. Every one of them runs in
    // all three phases, so the site's single decision is proven through each action a user
    // can name, on the same isolated root.
    const ACTIONS: [&[&str]; 4] = [
        &["--verbose", "sessions", "list"],
        &["--verbose", "sessions", "show", MISSING_SESSION_ID],
        &["--verbose", "sessions", "delete", MISSING_SESSION_ID],
        &["--verbose", "sessions", "fork", MISSING_SESSION_ID],
    ];

    let mut baseline = Vec::new();
    for action in ACTIONS {
        let output = root.run(action);
        assert_skip_site(
            &String::from_utf8_lossy(&output.stderr),
            MANAGEMENT_SKIP_CODE,
            "sessions/baseline",
        );
        baseline.push(output);
    }
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "a session report with no enabled scope must not create the host namespace"
    );

    let (lease, after_owner) = publish_owner_state(&root, "sessions").await;

    let mut cold = Vec::new();
    for action in ACTIONS {
        let output = root.run(action);
        assert_skip_site(
            &String::from_utf8_lossy(&output.stderr),
            MANAGEMENT_SKIP_CODE,
            "sessions/cold",
        );
        DrainPath::ReturnsThroughCli.assert_reported(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
            "sessions/cold",
        );
        cold.push(output);
    }
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        "sessions/cold",
    );

    let (owner, steady) = start_live_owner(&root, &lease, "sessions/warm").await;

    let mut warm = Vec::new();
    for action in ACTIONS {
        let output = root.run(action);
        assert_skip_site(
            &String::from_utf8_lossy(&output.stderr),
            MANAGEMENT_SKIP_CODE,
            "sessions/warm",
        );
        DrainPath::ReturnsThroughCli.assert_reported(
            output.status.success(),
            &String::from_utf8_lossy(&output.stderr),
            "sessions/warm",
        );
        warm.push(output);
    }
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        "sessions/warm",
    );
    assert_live_owner_intact(&owner, &lease, "sessions/warm").await;
    stop_live_owner(owner, &lease, "sessions/warm").await;

    // Each action keeps the baseline contract: the same stdout bytes and exit status as the
    // run that had no enabled scope.
    for (index, action) in ACTIONS.iter().enumerate() {
        let label = action[2];
        for (run, phase) in [(&cold[index], "cold"), (&warm[index], "warm")] {
            assert_same_stdout_and_exit(run, &baseline[index], &format!("sessions {label}/{phase}"));
        }
    }

    // The list action reports the owner's real answer for this workspace.
    let list = String::from_utf8_lossy(&cold[0].stdout).into_owned();
    assert!(
        names_path(
            &list,
            &format!("No history sessions for current project: {}", root.cwd())
        ),
        "sessions list must report this workspace's own session state: {list}"
    );
    assert_eq!(
        cold[0].status.code(),
        Some(0),
        "sessions list completes for a workspace with no session"
    );

    // Each id action answers for the id it was given, with the owner's own body text. Those
    // expectations are the shipped answers measured on this isolated root: the report and fork
    // paths fail with the owner's `Not found` message naming the id, and the delete path is
    // idempotent, so it reports the id it removed from this project. The text is taken from the
    // command's own plain output, never from the tracing channel.
    for (index, action) in ACTIONS.iter().enumerate().skip(1) {
        let verb = action[2];
        let stdout = String::from_utf8_lossy(&cold[index].stdout).into_owned();
        let stderr = String::from_utf8_lossy(&cold[index].stderr).into_owned();
        let diagnostics = plain_diagnostics(&stderr);
        let diagnostics = diagnostics.join("\n");
        match verb {
            "delete" => {
                assert_eq!(
                    cold[index].status.code(),
                    Some(0),
                    "sessions delete answers idempotently for an id this project does not have: \
                     {diagnostics}"
                );
                assert_eq!(
                    stdout.trim_end(),
                    format!("Deleted session from current project: {MISSING_SESSION_ID}"),
                    "sessions delete must name the id it removed"
                );
                assert!(
                    diagnostics.is_empty(),
                    "sessions delete must not report a failure for an id it answers: {diagnostics}"
                );
            }
            "show" | "fork" => {
                assert_eq!(
                    cold[index].status.code(),
                    Some(1),
                    "sessions {verb} fails for an id that exists nowhere: {stdout}{diagnostics}"
                );
                assert!(
                    stdout.is_empty(),
                    "sessions {verb} prints no report for an id it cannot resolve: {stdout}"
                );
                assert_eq!(
                    diagnostics.trim_end(),
                    format!(
                        "Error: Not found: Session metadata not found: {MISSING_SESSION_ID}"
                    ),
                    "sessions {verb} must report the owner's own message naming the id"
                );
            }
            other => panic!("unexpected session action in this test: {other}"),
        }
    }

    // After every snapshot the scope must still be takeable, which is only possible if the
    // earlier owner released it explicitly.
    assert_scope_takeable(&root, "sessions/takeover").await;
}

#[tokio::test]
async fn a_real_cli_server_skip_serves_the_protocol_and_leaves_the_enabled_scope_untouched() {
    let root = OnRoot::new();
    // The stdio Host opens its cwd as its workspace scope and reports git facts from it, so
    // the root is a real repository like the shipped surface expects.
    root.environment.initialize_git_repository();
    root.seed_workspace_record().await;

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "app/initialize",
        "params": {
            "protocolVersion": 3,
            "client": { "name": "host-skip-lifecycle-test", "version": "0.0.1" }
        }
    });
    let health = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "app/health",
        "params": {}
    });

    // Baseline: the same stdio Host on the same isolated root before the scope is enabled.
    // The site is skipped statically, so it is reached here too.
    assert_stdio_placement_site(
        &root.environment,
        "server",
        STDIO_SKIP_CODE,
        "server/baseline/placement",
    )
    .await;
    let (baseline_initialize, baseline_health, baseline_status, baseline_stderr) =
        exchange_app_server(&root.environment, &initialize, &health, "server/baseline").await;
    assert!(
        baseline_status.success(),
        "the baseline stdio Host must exit cleanly: {baseline_stderr}"
    );
    assert!(
        baseline_initialize.get("error").is_none(),
        "the baseline stdio Host must answer app/initialize without an error: {baseline_initialize}"
    );
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "a stdio Host with no enabled scope must not create the host namespace"
    );

    let (lease, after_owner) = publish_owner_state(&root, "server").await;

    // Cold: the owner is gone and its own state is on disk, so the placement run and the
    // protocol run are both measured against the state the skip must not touch.
    let cold_placement = assert_stdio_placement_site(
        &root.environment,
        "server",
        STDIO_SKIP_CODE,
        "server/cold/placement",
    )
    .await;
    assert!(
        cold_placement.success(),
        "the cold placement run of the stdio Host exits through its own body cleanly"
    );
    let (cold_initialize, cold_health, cold_status, cold_stderr) =
        exchange_app_server(&root.environment, &initialize, &health, "server/cold").await;
    // This run's stderr is the `ERROR`-level channel, so nothing at `INFO` reaches it and no
    // drain fact is taken from it. The drain of this site is asserted on the placement run
    // above, which is the run that carries `INFO`: the stdio Host leaves through
    // `std::process::exit` inside its own body, so it never reaches the CLI's bounded drain and
    // reports none at all.
    assert!(
        cold_status.success(),
        "the cold stdio Host must exit cleanly: {cold_stderr}"
    );
    assert!(
        cold_initialize.get("error").is_none(),
        "the cold stdio Host must answer app/initialize without an error: {cold_initialize}"
    );
    assert_eq!(
        cold_health.pointer("/result/status"),
        Some(&json!("ready")),
        "the cold stdio Host must answer app/health as ready: {cold_health}"
    );
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        "server/cold",
    );

    let (owner, steady) = start_live_owner(&root, &lease, "server/warm").await;

    let warm_placement = assert_stdio_placement_site(
        &root.environment,
        "server",
        STDIO_SKIP_CODE,
        "server/warm/placement",
    )
    .await;
    assert!(
        warm_placement.success(),
        "the warm placement run of the stdio Host exits through its own body cleanly"
    );
    let (warm_initialize, warm_health, warm_status, warm_stderr) =
        exchange_app_server(&root.environment, &initialize, &health, "server/warm").await;
    assert!(
        warm_status.success(),
        "the warm stdio Host must exit cleanly: {warm_stderr}"
    );
    assert!(
        warm_initialize.get("error").is_none(),
        "the warm stdio Host must answer app/initialize without an error: {warm_initialize}"
    );
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        "server/warm",
    );
    assert_live_owner_intact(&owner, &lease, "server/warm").await;
    stop_live_owner(owner, &lease, "server/warm").await;

    // The protocol projection: the same initialize and health payloads, and the same exit
    // status, as the run that had no enabled scope. Neither payload carries a random value,
    // so nothing is removed from the comparison, and this run reports its own exit because it
    // leaves on stdin EOF.
    assert_eq!(
        protocol_result(&cold_initialize),
        protocol_result(&baseline_initialize),
        "enabling the scope must not change the cold app/initialize answer"
    );
    assert_eq!(
        protocol_result(&cold_health),
        protocol_result(&baseline_health),
        "enabling the scope must not change the cold app/health answer"
    );
    assert_eq!(
        protocol_result(&warm_initialize),
        protocol_result(&baseline_initialize),
        "a live owner must not change the warm app/initialize answer"
    );
    assert_eq!(
        protocol_result(&warm_health),
        protocol_result(&baseline_health),
        "a live owner must not change the warm app/health answer"
    );
    for (run, phase) in [
        (cold_status, "cold"),
        (warm_status, "warm"),
        (baseline_status, "baseline"),
    ] {
        assert_eq!(
            run.code(),
            Some(0),
            "the {phase} stdio Host must report its own clean exit when stdin closes"
        );
    }

    assert_scope_takeable(&root, "server/takeover").await;
}

#[tokio::test]
async fn a_real_cli_acp_skip_serves_the_protocol_and_leaves_the_enabled_scope_untouched() {
    let root = OnRoot::new();
    root.environment.initialize_git_repository();
    root.seed_workspace_record().await;

    let initialize = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "protocolVersion": 1, "clientCapabilities": {} }
    });

    let (baseline_initialize, baseline_end, baseline_stderr) =
        exchange_acp(&root.environment, &initialize, "acp/baseline").await;
    assert_skip_site(&baseline_stderr, ACP_SKIP_CODE, "acp/baseline");
    baseline_end.assert_cancelled_by_test(&baseline_stderr, "acp/baseline");
    assert!(
        baseline_initialize.get("error").is_none(),
        "the baseline ACP server must answer initialize without an error: {baseline_initialize}"
    );
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "an ACP server with no enabled scope must not create the host namespace"
    );

    let (lease, after_owner) = publish_owner_state(&root, "acp").await;

    let (cold_initialize, cold_end, cold_stderr) =
        exchange_acp(&root.environment, &initialize, "acp/cold").await;
    assert_skip_site(&cold_stderr, ACP_SKIP_CODE, "acp/cold");
    cold_end.assert_cancelled_by_test(&cold_stderr, "acp/cold");
    assert!(
        cold_initialize.get("error").is_none(),
        "the cold ACP server must answer initialize without an error: {cold_initialize}"
    );
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        "acp/cold",
    );

    let (owner, steady) = start_live_owner(&root, &lease, "acp/warm").await;

    let (warm_initialize, warm_end, warm_stderr) =
        exchange_acp(&root.environment, &initialize, "acp/warm").await;
    assert_skip_site(&warm_stderr, ACP_SKIP_CODE, "acp/warm");
    warm_end.assert_cancelled_by_test(&warm_stderr, "acp/warm");
    assert!(
        warm_initialize.get("error").is_none(),
        "the warm ACP server must answer initialize without an error: {warm_initialize}"
    );
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        "acp/warm",
    );
    assert_live_owner_intact(&owner, &lease, "acp/warm").await;
    stop_live_owner(owner, &lease, "acp/warm").await;

    // The ACP protocol projection: a real initialize result, with no random value to remove
    // and no field dropped from the comparison. No exit status takes part, because the test
    // cancels the session itself and the shipped transport reports no exit it produced.
    assert_eq!(
        protocol_result(&cold_initialize),
        protocol_result(&baseline_initialize),
        "enabling the scope must not change the cold ACP initialize answer"
    );
    assert_eq!(
        protocol_result(&warm_initialize),
        protocol_result(&baseline_initialize),
        "a live owner must not change the warm ACP initialize answer"
    );
    assert_eq!(
        cold_initialize.pointer("/result/protocolVersion"),
        Some(&json!(1)),
        "ACP must answer the negotiated protocol version"
    );
    assert_eq!(
        cold_initialize.pointer("/result/agentInfo/name"),
        Some(&json!("openbitfun-acp")),
        "ACP must answer its own agent identity"
    );

    assert_scope_takeable(&root, "acp/takeover").await;
}
