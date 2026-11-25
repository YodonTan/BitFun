//! The two background workspace-intelligence skip sites, driven on the shipped binary.
//!
//! `host_skip_lifecycle_cli.rs` covers the management reports, the stdio app server and ACP.
//! This file adds the two sites that file cannot drive, because neither one ends by printing
//! a report:
//!
//! - `daemon run` places the host as a skip before it composes anything
//!   (`daemon/runner.rs`), then bootstraps the same core services the interactive profile
//!   uses and stops at its own missing account session. There is no isolated account session
//!   in this suite, so the shipped command really reports `not logged in` and exits. What this
//!   file proves is that the error exit is reached *after* the skip, and that the scope the
//!   daemon names is byte-identical before and after the run.
//! - `__shared-runtime` places the host as a skip, then serves the private Runtime IPC
//!   endpoint until its idle timeout. The test connects with the production client, checks
//!   that the handshake answer describes the child it started, disconnects, and lets the
//!   service leave on its own. No KILL stands in for that exit.
//!
//! Every phase of both scenarios runs on one isolated root, in the order the other host
//! tests use: an OFF baseline before the scope is enabled, then a cold run against the state a
//! real host published, then a warm run while this process really owns the scope.
//!
//! The daemon does not take its workspace root from its working directory: `runner.rs`
//! resolves the platform home directory (`dirs::home_dir()`). This file resolves the same fact
//! for the target it runs on and seeds the record production resolves for that root, so the
//! catalog lookup hits and the manager never builds a fresh workspace from a directory it
//! would have to inspect. All product state both runs can write is isolated: the user root,
//! the product home, the configuration root and the CLI logs are this test's own, the model
//! catalog is the copy already in the repository, and no account session, credential, relay
//! connection or model is used. The child inherits this test's temporary directory instead of
//! naming one of its own.
//!
//! Everything this suite asserts about the flag is asserted from the child's own log file,
//! which the daemon and the Shared Runtime service both write at `DEBUG`, so no assertion here
//! depends on a filtered stderr channel.
//!
//! Not covered by this file, on purpose: a Shared Runtime TUI, a relay or account connection,
//! remote control, dispatch and any Remote workspace transport. Both sites are exercised
//! locally only.

#[path = "../support/mod.rs"]
mod support;

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{ExitStatus, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use openbitfun_agent_runtime_ipc::{
    DiscoveryRecord, DiscoveryStore, HealthResult, RuntimeInstanceIdentity, RuntimeIpcClient,
    PROTOCOL_VERSION,
};
use openbitfun_core::runtime_ownership::CoreRuntimeOwnership;
use openbitfun_core::service::workspace_intelligence::host_fixture;
use openbitfun_services_core::workspace_identity::{
    local_workspace_stable_storage_id, normalize_local_workspace_root_for_stable_id,
};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader, ReadBuf};

use crate::host_skip_lifecycle_cli::{
    assert_drained_empty_slot, assert_lease_released, assert_live_owner_intact,
    assert_owner_published_state, assert_scope_takeable_for_scope, assert_skip_site,
    assert_tree_unchanged, plain_diagnostics, start_live_owner_for_scope, stop_live_owner,
    wi_tree_snapshot, LiveOwner, OnRoot, TreeEntry, REPOSITORY_MODEL_CATALOG, WORKSPACE_ID,
};

/// Stable placement codes of the two sites this file covers.
const DAEMON_SKIP_CODE: &str = "host_skip_daemon";
const SHARED_SKIP_CODE: &str = "host_skip_shared_runtime";

/// The daemon's own not-logged-in diagnostic, verbatim from `daemon/runner.rs`.
///
/// The daemon refuses to run without an account session, and this suite never creates one, so
/// this line is the error exit the site is proven to reach after its skip.
const NOT_LOGGED_IN_DIAGNOSTIC: &str = "Error: not logged in; run `openbitfun`, log in with \
                                        `/login`, then start the daemon again";

/// Absolute deadline of one background child, measured from its spawn.
///
/// It is one budget for the whole session rather than a timeout per step, so a child that
/// answers slowly but forever cannot extend it. The Shared Runtime's own idle timeout is
/// inside this budget, and a session that exceeds it is killed, reaped and failed rather than
/// passed.
const BACKGROUND_DEADLINE: Duration = Duration::from_secs(120);

/// How often a wait re-reads a file or polls a process that has not answered yet.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How long a child that was killed on an already failing path is given to be reaped.
const REAP_BUDGET: Duration = Duration::from_secs(10);

/// The production connect budget for one IPC handshake (`shared_runtime::CONNECT_TIMEOUT`).
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

/// The request budget for the one health call this file makes.
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn a_real_cli_daemon_skip_reports_its_own_placement_and_leaves_its_scope_untouched() {
    let root = OnRoot::new();
    // The daemon names no workspace of its caller: it composes one from the platform home
    // directory. Seeding the record production resolves for that directory is what makes the
    // treated runs meaningful: the catalog lookup hits, so the run reuses this record instead
    // of describing the directory from scratch.
    let scope = ScopeRecord::of(&daemon_scope_root(&root));
    host_fixture::seed_local_workspace(root.paths.as_ref(), scope.id(), &scope.root)
        .await
        .expect("seed the workspace record production resolves for the daemon's root");
    assert!(
        scope.id() != WORKSPACE_ID,
        "the daemon's scope must be the record production derives, not the fixed record the \
         directory-owned scenarios seed"
    );
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "seeding a workspace record must not create the host namespace"
    );
    assert_catalog_scope_record(&root, &scope, "daemon/seed");

    // OFF baseline: the same binary and the same arguments before the scope is enabled. The
    // placement is decided before any host state is read, so the site is reached here too.
    let (baseline, _) = run_daemon_phase(&root, &scope, "daemon/baseline");
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "a daemon with no enabled scope must not create the host namespace: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    // ON: the fixture enables the seeded scope in one control generation, and a real host
    // publishes the state a real owner leaves behind, then drains.
    let (lease, after_owner) = publish_real_owner(&root, &scope, "daemon").await;

    // Cold run: the owner is gone and the tree is the owner's own state.
    let (cold, _) = run_daemon_phase(&root, &scope, "daemon/cold");
    // Enabling the scope must not change one report byte or the exit the command reports.
    assert_eq!(
        cold.status.code(),
        baseline.status.code(),
        "enabling the scope must not change the daemon's exit status"
    );
    assert_eq!(
        cold.stdout, baseline.stdout,
        "enabling the scope must not add one stdout byte to the daemon"
    );
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        "daemon/cold",
    );

    // Warm run: this process really owns the scope while the daemon runs, so the incarnation
    // token and the lease are held rather than inferred.
    let (owner, steady) =
        start_live_owner_for_scope(&root, &lease, scope.id(), "daemon/warm").await;
    let (warm, _) = run_daemon_phase(&root, &scope, "daemon/warm");
    assert_eq!(
        warm.status.code(),
        baseline.status.code(),
        "a live owner must not change the daemon's exit status"
    );
    assert_eq!(
        warm.stdout, baseline.stdout,
        "a live owner must not add one stdout byte to the daemon"
    );
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        "daemon/warm",
    );
    assert_live_owner_intact(&owner, &lease, "daemon/warm").await;
    stop_live_owner(owner, &lease, "daemon/warm").await;

    // After the last snapshot the scope must still be takeable, which is only possible if the
    // earlier owner released it explicitly instead of leaving it to process exit.
    assert_scope_takeable_for_scope(&root, scope.id(), "daemon/takeover").await;
}

#[tokio::test]
async fn a_real_cli_shared_runtime_skip_serves_its_ipc_and_leaves_the_enabled_scope_untouched() {
    let root = OnRoot::new();
    // The Shared Runtime serves the workspace it is given, so that workspace is the scope this
    // scenario enables: the same isolated directory is the CLI's working directory, the
    // `--workspace` argument and the workspace record this test seeds. Its record id is again
    // the one production derives, so the service's own registration reuses it.
    let workspace = root.environment.workspace().to_path_buf();
    let scope = ScopeRecord::of(&workspace);
    host_fixture::seed_local_workspace(root.paths.as_ref(), scope.id(), &workspace)
        .await
        .expect("seed the workspace record production resolves for the served workspace");
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "seeding a workspace record must not create the host namespace"
    );
    let identity = shared_identity(&root, &workspace);
    let ipc_root = shared_ipc_root(&root);
    let store = DiscoveryStore::new(&ipc_root, identity.clone());

    // OFF baseline.
    let baseline = exercise_shared_service(
        &root,
        &store,
        &ipc_root,
        &identity,
        &workspace,
        "shared/baseline",
    )
    .await;
    assert!(
        !root.paths.workspace_intelligence_dir().exists(),
        "a Shared Runtime with no enabled scope must not create the host namespace"
    );
    assert_catalog_scope_record(&root, &scope, "shared/baseline");

    // ON: one control generation, a real owner, then the cold run.
    let (lease, after_owner) = publish_real_owner(&root, &scope, "shared").await;
    let cold = exercise_shared_service(
        &root,
        &store,
        &ipc_root,
        &identity,
        &workspace,
        "shared/cold",
    )
    .await;
    assert_catalog_scope_record(&root, &scope, "shared/cold");
    assert_tree_unchanged(
        &after_owner,
        &root.paths.workspace_intelligence_dir(),
        "shared/cold",
    );

    // Warm: a live owner of this process and the Shared Runtime child coexist on the workspace.
    let (owner, steady) =
        start_live_owner_for_scope(&root, &lease, scope.id(), "shared/warm").await;
    let warm = exercise_shared_service(
        &root,
        &store,
        &ipc_root,
        &identity,
        &workspace,
        "shared/warm",
    )
    .await;
    assert_catalog_scope_record(&root, &scope, "shared/warm");
    assert_tree_unchanged(
        &steady,
        &root.paths.workspace_intelligence_dir(),
        "shared/warm",
    );
    assert_live_owner_intact(&owner, &lease, "shared/warm").await;
    stop_live_owner(owner, &lease, "shared/warm").await;

    // The same stable business projection in every phase. The process id is the one field that
    // differs between phases, because it is the answering child's own: it is asserted against
    // the child each phase started instead of being compared across phases, and nothing else is
    // dropped from the comparison.
    assert_eq!(
        cold, baseline,
        "enabling the scope must not change the Shared Runtime handshake or its exit"
    );
    assert_eq!(
        warm, baseline,
        "a live host owner must not change the Shared Runtime handshake or its exit"
    );
    assert_eq!(
        cold.exit_code,
        Some(0),
        "an idle Shared Runtime leaves on its own with the CLI's success status"
    );
    assert_eq!(
        cold.protocol_version, PROTOCOL_VERSION,
        "the discovery record must carry the protocol version of this build"
    );
    assert_scope_takeable_for_scope(&root, scope.id(), "shared/takeover").await;
}

/// The pipe reader reports a failed read instead of passing as an empty capture.
///
/// A reader that stops on an error and returns success would let every "printed nothing" or
/// "logged nothing" assertion in this file pass on evidence that was never collected, so the
/// failure has to survive the join that collects it.
#[tokio::test]
async fn a_failed_pipe_read_is_reported_instead_of_passing_as_an_empty_capture() {
    let sink = Arc::new(Mutex::new(String::new()));
    let drained = drain_lines(FailingReader, Arc::clone(&sink)).await;
    let error = drained.expect_err("a failed pipe read must not be reported as a clean end");
    assert_eq!(
        error.kind(),
        io::ErrorKind::BrokenPipe,
        "the original pipe error must survive the drain"
    );
    assert_eq!(
        text_of(&sink),
        "",
        "nothing was read before the failure, so the capture stays empty"
    );
}

/// The workspace record production resolves for one scope root.
///
/// The workspace manager finds a local record by canonicalizing the root and deriving
/// `local_workspace_stable_storage_id` from that string (`manager.rs`,
/// `upsert_workspace_with_options`). When that id is present it takes the reuse branch, which
/// only rewrites the display name, the kind and the access facts. When it is absent it answers
/// with a brand-new `WorkspaceInfo::new`, and that constructor describes the directory: it
/// probes `Cargo.toml`/`package.json`, `read_dir`s the root and reads its `IDENTITY.md`. The
/// CLI reaches the manager through `register_local_workspace_record`, which tracks activity
/// with `TouchOnly`, so the reuse branch also skips the worktree probe and `load_identity`.
///
/// For a scope the command composes rather than the test, that directory can be a real user
/// directory, so this file always seeds the id production derives and proves the catalog holds
/// exactly that record: same id, same root, and still under the seeded name.
struct ScopeRecord {
    root: PathBuf,
    canonical_root: String,
    id: String,
}

impl ScopeRecord {
    /// Resolves `root` the way the workspace manager does before it looks the record up.
    fn of(root: &Path) -> Self {
        let canonical_root = normalize_local_workspace_root_for_stable_id(root)
            .unwrap_or_else(|error| panic!("normalize the scope root {root:?}: {error}"));
        let id = local_workspace_stable_storage_id(&canonical_root);
        assert!(
            id.starts_with("local_"),
            "a local scope record id is derived from the canonical root: {id}"
        );
        Self {
            root: root.to_path_buf(),
            canonical_root,
            id,
        }
    }

    fn id(&self) -> &str {
        &self.id
    }
}

/// The workspace root the daemon composes for itself, resolved the way the daemon resolves it.
///
/// `daemon/runner.rs` calls `dirs::home_dir()` and never looks at its own working directory.
/// On Windows both `dirs` versions in this tree answer with the OS profile folder
/// (`FOLDERID_Profile`), which ignores `HOME`/`USERPROFILE`: a probe run of the shipped binary
/// with both variables isolated still registered the real profile folder as its workspace
/// root. On Unix `dirs::home_dir()` reads `$HOME`, and the child is started with this
/// environment's isolated home, so the scope is that directory.
///
/// The non-Windows branch is the same fact read from the environment the child receives; it
/// has not been exercised on a Unix host by this slice, which is why the target split is
/// explicit instead of claiming one branch for both.
#[cfg(windows)]
fn daemon_scope_root(root: &OnRoot) -> PathBuf {
    let _ = root;
    dirs::home_dir().expect("the daemon composes its workspace root from the platform home")
}

/// See the Windows variant above: `dirs::home_dir()` reads the child's `$HOME` here.
#[cfg(not(windows))]
fn daemon_scope_root(root: &OnRoot) -> PathBuf {
    root.environment.home_root().to_path_buf()
}

/// Asserts the catalog resolves the scope root to the seeded record and to no other id.
///
/// This is the guard against the failure mode a test-chosen id used to hide: if the run
/// derived a different id for the same directory it would appear here as a second record
/// naming the scope root. The run also registers its own personal-assistant workspace during
/// bootstrap, so records for other directories are allowed as long as every one of them stays
/// inside this test's isolated user or home root instead of naming a machine path. "Inside" is
/// decided by path component (see [`is_within_root`]), so a sibling that only shares a string
/// prefix with an isolated root does not count as one.
fn assert_catalog_scope_record(root: &OnRoot, scope: &ScopeRecord, label: &str) {
    let path = root.paths.user_data_dir().join("workspace_data.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{label}: read the workspace catalog {path:?}: {error}"));
    let catalog: serde_json::Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{label}: parse the workspace catalog {path:?}: {error}"));
    let workspaces = catalog["workspaces"]
        .as_object()
        .unwrap_or_else(|| panic!("{label}: the workspace catalog holds no record map: {text}"));
    let isolated: Vec<String> = [root.environment.user_root(), root.environment.home_root()]
        .into_iter()
        .map(|dir| {
            normalize_local_workspace_root_for_stable_id(dir)
                .unwrap_or_else(|error| panic!("{label}: normalize the isolated root: {error}"))
        })
        .collect();
    let mut scope_records: Vec<&str> = Vec::new();
    for (id, record) in workspaces {
        let recorded = record["rootPath"]
            .as_str()
            .unwrap_or_else(|| panic!("{label}: the record {id} names no root path: {text}"));
        let normalized = normalize_local_workspace_root_for_stable_id(Path::new(recorded))
            .unwrap_or_else(|error| {
                panic!("{label}: normalize the recorded root {recorded:?}: {error}")
            });
        if normalized == scope.canonical_root {
            // A record rebuilt from the directory is named after that directory, so an
            // unchanged name is the second half of the proof that the lookup hit the seed and
            // the manager never described the root itself.
            assert_eq!(
                record["name"].as_str(),
                Some(scope.id()),
                "{label}: the scope record must be the seeded one, not one rebuilt from the \
                 directory: {text}"
            );
            scope_records.push(id.as_str());
        } else {
            assert!(
                isolated
                    .iter()
                    .any(|root| is_within_root(root.as_str(), &normalized)),
                "{label}: a run may only add records for its own isolated product state; the \
                 record {id} names {normalized:?}, outside {isolated:?}: {text}"
            );
        }
    }
    scope_records.sort_unstable();
    assert_eq!(
        scope_records,
        vec![scope.id()],
        "{label}: the scope root must resolve to exactly the seeded record and no second id: \
         {text}"
    );
}

/// Whether `candidate` is `root` itself or a path below it, by whole path component.
///
/// Both arguments are the canonical root strings production derives
/// (`normalize_local_workspace_root_for_stable_id`): absolute, with `/` separators. The
/// comparison is lexical and component-wise, so `.../user-root-foreign` is not inside
/// `.../user-root` even though the string begins with it. A trailing separator on `root` names
/// the same root, and a filesystem root keeps matching everything below it.
fn is_within_root(root: &str, candidate: &str) -> bool {
    Path::new(candidate).starts_with(Path::new(root))
}

/// The isolated-root boundary is a path-component boundary, not a string prefix.
///
/// The lexical cases use strings that are absolute on both targets this suite runs on, and the
/// Windows block mirrors the shape production actually produces there. Nothing here touches the
/// filesystem.
#[test]
fn an_isolated_root_admits_itself_and_its_children_but_not_a_prefix_sibling() {
    // Equality and a true child of one isolated root.
    assert!(is_within_root("/srv/runs/user-root", "/srv/runs/user-root"));
    assert!(is_within_root("/srv/runs/user-root", "/srv/runs/user-root/data/agent-runtime"));
    // A sibling whose name merely extends the root's name is outside it, at any depth.
    assert!(!is_within_root("/srv/runs/user-root", "/srv/runs/user-root-foreign"));
    assert!(!is_within_root("/srv/runs/user-root", "/srv/runs/user-root-foreign/workspace"));
    // The same boundary for the home root, which is a sibling of the user root.
    let foreign_home = "/srv/runs/home-foreign/personal_assistant/workspace";
    assert!(is_within_root("/srv/runs/home", "/srv/runs/home"));
    assert!(is_within_root("/srv/runs/home", "/srv/runs/home/personal_assistant/workspace"));
    assert!(!is_within_root("/srv/runs/home", foreign_home));
    // A trailing separator on the root names the same root, not a string prefix.
    assert!(is_within_root("/srv/runs/user-root/", "/srv/runs/user-root"));
    assert!(is_within_root("/srv/runs/user-root/", "/srv/runs/user-root/data"));
    assert!(!is_within_root("/srv/runs/user-root/", "/srv/runs/user-root-foreign/data"));
    // A filesystem root keeps matching its children.
    assert!(is_within_root("/", "/anything"));
    // On Windows the canonical strings are drive-rooted, so the same facts are checked in the
    // shape this suite actually writes there.
    #[cfg(windows)]
    {
        assert!(is_within_root("C:/runs/user-root", "C:/runs/user-root/data"));
        assert!(!is_within_root("C:/runs/user-root", "C:/runs/user-root-foreign/data"));
        assert!(is_within_root("C:/", "C:/runs/home"));
    }
}

/// The CLI log root the children compose: `<user root>/cli-logs`.
fn cli_logs_root(root: &OnRoot) -> PathBuf {
    root.environment.user_root().join("cli-logs")
}

/// Every CLI `app.log` under this root, keyed by its own path.
///
/// Session directory names have only second granularity, so two runs of this file can share
/// one directory. A per-path text map lets each phase take only what was appended to the file
/// it reads, instead of concatenating a whole tree and depending on cross-file order.
fn cli_log_snapshot(root: &OnRoot) -> BTreeMap<PathBuf, String> {
    fn walk(directory: &Path, logs: &mut BTreeMap<PathBuf, String>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("read a CLI log entry").path();
            if path.is_dir() {
                walk(&path, logs);
            } else if path.file_name().and_then(|name| name.to_str()) == Some("app.log") {
                let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
                    panic!("read a CLI app log {path:?}: {error}")
                });
                logs.insert(path, text);
            }
        }
    }

    let mut logs = BTreeMap::new();
    walk(&cli_logs_root(root), &mut logs);
    logs
}

/// The log text one run appended, in path order.
///
/// A file that existed before must still exist and extend its own text: a rewritten tree is a
/// failure rather than an empty suffix. Files that did not exist before belong to this run in
/// full, so the first run of a session directory is attributed too.
fn appended_text(
    before: &BTreeMap<PathBuf, String>,
    after: &BTreeMap<PathBuf, String>,
    label: &str,
) -> String {
    let mut text = String::new();
    for (path, previous) in before {
        let current = after.get(path).unwrap_or_else(|| {
            panic!("{label}: the CLI log {path:?} disappeared instead of being extended")
        });
        let appended = current.strip_prefix(previous.as_str()).unwrap_or_else(|| {
            panic!(
                "{label}: the CLI log {path:?} was rewritten instead of extended ({} bytes \
                 before, {} after)",
                previous.len(),
                current.len()
            )
        });
        text.push_str(appended);
    }
    for (path, current) in after {
        if !before.contains_key(path) {
            text.push_str(current);
        }
    }
    text
}

/// Runs one daemon phase and asserts everything the skip site owes on every phase.
///
/// The site is asserted from the child's own `DEBUG` log, the account-session error exit from
/// the child's own status and stderr, and the catalog from the document the run saves.
fn run_daemon_phase(root: &OnRoot, scope: &ScopeRecord, label: &'static str) -> (Output, String) {
    let before = cli_log_snapshot(root);
    let output = root.run(&["daemon", "run"]);
    let log = appended_text(&before, &cli_log_snapshot(root), label);
    assert_skip_site(&log, DAEMON_SKIP_CODE, label);
    assert_drained_empty_slot(&log, label);
    assert_not_logged_in(&output, label);
    assert_daemon_never_served(root, label);
    assert_catalog_scope_record(root, scope, label);
    (output, log)
}

/// Asserts the daemon stopped at its own missing account session.
///
/// The status and the diagnostic are the shipped command's own: the daemon exits with the
/// CLI's failure status, prints the owner's message on stderr and prints no report. Reaching
/// this line means the skip above ran before a real core bootstrap and that the bootstrap
/// completed, which an early startup failure could not do.
fn assert_not_logged_in(output: &Output, label: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "{label}: a daemon with no account session exits through the CLI's failure path: {stderr}"
    );
    let diagnostics = plain_diagnostics(&stderr);
    assert_eq!(
        diagnostics,
        vec![NOT_LOGGED_IN_DIAGNOSTIC],
        "{label}: the daemon must report its own not-logged-in diagnostic and nothing else: \
         {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "{label}: a daemon that never served prints no report: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}

/// Asserts the run left nothing behind that only a served daemon writes.
///
/// The management endpoint is published only by the management server, and the pid file only
/// after the account session was restored and routing started, so neither may exist after this
/// error exit. The owner lease file the reservation creates is not evidence of either: it is
/// created before the skip and is not removed by the owner, so it is deliberately not asserted
/// here.
fn assert_daemon_never_served(root: &OnRoot, label: &str) {
    let product_home = root.environment.home_root();
    let endpoint = product_home.join("cli-daemon-control").join("endpoint.json");
    assert!(
        !endpoint.exists(),
        "{label}: a daemon that stopped before serving must not leave its management endpoint: \
         {endpoint:?}"
    );
    let pid_file = product_home.join("cli_daemon.pid");
    assert!(
        !pid_file.exists(),
        "{label}: a daemon that stopped before serving must not leave its pid file: {pid_file:?}"
    );
}

/// Enables the seeded scope in one control generation and publishes a real owner's own state.
///
/// This is the same sequence the sibling file uses, repeated for a scope whose id production
/// derives; it asserts the generation, the drain, the released lease and a non-empty cognition
/// partition, so a treated run is compared against a workspace a live owner really published
/// rather than an empty database.
async fn publish_real_owner(
    root: &OnRoot,
    scope: &ScopeRecord,
    label: &str,
) -> (PathBuf, Vec<TreeEntry>) {
    let namespace = root.paths.workspace_intelligence_dir();
    assert!(
        !namespace.exists(),
        "{label}: the enable must publish the first host state"
    );
    let seeded = host_fixture::enable_workspace(root.paths.as_ref(), scope.id())
        .await
        .expect("enable the seeded workspace");
    assert_eq!(seeded.workspace_id(), scope.id());
    assert_eq!(
        seeded.generation(),
        1,
        "{label}: the fixture enables the seeded scope in one control generation"
    );
    let after_enable = wi_tree_snapshot(&namespace);

    let publisher_label = format!("{label}/publisher");
    let mut publisher =
        LiveOwner::bootstrap_for_scope(&root.paths, scope.id(), &publisher_label).await;
    publisher.stop(&publisher_label).await;
    drop(publisher);

    let lease = root.single_lease_file(&publisher_label);
    assert_lease_released(&lease, &publisher_label);
    let after_owner = wi_tree_snapshot(&namespace);
    assert_ne!(
        after_owner, after_enable,
        "{label}: the real owner must publish its own state on top of the enable"
    );
    assert_owner_published_state(&after_owner, root, label);
    (lease, after_owner)
}

/// The IPC root both the service and this test compose: `<user data>/agent-runtime/ipc-v<N>`.
fn shared_ipc_root(root: &OnRoot) -> PathBuf {
    root.paths
        .user_data_dir()
        .join("agent-runtime")
        .join(format!("ipc-v{PROTOCOL_VERSION}"))
}

/// The instance identity of one workspace, computed through the production API.
///
/// The release channel, product identity, user identity and protocol version are the ones the
/// service itself passes, so the child accepts the identity this test hands it instead of this
/// file re-deriving the hash by hand.
fn shared_identity(root: &OnRoot, workspace: &Path) -> RuntimeInstanceIdentity {
    RuntimeInstanceIdentity::for_workspace(
        workspace,
        CoreRuntimeOwnership::distribution_identity(),
        "stable",
        &root.paths.user_data_dir().to_string_lossy(),
        PROTOCOL_VERSION,
    )
    .expect("compute the Shared Runtime instance identity of the seeded workspace")
}

/// What one Shared Runtime phase observed, in the shape compared across phases.
#[derive(Debug, PartialEq, Eq)]
struct SharedProjection {
    /// Protocol version the service published in its discovery record.
    protocol_version: u32,
    /// Instance identity the service published and answered with.
    instance_identity: String,
    /// Instance identity of the health answer, which must be the same one.
    health_identity: String,
    /// Whether the service advertised the health capability the client needs.
    health_capability: bool,
    /// Status the service left with once its idle timeout expired.
    exit_code: Option<i32>,
}

/// What one phase observed once the child had left on its own.
struct SharedSession {
    projection: SharedProjection,
    log: String,
}

/// Runs one Shared Runtime session to its own exit and asserts everything it owes.
///
/// The session is driven inside [`drive_shared_session`], which reports failures instead of
/// unwinding, so a child still alive at that point is always stopped through the checked
/// [`SharedService::terminate_and_reap`] before this function fails the test.
async fn exercise_shared_service(
    root: &OnRoot,
    store: &DiscoveryStore,
    ipc_root: &Path,
    identity: &RuntimeInstanceIdentity,
    workspace: &Path,
    label: &'static str,
) -> SharedProjection {
    let mut service = SharedService::spawn(root, workspace, identity, label);
    let session = match drive_shared_session(&mut service, store, ipc_root, identity, label).await {
        Ok(session) => session,
        Err(failure) => {
            let stop = service.terminate_and_reap("a failed phase").await;
            panic!("{label}: {failure}\n{stop}");
        }
    };
    // The child has left on its own at this point, so the remaining assertions need no
    // cleanup and reuse the same site helpers as every other file.
    assert_skip_site(&session.log, SHARED_SKIP_CODE, label);
    assert_drained_empty_slot(&session.log, label);
    session.projection
}

/// Drives one session to the service's own exit and reports the first failure.
///
/// Nothing in here may unwind: the caller still owns the child and stops it on `Err`.
async fn drive_shared_session(
    service: &mut SharedService,
    store: &DiscoveryStore,
    ipc_root: &Path,
    identity: &RuntimeInstanceIdentity,
    label: &'static str,
) -> Result<SharedSession, String> {
    let record = service.wait_for_discovery(store).await?;
    ensure(
        record.protocol_version == PROTOCOL_VERSION,
        || {
            format!(
                "the discovery record must carry this build's protocol version \
                 ({PROTOCOL_VERSION}), not {}",
                record.protocol_version
            )
        },
    )?;
    ensure(
        record.instance_identity.as_str() == identity.as_str(),
        || {
            format!(
                "the discovery record must name the identity of this workspace, not {}",
                record.instance_identity.as_str()
            )
        },
    )?;
    ensure(record.process_id == service.pid(), || {
        format!(
            "the discovery record must describe the child this test started ({}), not {}",
            service.pid(),
            record.process_id
        )
    })?;

    let client = connect_shared_client(service, ipc_root, &record).await?;
    let health_capability = client.capabilities().health;
    ensure(health_capability, || {
        "the service must advertise the health capability a Shared client requires".to_owned()
    })?;
    let health = ask_shared_health(service, &client).await?;
    ensure(
        health.instance_identity == identity.as_str(),
        || {
            format!(
                "the health answer must come from this workspace's runtime, not {}",
                health.instance_identity
            )
        },
    )?;
    ensure(health.process_id == service.pid(), || {
        format!(
            "the health answer must come from the child this test started ({}), not {}",
            service.pid(),
            health.process_id
        )
    })?;
    // The client is the only connection this phase made, so dropping it leaves the service
    // with none and its own idle timeout then ends the process. The exit below is that natural
    // exit, not a kill.
    drop(client);

    let status = service
        .await_idle_exit("expire its idle timeout after the client left")
        .await?;
    ensure(status.code() == Some(0), || {
        format!(
            "an idle Shared Runtime leaves through the CLI's success path: {status}{}",
            service.tail()
        )
    })?;
    let (stdout, stderr) = service.read_output().await?;
    // The protocol of this site is the private IPC endpoint, so the process owns no stdout
    // report and writes nothing to stderr. Both are compared as the exact bytes the pipes
    // carried: a line, or even a lone newline, would be a second channel this slice does not
    // claim.
    ensure(stdout.is_empty(), || {
        format!("a served Shared Runtime writes no stdout report, but the pipe carried {stdout:?}")
    })?;
    ensure(stderr.is_empty(), || {
        format!("a served Shared Runtime writes no plain stderr, but the pipe carried {stderr:?}")
    })?;
    ensure(
        store.read().is_ok_and(|record| record.is_none()),
        || "a stopped Shared Runtime must remove its discovery record".to_owned(),
    )?;
    let log = service.log_text(label)?;

    Ok(SharedSession {
        projection: SharedProjection {
            protocol_version: record.protocol_version,
            instance_identity: record.instance_identity.as_str().to_string(),
            health_identity: health.instance_identity,
            health_capability,
            exit_code: status.code(),
        },
        log,
    })
}

/// Fails with `message` when `condition` does not hold.
fn ensure(condition: bool, message: impl FnOnce() -> String) -> Result<(), String> {
    if condition {
        Ok(())
    } else {
        Err(message())
    }
}

/// Accepts the IPC handshake inside what is left of the session budget.
async fn connect_shared_client(
    service: &SharedService,
    ipc_root: &Path,
    record: &DiscoveryRecord,
) -> Result<RuntimeIpcClient, String> {
    let remaining = service.budget("accept the IPC handshake")?;
    match tokio::time::timeout(
        remaining,
        RuntimeIpcClient::connect(
            ipc_root,
            record,
            &format!("host-skip-shared-{}", std::process::id()),
            env!("CARGO_PKG_VERSION"),
            IPC_CONNECT_TIMEOUT,
            IPC_REQUEST_TIMEOUT,
        ),
    )
    .await
    {
        Ok(Ok(client)) => Ok(client),
        Ok(Err(error)) => Err(format!(
            "connect to the Shared Runtime: {error}{}",
            service.tail()
        )),
        Err(_) => Err(format!(
            "the IPC handshake did not complete inside {remaining:?}{}",
            service.tail()
        )),
    }
}

/// Asks the connected service for health inside what is left of the session budget.
async fn ask_shared_health(
    service: &SharedService,
    client: &RuntimeIpcClient,
) -> Result<HealthResult, String> {
    let remaining = service.budget("answer health")?;
    match tokio::time::timeout(remaining, client.health()).await {
        Ok(Ok(health)) => Ok(health),
        Ok(Err(error)) => Err(format!(
            "ask the Shared Runtime for health: {error}{}",
            service.tail()
        )),
        Err(_) => Err(format!(
            "the health answer did not arrive inside {remaining:?}{}",
            service.tail()
        )),
    }
}

/// One `__shared-runtime` child this test started, with an absolute deadline.
///
/// The child is spawned through `process_manager` and the owned failure paths stop it through
/// [`SharedService::terminate_and_reap`], which kills it and checks the reap. `kill_on_drop`
/// backs that up if an assertion unwinds first. Both pipes are drained for the whole session by
/// tasks so the child can never block on a full pipe, and their text is kept for a failure
/// message. Every wait is bounded by the deadline taken at spawn.
struct SharedService {
    child: Option<tokio::process::Child>,
    pid: u32,
    stdout_reader: Option<tokio::task::JoinHandle<io::Result<()>>>,
    stderr_reader: Option<tokio::task::JoinHandle<io::Result<()>>>,
    stdout_text: Arc<Mutex<String>>,
    stderr_text: Arc<Mutex<String>>,
    /// The CLI log tree before this child was started, so its own log text is attributable
    /// even if the platform recycles a process id.
    logs_before: BTreeMap<PathBuf, String>,
    log_root: PathBuf,
    deadline: Instant,
}

impl SharedService {
    /// Starts one Shared Runtime service on `workspace` with `identity`.
    fn spawn(
        root: &OnRoot,
        workspace: &Path,
        identity: &RuntimeInstanceIdentity,
        label: &'static str,
    ) -> Self {
        let mut command = openbitfun_services_core::process_manager::create_tokio_command(env!(
            "CARGO_BIN_EXE_openbitfun"
        ));
        command
            .arg("__shared-runtime")
            .arg("--workspace")
            .arg(workspace)
            .arg("--instance-identity")
            .arg(identity.as_str())
            .env("OPENBITFUN_MODELS_DEV_PATH", REPOSITORY_MODEL_CATALOG)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        root.environment.apply_tokio_environment(&mut command);

        let logs_before = cli_log_snapshot(root);
        let mut child = command
            .spawn()
            .unwrap_or_else(|error| panic!("{label}: start the Shared Runtime child: {error}"));
        let pid = child
            .id()
            .unwrap_or_else(|| panic!("{label}: the Shared Runtime child reports no process id"));
        let stdout_text = Arc::new(Mutex::new(String::new()));
        let stderr_text = Arc::new(Mutex::new(String::new()));
        let stdout_reader = tokio::spawn(drain_lines(
            child.stdout.take().expect("the child stdout pipe"),
            Arc::clone(&stdout_text),
        ));
        let stderr_reader = tokio::spawn(drain_lines(
            child.stderr.take().expect("the child stderr pipe"),
            Arc::clone(&stderr_text),
        ));

        Self {
            child: Some(child),
            pid,
            stdout_reader: Some(stdout_reader),
            stderr_reader: Some(stderr_reader),
            stdout_text,
            stderr_text,
            logs_before,
            log_root: cli_logs_root(root),
            deadline: Instant::now() + BACKGROUND_DEADLINE,
        }
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    /// The budget left for `step`, or a failure that reports what the child printed.
    fn budget(&self, step: &str) -> Result<Duration, String> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(format!(
                "{step} exceeded the absolute deadline {BACKGROUND_DEADLINE:?} measured from \
                 the spawn of this child{}",
                self.tail()
            ));
        }
        Ok(remaining)
    }

    /// What the child printed so far, rendered for a failure message.
    fn tail(&self) -> String {
        format!(
            "\nstdout:\n{}\nstderr:\n{}",
            text_of(&self.stdout_text),
            text_of(&self.stderr_text)
        )
    }

    /// Waits for the discovery record the service publishes once its endpoint listens.
    async fn wait_for_discovery(
        &mut self,
        store: &DiscoveryStore,
    ) -> Result<DiscoveryRecord, String> {
        let mut last_read_error = None;
        loop {
            let remaining = self.budget("publish its IPC discovery record")?;
            match store.read() {
                Ok(Some(record)) => return Ok(record),
                Ok(None) => {}
                Err(error) => last_read_error = Some(error.to_string()),
            }
            // A service that leaves before publishing can never be connected to, so failing
            // here names the real outcome instead of waiting out the deadline.
            match self
                .child
                .as_mut()
                .expect("the child handle is present until it exits")
                .try_wait()
            {
                Ok(None) => {}
                Ok(Some(status)) => {
                    return Err(format!(
                        "the Shared Runtime left ({status}) before it published its discovery \
                         record; last read error: {last_read_error:?}{}",
                        self.tail()
                    ))
                }
                Err(error) => {
                    return Err(format!(
                        "poll the Shared Runtime child while waiting for discovery: {error}"
                    ))
                }
            }
            tokio::time::sleep(POLL_INTERVAL.min(remaining)).await;
        }
    }

    /// Waits for the service to leave on its own and returns the status it left with.
    ///
    /// A timeout is a failure, never a pass: the child is stopped through
    /// [`Self::terminate_and_reap`], and the failure reports both facts without ever presenting
    /// a kill as a natural exit.
    async fn await_idle_exit(&mut self, step: &str) -> Result<ExitStatus, String> {
        let remaining = self.budget(step)?;
        let waited = {
            let child = self
                .child
                .as_mut()
                .expect("the child handle is present until it exits");
            tokio::time::timeout(remaining, child.wait()).await
        };
        match waited {
            Ok(Ok(status)) => {
                self.child = None;
                Ok(status)
            }
            Ok(Err(error)) => {
                let stop = self.terminate_and_reap(&format!("a failed wait after {step}")).await;
                Err(format!(
                    "wait for the Shared Runtime child after {step}: {error}\n{stop}"
                ))
            }
            Err(_) => {
                let stop = self.terminate_and_reap(&format!("{step} timed out")).await;
                Err(format!(
                    "the idle Shared Runtime did not leave within {remaining:?} after {step}: a \
                     timeout is a failure, never a pass\n{stop}"
                ))
            }
        }
    }

    /// Stops this child and waits for the OS to reap it, and reports what happened.
    ///
    /// Every owned failure path of this session funnels through here before the test is failed,
    /// so a child is never left running because an earlier step returned an error. The wait is
    /// unconditional: a failed kill request still gets the bounded wait, because the process
    /// may have left on its own between the poll and the request. A failed or timed-out wait,
    /// or a failed kill request, is reported as a cleanup failure and never as a natural exit.
    /// The synchronous `Drop` below stays best effort; it cannot promise a reap.
    async fn terminate_and_reap(&mut self, step: &str) -> String {
        let Some(mut child) = self.child.take() else {
            return format!("{step}: no child handle remained, so no further stop was possible");
        };
        let polled = child.try_wait();
        if let Ok(Some(status)) = polled {
            return format!("{step}: the child had already exited with {status}");
        }
        let poll_note = match &polled {
            Ok(_) => String::new(),
            Err(error) => format!(" (pre-stop poll error: {error})"),
        };
        let kill = child.start_kill();
        let waited = tokio::time::timeout(REAP_BUDGET, child.wait()).await;
        let outcome = match waited {
            Ok(Ok(status)) => format!("reaped with {status}"),
            Ok(Err(error)) => format!("CLEANUP FAILED: the wait failed: {error}"),
            Err(_) => format!(
                "CLEANUP FAILED: the reap did not finish within {REAP_BUDGET:?}"
            ),
        };
        match kill {
            Ok(()) => format!("{step}: a stop was requested and the child {outcome}{poll_note}"),
            Err(error) => format!(
                "{step}: the kill request failed ({error}) and the child {outcome}{poll_note}"
            ),
        }
    }

    /// Joins both pipe readers after the child is gone and returns what they captured.
    async fn read_output(&mut self) -> Result<(String, String), String> {
        for (reader, stream) in [
            (self.stdout_reader.take(), "stdout"),
            (self.stderr_reader.take(), "stderr"),
        ] {
            let Some(reader) = reader else { continue };
            match tokio::time::timeout(REAP_BUDGET, reader).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    return Err(format!("read the Shared Runtime {stream}: {error}"))
                }
                Ok(Err(join_error)) => {
                    return Err(format!(
                        "join the Shared Runtime {stream} reader: {join_error}"
                    ))
                }
                Err(_) => {
                    return Err(format!(
                        "the Shared Runtime {stream} reader did not finish after the child exited"
                    ))
                }
            }
        }
        Ok((take_text(&self.stdout_text), take_text(&self.stderr_text)))
    }

    /// The log text this child appended, which is this phase's own site evidence.
    fn log_text(&self, label: &str) -> Result<String, String> {
        let path = self
            .log_root
            .join(format!("shared-runtime-{}", self.pid))
            .join("app.log");
        let after = std::fs::read_to_string(&path)
            .map_err(|error| format!("{label}: read the Shared Runtime log {path:?}: {error}"))?;
        // A recycled process id would make the file older than this child, so a file that
        // existed before contributes only its suffix; a fresh file is this child's in full. A
        // rewritten file is reported instead of unwinding, because the caller still owns the
        // child on this path.
        match self.logs_before.get(&path) {
            None => Ok(after),
            Some(previous) => after
                .strip_prefix(previous.as_str())
                .map(str::to_owned)
                .ok_or_else(|| {
                    format!(
                        "{label}: the Shared Runtime log {path:?} was rewritten instead of \
                         extended ({} bytes before, {} after)",
                        previous.len(),
                        after.len()
                    )
                }),
        }
    }
}

impl Drop for SharedService {
    fn drop(&mut self) {
        // A failing assertion unwinds before the owned exit path, so this asks the child to
        // stop and hands the wait to the runtime. Nothing can be awaited from a synchronous
        // drop, so this is best effort: it cannot promise that the child was reaped. The owned
        // path above does the bounded, checked wait.
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

/// Appends every line of `reader` to `sink` until the pipe closes.
///
/// A read error is returned instead of being treated as a clean end, and the join in
/// [`SharedService::read_output`] propagates it: a capture that never happened must not pass
/// for an empty stream.
async fn drain_lines<R>(reader: R, sink: Arc<Mutex<String>>) -> io::Result<()>
where
    R: AsyncRead + Unpin,
{
    let mut reader = BufReader::new(reader);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line).await {
            Ok(0) => return Ok(()),
            Ok(_) => sink
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push_str(&line),
            Err(error) => return Err(error),
        }
    }
}

/// A reader that fails on its first poll, standing in for a broken pipe.
struct FailingReader;

impl AsyncRead for FailingReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "simulated pipe failure",
        )))
    }
}

/// The text a pipe reader captured so far, without consuming it.
fn text_of(sink: &Mutex<String>) -> String {
    sink.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

/// Takes the text a pipe reader captured, leaving the buffer empty.
fn take_text(sink: &Mutex<String>) -> String {
    std::mem::take(&mut *sink.lock().unwrap_or_else(|poisoned| poisoned.into_inner()))
}
