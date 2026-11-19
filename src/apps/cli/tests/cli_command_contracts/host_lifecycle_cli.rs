//! Workspace intelligence host lifecycle driven through the shipped CLI binary.
//!
//! Every test starts the real binary in a child process and then reads the
//! persisted documents the host and the fixture write, plus the host's own log
//! inside the child's isolated user-data root. Ownership is checked by a host this
//! process bootstraps on the same root after the child is gone, so nothing here
//! encodes how a scope or an anchor is stored. Every root is a temporary
//! directory, so no test touches the user's own data, and the child each test
//! starts is the only process it waits for.

#[path = "../support/mod.rs"]
mod support;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use openbitfun_core::infrastructure::PathManager;
use openbitfun_core::service::workspace_intelligence::host_fixture;
use openbitfun_core::service::workspace_intelligence::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostSurface,
};
use openbitfun_services_core::exclusive_file_lease::ExclusiveFileLease;
use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
use serde_json::json;
use support::{MockOpenAiServer, STREAM_COMPLETED_MARKER};

/// Persisted workspace id of the scope these tests name.
const WORKSPACE_ID: &str = "cli-e2e-workspace";

/// Explicit session id, so two invocations emit byte-identical stdout.
const SESSION_ID: &str = "cli-e2e-session";

/// Prompt of the child invocation.
const PROMPT: &str = "workspace intelligence host lifecycle probe";

/// Field the host writes when a placement is decided.
const PLACEMENT_FIELD: &str = "host_placement=";

/// Field the host writes when the shutdown path has drained it.
const DRAIN_FIELD: &str = "host_drain=";

/// Value code of an admitted placement.
const INSTALL_CODE: &str = "install";

/// Value code of a drain that stopped with no outstanding owner work.
const DRAINED_CODE: &str = "drained";

/// How long a child may take to reach the model, and to finish afterwards.
const CHILD_TIMEOUT: Duration = Duration::from_secs(120);

/// One invocation's own isolated roots.
///
/// The workspace directory is passed in so that two invocations of one test share
/// the same workspace and differ only in their host root.
struct Invocation {
    user_root: PathBuf,
    home_root: PathBuf,
    config_root: PathBuf,
}

impl Invocation {
    fn new(base: &Path, name: &str) -> Self {
        let user_root = base.join(format!("{name}-user-root"));
        let home_root = base.join(format!("{name}-home"));
        let config_root = base.join(format!("{name}-config"));
        for root in [&home_root, &config_root] {
            std::fs::create_dir_all(root).expect("create an isolated root");
        }
        Self {
            user_root,
            home_root,
            config_root,
        }
    }

    /// The user-data root the host anchors on, as the CLI composes it.
    fn paths(&self) -> Arc<PathManager> {
        host_fixture::test_path_manager(&self.user_root)
    }

    /// The shipped binary as `exec` in `workspace`, not yet started.
    fn command(&self, workspace: &Path) -> std::process::Command {
        let mut command = openbitfun_services_core::process_manager::create_command(env!(
            "CARGO_BIN_EXE_openbitfun"
        ));
        command
            .args([
                "exec",
                PROMPT,
                "--output-format",
                "json",
                "--session-id",
                SESSION_ID,
            ])
            .current_dir(workspace)
            .env_remove("OPENBITFUN_USER_ROOT")
            .env_remove("OPENBITFUN_HOME")
            .env("OPENBITFUN_E2E_STORAGE_GUARD", "1")
            .env("OPENBITFUN_E2E_USER_ROOT", &self.user_root)
            .env("OPENBITFUN_E2E_HOME", &self.home_root)
            .env("APPDATA", &self.config_root)
            .env("XDG_CONFIG_HOME", &self.config_root)
            .env("HOME", &self.home_root);
        command
    }

    /// Runs the shipped binary as `exec` in `workspace`.
    fn run(&self, workspace: &Path) -> Output {
        self.command(workspace)
            .output()
            .expect("run the CLI exec command")
    }

    /// Points the child at a local mock model, inside this invocation's own root.
    ///
    /// The shape is the one the shared CLI test environment writes: one
    /// OpenAI-compatible model, no session title generation, a single round.
    fn configure_mock_model(&self, server_base_url: &str) {
        let config_dir = self.user_root.join("config");
        std::fs::create_dir_all(&config_dir).expect("create the model config directory");
        let base_url = format!("{}/v1", server_base_url.trim_end_matches('/'));
        let request_url = format!("{base_url}/chat/completions");
        let mut config =
            serde_json::to_value(openbitfun_core::service::config::GlobalConfig::default())
                .expect("serialize the default CLI config");
        config["app"]["ai_experience"]["enable_session_title_generation"] = json!(false);
        config["ai"]["models"] = json!([{
            "id": "cli-e2e-model",
            "name": "CLI E2E Model",
            "provider": "openai",
            "model_name": "cli-e2e-model",
            "base_url": base_url,
            "request_url": request_url,
            "api_key": "cli-e2e-key",
            "enabled": true,
            "category": "general_chat",
            "capabilities": ["text_chat", "function_calling"]
        }]);
        config["ai"]["default_models"] = json!({
            "primary": "cli-e2e-model",
            "fast": "cli-e2e-model"
        });
        config["ai"]["agent_model_defaults"] = json!({
            "mode": "cli-e2e-model"
        });
        config["ai"]["max_rounds"] = json!(1);
        config["ai"]["stream_idle_timeout_secs"] = json!(30);
        config["ai"]["stream_ttft_timeout_secs"] = json!(30);
        std::fs::write(
            config_dir.join("app.json"),
            serde_json::to_vec_pretty(&config).expect("serialize the model config"),
        )
        .expect("write the model config");
    }
}

/// Creates one shared workspace directory for a test.
fn shared_workspace(base: &Path) -> PathBuf {
    let workspace = base.join("workspace");
    std::fs::create_dir_all(&workspace).expect("create the probe workspace");
    workspace
}

/// Every control record under `root`, keyed by relative path, with its bytes.
///
/// Only documents are collected: a lock file is not a control record and the host
/// never rewrites one either way.
fn control_records(root: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("read a control directory entry").path();
            if path.is_dir() {
                walk(root, &path, out);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("control record inside its root")
                .to_string_lossy()
                .into_owned();
            out.push((relative, std::fs::read(&path).expect("read a control record")));
        }
    }

    let mut out = Vec::new();
    walk(root, root, &mut out);
    out.sort_by(|left, right| left.0.cmp(&right.0));
    out
}

/// Entry names directly inside `root`, or an empty set when it does not exist.
fn top_level(root: &Path) -> BTreeSet<String> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return BTreeSet::new();
    };
    entries
        .map(|entry| {
            entry
                .expect("read a namespace entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// The `.lock` files inside the host's lease root.
///
/// Discovered by directory enumeration, so nothing here encodes how a scope key or
/// a lease name is derived.
fn lease_files(paths: &PathManager) -> Vec<PathBuf> {
    let root = paths.workspace_intelligence_lease_dir();
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

/// Everything the child wrote to its own log files under `user_root`.
///
/// A non-interactive command logs to files, not to stderr, so the lifecycle a child
/// reports about itself is only visible here.
fn child_log_text(user_root: &Path) -> String {
    fn walk(dir: &Path, out: &mut String) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("read a log directory entry").path();
            if path.is_dir() {
                walk(&path, out);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("log") {
                continue;
            }
            let bytes = std::fs::read(&path).expect("read a log file");
            out.push_str(&String::from_utf8_lossy(&bytes));
            out.push('\n');
        }
    }

    let mut out = String::new();
    walk(&user_root.join("cli-logs"), &mut out);
    out
}

/// Lines of `text` that carry `needle`.
fn lines_with<'a>(text: &'a str, needle: &str) -> Vec<&'a str> {
    text.lines()
        .filter(|line| line.contains(needle))
        .collect()
}

/// Bootstraps a host on `paths` and reports the status it reaches.
///
/// This process asks the same public entry point the CLI uses, so the answer is the
/// host's own view of who owns the enabled scope now.
async fn observer_status(paths: Arc<PathManager>) -> (WorkspaceIntelligenceHostState, usize) {
    let observer = WorkspaceIntelligenceHost::bootstrap(
        paths,
        None,
        WorkspaceIntelligenceHostSurface::CliInteractive,
        RuntimeDeployment::Embedded,
    )
    .await;
    let status = observer.status().await;
    let observed = (status.state(), status.counts().active());
    let _ = observer.shutdown().await;
    observed
}

/// Waits for the child to reach the model, or reports that it never did.
fn wait_for_model_request(child: &mut std::process::Child, server: &MockOpenAiServer) {
    let deadline = Instant::now() + CHILD_TIMEOUT;
    loop {
        if !server.chat_completion_request_bodies().is_empty() {
            return;
        }
        if let Some(status) = child.try_wait().expect("poll the CLI process") {
            panic!("the child exited with {status:?} before it reached the model");
        }
        assert!(
            Instant::now() < deadline,
            "the child never reached the model within {CHILD_TIMEOUT:?}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Asserts the child stopped the host it admitted exactly once.
fn assert_one_drain(logs: &str) {
    let drain_lines = lines_with(logs, DRAIN_FIELD);
    assert_eq!(
        drain_lines.len(),
        1,
        "an admitted host reports exactly one drain before the process leaves: {logs}"
    );
    assert!(
        drain_lines[0].contains(DRAINED_CODE),
        "the drain must report the drained code: {}",
        drain_lines[0]
    );
    let placement_lines = lines_with(logs, PLACEMENT_FIELD);
    assert!(
        placement_lines
            .iter()
            .any(|line| line.contains(INSTALL_CODE)),
        "the child must log the admission it made: {logs}"
    );
}

#[tokio::test]
async fn a_real_cli_exec_publishes_a_claim_for_a_seeded_scope_and_drains_it() {
    let temp = tempfile::tempdir().expect("create an isolated probe root");
    let workspace = shared_workspace(temp.path());
    // The baseline invocation runs the same binary with the same arguments in the
    // same workspace on a root that carries neither a workspace record nor an
    // anchor, so its stdout is what the CLI emits without any host state to find.
    let baseline_invocation = Invocation::new(temp.path(), "baseline");
    let treated_invocation = Invocation::new(temp.path(), "enabled");

    let treated_paths = treated_invocation.paths();
    host_fixture::seed_local_workspace(treated_paths.as_ref(), WORKSPACE_ID, &workspace)
        .await
        .expect("seed the workspace record");
    let seeded = host_fixture::enable_workspace(treated_paths.as_ref(), WORKSPACE_ID)
        .await
        .expect("enable the seeded workspace");
    assert_eq!(seeded.workspace_id(), WORKSPACE_ID);
    assert_eq!(
        seeded.generation(),
        1,
        "the fixture enables the seeded scope in one control generation"
    );

    let control_before = control_records(&treated_paths.workspace_intelligence_control_dir());
    assert!(
        !control_before.is_empty(),
        "an enabled scope must leave exactly one control record to compare against"
    );
    let namespace_before = top_level(&treated_paths.workspace_intelligence_dir());

    let baseline = baseline_invocation.run(&workspace);
    let treated = treated_invocation.run(&workspace);

    // Process termination releases every OS lock the child held, so an acquirable
    // lease here only says the child is gone. What the drain did is asserted from
    // the child's own log below; these two lines pin that the lease exists and that
    // nothing in this process still holds it.
    let locks = lease_files(treated_paths.as_ref());
    assert_eq!(
        locks.len(),
        1,
        "one enabled scope takes exactly one lease file: {locks:?}"
    );
    let released = ExclusiveFileLease::try_acquire(&locks[0])
        .expect("a terminated process holds no scope lease");
    drop(released);

    // The shutdown path ran in the child: its own log carries the drain line, with
    // the code this module reports for a drain that had nothing outstanding.
    let logs = child_log_text(&treated_invocation.user_root);
    assert_one_drain(&logs);

    // The claim really happened and was really released: a host of this process now
    // owns the scope the child held, which no other process can do while a claim is
    // still held.
    let (state, active) = observer_status(Arc::clone(&treated_paths)).await;
    assert_eq!(
        state,
        WorkspaceIntelligenceHostState::Active,
        "the scope must be owned by this process once the child released it"
    );
    assert_eq!(active, 1, "exactly the seeded scope is owned");

    // The host wrote no byte to stdout and changed no exit status.
    assert_eq!(
        treated.status.code(),
        baseline.status.code(),
        "placing the host must not change the exit status; stderr: {}",
        String::from_utf8_lossy(&treated.stderr)
    );
    assert_eq!(
        treated.stdout, baseline.stdout,
        "placing the host must not add one stdout byte; baseline stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );

    // The host never writes control: every record is byte-identical to the seed.
    assert_eq!(
        control_records(&treated_paths.workspace_intelligence_control_dir()),
        control_before,
        "the host must never write a control record"
    );

    // Nothing appeared in the host namespace outside its own member roots.
    let added: BTreeSet<String> = top_level(&treated_paths.workspace_intelligence_dir())
        .difference(&namespace_before)
        .cloned()
        .collect();
    let allowed: BTreeSet<String> = ["control", "cognition", "lease"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert!(
        added.is_subset(&allowed),
        "the host wrote outside its member roots: {added:?}"
    );
    assert!(
        added.contains("lease"),
        "an admitted host takes a lease: {added:?}"
    );
}

/// The real sequence: a turn is in flight, the child leaves, and the scope is free.
///
/// The mock model holds the stream open, so the child is inside a real interactive
/// turn while its host is admitted, instead of failing before the surface is
/// reached. After the turn is released the child stops its host, and a host of this
/// process takes the scope over.
#[tokio::test]
async fn a_real_cli_exec_holding_a_turn_drains_and_hands_the_scope_over() {
    let temp = tempfile::tempdir().expect("create an isolated probe root");
    let workspace = shared_workspace(temp.path());
    let invocation = Invocation::new(temp.path(), "held");

    let paths = invocation.paths();
    host_fixture::seed_local_workspace(paths.as_ref(), WORKSPACE_ID, &workspace)
        .await
        .expect("seed the workspace record");
    host_fixture::enable_workspace(paths.as_ref(), WORKSPACE_ID)
        .await
        .expect("enable the seeded workspace");
    let control_before = control_records(&paths.workspace_intelligence_control_dir());

    let server = MockOpenAiServer::gated();
    invocation.configure_mock_model(server.base_url());

    let mut child = invocation
        .command(&workspace)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the CLI exec command");
    wait_for_model_request(&mut child, &server);

    // The turn is in flight and the child is still running: this is the window the
    // host exists in, not a startup that failed before the exec surface.
    assert!(
        child.try_wait().expect("poll the CLI process").is_none(),
        "the child must still be running while its turn is held"
    );

    // Two releases: the gated stream pauses twice before it completes.
    server.release();
    server.release();
    let output = child.wait_with_output().expect("wait for the CLI exec command");

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    assert!(
        stdout.contains(STREAM_COMPLETED_MARKER),
        "the held turn must complete once released: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let logs = child_log_text(&invocation.user_root);
    assert!(
        lines_with(&logs, PLACEMENT_FIELD)
            .iter()
            .any(|line| line.contains(INSTALL_CODE)),
        "the child must log the admission it made: {logs}"
    );
    let drain_lines = lines_with(&logs, DRAIN_FIELD);
    assert_eq!(
        drain_lines.len(),
        1,
        "a host admitted for a real turn reports exactly one drain: {logs}"
    );
    assert!(
        drain_lines[0].contains(DRAINED_CODE),
        "a real turn leaves no owner work behind: {}",
        drain_lines[0]
    );

    let locks = lease_files(paths.as_ref());
    assert_eq!(
        locks.len(),
        1,
        "one enabled scope takes exactly one lease file: {locks:?}"
    );
    let released = ExclusiveFileLease::try_acquire(&locks[0])
        .expect("a terminated process holds no scope lease");
    drop(released);

    let (state, active) = observer_status(Arc::clone(&paths)).await;
    assert_eq!(
        state,
        WorkspaceIntelligenceHostState::Active,
        "a host of this process owns the scope once the child is gone"
    );
    assert_eq!(active, 1, "exactly the seeded scope is owned");
    assert_eq!(
        control_records(&paths.workspace_intelligence_control_dir()),
        control_before,
        "a real turn and its drain write no control record"
    );
}

#[tokio::test]
async fn a_real_cli_off_invocation_creates_no_workspace_intelligence_writes() {
    let temp = tempfile::tempdir().expect("create an isolated probe root");
    let workspace = shared_workspace(temp.path());
    let baseline_invocation = Invocation::new(temp.path(), "baseline");
    let off_invocation = Invocation::new(temp.path(), "off");

    // A seeded workspace record without an enable: no anchor, no control record and
    // therefore no scope this build can claim.
    let off_paths = off_invocation.paths();
    host_fixture::seed_local_workspace(off_paths.as_ref(), WORKSPACE_ID, &workspace)
        .await
        .expect("seed the workspace record");
    assert!(
        !off_paths.workspace_intelligence_dir().exists(),
        "seeding a workspace record must not create the host namespace"
    );

    let baseline = baseline_invocation.run(&workspace);
    let off = off_invocation.run(&workspace);

    // Equal output on its own is satisfied by two runs that both fail early, so pin
    // that this child really reached the exec surface: the session id it was given
    // only appears once that session exists.
    let off_stdout = String::from_utf8_lossy(&off.stdout).into_owned();
    assert!(
        off_stdout.contains(SESSION_ID),
        "the child must reach the exec surface and name its session: {off_stdout}"
    );

    assert_eq!(
        off.status.code(),
        baseline.status.code(),
        "refusing the host must not change the exit status; stderr: {}",
        String::from_utf8_lossy(&off.stderr)
    );
    assert_eq!(
        off.stdout, baseline.stdout,
        "refusing the host must not add one stdout byte; baseline stderr: {}",
        String::from_utf8_lossy(&baseline.stderr)
    );
    assert!(
        !off_paths.workspace_intelligence_dir().exists(),
        "an invocation with no enabled scope must write no anchor, no lease and no cognition record"
    );
}
