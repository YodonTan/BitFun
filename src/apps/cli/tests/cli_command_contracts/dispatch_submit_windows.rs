//! Windows platform-gate contract for the target-side `dispatch submit` command.
//!
//! Detached dispatch workers are a Linux/macOS capability: `runner::is_supported()`
//! is compiled from `cfg!(any(target_os = "linux", target_os = "macos"))`, and the
//! submit handler answers the refusal before it opens the dispatch store. A target
//! that cannot detach must therefore reject a structurally valid submit and leave
//! no durable job, no queued state, and no worker behind. Accepting the job instead
//! would hand the controller a job that nothing on this machine can ever run.
//!
//! This module is only compiled on Windows (the `mod` declaration in
//! `cli_command_contracts.rs` carries the gate). It pins the Windows refusal and its
//! no-side-effect boundary only: real Linux/macOS worker startup and liveness are not
//! covered here and remain unverified, left to a later Unix slice.

#[path = "../support/mod.rs"]
mod support;

use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::Duration;

use openbitfun_services_core::dispatch_contract::DISPATCH_PROTOCOL_VERSION;
use support::{command_output_with_timeout, CliTestEnvironment};

const SUBMIT_JOB_ID: &str = "windows-platform-gate-job";
const SUBMIT_SESSION_ID: &str = "windows-platform-gate-session";

/// The complete wire body a controller sends, built from the shared protocol
/// version so the request stays valid as the protocol advances.
///
/// Every field is a real one: the point of this test is that the refusal is the
/// platform gate and not request validation. The workspace is the isolated test
/// workspace, so the payload would also pass the later canonicalization step.
fn submit_request_body(environment: &CliTestEnvironment) -> String {
    serde_json::json!({
        "protocolVersion": DISPATCH_PROTOCOL_VERSION,
        "jobId": SUBMIT_JOB_ID,
        "sessionId": SUBMIT_SESSION_ID,
        "workspacePath": environment.workspace().to_string_lossy(),
        "agentType": "Standard",
        "prompt": "Report whether this target can run a detached dispatch worker.",
        "approvalPolicy": "reject-and-report",
        "title": "Windows dispatch platform gate",
    })
    .to_string()
}

/// Runs the real binary's target-side `dispatch submit` with the request on stdin.
///
/// The body goes through a file redirected into the child's stdin, which keeps it
/// a real non-terminal stdin payload while letting the shared timeout helper reap
/// the process.
fn run_dispatch_submit(environment: &CliTestEnvironment) -> Output {
    let request_path = environment.user_root().join("dispatch-submit-request.json");
    std::fs::write(&request_path, submit_request_body(environment))
        .expect("write the dispatch submit request body");
    let stdin = std::fs::File::open(&request_path).expect("reopen the dispatch submit request");

    let mut command = environment.std_command();
    command.args(["dispatch", "submit"]);
    command.stdin(Stdio::from(stdin));
    command_output_with_timeout(&mut command, Duration::from_secs(120))
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Reads the protocol envelope the dispatch handler prints on its result channel.
fn protocol_envelope(output: &Output) -> serde_json::Value {
    stdout(output)
        .lines()
        .rev()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .unwrap_or_else(|| {
            panic!(
                "dispatch submit wrote no JSON protocol envelope\nstdout:\n{}\nstderr:\n{}",
                stdout(output),
                stderr(output)
            )
        })
}

/// Only the identifying words of the refusal are asserted; the wording around
/// them is the CLI's to change.
fn assert_platform_gate_refusal(message: &str, channel: &str) {
    assert!(
        message.contains("detached workers"),
        "the {channel} does not report the detached-worker platform gate: {message}"
    );
    assert!(
        message.contains("Linux and macOS"),
        "the {channel} does not name the platforms that can run a detached worker: {message}"
    );
}

/// Finds files with `name` anywhere under `root`, so a durable job record cannot
/// hide in a nested directory layout this test did not predict.
fn files_named(root: &Path, name: &str) -> Vec<PathBuf> {
    fn walk(directory: &Path, name: &str, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if file_type.is_dir() {
                walk(&path, name, found);
            } else if path.file_name().and_then(|value| value.to_str()) == Some(name) {
                found.push(path);
            }
        }
    }

    let mut found = Vec::new();
    walk(root, name, &mut found);
    found
}

/// Rejecting the job before it is durable is what keeps a controller from owning a
/// job this host can never run.
///
/// The submit handler validates the request, then checks the platform gate, and
/// only then opens the dispatch store, commits the job record, and starts a
/// detached worker. Every assertion below reads a production side effect from that
/// ordered path: the process result, the durable store directory the store creates
/// eagerly on open, and the persisted job record.
///
/// This fixture writes no model configuration, and the refusal assertion pins the
/// ordering that keeps a provider out of the run: the platform gate answers before
/// the handler reaches model selection or `AIClientFactory` initialization, so no
/// target provider client is constructed and no provider request can be attempted.
/// That boundary follows from the production path the refusal proves; it is not a
/// measurement of network traffic.
#[test]
fn dispatch_submit_refuses_a_valid_job_before_persisting_it_or_spawning_a_worker() {
    let environment = CliTestEnvironment::new();

    let output = run_dispatch_submit(&environment);

    // The real target-side entry point refuses instead of accepting the job.
    assert!(
        !output.status.success(),
        "dispatch submit accepted a job on Windows\nstdout:\n{}\nstderr:\n{}",
        stdout(&output),
        stderr(&output)
    );
    let envelope = protocol_envelope(&output);
    assert_eq!(
        envelope["protocolVersion"].as_u64(),
        Some(u64::from(DISPATCH_PROTOCOL_VERSION)),
        "the failure did not come from the dispatch protocol handler: {envelope}"
    );
    let refusal = envelope["error"].as_str().unwrap_or_else(|| {
        panic!("the dispatch protocol envelope carried no error message: {envelope}")
    });
    assert_platform_gate_refusal(refusal, "protocol envelope");
    assert!(
        envelope.get("accepted").is_none(),
        "a refusal must not report an accepted job: {envelope}"
    );
    assert!(
        envelope.get("jobId").is_none(),
        "a refusal must not report a durable job identity: {envelope}"
    );
    assert_platform_gate_refusal(&stderr(&output), "process diagnostics");

    // No dispatch state was created. `DispatchStore::open` creates its root and
    // child directories eagerly, and `PathManager`'s E2E product home override
    // points `product_home_dir()` exactly at this environment's home root, so an
    // absent `dispatch/` there proves the rejected submit never opened the store.
    // The job record scan is a second, layout-independent check that no job was
    // committed anywhere under the isolated roots.
    let dispatch_root = environment.home_root().join("dispatch");
    assert!(
        !dispatch_root.exists(),
        "the rejected submit created dispatch store state at {}",
        dispatch_root.display()
    );
    for root in [environment.home_root(), environment.user_root()] {
        let records = files_named(root, "job.json");
        assert!(
            records.is_empty(),
            "the rejected submit persisted a dispatch job record: {records:?}"
        );
    }

    // Per the notes above, the fixture configured no model and the refusal came
    // back before model selection, so no target provider client was constructed in
    // this run.
}
