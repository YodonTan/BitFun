//! Process-level evidence for the loopback Server's workspace intelligence exit path.
//!
//! The unit tests beside `src/workspace_intelligence.rs` prove the placement, the
//! drain and the release on this crate's own API. They cannot show that the shipped
//! `openbitfun-server` binary admits the host and runs the one awaited drain `main`
//! arms: this file spawns the binary cargo just built and reads the process, its two
//! streams and the isolated user-data root it wrote.
//!
//! The three origin-screen tests below drive one real command:
//! `--allowed-origin ftp://localhost:1422`.
//! The startup sequence refuses that value *after* `bootstrap::initialize` (which is
//! where the host is admitted) and *before* the loopback listener binds, before the
//! SSH store is resolved and before `dirs::data_local_dir()` is read, so the exit is
//! deterministic, occupies no port, and reaches the release path `main` runs on every
//! way out of the serve body. It is not a clap parse failure: clap accepts the value,
//! the origin screen rejects it, so the process ends on the same `anyhow` refusal in
//! every build and a build with the host body has already admitted the host by then.
//!
//! No user-specified workspace is passed: the child is started without `--workspace`,
//! so no operator-chosen root is opened. The workspace owner may still create or
//! activate the isolated assistant workspace inside its own user-data root, and the
//! host then enumerates whatever the persisted catalog holds for that root. The tests
//! below therefore never claim that the child's `initial_workspace` is `None`; they
//! only use the catalog they seeded, or the absence of any seeded record.
//!
//! The three cases are the two feature selections and the two runtimes:
//!
//! - default features, seeded and enabled scope: the claim happens, the error exit
//!   drains it, and the same root can be claimed again afterwards;
//! - default features, unenabled root: the host is admitted and drained exactly like
//!   the first case, and nothing is claimed, because no scope is enabled;
//! - `--no-default-features`: the same exit reports the typed `NotCompiled` refusal
//!   and creates no host namespace entry at all.
//!
//! One `#[cfg(windows)]` case joins the default-feature runtime: the same real process,
//! admitted on the same isolated root with an enabled scope, started without
//! `--allowed-origin` so the product's own defaults pass the origin screen, and run
//! while this test holds `127.0.0.1:8080` so the listener's `TcpListener::bind` fails
//! after the host was admitted. That case proves exactly one non-interactive exit path —
//! the listener's own bind error on Windows — and nothing about Ctrl+C, about any other
//! way out of `main`, or about a Unix target. It is not compiled on a non-Windows host,
//! so no run there is evidence in either direction.
//!
//! # What is and is not claimed
//!
//! The refusal is printed on stderr and the drain row on stdout, and two pipes carry
//! no total order. No assertion here compares their arrival; attribution comes from
//! each stream's own content: the refusal line identifies the error exit, and the one
//! parsed `host_drain` field identifies the lifecycle result of the admission. That
//! field is only read from the `INFO openbitfun_server:` record `main` writes, carrying
//! the message once at its payload position; another level, another target, a repeated
//! message or a sentence embedded in other text is not that record.
//!
//! `drained` is also the code an admitted but inactive host reports, so that code
//! alone never proves ownership: the first case pairs it with the claim products the
//! child left behind (a cognition partition and an owner lease document) and with a
//! second admission that reports the scope `active`. The second case pairs the same
//! code with the absence of every such product, which is why it is asserted as its own
//! baseline instead of being folded into the first.
//!
//! # Cleanup is bounded, not absolute
//!
//! A failed run attempts to stop and reap its own child inside one budget and reports
//! the attempt's outcome; it never claims the operating system has no process left. A
//! timed out parent-side step cancels its future, which does not terminate blocking work
//! that already started, and the runtime stop bounds how long this fixture waits for it
//! instead of guaranteeing it has finished.
//!
//! # Isolation
//!
//! Every root the child can reach through `PathManager`'s documented environment
//! contract lives under one temporary directory, the two unguarded override names the
//! isolation must not inherit are removed, `OPENBITFUN_E2E_STORAGE_GUARD` makes a
//! missing root a loud startup failure instead of a silent fallback, and
//! `OPENBITFUN_MODELS_DEV_PATH` points at the repository's bundled models.dev document
//! so no refresh source can be the HTTP default. No assertion here is evidence about
//! the developer's real storage when the child is not sandboxed: the boundary comes
//! from the paths the child can resolve, which the tests above pin to one temporary
//! root.

use std::any::Any;
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

/// One argument value the startup sequence refuses after bootstrapping the runtime.
const INVALID_ORIGIN: &str = "ftp://localhost:1422";

/// The exact stderr line a `main` returning this `anyhow` error prints.
const EXPECTED_ERROR: &str = "Error: --allowed-origin must use http or https";

/// The payload message of the one drain row `main` logs on every exit from the serve body.
const DRAIN_MESSAGE: &str = "Workspace intelligence host drained";

/// The field name that row carries the lifecycle code in.
const DRAIN_FIELD: &str = "host_drain=";

/// The level token of the record that carries the drain message.
const DRAIN_LEVEL: &str = "INFO";

/// The target token of the record that carries the drain message: it is `main` itself,
/// so a record from any other target is not the drain row even when it repeats the text.
const DRAIN_TARGET: &str = "openbitfun_server:";

/// The startup banner `main` logs before it parses arguments.
const STARTUP_BANNER: &str = "OpenBitFun Server v";

/// The bootstrap line that names the placement this app resolved.
const PLACEMENT_MESSAGE: &str = "workspace intelligence host placement resolved";

/// Listener-section banners. Each is logged at or after the origin screen and before
/// the listener binds, so none of them may appear on a path that ends at that screen.
const LISTENER_BANNERS: [&str; 4] = [
    "Server started: http://",
    "WebSocket endpoint: ws://",
    "Health check: http://",
    "Browser origin policy configured",
];

/// Lifecycle codes this host can log for a drain.
const DRAINED_CODE: &str = "drained";
const DRAIN_TIMED_OUT_CODE: &str = "drain_timed_out";
const NOT_INSTALLED_CODE: &str = "not_installed";
const NOT_COMPILED_CODE: &str = "not_compiled";

/// The loopback port the shipped `main` binds unconditionally. The bind case has to hold
/// it, so it is the one machine precondition this file does not own itself.
#[cfg(all(windows, feature = "workspace-intelligence-host"))]
const LOOPBACK_PORT: u16 = 8080;

/// The stable Windows token of a bind on an address another socket holds. The sentence in
/// front of it is the platform's localized text and is never compared.
#[cfg(all(windows, feature = "workspace-intelligence-host"))]
const WINDOWS_ADDR_IN_USE_TOKEN: &str = "(os error 10048)";

/// Absolute budget for the whole test: the child run, both stream drains and every
/// blocking wait on the parent side. A step that outlives it fails; none may hang.
const DEADLINE: Duration = Duration::from_secs(120);

/// Budget for stopping and reaping one child. It is deliberately separate from the
/// run deadline: cleanup is bounded on its own so it can never extend the run.
const CLEANUP_BUDGET: Duration = Duration::from_secs(10);

/// How often the child's exit is polled while it runs.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Upper bound on one captured stream. The child's logs are a few kilobytes; a stream
/// that grows past this is either a runaway or not the output this test expects, and
/// silently truncating it would make an assertion read a different document.
const OUTPUT_CAP: usize = 8 * 1024 * 1024;

/// One isolated storage layout the child is pointed at.
struct IsolatedStorage {
    temp: tempfile::TempDir,
}

impl IsolatedStorage {
    fn new() -> Self {
        Self {
            temp: tempfile::tempdir().expect("an isolated temporary root"),
        }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }

    /// The user root `PathManager` resolves from `OPENBITFUN_E2E_USER_ROOT`.
    fn user_root(&self) -> PathBuf {
        self.root().join("user")
    }

    /// The product home `PathManager` resolves from `OPENBITFUN_E2E_HOME`.
    fn home_root(&self) -> PathBuf {
        self.root().join("home")
    }

    fn roaming_app_data(&self) -> PathBuf {
        self.root().join("appdata-roaming")
    }

    fn local_app_data(&self) -> PathBuf {
        self.root().join("appdata-local")
    }

    fn xdg_config(&self) -> PathBuf {
        self.root().join("xdg-config")
    }

    fn xdg_data(&self) -> PathBuf {
        self.root().join("xdg-data")
    }

    fn xdg_cache(&self) -> PathBuf {
        self.root().join("xdg-cache")
    }

    fn scratch_dir(&self) -> PathBuf {
        self.root().join("tmp")
    }

    /// The working directory the child runs in. It is the same isolated root, so no
    /// relative path the child resolves can land outside it.
    fn working_dir(&self) -> PathBuf {
        self.root().join("workspace")
    }

    fn prepare(&self) {
        for directory in [
            self.user_root(),
            self.home_root(),
            self.roaming_app_data(),
            self.local_app_data(),
            self.xdg_config(),
            self.xdg_data(),
            self.xdg_cache(),
            self.scratch_dir(),
            self.working_dir(),
        ] {
            std::fs::create_dir_all(&directory).expect("create an isolated storage root");
        }
    }

    /// The real Server command with this isolated storage and no argument of its own.
    fn base_command(&self) -> Command {
        let mut command = openbitfun_core::util::process_manager::create_command(env!(
            "CARGO_BIN_EXE_openbitfun-server"
        ));
        command
            .current_dir(self.working_dir())
            .env_remove("OPENBITFUN_USER_ROOT")
            .env_remove("OPENBITFUN_HOME")
            .env_remove("OPENBITFUN_MODELS_DEV_URL")
            // Fails closed when a guarded root is missing instead of letting the child
            // fall back to the developer's real user directories.
            .env("OPENBITFUN_E2E_STORAGE_GUARD", "1")
            .env("OPENBITFUN_E2E_USER_ROOT", self.user_root())
            .env("OPENBITFUN_E2E_HOME", self.home_root())
            .env("HOME", self.home_root())
            .env("USERPROFILE", self.home_root())
            .env("APPDATA", self.roaming_app_data())
            .env("LOCALAPPDATA", self.local_app_data())
            .env("XDG_CONFIG_HOME", self.xdg_config())
            .env("XDG_DATA_HOME", self.xdg_data())
            .env("XDG_CACHE_HOME", self.xdg_cache())
            .env("TMP", self.scratch_dir())
            .env("TEMP", self.scratch_dir())
            .env("TMPDIR", self.scratch_dir())
            .env("OPENBITFUN_MODELS_DEV_PATH", models_dev_asset());
        command
    }

    /// The real Server command with the one refused origin argument.
    ///
    /// The argument is added after the shared setup so the origin-screen cases keep the
    /// exact arguments and environment they had before the setup was split out.
    fn command(&self) -> Command {
        let mut command = self.base_command();
        command.arg("--allowed-origin").arg(INVALID_ORIGIN);
        command
    }

    /// The real Server command with no origin argument, so the product defaults apply.
    ///
    /// A bind failure can only be observed by a process that passes the origin screen, and
    /// the shipped defaults are the allowed origins an operator would run with.
    #[cfg(all(windows, feature = "workspace-intelligence-host"))]
    fn default_origin_command(&self) -> Command {
        self.base_command()
    }
}

/// The repository's own models.dev document, so a refresh source is a local file.
///
/// The child resolves no model on this path; this removes the HTTP default from the
/// environment rather than assuming it is never consulted.
fn models_dev_asset() -> PathBuf {
    let asset = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/services/services-integrations/assets/models-dev.json");
    asset
        .canonicalize()
        .expect("the bundled models.dev asset exists in this repository")
}

/// Holds the product's loopback port and proves this machine reports the conflict.
///
/// The shipped `main` binds `127.0.0.1:8080` unconditionally, so the bind case can only be
/// evaluated where that port is free. The returned listener is the guard: it keeps the
/// address until dropped, and the second bind inside this process is the proof that the
/// platform reports an occupied address as `AddrInUse`. A taken port, a platform that
/// accepts the second bind, or any other failure kind leaves the behavior under test
/// unevaluated, and the failure says so instead of passing.
#[cfg(all(windows, feature = "workspace-intelligence-host"))]
fn occupy_loopback_port() -> std::net::TcpListener {
    let address = (std::net::Ipv4Addr::LOCALHOST, LOOPBACK_PORT);
    let listener = match std::net::TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => panic!(
            "this machine's precondition does not hold: {address:?} must be free for the \
             bind-failure case, but it could not be bound ({error}); the bind error path was \
             not evaluated"
        ),
    };
    match std::net::TcpListener::bind(address) {
        Ok(_) => panic!(
            "this machine's precondition does not hold: a second bind of {address:?} \
             succeeded inside this process, so no address conflict can be produced here; \
             the bind error path was not evaluated"
        ),
        Err(error) if error.kind() == io::ErrorKind::AddrInUse => {}
        Err(error) => panic!(
            "this machine's precondition does not hold: a second bind of {address:?} failed \
             with {error:?} instead of AddrInUse; the bind error path was not evaluated"
        ),
    }
    listener
}

/// What one real Server process produced.
struct ServerRun {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

/// Owns the spawned child, so no exit from these helpers leaves it unattempted.
///
/// The checked paths in [`run_server`] disarm the guard only after a reap that really
/// happened, so a failed stop hands the still-owned child to this drop. The drop is the
/// bounded best effort for that case and for a test that panicked before its wait: it
/// never waits without an end, and when the process cannot be reaped inside the cleanup
/// budget it reports that instead of pretending the process is gone. Cleanup is not a
/// guarantee about the operating system, only a bounded attempt plus a logged outcome.
struct ChildGuard {
    child: Option<std::process::Child>,
}

impl ChildGuard {
    fn new(mut command: Command) -> Self {
        let child = command.spawn().expect("the real Server binary is runnable");
        Self { child: Some(child) }
    }

    fn child(&mut self) -> &mut std::process::Child {
        self.child
            .as_mut()
            .expect("the guard owns the child until it is disarmed")
    }

    fn disarm(&mut self) {
        self.child = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        if let Err(report) = stop_and_reap(&mut child, CLEANUP_BUDGET) {
            eprintln!("the test could not reap its own Server process: {report}");
        }
    }
}

/// Stops and reaps one child inside its own budget.
///
/// `kill` is a request, not a guarantee, so the process is polled with `try_wait`
/// instead of waited for: `Ok` means `try_wait` reaped it, and `Err` reports exactly
/// what was observed. No path through this function can block past its budget, and no
/// `Err` here is evidence that the process is gone.
fn stop_and_reap(child: &mut std::process::Child, budget: Duration) -> Result<(), String> {
    let deadline = Instant::now() + budget;
    let kill_error = child.kill().err().map(|error| error.to_string());
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return Ok(()),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => {
                return Err(format!(
                    "still running {budget:?} after the stop request, kill_error={kill_error:?}"
                ))
            }
            Err(error) => {
                return Err(format!(
                    "could not observe the process: {error}, kill_error={kill_error:?}"
                ))
            }
        }
    }
}

/// Fails the run after a bounded stop attempt, keeping whatever happened to the child.
///
/// The guard is given up only when the reap really happened: on a failed stop it stays
/// armed, so unwinding runs the drop's own bounded attempt and its report, and the panic
/// message carries the first attempt's result instead of losing it.
fn fail_after_stop(guard: &mut ChildGuard, reason: String) -> ! {
    let stop = stop_and_reap(guard.child(), CLEANUP_BUDGET);
    if stop.is_ok() {
        guard.disarm();
    }
    panic!("{reason}; stop and reap: {stop:?}");
}

/// Reproduces a guarded step's own outcome after its cleanup already ran.
///
/// The three arms are the three facts this fixture must keep apart: a value is the step's
/// result, an elapsed timeout is a failure of this test, and a panic payload is resumed
/// unchanged so the original failure message survives the cleanup. A panic is never
/// turned into a result, and a timeout is never turned into one either.
fn resume_after_cleanup<T, E>(
    outcome: Result<Result<T, E>, Box<dyn Any + Send>>,
    deadline: Duration,
) -> T {
    match outcome {
        Ok(Ok(value)) => value,
        Ok(Err(_)) => panic!("a parent-side step did not finish before the {deadline:?} deadline"),
        Err(payload) => std::panic::resume_unwind(payload),
    }
}

/// Runs the real Server process to its own exit and returns what it wrote.
///
/// Both pipes are drained by their own thread, so neither can fill and block the child
/// while the other is unread. Every wait is bounded by `deadline`. A timeout and a
/// failed observation alike attempt a bounded stop and reap and then fail this call with
/// both facts, because a timeout or a lost exit status is never evidence of the behavior
/// under test. The stop is an attempt: this call never claims the process is gone.
fn run_server(command: Command, deadline: Instant) -> ServerRun {
    let mut command = command;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut guard = ChildGuard::new(command);
    let stdout_reader = spawn_capture(guard.child().stdout.take().expect("a piped stdout"));
    let stderr_reader = spawn_capture(guard.child().stderr.take().expect("a piped stderr"));

    let status = loop {
        match guard.child().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            Ok(None) => fail_after_stop(
                &mut guard,
                format!("the Server process did not exit before the {DEADLINE:?} deadline"),
            ),
            Err(error) => fail_after_stop(
                &mut guard,
                format!("could not observe the Server process: {error}"),
            ),
        }
    };
    // The child was reaped by `try_wait`, so the guard must not signal a completed process.
    guard.disarm();

    let stdout = join_capture(stdout_reader, deadline, "stdout");
    let stderr = join_capture(stderr_reader, deadline, "stderr");
    ServerRun {
        status,
        stdout,
        stderr,
    }
}

fn spawn_capture(
    stream: impl Read + Send + 'static,
) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
    std::thread::spawn(move || read_capped(stream))
}

/// Reads one stream to its end, failing instead of truncating at [`OUTPUT_CAP`].
fn read_capped(mut stream: impl Read) -> io::Result<Vec<u8>> {
    let mut captured = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(captured);
        }
        if captured.len() + read > OUTPUT_CAP {
            return Err(io::Error::other(format!(
                "one Server stream exceeded {OUTPUT_CAP} bytes"
            )));
        }
        captured.extend_from_slice(&buffer[..read]);
    }
}

/// Joins one stream reader under the shared deadline and returns its styling-free text.
///
/// The join only happens once the reader reports itself finished, so this never blocks
/// on a pipe. A pipe that never closes, a read error and a panicking reader are all
/// failures: an unreadable stream must never be mistaken for an empty one.
fn join_capture(
    reader: std::thread::JoinHandle<io::Result<Vec<u8>>>,
    deadline: Instant,
    stream: &str,
) -> String {
    while !reader.is_finished() {
        assert!(
            Instant::now() < deadline,
            "the Server {stream} pipe did not close before the {DEADLINE:?} deadline"
        );
        std::thread::sleep(POLL_INTERVAL);
    }
    let captured = match reader.join() {
        Ok(result) => result,
        Err(_) => panic!("the Server {stream} reader thread panicked"),
    };
    let captured = match captured {
        Ok(bytes) => bytes,
        Err(error) => panic!("could not read the Server {stream}: {error}"),
    };
    strip_ansi(&String::from_utf8_lossy(&captured))
}

/// Removes ANSI CSI sequences from captured text.
///
/// `tracing_subscriber::fmt` styles its fields whenever the `ansi` feature is compiled
/// in, so a captured pipe can carry escape sequences. The parser below reads exact
/// tokens, so styling is removed first instead of being matched around.
fn strip_ansi(text: &str) -> String {
    let mut plain = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.peek() == Some(&'[') {
            let _ = chars.next();
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        plain.push(ch);
    }
    plain
}

/// One drain record read out of the process's two streams.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DrainRecord {
    /// Which stream carried it. Reported, never asserted: the two pipes carry no order.
    stream: &'static str,
    /// The raw record line, for failure messages.
    line: String,
    /// The field value with exactly one well-formed quoting pair removed.
    value: String,
}

/// Why the two streams do not carry exactly one well-formed drain record.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DrainParseError {
    /// No line carries the message at a record's payload position.
    NoMessage,
    /// More than one line does.
    MessageTwice { count: usize },
    /// One line repeats the message, so it is not one record with one payload.
    DuplicateMessage { line: String },
    /// The message record carries no `host_drain` field.
    MissingField { line: String },
    /// One line carries more than one `host_drain` field.
    DuplicateField { line: String },
    /// A `host_drain` field appears on a line that is not the message record.
    StrayField { line: String },
    /// The field value opens a quote it does not close, or closes one it did not open.
    UnpairedQuote { value: String },
    /// The field has no value, or a value that is not a plain identifier.
    MalformedValue { value: String },
    /// The value is not a lifecycle code this host logs for a drain.
    UnknownCode { value: String },
}

impl fmt::Display for DrainParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMessage => write!(formatter, "no drain record carries the message"),
            Self::MessageTwice { count } => {
                write!(formatter, "{count} lines carry the drain message")
            }
            Self::DuplicateMessage { line } => {
                write!(formatter, "one line repeats the drain message: {line}")
            }
            Self::MissingField { line } => {
                write!(formatter, "the drain record carries no {DRAIN_FIELD} field: {line}")
            }
            Self::DuplicateField { line } => {
                write!(formatter, "one line carries more than one {DRAIN_FIELD} field: {line}")
            }
            Self::StrayField { line } => {
                write!(formatter, "a {DRAIN_FIELD} field appears off the drain record: {line}")
            }
            Self::UnpairedQuote { value } => write!(formatter, "unpaired quoting in {value:?}"),
            Self::MalformedValue { value } => write!(formatter, "malformed field value {value:?}"),
            Self::UnknownCode { value } => write!(formatter, "unknown drain code {value:?}"),
        }
    }
}

/// Reads exactly one drain record out of both streams.
///
/// Every `host_drain=` token of both streams is counted, not just the first one found:
/// a second field on the same line, on another line or in the other stream is a parse
/// failure, and so is a field without the message record or a record without its field.
/// A record is only the `INFO openbitfun_server:` row `main` writes, carrying the
/// message once at its payload position, so another level, another target or a line that
/// repeats the sentence cannot satisfy this.
fn parse_drain_record(stdout: &str, stderr: &str) -> Result<DrainRecord, DrainParseError> {
    let mut records: Vec<(String, &'static str, Vec<String>)> = Vec::new();
    let mut stray: Option<String> = None;
    for (stream, text) in [("stdout", stdout), ("stderr", stderr)] {
        for line in strip_ansi(text).lines() {
            let line = line.trim_end().to_owned();
            if line.trim().is_empty() {
                continue;
            }
            let fields: Vec<String> = line
                .split_whitespace()
                .filter_map(|token| token.strip_prefix(DRAIN_FIELD))
                .map(str::to_owned)
                .collect();
            let mentions = line.matches(DRAIN_MESSAGE).count();
            if mentions > 1 {
                // Two messages on one line cannot be one record with one payload, so this
                // is refused even when the line also looks like the drain row.
                return Err(DrainParseError::DuplicateMessage { line });
            }
            if mentions == 1 && drain_record_tail(&line).is_some() {
                records.push((line, stream, fields));
            } else if !fields.is_empty() && stray.is_none() {
                stray = Some(line);
            }
        }
    }

    if records.is_empty() {
        return Err(match stray {
            Some(line) => DrainParseError::StrayField { line },
            None => DrainParseError::NoMessage,
        });
    }
    if records.len() > 1 {
        return Err(DrainParseError::MessageTwice {
            count: records.len(),
        });
    }
    let (line, stream, mut fields) = records.pop().expect("exactly one record");
    if fields.is_empty() {
        return Err(DrainParseError::MissingField { line });
    }
    if fields.len() > 1 {
        return Err(DrainParseError::DuplicateField { line });
    }
    if let Some(stray) = stray {
        return Err(DrainParseError::StrayField { line: stray });
    }
    let raw = fields.pop().expect("one field");
    Ok(DrainRecord {
        stream,
        line,
        value: parse_field_value(&raw)?,
    })
}

/// The text that follows the drain message when this line is that one record.
///
/// `tracing_subscriber::fmt` writes `timestamp  LEVEL target: payload`, so the message
/// position is the payload prefix directly after the target token, and the level and
/// target are the ones `main` logs. The payload is taken after the first target token and
/// the message must be its prefix: a line that repeats the target to smuggle the sentence
/// into another position has no such prefix, and a line that merely contains the sentence
/// somewhere else does not either, so neither is a record.
fn drain_record_tail(line: &str) -> Option<&str> {
    let mut tokens = line.split_whitespace();
    let _timestamp = tokens.next()?;
    let level = tokens.next()?;
    let target = tokens.next()?;
    if level != DRAIN_LEVEL || target != DRAIN_TARGET {
        return None;
    }
    let payload = line.split_once(target)?.1.trim_start();
    let tail = payload.strip_prefix(DRAIN_MESSAGE)?;
    if tail.is_empty() || tail.starts_with(char::is_whitespace) {
        Some(tail)
    } else {
        None
    }
}

/// One field value: exactly one paired quoting level, then a known lifecycle code.
fn parse_field_value(raw: &str) -> Result<String, DrainParseError> {
    let unquoted = match raw.chars().next() {
        None => return Err(DrainParseError::MalformedValue { value: raw.to_owned() }),
        Some(quote @ ('"' | '\'')) => {
            let Some(inner) = raw
                .strip_prefix(quote)
                .and_then(|rest| rest.strip_suffix(quote))
            else {
                return Err(DrainParseError::UnpairedQuote {
                    value: raw.to_owned(),
                });
            };
            // Two quoting levels, or an empty one, are not a plain value.
            if inner.is_empty() || inner.contains(quote) {
                return Err(DrainParseError::UnpairedQuote {
                    value: raw.to_owned(),
                });
            }
            if inner.contains('"') || inner.contains('\'') {
                return Err(DrainParseError::UnpairedQuote {
                    value: raw.to_owned(),
                });
            }
            inner
        }
        Some(_) => {
            // A closing quote with no opener is unpaired quoting, not a bare value.
            if raw.contains('"') || raw.contains('\'') {
                return Err(DrainParseError::UnpairedQuote {
                    value: raw.to_owned(),
                });
            }
            raw
        }
    };
    if unquoted.is_empty()
        || !unquoted
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
    {
        return Err(DrainParseError::MalformedValue {
            value: raw.to_owned(),
        });
    }
    if ![DRAINED_CODE, DRAIN_TIMED_OUT_CODE, NOT_INSTALLED_CODE, NOT_COMPILED_CODE]
        .contains(&unquoted)
    {
        return Err(DrainParseError::UnknownCode {
            value: unquoted.to_owned(),
        });
    }
    Ok(unquoted.to_owned())
}

/// Asserts the process ended on the origin refusal instead of on anything else.
///
/// The exit code is 1, which is `Termination` reporting the `anyhow` error `main`
/// returned; a clap parse failure exits 2. On Windows a killed process also carries
/// exit code 1, so the exit code alone is never the whole evidence: the refusal must be
/// the only diagnostic on stderr, and the listener banners must be absent from stdout.
/// Both are content facts of a process that ran `main` to its own error exit and never
/// reached the listener it would have logged there. This is not a socket audit; it is
/// the source order of that section read from what the process actually printed.
fn assert_origin_refusal_exit(run: &ServerRun) {
    assert!(
        run.stdout.contains(STARTUP_BANNER),
        "the real Server binary must have run its startup, stdout was:\n{}",
        run.stdout
    );
    assert_eq!(
        run.status.code(),
        Some(1),
        "the Server must exit 1 on the origin refusal, stderr was:\n{}",
        run.stderr
    );
    let diagnostics: Vec<&str> = run
        .stderr
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        diagnostics.len(),
        1,
        "the error exit must print only its refusal, stderr was:\n{}",
        run.stderr
    );
    assert_eq!(
        diagnostics[0].trim(),
        EXPECTED_ERROR,
        "the one diagnostic must be the startup refusal, stderr was:\n{}",
        run.stderr
    );
    for banner in LISTENER_BANNERS {
        assert!(
            !run.stdout.contains(banner),
            "the exit happens before the listener section, so `{banner}` must not be \
             logged; stdout was:\n{}",
            run.stdout
        );
    }
}

/// Asserts the process ended on the listener's own TCP bind failure.
///
/// This is the mirror image of the origin-screen assertions above: the listener banners are
/// logged before the bind, so they must be present here. The exit code 1 is what
/// `Termination` reports for the `anyhow` error `main` returned, but a killed process also
/// carries it on Windows, so it is paired with stderr: exactly one diagnostic, the `Error: `
/// line, carrying the stable Windows occupied-address token. The localized sentence in front
/// of that token is the platform's own text and is never compared.
#[cfg(all(windows, feature = "workspace-intelligence-host"))]
fn assert_bind_failure_exit(run: &ServerRun) {
    assert!(
        run.stdout.contains(STARTUP_BANNER),
        "the real Server binary must have run its startup, stdout was:\n{}",
        run.stdout
    );
    assert_eq!(
        run.status.code(),
        Some(1),
        "the Server must exit 1 on the bind failure, stderr was:\n{}",
        run.stderr
    );
    let diagnostics: Vec<&str> = run
        .stderr
        .lines()
        .map(|line| line.trim_end_matches('\r'))
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        diagnostics.len(),
        1,
        "the error exit must print only its diagnostic, stderr was:\n{}",
        run.stderr
    );
    let diagnostic = diagnostics[0].trim();
    assert!(
        diagnostic.starts_with("Error: "),
        "the one diagnostic must be the error `main` returned, stderr was:\n{}",
        run.stderr
    );
    assert!(
        diagnostic.contains(WINDOWS_ADDR_IN_USE_TOKEN),
        "the diagnostic must name the occupied loopback address, so it must carry \
         `{WINDOWS_ADDR_IN_USE_TOKEN}`; stderr was:\n{}",
        run.stderr
    );
    for banner in LISTENER_BANNERS {
        assert!(
            run.stdout.contains(banner),
            "these banners are logged before the listener binds, so `{banner}` must be \
             present on this path; stdout was:\n{}",
            run.stdout
        );
    }
}

/// Asserts the placement the startup actually resolved and wrote to its own log.
fn assert_startup_placement(run: &ServerRun, expected_code: &str) {
    let expected = format!("{PLACEMENT_MESSAGE}: code={expected_code}");
    assert!(
        run.stdout.contains(&expected),
        "the startup must report the placement `{expected}`, stdout was:\n{}",
        run.stdout
    );
}

/// Every regular file under `root`, for the control assertion that the child really
/// used this isolated root.
fn regular_files(root: &Path) -> Vec<PathBuf> {
    fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("an isolated entry is readable").path();
            if path.is_dir() {
                collect(&path, files);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    let mut files = Vec::new();
    collect(root, &mut files);
    files
}

/// Every path under `root` that only the host body could have created: the anchor
/// document, or the host's own namespace directory.
///
/// A recursive walk is used instead of one derived path, so the assertion covers
/// whichever root the product would have chosen rather than the one this test expected.
fn host_namespace_entries(root: &Path) -> Vec<PathBuf> {
    fn collect(directory: &Path, found: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let path = entry.expect("an isolated entry is readable").path();
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == "host-anchor.json" || (name == "workspace-intelligence" && path.is_dir()) {
                found.push(path);
                continue;
            }
            if path.is_dir() {
                collect(&path, found);
            }
        }
    }

    let mut found = Vec::new();
    collect(root, &mut found);
    found
}

fn assert_no_host_namespace(root: &Path, when: &str) {
    let found = host_namespace_entries(root);
    assert!(
        found.is_empty(),
        "{when}: no workspace intelligence anchor, control, lease or cognition entry may \
         exist: {found:?}"
    );
}

#[cfg(feature = "workspace-intelligence-host")]
mod host_feature_on {
    use super::*;

    use std::future::Future;

    use openbitfun_core::infrastructure::PathManager;
    use openbitfun_core::runtime_ownership::RuntimeDeployment;
    use openbitfun_core::service::workspace_intelligence::{
        host_fixture, WorkspaceIntelligenceHost, WorkspaceIntelligenceHostDrain,
        WorkspaceIntelligenceHostSurface,
    };

    /// Persisted workspace id of the enabled scope the first case seeds.
    const WORKSPACE_ID: &str = "server-exit-workspace";

    /// The anchor document name the workspace intelligence namespace owns.
    const ANCHOR_FILE: &str = "host-anchor.json";

    /// The SQLite document header every committed cognition partition starts with.
    const SQLITE_HEADER: &[u8] = b"SQLite format 3\0";

    /// Budget for stopping the parent-side runtime after its step finished, failed or
    /// panicked. It is only used where a parent-side runtime exists, so it lives here
    /// instead of at file scope.
    const RUNTIME_SHUTDOWN_BUDGET: Duration = Duration::from_secs(10);

    /// What the parent observed when it claimed the root the child had released.
    struct Takeover {
        state: &'static str,
        active: usize,
        standby: usize,
        scope: Option<&'static str>,
        drain: &'static str,
    }

    /// An enabled scope is claimed by the real process, drained on its error exit, and
    /// the released root is claimable again from the same persisted facts.
    ///
    /// The child's own evidence is that its drain row is `drained` (only an admitted
    /// handle answers that) plus the two products a claim leaves on disk: one cognition
    /// partition with a committed row and one owner lease document. That pair is what
    /// separates this case from an admitted but inactive host, which reports the same
    /// drain code and leaves neither. The parent's evidence is that a second admission on
    /// the same root reports the scope `active` and `active == 1`: a tenure the child had
    /// left held would report the same scope as `standby`, the only row another holder
    /// can produce. The anchor and control bytes taken before the run are compared
    /// afterwards, so the claim and the drain are shown to leave the authoritative
    /// documents alone.
    #[test]
    fn an_error_exit_after_admission_releases_a_claimed_scope_in_the_real_server_process() {
        let deadline = Instant::now() + DEADLINE;
        let storage = IsolatedStorage::new();
        storage.prepare();
        let user_root = storage.user_root();
        let workspace_root = storage.working_dir();
        let paths = host_fixture::test_path_manager(&user_root);
        assert_eq!(
            paths.user_root_dir(),
            user_root.as_path(),
            "the fixture and the child must share one isolated user root"
        );

        let seeded = run_parent_step(deadline, async {
            host_fixture::seed_local_workspace(&paths, WORKSPACE_ID, &workspace_root)
                .await
                .expect("seed the workspace record");
            host_fixture::enable_workspace(&paths, WORKSPACE_ID)
                .await
                .expect("enable the seeded workspace")
        });
        assert_eq!(
            seeded.workspace_id(),
            WORKSPACE_ID,
            "the enabled scope is the one this test claims"
        );

        let anchor_before = read_anchor(&paths);
        let control_before = read_control_record(&paths);
        let catalog_before = catalog_workspace_root(&paths);
        assert_eq!(
            catalog_before,
            workspace_root.to_string_lossy(),
            "the seeded catalog record must name the isolated workspace root"
        );
        assert!(
            !paths.workspace_intelligence_cognition_dir().exists(),
            "no claim product exists before the process runs"
        );
        assert!(
            lease_files(&paths).is_empty(),
            "no owner lease exists before the process runs"
        );

        let run = run_server(storage.command(), deadline);
        println!(
            "server exit: {:?}\n--- server stdout ---\n{}--- server stderr ---\n{}",
            run.status.code(),
            run.stdout,
            run.stderr
        );

        assert_origin_refusal_exit(&run);
        assert_startup_placement(&run, "install");
        let drain = parse_drain_record(&run.stdout, &run.stderr)
            .unwrap_or_else(|error| panic!("the drain record could not be read: {error}"));
        println!("drain record on {}: {}", drain.stream, drain.line);
        assert_eq!(
            drain.value, DRAINED_CODE,
            "the admitted host must report an awaited drain, never {NOT_INSTALLED_CODE} or \
             {DRAIN_TIMED_OUT_CODE}"
        );

        // The claim products: one committed cognition partition and one owner lease
        // document. The lease file is expected to stay after the release (a stale file
        // never implies ownership), so its presence is the artifact of the claim, while
        // the second admission below proves the tenure itself is gone.
        let cognition_after_child = existing_cognition_files(&paths);
        assert_eq!(
            cognition_after_child.len(),
            1,
            "the claim must leave exactly one cognition partition behind, got {:?}",
            cognition_after_child
                .iter()
                .map(|(name, bytes)| (name, bytes.len()))
                .collect::<Vec<_>>()
        );
        assert_committed_partition(&cognition_after_child[0]);
        let leases_after_child = lease_files(&paths);
        assert_eq!(
            leases_after_child.len(),
            1,
            "the claim must leave exactly one owner lease document behind, got {leases_after_child:?}"
        );

        assert_eq!(
            read_anchor(&paths),
            anchor_before,
            "neither the claim nor the drain may rewrite the storage anchor"
        );
        assert_eq!(
            read_control_record(&paths),
            control_before,
            "the claim must not rewrite the control record, so its stored generation is unchanged"
        );
        assert_eq!(
            catalog_workspace_root(&paths),
            catalog_before,
            "the workspace owner's record must survive the claim and the drain"
        );

        let takeover = takeover(deadline, paths.clone());
        assert_eq!(
            takeover.state, "active",
            "the released root must be admitted again, got state {} with active {} standby {}",
            takeover.state, takeover.active, takeover.standby
        );
        assert_eq!(
            takeover.active, 1,
            "the same enabled scope must be owned by the second admission"
        );
        assert_eq!(
            takeover.standby, 0,
            "a standby row is the only row a still-held tenure produces"
        );
        assert_eq!(
            takeover.scope,
            Some("active"),
            "the scope itself must be claimed, not merely enumerated as standby"
        );
        assert_eq!(
            takeover.drain, DRAINED_CODE,
            "the second admission must drain as well, so it leaves no tenure behind"
        );

        let cognition_after_takeover = existing_cognition_files(&paths);
        assert_eq!(
            cognition_after_takeover.len(),
            1,
            "the second claim must not add or remove a partition, got {:?}",
            cognition_after_takeover
                .iter()
                .map(|(name, bytes)| (name, bytes.len()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            cognition_after_takeover[0].0, cognition_after_child[0].0,
            "the second claim must reuse the partition the child used"
        );
        assert_committed_partition(&cognition_after_takeover[0]);
        assert_ne!(
            cognition_after_takeover, cognition_after_child,
            "the second claim mints a new incarnation over the persisted one; the distinct \
             bytes are the token advance, and the partition is never reset or deleted"
        );
        assert_eq!(
            read_control_record(&paths),
            control_before,
            "no admission may rewrite the control record"
        );
        assert_eq!(
            read_anchor(&paths),
            anchor_before,
            "no admission may rewrite the storage anchor"
        );
    }

    /// A real bind failure after admission still drains the host and releases the claim.
    ///
    /// Scope: this case covers one non-interactive exit path, the listener's own
    /// `TcpListener::bind` failure, on Windows only. It is no evidence about Ctrl+C, about
    /// any other way out of `main`, or about a Unix target.
    ///
    /// The child runs the same binary on the same fixture with an enabled scope, so it only
    /// differs from the case above by reaching the listener: no `--allowed-origin` is
    /// passed, the product defaults pass the origin screen, and this test holds
    /// `127.0.0.1:8080` for the whole run. The listener banners are therefore expected
    /// *present* — they are logged before the bind — the exit is the one `Error: `
    /// diagnostic carrying the stable occupied-address token, and the drain is still
    /// `drained` with the claim products intact. The second admission proves the tenure
    /// itself is gone rather than a file having stayed behind.
    #[cfg(windows)]
    #[test]
    fn a_real_bind_failure_after_admission_still_drains_and_releases_the_claim() {
        let deadline = Instant::now() + DEADLINE;
        // Held until the child has exited, so the listener it reaches is this test's. A
        // machine where 8080 is taken fails here with the precondition report instead of
        // evaluating anything.
        let held_port = occupy_loopback_port();
        let storage = IsolatedStorage::new();
        storage.prepare();
        // The shipped `main` resolves its SSH store through the Windows shell known folder for
        // local application data. That API expands `%USERPROFILE%` and then verifies the path
        // exists, so it never reads the product's environment overrides: without the default
        // folders under the isolated home the child stops before the listener and the case
        // would prove nothing. It is layout this case needs, not a product assertion — a
        // machine whose known folder is redirected resolves its own existing path instead.
        for folder in ["Local", "Roaming"] {
            std::fs::create_dir_all(storage.home_root().join("AppData").join(folder))
                .expect("the shell known-folder layout under the isolated home");
        }
        let user_root = storage.user_root();
        let workspace_root = storage.working_dir();
        let paths = host_fixture::test_path_manager(&user_root);

        let seeded = run_parent_step(deadline, async {
            host_fixture::seed_local_workspace(&paths, WORKSPACE_ID, &workspace_root)
                .await
                .expect("seed the workspace record");
            host_fixture::enable_workspace(&paths, WORKSPACE_ID)
                .await
                .expect("enable the seeded workspace")
        });
        assert_eq!(
            seeded.workspace_id(),
            WORKSPACE_ID,
            "the enabled scope is the one this test claims"
        );

        let anchor_before = read_anchor(&paths);
        let control_before = read_control_record(&paths);
        let catalog_before = catalog_workspace_root(&paths);
        let claim_absent = !paths.workspace_intelligence_cognition_dir().exists()
            && lease_files(&paths).is_empty();
        assert!(claim_absent, "no claim product may exist before the process runs");

        let run = run_server(storage.default_origin_command(), deadline);
        println!(
            "server exit: {:?}\n--- server stdout ---\n{}--- server stderr ---\n{}",
            run.status.code(),
            run.stdout,
            run.stderr
        );

        assert_bind_failure_exit(&run);
        assert_startup_placement(&run, "install");
        let drain = parse_drain_record(&run.stdout, &run.stderr)
            .unwrap_or_else(|error| panic!("the drain record could not be read: {error}"));
        println!("drain record on {}: {}", drain.stream, drain.line);
        assert_eq!(
            drain.value, DRAINED_CODE,
            "a host admitted before the bind failure must still report an awaited drain, never \
             {NOT_INSTALLED_CODE}"
        );

        // The port is only needed while the child runs; the second admission is in-process.
        drop(held_port);

        let cognition_after_child = existing_cognition_files(&paths);
        assert_eq!(
            cognition_after_child.len(),
            1,
            "the claim must leave exactly one cognition partition behind, got {:?}",
            cognition_after_child
                .iter()
                .map(|(name, bytes)| (name, bytes.len()))
                .collect::<Vec<_>>()
        );
        assert_committed_partition(&cognition_after_child[0]);
        let leases_after_child = lease_files(&paths);
        assert_eq!(
            leases_after_child.len(),
            1,
            "the claim must leave exactly one owner lease document behind, got {leases_after_child:?}"
        );
        assert_eq!(
            read_anchor(&paths),
            anchor_before,
            "neither the claim nor the bind failure may rewrite the storage anchor"
        );
        assert_eq!(
            read_control_record(&paths),
            control_before,
            "the control record must survive the claim and the bind failure"
        );
        assert_eq!(
            catalog_workspace_root(&paths),
            catalog_before,
            "the workspace owner's record must survive the claim and the bind failure"
        );

        let takeover = takeover(deadline, paths.clone());
        assert_eq!(
            takeover.state, "active",
            "the released root must be admitted again, got state {} with active {} standby {}",
            takeover.state, takeover.active, takeover.standby
        );
        assert_eq!(
            takeover.active, 1,
            "the same enabled scope must be owned by the second admission"
        );
        assert_eq!(
            takeover.standby, 0,
            "a standby row is the only row a still-held tenure produces, so a lease the failed \
             process never released would show up here"
        );
        assert_eq!(
            takeover.scope,
            Some("active"),
            "the scope itself must be claimed, not merely enumerated as standby"
        );
        assert_eq!(
            takeover.drain, DRAINED_CODE,
            "the second admission must drain as well, so it leaves no tenure behind"
        );

        let cognition_after_takeover = existing_cognition_files(&paths);
        assert_eq!(
            cognition_after_takeover.len(),
            1,
            "the second claim must not add or remove a partition, got {:?}",
            cognition_after_takeover
                .iter()
                .map(|(name, bytes)| (name, bytes.len()))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            cognition_after_takeover[0].0, cognition_after_child[0].0,
            "the second claim must reuse the partition the child used"
        );
        assert_ne!(
            cognition_after_takeover, cognition_after_child,
            "the second claim mints a new incarnation over the persisted one; the distinct bytes \
             are the token advance, and the partition is never reset or deleted"
        );
    }

    /// An unenabled root is admitted and drained exactly like the claimed one, and
    /// nothing is claimed because no scope is enabled.
    ///
    /// This is the runtime-off baseline: the same binary, the same command and the same
    /// `drained` code as the case above, with no anchor, no control record, no lease and
    /// no partition, and a second admission that reports `inactive` with no scope. The
    /// compile-off case below reports a different code for the same command, so the two
    /// ways of hosting nothing stay distinguishable in the process's own output.
    #[test]
    fn an_unenabled_root_is_admitted_and_drained_without_a_claim_in_the_real_server_process() {
        let deadline = Instant::now() + DEADLINE;
        let storage = IsolatedStorage::new();
        storage.prepare();
        let user_root = storage.user_root();
        let paths = host_fixture::test_path_manager(&user_root);
        assert_no_host_namespace(&user_root, "before the run");

        let run = run_server(storage.command(), deadline);
        println!(
            "server exit: {:?}\n--- server stdout ---\n{}--- server stderr ---\n{}",
            run.status.code(),
            run.stdout,
            run.stderr
        );

        assert_origin_refusal_exit(&run);
        assert_startup_placement(&run, "install");
        let drain = parse_drain_record(&run.stdout, &run.stderr)
            .unwrap_or_else(|error| panic!("the drain record could not be read: {error}"));
        println!("drain record on {}: {}", drain.stream, drain.line);
        assert_eq!(
            drain.value, DRAINED_CODE,
            "an admitted handle reports a drain even when it owns nothing, never \
             {NOT_INSTALLED_CODE}"
        );

        assert!(
            !regular_files(&user_root).is_empty(),
            "the isolated user root must carry the child's own files, otherwise the \
             zero-write claim below would be vacuous"
        );
        assert!(
            !paths.workspace_intelligence_dir().exists(),
            "a host that owns nothing must not create its namespace root"
        );
        assert_no_host_namespace(&user_root, "after the error exit");
        assert!(
            cognition_files(&paths).is_empty(),
            "no enabled scope means no cognition partition"
        );
        assert!(
            lease_files(&paths).is_empty(),
            "no enabled scope means no owner lease document"
        );
        for directory in [
            paths.workspace_intelligence_control_dir(),
            paths.workspace_intelligence_cognition_dir(),
            paths.workspace_intelligence_lease_dir(),
        ] {
            assert!(
                !directory.exists(),
                "the host created a root it must not have: {directory:?}"
            );
        }

        let takeover = takeover(deadline, paths.clone());
        assert_eq!(
            takeover.state, "inactive",
            "a root with no enabled scope reports an inactive host, got {} with active {} \
             standby {}",
            takeover.state, takeover.active, takeover.standby
        );
        assert_eq!(takeover.active, 0, "nothing is owned on this root");
        assert_eq!(takeover.standby, 0, "nothing stands by on this root either");
        assert_eq!(
            takeover.scope, None,
            "no scope is enumerated for a catalog without an enabled record"
        );
        assert_eq!(
            takeover.drain, DRAINED_CODE,
            "an inactive host still drains as drained"
        );

        assert_no_host_namespace(&user_root, "after the second admission");
        assert!(
            lease_files(&paths).is_empty(),
            "the second admission must take no lease"
        );
    }

    /// Runs one parent-side async step on this thread's runtime, bounded by the shared
    /// deadline.
    ///
    /// The step runs on the calling thread, so a timeout cancels the future in place
    /// instead of leaving a detached worker behind. Cancelling is not a claim about work
    /// the step already started: a blocking task it spawned keeps running until it
    /// returns, and `shutdown_timeout` only bounds how long this fixture waits for it.
    /// The runtime is stopped on both paths — a step that panicked must not reach the
    /// unwinding scope with its runtime still alive, because dropping a runtime waits for
    /// its blocking tasks without a bound of its own — and the step's own panic is then
    /// resumed unchanged.
    fn run_parent_step<T>(deadline: Instant, work: impl Future<Output = T>) -> T {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "a parent-side step started after the {DEADLINE:?} deadline"
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime for the parent-side host");
        let step = std::panic::AssertUnwindSafe(|| {
            runtime.block_on(async move { tokio::time::timeout(remaining, work).await })
        });
        let outcome = std::panic::catch_unwind(step);
        // Bounded stop before the outcome is reproduced, so a panicking step still pays
        // its cleanup and the runtime never falls into an unbounded drop.
        runtime.shutdown_timeout(RUNTIME_SHUTDOWN_BUDGET);
        resume_after_cleanup(outcome, DEADLINE)
    }

    /// Admits the same root again with the surface and deployment the app's install
    /// passes, reads its status, and drains it.
    fn takeover(deadline: Instant, paths: std::sync::Arc<PathManager>) -> Takeover {
        run_parent_step(deadline, async move {
            let host = WorkspaceIntelligenceHost::bootstrap(
                paths,
                None,
                WorkspaceIntelligenceHostSurface::ServerLoopback,
                RuntimeDeployment::Embedded,
            )
            .await;
            let status = host.status().await;
            let scope = status.scope_state(WORKSPACE_ID).map(|state| state.code());
            Takeover {
                state: status.state().code(),
                active: status.counts().active(),
                standby: status.counts().standby(),
                scope,
                drain: match host.shutdown().await.drain() {
                    WorkspaceIntelligenceHostDrain::Drained => DRAINED_CODE,
                    WorkspaceIntelligenceHostDrain::DrainTimedOut { .. } => DRAIN_TIMED_OUT_CODE,
                },
            }
        })
    }

    fn read_anchor(paths: &PathManager) -> Vec<u8> {
        std::fs::read(paths.workspace_intelligence_dir().join(ANCHOR_FILE))
            .expect("the enabled root holds its storage anchor")
    }

    /// The single persisted control record of the enabled scope.
    ///
    /// The control generation is a field of this document, so comparing the bytes
    /// covers the generation as well as every other stored fact.
    fn read_control_record(paths: &PathManager) -> Vec<u8> {
        let mut records: Vec<PathBuf> = std::fs::read_dir(paths.workspace_intelligence_control_dir())
            .expect("the enabled root holds its control directory")
            .map(|entry| entry.expect("a control entry is readable").path())
            .filter(|path| {
                path.extension().and_then(|extension| extension.to_str()) == Some("json")
            })
            .collect();
        records.sort();
        assert_eq!(
            records.len(),
            1,
            "the fixture root holds one control record: {records:?}"
        );
        std::fs::read(&records[0]).expect("the control record is readable")
    }

    /// The root the owner's own catalog document still carries for this scope.
    ///
    /// The record's stored field name is the owner's own `rootPath` key.
    fn catalog_workspace_root(paths: &PathManager) -> String {
        let catalog_path = paths.user_data_dir().join("workspace_data.json");
        let document: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&catalog_path).expect("the seeded catalog exists"),
        )
        .expect("the seeded catalog is a JSON document");
        document["workspaces"][WORKSPACE_ID]["rootPath"]
            .as_str()
            .unwrap_or_else(|| {
                panic!(
                    "the enabled workspace record is missing from {}",
                    catalog_path.display()
                )
            })
            .to_owned()
    }

    /// Every file of the cognition root as `(name, bytes)`, sorted by name.
    ///
    /// A missing root is an empty map; any other read error fails, so an unreadable
    /// partition can never read as "no claim".
    fn cognition_files(paths: &PathManager) -> Vec<(String, Vec<u8>)> {
        let root = paths.workspace_intelligence_cognition_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("the cognition root {root:?} exists but is unreadable: {error}"),
        };
        let mut files: Vec<(String, Vec<u8>)> = entries
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("a cognition entry is unreadable: {error}"))
                    .path()
            })
            .filter(|path| path.is_file())
            .map(|path| {
                let bytes = std::fs::read(&path)
                    .unwrap_or_else(|error| panic!("the cognition file {path:?} is unreadable: {error}"));
                (
                    path.file_name()
                        .expect("a cognition file has a name")
                        .to_string_lossy()
                        .into_owned(),
                    bytes,
                )
            })
            .collect();
        files.sort();
        files
    }

    /// The cognition files of a root this test has already seen hold a partition.
    fn existing_cognition_files(paths: &PathManager) -> Vec<(String, Vec<u8>)> {
        let files = cognition_files(paths);
        assert!(
            !files.is_empty(),
            "the cognition root must still hold the partition the claim committed"
        );
        files
    }

    /// Asserts one partition document is a committed SQLite database, not a proposal.
    fn assert_committed_partition((name, bytes): &(String, Vec<u8>)) {
        assert!(
            name.ends_with(".sqlite"),
            "a cognition partition is a SQLite document, got {name}"
        );
        assert!(
            bytes.len() > SQLITE_HEADER.len() && bytes.starts_with(SQLITE_HEADER),
            "the cognition partition {name} must be a committed SQLite document, got {} bytes",
            bytes.len()
        );
    }

    /// Every lease document under the lease root. Owner tenure is the only thing this
    /// host may create there, and the file is expected to stay after the release.
    fn lease_files(paths: &PathManager) -> Vec<PathBuf> {
        let root = paths.workspace_intelligence_lease_dir();
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
            Err(error) => panic!("the lease root {root:?} exists but is unreadable: {error}"),
        };
        let mut leases: Vec<PathBuf> = entries
            .map(|entry| {
                entry
                    .unwrap_or_else(|error| panic!("a lease entry is unreadable: {error}"))
                    .path()
            })
            .filter(|path| path.extension().and_then(|extension| extension.to_str()) == Some("lock"))
            .collect();
        leases.sort();
        leases
    }
}

#[cfg(not(feature = "workspace-intelligence-host"))]
mod host_feature_off {
    use super::*;

    /// The same error exit in a build without the host body creates no host state.
    ///
    /// This is the compile-off half of the three cases: the same command, the same
    /// refusal and the same exit code, with the typed refusal instead of a drain state
    /// and with no workspace intelligence entry anywhere under the isolated user root.
    /// The root's own files are asserted to be non-empty first, so "nothing was written"
    /// cannot pass on a child that never reached this root.
    #[test]
    fn the_feature_off_server_exits_on_its_startup_refusal_without_host_state() {
        let deadline = Instant::now() + DEADLINE;
        let storage = IsolatedStorage::new();
        storage.prepare();
        let user_root = storage.user_root();

        let run = run_server(storage.command(), deadline);
        println!(
            "server exit: {:?}\n--- server stdout ---\n{}--- server stderr ---\n{}",
            run.status.code(),
            run.stdout,
            run.stderr
        );

        assert_origin_refusal_exit(&run);
        assert_startup_placement(&run, NOT_COMPILED_CODE);
        let drain = parse_drain_record(&run.stdout, &run.stderr)
            .unwrap_or_else(|error| panic!("the drain record could not be read: {error}"));
        println!("drain record on {}: {}", drain.stream, drain.line);
        assert_eq!(
            drain.value, NOT_COMPILED_CODE,
            "a build without the host body admits no handle, so its release answers the \
             typed refusal instead of a drain state"
        );

        assert!(
            !regular_files(&user_root).is_empty(),
            "the isolated user root must carry the child's own files, otherwise the \
             zero-write claim below would be vacuous"
        );
        assert_no_host_namespace(&user_root, "after the error exit");
    }
}

/// Unit coverage for the drain parser, so a record shape that must not be accepted is
/// pinned here instead of relying on the process-level runs to notice it.
mod drain_parser {
    use super::*;

    const TIMESTAMP: &str = "2026-11-25T15:45:30.559147Z";

    fn record(payload: &str) -> String {
        format!("{TIMESTAMP}  INFO openbitfun_server: {payload}")
    }

    fn message(fields: &str) -> String {
        record(&format!("{DRAIN_MESSAGE} {fields}"))
    }

    #[test]
    fn a_bare_field_is_read() {
        let line = message("host_drain=drained");
        let parsed = parse_drain_record(&line, "").expect("a bare field is a record");
        assert_eq!(parsed.value, DRAINED_CODE);
        assert_eq!(parsed.stream, "stdout");
    }

    #[test]
    fn a_quoted_field_is_read() {
        let line = message("host_drain=\"drained\"");
        let parsed = parse_drain_record("", &line).expect("a quoted field is a record");
        assert_eq!(parsed.value, DRAINED_CODE);
        assert_eq!(parsed.stream, "stderr");
    }

    #[test]
    fn a_styled_record_is_read() {
        let line = format!(
            "\u{1b}[2m{TIMESTAMP}\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m openbitfun_server: \
             {DRAIN_MESSAGE} host_drain=\u{1b}[0m\"drained\"\u{1b}[0m"
        );
        let parsed = parse_drain_record(&line, "").expect("styling is not part of the record");
        assert_eq!(parsed.value, DRAINED_CODE);
    }

    #[test]
    fn a_message_without_a_field_is_refused() {
        let line = message("");
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::MissingField { .. })
        ));
    }

    #[test]
    fn a_field_without_its_message_is_refused() {
        let line = record("some other event host_drain=drained");
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn the_message_inside_other_text_is_not_a_record() {
        let line = record(&format!(
            "before the sentence {DRAIN_MESSAGE} host_drain=drained"
        ));
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
        let glued = record(&format!("{DRAIN_MESSAGE}suffix host_drain=drained"));
        assert!(matches!(
            parse_drain_record(&glued, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn two_fields_on_one_line_are_refused() {
        let line = message("host_drain=drained host_drain=drained");
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::DuplicateField { .. })
        ));
    }

    #[test]
    fn a_second_field_on_another_line_is_refused() {
        let line = message("host_drain=drained");
        let extra = record("an unrelated row host_drain=not_installed");
        assert!(matches!(
            parse_drain_record(&format!("{line}\n{extra}"), ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn a_second_field_in_the_other_stream_is_refused() {
        let line = message("host_drain=drained");
        let extra = record("an unrelated row host_drain=drained");
        assert!(matches!(
            parse_drain_record(&line, &extra),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn a_second_message_record_is_refused() {
        let line = message("host_drain=drained");
        assert!(matches!(
            parse_drain_record(&line, &line),
            Err(DrainParseError::MessageTwice { count: 2 })
        ));
    }

    #[test]
    fn an_unpaired_quote_is_refused() {
        for raw in ["host_drain=\"drained", "host_drain=drained\"", "host_drain=\"\""] {
            let line = message(raw);
            assert!(
                matches!(
                    parse_drain_record(&line, ""),
                    Err(DrainParseError::UnpairedQuote { .. })
                ),
                "{raw} must not be read as a quoted value"
            );
        }
    }

    #[test]
    fn a_code_with_a_prefix_or_suffix_is_refused() {
        for raw in ["host_drain=xdrained", "host_drain=drained_extra", "host_drain=DRAINED"] {
            let line = message(raw);
            assert!(
                matches!(
                    parse_drain_record(&line, ""),
                    Err(DrainParseError::UnknownCode { .. })
                ),
                "{raw} must not be read as a lifecycle code"
            );
        }
    }

    #[test]
    fn a_value_that_is_not_an_identifier_is_refused() {
        for raw in ["host_drain=", "host_drain=drained!", "host_drain=drained\x01"] {
            let line = message(raw);
            assert!(
                matches!(
                    parse_drain_record(&line, ""),
                    Err(DrainParseError::MalformedValue { .. })
                ),
                "{raw} must not be read as a field value"
            );
        }
    }

    #[test]
    fn empty_streams_carry_no_record() {
        assert!(matches!(
            parse_drain_record("", ""),
            Err(DrainParseError::NoMessage)
        ));
    }

    #[test]
    fn a_prose_line_without_a_level_is_not_a_record() {
        let line = format!("note: {DRAIN_MESSAGE} host_drain=drained");
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn another_level_is_not_the_drain_record() {
        let line = format!(
            "{TIMESTAMP}  WARN openbitfun_server: {DRAIN_MESSAGE} host_drain=drained"
        );
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn another_target_is_not_the_drain_record() {
        let line = format!(
            "{TIMESTAMP}  INFO openbitfun_core::service::workspace_intelligence::host::compiled: \
             {DRAIN_MESSAGE} host_drain=drained"
        );
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }

    #[test]
    fn a_repeated_message_on_one_line_is_refused() {
        let line = message(&format!("{DRAIN_MESSAGE} host_drain=drained"));
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::DuplicateMessage { .. })
        ));
    }

    #[test]
    fn a_nested_target_with_the_message_is_not_the_drain_record() {
        // Same level and same target, but the sentence follows a second copy of the
        // target inside the payload instead of sitting at the payload position.
        let line = format!(
            "{TIMESTAMP}  INFO openbitfun_server: unrelated openbitfun_server: \
             {DRAIN_MESSAGE} host_drain=drained"
        );
        assert!(matches!(
            parse_drain_record(&line, ""),
            Err(DrainParseError::StrayField { .. })
        ));
    }
}

/// Unit coverage for the boundary between a fixture step and its cleanup, so a panic is
/// pinned as resumed rather than swallowed and a timeout as a failure rather than a value.
mod fixture_step_outcome {
    use super::*;

    #[test]
    fn a_value_survives_its_cleanup() {
        let outcome: Result<Result<u32, ()>, Box<dyn Any + Send>> = Ok(Ok(7));
        assert_eq!(resume_after_cleanup(outcome, DEADLINE), 7);
    }

    #[test]
    fn an_elapsed_step_still_fails() {
        let outcome: Result<Result<u32, ()>, Box<dyn Any + Send>> = Ok(Err(()));
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resume_after_cleanup(outcome, DEADLINE)
        }))
        .expect_err("a timed out step must fail this test");
        let message = failure
            .downcast_ref::<String>()
            .expect("the deadline message is a formatted string");
        assert!(
            message.contains("did not finish before"),
            "the failure must name the deadline, got {message}"
        );
    }

    #[test]
    fn a_step_panic_is_resumed_unchanged() {
        let outcome: Result<Result<u32, ()>, Box<dyn Any + Send>> =
            Err(Box::new("the fixture's own panic"));
        let resumed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            resume_after_cleanup(outcome, DEADLINE)
        }))
        .expect_err("the step's panic must be resumed");
        assert_eq!(
            resumed.downcast_ref::<&str>().copied(),
            Some("the fixture's own panic"),
            "the original payload must survive the cleanup"
        );
    }
}
