//! Workspace intelligence host placement for the desktop process.
//!
//! The desktop is a composition root: it admits at most one process-wide
//! workspace intelligence host on the `Desktop` surface, and the one graceful
//! exit path in this crate drains that host before the process reports its
//! cleanup complete. Hiding the window, closing a workspace and switching
//! workspaces are not process exits, so none of them stops the host.
//!
//! Placement follows the real deployment of this process. A `Shared` deployment
//! keeps the workspace under another owner until that owner drains, so it is a
//! typed refusal here: a refusal reads no storage anchor, reads no catalog, takes
//! no lease and creates no root. A build without the host feature answers the
//! typed `NotCompiled` refusal instead of pretending to succeed.
//!
//! Every owner that constructs this host today builds it with `Embedded`, so the
//! `Shared` refusal is the reserved branch for a future shared selection and no
//! production path reaches it today. It is still decided here rather than left to
//! the host owner, so a future selection cannot take a lease by accident.
//!
//! The graceful exit path of this crate stops the plugin host before it drains this
//! one, so plugin work that could hold a workspace intelligence lease is already
//! stopped when the drain budget starts.
//!
//! ## One slot, three states
//!
//! The slot moves `Empty -> Running -> Closed` and never back. Both the install
//! and the drain reach it under one lock, and `bootstrap` runs entirely inside
//! that critical section, so a drain can observe an empty slot only after every
//! install that already started has finished. The terminal state is what keeps a
//! late install from taking a lease after the exit path already drained: an
//! install that finds `Closed` is refused and bootstraps nothing, so a lease can
//! never outlive the exit path that reports completion. A drain answers the same
//! code on every later call instead of stopping the host twice.
//!
//! An install that must not bootstrap is decided before the slot is touched, and a
//! drain keeps the handle in place while it stops the host, so a cancelled drain
//! leaves an installed host to be drained again rather than a half-stopped one.
//!
//! ## What the drain budget does not cover
//!
//! The install holds the slot lock for the whole bootstrap, so an exit path that
//! arrives during an install waits for that bootstrap before the drain even starts,
//! and that wait is not part of the drain's bounded budget (12 s in the host owner
//! today). Bootstrap reads the anchor, the control records and the persisted catalog
//! and carries no wall-clock deadline of its own, so the graceful exit is bounded
//! only by "the install in flight plus the drain budget" and this module cannot claim
//! that the whole exit finishes inside that budget. A drain that stops waiting stays
//! in its own draining state and does not take a lease back from owner work that is
//! still in flight: that work keeps the lease until its real operation ends.
//!
//! Nothing here prints. The module reports stable codes, and the calling
//! composition root writes them as `log` fields.

use std::sync::Arc;

use openbitfun_core::infrastructure::PathManager;
use openbitfun_core::runtime_ownership::RuntimeDeployment;
use tokio::sync::watch;

/// Stable code of an install that left this process holding one host.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host body to place")
)]
const INSTALL_CODE: &str = "install";

/// Stable code of an install refused by a slot the exit path already closed.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host body to place")
)]
const CLOSED_CODE: &str = "host_closed";

/// Stable code of a drain that stopped with no owner work outstanding.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host body to drain")
)]
const DRAINED_CODE: &str = "drained";

/// Stable code of a drain that stopped waiting while owner work was in flight.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host body to drain")
)]
const DRAIN_TIMED_OUT_CODE: &str = "drain_timed_out";

/// Stable code of a drain that found no installed host.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host slot to read")
)]
const NOT_INSTALLED_CODE: &str = "drain_not_installed";

/// Why the desktop did not install the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DesktopHostSkip {
    /// A Shared Runtime owns this process's workspace until that owner drains.
    #[cfg_attr(
        not(feature = "workspace-intelligence-host"),
        allow(dead_code, reason = "this build cannot reach the deployment check")
    )]
    SharedRuntime,
    /// This build does not compile the host feature.
    #[cfg_attr(
        feature = "workspace-intelligence-host",
        allow(dead_code, reason = "this build never answers the not-compiled code")
    )]
    NotCompiled,
}

impl DesktopHostSkip {
    /// Stable machine-readable code for status data and logs.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::SharedRuntime => "host_skip_shared_runtime",
            Self::NotCompiled => "not_compiled",
        }
    }
}

#[cfg(feature = "workspace-intelligence-host")]
type HostHandle = openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHost;

/// The one host slot of this process.
///
/// It starts empty, and the install and the drain both act on it under one lock,
/// so neither can act on a state the other is about to change.
#[cfg(feature = "workspace-intelligence-host")]
enum HostSlot {
    /// No install has happened yet.
    Empty,
    /// The host this process installed.
    Running(HostHandle),
    /// Terminal. `reported` carries the code the drain that closed the slot
    /// answered, so a repeated drain repeats that answer instead of stopping the
    /// host a second time, and an install that finds this state never bootstraps.
    Closed { reported: &'static str },
}

#[cfg(feature = "workspace-intelligence-host")]
static SLOT: tokio::sync::Mutex<HostSlot> = tokio::sync::Mutex::const_new(HostSlot::Empty);

/// Installs the process-wide host once and returns its stable code.
///
/// `install` is returned both for the call that bootstrapped the host and for a
/// repeat call that found it already installed, because either way this process
/// now holds exactly one host. A slot the exit path already closed answers
/// `host_closed` and bootstraps nothing, so no lease is taken after that point. A
/// skip returns its own code and initializes nothing: a `Shared` deployment reads
/// and creates nothing at all, and a build without the host feature performs no IO
/// of any kind.
pub(crate) async fn install_once(
    paths: Arc<PathManager>,
    catalog_revision: Option<watch::Receiver<u64>>,
    deployment: RuntimeDeployment,
) -> &'static str {
    #[cfg(feature = "workspace-intelligence-host")]
    let code = install_compiled(paths, catalog_revision, deployment).await;
    #[cfg(not(feature = "workspace-intelligence-host"))]
    let code = {
        // No host body exists in this build, so an install resolves neither the
        // user-data root it was given nor the catalog revision hint: no storage
        // anchor read, no catalog read, no lease and no directory.
        let _ = (paths, catalog_revision, deployment);
        DesktopHostSkip::NotCompiled.code()
    };
    code
}

/// Awaits the bounded drain of the installed host and returns a stable code.
///
/// The slot is read and written under the same lock an install holds for the whole
/// bootstrap, so a drain that starts while an install is in flight waits for it
/// instead of reporting that nothing was installed. The first drain of an empty
/// slot answers `drain_not_installed` and closes the slot, so a later install is
/// refused. Every later call answers the code the first drain reported.
pub(crate) async fn drain_once() -> &'static str {
    #[cfg(feature = "workspace-intelligence-host")]
    let code = drain_compiled().await;
    #[cfg(not(feature = "workspace-intelligence-host"))]
    let code = DesktopHostSkip::NotCompiled.code();
    code
}

#[cfg(feature = "workspace-intelligence-host")]
async fn install_compiled(
    paths: Arc<PathManager>,
    catalog_revision: Option<watch::Receiver<u64>>,
    deployment: RuntimeDeployment,
) -> &'static str {
    // Decided before the slot is touched and before bootstrap is called: a Shared
    // deployment installs nothing, so this refusal must not rely on the host to
    // reject it after it has already read or created something.
    if deployment == RuntimeDeployment::Shared {
        return DesktopHostSkip::SharedRuntime.code();
    }

    let mut slot = SLOT.lock().await;
    match &*slot {
        // One host per process: a repeat install answers the first one's code
        // instead of taking a second lease on the same scopes.
        HostSlot::Running(_) => return INSTALL_CODE,
        // The exit path already drained, or already decided there was nothing to
        // drain. Bootstrapping here would take leases no exit path would release.
        HostSlot::Closed { .. } => return CLOSED_CODE,
        HostSlot::Empty => {}
    }
    #[cfg(test)]
    hold_install_window().await;
    let host = openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHost::bootstrap(
        paths,
        catalog_revision,
        openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostSurface::Desktop,
        deployment,
    )
    .await;
    *slot = HostSlot::Running(host);
    INSTALL_CODE
}

#[cfg(feature = "workspace-intelligence-host")]
async fn drain_compiled() -> &'static str {
    /// What this drain found when it looked at the slot.
    enum Looked {
        Nothing,
        AlreadyClosed(&'static str),
        Installed(HostHandle),
    }

    let mut slot = SLOT.lock().await;
    let looked = match &*slot {
        HostSlot::Empty => Looked::Nothing,
        HostSlot::Closed { reported } => Looked::AlreadyClosed(*reported),
        // Cloned, not taken: the handle stays installed until the drain actually
        // produced a code, so a cancelled drain leaves a host that can be drained
        // again instead of one that was dropped without its bounded stop.
        HostSlot::Running(host) => Looked::Installed(host.clone()),
    };
    let host = match looked {
        Looked::Nothing => {
            // Nothing was installed, and this answer is the state: a later install
            // must not fill a slot the exit path has already passed.
            *slot = HostSlot::Closed {
                reported: NOT_INSTALLED_CODE,
            };
            return NOT_INSTALLED_CODE;
        }
        Looked::AlreadyClosed(code) => return code,
        Looked::Installed(host) => host,
    };

    let shutdown = host.shutdown().await;
    let host_state = shutdown.state().code();
    let code = match shutdown.drain() {
        openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostDrain::Drained => {
            DRAINED_CODE
        }
        openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostDrain::DrainTimedOut {
            outstanding,
        } => {
            log::warn!(
                "Desktop workspace intelligence host drain stopped waiting: host_state={}, outstanding={}",
                host_state,
                outstanding
            );
            DRAIN_TIMED_OUT_CODE
        }
    };
    // Closing the slot drops the installed handle, which is what releases the scope
    // leases it still held, and it does so before the caller declares the process
    // cleanup complete. A drain that stopped waiting does not take a lease back from
    // owner work that is still in flight: that work keeps it until its own operation
    // ends, so the lease is then released by the process exit that follows the
    // cleanup instead.
    *slot = HostSlot::Closed { reported: code };
    drop(host);
    code
}

/// Test-only gate that parks one install inside the shared critical section.
///
/// It exists so a test can prove that a concurrent drain waits for an install
/// that already started, without guessing at timing.
#[cfg(test)]
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no install body to park")
)]
static INSTALL_GATE: std::sync::Mutex<Option<Arc<InstallGate>>> = std::sync::Mutex::new(None);

#[cfg(test)]
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no install body to park")
)]
struct InstallGate {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: tokio::sync::Notify,
}

#[cfg(test)]
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no install body to park")
)]
impl InstallGate {
    /// Arms the gate for the next install and reports the moment it is entered.
    fn arm() -> (Arc<Self>, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let gate = Arc::new(Self {
            entered,
            release: tokio::sync::Notify::new(),
        });
        if let Ok(mut slot) = INSTALL_GATE.lock() {
            *slot = Some(Arc::clone(&gate));
        }
        (gate, receiver)
    }

    /// Lets a later install in the same process run through unhindered.
    fn disarm() {
        if let Ok(mut slot) = INSTALL_GATE.lock() {
            *slot = None;
        }
    }
}

#[cfg(test)]
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no install body to park")
)]
async fn hold_install_window() {
    let gate = match INSTALL_GATE.lock() {
        Ok(slot) => slot.as_ref().map(Arc::clone),
        Err(_) => None,
    };
    if let Some(gate) = gate {
        let _ = gate.entered.send(());
        gate.release.notified().await;
    }
}

/// Read-only status of the installed host, for a test that must observe what the
/// install claimed. It is not part of the production surface.
#[cfg(all(test, feature = "workspace-intelligence-host"))]
async fn installed_status_for_tests(
) -> Option<openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostStatus> {
    let host = match &*SLOT.lock().await {
        HostSlot::Running(host) => host.clone(),
        HostSlot::Empty | HostSlot::Closed { .. } => return None,
    };
    Some(host.status().await)
}

/// Returns the slot to `Empty` so one slot test cannot inherit another's state.
///
/// Dropping a running handle releases the leases it held, which is the only thing
/// a test needs from a host it never drains.
#[cfg(all(test, feature = "workspace-intelligence-host"))]
async fn reset_slot_for_tests() {
    *SLOT.lock().await = HostSlot::Empty;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The slot and the install gate are process-wide, so the slot tests take
    /// turns instead of observing each other's host.
    #[cfg(feature = "workspace-intelligence-host")]
    static SLOT_TESTS: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Deadline of a test that waits for the host to observe a catalog change.
    ///
    /// The host re-reads the catalog on its own schedule when no revision hint
    /// reaches it: the delay starts at 250 ms and doubles up to a 30 s cap, so the
    /// ticks land at 0.25, 0.75, 1.75, 3.75, 7.75, 15.75 and 31.75 s and every 30 s
    /// after that. Two cases bound how late a change is first observed:
    ///
    /// - a change written early in the ramp, such as at 15.75 s, waits for the
    ///   doubling interval that is still growing, which ends at 31.75 s;
    /// - a change written once the schedule already sits at the cap waits for one
    ///   capped interval, which is at most 30 s.
    ///
    /// The worse of the two is the 31.75 s of the early case, and the deadline must
    /// be strictly greater: 45 s leaves 13.25 s for the 20 ms poll interval and the
    /// host's own read, and the inequality that has to hold is
    /// `31.75 s < SCOPE_TESTS_DEADLINE` (with `30 s < 31.75 s` on the other case).
    #[cfg(feature = "workspace-intelligence-host")]
    const SCOPE_TESTS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(45);

    /// Window a test waits for the host to keep answering the state it already
    /// reported, after the wake-up that produced it.
    ///
    /// The state is read right after a wake-up the revision hint caused, and a hint
    /// wake-up resets the fallback delay, so the window spans that reset's first
    /// ticks: 0.25, 0.75, 1.75 and 3.75 s. With the window opening within a poll
    /// interval of the wake-up, the ticks at 0.75, 1.75 and 3.75 s fall inside it and
    /// the tick at 0.25 s may, so the host re-reads the registry one to three more
    /// times here. The window deliberately does not reach the next tick at 7.75 s,
    /// where the gap after 3.75 s is a full 4 s. A state that only a new control
    /// generation can clear must survive every one of those reads.
    #[cfg(feature = "workspace-intelligence-host")]
    const SCOPE_SETTLE_WINDOW: std::time::Duration = std::time::Duration::from_secs(4);

    /// The single scope lease file under this user-data root.
    ///
    /// The lease name is a digest of the internal scope key, which this app cannot
    /// spell and must not re-derive, so the test names the file the host actually
    /// created instead of recomputing it.
    #[cfg(feature = "workspace-intelligence-host")]
    fn sole_scope_lease(paths: &PathManager) -> std::path::PathBuf {
        let leases = lease_files(paths);
        assert_eq!(
            leases.len(),
            1,
            "one claimed scope owns one lease file under the lease root"
        );
        leases[0].clone()
    }

    #[cfg(feature = "workspace-intelligence-host")]
    fn lease_files(paths: &PathManager) -> Vec<std::path::PathBuf> {
        let lease_root = paths.workspace_intelligence_lease_dir();
        let Ok(entries) = std::fs::read_dir(&lease_root) else {
            return Vec::new();
        };
        let mut leases: Vec<std::path::PathBuf> = entries
            .map(|entry| entry.expect("read a lease entry").path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "lock"))
            .collect();
        leases.sort();
        leases
    }

    /// An enabled local workspace the host can claim, in an isolated user root.
    #[cfg(feature = "workspace-intelligence-host")]
    async fn seeded_scope(
        user_root: &std::path::Path,
    ) -> (
        Arc<PathManager>,
        openbitfun_core::service::workspace_intelligence::host_fixture::SeededWorkspace,
    ) {
        use openbitfun_core::service::workspace_intelligence::host_fixture::{
            enable_workspace, seed_local_workspace, test_path_manager,
        };

        let paths = test_path_manager(user_root);
        let workspace_root = user_root.join("workspace");
        seed_local_workspace(&paths, "workspace-a", &workspace_root)
            .await
            .expect("seed one local workspace");
        let enabled = enable_workspace(&paths, "workspace-a")
            .await
            .expect("enable the seeded workspace");
        (paths, enabled)
    }

    /// Polls the installed host until one scope reaches a state the caller accepts.
    ///
    /// The wait is a deadline, never a fixed sleep, because the host decides when it
    /// reads the registry again: a catalog revision hint short-circuits that wait and
    /// the fallback schedule bounds it. The only deterministic assertion is
    /// therefore "the host reaches this state, before the deadline".
    #[cfg(feature = "workspace-intelligence-host")]
    async fn wait_for_scope_state(
        workspace_id: &str,
        wanted: impl Fn(
            &openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostScopeState,
        ) -> bool,
    ) -> openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostScopeState {
        let deadline = tokio::time::Instant::now() + SCOPE_TESTS_DEADLINE;
        loop {
            let status = installed_status_for_tests()
                .await
                .expect("the install produced a host");
            if let Some(state) = status.scope_state(workspace_id) {
                if wanted(&state) {
                    return state;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "the host reached no accepted state for the scope before the deadline: {status:?}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Runs real git in one fixture repository.
    ///
    /// The command goes through the shared process helper, which is what keeps a
    /// host without a console window from flashing one per call. A missing git is a
    /// failure of the fixture, not a skipped assertion: a worktree fact this test
    /// did not really change would make the test prove nothing.
    #[cfg(feature = "workspace-intelligence-host")]
    fn git(root: &std::path::Path, args: &[&str]) {
        let output = openbitfun_services_core::process_manager::create_command("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("git is available for the worktree facts test");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_seeded_scope_is_claimed_then_drained_and_its_lease_is_released() {
        use openbitfun_core::service::workspace::WorkspaceService;
        use openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostScopeState;
        use openbitfun_services_core::exclusive_file_lease::{
            ExclusiveFileLease, ExclusiveFileLeaseError,
        };

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let (paths, enabled) = seeded_scope(user_root.path()).await;
        let generation = enabled.generation();
        assert!(
            generation >= 1,
            "the enabled record carries a control generation: {generation}"
        );

        let install = install_once(
            paths.clone(),
            Some(WorkspaceService::subscribe_catalog_changes()),
            RuntimeDeployment::Embedded,
        )
        .await;
        assert_eq!(install, INSTALL_CODE);

        // The claim is real, not merely reported: the scope is owned by this
        // process and its exclusive lease file cannot be taken a second time.
        let status = installed_status_for_tests()
            .await
            .expect("the install produced a host");
        let claimed = status
            .scope_state(enabled.workspace_id())
            .expect("the seeded workspace is enumerated");
        assert!(
            matches!(
                claimed,
                WorkspaceIntelligenceHostScopeState::Active
                    | WorkspaceIntelligenceHostScopeState::Standby
            ),
            "the seeded scope is claimed: {claimed:?}"
        );
        let lease_path = sole_scope_lease(&paths);
        let held = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            matches!(held, Err(ExclusiveFileLeaseError::InUse)),
            "a claimed scope holds its lease: {held:?}"
        );
        drop(held);

        // No owner operation of this test is in flight, so the bounded drain has
        // nothing to wait for and must report the drained answer rather than the
        // timeout one.
        let drain = drain_once().await;
        assert_eq!(
            drain, DRAINED_CODE,
            "a drain with no owner work in flight completes: {drain}"
        );

        // The lease is released with the drained host, so the same scope can be
        // owned again by a later process or a later host.
        let reacquired = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            reacquired.is_ok(),
            "the drained host released its scope lease: {reacquired:?}"
        );
        drop(reacquired);
    }

    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shared_deployment_is_refused_without_touching_the_filesystem() {
        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let paths = openbitfun_core::service::workspace_intelligence::host_fixture::test_path_manager(
            user_root.path(),
        );
        let intelligence_root = paths.workspace_intelligence_dir();
        let lease_root = paths.workspace_intelligence_lease_dir();

        let install = install_once(paths.clone(), None, RuntimeDeployment::Shared).await;

        assert_eq!(install, DesktopHostSkip::SharedRuntime.code());
        assert_eq!(install, "host_skip_shared_runtime");
        assert!(
            !intelligence_root.exists(),
            "a refused install creates no workspace intelligence root"
        );
        assert!(
            !lease_root.exists(),
            "a refused install creates no lease root and takes no lease"
        );
        assert!(
            lease_files(&paths).is_empty(),
            "a refused install creates no lease file"
        );
        assert_eq!(
            installed_status_for_tests().await,
            None,
            "a refused install leaves the slot empty"
        );
    }

    /// A catalog that holds a workspace the owner opened, but no enabled scope,
    /// installs the host without creating any workspace intelligence storage.
    ///
    /// "No work" is claimed only through what this host writes and publishes: the
    /// storage roots stay absent and the reported state is not active. The host's
    /// status carries no counter of governed work, so this test does not assert on
    /// one, and it does not reach into the host's internals to count anything.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_catalog_with_no_enabled_scope_installs_inactive_and_writes_nothing() {
        use openbitfun_core::service::workspace::WorkspaceService;
        use openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostState;

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let temp = tempfile::tempdir().expect("an isolated root");
        let workspace_root = temp.path().join("ws");
        std::fs::create_dir_all(&workspace_root).expect("the workspace directory exists");
        let service = WorkspaceService::new_isolated_for_tests(temp.path().join("user")).await;
        let paths = service.path_manager().clone();
        // The record exists because the owner opened it; nothing enables it.
        let opened = service
            .open_workspace(workspace_root)
            .await
            .expect("the workspace owner opens one local workspace");
        assert!(
            !opened.id.is_empty(),
            "the owner persisted a record the host can enumerate"
        );

        let intelligence_root = paths.workspace_intelligence_dir();
        assert!(
            !intelligence_root.exists(),
            "an opened workspace alone writes no workspace intelligence storage"
        );

        assert_eq!(
            install_once(
                paths.clone(),
                Some(WorkspaceService::subscribe_catalog_changes()),
                RuntimeDeployment::Embedded,
            )
            .await,
            INSTALL_CODE
        );

        let status = installed_status_for_tests()
            .await
            .expect("the install produced a host");
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Inactive,
            "a catalog with no enabled scope leaves the host inactive"
        );
        assert_eq!(status.counts().active(), 0, "no scope is owned");
        assert_eq!(status.counts().standby(), 0, "no scope is queued");
        assert!(
            !intelligence_root.exists(),
            "installing over that catalog creates no anchor, control or cognition root"
        );
        assert!(
            !paths.workspace_intelligence_control_dir().exists(),
            "no control record is written"
        );
        assert!(
            !paths.workspace_intelligence_cognition_dir().exists(),
            "an inactive host writes no cognition partition"
        );
        assert!(
            !paths.workspace_intelligence_lease_dir().exists(),
            "an inactive host creates no lease root"
        );
        assert!(lease_files(&paths).is_empty(), "no scope lease is taken");

        // The installed host is still stopped by the one exit path, and that stop has
        // nothing outstanding to wait for.
        assert_eq!(drain_once().await, DRAINED_CODE);
        assert!(
            !intelligence_root.exists(),
            "draining an inactive host writes nothing either"
        );
        assert!(lease_files(&paths).is_empty(), "no lease survives the drain");
    }

    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_install_in_flight_makes_a_concurrent_drain_wait_instead_of_returning_early() {
        use openbitfun_services_core::exclusive_file_lease::{
            ExclusiveFileLease, ExclusiveFileLeaseError,
        };

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let (paths, _enabled) = seeded_scope(user_root.path()).await;

        let (gate, mut entered) = InstallGate::arm();
        let install_paths = paths.clone();
        let install = tokio::spawn(async move {
            install_once(install_paths, None, RuntimeDeployment::Embedded).await
        });

        // The install holds the shared lock from here until the gate is released.
        entered
            .recv()
            .await
            .expect("the install entered the shared critical section");
        // Disarmed before the assertions below: the parked install already holds its
        // own handle, and a later failure must not leave a gate that parks another
        // test's install.
        InstallGate::disarm();
        let raced = tokio::time::timeout(std::time::Duration::from_millis(100), drain_once()).await;
        assert!(
            raced.is_err(),
            "a drain waits for an install that already started instead of answering an empty slot: {raced:?}"
        );

        gate.release.notify_one();
        let install_code = install.await.expect("the install finished");
        assert_eq!(install_code, INSTALL_CODE);

        let lease_path = sole_scope_lease(&paths);
        let held = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            matches!(held, Err(ExclusiveFileLeaseError::InUse)),
            "the released install claimed its scope: {held:?}"
        );
        drop(held);

        // The claim of this install already finished, so nothing this test started is
        // in flight and the bounded drain reports the drained answer.
        let drain_code = drain_once().await;
        assert_eq!(
            drain_code, DRAINED_CODE,
            "the waiting drain observed the host the install published and stopped it: {drain_code}"
        );
        let released = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            released.is_ok(),
            "the drained host released the lease the install took: {released:?}"
        );
        drop(released);
    }

    /// A drain that runs before any install is the last word: the slot closes and
    /// a later install cannot take a lease no exit path would release.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_drain_before_any_install_closes_the_slot_and_a_late_install_is_refused() {
        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let (paths, _enabled) = seeded_scope(user_root.path()).await;

        assert_eq!(drain_once().await, NOT_INSTALLED_CODE);

        let late_install = install_once(paths.clone(), None, RuntimeDeployment::Embedded).await;
        assert_eq!(late_install, CLOSED_CODE);
        assert_eq!(late_install, "host_closed");
        assert!(
            installed_status_for_tests().await.is_none(),
            "a refused install leaves no host installed"
        );
        assert!(
            lease_files(&paths).is_empty(),
            "a refused install creates no lease file"
        );
        assert!(
            !paths.workspace_intelligence_lease_dir().exists(),
            "a refused install does not even create the lease root"
        );

        // The closed answer is the state, not a single-shot reply.
        assert_eq!(drain_once().await, NOT_INSTALLED_CODE);
        assert_eq!(
            install_once(paths.clone(), None, RuntimeDeployment::Embedded).await,
            CLOSED_CODE
        );
    }

    /// A second install is idempotent and a second drain repeats the first
    /// answer: one process holds one host and stops it once.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repeated_install_and_a_repeated_drain_answer_the_same_codes_with_one_lease() {
        use openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostScopeState;

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let (paths, enabled) = seeded_scope(user_root.path()).await;

        assert_eq!(
            install_once(paths.clone(), None, RuntimeDeployment::Embedded).await,
            INSTALL_CODE
        );
        assert_eq!(
            install_once(paths.clone(), None, RuntimeDeployment::Embedded).await,
            INSTALL_CODE
        );
        assert_eq!(
            lease_files(&paths).len(),
            1,
            "a repeat install takes no second lease"
        );
        let status = installed_status_for_tests()
            .await
            .expect("the install produced a host");
        assert_eq!(
            status.scope_state(enabled.workspace_id()),
            Some(WorkspaceIntelligenceHostScopeState::Active),
            "the claimed scope stays active"
        );

        // Either drain answer is acceptable here, because this test asserts nothing
        // about leases after the stop: what it proves is that the second drain
        // repeats the first one instead of stopping the host a second time.
        let first_drain = drain_once().await;
        let second_drain = drain_once().await;
        assert!(
            first_drain == DRAINED_CODE || first_drain == DRAIN_TIMED_OUT_CODE,
            "the drain reports a drain code: {first_drain}"
        );
        assert_eq!(
            second_drain, first_drain,
            "a repeated drain repeats the answer instead of stopping the host twice"
        );
    }

    /// A real owner rescan that flips a linked worktree into its own main workspace
    /// makes the host refuse the scope, and the host does not adopt the scope again
    /// inside the control generation the block was latched at.
    ///
    /// The enable stores the binding observed while the directory was still a
    /// worktree child of the main repository, so the rescan is what makes the live
    /// facts differ from the stored authority. The control record is never rewritten
    /// afterwards, so that generation stays the one in force, and the latch contract
    /// allows exactly one recovery: a strictly newer generation whose stored binding
    /// matches the live facts. A re-read alone must not recover the scope.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_real_rescan_that_flips_worktree_facts_blocks_the_scope_and_the_latch_holds() {
        use openbitfun_core::service::workspace::WorkspaceService;
        use openbitfun_core::service::workspace_intelligence::host_fixture::enable_workspace;
        use openbitfun_core::service::workspace_intelligence::{
            WorkspaceIntelligenceHostReason, WorkspaceIntelligenceHostScopeState,
        };
        use openbitfun_services_core::exclusive_file_lease::{
            ExclusiveFileLease, ExclusiveFileLeaseError,
        };

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let temp = tempfile::tempdir().expect("an isolated root");
        let repositories = temp.path().join("repositories");
        std::fs::create_dir_all(&repositories).expect("the repository root exists");

        // A main repository and one linked worktree of it, through real git.
        let main_path = repositories.join("main-repo");
        std::fs::create_dir_all(&main_path).expect("the main repository directory exists");
        git(&main_path, &["init"]);
        git(&main_path, &["config", "user.name", "OpenBitFun Tests"]);
        git(
            &main_path,
            &["config", "user.email", "openbitfun@example.com"],
        );
        std::fs::write(main_path.join("tracked.txt"), "initial\n").expect("the fixture file");
        git(&main_path, &["add", "tracked.txt"]);
        git(&main_path, &["commit", "-m", "initial"]);
        let linked_path = repositories.join("linked");
        git(
            &main_path,
            &[
                "worktree",
                "add",
                "-b",
                "linked-test",
                linked_path.to_string_lossy().as_ref(),
            ],
        );

        // The workspace owner persists both records before this test writes anything
        // else, so no later call can replace the registry from an empty memory state.
        let service = WorkspaceService::new_isolated_for_tests(temp.path().join("user")).await;
        let paths = service.path_manager().clone();
        let main = service
            .open_workspace(main_path.clone())
            .await
            .expect("the main repository opens");
        let linked = service
            .open_workspace(linked_path.clone())
            .await
            .expect("the linked worktree opens");
        let tree = linked
            .worktree
            .as_ref()
            .expect("the linked record carries worktree facts");
        assert!(
            !tree.is_main,
            "the linked directory starts as a worktree child"
        );
        assert_eq!(
            tree.main_workspace_id.as_deref(),
            Some(main.id.as_str()),
            "the linked record points at the main workspace"
        );

        let enabled = enable_workspace(&paths, &linked.id)
            .await
            .expect("the linked scope is enabled");
        assert_eq!(enabled.workspace_id(), linked.id.as_str());
        assert!(
            enabled.generation() >= 1,
            "the enable publishes a control generation: {}",
            enabled.generation()
        );

        assert_eq!(
            install_once(
                paths.clone(),
                Some(WorkspaceService::subscribe_catalog_changes()),
                RuntimeDeployment::Embedded,
            )
            .await,
            INSTALL_CODE
        );
        let claimed = wait_for_scope_state(&linked.id, |state| {
            matches!(state, WorkspaceIntelligenceHostScopeState::Active)
        })
        .await;
        assert_eq!(
            claimed,
            WorkspaceIntelligenceHostScopeState::Active,
            "the host claims the enabled linked scope"
        );
        let lease_path = sole_scope_lease(&paths);
        let held = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            matches!(held, Err(ExclusiveFileLeaseError::InUse)),
            "the claimed scope holds its lease: {held:?}"
        );
        drop(held);

        // Change the fact on disk: the directory stops being a worktree of the main
        // repository and becomes its own repository, and the owner's own rescan has to
        // re-derive that from the working tree.
        git(
            &main_path,
            &[
                "worktree",
                "remove",
                "--force",
                linked_path.to_string_lossy().as_ref(),
            ],
        );
        std::fs::create_dir_all(&linked_path).expect("the former link is recreated");
        git(&linked_path, &["init"]);
        let rescanned = service
            .rescan_workspace(&linked.id)
            .await
            .expect("the owner rescans the record");
        assert_eq!(
            rescanned.id, linked.id,
            "a rescan never recomputes the stable id"
        );
        let tree = rescanned
            .worktree
            .as_ref()
            .expect("the rescanned record carries worktree facts");
        assert!(
            tree.is_main,
            "the rescan re-derived the facts from the working tree"
        );
        assert_eq!(
            tree.main_workspace_id, None,
            "a main workspace has no parent id"
        );

        // The rescan is a catalog write by the owner, so the host reaches it through
        // the revision hint it was composed with, and the stored binding it holds no
        // longer matches the live facts.
        let blocked = wait_for_scope_state(&linked.id, |state| {
            matches!(state, WorkspaceIntelligenceHostScopeState::Blocked(_))
        })
        .await;
        assert_eq!(
            blocked,
            WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::BindingChanged
            ),
            "the refused row names the binding change"
        );
        let status = installed_status_for_tests()
            .await
            .expect("the host is still installed");
        assert_eq!(
            status.counts().active(),
            0,
            "no tenure over a changed binding"
        );
        assert_eq!(status.counts().standby(), 0, "no new claim is attempted");
        assert_ne!(
            status.state(),
            openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostState::Active
        );
        let released = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            released.is_ok(),
            "the refused scope released the lease it held: {released:?}"
        );
        drop(released);

        // Same generation, later reads: nothing advanced the control generation, so
        // the latch may only be cleared by a newer authority, and the host's own
        // re-reads inside this window must leave the scope refused.
        tokio::time::sleep(SCOPE_SETTLE_WINDOW).await;
        let status = installed_status_for_tests()
            .await
            .expect("the host is still installed");
        assert_eq!(
            status.scope_state(&linked.id),
            Some(WorkspaceIntelligenceHostScopeState::Blocked(
                WorkspaceIntelligenceHostReason::BindingChanged
            )),
            "the latched block survives the host's own re-reads: {status:?}"
        );
        assert_eq!(
            status.counts().active(),
            0,
            "no tenure inside the latched generation"
        );
        assert_eq!(
            status.counts().standby(),
            0,
            "no re-claim inside the latched generation"
        );
        let still_free = ExclusiveFileLease::try_acquire(&lease_path);
        assert!(
            still_free.is_ok(),
            "the refused scope keeps no lease across re-reads: {still_free:?}"
        );
        drop(still_free);

        // Nothing of this test's own work is in flight, so the bounded drain reports
        // the drained answer: a timeout would mean the stop kept waiting on work this
        // test never started.
        let drain = drain_once().await;
        assert_eq!(
            drain, DRAINED_CODE,
            "a drain after the refused claim completes: {drain}"
        );
    }

    /// A build without the host feature answers the typed refusal and writes no
    /// workspace intelligence entry.
    ///
    /// Such a build compiles no host body, so both production entry points answer a
    /// typed refusal instead of pretending to succeed. The isolated user root comes
    /// from the workspace owner's own test constructor, which needs only that
    /// owner's test support and not the host feature, so this test never resolves
    /// this process's real user-data root. That constructor also initializes the
    /// owner's user directories, so the assertions cover the workspace intelligence
    /// namespace only and claim nothing about the rest of that initialization.
    #[cfg(not(feature = "workspace-intelligence-host"))]
    #[tokio::test]
    async fn the_feature_off_build_answers_not_compiled_and_creates_nothing() {
        use openbitfun_core::service::workspace::WorkspaceService;

        /// The four roots that make up the workspace intelligence namespace.
        fn namespace_entries(paths: &PathManager) -> [std::path::PathBuf; 4] {
            [
                paths.workspace_intelligence_dir(),
                paths.workspace_intelligence_control_dir(),
                paths.workspace_intelligence_cognition_dir(),
                paths.workspace_intelligence_lease_dir(),
            ]
        }

        let temp = tempfile::tempdir().expect("an isolated root");
        let service = WorkspaceService::new_isolated_for_tests(temp.path().join("user")).await;
        let paths = service.path_manager().clone();

        assert!(
            namespace_entries(&paths).iter().all(|root| !root.exists()),
            "the isolated owner root starts with no workspace intelligence entry"
        );

        let install = install_once(paths.clone(), None, RuntimeDeployment::Embedded).await;
        assert_eq!(install, DesktopHostSkip::NotCompiled.code());
        assert_eq!(install, "not_compiled");
        assert!(
            namespace_entries(&paths).iter().all(|root| !root.exists()),
            "this build writes no anchor, control, lease or cognition entry"
        );

        let drain = drain_once().await;
        assert_eq!(drain, "not_compiled");
        assert!(
            namespace_entries(&paths).iter().all(|root| !root.exists()),
            "draining a build without the host feature writes nothing either"
        );
    }
    /// A `Shared` refusal leaves the slot `Empty` rather than closing it, so the exit
    /// path's drain is still the call that decides the slot, and an `Embedded` install
    /// that arrives after that drain is refused instead of taking a lease the exit path
    /// already passed.
    ///
    /// `Empty` and `Closed` are both "no host installed", so the status alone cannot
    /// tell them apart: this test reads the slot itself, which is why it lives in the
    /// module's own test module.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_shared_refusal_then_an_empty_drain_then_a_late_embedded_install_is_refused() {
        use openbitfun_core::service::workspace_intelligence::host_fixture::test_path_manager;

        let _serial = SLOT_TESTS.lock().await;
        reset_slot_for_tests().await;

        let user_root = tempfile::tempdir().expect("isolated user-data root");
        let paths = test_path_manager(user_root.path());
        let namespace = [
            paths.workspace_intelligence_dir(),
            paths.workspace_intelligence_control_dir(),
            paths.workspace_intelligence_cognition_dir(),
            paths.workspace_intelligence_lease_dir(),
        ];

        // Shared is decided before the slot is touched: it installs nothing, writes no
        // workspace intelligence entry, and does not decide the slot either.
        let refused = install_once(paths.clone(), None, RuntimeDeployment::Shared).await;
        assert_eq!(refused, DesktopHostSkip::SharedRuntime.code());
        assert_ne!(
            refused, NOT_INSTALLED_CODE,
            "a skip answer is not the empty-drain answer"
        );
        assert_ne!(
            refused, DRAINED_CODE,
            "a skip answer is not the drained answer"
        );
        assert!(
            matches!(&*super::SLOT.lock().await, super::HostSlot::Empty),
            "a Shared refusal leaves the slot Empty instead of closing it"
        );
        assert_eq!(
            installed_status_for_tests().await,
            None,
            "a refused install leaves no host installed"
        );
        for root in &namespace {
            assert!(
                !root.exists(),
                "a refused install creates no workspace intelligence entry: {root:?}"
            );
        }

        // The slot is still `Empty`, so this drain is what closes it, and it answers the
        // empty-slot code rather than a drained one.
        assert_eq!(drain_once().await, NOT_INSTALLED_CODE);

        // The drain owns the terminal state: the later Embedded install is refused and
        // bootstraps nothing, so no host and no lease outlive the exit path.
        assert_eq!(
            install_once(paths.clone(), None, RuntimeDeployment::Embedded).await,
            CLOSED_CODE
        );
        assert_eq!(
            installed_status_for_tests().await,
            None,
            "the late install leaves no host installed"
        );
        assert!(
            matches!(
                &*super::SLOT.lock().await,
                super::HostSlot::Closed { .. }
            ),
            "the drain closed the slot and the late install left it closed"
        );
        for root in &namespace {
            assert!(
                !root.exists(),
                "neither the drain nor the late install writes a workspace intelligence entry: {root:?}"
            );
        }
        assert_eq!(
            drain_once().await,
            NOT_INSTALLED_CODE,
            "the closed answer is the state, not a single-shot reply"
        );
    }
}
