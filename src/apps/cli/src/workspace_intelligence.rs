//! Workspace intelligence host placement for one CLI invocation.
//!
//! The CLI is a composition root. An invocation either admits the one
//! process-wide workspace intelligence host on the surface its own command really
//! is, or it refuses with a typed reason and writes nothing at all. Both
//! statements sit at the call site that names the command, because the command is
//! the only fact that decides the surface: this app's bootstrap profile is
//! `Interactive` for a daemon and for a shared-runtime service as well, so
//! `Embedded` plus a generic profile identifies no real interactive surface.
//! There is deliberately no default placement and no inference from a profile.
//!
//! Every command that assembles a core runtime states its placement, including the
//! one-shot diagnoses that assemble one only to report on it. A command that
//! assembles none can host nothing and states nothing.
//!
//! An admission also runs on the deployment the process's own runtime ownership
//! was built with. Every entry point that can admit a host records that fact after
//! constructing the owner; an entry point that builds its own owner and refuses the
//! host records nothing. This module refuses to admit anything when no such fact
//! exists rather than defaulting to one: a host bootstrapped on a guessed
//! deployment would answer for a workspace nobody owns.
//!
//! A refusal resolves no user-data root, reads no catalog, takes no lease and
//! writes no file. An admission bootstraps the host exactly once per process, and
//! [`drain`] is awaited on the single shutdown path every invocation reaches, so a
//! late admission cannot outlive the process. A second admission that names a
//! different surface is reported, because one process holds one surface and a
//! disagreement between two call sites is a wiring defect rather than a state the
//! host can serve. Nothing here prints: the whole module reports through `tracing`
//! fields only, so a caller that owns stdout keeps it byte-identical.
//!
//! The slot in this module is one lock over one state machine rather than a set of
//! independent flags, because the shutdown path can arrive before an admission
//! starts, while one is in flight, or after it finished, and each of those orders
//! has exactly one outcome. A drain that finds the slot empty closes it, so an
//! admission arriving afterwards cannot bootstrap a host that nothing would ever
//! drain.

use std::sync::OnceLock;

use openbitfun_core::infrastructure::PathManager;
use openbitfun_core::service::workspace::WorkspaceService;
use openbitfun_core::service::workspace_intelligence::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostSurface,
};
use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
use tokio::sync::{watch, Mutex};

/// Stable code of a placement that admitted the host.
pub(crate) const INSTALL_CODE: &str = "install";

/// Stable code of a drain that stopped with no outstanding owner work.
const DRAINED_CODE: &str = "drained";

/// Stable code of a drain that stopped waiting while owner work was in flight.
const DRAIN_TIMED_OUT_CODE: &str = "drain_timed_out";

/// Stable code of an admission refused by a slot the shutdown path closed.
const CLOSED_CODE: &str = "host_closed";

/// Stable code of a drain that found no admitted host.
const NOT_INSTALLED_CODE: &str = "not_installed";

/// The one host slot of this process.
///
/// It starts empty, and both the admission and the shutdown path reach it under
/// this lock, so neither can act on a state the other is about to change. A
/// refusal never touches it at all, so a refused invocation leaves the slot, the
/// lease root and the cognition root untouched.
enum HostSlot {
    /// No admission has happened yet.
    Empty,
    /// The host this process admitted.
    Running(WorkspaceIntelligenceHost),
    /// Terminal. `reported` carries what a drain answered, so a repeated drain
    /// repeats that answer instead of stopping the host a second time; an
    /// admission that finds this state never bootstraps.
    Closed { reported: Option<&'static str> },
}

static SLOT: Mutex<HostSlot> = Mutex::const_new(HostSlot::Empty);

/// The deployment this process built its runtime ownership with.
///
/// Every entry point that can admit a host records it after constructing that
/// owner. An entry point that builds its own owner and refuses the host, such as
/// the ACP and app-server surfaces, records nothing, because no admission ever
/// asks there. It is never defaulted: an admission without it fails instead of
/// hosting on a guess.
static DEPLOYMENT: OnceLock<RuntimeDeployment> = OnceLock::new();

/// The surface the first admission named.
///
/// One process holds one host on one surface, so this is the only place a second,
/// disagreeing call site can be noticed at all.
static ADMITTED_SURFACE: OnceLock<WorkspaceIntelligenceHostSurface> = OnceLock::new();

/// Where this CLI invocation would have admitted the workspace intelligence host.
///
/// Every call site names the surface it is. The command is the only fact that
/// decides it, so there is no default variant and no `From` conversion from a
/// bootstrap profile or a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliHostPlacement {
    /// Admit the host for this surface.
    Install(WorkspaceIntelligenceHostSurface),
    /// Never admit a host, for a typed reason reported as a stable code.
    Skip(CliHostSkip),
}

/// Why an invocation refuses to admit a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CliHostSkip {
    /// A daemon runs headless with no interactive host of its own.
    Daemon,
    /// A shared runtime owns the workspace and has not drained.
    SharedRuntime,
    /// The stdio app server speaks a protocol on stdout.
    StdioServer,
    /// A dispatched job outlives any host tenure.
    DetachedDispatch,
    /// A management command owns no workspace.
    Management,
    /// ACP owns its own session lifetime.
    Acp,
}

impl CliHostSkip {
    /// Stable machine-readable code for status data and logs.
    ///
    /// The codes are lowercase, separator-free and distinct per variant, so a
    /// log line names exactly one refusal.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Daemon => "host_skip_daemon",
            Self::SharedRuntime => "host_skip_shared_runtime",
            Self::StdioServer => "host_skip_stdio_server",
            Self::DetachedDispatch => "host_skip_detached_dispatch",
            Self::Management => "host_skip_management",
            Self::Acp => "host_skip_acp",
        }
    }
}

impl CliHostPlacement {
    /// Stable machine-readable code for status data and logs.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Install(_) => INSTALL_CODE,
            Self::Skip(skip) => skip.code(),
        }
    }
}

/// Records the deployment the process owner was built with.
///
/// The composition root calls this with the value it passed to the runtime owner,
/// read back from that owner, so this module never decides a deployment itself.
/// A later disagreement is reported and the first record stands.
pub(crate) fn record_deployment(deployment: RuntimeDeployment) {
    match DEPLOYMENT.set(deployment) {
        Ok(()) => {}
        Err(recorded) if recorded == deployment => {}
        Err(recorded) => tracing::warn!(
            recorded_deployment = %recorded,
            requested_deployment = %deployment,
            "workspace intelligence host deployment disagrees with the one already recorded"
        ),
    }
}

/// Installs the one process-wide host for this invocation, or does nothing for a
/// skip.
///
/// A skip returns its own code and initializes nothing. An admission bootstraps
/// once: a second call returns the already-installed handle's code instead of
/// bootstrapping twice, so no second lease can be taken in one process. An
/// admission that arrives after the shutdown path drained the slot, or that finds
/// the slot closed by a drain which never saw a host, returns the closed code
/// without bootstrapping. An admission without a recorded deployment fails rather
/// than hosting on a guess. A second call that names a different surface is
/// reported, and the surface the first admission claimed stays the one the host
/// runs on.
pub(crate) async fn install(
    paths: std::sync::Arc<PathManager>,
    catalog_revision: watch::Receiver<u64>,
    placement: CliHostPlacement,
) -> anyhow::Result<&'static str> {
    let surface = match placement {
        CliHostPlacement::Skip(skip) => return Ok(refuse(skip)),
        CliHostPlacement::Install(surface) => surface,
    };
    let mut slot = SLOT.lock().await;
    match &*slot {
        HostSlot::Running(_) => {
            // A repeated admission is the only place a second, disagreeing surface
            // can still be noticed, so it compares here as well.
            record_surface(surface);
            tracing::info!(
                host_placement = placement.code(),
                host_surface = ?surface,
                "workspace intelligence host placement resolved from the host already admitted"
            );
            return Ok(INSTALL_CODE);
        }
        HostSlot::Closed { .. } => {
            tracing::info!(
                host_placement = CLOSED_CODE,
                host_surface = ?surface,
                "workspace intelligence host admission refused because the host slot is closed"
            );
            return Ok(CLOSED_CODE);
        }
        HostSlot::Empty => {}
    }
    // Only an admission that really publishes a host claims the surface, so a
    // refusal cannot make a later admission look like a disagreement.
    record_surface(surface);

    let Some(deployment) = DEPLOYMENT.get().copied() else {
        tracing::error!(
            host_placement = placement.code(),
            "workspace intelligence host admission has no recorded runtime ownership deployment"
        );
        anyhow::bail!(
            "workspace intelligence host admission requires the deployment the process runtime ownership was built with"
        );
    };

    let host = WorkspaceIntelligenceHost::bootstrap(
        paths,
        Some(catalog_revision),
        surface,
        deployment,
    )
    .await;
    *slot = HostSlot::Running(host);
    tracing::info!(
        host_placement = placement.code(),
        host_surface = ?surface,
        host_deployment = %deployment,
        "workspace intelligence host placement resolved"
    );
    Ok(INSTALL_CODE)
}

/// Resolves this invocation's own user-data root and catalog revision, then
/// installs `placement`.
///
/// A skip resolves nothing: no root, no revision, no environment. An admission
/// asks for the process-wide root the CLI composition already initialized, and a
/// path manager that failed to initialize is an error instead of a fallback root
/// a host would then anchor on.
pub(crate) async fn install_for(placement: CliHostPlacement) -> anyhow::Result<&'static str> {
    if let CliHostPlacement::Skip(skip) = placement {
        return Ok(refuse(skip));
    }
    let paths = openbitfun_core::infrastructure::try_get_path_manager_arc()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    install(
        paths,
        WorkspaceService::subscribe_catalog_changes(),
        placement,
    )
    .await
}

/// Awaits the host's bounded drain when one was installed, and closes the slot.
///
/// Every exit path of the invocation reaches this before the process leaves, so a
/// late install cannot outlive it. The state is claimed under the slot lock before
/// the host is stopped, so a repeated drain reports the drain that already ran
/// instead of stopping the host twice, and an admission still in flight holds the
/// lock until it published its host. A drain that finds an empty slot closes it,
/// so nothing can bootstrap afterwards. Returns the reported status code for a log
/// line, or the code of the drain that already ran.
pub(crate) async fn drain() -> Option<&'static str> {
    let mut slot = SLOT.lock().await;
    let host = match std::mem::replace(&mut *slot, HostSlot::Closed { reported: None }) {
        HostSlot::Empty => {
            // The slot stays closed and reports this answer, so a second drain
            // repeats it instead of answering nothing.
            *slot = HostSlot::Closed {
                reported: Some(NOT_INSTALLED_CODE),
            };
            tracing::info!(
                host_drain = NOT_INSTALLED_CODE,
                "workspace intelligence host drain found no admitted host"
            );
            return Some(NOT_INSTALLED_CODE);
        }
        HostSlot::Closed { reported } => {
            *slot = HostSlot::Closed { reported };
            return reported;
        }
        HostSlot::Running(host) => host,
    };

    let shutdown = host.shutdown().await;
    let host_state = shutdown.state().code();
    let code = match shutdown.drain() {
        WorkspaceIntelligenceHostDrain::Drained => {
            tracing::info!(
                host_state = host_state,
                host_drain = DRAINED_CODE,
                "workspace intelligence host stopped waiting with no owner work outstanding"
            );
            DRAINED_CODE
        }
        WorkspaceIntelligenceHostDrain::DrainTimedOut { outstanding } => {
            tracing::info!(
                host_state = host_state,
                host_drain = DRAIN_TIMED_OUT_CODE,
                outstanding = outstanding,
                "workspace intelligence host stopped waiting while owner work was in flight"
            );
            DRAIN_TIMED_OUT_CODE
        }
    };
    *slot = HostSlot::Closed {
        reported: Some(code),
    };
    Some(code)
}

/// Records the surface the first admission named and reports a later mismatch.
fn record_surface(surface: WorkspaceIntelligenceHostSurface) {
    let admitted = *ADMITTED_SURFACE.get_or_init(|| surface);
    if admitted != surface {
        tracing::warn!(
            admitted_surface = ?admitted,
            requested_surface = ?surface,
            "workspace intelligence host placement disagrees with the surface already admitted"
        );
    }
}

/// Reports one refusal and returns its stable code.
fn refuse(skip: CliHostSkip) -> &'static str {
    tracing::info!(
        host_placement = skip.code(),
        "workspace intelligence host refused for this command"
    );
    skip.code()
}

#[cfg(test)]
mod tests {
    use super::{
        drain, install, record_deployment, CliHostPlacement, CliHostSkip, HostSlot, CLOSED_CODE,
        DRAINED_CODE, INSTALL_CODE, NOT_INSTALLED_CODE, SLOT,
    };
    use openbitfun_core::infrastructure::PathManager;
    use openbitfun_core::service::workspace_intelligence::host_fixture;
    use openbitfun_core::service::workspace_intelligence::{
        WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostSurface,
    };
    use openbitfun_services_core::exclusive_file_lease::ExclusiveFileLease;
    use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio::sync::{watch, Mutex, MutexGuard};

    const ALL_SKIPS: [CliHostSkip; 6] = [
        CliHostSkip::Daemon,
        CliHostSkip::SharedRuntime,
        CliHostSkip::StdioServer,
        CliHostSkip::DetachedDispatch,
        CliHostSkip::Management,
        CliHostSkip::Acp,
    ];

    /// The slot is one process-wide resource, so these probes take turns.
    static PROBE_TURN: Mutex<()> = Mutex::const_new(());

    /// Takes the probe turn, empties the slot and records this probe's deployment.
    async fn probe_slot() -> MutexGuard<'static, ()> {
        let turn = PROBE_TURN.lock().await;
        *SLOT.lock().await = HostSlot::Empty;
        record_deployment(RuntimeDeployment::Embedded);
        turn
    }

    /// One isolated user-data root with one enabled scope.
    struct EnabledRoot {
        _temp: tempfile::TempDir,
        paths: Arc<PathManager>,
    }

    /// Builds an isolated root whose single workspace is seeded and enabled.
    async fn enabled_root(workspace_id: &str) -> EnabledRoot {
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let workspace = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace).expect("create the probe workspace");
        let paths = host_fixture::test_path_manager(&temp.path().join("user-root"));
        host_fixture::seed_local_workspace(paths.as_ref(), workspace_id, &workspace)
            .await
            .expect("seed the workspace record");
        host_fixture::enable_workspace(paths.as_ref(), workspace_id)
            .await
            .expect("enable the seeded workspace");
        EnabledRoot {
            _temp: temp,
            paths,
        }
    }

    #[test]
    fn every_refused_command_names_its_own_skip_code() {
        let mut seen: Vec<&'static str> = Vec::new();
        for skip in ALL_SKIPS {
            let code = skip.code();
            assert!(!code.is_empty(), "{skip:?} has an empty code");
            assert!(
                code.starts_with("host_skip_"),
                "{skip:?} code {code} is not a host_skip_ code"
            );
            assert!(
                !code.contains('/') && !code.contains('\\'),
                "{skip:?} code {code} contains a path separator"
            );
            assert!(
                !seen.contains(&code),
                "{skip:?} reuses the code {code} of another refusal"
            );
            seen.push(code);
        }
        assert_eq!(seen.len(), ALL_SKIPS.len());
    }

    #[test]
    fn an_install_placement_reports_the_install_code_and_the_expected_surface() {
        let interactive =
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive);
        let execution = CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliExecution);

        assert_eq!(interactive.code(), INSTALL_CODE);
        assert_eq!(interactive.code(), "install");
        assert_eq!(execution.code(), "install");
        assert!(matches!(
            interactive,
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive)
        ));
        assert!(matches!(
            execution,
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliExecution)
        ));
    }

    #[test]
    fn a_skip_placement_reports_its_skip_code_and_never_the_install_code() {
        for skip in ALL_SKIPS {
            let placement = CliHostPlacement::Skip(skip);
            assert_eq!(placement.code(), skip.code());
            assert_ne!(placement.code(), INSTALL_CODE);
        }
    }

    /// Proves the drain from inside one live process.
    ///
    /// A process that exits releases every OS lock it held, so a released lease
    /// observed after an exit status says nothing about the shutdown path. Here the
    /// process stays alive: while the host is installed the scope's lease cannot be
    /// taken, and only after [`drain`] returns can it be taken again.
    #[tokio::test]
    async fn a_drain_releases_the_lease_the_install_took() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-workspace").await;

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        let code = install(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
        )
        .await
        .expect("the admission must succeed");
        assert_eq!(code, INSTALL_CODE);

        let leases = lease_files(root.paths.as_ref());
        assert_eq!(
            leases.len(),
            1,
            "one enabled scope takes exactly one lease file: {leases:?}"
        );
        assert!(
            ExclusiveFileLease::try_acquire(&leases[0]).is_err(),
            "an installed host holds the scope lease while this process is alive"
        );

        assert_eq!(drain().await, Some(DRAINED_CODE));
        let released = ExclusiveFileLease::try_acquire(&leases[0])
            .expect("a drained host must release the scope lease it took");
        drop(released);
    }

    /// A second admission returns the first host instead of taking a second one.
    #[tokio::test]
    async fn a_second_admission_reuses_the_host_the_first_one_took() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-repeat-workspace").await;
        let placement = CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliExecution);

        let (_catalog, first_revision) = watch::channel(0_u64);
        let first = install(Arc::clone(&root.paths), first_revision, placement)
            .await
            .expect("the first admission must succeed");
        let (_catalog, second_revision) = watch::channel(0_u64);
        let second = install(Arc::clone(&root.paths), second_revision, placement)
            .await
            .expect("the second admission must succeed");

        assert_eq!(first, INSTALL_CODE);
        assert_eq!(second, INSTALL_CODE);

        let leases = lease_files(root.paths.as_ref());
        assert_eq!(
            leases.len(),
            1,
            "a repeated admission must not take a second lease: {leases:?}"
        );
        assert!(
            ExclusiveFileLease::try_acquire(&leases[0]).is_err(),
            "the lease the first admission took stays held by this process"
        );

        // A second bootstrap of the same scope in one process cannot own it, so the
        // slot would report a degraded host rather than this active one.
        let slot = SLOT.lock().await;
        let HostSlot::Running(host) = &*slot else {
            panic!("the slot must hold the admitted host");
        };
        let status = host.status().await;
        drop(slot);
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Active,
            "the slot must hold the host that owns the enabled scope"
        );
        assert_eq!(status.counts().active(), 1);

        assert_eq!(drain().await, Some(DRAINED_CODE));
    }

    /// A second drain repeats the first answer and stops nothing again.
    #[tokio::test]
    async fn a_second_drain_reports_the_drain_that_already_ran() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-redrain-workspace").await;

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        install(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
        )
        .await
        .expect("the admission must succeed");

        let first = drain().await;
        let second = drain().await;
        assert_eq!(first, Some(DRAINED_CODE));
        assert_eq!(
            second, first,
            "a repeated drain reports the drain that already ran"
        );
    }

    /// A drain that finds no host closes the slot against a late admission.
    ///
    /// The answer is sticky too: a second drain repeats the code instead of
    /// answering nothing, which is what the module promises for a repeated drain.
    #[tokio::test]
    async fn a_drain_before_an_admission_closes_the_slot() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-late-workspace").await;

        assert_eq!(drain().await, Some(NOT_INSTALLED_CODE));
        assert_eq!(
            drain().await,
            Some(NOT_INSTALLED_CODE),
            "a repeated drain reports the code of the drain that already ran"
        );

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        let late = install(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliExecution),
        )
        .await
        .expect("a closed slot answers with a code rather than an error");
        assert_eq!(late, CLOSED_CODE);
        assert!(
            !root.paths.workspace_intelligence_lease_dir().exists(),
            "an admission refused by a closed slot takes no lease"
        );
    }

    /// A drain arriving while an admission is in flight drains that admission.
    #[tokio::test]
    async fn an_admission_in_flight_is_not_overtaken_by_a_drain() {
        let _turn = probe_slot().await;
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user-root"));

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        let (admitted, drained) = tokio::join!(
            install(
                Arc::clone(&paths),
                catalog_revision,
                CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliExecution),
            ),
            drain()
        );
        assert_eq!(
            admitted.expect("the admission must succeed"),
            INSTALL_CODE
        );
        assert_eq!(
            drained,
            Some(DRAINED_CODE),
            "a drain that arrives while the admission holds the slot must drain it"
        );
    }

    /// Every `.lock` file inside the host's lease root.
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
}
