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
//! A `Shared` deployment is refused by this module before the slot is touched,
//! before a root is resolved, before a catalog is subscribed and before any lease
//! or partition exists: the shared runtime owns the workspace until it drains, so
//! this process admits nothing for it. The host owner answers the same refusal,
//! but only after this module had already published a handle and claimed a surface
//! for a host that owns nothing.
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
/// A later disagreement is reported and the first record stands: this reads back
/// the stored value with `get_or_init`, so the comparison sees what is really
/// recorded. `OnceLock::set` would answer `Err` with the value that failed to be
/// stored rather than the stored one, which would make a disagreement look equal.
pub(crate) fn record_deployment(deployment: RuntimeDeployment) {
    let recorded = *DEPLOYMENT.get_or_init(|| deployment);
    if recorded != deployment {
        tracing::warn!(
            recorded_deployment = %recorded,
            requested_deployment = %deployment,
            "workspace intelligence host deployment disagrees with the one already recorded"
        );
    }
}

/// Reads the deployment this process built its runtime ownership with, if any.
///
/// This is the one place an admission learns its deployment, and the record itself
/// keeps the first value: a later, disagreeing record only reports, so a running
/// process cannot switch its live profile. An admission without a record is
/// answered by [`host_admission`] instead of being defaulted here.
fn recorded_deployment() -> Option<RuntimeDeployment> {
    DEPLOYMENT.get().copied()
}

/// What an admission may do, decided from the recorded deployment alone.
enum HostAdmission {
    /// The deployment this process may host on.
    Admit(RuntimeDeployment),
    /// A typed refusal that reads and takes nothing.
    Refuse(&'static str),
}

/// Decides an admission from the deployment fact before any dependency is read.
///
/// A `Shared` deployment keeps the workspace under the shared runtime until that
/// owner drains, so this process admits nothing for it. The refusal is decided
/// here, before the slot, the user-data root, the catalog subscription, the lease
/// and the partition: the host owner answers the same refusal, but only after this
/// module had already published a handle and claimed a surface for a host that owns
/// nothing, and that handle is what a later call would reuse as if it were live.
///
/// A missing fact fails closed instead of defaulting to `Embedded`: a host
/// bootstrapped on a guess would take a lease and answer for a workspace nobody
/// owns, and `Embedded` is exactly the deployment the composition root did not
/// record.
fn host_admission(deployment: Option<RuntimeDeployment>) -> anyhow::Result<HostAdmission> {
    match deployment {
        Some(RuntimeDeployment::Embedded) => {
            Ok(HostAdmission::Admit(RuntimeDeployment::Embedded))
        }
        Some(RuntimeDeployment::Shared) => {
            tracing::info!(
                host_placement = CliHostSkip::SharedRuntime.code(),
                host_deployment = %RuntimeDeployment::Shared,
                "workspace intelligence host admission refused on a shared runtime deployment"
            );
            Ok(HostAdmission::Refuse(CliHostSkip::SharedRuntime.code()))
        }
        None => {
            tracing::error!(
                host_placement = INSTALL_CODE,
                "workspace intelligence host admission has no recorded runtime ownership deployment"
            );
            anyhow::bail!(
                "workspace intelligence host admission requires the deployment the process runtime ownership was built with"
            )
        }
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
/// without bootstrapping. A `Shared` deployment is refused with its own code and a
/// missing deployment fails, both before the slot is touched. A second call that
/// names a different surface is reported, and the surface the first admission
/// claimed stays the one the host runs on.
pub(crate) async fn install(
    paths: std::sync::Arc<PathManager>,
    catalog_revision: watch::Receiver<u64>,
    placement: CliHostPlacement,
) -> anyhow::Result<&'static str> {
    install_resolved(paths, catalog_revision, placement, recorded_deployment()).await
}

/// The one admission body, with the deployment fact as a parameter.
///
/// `deployment` is the fact read from the process runtime ownership record, so a
/// probe can supply the two facts production cannot arrange there — no record, and
/// `Shared` — through the same decision and publish code [`install`] runs, without
/// resetting the process-wide record, patching a global or waiting on a clock. The
/// placement and the deployment are decided before the slot is taken and before the
/// host owner is called, so a refusal reaches neither.
async fn install_resolved(
    paths: std::sync::Arc<PathManager>,
    catalog_revision: watch::Receiver<u64>,
    placement: CliHostPlacement,
    deployment: Option<RuntimeDeployment>,
) -> anyhow::Result<&'static str> {
    let surface = match placement {
        CliHostPlacement::Skip(skip) => return Ok(refuse(skip)),
        CliHostPlacement::Install(surface) => surface,
    };
    let deployment = match host_admission(deployment)? {
        HostAdmission::Admit(deployment) => deployment,
        HostAdmission::Refuse(code) => return Ok(code),
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

    let host = WorkspaceIntelligenceHost::bootstrap(
        paths,
        Some(catalog_revision),
        surface,
        deployment,
    )
    .await;
    // Only an admission that really publishes a host claims the surface, so a
    // failed or refused admission cannot make a later admission look like a
    // disagreement that no host ever had.
    *slot = HostSlot::Running(host);
    record_surface(surface);
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
/// A skip answers before any source is consulted. A refusal decided from the
/// deployment alone returns before the root is resolved, so a `Shared` deployment
/// or a missing record cannot touch storage at all. The admitted case resolves the
/// root and the catalog revision and then runs [`install`], which reads the same
/// first-wins deployment record before it publishes anything. A path manager that
/// failed to initialize is an error instead of a fallback root a host would then
/// anchor on.
pub(crate) async fn install_for(placement: CliHostPlacement) -> anyhow::Result<&'static str> {
    install_for_with(placement, recorded_deployment, resolve_install_source).await
}

/// Resolves the root and catalog revision the production wrapper admits on.
///
/// This is the only place the wrapper reads the process-wide path owner. It is a
/// zero-argument function of its own so [`install_for_with`] can replace both reads
/// with counters in a probe: the ordering between the deployment screen and the
/// storage read is then proven without resetting the shared path manager.
fn resolve_install_source() -> anyhow::Result<(std::sync::Arc<PathManager>, watch::Receiver<u64>)> {
    let paths = resolve_install_root(openbitfun_core::infrastructure::try_get_path_manager_arc())?;
    Ok((paths, WorkspaceService::subscribe_catalog_changes()))
}

/// The wrapper body with its two process-wide sources injected.
///
/// `deployment` reads the first-wins record the runtime owner was built with and
/// `source` resolves the user-data root and the catalog revision. Both are
/// parameters so a probe can supply a missing or `Shared` deployment and count the
/// source reads: a refusal must answer before the root is resolved, and an
/// unavailable root must keep its own error instead of becoming a host-profile
/// refusal. Production passes [`recorded_deployment`] and
/// [`resolve_install_source`], so the second read [`install`] makes sees the same
/// first-wins record the screen saw.
async fn install_for_with<D, S>(
    placement: CliHostPlacement,
    deployment: D,
    source: S,
) -> anyhow::Result<&'static str>
where
    D: FnOnce() -> Option<RuntimeDeployment>,
    S: FnOnce() -> anyhow::Result<(std::sync::Arc<PathManager>, watch::Receiver<u64>)>,
{
    if let CliHostPlacement::Skip(skip) = placement {
        return Ok(refuse(skip));
    }
    match host_admission(deployment())? {
        HostAdmission::Admit(_) => {}
        HostAdmission::Refuse(code) => return Ok(code),
    }
    let (paths, catalog_revision) = source()?;
    install(paths, catalog_revision, placement).await
}

/// Turns the path owner's lookup into the root an admission runs on.
///
/// The path owner's own diagnostic is kept verbatim, and a failed lookup stays an
/// error rather than becoming a fallback root: a host bootstrapped on a fallback
/// would anchor, lease and partition a workspace nobody selected. An unreadable
/// storage root is not an unsupported host profile either, so it must not turn into
/// a refusal code.
fn resolve_install_root(
    resolved: openbitfun_core::OpenBitFunResult<std::sync::Arc<PathManager>>,
) -> anyhow::Result<std::sync::Arc<PathManager>> {
    resolved.map_err(|error| anyhow::anyhow!(error.to_string()))
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
    //! Probes for the CLI host placement.
    //!
    //! Two of them cannot be reached through this module's exported wrappers.
    //! Production always records the deployment of the owner it just built before an
    //! admission, and a process that really runs `Shared` already places
    //! `Skip(SharedRuntime)` at its entry point, so a missing record and a `Shared`
    //! deployment reaching an `Install` placement are defense branches. They are
    //! proven by handing the deployment fact straight to the private admission body
    //! `install_resolved`, which is the same decision and publish code the wrappers
    //! call. No probe resets the process-wide record, patches a global, or depends on
    //! a clock or on the order the harness runs tests in.

    use super::{
        drain, install, install_for_with, install_resolved, record_deployment, recorded_deployment,
        resolve_install_root, CliHostPlacement, CliHostSkip, HostSlot, CLOSED_CODE, DRAINED_CODE,
        INSTALL_CODE, NOT_INSTALLED_CODE, SLOT,
    };
    use openbitfun_core::infrastructure::PathManager;
    use openbitfun_core::service::workspace_intelligence::host_fixture;
    use openbitfun_core::service::workspace_intelligence::{
        WorkspaceIntelligenceHostState, WorkspaceIntelligenceHostSurface,
    };
    use openbitfun_services_core::exclusive_file_lease::ExclusiveFileLease;
    use openbitfun_services_core::runtime_ownership::RuntimeDeployment;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use tokio::sync::{watch, Mutex, MutexGuard};

    /// A `MakeWriter` that keeps what a subscriber formats, so a probe can read the
    /// warning a real `record_deployment` disagreement produces.
    ///
    /// It is only a byte sink for this module's own subscriber; it adds no
    /// dependency (both `tracing` and `tracing-subscriber` are already direct
    /// dependencies of this crate) and installs nothing globally, so a parallel test
    /// thread keeps whatever subscriber it had.
    #[derive(Clone, Default)]
    struct CapturedLog(Arc<StdMutex<Vec<u8>>>);

    impl CapturedLog {
        fn contents(&self) -> String {
            String::from_utf8(
                self.0
                    .lock()
                    .expect("the capturing log lock is never poisoned")
                    .clone(),
            )
            .expect("a tracing subscriber writes UTF-8 text")
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLog {
        type Writer = Self;

        fn make_writer(&'writer self) -> Self::Writer {
            self.clone()
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the capturing log lock is never poisoned")
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    const ALL_SKIPS: [CliHostSkip; 6] = [
        CliHostSkip::Daemon,
        CliHostSkip::SharedRuntime,
        CliHostSkip::StdioServer,
        CliHostSkip::DetachedDispatch,
        CliHostSkip::Management,
        CliHostSkip::Acp,
    ];

    /// The surface the refused-admission probes name.
    ///
    /// It is a surface no real host is ever bootstrapped on here: every probe using
    /// it reports before the slot or the host owner is reached, so a defect that
    /// bootstrapped on it would still be caught by the empty slot and the unchanged
    /// user-data tree.
    ///
    /// `ADMITTED_SURFACE` is deliberately **not** asserted from these probes. It is a
    /// process-wide first-wins value, and another probe in this same process may have
    /// claimed a different surface already, so `ADMITTED_SURFACE != Some(here)` would
    /// hold whether or not the refusal wrongly recorded one. Reading it back would be
    /// a vacuous assertion, not evidence, so the unconditional evidence used instead
    /// is: the slot is still empty, the refusal's own source read count is zero, and
    /// the user-data tree (including the control record bytes) is unchanged.
    const REFUSED_PROBE_SURFACE: WorkspaceIntelligenceHostSurface =
        WorkspaceIntelligenceHostSurface::Daemon;

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

    /// A `Shared` deployment is refused before the host owns anything.
    ///
    /// The probe injects the deployment fact into the same admission body the
    /// wrappers call, because a production process that really runs `Shared` places
    /// `Skip(SharedRuntime)` at its entry point and never reaches this branch. The
    /// enabled root is a real ON fixture, so the byte snapshot covers the control
    /// record and its generation token: a refusal cannot re-stamp either of them.
    #[tokio::test]
    async fn a_shared_deployment_is_refused_before_the_host_owns_anything() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-shared-workspace").await;
        let before = tree_snapshot(&root.paths.user_data_dir());
        let (_catalog, catalog_revision) = watch::channel(0_u64);

        let code = install_resolved(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            Some(RuntimeDeployment::Shared),
        )
        .await
        .expect("a shared deployment answers a typed refusal instead of an error");

        assert_eq!(code, "host_skip_shared_runtime");
        assert_eq!(code, CliHostSkip::SharedRuntime.code());
        assert_ne!(code, INSTALL_CODE, "a refusal must never claim an install");
        // The empty slot and the byte-identical tree below are the unconditional
        // evidence; the surface record is not asserted, because it is a process-wide
        // first-wins value this probe cannot read as a claim it did not make.
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a shared refusal must not put anything in the host slot"
        );
        assert!(
            !root.paths.workspace_intelligence_lease_dir().exists(),
            "a shared refusal takes no lease"
        );
        assert_tree_unchanged(&before, &root.paths.user_data_dir());

        assert_eq!(drain().await, Some(NOT_INSTALLED_CODE));
        assert_eq!(
            drain().await,
            Some(NOT_INSTALLED_CODE),
            "the drain answer stays sticky after a shared refusal"
        );
        assert_tree_unchanged(&before, &root.paths.user_data_dir());
    }

    /// A later `Shared` refusal leaves an admitted host and its lease untouched.
    ///
    /// This is the refused direction of the reuse rule: the refusal answers its own
    /// code and cannot replace, stop or re-claim the handle this process already
    /// published.
    #[tokio::test]
    async fn a_later_shared_refusal_leaves_the_admitted_host_untouched() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-shared-after-workspace").await;
        let (_catalog, catalog_revision) = watch::channel(0_u64);
        assert_eq!(
            install(
                Arc::clone(&root.paths),
                catalog_revision,
                CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
            )
            .await
            .expect("the admission must succeed"),
            INSTALL_CODE
        );
        let leases = lease_files(root.paths.as_ref());
        assert_eq!(
            leases.len(),
            1,
            "one enabled scope takes exactly one lease file: {leases:?}"
        );

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        let code = install_resolved(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            Some(RuntimeDeployment::Shared),
        )
        .await
        .expect("a shared deployment answers a typed refusal instead of an error");
        assert_eq!(code, CliHostSkip::SharedRuntime.code());
        assert_ne!(code, INSTALL_CODE);
        assert!(
            ExclusiveFileLease::try_acquire(&leases[0]).is_err(),
            "a shared refusal must not release or retake the lease of the admitted host"
        );

        let slot = SLOT.lock().await;
        let HostSlot::Running(host) = &*slot else {
            panic!("a shared refusal must leave the admitted host in the slot");
        };
        let status = host.status().await;
        drop(slot);
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Active,
            "the admitted host must still own its enabled scope"
        );

        assert_eq!(drain().await, Some(DRAINED_CODE));
    }

    /// A missing deployment fact fails closed and leaves nothing behind.
    ///
    /// Production always records the fact before an admission, so this is the other
    /// defense branch; it is injected rather than produced by resetting the record.
    #[tokio::test]
    async fn a_missing_deployment_fails_closed_without_a_slot_a_surface_or_a_write() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-unrecorded-workspace").await;
        let before = tree_snapshot(&root.paths.user_data_dir());
        let (_catalog, catalog_revision) = watch::channel(0_u64);

        let error = install_resolved(
            Arc::clone(&root.paths),
            catalog_revision,
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            None,
        )
        .await
        .expect_err("an admission without a recorded deployment must fail");

        assert!(
            error.to_string().contains("requires the deployment"),
            "the failure must name the missing fact: {error}"
        );
        // Unconditional evidence as above: an untouched slot and an unchanged tree.
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a missing deployment must not put anything in the host slot"
        );
        assert!(
            !root.paths.workspace_intelligence_lease_dir().exists(),
            "a failed admission takes no lease"
        );
        assert_tree_unchanged(&before, &root.paths.user_data_dir());

        // The failed admission left the slot open, so the real record still admits.
        let (_catalog, admission_catalog) = watch::channel(0_u64);
        assert_eq!(
            install(
                Arc::clone(&root.paths),
                admission_catalog,
                CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
            )
            .await
            .expect("the recorded deployment still admits"),
            INSTALL_CODE
        );
        assert_eq!(drain().await, Some(DRAINED_CODE));
    }

    /// A skip answers before the deployment fact or a root is used.
    ///
    /// A process that names a skip owns no workspace, so it must not resolve a root,
    /// subscribe to a catalog or read the deployment record, and a refusal is not an
    /// error. The isolated root is never handed to the admission, so the OFF
    /// direction writes nothing.
    #[tokio::test]
    async fn a_skip_placement_answers_before_any_source_is_read() {
        let _turn = probe_slot().await;
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user-root"));

        for skip in [CliHostSkip::SharedRuntime, CliHostSkip::Daemon] {
            // The injected deployment is missing on purpose: a skip is decided before
            // the deployment is consulted, exactly as it is before the root.
            let (_catalog, catalog_revision) = watch::channel(0_u64);
            let code = install_resolved(
                Arc::clone(&paths),
                catalog_revision,
                CliHostPlacement::Skip(skip),
                None,
            )
            .await
            .expect("a skip answers with its code rather than an error");
            assert_eq!(code, skip.code());
            assert_ne!(code, INSTALL_CODE);
        }

        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a skip must not put anything in the host slot"
        );
        assert!(
            !paths.workspace_intelligence_dir().exists(),
            "a skip creates no workspace intelligence root"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read the isolated probe root")
                .count(),
            0,
            "a refusal writes nothing at all"
        );
    }

    /// A `Shared` deployment through the real wrapper refuses before the root.
    ///
    /// The deployment and the source are injected because the probe cannot make the
    /// first-wins record `Shared` or the process-wide path owner fail without
    /// resetting a global. They are the same two reads the production wrapper makes,
    /// so the ordering is proven on the real wrapper body: the refusal answers with
    /// zero source reads, which is why no root, catalog or lease is touched. This is
    /// a defense branch: a process that really runs `Shared` places
    /// `Skip(SharedRuntime)` at its entry point and never reaches an `Install`
    /// placement.
    #[tokio::test]
    async fn an_install_for_shared_deployment_refuses_before_the_root_is_resolved() {
        let _turn = probe_slot().await;
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user-root"));
        let deployment_reads = AtomicUsize::new(0);
        let source_reads = AtomicUsize::new(0);

        let code = install_for_with(
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            || {
                deployment_reads.fetch_add(1, Ordering::SeqCst);
                Some(RuntimeDeployment::Shared)
            },
            || {
                source_reads.fetch_add(1, Ordering::SeqCst);
                Ok((Arc::clone(&paths), watch::channel(0_u64).1))
            },
        )
        .await
        .expect("a shared deployment answers a code rather than an error");

        assert_eq!(
            deployment_reads.load(Ordering::SeqCst),
            1,
            "the wrapper must screen the deployment exactly once"
        );
        assert_eq!(
            source_reads.load(Ordering::SeqCst),
            0,
            "a shared refusal must not resolve a root or subscribe a catalog"
        );
        assert_eq!(code, CliHostSkip::SharedRuntime.code());
        assert_ne!(code, INSTALL_CODE, "a refusal must never claim an install");
        // Unconditional evidence: the refusal answered with zero source reads, so no
        // root or catalog was touched, and the slot stayed empty. The process-wide
        // surface record is not asserted here; see its note in this module's tests.
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a shared refusal must not put anything in the host slot"
        );
        assert!(
            !paths.workspace_intelligence_dir().exists(),
            "a shared refusal creates no workspace intelligence root"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read the isolated probe root")
                .count(),
            0,
            "a refused admission writes nothing at all"
        );
    }

    /// A missing deployment through the real wrapper fails before the root too.
    ///
    /// This is the other defense branch production cannot arrange: the composition
    /// root records the deployment before it registers a host placement. The probe
    /// injects the missing fact into the wrapper body instead of resetting the
    /// first-wins record, and counts the source reads to prove the failure precedes
    /// any storage lookup.
    #[tokio::test]
    async fn an_install_for_missing_deployment_fails_before_the_root_is_resolved() {
        let _turn = probe_slot().await;
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let source_reads = AtomicUsize::new(0);

        let error = install_for_with(
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            || None,
            || {
                source_reads.fetch_add(1, Ordering::SeqCst);
                Ok((
                    host_fixture::test_path_manager(&temp.path().join("user-root")),
                    watch::channel(0_u64).1,
                ))
            },
        )
        .await
        .expect_err("an admission without a recorded deployment must fail");

        assert!(
            error.to_string().contains("requires the deployment"),
            "the failure must name the missing fact: {error}"
        );
        assert_eq!(
            source_reads.load(Ordering::SeqCst),
            0,
            "a missing deployment must not resolve a root or subscribe a catalog"
        );
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a missing deployment must not put anything in the host slot"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read the isolated probe root")
                .count(),
            0,
            "a failed admission writes nothing at all"
        );
    }

    /// A skip through the real wrapper answers before the deployment or the root.
    ///
    /// A process that names a skip owns no workspace, so the wrapper must not read
    /// the deployment record or the storage source. `SharedRuntime` is included: the
    /// static entry-point skip stays the first answer, ahead of the deployment screen
    /// that would refuse the same command dynamically.
    #[tokio::test]
    async fn an_install_for_skip_answers_before_the_deployment_or_the_root() {
        let _turn = probe_slot().await;
        let deployment_reads = AtomicUsize::new(0);
        let source_reads = AtomicUsize::new(0);

        for skip in [CliHostSkip::SharedRuntime, CliHostSkip::Daemon] {
            let code = install_for_with(
                CliHostPlacement::Skip(skip),
                || {
                    deployment_reads.fetch_add(1, Ordering::SeqCst);
                    None
                },
                || {
                    source_reads.fetch_add(1, Ordering::SeqCst);
                    Err(anyhow::anyhow!("a skip must not resolve a root"))
                },
            )
            .await
            .expect("a skip answers with its code rather than an error");
            assert_eq!(code, skip.code());
            assert_ne!(code, INSTALL_CODE);
        }

        assert_eq!(
            deployment_reads.load(Ordering::SeqCst),
            0,
            "a skip must not read the deployment record"
        );
        assert_eq!(
            source_reads.load(Ordering::SeqCst),
            0,
            "a skip must not resolve a root"
        );
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "a skip must not put anything in the host slot"
        );
    }

    /// An unavailable root through the real wrapper keeps its own error.
    ///
    /// The injection replaces the production `try_get_path_manager_arc` lookup with
    /// the same error that lookup returns when the shared path owner failed. The
    /// wrapper must propagate it verbatim rather than fall back to another root or
    /// report a host-profile refusal: an unreadable storage root is not an
    /// unsupported profile, and nothing may be leased or partitioned.
    #[tokio::test]
    async fn an_install_for_unavailable_root_keeps_its_own_error() {
        let _turn = probe_slot().await;
        let expected =
            "global path manager is using a temporary fallback after initialization failed";

        let error = install_for_with(
            CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
            || Some(RuntimeDeployment::Embedded),
            || Err(anyhow::anyhow!(expected)),
        )
        .await
        .expect_err("an unavailable root is an error, not a hosted refusal");

        assert_eq!(
            error.to_string(),
            expected,
            "the source's own diagnostic must survive the wrapper"
        );
        assert!(
            !error.to_string().contains("profile"),
            "unreadable storage must not be reported as an unsupported profile: {error}"
        );
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "an unavailable root must not put anything in the host slot"
        );
    }

    /// The wrapper's admitted path still bootstraps and drains the legacy host.
    ///
    /// Only the source is injected here; the deployment is the real first-wins
    /// record the probe set, so this is the same `Embedded` path a production CLI
    /// command takes.
    #[tokio::test]
    async fn an_install_for_embedded_scope_still_bootstraps_and_drains() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-install-for-workspace").await;
        let (_catalog, catalog_revision) = watch::channel(0_u64);

        let code = install_for_with(
            CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
            recorded_deployment,
            || Ok((Arc::clone(&root.paths), catalog_revision)),
        )
        .await
        .expect("the wrapper admits the embedded deployment");
        assert_eq!(code, INSTALL_CODE);
        assert_eq!(
            lease_files(root.paths.as_ref()).len(),
            1,
            "the admitted scope takes exactly one lease"
        );

        assert_eq!(drain().await, Some(DRAINED_CODE));
    }

    /// An unavailable root keeps the path owner's own error and hosts nothing.
    ///
    /// The real wrapper resolves its root through this mapping, so an admission that
    /// cannot resolve one must not fall back to another root and must not report a
    /// host-profile refusal: an unreadable storage root is not an unsupported
    /// profile.
    #[tokio::test]
    async fn an_unresolvable_root_keeps_its_own_error_and_answers_no_install() {
        let _turn = probe_slot().await;
        let temp = tempfile::tempdir().expect("create an isolated probe root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user-root"));
        let source = openbitfun_core::OpenBitFunError::config(
            "global path manager is using a temporary fallback after initialization failed",
        );
        let expected = source.to_string();

        let error = resolve_install_root(Err(source))
            .expect_err("an unavailable root is an error, not a hosted refusal");

        assert_eq!(
            error.to_string(),
            expected,
            "the path owner's own diagnostic must survive the admission"
        );
        assert!(
            !error.to_string().contains("profile"),
            "unreadable storage must not be reported as an unsupported profile: {error}"
        );
        assert!(
            Arc::ptr_eq(
                &resolve_install_root(Ok(Arc::clone(&paths))).expect("a resolved root is used as is"),
                &paths
            ),
            "a resolved root must be used as it was found, not replaced by a fallback"
        );
        assert!(
            matches!(&*SLOT.lock().await, HostSlot::Empty),
            "an unavailable root must not put anything in the host slot"
        );
        assert_eq!(
            std::fs::read_dir(temp.path())
                .expect("read the isolated probe root")
                .count(),
            0,
            "a failed admission writes nothing"
        );
    }

    /// A refusal cannot reopen a slot a drain closed.
    ///
    /// Both defense branches answer before the slot is touched, and neither may let a
    /// later admission bootstrap past the closed state that keeps a lease from
    /// outliving the shutdown path.
    #[tokio::test]
    async fn a_refusal_does_not_reopen_a_slot_a_drain_closed() {
        let _turn = probe_slot().await;
        let root = enabled_root("wi-unit-closed-refusal-workspace").await;
        assert_eq!(drain().await, Some(NOT_INSTALLED_CODE));

        let (_catalog, shared_catalog) = watch::channel(0_u64);
        assert_eq!(
            install_resolved(
                Arc::clone(&root.paths),
                shared_catalog,
                CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
                Some(RuntimeDeployment::Shared),
            )
            .await
            .expect("a shared deployment answers a code"),
            CliHostSkip::SharedRuntime.code()
        );
        let (_catalog, missing_catalog) = watch::channel(0_u64);
        assert!(
            install_resolved(
                Arc::clone(&root.paths),
                missing_catalog,
                CliHostPlacement::Install(REFUSED_PROBE_SURFACE),
                None,
            )
            .await
            .is_err(),
            "a missing deployment stays an error after a drain closed the slot"
        );

        let (_catalog, catalog_revision) = watch::channel(0_u64);
        assert_eq!(
            install(
                Arc::clone(&root.paths),
                catalog_revision,
                CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
            )
            .await
            .expect("a closed slot answers with a code rather than an error"),
            CLOSED_CODE,
            "no refusal may reopen the slot the shutdown path closed"
        );
        assert!(
            !root.paths.workspace_intelligence_lease_dir().exists(),
            "nothing may take a lease after the slot closed"
        );
    }

    /// A disagreeing record is reported and the first record still stands.
    ///
    /// This is the observable half of `record_deployment`: the comparison reads the
    /// stored value back, so a `Shared` record arriving after `Embedded` really does
    /// warn. `OnceLock::set` would have answered `Err` with the value it failed to
    /// store, which is how a previous version of this function became a silent
    /// no-op. The subscriber is thread-local and captures formatted bytes, so the
    /// probe neither installs a global subscriber nor depends on another test's
    /// thread.
    #[tokio::test]
    async fn a_disagreeing_record_warns_and_leaves_the_first_record_in_place() {
        let _turn = probe_slot().await;
        assert_eq!(
            recorded_deployment(),
            Some(RuntimeDeployment::Embedded),
            "the probe records its deployment before this comparison"
        );

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            record_deployment(RuntimeDeployment::Shared);
        });
        let logged = captured.contents();

        assert!(
            logged.contains("workspace intelligence host deployment disagrees"),
            "a disagreeing record must report the disagreement: {logged}"
        );
        assert!(
            logged.contains("recorded_deployment=embedded"),
            "the report must name the record that stands: {logged}"
        );
        assert!(
            logged.contains("requested_deployment=shared"),
            "the report must name the record that was refused: {logged}"
        );
        assert_eq!(
            recorded_deployment(),
            Some(RuntimeDeployment::Embedded),
            "a later record must not switch the live profile"
        );
    }

    /// An agreeing repeated record stays silent and keeps the first record.
    ///
    /// The other half of the same contract: the ordinary case reports nothing, so the
    /// warning above is a disagreement signal rather than a line every CLI start
    /// produces.
    #[tokio::test]
    async fn an_agreeing_repeated_record_is_silent() {
        let _turn = probe_slot().await;

        let captured = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            record_deployment(RuntimeDeployment::Embedded);
        });
        let logged = captured.contents();

        assert!(
            !logged.contains("deployment disagrees"),
            "an agreeing record must not warn: {logged}"
        );
        assert_eq!(
            recorded_deployment(),
            Some(RuntimeDeployment::Embedded),
            "the agreeing record keeps the deployment it agrees with"
        );
    }

    /// The first recorded deployment stands against a later record.
    ///
    /// A second record cannot switch the live profile of a running process: the
    /// record is what an admission runs on, so a later `Shared` record must leave an
    /// `Embedded` process admitting exactly as before.
    #[tokio::test]
    async fn the_first_recorded_deployment_stands_against_a_later_record() {
        let _turn = probe_slot().await;
        assert_eq!(
            recorded_deployment(),
            Some(RuntimeDeployment::Embedded),
            "the probe records its deployment before any admission"
        );

        record_deployment(RuntimeDeployment::Shared);
        assert_eq!(
            recorded_deployment(),
            Some(RuntimeDeployment::Embedded),
            "a later record must not switch the live profile"
        );

        let root = enabled_root("wi-unit-first-record-workspace").await;
        let (_catalog, catalog_revision) = watch::channel(0_u64);
        assert_eq!(
            install(
                Arc::clone(&root.paths),
                catalog_revision,
                CliHostPlacement::Install(WorkspaceIntelligenceHostSurface::CliInteractive),
            )
            .await
            .expect("the first record still admits"),
            INSTALL_CODE
        );
        assert_eq!(drain().await, Some(DRAINED_CODE));
    }

    /// Every file under `root` with its exact bytes.
    ///
    /// The user-data tree is the whole footprint of an admission: the workspace
    /// catalog, the storage anchor, the control record including its generation
    /// token, the cognition partition and the lease root. Byte equality is therefore
    /// the strongest statement a refusal can make: nothing was created, rewritten or
    /// re-stamped.
    fn tree_snapshot(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut files = Vec::new();
        collect_tree(root, root, &mut files);
        files.sort();
        files
    }

    fn collect_tree(root: &Path, directory: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("read a probe tree entry");
            let path = entry.path();
            if entry
                .file_type()
                .expect("read a probe tree entry type")
                .is_dir()
            {
                collect_tree(root, &path, files);
            } else {
                let relative = path
                    .strip_prefix(root)
                    .expect("a probe tree entry stays under its root")
                    .to_path_buf();
                files.push((relative, std::fs::read(&path).expect("read a probe tree file")));
            }
        }
    }

    fn assert_tree_unchanged(before: &[(PathBuf, Vec<u8>)], root: &Path) {
        assert_eq!(
            tree_snapshot(root),
            before,
            "a refused admission must not create, rewrite or re-stamp anything under {root:?}; \
             the control record bytes and its generation token are part of this comparison"
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
