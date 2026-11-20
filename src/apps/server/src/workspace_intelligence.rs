//! Workspace intelligence host placement for the loopback app server.
//!
//! This app serves one loopback endpoint and drives one in-process Agent Runtime,
//! so it admits at most one workspace intelligence host: on the `ServerLoopback`
//! surface and on the deployment the server's own runtime ownership already
//! selected. The surface is a constant rather than a parameter because the stdio
//! app-server surface is served by the CLI command that speaks that protocol on
//! its own streams, so a parameter would only let a caller name a surface this app
//! cannot be.
//!
//! A refusal is a typed code, not a startup failure, and it costs no IO: no
//! anchor, no catalog read, no lease and no write. The admitted handle is returned
//! to the caller and kept in the server's own state instead of a module static,
//! because that state is already this process's single owner; the shutdown path
//! takes the handle back out and drains it before the plugin host stops, so a host
//! never outlives the listener that admitted it.
//!
//! Nothing here prints: the module reports through the codes its two call sites
//! log, so the loopback listener's own output stays byte-identical.

use std::sync::Arc;

use openbitfun_core::infrastructure::PathManager;
use openbitfun_core::runtime_ownership::RuntimeDeployment;
use openbitfun_core::service::workspace_intelligence::{
    WorkspaceIntelligenceHost, WorkspaceIntelligenceHostDrain, WorkspaceIntelligenceHostSurface,
};
use tokio::sync::{watch, Mutex};

/// Stable code of a placement that admitted the host.
#[cfg_attr(
    not(feature = "workspace-intelligence-host"),
    allow(dead_code, reason = "this build compiles no host body to admit")
)]
pub(crate) const INSTALL_CODE: &str = "install";

/// Stable code of a drain that stopped with no owner work outstanding.
pub(crate) const DRAINED_CODE: &str = "drained";

/// Stable code of a drain that stopped waiting while owner work was in flight.
pub(crate) const DRAIN_TIMED_OUT_CODE: &str = "drain_timed_out";

/// Stable code of a drain that found no handle because none was admitted.
pub(crate) const NOT_INSTALLED_CODE: &str = "not_installed";

/// The one delivery surface this app hosts.
const ADMITTED_SURFACE: WorkspaceIntelligenceHostSurface =
    WorkspaceIntelligenceHostSurface::ServerLoopback;

/// Why this server admitted no workspace intelligence host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ServerHostSkip {
    /// The stdio app-server surface speaks a protocol on the process streams and is
    /// hosted by the CLI command that owns it, never by this loopback app.
    StdioServer,
    /// A shared runtime owns the workspace and has not drained it.
    SharedRuntime,
    /// This build does not compile the host body.
    NotCompiled,
}

impl ServerHostSkip {
    /// Stable machine-readable code for status data and logs.
    ///
    /// The codes are lowercase, separator-free and distinct per variant, so a log
    /// line names exactly one refusal.
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::StdioServer => "host_skip_stdio_server",
            Self::SharedRuntime => "host_skip_shared_runtime",
            Self::NotCompiled => "not_compiled",
        }
    }
}

/// Screens the delivery surface this app is about to admit.
///
/// [`ADMITTED_SURFACE`] is the only hostable one. The app-server surfaces are the
/// loopback endpoint this app serves and the stdio protocol another command owns,
/// so a surface that is not the admitted one is refused with the stdio code
/// instead of being bootstrapped: this app runs no stdio host and bootstraps no
/// host for a surface it does not serve.
fn screen_surface(surface: WorkspaceIntelligenceHostSurface) -> Result<(), ServerHostSkip> {
    if surface == ADMITTED_SURFACE {
        return Ok(());
    }
    Err(ServerHostSkip::StdioServer)
}

/// Installs the host for this app's loopback surface and returns its stable code.
///
/// The code is the placement's own answer and the handle is the admitted host, or
/// `None` when this app admitted none. A `Shared` deployment is refused before
/// anything is read, and a build without the host feature answers the typed
/// refusal without touching `paths`.
pub(crate) async fn install(
    paths: Arc<PathManager>,
    catalog_revision: Option<watch::Receiver<u64>>,
    deployment: RuntimeDeployment,
) -> (&'static str, Option<WorkspaceIntelligenceHost>) {
    if let Err(skip) = screen_surface(ADMITTED_SURFACE) {
        return (skip.code(), None);
    }
    if deployment == RuntimeDeployment::Shared {
        // A shared runtime owns the workspace until it drains, so this app admits
        // nothing for it: the refusal is total and costs no IO.
        return (ServerHostSkip::SharedRuntime.code(), None);
    }

    #[cfg(feature = "workspace-intelligence-host")]
    {
        let host = WorkspaceIntelligenceHost::bootstrap(
            paths,
            catalog_revision,
            ADMITTED_SURFACE,
            deployment,
        )
        .await;
        (INSTALL_CODE, Some(host))
    }

    #[cfg(not(feature = "workspace-intelligence-host"))]
    {
        // No host body exists in this build, so nothing is resolved, leased or
        // written; the inputs are consumed without being used.
        let _ = (paths, catalog_revision);
        (ServerHostSkip::NotCompiled.code(), None)
    }
}

/// Awaits the host's bounded drain once and returns its stable code.
///
/// The handle is consumed, and the shutdown path takes it out of the server state
/// before calling this, so one admission is drained at most once.
pub(crate) async fn drain(host: Option<WorkspaceIntelligenceHost>) -> &'static str {
    let Some(host) = host else {
        // A build without the host feature never admits a handle, so its own
        // answer is the typed refusal rather than a lifecycle state.
        return if cfg!(feature = "workspace-intelligence-host") {
            NOT_INSTALLED_CODE
        } else {
            ServerHostSkip::NotCompiled.code()
        };
    };

    match host.shutdown().await.drain() {
        WorkspaceIntelligenceHostDrain::Drained => DRAINED_CODE,
        WorkspaceIntelligenceHostDrain::DrainTimedOut { .. } => DRAIN_TIMED_OUT_CODE,
    }
}

/// Releases the host this server admitted, whichever way the serve body ended.
///
/// `main` calls this exactly once on every exit from the serve body, an error exit
/// and a normal one alike, so the tenure a startup admission took is released by one
/// implementation instead of by a copy per exit path. The slot is emptied first, so
/// a second call answers the empty-slot code rather than draining twice.
pub(crate) async fn release_admitted_host(
    slot: &Mutex<Option<WorkspaceIntelligenceHost>>,
) -> &'static str {
    let host = {
        let mut admitted = slot.lock().await;
        admitted.take()
    };
    drain(host).await
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use openbitfun_core::infrastructure::PathManager;
    use openbitfun_core::runtime_ownership::RuntimeDeployment;
    use openbitfun_core::service::workspace::WorkspaceService;
    use openbitfun_core::service::workspace_intelligence::WorkspaceIntelligenceHostSurface;

    use super::{drain, install, screen_surface, ServerHostSkip, ADMITTED_SURFACE, INSTALL_CODE};

    #[cfg(feature = "workspace-intelligence-host")]
    use super::{release_admitted_host, DRAINED_CODE, NOT_INSTALLED_CODE};
    #[cfg(feature = "workspace-intelligence-host")]
    use openbitfun_core::service::workspace_intelligence::{
        host_fixture, WorkspaceIntelligenceHostScopeState, WorkspaceIntelligenceHostState,
    };
    #[cfg(feature = "workspace-intelligence-host")]
    use tokio::sync::Mutex;

    /// Persisted workspace id of the scope these tests enable.
    #[cfg(feature = "workspace-intelligence-host")]
    const WORKSPACE_ID: &str = "server-loopback-workspace";

    /// Namespace entries directly under the workspace intelligence root.
    ///
    /// `None` means the root does not exist. Only this namespace is inspected: the
    /// workspace owner keeps its catalog and directories elsewhere and building one
    /// already writes them, so no assertion here claims a whole-owner zero-write
    /// result.
    fn workspace_intelligence_entries(paths: &PathManager) -> Option<Vec<String>> {
        let entries = std::fs::read_dir(paths.workspace_intelligence_dir()).ok()?;
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        Some(names)
    }

    /// `.lock` files under the workspace intelligence lease root.
    fn workspace_intelligence_lease_files(paths: &PathManager) -> Vec<PathBuf> {
        let Ok(entries) = std::fs::read_dir(paths.workspace_intelligence_lease_dir()) else {
            return Vec::new();
        };
        let mut locks: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("lock"))
            .collect();
        locks.sort();
        locks
    }

    /// An enabled scope on the loopback surface is admitted and reported, and the
    /// drain releases everything the tenure held.
    ///
    /// The second admission on the same root is the release proof: the owner lease,
    /// its transactional marker and the in-process lease registry are all released
    /// by the drain, so the scope is claimed again and reported `Active` instead of
    /// `Standby`, which is the only row another holder can produce.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test]
    async fn a_seeded_scope_is_installed_for_the_loopback_surface_and_drained() {
        let temp = tempfile::tempdir().expect("create an isolated user-data root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user"));
        let workspace_root = temp.path().join("workspace");
        host_fixture::seed_local_workspace(paths.as_ref(), WORKSPACE_ID, &workspace_root)
            .await
            .expect("seed the workspace record");
        let seeded = host_fixture::enable_workspace(paths.as_ref(), WORKSPACE_ID)
            .await
            .expect("enable the seeded workspace");

        let (code, handle) = install(paths.clone(), None, RuntimeDeployment::Embedded).await;
        assert_eq!(code, INSTALL_CODE, "the loopback surface must be admitted");
        let handle = handle.expect("an admitted surface returns a handle");

        let state = handle
            .status()
            .await
            .scope_state(seeded.workspace_id())
            .expect("the enabled scope is enumerated");
        assert!(
            matches!(
                state,
                WorkspaceIntelligenceHostScopeState::Active
                    | WorkspaceIntelligenceHostScopeState::Standby
            ),
            "the seeded scope must be admitted, got {}",
            state.code()
        );

        assert_eq!(
            drain(Some(handle)).await,
            DRAINED_CODE,
            "no owner work is outstanding in this fixture, so the drain completes"
        );

        let (reinstall_code, reinstalled) = install(paths, None, RuntimeDeployment::Embedded).await;
        assert_eq!(reinstall_code, INSTALL_CODE);
        let reinstalled = reinstalled.expect("the second admission returns a handle");
        let released = reinstalled
            .status()
            .await
            .scope_state(seeded.workspace_id())
            .expect("the enabled scope is enumerated again");
        assert_eq!(
            released,
            WorkspaceIntelligenceHostScopeState::Active,
            "the drained host must have released the scope's exclusive owner lease"
        );
        assert_eq!(drain(Some(reinstalled)).await, DRAINED_CODE);
    }

    /// A shared runtime owns the workspace, so this app refuses before resolving
    /// anything: no anchor, no control record, no lease and no cognition root.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test]
    async fn a_shared_deployment_is_refused_without_touching_the_filesystem() {
        let temp = tempfile::tempdir().expect("create an isolated user-data root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user"));

        let (code, handle) = install(paths.clone(), None, RuntimeDeployment::Shared).await;

        assert_eq!(code, ServerHostSkip::SharedRuntime.code());
        assert_eq!(code, "host_skip_shared_runtime");
        assert!(handle.is_none(), "a refused placement returns no handle");
        assert!(
            !paths.workspace_intelligence_dir().exists(),
            "a refusal must create no host namespace entry"
        );
    }

    /// The admitted surface is a compile-time fact, not a parameter, so the
    /// loopback endpoint is the only one this module can ever bootstrap.
    #[test]
    fn a_stdio_only_surface_is_never_admitted_here() {
        assert!(
            matches!(
                ADMITTED_SURFACE,
                WorkspaceIntelligenceHostSurface::ServerLoopback
            ),
            "this app admits the loopback surface only, not {ADMITTED_SURFACE:?}"
        );
        assert_eq!(screen_surface(ADMITTED_SURFACE), Ok(()));
        assert_eq!(
            screen_surface(WorkspaceIntelligenceHostSurface::ServerStdio),
            Err(ServerHostSkip::StdioServer),
            "the stdio surface belongs to the CLI command that serves it"
        );
        assert_eq!(ServerHostSkip::StdioServer.code(), "host_skip_stdio_server");
        assert_ne!(ServerHostSkip::StdioServer.code(), INSTALL_CODE);
    }

    /// A build without the host body answers the typed refusal from the production
    /// entry point and creates no host state.
    ///
    /// The enabled-scope fixture is compiled out together with the host body, so the
    /// isolated workspace owner is the only test constructor this build can use. Only
    /// the host namespace is asserted: that owner writes its own catalog and
    /// directories when it is built, so this is not a whole-owner zero-write claim.
    #[cfg(not(feature = "workspace-intelligence-host"))]
    #[tokio::test]
    async fn the_feature_off_build_answers_not_compiled_and_creates_nothing() {
        let temp = tempfile::tempdir().expect("create an isolated user-data root");
        let service = WorkspaceService::new_isolated_for_tests(temp.path().join("user")).await;
        let paths = service.path_manager().clone();

        assert_eq!(
            workspace_intelligence_entries(paths.as_ref()),
            None,
            "the host namespace must not exist before the placement runs"
        );
        assert!(workspace_intelligence_lease_files(paths.as_ref()).is_empty());

        let (code, handle) = install(paths.clone(), None, RuntimeDeployment::Embedded).await;

        assert_eq!(code, ServerHostSkip::NotCompiled.code());
        assert_eq!(code, "not_compiled");
        assert!(handle.is_none(), "a build without the host body admits no handle");
        assert_eq!(
            workspace_intelligence_entries(paths.as_ref()),
            None,
            "a build without the host body must write no anchor, control, lease or cognition entry"
        );
        assert!(workspace_intelligence_lease_files(paths.as_ref()).is_empty());
        assert_eq!(
            drain(None).await,
            ServerHostSkip::NotCompiled.code(),
            "a build with no host body has nothing to drain and says so"
        );
    }

    /// A workspace the owner opened but never enabled leaves no host state behind.
    ///
    /// The record is created by the workspace owner itself, so the host sees the same
    /// persisted catalog a real startup produces. No enabled scope exists, which is
    /// why the host reports `Inactive`, claims nothing and takes no lease; the host
    /// publishes no task count, so none is asserted and "no standby work ran" rests on
    /// the absent claim and the absent writes.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test]
    async fn an_opened_but_disabled_workspace_is_admitted_without_writing_host_state() {
        let temp = tempfile::tempdir().expect("create an isolated user-data root");
        let service = WorkspaceService::new_isolated_for_tests(temp.path().join("user")).await;
        let paths = service.path_manager().clone();
        let workspace_root = temp.path().join("workspace");
        std::fs::create_dir_all(&workspace_root).expect("create the probe workspace");
        let record = service
            .open_workspace(workspace_root)
            .await
            .expect("open the probe workspace through its owner");
        assert!(
            !record.id.is_empty(),
            "the owner persists a workspace record with an id"
        );

        assert_eq!(
            workspace_intelligence_entries(paths.as_ref()),
            None,
            "opening a workspace must not create the host namespace"
        );

        let (code, handle) = install(
            paths.clone(),
            Some(WorkspaceService::subscribe_catalog_changes()),
            RuntimeDeployment::Embedded,
        )
        .await;
        assert_eq!(code, INSTALL_CODE);
        let handle = handle.expect("the loopback surface returns a handle");

        let status = handle.status().await;
        assert_eq!(
            status.state(),
            WorkspaceIntelligenceHostState::Inactive,
            "a workspace that was never enabled leaves the host inactive, got {} ({:?})",
            status.state().code(),
            status.reason()
        );
        assert_eq!(status.counts().active(), 0);
        assert_eq!(status.counts().standby(), 0);
        assert!(
            workspace_intelligence_lease_files(paths.as_ref()).is_empty(),
            "no enabled scope means no owner lease is taken"
        );
        assert_eq!(
            workspace_intelligence_entries(paths.as_ref()),
            None,
            "an inactive host must write no anchor, control, lease or cognition entry"
        );

        assert_eq!(drain(Some(handle)).await, DRAINED_CODE);
        assert_eq!(workspace_intelligence_entries(paths.as_ref()), None);
        assert!(workspace_intelligence_lease_files(paths.as_ref()).is_empty());
    }

    /// An error exit after admission releases the host through the same release path a
    /// normal exit uses.
    #[cfg(feature = "workspace-intelligence-host")]
    #[tokio::test]
    async fn an_error_exit_still_releases_the_admitted_host() {
        let temp = tempfile::tempdir().expect("create an isolated user-data root");
        let paths = host_fixture::test_path_manager(&temp.path().join("user"));
        let workspace_root = temp.path().join("workspace");
        host_fixture::seed_local_workspace(paths.as_ref(), WORKSPACE_ID, &workspace_root)
            .await
            .expect("seed the workspace record");
        let seeded = host_fixture::enable_workspace(paths.as_ref(), WORKSPACE_ID)
            .await
            .expect("enable the seeded workspace");

        let (code, handle) = install(paths.clone(), None, RuntimeDeployment::Embedded).await;
        assert_eq!(code, INSTALL_CODE);
        let handle = handle.expect("an admitted host");
        let admitted = handle.status().await.scope_state(seeded.workspace_id());
        assert!(
            matches!(
                admitted,
                Some(
                    WorkspaceIntelligenceHostScopeState::Active
                        | WorkspaceIntelligenceHostScopeState::Standby
                )
            ),
            "the scope must be admitted before the error exit, got {admitted:?}"
        );
        let slot = Mutex::new(Some(handle));

        // The serve body fails after admission: the exit is an error, not a shutdown.
        let serve_result: anyhow::Result<()> = Err(anyhow::anyhow!("serve body failed"));
        assert!(serve_result.is_err(), "the modelled exit is an error");

        let drain_code = release_admitted_host(&slot).await;
        assert_eq!(
            drain_code, DRAINED_CODE,
            "an error exit must still drain the admitted host"
        );
        assert!(
            slot.lock().await.is_none(),
            "the release path empties the slot it drained"
        );

        // The drained host released the scope's exclusive owner lease: a second
        // admission on the same root claims the scope again instead of reporting it as
        // standby, which is the only row a still-held tenure can produce.
        let (reinstall_code, reinstalled) =
            install(paths.clone(), None, RuntimeDeployment::Embedded).await;
        assert_eq!(reinstall_code, INSTALL_CODE);
        let reinstalled = reinstalled.expect("the second admission returns a handle");
        assert_eq!(
            reinstalled
                .status()
                .await
                .scope_state(seeded.workspace_id()),
            Some(WorkspaceIntelligenceHostScopeState::Active),
            "the error exit must not leave the scope's owner lease held"
        );

        // A normal exit runs the same release path, and a second call on the drained
        // slot answers the empty-slot code instead of draining twice.
        let slot = Mutex::new(Some(reinstalled));
        assert_eq!(release_admitted_host(&slot).await, DRAINED_CODE);
        assert!(slot.lock().await.is_none());
        assert_eq!(
            release_admitted_host(&slot).await,
            NOT_INSTALLED_CODE,
            "a released slot answers the empty-slot code"
        );
    }
}
