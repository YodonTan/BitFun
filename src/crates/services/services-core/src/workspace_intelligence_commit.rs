//! One governed owner commit under the control record's own cross-process OS guard.
//!
//! This intent only recovers the cognition partition of an ALREADY-ENABLED scope.
//! It is not the OFF-to-ON enabling path: no PrepareInitialEnabling, claim/lease,
//! or token/cursor write. This is a WP1.2b primitive plus the narrowest real
//! consumer (`initialize`), NOT a WP1.2b exit and NOT a P1 exit. Roots are injected
//! host-local storage paths; this module performs no remote execution.
//!
//! The request-scoped five-field projection excludes unknown root fields: an
//! external edit that only adds/edits unknown root fields does not change the
//! projection. Writers ignoring the OS guard are not coordinated by this gate.
//! The SQLite `busy_timeout` is not an upper bound on how long the control guard
//! is held: it excludes OS flock and file IO time.
//!
//! Only the five projection fields participate in the safety comparison. Facts
//! outside them, including unknown root fields, are not safety-judged here. A
//! future fact that must veto a commit requires a schema-version upgrade: an
//! older fence cannot recognize, compare, or refuse on a field it does not model.
//!
//! Calling WorkspaceIntelligenceCognitionStore::initialize directly is not an
//! authorized governance commit path: it remains a low-level storage primitive
//! with no authorization. This gate is the intended governed-commit path, and
//! future production governance must not bypass it. Nothing enforces that today;
//! this slice has no production caller.
//!
//! Timing: guard acquisition and the fresh read are awaits; from the final fresh
//! read returning to the spawn_blocking hand-off there is no await point; the
//! guard moves into the blocking closure and covers the initialize transaction
//! through COMMIT.
//!
//! # Cancellation
//!
//! Phase 1 — during lock acquisition. The caller's future is dropped before this
//! future owns any guard. `acquire_cross_process_lock` hands the blocking open +
//! flock to a detached blocking task, and awaiting its JoinHandle does not tie
//! that task's lifetime to ours: dropping our future detaches the task instead
//! of aborting it. That task may still create the `<sha256>.json.lock` file (a
//! payload-free lock file), may still acquire the OS lock, and if it does it
//! drops the unclaimed guard immediately. No cognition root, database or
//! partition is created on this path and no control record is written: the owner
//! commit is a separate blocking closure only started after phase 2 succeeds.
//! Unlike phase 2, the OS lock's lifetime is not tied to our future here.
//!
//! Phase 2 — after the fresh read returns, before the hand-off. The guard is an
//! ordinary local owned by this future, so dropping the future drops the guard
//! promptly and releases the OS lock. There is no await point in this phase in
//! production builds, and no owner write occurs because the owner closure was
//! never spawned. This deliberately differs from WorkspaceIntelligenceStore::update,
//! whose accepted mutation moves onto an owned task and finishes after the caller
//! stops awaiting: here the side effect creates a durable partition, so a commit
//! cancelled before hand-off must not create one.
//!
//! Phase 3 — inside the blocking closure. The guard moved into the closure; the
//! call and its result ownership are with the closure. The initialize transaction
//! runs to COMMIT or rollback; the caller loses only the result. If the runtime
//! is already shutting down so the closure never runs, return OwnerTask and
//! perform no owner write.

use crate::workspace_intelligence_cognition::{
    CognitionInitialization, WorkspaceIntelligenceCognitionError,
    WorkspaceIntelligenceCognitionStore,
};
use crate::workspace_intelligence_store::{
    WorkspaceIntelligenceControlRecord, WorkspaceIntelligenceStore,
    WorkspaceIntelligenceStoreError,
};
use std::path::{Path, PathBuf};
#[cfg(feature = "workspace-intelligence-claim")]
use crate::workspace_intelligence_claim::ClaimLeaseBinding;
#[cfg(feature = "workspace-intelligence-claim")]
use crate::workspace_intelligence_cognition::{scope_digest, IncarnationAdvance};
#[cfg(all(test, feature = "workspace-intelligence-claim"))]
use std::sync::Arc;
#[cfg(all(test, feature = "workspace-intelligence-claim"))]
use crate::exclusive_file_lease::ExclusiveFileLease;

/// A closed owner-commit gate; construction performs no IO.
#[derive(Debug, Clone)]
pub struct WorkspaceIntelligenceCommitGate {
    control: WorkspaceIntelligenceStore,
    control_root: PathBuf,
    cognition_root: PathBuf,
    #[cfg(test)]
    pub(crate) after_precheck: Option<TestPause>,
    #[cfg(test)]
    pub(crate) after_fresh: Option<TestPause>,
    #[cfg(test)]
    pub(crate) inside_owner: Option<TestPause>,
    #[cfg(all(test, feature = "workspace-intelligence-claim"))]
    pub(crate) inside_verification: Option<TestPause>,
}

/// Request-scoped observation, minted only by `observe`, never persisted or cached.
/// It is never compared against a "latest" value and is never a grant/authority.
#[derive(Debug, Clone)]
pub struct GovernedCommitSnapshot {
    control_root: PathBuf,
    cognition_root: PathBuf,
    scope: String,
    authority: GovernedCommitAuthority,
}

impl GovernedCommitSnapshot {
    pub fn scope(&self) -> &str { &self.scope }
    pub fn control_root(&self) -> &Path { &self.control_root }
    pub fn cognition_root(&self) -> &Path { &self.cognition_root }
    pub fn authority(&self) -> &GovernedCommitAuthority { &self.authority }
}

/// Exactly five fields projected from one WorkspaceIntelligenceControlRecord.
/// Request-scoped: never persisted, never cached, never compared against a
/// "latest" value, never a grant/authority. This is the equivalence unit only.
#[derive(Debug, Clone, PartialEq)]
pub struct GovernedCommitAuthority {
    control_generation: u64,
    schema_version: Option<u32>,
    enabled: Option<bool>,
    model_ref: Option<String>,
    policy: Option<serde_json::Value>,
}

impl GovernedCommitAuthority {
    pub fn control_generation(&self) -> u64 { self.control_generation }
    pub fn schema_version(&self) -> Option<u32> { self.schema_version }
    pub fn enabled(&self) -> Option<bool> { self.enabled }
    pub fn model_ref(&self) -> Option<&str> { self.model_ref.as_deref() }
    pub fn policy(&self) -> Option<&serde_json::Value> { self.policy.as_ref() }

    /// The one equivalence unit, shared with the initial-enable reservation so a
    /// second consumer compares this exact projection instead of re-deriving a
    /// subset of it. Visibility only: the meaning of the five fields is unchanged.
    pub(crate) fn project(record: WorkspaceIntelligenceControlRecord) -> Self {
        Self {
            control_generation: record.control_generation,
            schema_version: record.schema_version,
            enabled: record.enabled,
            model_ref: record.model_ref,
            policy: record.policy,
        }
    }
}

#[derive(Debug)]
pub enum GovernedCommitIntent { RecoverEnabledCognitionPartition }

#[derive(Debug)]
pub enum GovernedCommitOutcome {
    Committed { authority: GovernedCommitAuthority, owner: GovernedOwnerCommitResult },
    Refused(GovernedCommitRefusal),
}

#[derive(Debug)]
pub enum GovernedOwnerCommitResult { CognitionPartition(CognitionInitialization) }

#[derive(Debug)]
pub enum GovernedCommitRefusal { ForeignSnapshot, NotObserved, AuthorityChanged, NotEnabled }

impl GovernedCommitRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ForeignSnapshot => "foreign_snapshot",
            Self::NotObserved => "not_observed",
            Self::AuthorityChanged => "authority_changed",
            Self::NotEnabled => "not_enabled",
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WorkspaceIntelligenceCommitError {
    #[error("Workspace intelligence commit control read failed: {0}")]
    Control(#[from] WorkspaceIntelligenceStoreError),
    #[error("Workspace intelligence cognition owner failed: {0}")]
    Cognition(#[from] WorkspaceIntelligenceCognitionError),
    #[error("Workspace intelligence owner task failed: {0}")]
    OwnerTask(tokio::task::JoinError),
}

impl WorkspaceIntelligenceCommitGate {
    pub fn new(control: WorkspaceIntelligenceStore, cognition_root: PathBuf) -> Self {
        Self {
            control_root: control.control_root().to_path_buf(),
            control,
            cognition_root,
            #[cfg(test)]
            after_precheck: None,
            #[cfg(test)]
            after_fresh: None,
            #[cfg(test)]
            inside_owner: None,
            #[cfg(all(test, feature = "workspace-intelligence-claim"))]
            inside_verification: None,
        }
    }

    pub fn control_root(&self) -> &Path { &self.control_root }
    pub fn cognition_root(&self) -> &Path { &self.cognition_root }

    pub async fn observe(
        &self, scope: &str,
    ) -> Result<Option<GovernedCommitSnapshot>, WorkspaceIntelligenceCommitError> {
        let record = self.control.read(scope).await?;
        Ok(record.map(|record| GovernedCommitSnapshot {
            control_root: self.control_root.clone(),
            cognition_root: self.cognition_root.clone(),
            scope: scope.to_owned(),
            authority: GovernedCommitAuthority::project(record),
        }))
    }

    fn binding_refusal(&self, snapshot: &GovernedCommitSnapshot) -> Option<GovernedCommitRefusal> {
        if snapshot.control_root.as_os_str() != self.control_root.as_os_str()
            || snapshot.cognition_root.as_os_str() != self.cognition_root.as_os_str()
        { Some(GovernedCommitRefusal::ForeignSnapshot) } else { None }
    }

    fn projection_refusal(
        record: Option<WorkspaceIntelligenceControlRecord>, snapshot: &GovernedCommitSnapshot,
    ) -> Result<GovernedCommitAuthority, GovernedCommitRefusal> {
        let record = record.ok_or(GovernedCommitRefusal::NotObserved)?;
        let projection = GovernedCommitAuthority::project(record);
        if projection != *snapshot.authority() { return Err(GovernedCommitRefusal::AuthorityChanged); }
        if projection.enabled != Some(true) { return Err(GovernedCommitRefusal::NotEnabled); }
        Ok(projection)
    }

    pub async fn commit(
        &self, snapshot: &GovernedCommitSnapshot, intent: GovernedCommitIntent,
    ) -> Result<GovernedCommitOutcome, WorkspaceIntelligenceCommitError> {
        if let Some(refusal) = self.binding_refusal(snapshot) {
            return Ok(GovernedCommitOutcome::Refused(refusal));
        }
        match intent { GovernedCommitIntent::RecoverEnabledCognitionPartition => {} }

        // Reject only: never license an owner commit from this lock-free read.
        let _projection = match Self::projection_refusal(self.control.read(&snapshot.scope).await?, snapshot) {
            Ok(projection) => projection,
            Err(refusal) => return Ok(GovernedCommitOutcome::Refused(refusal)),
        };
        #[cfg(test)]
        if let Some(pause) = &self.after_precheck { Self::wait_async(pause).await; }

        let (guard, fresh) = self.control.lock_and_read_authority(&snapshot.scope).await?;
        let projection = match Self::projection_refusal(fresh, snapshot) {
            Ok(projection) => projection,
            Err(refusal) => return Ok(GovernedCommitOutcome::Refused(refusal)),
        };
        // Production has no extra cancellation point here. Only tests insert one
        // to inspect destruction of the local guard before the owner hand-off.
        #[cfg(test)]
        if let Some(pause) = &self.after_fresh { Self::wait_async(pause).await; }

        let scope = snapshot.scope.clone();
        let root = self.cognition_root.clone();
        let authority = projection;
        #[cfg(test)]
        let pause = self.inside_owner.clone();
        let init = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            #[cfg(test)]
            if let Some(pause) = pause { Self::wait_blocking(&pause); }
            WorkspaceIntelligenceCognitionStore::new(root).initialize(&scope)
        }).await.map_err(WorkspaceIntelligenceCommitError::OwnerTask)??;
        Ok(GovernedCommitOutcome::Committed {
            authority, owner: GovernedOwnerCommitResult::CognitionPartition(init),
        })
    }
}

#[cfg(test)]
pub(crate) type TestPause = (
    tokio::sync::mpsc::UnboundedSender<()>,
    std::sync::Arc<std::sync::Mutex<std::sync::mpsc::Receiver<()>>>,
);

#[cfg(test)]
impl WorkspaceIntelligenceCommitGate {
    async fn wait_async(pause: &TestPause) {
        pause.0.send(()).unwrap();
        loop {
            let released = pause.1.lock().unwrap().try_recv();
            match released {
                Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                Err(std::sync::mpsc::TryRecvError::Empty) => tokio::task::yield_now().await,
            }
        }
    }

    fn wait_blocking(pause: &TestPause) {
        pause.0.send(()).unwrap();
        let _ = pause.1.lock().unwrap().recv();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json_store::JsonFileStore;
    use crate::workspace_intelligence_store::{ControlFieldUpdate, ControlGenerationExpectation, WorkspaceIntelligenceControlPatch};
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::future::Future;
    use std::task::{Context, Poll, Waker};
    use std::time::{Duration, Instant};

    const SCOPE: &str = "workspace-a@host";
    const DEADLINE: Duration = Duration::from_secs(30);

    fn gate(base: &Path) -> WorkspaceIntelligenceCommitGate {
        WorkspaceIntelligenceCommitGate::new(
            WorkspaceIntelligenceStore::new(base.join("control"), vec![1]), base.join("cognition"),
        )
    }
    fn patch(enabled: bool) -> WorkspaceIntelligenceControlPatch {
        WorkspaceIntelligenceControlPatch { enabled: ControlFieldUpdate::Set(enabled), ..Default::default() }
    }
    async fn seed(gate: &WorkspaceIntelligenceCommitGate, scope: &str, enabled: bool) {
        gate.control.update(scope, ControlGenerationExpectation::Absent, patch(enabled)).await.unwrap();
    }
    async fn close(gate: &WorkspaceIntelligenceCommitGate, scope: &str) {
        let result = gate.control.update(scope, ControlGenerationExpectation::Exactly(1), patch(false)).await.unwrap();
        assert_eq!(result.record().control_generation, 2);
    }
    fn path(root: &Path, scope: &str, extension: &str) -> PathBuf {
        root.join(format!("{:x}.{extension}", Sha256::digest(scope.as_bytes())))
    }
    fn control_bytes(gate: &WorkspaceIntelligenceCommitGate) -> Vec<u8> {
        std::fs::read(path(gate.control_root(), SCOPE, "json")).unwrap()
    }
    async fn commit(gate: &WorkspaceIntelligenceCommitGate, snapshot: &GovernedCommitSnapshot) -> Result<GovernedCommitOutcome, WorkspaceIntelligenceCommitError> {
        gate.commit(snapshot, GovernedCommitIntent::RecoverEnabledCognitionPartition).await
    }
    fn refused(outcome: GovernedCommitOutcome, code: &str) {
        match outcome {
            GovernedCommitOutcome::Refused(reason) => assert_eq!(reason.code(), code),
            other => panic!("expected {code}: {other:?}"),
        }
    }
    fn committed(outcome: GovernedCommitOutcome, initialized: bool) {
        match outcome {
            GovernedCommitOutcome::Committed { authority, owner: GovernedOwnerCommitResult::CognitionPartition(init) } => {
                assert_eq!(authority.control_generation(), 1);
                assert_eq!(authority.enabled(), Some(true));
                assert_eq!(init.is_initialized(), initialized);
            }
            other => panic!("expected committed: {other:?}"),
        }
    }
    struct ReleasePause(std::sync::mpsc::Sender<()>);
    impl ReleasePause {
        fn send(&self, value: ()) -> Result<(), std::sync::mpsc::SendError<()>> { self.0.send(value) }
    }
    impl Drop for ReleasePause {
        fn drop(&mut self) { let _ = self.0.send(()); }
    }

    fn pause() -> (TestPause, tokio::sync::mpsc::UnboundedReceiver<()>, ReleasePause) {
        let (entered, receiver) = tokio::sync::mpsc::unbounded_channel();
        let (release, wait) = std::sync::mpsc::channel();
        ((entered, std::sync::Arc::new(std::sync::Mutex::new(wait))), receiver, ReleasePause(release))
    }
    async fn entered(receiver: &mut tokio::sync::mpsc::UnboundedReceiver<()>) {
        tokio::time::timeout(DEADLINE, receiver.recv()).await.unwrap().unwrap();
    }
    fn spawn(gate: WorkspaceIntelligenceCommitGate, snapshot: GovernedCommitSnapshot) -> tokio::task::JoinHandle<Result<GovernedCommitOutcome, WorkspaceIntelligenceCommitError>> {
        tokio::spawn(async move { commit(&gate, &snapshot).await })
    }
    async fn finish(task: tokio::task::JoinHandle<Result<GovernedCommitOutcome, WorkspaceIntelligenceCommitError>>) -> GovernedCommitOutcome {
        tokio::time::timeout(DEADLINE, task).await.unwrap().unwrap().unwrap()
    }
    fn valid_v1(gate: &WorkspaceIntelligenceCommitGate, scope: &str) {
        let state = WorkspaceIntelligenceCognitionStore::new(gate.cognition_root.clone()).read(scope).unwrap().unwrap();
        assert_eq!(state.cursor, None);
        assert_eq!(state.incarnation_token, None);
        let db = rusqlite::Connection::open(path(gate.cognition_root(), scope, "sqlite")).unwrap();
        assert_eq!(db.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(db.query_row("SELECT COUNT(*) FROM partition_state", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        let columns: Vec<String> = db.prepare("PRAGMA table_info(partition_state)").unwrap()
            .query_map([], |r| r.get(1)).unwrap().map(Result::unwrap).collect();
        assert_eq!(columns, ["state_id", "partition_key", "cursor", "incarnation_token"]);
    }

    #[tokio::test]
    async fn missing_observation_creates_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        assert!(gate.observe(SCOPE).await.unwrap().is_none());
        assert!(!gate.control_root().exists());
        assert!(!gate.cognition_root().exists());
        assert_eq!(std::fs::read_dir(tmp.path()).unwrap().count(), 0);
        assert!(matches!(gate.observe("").await, Err(WorkspaceIntelligenceCommitError::Control(WorkspaceIntelligenceStoreError::EmptyScope))));
    }

    #[tokio::test]
    async fn initializes_v1_then_idempotently_preserves_state_and_control_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let bytes = control_bytes(&gate);
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        assert_eq!(snapshot.scope(), SCOPE);
        assert_eq!(snapshot.control_root(), gate.control_root());
        assert_eq!(snapshot.cognition_root(), gate.cognition_root());
        assert_eq!(snapshot.authority().schema_version(), Some(1));
        assert_eq!(snapshot.authority().model_ref(), None);
        assert_eq!(snapshot.authority().policy(), None);
        committed(commit(&gate, &snapshot).await.unwrap(), true);
        valid_v1(&gate, SCOPE);
        let dbpath = path(gate.cognition_root(), SCOPE, "sqlite");
        {
            let db = rusqlite::Connection::open(&dbpath).unwrap();
            db.execute("UPDATE partition_state SET cursor = 'retained', incarnation_token = 'opaque'", []).unwrap();
        }
        let before = std::fs::read(&dbpath).unwrap();
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        committed(commit(&gate, &snapshot).await.unwrap(), false);
        assert_eq!(std::fs::read(&dbpath).unwrap(), before);
        assert_eq!(std::fs::read_dir(gate.cognition_root()).unwrap().count(), 1);
        assert_eq!(control_bytes(&gate), bytes);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
    }

    #[tokio::test]
    async fn close_first_and_changed_disabled_prioritize_authority_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        close(&gate, SCOPE).await;
        assert_eq!(snapshot.authority().control_generation(), 1);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 2);
        refused(commit(&gate, &snapshot).await.unwrap(), "authority_changed");
        assert!(!gate.cognition_root().exists());
    }

    #[tokio::test]
    async fn unchanged_disabled_is_not_enabled_without_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, false).await;
        let bytes = control_bytes(&gate);
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        refused(commit(&gate, &snapshot).await.unwrap(), "not_enabled");
        assert!(!gate.cognition_root().exists());
        assert_eq!(control_bytes(&gate), bytes);
    }

    fn assert_no_sqlite(root: &Path) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_no_sqlite(&path);
            } else {
                assert_ne!(path.extension().and_then(|value| value.to_str()), Some("sqlite"));
            }
        }
    }

    #[tokio::test]
    async fn absent_enabled_key_is_not_enabled_without_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        let created = gate.control.update(
            SCOPE, ControlGenerationExpectation::Absent, WorkspaceIntelligenceControlPatch::default(),
        ).await.unwrap();
        assert_eq!(created.record().control_generation, 1);
        assert_eq!(created.record().schema_version, Some(1));
        let bytes = control_bytes(&gate);
        let raw: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(!raw.as_object().unwrap().contains_key("enabled"));
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        assert_eq!(snapshot.authority().enabled(), None);
        refused(commit(&gate, &snapshot).await.unwrap(), "not_enabled");
        assert!(!gate.cognition_root().exists());
        assert_no_sqlite(tmp.path());
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn same_generation_supported_schema_version_change_is_authority_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let initial = gate(tmp.path());
        // The seed owner stamps version 1; the observing gate understands both
        // versions so decoding version 2 cannot mask the projection comparison.
        seed(&initial, SCOPE, true).await;
        let gate = WorkspaceIntelligenceCommitGate::new(
            WorkspaceIntelligenceStore::new(initial.control_root.clone(), vec![1, 2]),
            initial.cognition_root.clone(),
        );
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        assert_eq!(snapshot.authority().schema_version(), Some(1));
        assert_eq!(snapshot.authority().control_generation(), 1);
        let mut raw = gate.control.read(SCOPE).await.unwrap().unwrap().raw;
        raw["schema_version"] = json!(2);
        JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
        let observed = gate.control.read(SCOPE).await.unwrap().unwrap();
        assert_eq!(observed.schema_version, Some(2));
        assert_eq!(observed.control_generation, 1);
        assert_eq!(observed.enabled, Some(true));
        let bytes = control_bytes(&gate);
        refused(commit(&gate, &snapshot).await.unwrap(), "authority_changed");
        assert!(!gate.cognition_root().exists());
        assert_no_sqlite(tmp.path());
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn same_generation_legacy_schema_version_addition_is_authority_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = WorkspaceIntelligenceCommitGate::new(
            WorkspaceIntelligenceStore::new(tmp.path().join("control"), vec![]),
            tmp.path().join("cognition"),
        );
        seed(&gate, SCOPE, true).await;
        let gate = WorkspaceIntelligenceCommitGate::new(
            WorkspaceIntelligenceStore::new(gate.control_root.clone(), vec![1]),
            gate.cognition_root.clone(),
        );
        let mut raw: serde_json::Value = serde_json::from_slice(&control_bytes(&gate)).unwrap();
        assert!(!raw.as_object().unwrap().contains_key("schema_version"));
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        assert_eq!(snapshot.authority().schema_version(), None);
        assert_eq!(snapshot.authority().control_generation(), 1);
        raw["schema_version"] = json!(1);
        JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
        let observed = gate.control.read(SCOPE).await.unwrap().unwrap();
        assert_eq!(observed.schema_version, Some(1));
        assert_eq!(observed.control_generation, 1);
        assert_eq!(observed.enabled, Some(true));
        let bytes = control_bytes(&gate);
        refused(commit(&gate, &snapshot).await.unwrap(), "authority_changed");
        assert!(!gate.cognition_root().exists());
        assert_no_sqlite(tmp.path());
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn policy_key_order_is_semantically_equal_at_the_same_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        gate.control.update(SCOPE, ControlGenerationExpectation::Absent, WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            policy: ControlFieldUpdate::Set(json!({"a": 1, "b": 2})),
            ..Default::default()
        }).await.unwrap();
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let mut raw = gate.control.read(SCOPE).await.unwrap().unwrap().raw;
        raw["policy"] = serde_json::from_str(r#"{"b":2,"a":1}"#).unwrap();
        JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
        let observed = gate.control.read(SCOPE).await.unwrap().unwrap();
        assert_eq!(observed.control_generation, 1);
        assert_eq!(snapshot.authority().policy(), observed.policy.as_ref());
        let bytes = control_bytes(&gate);
        committed(commit(&gate, &snapshot).await.unwrap(), true);
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn policy_integer_to_float_change_is_authority_changed_at_the_same_generation() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        gate.control.update(SCOPE, ControlGenerationExpectation::Absent, WorkspaceIntelligenceControlPatch {
            enabled: ControlFieldUpdate::Set(true),
            policy: ControlFieldUpdate::Set(json!({"a": 1})),
            ..Default::default()
        }).await.unwrap();
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let mut raw = gate.control.read(SCOPE).await.unwrap().unwrap().raw;
        raw["policy"] = json!({"a": 1.0});
        JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
        let observed = gate.control.read(SCOPE).await.unwrap().unwrap();
        assert_eq!(observed.control_generation, 1);
        assert_ne!(snapshot.authority().policy(), observed.policy.as_ref());
        let bytes = control_bytes(&gate);
        refused(commit(&gate, &snapshot).await.unwrap(), "authority_changed");
        assert!(!gate.cognition_root().exists());
        assert_no_sqlite(tmp.path());
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn same_generation_changes_compare_the_full_projection() {
        for (field, value) in [("enabled", json!(false)), ("policy", json!({"changed": true})), ("model_ref", json!("another-model"))] {
            let tmp = tempfile::tempdir().unwrap();
            let gate = gate(tmp.path());
            seed(&gate, SCOPE, true).await;
            let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
            let mut raw = gate.control.read(SCOPE).await.unwrap().unwrap().raw;
            raw[field] = value;
            JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
            assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
            refused(commit(&gate, &snapshot).await.unwrap(), "authority_changed");
            assert!(!gate.cognition_root().exists());
        }
    }

    #[tokio::test]
    async fn unknown_root_fields_do_not_change_the_projection() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let mut raw = gate.control.read(SCOPE).await.unwrap().unwrap().raw;
        raw["future"] = json!({"opaque": [1, 2]});
        JsonFileStore.write_atomic_strict(&path(gate.control_root(), SCOPE, "json"), &raw).await.unwrap();
        let bytes = control_bytes(&gate);
        committed(commit(&gate, &snapshot).await.unwrap(), true);
        assert_eq!(control_bytes(&gate), bytes);
    }

    #[tokio::test]
    async fn foreign_bindings_reject_before_io_but_same_pairing_handles_interoperate() {
        let tmp = tempfile::tempdir().unwrap();
        let a = gate(&tmp.path().join("a"));
        seed(&a, SCOPE, true).await;
        let snapshot = a.observe(SCOPE).await.unwrap().unwrap();
        let b = gate(&tmp.path().join("b"));
        refused(commit(&b, &snapshot).await.unwrap(), "foreign_snapshot");
        assert!(!tmp.path().join("b").exists());
        let c = WorkspaceIntelligenceCommitGate::new(a.control.clone(), tmp.path().join("other-cognition"));
        refused(commit(&c, &snapshot).await.unwrap(), "foreign_snapshot");
        assert!(!a.cognition_root().exists());
        assert!(!c.cognition_root().exists());
        // Path PartialEq would normalize the trailing separator; OsStr must not.
        let mut spelling = a.control_root().as_os_str().to_os_string();
        spelling.push(std::path::MAIN_SEPARATOR.to_string());
        let d = WorkspaceIntelligenceCommitGate::new(WorkspaceIntelligenceStore::new(spelling.into(), vec![1]), a.cognition_root.clone());
        refused(commit(&d, &snapshot).await.unwrap(), "foreign_snapshot");
        let same = WorkspaceIntelligenceCommitGate::new(a.control.clone(), a.cognition_root.clone());
        committed(commit(&same, &snapshot).await.unwrap(), true);
    }

    #[tokio::test]
    async fn scopes_create_only_the_selected_database() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        seed(&gate, "b", true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        committed(commit(&gate, &snapshot).await.unwrap(), true);
        assert!(path(gate.cognition_root(), SCOPE, "sqlite").exists());
        assert!(!path(gate.cognition_root(), "b", "sqlite").exists());
        assert_eq!(std::fs::read_dir(gate.cognition_root()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn precheck_does_not_recreate_deleted_control_root() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        std::fs::remove_dir_all(gate.control_root()).unwrap();
        refused(commit(&gate, &snapshot).await.unwrap(), "not_observed");
        assert!(!gate.control_root().exists());
        assert!(!gate.cognition_root().exists());
    }

    #[tokio::test]
    async fn control_errors_fail_closed_without_owner_io() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let record = path(gate.control_root(), SCOPE, "json");
        for bytes in [b"broken".as_slice(), br#"{"schema_version":99}"#.as_slice()] {
            std::fs::write(&record, bytes).unwrap();
            assert!(matches!(gate.observe(SCOPE).await, Err(WorkspaceIntelligenceCommitError::Control(_))));
            assert!(matches!(commit(&gate, &snapshot).await, Err(WorkspaceIntelligenceCommitError::Control(_))));
            assert_eq!(std::fs::read(&record).unwrap(), bytes);
            assert!(!gate.cognition_root().exists());
        }
    }

    #[tokio::test]
    async fn cancelled_acquisition_never_starts_owner_and_eventually_releases_unclaimed_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let bytes = control_bytes(&gate);
        let record = path(gate.control_root(), SCOPE, "json");
        let held = JsonFileStore.acquire_cross_process_lock(&record).await.unwrap();
        let (hook, mut receiver, release) = pause();
        let mut queued = gate.clone();
        queued.after_precheck = Some(hook);
        // Pre-release the test hook so the poll which reports entry continues
        // directly into the real acquisition path, not a hook cancellation point.
        release.send(()).unwrap();
        let mut future = Box::pin(commit(&queued, &snapshot));
        let deadline = Instant::now() + DEADLINE;
        loop {
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            if receiver.try_recv().is_ok() { break; }
            assert!(Instant::now() < deadline, "precheck did not complete");
            tokio::task::yield_now().await;
        }
        // Allow the blocking acquisition to be queued; correctness does not
        // assume whether it has opened the payload-free lock file yet.
        for _ in 0..64 {
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
            tokio::task::yield_now().await;
        }
        drop(future);
        assert_eq!(control_bytes(&gate), bytes);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
        assert!(!gate.cognition_root().exists());
        drop(held);
        // This may race the detached acquisition; neither acquisition can keep
        // an unclaimed guard alive. Re-acquisition has a hard deadline.
        for _ in 0..64 {
            tokio::task::yield_now().await;
            assert!(!gate.cognition_root().exists());
        }
        let guard = tokio::time::timeout(DEADLINE, JsonFileStore.acquire_cross_process_lock(&record)).await.unwrap().unwrap();
        drop(guard);
        let lock = path(gate.control_root(), SCOPE, "json.lock");
        assert!(!lock.exists() || std::fs::metadata(lock).unwrap().len() == 0);
        assert_eq!(control_bytes(&gate), bytes);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
        assert!(!gate.cognition_root().exists());
        committed(commit(&gate, &snapshot).await.unwrap(), true);
    }

    #[tokio::test]
    async fn cancelled_after_fresh_read_releases_local_guard_without_owner_write() {
        let tmp = tempfile::tempdir().unwrap();
        let mut gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let (hook, mut receiver, _release) = pause();
        gate.after_fresh = Some(hook);
        let task = spawn(gate.clone(), snapshot.clone());
        entered(&mut receiver).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(!gate.cognition_root().exists());
        let guard = tokio::time::timeout(DEADLINE, gate.control.lock_and_read_authority(SCOPE)).await.unwrap().unwrap().0;
        drop(guard);
        gate.after_fresh = None;
        committed(commit(&gate, &snapshot).await.unwrap(), true);
    }

    #[tokio::test]
    async fn cancelled_inside_owner_still_commits_a_valid_partition() {
        let tmp = tempfile::tempdir().unwrap();
        let mut gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let (hook, mut receiver, release) = pause();
        gate.inside_owner = Some(hook);
        let task = spawn(gate.clone(), snapshot);
        entered(&mut receiver).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        release.send(()).unwrap();
        // A real close cannot finish until initialize has returned and its
        // guard drops; completion therefore proves the detached owner finished.
        tokio::time::timeout(DEADLINE, close(&gate, SCOPE)).await.unwrap();
        valid_v1(&gate, SCOPE);
    }

    #[tokio::test]
    async fn close_wins_after_precheck_and_locked_missing_observation_writes_nothing() {
        for remove in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let mut gate = gate(tmp.path());
            seed(&gate, SCOPE, true).await;
            let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
            let (hook, mut receiver, release) = pause();
            gate.after_precheck = Some(hook);
            let task = spawn(gate.clone(), snapshot);
            entered(&mut receiver).await;
            if remove {
                std::fs::remove_file(path(gate.control_root(), SCOPE, "json")).unwrap();
            } else { close(&gate, SCOPE).await; }
            release.send(()).unwrap();
            refused(finish(task).await, if remove { "not_observed" } else { "authority_changed" });
            assert!(!gate.cognition_root().exists());
        }
    }

    #[tokio::test]
    async fn commit_wins_blocks_close_but_not_other_scopes_or_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let mut gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let bytes = control_bytes(&gate);
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let (hook, mut receiver, release) = pause();
        gate.inside_owner = Some(hook);
        let task = spawn(gate.clone(), snapshot);
        entered(&mut receiver).await;
        let closer = gate.control.clone();
        let mut close_future = Box::pin(closer.update(
            SCOPE, ControlGenerationExpectation::Exactly(1), patch(false),
        ));
        {
            let mut context = Context::from_waker(Waker::noop());
            assert!(matches!(close_future.as_mut().poll(&mut context), Poll::Pending));
        }
        let locks: Vec<_> = std::fs::read_dir(gate.control_root()).unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap().to_string_lossy().ends_with(".json.lock"))
            .collect();
        assert_eq!(locks.len(), 1);
        let probe = std::fs::OpenOptions::new().read(true).write(true).open(&locks[0]).unwrap();
        // WouldBlock is the actual evidence that the owner holds the OS lock;
        // "did not complete yet" alone is not contention evidence.
        let contention = fs2::FileExt::try_lock_exclusive(&probe);
        drop(probe); // Release even a successful probe before any assertion.
        let contention = contention.map_err(|error| {
            // Windows reports fs2's native lock-contended error as Uncategorized.
            // Normalize only that exact OS error to its WouldBlock meaning.
            assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error());
            std::io::ErrorKind::WouldBlock
        });
        assert_eq!(contention.unwrap_err(), std::io::ErrorKind::WouldBlock);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
        assert_eq!(control_bytes(&gate), bytes);
        seed(&gate, "other", true).await;
        let other = WorkspaceIntelligenceCommitGate::new(gate.control.clone(), gate.cognition_root.clone());
        let snapshot = other.observe("other").await.unwrap().unwrap();
        committed(tokio::time::timeout(DEADLINE, commit(&other, &snapshot)).await.unwrap().unwrap(), true);
        let separate = self::gate(&tmp.path().join("separate"));
        seed(&separate, SCOPE, true).await;
        let snapshot = separate.observe(SCOPE).await.unwrap().unwrap();
        committed(tokio::time::timeout(DEADLINE, commit(&separate, &snapshot)).await.unwrap().unwrap(), true);
        release.send(()).unwrap();
        committed(finish(task).await, true);
        let closed = tokio::time::timeout(DEADLINE, close_future).await.unwrap().unwrap();
        assert!(closed.is_applied());
        assert_eq!(closed.record().control_generation, 2);
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 2);
        valid_v1(&gate, SCOPE);
    }

    #[tokio::test]
    async fn bad_and_foreign_databases_are_preserved_without_reset() {
        for case in ["unsupported_schema_version", "corrupt_database", "partition_scope_mismatch"] {
            let tmp = tempfile::tempdir().unwrap();
            let gate = gate(tmp.path());
            seed(&gate, SCOPE, true).await;
            let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
            let bytes = control_bytes(&gate);
            std::fs::create_dir_all(gate.cognition_root()).unwrap();
            let dbpath = path(gate.cognition_root(), SCOPE, "sqlite");
            match case {
                "unsupported_schema_version" => { rusqlite::Connection::open(&dbpath).unwrap().execute_batch("PRAGMA user_version = 2;").unwrap(); }
                "corrupt_database" => std::fs::write(&dbpath, b"this is not SQLite").unwrap(),
                _ => {
                    WorkspaceIntelligenceCognitionStore::new(gate.cognition_root.clone()).initialize("foreign").unwrap();
                    std::fs::copy(path(gate.cognition_root(), "foreign", "sqlite"), &dbpath).unwrap();
                }
            }
            let database_bytes = std::fs::read(&dbpath).unwrap();
            match commit(&gate, &snapshot).await {
                Err(WorkspaceIntelligenceCommitError::Cognition(error)) => assert_eq!(error.code(), case),
                other => panic!("{case}: {other:?}"),
            }
            assert_eq!(std::fs::read(&dbpath).unwrap(), database_bytes);
            assert_eq!(control_bytes(&gate), bytes);
            assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
        }
    }

    #[tokio::test]
    async fn gate_snapshot_and_commit_future_are_send_and_sync() {
        fn send_sync<T: Send + Sync>() {}
        fn send_sync_value<T: Send + Sync>(_: T) {}
        send_sync::<WorkspaceIntelligenceCommitGate>();
        send_sync::<GovernedCommitSnapshot>();
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        send_sync_value(gate.commit(&snapshot, GovernedCommitIntent::RecoverEnabledCognitionPartition));
    }

    #[cfg(feature = "workspace-intelligence-claim")]
    fn lease(gate: &WorkspaceIntelligenceCommitGate, scope: &str) -> ClaimLeaseBinding {
        let path = path(&gate.control_root().join("leases"), scope, "lock");
        ClaimLeaseBinding::bind(Arc::new(ExclusiveFileLease::try_acquire(&path).unwrap()),
            gate.control_root.clone(), gate.cognition_root.clone(), scope.into(), path)
    }
    #[cfg(feature = "workspace-intelligence-claim")]
    fn claim_refused(outcome: GovernedFenceOutcome, expected: GovernedClaimRefusal) {
        assert!(matches!(outcome, GovernedFenceOutcome::Refused(reason) if reason == expected), "{outcome:?}");
    }
    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn commit_governed_advances_only_an_enabled_scope_and_reports_typed_refusals() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let held = lease(&gate, SCOPE);
        let other = lease(&gate, "other");
        claim_refused(gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &other).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
        let foreign = self::gate(&tmp.path().join("foreign"));
        claim_refused(foreign.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &held).await.unwrap(), GovernedClaimRefusal::ForeignSnapshot);
        close(&gate, SCOPE).await;
        claim_refused(gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &held).await.unwrap(), GovernedClaimRefusal::AuthorityChanged);
        let disabled = gate.observe(SCOPE).await.unwrap().unwrap();
        claim_refused(gate.commit_governed(&disabled, GovernedFenceOperation::AdvanceIncarnation, &held).await.unwrap(), GovernedClaimRefusal::NotEnabled);
        std::fs::remove_file(path(gate.control_root(), SCOPE, "json")).unwrap();
        claim_refused(gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &held).await.unwrap(), GovernedClaimRefusal::NotObserved);
        assert!(!gate.cognition_root().exists());
    }
    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn commit_governed_holds_guard_and_lease_through_commit_and_after_caller_handoff() {
        let tmp = tempfile::tempdir().unwrap();
        let mut gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let held = lease(&gate, SCOPE);
        let lease_path = held.lease_path().to_path_buf();
        let (hook, mut receiver, release) = pause();
        gate.inside_owner = Some(hook);
        let cloned = gate.clone();
        let task = tokio::spawn(async move { cloned.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &held).await });
        entered(&mut receiver).await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let probe = std::fs::OpenOptions::new().read(true).write(true).open(&lease_path).unwrap();
        let error = fs2::FileExt::try_lock_exclusive(&probe).unwrap_err();
        assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error());
        drop(probe);
        release.send(()).unwrap();
        tokio::time::timeout(DEADLINE, close(&gate, SCOPE)).await.unwrap();
        let state = WorkspaceIntelligenceCognitionStore::new(gate.cognition_root.clone()).read(SCOPE).unwrap().unwrap();
        assert!(state.incarnation_token.is_some());
        let probe = std::fs::OpenOptions::new().read(true).write(true).open(&lease_path).unwrap();
        // The close completion proves the closure dropped the control guard;
        // both owned locks are destroyed before that blocking closure returns.
        let deadline = Instant::now() + DEADLINE;
        loop {
            match fs2::FileExt::try_lock_exclusive(&probe) {
                Ok(()) => break,
                Err(error) => { assert_eq!(error.raw_os_error(), fs2::lock_contended_error().raw_os_error()); assert!(Instant::now() < deadline); tokio::task::yield_now().await; }
            }
        }
    }
    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn commit_governed_verify_is_read_only() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let held = lease(&gate, SCOPE);
        let outcome = gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &held).await.unwrap();
        let GovernedFenceOutcome::Advanced(advance) = outcome else { panic!("{outcome:?}") };
        let db = path(gate.cognition_root(), SCOPE, "sqlite");
        let bytes = std::fs::read(&db).unwrap();
        let outcome = gate.commit_governed(&snapshot, GovernedFenceOperation::VerifyIncarnation { expected: advance.token.clone(), origin: advance.token }, &held).await.unwrap();
        let GovernedFenceOutcome::Verified { control_generation } = outcome else { panic!("{outcome:?}") };
        assert_eq!(control_generation, 1);
        assert_eq!(std::fs::read(&db).unwrap(), bytes);
    }


    /// The former bare-Arc gate accepted any matching file name, even when the
    /// lease was acquired for another root pairing. The sealed tuple closes that
    /// hole; caller-selected lease-root location alone is not gate authority.
    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn foreign_root_pairing_with_the_same_file_name_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let before = control_bytes(&gate);
        for field in 0..3 {
            let scope = if field == 2 { "another-scope" } else { SCOPE };
            let lease_path = path(&tmp.path().join(format!("foreign-leases-{field}")), scope, "lock");
            let lease = Arc::new(ExclusiveFileLease::try_acquire(&lease_path).unwrap());
            let control_root = if field == 0 { tmp.path().join("foreign-control") } else { gate.control_root.clone() };
            let cognition_root = if field == 1 { tmp.path().join("foreign-cognition") } else { gate.cognition_root.clone() };
            if field != 2 { assert_eq!(lease_path.file_name(), path(&tmp.path().join("leases"), SCOPE, "lock").file_name()); }
            let binding = ClaimLeaseBinding::bind(lease, control_root, cognition_root, scope.into(), lease_path);
            claim_refused(gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
            assert_eq!(control_bytes(&gate), before);
            assert!(!gate.cognition_root().exists());
        }
    }

    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn binding_declaring_another_path_than_the_held_lease_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let actual = path(&tmp.path().join("actual"), SCOPE, "lock");
        let declared = path(&tmp.path().join("declared"), SCOPE, "lock");
        let binding = ClaimLeaseBinding::bind(Arc::new(ExclusiveFileLease::try_acquire(&actual).unwrap()),
            gate.control_root.clone(), gate.cognition_root.clone(), SCOPE.into(), declared);
        claim_refused(gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await.unwrap(), GovernedClaimRefusal::ForeignBinding);
        assert!(!gate.cognition_root().exists());
    }

    #[cfg(feature = "workspace-intelligence-claim")]
    #[tokio::test]
    async fn same_full_pairing_is_reusable_across_handles() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
        let binding = lease(&gate, SCOPE);
        let second = ClaimLeaseBinding::bind(binding.lease(), binding.control_root().to_path_buf(),
            binding.cognition_root().to_path_buf(), binding.scope().into(), binding.lease_path().to_path_buf());
        let other_handle = WorkspaceIntelligenceCommitGate::new(gate.control.clone(), gate.cognition_root.clone());
        let first = gate.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &binding).await.unwrap();
        let GovernedFenceOutcome::Advanced(first) = first else { panic!("{first:?}") };
        let next = other_handle.commit_governed(&snapshot, GovernedFenceOperation::AdvanceIncarnation, &second).await.unwrap();
        let GovernedFenceOutcome::Advanced(next) = next else { panic!("{next:?}") };
        assert_eq!(next.previous_token.as_deref(), Some(first.token.as_str()));
        assert_ne!(next.token, first.token);
    }

    const CHILD_DIR: &str = "OPENBITFUN_WI_COMMIT_CHILD_DIR";
    const CHILD_ROLE: &str = "OPENBITFUN_WI_COMMIT_CHILD_ROLE";

    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); }
    }
    async fn wait_file(path: &Path, deadline: Instant) -> String {
        loop {
            if let Ok(text) = tokio::fs::read_to_string(path).await { return text; }
            assert!(Instant::now() < deadline, "child deadline: {}", path.display());
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn cross_process_gate_and_close_share_one_os_guard() {
        let tmp = tempfile::tempdir().unwrap();
        let gate = gate(tmp.path());
        seed(&gate, SCOPE, true).await;
        let mut children = Vec::new();
        for role in ["commit", "close"] {
            // Same binary fixture, no process-runtime dependency. Hide the
            // non-interactive child console on Windows explicitly.
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x0800_0000);
            }
            children.push(Child(command.args(["--exact", "workspace_intelligence_commit::tests::governed_commit_process_fixture", "--nocapture"])
                .env(CHILD_DIR, tmp.path()).env(CHILD_ROLE, role)
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn().unwrap()));
        }
        let deadline = Instant::now() + DEADLINE;
        wait_file(&tmp.path().join("commit.ready"), deadline).await;
        wait_file(&tmp.path().join("close.ready"), deadline).await;
        // The close child must observe OS-lock contention before we release
        // the paused owner; readiness or an unfinished close alone is not proof.
        assert_eq!(wait_file(&tmp.path().join("close.contended"), deadline).await, "0");
        assert!(!tmp.path().join("close.outcome").exists());
        assert_eq!(gate.control.read(SCOPE).await.unwrap().unwrap().control_generation, 1);
        JsonFileStore.write_text_atomic_strict(&tmp.path().join("release.ready"), "release").await.unwrap();
        assert_eq!(wait_file(&tmp.path().join("commit.outcome"), deadline).await, "committed");
        assert_eq!(wait_file(&tmp.path().join("close.outcome"), deadline).await, "closed 2");
        valid_v1(&gate, SCOPE);
        let record = gate.control.read(SCOPE).await.unwrap().unwrap();
        assert_eq!(record.control_generation, 2);
        assert_eq!(record.enabled, Some(false));
        drop(children);
    }

    #[tokio::test]
    async fn governed_commit_process_fixture() {
        let Some(root) = std::env::var_os(CHILD_DIR) else { return; };
        let root = PathBuf::from(root);
        let role = std::env::var(CHILD_ROLE).unwrap();
        let mut gate = gate(&root);
        let deadline = Instant::now() + DEADLINE;
        let outcome = if role == "commit" {
            let snapshot = gate.observe(SCOPE).await.unwrap().unwrap();
            let (hook, mut receiver, release) = pause();
            gate.inside_owner = Some(hook);
            let task = spawn(gate.clone(), snapshot);
            entered(&mut receiver).await;
            // Readiness means the real gate closure owns the cross-process guard.
            JsonFileStore.write_text_atomic_strict(&root.join("commit.ready"), "ready").await.unwrap();
            wait_file(&root.join("release.ready"), deadline).await;
            release.send(()).unwrap();
            committed(finish(task).await, true);
            "committed"
        } else {
            wait_file(&root.join("commit.ready"), deadline).await;
            JsonFileStore.write_text_atomic_strict(&root.join("close.ready"), "ready").await.unwrap();
            let locks: Vec<_> = std::fs::read_dir(gate.control_root()).unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.file_name().unwrap().to_string_lossy().ends_with(".json.lock"))
                .collect();
            assert_eq!(locks.len(), 1);
            let mut successful_probes = 0_u64;
            loop {
                assert!(Instant::now() < deadline, "contention probe never observed WouldBlock");
                let probe = std::fs::OpenOptions::new().read(true).write(true).open(&locks[0]).unwrap();
                // WouldBlock is actual evidence that the owner holds the OS lock;
                // "did not complete yet" alone is not contention evidence.
                let contention = fs2::FileExt::try_lock_exclusive(&probe);
                drop(probe); // Never retain a successful probe while waiting.
                match contention {
                    // fs2's Windows lock-contended error has kind Uncategorized;
                    // accept only its exact native WouldBlock equivalent.
                    Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => break,
                    Err(error) => panic!("contention probe failed unexpectedly: {error}"),
                    Ok(()) => successful_probes += 1,
                }
                tokio::task::yield_now().await;
            }
            // The parent rejects any success-before-contention observation:
            // the owner must already hold the guard throughout this protocol.
            JsonFileStore.write_text_atomic_strict(
                &root.join("close.contended"), &successful_probes.to_string(),
            ).await.unwrap();
            let closed = gate.control.update(
                SCOPE, ControlGenerationExpectation::Exactly(1), patch(false),
            ).await.unwrap();
            assert!(closed.is_applied());
            assert_eq!(closed.record().control_generation, 2);
            "closed 2"
        };
        JsonFileStore.write_text_atomic_strict(&root.join(format!("{role}.outcome")), outcome).await.unwrap();
    }
}

#[cfg(feature = "workspace-intelligence-claim")]
#[derive(Debug)]
pub(crate) enum GovernedFenceOperation {
    AdvanceIncarnation,
    VerifyIncarnation { expected: String, origin: String },
}

#[cfg(feature = "workspace-intelligence-claim")]
#[derive(Debug)]
pub(crate) enum GovernedFenceOutcome {
    Advanced(IncarnationAdvance),
    Verified { control_generation: u64 },
    Refused(GovernedClaimRefusal),
}

#[cfg(feature = "workspace-intelligence-claim")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernedClaimRefusal {
    ForeignSnapshot, ForeignBinding, NotObserved, NotEnabled, AuthorityChanged, StaleIncarnation,
}

#[cfg(feature = "workspace-intelligence-claim")]
impl GovernedClaimRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ForeignSnapshot => "foreign_snapshot",
            Self::ForeignBinding => "foreign_binding",
            Self::NotObserved => "not_observed",
            Self::NotEnabled => "not_enabled",
            Self::AuthorityChanged => "authority_changed",
            Self::StaleIncarnation => "stale_incarnation",
        }
    }
}

#[cfg(feature = "workspace-intelligence-claim")]
impl From<GovernedCommitRefusal> for GovernedClaimRefusal {
    fn from(refusal: GovernedCommitRefusal) -> Self {
        match refusal {
            GovernedCommitRefusal::ForeignSnapshot => Self::ForeignSnapshot,
            GovernedCommitRefusal::NotObserved => Self::NotObserved,
            GovernedCommitRefusal::AuthorityChanged => Self::AuthorityChanged,
            GovernedCommitRefusal::NotEnabled => Self::NotEnabled,
        }
    }
}

#[cfg(feature = "workspace-intelligence-claim")]
impl WorkspaceIntelligenceCommitGate {
    /// Guard acquisition and the fresh read are awaits. From the final fresh
    /// read returning to hand-off there is no await. The blocking closure owns
    /// both the guard and its own lease Arc. Advancement is covered through
    /// COMMIT/rollback; verification is read-only and always rolls back on drop.
    /// The binding is immutable, with private fields and no interior mutability,
    /// so checks before the control lock cannot be invalidated before hand-off.
    /// Caller cancellation after hand-off loses only the result, not either lock.
    pub(crate) async fn commit_governed(
        &self, snapshot: &GovernedCommitSnapshot, op: GovernedFenceOperation,
        hold: &ClaimLeaseBinding,
    ) -> Result<GovernedFenceOutcome, WorkspaceIntelligenceCommitError> {
        use GovernedFenceOutcome::Refused;
        if let Some(refusal) = self.binding_refusal(snapshot) { return Ok(Refused(refusal.into())); }
        if hold.control_root().as_os_str() != self.control_root.as_os_str() {
            return Ok(Refused(GovernedClaimRefusal::ForeignBinding));
        }
        if hold.cognition_root().as_os_str() != self.cognition_root.as_os_str() {
            return Ok(Refused(GovernedClaimRefusal::ForeignBinding));
        }
        if hold.scope() != snapshot.scope {
            return Ok(Refused(GovernedClaimRefusal::ForeignBinding));
        }
        let name = format!("{}.lock", scope_digest(&snapshot.scope)?);
        if hold.lease_path().file_name() != Some(std::ffi::OsStr::new(&name)) {
            return Ok(Refused(GovernedClaimRefusal::ForeignBinding));
        }
        if hold.lease().lock_path().as_os_str() != hold.lease_path().as_os_str() {
            return Ok(Refused(GovernedClaimRefusal::ForeignBinding));
        }
        if let Err(refusal) = Self::projection_refusal(self.control.read(&snapshot.scope).await?, snapshot) {
            return Ok(Refused(refusal.into()));
        }
        #[cfg(test)]
        if let Some(pause) = &self.after_precheck { Self::wait_async(pause).await; }
        let (guard, fresh) = self.control.lock_and_read_authority(&snapshot.scope).await?;
        let projection = match Self::projection_refusal(fresh, snapshot) {
            Ok(projection) => projection,
            Err(refusal) => return Ok(Refused(refusal.into())),
        };
        #[cfg(test)]
        if let Some(pause) = &self.after_fresh { Self::wait_async(pause).await; }
        let scope = snapshot.scope.clone();
        let store = WorkspaceIntelligenceCognitionStore::new(self.cognition_root.clone());
        #[cfg(test)]
        let store = { let mut store = store; store.verify_pause = self.inside_verification.clone(); store };
        let control_generation = projection.control_generation;
        #[cfg(test)]
        let pause = self.inside_owner.clone();
        let lease = hold.lease();
        let outcome = tokio::task::spawn_blocking(move || {
            let _guard = guard;
            let _lease = lease;
            #[cfg(test)]
            if let Some(pause) = pause { Self::wait_blocking(&pause); }
            match op {
                GovernedFenceOperation::AdvanceIncarnation => store.advance_incarnation(&scope)
                    .map(GovernedFenceOutcome::Advanced),
                GovernedFenceOperation::VerifyIncarnation { expected, origin } =>
                    store.verify_incarnation(&scope, &expected, &origin)
                        .map(|_| GovernedFenceOutcome::Verified { control_generation }),
            }
        }).await.map_err(WorkspaceIntelligenceCommitError::OwnerTask)?;
        match outcome {
            Err(WorkspaceIntelligenceCognitionError::StaleIncarnation { .. }) => Ok(Refused(GovernedClaimRefusal::StaleIncarnation)),
            Err(error) => Err(error.into()),
            Ok(outcome) => Ok(outcome),
        }
    }
}
