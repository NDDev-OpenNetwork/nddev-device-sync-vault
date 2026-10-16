//! Typed replica-storage boundary. Native execution and the browser worker run
//! the same journal transactions; no SQL, keys or plaintext cross the IPC port.
use crate::{
    Error,
    journal::{
        Enqueued, Entity, Journal, ObservationBaselines, ObservationTarget, Pending, RecordEntry,
    },
};
use nddev_device_sync_accounts::sync_wire as wire;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize)]
pub(crate) enum Command {
    EditTarget {
        kind: String,
        id: String,
        known: u64,
    },
    CheckpointHandle {
        scope_tag: String,
        key_id: String,
    },
    EnqueueWriter {
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
        writer: crate::journal::WriterEnqueueGuard,
    },
    WriterSnapshot,
    ConfirmWriter {
        expected: crate::journal::WriterSnapshot,
        mode: u8,
        key_id: String,
        basis: Option<u64>,
    },
    MarkUnknown {
        id: String,
        request: Vec<u8>,
        reason: String,
    },
    UnknownReason,
    CheckpointProgress {
        guard: crate::journal::StageGuard,
    },
    AcknowledgeOriginal {
        request: Vec<u8>,
        result: Vec<u8>,
        status: u16,
        resolved: u64,
    },
    IngestOriginal {
        head: u64,
        floor: u64,
        after: u64,
        rows: Vec<crate::journal::RawRow>,
        next: u64,
        more: bool,
    },
    ResumeCheckpoint {
        scope_tag: String,
        key_id: String,
        known: u64,
    },
    ResetCheckpoint {
        scope_tag: String,
        key_id: String,
    },
    BeginCheckpoint {
        scope_tag: String,
        key_id: String,
        base: u64,
        total: usize,
        known: u64,
    },
    StageBase {
        guard: crate::journal::StageGuard,
        base: u64,
        total: usize,
        rows: Vec<crate::journal::RawRow>,
        next: u64,
        more: bool,
    },
    StageDelta {
        guard: crate::journal::StageGuard,
        floor: u64,
        rows: Vec<crate::journal::RawRow>,
        next: u64,
        more: bool,
    },
    InstallCheckpoint {
        guard: crate::journal::StageGuard,
    },
    DiscardCheckpoint {
        guard: crate::journal::StageGuard,
    },
    Stats,
    Pending,
    Cursor,
    ObservationTarget {
        id: String,
    },
    ObservationResolution {
        id: String,
        selected: nddev_device_sync_domain::repositories::catalog::CredentialSelection,
        selected_operation: Vec<u8>,
    },
    RepositoryPage {
        after: String,
    },
    RepositoryOwners {
        ids: Vec<String>,
        expected: u64,
    },
    ObservationBaselines {
        selected: nddev_device_sync_domain::repositories::catalog::CredentialSelection,
    },
    // A distinct IPC command makes older workers reject the combined guard
    // instead of silently ignoring an added field on the old command.
    EnqueueObservedWriter {
        body: Vec<u8>,
        expected_revision: u64,
        expected_pending: Option<String>,
        selected: nddev_device_sync_domain::repositories::catalog::CredentialSelection,
        selected_operation: Vec<u8>,
        writer: crate::journal::WriterEnqueueGuard,
    },
    // Distinct command: an older worker must reject a resolver, never ignore
    // added fields and treat it as an ordinary observation enqueue.
    EnqueueResolvedObservation {
        body: Vec<u8>,
        expected_revision: u64,
        expected_pending: Option<String>,
        selected: nddev_device_sync_domain::repositories::catalog::CredentialSelection,
        selected_operation: Vec<u8>,
        writer: crate::journal::WriterEnqueueGuard,
        resolution: crate::journal::ResolutionGuard,
    },
    Entity {
        kind: String,
        id: String,
    },
    Records {
        after: String,
    },
    Resolution {
        id: String,
    },
    Clipboard,
    Enqueue {
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
    },
    States {
        after: Option<(String, String)>,
    },
    Acknowledge {
        request: Vec<u8>,
        result: Vec<u8>,
        resolved: u64,
    },
    Ingest {
        page: wire::SyncPage,
        resolutions: Vec<u64>,
    },
    CaughtUp {
        cursor: u64,
        at: u64,
    },
}
impl Command {
    fn event(&self) -> &'static str {
        match self {
            Self::EditTarget { .. } => "vault.storage.edit_target",
            Self::CheckpointHandle { .. } => "vault.storage.checkpoint_handle",
            Self::EnqueueWriter { .. } => "vault.storage.enqueue_writer",
            Self::WriterSnapshot => "vault.storage.writer_snapshot",
            Self::ConfirmWriter { .. } => "vault.storage.writer_confirm",
            Self::MarkUnknown { .. } => "vault.storage.unknown",
            Self::UnknownReason => "vault.storage.unknown_reason",
            Self::CheckpointProgress { .. } => "vault.storage.checkpoint_progress",
            Self::AcknowledgeOriginal { .. } => "vault.storage.acknowledge_original",
            Self::IngestOriginal { .. } => "vault.storage.ingest_original",
            Self::ResumeCheckpoint { .. } => "vault.storage.checkpoint_resume",
            Self::ResetCheckpoint { .. } => "vault.storage.checkpoint_reset",
            Self::BeginCheckpoint { .. } => "vault.storage.checkpoint_begin",
            Self::StageBase { .. } => "vault.storage.checkpoint_base",
            Self::StageDelta { .. } => "vault.storage.checkpoint_delta",
            Self::InstallCheckpoint { .. } => "vault.storage.checkpoint_install",
            Self::DiscardCheckpoint { .. } => "vault.storage.checkpoint_discard",
            Self::Stats => "vault.storage.stats",
            Self::Pending => "vault.storage.claim",
            Self::Cursor => "vault.storage.cursor",
            Self::ObservationTarget { .. } => "vault.storage.observation_target",
            Self::ObservationResolution { .. } => "vault.storage.observation_resolution",
            Self::RepositoryPage { .. } => "vault.storage.repository_page",
            Self::RepositoryOwners { .. } => "vault.storage.repository_owners",
            Self::ObservationBaselines { .. } => "vault.storage.observation_baselines",
            Self::EnqueueObservedWriter { .. } => "vault.storage.enqueue_observation",
            Self::EnqueueResolvedObservation { .. } => "vault.storage.resolve_observation",
            Self::Entity { .. } => "vault.storage.entity",
            Self::Records { .. } => "vault.storage.records",
            Self::Resolution { .. } => "vault.storage.resolution",
            Self::Clipboard => "vault.storage.clipboard",
            Self::Enqueue { .. } => "vault.storage.enqueue",
            Self::States { .. } => "vault.storage.states",
            Self::Acknowledge { .. } => "vault.storage.acknowledge",
            Self::Ingest { .. } => "vault.storage.ingest",
            Self::CaughtUp { .. } => "vault.storage.caught_up",
        }
    }
}
fn completed(
    event: &'static str,
    started: nddev_device_sync_accounts::runtime::Instant,
    result: &Result<Reply, Error>,
) {
    match result {
        Ok(_) => {
            tracing::event!(target:"nddev_device_sync_vault",tracing::Level::INFO,{event.name=event,outcome="ok",duration_ms=started.elapsed().as_millis() as u64})
        }
        Err(Error::Cancelled) => {
            tracing::event!(target:"nddev_device_sync_vault",tracing::Level::INFO,{event.name=event,outcome="stopped",error.type="vault_cancelled",duration_ms=started.elapsed().as_millis() as u64})
        }
        Err(error) => {
            tracing::event!(target:"nddev_device_sync_vault",tracing::Level::WARN,{event.name=event,outcome="error",error.type=error.code(),duration_ms=started.elapsed().as_millis() as u64})
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Reply {
    EditTarget(crate::journal::EditTarget),
    WriterSnapshot(crate::journal::WriterSnapshot),
    UnknownReason(Option<String>),
    CheckpointProgress(crate::journal::StageProgress),
    Stage(crate::journal::StageGuard),
    MaybeStage(Option<crate::journal::StageGuard>),
    Stats(u32, u32, u64, u64, u64),
    Pending(Vec<Pending>),
    Cursor(u64),
    ObservationBaselines(ObservationBaselines),
    ObservationTarget(ObservationTarget),
    ObservationResolution(crate::journal::ObservationResolution),
    CatalogRows(crate::journal::CatalogRows),
    Entity(Option<Entity>),
    Records(Vec<RecordEntry>, u64, u64),
    Resolution(Entity, Option<Vec<u8>>, crate::journal::ResolutionGuard),
    Bool(bool),
    Clipboard(Option<(String, Entity)>),
    Enqueued(Enqueued),
    States(crate::journal::StateRows),
    Done,
}

pub(crate) fn execute(journal: &Journal, command: Command) -> Result<Reply, Error> {
    Ok(match command {
        Command::EnqueueResolvedObservation {
            body,
            expected_revision,
            expected_pending,
            selected,
            selected_operation,
            writer,
            resolution,
        } => Reply::Enqueued(journal.enqueue_observation_resolution(
            body,
            expected_revision,
            expected_pending,
            (&selected, &selected_operation),
            &writer,
            &resolution,
        )?),
        Command::ObservationResolution {
            id,
            selected,
            selected_operation,
        } => Reply::ObservationResolution(journal.observation_resolution(
            &id,
            &selected,
            &selected_operation,
        )?),
        Command::RepositoryPage { after } => Reply::CatalogRows(journal.repository_page(&after)?),
        Command::RepositoryOwners { ids, expected } => {
            Reply::CatalogRows(journal.repository_owners(&ids, expected)?)
        }
        Command::EditTarget { kind, id, known } => {
            Reply::EditTarget(journal.edit_target(&kind, &id, known)?)
        }
        Command::CheckpointHandle { scope_tag, key_id } => {
            Reply::MaybeStage(journal.checkpoint_handle(&scope_tag, &key_id)?)
        }
        Command::EnqueueWriter {
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
            writer,
        } => Reply::Enqueued(journal.enqueue_writer(
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
            &writer,
        )?),
        Command::WriterSnapshot => Reply::WriterSnapshot(journal.writer_snapshot()?),
        Command::ConfirmWriter {
            expected,
            mode,
            key_id,
            basis,
        } => Reply::WriterSnapshot(journal.confirm_writer(&expected, mode, &key_id, basis)?),
        Command::MarkUnknown {
            id,
            request,
            reason,
        } => {
            journal.mark_unknown(&id, &request, &reason)?;
            Reply::Done
        }
        Command::UnknownReason => Reply::UnknownReason(journal.unknown_reason()?),
        Command::CheckpointProgress { guard } => {
            Reply::CheckpointProgress(journal.checkpoint_progress(&guard)?)
        }
        Command::AcknowledgeOriginal {
            request,
            result,
            status,
            resolved,
        } => {
            journal.acknowledge_original(&request, &result, status, resolved)?;
            Reply::Done
        }
        Command::IngestOriginal {
            head,
            floor,
            after,
            rows,
            next,
            more,
        } => {
            journal.ingest_original(
                nddev_device_sync_domain::sync::history::HistoryVersion {
                    head,
                    floor,
                    base: floor,
                },
                after,
                &rows,
                next,
                more,
            )?;
            Reply::Done
        }
        Command::ResumeCheckpoint {
            scope_tag,
            key_id,
            known,
        } => Reply::MaybeStage(journal.resume_checkpoint(&scope_tag, &key_id, known)?),
        Command::ResetCheckpoint { scope_tag, key_id } => {
            journal.reset_checkpoint(&scope_tag, &key_id)?;
            Reply::Done
        }
        Command::BeginCheckpoint {
            scope_tag,
            key_id,
            base,
            total,
            known,
        } => Reply::Stage(journal.begin_checkpoint(&scope_tag, &key_id, base, total, known)?),
        Command::StageBase {
            guard,
            base,
            total,
            rows,
            next,
            more,
        } => {
            journal.stage_base(&guard, base, total, &rows, next, more)?;
            Reply::Done
        }
        Command::StageDelta {
            guard,
            floor,
            rows,
            next,
            more,
        } => {
            journal.stage_delta(&guard, floor, &rows, next, more)?;
            Reply::Done
        }
        Command::InstallCheckpoint { guard } => {
            journal.install_checkpoint(&guard)?;
            Reply::Done
        }
        Command::DiscardCheckpoint { guard } => {
            journal.discard_checkpoint(&guard)?;
            Reply::Done
        }
        Command::Stats => {
            let (pending, conflicts, cursor, at, local) = journal.stats()?;
            Reply::Stats(pending, conflicts, cursor, at, local)
        }
        Command::Pending => Reply::Pending(journal.pending()?),
        Command::Cursor => Reply::Cursor(journal.cursor()?),
        Command::ObservationTarget { id } => {
            Reply::ObservationTarget(journal.observation_target(&id)?)
        }
        Command::ObservationBaselines { selected } => {
            Reply::ObservationBaselines(journal.observation_baselines(&selected)?)
        }
        Command::EnqueueObservedWriter {
            body,
            expected_revision,
            expected_pending,
            selected,
            selected_operation,
            writer,
        } => Reply::Enqueued(journal.enqueue_observation(
            body,
            expected_revision,
            expected_pending,
            &selected,
            &selected_operation,
            &writer,
        )?),
        Command::Entity { kind, id } => Reply::Entity(journal.entity(&kind, &id)?),
        Command::Records { after } => {
            let (items, cursor, local) = journal.record_page(&after)?;
            Reply::Records(items, cursor, local)
        }
        Command::Resolution { id } => {
            let (e, c, s) = journal.resolution(&id)?;
            Reply::Resolution(e, c, s)
        }
        Command::Clipboard => Reply::Clipboard(journal.latest_clipboard()?),
        Command::Enqueue {
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
        } => Reply::Enqueued(journal.enqueue(
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
        )?),
        Command::States { after } => Reply::States(journal.state_page(after)?),
        Command::Acknowledge {
            request,
            result,
            resolved,
        } => {
            journal.acknowledge(&request, &result, resolved)?;
            Reply::Done
        }
        Command::Ingest { page, resolutions } => {
            journal.ingest(&page, &resolutions)?;
            Reply::Done
        }
        Command::CaughtUp { cursor, at } => Reply::Bool(journal.caught_up(cursor, at)?),
    })
}

pub(crate) struct Storage {
    #[cfg(not(target_arch = "wasm32"))]
    journal: Journal,
    #[cfg(target_arch = "wasm32")]
    scope: String,
    io: Arc<Semaphore>,
    admission: Arc<Semaphore>,
}
impl Storage {
    pub async fn open(path: PathBuf) -> Result<Self, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let journal = tokio::task::spawn_blocking(move || Journal::open(path))
                .await
                .map_err(|_| Error::Unavailable)??;
            Ok(Self {
                journal,
                io: Arc::new(Semaphore::new(1)),
                admission: Arc::new(Semaphore::new(4)),
            })
        }
        #[cfg(target_arch = "wasm32")]
        {
            let scope = path
                .file_stem()
                .and_then(|v| v.to_str())
                .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or(Error::Invalid)?
                .to_owned();
            Ok(Self {
                scope,
                io: Arc::new(Semaphore::new(1)),
                admission: Arc::new(Semaphore::new(4)),
            })
        }
    }
    pub(crate) async fn call(&self, command: Command) -> Result<Reply, Error> {
        self.call_guarded(command, || Ok(())).await
    }
    /// Synchronous caller guard after admission, before any transaction starts.
    /// It is not serialized to the worker and must perform no I/O.
    pub(crate) async fn call_guarded(
        &self,
        command: Command,
        check: impl FnOnce() -> Result<(), Error>,
    ) -> Result<Reply, Error> {
        let event = command.event();
        let span = nddev_device_sync_telemetry::operation_span("vault", "io")
            .map_err(|_| Error::Unavailable)?;
        let started = nddev_device_sync_accounts::runtime::Instant::now();
        // Local UI and synchronization share short transactions. Permit a
        // bounded FIFO wait instead of rejecting a foreground call whenever a
        // background read happens to own the connection. Both permits outlive
        // a cancelled caller until actual native/worker I/O has completed.
        let admission = self
            .admission
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        let permit = nddev_device_sync_accounts::runtime::timeout(
            std::time::Duration::from_millis(500),
            self.io.clone().acquire_owned(),
        )
        .await;
        if let Err(error) = check() {
            span.in_scope(|| completed(event, started, &Err(error)));
            return Err(error);
        }
        let permit = permit
            .map_err(|_| Error::Busy)?
            .map_err(|_| Error::Unavailable)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let journal = self.journal.clone();
            tokio::task::spawn_blocking(move || {
                let _permits = (permit, admission);
                span.in_scope(|| {
                    let result = execute(&journal, command);
                    completed(event, started, &result);
                    result
                })
            })
            .await
            .map_err(|_| Error::Unavailable)?
        }
        #[cfg(target_arch = "wasm32")]
        {
            use tracing::Instrument;
            let (send, receive) = tokio::sync::oneshot::channel();
            let scope = self.scope.clone();
            // Keep admission and the completion event through actual worker
            // completion even if the presentation cancels its waiting future.
            nddev_device_sync_accounts::runtime::spawn(
                async move {
                    let _permits = (permit, admission);
                    let result = crate::browser::request(&scope, command).await;
                    completed(event, started, &result);
                    let _ = send.send(result);
                }
                .instrument(span),
            );
            receive.await.map_err(|_| Error::Unavailable)?
        }
    }
    pub async fn stats(&self) -> Result<(u32, u32, u64, u64, u64), Error> {
        match self.call(Command::Stats).await? {
            Reply::Stats(p, c, s, at, l) => Ok((p, c, s, at, l)),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn pending(&self) -> Result<Vec<Pending>, Error> {
        match self.call(Command::Pending).await? {
            Reply::Pending(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn cursor(&self) -> Result<u64, Error> {
        match self.call(Command::Cursor).await? {
            Reply::Cursor(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn entity(&self, kind: &str, id: &str) -> Result<Option<Entity>, Error> {
        match self
            .call(Command::Entity {
                kind: kind.into(),
                id: id.into(),
            })
            .await?
        {
            Reply::Entity(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn record_page(&self, after: String) -> Result<(Vec<RecordEntry>, u64, u64), Error> {
        match self.call(Command::Records { after }).await? {
            Reply::Records(v, c, l) => Ok((v, c, l)),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn resolution(
        &self,
        id: String,
    ) -> Result<(Entity, Option<Vec<u8>>, crate::journal::ResolutionGuard), Error> {
        match self.call(Command::Resolution { id }).await? {
            Reply::Resolution(e, c, s) => Ok((e, c, s)),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn latest_clipboard(&self) -> Result<Option<(String, Entity)>, Error> {
        match self.call(Command::Clipboard).await? {
            Reply::Clipboard(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn state_page(
        &self,
        after: Option<(String, String)>,
    ) -> Result<crate::journal::StateRows, Error> {
        match self.call(Command::States { after }).await? {
            Reply::States(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn ingest(&self, page: wire::SyncPage, resolutions: Vec<u64>) -> Result<(), Error> {
        match self.call(Command::Ingest { page, resolutions }).await? {
            Reply::Done => Ok(()),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn caught_up(&self, cursor: u64, at: u64) -> Result<bool, Error> {
        match self.call(Command::CaughtUp { cursor, at }).await? {
            Reply::Bool(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }

    #[cfg(not(target_arch = "wasm32"))]
    pub async fn key_lock(&self) -> Result<std::fs::File, Error> {
        let journal = self.journal.clone();
        tokio::task::spawn_blocking(move || journal.key_lock())
            .await
            .map_err(|_| Error::Unavailable)?
    }
    #[cfg(target_arch = "wasm32")]
    pub async fn key_lock(&self) -> Result<crate::browser::KeyLock, Error> {
        crate::browser::key_lock(&self.scope).await
    }

    #[cfg(all(test, not(target_arch = "wasm32")))]
    pub fn path_for_acceptance(&self) -> PathBuf {
        self.journal.path_for_acceptance()
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod admission_tests {
    use super::*;

    #[tokio::test]
    async fn cancelled_guard_after_queue_wait_cannot_start_a_transaction() {
        struct Owned(PathBuf);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let directory = Owned(
            std::env::temp_dir().join(format!("nds-storage-admission-{}", uuid::Uuid::new_v4())),
        );
        let storage = Arc::new(Storage::open(directory.0.join("replica.db")).await.unwrap());
        let held = storage.io.clone().acquire_owned().await.unwrap();
        let cancellation = tokio_util::sync::CancellationToken::new();
        let cancelled = cancellation.clone();
        let queued = storage.clone();
        let task = tokio::spawn(async move {
            queued
                .call_guarded(Command::CaughtUp { cursor: 0, at: 77 }, || {
                    if cancelled.is_cancelled() {
                        Err(Error::Cancelled)
                    } else {
                        Ok(())
                    }
                })
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while storage.admission.available_permits() == 4 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cancellation.cancel();
        drop(held);
        assert!(matches!(task.await.unwrap(), Err(Error::Cancelled)));
        assert_eq!(storage.journal.stats().unwrap().3, 0);
        assert_eq!(storage.io.available_permits(), 1);
        assert_eq!(storage.admission.available_permits(), 4);
        assert!(matches!(
            storage
                .call(Command::CaughtUp { cursor: 0, at: 77 })
                .await
                .unwrap(),
            Reply::Bool(true)
        ));
        assert_eq!(storage.journal.stats().unwrap().3, 77);
    }
}
