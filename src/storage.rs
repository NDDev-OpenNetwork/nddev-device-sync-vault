//! Typed replica-storage boundary. Native execution and the browser worker run
//! the same journal transactions; no SQL, keys or plaintext cross the IPC port.
use crate::{
    Error,
    journal::{Enqueued, Entity, Journal, Pending, RecordEntry},
};
use nddev_device_sync_accounts::sync_wire as wire;
use serde::{Deserialize, Serialize};
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Semaphore;

#[derive(Serialize, Deserialize)]
pub(crate) enum Command {
    Stats,
    Pending,
    Cursor,
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
        id: String,
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
            Self::Stats => "vault.storage.stats",
            Self::Pending => "vault.storage.claim",
            Self::Cursor => "vault.storage.cursor",
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
        Err(error) => {
            tracing::event!(target:"nddev_device_sync_vault",tracing::Level::WARN,{event.name=event,outcome="error",error.type=error.code(),duration_ms=started.elapsed().as_millis() as u64})
        }
    }
}
#[derive(Serialize, Deserialize)]
pub(crate) enum Reply {
    Stats(u32, u32, u64, u64),
    Pending(Vec<Pending>),
    Cursor(u64),
    Entity(Option<Entity>),
    Records(Vec<RecordEntry>, u64),
    Resolution(Entity, Option<Vec<u8>>, u64),
    Bool(bool),
    Clipboard(Option<(String, Entity)>),
    Enqueued(Enqueued),
    States(Vec<(String, String, Entity)>),
    Done,
}

pub(crate) fn execute(journal: &Journal, command: Command) -> Result<Reply, Error> {
    Ok(match command {
        Command::Stats => {
            let (pending, conflicts, cursor, at) = journal.stats()?;
            Reply::Stats(pending, conflicts, cursor, at)
        }
        Command::Pending => Reply::Pending(journal.pending()?),
        Command::Cursor => Reply::Cursor(journal.cursor()?),
        Command::Entity { kind, id } => Reply::Entity(journal.entity(&kind, &id)?),
        Command::Records { after } => {
            let (items, cursor) = journal.record_page(&after)?;
            Reply::Records(items, cursor)
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
            id,
            result,
            resolved,
        } => {
            journal.acknowledge(&id, &result, resolved)?;
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
            })
        }
    }
    async fn call(&self, command: Command) -> Result<Reply, Error> {
        let event = command.event();
        let span = nddev_device_sync_telemetry::operation_span("vault", "io")
            .map_err(|_| Error::Unavailable)?;
        let started = nddev_device_sync_accounts::runtime::Instant::now();
        let permit = self
            .io
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        #[cfg(not(target_arch = "wasm32"))]
        {
            let journal = self.journal.clone();
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
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
                    let _permit = permit;
                    let result = crate::browser::request(&scope, command).await;
                    completed(event, started, &result);
                    let _ = send.send(result);
                }
                .instrument(span),
            );
            receive.await.map_err(|_| Error::Unavailable)?
        }
    }
    pub async fn stats(&self) -> Result<(u32, u32, u64, u64), Error> {
        match self.call(Command::Stats).await? {
            Reply::Stats(p, c, s, at) => Ok((p, c, s, at)),
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
    pub async fn record_page(&self, after: String) -> Result<(Vec<RecordEntry>, u64), Error> {
        match self.call(Command::Records { after }).await? {
            Reply::Records(v, c) => Ok((v, c)),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn resolution(&self, id: String) -> Result<(Entity, Option<Vec<u8>>, u64), Error> {
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
    pub async fn enqueue(
        &self,
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
    ) -> Result<Enqueued, Error> {
        match self
            .call(Command::Enqueue {
                body,
                expected_cursor,
                expected_revision,
                expected_pending,
            })
            .await?
        {
            Reply::Enqueued(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn state_page(
        &self,
        after: Option<(String, String)>,
    ) -> Result<Vec<(String, String, Entity)>, Error> {
        match self.call(Command::States { after }).await? {
            Reply::States(v) => Ok(v),
            _ => Err(Error::Invalid),
        }
    }
    pub async fn acknowledge(
        &self,
        id: String,
        result: Vec<u8>,
        resolved: u64,
    ) -> Result<(), Error> {
        match self
            .call(Command::Acknowledge {
                id,
                result,
                resolved,
            })
            .await?
        {
            Reply::Done => Ok(()),
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
