//! Bounded native SQLite durability. Only encrypted operation bodies and public
//! revision/receipt metadata live here. Vault/signing/session keys stay native.
use crate::Error;
use nddev_device_sync_accounts::sync_wire as wire;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File, OpenOptions};
use std::{path::PathBuf, time::Duration};

#[derive(Clone)]
pub struct Journal {
    path: PathBuf,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Pending {
    pub id: String,
    pub body: Vec<u8>,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Entity {
    pub revision: u64,
    pub body: Vec<u8>,
    pub conflicted: bool,
    pub server_seq: u64,
    pub pending_id: Option<String>,
    pub next_base: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct Enqueued {
    pub id: String,
    pub pending: u32,
    pub conflicts: u32,
    pub cursor: u64,
    pub local_revision: u64,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct RecordEntry {
    pub id: String,
    pub entity: Entity,
    pub conflict: Option<Vec<u8>>,
}
fn failed<E>(_: E) -> Error {
    Error::Unavailable
}
fn sql_failed(error: rusqlite::Error) -> Error {
    match error {
        rusqlite::Error::SqliteFailure(code, _) => match code.code {
            rusqlite::ErrorCode::DiskFull => Error::StorageFull,
            rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => Error::Busy,
            _ => Error::Unavailable,
        },
        _ => Error::Unavailable,
    }
}

impl Journal {
    #[cfg(test)]
    pub fn path_for_acceptance(&self) -> PathBuf {
        self.path.clone()
    }
    pub fn open(path: PathBuf) -> Result<Self, Error> {
        #[cfg(not(target_arch = "wasm32"))]
        if !path.is_absolute() {
            return Err(Error::Invalid);
        }
        // wasm32-unknown-unknown has no OS root and Path::is_absolute is false.
        // The worker's scoped VFS owns exactly this virtual database filename.
        #[cfg(target_arch = "wasm32")]
        if path.to_str() != Some("replica.db") {
            return Err(Error::Invalid);
        }
        #[cfg(not(target_arch = "wasm32"))]
        let path = {
            let parent = path.parent().ok_or(Error::Invalid)?;
            fs::create_dir_all(parent).map_err(failed)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(failed)?;
            }
            // Native platform roots can have system-owned aliases (e.g. macOS
            // /var -> /private/var). Resolve the directory once, while still refusing
            // database symlinks on every subsequent SQLite connection.
            let path = fs::canonicalize(parent)
                .map_err(failed)?
                .join(path.file_name().ok_or(Error::Invalid)?);
            if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
                return Err(Error::Invalid);
            }
            path
        };
        let journal = Self { path };
        journal.initialize()?;
        Ok(journal)
    }
    fn connection(&self) -> Result<Connection, Error> {
        let connection = Connection::open_with_flags(
            &self.path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(sql_failed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(failed)?;
        }
        connection
            .busy_timeout(Duration::from_millis(500))
            .map_err(sql_failed)?;
        #[cfg(not(target_arch = "wasm32"))]
        connection
            .execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(sql_failed)?;
        #[cfg(target_arch = "wasm32")]
        connection
            .execute_batch("PRAGMA journal_mode=DELETE;")
            .map_err(sql_failed)?;
        connection.execute_batch("PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA max_page_count=65536; PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=1048576;").map_err(sql_failed)?;
        Ok(connection)
    }
    /// Held across native key creation/import. The OS lock serializes independent
    /// app processes too; an in-process semaphore alone cannot protect a key.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn key_lock(&self) -> Result<File, Error> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options
            .open(self.path.with_extension("key-lock"))
            .map_err(failed)?;
        if !file.metadata().map_err(failed)?.file_type().is_file() {
            return Err(Error::Invalid);
        }
        file.try_lock().map_err(|_| Error::Busy)?;
        Ok(file)
    }
}

mod apply;
mod outbox;
mod reads;
mod schema;
use apply::{apply, kind};
#[cfg(test)]
mod tests;
