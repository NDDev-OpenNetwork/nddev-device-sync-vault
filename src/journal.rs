//! Bounded native SQLite durability. Only encrypted operation bodies and public
//! revision/receipt metadata live here. Vault/signing/session keys stay native.
use crate::Error;
use nddev_device_sync_accounts::sync_wire as wire;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    fs::{self, File, OpenOptions},
    path::PathBuf,
    time::Duration,
};

#[derive(Clone)]
pub struct Journal {
    path: PathBuf,
}
pub struct Pending {
    pub id: String,
    pub body: Vec<u8>,
}
pub struct Entity {
    pub revision: u64,
    pub body: Vec<u8>,
    pub conflicted: bool,
}
fn failed<E>(_: E) -> Error {
    Error::Unavailable
}

impl Journal {
    #[cfg(test)]
    pub fn path_for_acceptance(&self) -> PathBuf {
        self.path.clone()
    }
    pub fn open(path: PathBuf) -> Result<Self, Error> {
        if !path.is_absolute() {
            return Err(Error::Invalid);
        }
        let parent = path.parent().ok_or(Error::Invalid)?;
        fs::create_dir_all(parent).map_err(failed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(failed)?;
        }
        if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
            return Err(Error::Invalid);
        }
        let journal = Self { path };
        let connection = journal.connection()?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,cursor INTEGER NOT NULL DEFAULT 0 CHECK(cursor BETWEEN 0 AND 9007199254740991));
            INSERT OR IGNORE INTO meta(singleton,schema_version) VALUES(1,1);
            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),state TEXT NOT NULL CHECK(state IN ('pending','conflict')));
            CREATE UNIQUE INDEX IF NOT EXISTS outbox_entity_pending ON outbox(kind,entity_id) WHERE state='pending';
            CREATE TABLE IF NOT EXISTS entities(kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS conflicts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),result BLOB NOT NULL);").map_err(failed)?;
        let version: i64 = connection
            .query_row(
                "SELECT schema_version FROM meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(failed)?;
        if version != 1 {
            return Err(Error::Invalid);
        }
        Ok(journal)
    }
    fn connection(&self) -> Result<Connection, Error> {
        let connection = Connection::open(&self.path).map_err(failed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).map_err(failed)?;
        }
        connection
            .busy_timeout(Duration::from_millis(500))
            .map_err(failed)?;
        connection.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA max_page_count=65536; PRAGMA wal_autocheckpoint=64; PRAGMA journal_size_limit=1048576;").map_err(failed)?;
        Ok(connection)
    }
    /// Held across native key creation/import. The OS lock serializes independent
    /// app processes too; an in-process semaphore alone cannot protect a key.
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
    pub fn cursor(&self) -> Result<u64, Error> {
        self.connection()?
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(failed)
    }
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        let connection = self.connection()?;
        let mut query = connection
            .prepare("SELECT id,body FROM outbox WHERE state='pending' ORDER BY rowid LIMIT 16")
            .map_err(failed)?;
        query
            .query_map([], |row| {
                Ok(Pending {
                    id: row.get(0)?,
                    body: row.get(1)?,
                })
            })
            .map_err(failed)?
            .collect::<Result<_, _>>()
            .map_err(failed)
    }
    pub fn counts(&self) -> Result<(u32, u32), Error> {
        self.connection()?.query_row("SELECT (SELECT count(*) FROM outbox WHERE state='pending'),(SELECT count(*) FROM conflicts)",[],|row|Ok((row.get(0)?,row.get(1)?))).map_err(failed)
    }
    pub fn entity(&self, kind: &str, id: &str) -> Result<Option<Entity>, Error> {
        self.connection()?.query_row("SELECT revision,body,EXISTS(SELECT 1 FROM conflicts WHERE kind=?1 AND entity_id=?2) FROM entities WHERE kind=?1 AND id=?2",params![kind,id],|row|Ok(Entity{revision:row.get(0)?,body:row.get(1)?,conflicted:row.get(2)?})).optional().map_err(failed)
    }
    pub fn list(&self, kind: &str) -> Result<Vec<(String, Entity)>, Error> {
        let connection = self.connection()?;
        let mut query=connection.prepare("SELECT id,revision,body,EXISTS(SELECT 1 FROM conflicts WHERE kind=?1 AND entity_id=entities.id) FROM entities WHERE kind=?1 ORDER BY id LIMIT 100").map_err(failed)?;
        query
            .query_map([kind], |row| {
                Ok((
                    row.get(0)?,
                    Entity {
                        revision: row.get(1)?,
                        body: row.get(2)?,
                        conflicted: row.get(3)?,
                    },
                ))
            })
            .map_err(failed)?
            .collect::<Result<_, _>>()
            .map_err(failed)
    }
    pub fn enqueue(&self, body: Vec<u8>) -> Result<String, Error> {
        if body.len() > 24576 {
            return Err(Error::Invalid);
        }
        let operation: wire::SyncOperation =
            serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
        crate::codec::operation(&operation, body.len())?;
        let kind = kind(&operation.entity_type);
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let count: u64 = tx
            .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
            .map_err(failed)?;
        if count >= 1024 {
            return Err(Error::Busy);
        }
        let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM outbox WHERE kind=?1 AND entity_id=?2 AND state='pending')",params![kind,operation.entity_id],|row|row.get(0)).map_err(failed)?;
        if exists {
            return Err(Error::Busy);
        }
        tx.execute(
            "INSERT INTO outbox(id,kind,entity_id,body,state) VALUES (?1,?2,?3,?4,'pending')",
            params![operation.operation_id, kind, operation.entity_id, body],
        )
        .map_err(failed)?;
        tx.commit().map_err(failed)?;
        Ok(operation.operation_id)
    }
    pub fn acknowledge(&self, id: &str, result: &[u8]) -> Result<(), Error> {
        let outcome: wire::Sync = serde_json::from_slice(result).map_err(|_| Error::Invalid)?;
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let body: Vec<u8> = tx
            .query_row("SELECT body FROM outbox WHERE id=?1", [id], |row| {
                row.get(0)
            })
            .map_err(failed)?;
        let operation: wire::SyncOperation = serde_json::from_slice(&body).map_err(failed)?;
        apply(&tx, &operation, &body, &outcome, result)?;
        tx.execute("DELETE FROM outbox WHERE id=?1", [id])
            .map_err(failed)?;
        tx.commit().map_err(failed)
    }
    /// Only advance after every entry is durably applied or retained as an
    /// explicit conflict. A crash replays the same inbox page safely.
    pub fn ingest(&self, page: &wire::SyncPage) -> Result<(), Error> {
        if page.entries.len() > 100 || page.next_after_seq < 0 {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let mut previous: i64 = tx
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(failed)?;
        for entry in &page.entries {
            let seq = match &entry.result {
                wire::Sync::Applied(value) => value.server_seq,
                wire::Sync::Conflict(value) => value.server_seq,
            };
            if seq != previous + 1 {
                return Err(Error::Invalid);
            }
            let body = serde_json::to_vec(&entry.operation).map_err(failed)?;
            let result = serde_json::to_vec(&entry.result).map_err(failed)?;
            apply(&tx, &entry.operation, &body, &entry.result, &result)?;
            previous = seq;
        }
        if page.next_after_seq != previous || page.has_more && page.entries.is_empty() {
            return Err(Error::Invalid);
        }
        tx.execute("UPDATE meta SET cursor=?1 WHERE singleton=1", [previous])
            .map_err(failed)?;
        tx.commit().map_err(failed)
    }
}
fn kind(kind: &wire::EntityType) -> &'static str {
    match kind {
        wire::EntityType::AccountState => "account_state",
        wire::EntityType::ClipboardItem => "clipboard_item",
        wire::EntityType::DeviceState => "device_state",
        wire::EntityType::ModuleState => "module_state",
        wire::EntityType::VaultRecord => "vault_record",
    }
}
fn apply(
    tx: &rusqlite::Transaction<'_>,
    operation: &wire::SyncOperation,
    body: &[u8],
    outcome: &wire::Sync,
    result: &[u8],
) -> Result<(), Error> {
    crate::codec::operation(operation, body.len())?;
    let kind = kind(&operation.entity_type);
    match outcome {
        wire::Sync::Applied(value) => {
            if value.operation_id != operation.operation_id
                || value.revision != operation.base_revision + 1
                || value.server_seq < 1
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT INTO entities(kind,id,revision,body) VALUES(?1,?2,?3,?4) ON CONFLICT(kind,id) DO UPDATE SET revision=EXCLUDED.revision,body=EXCLUDED.body WHERE entities.revision<EXCLUDED.revision",params![kind,operation.entity_id,value.revision,body]).map_err(failed)?;
        }
        wire::Sync::Conflict(value) => {
            if value.operation_id != operation.operation_id
                || value.base_revision != operation.base_revision
                || value.current_revision < 0
                || value.server_seq < 1
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT OR IGNORE INTO conflicts(id,kind,entity_id,body,result) VALUES(?1,?2,?3,?4,?5)",params![operation.operation_id,kind,operation.entity_id,body,result]).map_err(failed)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Scope, VaultKey};
    use nddev_device_sync_domain::{
        DeviceId,
        sync::{EncryptedPayload, EntityKind, Operation},
    };
    struct Owned(std::path::PathBuf);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn encrypted(key: &VaultKey, id: &str, entity: &str) -> Vec<u8> {
        let scope = Scope {
            origin: "https://instance.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: "device".into(),
        };
        let mut operation = Operation {
            id: id.into(),
            device: DeviceId::new("device").unwrap(),
            entity_kind: EntityKind::VaultRecord,
            entity_id: entity.into(),
            base_revision: 0,
            idempotency_key: id.into(),
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        };
        operation.payload = key
            .encrypt(&scope, &operation, b"PRIVATE_NATIVE_PLAINTEXT_NEVER_STORED")
            .unwrap();
        crate::codec::body(&operation).unwrap()
    }
    fn result(id: &str, seq: i64) -> wire::Sync {
        wire::Sync::Applied(wire::SyncApplied {
            operation_id: id.into(),
            outcome: wire::SyncAppliedOutcome::Applied,
            revision: 1,
            server_seq: seq,
        })
    }
    #[test]
    fn actual_sqlite_reopen_key_lock_and_inbox_transaction_preserve_durability() {
        let owned = Owned(std::env::temp_dir().join(format!("nds-vault-{}", uuid::Uuid::new_v4())));
        let path = owned.0.join("journal.db");
        let key = VaultKey::generate().unwrap();
        let first = encrypted(&key, "operation-1", "record-1");
        let journal = Journal::open(path.clone()).unwrap();
        journal.enqueue(first.clone()).unwrap();
        drop(journal);
        let journal = Journal::open(path.clone()).unwrap();
        assert_eq!(journal.pending().unwrap()[0].body, first);
        assert!(matches!(journal.enqueue(first.clone()), Err(Error::Busy)));
        let lock = journal.key_lock().unwrap();
        assert!(matches!(
            Journal::open(path.clone()).unwrap().key_lock(),
            Err(Error::Busy)
        ));
        drop(lock);
        let _lock = journal.key_lock().unwrap();
        journal
            .acknowledge(
                "operation-1",
                &serde_json::to_vec(&result("operation-1", 1)).unwrap(),
            )
            .unwrap();
        assert_eq!(journal.cursor().unwrap(), 0);
        assert_eq!(journal.counts().unwrap(), (0, 0));
        let page = wire::SyncPage {
            entries: vec![wire::SyncEntry {
                operation: serde_json::from_slice(&first).unwrap(),
                result: result("operation-1", 1),
            }],
            next_after_seq: 1,
            has_more: false,
        };
        journal.ingest(&page).unwrap();
        assert_eq!(journal.cursor().unwrap(), 1);
        let second = encrypted(&key, "operation-2", "record-2");
        let invalid = wire::SyncPage {
            entries: vec![
                wire::SyncEntry {
                    operation: serde_json::from_slice(&second).unwrap(),
                    result: result("operation-2", 2),
                },
                wire::SyncEntry {
                    operation: serde_json::from_slice(&second).unwrap(),
                    result: result("operation-2", 4),
                },
            ],
            next_after_seq: 4,
            has_more: false,
        };
        assert!(matches!(journal.ingest(&invalid), Err(Error::Invalid)));
        assert_eq!(journal.cursor().unwrap(), 1);
        assert!(
            journal
                .entity("vault_record", "record-2")
                .unwrap()
                .is_none()
        );
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(35)
                .any(|value| value == b"PRIVATE_NATIVE_PLAINTEXT_NEVER_STORED")
        );
        assert!(
            !bytes
                .windows(48)
                .any(|value| value == key.native_secret().as_slice())
        );
    }
}
