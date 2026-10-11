//! Bounded native SQLite durability. Only encrypted operation bodies and public
//! revision/receipt metadata live here. Vault/signing/session keys stay native.
use crate::Error;
use nddev_device_sync_accounts::sync_wire as wire;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
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
    pub server_seq: u64,
}
pub struct RecordEntry {
    pub id: String,
    pub entity: Entity,
    pub conflict: Option<Vec<u8>>,
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
        // Native platform roots can have system-owned aliases (e.g. macOS
        // /var -> /private/var). Resolve the directory once, while still refusing
        // database symlinks on every subsequent SQLite connection.
        let path = fs::canonicalize(parent)
            .map_err(failed)?
            .join(path.file_name().ok_or(Error::Invalid)?);
        if fs::symlink_metadata(&path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
            return Err(Error::Invalid);
        }
        let journal = Self { path };
        let mut connection = journal.connection()?;
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
        if version == 1 {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(failed)?;
            let current: i64 = tx
                .query_row(
                    "SELECT schema_version FROM meta WHERE singleton=1",
                    [],
                    |row| row.get(0),
                )
                .map_err(failed)?;
            // Preserve ciphertext, pending operations and conflicts. Replay the
            // existing stream to recover committed ordering absent in schema1.
            if current == 1 {
                tx.execute_batch("ALTER TABLE entities ADD COLUMN server_seq INTEGER NOT NULL DEFAULT 0 CHECK(server_seq BETWEEN 0 AND 9007199254740991); UPDATE meta SET schema_version=2,cursor=0 WHERE singleton=1;").map_err(failed)?;
            } else if current != 2 {
                return Err(Error::Invalid);
            }
            tx.commit().map_err(failed)?;
        } else if version != 2 {
            return Err(Error::Invalid);
        }
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
        .map_err(failed)?;
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
        self.connection()?.query_row("SELECT revision,body,server_seq,EXISTS(SELECT 1 FROM conflicts WHERE kind=?1 AND entity_id=?2) FROM entities WHERE kind=?1 AND id=?2",params![kind,id],|row|Ok(Entity{revision:row.get(0)?,body:row.get(1)?,server_seq:row.get(2)?,conflicted:row.get(3)?})).optional().map_err(failed)
    }
    pub fn record_page(&self, after: &str) -> Result<(Vec<RecordEntry>, u64), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction().map_err(failed)?;
        let entries = {
            let mut query = tx.prepare("SELECT id,revision,body,server_seq,(SELECT body FROM conflicts WHERE kind='vault_record' AND entity_id=entities.id ORDER BY json_extract(CAST(result AS TEXT),'$.server_seq') DESC LIMIT 1) FROM entities WHERE kind='vault_record' AND id>?1 ORDER BY id LIMIT 51").map_err(failed)?;
            query
                .query_map([after], |row| {
                    let conflict: Option<Vec<u8>> = row.get(4)?;
                    Ok(RecordEntry {
                        id: row.get(0)?,
                        entity: Entity {
                            revision: row.get(1)?,
                            body: row.get(2)?,
                            server_seq: row.get(3)?,
                            conflicted: conflict.is_some(),
                        },
                        conflict,
                    })
                })
                .map_err(failed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(failed)?
        };
        let cursor = tx
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(failed)?;
        tx.commit().map_err(failed)?;
        Ok((entries, cursor))
    }
    pub fn record_conflict(&self, id: &str) -> Result<Option<Vec<u8>>, Error> {
        self.connection()?.query_row("SELECT body FROM conflicts WHERE kind='vault_record' AND entity_id=?1 ORDER BY json_extract(CAST(result AS TEXT),'$.server_seq') DESC LIMIT 1", [id], |row| row.get(0)).optional().map_err(failed)
    }
    pub fn has_pending(&self, kind: &str, id: &str) -> Result<bool, Error> {
        self.connection()?.query_row("SELECT EXISTS(SELECT 1 FROM outbox WHERE kind=?1 AND entity_id=?2 AND state='pending')",params![kind,id],|row|row.get(0)).map_err(failed)
    }
    pub fn latest_clipboard(&self) -> Result<Option<(String, Entity)>, Error> {
        self.connection()?.query_row("SELECT id,revision,body,server_seq,EXISTS(SELECT 1 FROM conflicts WHERE kind='clipboard_item' AND entity_id=entities.id) FROM entities WHERE kind='clipboard_item' AND server_seq>0 ORDER BY server_seq DESC LIMIT 1",[],|row|Ok((row.get(0)?,Entity { revision:row.get(1)?,body:row.get(2)?,server_seq:row.get(3)?,conflicted:row.get(4)? }))).optional().map_err(failed)
    }
    pub fn enqueue(&self, body: Vec<u8>, expected_cursor: Option<u64>) -> Result<String, Error> {
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
        if let Some(expected) = expected_cursor {
            let actual: u64 = tx
                .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |row| {
                    row.get(0)
                })
                .map_err(failed)?;
            if actual != expected {
                return Err(Error::Busy);
            }
        }
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
    pub fn state_page(
        &self,
        after: Option<(String, String)>,
    ) -> Result<Vec<(String, String, Entity)>, Error> {
        let connection = self.connection()?;
        let (kind, id) = after.map_or((None, None), |(kind, id)| (Some(kind), Some(id)));
        let mut query=connection.prepare("SELECT kind,id,revision,body,EXISTS(SELECT 1 FROM conflicts WHERE kind=entities.kind AND entity_id=entities.id),server_seq FROM entities WHERE kind IN ('device_state','module_state','account_state') AND (?1 IS NULL OR (kind,id)>(?1,?2)) ORDER BY kind,id LIMIT 51").map_err(failed)?;
        query
            .query_map(params![kind, id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    Entity {
                        revision: row.get(2)?,
                        body: row.get(3)?,
                        conflicted: row.get(4)?,
                        server_seq: row.get(5)?,
                    },
                ))
            })
            .map_err(failed)?
            .collect::<Result<_, _>>()
            .map_err(failed)
    }
    pub fn acknowledge(&self, id: &str, result: &[u8], resolved: u64) -> Result<(), Error> {
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
        apply(&tx, &operation, &body, &outcome, result, resolved)?;
        tx.execute("DELETE FROM outbox WHERE id=?1", [id])
            .map_err(failed)?;
        tx.commit().map_err(failed)
    }
    /// Only advance after every entry is durably applied or retained as an
    /// explicit conflict. A crash replays the same inbox page safely.
    pub fn ingest(&self, page: &wire::SyncPage, resolutions: &[u64]) -> Result<(), Error> {
        if page.entries.len() > 100
            || page.next_after_seq < 0
            || resolutions.len() != page.entries.len()
        {
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
        for (entry, resolved) in page.entries.iter().zip(resolutions) {
            let seq = match &entry.result {
                wire::Sync::Applied(value) => value.server_seq,
                wire::Sync::Conflict(value) => value.server_seq,
            };
            if seq != previous + 1 {
                return Err(Error::Invalid);
            }
            let body = serde_json::to_vec(&entry.operation).map_err(failed)?;
            let result = serde_json::to_vec(&entry.result).map_err(failed)?;
            apply(
                &tx,
                &entry.operation,
                &body,
                &entry.result,
                &result,
                *resolved,
            )?;
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
    resolved: u64,
) -> Result<(), Error> {
    crate::codec::operation(operation, body.len())?;
    let kind = kind(&operation.entity_type);
    match outcome {
        wire::Sync::Applied(value) => {
            if value.operation_id != operation.operation_id
                || value.revision != operation.base_revision + 1
                || value.server_seq < 1
                || resolved >= value.server_seq as u64
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT INTO entities(kind,id,revision,body,server_seq) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(kind,id) DO UPDATE SET revision=EXCLUDED.revision,body=EXCLUDED.body,server_seq=EXCLUDED.server_seq WHERE entities.revision<EXCLUDED.revision OR (entities.revision=EXCLUDED.revision AND entities.body=EXCLUDED.body AND entities.server_seq=0)",params![kind,operation.entity_id,value.revision,body,value.server_seq]).map_err(failed)?;
            if resolved > 0 {
                if kind != "vault_record" {
                    return Err(Error::Invalid);
                }
                tx.execute("DELETE FROM conflicts WHERE kind=?1 AND entity_id=?2 AND json_extract(CAST(result AS TEXT),'$.server_seq')<=?3", params![kind,operation.entity_id,resolved]).map_err(failed)?;
            }
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
        journal.enqueue(first.clone(), None).unwrap();
        drop(journal);
        let journal = Journal::open(path.clone()).unwrap();
        assert_eq!(journal.pending().unwrap()[0].body, first);
        assert!(matches!(
            journal.enqueue(first.clone(), None),
            Err(Error::Busy)
        ));
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
                0,
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
        journal.ingest(&page, &vec![0; page.entries.len()]).unwrap();
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
        assert!(matches!(
            journal.ingest(&invalid, &vec![0; invalid.entries.len()]),
            Err(Error::Invalid)
        ));
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

    #[cfg(unix)]
    #[test]
    fn actual_sqlite_refuses_a_replaced_database_symlink() {
        let owned = Owned(std::env::temp_dir().join(format!("nds-vault-{}", uuid::Uuid::new_v4())));
        let path = owned.0.join("journal.db");
        let journal = Journal::open(path.clone()).unwrap();
        let original = owned.0.join("original.db");
        std::fs::rename(&path, &original).unwrap();
        std::os::unix::fs::symlink(&original, &path).unwrap();
        // A retained handle must refuse the replacement on every connection,
        // even though its initial open validated the original regular file.
        assert!(journal.cursor().is_err());
    }
}
