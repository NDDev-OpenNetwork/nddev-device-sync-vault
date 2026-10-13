use super::*;
use crate::crypto::{Scope, VaultKey};
use nddev_device_sync_domain::{
    DeviceId,
    sync::{EncryptedPayload, EntityKind, Operation},
};
mod fence;
mod receipts;
struct Owned(std::path::PathBuf);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn encrypted(key: &VaultKey, id: &str, entity: &str) -> Vec<u8> {
    encrypted_at(key, id, entity, 0)
}
fn encrypted_at(key: &VaultKey, id: &str, entity: &str, revision: u64) -> Vec<u8> {
    encrypted_by(key, "device", id, entity, revision)
}
fn encrypted_by(key: &VaultKey, device: &str, id: &str, entity: &str, revision: u64) -> Vec<u8> {
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: device.into(),
    };
    let mut operation = Operation {
        id: id.into(),
        device: DeviceId::new(device).unwrap(),
        entity_kind: EntityKind::VaultRecord,
        entity_id: entity.into(),
        base_revision: revision,
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
    journal.enqueue(first.clone(), None, 0, None).unwrap();
    drop(journal);
    let journal = Journal::open(path.clone()).unwrap();
    assert_eq!(journal.pending().unwrap()[0].body, first);
    assert!(matches!(
        journal.enqueue(first.clone(), None, 0, None),
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
            &first,
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

fn owned_journal() -> (Owned, Journal, VaultKey) {
    let owned =
        Owned(std::env::temp_dir().join(format!("nds-offline-journal-{}", uuid::Uuid::new_v4())));
    let journal = Journal::open(owned.0.join("replica.db")).unwrap();
    (owned, journal, VaultKey::generate().unwrap())
}
fn applied(id: &str, revision: i64, seq: i64) -> wire::Sync {
    wire::Sync::Applied(wire::SyncApplied {
        operation_id: id.into(),
        outcome: wire::SyncAppliedOutcome::Applied,
        revision,
        server_seq: seq,
    })
}
fn page(body: &[u8], outcome: wire::Sync, seq: i64) -> wire::SyncPage {
    wire::SyncPage {
        entries: vec![wire::SyncEntry {
            operation: serde_json::from_slice(body).unwrap(),
            result: outcome,
        }],
        next_after_seq: seq,
        has_more: false,
    }
}
#[test]
fn offline_edits_coalesce_but_claimed_bytes_and_successor_order_survive_restart() {
    let (owned, journal, key) = owned_journal();
    let first = encrypted(&key, "first", "record");
    journal.enqueue(first.clone(), None, 0, None).unwrap();
    let initial_local_revision = journal.stats().unwrap().4;
    let second = encrypted(&key, "second", "record");
    assert!(matches!(
        journal.enqueue(second.clone(), None, 0, None),
        Err(Error::Busy)
    ));
    journal
        .enqueue(second.clone(), None, 0, Some("first".into()))
        .unwrap();
    let (mut records, cursor, local_revision) = journal.record_page("").unwrap();
    assert_eq!(cursor, 0);
    assert!(local_revision > initial_local_revision);
    let record = records.remove(0);
    assert_eq!(record.entity.body, second);
    assert_eq!(record.entity.revision, 0);
    assert_eq!(record.entity.pending_id.as_deref(), Some("second"));
    assert_eq!(journal.counts().unwrap(), (1, 0));
    assert_eq!(journal.pending().unwrap()[0].body, second);
    let tail = encrypted_at(&key, "tail", "record", 1);
    journal
        .enqueue(tail, None, 0, Some("second".into()))
        .unwrap();
    let last = encrypted_at(&key, "last", "record", 1);
    journal
        .enqueue(last.clone(), None, 0, Some("tail".into()))
        .unwrap();
    drop(journal);
    let journal = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(journal.pending().unwrap()[0].body, second);
    assert_eq!(
        journal
            .entity("vault_record", "record")
            .unwrap()
            .unwrap()
            .body,
        last
    );
    // Receipt arrives through the inbox while the append response was lost.
    journal
        .ingest(&page(&second, applied("second", 1, 1), 1), &[0])
        .unwrap();
    journal
        .acknowledge(
            &second,
            &serde_json::to_vec(&applied("second", 1, 1)).unwrap(),
            0,
        )
        .unwrap();
    assert_eq!(journal.pending().unwrap()[0].body, last);
    assert_eq!(
        journal
            .entity("vault_record", "record")
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    journal
        .ingest(&page(&last, applied("last", 2, 2), 2), &[0])
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 0));
    assert!(journal.caught_up(2, 123).unwrap());
    let stats = journal.stats().unwrap();
    assert_eq!((stats.0, stats.1, stats.2, stats.3), (0, 0, 2, 123));
    assert!(stats.4 > 0);
    assert_eq!(
        Journal::open(owned.0.join("replica.db"))
            .unwrap()
            .stats()
            .unwrap(),
        stats
    );
}
#[test]
fn conflicted_predecessor_blocks_latest_intent_until_observed_resolution() {
    conflict_resolution(false);
}
#[test]
fn another_devices_resolution_does_not_erase_unsent_local_successor() {
    conflict_resolution(true);
}
fn conflict_resolution(remote_resolution: bool) {
    let (_owned, journal, key) = owned_journal();
    let local = encrypted(&key, "local", "record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let tail = encrypted_at(&key, "tail", "record", 1);
    journal
        .enqueue(tail.clone(), None, 0, Some("local".into()))
        .unwrap();
    let remote = encrypted(&key, "remote", "record");
    journal
        .ingest(&page(&remote, applied("remote", 1, 1), 1), &[0])
        .unwrap();
    let conflict = wire::Sync::Conflict(wire::SyncConflict {
        operation_id: "local".into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    });
    journal.ingest(&page(&local, conflict, 2), &[0]).unwrap();
    assert!(journal.pending().unwrap().is_empty());
    let (entity, latest, _) = journal.resolution("record").unwrap();
    assert_eq!(entity.body, remote);
    assert_eq!(latest, Some(tail));
    assert_eq!(entity.pending_id.as_deref(), Some("tail"));
    assert!(entity.conflicted);
    if remote_resolution {
        let other = encrypted_at(&key, "other-resolution", "record", 1);
        journal
            .ingest(&page(&other, applied("other-resolution", 2, 3), 3), &[2])
            .unwrap();
        assert_eq!(journal.counts().unwrap(), (0, 1));
    }
    let (entity, _, cursor) = journal.resolution("record").unwrap();
    let revision = entity.revision;
    let resolution = encrypted_at(&key, "resolution", "record", revision);
    assert!(matches!(
        journal.enqueue(
            resolution.clone(),
            Some(cursor - 1),
            revision,
            Some("tail".into())
        ),
        Err(Error::Busy)
    ));
    assert!(matches!(
        journal.enqueue(resolution.clone(), Some(cursor), revision, None),
        Err(Error::Busy)
    ));
    journal
        .enqueue(
            resolution.clone(),
            Some(cursor),
            revision,
            Some("tail".into()),
        )
        .unwrap();
    journal.pending().unwrap();
    journal
        .ingest(
            &page(
                &resolution,
                applied("resolution", revision as i64 + 1, cursor as i64 + 1),
                cursor as i64 + 1,
            ),
            &[cursor],
        )
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 0));
    assert!(
        !journal
            .entity("vault_record", "record")
            .unwrap()
            .unwrap()
            .conflicted
    );
}
#[test]
fn concurrent_editors_cannot_replace_unobserved_local_intent() {
    let (_owned, journal, key) = owned_journal();
    journal
        .enqueue(encrypted(&key, "first", "record"), None, 0, None)
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = ["a", "b"]
        .into_iter()
        .map(|id| {
            let journal = journal.clone();
            let body = encrypted(&key, id, "record");
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                journal.enqueue(body, None, 0, Some("first".into()))
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::Busy)))
            .count(),
        1
    );
    assert_eq!(journal.counts().unwrap(), (1, 0));
}
#[test]
fn schema_two_pending_operations_remain_immutable_on_upgrade() {
    let owned = Owned(std::env::temp_dir().join(format!("nds-schema2-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir(&owned.0).unwrap();
    let path = owned.0.join("replica.db");
    let key = VaultKey::generate().unwrap();
    let body = encrypted(&key, "legacy", "record");
    let connection = Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE meta(singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL,cursor INTEGER NOT NULL DEFAULT 0); INSERT INTO meta VALUES(1,2,0); CREATE TABLE outbox(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL,state TEXT NOT NULL); CREATE UNIQUE INDEX outbox_entity_pending ON outbox(kind,entity_id) WHERE state='pending'; CREATE TABLE entities(kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,body BLOB NOT NULL,server_seq INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(kind,id)); CREATE TABLE conflicts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL,result BLOB NOT NULL);").unwrap();
    connection
        .execute(
            "INSERT INTO outbox VALUES('legacy','vault_record','record',?1,'pending')",
            [&body],
        )
        .unwrap();
    drop(connection);
    let journal = Journal::open(path).unwrap();
    assert_eq!(
        journal
            .entity("vault_record", "record")
            .unwrap()
            .unwrap()
            .next_base,
        1
    );
    journal
        .enqueue(
            encrypted_at(&key, "successor", "record", 1),
            None,
            0,
            Some("legacy".into()),
        )
        .unwrap();
    assert_eq!(journal.pending().unwrap()[0].body, body);
    assert_eq!(journal.counts().unwrap(), (2, 0));
}

#[test]
fn actual_sqlite_capacity_failure_is_typed_and_leaves_no_partial_write() {
    let db = Connection::open_in_memory().unwrap();
    db.execute_batch("PRAGMA page_size=4096; PRAGMA max_page_count=2; CREATE TABLE owned_capacity(payload BLOB);").unwrap();
    let error = db
        .execute("INSERT INTO owned_capacity VALUES(?1)", [vec![0_u8; 24576]])
        .unwrap_err();
    assert_eq!(sql_failed(error), Error::StorageFull);
    assert_eq!(
        db.query_row("SELECT count(*) FROM owned_capacity", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
}

fn legacy_layout(connection: &Connection) {
    connection
        .execute_batch(
            "DROP VIEW meta;
        ALTER TABLE replica_meta RENAME TO meta;
        ALTER TABLE replica_outbox RENAME TO outbox;
        ALTER TABLE replica_entities RENAME TO entities;
        ALTER TABLE replica_conflicts RENAME TO conflicts;",
        )
        .unwrap();
}
