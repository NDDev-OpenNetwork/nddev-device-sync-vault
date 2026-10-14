use super::*;

fn conflict(id: &str, seq: i64) -> wire::Sync {
    wire::Sync::Conflict(wire::SyncConflict {
        operation_id: id.into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: seq,
    })
}

#[test]
fn foreign_receipts_preserve_claimed_roots_and_successors() {
    for conflicted in [false, true] {
        let (owned, journal, key) = owned_journal();
        let local = encrypted_by(&key, "local-device", "collision", "local-record", 0);
        journal.enqueue(local.clone(), None, 0, None).unwrap();
        journal.pending().unwrap();
        let successor = encrypted_by(&key, "local-device", "successor", "local-record", 1);
        journal
            .enqueue(successor.clone(), None, 0, Some("collision".into()))
            .unwrap();
        let seed = encrypted_by(&key, "other-device", "seed", "remote-record", 0);
        journal
            .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
            .unwrap();
        let foreign = encrypted_by(
            &key,
            "other-device",
            "collision",
            "remote-record",
            if conflicted { 0 } else { 1 },
        );
        let outcome = if conflicted {
            conflict("collision", 2)
        } else {
            applied("collision", 2, 2)
        };
        journal.ingest(&page(&foreign, outcome, 2), &[0]).unwrap();
        let journal = Journal::open(owned.0.join("replica.db")).unwrap();
        assert_eq!(journal.counts().unwrap(), (2, u32::from(conflicted)));
        assert_eq!(journal.pending().unwrap()[0].body, local);
        let local_view = journal
            .entity("vault_record", "local-record")
            .unwrap()
            .unwrap();
        assert_eq!(local_view.body, successor);
        assert!(!local_view.conflicted);
        // Only the actual local receipt may release this successor.
        journal
            .ingest(&page(&local, applied("collision", 1, 3), 3), &[0])
            .unwrap();
        assert_eq!(journal.pending().unwrap()[0].body, successor);
    }
}

#[test]
fn inbox_matches_all_operation_fields_and_ignores_json_formatting() {
    let (_owned, journal, key) = owned_journal();
    let original = encrypted(&key, "same-id", "record");
    let value: wire::SyncOperation = serde_json::from_slice(&original).unwrap();
    let formatted = serde_json::to_vec_pretty(&value).unwrap();
    journal.enqueue(formatted.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let mut changed = value.clone();
    // Idempotency key is a wire field outside the encrypted record's AAD.
    changed.idempotency_key = "different-request".into();
    let changed = serde_json::to_vec(&changed).unwrap();
    journal
        .ingest(&page(&changed, applied("same-id", 1, 1), 1), &[0])
        .unwrap();
    assert_eq!(journal.pending().unwrap()[0].body, formatted);
    // A canonical inbox copy of the exact request still settles a formatted POST.
    let (_owned, journal, _) = owned_journal();
    journal.enqueue(formatted, None, 0, None).unwrap();
    journal.pending().unwrap();
    journal
        .ingest(&page(&original, applied("same-id", 1, 1), 1), &[0])
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 0));
}

#[test]
fn typed_acknowledgement_requires_exact_claimed_bytes() {
    use crate::storage::{Command, execute};
    let (_owned, journal, key) = owned_journal();
    let original = encrypted(&key, "same-id", "record");
    journal.enqueue(original.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let before = journal.stats().unwrap();
    let operation: wire::SyncOperation = serde_json::from_slice(&original).unwrap();
    let wrong = [
        encrypted_by(&key, "foreign-device", "same-id", "record", 0),
        encrypted(&key, "same-id", "other-record"),
        serde_json::to_vec_pretty(&operation).unwrap(),
    ];
    let result = serde_json::to_vec(&applied("same-id", 1, 1)).unwrap();
    for request in wrong {
        // Native execution and the browser worker deserialize this same command.
        let command = Command::Acknowledge {
            request,
            result: result.clone(),
            resolved: 0,
        };
        let encoded = serde_json::to_string(&command).unwrap();
        assert!(matches!(
            execute(&journal, serde_json::from_str(&encoded).unwrap()),
            Err(Error::Invalid)
        ));
        assert_eq!(journal.stats().unwrap(), before);
        assert_eq!(journal.pending().unwrap()[0].body, original);
    }
    execute(
        &journal,
        Command::Acknowledge {
            request: original.clone(),
            result: result.clone(),
            resolved: 0,
        },
    )
    .unwrap();
    journal
        .ingest(&page(&original, applied("same-id", 1, 1), 1), &[0])
        .unwrap();
    journal.acknowledge(&original, &result, 0).unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 0));
    assert_eq!(journal.cursor().unwrap(), 1);
}

#[test]
fn device_scoped_conflicts_survive_ack_inbox_replay_and_resolution() {
    let (owned, journal, key) = owned_journal();
    let seed = encrypted(&key, "seed", "record");
    journal
        .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
        .unwrap();
    let first = encrypted_by(&key, "device-a", "same-id", "record", 0);
    let second = encrypted_by(&key, "device-b", "same-id", "record", 0);
    journal
        .ingest(&page(&first, conflict("same-id", 2), 2), &[0])
        .unwrap();
    journal
        .ingest(&page(&second, conflict("same-id", 3), 3), &[0])
        .unwrap();
    let journal = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 2));
    assert_eq!(journal.resolution("record").unwrap().1, Some(second));
    let partial = encrypted_at(&key, "partial-resolution", "record", 1);
    journal
        .ingest(
            &page(&partial, applied("partial-resolution", 2, 4), 4),
            &[2],
        )
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 1));
    let complete = encrypted_at(&key, "complete-resolution", "record", 2);
    journal
        .ingest(
            &page(&complete, applied("complete-resolution", 3, 5), 5),
            &[3],
        )
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 0));

    // Local conflict acknowledgement followed by its inbox echo is one receipt.
    let (_owned, journal, key) = owned_journal();
    let local = encrypted(&key, "local", "record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let remote = encrypted_by(&key, "remote-device", "remote", "record", 0);
    journal
        .ingest(&page(&remote, applied("remote", 1, 1), 1), &[0])
        .unwrap();
    journal
        .acknowledge(
            &local,
            &serde_json::to_vec(&conflict("local", 2)).unwrap(),
            0,
        )
        .unwrap();
    journal
        .ingest(&page(&local, conflict("local", 2), 2), &[0])
        .unwrap();
    assert_eq!(journal.counts().unwrap(), (0, 1));
}

#[test]
fn conflicting_receipt_reuse_rolls_back_the_entire_inbox_page() {
    let (_owned, journal, key) = owned_journal();
    let local = encrypted(&key, "local", "record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    // Append acknowledgements may arrive before their older inbox history.
    journal
        .acknowledge(
            &local,
            &serde_json::to_vec(&conflict("local", 2)).unwrap(),
            0,
        )
        .unwrap();
    let before = journal.stats().unwrap();
    let seed = encrypted_by(&key, "remote-device", "seed", "record", 0);
    let changed = encrypted(&key, "local", "another-record");
    let mut incoming = page(&seed, applied("seed", 1, 1), 2);
    incoming.entries.push(wire::SyncEntry {
        operation: serde_json::from_slice(&changed).unwrap(),
        result: conflict("local", 2),
    });
    assert!(matches!(
        journal.ingest(&incoming, &[0, 0]),
        Err(Error::Invalid)
    ));
    assert_eq!(journal.stats().unwrap(), before);
    assert!(journal.entity("vault_record", "record").unwrap().is_none());
}

#[test]
fn schema_four_rekeys_conflicts_atomically_without_changing_other_state() {
    let (owned, journal, key) = owned_journal();
    let seed = encrypted(&key, "seed", "record");
    journal
        .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
        .unwrap();
    let retained = encrypted_by(&key, "device:a", "operation:b", "record", 0);
    journal
        .ingest(&page(&retained, conflict("operation:b", 2), 2), &[0])
        .unwrap();
    let pending = encrypted(&key, "pending", "other-record");
    journal.enqueue(pending.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let tail = encrypted_at(&key, "tail", "other-record", 1);
    journal
        .enqueue(tail.clone(), None, 0, Some("pending".into()))
        .unwrap();
    let before = journal.stats().unwrap();
    let path = owned.0.join("replica.db");
    let db = Connection::open(&path).unwrap();
    legacy_layout(&db);
    db.execute_batch("UPDATE conflicts SET id='operation:b'; UPDATE meta SET schema_version=4; CREATE TRIGGER reject_rekey BEFORE UPDATE ON conflicts BEGIN SELECT RAISE(ABORT,'synthetic migration failure'); END;").unwrap();
    assert!(Journal::open(path.clone()).is_err());
    assert_eq!(
        db.query_row("SELECT schema_version FROM meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        4
    );
    assert_eq!(
        db.query_row("SELECT id FROM conflicts", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "operation:b"
    );
    db.execute_batch("DROP TRIGGER reject_rekey;").unwrap();
    let journal = Journal::open(path.clone()).unwrap();
    assert_eq!(journal.stats().unwrap(), before);
    assert_eq!(journal.pending().unwrap()[0].body, pending);
    assert_eq!(
        journal
            .entity("vault_record", "other-record")
            .unwrap()
            .unwrap()
            .body,
        tail
    );
    assert_eq!(journal.resolution("record").unwrap().1, Some(retained));
    assert_eq!(
        db.query_row("SELECT id FROM replica_conflicts", [], |r| r
            .get::<_, String>(0))
            .unwrap(),
        "[\"device:a\",\"operation:b\"]"
    );
    assert_eq!(
        db.query_row("SELECT schema_version FROM meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        7
    );
    assert_eq!(Journal::open(path).unwrap().stats().unwrap(), before);
}

#[test]
fn concurrent_acknowledgement_and_inbox_settle_one_root_once() {
    for conflicted in [false, true] {
        let (_owned, journal, key) = owned_journal();
        let local = encrypted(&key, "local", "record");
        journal.enqueue(local.clone(), None, 0, None).unwrap();
        journal.pending().unwrap();
        let tail = encrypted_at(&key, "tail", "record", 1);
        journal
            .enqueue(tail.clone(), None, 0, Some("local".into()))
            .unwrap();
        let seed = encrypted_by(
            &key,
            "remote-device",
            "seed",
            if conflicted { "record" } else { "other-record" },
            0,
        );
        journal
            .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
            .unwrap();
        let result = if conflicted {
            conflict("local", 2)
        } else {
            applied("local", 1, 2)
        };
        let incoming = page(&local, result.clone(), 2);
        let receipt = serde_json::to_vec(&result).unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let ack_journal = journal.clone();
        let ack_barrier = barrier.clone();
        let ack = std::thread::spawn(move || {
            ack_barrier.wait();
            ack_journal.acknowledge(&local, &receipt, 0)
        });
        let inbox_journal = journal.clone();
        let inbox = std::thread::spawn(move || {
            barrier.wait();
            inbox_journal.ingest(&incoming, &[0])
        });
        ack.join().unwrap().unwrap();
        inbox.join().unwrap().unwrap();
        assert_eq!(journal.cursor().unwrap(), 2);
        if conflicted {
            assert_eq!(journal.counts().unwrap(), (0, 1));
            assert!(journal.pending().unwrap().is_empty());
            assert_eq!(journal.resolution("record").unwrap().1, Some(tail));
        } else {
            assert_eq!(journal.counts().unwrap(), (1, 0));
            assert_eq!(journal.pending().unwrap()[0].body, tail);
        }
    }
}

#[test]
fn every_retained_schema_upgrades_to_device_scoped_conflict_keys() {
    for version in 1..=5 {
        let (owned, journal, key) = owned_journal();
        let seed = encrypted(&key, "seed", "record");
        journal
            .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
            .unwrap();
        let retained = encrypted(&key, "conflict", "record");
        journal
            .ingest(&page(&retained, conflict("conflict", 2), 2), &[0])
            .unwrap();
        let path = owned.0.join("replica.db");
        let db = Connection::open(&path).unwrap();
        legacy_layout(&db);
        db.execute_batch("DROP VIEW local_entities;").unwrap();
        if version < 5 {
            db.execute_batch("UPDATE conflicts SET id='conflict';")
                .unwrap();
        }
        if version < 4 {
            db.execute_batch("ALTER TABLE meta DROP COLUMN local_revision;")
                .unwrap();
        }
        if version < 3 {
            db.execute_batch("DROP INDEX outbox_unsent; DROP INDEX outbox_dispatched; DROP INDEX conflict_entity; ALTER TABLE outbox DROP COLUMN dispatched; ALTER TABLE outbox DROP COLUMN predecessor; ALTER TABLE meta DROP COLUMN last_sync_at;").unwrap();
        }
        if version < 2 {
            db.execute_batch("ALTER TABLE entities DROP COLUMN server_seq;")
                .unwrap();
        }
        db.execute("UPDATE meta SET schema_version=?1", [version])
            .unwrap();
        let upgraded = Journal::open(path).unwrap();
        assert_eq!(upgraded.resolution("record").unwrap().1, Some(retained));
        assert_eq!(upgraded.cursor().unwrap(), if version == 1 { 0 } else { 2 });
        assert_eq!(
            db.query_row("SELECT schema_version FROM meta", [], |r| r
                .get::<_, u32>(0))
                .unwrap(),
            7
        );
    }
}
