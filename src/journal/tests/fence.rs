use super::*;

fn names(connection: &Connection) -> Vec<(String, String)> {
    let mut statement = connection
        .prepare("SELECT name,type FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

#[test]
fn schema_five_rename_preserves_rows_receipts_intents_and_rolls_back_as_one_unit() {
    let (owned, journal, key) = owned_journal();
    let seed = encrypted(&key, "seed", "record");
    journal
        .ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
        .unwrap();
    assert!(journal.caught_up(1, 87).unwrap());
    let local = encrypted(&key, "local", "pending-record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    journal.pending().unwrap();
    let tail = encrypted_at(&key, "tail", "pending-record", 1);
    journal
        .enqueue(tail.clone(), None, 0, Some("local".into()))
        .unwrap();
    let conflict_body = encrypted(&key, "competing", "record");
    let receipt = wire::Sync::Conflict(wire::SyncConflict {
        operation_id: "competing".into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    });
    journal
        .ingest(&page(&conflict_body, receipt, 2), &[0])
        .unwrap();
    let before = journal.stats().unwrap();
    let path = owned.0.join("replica.db");
    let db = Connection::open(&path).unwrap();
    legacy_layout(&db);
    db.execute_batch(
        "UPDATE meta SET schema_version=5;
        CREATE TRIGGER reject_schema_six BEFORE UPDATE OF schema_version ON meta
        WHEN NEW.schema_version=6 BEGIN SELECT RAISE(ABORT,'synthetic migration failure'); END;",
    )
    .unwrap();
    let layout = names(&db);
    let retained: (i64, Vec<u8>, Vec<u8>) = db
        .query_row("SELECT rowid,body,result FROM conflicts", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert!(Journal::open(path.clone()).is_err());
    assert_eq!(names(&db), layout);
    assert_eq!(
        db.query_row("SELECT schema_version FROM meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        5
    );
    db.execute_batch("DROP TRIGGER reject_schema_six;").unwrap();
    let upgraded = Journal::open(path.clone()).unwrap();
    assert_eq!(upgraded.stats().unwrap(), before);
    assert_eq!(upgraded.pending().unwrap()[0].body, local);
    assert_eq!(
        upgraded
            .entity("vault_record", "pending-record")
            .unwrap()
            .unwrap()
            .body,
        tail
    );
    assert_eq!(
        upgraded
            .entity("vault_record", "record")
            .unwrap()
            .unwrap()
            .body,
        seed
    );
    assert_eq!(
        upgraded.resolution("record").unwrap().1,
        Some(conflict_body)
    );
    assert_eq!(
        db.query_row("SELECT rowid,body,result FROM replica_conflicts", [], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, Vec<u8>>(2)?,
            ))
        })
        .unwrap(),
        retained
    );
    for name in ["outbox", "entities", "conflicts"] {
        assert!(!names(&db).iter().any(|(found, _)| found == name));
    }
    assert!(names(&db).contains(&("meta".into(), "view".into())));
    assert_eq!(Journal::open(path).unwrap().stats().unwrap(), before);
}

#[test]
fn legacy_bootstrap_and_mutations_cannot_create_a_parallel_journal() {
    let (owned, journal, key) = owned_journal();
    let local = encrypted(&key, "local", "record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    let before = journal.stats().unwrap();
    let mut db = Connection::open(owned.0.join("replica.db")).unwrap();
    let layout = names(&db);
    {
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(tx.execute_batch("CREATE TABLE IF NOT EXISTS meta(singleton INTEGER PRIMARY KEY,schema_version INTEGER NOT NULL,cursor INTEGER NOT NULL DEFAULT 0);
            INSERT OR IGNORE INTO meta(singleton,schema_version) VALUES(1,1);
            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,body BLOB);").is_err());
    }
    assert_eq!(names(&db), layout);
    assert!(
        db.execute("UPDATE meta SET cursor=99 WHERE singleton=1", [])
            .is_err()
    );
    assert!(
        db.execute("DELETE FROM outbox WHERE id='local'", [])
            .is_err()
    );
    assert!(db.execute("INSERT INTO conflicts(id,kind,entity_id,body,result) VALUES('legacy','vault_record','record',?1,?2)", params![local, b"{}".as_slice()]).is_err());
    assert_eq!(journal.stats().unwrap(), before);
}

#[test]
fn cached_current_handles_reject_future_versions_without_ddl_or_data_mutation() {
    let (owned, journal, key) = owned_journal();
    let local = encrypted(&key, "local", "record");
    journal.enqueue(local.clone(), None, 0, None).unwrap();
    let db = Connection::open(owned.0.join("replica.db")).unwrap();
    db.execute("UPDATE v3_meta SET schema_version=8", [])
        .unwrap();
    let layout = names(&db);
    assert!(matches!(
        Journal::open(owned.0.join("replica.db")),
        Err(Error::Invalid)
    ));
    assert!(matches!(journal.pending(), Err(Error::Invalid)));
    assert!(matches!(
        journal.enqueue(encrypted(&key, "other", "other-record"), None, 0, None),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        journal.acknowledge(
            &local,
            &serde_json::to_vec(&applied("local", 1, 1)).unwrap(),
            0
        ),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        journal.ingest(&page(&local, applied("local", 1, 1), 1), &[0]),
        Err(Error::Invalid)
    ));
    assert!(matches!(journal.caught_up(0, 99), Err(Error::Invalid)));
    assert!(matches!(journal.stats(), Err(Error::Invalid)));
    assert!(matches!(
        journal.entity("vault_record", "record"),
        Err(Error::Invalid)
    ));
    assert!(matches!(journal.record_page(""), Err(Error::Invalid)));
    assert_eq!(names(&db), layout);
    assert_eq!(
        db.query_row("SELECT body FROM replica_outbox", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        local
    );
    assert_eq!(
        db.query_row("SELECT cursor FROM replica_meta", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn an_uncertain_nonempty_store_is_never_bootstrapped_as_an_empty_replica() {
    let owned = Owned(std::env::temp_dir().join(format!("nds-uncertain-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir_all(&owned.0).unwrap();
    let path = owned.0.join("replica.db");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TABLE retained(value TEXT); INSERT INTO retained VALUES('synthetic retained value');").unwrap();
    let layout = names(&db);
    assert!(matches!(Journal::open(path), Err(Error::Invalid)));
    assert_eq!(names(&db), layout);
}
