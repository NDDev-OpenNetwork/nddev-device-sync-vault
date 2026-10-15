use super::super::checkpoint::{RawRow, StageGuard};
use super::*;
const TAG: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
fn raw(key: &VaultKey, id: &str, entity: &str, seq: u64) -> RawRow {
    let body = encrypted(key, id, entity);
    RawRow {
        legacy_resolved: 0,
        body,
        result: serde_json::to_vec(&result(id, seq as i64)).unwrap(),
        status: 201,
        sequence: seq,
    }
}
type StoredOutbox = (String, Vec<u8>, String, u32, Option<String>);
fn stored_outbox(j: &Journal) -> Vec<StoredOutbox> {
    let c = j.connection().unwrap();
    let mut q = c
        .prepare("SELECT id,body,state,dispatched,predecessor FROM v3_outbox ORDER BY rowid")
        .unwrap();
    q.query_map([], |r| {
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
    })
    .unwrap()
    .collect::<Result<Vec<_>, _>>()
    .unwrap()
}
#[test]
fn checkpoint_sparse_base_atomic_install_preserves_dispatched_successor_unknown_and_full_conflicts()
{
    let (_owned, j, key) = owned_journal();
    let local = encrypted(&key, "local-unknown", "local");
    j.enqueue(local.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let successor = encrypted_at(&key, "successor", "local", 1);
    j.enqueue(successor, None, 0, Some("local-unknown".into()))
        .unwrap();
    let before = stored_outbox(&j);
    let guard = j.begin_checkpoint(TAG, &key.id(), 8, 2, 0).unwrap();
    let one = raw(&key, "head-a", "a", 3);
    let two = raw(&key, "head-b", "b", 8);
    j.stage_base(&guard, 8, 2, &[one], 3, true).unwrap();
    assert_eq!(j.cursor().unwrap(), 0);
    assert!(matches!(j.install_checkpoint(&guard), Err(Error::Busy)));
    j.stage_base(&guard, 8, 2, &[two], 8, false).unwrap();
    j.stage_delta(&guard, 8, &[], 8, false).unwrap();
    j.install_checkpoint(&guard).unwrap();
    assert_eq!(stored_outbox(&j), before);
    assert_eq!(j.cursor().unwrap(), 8);
    assert_eq!(j.stats().unwrap().3, 0);
    assert!(j.entity("vault_record", "a").unwrap().is_some());
    assert_eq!(
        j.connection()
            .unwrap()
            .query_row("SELECT count(*) FROM checkpoint_rows", [], |r| r
                .get::<_, u32>(0))
            .unwrap(),
        0
    );
}
#[test]
fn checkpoint_rejected_whole_page_does_not_advance_and_wrong_scope_key_cannot_resume_reset() {
    let (_owned, j, key) = owned_journal();
    let g = j.begin_checkpoint(TAG, &key.id(), 9, 2, 0).unwrap();
    let first = raw(&key, "one", "a", 2);
    let mut invalid = raw(&key, "two", "b", 9);
    invalid.status = 409;
    assert_eq!(
        j.stage_base(&g, 9, 2, &[first, invalid], 9, false)
            .unwrap_err(),
        Error::Invalid
    );
    let c = j.connection().unwrap();
    assert_eq!(
        c.query_row("SELECT received FROM checkpoint_meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        c.query_row("SELECT count(*) FROM checkpoint_rows", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        0
    );
    assert!(matches!(
        j.resume_checkpoint(
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            &key.id(),
            0
        ),
        Err(Error::Locked)
    ));
    assert_eq!(
        j.reset_checkpoint(TAG, &VaultKey::generate().unwrap().id())
            .unwrap_err(),
        Error::Locked
    );
    j.reset_checkpoint(TAG, &key.id()).unwrap();
    assert!(j.resume_checkpoint(TAG, &key.id(), 0).unwrap().is_none());
}
#[test]
fn checkpoint_ack_after_begin_invalidates_guard_and_authorized_reset_preserves_active_family() {
    let (_owned, j, key) = owned_journal();
    let body = encrypted(&key, "ack", "a");
    j.enqueue(body.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 4, 0, 0).unwrap();
    j.acknowledge(&body, &serde_json::to_vec(&result("ack", 4)).unwrap(), 0)
        .unwrap();
    assert!(matches!(
        j.stage_delta(&g, 4, &[], 4, false),
        Err(Error::Busy)
    ));
    assert!(matches!(
        j.resume_checkpoint(TAG, &key.id(), 0),
        Err(Error::Busy)
    ));
    assert!(matches!(j.install_checkpoint(&g), Err(Error::Busy)));
    let before = j.entity("vault_record", "a").unwrap().unwrap().body;
    j.reset_checkpoint(TAG, &key.id()).unwrap();
    assert_eq!(j.entity("vault_record", "a").unwrap().unwrap().body, before);
}
#[test]
fn checkpoint_known_remote_ack_even_without_local_persist_refuses_short_stage() {
    let (_owned, j, key) = owned_journal();
    let g = j.begin_checkpoint(TAG, &key.id(), 3, 0, 7).unwrap();
    j.stage_delta(&g, 3, &[], 3, false).unwrap();
    assert!(matches!(j.install_checkpoint(&g), Err(Error::Busy)));
    assert_eq!(j.cursor().unwrap(), 0);
}
#[test]
fn checkpoint_must_not_retire_known_identity_by_omission() {
    let (_owned, j, key) = owned_journal();
    let seed = encrypted(&key, "seed", "known");
    j.ingest(&page(&seed, applied("seed", 1, 1), 1), &[0])
        .unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 1, 0, 0).unwrap();
    j.stage_delta(&g, 1, &[], 1, false).unwrap();
    assert_eq!(j.install_checkpoint(&g).unwrap_err(), Error::Invalid);
    assert_eq!(
        j.entity("vault_record", "known").unwrap().unwrap().body,
        seed
    );
}
#[test]
fn checkpoint_exact_v3_outer_lifecycle_keeps_uncovered_conflict_and_never_rewrites_outbox() {
    use nddev_device_sync_domain::sync::history::{Lifecycle, VersionedOperation};
    let (_owned, j, key) = owned_journal();
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let make = |suffix: &str, basis: u64, base: u64, r: u64| {
        let old = crate::codec::versioned(&encrypted_at(&key, suffix, "a", base))
            .unwrap()
            .operation;
        let mut o = VersionedOperation::qualify(
            old,
            basis,
            Lifecycle {
                resolved_through_seq: r,
            },
        )
        .unwrap();
        let plain =
            br#"{"version":3,"deleted":false,"title":"Record","username":"","secret":"fixture"}"#;
        o.operation.payload = key.encrypt_versioned(&scope, &o, plain).unwrap();
        crate::codec::versioned_body(&o).unwrap()
    };
    let conflict_body = make("conflict", 0, 0, 0);
    let conflict_id = crate::codec::versioned(&conflict_body)
        .unwrap()
        .operation
        .id;
    let conflict = serde_json::to_vec(&wire::Sync::Conflict(wire::SyncConflict {
        operation_id: conflict_id,
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    }))
    .unwrap();
    let applied_body = make("head", 2, 0, 0);
    let applied_id = crate::codec::versioned(&applied_body).unwrap().operation.id;
    let applied_result = serde_json::to_vec(&result(&applied_id, 3)).unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 3, 2, 0).unwrap();
    j.stage_base(
        &g,
        3,
        2,
        &[
            RawRow {
                legacy_resolved: 0,
                body: conflict_body.clone(),
                result: conflict.clone(),
                status: 409,
                sequence: 2,
            },
            RawRow {
                legacy_resolved: 0,
                body: applied_body.clone(),
                result: applied_result.clone(),
                status: 201,
                sequence: 3,
            },
        ],
        3,
        false,
    )
    .unwrap();
    j.stage_delta(&g, 3, &[], 3, false).unwrap();
    j.install_checkpoint(&g).unwrap();
    let c = j.connection().unwrap();
    assert_eq!(
        c.query_row("SELECT body,result FROM v3_conflicts", [], |r| Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?
        )))
        .unwrap(),
        (conflict_body, conflict)
    );
    assert_eq!(
        c.query_row("SELECT body,receipt_body FROM v3_entities", [], |r| Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?
        )))
        .unwrap(),
        (applied_body, applied_result)
    );
}
// Child process owns only this disposable fixture; no keyring/account/browser.
#[test]
#[ignore]
fn checkpoint_crash_child() {
    let root = std::path::PathBuf::from(std::env::var_os("NDS_CHECKPOINT_CRASH_FIXTURE").unwrap());
    let phase = std::env::var("NDS_CHECKPOINT_CRASH_PHASE").unwrap();
    let key = VaultKey::generate().unwrap();
    let j = Journal::open(root.join("replica.db")).unwrap();
    let local = encrypted(&key, "unknown", "local");
    j.enqueue(local, None, 0, None).unwrap();
    j.pending().unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 9, 2, 0).unwrap();
    j.stage_base(&g, 9, 2, &[raw(&key, "one", "a", 2)], 2, true)
        .unwrap();
    if phase == "before_install" {
        j.stage_base(&g, 9, 2, &[raw(&key, "two", "b", 9)], 9, false)
            .unwrap();
        j.stage_delta(&g, 9, &[], 9, false).unwrap();
    }
    std::fs::write(root.join("ready"), key.id()).unwrap();
    loop {
        std::thread::park();
    }
}
#[test]
fn checkpoint_kill_reopen_between_pages_and_before_install_resumes_or_resets_only_operational_rows()
{
    for phase in ["between_pages", "before_install"] {
        let root = Owned(
            std::env::temp_dir().join(format!("nds-checkpoint-crash-{}", uuid::Uuid::new_v4())),
        );
        std::fs::create_dir_all(&root.0).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "journal::tests::checkpoint::checkpoint_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("NDS_CHECKPOINT_CRASH_FIXTURE", &root.0)
            .env("NDS_CHECKPOINT_CRASH_PHASE", phase)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        while !root.0.join("ready").exists() {
            assert!(start.elapsed() < Duration::from_secs(10));
            std::thread::sleep(Duration::from_millis(5));
        }
        child.kill().unwrap();
        child.wait().unwrap();
        let key_id = std::fs::read_to_string(root.0.join("ready")).unwrap();
        let j = Journal::open(root.0.join("replica.db")).unwrap();
        let before = stored_outbox(&j);
        let g: StageGuard = j.resume_checkpoint(TAG, &key_id, 0).unwrap().unwrap();
        assert_eq!(j.cursor().unwrap(), 0);
        assert_eq!(before.len(), 1);
        assert_eq!(before[0].3, 1);
        if phase == "before_install" {
            j.install_checkpoint(&g).unwrap();
            assert_eq!(j.cursor().unwrap(), 9);
        } else {
            j.reset_checkpoint(TAG, &key_id).unwrap();
            assert_eq!(j.cursor().unwrap(), 0);
        }
        assert_eq!(stored_outbox(&j), before);
    }
}
#[test]
fn checkpoint_schema_six_migration_preserves_exact_rows_and_cached_old_statements_cannot_write() {
    let (owned, j, key) = owned_journal();
    let first = encrypted(&key, "dispatched", "local");
    j.enqueue(first.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let successor = encrypted_at(&key, "successor", "local", 1);
    j.enqueue(successor, None, 0, Some("dispatched".into()))
        .unwrap();
    let before = stored_outbox(&j);
    let c = Connection::open(owned.0.join("replica.db")).unwrap();
    legacy_layout(&c);
    c.execute_batch("ALTER TABLE meta RENAME TO replica_meta; ALTER TABLE outbox RENAME TO replica_outbox; ALTER TABLE entities RENAME TO replica_entities; ALTER TABLE conflicts RENAME TO replica_conflicts; UPDATE replica_meta SET schema_version=6; CREATE VIEW meta AS SELECT * FROM replica_meta;").unwrap();
    let mut cached = c.prepare("DELETE FROM replica_outbox WHERE id=?1").unwrap();
    let mut cached_meta = c
        .prepare("UPDATE replica_meta SET cursor=123 WHERE singleton=1")
        .unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(stored_outbox(&reopened), before);
    assert!(cached.execute(["dispatched"]).is_err());
    assert!(cached_meta.execute([]).is_err());
    assert_eq!(reopened.cursor().unwrap(), 0);
    assert_eq!(
        c.query_row("SELECT schema_version FROM replica_meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        7
    );
    assert_eq!(stored_outbox(&reopened), before);
}
#[test]
fn checkpoint_migrated_v2_without_receipt_installs_newer_v2_and_v3_heads_preserving_outbox() {
    for use_v3 in [false, true] {
        let (_owned, j, key) = owned_journal();
        let old = raw(&key, "old", "a", 1);
        j.ingest(&page(&old.body, applied("old", 1, 1), 1), &[0])
            .unwrap();
        j.connection()
            .unwrap()
            .execute(
                "UPDATE v3_entities SET receipt_body=NULL,receipt_status=NULL",
                [],
            )
            .unwrap();
        let local = encrypted(&key, "unknown", "local");
        j.enqueue(local, None, 0, None).unwrap();
        j.pending().unwrap();
        j.enqueue(
            encrypted_at(&key, "successor", "local", 1),
            None,
            0,
            Some("unknown".into()),
        )
        .unwrap();
        let before = stored_outbox(&j);
        let g = j.begin_checkpoint(TAG, &key.id(), 4, 1, 0).unwrap();
        let row = if use_v3 {
            v3_raw(&key, "new", 3, 1, 0, 2, 4)
        } else {
            RawRow {
                legacy_resolved: 0,
                body: encrypted_at(&key, "new", "a", 1),
                result: serde_json::to_vec(&applied("new", 2, 4)).unwrap(),
                status: 201,
                sequence: 4,
            }
        };
        let expected_body = row.body.clone();
        let expected_receipt = row.result.clone();
        j.stage_base(&g, 4, 1, &[row], 4, false).unwrap();
        j.stage_delta(&g, 4, &[], 4, false).unwrap();
        j.install_checkpoint(&g).unwrap();
        let entity = j.entity("vault_record", "a").unwrap().unwrap();
        assert_eq!((entity.revision, entity.server_seq), (2, 4));
        assert_eq!(entity.body, expected_body);
        assert_eq!(j.connection().unwrap().query_row("SELECT receipt_body,receipt_status FROM v3_entities WHERE kind='vault_record' AND id='a'",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,u16>(1)?))).unwrap(),(expected_receipt,201));
        assert_eq!(stored_outbox(&j), before);
        assert_eq!(j.cursor().unwrap(), 4);
        assert_eq!(j.stats().unwrap().3, 0);
    }
}
#[test]
fn checkpoint_missing_v2_receipt_same_position_checks_identity_before_exact_hydration() {
    let (_owned, j, key) = owned_journal();
    let old = raw(&key, "old", "a", 1);
    j.ingest(&page(&old.body, applied("old", 1, 1), 1), &[0])
        .unwrap();
    j.connection()
        .unwrap()
        .execute(
            "UPDATE v3_entities SET receipt_body=NULL,receipt_status=NULL",
            [],
        )
        .unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 1, 1, 0).unwrap();
    j.stage_base(&g, 1, 1, &[raw(&key, "contradictory", "a", 1)], 1, false)
        .unwrap();
    j.stage_delta(&g, 1, &[], 1, false).unwrap();
    assert_eq!(j.install_checkpoint(&g).unwrap_err(), Error::Invalid);
    assert_eq!(
        j.entity("vault_record", "a").unwrap().unwrap().body,
        old.body
    );
    assert!(
        j.connection()
            .unwrap()
            .query_row("SELECT receipt_body FROM v3_entities", [], |r| r
                .get::<_, Option<Vec<u8>>>(0))
            .unwrap()
            .is_none()
    );
    j.reset_checkpoint(TAG, &key.id()).unwrap();
    let wire: wire::SyncOperation = serde_json::from_slice(&old.body).unwrap();
    let original = serde_json::to_vec_pretty(&wire).unwrap();
    assert_ne!(original, old.body);
    let g = j.begin_checkpoint(TAG, &key.id(), 1, 1, 0).unwrap();
    let expected = old.result.clone();
    j.stage_base(
        &g,
        1,
        1,
        &[RawRow {
            legacy_resolved: 0,
            body: original.clone(),
            ..old
        }],
        1,
        false,
    )
    .unwrap();
    j.stage_delta(&g, 1, &[], 1, false).unwrap();
    j.install_checkpoint(&g).unwrap();
    assert_eq!(
        j.connection()
            .unwrap()
            .query_row(
                "SELECT body,receipt_body,receipt_status FROM v3_entities",
                [],
                |r| Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u16>(2)?
                ))
            )
            .unwrap(),
        (original, expected, 201)
    );
}
#[test]
fn checkpoint_missing_receipt_unknown_seq_and_v3_head_remain_fail_closed() {
    for v3 in [false, true] {
        let (_owned, j, key) = owned_journal();
        let old = if v3 {
            v3_raw(&key, "old", 2, 0, 0, 1, 3)
        } else {
            raw(&key, "old", "a", 1)
        };
        let seq = old.sequence;
        let before = old.body.clone();
        let g = j.begin_checkpoint(TAG, &key.id(), seq, 1, 0).unwrap();
        j.stage_base(&g, seq, 1, &[old], seq, false).unwrap();
        j.stage_delta(&g, seq, &[], seq, false).unwrap();
        j.install_checkpoint(&g).unwrap();
        let c = j.connection().unwrap();
        c.execute(
            "UPDATE v3_entities SET receipt_body=NULL,receipt_status=NULL",
            [],
        )
        .unwrap();
        if !v3 {
            c.execute("UPDATE v3_entities SET server_seq=0", [])
                .unwrap();
        }
        let g = j.begin_checkpoint(TAG, &key.id(), 4, 1, 0).unwrap();
        j.stage_base(&g, 4, 1, &[v3_raw(&key, "new", 3, 1, 0, 2, 4)], 4, false)
            .unwrap();
        j.stage_delta(&g, 4, &[], 4, false).unwrap();
        assert_eq!(j.install_checkpoint(&g).unwrap_err(), Error::Invalid);
        let entity = j.entity("vault_record", "a").unwrap().unwrap();
        assert_eq!(entity.body, before);
        assert_eq!(entity.server_seq, if v3 { 3 } else { 0 });
        assert_eq!(j.cursor().unwrap(), seq);
    }
}

pub(super) fn v3_raw(
    key: &VaultKey,
    suffix: &str,
    basis: u64,
    base_revision: u64,
    resolved: u64,
    revision: u64,
    seq: u64,
) -> RawRow {
    use nddev_device_sync_domain::sync::history::{Lifecycle, VersionedOperation};
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let old = crate::codec::versioned(&encrypted_at(key, suffix, "a", base_revision))
        .unwrap()
        .operation;
    let mut o = VersionedOperation::qualify(
        old,
        basis,
        Lifecycle {
            resolved_through_seq: resolved,
        },
    )
    .unwrap();
    o.operation.payload = key
        .encrypt_versioned(
            &scope,
            &o,
            br#"{"version":3,"deleted":false,"title":"Record","username":"","secret":"fixture"}"#,
        )
        .unwrap();
    RawRow {
        legacy_resolved: 0,
        body: crate::codec::versioned_body(&o).unwrap(),
        result: serde_json::to_vec(&applied(&o.operation.id, revision as i64, seq as i64)).unwrap(),
        status: 201,
        sequence: seq,
    }
}
#[test]
fn checkpoint_canonical_projection_refuses_outer_watermark_rollback_without_partial_install() {
    let (_owned, j, key) = owned_journal();
    let head = v3_raw(&key, "head", 2, 0, 2, 1, 5);
    let before = head.body.clone();
    let g = j.begin_checkpoint(TAG, &key.id(), 5, 1, 0).unwrap();
    j.stage_base(&g, 5, 1, &[head], 5, false).unwrap();
    j.stage_delta(&g, 5, &[], 5, false).unwrap();
    j.install_checkpoint(&g).unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 6, 1, 0).unwrap();
    j.stage_base(
        &g,
        6,
        1,
        &[v3_raw(&key, "rollback", 5, 1, 0, 2, 6)],
        6,
        false,
    )
    .unwrap();
    j.stage_delta(&g, 6, &[], 6, false).unwrap();
    assert_eq!(j.install_checkpoint(&g).unwrap_err(), Error::Invalid);
    assert_eq!(j.entity("vault_record", "a").unwrap().unwrap().body, before);
    assert_eq!(j.cursor().unwrap(), 5);
}
#[test]
fn checkpoint_late_original_v2_ack_settles_family_and_preserves_newer_v3_head() {
    let (_owned, j, key) = owned_journal();
    let old = encrypted(&key, "old-local", "a");
    j.enqueue(old.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let head = v3_raw(&key, "newer", 2, 1, 0, 2, 3);
    let before = head.body.clone();
    let g = j.begin_checkpoint(TAG, &key.id(), 3, 1, 0).unwrap();
    j.stage_base(&g, 3, 1, &[head], 3, false).unwrap();
    j.stage_delta(&g, 3, &[], 3, false).unwrap();
    j.install_checkpoint(&g).unwrap();
    j.acknowledge(
        &old,
        &serde_json::to_vec(&applied("old-local", 1, 1)).unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(j.entity("vault_record", "a").unwrap().unwrap().body, before);
    assert!(stored_outbox(&j).is_empty());
    assert!(matches!(
        j.enqueue(encrypted_at(&key, "downgrade", "a", 2), None, 2, None),
        Err(Error::Invalid)
    ));
}

pub(super) fn valid_legacy_record_body(
    key: &VaultKey,
    id: &str,
    entity: &str,
    base: u64,
) -> Vec<u8> {
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let record = nddev_device_sync_domain::vault::Record {
        version: 1,
        deleted: false,
        title: "Owned migration fixture".into(),
        username: String::new(),
        secret: zeroize::Zeroizing::new("fixture".into()),
        resolved_through_seq: 0,
    };
    record.validate().unwrap();
    let plain = serde_json::to_vec(&record).unwrap();
    let mut o = crate::codec::versioned(&encrypted_at(key, id, entity, base))
        .unwrap()
        .operation;
    o.payload = key.encrypt(&scope, &o, &plain).unwrap();
    crate::codec::body(&o).unwrap()
}
fn supported_unknown_sequence_original_receipt_hydration(version: u32, normalized: bool) {
    let owned =
        Owned(std::env::temp_dir().join(format!("nds-legacy-receipt-{}", uuid::Uuid::new_v4())));
    std::fs::create_dir_all(&owned.0).unwrap();
    let path = owned.0.join("replica.db");
    let key = VaultKey::generate().unwrap();
    let original = valid_legacy_record_body(&key, "original", "a", 0);
    let stored = if normalized {
        let w: wire::SyncOperation = serde_json::from_slice(&original).unwrap();
        serde_json::to_vec_pretty(&w).unwrap()
    } else {
        original.clone()
    };
    let unknown = valid_legacy_record_body(&key, "unknown", "local", 0);
    {
        let c = Connection::open(&path).unwrap();
        c.execute_batch("CREATE TABLE meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,cursor INTEGER NOT NULL DEFAULT 0 CHECK(cursor BETWEEN 0 AND 9007199254740991));
        CREATE TABLE outbox(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),state TEXT NOT NULL CHECK(state IN ('pending','conflict')));
        CREATE TABLE entities(kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),PRIMARY KEY(kind,id));
        CREATE TABLE conflicts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),result BLOB NOT NULL);").unwrap();
        c.execute(
            "INSERT INTO meta(singleton,schema_version,cursor) VALUES(1,?1,0)",
            [version],
        )
        .unwrap();
        if version == 2 {
            c.execute_batch("ALTER TABLE entities ADD COLUMN server_seq INTEGER NOT NULL DEFAULT 0 CHECK(server_seq BETWEEN 0 AND 9007199254740991);").unwrap();
        }
        c.execute(
            "INSERT INTO entities(kind,id,revision,body) VALUES('vault_record','a',1,?1)",
            [&stored],
        )
        .unwrap();
        c.execute("INSERT INTO outbox(id,kind,entity_id,body,state) VALUES('unknown','vault_record','local',?1,'pending')",[&unknown]).unwrap();
    }
    // Exercise actual initialize/legacy migrations, not a schema7 field rewrite.
    let j = Journal::open(path).unwrap();
    let e = j.entity("vault_record", "a").unwrap().unwrap();
    assert_eq!((e.revision, e.server_seq), (1, 0));
    assert_eq!(e.body, stored);
    let c = j.connection().unwrap();
    assert_eq!(
        c.query_row("SELECT schema_version FROM v3_meta", [], |r| r
            .get::<_, u32>(0))
            .unwrap(),
        7
    );
    assert!(
        c.query_row(
            "SELECT receipt_body FROM v3_entities WHERE id='a'",
            [],
            |r| r.get::<_, Option<Vec<u8>>>(0)
        )
        .unwrap()
        .is_none()
    );
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let decoded = crate::codec::versioned(&e.body).unwrap();
    let plain = key.decrypt_versioned(&scope, &decoded).unwrap();
    serde_json::from_slice::<nddev_device_sync_domain::vault::Record>(&plain)
        .unwrap()
        .validate()
        .unwrap();
    assert_eq!(stored_outbox(&j)[0].3, 1);
    j.enqueue(
        valid_legacy_record_body(&key, "successor", "local", 1),
        None,
        0,
        Some("unknown".into()),
    )
    .unwrap();
    let before = stored_outbox(&j);
    let expected = serde_json::to_vec_pretty(&applied("original", 1, 5)).unwrap();
    let row = RawRow {
        legacy_resolved: 0,
        body: original.clone(),
        result: expected.clone(),
        status: 201,
        sequence: 5,
    };
    crate::codec::original_receipt(&row.body, &row.result, row.status).unwrap();
    let g = j.begin_checkpoint(TAG, &key.id(), 5, 1, 0).unwrap();
    j.stage_base(&g, 5, 1, &[row], 5, false).unwrap();
    j.stage_delta(&g, 5, &[], 5, false).unwrap();
    let installed = j.install_checkpoint(&g);
    if installed.is_err() {
        let e = j.entity("vault_record", "a").unwrap().unwrap();
        assert_eq!((e.revision, e.server_seq), (1, 0));
        assert_eq!(e.body, stored);
        assert_eq!(j.cursor().unwrap(), 0);
        assert_eq!(stored_outbox(&j), before);
    }
    assert!(
        installed.is_ok(),
        "supported schema{version} same original/full observed receipt failed: {installed:?}"
    );
    assert_eq!(c.query_row("SELECT body,revision,server_seq,receipt_body,receipt_status FROM v3_entities WHERE id='a'",[],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?,r.get::<_,Vec<u8>>(3)?,r.get::<_,u16>(4)?))).unwrap(),(original,1,5,expected,201));
    assert_eq!(stored_outbox(&j), before);
    assert_eq!(j.cursor().unwrap(), 5);
}
#[test]
fn unknown_sequence_original_receipt_schema_one_upgrade() {
    supported_unknown_sequence_original_receipt_hydration(1, false);
}
#[test]
fn unknown_sequence_original_receipt_schema_two_normalized_upgrade() {
    supported_unknown_sequence_original_receipt_hydration(2, true);
}
#[test]
fn unknown_sequence_different_v2_original_at_same_revision_is_not_hydrated() {
    let (_owned, j, key) = owned_journal();
    let old = valid_legacy_record_body(&key, "old", "a", 0);
    j.ingest(&page(&old, applied("old", 1, 1), 1), &[0])
        .unwrap();
    j.connection()
        .unwrap()
        .execute(
            "UPDATE v3_entities SET server_seq=0,receipt_body=NULL,receipt_status=NULL",
            [],
        )
        .unwrap();
    let other = valid_legacy_record_body(&key, "other", "a", 0);
    let row = RawRow {
        legacy_resolved: 0,
        body: other,
        result: serde_json::to_vec(&applied("other", 1, 5)).unwrap(),
        status: 201,
        sequence: 5,
    };
    let g = j.begin_checkpoint(TAG, &key.id(), 5, 1, 0).unwrap();
    j.stage_base(&g, 5, 1, &[row], 5, false).unwrap();
    j.stage_delta(&g, 5, &[], 5, false).unwrap();
    assert_eq!(j.install_checkpoint(&g).unwrap_err(), Error::Invalid);
    let c = j.connection().unwrap();
    assert_eq!(
        c.query_row(
            "SELECT body,revision,server_seq,receipt_body FROM v3_entities WHERE id='a'",
            [],
            |r| Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, Option<Vec<u8>>>(3)?
            ))
        )
        .unwrap(),
        (old, 1, 0, None)
    );
    assert_eq!(j.cursor().unwrap(), 1);
}

#[test]
fn checkpoint_preserves_legacy_resolution_after_reopen() {
    for resolver_in_base in [true, false] {
        let (owned, j, key) = owned_journal();
        let scope = Scope {
            origin: "https://instance.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: "device".into(),
        };
        let make = |id: &str, revision: u64, resolved: u64| {
            let mut operation =
                crate::codec::versioned(&encrypted_at(&key, id, "a", revision)).unwrap();
            let plain = serde_json::to_vec(&serde_json::json!({
                "version": 2, "deleted": false, "title": "Record", "username": "",
                "secret": "generated fixture", "resolved_through_seq": resolved
            }))
            .unwrap();
            operation.operation.payload =
                key.encrypt_versioned(&scope, &operation, &plain).unwrap();
            crate::codec::versioned_body(&operation).unwrap()
        };
        let first = make("head", 0, 0);
        let conflict_body = make("alternative", 0, 0);
        let resolved_body = make("resolve", 1, 2);
        let conflict_result = |id: &str, seq: i64, revision: i64| {
            wire::Sync::Conflict(wire::SyncConflict {
                operation_id: id.into(),
                outcome: wire::SyncConflictOutcome::Conflict,
                base_revision: 0,
                current_revision: revision,
                resolution_state: wire::ResolutionState::Unresolved,
                server_seq: seq,
            })
        };
        let conflict = conflict_result("alternative", 2, 1);
        let resolved_result = applied("resolve", 2, 3);
        let verify = |body: Vec<u8>, outcome: wire::Sync, status: i64, sequence: i64| {
            crate::VaultClient::verify_row(
                &scope,
                &key,
                crate::sync3_wire::SyncRow {
                    operation_body: String::from_utf8(body).unwrap(),
                    result_body: serde_json::to_string(&outcome).unwrap(),
                    result_status: status,
                    server_seq: sequence,
                },
            )
            .unwrap()
        };
        let page = wire::SyncPage {
            entries: vec![
                wire::SyncEntry {
                    operation: serde_json::from_slice(&first).unwrap(),
                    result: result("head", 1),
                },
                wire::SyncEntry {
                    operation: serde_json::from_slice(&conflict_body).unwrap(),
                    result: conflict.clone(),
                },
                wire::SyncEntry {
                    operation: serde_json::from_slice(&resolved_body).unwrap(),
                    result: resolved_result.clone(),
                },
            ],
            next_after_seq: 3,
            has_more: false,
        };
        j.ingest(&page, &[0, 0, 2]).unwrap();
        assert!(!j.entity("vault_record", "a").unwrap().unwrap().conflicted);
        j.enqueue(encrypted(&key, "pending", "local"), None, 0, None)
            .unwrap();
        j.pending().unwrap();
        let pending = stored_outbox(&j);
        let alternative = verify(conflict_body, conflict, 409, 2);
        let resolved = verify(resolved_body.clone(), resolved_result, 201, 3);
        assert_eq!(resolved.legacy_resolved, 2);
        // The same typed row crosses the native/browser storage command boundary.
        let resolved =
            serde_json::from_slice::<RawRow>(&serde_json::to_vec(&resolved).unwrap()).unwrap();
        let g = if resolver_in_base {
            let g = j.begin_checkpoint(TAG, &key.id(), 3, 2, 0).unwrap();
            j.stage_base(&g, 3, 2, &[alternative, resolved], 3, false)
                .unwrap();
            g
        } else {
            let g = j.begin_checkpoint(TAG, &key.id(), 1, 1, 0).unwrap();
            j.stage_base(
                &g,
                1,
                1,
                &[verify(first, result("head", 1), 201, 1)],
                1,
                false,
            )
            .unwrap();
            j.stage_delta(&g, 1, &[alternative, resolved], 3, true)
                .unwrap();
            g
        };
        // Newer failed decisions cannot acquire resolution authority from their payload.
        let later_body = make("later", 0, 3);
        let later = verify(later_body.clone(), conflict_result("later", 4, 2), 409, 4);
        j.stage_delta(&g, 3, &[later], 4, false).unwrap();
        drop(j);
        let j = Journal::open(owned.0.join("replica.db")).unwrap();
        j.install_checkpoint(&g).unwrap();
        let current = j.entity("vault_record", "a").unwrap().unwrap();
        assert!(
            current.conflicted,
            "newer unresolved alternative must remain"
        );
        assert_eq!(current.body, resolved_body);
        assert_eq!(j.cursor().unwrap(), 4);
        assert_eq!(stored_outbox(&j), pending);
        let c = j.connection().unwrap();
        let conflicts: Vec<Vec<u8>> = c
            .prepare("SELECT body FROM v3_conflicts ORDER BY rowid")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            conflicts,
            vec![later_body],
            "checkpoint resurrected a resolved legacy conflict"
        );
    }
}

#[test]
fn checkpoint_rejects_invalid_projection_metadata_without_partial_stage_write() {
    let (_owned, j, key) = owned_journal();
    let g = j.begin_checkpoint(TAG, &key.id(), 3, 2, 0).unwrap();
    for mut invalid in [
        raw(&key, "legacy", "b", 3),
        v3_raw(&key, "current", 2, 0, 0, 1, 3),
    ] {
        invalid.legacy_resolved = 3;
        assert_eq!(
            j.stage_base(&g, 3, 2, &[raw(&key, "first", "a", 1), invalid], 3, false)
                .unwrap_err(),
            Error::Invalid
        );
        assert_eq!(j.checkpoint_progress(&g).unwrap().received, 0);
        assert_eq!(j.cursor().unwrap(), 0);
        assert_eq!(
            j.connection()
                .unwrap()
                .query_row("SELECT count(*) FROM checkpoint_rows", [], |r| r
                    .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn ordinary_legacy_edit_preserves_a_committed_resolution_through_checkpoint() {
    resolution_survives_ordinary_edit(false);
}

#[test]
fn ordinary_format_transition_preserves_a_committed_resolution_through_checkpoint() {
    resolution_survives_ordinary_edit(true);
}

fn resolution_survives_ordinary_edit(current: bool) {
    let (_owned, j, key) = owned_journal();
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let mut committed = crate::codec::versioned(&encrypted_at(&key, "resolved", "a", 1)).unwrap();
    let prior=br#"{"version":2,"deleted":false,"title":"Chosen","username":"","secret":"generated old","resolved_through_seq":2}"#;
    committed.operation.payload = key.encrypt_versioned(&scope, &committed, prior).unwrap();
    let committed = crate::codec::versioned_body(&committed).unwrap();
    let seed = valid_legacy_record_body(&key, "seed", "a", 0);
    let conflict_body = valid_legacy_record_body(&key, "alternative", "a", 0);
    let conflict_result = wire::Sync::Conflict(wire::SyncConflict {
        operation_id: "alternative".into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    });
    j.ingest(
        &wire::SyncPage {
            entries: vec![
                wire::SyncEntry {
                    operation: serde_json::from_slice(&seed).unwrap(),
                    result: applied("seed", 1, 1),
                },
                wire::SyncEntry {
                    operation: serde_json::from_slice(&conflict_body).unwrap(),
                    result: conflict_result.clone(),
                },
                wire::SyncEntry {
                    operation: serde_json::from_slice(&committed).unwrap(),
                    result: applied("resolved", 2, 3),
                },
            ],
            next_after_seq: 3,
            has_more: false,
        },
        &[0, 0, 2],
    )
    .unwrap();
    assert!(!j.entity("vault_record", "a").unwrap().unwrap().conflicted);
    let captured = j.edit_target("vault_record", "a", 0).unwrap();
    assert_eq!(captured.committed.as_ref(), Some(&committed));
    let mut next = crate::codec::versioned(&encrypted_at(&key, "edit", "a", 2)).unwrap();
    if current {
        next = nddev_device_sync_domain::sync::history::VersionedOperation::qualify(
            next.operation,
            3,
            nddev_device_sync_domain::sync::history::Lifecycle {
                resolved_through_seq: 0,
            },
        )
        .unwrap();
    }
    next.operation.payload.ciphertext.clear();
    let committed_entity = captured.entity.as_ref().unwrap();
    next = crate::VaultClient::inherit_legacy_resolution(
        &scope,
        &key,
        next,
        captured.committed.as_deref(),
        committed_entity.revision,
        committed_entity.server_seq,
    )
    .unwrap();
    let draft =
        br#"{"version":1,"deleted":false,"title":"Edited","username":"","secret":"generated new"}"#;
    let plain = crate::VaultClient::record_plaintext(
        &scope,
        &key,
        &next,
        draft,
        captured.committed.as_deref(),
    )
    .unwrap();
    next.operation.payload = key.encrypt_versioned(&scope, &next, &plain).unwrap();
    let body = crate::codec::versioned_body(&next).unwrap();
    let verified = crate::VaultClient::verify_row(
        &scope,
        &key,
        crate::sync3_wire::SyncRow {
            operation_body: String::from_utf8(body.clone()).unwrap(),
            result_body: serde_json::to_string(&applied(&next.operation.id, 3, 4)).unwrap(),
            result_status: 201,
            server_seq: 4,
        },
    )
    .unwrap();
    j.ingest_original(
        nddev_device_sync_domain::sync::history::HistoryVersion {
            head: 4,
            floor: 0,
            base: 0,
        },
        3,
        &[verified],
        4,
        false,
    )
    .unwrap();
    assert!(!j.entity("vault_record", "a").unwrap().unwrap().conflicted);
    let verified = crate::VaultClient::verify_row(
        &scope,
        &key,
        crate::sync3_wire::SyncRow {
            operation_body: String::from_utf8(body.clone()).unwrap(),
            result_body: serde_json::to_string(&applied(&next.operation.id, 3, 4)).unwrap(),
            result_status: 201,
            server_seq: 4,
        },
    )
    .unwrap();
    let conflict = conflict_result;
    let conflict = crate::VaultClient::verify_row(
        &scope,
        &key,
        crate::sync3_wire::SyncRow {
            operation_body: String::from_utf8(conflict_body).unwrap(),
            result_body: serde_json::to_string(&conflict).unwrap(),
            result_status: 409,
            server_seq: 2,
        },
    )
    .unwrap();
    let guard = j.begin_checkpoint(TAG, &key.id(), 4, 2, 0).unwrap();
    j.stage_base(&guard, 4, 2, &[conflict, verified], 4, false)
        .unwrap();
    j.install_checkpoint(&guard).unwrap();
    let entity = j.entity("vault_record", "a").unwrap().unwrap();
    assert_eq!(entity.body, body);
    assert!(
        !entity.conflicted,
        "ordinary edit lost an already committed resolution"
    );
}
