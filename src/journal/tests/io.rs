use super::checkpoint::{v3_raw, valid_legacy_record_body};
use super::*;
fn original_result(id: &str, revision: i64, seq: i64) -> Vec<u8> {
    serde_json::to_vec_pretty(&applied(id, revision, seq)).unwrap()
}
#[test]
fn capacity_claim_dispatches_one_exact_root_and_preserves_unknown_and_other_work() {
    let (owned, journal, key) = owned_journal();
    let bodies = (0..16)
        .map(|i| encrypted(&key, &format!("pending-{i}"), &format!("record-{i}")))
        .collect::<Vec<_>>();
    for body in &bodies {
        journal.enqueue(body.clone(), None, 0, None).unwrap();
    }
    let command = crate::storage::Command::ClaimOne;
    assert_eq!(
        serde_json::to_value(&command).unwrap(),
        serde_json::json!("ClaimOne")
    );
    let crate::storage::Reply::Pending(first) = crate::storage::execute(&journal, command).unwrap()
    else {
        panic!("pending reply")
    };
    assert_eq!(first.len(), 1);
    assert_eq!(first[0].body, bodies[0]);
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    let dispatched = || {
        connection
            .query_row(
                "SELECT count(*) FROM v3_outbox WHERE dispatched=1",
                [],
                |r| r.get::<_, u32>(0),
            )
            .unwrap()
    };
    assert_eq!(dispatched(), 1);
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(reopened.claim_one().unwrap()[0].body, bodies[0]);
    assert_eq!(dispatched(), 1);
    reopened
        .mark_unknown(&first[0].id, &first[0].body, "legacy_missing")
        .unwrap();
    let second = reopened.claim_one().unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].body, bodies[1]);
    assert_eq!(dispatched(), 2);
    let original: Vec<u8> = connection
        .query_row(
            "SELECT body FROM v3_outbox WHERE id=?1 AND terminal_unknown_reason='legacy_missing'",
            [&first[0].id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(original, bodies[0]);
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM v3_outbox WHERE dispatched=0",
                [],
                |r| r.get::<_, u32>(0)
            )
            .unwrap(),
        14
    );
}
#[test]
fn writer_provenance_distinguishes_preexisting_legacy_from_fresh_bootstrap_and_reopen() {
    let (owned, j, key) = owned_journal();
    let initial = j.writer_snapshot().unwrap();
    assert!(!initial.facts.legacy_v2_context);
    assert!(initial.facts.mode.is_none());
    assert!(initial.facts.confirmed_basis_seq.is_none());
    assert!(
        !Journal::open(owned.0.join("replica.db"))
            .unwrap()
            .writer_snapshot()
            .unwrap()
            .facts
            .legacy_v2_context
    );
    let c = Connection::open(owned.0.join("replica.db")).unwrap();
    legacy_layout(&c);
    c.execute("UPDATE meta SET schema_version=5", []).unwrap();
    let legacy = Journal::open(owned.0.join("replica.db")).unwrap();
    let facts = legacy.writer_snapshot().unwrap();
    assert!(facts.facts.legacy_v2_context);
    assert!(facts.facts.mode.is_none());
    assert!(facts.facts.confirmed_basis_seq.is_none());
    let body = valid_legacy_record_body(&key, "offline-v2", "record", 0);
    legacy.enqueue(body.clone(), None, 0, None).unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(reopened.pending().unwrap()[0].body, body);
    assert!(reopened.writer_snapshot().unwrap().facts.legacy_v2_context);
}
#[test]
fn writer_exact_cas_preserves_real_confirmed_facts_and_basis_only_update_preserves_stage_guard() {
    let (owned, j, key) = owned_journal();
    let old = j.writer_snapshot().unwrap();
    let first = j.confirm_writer(&old, 3, &key.id(), Some(42)).unwrap();
    assert_eq!(first.facts.mode, Some(3));
    assert_eq!(first.facts.confirmed_basis_seq, Some(42));
    assert!(first.local_revision > old.local_revision);
    assert!(matches!(
        j.confirm_writer(&old, 2, &key.id(), None),
        Err(Error::Busy)
    ));
    let g = j
        .begin_checkpoint(&"a".repeat(64), &key.id(), 42, 0, 0)
        .unwrap();
    let before = j.writer_snapshot().unwrap();
    let new = j.confirm_writer(&before, 3, &key.id(), Some(48)).unwrap();
    assert_eq!(new.local_revision, before.local_revision);
    assert_eq!(j.checkpoint_progress(&g).unwrap().through, 42);
    assert_eq!(
        Journal::open(owned.0.join("replica.db"))
            .unwrap()
            .writer_snapshot()
            .unwrap(),
        new
    );
}
#[test]
fn unknown_exact_body_guard_skips_family_but_true_late_applied_receipt_settles() {
    let (_owned, j, key) = owned_journal();
    let first = valid_legacy_record_body(&key, "unknown", "record", 0);
    j.enqueue(first.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let successor = valid_legacy_record_body(&key, "successor", "record", 1);
    j.enqueue(successor.clone(), None, 0, Some("unknown".into()))
        .unwrap();
    let wire: wire::SyncOperation = serde_json::from_slice(&first).unwrap();
    let altered = serde_json::to_vec_pretty(&wire).unwrap();
    assert_eq!(
        j.mark_unknown("unknown", &altered, "legacy_missing")
            .unwrap_err(),
        Error::Invalid
    );
    j.mark_unknown("unknown", &first, "legacy_missing").unwrap();
    assert_eq!(
        j.unknown_reason().unwrap().as_deref(),
        Some("legacy_missing")
    );
    assert!(j.pending().unwrap().is_empty());
    let c = j.connection().unwrap();
    assert_eq!(
        c.query_row(
            "SELECT body,state,dispatched FROM v3_outbox WHERE id='unknown'",
            [],
            |r| Ok((
                r.get::<_, Vec<u8>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, u32>(2)?
            ))
        )
        .unwrap(),
        (first.clone(), "pending".into(), 1)
    );
    assert_eq!(
        j.acknowledge_original(&first, &original_result("unknown", 1, 5), 409, 0)
            .unwrap_err(),
        Error::Invalid
    );
    assert!(j.unknown_reason().unwrap().is_some());
    j.acknowledge_original(&first, &original_result("unknown", 1, 5), 201, 0)
        .unwrap();
    assert!(j.unknown_reason().unwrap().is_none());
    assert_eq!(j.pending().unwrap()[0].body, successor);
}
#[test]
fn unknown_late_conflict_receipt_preserves_blocked_successor_as_conflict() {
    let (_owned, j, key) = owned_journal();
    let first = valid_legacy_record_body(&key, "unknown", "record", 0);
    j.enqueue(first.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    j.enqueue(
        valid_legacy_record_body(&key, "successor", "record", 1),
        None,
        0,
        Some("unknown".into()),
    )
    .unwrap();
    j.mark_unknown("unknown", &first, "legacy_missing").unwrap();
    let receipt = wire::Sync::Conflict(wire::SyncConflict {
        operation_id: "unknown".into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 5,
    });
    j.acknowledge_original(&first, &serde_json::to_vec(&receipt).unwrap(), 409, 0)
        .unwrap();
    assert!(j.unknown_reason().unwrap().is_none());
    assert!(j.pending().unwrap().is_empty());
    assert_eq!(
        j.connection()
            .unwrap()
            .query_row(
                "SELECT state,predecessor FROM v3_outbox WHERE id='successor'",
                [],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            )
            .unwrap(),
        ("conflict".into(), None)
    );
}
#[test]
fn original_v3_normal_ingest_is_atomic_preserves_full_bytes_and_settles_claimed_request() {
    let (_owned, j, key) = owned_journal();
    let mut first = v3_raw(&key, "first", 0, 0, 0, 1, 1);
    let o = crate::codec::versioned(&first.body).unwrap();
    first.result = original_result(&o.operation.id, 1, 1);
    let first_body = first.body.clone();
    let first_result = first.result.clone();
    j.enqueue(first_body.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    let second_body = valid_legacy_record_body(&key, "second", "b", 0);
    let mut second = RawRow {
        legacy_resolved: 0,
        body: second_body,
        result: original_result("second", 1, 2),
        status: 409,
        sequence: 2,
    };
    assert_eq!(
        j.ingest_original(
            nddev_device_sync_domain::sync::history::HistoryVersion {
                head: 2,
                floor: 0,
                base: 0
            },
            0,
            &[
                RawRow {
                    legacy_resolved: 0,
                    body: first.body.clone(),
                    result: first.result.clone(),
                    status: 201,
                    sequence: 1
                },
                second
            ],
            2,
            false
        )
        .unwrap_err(),
        Error::Invalid
    );
    assert_eq!(j.cursor().unwrap(), 0);
    assert!(
        j.entity("vault_record", "a")
            .unwrap()
            .unwrap()
            .pending_id
            .is_some()
    );
    second = RawRow {
        legacy_resolved: 0,
        body: valid_legacy_record_body(&key, "second", "b", 0),
        result: original_result("second", 1, 2),
        status: 201,
        sequence: 2,
    };
    j.ingest_original(
        nddev_device_sync_domain::sync::history::HistoryVersion {
            head: 2,
            floor: 0,
            base: 0,
        },
        0,
        &[first, second],
        2,
        false,
    )
    .unwrap();
    assert_eq!(j.cursor().unwrap(), 2);
    assert!(j.pending().unwrap().is_empty());
    assert_eq!(
        j.connection()
            .unwrap()
            .query_row(
                "SELECT body,receipt_body,receipt_status FROM v3_entities WHERE id='a'",
                [],
                |r| Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Vec<u8>>(1)?,
                    r.get::<_, u16>(2)?
                ))
            )
            .unwrap(),
        (first_body, first_result, 201)
    );
}
#[test]
fn freshness_cannot_pass_an_already_known_direct_ack_horizon() {
    let (_owned, j, key) = owned_journal();
    let body = valid_legacy_record_body(&key, "direct", "record", 0);
    j.enqueue(body.clone(), None, 0, None).unwrap();
    j.pending().unwrap();
    j.acknowledge_original(&body, &original_result("direct", 1, 5), 201, 0)
        .unwrap();
    j.ingest_original(
        nddev_device_sync_domain::sync::history::HistoryVersion {
            head: 0,
            floor: 0,
            base: 0,
        },
        0,
        &[],
        0,
        false,
    )
    .unwrap();
    assert!(!j.caught_up(0, 100).unwrap());
    assert_eq!(j.stats().unwrap().3, 0);
}
#[test]
fn guarded_offline_original_v3_survives_reopen_and_refuses_stale_writer_context() {
    let (owned, j, key) = owned_journal();
    let snapshot = j.writer_snapshot().unwrap();
    j.confirm_writer(&snapshot, 3, &key.id(), Some(42)).unwrap();
    let facts = j.writer_snapshot().unwrap().facts;
    let guard = WriterEnqueueGuard {
        expected_local_revision: None,
        facts,
        actual_key_id: key.id(),
        basis_seq: Some(42),
    };
    let row = v3_raw(&key, "offline", 42, 0, 0, 1, 43);
    let body = row.body.clone();
    j.enqueue_writer(body.clone(), None, 0, None, &guard)
        .unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(reopened.pending().unwrap()[0].body, body);
    let current = reopened.writer_snapshot().unwrap();
    let foreign = VaultKey::generate().unwrap();
    reopened
        .confirm_writer(&current, 3, &foreign.id(), Some(44))
        .unwrap();
    let other = v3_raw(&key, "stale", 42, 0, 0, 1, 43);
    assert!(matches!(
        reopened.enqueue_writer(
            other.body,
            None,
            0,
            Some(crate::codec::versioned(&body).unwrap().operation.id),
            &guard
        ),
        Err(Error::Busy)
    ));
}
#[test]
fn operational_stage_progress_survives_reopen_without_advancing_active_cursor() {
    let (owned, j, key) = owned_journal();
    let g = j
        .begin_checkpoint(&"a".repeat(64), &key.id(), 9, 2, 0)
        .unwrap();
    let one = RawRow {
        legacy_resolved: 0,
        body: valid_legacy_record_body(&key, "one", "a", 0),
        result: original_result("one", 1, 2),
        status: 201,
        sequence: 2,
    };
    j.stage_base(&g, 9, 2, &[one], 2, true).unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let g = reopened
        .resume_checkpoint(&"a".repeat(64), &key.id(), 0)
        .unwrap()
        .unwrap();
    let p = reopened.checkpoint_progress(&g).unwrap();
    assert_eq!(
        (
            p.base,
            p.total,
            p.received,
            p.after_member,
            p.through,
            p.tail_complete
        ),
        (9, 2, 1, 2, 9, false)
    );
    assert_eq!(reopened.cursor().unwrap(), 0);
}
#[test]
fn complete_old_base_and_contiguous_tail_cover_known_ack_with_new_floor_partial_install() {
    let (_owned, j, key) = owned_journal();
    let g = j
        .begin_checkpoint(&"a".repeat(64), &key.id(), 10, 1, 40)
        .unwrap();
    let row = |seq: u64| RawRow {
        legacy_resolved: 0,
        body: valid_legacy_record_body(&key, &format!("op{seq}"), &format!("record{seq}"), 0),
        result: original_result(&format!("op{seq}"), 1, seq as i64),
        status: 201,
        sequence: seq,
    };
    j.stage_base(&g, 10, 1, &[row(10)], 10, false).unwrap();
    j.stage_delta(&g, 10, &(11..=30).map(row).collect::<Vec<_>>(), 30, true)
        .unwrap();
    j.stage_delta(&g, 20, &(31..=40).map(row).collect::<Vec<_>>(), 40, true)
        .unwrap();
    assert!(!j.checkpoint_progress(&g).unwrap().tail_complete);
    j.install_checkpoint(&g).unwrap();
    assert_eq!(j.cursor().unwrap(), 40);
    assert_eq!(j.stats().unwrap().3, 0);
}
#[test]
fn actual_core_offline_preparation_reuses_confirmed_mode_on_reopen_without_http() {
    use nddev_device_sync_application::replica::{LocalWriterContext, prepare_offline_operation};
    use nddev_device_sync_domain::sync::history::Lifecycle;
    let (owned, j, key) = owned_journal();
    j.confirm_writer(&j.writer_snapshot().unwrap(), 3, &key.id(), Some(42))
        .unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let snapshot = reopened.writer_snapshot().unwrap();
    let facts = crate::client::history_replica::facts(&snapshot).unwrap();
    let old = crate::codec::versioned(&valid_legacy_record_body(&key, "core-offline", "a", 0))
        .unwrap()
        .operation;
    let mut op = prepare_offline_operation(
        old,
        Lifecycle {
            resolved_through_seq: 0,
        },
        &facts,
        LocalWriterContext {
            authorized: true,
            actual_key: &key.id(),
            cursor: snapshot.cursor,
            known_committed: snapshot.known_committed_seq,
        },
    )
    .unwrap();
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    op.operation.payload = key
        .encrypt_versioned(
            &scope,
            &op,
            br#"{"version":3,"deleted":false,"title":"Record","username":"","secret":"fixture"}"#,
        )
        .unwrap();
    let body = crate::codec::versioned_body(&op).unwrap();
    let guard = WriterEnqueueGuard {
        expected_local_revision: None,
        facts: snapshot.facts,
        actual_key_id: key.id(),
        basis_seq: Some(42),
    };
    reopened
        .enqueue_writer(body.clone(), None, 0, None, &guard)
        .unwrap();
    assert_eq!(
        Journal::open(owned.0.join("replica.db"))
            .unwrap()
            .pending()
            .unwrap()[0]
            .body,
        body
    );
}
#[test]
fn inherited_legacy_offline_core_preparation_has_no_guessed_basis_and_reopens_exact_v2() {
    use nddev_device_sync_application::replica::{LocalWriterContext, prepare_offline_operation};
    use nddev_device_sync_domain::sync::history::{Lifecycle, OperationVersion};
    let (owned, _j, key) = owned_journal();
    let c = Connection::open(owned.0.join("replica.db")).unwrap();
    legacy_layout(&c);
    c.execute("UPDATE meta SET schema_version=5", []).unwrap();
    let j = Journal::open(owned.0.join("replica.db")).unwrap();
    let snapshot = j.writer_snapshot().unwrap();
    let facts = crate::client::history_replica::facts(&snapshot).unwrap();
    assert!(facts.legacy_v2_initialized);
    assert!(facts.confirmed.is_none());
    let body = valid_legacy_record_body(&key, "legacy-core-offline", "a", 0);
    let o = crate::codec::versioned(&body).unwrap().operation;
    let prepared = prepare_offline_operation(
        o,
        Lifecycle {
            resolved_through_seq: 0,
        },
        &facts,
        LocalWriterContext {
            authorized: true,
            actual_key: &key.id(),
            cursor: 0,
            known_committed: 0,
        },
    )
    .unwrap();
    assert_eq!(prepared.version, OperationVersion::V2);
    let bytes = crate::codec::versioned_body(&prepared).unwrap();
    assert_eq!(bytes, body);
    j.enqueue_writer(
        bytes.clone(),
        None,
        0,
        None,
        &WriterEnqueueGuard {
            expected_local_revision: None,
            facts: snapshot.facts,
            actual_key_id: key.id(),
            basis_seq: None,
        },
    )
    .unwrap();
    assert_eq!(
        Journal::open(owned.0.join("replica.db"))
            .unwrap()
            .pending()
            .unwrap()[0]
            .body,
        bytes
    );
}

#[test]
fn explicit_resolution_uses_entity_receipts_and_preserves_unknown_until_actual_ack() {
    use nddev_device_sync_application::replica::{
        ConfirmedWriter, LocalWriterContext, WriterFacts, WriterMode, prepare_offline_operation,
    };
    use nddev_device_sync_domain::sync::history::HistoryVersion;
    let (owned, j, key) = owned_journal();
    let head = v3_raw(&key, "head", 0, 0, 0, 1, 1);
    let mut alternative = v3_raw(&key, "alternative", 1, 0, 0, 1, 2);
    let id = crate::codec::versioned(&alternative.body)
        .unwrap()
        .operation
        .id;
    alternative.result = serde_json::to_vec(&wire::Sync::Conflict(wire::SyncConflict {
        operation_id: id,
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    }))
    .unwrap();
    alternative.status = 409;
    let other = RawRow {
        legacy_resolved: 0,
        body: valid_legacy_record_body(&key, "other", "b", 0),
        result: original_result("other", 1, 3),
        status: 201,
        sequence: 3,
    };
    j.ingest_original(
        HistoryVersion {
            head: 3,
            floor: 0,
            base: 0,
        },
        0,
        &[head, alternative, other],
        3,
        false,
    )
    .unwrap();
    let state = j.writer_snapshot().unwrap();
    j.confirm_writer(&state, 3, &key.id(), Some(3)).unwrap();
    let (entity, alternative, resolution) = j.resolution("a").unwrap();
    assert!(alternative.is_some());
    assert_eq!(resolution.cursor, 3);
    assert_eq!(resolution.lifecycle.resolved_through_seq, 2);
    let state = j.writer_snapshot().unwrap();
    let scope = Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    };
    let new = crate::codec::versioned(&encrypted_at(&key, "decision", "a", entity.next_base))
        .unwrap()
        .operation;
    let mut operation = prepare_offline_operation(
        new,
        resolution.lifecycle,
        &WriterFacts {
            confirmed: Some(ConfirmedWriter {
                mode: WriterMode::V3,
                key_id: key.id(),
                basis: state.facts.confirmed_basis_seq.unwrap(),
            }),
            legacy_v2_initialized: false,
        },
        LocalWriterContext {
            authorized: true,
            actual_key: &key.id(),
            cursor: state.cursor,
            known_committed: state.known_committed_seq,
        },
    )
    .unwrap();
    operation.operation.payload=key.encrypt_versioned(&scope,&operation,br#"{"version":3,"deleted":false,"title":"Chosen","username":"","secret":"generated choice"}"#).unwrap();
    let body = crate::codec::versioned_body(&operation).unwrap();
    let guard = WriterEnqueueGuard {
        facts: state.facts,
        actual_key_id: key.id(),
        basis_seq: Some(3),
        expected_local_revision: Some(resolution.local_revision),
    };
    // A concurrent local edit changes no server cursor or target revision.
    j.enqueue(
        valid_legacy_record_body(&key, "concurrent", "other", 0),
        None,
        0,
        None,
    )
    .unwrap();
    let before = j.stats().unwrap();
    assert!(matches!(
        j.enqueue_writer(body.clone(), Some(3), entity.revision, None, &guard),
        Err(Error::Busy)
    ));
    assert_eq!(j.stats().unwrap(), before);
    let (_, _, current) = j.resolution("a").unwrap();
    let guard = WriterEnqueueGuard {
        expected_local_revision: Some(current.local_revision),
        ..guard
    };
    j.enqueue_writer(body.clone(), Some(3), entity.revision, None, &guard)
        .unwrap();
    assert!(j.entity("vault_record", "a").unwrap().unwrap().conflicted);
    j.pending().unwrap();
    j.mark_unknown(&operation.operation.id, &body, "basis_expired")
        .unwrap();
    drop(j);
    let j = Journal::open(owned.0.join("replica.db")).unwrap();
    let (entity, _, current) = j.resolution("a").unwrap();
    let second = v3_raw(
        &key,
        "replacement",
        3,
        entity.next_base,
        2,
        entity.next_base + 1,
        4,
    );
    let guard = WriterEnqueueGuard {
        expected_local_revision: Some(current.local_revision),
        ..guard
    };
    let before = j.stats().unwrap();
    assert!(matches!(
        j.enqueue_writer(
            second.body,
            Some(3),
            entity.revision,
            entity.pending_id,
            &guard
        ),
        Err(Error::Busy)
    ));
    assert_eq!(j.stats().unwrap(), before);
    assert_eq!(
        j.unknown_reason().unwrap().as_deref(),
        Some("basis_expired")
    );
    let stored: Vec<u8> = j
        .connection()
        .unwrap()
        .query_row(
            "SELECT body FROM v3_outbox WHERE id=?1",
            [&operation.operation.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(stored, body);
    j.acknowledge_original(
        &body,
        &original_result(&operation.operation.id, 2, 4),
        201,
        0,
    )
    .unwrap();
    assert!(j.unknown_reason().unwrap().is_none());
    assert!(!j.entity("vault_record", "a").unwrap().unwrap().conflicted);
    assert_eq!(j.entity("vault_record", "a").unwrap().unwrap().body, body);
    assert_eq!(j.cursor().unwrap(), 3);
}

#[test]
fn resolution_refuses_a_stored_receipt_for_another_entity_without_mutation() {
    use nddev_device_sync_domain::sync::history::HistoryVersion;
    let (_owned, j, key) = owned_journal();
    j.ingest_original(
        HistoryVersion {
            head: 1,
            floor: 0,
            base: 0,
        },
        0,
        &[v3_raw(&key, "head", 0, 0, 0, 1, 1)],
        1,
        false,
    )
    .unwrap();
    let body = valid_legacy_record_body(&key, "foreign", "b", 0);
    let receipt = serde_json::to_vec(&wire::Sync::Conflict(wire::SyncConflict {
        operation_id: "foreign".into(),
        outcome: wire::SyncConflictOutcome::Conflict,
        base_revision: 0,
        current_revision: 1,
        resolution_state: wire::ResolutionState::Unresolved,
        server_seq: 2,
    }))
    .unwrap();
    j.connection().unwrap().execute("INSERT INTO v3_conflicts(id,kind,entity_id,body,result) VALUES('corrupt','vault_record','a',?1,?2)",params![body,receipt]).unwrap();
    let before = j.stats().unwrap();
    assert!(matches!(j.resolution("a"), Err(Error::Invalid)));
    assert_eq!(j.stats().unwrap(), before);
}
