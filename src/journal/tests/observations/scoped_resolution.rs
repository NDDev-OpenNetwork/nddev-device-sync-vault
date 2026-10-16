use super::*;

#[test]
fn unrelated_local_or_inbox_progress_does_not_invalidate_a_repository_resolution() {
    for inbox in [false, true] {
        let (owned, journal, key, selected, before) = resolution_fixture();
        let capture = journal
            .observation_resolution("github:repo:9", &selected, &before.selected_operation)
            .unwrap();
        let writer = resolution_writer(&journal, &key, &capture);
        let other = Journal::open(owned.0.join("replica.db")).unwrap();
        let body = if inbox {
            let old =
                crate::codec::versioned(&observed_repository(&key, &selected, "unrelated", 10))
                    .unwrap();
            let plain = key.decrypt_versioned(&scope(), &old).unwrap();
            let mut op = old.operation;
            op.id = "unrelated".into();
            op.idempotency_key = op.id.clone();
            let mut fresh = VersionedOperation::qualify(
                op,
                44,
                Lifecycle {
                    resolved_through_seq: 0,
                },
            )
            .unwrap();
            fresh.operation.payload = key.encrypt_versioned(&scope(), &fresh, &plain).unwrap();
            let body = crate::codec::versioned_body(&fresh).unwrap();
            let result = serde_json::to_vec(&wire::Sync::Applied(wire::SyncApplied {
                operation_id: fresh.operation.id,
                outcome: wire::SyncAppliedOutcome::Applied,
                revision: 1,
                server_seq: 45,
            }))
            .unwrap();
            other
                .ingest_original(
                    nddev_device_sync_domain::sync::history::HistoryVersion {
                        head: 45,
                        floor: 44,
                        base: 44,
                    },
                    44,
                    &[RawRow {
                        body: body.clone(),
                        result,
                        status: 201,
                        sequence: 45,
                        legacy_resolved: 0,
                    }],
                    45,
                    false,
                )
                .unwrap();
            body
        } else {
            let body = observed_repository(&key, &selected, "unrelated", 10);
            other
                .enqueue_observation(
                    body.clone(),
                    0,
                    None,
                    &selected,
                    &before.selected_operation,
                    &guard(&key, &before),
                )
                .unwrap();
            body
        };
        assert_ne!(other.stats().unwrap().4, capture.guard.local_revision);
        journal
            .enqueue_observation_resolution(
                new_resolution_body(&key, &selected, 1, 44, 44),
                1,
                capture.target.pending_id,
                (&selected, &before.selected_operation),
                &writer,
                &capture.guard,
            )
            .unwrap();
        assert_eq!(
            other
                .entity("repository_state", "github:repo:10")
                .unwrap()
                .unwrap()
                .body,
            body
        );
        assert_eq!(other.stats().unwrap().1, 1); // Resolution is not an Applied receipt.
    }
}

#[test]
fn complete_witness_changes_are_rejected_even_when_cursor_revision_and_maximum_stay_equal() {
    for add_older in [false, true] {
        let (owned, journal, key, selected, before) = setup();
        let stage = journal
            .begin_checkpoint(&"d".repeat(64), &key.id(), 46, 2, 0)
            .unwrap();
        journal
            .stage_base(
                &stage,
                46,
                2,
                &[
                    retained_row(&key, &selected, "head", 43, false),
                    retained_row(&key, &selected, "latest", 46, true),
                ],
                46,
                false,
            )
            .unwrap();
        journal.stage_delta(&stage, 46, &[], 46, false).unwrap();
        journal.install_checkpoint(&stage).unwrap();
        let capture = journal
            .observation_resolution("github:repo:9", &selected, &before.selected_operation)
            .unwrap();
        let writer = resolution_writer(&journal, &key, &capture);
        let connection = Connection::open(owned.0.join("replica.db")).unwrap();
        // Deliberate SQLite witness mutation isolates the full-snapshot guard
        // from global counters. This is not a fabricated server acceptance run.
        if add_older {
            let older = retained_row(&key, &selected, "older", 44, true);
            let op = crate::codec::versioned(&older.body).unwrap().operation;
            let id = serde_json::to_string(&(op.device.as_str(), op.id)).unwrap();
            connection.execute("INSERT INTO v3_conflicts(id,kind,entity_id,body,result) VALUES(?1,'repository_state','github:repo:9',?2,?3)", params![id, older.body, older.result]).unwrap();
        } else {
            let original: Vec<u8> = connection
                .query_row(
                    "SELECT result FROM v3_conflicts WHERE entity_id='github:repo:9'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
            let changed = serde_json::to_vec_pretty(&value).unwrap();
            assert_ne!(original, changed);
            connection
                .execute(
                    "UPDATE v3_conflicts SET result=?1 WHERE entity_id='github:repo:9'",
                    [changed],
                )
                .unwrap();
        }
        let current = journal
            .observation_resolution("github:repo:9", &selected, &before.selected_operation)
            .unwrap();
        assert_eq!(current.guard.cursor, capture.guard.cursor);
        assert_eq!(current.guard.local_revision, capture.guard.local_revision);
        assert_eq!(current.guard.lifecycle, capture.guard.lifecycle);
        assert_ne!(
            current.guard.repository_fingerprint,
            capture.guard.repository_fingerprint
        );
        let stats = journal.stats().unwrap();
        assert!(matches!(
            journal.enqueue_observation_resolution(
                new_resolution_body(&key, &selected, 1, 46, 46),
                1,
                None,
                (&selected, &before.selected_operation),
                &writer,
                &capture.guard,
            ),
            Err(Error::Busy)
        ));
        assert_eq!(journal.stats().unwrap(), stats);
    }
}

#[test]
fn same_pending_identity_cannot_hide_changed_encrypted_bytes_or_lineage() {
    for lineage in [false, true] {
        let (owned, journal, key, selected, before) = resolution_fixture();
        let capture = journal
            .observation_resolution("github:repo:9", &selected, &before.selected_operation)
            .unwrap();
        let writer = resolution_writer(&journal, &key, &capture);
        let connection = Connection::open(owned.0.join("replica.db")).unwrap();
        if lineage {
            connection
                .execute(
                    "UPDATE v3_outbox SET predecessor='changed-root' WHERE kind='repository_state'",
                    [],
                )
                .unwrap();
        } else {
            let body = observed(&key, &selected, "local-intent");
            assert_ne!(capture.pending.as_ref().unwrap(), &body);
            connection
                .execute(
                    "UPDATE v3_outbox SET body=?1 WHERE kind='repository_state'",
                    [body],
                )
                .unwrap();
        }
        let stats = journal.stats().unwrap();
        assert!(matches!(
            journal.enqueue_observation_resolution(
                new_resolution_body(&key, &selected, 1, 44, 44),
                1,
                capture.target.pending_id,
                (&selected, &before.selected_operation),
                &writer,
                &capture.guard,
            ),
            Err(Error::Busy)
        ));
        assert_eq!(journal.stats().unwrap(), stats);
    }
}
