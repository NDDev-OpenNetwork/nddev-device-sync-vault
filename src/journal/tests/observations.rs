use super::*;
mod capacity;
mod scoped_resolution;
use nddev_device_sync_domain::{
    repositories::catalog::{observations::*, *},
    state::{Snapshot, State},
    sync::history::{Lifecycle, VersionedOperation},
};

fn setup() -> (
    Owned,
    Journal,
    VaultKey,
    CredentialSelection,
    ObservationBaselines,
) {
    let (owned, journal, key) = owned_journal();
    let source =
        super::checkpoint::valid_legacy_record_body(&key, "credential-op", "credential", 0);
    journal.enqueue(source, None, 0, None).unwrap();
    journal
        .confirm_writer(&journal.writer_snapshot().unwrap(), 3, &key.id(), Some(42))
        .unwrap();
    let selected =
        CredentialSelection::new("credential".into(), 0, Some("credential-op".into())).unwrap();
    let before = journal.observation_baselines(&selected).unwrap();
    (owned, journal, key, selected, before)
}

fn scope() -> Scope {
    Scope {
        origin: "https://instance.example/".into(),
        tenant: "tenant".into(),
        user: "owner".into(),
        device: "device".into(),
    }
}

fn guard(key: &VaultKey, baseline: &ObservationBaselines) -> WriterEnqueueGuard {
    WriterEnqueueGuard {
        facts: baseline.writer.facts.clone(),
        actual_key_id: key.id(),
        basis_seq: Some(42),
        expected_local_revision: None,
    }
}

fn observed(key: &VaultKey, selected: &CredentialSelection, operation_id: &str) -> Vec<u8> {
    observed_repository(key, selected, operation_id, 9)
}

fn observed_repository(
    key: &VaultKey,
    selected: &CredentialSelection,
    operation_id: &str,
    repository_id: u64,
) -> Vec<u8> {
    observed_data(
        key,
        selected,
        operation_id,
        ObservationData::Repository {
            repository: RepositoryFact {
                id: RepositoryId::new(repository_id).unwrap(),
                owner_id: GithubAccountId::new(1).unwrap(),
                name: "private-repository-observation".into(),
                visibility: RepositoryVisibility::Private,
                archived: false,
                default_branch: Some("main".into()),
            },
        },
    )
}
fn observed_data(
    key: &VaultKey,
    selected: &CredentialSelection,
    operation_id: &str,
    data: ObservationData,
) -> Vec<u8> {
    let observation = RepositoryObservation {
        source: ObservationSource {
            context: ObservationContext {
                principal: GithubAccountId::new(1).unwrap(),
                selection: selected.clone(),
                scan_id: "owned-scan".into(),
            },
            page: Some(1),
        },
        data,
    };
    let entity_id = observation.key().entity_id();
    let snapshot = Snapshot {
        schema_version: 2,
        observed_at_ms: 100,
        data: State::Repository { observation },
    };
    let writer = DeviceId::new("device").unwrap();
    snapshot
        .validate(&writer, EntityKind::RepositoryState, &entity_id)
        .unwrap();
    let mut operation = VersionedOperation::qualify(
        Operation {
            id: operation_id.into(),
            device: writer,
            entity_kind: EntityKind::RepositoryState,
            entity_id,
            base_revision: 0,
            idempotency_key: operation_id.into(),
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        },
        42,
        Lifecycle {
            resolved_through_seq: 0,
        },
    )
    .unwrap();
    operation.operation.payload = key
        .encrypt_versioned(
            &scope(),
            &operation,
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
    crate::codec::versioned_body(&operation).unwrap()
}

#[test]
fn actual_observation_transaction_preserves_encrypted_state_and_writer_capture() {
    let (owned, journal, key, selected, before) = setup();
    assert!(before.targets.is_empty());
    assert_eq!(before.writer, journal.writer_snapshot().unwrap());
    let body = observed(&key, &selected, "observation");
    let expected = guard(&key, &before);
    let result = journal
        .enqueue_observation(
            body.clone(),
            0,
            None,
            &selected,
            &before.selected_operation,
            &expected,
        )
        .unwrap();
    assert_eq!(result.id, "v3:42:observation");
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let entity = reopened
        .entity("repository_state", "github:repo:9")
        .unwrap()
        .unwrap();
    assert_eq!(entity.body, body);
    let stats = reopened.stats().unwrap();
    assert!(matches!(
        reopened.enqueue_observation(
            observed(&key, &selected, "late-target"),
            0,
            None,
            &selected,
            &before.selected_operation,
            &expected,
        ),
        Err(Error::Busy)
    ));
    assert_eq!(reopened.stats().unwrap(), stats);
    let operation = crate::codec::versioned(&entity.body).unwrap();
    let bytes = key.decrypt_versioned(&scope(), &operation).unwrap();
    let decoded: Snapshot = serde_json::from_slice(&bytes).unwrap();
    decoded
        .validate(
            &operation.operation.device,
            EntityKind::RepositoryState,
            "github:repo:9",
        )
        .unwrap();
    let after = reopened.observation_baselines(&selected).unwrap();
    assert_eq!(after.targets.len(), 1);
    assert_eq!(
        after.targets[0].pending_id.as_deref(),
        Some("v3:42:observation")
    );
    assert_eq!(after.writer, reopened.writer_snapshot().unwrap());
    let file = std::fs::read(owned.0.join("replica.db")).unwrap();
    assert!(
        !file
            .windows(b"private-repository-observation".len())
            .any(|v| v == b"private-repository-observation")
    );
}

#[test]
fn another_connection_changing_the_selected_record_refuses_the_observation() {
    let (owned, journal, key, selected, before) = setup();
    let other = Journal::open(owned.0.join("replica.db")).unwrap();
    let changed = super::checkpoint::valid_legacy_record_body(&key, "replacement", "credential", 0);
    other
        .enqueue(changed, None, 0, Some("credential-op".into()))
        .unwrap();
    let stats = journal.stats().unwrap();
    assert!(matches!(
        journal.enqueue_observation(
            observed(&key, &selected, "late"),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before)
        ),
        Err(Error::SelectionChanged)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
    assert!(
        journal
            .entity("repository_state", "github:repo:9")
            .unwrap()
            .is_none()
    );
}

#[test]
fn another_connection_changing_writer_facts_refuses_the_observation() {
    let (owned, journal, key, selected, before) = setup();
    let other = Journal::open(owned.0.join("replica.db")).unwrap();
    let replacement = VaultKey::generate().unwrap();
    other
        .confirm_writer(
            &other.writer_snapshot().unwrap(),
            3,
            &replacement.id(),
            Some(43),
        )
        .unwrap();
    let stats = journal.stats().unwrap();
    assert!(matches!(
        journal.enqueue_observation(
            observed(&key, &selected, "late"),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before)
        ),
        Err(Error::Busy)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
    assert!(
        journal
            .entity("repository_state", "github:repo:9")
            .unwrap()
            .is_none()
    );
}

#[test]
fn same_selection_metadata_does_not_hide_a_changed_encrypted_source() {
    let (owned, journal, key, selected, before) = setup();
    let altered =
        super::checkpoint::valid_legacy_record_body(&key, "credential-op", "credential", 0);
    assert_ne!(altered, before.selected_operation);
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    connection
        .execute(
            "UPDATE v3_outbox SET body=?1 WHERE kind='vault_record' AND id='credential-op'",
            [&altered],
        )
        .unwrap();
    let stats = journal.stats().unwrap();
    assert!(matches!(
        journal.enqueue_observation(
            observed(&key, &selected, "late-body"),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before)
        ),
        Err(Error::SelectionChanged)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
    assert!(
        journal
            .entity("repository_state", "github:repo:9")
            .unwrap()
            .is_none()
    );
}

#[test]
fn combined_guard_cannot_be_downgraded_to_the_older_storage_command() {
    let (_owned, _journal, key, selected, before) = setup();
    let command = crate::storage::Command::EnqueueObservedWriter {
        body: observed(&key, &selected, "observation"),
        expected_revision: 0,
        expected_pending: None,
        selected,
        selected_operation: before.selected_operation.clone(),
        writer: guard(&key, &before),
    };
    let mut encoded = serde_json::to_value(command).unwrap();
    let payload = encoded
        .as_object_mut()
        .unwrap()
        .remove("EnqueueObservedWriter")
        .unwrap();
    assert!(
        serde_json::from_value::<crate::storage::Command>(
            serde_json::json!({"EnqueueObservation": payload})
        )
        .is_err()
    );
    let mut payload = payload;
    payload.as_object_mut().unwrap().remove("writer");
    assert!(
        serde_json::from_value::<crate::storage::Command>(
            serde_json::json!({"EnqueueObservedWriter": payload})
        )
        .is_err()
    );
}

#[test]
fn selected_ciphertext_must_be_bound_to_its_record_identity() {
    let (owned, journal, key, selected, _before) = setup();
    let foreign =
        super::checkpoint::valid_legacy_record_body(&key, "credential-op", "other-record", 0);
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    connection
        .execute(
            "UPDATE v3_outbox SET body=?1 WHERE id='credential-op'",
            [&foreign],
        )
        .unwrap();
    assert!(matches!(
        journal.observation_baselines(&selected),
        Err(Error::Invalid)
    ));
}

#[test]
fn observation_window_is_transactional_and_preserves_replacement_and_other_writes() {
    let (owned, journal, key, selected, before) = setup();
    let writer = guard(&key, &before);
    for id in 1..=32 {
        journal
            .enqueue_observation(
                observed_repository(&key, &selected, &format!("observation-{id}"), id),
                0,
                None,
                &selected,
                &before.selected_operation,
                &writer,
            )
            .unwrap();
    }
    // A second connection must observe the first producer's completed writes.
    let other = Journal::open(owned.0.join("replica.db")).unwrap();
    let stats = other.stats().unwrap();
    assert_eq!(stats.0, 33); // 32 observations plus the selected credential.
    assert!(matches!(
        other.enqueue_observation(
            observed_repository(&key, &selected, "overflow", 33),
            0,
            None,
            &selected,
            &before.selected_operation,
            &writer,
        ),
        Err(Error::Busy)
    ));
    assert_eq!(other.stats().unwrap(), stats);
    assert!(
        other
            .entity("repository_state", "github:repo:33")
            .unwrap()
            .is_none()
    );
    let replacement = observed_repository(&key, &selected, "replacement", 1);
    other
        .enqueue_observation(
            replacement.clone(),
            0,
            Some("v3:42:observation-1".into()),
            &selected,
            &before.selected_operation,
            &writer,
        )
        .unwrap();
    assert_eq!(other.stats().unwrap().0, 33);
    assert_eq!(
        other
            .entity("repository_state", "github:repo:1")
            .unwrap()
            .unwrap()
            .body,
        replacement
    );
    other
        .enqueue(
            super::checkpoint::valid_legacy_record_body(&key, "another-record", "another", 0),
            None,
            0,
            None,
        )
        .unwrap();
    assert_eq!(other.stats().unwrap().0, 34);
}

#[test]
fn saved_catalog_pages_survive_reopen_and_owner_reads_reject_revision_drift() {
    let (owned, journal, key, selected, before) = setup();
    let writer = guard(&key, &before);
    for id in 1..=30 {
        journal
            .enqueue_observation(
                observed_repository(&key, &selected, &format!("observation-{id}"), id),
                0,
                None,
                &selected,
                &before.selected_operation,
                &writer,
            )
            .unwrap();
    }
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let mut first = reopened.repository_page("").unwrap();
    assert_eq!(first.entries.len(), 26);
    first.entries.truncate(25);
    let last = first.entries.last().unwrap().0.clone();
    let next = reopened.repository_page(&last).unwrap();
    assert_eq!(next.entries.len(), 5);
    let ids = first
        .entries
        .iter()
        .chain(&next.entries)
        .map(|(id, _)| id)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(ids.len(), 30);
    assert_eq!(first.cursor, next.cursor);
    assert_eq!(first.local_revision, next.local_revision);
    let owners = vec!["github:owner:1".into()];
    assert!(
        reopened
            .repository_owners(&owners, first.local_revision)
            .unwrap()
            .entries
            .is_empty()
    );
    let owner_body = observed_data(
        &key,
        &selected,
        "owner-profile",
        ObservationData::Owner {
            owner: GithubOwner {
                id: GithubAccountId::new(1).unwrap(),
                kind: GithubOwnerKind::Organization,
                login: "observed-owner".into(),
            },
        },
    );
    journal
        .enqueue_observation(
            owner_body.clone(),
            0,
            None,
            &selected,
            &before.selected_operation,
            &writer,
        )
        .unwrap();
    assert!(matches!(
        reopened.repository_owners(&owners, first.local_revision),
        Err(Error::Busy)
    ));
    let refreshed = reopened.repository_page("").unwrap();
    let joined = reopened
        .repository_owners(&owners, refreshed.local_revision)
        .unwrap();
    assert_eq!(joined.entries.len(), 1);
    assert_eq!(joined.entries[0].0, "github:owner:1");
    assert_eq!(joined.entries[0].1.body, owner_body);
    let decoded = crate::codec::versioned(&joined.entries[0].1.body).unwrap();
    let plain = key.decrypt_versioned(&scope(), &decoded).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&plain).unwrap();
    snapshot
        .validate(
            &decoded.operation.device,
            EntityKind::RepositoryState,
            &joined.entries[0].0,
        )
        .unwrap();
    // An ordinary concurrent write must invalidate the second half of a read.
    journal
        .enqueue(
            super::checkpoint::valid_legacy_record_body(&key, "later-record", "later", 0),
            None,
            0,
            None,
        )
        .unwrap();
    assert!(matches!(
        reopened.repository_owners(&owners, refreshed.local_revision),
        Err(Error::Busy)
    ));
    let too_many = (1..=26)
        .map(|id| format!("github:owner:{id}"))
        .collect::<Vec<_>>();
    assert!(matches!(
        reopened.repository_owners(&too_many, first.local_revision),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        reopened.repository_owners(
            &["github:owner:1".into(), "github:owner:1".into()],
            first.local_revision
        ),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        reopened.repository_owners(&["github:repo:1".into()], first.local_revision),
        Err(Error::Invalid)
    ));
}

#[test]
fn partial_scope_summary_retains_encrypted_completion_evidence_after_reopen() {
    let (owned, journal, key, selected, before) = setup();
    let scan = ScopeScan {
        outcome: TraversalOutcome::Partial,
        pages: 1,
        repositories: 1,
        last_complete: Some(CompleteTraversal {
            pages: 3,
            repositories: 50,
            observed_at_ms: 99,
            scan_id: "earlier".into(),
        }),
    };
    let body = observed_data(
        &key,
        &selected,
        "scope-summary",
        ObservationData::ScopeScan { scan: scan.clone() },
    );
    journal
        .enqueue_observation(
            body.clone(),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before),
        )
        .unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let id = ObservationKey::Scope {
        principal: GithubAccountId::new(1).unwrap(),
        record_ref: "credential".into(),
    }
    .entity_id();
    let target = reopened.observation_target(&id).unwrap().effective.unwrap();
    assert_eq!(target.body, body);
    let operation = crate::codec::versioned(&target.body).unwrap();
    let plaintext = key.decrypt_versioned(&scope(), &operation).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&plaintext).unwrap();
    snapshot
        .validate(
            &operation.operation.device,
            EntityKind::RepositoryState,
            &id,
        )
        .unwrap();
    let State::Repository { observation } = snapshot.data else {
        panic!()
    };
    assert_eq!(observation.data, ObservationData::ScopeScan { scan });
    let baseline = reopened.observation_baselines(&selected).unwrap();
    let summary = baseline
        .targets
        .iter()
        .find(|target| target.id == id)
        .unwrap();
    assert_eq!(summary.pending_id.as_deref(), Some("v3:42:scope-summary"));
}

fn retained_row(
    key: &VaultKey,
    selected: &CredentialSelection,
    id: &str,
    seq: u64,
    conflict: bool,
) -> RawRow {
    let body = observed(key, selected, id);
    let operation_id = crate::codec::versioned(&body).unwrap().operation.id;
    let result = if conflict {
        wire::Sync::Conflict(wire::SyncConflict {
            operation_id,
            outcome: wire::SyncConflictOutcome::Conflict,
            base_revision: 0,
            current_revision: 1,
            resolution_state: wire::ResolutionState::Unresolved,
            server_seq: seq as i64,
        })
    } else {
        super::result(&operation_id, seq as i64)
    };
    RawRow {
        body,
        result: serde_json::to_vec(&result).unwrap(),
        status: if conflict { 409 } else { 201 },
        sequence: seq,
        legacy_resolved: 0,
    }
}

#[test]
fn actual_conflict_capture_reopens_exact_originals_and_preserves_pending_ancestry() {
    let (owned, journal, key, selected, before) = setup();
    let pending = observed(&key, &selected, "local-intent");
    journal
        .enqueue_observation(
            pending.clone(),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before),
        )
        .unwrap();
    let committed = retained_row(&key, &selected, "committed", 43, false);
    let conflict = retained_row(&key, &selected, "conflicted", 44, true);
    let committed_bytes = committed.body.clone();
    let conflict_bytes = conflict.body.clone();
    let conflict_result = conflict.result.clone();
    let checkpoint = journal
        .begin_checkpoint(&"c".repeat(64), &key.id(), 44, 2, 0)
        .unwrap();
    journal
        .stage_base(&checkpoint, 44, 2, &[committed, conflict], 44, false)
        .unwrap();
    journal
        .stage_delta(&checkpoint, 44, &[], 44, false)
        .unwrap();
    journal.install_checkpoint(&checkpoint).unwrap();
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let counts = reopened.stats().unwrap();
    let restored = reopened
        .observation_resolution("github:repo:9", &selected, &before.selected_operation)
        .unwrap();
    assert_eq!(restored.target.body, committed_bytes);
    assert_eq!(restored.target.revision, 1);
    assert_eq!(restored.target.next_base, 0); // A real unsent original behind the caught-up head.
    assert_eq!(
        restored.target.pending_id.as_deref(),
        Some("v3:42:local-intent")
    );
    assert_eq!(restored.pending.as_deref(), Some(pending.as_slice()));
    assert_eq!(restored.guard.cursor, 44);
    assert_eq!(restored.guard.local_revision, counts.4);
    assert_eq!(restored.guard.lifecycle.resolved_through_seq, 44);
    let retained = restored.conflict.unwrap();
    assert_eq!(retained.body, conflict_bytes);
    assert_eq!(retained.result, conflict_result);
    let (original, receipt) = retained.decode().unwrap();
    assert_eq!(original.operation.base_revision, 0);
    assert_eq!(receipt.server_seq, 44);
    let plaintext = key.decrypt_versioned(&scope(), &original).unwrap();
    let snapshot: Snapshot = serde_json::from_slice(&plaintext).unwrap();
    snapshot
        .validate(
            &original.operation.device,
            EntityKind::RepositoryState,
            "github:repo:9",
        )
        .unwrap();
    assert_eq!(reopened.stats().unwrap(), counts); // Read-only capture.
    reopened.pending().unwrap();
    assert!(matches!(
        reopened.observation_resolution("github:repo:9", &selected, &before.selected_operation),
        Err(Error::Busy)
    ));
    let new_selection = CredentialSelection::new("credential".into(), 1, None).unwrap();
    assert!(matches!(
        reopened.observation_resolution(
            "github:repo:9",
            &new_selection,
            &before.selected_operation
        ),
        Err(Error::SelectionChanged)
    ));
}

#[test]
fn resolution_capture_rejects_a_conflict_original_bound_to_another_entity() {
    let (owned, journal, key, selected, before) = setup();
    let committed = retained_row(&key, &selected, "committed", 43, false);
    let conflict = retained_row(&key, &selected, "conflicted", 44, true);
    let checkpoint = journal
        .begin_checkpoint(&"c".repeat(64), &key.id(), 44, 2, 0)
        .unwrap();
    journal
        .stage_base(&checkpoint, 44, 2, &[committed, conflict], 44, false)
        .unwrap();
    journal
        .stage_delta(&checkpoint, 44, &[], 44, false)
        .unwrap();
    journal.install_checkpoint(&checkpoint).unwrap();
    let other = observed_repository(&key, &selected, "conflicted", 10);
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    connection
        .execute(
            "UPDATE v3_conflicts SET body=?1 WHERE entity_id='github:repo:9'",
            [other],
        )
        .unwrap();
    let before_read = journal.stats().unwrap();
    assert!(matches!(
        journal.observation_resolution("github:repo:9", &selected, &before.selected_operation),
        Err(Error::Invalid)
    ));
    assert_eq!(journal.stats().unwrap(), before_read);
}

#[test]
fn resolution_capture_checks_all_witnesses_and_chooses_latest_by_sequence() {
    let (owned, journal, key, selected, before) = setup();
    let head = retained_row(&key, &selected, "head", 43, false);
    let older = retained_row(&key, &selected, "z-older", 44, true);
    let newer = retained_row(&key, &selected, "a-newer", 45, true);
    let latest_body = newer.body.clone();
    let checkpoint = journal
        .begin_checkpoint(&"c".repeat(64), &key.id(), 45, 3, 0)
        .unwrap();
    journal
        .stage_base(&checkpoint, 45, 3, &[head, older, newer], 45, false)
        .unwrap();
    journal
        .stage_delta(&checkpoint, 45, &[], 45, false)
        .unwrap();
    journal.install_checkpoint(&checkpoint).unwrap();
    let capture = journal
        .observation_resolution("github:repo:9", &selected, &before.selected_operation)
        .unwrap();
    assert_eq!(capture.conflict.unwrap().body, latest_body);
    assert_eq!(capture.guard.lifecycle.resolved_through_seq, 45);
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    connection.execute("UPDATE v3_conflicts SET result=CAST(json_set(CAST(result AS TEXT),'$.server_seq',45) AS BLOB) WHERE json_extract(CAST(result AS TEXT),'$.server_seq')=44", []).unwrap();
    assert!(matches!(
        journal.observation_resolution("github:repo:9", &selected, &before.selected_operation),
        Err(Error::Invalid)
    ));
}

#[test]
fn blocked_only_resolution_preserves_real_lifecycle_through_reopen_and_receipt() {
    let (owned, journal, key, selected, before) = setup();
    let pending = observed(&key, &selected, "remaining-local-intent");
    journal
        .enqueue_observation(
            pending.clone(),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before),
        )
        .unwrap();
    // Structurally valid retained state after a peer resolved the known family.
    // This exercises local storage/crypto, not a server resolution acceptance path.
    let template = crate::codec::versioned(&observed(&key, &selected, "template")).unwrap();
    let plain = key.decrypt_versioned(&scope(), &template).unwrap();
    let mut operation = template.operation;
    operation.id = "peer-resolver".into();
    operation.idempotency_key = "peer-resolver".into();
    operation.base_revision = 1;
    let mut resolver = VersionedOperation::qualify(
        operation,
        44,
        Lifecycle {
            resolved_through_seq: 44,
        },
    )
    .unwrap();
    resolver.operation.payload = key.encrypt_versioned(&scope(), &resolver, &plain).unwrap();
    let result = wire::Sync::Applied(wire::SyncApplied {
        operation_id: resolver.operation.id.clone(),
        outcome: wire::SyncAppliedOutcome::Applied,
        revision: 2,
        server_seq: 45,
    });
    let row = RawRow {
        body: crate::codec::versioned_body(&resolver).unwrap(),
        result: serde_json::to_vec(&result).unwrap(),
        status: 201,
        sequence: 45,
        legacy_resolved: 0,
    };
    let checkpoint = journal
        .begin_checkpoint(&"c".repeat(64), &key.id(), 45, 1, 0)
        .unwrap();
    journal
        .stage_base(&checkpoint, 45, 1, &[row], 45, false)
        .unwrap();
    journal
        .stage_delta(&checkpoint, 45, &[], 45, false)
        .unwrap();
    journal.install_checkpoint(&checkpoint).unwrap();
    let connection = Connection::open(owned.0.join("replica.db")).unwrap();
    connection
        .execute(
            "UPDATE v3_outbox SET state='conflict' WHERE id='v3:42:remaining-local-intent'",
            [],
        )
        .unwrap();
    let capture = journal
        .observation_resolution("github:repo:9", &selected, &before.selected_operation)
        .unwrap();
    assert!(capture.conflict.is_none());
    assert_eq!(capture.pending.as_deref(), Some(pending.as_slice()));
    assert_eq!(capture.guard.cursor, 45);
    assert_eq!(capture.guard.lifecycle.resolved_through_seq, 44);
    assert_eq!(capture.target.revision, 2);
    assert!(capture.target.conflicted);
    assert!(capture.pending_blocked);
    let pending_operation = crate::codec::versioned(&pending).unwrap();
    let plaintext = key.decrypt_versioned(&scope(), &pending_operation).unwrap();
    let Snapshot {
        data: State::Repository { observation },
        ..
    } = serde_json::from_slice(&plaintext).unwrap()
    else {
        panic!("repository observation")
    };
    let committed_operation = crate::codec::versioned(&capture.target.body).unwrap();
    let committed_plaintext = key
        .decrypt_versioned(&scope(), &committed_operation)
        .unwrap();
    let Snapshot {
        data: State::Repository {
            observation: committed_observation,
        },
        ..
    } = serde_json::from_slice(&committed_plaintext).unwrap()
    else {
        panic!("committed observation")
    };
    let current = ObservedTarget {
        key: observation.key(),
        version: TargetVersion {
            revision: capture.target.revision,
            next_base: capture.target.next_base,
            pending_id: capture.target.pending_id.clone(),
            conflicted: capture.target.conflicted,
        },
        value: Some(committed_observation),
        history_cursor: capture.guard.cursor,
    };
    let reread = ResolutionRead::blocked_intent(
        observation.clone(),
        &pending_operation,
        pending.len(),
        &current,
        capture.pending_blocked,
    )
    .unwrap();
    // Explicit pure-rule input, not evidence of an actual provider request.
    let mut fresh = observation;
    fresh.source.context.scan_id = "fresh-provider-scan".into();
    let confirmed = reread.confirm(fresh.clone()).unwrap();
    let ResolutionDecision::Equivalent(reviewed) = confirmed
        .decide(&current, Some(&fresh.source.context))
        .unwrap()
    else {
        panic!("equivalent observation still needs a durable operation")
    };
    assert_eq!(reviewed.receipt_seq, None);
    assert_eq!(reviewed.resolution_base(), 2);

    let writer = resolution_writer(&journal, &key, &capture);
    let stats = journal.stats().unwrap();
    let mut invented = capture.guard.clone();
    invented.lifecycle.resolved_through_seq = capture.guard.cursor;
    assert!(matches!(
        journal.enqueue_observation_resolution(
            new_resolution_body(&key, &selected, 2, 45, 45),
            2,
            capture.target.pending_id.clone(),
            (&selected, &before.selected_operation),
            &writer,
            &invented,
        ),
        Err(Error::Busy)
    ));
    assert_eq!(journal.stats().unwrap(), stats);

    let body = new_resolution_body(&key, &selected, 2, 45, 44);
    let queued = journal
        .enqueue_observation_resolution(
            body.clone(),
            reviewed.resolution_base(),
            capture.target.pending_id,
            (&selected, &before.selected_operation),
            &writer,
            &capture.guard,
        )
        .unwrap();
    assert_eq!(queued.id, "v3:45:fresh-resolution");
    assert_eq!(queued.conflicts, 0);
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    let current = reopened
        .entity("repository_state", "github:repo:9")
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, 2);
    assert_eq!(current.pending_id.as_deref(), Some(queued.id.as_str()));
    assert_eq!(current.body, body);
    let claimed = reopened.pending().unwrap();
    assert_eq!(
        claimed.iter().find(|p| p.id == queued.id).unwrap().body,
        body
    );
    let pending_operation = crate::codec::versioned(&body).unwrap();
    assert_eq!(pending_operation.lifecycle().resolved_through_seq, 44);
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM v3_conflicts", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    let result = wire::Sync::Applied(wire::SyncApplied {
        operation_id: queued.id,
        outcome: wire::SyncAppliedOutcome::Applied,
        revision: 3,
        server_seq: 46,
    });
    reopened
        .acknowledge_original(&body, &serde_json::to_vec(&result).unwrap(), 201, 0)
        .unwrap();
    let current = reopened
        .entity("repository_state", "github:repo:9")
        .unwrap()
        .unwrap();
    assert_eq!(current.revision, 3);
    assert!(current.pending_id.is_none());
    assert!(!current.conflicted);
    assert_eq!(current.body, body);
}

fn resolution_fixture() -> (
    Owned,
    Journal,
    VaultKey,
    CredentialSelection,
    ObservationBaselines,
) {
    let (owned, journal, key, selected, before) = setup();
    journal
        .enqueue_observation(
            observed(&key, &selected, "local-intent"),
            0,
            None,
            &selected,
            &before.selected_operation,
            &guard(&key, &before),
        )
        .unwrap();
    let checkpoint = journal
        .begin_checkpoint(&"c".repeat(64), &key.id(), 44, 2, 0)
        .unwrap();
    journal
        .stage_base(
            &checkpoint,
            44,
            2,
            &[
                retained_row(&key, &selected, "committed", 43, false),
                retained_row(&key, &selected, "conflicted", 44, true),
            ],
            44,
            false,
        )
        .unwrap();
    journal
        .stage_delta(&checkpoint, 44, &[], 44, false)
        .unwrap();
    journal.install_checkpoint(&checkpoint).unwrap();
    (owned, journal, key, selected, before)
}
fn new_resolution_body(
    key: &VaultKey,
    selected: &CredentialSelection,
    base: u64,
    basis: u64,
    resolved: u64,
) -> Vec<u8> {
    let template = crate::codec::versioned(&observed(key, selected, "template")).unwrap();
    let plain = key.decrypt_versioned(&scope(), &template).unwrap();
    let mut snapshot: Snapshot = serde_json::from_slice(&plain).unwrap();
    if let State::Repository { observation } = &mut snapshot.data {
        observation.source.context.scan_id = "fresh-provider-scan".into();
    }
    let mut operation = template.operation;
    operation.id = "fresh-resolution".into();
    operation.idempotency_key = "fresh-resolution".into();
    operation.base_revision = base;
    let mut resolver = VersionedOperation::qualify(
        operation,
        basis,
        Lifecycle {
            resolved_through_seq: resolved,
        },
    )
    .unwrap();
    resolver.operation.payload = key
        .encrypt_versioned(&scope(), &resolver, &serde_json::to_vec(&snapshot).unwrap())
        .unwrap();
    crate::codec::versioned_body(&resolver).unwrap()
}
fn resolution_writer(
    journal: &Journal,
    key: &VaultKey,
    capture: &ObservationResolution,
) -> WriterEnqueueGuard {
    WriterEnqueueGuard {
        facts: journal.writer_snapshot().unwrap().facts,
        actual_key_id: key.id(),
        basis_seq: Some(capture.guard.cursor),
        expected_local_revision: None,
    }
}

#[test]
fn resolved_observation_is_durable_but_only_applied_receipt_retires_known_conflicts() {
    for applied in [false, true] {
        let (owned, journal, key, selected, before) = resolution_fixture();
        let capture = journal
            .observation_resolution("github:repo:9", &selected, &before.selected_operation)
            .unwrap();
        assert_eq!(capture.target.next_base, 0);
        let original = capture.target.body.clone();
        let body = new_resolution_body(&key, &selected, 1, 44, 44);
        let writer = resolution_writer(&journal, &key, &capture);
        let receipt = journal
            .enqueue_observation_resolution(
                body.clone(),
                1,
                capture.target.pending_id.clone(),
                (&selected, &before.selected_operation),
                &writer,
                &capture.guard,
            )
            .unwrap();
        assert_eq!(receipt.id, "v3:44:fresh-resolution");
        assert_eq!(journal.stats().unwrap().1, 1);
        let current = journal
            .entity("repository_state", "github:repo:9")
            .unwrap()
            .unwrap();
        assert!(current.conflicted);
        assert_eq!(current.body, original);
        assert_eq!(current.pending_id.as_deref(), Some(receipt.id.as_str()));
        let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
        let claimed = reopened.pending().unwrap();
        assert_eq!(
            claimed.iter().find(|p| p.id == receipt.id).unwrap().body,
            body
        );
        assert_eq!(
            reopened
                .pending()
                .unwrap()
                .iter()
                .find(|p| p.id == receipt.id)
                .unwrap()
                .body,
            body
        );
        let result = if applied {
            wire::Sync::Applied(wire::SyncApplied {
                operation_id: receipt.id,
                outcome: wire::SyncAppliedOutcome::Applied,
                revision: 2,
                server_seq: 45,
            })
        } else {
            wire::Sync::Conflict(wire::SyncConflict {
                operation_id: receipt.id,
                outcome: wire::SyncConflictOutcome::Conflict,
                base_revision: 1,
                current_revision: 2,
                resolution_state: wire::ResolutionState::Unresolved,
                server_seq: 45,
            })
        };
        reopened
            .acknowledge_original(
                &body,
                &serde_json::to_vec(&result).unwrap(),
                if applied { 201 } else { 409 },
                0,
            )
            .unwrap();
        let current = reopened
            .entity("repository_state", "github:repo:9")
            .unwrap()
            .unwrap();
        assert_eq!(current.conflicted, !applied);
        assert_eq!(reopened.stats().unwrap().1, if applied { 0 } else { 2 });
        assert_eq!(current.body, if applied { body } else { original });
    }
}

#[test]
fn resolved_observation_refuses_incomplete_witnesses_changed_source_and_dispatched_intent() {
    let (_owned, journal, key, selected, before) = resolution_fixture();
    let capture = journal
        .observation_resolution("github:repo:9", &selected, &before.selected_operation)
        .unwrap();
    let writer = resolution_writer(&journal, &key, &capture);
    let stats = journal.stats().unwrap();
    let mut partial = capture.guard.clone();
    partial.lifecycle.resolved_through_seq = 43;
    assert!(matches!(
        journal.enqueue_observation_resolution(
            new_resolution_body(&key, &selected, 1, 44, 43),
            1,
            capture.target.pending_id.clone(),
            (&selected, &before.selected_operation),
            &writer,
            &partial
        ),
        Err(Error::Busy)
    ));
    let mut wrong_source = before.selected_operation.clone();
    wrong_source.push(b' ');
    assert!(matches!(
        journal.enqueue_observation_resolution(
            new_resolution_body(&key, &selected, 1, 44, 44),
            1,
            capture.target.pending_id.clone(),
            (&selected, &wrong_source),
            &writer,
            &capture.guard
        ),
        Err(Error::SelectionChanged)
    ));
    let mut missing = capture.guard.clone();
    missing.repository_fingerprint = None;
    assert!(matches!(
        journal.enqueue_observation_resolution(
            new_resolution_body(&key, &selected, 1, 44, 44),
            1,
            capture.target.pending_id.clone(),
            (&selected, &before.selected_operation),
            &writer,
            &missing
        ),
        Err(Error::Invalid)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
    let intent = journal
        .entity("repository_state", "github:repo:9")
        .unwrap()
        .unwrap()
        .pending_id
        .unwrap();
    let claimed = journal
        .pending()
        .unwrap()
        .into_iter()
        .find(|p| p.id == intent)
        .unwrap()
        .body;
    let now = journal.writer_snapshot().unwrap();
    let mut guard = capture.guard;
    guard.local_revision = now.local_revision;
    let writer = WriterEnqueueGuard {
        facts: now.facts,
        expected_local_revision: None,
        ..writer
    };
    assert!(matches!(
        journal.enqueue_observation_resolution(
            new_resolution_body(&key, &selected, 1, 44, 44),
            1,
            Some(intent.clone()),
            (&selected, &before.selected_operation),
            &writer,
            &guard
        ),
        Err(Error::Busy)
    ));
    assert_eq!(
        journal
            .pending()
            .unwrap()
            .into_iter()
            .find(|p| p.id == intent)
            .unwrap()
            .body,
        claimed
    );
}

#[test]
fn resolution_command_cannot_lose_its_guard_or_downgrade_to_an_ordinary_write() {
    let (_owned, journal, key, selected, before) = resolution_fixture();
    let capture = journal
        .observation_resolution("github:repo:9", &selected, &before.selected_operation)
        .unwrap();
    let command = crate::storage::Command::EnqueueRepositoryResolution {
        body: new_resolution_body(&key, &selected, 1, 44, 44),
        expected_revision: 1,
        expected_pending: capture.target.pending_id.clone(),
        selected,
        selected_operation: before.selected_operation,
        writer: resolution_writer(&journal, &key, &capture),
        resolution: capture.guard,
    };
    let mut encoded = serde_json::to_value(command).unwrap();
    let payload = encoded
        .as_object_mut()
        .unwrap()
        .remove("EnqueueRepositoryResolution")
        .unwrap();
    assert!(
        serde_json::from_value::<crate::storage::Command>(
            serde_json::json!({"EnqueueResolvedObservation": payload.clone()})
        )
        .is_err()
    );
    let mut fingerprint_missing = payload.clone();
    fingerprint_missing["resolution"]
        .as_object_mut()
        .unwrap()
        .remove("repository_fingerprint");
    let command = serde_json::from_value::<crate::storage::Command>(
        serde_json::json!({"EnqueueRepositoryResolution": fingerprint_missing}),
    )
    .unwrap();
    let stats = journal.stats().unwrap();
    assert!(matches!(
        crate::storage::execute(&journal, command),
        Err(Error::Invalid)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
    let mut missing = payload.clone();
    missing.as_object_mut().unwrap().remove("resolution");
    assert!(
        serde_json::from_value::<crate::storage::Command>(
            serde_json::json!({"EnqueueRepositoryResolution":missing})
        )
        .is_err()
    );
    let downgraded = serde_json::from_value::<crate::storage::Command>(
        serde_json::json!({"EnqueueObservedWriter":payload}),
    )
    .unwrap();
    let stats = journal.stats().unwrap();
    assert!(matches!(
        crate::storage::execute(&journal, downgraded),
        Err(Error::Busy)
    ));
    assert_eq!(journal.stats().unwrap(), stats);
}
