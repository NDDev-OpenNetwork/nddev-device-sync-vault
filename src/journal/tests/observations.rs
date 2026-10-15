use super::*;
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
