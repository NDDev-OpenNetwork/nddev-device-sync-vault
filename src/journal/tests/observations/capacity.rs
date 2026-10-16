//! Real SQLite/encryption qualification with generated receipt inputs. This
//! exercises local durability, not a provider or deployed-device sync session.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[test]
fn saved_1024_repository_catalog_preserves_committed_and_pending_rows_after_restart() {
    let (owned, journal, key, selected, before) = setup();
    let writer = guard(&key, &before);
    let mut expected = BTreeMap::new();
    let mut sequence = 42;
    let mut data = (1..=32)
        .map(|id| ObservationData::Owner {
            owner: GithubOwner {
                id: GithubAccountId::new(id).unwrap(),
                kind: if id == 1 {
                    GithubOwnerKind::User
                } else {
                    GithubOwnerKind::Organization
                },
                login: format!("owner-{id}"),
            },
        })
        .collect::<Vec<_>>();
    data.extend((1..=1024).map(|id| ObservationData::Repository {
        repository: RepositoryFact {
            id: RepositoryId::new(id).unwrap(),
            owner_id: GithubAccountId::new(1 + (id - 1) % 32).unwrap(),
            name: format!("private-saved-repository-{id}"),
            visibility: RepositoryVisibility::Private,
            archived: false,
            default_branch: Some("main".into()),
        },
    }));
    for (index, batch) in data.chunks(32).enumerate() {
        for (offset, value) in batch.iter().enumerate() {
            let body = observed_data(
                &key,
                &selected,
                &format!("catalog-{index}-{offset}"),
                value.clone(),
            );
            let operation = crate::codec::versioned(&body).unwrap();
            expected.insert(operation.operation.entity_id.clone(), body.clone());
            journal
                .enqueue_observation(
                    body,
                    0,
                    None,
                    &selected,
                    &before.selected_operation,
                    &writer,
                )
                .unwrap();
        }
        assert_eq!(journal.stats().unwrap().0, 33); //32 facts and the selected record.
        if index == 32 {
            break;
        } // Preserve the final32 encrypted pending facts.
        loop {
            let claimed = journal
                .pending()
                .unwrap()
                .into_iter()
                .filter(|row| {
                    crate::codec::versioned(&row.body)
                        .unwrap()
                        .operation
                        .entity_kind
                        == EntityKind::RepositoryState
                })
                .collect::<Vec<_>>();
            if claimed.is_empty() {
                break;
            }
            for row in claimed {
                sequence += 1;
                let receipt = serde_json::to_vec(&wire::Sync::Applied(wire::SyncApplied {
                    operation_id: row.id,
                    outcome: wire::SyncAppliedOutcome::Applied,
                    revision: 1,
                    server_seq: sequence,
                }))
                .unwrap();
                journal
                    .acknowledge_original(&row.body, &receipt, 201, 0)
                    .unwrap();
            }
        }
    }
    let before_restart = journal.stats().unwrap();
    drop(journal);
    let reopened = Journal::open(owned.0.join("replica.db")).unwrap();
    assert_eq!(reopened.stats().unwrap(), before_restart);
    let baseline = reopened.observation_baselines(&selected).unwrap();
    assert_eq!(baseline.targets.len(), 1056);
    assert_eq!(
        baseline
            .targets
            .iter()
            .filter(|row| row.pending_id.is_some())
            .count(),
        32
    );
    let mut after = String::new();
    let mut seen = BTreeSet::new();
    let mut pending = 0;
    let mut pages = 0;
    loop {
        let mut page = reopened.repository_page(&after).unwrap();
        assert!(page.entries.len() <= REPOSITORIES_PER_PAGE + 1);
        let more = page.entries.len() > REPOSITORIES_PER_PAGE;
        page.entries.truncate(REPOSITORIES_PER_PAGE);
        let mut owners = BTreeSet::new();
        for (id, row) in &page.entries {
            assert!(seen.insert(id.clone()));
            assert_eq!(row.body, expected[id]);
            let operation = crate::codec::versioned(&row.body).unwrap();
            let plain = key.decrypt_versioned(&scope(), &operation).unwrap();
            let snapshot: Snapshot = serde_json::from_slice(&plain).unwrap();
            snapshot
                .validate(&operation.operation.device, EntityKind::RepositoryState, id)
                .unwrap();
            let State::Repository { observation } = snapshot.data else {
                panic!("repository observation")
            };
            let ObservationData::Repository { repository } = observation.data else {
                panic!("repository fact")
            };
            owners.insert(format!("github:owner:{}", repository.owner_id.value()));
            if let Some(id) = &row.pending_id {
                pending += 1;
                assert_eq!(id, &operation.operation.id);
                assert_eq!(row.revision, 0);
            } else {
                assert_eq!(row.revision, 1);
            }
        }
        let owners = owners.into_iter().collect::<Vec<_>>();
        let profiles = reopened
            .repository_owners(&owners, page.local_revision)
            .unwrap();
        assert_eq!(profiles.entries.len(), owners.len());
        for (id, row) in profiles.entries {
            assert_eq!(row.body, expected[&id]);
        }
        pages += 1;
        if !more {
            break;
        }
        after = page.entries.last().unwrap().0.clone();
    }
    assert_eq!((seen.len(), pending, pages), (1024, 32, 41));
    // Claiming after reopen must recover the same immutable pending originals.
    for row in reopened.pending().unwrap() {
        let operation = crate::codec::versioned(&row.body).unwrap();
        if operation.operation.entity_kind == EntityKind::RepositoryState {
            assert_eq!(row.body, expected[&operation.operation.entity_id]);
        }
    }
}
