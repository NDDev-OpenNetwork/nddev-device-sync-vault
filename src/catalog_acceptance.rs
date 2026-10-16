//! Actual HTTP/PostgreSQL acceptance of generated catalog facts. This is not
//! GitHub-provider acceptance or proof of 32 distinct enrolled devices.
use super::*;
use nddev_device_sync_domain::repositories::catalog::{
    GithubAccountId, GithubOwner, GithubOwnerKind, RepositoryId, RepositoryVisibility,
    observations::{
        Capture, ObservationContext, ObservationData, ObservationSource, RepositoryFact,
        RepositoryObservation, TargetVersion,
    },
};
use std::collections::BTreeMap;
use tokio_util::sync::CancellationToken;

fn originals(vault: &VaultClient) -> Result<BTreeMap<String, Vec<u8>>, Error> {
    let db = rusqlite::Connection::open_with_flags(
        vault.journal.path_for_acceptance(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .map_err(dependency)?;
    let mut query = db
        .prepare("SELECT id,body FROM v3_outbox")
        .map_err(dependency)?;
    query
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(dependency)?
        .collect::<Result<_, _>>()
        .map_err(dependency)
}

// Timed-out callers do not release an in-flight OS credential operation. Let
// that actual completion settle before deleting this fixture's credentials.
async fn after_io<T, F>(
    mut action: impl FnMut() -> F,
) -> Result<T, nddev_device_sync_accounts::ClientError>
where
    F: std::future::Future<Output = Result<T, nddev_device_sync_accounts::ClientError>>,
{
    nddev_device_sync_accounts::runtime::timeout(std::time::Duration::from_secs(16), async {
        loop {
            match action().await {
                Err(nddev_device_sync_accounts::ClientError::Busy) => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                result => return result,
            }
        }
    })
    .await
    .map_err(|_| nddev_device_sync_accounts::ClientError::Timeout)?
}

async fn settle(vault: &VaultClient) -> Result<VaultView, Error> {
    use nddev_device_sync_application::lifecycle::{BatchOutcome, ReplicaSchedule};
    let mut schedule = ReplicaSchedule::default();
    for _ in 0..128 {
        let before = originals(vault)?;
        let attempt = vault.synchronize_attempt(false).await?.result;
        for (id, body) in originals(vault)? {
            assert!(
                before.get(&id) == Some(&body),
                "sync changed a pending original"
            );
        }
        let progress = match attempt {
            Ok(progress) => progress,
            Err(Error::Busy) => {
                // Real signed-request admission can fill its nonce window.
                // Use the same Core backoff as the client, with unchanged
                // durable originals; never raise the quota or alter clocks.
                let delay = schedule.after(BatchOutcome::Retryable).unwrap();
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"catalog.acceptance.backoff", "reason":"busy", "delay_ms":delay.as_millis()})
                );
                nddev_device_sync_accounts::runtime::sleep(delay).await;
                continue;
            }
            Err(error) => return Err(error),
        };
        schedule.after(if progress.caught_up {
            BatchOutcome::CaughtUp
        } else {
            BatchOutcome::CatchingUp
        });
        if progress.caught_up {
            assert!(progress.inbox_at_head && progress.view.pending == 0);
            assert_eq!(progress.view.conflicts, 0);
            assert!(progress.view.sync_error.is_empty());
            return Ok(progress.view);
        }
    }
    Err(Error::Unavailable)
}

async fn publish(
    vault: &VaultClient,
    context: &ObservationContext,
    values: &[ObservationData],
) -> Result<usize, Error> {
    let mut queued = 0;
    for batch in values.chunks(32) {
        let fence = Arc::new(
            vault
                .identity
                .local_use_fence()
                .await
                .map_err(identity_failure)?,
        );
        let read = vault
            .capture_repository_observations(
                context.selection.clone(),
                fence,
                CancellationToken::new(),
            )
            .await?;
        assert!(matches!(read.writer_mode(), Some(replica::WriterMode::V3)));
        let baselines: BTreeMap<_, _> = read.baselines().into_iter().collect();
        for data in batch {
            let observation = RepositoryObservation {
                source: ObservationSource {
                    context: context.clone(),
                    page: Some(1),
                },
                data: data.clone(),
            };
            let key = observation.key();
            let before = baselines
                .get(&key.entity_id())
                .cloned()
                .unwrap_or_else(TargetVersion::absent);
            let candidate = Capture::before_read(key, before)
                .unwrap()
                .confirm(observation)
                .unwrap();
            match vault
                .publish_repository_observation(&read, candidate, Some(context), now_ms()?)
                .await?
            {
                RepositoryPublication::Queued { .. } => queued += 1,
                RepositoryPublication::Unchanged => {}
                _ => panic!("fresh sequential observation was not accepted"),
            }
        }
        assert!(vault.refresh_local().await?.pending <= 32);
        let view = settle(vault).await?;
        if queued > 0 && queued % 256 == 0 {
            eprintln!(
                "{}",
                serde_json::json!({"event":"catalog.acceptance.progress", "queued":queued, "cursor":view.cursor})
            );
        }
    }
    Ok(queued)
}

async fn catalog(vault: &VaultClient) -> Result<BTreeMap<String, (ObservationData, u64)>, Error> {
    let mut after = None;
    let mut saved = BTreeMap::new();
    let mut pages = 0;
    loop {
        let page = vault
            .repository_catalog_page(after.as_ref(), CancellationToken::new())
            .await?;
        pages += 1;
        assert!(pages <= 41);
        for (target, _) in page.observations {
            assert!(target.version.pending_id.is_none() && !target.version.conflicted);
            let value = (target.value.unwrap().data, target.version.revision);
            if let Some(old) = saved.insert(target.key.entity_id(), value.clone()) {
                assert!(old == value, "joined owner profile changed");
            }
        }
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!((pages, saved.len()), (41, 1056));
    Ok(saved)
}

async fn exercise(
    identity: Arc<IdentityClient>,
    directory: PathBuf,
    receipt: serde_json::Value,
) -> Result<(), Error> {
    let started = std::time::Instant::now();
    let phase = |name, cursor| {
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"catalog.acceptance.phase", "phase":name, "cursor":cursor,
                "elapsed_ms":started.elapsed().as_millis()
            })
        )
    };
    let vault = VaultClient::new(identity.clone(), directory.clone()).await?;
    assert_eq!(vault.refresh().await?.cursor, 0);
    // The isolated fixture operator activates the empty owner explicitly. The
    // actual client must negotiate it; no fabricated writer facts are installed.
    nddev_device_sync_accounts::runtime::timeout(std::time::Duration::from_secs(15), async {
        loop {
            settle(&vault).await?;
            let crate::storage::Reply::WriterSnapshot(writer) = vault
                .journal
                .call(crate::storage::Command::WriterSnapshot)
                .await?
            else {
                return Err(Error::Invalid);
            };
            if history_replica::facts(&writer)?
                .confirmed
                .is_some_and(|facts| facts.mode == replica::WriterMode::V3)
            {
                return Ok::<_, Error>(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(dependency)??;
    vault
        .save_record(
            Some("catalog-credential".into()),
            0,
            None,
            "Generated invalid credential".into(),
            String::new(),
            Zeroizing::new("intentionally-invalid-github-value".into()),
        )
        .await?;
    settle(&vault).await?;
    let context = ObservationContext {
        principal: GithubAccountId::new(1).unwrap(),
        selection: CredentialSelection::new("catalog-credential".into(), 1, None).unwrap(),
        scan_id: "generated-catalog".into(),
    };
    let mut values = (1..=32)
        .map(|id| ObservationData::Owner {
            owner: GithubOwner {
                id: GithubAccountId::new(id).unwrap(),
                kind: if id == 1 {
                    GithubOwnerKind::User
                } else {
                    GithubOwnerKind::Organization
                },
                login: format!("generated-owner-{id}"),
            },
        })
        .collect::<Vec<_>>();
    values.extend((1..=1024).map(|id| ObservationData::Repository {
        repository: RepositoryFact {
            id: RepositoryId::new(id).unwrap(),
            owner_id: GithubAccountId::new(1 + (id - 1) % 32).unwrap(),
            name: format!("generated-repository-{id}"),
            visibility: RepositoryVisibility::Private,
            archived: false,
            default_branch: Some("main".into()),
        },
    }));
    let mut expected: BTreeMap<_, _> = values
        .iter()
        .map(|data| {
            let key = match data {
                ObservationData::Owner { owner } => format!("github:owner:{}", owner.id.value()),
                ObservationData::Repository { repository } => {
                    format!("github:repo:{}", repository.id.value())
                }
                ObservationData::ScopeScan { .. } => {
                    unreachable!("only generated owner/repository facts")
                }
            };
            (key, (data.clone(), 1))
        })
        .collect();
    assert_eq!(publish(&vault, &context, &values).await?, 1056);
    let first = settle(&vault).await?;
    assert_eq!(first.cursor, 1057); // One credential and one write per fact.
    assert!(
        catalog(&vault).await? == expected,
        "published catalog differs from input"
    );
    phase("published", first.cursor);
    let reader_directory = directory.join("reader");
    let reader = VaultClient::new(identity.clone(), reader_directory.clone()).await?;
    assert_eq!(settle(&reader).await?.cursor, first.cursor);
    assert!(
        catalog(&reader).await? == expected,
        "received catalog differs from input"
    );
    assert_eq!(publish(&vault, &context, &values).await?, 0);
    assert_eq!(settle(&vault).await?.cursor, first.cursor);
    phase("unchanged", first.cursor);
    let changed = values
        .iter()
        .filter_map(|value| match value {
            ObservationData::Repository { repository } if repository.id.value() % 32 == 0 => {
                let mut repository = repository.clone();
                repository.archived = true;
                Some(ObservationData::Repository { repository })
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(publish(&vault, &context, &changed).await?, 32);
    for value in changed {
        let ObservationData::Repository { repository } = &value else {
            unreachable!()
        };
        let key = format!("github:repo:{}", repository.id.value());
        *expected.get_mut(&key).unwrap() = (value, 2);
    }
    let end = settle(&vault).await?;
    assert_eq!(end.cursor, first.cursor + 32);
    assert_eq!(settle(&reader).await?.cursor, end.cursor);
    assert!(
        catalog(&vault).await? == expected,
        "updated catalog differs from input"
    );
    assert!(
        catalog(&reader).await? == expected,
        "received changes differ from input"
    );
    phase("changes_converged", end.cursor);
    assert_eq!(
        expected
            .values()
            .filter(|(_, revision)| *revision == 2)
            .count(),
        32
    );
    drop(reader);
    super::tests::fixture_mode(&receipt, "offline").await?;
    let reopened = VaultClient::new(identity, reader_directory).await?;
    let local = reopened.refresh_local().await?;
    assert_eq!(
        (local.cursor, local.pending, local.conflicts),
        (end.cursor, 0, 0)
    );
    assert!(
        catalog(&reopened).await? == expected,
        "offline catalog differs from input"
    );
    phase("offline_reopened", end.cursor);
    Ok(())
}

#[tokio::test]
#[ignore = "requires an owned --fixture-sync3 PostgreSQL/Mailpit fixture and actual native credentials"]
async fn actual_1024_catalog_http_replay_and_offline_reopen() {
    let (receipt, identity) = super::tests::fixture_identity().await;
    let directory =
        std::env::temp_dir().join(format!("nds-catalog-acceptance-{}", uuid::Uuid::new_v4()));
    let store = identity.vault_credentials().unwrap();
    // Join owns panic cleanup as well as ordinary Result failures.
    let task = exercise(identity.clone(), directory.clone(), receipt.clone());
    let result = tokio::spawn(async move {
        nddev_device_sync_accounts::runtime::timeout(std::time::Duration::from_secs(900), task)
            .await
            .expect("catalog acceptance exceeded its deadline")
    })
    .await;
    let restored = super::tests::fixture_mode(&receipt, "online").await;
    let deleted = after_io(|| store.delete()).await;
    let logged_out = after_io(|| identity.logout()).await;
    let removed = std::fs::remove_dir_all(directory);
    restored.unwrap();
    deleted.unwrap();
    logged_out.unwrap();
    removed.unwrap();
    result.unwrap().unwrap();
}
