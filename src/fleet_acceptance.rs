//! Ordinary fleet acceptance over real Accounts, Secret Service, SQLite and HTTP.
//! The supervisor owns isolated native stores and one generated server fixture.
//! A genuine fixture session is restored through private IPC; no runtime login
//! bypass or substitute credential backend is introduced.
use super::catalog_acceptance::{catalog, generated_values, originals, publish, settle};
use super::*;
use nddev_device_sync_accounts::SessionStore;
use nddev_device_sync_domain::repositories::catalog::{
    GithubAccountId,
    observations::{
        Capture, ObservationContext, ObservationData, ObservationSource, RepositoryObservation,
    },
};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{BufRead, BufReader, Read, Write},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
};
use tokio_util::sync::CancellationToken;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

// The generated session stays in Rust/native stores. The Python supervisor
// never receives credentials; this private socket serves only owned Rust peers.
async fn distribute_session(endpoint: String, path: PathBuf, peers: usize) -> Result<()> {
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    listener.set_nonblocking(true)?;
    let store = SessionStore::for_endpoint(&endpoint)?;
    let mut served = 0;
    while served < peers {
        match listener.accept() {
            Ok((mut peer, _)) => {
                peer.set_write_timeout(Some(std::time::Duration::from_secs(5)))?;
                let token = store.read().await?.ok_or("fixture session unavailable")?;
                peer.write_all(&token)?;
                served += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await
            }
            Err(error) => return Err(error.into()),
        }
    }
    drop(listener);
    std::fs::remove_file(path)?;
    Ok(())
}

fn receive(reader: &mut BufReader<UnixStream>) -> Result<Value> {
    let mut text = Zeroizing::new(String::new());
    let size = reader.by_ref().take(65_537).read_line(&mut text)?;
    if size == 0 || size > 65_536 || !text.ends_with('\n') {
        return Err("invalid fleet command frame".into());
    }
    Ok(serde_json::from_str(&text)?)
}

fn send(stream: &mut UnixStream, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *stream, value)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    Ok(())
}

fn context() -> ObservationContext {
    ObservationContext {
        principal: GithubAccountId::new(1).unwrap(),
        selection: CredentialSelection::new("catalog-credential".into(), 1, None).unwrap(),
        scan_id: uuid::Uuid::new_v4().to_string(),
    }
}

fn changed(id: u64, offline: bool) -> ObservationData {
    let mut data = generated_values()
        .into_iter()
        .find(|value| {
            matches!(value,
        ObservationData::Repository { repository } if repository.id.value() == id)
        })
        .unwrap();
    if let ObservationData::Repository { repository } = &mut data {
        repository.archived = true;
        if offline {
            repository.default_branch = Some("fleet-offline".into());
        }
    }
    data
}

async fn queue(vault: &VaultClient, data: ObservationData) -> Result<()> {
    let context = context();
    let fence = Arc::new(vault.identity.local_use_fence().await?);
    let read = vault
        .capture_repository_observations(context.selection.clone(), fence, CancellationToken::new())
        .await?;
    let observation = RepositoryObservation {
        source: ObservationSource {
            context: context.clone(),
            page: Some(1),
        },
        data,
    };
    let key = observation.key();
    let before = read
        .baselines()
        .into_iter()
        .find(|(id, _)| *id == key.entity_id())
        .unwrap()
        .1;
    let candidate = Capture::before_read(key, before)?.confirm(observation)?;
    assert!(matches!(
        vault
            .publish_repository_observation(&read, candidate, Some(&context), now_ms()?)
            .await?,
        RepositoryPublication::Queued { .. }
    ));
    Ok(())
}

async fn drain(vault: &VaultClient) -> Result<VaultView> {
    use nddev_device_sync_application::lifecycle::{BatchOutcome, ReplicaSchedule};
    let mut schedule = ReplicaSchedule::default();
    for _ in 0..128 {
        let before = originals(vault)?;
        let result = vault.synchronize_attempt(false).await?.result;
        for (id, bytes) in originals(vault)? {
            assert!(before.get(&id) == Some(&bytes), "pending original changed");
        }
        match result {
            Ok(progress) if progress.inbox_at_head && progress.view.pending == 0 => {
                return Ok(progress.view);
            }
            Ok(_) => {
                schedule.after(BatchOutcome::CatchingUp);
            }
            Err(Error::Busy) => {
                tokio::time::sleep(schedule.after(BatchOutcome::Retryable).unwrap()).await
            }
            Err(error) => return Err(error.into()),
        }
    }
    Err("fleet catch-up did not converge".into())
}

async fn resolve(vault: &VaultClient) -> Result<()> {
    if drain(vault).await?.conflicts == 0 {
        return Ok(());
    }
    let before = context();
    let read = Arc::new(
        vault
            .capture_repository_observations(
                before.selection,
                Arc::new(vault.identity.local_use_fence().await?),
                CancellationToken::new(),
            )
            .await?,
    );
    let key = nddev_device_sync_domain::repositories::catalog::observations::ObservationKey::parse(
        "github:repo:1",
    )?;
    let resolution = vault.repository_resolution(read, &key).await?;
    let reread = resolution
        .fresh_read()?
        .ok_or("resolution requires catch-up")?;
    // Generated input is supplied after the actual retained-family capture.
    // This qualifies NDS resolution, not a GitHub provider read.
    let fresh = RepositoryObservation {
        source: ObservationSource {
            context: context(),
            page: Some(1),
        },
        data: changed(1, false),
    };
    assert!(matches!(
        vault
            .resolve_repository_observation(
                &resolution,
                reread,
                fresh.clone(),
                Some(&fresh.source.context),
                now_ms()?
            )
            .await?,
        RepositoryPublication::Queued { .. }
    ));
    settle(vault).await?;
    Ok(())
}

async fn inspect(vault: &VaultClient, count: usize, updated: bool, offline: bool) -> Result<Value> {
    let view = settle(vault).await?;
    let saved = catalog(vault).await?;
    let mut expected = generated_values();
    if updated {
        for data in &mut expected {
            if let ObservationData::Repository { repository } = data {
                if repository.id.value() == 1 {
                    repository.archived = true;
                }
                if offline && (33..33 + count as u64).contains(&repository.id.value()) {
                    repository.archived = true;
                    repository.default_branch = Some("fleet-offline".into());
                }
            }
        }
    }
    for data in expected {
        let observation = RepositoryObservation {
            source: ObservationSource {
                context: context(),
                page: Some(1),
            },
            data: data.clone(),
        };
        assert!(
            saved
                .get(&observation.key().entity_id())
                .is_some_and(|(actual, _)| *actual == data),
            "catalog differs from generated inputs"
        );
    }
    let digest = base16ct::lower::encode_string(&Sha256::digest(serde_json::to_vec(&saved)?));
    Ok(
        json!({"cursor":view.cursor,"pending":view.pending,"conflicts":view.conflicts,"facts":saved.len(),"digest":digest}),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the owned Linux fleet supervisor and a real local server fixture"]
async fn native_fleet_member() -> Result<()> {
    let root = PathBuf::from(std::env::var("NDS_FLEET_ROOT")?);
    assert!(root.is_absolute() && root.is_dir());
    for name in ["XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"] {
        assert!(PathBuf::from(std::env::var(name)?).starts_with(&root));
    }
    let index: usize = std::env::var("NDS_FLEET_INDEX")?.parse()?;
    let count: usize = std::env::var("NDS_FLEET_COUNT")?.parse()?;
    let epoch: u8 = std::env::var("NDS_FLEET_EPOCH")?.parse()?;
    assert!((2..=32).contains(&count) && index < count && epoch <= 1);
    let receipt: Value =
        serde_json::from_slice(&std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT")?)?)?;
    let endpoint = receipt["base_url"].as_str().ok_or("missing endpoint")?;
    assert!(
        receipt["owner_email"]
            .as_str()
            .unwrap()
            .ends_with(".invalid")
    );
    let origin = reqwest::Url::parse(endpoint)?;
    assert!(
        origin.scheme() == "http"
            && origin.host_str() == Some("127.0.0.1")
            && origin.port().is_some()
    );
    let mut logger = nddev_device_sync_telemetry::install(nddev_device_sync_telemetry::Config {
        service: "nds-fleet-acceptance".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        repository: "NDDev-Technocracy-OpenNetwork-NDS/nddev-device-sync-vault".into(),
        commit: std::env::var("NDS_FLEET_SOURCE")?,
        channel: "alpha".into(),
        standards: "unreleased".into(),
        environment: "test".into(),
        target_prefixes: vec!["nds_accounts".into(), "nddev_device_sync_vault".into()],
        default_module: "vault".into(),
        debug: None,
    })?;
    let protected = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
        protected(panic);
        if let Some(location) = panic.location()
            && location.file().ends_with("fleet_acceptance.rs")
        {
            eprintln!("Fleet assertion at source line {}", location.line());
        }
    }));
    let mut stream = UnixStream::connect(std::env::var("NDS_FLEET_SOCKET")?)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(3500)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    send(&mut stream, &json!({"index":index,"epoch":epoch}))?;
    let command = receive(&mut reader)?;
    assert_eq!(command["action"], "initialize");
    let identity = if index == 0 && epoch == 0 {
        super::tests::fixture_identity().await.1
    } else {
        if epoch == 0 {
            let mut peer = UnixStream::connect(std::env::var("NDS_FLEET_TOKEN_SOCKET")?)?;
            peer.set_read_timeout(Some(std::time::Duration::from_secs(15)))?;
            let mut token = Zeroizing::new(Vec::new());
            std::io::Read::by_ref(&mut peer)
                .take(129)
                .read_to_end(&mut token)?;
            assert_eq!(token.len(), 43);
            let store = SessionStore::for_endpoint(endpoint)?;
            assert!(store.read().await?.is_none());
            store.write(&token).await?;
        }
        let identity = Arc::new(IdentityClient::new(endpoint)?);
        let view = identity.refresh().await?;
        assert!(view.authenticated);
        if epoch == 0 {
            loop {
                match identity
                    .prepare_device(format!("Fleet device {index}"))
                    .await
                {
                    Ok(_) => break,
                    Err(error) if error.code() == "rate_limited" => {
                        std::fs::write(root.join("rate-wait"), b"device enrollment rate limit")?;
                        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else {
            assert!(view.offline_authorized && !view.current_device_id.is_empty());
        }
        identity
    };
    let vault = VaultClient::new(identity.clone(), root.join("replica")).await?;
    let view = if epoch == 0 {
        vault.refresh().await?
    } else {
        vault.refresh_local().await?
    };
    if epoch == 1 {
        assert_eq!(view.pending, 1);
        let expected: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(root.join("originals.json"))?)?;
        let actual: BTreeMap<_, _> = originals(&vault)?
            .into_iter()
            .map(|(id, b)| (id, base16ct::lower::encode_string(&Sha256::digest(b))))
            .collect();
        assert_eq!(actual, expected);
    }
    let broker = if index == 0 && epoch == 0 {
        let path = PathBuf::from(std::env::var("NDS_FLEET_TOKEN_SOCKET")?);
        let task = tokio::spawn(distribute_session(endpoint.into(), path.clone(), count - 1));
        nddev_device_sync_accounts::runtime::timeout(std::time::Duration::from_secs(5), async {
            while !path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .map_err(|_| "fixture session broker did not start")?;
        Some(task)
    } else {
        None
    };
    #[derive(Serialize)]
    struct Ready<'a> {
        device: &'a str,
        user: &'a str,
        tenant: &'a str,
    }
    let identity_view = identity.view();
    send(
        &mut stream,
        &Ready {
            device: &identity_view.current_device_id,
            user: &identity_view.user_id,
            tenant: &identity_view.tenant_id,
        },
    )?;
    loop {
        let command = receive(&mut reader)?;
        let action = command["action"].as_str().ok_or("missing fleet action")?;
        let result = nddev_device_sync_accounts::runtime::timeout(
            std::time::Duration::from_secs(600),
            async {
                match action {
                    "seed" => {
                        assert_eq!(index, 0);
                        for _ in 0..100 {
                            drain(&vault).await?;
                            let crate::storage::Reply::WriterSnapshot(w) = vault
                                .journal
                                .call(crate::storage::Command::WriterSnapshot)
                                .await?
                            else {
                                return Err("missing writer state".into());
                            };
                            if history_replica::facts(&w)?
                                .confirmed
                                .is_some_and(|f| f.mode == replica::WriterMode::V3)
                            {
                                break;
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }
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
                        assert_eq!(
                            publish(&vault, &context(), &generated_values()).await?,
                            1056
                        );
                        inspect(&vault, count, false, false).await
                    }
                    "inspect" => {
                        inspect(
                            &vault,
                            count,
                            command["updated"] == true,
                            command["offline"] == true,
                        )
                        .await
                    }
                    "unchanged" => {
                        let cursor = settle(&vault).await?.cursor;
                        assert_eq!(publish(&vault, &context(), &generated_values()).await?, 0);
                        assert_eq!(settle(&vault).await?.cursor, cursor);
                        Ok(json!({"unchanged":true,"cursor":cursor}))
                    }
                    "race" => {
                        queue(&vault, changed(1, false)).await?;
                        Ok(json!({"queued":true}))
                    }
                    "drain" => {
                        let v = drain(&vault).await?;
                        Ok(json!({"cursor":v.cursor,"pending":v.pending,"conflicts":v.conflicts}))
                    }
                    "resolve" => {
                        resolve(&vault).await?;
                        Ok(json!({"resolved":true}))
                    }
                    "offline" => {
                        let before = vault.refresh_local().await?;
                        queue(&vault, changed(33 + index as u64, true)).await?;
                        let after = vault.refresh_local().await?;
                        assert_eq!(after.cursor, before.cursor);
                        assert!(after.local_revision > before.local_revision);
                        assert_eq!(after.pending, 1);
                        let data: BTreeMap<_, _> = originals(&vault)?
                            .into_iter()
                            .map(|(id, b)| (id, base16ct::lower::encode_string(&Sha256::digest(b))))
                            .collect();
                        std::fs::write(root.join("originals.json"), serde_json::to_vec(&data)?)?;
                        Ok(json!({"pending":1,"cursor":after.cursor}))
                    }
                    "stop" => Ok(json!({"stopped":true})),
                    "finish" => {
                        if index == 0 {
                            assert_eq!(
                                identity
                                    .refresh_devices()
                                    .await?
                                    .devices
                                    .iter()
                                    .filter(|d| !d.revoked)
                                    .count(),
                                count
                            );
                            identity.logout().await?;
                        }
                        Ok(json!({"finished":true}))
                    }
                    _ => Err("unknown fleet action".into()),
                }
            },
        )
        .await
        .map_err(|_| "fleet action deadline")??;
        send(&mut stream, &result)?;
        if matches!(action, "stop" | "finish") {
            break;
        }
    }
    if let Some(broker) = broker {
        broker.await??;
    }
    drop(vault);
    drop(identity);
    logger.shutdown();
    let output = logger.control.output_health();
    assert_eq!(
        (
            output.pending_events,
            output.dropped_events,
            output.write_failures
        ),
        (0, 0, 0)
    );
    assert!(!output.shutdown_incomplete);
    assert_eq!(logger.control.rejected_fields_or_events(), 0);
    Ok(())
}
