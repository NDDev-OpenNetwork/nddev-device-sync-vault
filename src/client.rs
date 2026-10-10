use crate::{
    Error, codec,
    crypto::{Grant, Invitation, Pairing, Scope, VaultKey},
    journal::Journal,
};
use nddev_device_sync_accounts::{IdentityClient, SyncRequest, sync_wire as wire};
use nddev_device_sync_domain::{
    DeviceId,
    sync::{EncryptedPayload, EntityKind, MAX_PLAIN_BYTES, Operation},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::view::{RecordView, VaultView};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    deleted: bool,
    title: String,
    username: String,
    secret: Zeroizing<String>,
}

pub struct VaultClient {
    identity: Arc<IdentityClient>,
    scope: Scope,
    journal: Journal,
    gate: Arc<Semaphore>,
    io: Arc<Semaphore>,
    view: Mutex<VaultView>,
    pairing: Mutex<Option<Pairing>>,
    expected_key: Mutex<Option<String>>,
}
fn dependency<E>(_: E) -> Error {
    Error::Unavailable
}
impl VaultClient {
    pub async fn new(identity: Arc<IdentityClient>, data_dir: PathBuf) -> Result<Self, Error> {
        let scope = scope(&identity)?;
        let encoded =
            serde_json::to_vec(&(&scope.origin, &scope.tenant, &scope.user, &scope.device))
                .map_err(dependency)?;
        let name = format!("{:x}.db", Sha256::digest(encoded));
        let journal =
            tokio::task::spawn_blocking(move || Journal::open(data_dir.join("sync").join(name)))
                .await
                .map_err(dependency)??;
        Ok(Self {
            identity,
            scope,
            journal,
            gate: Arc::new(Semaphore::new(1)),
            io: Arc::new(Semaphore::new(1)),
            view: Mutex::default(),
            pairing: Mutex::default(),
            expected_key: Mutex::default(),
        })
    }
    fn admitted(&self) -> Result<OwnedSemaphorePermit, Error> {
        let current = scope(&self.identity)?;
        if current.device != self.scope.device
            || current.user != self.scope.user
            || current.tenant != self.scope.tenant
        {
            return Err(Error::Locked);
        }
        self.gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)
    }
    async fn local<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Journal) -> Result<T, Error> + Send + 'static,
    ) -> Result<T, Error> {
        let journal = self.journal.clone();
        let permit = self
            .io
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&journal)
        })
        .await
        .map_err(dependency)?
    }
    async fn key(&self) -> Result<Option<VaultKey>, Error> {
        let secret = self
            .identity
            .vault_credentials()
            .map_err(dependency)?
            .read()
            .await
            .map_err(dependency)?;
        let Some(secret) = secret else {
            return Ok(None);
        };
        let keys = key_registry(secret.as_slice())?;
        let expected = self
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        Ok(match expected {
            Some(expected) => keys.into_iter().find(|key| key.id() == expected),
            None => keys.into_iter().next(),
        })
    }
    pub fn snapshot(&self) -> VaultView {
        let mut pairing = self.pairing.lock().unwrap_or_else(|e| e.into_inner());
        if pairing.as_ref().is_some_and(|pairing| !pairing.active()) {
            pairing.take();
            self.view
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .pairing_code
                .clear();
        }
        drop(pairing);
        self.view.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    async fn update_view(&self) -> Result<VaultView, Error> {
        let key = self.key().await?;
        let (pending, conflicts, cursor) = self
            .local(|journal| {
                let (pending, conflicts) = journal.counts()?;
                Ok((pending, conflicts, journal.cursor()?))
            })
            .await?;
        let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
        view.unlocked = key.is_some();
        view.key_id = key.as_ref().map(VaultKey::id).unwrap_or_default();
        view.pending = pending;
        view.conflicts = conflicts;
        view.cursor = cursor;
        Ok(view.clone())
    }
    pub async fn refresh(&self) -> Result<VaultView, Error> {
        let _permit = self.admitted()?;
        self.discover_key().await?;
        self.update_view().await
    }
    async fn discover_key(&self) -> Result<(), Error> {
        let reply = self
            .identity
            .sync_request(SyncRequest::Page { after: 0, limit: 1 })
            .await
            .map_err(dependency)?;
        let page: wire::SyncPage =
            serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
        let expected = if let Some(entry) = page.entries.first() {
            let body = serde_json::to_vec(&entry.operation).map_err(dependency)?;
            codec::operation(&entry.operation, body.len())?;
            Some(entry.operation.payload.key_id.clone())
        } else {
            if page.next_after_seq != 0 || page.has_more {
                return Err(Error::Invalid);
            }
            None
        };
        *self.expected_key.lock().unwrap_or_else(|e| e.into_inner()) = expected;
        Ok(())
    }
    async fn retain_key(&self, key: &VaultKey) -> Result<(), Error> {
        let store = self.identity.vault_credentials().map_err(dependency)?;
        let previous = store.read().await.map_err(dependency)?;
        let mut keys = previous
            .as_ref()
            .map(|value| key_registry(value.as_slice()))
            .transpose()?
            .unwrap_or_default();
        if let Some(existing) = keys.iter().find(|existing| existing.id() == key.id()) {
            return if existing.native_secret().as_slice() == key.native_secret().as_slice() {
                Ok(())
            } else {
                Err(Error::Authentication)
            };
        }
        if keys.len() >= 4 {
            return Err(Error::Busy);
        }
        let added = VaultKey::from_native_secret(key.native_secret().as_slice())?;
        keys.push(added);
        let mut bytes = Zeroizing::new(vec![1, keys.len() as u8]);
        for key in &keys {
            bytes.extend_from_slice(key.native_secret().as_slice());
        }
        store.write(bytes.as_slice()).await.map_err(dependency)?;
        let verified = store
            .read()
            .await
            .map_err(dependency)?
            .ok_or(Error::Unavailable)?;
        if verified.as_slice() != bytes.as_slice() {
            return Err(Error::Unavailable);
        }
        Ok(())
    }
    /// Explicit initial creation requires freshly observed empty remote history.
    /// Existing native key material is never replaced, even after uncertainty.
    pub async fn create(&self) -> Result<VaultView, Error> {
        let _permit = self.admitted()?;
        self.discover_key().await?;
        let established = self
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some();
        if established {
            return if self.key().await?.is_some() {
                self.update_view().await
            } else {
                Err(Error::Locked)
            };
        }
        let lock = self.local(Journal::key_lock).await?;
        if self.key().await?.is_none() {
            let key = VaultKey::generate()?;
            self.retain_key(&key).await?;
        }
        drop(lock);
        let pending = self.local(Journal::pending).await?;
        if pending.is_empty() {
            let body = Zeroizing::new(
                serde_json::to_vec(
                    &serde_json::json!({"schema_version":1,"device_id":self.scope.device}),
                )
                .map_err(dependency)?,
            );
            self.put_inner(
                EntityKind::DeviceState,
                self.scope.device.clone(),
                body.as_slice(),
            )
            .await?;
        }
        self.synchronize_inner().await?;
        self.discover_key().await?;
        self.update_view().await
    }
    pub async fn put(
        &self,
        kind: EntityKind,
        id: String,
        plaintext: Zeroizing<Vec<u8>>,
    ) -> Result<String, Error> {
        let _permit = self.admitted()?;
        self.put_inner(kind, id, plaintext.as_slice()).await
    }
    async fn put_inner(
        &self,
        kind: EntityKind,
        id: String,
        plaintext: &[u8],
    ) -> Result<String, Error> {
        if plaintext.len() > MAX_PLAIN_BYTES {
            return Err(Error::Invalid);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let entity_id = id.clone();
        let existing = self
            .local(move |journal| journal.entity(kind.as_str(), &entity_id))
            .await?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        let mut operation = Operation {
            id: operation_id.clone(),
            device: DeviceId::new(&self.scope.device).map_err(dependency)?,
            entity_kind: kind,
            entity_id: id,
            base_revision: existing.map_or(0, |entity| entity.revision),
            idempotency_key: operation_id,
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        };
        operation.payload = key.encrypt(&self.scope, &operation, plaintext)?;
        let bytes = codec::body(&operation)?;
        let id = self.local(move |journal| journal.enqueue(bytes)).await?;
        self.update_view().await?;
        Ok(id)
    }
    pub async fn save_record(
        &self,
        id: Option<String>,
        title: String,
        username: String,
        secret: Zeroizing<String>,
    ) -> Result<String, Error> {
        let _permit = self.admitted()?;
        if title.trim().is_empty()
            || title.chars().count() > 128
            || username.len() > 254
            || secret.len() > MAX_PLAIN_BYTES
        {
            return Err(Error::Invalid);
        }
        let record = Record {
            version: 1,
            deleted: false,
            title,
            username,
            secret,
        };
        let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(dependency)?);
        let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.put_inner(EntityKind::VaultRecord, id, plaintext.as_slice())
            .await
    }
    pub async fn records(&self) -> Result<Vec<RecordView>, Error> {
        let _permit = self.admitted()?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let entities = self.local(|journal| journal.list("vault_record")).await?;
        let mut values = Vec::new();
        for (id, entity) in entities {
            let wire: wire::SyncOperation =
                serde_json::from_slice(&entity.body).map_err(dependency)?;
            let operation = codec::operation(&wire, entity.body.len())?;
            let plaintext = key.decrypt(&self.scope, &operation)?;
            let record: Record = serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
            if record.version != 1 {
                return Err(Error::Invalid);
            }
            if !record.deleted {
                values.push(RecordView {
                    id,
                    title: record.title,
                    username: record.username,
                    revision: entity.revision,
                    conflicted: entity.conflicted,
                });
            }
        }
        Ok(values)
    }
    /// Native use only. The presentation wrapper delegates to native clipboard
    /// or declared provider adapters; it never returns this value through FFI.
    pub async fn native_secret(&self, id: String) -> Result<Zeroizing<String>, Error> {
        let _permit = self.admitted()?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let entity = self
            .local(move |journal| journal.entity("vault_record", &id))
            .await?
            .ok_or(Error::Invalid)?;
        let wire: wire::SyncOperation = serde_json::from_slice(&entity.body).map_err(dependency)?;
        let operation = codec::operation(&wire, entity.body.len())?;
        let plaintext = key.decrypt(&self.scope, &operation)?;
        let record: Record = serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
        if record.deleted || record.version != 1 {
            return Err(Error::Invalid);
        }
        Ok(record.secret)
    }
    pub async fn synchronize(&self) -> Result<VaultView, Error> {
        let _permit = self.admitted()?;
        tokio::time::timeout(std::time::Duration::from_secs(60), self.synchronize_inner())
            .await
            .map_err(dependency)?
    }
    async fn synchronize_inner(&self) -> Result<VaultView, Error> {
        for pending in self.local(Journal::pending).await? {
            let result = self
                .identity
                .sync_request(SyncRequest::Append(pending.body))
                .await
                .map_err(dependency)?;
            if !matches!(result.status, 201 | 409) {
                return Err(Error::Invalid);
            }
            self.local(move |journal| journal.acknowledge(&pending.id, &result.body))
                .await?;
        }
        for _ in 0..16 {
            let cursor = self.local(Journal::cursor).await?;
            let result = self
                .identity
                .sync_request(SyncRequest::Page {
                    after: cursor,
                    limit: 2,
                })
                .await
                .map_err(dependency)?;
            let page: wire::SyncPage =
                serde_json::from_slice(&result.body).map_err(|_| Error::Invalid)?;
            let more = page.has_more;
            self.local(move |journal| journal.ingest(&page)).await?;
            if !more {
                break;
            }
        }
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .last_sync_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(dependency)?
            .as_secs();
        self.update_view().await
    }
    pub fn start_pairing(&self) -> Result<String, Error> {
        let _permit = self.admitted()?;
        let pairing = Pairing::start(&self.scope.device)?;
        let code = pairing.code()?;
        *self.pairing.lock().unwrap_or_else(|e| e.into_inner()) = Some(pairing);
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pairing_code = code.clone();
        Ok(code)
    }
    pub async fn grant_pairing(&self, code: String) -> Result<String, Error> {
        let _permit = self.admitted()?;
        self.identity.refresh_devices().await.map_err(dependency)?;
        self.discover_key().await?;
        if code.len() > 2048 {
            return Err(Error::Invalid);
        }
        let invitation: Invitation = serde_json::from_str(&code).map_err(|_| Error::Invalid)?;
        // The owner explicitly chooses the freshly verified recipient in UI.
        let peer = self.identity.view().devices.into_iter().any(|device| {
            device.device_id == invitation.recipient_device && !device.revoked && !device.is_current
        });
        if !peer {
            return Err(Error::Invalid);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        serde_json::to_string(&crate::crypto::grant(&self.scope, &key, invitation)?)
            .map_err(dependency)
    }
    pub async fn import_pairing(&self, code: String) -> Result<VaultView, Error> {
        let _permit = self.admitted()?;
        self.identity.refresh_devices().await.map_err(dependency)?;
        self.discover_key().await?;
        if code.len() > 2048 {
            return Err(Error::Invalid);
        }
        let lock = self.local(Journal::key_lock).await?;
        if self.key().await?.is_some() {
            return Err(Error::KeyExists);
        }
        let grant: Grant = serde_json::from_str(&code).map_err(|_| Error::Invalid)?;
        let peer = self.identity.view().devices.into_iter().any(|device| {
            device.device_id == grant.sender_device && !device.revoked && !device.is_current
        });
        if !peer {
            return Err(Error::Invalid);
        }
        let pairing = self
            .pairing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .ok_or(Error::Invalid)?;
        let key = pairing.accept(&self.scope, grant)?;
        let expected = self
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(Error::Invalid)?;
        if key.id() != expected {
            return Err(Error::Authentication);
        }
        self.retain_key(&key).await?;
        let restored = self.key().await?.ok_or(Error::Unavailable)?;
        if restored.id() != key.id() {
            return Err(Error::Unavailable);
        }
        drop(lock);
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pairing_code
            .clear();
        self.update_view().await
    }
}
fn key_registry(secret: &[u8]) -> Result<Vec<VaultKey>, Error> {
    if secret.len() == 48 {
        return Ok(vec![VaultKey::from_native_secret(secret)?]);
    }
    if secret.len() < 2
        || secret[0] != 1
        || !(1..=4).contains(&secret[1])
        || secret.len() != 2 + 48 * secret[1] as usize
    {
        return Err(Error::Invalid);
    }
    let mut keys = Vec::new();
    for value in secret[2..].as_chunks::<48>().0 {
        let key = VaultKey::from_native_secret(value)?;
        if keys
            .iter()
            .any(|existing: &VaultKey| existing.id() == key.id())
        {
            return Err(Error::Invalid);
        }
        keys.push(key);
    }
    Ok(keys)
}

fn scope(identity: &IdentityClient) -> Result<Scope, Error> {
    let view = identity.view();
    if !view.authenticated || !view.session_verified || view.credential_revalidation_required {
        return Err(Error::Locked);
    }
    let device = view
        .devices
        .into_iter()
        .find(|device| device.is_current && !device.revoked)
        .ok_or(Error::Locked)?;
    Ok(Scope {
        origin: identity.origin(),
        tenant: view.tenant_id,
        user: view.user_id,
        device: device.device_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires an owned PostgreSQL/Mailpit fixture and actual native credentials"]
    async fn actual_native_vault_outbox_backend_and_process_recreation() {
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
        )
        .unwrap();
        let endpoint = receipt["base_url"].as_str().unwrap();
        let mailbox = receipt["mailpit_url"].as_str().unwrap();
        let owner = receipt["owner_email"].as_str().unwrap();
        assert!(
            endpoint.starts_with("http://127.0.0.1:")
                && mailbox.starts_with("http://127.0.0.1:")
                && owner.ends_with(".invalid")
        );
        let identity = Arc::new(IdentityClient::new(endpoint).unwrap());
        identity.refresh().await.unwrap();
        identity.request_email(owner.into(), "en").await.unwrap();
        let http = reqwest::Client::builder().no_proxy().build().unwrap();
        let code = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let messages: serde_json::Value = http
                    .get(format!("{mailbox}/api/v1/messages"))
                    .send()
                    .await
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if let Some(id) = messages["messages"]
                    .as_array()
                    .and_then(|values| values.first())
                    .and_then(|value| value["ID"].as_str())
                {
                    let message: serde_json::Value = http
                        .get(format!("{mailbox}/api/v1/message/{id}"))
                        .send()
                        .await
                        .unwrap()
                        .json()
                        .await
                        .unwrap();
                    if let Some((_, suffix)) =
                        message["Text"].as_str().unwrap().split_once("code: ")
                    {
                        break suffix.chars().take(8).collect::<String>();
                    }
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        })
        .await
        .unwrap();
        identity.verify_email(code).await.unwrap();
        identity
            .enroll_device("Native vault acceptance".into())
            .await
            .unwrap();
        let directory =
            std::env::temp_dir().join(format!("nds-vault-acceptance-{}", uuid::Uuid::new_v4()));
        let vault = VaultClient::new(identity.clone(), directory.clone())
            .await
            .unwrap();
        let store = identity.vault_credentials().unwrap();
        let outcome = async {
            let created = vault.create().await?;
            assert!(created.unlocked && created.cursor == 1);
            let key = store.read().await.map_err(dependency)?.unwrap();
            let secret = "PRIVATE_ACTUAL_VAULT_VALUE";
            vault
                .save_record(
                    Some("acceptance-record".into()),
                    "Acceptance record".into(),
                    "test-user".into(),
                    Zeroizing::new(secret.into()),
                )
                .await?;
            assert_eq!(vault.snapshot().pending, 1);
            let view = vault.synchronize().await?;
            assert_eq!(view.pending, 0);
            assert_eq!(view.cursor, 2);
            let records = vault.records().await?;
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].title, "Acceptance record");
            assert_eq!(
                vault
                    .native_secret("acceptance-record".into())
                    .await?
                    .as_str(),
                secret
            );
            let restarted = VaultClient::new(identity.clone(), directory.clone()).await?;
            assert_eq!(restarted.refresh().await?.key_id, created.key_id);
            assert_eq!(
                restarted
                    .native_secret("acceptance-record".into())
                    .await?
                    .as_str(),
                secret
            );
            assert_eq!(
                store.read().await.map_err(dependency)?.unwrap().as_slice(),
                key.as_slice()
            );
            // Actual persisted SQLite bytes contain ciphertext, not native keys
            // or the record's plaintext. Native credentials use a separate store.
            let path = vault.journal.path_for_acceptance();
            let data = std::fs::read(path).map_err(dependency)?;
            assert!(
                !data
                    .windows(secret.len())
                    .any(|value| value == secret.as_bytes())
            );
            assert!(!data.windows(key.len()).any(|value| value == key.as_slice()));
            Ok::<_, Error>(())
        }
        .await;
        store.delete().await.unwrap();
        identity.logout().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        outcome.unwrap();
    }
}
