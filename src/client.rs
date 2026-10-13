use crate::{
    Error, codec,
    crypto::{Scope, VaultKey},
    storage::Storage,
};
use nddev_device_sync_accounts::{IdentityClient, SyncRequest, sync_wire as wire};
use nddev_device_sync_application::replica::{self, ReplicaPort, VerifiedPage};
use nddev_device_sync_domain::vault::Record;
use nddev_device_sync_domain::{
    DeviceId,
    sync::{EncryptedPayload, EntityKind, MAX_PLAIN_BYTES, Operation},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;

use crate::view::{RecordPage, RecordView, StatePage, StateView, VaultView};
use nddev_device_sync_domain::state::{Reachability, Snapshot, State};

struct Expected {
    revision: u64,
    cursor: Option<u64>,
    pending: Option<String>,
}
pub struct VaultClient {
    identity: Arc<IdentityClient>,
    scope: Scope,
    journal: Storage,
    gate: Arc<Semaphore>,
    sync_gate: Arc<Semaphore>,
    view: Mutex<VaultView>,
    expected_key: Mutex<Option<String>>,
}
fn dependency<E>(_: E) -> Error {
    Error::Unavailable
}
fn identity_failure(error: nddev_device_sync_accounts::ClientError) -> Error {
    use nddev_device_sync_accounts::ClientError;
    match error {
        ClientError::Busy => Error::Busy,
        ClientError::DeviceRevoked | ClientError::RevalidationRequired => Error::Locked,
        _ => Error::Unavailable,
    }
}
impl VaultClient {
    pub async fn new(identity: Arc<IdentityClient>, data_dir: PathBuf) -> Result<Self, Error> {
        let scope = scope(&identity)?;
        let encoded =
            serde_json::to_vec(&(&scope.origin, &scope.tenant, &scope.user, &scope.device))
                .map_err(dependency)?;
        let name = format!("{:x}.db", Sha256::digest(encoded));
        let journal = Storage::open(data_dir.join("sync").join(name)).await?;
        let client = Self {
            identity,
            scope,
            journal,
            gate: Arc::new(Semaphore::new(1)),
            sync_gate: Arc::new(Semaphore::new(1)),
            view: Mutex::default(),
            expected_key: Mutex::default(),
        };
        client.update_view().await?;
        #[cfg(target_arch = "wasm32")]
        {
            let persistent = crate::browser::request_persistence().await;
            client
                .view
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .browser_persistent = Some(persistent);
            tracing::event!(target:"nddev_device_sync_vault",tracing::Level::INFO,{
                event.name="vault.storage.persistence",module="vault",scope="io",
                outcome=if persistent {"accepted"} else {"unavailable"}
            });
        }
        {
            let mut view = client.view.lock().unwrap_or_else(|e| e.into_inner());
            view.catching_up = view.pending > 0 || view.last_sync_at == 0;
        }
        Ok(client)
    }
    fn authorized(&self) -> Result<(), Error> {
        let current = scope(&self.identity)?;
        if current.device != self.scope.device
            || current.user != self.scope.user
            || current.tenant != self.scope.tenant
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
    fn admitted(&self) -> Result<OwnedSemaphorePermit, Error> {
        self.authorized()?;
        self.gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)
    }
    async fn key(&self) -> Result<Option<VaultKey>, Error> {
        if let Err(error) = self.identity.authorize_local().await {
            let error = identity_failure(error);
            if error == Error::Locked {
                let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
                view.unlocked = false;
                view.key_id.clear();
                view.sync_error = error.code();
            }
            return Err(error);
        }
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
        if self.authorized().is_err() {
            return VaultView {
                sync_error: Error::Locked.code(),
                ..VaultView::default()
            };
        }
        self.view.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
    async fn update_view(&self) -> Result<VaultView, Error> {
        let key = self.key().await?;
        let (pending, conflicts, cursor, last_sync_at, local_revision) =
            self.journal.stats().await?;
        let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
        if local_revision < view.local_revision {
            return Ok(view.clone());
        }
        view.unlocked = key.is_some();
        view.key_id = key.as_ref().map(VaultKey::id).unwrap_or_default();
        view.pending = pending;
        view.conflicts = conflicts;
        view.cursor = cursor;
        view.local_revision = local_revision;
        view.catching_up |= pending > 0;
        view.last_sync_at = last_sync_at;
        Ok(view.clone())
    }
    pub async fn refresh(&self) -> Result<VaultView, Error> {
        self.synchronize().await
    }
    /// Re-read durable local state after a resume or another tab's notification.
    /// Does not turn a cached authorization into a live server observation.
    pub async fn refresh_local(&self) -> Result<VaultView, Error> {
        let _permit = self.admitted()?;
        self.update_view().await
    }
    async fn ensure_key(&self) -> Result<(), Error> {
        if !self.identity.view().session_verified {
            let view = self.identity.refresh().await.map_err(identity_failure)?;
            if !view.authenticated {
                return Err(Error::Locked);
            }
            if !view.session_verified {
                return Err(Error::Unavailable);
            }
            self.identity.refresh_devices().await.map_err(dependency)?;
            self.authorized()?;
        }
        self.discover_key().await?;
        let lock = self.journal.key_lock().await?;
        let existing = self.key().await?;
        let material = existing
            .as_ref()
            .map(|key| {
                nddev_device_sync_domain::vault::KeyMaterial::new(key.native_secret().as_slice())
                    .map_err(|_| Error::Authentication)
            })
            .transpose()?;
        let delivered = self
            .identity
            .ensure_vault_key(material.as_ref())
            .await
            .map_err(|error| match error {
                nddev_device_sync_accounts::ClientError::Server(code)
                    if code == "vault_key_registration_required" =>
                {
                    Error::RegistrationRequired
                }
                nddev_device_sync_accounts::ClientError::Server(code)
                    if code == "operation_conflict" =>
                {
                    Error::Authentication
                }
                nddev_device_sync_accounts::ClientError::DeviceRevoked
                | nddev_device_sync_accounts::ClientError::RevalidationRequired => Error::Locked,
                _ => Error::Unavailable,
            })?;
        let expected = self
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if expected.is_some_and(|id| id != delivered.id()) {
            return Err(Error::Authentication);
        }
        let key = VaultKey::from_native_secret(delivered.expose())?;
        self.retain_key(&key).await?;
        *self.expected_key.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.id());
        drop(lock);
        Ok(())
    }
    async fn discover_key(&self) -> Result<(), Error> {
        let reply = self
            .identity
            .sync_request(SyncRequest::Page { after: 0, limit: 1 })
            .await
            .map_err(identity_failure)?;
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
    async fn put_inner(
        &self,
        kind: EntityKind,
        id: String,
        plaintext: &[u8],
        expected: Option<Expected>,
    ) -> Result<String, Error> {
        if plaintext.len() > MAX_PLAIN_BYTES {
            return Err(Error::Invalid);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let entity_id = id.clone();
        let existing = self.journal.entity(kind.as_str(), &entity_id).await?;
        let revision = existing.as_ref().map_or(0, |entity| entity.revision);
        let pending = existing
            .as_ref()
            .and_then(|entity| entity.pending_id.clone());
        let base = existing.as_ref().map_or(0, |entity| entity.next_base);
        if expected
            .as_ref()
            .is_some_and(|expected| expected.revision != revision || expected.pending != pending)
        {
            return Err(Error::Busy);
        }
        let expected_cursor = expected.as_ref().and_then(|expected| expected.cursor);
        let operation_id = uuid::Uuid::new_v4().to_string();
        let mut operation = Operation {
            id: operation_id.clone(),
            device: DeviceId::new(&self.scope.device).map_err(dependency)?,
            entity_kind: kind,
            entity_id: id,
            base_revision: base,
            idempotency_key: operation_id,
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        };
        operation.payload = key.encrypt(&self.scope, &operation, plaintext)?;
        let bytes = codec::body(&operation)?;
        let receipt = self
            .journal
            .enqueue(bytes, expected_cursor, revision, pending)
            .await?;
        // The transaction has committed. No subsequent native-store/SQLite read
        // may turn this durable success into an apparent failed mutation.
        let mut view = self.view.lock().unwrap_or_else(|error| error.into_inner());
        if receipt.local_revision >= view.local_revision {
            view.unlocked = true;
            view.key_id = key.id();
            view.pending = receipt.pending;
            view.conflicts = receipt.conflicts;
            view.cursor = receipt.cursor;
            view.local_revision = receipt.local_revision;
            view.catching_up = true;
        }
        Ok(receipt.id)
    }
    pub async fn share_clipboard(&self, text: Zeroizing<String>) -> Result<String, Error> {
        let _permit = self.admitted()?;
        let payload =
            nddev_device_sync_domain::clipboard::Text::new(text).map_err(|_| Error::Invalid)?;
        let id = format!("{}:clipboard", self.scope.device);
        let plaintext = Zeroizing::new(serde_json::to_vec(&payload).map_err(dependency)?);
        if let Some(previous) = self.journal.entity("clipboard_item", &id).await? {
            let wire: wire::SyncOperation =
                serde_json::from_slice(&previous.body).map_err(dependency)?;
            let operation = codec::operation(&wire, previous.body.len())?;
            let key = self.key().await?.ok_or(Error::Locked)?;
            if key.decrypt(&self.scope, &operation)?.as_slice() == plaintext.as_slice() {
                return Ok(id);
            }
        }
        self.put_inner(
            EntityKind::ClipboardItem,
            id.clone(),
            plaintext.as_slice(),
            None,
        )
        .await?;
        Ok(id)
    }
    /// Resolve only committed server order; a device timestamp never wins.
    pub async fn clipboard(
        &self,
    ) -> Result<Option<(crate::view::ClipboardView, Zeroizing<String>)>, Error> {
        let _permit = self.admitted()?;
        if self.snapshot().catching_up || self.snapshot().last_sync_at == 0 {
            return Err(Error::Busy);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let Some((id, entity)) = self.journal.latest_clipboard().await? else {
            return Ok(None);
        };
        let wire: wire::SyncOperation = serde_json::from_slice(&entity.body).map_err(dependency)?;
        let operation = codec::operation(&wire, entity.body.len())?;
        let plaintext = key.decrypt(&self.scope, &operation)?;
        let value: nddev_device_sync_domain::clipboard::Text =
            serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
        value.validate().map_err(|_| Error::Invalid)?;
        let metadata = crate::view::ClipboardView {
            present: true,
            id,
            device_id: operation.device.as_str().into(),
            server_seq: entity.server_seq,
            bytes: value.text.len() as u32,
            conflicted: entity.conflicted,
        };
        if entity.conflicted {
            return Err(Error::Busy);
        }
        Ok(Some((metadata, value.text)))
    }
    pub async fn save_record(
        &self,
        id: Option<String>,
        expected_revision: u64,
        expected_pending: Option<String>,
        title: String,
        username: String,
        secret: Zeroizing<String>,
    ) -> Result<String, Error> {
        let _permit = self.admitted()?;
        let record = Record {
            version: 1,
            deleted: false,
            title,
            username,
            secret,
            resolved_through_seq: 0,
        };
        record.validate().map_err(|_| Error::Invalid)?;
        let plaintext = Zeroizing::new(serde_json::to_vec(&record).map_err(dependency)?);
        let id = id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let lookup = id.clone();
        if self
            .journal
            .entity("vault_record", &lookup)
            .await?
            .is_some_and(|entity| entity.conflicted)
        {
            return Err(Error::Busy);
        }
        self.put_inner(
            EntityKind::VaultRecord,
            id,
            plaintext.as_slice(),
            Some(Expected {
                revision: expected_revision,
                cursor: None,
                pending: expected_pending,
            }),
        )
        .await
    }
    pub async fn records(&self, after: String) -> Result<RecordPage, Error> {
        let _permit = self.admitted()?;
        if !after.is_empty() && nddev_device_sync_domain::ModuleId::new(&after).is_err() {
            return Err(Error::Invalid);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let (mut entities, observed_seq, local_revision) = self.journal.record_page(after).await?;
        let has_more = entities.len() > 50;
        entities.truncate(50);
        let next_after = entities
            .last()
            .map(|entry| entry.id.clone())
            .unwrap_or_default();
        let mut items = Vec::new();
        for entry in entities {
            let crate::journal::RecordEntry {
                id,
                entity,
                conflict,
            } = entry;
            let record = self.decode_record(&key, &entity.body)?;
            let conflict = conflict
                .map(|body| {
                    let wire: wire::SyncOperation =
                        serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
                    let record = self.decode_record(&key, &body)?;
                    Ok::<_, Error>(crate::view::ConflictView {
                        title: record.title,
                        username: record.username,
                        device_id: wire.device_id,
                        deleted: record.deleted,
                    })
                })
                .transpose()?;
            if !record.deleted || entity.conflicted {
                items.push(RecordView {
                    deleted: record.deleted,
                    observed_seq,
                    id,
                    title: record.title,
                    username: record.username,
                    revision: entity.revision,
                    pending_id: entity.pending_id,
                    conflicted: entity.conflicted,
                    conflict,
                });
            }
        }
        Ok(RecordPage {
            observed_seq,
            local_revision,
            items,
            next_after,
            has_more,
        })
    }
    fn decode_record(&self, key: &VaultKey, body: &[u8]) -> Result<Record, Error> {
        let wire = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        let operation = codec::operation(&wire, body.len())?;
        let plaintext = key.decrypt(&self.scope, &operation)?;
        let record: Record = serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
        record.validate().map_err(|_| Error::Invalid)?;
        Ok(record)
    }
    /// Publish an explicit decision at the observed revision. A competing server
    /// commit creates another conflict; local conflicts clear only on an applied
    /// encrypted version 2 record, and every replica observes the same decision.
    pub async fn resolve_record(
        &self,
        id: String,
        expected_revision: u64,
        expected_cursor: u64,
        expected_pending: Option<String>,
        use_conflict: bool,
    ) -> Result<String, Error> {
        nddev_device_sync_domain::ModuleId::new(&id).map_err(|_| Error::Invalid)?;
        let _permit = self.admitted()?;
        if self.snapshot().catching_up || self.snapshot().last_sync_at == 0 {
            return Err(Error::Busy);
        }
        let lookup = id.clone();
        let (entity, conflict, cursor) = self.journal.resolution(lookup).await?;
        if !entity.conflicted
            || entity.revision != expected_revision
            || cursor != expected_cursor
            || entity.pending_id != expected_pending
        {
            return Err(Error::Busy);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let body = if use_conflict {
            conflict.ok_or(Error::Invalid)?
        } else {
            entity.body
        };
        let mut record = self.decode_record(&key, &body)?;
        record.version = 2;
        record.resolved_through_seq = cursor;
        record.validate().map_err(|_| Error::Invalid)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&record).map_err(dependency)?);
        self.put_inner(
            EntityKind::VaultRecord,
            id,
            &bytes,
            Some(Expected {
                revision: expected_revision,
                cursor: Some(expected_cursor),
                pending: expected_pending,
            }),
        )
        .await
    }
    pub async fn delete_record(
        &self,
        id: String,
        expected_revision: u64,
        expected_pending: Option<String>,
    ) -> Result<String, Error> {
        nddev_device_sync_domain::ModuleId::new(&id).map_err(|_| Error::Invalid)?;
        let _permit = self.admitted()?;
        let lookup = id.clone();
        let entity = self
            .journal
            .entity("vault_record", &lookup)
            .await?
            .ok_or(Error::Invalid)?;
        if entity.conflicted
            || entity.revision != expected_revision
            || entity.pending_id != expected_pending
        {
            return Err(Error::Busy);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        let mut record = self.decode_record(&key, &entity.body)?;
        record.deleted = true;
        record.secret.clear();
        record.validate().map_err(|_| Error::Invalid)?;
        let bytes = Zeroizing::new(serde_json::to_vec(&record).map_err(dependency)?);
        self.put_inner(
            EntityKind::VaultRecord,
            id,
            &bytes,
            Some(Expected {
                revision: expected_revision,
                cursor: None,
                pending: expected_pending,
            }),
        )
        .await
    }
    fn verify_operation(
        &self,
        key: &VaultKey,
        operation: &wire::SyncOperation,
    ) -> Result<u64, Error> {
        let body = serde_json::to_vec(operation).map_err(dependency)?;
        let operation = codec::operation(operation, body.len())?;
        let plaintext = key.decrypt(&self.scope, &operation)?;
        match operation.entity_kind {
            EntityKind::VaultRecord => {
                let record: Record =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                record.validate().map_err(|_| Error::Invalid)?;
                Ok(record.resolved_through_seq)
            }
            EntityKind::ClipboardItem => {
                let text: nddev_device_sync_domain::clipboard::Text =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                text.validate().map_err(|_| Error::Invalid)?;
                Ok(0)
            }
            kind => {
                let snapshot: Snapshot =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                snapshot
                    .validate(&operation.device, kind, &operation.entity_id)
                    .map_err(|_| Error::Invalid)?;
                Ok(0)
            }
        }
    }
    /// Native use only. The presentation wrapper delegates to native clipboard
    /// or declared provider adapters; it never returns this value through FFI.
    pub async fn native_secret(&self, id: String) -> Result<Zeroizing<String>, Error> {
        nddev_device_sync_domain::ModuleId::new(&id).map_err(|_| Error::Invalid)?;
        let _permit = self.admitted()?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let entity = self
            .journal
            .entity("vault_record", &id)
            .await?
            .ok_or(Error::Invalid)?;
        if entity.conflicted {
            return Err(Error::Busy);
        }
        let record = self.decode_record(&key, &entity.body)?;
        if record.deleted {
            return Err(Error::Invalid);
        }
        Ok(record.secret)
    }
    pub async fn synchronize(&self) -> Result<VaultView, Error> {
        self.authorized()?;
        let _permit = self
            .sync_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .catching_up = true;
        let result = nddev_device_sync_accounts::runtime::timeout(replica::BATCH_DEADLINE, async {
            self.ensure_key().await?;
            self.synchronize_inner().await
        })
        .await
        .map_err(dependency)
        .and_then(std::convert::identity);
        {
            let mut view = self.view.lock().unwrap_or_else(|e| e.into_inner());
            view.sync_error = result.as_ref().err().map(Error::code).unwrap_or_default();
            if matches!(result, Err(Error::Locked | Error::RegistrationRequired)) {
                view.unlocked = false;
            }
        }
        result
    }
    /// Native callers provide actual observations, never presentation-authored
    /// DTOs. A bounded batch is encrypted/durable before network acknowledgement.
    pub async fn publish_states(&self, snapshots: Vec<Snapshot>) -> Result<VaultView, Error> {
        self.authorized()?;
        let _permit = self
            .sync_gate
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::Busy)?;
        nddev_device_sync_accounts::runtime::timeout(replica::BATCH_DEADLINE, async {
            if snapshots.is_empty() || snapshots.len() > 32 {
                return Err(Error::Invalid);
            }
            self.ensure_key().await?;
            let key = self.key().await?.ok_or(Error::Locked)?;
            self.synchronize_inner().await?;
            let writer = DeviceId::new(self.scope.device.clone()).map_err(dependency)?;
            let mut targets = std::collections::BTreeSet::new();
            let mut prepared = Vec::new();
            for snapshot in snapshots {
                let (kind, id) = match &snapshot.data {
                    State::Device { .. } => (EntityKind::DeviceState, self.scope.device.clone()),
                    State::Module { module_id, .. } => (
                        EntityKind::ModuleState,
                        format!("{}:{module_id}", self.scope.device),
                    ),
                    State::Account { .. } => (
                        EntityKind::AccountState,
                        format!("{}:nds", self.scope.device),
                    ),
                };
                snapshot
                    .validate(&writer, kind, &id)
                    .map_err(|_| Error::Invalid)?;
                if !targets.insert((kind.as_str(), id.clone())) {
                    return Err(Error::Invalid);
                }
                let lookup_id = id.clone();
                let previous = self.journal.entity(kind.as_str(), &lookup_id).await?;
                if let Some(previous) = previous {
                    let wire: wire::SyncOperation =
                        serde_json::from_slice(&previous.body).map_err(dependency)?;
                    let operation = codec::operation(&wire, previous.body.len())?;
                    let bytes = key.decrypt(&self.scope, &operation)?;
                    if let Ok(previous) = serde_json::from_slice::<Snapshot>(&bytes)
                        && previous.data == snapshot.data
                    {
                        continue;
                    }
                }
                let bytes = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(dependency)?);
                if bytes.len() > MAX_PLAIN_BYTES {
                    return Err(Error::Invalid);
                }
                prepared.push((kind, id, bytes));
            }
            for (kind, id, bytes) in prepared {
                self.put_inner(kind, id, bytes.as_slice(), None).await?;
            }
            self.synchronize_inner().await
        })
        .await
        .map_err(dependency)?
    }
    pub async fn states(&self, after: String) -> Result<StatePage, Error> {
        let _permit = self.admitted()?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let cursor = if after.is_empty() {
            None
        } else {
            let (kind, id) = after.split_once(':').ok_or(Error::Invalid)?;
            if !matches!(kind, "device_state" | "module_state" | "account_state")
                || nddev_device_sync_domain::ModuleId::new(id).is_err()
            {
                return Err(Error::Invalid);
            }
            Some((kind.to_owned(), id.to_owned()))
        };
        let mut entries = self.journal.state_page(cursor).await?;
        let has_more = entries.len() > 50;
        entries.truncate(50);
        let next_after = entries
            .last()
            .map(|(kind, id, _)| format!("{kind}:{id}"))
            .unwrap_or(after);
        let mut items = Vec::new();
        for (kind, id, entity) in entries {
            let wire: wire::SyncOperation =
                serde_json::from_slice(&entity.body).map_err(dependency)?;
            let operation = codec::operation(&wire, entity.body.len())?;
            let plaintext = key.decrypt(&self.scope, &operation)?;
            let snapshot: Snapshot = match serde_json::from_slice(&plaintext) {
                Ok(value) => value,
                Err(_) => {
                    // Exact published alpha.1 initialization marker. It asserts
                    // no observation; a subsequent device publication replaces
                    // this read model without rewriting encrypted history.
                    #[derive(Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct Initialization {
                        schema_version: u16,
                        device_id: String,
                    }
                    let old: Initialization =
                        serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                    if operation.entity_kind != EntityKind::DeviceState
                        || old.schema_version != 1
                        || old.device_id != operation.device.as_str()
                        || operation.entity_id != old.device_id
                    {
                        return Err(Error::Invalid);
                    }
                    continue;
                }
            };
            snapshot
                .validate(&operation.device, operation.entity_kind, &id)
                .map_err(|_| Error::Invalid)?;
            let mut value = StateView {
                kind,
                id,
                device_id: operation.device.as_str().into(),
                label: String::new(),
                version: String::new(),
                platform: String::new(),
                reachability: String::new(),
                configured: false,
                checked_at_ms: 0,
                observed_at_ms: snapshot.observed_at_ms,
                expires_at_ms: 0,
                error_class: String::new(),
                revision: entity.revision,
                conflicted: entity.conflicted,
            };
            match snapshot.data {
                State::Device {
                    display_name,
                    platform,
                    client_version,
                } => {
                    value.label = display_name;
                    value.platform = platform;
                    value.version = client_version;
                }
                State::Module {
                    module_id,
                    version,
                    configured,
                    reachability,
                    checked_at_ms,
                    error_class,
                } => {
                    value.label = module_id;
                    value.version = version;
                    value.configured = configured;
                    value.reachability = match reachability {
                        Reachability::NotChecked => "not_checked",
                        Reachability::Reachable => "reachable",
                        Reachability::Unavailable => "unavailable",
                        Reachability::Failed => "failed",
                    }
                    .into();
                    value.checked_at_ms = checked_at_ms.unwrap_or(0);
                    value.error_class = error_class.unwrap_or_default();
                }
                State::Account {
                    auth_method,
                    checked_at_ms,
                    expires_at_ms,
                } => {
                    value.label = auth_method;
                    value.checked_at_ms = checked_at_ms;
                    value.expires_at_ms = expires_at_ms;
                }
            }
            items.push(value);
        }
        Ok(StatePage {
            items,
            next_after,
            has_more,
        })
    }
    async fn synchronize_inner(&self) -> Result<VaultView, Error> {
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .catching_up = true;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let progress = replica::reconcile(&Replica { client: self, key }).await?;
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .catching_up = !progress.caught_up;
        self.update_view().await
    }
}

// Concrete wire/crypto/storage composition for the shared application use case.
struct Replica<'a> {
    client: &'a VaultClient,
    key: VaultKey,
}
impl From<nddev_device_sync_domain::sync::SyncError> for Error {
    fn from(error: nddev_device_sync_domain::sync::SyncError) -> Self {
        use nddev_device_sync_domain::sync::SyncError;
        match error {
            SyncError::Denied | SyncError::Revoked => Self::Locked,
            SyncError::Unavailable => Self::Unavailable,
            SyncError::Capacity => Self::Busy,
            SyncError::KeyRegistration => Self::RegistrationRequired,
            _ => Self::Invalid,
        }
    }
}
impl ReplicaPort for Replica<'_> {
    type Error = Error;
    type Pending = crate::journal::Pending;
    type Receipt = (Vec<u8>, u64);
    type Page = (wire::SyncPage, Vec<u64>);

    async fn claim(&self) -> Result<Vec<Self::Pending>, Error> {
        self.client.journal.pending().await
    }
    async fn append(&self, pending: &Self::Pending) -> Result<Self::Receipt, Error> {
        let operation = serde_json::from_slice(&pending.body).map_err(|_| Error::Invalid)?;
        let resolved = self.client.verify_operation(&self.key, &operation)?;
        let result = self
            .client
            .identity
            .sync_request(SyncRequest::Append(pending.body.clone()))
            .await
            .map_err(identity_failure)?;
        if !matches!(result.status, 201 | 409) {
            return Err(Error::Invalid);
        }
        Ok((result.body, resolved))
    }
    async fn acknowledge(
        &self,
        pending: Self::Pending,
        receipt: Self::Receipt,
    ) -> Result<(), Error> {
        self.client
            .journal
            .acknowledge(pending.body, receipt.0, receipt.1)
            .await
    }
    async fn cursor(&self) -> Result<u64, Error> {
        self.client.journal.cursor().await
    }
    async fn verified_page(
        &self,
        after: u64,
        limit: usize,
    ) -> Result<VerifiedPage<Self::Page>, Error> {
        let result = self
            .client
            .identity
            .sync_request(SyncRequest::Page {
                after,
                limit: limit.try_into().map_err(|_| Error::Invalid)?,
            })
            .await
            .map_err(identity_failure)?;
        let page: wire::SyncPage =
            serde_json::from_slice(&result.body).map_err(|_| Error::Invalid)?;
        let resolutions = page
            .entries
            .iter()
            .map(|entry| self.client.verify_operation(&self.key, &entry.operation))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(VerifiedPage {
            next_after: page.next_after_seq.try_into().map_err(|_| Error::Invalid)?,
            entries: page.entries.len(),
            has_more: page.has_more,
            contents: (page, resolutions),
        })
    }
    async fn ingest(&self, (page, resolutions): Self::Page) -> Result<(), Error> {
        self.client.journal.ingest(page, resolutions).await
    }
    async fn caught_up(&self, cursor: u64) -> Result<bool, Error> {
        self.client
            .journal
            .caught_up(
                cursor,
                time::OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            )
            .await
    }
}

#[cfg(test)]
fn now_ms() -> Result<u64, Error> {
    (time::OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000)
        .try_into()
        .map_err(dependency)
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
    if !view.authenticated || view.credential_revalidation_required {
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

    async fn fixture_mode(receipt: &serde_json::Value, mode: &str) -> Result<(), Error> {
        let path = std::env::var("NDS_FIXTURE_RECEIPT").map_err(dependency)?;
        let control = receipt["control_file"].as_str().ok_or(Error::Invalid)?;
        std::fs::write(
            control,
            serde_json::to_vec(&serde_json::json!({"mode":mode})).map_err(dependency)?,
        )
        .map_err(dependency)?;
        tokio::time::timeout(std::time::Duration::from_secs(12), async {
            loop {
                let state: serde_json::Value =
                    serde_json::from_slice(&std::fs::read(&path).map_err(dependency)?)
                        .map_err(dependency)?;
                if state["status"] == if mode == "online" { "running" } else { mode } {
                    return Ok(());
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(dependency)?
    }
    async fn concurrent_offline_write(
        identity: Arc<IdentityClient>,
        directory: PathBuf,
        receipt: &serde_json::Value,
    ) -> Result<(), Error> {
        let probe = Arc::new(VaultClient::new(identity.clone(), directory.clone()).await?);
        fixture_mode(receipt, "offline").await?;
        let result = async {
            let address = receipt["base_url"]
                .as_str()
                .ok_or(Error::Invalid)?
                .strip_prefix("http://")
                .ok_or(Error::Invalid)?;
            let listener = std::net::TcpListener::bind(address).map_err(dependency)?;
            listener.set_nonblocking(true).map_err(dependency)?;
            let (connected, accepted) = tokio::sync::oneshot::channel();
            let (release, hold) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                let connection = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && std::time::Instant::now() < deadline =>
                        {
                            std::thread::sleep(std::time::Duration::from_millis(5))
                        }
                        Err(_) => return Err(Error::Unavailable),
                    }
                };
                let _ = connected.send(());
                let _ = hold.recv_timeout(std::time::Duration::from_secs(10));
                drop(connection);
                Ok(())
            });
            // Match the production coordinator's task boundary. The long
            // acceptance future must not nest the HTTP poll stack inside its
            // unrelated local-edit future on the test runner's thread.
            let background = probe.clone();
            let mut synchronization = tokio::spawn(async move { background.synchronize().await });
            let outcome = async {
                tokio::select! {
                    _=&mut synchronization=>return Err(Error::Invalid),
                    result=accepted=>result.map_err(dependency)?,
                }
                // The genuine network request remains unanswered, but local
                // encryption/commit and read-your-writes have their own gate.
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    probe.save_record(
                        Some("concurrent-offline".into()),
                        0,
                        None,
                        "Offline during stalled sync".into(),
                        String::new(),
                        Zeroizing::new("PRIVATE_OFFLINE_CONCURRENT_VALUE".into()),
                    ),
                )
                .await
                .map_err(dependency)??;
                let reopened = VaultClient::new(identity, directory).await?;
                let page = reopened.records(String::new()).await?;
                if page.items.len() != 1
                    || page.items[0].title != "Offline during stalled sync"
                    || page.items[0].pending_id.is_none()
                {
                    return Err(Error::Invalid);
                }
                Ok(())
            }
            .await;
            synchronization.abort();
            let _ = synchronization.await;
            let _ = release.send(());
            worker.join().map_err(dependency)??;
            outcome
        }
        .await;
        fixture_mode(receipt, "online").await?;
        result
    }
    async fn fixture_identity() -> (serde_json::Value, Arc<IdentityClient>) {
        let receipt: serde_json::Value = serde_json::from_slice(
            &std::fs::read(std::env::var("NDS_FIXTURE_RECEIPT").unwrap()).unwrap(),
        )
        .unwrap();
        let endpoint = receipt["base_url"].as_str().unwrap();
        let mailbox = receipt["mailpit_url"].as_str().unwrap();
        let owner = receipt["owner_email"].as_str().unwrap();
        for value in [endpoint, mailbox] {
            let url = reqwest::Url::parse(value).unwrap();
            assert_eq!(url.scheme(), "http");
            assert!(matches!(url.host_str(), Some("127.0.0.1" | "localhost")));
            assert!(url.port().is_some());
        }
        assert!(owner.ends_with(".invalid"));
        let identity = Arc::new(IdentityClient::new(endpoint).unwrap());
        identity.refresh().await.unwrap();
        let http = reqwest::Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let previous: serde_json::Value = http
            .get(format!("{mailbox}/api/v1/messages"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let previous_ids: Vec<String> = previous["messages"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|message| message["ID"].as_str().map(str::to_owned))
            .collect();
        identity.request_email(owner.into(), "en").await.unwrap();
        let code = nddev_device_sync_accounts::runtime::timeout(
            std::time::Duration::from_secs(10),
            async {
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
                        .filter(|id| !previous_ids.iter().any(|previous| previous == id))
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
            },
        )
        .await
        .unwrap();
        identity.verify_email(code).await.unwrap();
        identity
            .enroll_device("Native vault acceptance".into())
            .await
            .unwrap();
        (receipt, identity)
    }

    #[tokio::test]
    #[ignore = "requires an owned PostgreSQL/Mailpit fixture and actual native credentials"]
    async fn actual_native_vault_outbox_backend_and_process_recreation() {
        let (receipt, identity) = fixture_identity().await;
        let directory =
            std::env::temp_dir().join(format!("nds-vault-acceptance-{}", uuid::Uuid::new_v4()));
        let vault = VaultClient::new(identity.clone(), directory.clone())
            .await
            .unwrap();
        let store = identity.vault_credentials().unwrap();
        let outcome = async {
            let created = vault.refresh().await?;
            assert!(created.unlocked && created.cursor == 0);
            Box::pin(concurrent_offline_write(identity.clone(),directory.join("concurrent-probe"),&receipt)).await?;
            let key = store.read().await.map_err(dependency)?.unwrap();
            let secret = "PRIVATE_ACTUAL_VAULT_VALUE";
            vault
                .save_record(
                    Some("acceptance-record".into()),
                    0,
                    None, "Acceptance record".into(),
                    "test-user".into(),
                    Zeroizing::new(secret.into()),
                )
                .await?;
            assert_eq!(vault.snapshot().pending, 1);
            let view = vault.synchronize().await?;
            assert_eq!(view.pending, 0);
            assert_eq!(view.cursor, 1);
            let records = vault.records(String::new()).await?.items;
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].title, "Acceptance record");
            let identity_view = identity.view();
            let current = identity_view
                .devices
                .iter()
                .find(|device| device.is_current)
                .unwrap();
            let observed = now_ms()?;
            let states = vec![
                Snapshot {
                    schema_version: 1,
                    observed_at_ms: observed,
                    data: State::Device {
                        display_name: current.display_name.clone(),
                        platform: current.platform.clone(),
                        client_version: env!("CARGO_PKG_VERSION").into(),
                    },
                },
                Snapshot {
                    schema_version: 1,
                    observed_at_ms: observed,
                    data: State::Account {
                        auth_method: identity_view.auth_method.clone(),
                        checked_at_ms: (identity_view.session_checked_at as u64) * 1000,
                        expires_at_ms: time::OffsetDateTime::parse(
                            &identity_view.expires_at,
                            &time::format_description::well_known::Rfc3339,
                        )
                        .unwrap()
                        .unix_timestamp() as u64
                            * 1000,
                    },
                },
            ];
            vault.publish_states(states.clone()).await?;
            let mut unchanged = states;
            for value in &mut unchanged {
                value.observed_at_ms = now_ms()?;
            }
            vault.publish_states(unchanged).await?;
            let state_page = vault.states(String::new()).await?;
            assert_eq!(state_page.items.len(), 2);
            assert!(!state_page.has_more);
            assert_eq!(vault.snapshot().cursor, 3);
            assert!(
                state_page
                    .items
                    .iter()
                    .any(|value| value.kind == "device_state"
                        && value.label == current.display_name
                        && value.revision == 1)
            );
            assert!(
                state_page
                    .items
                    .iter()
                    .any(|value| value.kind == "account_state" && value.label == "email_otp")
            );
            assert_eq!(
                vault
                    .native_secret("acceptance-record".into())
                    .await?
                    .as_str(),
                secret
            );
            let restarted = VaultClient::new(identity.clone(), directory.clone()).await?;
            assert_eq!(restarted.refresh().await?.key_id, created.key_id);
            assert_eq!(restarted.states(String::new()).await?.items.len(), 2);
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
            // Large real ciphertext entries exceed one byte-bounded catch-up
            // batch even when the server permits 100 small entries per page.
            // A partial observation must not advance durable freshness.
            for index in 0..33 {
                vault
                    .save_record(
                        Some(format!("catchup-{index}")),
                        0,
                        None, format!("Record {index}"),
                        String::new(),
                        Zeroizing::new("x".repeat(16_000)),
                    )
                    .await?;
            }
            let old_sync = vault.refresh_local().await?.last_sync_at;
            for _ in 0..2 {
                let partial = vault.synchronize().await?;
                assert!(partial.catching_up && partial.pending > 0);
                assert_eq!(partial.last_sync_at, old_sync);
            }
            assert!(!vault.synchronize().await?.catching_up);
            let fresh = VaultClient::new(identity.clone(), directory.join("fresh-replica")).await?;
            let partial = fresh.refresh().await?;
            assert!(partial.catching_up && partial.cursor > 0 && partial.cursor < 36);
            assert_eq!(partial.last_sync_at, 0);
            let complete = fresh.synchronize().await?;
            assert!(!complete.catching_up && complete.cursor == 36 && complete.last_sync_at > 0);
            assert_eq!(fresh.records(String::new()).await?.items.len(), 34);
            let clipboard_text="Actual encrypted shared clipboard: проверка";
            vault.share_clipboard(Zeroizing::new(clipboard_text.into())).await?;
            let mut synced=vault.synchronize().await?;
            while synced.catching_up {synced=vault.synchronize().await?;}
            fresh.synchronize().await?;
            let (received,plain)=fresh.clipboard().await?.unwrap();
            assert_eq!(plain.as_str(),clipboard_text);
            assert_eq!(received.server_seq,37);
            assert_eq!(received.device_id,current.device_id);
            let cursor=vault.snapshot().cursor;
            vault.share_clipboard(Zeroizing::new(clipboard_text.into())).await?;
            assert_eq!(vault.synchronize().await?.cursor,cursor);
            fresh.share_clipboard(Zeroizing::new("A later committed clipboard item".into())).await?;
            fresh.synchronize().await?;vault.synchronize().await?;
            let (newer,plain)=vault.clipboard().await?.unwrap();
            assert_eq!(newer.server_seq,38);assert_eq!(plain.as_str(),"A later committed clipboard item");
            // Real schema1 migration preserves ciphertext and receipts. Replaying
            // recovers committed sequence without resetting any native key.
            let path=vault.journal.path_for_acceptance();
            let sqlite=rusqlite::Connection::open(&path).map_err(dependency)?;
            sqlite.execute_batch("DROP VIEW local_entities; DROP VIEW meta; ALTER TABLE replica_meta RENAME TO meta; ALTER TABLE replica_outbox RENAME TO outbox; ALTER TABLE replica_entities RENAME TO entities; ALTER TABLE replica_conflicts RENAME TO conflicts; DROP INDEX outbox_unsent; DROP INDEX outbox_dispatched; DROP INDEX conflict_entity; ALTER TABLE outbox DROP COLUMN predecessor; ALTER TABLE outbox DROP COLUMN dispatched; ALTER TABLE meta DROP COLUMN last_sync_at; ALTER TABLE meta DROP COLUMN local_revision; ALTER TABLE entities DROP COLUMN server_seq; UPDATE meta SET schema_version=1;").map_err(dependency)?;drop(sqlite);
            let migrated=VaultClient::new(identity.clone(),directory.clone()).await?;
            assert!(matches!(migrated.clipboard().await,Err(Error::Busy)));
            let mut progress=migrated.synchronize().await?;while progress.catching_up{progress=migrated.synchronize().await?;}
            assert_eq!(migrated.native_secret("acceptance-record".into()).await?.as_str(),secret);
            assert_eq!(migrated.clipboard().await?.unwrap().0.server_seq,38);
            // Two independent durable replicas retain competing edits. Both
            // deny native use until a revision/cursor-bound owner decision lands.
            vault.save_record(Some("acceptance-record".into()), 1, None, "Server edit".into(), "test-user".into(), Zeroizing::new(secret.into())).await?;
            fresh.save_record(Some("acceptance-record".into()), 1, None, "Competing edit".into(), "test-user".into(), Zeroizing::new("PRIVATE_COMPETING_VALUE".into())).await?;
            vault.synchronize().await?; fresh.synchronize().await?; vault.synchronize().await?;
            assert!(matches!(vault.native_secret("acceptance-record".into()).await, Err(Error::Busy)));
            assert!(matches!(fresh.native_secret("acceptance-record".into()).await, Err(Error::Busy)));
            let record = fresh.records(String::new()).await?.items.into_iter().find(|record| record.id == "acceptance-record").unwrap();
            assert!(record.conflicted && record.conflict.as_ref().unwrap().title == "Competing edit");
            assert!(matches!(fresh.resolve_record(record.id.clone(), record.revision - 1, record.observed_seq, None, false).await, Err(Error::Busy)));
            assert!(matches!(fresh.resolve_record(record.id.clone(), record.revision, record.observed_seq - 1, None, false).await, Err(Error::Busy)));
            fresh.resolve_record(record.id, record.revision, record.observed_seq, None, false).await?;
            fresh.synchronize().await?; vault.synchronize().await?;
            assert_eq!(vault.snapshot().conflicts, 0); assert_eq!(fresh.snapshot().conflicts, 0);
            assert_eq!(vault.native_secret("acceptance-record".into()).await?.as_str(), secret);
            for index in 0..120 {
                vault.save_record(Some(format!("bulk-{index:03}")), 0, None, format!("Page record {index}"), String::new(), Zeroizing::new("PRIVATE_PAGE_VALUE".into())).await?;
            }
            for _ in 0..16 { if !vault.synchronize().await?.catching_up { break; } }
            assert!(!vault.snapshot().catching_up);
            for _ in 0..16 { if !fresh.synchronize().await?.catching_up { break; } }
            assert!(!fresh.snapshot().catching_up);
            // A stale edit of a deleted record must remain visible as a
            // resolvable conflict. Choosing it restores only that chosen value.
            vault.delete_record("bulk-000".into(), 1, None).await?;
            fresh.save_record(Some("bulk-000".into()), 1, None, "Restore chosen edit".into(), String::new(), Zeroizing::new("PRIVATE_RESTORED_VALUE".into())).await?;
            vault.synchronize().await?; fresh.synchronize().await?;
            let record = fresh.records(String::new()).await?.items.into_iter().find(|record| record.id == "bulk-000").unwrap();
            assert!(record.deleted && record.conflicted);
            fresh.resolve_record(record.id, record.revision, record.observed_seq, None, true).await?;
            fresh.synchronize().await?; vault.synchronize().await?;
            assert_eq!(vault.native_secret("bulk-000".into()).await?.as_str(), "PRIVATE_RESTORED_VALUE");
            for index in 1..=5 { vault.delete_record(format!("bulk-{index:03}"), 1, None).await?; }
            vault.synchronize().await?;
            let mut after = String::new(); let mut ids = std::collections::BTreeSet::new();
            for _ in 0..8 {
                let page = vault.records(after.clone()).await?;
                assert!(page.items.len() <= 50);
                for record in page.items { assert!(ids.insert(record.id)); }
                if !page.has_more { break; }
                assert!(page.next_after > after); after = page.next_after;
            }
            assert_eq!(ids.len(), 149);
            assert!(ids.contains("bulk-119") && ids.contains("catchup-9"));
            // An authenticated but corrupt server record must not advance the
            // verified inbox cursor or freshness. This poisons only this owned
            // disposable server; production has no reset/repair bypass.
            let cursor = vault.journal.cursor().await?;
            fresh.save_record(Some("before-invalid".into()), 0, None, "Valid preceding record".into(), String::new(), Zeroizing::new("PRIVATE_VALID_PREFIX".into())).await?;
            for _ in 0..16 { if !fresh.synchronize().await?.catching_up { break; } }
            assert!(!fresh.snapshot().catching_up);
            let native_key = vault.key().await?.unwrap();
            let mut invalid = Operation { id: uuid::Uuid::new_v4().to_string(), device: DeviceId::new(&vault.scope.device).unwrap(), entity_kind: EntityKind::VaultRecord, entity_id: "invalid-authentication".into(), base_revision: 0, idempotency_key: uuid::Uuid::new_v4().to_string(), payload: EncryptedPayload { key_id: native_key.id(), nonce: [0; 12], ciphertext: Vec::new() } };
            let plaintext = Zeroizing::new(serde_json::to_vec(&Record { version: 1, deleted: false, title: "Invalid fixture record".into(), username: String::new(), secret: Zeroizing::new("PRIVATE_TAMPER_VALUE".into()), resolved_through_seq: 0 }).unwrap());
            invalid.payload = native_key.encrypt(&vault.scope, &invalid, &plaintext)?;
            invalid.payload.ciphertext[0] ^= 1;
            let accepted = identity.sync_request(SyncRequest::Append(codec::body(&invalid)?)).await.map_err(dependency)?;
            assert_eq!(accepted.status, 201);
            let freshness = vault.snapshot().last_sync_at;
            assert!(matches!(vault.synchronize().await, Err(Error::Authentication)));
            assert_eq!(vault.journal.cursor().await?, cursor);
            assert_eq!(vault.snapshot().last_sync_at, freshness);
            assert!(vault.journal.entity("vault_record", "invalid-authentication").await?.is_none());
            assert!(vault.journal.entity("vault_record", "before-invalid").await?.is_none());
            assert_eq!(store.read().await.map_err(dependency)?.unwrap().as_slice(), key.as_slice());
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
        assert!(!vault.snapshot().unlocked);
        assert!(matches!(
            vault.native_secret("acceptance-record".into()).await,
            Err(Error::Locked)
        ));
        std::fs::remove_dir_all(directory).unwrap();
        outcome.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires an owned byte-bounded PostgreSQL/Mailpit fixture and actual native credentials"]
    async fn actual_native_large_page_catchup_preserves_bounds_and_freshness() {
        let (_receipt, identity) = fixture_identity().await;
        let directory =
            std::env::temp_dir().join(format!("nds-page-acceptance-{}", uuid::Uuid::new_v4()));
        let vault = VaultClient::new(identity.clone(), directory.clone())
            .await
            .unwrap();
        let store = identity.vault_credentials().unwrap();
        let outcome = async {
            assert_eq!(vault.refresh().await?.cursor, 0);
            for index in 0..133 {
                vault
                    .save_record(
                        Some(format!("page-record-{index:03}")),
                        0,
                        None,
                        format!("Page record {index}"),
                        String::new(),
                        Zeroizing::new(if index < 33 {
                            "x".repeat(16_000)
                        } else {
                            "synthetic".into()
                        }),
                    )
                    .await?;
            }
            let mut writer = vault.snapshot();
            for _ in 0..16 {
                writer = vault.synchronize().await?;
                if !writer.catching_up {
                    break;
                }
            }
            assert!(!writer.catching_up && writer.pending == 0 && writer.cursor == 133);

            let large = identity
                .sync_request(SyncRequest::Page {
                    after: 0,
                    limit: 100,
                })
                .await
                .map_err(identity_failure)?;
            assert!(large.body.len() <= nddev_device_sync_domain::sync::MAX_PAGE_BYTES);
            let page: wire::SyncPage = serde_json::from_slice(&large.body).map_err(dependency)?;
            assert_eq!(page.entries.len(), 2);
            assert!(page.has_more && page.next_after_seq == 2);
            let small = identity
                .sync_request(SyncRequest::Page {
                    after: 33,
                    limit: 100,
                })
                .await
                .map_err(identity_failure)?;
            assert!(small.body.len() <= nddev_device_sync_domain::sync::MAX_PAGE_BYTES);
            let page: wire::SyncPage = serde_json::from_slice(&small.body).map_err(dependency)?;
            assert!(page.entries.len() > 2 && page.entries.len() <= 100);
            assert_eq!(page.next_after_seq, 33 + page.entries.len() as i64);

            let fresh = VaultClient::new(identity.clone(), directory.join("fresh-replica")).await?;
            let partial = fresh.refresh().await?;
            assert!(partial.catching_up && partial.cursor > 0 && partial.cursor < 133);
            assert_eq!(partial.last_sync_at, 0);
            let complete = fresh.synchronize().await?;
            assert!(!complete.catching_up && complete.cursor == 133 && complete.last_sync_at > 0);
            let mut after = String::new();
            let mut seen = std::collections::BTreeSet::new();
            loop {
                let page = fresh.records(after).await?;
                for item in page.items {
                    assert_eq!(item.revision, 1);
                    assert!(!item.conflicted && item.pending_id.is_none());
                    assert!(seen.insert(item.id));
                }
                if !page.has_more {
                    break;
                }
                after = page.next_after;
            }
            assert_eq!(seen.len(), 133);
            assert_eq!(
                fresh.native_secret("page-record-000".into()).await?.len(),
                16_000
            );
            Ok::<_, Error>(())
        }
        .await;
        store.delete().await.unwrap();
        identity.logout().await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
        outcome.unwrap();
    }
}
