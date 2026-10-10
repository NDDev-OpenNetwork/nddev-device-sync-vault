use crate::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_accounts::sync_wire as wire;
use nddev_device_sync_domain::{DeviceId, sync::*};

pub fn operation(value: &wire::SyncOperation, size: usize) -> Result<Operation, Error> {
    if value.schema_version != 2
        || value.base_revision < 0
        || value.payload.ciphertext.len() > 21867
        || value.payload.nonce.len() != 16
    {
        return Err(Error::Invalid);
    }
    let ciphertext = URL_SAFE_NO_PAD
        .decode(&value.payload.ciphertext)
        .map_err(|_| Error::Invalid)?;
    let nonce = URL_SAFE_NO_PAD
        .decode(&value.payload.nonce)
        .map_err(|_| Error::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&ciphertext) != value.payload.ciphertext
        || URL_SAFE_NO_PAD.encode(&nonce) != value.payload.nonce
    {
        return Err(Error::Invalid);
    }
    let value = Operation {
        id: value.operation_id.clone(),
        device: DeviceId::new(&value.device_id).map_err(|_| Error::Invalid)?,
        entity_kind: match value.entity_type {
            wire::EntityType::DeviceState => EntityKind::DeviceState,
            wire::EntityType::ModuleState => EntityKind::ModuleState,
            wire::EntityType::VaultRecord => EntityKind::VaultRecord,
            wire::EntityType::AccountState => EntityKind::AccountState,
            wire::EntityType::ClipboardItem => EntityKind::ClipboardItem,
        },
        entity_id: value.entity_id.clone(),
        base_revision: value.base_revision as u64,
        idempotency_key: value.idempotency_key.clone(),
        payload: EncryptedPayload {
            key_id: value.payload.key_id.clone(),
            nonce: nonce.try_into().map_err(|_| Error::Invalid)?,
            ciphertext,
        },
    };
    value.validate(size).map_err(|_| Error::Invalid)?;
    Ok(value)
}
pub fn body(value: &Operation) -> Result<Vec<u8>, Error> {
    let wire = wire::SyncOperation {
        schema_version: 2,
        operation_id: value.id.clone(),
        device_id: value.device.as_str().into(),
        entity_id: value.entity_id.clone(),
        base_revision: value.base_revision.try_into().map_err(|_| Error::Invalid)?,
        idempotency_key: value.idempotency_key.clone(),
        entity_type: match value.entity_kind {
            EntityKind::DeviceState => wire::EntityType::DeviceState,
            EntityKind::ModuleState => wire::EntityType::ModuleState,
            EntityKind::VaultRecord => wire::EntityType::VaultRecord,
            EntityKind::AccountState => wire::EntityType::AccountState,
            EntityKind::ClipboardItem => wire::EntityType::ClipboardItem,
        },
        payload: wire::EncryptedPayload {
            algorithm: wire::Algorithm::Aes256Gcm,
            key_id: value.payload.key_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(value.payload.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&value.payload.ciphertext),
        },
    };
    let body = serde_json::to_vec(&wire).map_err(|_| Error::Invalid)?;
    value.validate(body.len()).map_err(|_| Error::Invalid)?;
    Ok(body)
}
