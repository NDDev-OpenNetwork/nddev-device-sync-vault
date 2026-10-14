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
            EntityKind::RepositoryState => return Err(Error::Invalid),
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

/// Decode without reconstructing the original request. Storage retains `body`.
pub(crate) fn versioned(body: &[u8]) -> Result<history::VersionedOperation, Error> {
    if !(1..=MAX_OPERATION_BYTES).contains(&body.len()) {
        return Err(Error::Invalid);
    }
    #[derive(serde::Deserialize)]
    struct Version {
        schema_version: u8,
    }
    match serde_json::from_slice::<Version>(body)
        .map_err(|_| Error::Invalid)?
        .schema_version
    {
        2 => Ok(history::VersionedOperation {
            operation: operation(
                &serde_json::from_slice(body).map_err(|_| Error::Invalid)?,
                body.len(),
            )?,
            version: history::OperationVersion::V2,
        }),
        3 => {
            let v: crate::sync3_wire::SyncOperationV3 =
                serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
            let integer = |n: i64| u64::try_from(n).map_err(|_| Error::Invalid);
            let nonce = decode_base64(&v.payload.nonce)?;
            let value = history::VersionedOperation {
                operation: Operation {
                    id: v.operation_id,
                    device: DeviceId::new(v.device_id).map_err(|_| Error::Invalid)?,
                    entity_kind: match v.entity_type {
                        crate::sync3_wire::EntityType::DeviceState => EntityKind::DeviceState,
                        crate::sync3_wire::EntityType::ModuleState => EntityKind::ModuleState,
                        crate::sync3_wire::EntityType::VaultRecord => EntityKind::VaultRecord,
                        crate::sync3_wire::EntityType::AccountState => EntityKind::AccountState,
                        crate::sync3_wire::EntityType::ClipboardItem => EntityKind::ClipboardItem,
                        crate::sync3_wire::EntityType::RepositoryState => {
                            EntityKind::RepositoryState
                        }
                    },
                    entity_id: v.entity_id,
                    base_revision: integer(v.base_revision)?,
                    idempotency_key: v.idempotency_key,
                    payload: EncryptedPayload {
                        key_id: v.payload.key_id,
                        nonce: nonce.try_into().map_err(|_| Error::Invalid)?,
                        ciphertext: decode_base64(&v.payload.ciphertext)?,
                    },
                },
                version: history::OperationVersion::V3 {
                    basis_seq: integer(v.basis_seq)?,
                    lifecycle: history::Lifecycle {
                        resolved_through_seq: integer(v.lifecycle.resolved_through_seq)?,
                    },
                },
            };
            value.validate(body.len()).map_err(|_| Error::Invalid)?;
            Ok(value)
        }
        _ => Err(Error::Invalid),
    }
}
fn decode_base64(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(Error::Invalid);
    }
    Ok(bytes)
}
pub(crate) fn versioned_body(value: &history::VersionedOperation) -> Result<Vec<u8>, Error> {
    use crate::sync3_wire as v3;
    let history::OperationVersion::V3 {
        basis_seq,
        lifecycle,
    } = value.version
    else {
        return body(&value.operation);
    };
    let o = &value.operation;
    let wire = v3::SyncOperationV3 {
        schema_version: 3,
        operation_id: o.id.clone(),
        device_id: o.device.as_str().into(),
        entity_id: o.entity_id.clone(),
        idempotency_key: o.idempotency_key.clone(),
        entity_type: match o.entity_kind {
            EntityKind::DeviceState => v3::EntityType::DeviceState,
            EntityKind::ModuleState => v3::EntityType::ModuleState,
            EntityKind::VaultRecord => v3::EntityType::VaultRecord,
            EntityKind::AccountState => v3::EntityType::AccountState,
            EntityKind::ClipboardItem => v3::EntityType::ClipboardItem,
            EntityKind::RepositoryState => v3::EntityType::RepositoryState,
        },
        base_revision: o.base_revision.try_into().map_err(|_| Error::Invalid)?,
        basis_seq: basis_seq.try_into().map_err(|_| Error::Invalid)?,
        lifecycle: v3::Lifecycle {
            resolved_through_seq: lifecycle
                .resolved_through_seq
                .try_into()
                .map_err(|_| Error::Invalid)?,
        },
        payload: v3::EncryptedPayload {
            algorithm: v3::Algorithm::Aes256Gcm,
            key_id: o.payload.key_id.clone(),
            nonce: URL_SAFE_NO_PAD.encode(o.payload.nonce),
            ciphertext: URL_SAFE_NO_PAD.encode(&o.payload.ciphertext),
        },
    };
    let body = serde_json::to_vec(&wire).map_err(|_| Error::Invalid)?;
    value.validate(body.len()).map_err(|_| Error::Invalid)?;
    Ok(body)
}

pub(crate) fn original_receipt(
    body: &[u8],
    result: &[u8],
    status: u16,
) -> Result<(history::VersionedOperation, Receipt), Error> {
    history::validate_original_lengths(body.len(), result.len()).map_err(|_| Error::Invalid)?;
    let operation = versioned(body)?;
    let wire: wire::Sync = serde_json::from_slice(result).map_err(|_| Error::Invalid)?;
    let receipt = receipt(&wire)?;
    receipt
        .validate_for(&operation.operation)
        .map_err(|_| Error::Invalid)?;
    if status
        != match receipt.decision {
            Decision::Apply { .. } => 201,
            Decision::Conflict { .. } => 409,
        }
    {
        return Err(Error::Invalid);
    }
    if let history::OperationVersion::V3 { basis_seq, .. } = operation.version
        && basis_seq >= receipt.server_seq
    {
        return Err(Error::Invalid);
    }
    Ok((operation, receipt))
}

/// Decode the generated receipt into the pure core invariant.
pub fn receipt(value: &wire::Sync) -> Result<Receipt, Error> {
    let integer = |value: i64| u64::try_from(value).map_err(|_| Error::Invalid);
    Ok(match value {
        wire::Sync::Applied(value) => Receipt {
            operation_id: value.operation_id.clone(),
            server_seq: integer(value.server_seq)?,
            decision: Decision::Apply {
                revision: integer(value.revision)?,
            },
        },
        wire::Sync::Conflict(value) => Receipt {
            operation_id: value.operation_id.clone(),
            server_seq: integer(value.server_seq)?,
            decision: Decision::Conflict {
                base_revision: integer(value.base_revision)?,
                current_revision: integer(value.current_revision)?,
            },
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Scope, VaultKey};
    #[test]
    fn versioned_v2_aad_is_compatible_and_v3_header_is_authenticated_with_record3() {
        let key = VaultKey::generate().unwrap();
        let scope = Scope {
            origin: "https://instance.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: "local".into(),
        };
        let mut o = Operation {
            id: "op".into(),
            device: DeviceId::new("writer").unwrap(),
            entity_kind: EntityKind::VaultRecord,
            entity_id: "record".into(),
            base_revision: 0,
            idempotency_key: "op".into(),
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        };
        o.payload = key.encrypt(&scope, &o, b"legacy retained bytes").unwrap();
        let raw = body(&o).unwrap();
        let v = versioned(&raw).unwrap();
        assert_eq!(v.version, history::OperationVersion::V2);
        assert_eq!(
            &*key.decrypt_versioned(&scope, &v).unwrap(),
            b"legacy retained bytes"
        );
        let canonical = serde_json::to_vec(
            &v.aad(
                history::AadScope {
                    origin: &scope.origin,
                    tenant: &scope.tenant,
                    user: &scope.user,
                },
                &key.id(),
            )
            .unwrap(),
        )
        .unwrap();
        let original = serde_json::to_vec(&(
            "NDS-RECORD-V2",
            &scope.origin,
            &scope.tenant,
            &scope.user,
            o.device.as_str(),
            o.entity_kind.as_str(),
            &o.entity_id,
            &o.id,
            o.base_revision,
            &key.id(),
        ))
        .unwrap();
        assert_eq!(canonical, original);
        let mut current = history::VersionedOperation::qualify(
            o,
            7,
            history::Lifecycle {
                resolved_through_seq: 3,
            },
        )
        .unwrap();
        let plain=br#"{"version":3,"deleted":false,"title":"Owned fixture","username":"","secret":"fixture"}"#;
        current.operation.payload = key.encrypt_versioned(&scope, &current, plain).unwrap();
        let encoded = versioned_body(&current).unwrap();
        let mut decoded = versioned(&encoded).unwrap();
        assert!(decoded == current);
        let plaintext = key.decrypt_versioned(&scope, &decoded).unwrap();
        let r: nddev_device_sync_domain::vault::Record3 =
            serde_json::from_slice(&plaintext).unwrap();
        r.validate().unwrap();
        assert!(
            serde_json::from_slice::<nddev_device_sync_domain::vault::Record>(&plaintext)
                .is_ok_and(|r| r.validate().is_err())
        );
        decoded.version = history::OperationVersion::V3 {
            basis_seq: 7,
            lifecycle: history::Lifecycle {
                resolved_through_seq: 4,
            },
        };
        assert_eq!(
            key.decrypt_versioned(&scope, &decoded).unwrap_err(),
            Error::Authentication
        );
        decoded = current.clone();
        decoded.operation.idempotency_key = "v3:7:another".into();
        assert_eq!(
            key.decrypt_versioned(&scope, &decoded).unwrap_err(),
            Error::Authentication
        );
        let mut foreign = scope.clone();
        foreign.user = "foreign".into();
        assert_eq!(
            key.decrypt_versioned(&foreign, &current).unwrap_err(),
            Error::Authentication
        );
    }
    #[test]
    fn versioned_codec_receipt_sizes_status_and_v2_repository_fail_closed() {
        let body=br#"{"schema_version":2,"operation_id":"op","device_id":"writer","entity_type":"repository_state","entity_id":"github:repo:1","base_revision":0,"idempotency_key":"op","payload":{"algorithm":"aes-256-gcm","key_id":"key","nonce":"AAAAAAAAAAAAAAAA","ciphertext":"AAAAAAAAAAAAAAAAAAAAAA"}}"#;
        assert!(matches!(versioned(body), Err(Error::Invalid)));
        assert!(history::validate_original_lengths(1, 2049).is_err());
        assert!(matches!(
            versioned(&vec![b' '; MAX_OPERATION_BYTES + 1]),
            Err(Error::Invalid)
        ));
    }
}
