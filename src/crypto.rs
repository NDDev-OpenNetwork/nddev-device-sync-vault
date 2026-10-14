//! Maintained native AES-GCM record encryption; no bespoke cipher.
use crate::Error;
use nddev_device_sync_domain::sync::history::{AadScope, OperationVersion, VersionedOperation};
use nddev_device_sync_domain::sync::{EncryptedPayload, MAX_PLAIN_BYTES, Operation};
use ring::{
    aead,
    rand::{SecureRandom, SystemRandom},
};
use zeroize::Zeroizing;

#[derive(Clone, PartialEq, Eq)]
pub struct Scope {
    pub origin: String,
    pub tenant: String,
    pub user: String,
    pub device: String,
}
pub struct VaultKey {
    id: uuid::Uuid,
    key: Zeroizing<[u8; 32]>,
}
impl VaultKey {
    #[cfg(test)]
    pub fn generate() -> Result<Self, Error> {
        let mut key = Zeroizing::new([0; 32]);
        random(key.as_mut())?;
        Ok(Self {
            id: uuid::Uuid::new_v4(),
            key,
        })
    }
    pub fn id(&self) -> String {
        self.id.to_string()
    }
    /// Only native credential adapters consume these zeroizing bytes. Never put
    /// this method or its result in a presentation/FFI API or a metadata store.
    pub(crate) fn native_secret(&self) -> Zeroizing<Vec<u8>> {
        let mut secret = Zeroizing::new(self.id.as_bytes().to_vec());
        secret.extend_from_slice(self.key.as_slice());
        secret
    }
    pub(crate) fn from_native_secret(secret: &[u8]) -> Result<Self, Error> {
        if secret.len() != 48 {
            return Err(Error::Invalid);
        }
        let id = uuid::Uuid::from_slice(&secret[..16]).map_err(|_| Error::Invalid)?;
        if id.is_nil() {
            return Err(Error::Invalid);
        }
        let key = Zeroizing::new(secret[16..].try_into().map_err(|_| Error::Invalid)?);
        Ok(Self { id, key })
    }
    pub fn encrypt(
        &self,
        scope: &Scope,
        operation: &Operation,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, Error> {
        self.encrypt_versioned(
            scope,
            &VersionedOperation {
                operation: operation.clone(),
                version: OperationVersion::V2,
            },
            plaintext,
        )
    }
    pub(crate) fn encrypt_versioned(
        &self,
        scope: &Scope,
        operation: &VersionedOperation,
        plaintext: &[u8],
    ) -> Result<EncryptedPayload, Error> {
        if plaintext.len() > MAX_PLAIN_BYTES {
            return Err(Error::Invalid);
        }
        let nonce = random_array()?;
        let aad = record_aad(scope, operation, &self.id())?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, self.key.as_slice())
                .map_err(|_| Error::Unavailable)?,
        );
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut ciphertext,
        )
        .map_err(|_| Error::Unavailable)?;
        Ok(EncryptedPayload {
            key_id: self.id(),
            nonce,
            ciphertext,
        })
    }
    pub fn decrypt(
        &self,
        scope: &Scope,
        operation: &Operation,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.decrypt_versioned(
            scope,
            &VersionedOperation {
                operation: operation.clone(),
                version: OperationVersion::V2,
            },
        )
    }
    pub(crate) fn decrypt_versioned(
        &self,
        scope: &Scope,
        operation: &VersionedOperation,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let payload = &operation.operation.payload;
        if payload.key_id != self.id() {
            return Err(Error::Locked);
        }
        if !(16..=MAX_PLAIN_BYTES + 16).contains(&payload.ciphertext.len()) {
            return Err(Error::Invalid);
        }
        let aad = record_aad(scope, operation, &self.id())?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, self.key.as_slice())
                .map_err(|_| Error::Unavailable)?,
        );
        let mut plain = Zeroizing::new(payload.ciphertext.clone());
        let length = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(payload.nonce),
                aead::Aad::from(aad),
                plain.as_mut_slice(),
            )
            .map_err(|_| Error::Authentication)?
            .len();
        plain.truncate(length);
        Ok(plain)
    }
}
fn record_aad(scope: &Scope, operation: &VersionedOperation, key: &str) -> Result<Vec<u8>, Error> {
    validate_scope(scope)?;
    serde_json::to_vec(
        &operation
            .aad(
                AadScope {
                    origin: &scope.origin,
                    tenant: &scope.tenant,
                    user: &scope.user,
                },
                key,
            )
            .map_err(|_| Error::Invalid)?,
    )
    .map_err(|_| Error::Invalid)
}
fn random(bytes: &mut [u8]) -> Result<(), Error> {
    SystemRandom::new()
        .fill(bytes)
        .map_err(|_| Error::Unavailable)
}
fn random_array<const N: usize>() -> Result<[u8; N], Error> {
    let mut bytes = [0; N];
    random(&mut bytes)?;
    Ok(bytes)
}
fn validate_scope(scope: &Scope) -> Result<(), Error> {
    if scope.origin.is_empty() || scope.origin.len() > 2048 {
        return Err(Error::Invalid);
    }
    nddev_device_sync_domain::TenantId::new(&scope.tenant).map_err(|_| Error::Invalid)?;
    nddev_device_sync_domain::UserId::new(&scope.user).map_err(|_| Error::Invalid)?;
    nddev_device_sync_domain::DeviceId::new(&scope.device).map_err(|_| Error::Invalid)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::{DeviceId, sync::EntityKind};
    fn scope(device: &str) -> Scope {
        Scope {
            origin: "https://instance.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: device.into(),
        }
    }
    fn operation() -> Operation {
        Operation {
            id: "operation".into(),
            device: DeviceId::new("device-1").unwrap(),
            entity_kind: EntityKind::VaultRecord,
            entity_id: "record".into(),
            base_revision: 0,
            idempotency_key: "operation".into(),
            payload: EncryptedPayload {
                key_id: "pending".into(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        }
    }
    #[test]
    fn actual_aead_rejects_tampering_and_cross_owner_entity_operation_reuse() {
        let key = VaultKey::generate().unwrap();
        let scope = scope("device-1");
        let mut operation = operation();
        let plaintext = b"actual vault plaintext stays outside server storage";
        operation.payload = key.encrypt(&scope, &operation, plaintext).unwrap();
        assert_eq!(
            key.decrypt(&scope, &operation).unwrap().as_slice(),
            plaintext
        );
        assert!(
            !operation
                .payload
                .ciphertext
                .windows(plaintext.len())
                .any(|value| value == plaintext)
        );
        operation.payload.ciphertext[0] ^= 1;
        assert!(matches!(
            key.decrypt(&scope, &operation),
            Err(Error::Authentication)
        ));
        operation.payload.ciphertext[0] ^= 1;
        let other = Scope {
            user: "other".into(),
            ..scope.clone()
        };
        assert!(matches!(
            key.decrypt(&other, &operation),
            Err(Error::Authentication)
        ));
        operation.entity_id = "other-record".into();
        assert!(matches!(
            key.decrypt(&scope, &operation),
            Err(Error::Authentication)
        ));
    }
}
