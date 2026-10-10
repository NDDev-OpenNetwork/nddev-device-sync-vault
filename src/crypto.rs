//! Maintained native AES-GCM, X25519 and HKDF primitives; no bespoke cipher.
use crate::Error;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nddev_device_sync_domain::sync::{EncryptedPayload, MAX_PLAIN_BYTES, Operation};
use ring::{
    aead, agreement, hkdf,
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Clone)]
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
        let payload = &operation.payload;
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
fn record_aad(scope: &Scope, operation: &Operation, key: &str) -> Result<Vec<u8>, Error> {
    validate_scope(scope)?;
    serde_json::to_vec(&(
        "NDS-RECORD-V2",
        &scope.origin,
        &scope.tenant,
        &scope.user,
        operation.device.as_str(),
        operation.entity_kind.as_str(),
        &operation.entity_id,
        &operation.id,
        operation.base_revision,
        key,
    ))
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
fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}
fn decode<const N: usize>(value: &str) -> Result<[u8; N], Error> {
    if value.len() != (N * 8).div_ceil(6) {
        return Err(Error::Invalid);
    }
    let bytes = URL_SAFE_NO_PAD.decode(value).map_err(|_| Error::Invalid)?;
    if encode(&bytes) != value {
        return Err(Error::Invalid);
    }
    bytes.try_into().map_err(|_| Error::Invalid)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation {
    pub version: u8,
    pub recipient_device: String,
    pub public_key: String,
    pub challenge: String,
}
/// A public, canonical digest for the owner to compare across the two devices.
pub fn invitation_fingerprint(invitation: &Invitation) -> Result<String, Error> {
    use sha2::{Digest, Sha256};
    if invitation.version != 1 {
        return Err(Error::Invalid);
    }
    nddev_device_sync_domain::DeviceId::new(&invitation.recipient_device)
        .map_err(|_| Error::Invalid)?;
    decode::<32>(&invitation.public_key)?;
    decode::<32>(&invitation.challenge)?;
    let bytes = serde_json::to_vec(invitation).map_err(|_| Error::Invalid)?;
    let digest = Sha256::digest(bytes);
    Ok(digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub version: u8,
    pub recipient_device: String,
    pub sender_device: String,
    pub challenge: String,
    pub public_key: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// One in-memory exchange, consumed once and expiring autonomously. Restart
/// cancels pairing; it never recovers or reconstructs an existing vault key.
pub struct Pairing {
    private: agreement::EphemeralPrivateKey,
    invitation: Invitation,
    expires: Instant,
}
impl Pairing {
    pub fn start(device: &str) -> Result<Self, Error> {
        nddev_device_sync_domain::DeviceId::new(device).map_err(|_| Error::Invalid)?;
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
                .map_err(|_| Error::Unavailable)?;
        let invitation = Invitation {
            version: 1,
            recipient_device: device.into(),
            public_key: encode(
                private
                    .compute_public_key()
                    .map_err(|_| Error::Unavailable)?,
            ),
            challenge: encode(random_array::<32>()?),
        };
        Ok(Self {
            private,
            invitation,
            expires: Instant::now() + Duration::from_secs(300),
        })
    }
    pub fn invitation(&self) -> &Invitation {
        &self.invitation
    }
    pub fn active(&self) -> bool {
        Instant::now() < self.expires
    }
    pub fn code(&self) -> Result<String, Error> {
        serde_json::to_string(&self.invitation).map_err(|_| Error::Invalid)
    }
    pub fn accept(self, scope: &Scope, grant: Grant) -> Result<VaultKey, Error> {
        if Instant::now() >= self.expires
            || grant.version != 1
            || grant.recipient_device != self.invitation.recipient_device
            || grant.recipient_device != scope.device
            || grant.challenge != self.invitation.challenge
        {
            return Err(Error::Invalid);
        }
        nddev_device_sync_domain::DeviceId::new(&grant.sender_device)
            .map_err(|_| Error::Invalid)?;
        let aad = pair_aad(scope, &grant.sender_device, &self.invitation)?;
        let key = shared_key(
            self.private,
            &grant.public_key,
            &self.invitation.challenge,
            &aad,
        )?;
        let bytes = decode::<64>(&grant.ciphertext)?;
        let mut secret = Zeroizing::new(bytes.to_vec());
        let nonce = decode(&grant.nonce)?;
        let length = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                secret.as_mut_slice(),
            )
            .map_err(|_| Error::Authentication)?
            .len();
        VaultKey::from_native_secret(&secret[..length])
    }
}

/// The caller must confirm this exact invitation/recipient with the owner on a
/// trusted device before calling this native operation. Codes/QR carry public
/// invitation data or wrapped key material; never a plaintext vault key.
pub fn grant(scope: &Scope, key: &VaultKey, invitation: Invitation) -> Result<Grant, Error> {
    if invitation.version != 1 || invitation.recipient_device == scope.device {
        return Err(Error::Invalid);
    }
    nddev_device_sync_domain::DeviceId::new(&invitation.recipient_device)
        .map_err(|_| Error::Invalid)?;
    decode::<32>(&invitation.public_key)?;
    decode::<32>(&invitation.challenge)?;
    let private =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &SystemRandom::new())
            .map_err(|_| Error::Unavailable)?;
    let public = encode(
        private
            .compute_public_key()
            .map_err(|_| Error::Unavailable)?,
    );
    let aad = pair_aad(scope, &scope.device, &invitation)?;
    let encryption = shared_key(private, &invitation.public_key, &invitation.challenge, &aad)?;
    let nonce = random_array::<12>()?;
    let mut bytes = key.native_secret();
    encryption
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad),
            &mut *bytes,
        )
        .map_err(|_| Error::Unavailable)?;
    Ok(Grant {
        version: 1,
        recipient_device: invitation.recipient_device,
        sender_device: scope.device.clone(),
        challenge: invitation.challenge,
        public_key: public,
        nonce: encode(nonce),
        ciphertext: encode(bytes.as_slice()),
    })
}
fn pair_aad(scope: &Scope, sender: &str, invitation: &Invitation) -> Result<Vec<u8>, Error> {
    validate_scope(scope)?;
    serde_json::to_vec(&(
        "NDS-VAULT-PAIRING-V1",
        &scope.origin,
        &scope.tenant,
        &scope.user,
        sender,
        &invitation.recipient_device,
        &invitation.public_key,
        &invitation.challenge,
    ))
    .map_err(|_| Error::Invalid)
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

fn shared_key(
    private: agreement::EphemeralPrivateKey,
    public: &str,
    challenge: &str,
    aad: &[u8],
) -> Result<aead::LessSafeKey, Error> {
    let public = decode::<32>(public)?;
    let salt = decode::<32>(challenge)?;
    let peer = agreement::UnparsedPublicKey::new(&agreement::X25519, public);
    agreement::agree_ephemeral(private, &peer, |material| {
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(material);
        let info = [aad];
        let okm = prk
            .expand(&info, &aead::AES_256_GCM)
            .map_err(|_| Error::Unavailable)?;
        Ok(aead::LessSafeKey::new(aead::UnboundKey::from(okm)))
    })
    .map_err(|_| Error::Authentication)?
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
    #[test]
    fn actual_x25519_hkdf_key_grant_allows_another_device_to_decrypt() {
        let first = scope("device-1");
        let second = scope("device-2");
        let key = VaultKey::generate().unwrap();
        let receiver = Pairing::start(&second.device).unwrap();
        let invitation: Invitation = serde_json::from_str(&receiver.code().unwrap()).unwrap();
        let fingerprint = invitation_fingerprint(&invitation).unwrap();
        let mut changed: Invitation = serde_json::from_str(&receiver.code().unwrap()).unwrap();
        changed.recipient_device = "other-device".into();
        assert_ne!(invitation_fingerprint(&changed).unwrap(), fingerprint);
        changed.version = 2;
        assert!(invitation_fingerprint(&changed).is_err());
        let wrapped = grant(&first, &key, invitation).unwrap();
        assert!(
            !wrapped
                .ciphertext
                .contains(&encode(key.native_secret().as_slice()))
        );
        let imported = receiver.accept(&second, wrapped).unwrap();
        assert_eq!(imported.id(), key.id());
        let mut operation = operation();
        operation.payload = key.encrypt(&first, &operation, b"shared secret").unwrap();
        assert_eq!(
            imported.decrypt(&second, &operation).unwrap().as_slice(),
            b"shared secret"
        );
        let wrong = Pairing::start(&second.device).unwrap();
        let invitation: Invitation = serde_json::from_str(&wrong.code().unwrap()).unwrap();
        let mut wrapped = grant(&first, &key, invitation).unwrap();
        wrapped.recipient_device = "other".into();
        assert!(matches!(
            wrong.accept(&second, wrapped),
            Err(Error::Invalid)
        ));
    }
}
