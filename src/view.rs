//! Public presentation metadata and redacted error classes only.
#[derive(Clone, Default)]
pub struct VaultView {
    pub unlocked: bool,
    pub key_id: String,
    pub pending: u32,
    pub conflicts: u32,
    pub cursor: u64,
    pub last_sync_at: u64,
    pub pairing_code: String,
}
#[derive(Clone)]
pub struct RecordView {
    pub id: String,
    pub title: String,
    pub username: String,
    pub revision: u64,
    pub conflicted: bool,
}

#[derive(Clone)]
pub struct PairingPeer {
    pub device_id: String,
    pub name: String,
    pub fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum VaultError {
    #[error("vault_invalid_input")]
    Invalid,
    #[error("vault_locked")]
    Locked,
    #[error("vault_authentication_failed")]
    Authentication,
    #[error("vault_dependency_unavailable")]
    Unavailable,
    #[error("vault_busy")]
    Busy,
    #[error("vault_key_exists")]
    KeyExists,
}

impl VaultError {
    /// Stable presentation class; never an underlying driver/secret message.
    pub fn code(&self) -> String {
        self.to_string()
    }
}
