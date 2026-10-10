//! Native E2EE adapters. No plaintext or decryption key is sent to the server.
mod client;
mod codec;
pub use client::{RecordView, VaultClient, VaultView};
pub mod crypto;
mod journal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Error {
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

impl Error {
    /// Stable presentation class; never an underlying driver/secret message.
    pub fn code(&self) -> String {
        self.to_string()
    }
}
