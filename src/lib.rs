//! Native E2EE adapters. No plaintext or decryption key is sent to the server.
mod client;
mod codec;
pub use client::VaultClient;
pub mod view;
pub use view::{RecordView, VaultError as Error, VaultView};
pub mod crypto;
mod journal;
