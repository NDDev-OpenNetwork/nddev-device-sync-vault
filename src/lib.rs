//! Native encrypted replica and server-managed key provisioning adapters.
mod client;
mod codec;
pub use client::{InboxProgress, VaultClient};
pub mod view;
pub use view::{RecordView, VaultError as Error, VaultView};
#[cfg(target_arch = "wasm32")]
pub mod browser;
pub mod crypto;
mod journal;
mod storage;
