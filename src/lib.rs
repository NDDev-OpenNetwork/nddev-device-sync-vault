//! Native encrypted replica and server-managed key provisioning adapters.
mod client;
mod codec;
pub use client::VaultClient;
pub mod view;
pub use view::{RecordView, VaultError as Error, VaultView};
pub mod crypto;
mod journal;
