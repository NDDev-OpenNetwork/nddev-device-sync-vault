//! Native encrypted replica and server-managed key provisioning adapters.
mod client;
mod codec;
mod key_discovery;
pub use client::{
    CheckpointStage, InboxProgress, RepositoryCatalogCursor, RepositoryCatalogPage,
    RepositoryPublication, RepositoryRead, VaultClient,
};
use nddev_device_sync_accounts::sync3_wire;
pub mod view;
pub use view::{RecordView, VaultError as Error, VaultView};
#[cfg(target_arch = "wasm32")]
pub mod browser;
pub mod crypto;
mod journal;
mod storage;
