//! Public presentation metadata and redacted error classes only.
#[derive(Clone, Default)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct VaultView {
    pub unlocked: bool,
    pub key_id: String,
    pub pending: u32,
    pub conflicts: u32,
    pub cursor: u64,
    /// Local durable mutation counter, independent of the committed cursor.
    pub local_revision: u64,
    pub last_sync_at: u64,
    pub catching_up: bool,
    pub sync_error: String,
    /// Browser retention preference observed at client startup; native is None.
    /// Even persistent browser storage can be cleared explicitly by the user.
    pub browser_persistent: Option<bool>,
}
#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct ConflictView {
    pub title: String,
    pub username: String,
    pub device_id: String,
    pub deleted: bool,
}
#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct RecordView {
    pub observed_seq: u64,
    pub deleted: bool,
    pub id: String,
    pub title: String,
    pub username: String,
    pub revision: u64,
    /// Local operation identity for optimistic editing; not a server revision.
    pub pending_id: Option<String>,
    pub conflicted: bool,
    pub conflict: Option<ConflictView>,
}

#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct RecordPage {
    pub observed_seq: u64,
    pub local_revision: u64,
    pub items: Vec<RecordView>,
    pub next_after: String,
    pub has_more: bool,
}

#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct StateView {
    pub kind: String,
    pub id: String,
    pub device_id: String,
    pub label: String,
    pub version: String,
    pub platform: String,
    pub reachability: String,
    pub configured: bool,
    pub checked_at_ms: u64,
    pub observed_at_ms: u64,
    pub expires_at_ms: u64,
    pub error_class: String,
    pub revision: u64,
    pub pending_id: Option<String>,
    pub conflicted: bool,
}
#[derive(Clone)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct StatePage {
    pub observed_seq: u64,
    pub local_revision: u64,
    pub items: Vec<StateView>,
    pub next_after: String,
    pub has_more: bool,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, thiserror::Error, serde::Serialize, serde::Deserialize,
)]
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
    #[error("vault_selection_changed")]
    SelectionChanged,
    #[error("vault_cancelled")]
    Cancelled,
    #[error("vault_storage_full")]
    StorageFull,
    #[error("sync_capacity_exhausted")]
    CapacityExhausted,
    #[error("vault_key_registration_required")]
    RegistrationRequired,
}

impl VaultError {
    /// Stable presentation class; never an underlying driver/secret message.
    pub fn code(&self) -> String {
        self.to_string()
    }
}

/// Clipboard metadata only; plaintext is consumed by the native OS adapter.
#[derive(Clone, Default)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    derive(tsify::Tsify, serde::Serialize)
)]
#[cfg_attr(
    all(target_arch = "wasm32", feature = "browser-bindings"),
    tsify(large_number_types_as_bigints, missing_as_null)
)]
pub struct ClipboardView {
    pub present: bool,
    pub id: String,
    pub device_id: String,
    pub server_seq: u64,
    pub bytes: u32,
    pub conflicted: bool,
}
