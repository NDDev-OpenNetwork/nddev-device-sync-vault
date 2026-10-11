//! Browser storage composition. Only encrypted journal commands reach the owned
//! worker; credentials and record decryption stay in the client adapter.
use crate::{
    Error,
    journal::Journal,
    storage::{Command, Reply},
};
use std::cell::RefCell;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

const MAX_IPC: usize = 8 * 1024 * 1024;
#[wasm_bindgen(module = "/src/browser_journal.js")]
extern "C" {
    #[wasm_bindgen(catch,js_name=configureJournal)]
    fn configure(worker: &str, module: &str) -> Result<(), JsValue>;
    #[wasm_bindgen(catch,js_name=journalRequest)]
    fn call(scope: &str, command: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(catch,js_name=acquireKey)]
    fn acquire_key(id: &str, scope: &str) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(js_name=releaseKey)]
    fn release_key(id: &str);
}
fn failure(value: JsValue) -> Error {
    use wasm_bindgen::JsCast;
    if value
        .dyn_ref::<js_sys::Error>()
        .is_some_and(|e| e.message() == "vault_busy")
    {
        Error::Busy
    } else {
        Error::Unavailable
    }
}
pub fn configure_worker(worker_url: &str, module_url: &str) -> Result<(), Error> {
    configure(worker_url, module_url).map_err(failure)
}
pub(crate) async fn request(scope: &str, command: Command) -> Result<Reply, Error> {
    let command = serde_json::to_string(&command).map_err(|_| Error::Invalid)?;
    if command.len() > MAX_IPC {
        return Err(Error::Invalid);
    }
    let promise = call(scope, &command).map_err(failure)?;
    let output = JsFuture::from(promise)
        .await
        .map_err(failure)?
        .as_string()
        .filter(|s| s.len() <= MAX_IPC)
        .ok_or(Error::Invalid)?;
    serde_json::from_str::<Result<Reply, Error>>(&output).map_err(|_| Error::Invalid)?
}
pub struct KeyLock {
    id: String,
}
impl Drop for KeyLock {
    fn drop(&mut self) {
        release_key(&self.id);
    }
}
pub(crate) async fn key_lock(scope: &str) -> Result<KeyLock, Error> {
    let lock = KeyLock {
        id: uuid::Uuid::new_v4().to_string(),
    };
    JsFuture::from(acquire_key(&lock.id, scope).map_err(failure)?)
        .await
        .map_err(failure)?;
    Ok(lock)
}

thread_local! {
    static POOL:RefCell<Option<sqlite_wasm_vfs::sahpool::OpfsSAHPoolUtil>>=const {RefCell::new(None)};
    static SCOPE:RefCell<Option<String>>=const {RefCell::new(None)};
}
/// Called only by the composition root's explicit WASM worker entrypoint.
pub async fn worker_open(scope: String) -> Result<(), Error> {
    if scope.len() != 64
        || !scope
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || SCOPE.with(|s| s.borrow().is_some())
    {
        return Err(Error::Invalid);
    }
    std::panic::set_hook(Box::new(|_| {}));
    let cfg = sqlite_wasm_vfs::sahpool::OpfsSAHPoolCfg {
        directory: format!("/nds-replica/{scope}"),
        initial_capacity: 4,
        ..Default::default()
    };
    let pool = sqlite_wasm_vfs::sahpool::install::<sqlite_wasm_rs::WasmOsCallback>(&cfg, true)
        .await
        .map_err(|_| Error::Unavailable)?;
    pool.pause_vfs().map_err(|_| Error::Unavailable)?;
    SCOPE.with(|s| s.replace(Some(scope)));
    POOL.with(|s| s.replace(Some(pool)));
    Ok(())
}
pub async fn worker_resume() -> Result<(), Error> {
    let pool = POOL
        .with(|s| s.borrow_mut().take())
        .ok_or(Error::Unavailable)?;
    let result = pool.unpause_vfs().await.map_err(|_| Error::Unavailable);
    POOL.with(|s| s.replace(Some(pool)));
    result
}
pub fn worker_pause() -> Result<(), Error> {
    POOL.with(|s| {
        s.borrow()
            .as_ref()
            .ok_or(Error::Unavailable)?
            .pause_vfs()
            .map_err(|_| Error::Unavailable)
    })
}
pub fn worker_execute(command: &str) -> Result<String, Error> {
    if command.len() > MAX_IPC || SCOPE.with(|s| s.borrow().is_none()) {
        return Err(Error::Invalid);
    }
    let command: Command = serde_json::from_str(command).map_err(|_| Error::Invalid)?;
    let result = Journal::open("replica.db".into())
        .and_then(|journal| crate::storage::execute(&journal, command));
    let output = serde_json::to_string(&result).map_err(|_| Error::Invalid)?;
    if output.len() > MAX_IPC {
        return Err(Error::Invalid);
    }
    Ok(output)
}
