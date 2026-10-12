use super::*;

pub(super) fn kind(kind: &wire::EntityType) -> &'static str {
    match kind {
        wire::EntityType::AccountState => "account_state",
        wire::EntityType::ClipboardItem => "clipboard_item",
        wire::EntityType::DeviceState => "device_state",
        wire::EntityType::ModuleState => "module_state",
        wire::EntityType::VaultRecord => "vault_record",
    }
}
pub(super) fn apply(
    tx: &rusqlite::Transaction<'_>,
    operation: &wire::SyncOperation,
    body: &[u8],
    outcome: &wire::Sync,
    result: &[u8],
    resolved: u64,
) -> Result<(), Error> {
    crate::codec::operation(operation, body.len())?;
    let kind = kind(&operation.entity_type);
    match outcome {
        wire::Sync::Applied(value) => {
            if value.operation_id != operation.operation_id
                || value.revision != operation.base_revision + 1
                || value.server_seq < 1
                || resolved >= value.server_seq as u64
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT INTO entities(kind,id,revision,body,server_seq) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(kind,id) DO UPDATE SET revision=EXCLUDED.revision,body=EXCLUDED.body,server_seq=EXCLUDED.server_seq WHERE entities.revision<EXCLUDED.revision OR (entities.revision=EXCLUDED.revision AND entities.body=EXCLUDED.body AND entities.server_seq=0)",params![kind,operation.entity_id,value.revision,body,value.server_seq]).map_err(sql_failed)?;
            if resolved > 0 {
                if kind != "vault_record" {
                    return Err(Error::Invalid);
                }
                tx.execute("DELETE FROM conflicts WHERE kind=?1 AND entity_id=?2 AND json_extract(CAST(result AS TEXT),'$.server_seq')<=?3", params![kind,operation.entity_id,resolved]).map_err(sql_failed)?;
            }
        }
        wire::Sync::Conflict(value) => {
            if value.operation_id != operation.operation_id
                || value.base_revision != operation.base_revision
                || value.current_revision < 0
                || value.server_seq < 1
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT OR IGNORE INTO conflicts(id,kind,entity_id,body,result) VALUES(?1,?2,?3,?4,?5)",params![operation.operation_id,kind,operation.entity_id,body,result]).map_err(sql_failed)?;
        }
    }
    Ok(())
}
