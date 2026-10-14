use super::*;

pub(super) fn same_operation(body: &[u8], operation: &wire::SyncOperation) -> Result<bool, Error> {
    let stored: wire::SyncOperation = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    Ok(crate::codec::operation(&stored, body.len())?
        == crate::codec::operation(
            operation,
            serde_json::to_vec(operation).map_err(failed)?.len(),
        )?)
}

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
    let validated = crate::codec::operation(operation, body.len())?;
    crate::codec::receipt(outcome)?.validate_for(&validated)?;
    let kind = kind(&operation.entity_type);
    match outcome {
        wire::Sync::Applied(value) => {
            if resolved >= value.server_seq as u64 {
                return Err(Error::Invalid);
            }
            checkpoint::apply_original(
                tx,
                &RawRow {
                    legacy_resolved: 0,
                    body: body.to_vec(),
                    result: result.to_vec(),
                    status: 201,
                    sequence: crate::codec::receipt(outcome)?.server_seq,
                },
            )?;
            if resolved > 0 {
                if kind != "vault_record" {
                    return Err(Error::Invalid);
                }
                tx.execute("DELETE FROM v3_conflicts WHERE kind=?1 AND entity_id=?2 AND json_extract(CAST(result AS TEXT),'$.server_seq')<=?3", params![kind,operation.entity_id,resolved]).map_err(sql_failed)?;
            }
        }
        wire::Sync::Conflict(_) => {
            // Owner scope is fixed by the replica; operation IDs are unique
            // only within one device. JSON tuple encoding is unambiguous even
            // when identifiers contain punctuation allowed by the protocol.
            let id = serde_json::to_string(&(&operation.device_id, &operation.operation_id))
                .map_err(failed)?;
            let inserted = tx.execute("INSERT OR IGNORE INTO v3_conflicts(id,kind,entity_id,body,result) VALUES(?1,?2,?3,?4,?5)",params![id,kind,operation.entity_id,body,result]).map_err(sql_failed)?;
            if inserted == 0 {
                let (stored_body, stored_result): (Vec<u8>, Vec<u8>) = tx
                    .query_row(
                        "SELECT body,result FROM v3_conflicts WHERE id=?1",
                        [&id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(sql_failed)?;
                let stored: wire::Sync =
                    serde_json::from_slice(&stored_result).map_err(|_| Error::Invalid)?;
                if !same_operation(&stored_body, operation)?
                    || crate::codec::receipt(&stored)? != crate::codec::receipt(outcome)?
                {
                    return Err(Error::Invalid);
                }
            }
        }
    }
    let seq = crate::codec::receipt(outcome)?.server_seq;
    tx.execute(
        "UPDATE v3_meta SET known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",
        [seq],
    )
    .map_err(sql_failed)?;
    Ok(())
}
