//! Exact encrypted repository-family snapshot for a later SQLite CAS. No key,
//! plaintext, authorization or hash is persisted or exposed to presentation.
use super::*;
use ring::digest::{Context, SHA256};

pub(super) fn field(hash: &mut Context, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}

pub(super) fn begin(
    connection: &Connection,
    kind: &str,
    id: &str,
    committed: &[u8],
) -> Result<Context, Error> {
    let mut hash = Context::new(&SHA256);
    field(&mut hash, b"NDS-REPOSITORY-RESOLUTION");
    field(&mut hash, kind.as_bytes());
    field(&mut hash, id.as_bytes());
    field(&mut hash, committed);
    let target = reads::entity(connection, kind, id)?.ok_or(Error::Invalid)?;
    field(&mut hash, &target.body);
    field(
        &mut hash,
        &serde_json::to_vec(&(
            target.revision,
            target.server_seq,
            target.conflicted,
            target.pending_id,
            target.next_base,
        ))
        .map_err(|_| Error::Invalid)?,
    );
    // A family has at most one dispatched root and one unsent successor under
    // the existing unique indexes. Include dispatch/unknown state and lineage.
    let mut query = connection.prepare("SELECT id,body,state,dispatched,predecessor,terminal_unknown_reason FROM v3_outbox WHERE kind=?1 AND entity_id=?2 ORDER BY id LIMIT 3").map_err(sql_failed)?;
    let mut rows = query.query(params![kind, id]).map_err(sql_failed)?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(sql_failed)? {
        count += 1;
        if count > 2 {
            return Err(Error::Invalid);
        }
        let body: Vec<u8> = row.get(1).map_err(sql_failed)?;
        field(&mut hash, b"pending");
        field(&mut hash, &body);
        field(
            &mut hash,
            &serde_json::to_vec(&(
                row.get::<_, String>(0).map_err(sql_failed)?,
                row.get::<_, String>(2).map_err(sql_failed)?,
                row.get::<_, u32>(3).map_err(sql_failed)?,
                row.get::<_, Option<String>>(4).map_err(sql_failed)?,
                row.get::<_, Option<String>>(5).map_err(sql_failed)?,
            ))
            .map_err(|_| Error::Invalid)?,
        );
    }
    Ok(hash)
}
