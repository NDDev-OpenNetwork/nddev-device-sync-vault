use super::*;

pub(super) fn entity(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<Entity>, Error> {
    connection.query_row("SELECT revision,body,server_seq,conflicted,pending_id,next_base FROM local_entities WHERE kind=?1 AND id=?2",params![kind,id],read_entity).optional().map_err(sql_failed)
}
fn read_entity(row: &rusqlite::Row<'_>) -> rusqlite::Result<Entity> {
    Ok(Entity {
        revision: row.get(0)?,
        body: row.get(1)?,
        server_seq: row.get(2)?,
        conflicted: row.get(3)?,
        pending_id: row.get(4)?,
        next_base: row.get(5)?,
    })
}
fn conflict(connection: &Connection, id: &str) -> Result<Option<Vec<u8>>, Error> {
    // A blocked successor is the latest local intent. Preserve it even though
    // only its predecessor received a server conflict receipt.
    connection.query_row("SELECT COALESCE(
        (SELECT body FROM outbox WHERE kind='vault_record' AND entity_id=?1 AND state='conflict' ORDER BY rowid DESC LIMIT 1),
        (SELECT body FROM conflicts WHERE kind='vault_record' AND entity_id=?1 ORDER BY json_extract(CAST(result AS TEXT),'$.server_seq') DESC LIMIT 1))",[id],|r|r.get(0)).map_err(sql_failed)
}
impl Journal {
    pub fn cursor(&self) -> Result<u64, Error> {
        self.connection()?
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)
    }
    pub fn stats(&self) -> Result<(u32, u32, u64, u64), Error> {
        self.connection()?.query_row("SELECT (SELECT count(*) FROM outbox WHERE state='pending'),((SELECT count(*) FROM conflicts)+(SELECT count(*) FROM outbox o WHERE state='conflict' AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.kind=o.kind AND c.entity_id=o.entity_id))),cursor,last_sync_at FROM meta WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(sql_failed)
    }
    #[cfg(test)]
    pub fn counts(&self) -> Result<(u32, u32), Error> {
        let (p, c, _, _) = self.stats()?;
        Ok((p, c))
    }
    pub fn entity(&self, kind: &str, id: &str) -> Result<Option<Entity>, Error> {
        entity(&self.connection()?, kind, id)
    }
    pub fn resolution(&self, id: &str) -> Result<(Entity, Option<Vec<u8>>, u64), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction().map_err(sql_failed)?;
        let entity = entity(&tx, "vault_record", id)?.ok_or(Error::Invalid)?;
        let conflict = conflict(&tx, id)?;
        let cursor = tx
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok((entity, conflict, cursor))
    }
    pub fn record_page(&self, after: &str) -> Result<(Vec<RecordEntry>, u64), Error> {
        let mut connection = self.connection()?;
        let tx = connection.transaction().map_err(sql_failed)?;
        let mut entries = {
            let mut query=tx.prepare("SELECT revision,body,server_seq,conflicted,pending_id,next_base,id FROM local_entities WHERE kind='vault_record' AND id>?1 ORDER BY id LIMIT 51").map_err(sql_failed)?;
            query
                .query_map([after], |row| {
                    Ok(RecordEntry {
                        id: row.get(6)?,
                        entity: read_entity(row)?,
                        conflict: None,
                    })
                })
                .map_err(sql_failed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_failed)?
        };
        for entry in &mut entries {
            if entry.entity.conflicted {
                entry.conflict = conflict(&tx, &entry.id)?;
            }
        }
        let cursor = tx
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok((entries, cursor))
    }
    pub fn latest_clipboard(&self) -> Result<Option<(String, Entity)>, Error> {
        self.connection()?.query_row("SELECT revision,body,server_seq,EXISTS(SELECT 1 FROM conflicts WHERE kind='clipboard_item' AND entity_id=entities.id),NULL,revision,id FROM entities WHERE kind='clipboard_item' AND server_seq>0 ORDER BY server_seq DESC LIMIT 1",[],|r|Ok((r.get(6)?,read_entity(r)?))).optional().map_err(sql_failed)
    }
    pub fn state_page(
        &self,
        after: Option<(String, String)>,
    ) -> Result<Vec<(String, String, Entity)>, Error> {
        let connection = self.connection()?;
        let (kind, id) = after.map_or((None, None), |(k, i)| (Some(k), Some(i)));
        let mut query=connection.prepare("SELECT revision,body,server_seq,conflicted,pending_id,next_base,kind,id FROM local_entities WHERE kind IN ('device_state','module_state','account_state') AND (?1 IS NULL OR (kind,id)>(?1,?2)) ORDER BY kind,id LIMIT 51").map_err(sql_failed)?;
        query
            .query_map(params![kind, id], |r| {
                Ok((r.get(6)?, r.get(7)?, read_entity(r)?))
            })
            .map_err(sql_failed)?
            .collect::<Result<_, _>>()
            .map_err(sql_failed)
    }
    pub fn caught_up(&self, cursor: u64, at: u64) -> Result<bool, Error> {
        Ok(self.connection()?.execute("UPDATE meta SET last_sync_at=?1 WHERE singleton=1 AND cursor=?2 AND NOT EXISTS(SELECT 1 FROM outbox WHERE state='pending')",params![at,cursor]).map_err(sql_failed)?==1)
    }
}
