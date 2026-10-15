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
        (SELECT body FROM v3_outbox WHERE kind='vault_record' AND entity_id=?1 AND state='conflict' ORDER BY rowid DESC LIMIT 1),
        (SELECT body FROM v3_conflicts WHERE kind='vault_record' AND entity_id=?1 ORDER BY json_extract(CAST(result AS TEXT),'$.server_seq') DESC LIMIT 1))",[id],|r|r.get(0)).map_err(sql_failed)
}
pub(super) fn selected_current(
    connection: &Connection,
    selected: &nddev_device_sync_domain::repositories::catalog::CredentialSelection,
) -> Result<Entity, Error> {
    selected.validate().map_err(|_| Error::Invalid)?;
    let record = entity(connection, "vault_record", selected.record_ref())?
        .ok_or(Error::SelectionChanged)?;
    if record.conflicted
        || record.revision != selected.revision()
        || record.pending_id.as_deref() != selected.pending_id()
    {
        return Err(Error::SelectionChanged);
    }
    let operation = crate::codec::versioned(&record.body)?;
    if operation.operation.entity_kind != nddev_device_sync_domain::sync::EntityKind::VaultRecord
        || operation.operation.entity_id != selected.record_ref()
    {
        return Err(Error::Invalid);
    }
    Ok(record)
}
impl Journal {
    pub(crate) fn repository_page(&self, after: &str) -> Result<CatalogRows, Error> {
        if !after.is_empty()
            && (nddev_device_sync_domain::ModuleId::new(after).is_err()
                || !after.starts_with("github:repo:"))
        {
            return Err(Error::Invalid);
        }
        self.read(|connection| {
            let (cursor, local_revision) = catalog_revision(connection)?;
            let mut query = connection.prepare(
                "SELECT id,revision,body,server_seq,conflicted,pending_id,next_base FROM local_entities WHERE kind='repository_state' AND id GLOB 'github:repo:*' AND id>?1 ORDER BY id LIMIT ?2",
            ).map_err(sql_failed)?;
            let entries = query.query_map(
                params![after, (nddev_device_sync_domain::repositories::catalog::REPOSITORIES_PER_PAGE + 1) as u32],
                read_catalog_entry,
            ).map_err(sql_failed)?.collect::<Result<Vec<_>, _>>().map_err(sql_failed)?;
            Ok(CatalogRows { entries, cursor, local_revision })
        })
    }
    /// Resolve this page's owner headers under the same observed local revision.
    /// No transaction remains open while the main Rust owner decrypts the page.
    pub(crate) fn repository_owners(
        &self,
        ids: &[String],
        expected: u64,
    ) -> Result<CatalogRows, Error> {
        let unique = ids.iter().collect::<std::collections::BTreeSet<_>>();
        if ids.len() > nddev_device_sync_domain::repositories::catalog::REPOSITORIES_PER_PAGE
            || unique.len() != ids.len()
            || ids.iter().any(|id| {
                nddev_device_sync_domain::ModuleId::new(id.as_str()).is_err()
                    || !id.starts_with("github:owner:")
            })
        {
            return Err(Error::Invalid);
        }
        self.read(|connection| {
            let (cursor, local_revision) = catalog_revision(connection)?;
            if local_revision != expected {
                return Err(Error::Busy);
            }
            let mut entries = Vec::new();
            for id in ids {
                if let Some(value) = entity(connection, "repository_state", id)? {
                    entries.push((id.clone(), value));
                }
            }
            Ok(CatalogRows {
                entries,
                cursor,
                local_revision,
            })
        })
    }
    pub(crate) fn edit_target(
        &self,
        kind: &str,
        id: &str,
        known: u64,
    ) -> Result<EditTarget, Error> {
        if known > nddev_device_sync_domain::sync::MAX_REVISION {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE v3_meta SET known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",
            [known],
        )
        .map_err(sql_failed)?;
        let target = EditTarget {
            entity: entity(&tx, kind, id)?,
            committed: tx
                .query_row(
                    "SELECT body FROM v3_entities WHERE kind=?1 AND id=?2",
                    params![kind, id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(sql_failed)?,
            writer: writer::read(&tx)?,
        };
        tx.commit().map_err(sql_failed)?;
        Ok(target)
    }
    pub fn observation_target(&self, id: &str) -> Result<ObservationTarget, Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Deferred)?;
        let effective = entity(&tx, "repository_state", id)?;
        let cursor = tx
            .query_row("SELECT cursor FROM v3_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok(ObservationTarget { effective, cursor })
    }
    /// One short metadata/selection transaction before provider I/O.
    /// Canonical key parsing and decisions remain in Core/main Rust.
    pub fn observation_baselines(
        &self,
        selected: &nddev_device_sync_domain::repositories::catalog::CredentialSelection,
    ) -> Result<ObservationBaselines, Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Deferred)?;
        let selected_operation = selected_current(&tx, selected)?.body;
        let targets = {
            let mut query = tx.prepare("SELECT id,revision,next_base,pending_id,conflicted FROM local_entities WHERE kind='repository_state' ORDER BY id LIMIT ?1").map_err(sql_failed)?;
            query
                .query_map([(nddev_device_sync_application::repositories::catalog::observations::MAX_BASELINES + 1) as u32], |row| {
                    Ok(ObservationMetadata {
                        id: row.get(0)?,
                        revision: row.get(1)?,
                        next_base: row.get(2)?,
                        pending_id: row.get(3)?,
                        conflicted: row.get(4)?,
                    })
                })
                .map_err(sql_failed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_failed)?
        };
        if targets.len()
            > nddev_device_sync_application::repositories::catalog::observations::MAX_BASELINES
        {
            return Err(Error::Busy);
        }
        let writer = writer::read(&tx)?;
        tx.commit().map_err(sql_failed)?;
        Ok(ObservationBaselines {
            selected_operation,
            targets,
            writer,
        })
    }
    pub fn cursor(&self) -> Result<u64, Error> {
        self.read(|connection| {
            connection
                .query_row("SELECT cursor FROM v3_meta WHERE singleton=1", [], |r| {
                    r.get(0)
                })
                .map_err(sql_failed)
        })
    }
    pub fn stats(&self) -> Result<(u32, u32, u64, u64, u64), Error> {
        self.read(|connection| connection.query_row("SELECT (SELECT count(*) FROM v3_outbox WHERE state='pending'),((SELECT count(*) FROM v3_conflicts)+(SELECT count(*) FROM v3_outbox o WHERE state='conflict' AND NOT EXISTS(SELECT 1 FROM v3_conflicts c WHERE c.kind=o.kind AND c.entity_id=o.entity_id))),cursor,last_sync_at,local_revision FROM v3_meta WHERE singleton=1",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).map_err(sql_failed))
    }
    #[cfg(test)]
    pub fn counts(&self) -> Result<(u32, u32), Error> {
        let (p, c, _, _, _) = self.stats()?;
        Ok((p, c))
    }
    pub fn entity(&self, kind: &str, id: &str) -> Result<Option<Entity>, Error> {
        self.read(|connection| entity(connection, kind, id))
    }
    pub(crate) fn resolution(
        &self,
        id: &str,
    ) -> Result<(Entity, Option<Vec<u8>>, ResolutionGuard), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Deferred)?;
        let entity = entity(&tx, "vault_record", id)?.ok_or(Error::Invalid)?;
        let conflict = conflict(&tx, id)?;
        let (_, _, guard) = resolution_evidence(&tx, "vault_record", id)?;
        tx.commit().map_err(sql_failed)?;
        Ok((entity, conflict, guard))
    }
    pub(crate) fn observation_resolution(
        &self,
        id: &str,
        selected: &nddev_device_sync_domain::repositories::catalog::CredentialSelection,
        selected_operation: &[u8],
    ) -> Result<ObservationResolution, Error> {
        self.read(|connection| {
            if selected_current(connection, selected)?.body != selected_operation {
                return Err(Error::SelectionChanged);
            }
            let mut target = entity(connection, "repository_state", id)?.ok_or(Error::Invalid)?;
            if !target.conflicted { return Err(Error::Busy); }
            let dispatched: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM v3_outbox WHERE kind='repository_state' AND entity_id=?1 AND dispatched=1)",
                [id], |r| r.get(0),
            ).map_err(sql_failed)?;
            if dispatched { return Err(Error::Busy); }
            let (committed, conflict, guard) = resolution_evidence(connection, "repository_state", id)?;
            target.body = committed;
            let pending = target.pending_id.as_ref().map(|id| {
                connection.query_row("SELECT body FROM v3_outbox WHERE id=?1 AND dispatched=0", [id], |r| r.get(0)).map_err(sql_failed)
            }).transpose()?;
            if conflict.is_none() && pending.is_none() { return Err(Error::Invalid); }
            Ok(ObservationResolution { target, conflict, pending, guard })
        })
    }

    pub fn record_page(&self, after: &str) -> Result<(Vec<RecordEntry>, u64, u64), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Deferred)?;
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
        let (cursor, local_revision) = tx
            .query_row(
                "SELECT cursor,local_revision FROM v3_meta WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok((entries, cursor, local_revision))
    }
    pub fn latest_clipboard(&self) -> Result<Option<(String, Entity)>, Error> {
        self.read(|connection| connection.query_row("SELECT revision,body,server_seq,EXISTS(SELECT 1 FROM v3_conflicts WHERE kind='clipboard_item' AND entity_id=v3_entities.id),NULL,revision,id FROM v3_entities WHERE kind='clipboard_item' AND server_seq>0 ORDER BY server_seq DESC LIMIT 1",[],|r|Ok((r.get(6)?,read_entity(r)?))).optional().map_err(sql_failed))
    }
    pub fn state_page(
        &self,
        after: Option<(String, String)>,
    ) -> Result<Vec<(String, String, Entity)>, Error> {
        self.read(|connection| {
        let (kind, id) = after.map_or((None, None), |(k, i)| (Some(k), Some(i)));
        let mut query=connection.prepare("SELECT revision,body,server_seq,conflicted,pending_id,next_base,kind,id FROM local_entities WHERE kind IN ('device_state','module_state','account_state') AND (?1 IS NULL OR (kind,id)>(?1,?2)) ORDER BY kind,id LIMIT 51").map_err(sql_failed)?;
        query
            .query_map(params![kind, id], |r| {
                Ok((r.get(6)?, r.get(7)?, read_entity(r)?))
            })
            .map_err(sql_failed)?
            .collect::<Result<_, _>>()
            .map_err(sql_failed)
        })
    }
    pub fn caught_up(&self, cursor: u64, at: u64) -> Result<bool, Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let changed = tx.execute("UPDATE v3_meta SET last_sync_at=?1 WHERE singleton=1 AND cursor=?2 AND known_committed_seq<=cursor AND NOT EXISTS(SELECT 1 FROM v3_outbox WHERE state='pending')",params![at,cursor]).map_err(sql_failed)? == 1;
        tx.commit().map_err(sql_failed)?;
        Ok(changed)
    }
}

fn catalog_revision(connection: &Connection) -> Result<(u64, u64), Error> {
    connection
        .query_row(
            "SELECT cursor,local_revision FROM v3_meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql_failed)
}
fn read_catalog_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<(String, Entity)> {
    Ok((
        row.get(0)?,
        Entity {
            revision: row.get(1)?,
            body: row.get(2)?,
            server_seq: row.get(3)?,
            conflicted: row.get(4)?,
            pending_id: row.get(5)?,
            next_base: row.get(6)?,
        },
    ))
}

/// Shared resolution read: exact committed bytes and complete scoped receipt
/// witnesses from one transaction. Only the latest original crosses IPC; all
/// witnesses contribute to the existing lifecycle rule without loading a second
/// complete ciphertext set into memory.
fn resolution_evidence(
    connection: &Connection,
    kind: &str,
    id: &str,
) -> Result<(Vec<u8>, Option<RawRow>, ResolutionGuard), Error> {
    let (cursor, local_revision, known): (u64, u64, u64) = connection
        .query_row(
            "SELECT cursor,local_revision,known_committed_seq FROM v3_meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(sql_failed)?;
    let body: Vec<u8> = connection
        .query_row(
            "SELECT body FROM v3_entities WHERE kind=?1 AND id=?2",
            params![kind, id],
            |r| r.get(0),
        )
        .map_err(sql_failed)?;
    let committed = crate::codec::versioned(&body)?;
    if committed.operation.entity_kind.as_str() != kind || committed.operation.entity_id != id {
        return Err(Error::Invalid);
    }
    let mut sequences = Vec::new();
    let mut latest: Option<RawRow> = None;
    let mut query = connection
        .prepare("SELECT body,result FROM v3_conflicts WHERE kind=?1 AND entity_id=?2 LIMIT ?3")
        .map_err(sql_failed)?;
    let mut rows = query
        .query(params![
            kind,
            id,
            nddev_device_sync_domain::sync::MAX_OPERATIONS + 1
        ])
        .map_err(sql_failed)?;
    while let Some(row) = rows.next().map_err(sql_failed)? {
        let request: Vec<u8> = row.get(0).map_err(sql_failed)?;
        let result: Vec<u8> = row.get(1).map_err(sql_failed)?;
        let (operation, receipt) = crate::codec::original_receipt(&request, &result, 409)?;
        if operation.operation.entity_kind != committed.operation.entity_kind
            || operation.operation.entity_id != id
        {
            return Err(Error::Invalid);
        }
        sequences.push(receipt.server_seq);
        if latest
            .as_ref()
            .is_none_or(|old| old.sequence < receipt.server_seq)
        {
            latest = Some(RawRow {
                body: request,
                result,
                status: 409,
                sequence: receipt.server_seq,
                legacy_resolved: 0,
            });
        }
    }
    let lifecycle = nddev_device_sync_domain::sync::history::resolution_lifecycle(
        committed.lifecycle(),
        &sequences,
        cursor.max(known),
    )?;
    Ok((
        body,
        latest,
        ResolutionGuard {
            cursor,
            local_revision,
            lifecycle,
        },
    ))
}
