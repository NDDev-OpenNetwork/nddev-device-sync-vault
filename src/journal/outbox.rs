use super::*;

impl Journal {
    /// Claim immutable roots before any network I/O. Repeated claims return the
    /// same bytes; successors cannot be sent until the predecessor is applied.
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        let entries = {
            let mut query=tx.prepare("SELECT id,body FROM outbox WHERE state='pending' AND predecessor IS NULL ORDER BY rowid LIMIT ?1").map_err(sql_failed)?;
            query
                .query_map(
                    [nddev_device_sync_application::replica::MAX_UPLOADS as u32],
                    |r| {
                        Ok(Pending {
                            id: r.get(0)?,
                            body: r.get(1)?,
                        })
                    },
                )
                .map_err(sql_failed)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_failed)?
        };
        let mut changed = 0;
        for entry in &entries {
            changed += tx
                .execute(
                    "UPDATE outbox SET dispatched=1 WHERE id=?1 AND dispatched=0",
                    [&entry.id],
                )
                .map_err(sql_failed)?;
        }
        if changed > 0 {
            bump(&tx)?;
        }
        tx.commit().map_err(sql_failed)?;
        Ok(entries)
    }
    pub fn enqueue(
        &self,
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
    ) -> Result<Enqueued, Error> {
        if body.len() > 24576 {
            return Err(Error::Invalid);
        }
        let operation: wire::SyncOperation =
            serde_json::from_slice(&body).map_err(|_| Error::Invalid)?;
        crate::codec::operation(&operation, body.len())?;
        let kind = kind(&operation.entity_type);
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        let entity = reads::entity(&tx, kind, &operation.entity_id)?;
        let revision = entity.as_ref().map_or(0, |e| e.revision);
        let pending = entity.as_ref().and_then(|e| e.pending_id.clone());
        let base = entity.as_ref().map_or(0, |e| e.next_base);
        if revision != expected_revision
            || pending != expected_pending
            || operation.base_revision < 0
            || operation.base_revision as u64 != base
        {
            return Err(Error::Busy);
        }
        if let Some(expected) = expected_cursor {
            let actual: u64 = tx
                .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |r| {
                    r.get(0)
                })
                .map_err(sql_failed)?;
            if actual != expected
                || kind != "vault_record"
                || !entity.as_ref().is_some_and(|e| e.conflicted)
            {
                return Err(Error::Busy);
            }
            // An unacknowledged dispatched operation is still immutable. The
            // user must observe its server outcome before resolving the family.
            let in_flight:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM outbox WHERE kind=?1 AND entity_id=?2 AND dispatched=1)",params![kind,operation.entity_id],|r|r.get(0)).map_err(sql_failed)?;
            if in_flight {
                return Err(Error::Busy);
            }
        } else if entity.as_ref().is_some_and(|e| e.conflicted) {
            return Err(Error::Busy);
        }
        let old:Option<(String,u32,Option<String>)>=tx.query_row("SELECT id,dispatched,predecessor FROM outbox WHERE kind=?1 AND entity_id=?2 ORDER BY rowid DESC LIMIT 1",params![kind,operation.entity_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql_failed)?;
        let predecessor = match old {
            Some((id, 0, predecessor)) => {
                tx.execute("DELETE FROM outbox WHERE id=?1", [id])
                    .map_err(sql_failed)?;
                predecessor
            }
            Some((id, _, _)) => Some(id),
            None => None,
        };
        let count: u64 = tx
            .query_row("SELECT count(*) FROM outbox", [], |r| r.get(0))
            .map_err(sql_failed)?;
        if count >= 1024 {
            return Err(Error::Busy);
        }
        tx.execute("INSERT INTO outbox(id,kind,entity_id,body,state,dispatched,predecessor) VALUES(?1,?2,?3,?4,'pending',0,?5)",params![operation.operation_id,kind,operation.entity_id,body,predecessor]).map_err(sql_failed)?;
        bump(&tx)?;
        let receipt=tx.query_row("SELECT (SELECT count(*) FROM outbox WHERE state='pending'),((SELECT count(*) FROM conflicts)+(SELECT count(*) FROM outbox o WHERE state='conflict' AND NOT EXISTS(SELECT 1 FROM conflicts c WHERE c.kind=o.kind AND c.entity_id=o.entity_id))),cursor,local_revision FROM meta WHERE singleton=1",[],|r|Ok(Enqueued{id:operation.operation_id.clone(),pending:r.get(0)?,conflicts:r.get(1)?,cursor:r.get(2)?,local_revision:r.get(3)?})).map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok(receipt)
    }
    pub fn acknowledge(&self, request: &[u8], result: &[u8], resolved: u64) -> Result<(), Error> {
        let operation: wire::SyncOperation =
            serde_json::from_slice(request).map_err(|_| Error::Invalid)?;
        crate::codec::operation(&operation, request.len())?;
        let outcome: wire::Sync = serde_json::from_slice(result).map_err(|_| Error::Invalid)?;
        let outcome_id = match &outcome {
            wire::Sync::Applied(v) => &v.operation_id,
            wire::Sync::Conflict(v) => &v.operation_id,
        };
        if outcome_id != &operation.operation_id {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM outbox WHERE id=?1 AND dispatched=1",
                [&operation.operation_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_failed)?;
        if let Some(body) = body {
            // The response belongs to the exact claimed POST, including its
            // device. An ID alone cannot acknowledge a replacement request.
            if body != request {
                return Err(Error::Invalid);
            }
            apply(&tx, &operation, &body, &outcome, result, resolved)?;
            settle(&tx, &operation, &outcome)?;
            bump(&tx)?;
        }
        // Another process may already have ingested this exact server receipt.
        tx.commit().map_err(sql_failed)
    }
    pub fn ingest(&self, page: &wire::SyncPage, resolutions: &[u64]) -> Result<(), Error> {
        if page.entries.len() > 100
            || page.next_after_seq < 0
            || resolutions.len() != page.entries.len()
        {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        let mut previous: i64 = tx
            .query_row("SELECT cursor FROM meta WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)?;
        for (entry, resolved) in page.entries.iter().zip(resolutions) {
            let seq = match &entry.result {
                wire::Sync::Applied(v) => v.server_seq,
                wire::Sync::Conflict(v) => v.server_seq,
            };
            if seq <= previous {
                return Err(Error::Busy);
            }
            if seq != previous + 1 {
                return Err(Error::Invalid);
            }
            let body = serde_json::to_vec(&entry.operation).map_err(failed)?;
            let result = serde_json::to_vec(&entry.result).map_err(failed)?;
            apply(
                &tx,
                &entry.operation,
                &body,
                &entry.result,
                &result,
                *resolved,
            )?;
            settle(&tx, &entry.operation, &entry.result)?;
            previous = seq;
        }
        if page.next_after_seq != previous || page.has_more && page.entries.is_empty() {
            return Err(Error::Invalid);
        }
        if !page.entries.is_empty() {
            bump(&tx)?;
        }
        tx.execute("UPDATE meta SET cursor=?1 WHERE singleton=1", [previous])
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
}
fn settle(
    tx: &rusqlite::Transaction<'_>,
    operation: &wire::SyncOperation,
    outcome: &wire::Sync,
) -> Result<(), Error> {
    let id = &operation.operation_id;
    let pending: Option<Vec<u8>> = tx
        .query_row("SELECT body FROM outbox WHERE id=?1", [id], |r| r.get(0))
        .optional()
        .map_err(sql_failed)?;
    let Some(pending) = pending else {
        return Ok(());
    };
    // Inbox entries contain parsed operations, not original POST bytes. Match
    // every field after typed decoding; formatting is irrelevant here. Foreign
    // device IDs and any changed content must leave this local family intact.
    if !apply::same_operation(&pending, operation)? {
        return Ok(());
    }
    let state = if matches!(outcome, wire::Sync::Applied(_)) {
        "pending"
    } else {
        "conflict"
    };
    tx.execute(
        "UPDATE outbox SET predecessor=NULL,state=?1 WHERE predecessor=?2",
        params![state, id],
    )
    .map_err(sql_failed)?;
    tx.execute("DELETE FROM outbox WHERE id=?1", [id])
        .map_err(sql_failed)?;
    Ok(())
}

fn bump(tx: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    tx.execute(
        "UPDATE meta SET local_revision=local_revision+1 WHERE singleton=1",
        [],
    )
    .map_err(sql_failed)?;
    Ok(())
}
