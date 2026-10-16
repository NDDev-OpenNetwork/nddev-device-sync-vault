use super::*;

impl Journal {
    /// Claim immutable roots before any network I/O. Repeated claims return the
    /// same bytes; successors cannot be sent until the predecessor is applied.
    pub fn pending(&self) -> Result<Vec<Pending>, Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let entries = {
            let mut query=tx.prepare("SELECT id,body FROM v3_outbox WHERE state='pending' AND predecessor IS NULL AND terminal_unknown_reason IS NULL ORDER BY rowid LIMIT ?1").map_err(sql_failed)?;
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
                    "UPDATE v3_outbox SET dispatched=1 WHERE id=?1 AND dispatched=0",
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
        self.enqueue_checked(
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
            None,
            None,
        )
    }
    /// The source selection and prepared writer facts must still match in the
    /// same transaction. Conflict settlement uses its own reviewed transition.
    pub(crate) fn enqueue_observation(
        &self,
        body: Vec<u8>,
        expected_revision: u64,
        expected_pending: Option<String>,
        selected: &nddev_device_sync_domain::repositories::catalog::CredentialSelection,
        selected_operation: &[u8],
        writer: &WriterEnqueueGuard,
    ) -> Result<Enqueued, Error> {
        self.enqueue_checked(
            body,
            None,
            expected_revision,
            expected_pending,
            Some(ObservationEnqueueGuard {
                selected,
                selected_operation,
                resolution: None,
            }),
            Some(writer),
        )
    }
    pub(crate) fn enqueue_observation_resolution(
        &self,
        body: Vec<u8>,
        expected_revision: u64,
        expected_pending: Option<String>,
        source: (
            &nddev_device_sync_domain::repositories::catalog::CredentialSelection,
            &[u8],
        ),
        writer: &WriterEnqueueGuard,
        resolution: &ResolutionGuard,
    ) -> Result<Enqueued, Error> {
        self.enqueue_checked(
            body,
            Some(resolution.cursor),
            expected_revision,
            expected_pending,
            Some(ObservationEnqueueGuard {
                selected: source.0,
                selected_operation: source.1,
                resolution: Some(resolution),
            }),
            Some(writer),
        )
    }
    pub(crate) fn enqueue_writer(
        &self,
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
        writer: &WriterEnqueueGuard,
    ) -> Result<Enqueued, Error> {
        self.enqueue_checked(
            body,
            expected_cursor,
            expected_revision,
            expected_pending,
            None,
            Some(writer),
        )
    }
    fn enqueue_checked(
        &self,
        body: Vec<u8>,
        expected_cursor: Option<u64>,
        expected_revision: u64,
        expected_pending: Option<String>,
        selected: Option<ObservationEnqueueGuard<'_>>,
        writer: Option<&WriterEnqueueGuard>,
    ) -> Result<Enqueued, Error> {
        if body.len() > 24576 {
            return Err(Error::Invalid);
        }
        let versioned = crate::codec::versioned(&body)?;
        let operation = &versioned.operation;
        let kind = operation.entity_kind.as_str();
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        if let Some(writer) = writer {
            writer::guard_enqueue(&tx, writer, &versioned)?;
        }
        if let Some(observation) = &selected {
            if kind != "repository_state" {
                return Err(Error::Invalid);
            }
            let source = reads::selected_current(&tx, observation.selected)?;
            if source.body != observation.selected_operation {
                return Err(Error::SelectionChanged);
            }
            if let Some(resolution) = observation.resolution {
                if expected_cursor != Some(resolution.cursor)
                    || resolution.lifecycle.resolved_through_seq > resolution.cursor
                    || resolution.repository_fingerprint.is_none()
                    || writer.is_none_or(|writer| writer.expected_local_revision.is_some())
                    || !matches!(
                        versioned.version,
                        nddev_device_sync_domain::sync::history::OperationVersion::V3 { .. }
                    )
                    || versioned.lifecycle() != resolution.lifecycle
                {
                    return Err(Error::Invalid);
                }
                let (_, _, current) = reads::resolution_evidence(&tx, kind, &operation.entity_id)?;
                if !resolution.repository_matches(&current) {
                    return Err(Error::Busy);
                }
            }
        }
        let entity = reads::entity(&tx, kind, &operation.entity_id)?;
        if versioned.version == nddev_device_sync_domain::sync::history::OperationVersion::V2
            && entity.as_ref().is_some_and(|e| {
                crate::codec::versioned(&e.body).is_ok_and(|o| {
                    o.version != nddev_device_sync_domain::sync::history::OperationVersion::V2
                })
            })
        {
            return Err(Error::Invalid);
        }
        let revision = entity.as_ref().map_or(0, |e| e.revision);
        let pending = entity.as_ref().and_then(|e| e.pending_id.clone());
        let base = if expected_cursor.is_some() {
            revision
        } else {
            entity.as_ref().map_or(0, |e| e.next_base)
        };
        if revision != expected_revision
            || pending != expected_pending
            || operation.base_revision != base
        {
            return Err(Error::Busy);
        }
        if let Some(expected) = expected_cursor {
            let actual: u64 = tx
                .query_row("SELECT cursor FROM v3_meta WHERE singleton=1", [], |r| {
                    r.get(0)
                })
                .map_err(sql_failed)?;
            let scoped = selected
                .as_ref()
                .is_some_and(|guard| guard.resolution.is_some());
            if (if scoped {
                actual < expected
            } else {
                actual != expected
            }) || !(kind == "vault_record"
                || kind == "repository_state"
                    && selected
                        .as_ref()
                        .is_some_and(|guard| guard.resolution.is_some()))
                || !entity.as_ref().is_some_and(|e| e.conflicted)
            {
                return Err(Error::Busy);
            }
            // An unacknowledged dispatched operation is still immutable. The
            // user must observe its server outcome before resolving the family.
            let in_flight:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM v3_outbox WHERE kind=?1 AND entity_id=?2 AND dispatched=1)",params![kind,operation.entity_id],|r|r.get(0)).map_err(sql_failed)?;
            if in_flight {
                return Err(Error::Busy);
            }
        } else if entity.as_ref().is_some_and(|e| e.conflicted) {
            return Err(Error::Busy);
        }
        let old:Option<(String,u32,Option<String>)>=tx.query_row("SELECT id,dispatched,predecessor FROM v3_outbox WHERE kind=?1 AND entity_id=?2 ORDER BY rowid DESC LIMIT 1",params![kind,operation.entity_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(sql_failed)?;
        let predecessor = match old {
            Some((id, 0, predecessor)) => {
                tx.execute("DELETE FROM v3_outbox WHERE id=?1", [id])
                    .map_err(sql_failed)?;
                predecessor
            }
            Some((id, _, _)) => Some(id),
            None => None,
        };
        let count: u64 = tx
            .query_row("SELECT count(*) FROM v3_outbox", [], |r| r.get(0))
            .map_err(sql_failed)?;
        if count >= 1024 {
            return Err(Error::Busy);
        }
        if selected.is_some() {
            let observations: usize = tx
                .query_row(
                    "SELECT count(*) FROM v3_outbox WHERE kind='repository_state'",
                    [],
                    |r| r.get(0),
                )
                .map_err(sql_failed)?;
            // Enforce Core's producer window in the insertion transaction.
            // Replacing an undispatched value above consumes no additional slot.
            if nddev_device_sync_application::repositories::catalog::observations::stage_count(
                1,
                observations,
                (1024 - count) as usize,
            ) == 0
            {
                return Err(Error::Busy);
            }
        }
        tx.execute("INSERT INTO v3_outbox(id,kind,entity_id,body,state,dispatched,predecessor) VALUES(?1,?2,?3,?4,'pending',0,?5)",params![operation.id,kind,operation.entity_id,body,predecessor]).map_err(sql_failed)?;
        bump(&tx)?;
        let receipt=tx.query_row("SELECT (SELECT count(*) FROM v3_outbox WHERE state='pending'),((SELECT count(*) FROM v3_conflicts)+(SELECT count(*) FROM v3_outbox o WHERE state='conflict' AND NOT EXISTS(SELECT 1 FROM v3_conflicts c WHERE c.kind=o.kind AND c.entity_id=o.entity_id))),cursor,local_revision FROM v3_meta WHERE singleton=1",[],|r|Ok(Enqueued{id:operation.id.clone(),pending:r.get(0)?,conflicts:r.get(1)?,cursor:r.get(2)?,local_revision:r.get(3)?})).map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok(receipt)
    }
    pub fn acknowledge(&self, request: &[u8], result: &[u8], resolved: u64) -> Result<(), Error> {
        let outcome: wire::Sync = serde_json::from_slice(result).map_err(|_| Error::Invalid)?;
        let status = match crate::codec::receipt(&outcome)?.decision {
            nddev_device_sync_domain::sync::Decision::Apply { .. } => 201,
            _ => 409,
        };
        self.acknowledge_original(request, result, status, resolved)
    }
    pub(crate) fn acknowledge_original(
        &self,
        request: &[u8],
        result: &[u8],
        status: u16,
        resolved: u64,
    ) -> Result<(), Error> {
        let (operation, receipt) = crate::codec::original_receipt(request, result, status)?;
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let body: Option<Vec<u8>> = tx
            .query_row(
                "SELECT body FROM v3_outbox WHERE id=?1 AND dispatched=1",
                [&operation.operation.id],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql_failed)?;
        if let Some(body) = body {
            if body != request {
                return Err(Error::Invalid);
            }
            let row = RawRow {
                legacy_resolved: match operation.version {
                    nddev_device_sync_domain::sync::history::OperationVersion::V2 => resolved,
                    nddev_device_sync_domain::sync::history::OperationVersion::V3 { .. } => 0,
                },
                body,
                result: result.to_vec(),
                status,
                sequence: receipt.server_seq,
            };
            apply_row(&tx, &row)?;
            settle_row(&tx, &row)?;
            bump(&tx)?;
        }
        tx.execute(
            "UPDATE v3_meta SET known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",
            [receipt.server_seq],
        )
        .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn ingest_original(
        &self,
        header: nddev_device_sync_domain::sync::history::HistoryVersion,
        after: u64,
        rows: &[RawRow],
        next: u64,
        more: bool,
    ) -> Result<(), Error> {
        use nddev_device_sync_domain::sync::history;
        let head = header.head;
        let floor = header.floor;
        header.validate().map_err(|_| Error::Invalid)?;
        if next > head || more != (next < head) {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let cursor: u64 = tx
            .query_row("SELECT cursor FROM v3_meta WHERE singleton=1", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)?;
        if cursor != after {
            return Err(Error::Busy);
        }
        if cursor < floor {
            return Err(Error::Invalid);
        }
        history::delta_progress(
            cursor,
            &rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            next,
            more,
        )
        .map_err(|_| Error::Invalid)?;
        for row in rows {
            apply_row(&tx, row)?;
            settle_row(&tx, row)?;
        }
        if !rows.is_empty() {
            bump(&tx)?;
        }
        tx.execute("UPDATE v3_meta SET cursor=?1 WHERE singleton=1", [next])
            .map_err(sql_failed)?;
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
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let mut previous: i64 = tx
            .query_row("SELECT cursor FROM v3_meta WHERE singleton=1", [], |r| {
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
        tx.execute("UPDATE v3_meta SET cursor=?1 WHERE singleton=1", [previous])
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
        .query_row("SELECT body FROM v3_outbox WHERE id=?1", [id], |r| r.get(0))
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
        "UPDATE v3_outbox SET predecessor=NULL,state=?1 WHERE predecessor=?2",
        params![state, id],
    )
    .map_err(sql_failed)?;
    tx.execute("DELETE FROM v3_outbox WHERE id=?1", [id])
        .map_err(sql_failed)?;
    Ok(())
}

fn bump(tx: &rusqlite::Transaction<'_>) -> Result<(), Error> {
    tx.execute(
        "UPDATE v3_meta SET local_revision=local_revision+1 WHERE singleton=1",
        [],
    )
    .map_err(sql_failed)?;
    Ok(())
}

pub(super) fn apply_row(tx: &rusqlite::Transaction<'_>, row: &RawRow) -> Result<(), Error> {
    let (operation, receipt) = row.decode()?;
    match operation.version {
        nddev_device_sync_domain::sync::history::OperationVersion::V2 => {
            let wire: wire::SyncOperation =
                serde_json::from_slice(&row.body).map_err(|_| Error::Invalid)?;
            let outcome: wire::Sync =
                serde_json::from_slice(&row.result).map_err(|_| Error::Invalid)?;
            apply(
                tx,
                &wire,
                &row.body,
                &outcome,
                &row.result,
                row.legacy_resolved,
            )?;
        }
        nddev_device_sync_domain::sync::history::OperationVersion::V3 { .. } => {
            checkpoint::apply_original(tx, row)?
        }
    }
    tx.execute(
        "UPDATE v3_meta SET known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",
        [receipt.server_seq],
    )
    .map_err(sql_failed)?;
    Ok(())
}
fn settle_row(tx: &rusqlite::Transaction<'_>, row: &RawRow) -> Result<(), Error> {
    let (operation, receipt) = row.decode()?;
    let id = &operation.operation.id;
    let pending: Option<Vec<u8>> = tx
        .query_row("SELECT body FROM v3_outbox WHERE id=?1", [id], |r| r.get(0))
        .optional()
        .map_err(sql_failed)?;
    let Some(pending) = pending else {
        return Ok(());
    };
    if !checkpoint::same_original(&pending, &row.body)? {
        return Ok(());
    }
    let state = match receipt.decision {
        nddev_device_sync_domain::sync::Decision::Apply { .. } => "pending",
        _ => "conflict",
    };
    tx.execute(
        "UPDATE v3_outbox SET predecessor=NULL,state=?1 WHERE predecessor=?2",
        params![state, id],
    )
    .map_err(sql_failed)?;
    tx.execute("DELETE FROM v3_outbox WHERE id=?1", [id])
        .map_err(sql_failed)?;
    Ok(())
}
