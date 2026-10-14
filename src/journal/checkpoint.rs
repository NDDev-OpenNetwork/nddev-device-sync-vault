//! Operational checkpoint staging in the existing owner database. No keys,
//! plaintext, second payload store, or policy implementation lives here.
use super::*;
use nddev_device_sync_domain::sync::{
    Decision, Receipt,
    history::{self, VersionedOperation},
};

#[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct StageGuard {
    pub id: String,
    pub scope_tag: String,
    pub key_id: String,
    pub cursor: u64,
    pub local_revision: u64,
    pub known_committed_seq: u64,
}
impl StageGuard {
    pub fn version(&self) -> history::InstallVersion {
        history::InstallVersion {
            cursor: self.cursor,
            local_revision: self.local_revision,
            known_committed_seq: self.known_committed_seq,
        }
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct RawRow {
    pub body: Vec<u8>,
    pub result: Vec<u8>,
    pub status: u16,
    pub sequence: u64,
    // Authenticated Record2 projection metadata, never a retention witness.
    // The encrypted original and its receipt remain unchanged.
    pub legacy_resolved: u64,
}
impl RawRow {
    pub(crate) fn decode(&self) -> Result<(VersionedOperation, Receipt), Error> {
        let (operation, receipt) =
            crate::codec::original_receipt(&self.body, &self.result, self.status)?;
        if self.sequence != receipt.server_seq {
            return Err(Error::Invalid);
        }
        if self.legacy_resolved != 0
            && (operation.version != history::OperationVersion::V2
                || operation.operation.entity_kind
                    != nddev_device_sync_domain::sync::EntityKind::VaultRecord
                || self.legacy_resolved > nddev_device_sync_domain::sync::MAX_REVISION
                || matches!(receipt.decision, Decision::Apply { .. })
                    && self.legacy_resolved >= receipt.server_seq)
        {
            return Err(Error::Invalid);
        }
        Ok((operation, receipt))
    }
}
fn version(connection: &Connection) -> Result<history::InstallVersion, Error> {
    connection
        .query_row(
            "SELECT cursor,local_revision,known_committed_seq FROM v3_meta WHERE singleton=1",
            [],
            |r| {
                Ok(history::InstallVersion {
                    cursor: r.get(0)?,
                    local_revision: r.get(1)?,
                    known_committed_seq: r.get(2)?,
                })
            },
        )
        .map_err(sql_failed)
}
#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct StageProgress {
    pub base: u64,
    pub total: usize,
    pub received: usize,
    pub after_member: u64,
    pub through: u64,
    pub tail_complete: bool,
}
struct Progress {
    base: history::BaseProgress,
    through: u64,
    tail_complete: bool,
}
fn guarded(tx: &rusqlite::Transaction<'_>, expected: &StageGuard) -> Result<Progress, Error> {
    let (guard, progress) = tx.query_row("SELECT stage_id,scope_tag,key_id,expected_cursor,expected_local,expected_known,base_seq,total_members,received,after_member,through_seq,tail_complete FROM checkpoint_meta WHERE singleton=1", [], |r| Ok((StageGuard {id:r.get(0)?,scope_tag:r.get(1)?,key_id:r.get(2)?,cursor:r.get(3)?,local_revision:r.get(4)?,known_committed_seq:r.get(5)?},Progress {base:history::BaseProgress {base:r.get(6)?,total:r.get(7)?,received:r.get(8)?,after_member:r.get(9)?},through:r.get(10)?,tail_complete:r.get(11)?}))).map_err(sql_failed)?;
    if &guard != expected || version(tx)? != expected.version() {
        return Err(Error::Busy);
    }
    Ok(progress)
}
fn store_rows(
    tx: &rusqlite::Transaction<'_>,
    guard: &StageGuard,
    rows: &[RawRow],
) -> Result<(), Error> {
    for row in rows {
        let (operation, _) = row.decode()?;
        if operation.operation.payload.key_id != guard.key_id {
            return Err(Error::Locked);
        }
        tx.execute(
            "INSERT INTO checkpoint_rows(server_seq,body,result,status,legacy_resolved) VALUES(?1,?2,?3,?4,?5)",
            params![row.sequence, row.body, row.result, row.status, row.legacy_resolved],
        )
        .map_err(sql_failed)?;
    }
    let (rows, bytes): (u64, u64) = tx
        .query_row(
            "SELECT count(*),COALESCE(sum(2*length(body)+length(result)),0) FROM checkpoint_rows",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .map_err(sql_failed)?;
    if rows > nddev_device_sync_domain::sync::MAX_OPERATIONS
        || bytes > nddev_device_sync_domain::sync::MAX_STORED_BYTES
    {
        return Err(Error::CapacityExhausted);
    }
    Ok(())
}
impl Journal {
    pub(crate) fn checkpoint_progress(&self, guard: &StageGuard) -> Result<StageProgress, Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Deferred)?;
        let p = guarded(&tx, guard)?;
        let progress = StageProgress {
            base: p.base.base,
            total: p.base.total,
            received: p.base.received,
            after_member: p.base.after_member,
            through: p.through,
            tail_complete: p.tail_complete,
        };
        tx.commit().map_err(sql_failed)?;
        Ok(progress)
    }

    pub(crate) fn checkpoint_handle(
        &self,
        scope_tag: &str,
        key_id: &str,
    ) -> Result<Option<StageGuard>, Error> {
        self.read(|c|{
            let g=c.query_row("SELECT stage_id,scope_tag,key_id,expected_cursor,expected_local,expected_known FROM checkpoint_meta WHERE singleton=1",[],|r|Ok(StageGuard{id:r.get(0)?,scope_tag:r.get(1)?,key_id:r.get(2)?,cursor:r.get(3)?,local_revision:r.get(4)?,known_committed_seq:r.get(5)?})).optional().map_err(sql_failed)?;
            if g.as_ref().is_some_and(|g|g.scope_tag!=scope_tag || g.key_id!=key_id){return Err(Error::Locked);}Ok(g)
        })
    }
    pub(crate) fn resume_checkpoint(
        &self,
        scope_tag: &str,
        key_id: &str,
        known: u64,
    ) -> Result<Option<StageGuard>, Error> {
        self.read(|connection|{
            let stored=connection.query_row("SELECT stage_id,scope_tag,key_id,expected_cursor,expected_local,expected_known FROM checkpoint_meta WHERE singleton=1",[],|r|Ok(StageGuard{id:r.get(0)?,scope_tag:r.get(1)?,key_id:r.get(2)?,cursor:r.get(3)?,local_revision:r.get(4)?,known_committed_seq:r.get(5)?})).optional().map_err(sql_failed)?;
            if let Some(g)=&stored {
                if g.scope_tag!=scope_tag || g.key_id!=key_id {return Err(Error::Locked);}
                if version(connection)?!=g.version() || known>g.known_committed_seq {return Err(Error::Busy);}
            }
            Ok(stored)
        })
    }
    pub(crate) fn reset_checkpoint(&self, scope_tag: &str, key_id: &str) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let stored: Option<(String, String)> = tx
            .query_row(
                "SELECT scope_tag,key_id FROM checkpoint_meta WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql_failed)?;
        if let Some((scope, key)) = stored
            && (scope != scope_tag || key != key_id)
        {
            return Err(Error::Locked);
        }
        tx.execute("DELETE FROM checkpoint_rows", [])
            .map_err(sql_failed)?;
        tx.execute("DELETE FROM checkpoint_meta", [])
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn begin_checkpoint(
        &self,
        scope_tag: &str,
        key_id: &str,
        base: u64,
        total: usize,
        known: u64,
    ) -> Result<StageGuard, Error> {
        if scope_tag.len() != 64
            || !scope_tag.bytes().all(|b| b.is_ascii_hexdigit())
            || uuid::Uuid::parse_str(key_id).is_err()
            || base > nddev_device_sync_domain::sync::MAX_REVISION
            || total > nddev_device_sync_domain::sync::MAX_OPERATIONS as usize
            || known > nddev_device_sync_domain::sync::MAX_REVISION
        {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        // A lost handle can be discarded explicitly, never silently replaced.
        let exists: bool = tx
            .query_row("SELECT EXISTS(SELECT 1 FROM checkpoint_meta)", [], |r| {
                r.get(0)
            })
            .map_err(sql_failed)?;
        if exists {
            return Err(Error::Busy);
        }
        tx.execute(
            "UPDATE v3_meta SET known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",
            [known],
        )
        .map_err(sql_failed)?;
        let v = version(&tx)?;
        let guard = StageGuard {
            id: uuid::Uuid::new_v4().to_string(),
            scope_tag: scope_tag.into(),
            key_id: key_id.into(),
            cursor: v.cursor,
            local_revision: v.local_revision,
            known_committed_seq: v.known_committed_seq,
        };
        tx.execute("INSERT INTO checkpoint_meta(singleton,stage_id,scope_tag,key_id,expected_cursor,expected_local,expected_known,base_seq,total_members,through_seq) VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?7)",params![guard.id,scope_tag,key_id,v.cursor,v.local_revision,v.known_committed_seq,base,total]).map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)?;
        Ok(guard)
    }
    pub(crate) fn stage_base(
        &self,
        guard: &StageGuard,
        base: u64,
        total: usize,
        rows: &[RawRow],
        next: u64,
        more: bool,
    ) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let progress = guarded(&tx, guard)?;
        if progress.through != progress.base.base || progress.tail_complete {
            return Err(Error::Busy);
        }
        let sequences = rows.iter().map(|r| r.sequence).collect::<Vec<_>>();
        let new = progress
            .base
            .advance(base, total, &sequences, next, more)
            .map_err(|_| Error::Invalid)?;
        store_rows(&tx, guard, rows)?;
        tx.execute(
            "UPDATE checkpoint_meta SET received=?1,after_member=?2 WHERE singleton=1",
            params![new.received, new.after_member],
        )
        .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn stage_delta(
        &self,
        guard: &StageGuard,
        floor: u64,
        rows: &[RawRow],
        next: u64,
        more: bool,
    ) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let progress = guarded(&tx, guard)?;
        if !progress.base.complete() || floor > progress.through {
            return Err(Error::Busy);
        }
        history::delta_progress(
            progress.through,
            &rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            next,
            more,
        )
        .map_err(|_| Error::Invalid)?;
        store_rows(&tx, guard, rows)?;
        tx.execute(
            "UPDATE checkpoint_meta SET through_seq=?1,tail_complete=?2 WHERE singleton=1",
            params![next, !more],
        )
        .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn discard_checkpoint(&self, guard: &StageGuard) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        // Active version may have changed; discard only this operational handle.
        let changed = tx
            .execute(
                "DELETE FROM checkpoint_meta WHERE stage_id=?1 AND scope_tag=?2 AND key_id=?3",
                params![guard.id, guard.scope_tag, guard.key_id],
            )
            .map_err(sql_failed)?;
        if changed != 1 {
            return Err(Error::Busy);
        }
        tx.execute("DELETE FROM checkpoint_rows", [])
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn install_checkpoint(&self, guard: &StageGuard) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let progress = guarded(&tx, guard)?;
        history::install_decision(
            guard,
            guard,
            guard.version(),
            version(&tx)?,
            progress.through,
            progress.base.complete(),
        )
        .map_err(|_| Error::Busy)?;
        // Metadata only: resolve policy sequence references inside this transaction.
        struct Meta {
            sequence: u64,
            kind: nddev_device_sync_domain::sync::EntityKind,
            entity: String,
            decision: Decision,
            version: history::OperationVersion,
            request_bytes: u32,
            result_bytes: u32,
        }
        let mut metadata = Vec::new();
        {
            let mut query = tx
                .prepare(
                    "SELECT server_seq,body,result,status,legacy_resolved FROM checkpoint_rows ORDER BY server_seq",
                )
                .map_err(sql_failed)?;
            let mut rows = query.query([]).map_err(sql_failed)?;
            while let Some(r) = rows.next().map_err(sql_failed)? {
                let row = RawRow {
                    sequence: r.get(0).map_err(sql_failed)?,
                    body: r.get(1).map_err(sql_failed)?,
                    result: r.get(2).map_err(sql_failed)?,
                    status: r.get(3).map_err(sql_failed)?,
                    legacy_resolved: r.get(4).map_err(sql_failed)?,
                };
                let (o, r) = row.decode()?;
                metadata.push(Meta {
                    sequence: row.sequence,
                    kind: o.operation.entity_kind,
                    entity: o.operation.entity_id,
                    decision: r.decision,
                    version: o.version,
                    request_bytes: row.body.len() as u32,
                    result_bytes: row.result.len() as u32,
                });
            }
        }
        let refs = metadata
            .iter()
            .map(|m| history::RetainedMeta {
                sequence: m.sequence,
                kind: m.kind,
                entity: &m.entity,
                decision: m.decision,
                version: m.version,
                request_bytes: m.request_bytes,
                result_bytes: m.result_bytes,
            })
            .collect::<Vec<_>>();
        let plan = history::retention_plan(
            &refs,
            None,
            history::HistoryVersion {
                head: progress.through,
                floor: progress.base.base,
                base: progress.base.base,
            },
            progress.through,
            history::RetentionCaps {
                rows: nddev_device_sync_domain::sync::MAX_OPERATIONS,
                bytes: nddev_device_sync_domain::sync::MAX_STORED_BYTES,
                entities: nddev_device_sync_domain::sync::MAX_ENTITY_COUNT,
            },
        )
        .map_err(|_| Error::Invalid)?;
        // Retirement by omission is not authorized, even on a complete base.
        let mut query = tx
            .prepare("SELECT kind,id FROM v3_entities")
            .map_err(sql_failed)?;
        for key in query
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
            .map_err(sql_failed)?
        {
            let (kind, id) = key.map_err(sql_failed)?;
            if !metadata.iter().any(|m| {
                m.kind.as_str() == kind
                    && m.entity == id
                    && matches!(m.decision, Decision::Apply { .. })
            }) {
                return Err(Error::Invalid);
            }
        }
        drop(query);
        for seq in &plan.keep {
            let row = tx
                .query_row(
                    "SELECT body,result,status,legacy_resolved FROM checkpoint_rows WHERE server_seq=?1",
                    [seq],
                    |r| {
                        Ok(RawRow {
                            sequence: *seq,
                            body: r.get(0)?,
                            result: r.get(1)?,
                            status: r.get(2)?,
                            legacy_resolved: r.get(3)?,
                        })
                    },
                )
                .map_err(sql_failed)?;
            outbox::apply_row(&tx, &row)?;
        }
        // Outbox is deliberately untouched: no settle, rebase, requalification,
        // implicit retry, coalescing, or deletion of Unknown/dispatched families.
        tx.execute("UPDATE v3_meta SET cursor=?1,last_sync_at=0,local_revision=local_revision+1,known_committed_seq=MAX(known_committed_seq,?1) WHERE singleton=1",[progress.through]).map_err(sql_failed)?;
        tx.execute("DELETE FROM checkpoint_rows", [])
            .map_err(sql_failed)?;
        tx.execute("DELETE FROM checkpoint_meta", [])
            .map_err(sql_failed)?;
        tx.commit().map_err(sql_failed)
    }
}
fn meta<'a>(
    o: &'a VersionedOperation,
    r: &Receipt,
    body: &[u8],
    result: &[u8],
) -> history::RetainedMeta<'a> {
    history::RetainedMeta {
        sequence: r.server_seq,
        kind: o.operation.entity_kind,
        entity: &o.operation.entity_id,
        decision: r.decision,
        version: o.version,
        request_bytes: body.len() as u32,
        result_bytes: result.len() as u32,
    }
}
pub(super) fn same_original(old: &[u8], new: &[u8]) -> Result<bool, Error> {
    if old == new {
        return Ok(true);
    }
    let a = crate::codec::versioned(old)?;
    let b = crate::codec::versioned(new)?;
    // Only deployed V2 typed inboxes normalized JSON. V3 always retains originals.
    Ok(a.version == history::OperationVersion::V2
        && b.version == history::OperationVersion::V2
        && a == b)
}
type StoredApplied = (Vec<u8>, u64, u64, Option<Vec<u8>>);
pub(super) fn apply_original(tx: &rusqlite::Transaction<'_>, row: &RawRow) -> Result<(), Error> {
    let (o, r) = row.decode()?;
    let kind = o.operation.entity_kind.as_str();
    let id = &o.operation.entity_id;
    match r.decision {
        Decision::Apply { revision } => {
            let current:Option<StoredApplied>=tx.query_row("SELECT body,revision,server_seq,receipt_body FROM v3_entities WHERE kind=?1 AND id=?2",params![kind,id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(sql_failed)?;
            if let Some((body, old_revision, old_seq, result)) = current {
                if let Some(result) = result {
                    let (old, receipt) = crate::codec::original_receipt(&body, &result, 201)?;
                    if receipt.server_seq != old_seq
                        || receipt.decision
                            != (Decision::Apply {
                                revision: old_revision,
                            })
                    {
                        return Err(Error::Invalid);
                    }
                    match history::applied_projection(
                        meta(&old, &receipt, &body, &result),
                        meta(&o, &r, &row.body, &row.result),
                    )
                    .map_err(|_| Error::Invalid)?
                    {
                        history::AppliedProjection::IgnoreEarlier => return Ok(()),
                        history::AppliedProjection::VerifySameOriginal => {
                            if !same_original(&body, &row.body)?
                                || crate::codec::receipt(
                                    &serde_json::from_slice(&result).map_err(|_| Error::Invalid)?,
                                )? != r
                            {
                                return Err(Error::Invalid);
                            }
                        }
                        history::AppliedProjection::Replace => {}
                    }
                } else {
                    // Migrated V2 metadata is distinct from an original receipt.
                    // Core validates its real bytes/revision/nonzero sequence
                    // and owns the same monotonic comparison as full rows.
                    let old = crate::codec::versioned(&body)?;
                    let observed_sequence = if old_seq == 0 {
                        // A full receipt for this exact stored V2 original is
                        // an observation, not a guess about a different head.
                        if old.version != history::OperationVersion::V2
                            || revision != old_revision
                            || !same_original(&body, &row.body)?
                        {
                            return Err(Error::Invalid);
                        }
                        r.validate_for(&old.operation).map_err(|_| Error::Invalid)?;
                        r.server_seq
                    } else {
                        old_seq
                    };
                    let current = history::AppliedHeadMeta::verified_v2(
                        &old,
                        body.len(),
                        old_revision,
                        observed_sequence,
                    )
                    .map_err(|_| Error::Invalid)?;
                    match history::applied_head_projection(
                        current,
                        meta(&o, &r, &row.body, &row.result),
                    )
                    .map_err(|_| Error::Invalid)?
                    {
                        history::AppliedProjection::IgnoreEarlier => return Ok(()),
                        history::AppliedProjection::VerifySameOriginal => {
                            if !same_original(&body, &row.body)? {
                                return Err(Error::Invalid);
                            }
                        }
                        history::AppliedProjection::Replace => {}
                    }
                }
            }
            tx.execute("INSERT INTO v3_entities(kind,id,revision,body,server_seq,receipt_body,receipt_status) VALUES(?1,?2,?3,?4,?5,?6,201) ON CONFLICT(kind,id) DO UPDATE SET revision=excluded.revision,body=excluded.body,server_seq=excluded.server_seq,receipt_body=excluded.receipt_body,receipt_status=201",params![kind,id,revision,row.body,r.server_seq,row.result]).map_err(sql_failed)?;
            let resolved = o.lifecycle().resolved_through_seq;
            if resolved > 0 {
                tx.execute("DELETE FROM v3_conflicts WHERE kind=?1 AND entity_id=?2 AND json_extract(CAST(result AS TEXT),'$.server_seq')<=?3",params![kind,id,resolved]).map_err(sql_failed)?;
            }
        }
        Decision::Conflict { .. } => {
            let conflict_id =
                serde_json::to_string(&(o.operation.device.as_str(), &o.operation.id))
                    .map_err(failed)?;
            let old: Option<(Vec<u8>, Vec<u8>)> = tx
                .query_row(
                    "SELECT body,result FROM v3_conflicts WHERE id=?1",
                    [&conflict_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()
                .map_err(sql_failed)?;
            if let Some((body, result)) = old
                && (!same_original(&body, &row.body)?
                    || crate::codec::original_receipt(&body, &result, 409)?.1 != r)
            {
                return Err(Error::Invalid);
            }
            tx.execute("INSERT INTO v3_conflicts(id,kind,entity_id,body,result) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET body=excluded.body,result=excluded.result",params![conflict_id,kind,id,row.body,row.result]).map_err(sql_failed)?;
        }
    }
    Ok(())
}
