//! Stored public writer facts, not authorization or transition policy. Main Rust
//! owns actual scope/key/fence checks; Core approves a confirmation transition.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WriterFacts {
    pub legacy_v2_context: bool,
    pub mode: Option<u8>,
    pub key_id: Option<String>,
    pub confirmed_basis_seq: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct WriterSnapshot {
    pub facts: WriterFacts,
    pub cursor: u64,
    pub known_committed_seq: u64,
    pub local_revision: u64,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WriterEnqueueGuard {
    pub facts: WriterFacts,
    pub actual_key_id: String,
    pub basis_seq: Option<u64>,
    pub expected_local_revision: Option<u64>,
}
pub(super) fn guard_enqueue(
    connection: &Connection,
    expected: &WriterEnqueueGuard,
    operation: &nddev_device_sync_domain::sync::history::VersionedOperation,
) -> Result<(), Error> {
    let now = read(connection)?;
    if expected
        .expected_local_revision
        .is_some_and(|revision| revision != now.local_revision)
    {
        return Err(Error::Busy);
    }
    if now.facts.mode != expected.facts.mode
        || now.facts.key_id != expected.facts.key_id
        || now.facts.legacy_v2_context != expected.facts.legacy_v2_context
    {
        return Err(Error::Busy);
    }
    if now
        .facts
        .key_id
        .as_deref()
        .is_some_and(|key| key != expected.actual_key_id)
        || operation.operation.payload.key_id != expected.actual_key_id
    {
        return Err(Error::Locked);
    }
    match operation.version {
        nddev_device_sync_domain::sync::history::OperationVersion::V2 => {
            if expected.basis_seq.is_some() {
                return Err(Error::Invalid);
            }
        }
        nddev_device_sync_domain::sync::history::OperationVersion::V3 { basis_seq, .. } => {
            if expected.basis_seq != Some(basis_seq) {
                return Err(Error::Invalid);
            }
            let known = now
                .facts
                .confirmed_basis_seq
                .into_iter()
                .chain((now.cursor > 0).then_some(now.cursor))
                .chain((now.known_committed_seq > 0).then_some(now.known_committed_seq))
                .max();
            if known.is_none_or(|n| n < basis_seq) {
                return Err(Error::Busy);
            }
        }
    }
    Ok(())
}
pub(super) fn read(connection: &Connection) -> Result<WriterSnapshot, Error> {
    connection.query_row("SELECT legacy_v2_context,writer_mode,writer_key_id,confirmed_basis_seq,cursor,known_committed_seq,local_revision FROM v3_meta WHERE singleton=1",[],|r|Ok(WriterSnapshot {facts:WriterFacts {legacy_v2_context:r.get(0)?,mode:r.get(1)?,key_id:r.get(2)?,confirmed_basis_seq:r.get(3)?},cursor:r.get(4)?,known_committed_seq:r.get(5)?,local_revision:r.get(6)?})).map_err(sql_failed)
}
impl Journal {
    pub(crate) fn writer_snapshot(&self) -> Result<WriterSnapshot, Error> {
        self.read(read)
    }
    /// Mechanical exact CAS of facts already verified in main Rust and accepted
    /// by Core. It neither negotiates nor decides an admission-mode transition.
    pub(crate) fn confirm_writer(
        &self,
        expected: &WriterSnapshot,
        mode: u8,
        key_id: &str,
        basis: Option<u64>,
    ) -> Result<WriterSnapshot, Error> {
        if !matches!(mode, 2 | 3)
            || uuid::Uuid::parse_str(key_id).is_err()
            || basis.is_some_and(|n| n > nddev_device_sync_domain::sync::MAX_REVISION)
        {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        if read(&tx)? != *expected {
            return Err(Error::Busy);
        }
        let material =
            expected.facts.mode != Some(mode) || expected.facts.key_id.as_deref() != Some(key_id);
        let confirmed = if expected.facts.key_id.as_deref() == Some(key_id) {
            match (expected.facts.confirmed_basis_seq, basis) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, None) => a,
                (None, b) => b,
            }
        } else {
            basis
        };
        tx.execute("UPDATE v3_meta SET writer_mode=?1,writer_key_id=?2,confirmed_basis_seq=?3,local_revision=local_revision+?4 WHERE singleton=1",params![mode,key_id,confirmed,u8::from(material)]).map_err(sql_failed)?;
        let current = read(&tx)?;
        tx.commit().map_err(sql_failed)?;
        Ok(current)
    }
    /// Exact original root metadata only. State, ciphertext, UUID and successor
    /// pointers are unchanged; a real late receipt can still settle this row.
    pub(crate) fn mark_unknown(&self, id: &str, request: &[u8], reason: &str) -> Result<(), Error> {
        if !matches!(reason, "basis_expired" | "legacy_missing") {
            return Err(Error::Invalid);
        }
        let operation = crate::codec::versioned(request)?;
        if operation.operation.id != id {
            return Err(Error::Invalid);
        }
        let mut connection = self.connection()?;
        let tx = transaction(&mut connection, TransactionBehavior::Immediate)?;
        let current: Option<(Vec<u8>, Option<String>)> = tx
            .query_row(
                "SELECT body,terminal_unknown_reason FROM v3_outbox WHERE id=?1 AND dispatched=1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql_failed)?;
        if let Some((body, old_reason)) = current {
            if body != request {
                return Err(Error::Invalid);
            }
            if old_reason.as_deref() != Some(reason) {
                tx.execute("UPDATE v3_outbox SET terminal_unknown_reason=?1 WHERE id=?2 AND dispatched=1 AND body=?3",params![reason,id,request]).map_err(sql_failed)?;
                tx.execute(
                    "UPDATE v3_meta SET local_revision=local_revision+1 WHERE singleton=1",
                    [],
                )
                .map_err(sql_failed)?;
            }
        }
        tx.commit().map_err(sql_failed)
    }
    pub(crate) fn unknown_reason(&self) -> Result<Option<String>, Error> {
        self.read(|c|c.query_row("SELECT terminal_unknown_reason FROM v3_outbox WHERE terminal_unknown_reason IS NOT NULL ORDER BY rowid LIMIT 1",[],|r|r.get(0)).optional().map_err(sql_failed))
    }
}
