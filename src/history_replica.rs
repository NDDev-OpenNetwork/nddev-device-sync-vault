//! Actual typed transport/crypto/journal composition. Core owns the calling loop,
//! writer transitions, expiry policy, budgets, restart and freshness decisions.
use super::*;
use crate::{
    journal::{RawRow, StageGuard, WriterSnapshot},
    storage::{Command, Reply},
};
use nddev_device_sync_accounts::{SyncExpiry, SyncReply};
use nddev_device_sync_application::{
    replica::*,
    sync::history::{ActiveStage, BaseRead, CheckpointPort, StageResume, VerifiedBasePage},
};
use nddev_device_sync_domain::sync::history::{BaseProgress, HistoryVersion};
use std::sync::atomic::Ordering;
pub(super) struct Replica<'a> {
    client: &'a VaultClient,
    fence: nddev_device_sync_accounts::LocalUseFence,
    key_id: Mutex<Option<String>>,
    writer: Mutex<Option<WriterSnapshot>>,
}
pub(super) enum PageData {
    Legacy(wire::SyncPage, Vec<u64>),
    Versioned(checkpoint::VerifiedHistory),
}
pub(super) struct ReceiptData {
    body: Vec<u8>,
    status: u16,
    resolved: u64,
}
pub(super) struct BaseData {
    rows: Vec<RawRow>,
}
pub(crate) fn facts(snapshot: &WriterSnapshot) -> Result<WriterFacts, Error> {
    let f = &snapshot.facts;
    let confirmed = match (f.mode, f.key_id.as_ref(), f.confirmed_basis_seq) {
        (None, None, None) => None,
        (Some(mode), Some(key), Some(basis)) => Some(ConfirmedWriter {
            mode: match mode {
                2 => WriterMode::V2,
                3 => WriterMode::V3,
                _ => return Err(Error::Invalid),
            },
            key_id: key.clone(),
            basis,
        }),
        _ => return Err(Error::Invalid),
    };
    Ok(WriterFacts {
        confirmed,
        legacy_v2_initialized: f.legacy_v2_context,
    })
}
impl<'a> Replica<'a> {
    pub(super) async fn new(client: &'a VaultClient) -> Result<Self, Error> {
        let fence = client
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        Ok(Self {
            client,
            fence,
            key_id: Mutex::new(None),
            writer: Mutex::new(None),
        })
    }
    async fn validate(&self) -> Result<(), Error> {
        self.client.authorized()?;
        self.client
            .identity
            .validate_local_use(&self.fence)
            .await
            .map_err(identity_failure)
    }
    async fn request(&self, request: SyncRequest) -> Result<SyncReply, Error> {
        self.validate().await?;
        let result = self.client.identity.sync_request(request).await;
        self.validate().await?;
        result.map_err(identity_failure)
    }
    async fn key(&self) -> Result<VaultKey, Error> {
        self.validate().await?;
        let key = self.client.key().await?.ok_or(Error::Locked)?;
        if self
            .key_id
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref()
            != Some(key.id().as_str())
        {
            return Err(Error::Locked);
        }
        Ok(key)
    }
    async fn snapshot(&self) -> Result<WriterSnapshot, Error> {
        match self.client.journal.call(Command::WriterSnapshot).await? {
            Reply::WriterSnapshot(s) => Ok(s),
            _ => Err(Error::Invalid),
        }
    }
    async fn active(
        &self,
        stage: CheckpointStage,
    ) -> Result<ActiveStage<CheckpointStage, StageGuard>, Error> {
        let p = match self
            .client
            .journal
            .call(Command::CheckpointProgress {
                guard: stage.guard.clone(),
            })
            .await?
        {
            Reply::CheckpointProgress(p) => p,
            _ => return Err(Error::Invalid),
        };
        Ok(ActiveStage {
            guard: stage.guard.clone(),
            install_version: stage.guard.version(),
            stage,
            base: BaseProgress {
                base: p.base,
                total: p.total,
                received: p.received,
                after_member: p.after_member,
            },
            through: p.through,
            tail_at_head: p.tail_complete,
        })
    }
    fn expired(reply: &SyncReply) -> Result<Option<ReadOutcome<()>>, Error> {
        Ok(match reply.expiry().map_err(identity_failure)? {
            None => None,
            Some(SyncExpiry::V2CursorExpired) => Some(ReadOutcome::LegacyExpired),
            Some(SyncExpiry::V3(e)) => Some(ReadOutcome::Expired(HistoryVersion {
                head: e.head_seq.try_into().map_err(|_| Error::Invalid)?,
                floor: e.floor_seq.try_into().map_err(|_| Error::Invalid)?,
                base: e.floor_seq.try_into().map_err(|_| Error::Invalid)?,
            })),
        })
    }
}
fn decode_negotiation(reply: SyncReply) -> Result<Negotiation, Error> {
    if reply.status == 404 {
        return Ok(Negotiation::LegacyUnsupported);
    }
    if reply.status != 200 {
        return Err(Error::Invalid);
    }
    let c: crate::sync3_wire::SyncCapabilities =
        serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
    if c.schema_version != 3 {
        return Err(Error::Invalid);
    }
    let readers = c
        .read_operation_versions
        .into_iter()
        .map(|n| u8::try_from(n).map_err(|_| Error::Invalid))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Negotiation::Capabilities(Capabilities {
        reader_versions: readers.try_into().map_err(|_| Error::Invalid)?,
        writer: match c.new_operation_version {
            2 => WriterMode::V2,
            3 => WriterMode::V3,
            _ => return Err(Error::Invalid),
        },
        retention: c.history_retention,
    }))
}
impl ReplicaPort for Replica<'_> {
    type Error = Error;
    type Pending = crate::journal::Pending;
    type Receipt = ReceiptData;
    type Page = PageData;
    async fn negotiate(&self) -> Result<Negotiation, Error> {
        self.validate().await?;
        let reply = self
            .client
            .identity
            .sync_request(SyncRequest::CapabilitiesV3)
            .await;
        self.validate().await?;
        let reply = match reply {
            Err(nddev_device_sync_accounts::ClientError::Server(code))
                if code == "method_unavailable" =>
            {
                return Ok(Negotiation::LegacyUnsupported);
            }
            r => r.map_err(identity_failure)?,
        };
        decode_negotiation(reply)
    }
    async fn writer_facts(&self) -> Result<WriterFacts, Error> {
        self.validate().await?;
        let snapshot = self.snapshot().await?;
        let result = facts(&snapshot)?;
        *self.writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(snapshot);
        Ok(result)
    }
    async fn prepare_context(
        &self,
        mode: ReadMode,
        budget: &mut BatchBudget,
    ) -> Result<Preparation, Error> {
        if !budget.take_read() {
            return Ok(Preparation::ReadBudgetExhausted);
        }
        let mut observed = None;
        let hint = match mode {
            ReadMode::Legacy => {
                let reply = self
                    .request(SyncRequest::Page { after: 0, limit: 1 })
                    .await?;
                if Self::expired(&reply)?.is_some() {
                    return Err(Error::Unavailable);
                }
                if reply.status != 200 {
                    return Err(Error::Invalid);
                }
                let p: wire::SyncPage =
                    serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
                if p.entries.len() > 1 || p.next_after_seq < 0 || p.has_more && p.entries.is_empty()
                {
                    return Err(Error::Invalid);
                }
                if let Some(e) = p.entries.first() {
                    let b = serde_json::to_vec(&e.operation).map_err(dependency)?;
                    let o = codec::operation(&e.operation, b.len())?;
                    Some(o.payload.key_id)
                } else {
                    if p.next_after_seq != 0 || p.has_more {
                        return Err(Error::Invalid);
                    }
                    None
                }
            }
            ReadMode::Versioned => {
                let reply = self
                    .request(SyncRequest::HistoryV3 { after: 0, limit: 1 })
                    .await?;
                match Self::expired(&reply)? {
                    Some(ReadOutcome::Expired(h)) => {
                        observed = Some(h.head);
                        if !budget.take_read() {
                            return Ok(Preparation::ReadBudgetExhausted);
                        }
                        let base = self
                            .request(SyncRequest::BaseV3 {
                                base: h.base,
                                after_member: 0,
                                limit: 1,
                            })
                            .await?;
                        if base.status != 200 {
                            return Err(Error::Unavailable);
                        }
                        crate::key_discovery::base_hint(&base.body, h.base)?
                    }
                    Some(_) => return Err(Error::Invalid),
                    None => {
                        if reply.status != 200 {
                            return Err(Error::Invalid);
                        }
                        let p: crate::sync3_wire::SyncDeltaPage =
                            serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
                        observed = Some(p.head_seq.try_into().map_err(|_| Error::Invalid)?);
                        crate::key_discovery::history_hint(&reply.body, 0)?
                    }
                }
            }
        };
        self.validate().await?;
        *self
            .client
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = hint.clone();
        let lock = self.client.journal.key_lock().await?;
        let existing = self.client.key().await?;
        let material = existing
            .as_ref()
            .map(|k| {
                nddev_device_sync_domain::vault::KeyMaterial::new(k.native_secret().as_slice())
                    .map_err(|_| Error::Authentication)
            })
            .transpose()?;
        let delivered = self
            .client
            .identity
            .ensure_vault_key(material.as_ref())
            .await
            .map_err(identity_failure)?;
        self.validate().await?;
        if hint.as_ref().is_some_and(|id| *id != delivered.id()) {
            return Err(Error::Authentication);
        }
        let key = VaultKey::from_native_secret(delivered.expose())?;
        self.client.retain_key(&key).await?;
        self.validate().await?;
        drop(lock);
        *self
            .client
            .expected_key
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Some(key.id());
        *self.key_id.lock().unwrap_or_else(|e| e.into_inner()) = Some(key.id());
        Ok(Preparation::Ready(PreparedContext {
            key_id: key.id(),
            observed_basis: observed,
        }))
    }
    async fn confirm_writer(
        &self,
        expected: &WriterFacts,
        confirmed: ConfirmedWriter,
    ) -> Result<(), Error> {
        self.validate().await?;
        let key = self.key().await?;
        if key.id() != confirmed.key_id {
            return Err(Error::Locked);
        }
        let snapshot = self
            .writer
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .ok_or(Error::Invalid)?;
        if facts(&snapshot)? != *expected {
            return Err(Error::Busy);
        }
        let mode = match confirmed.mode {
            WriterMode::V2 => 2,
            WriterMode::V3 => 3,
        };
        match self
            .client
            .journal
            .call(Command::ConfirmWriter {
                expected: snapshot,
                mode,
                key_id: confirmed.key_id,
                basis: Some(confirmed.basis),
            })
            .await?
        {
            Reply::WriterSnapshot(s) => {
                *self.writer.lock().unwrap_or_else(|e| e.into_inner()) = Some(s);
                Ok(())
            }
            _ => Err(Error::Invalid),
        }
    }
    async fn claim(&self) -> Result<Vec<Self::Pending>, Error> {
        self.validate().await?;
        self.client.journal.pending().await
    }
    async fn append_outcome(
        &self,
        pending: &Self::Pending,
    ) -> Result<AppendOutcome<Self::Receipt>, Error> {
        let key = self.key().await?;
        let operation = codec::versioned(&pending.body)?;
        let resolved = VaultClient::verify_versioned(&self.client.scope, &key, &operation)?;
        let request = match operation.version {
            OperationVersion::V2 => SyncRequest::Append(pending.body.clone()),
            OperationVersion::V3 { .. } => SyncRequest::AppendV3(pending.body.clone()),
        };
        let reply = self.request(request).await?;
        if let Some(expiry) = reply.expiry().map_err(identity_failure)? {
            let reason = match expiry {
                SyncExpiry::V2CursorExpired => UnknownReason::LegacyMissing,
                SyncExpiry::V3(e) => match e.error {
                    crate::sync3_wire::SyncExpiredError::BasisExpired => {
                        UnknownReason::BasisExpired
                    }
                    crate::sync3_wire::SyncExpiredError::LegacyOutcomeUnknown => {
                        UnknownReason::LegacyMissing
                    }
                    _ => return Err(Error::Invalid),
                },
            };
            return Ok(AppendOutcome::Unknown(reason));
        }
        let (_, receipt) = codec::original_receipt(&pending.body, &reply.body, reply.status)?;
        self.client
            .known_committed_seq
            .fetch_max(receipt.server_seq, Ordering::AcqRel);
        Ok(AppendOutcome::Receipt(ReceiptData {
            body: reply.body,
            status: reply.status,
            resolved,
        }))
    }
    async fn remember_unknown(
        &self,
        pending: &Self::Pending,
        reason: UnknownReason,
    ) -> Result<(), Error> {
        self.key().await?;
        let reason = match reason {
            UnknownReason::BasisExpired => "basis_expired",
            UnknownReason::LegacyMissing => "legacy_missing",
        };
        self.client
            .journal
            .call(Command::MarkUnknown {
                id: pending.id.clone(),
                request: pending.body.clone(),
                reason: reason.into(),
            })
            .await?;
        Ok(())
    }
    async fn acknowledge(
        &self,
        pending: Self::Pending,
        receipt: Self::Receipt,
    ) -> Result<(), Error> {
        self.key().await?;
        self.client
            .journal
            .call(Command::AcknowledgeOriginal {
                request: pending.body,
                result: receipt.body,
                status: receipt.status,
                resolved: receipt.resolved,
            })
            .await?;
        Ok(())
    }
    async fn cursor(&self) -> Result<u64, Error> {
        self.validate().await?;
        self.client.journal.cursor().await
    }
    async fn history_outcome(
        &self,
        mode: ReadMode,
        after: u64,
        limit: usize,
    ) -> Result<ReadOutcome<VerifiedPage<Self::Page>>, Error> {
        let limit = limit.try_into().map_err(|_| Error::Invalid)?;
        let request = match mode {
            ReadMode::Legacy => SyncRequest::Page { after, limit },
            ReadMode::Versioned => SyncRequest::HistoryV3 { after, limit },
        };
        let reply = self.request(request).await?;
        match Self::expired(&reply)? {
            Some(ReadOutcome::Expired(h)) => return Ok(ReadOutcome::Expired(h)),
            Some(_) => return Ok(ReadOutcome::LegacyExpired),
            None => {}
        }
        if reply.status != 200 {
            return Err(Error::Invalid);
        }
        let key = self.key().await?;
        Ok(ReadOutcome::Page(match mode {
            ReadMode::Legacy => {
                let p: wire::SyncPage =
                    serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
                let resolutions = p
                    .entries
                    .iter()
                    .map(|e| self.client.verify_operation(&key, &e.operation))
                    .collect::<Result<Vec<_>, _>>()?;
                VerifiedPage {
                    next_after: p.next_after_seq.try_into().map_err(|_| Error::Invalid)?,
                    entries: p.entries.len(),
                    has_more: p.has_more,
                    history: None,
                    contents: PageData::Legacy(p, resolutions),
                }
            }
            ReadMode::Versioned => {
                let p = self.client.decode_history_page(&key, &reply.body, after)?;
                VerifiedPage {
                    next_after: p.next,
                    entries: p.rows.len(),
                    has_more: p.more,
                    history: Some(HistoryVersion {
                        head: p.head,
                        floor: p.floor,
                        base: p.floor,
                    }),
                    contents: PageData::Versioned(p),
                }
            }
        }))
    }
    async fn ingest(&self, page: Self::Page) -> Result<(), Error> {
        self.key().await?;
        match page {
            PageData::Legacy(p, r) => self.client.journal.ingest(p, r).await,
            PageData::Versioned(p) => {
                self.client
                    .journal
                    .call(Command::IngestOriginal {
                        head: p.head,
                        floor: p.floor,
                        after: p.after,
                        rows: p.rows,
                        next: p.next,
                        more: p.more,
                    })
                    .await?;
                Ok(())
            }
        }
    }
    async fn caught_up(&self, cursor: u64) -> Result<bool, Error> {
        self.validate().await?;
        self.client
            .journal
            .caught_up(
                cursor,
                time::OffsetDateTime::now_utc()
                    .unix_timestamp()
                    .try_into()
                    .map_err(|_| Error::Invalid)?,
            )
            .await
    }
}
impl CheckpointPort for Replica<'_> {
    type Stage = CheckpointStage;
    type Guard = StageGuard;
    type BaseContents = BaseData;
    async fn checkpoint_resume(&self) -> Result<StageResume<Self::Stage, Self::Guard>, Error> {
        let key = self.key().await?;
        let g = match self
            .client
            .journal
            .call(Command::CheckpointHandle {
                scope_tag: self.client.checkpoint_scope_tag()?,
                key_id: key.id(),
            })
            .await?
        {
            Reply::MaybeStage(g) => g,
            _ => return Err(Error::Invalid),
        };
        let Some(guard) = g else {
            return Ok(StageResume::Absent);
        };
        let fence = self
            .client
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        let stage = CheckpointStage {
            guard,
            fence,
            scope: self.client.scope.clone(),
        };
        if self.client.known_committed_seq.load(Ordering::Acquire) > stage.guard.known_committed_seq
        {
            return Ok(StageResume::Stale(stage));
        }
        match self.active(stage).await {
            Ok(s) => Ok(StageResume::Active(s)),
            Err(Error::Busy) => {
                let guard = match self
                    .client
                    .journal
                    .call(Command::CheckpointHandle {
                        scope_tag: self.client.checkpoint_scope_tag()?,
                        key_id: key.id(),
                    })
                    .await?
                {
                    Reply::MaybeStage(Some(g)) => g,
                    _ => return Err(Error::Busy),
                };
                Ok(StageResume::Stale(CheckpointStage {
                    guard,
                    fence: self
                        .client
                        .identity
                        .local_use_fence()
                        .await
                        .map_err(identity_failure)?,
                    scope: self.client.scope.clone(),
                }))
            }
            Err(e) => Err(e),
        }
    }
    async fn checkpoint_begin(
        &self,
        base: u64,
        total: usize,
    ) -> Result<ActiveStage<Self::Stage, Self::Guard>, Error> {
        self.validate().await?;
        let s = self.client.begin_checkpoint(base, total).await?;
        self.active(s).await
    }
    async fn checkpoint_page(
        &self,
        token: BaseRead,
    ) -> Result<ReadOutcome<VerifiedBasePage<Self::BaseContents>>, Error> {
        let reply = self
            .request(SyncRequest::BaseV3 {
                base: token.base,
                after_member: token.after_member,
                limit: token.limit.try_into().map_err(|_| Error::Invalid)?,
            })
            .await?;
        match Self::expired(&reply)? {
            Some(ReadOutcome::Expired(h)) => return Ok(ReadOutcome::Expired(h)),
            Some(_) => return Err(Error::Invalid),
            None => {}
        }
        if reply.status != 200 || reply.body.len() > nddev_device_sync_domain::sync::MAX_PAGE_BYTES
        {
            return Err(Error::Invalid);
        }
        let p: crate::sync3_wire::SyncBasePage =
            serde_json::from_slice(&reply.body).map_err(|_| Error::Invalid)?;
        let base = p.base_seq.try_into().map_err(|_| Error::Invalid)?;
        let total = p.total_members.try_into().map_err(|_| Error::Invalid)?;
        let next = p.next_member_seq.try_into().map_err(|_| Error::Invalid)?;
        if p.schema_version != 3
            || base != token.base
            || p.entries.len() > token.limit
            || p.has_more && p.entries.is_empty()
        {
            return Err(Error::Invalid);
        }
        let key = self.key().await?;
        let rows = p
            .entries
            .into_iter()
            .map(|r| VaultClient::verify_row(&self.client.scope, &key, r))
            .collect::<Result<Vec<_>, _>>()?;
        let sequences = rows.iter().map(|r| r.sequence).collect::<Vec<_>>();
        if sequences
            .iter()
            .any(|seq| *seq <= token.after_member || *seq > base)
            || sequences.windows(2).any(|pair| pair[0] >= pair[1])
            || next != sequences.last().copied().unwrap_or(token.after_member)
        {
            return Err(Error::Invalid);
        }
        Ok(ReadOutcome::Page(VerifiedBasePage {
            contents: BaseData { rows },
            base,
            expected_members: total,
            sequences,
            next_member: next,
            has_more: p.has_more,
        }))
    }
    async fn stage_page(
        &self,
        stage: &Self::Stage,
        page: VerifiedBasePage<Self::BaseContents>,
    ) -> Result<(), Error> {
        self.validate().await?;
        self.client.checkpoint_key(stage).await?;
        self.client
            .identity
            .validate_local_use(&stage.fence)
            .await
            .map_err(identity_failure)?;
        self.client
            .journal
            .call(Command::StageBase {
                guard: stage.guard.clone(),
                base: page.base,
                total: page.expected_members,
                rows: page.contents.rows,
                next: page.next_member,
                more: page.has_more,
            })
            .await?;
        Ok(())
    }
    async fn checkpoint_delta(
        &self,
        stage: &Self::Stage,
        page: VerifiedPage<Self::Page>,
    ) -> Result<(), Error> {
        self.validate().await?;
        self.client.checkpoint_key(stage).await?;
        self.client
            .identity
            .validate_local_use(&stage.fence)
            .await
            .map_err(identity_failure)?;
        let PageData::Versioned(p) = page.contents else {
            return Err(Error::Invalid);
        };
        self.client
            .journal
            .call(Command::StageDelta {
                guard: stage.guard.clone(),
                floor: p.floor,
                rows: p.rows,
                next: p.next,
                more: p.more,
            })
            .await?;
        Ok(())
    }
    async fn checkpoint_discard(&self, stage: Self::Stage) -> Result<(), Error> {
        self.validate().await?;
        self.client
            .identity
            .validate_local_use(&stage.fence)
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?;
        if stage.scope != self.client.scope || stage.guard.key_id != key.id() {
            return Err(Error::Locked);
        }
        self.client
            .journal
            .call(Command::DiscardCheckpoint { guard: stage.guard })
            .await?;
        Ok(())
    }
    async fn install_checkpoint(
        &self,
        expected: &Self::Guard,
        stage: Self::Stage,
    ) -> Result<(), Error> {
        self.validate().await?;
        if *expected != stage.guard {
            return Err(Error::Busy);
        }
        self.client.install_checkpoint(&stage).await.map(|_| ())
    }
}

#[cfg(test)]
mod negotiation_tests {
    use super::*;

    #[test]
    fn missing_capabilities_is_not_a_writer_grant() {
        for body in [Vec::new(), b"not found".to_vec()] {
            assert!(matches!(
                decode_negotiation(SyncReply { status: 404, body }),
                Ok(Negotiation::LegacyUnsupported)
            ));
        }
        for status in [401, 403, 405, 410, 429, 500, 503] {
            assert!(
                decode_negotiation(SyncReply {
                    status,
                    body: Vec::new()
                })
                .is_err()
            );
        }
    }

    #[test]
    fn advertised_capabilities_still_require_the_versioned_wire_shape() {
        let body = br#"{"schema_version":3,"read_operation_versions":[2,3],"new_operation_version":3,"history_retention":true}"#.to_vec();
        let Ok(Negotiation::Capabilities(value)) =
            decode_negotiation(SyncReply { status: 200, body })
        else {
            panic!("valid capabilities");
        };
        assert_eq!(value.reader_versions, [2, 3]);
        assert_eq!(value.writer, WriterMode::V3);
        assert!(value.retention);
        assert!(
            decode_negotiation(SyncReply {
                status: 200,
                body: Vec::new()
            })
            .is_err()
        );
    }
}
