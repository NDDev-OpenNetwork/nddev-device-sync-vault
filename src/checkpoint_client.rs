use super::*;
use crate::{
    journal::{RawRow, StageGuard},
    storage::{Command, Reply},
};
use nddev_device_sync_domain::sync::history::OperationVersion;
use std::sync::atomic::Ordering;

/// Opaque local handle: the protected authorization observation remains Rust
/// memory. SQLite/OPFS receives only encrypted rows and public version metadata.
pub struct CheckpointStage {
    pub(super) guard: StageGuard,
    pub(super) fence: nddev_device_sync_accounts::LocalUseFence,
    pub(super) scope: Scope,
}
impl VaultClient {
    /// Resume only after a fresh protected local-use observation in this process.
    pub async fn resume_checkpoint(&self) -> Result<Option<CheckpointStage>, Error> {
        let fence = self
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let scope_tag = self.checkpoint_scope_tag()?;
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        let reply = self
            .journal
            .call(Command::ResumeCheckpoint {
                scope_tag,
                key_id: key.id(),
                known: self.known_committed_seq.load(Ordering::Acquire),
            })
            .await?;
        let Reply::MaybeStage(guard) = reply else {
            return Err(Error::Invalid);
        };
        Ok(guard.map(|guard| CheckpointStage {
            guard,
            fence,
            scope: self.scope.clone(),
        }))
    }
    /// Explicitly discard a lost/stale operational stage under current owner/key.
    /// Active entities, pending families and conflict alternatives are untouched.
    pub async fn reset_checkpoint_stage(&self) -> Result<(), Error> {
        let fence = self
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let scope_tag = self.checkpoint_scope_tag()?;
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        self.journal
            .call(Command::ResetCheckpoint {
                scope_tag,
                key_id: key.id(),
            })
            .await?;
        Ok(())
    }
    pub(super) fn checkpoint_scope_tag(&self) -> Result<String, Error> {
        let encoded = serde_json::to_vec(&(
            &self.scope.origin,
            &self.scope.tenant,
            &self.scope.user,
            &self.scope.device,
        ))
        .map_err(dependency)?;
        Ok(format!("{:x}", Sha256::digest(encoded)))
    }
    pub async fn begin_checkpoint(
        &self,
        base: u64,
        total_members: usize,
    ) -> Result<CheckpointStage, Error> {
        let fence = self
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let encoded = serde_json::to_vec(&(
            &self.scope.origin,
            &self.scope.tenant,
            &self.scope.user,
            &self.scope.device,
        ))
        .map_err(dependency)?;
        let scope_tag = format!("{:x}", Sha256::digest(encoded));
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        let reply = self
            .journal
            .call(Command::BeginCheckpoint {
                scope_tag,
                key_id: key.id(),
                base,
                total: total_members,
                known: self.known_committed_seq.load(Ordering::Acquire),
            })
            .await?;
        let Reply::Stage(guard) = reply else {
            return Err(Error::Invalid);
        };
        Ok(CheckpointStage {
            guard,
            fence,
            scope: self.scope.clone(),
        })
    }
    pub(super) async fn checkpoint_key(&self, stage: &CheckpointStage) -> Result<VaultKey, Error> {
        if stage.scope != self.scope
            || self.known_committed_seq.load(Ordering::Acquire) > stage.guard.known_committed_seq
        {
            return Err(Error::Busy);
        }
        self.identity
            .validate_local_use(&stage.fence)
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        if key.id() != stage.guard.key_id {
            return Err(Error::Locked);
        }
        Ok(key)
    }
    pub(crate) fn decode_history_page(
        &self,
        key: &VaultKey,
        body: &[u8],
        after: u64,
    ) -> Result<VerifiedHistory, Error> {
        use nddev_device_sync_domain::sync::{MAX_PAGE_BYTES, MAX_PAGE_ITEMS, history};
        if !(1..=MAX_PAGE_BYTES).contains(&body.len()) {
            return Err(Error::Invalid);
        }
        let p: crate::sync3_wire::SyncDeltaPage =
            serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        let head = u64::try_from(p.head_seq).map_err(|_| Error::Invalid)?;
        let floor = u64::try_from(p.floor_seq).map_err(|_| Error::Invalid)?;
        let next = u64::try_from(p.next_after_seq).map_err(|_| Error::Invalid)?;
        history::HistoryVersion {
            head,
            floor,
            base: floor,
        }
        .validate()
        .map_err(|_| Error::Invalid)?;
        if p.schema_version != 3
            || after < floor
            || next > head
            || p.has_more != (next < head)
            || p.entries.len() > MAX_PAGE_ITEMS
        {
            return Err(Error::Invalid);
        }
        let mut rows = Vec::with_capacity(p.entries.len());
        for row in p.entries {
            rows.push(Self::verify_row(&self.scope, key, row)?);
        }
        history::delta_progress(
            after,
            &rows.iter().map(|r| r.sequence).collect::<Vec<_>>(),
            next,
            p.has_more,
        )
        .map_err(|_| Error::Invalid)?;
        Ok(VerifiedHistory {
            head,
            floor,
            after,
            rows,
            next,
            more: p.has_more,
        })
    }
    pub(crate) fn verify_row(
        scope: &Scope,
        key: &VaultKey,
        row: crate::sync3_wire::SyncRow,
    ) -> Result<RawRow, Error> {
        let status = row.result_status.try_into().map_err(|_| Error::Invalid)?;
        let sequence = row.server_seq.try_into().map_err(|_| Error::Invalid)?;
        let mut raw = RawRow {
            legacy_resolved: 0,
            body: row.operation_body.into_bytes(),
            result: row.result_body.into_bytes(),
            status,
            sequence,
        };
        let (operation, receipt) = codec::original_receipt(&raw.body, &raw.result, status)?;
        if receipt.server_seq != sequence {
            return Err(Error::Invalid);
        }
        let resolved = Self::verify_versioned(scope, key, &operation)?;
        if operation.version == OperationVersion::V2 {
            raw.legacy_resolved = resolved;
        }
        raw.decode()?;
        Ok(raw)
    }
    pub async fn stage_checkpoint_base(
        &self,
        stage: &CheckpointStage,
        body: &[u8],
    ) -> Result<(), Error> {
        if !(1..=nddev_device_sync_domain::sync::MAX_PAGE_BYTES).contains(&body.len()) {
            return Err(Error::Invalid);
        }
        let key = self.checkpoint_key(stage).await?;
        let page: crate::sync3_wire::SyncBasePage =
            serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        if page.schema_version != 3 {
            return Err(Error::Invalid);
        }
        let base = page.base_seq.try_into().map_err(|_| Error::Invalid)?;
        let total = page.total_members.try_into().map_err(|_| Error::Invalid)?;
        let next = page
            .next_member_seq
            .try_into()
            .map_err(|_| Error::Invalid)?;
        if page.entries.len() > nddev_device_sync_domain::sync::MAX_PAGE_ITEMS {
            return Err(Error::Invalid);
        }
        let rows = page
            .entries
            .into_iter()
            .map(|r| Self::verify_row(&self.scope, &key, r))
            .collect::<Result<Vec<_>, _>>()?;
        self.checkpoint_key(stage).await?;
        self.journal
            .call(Command::StageBase {
                guard: stage.guard.clone(),
                base,
                total,
                rows,
                next,
                more: page.has_more,
            })
            .await?;
        Ok(())
    }
    pub async fn stage_checkpoint_delta(
        &self,
        stage: &CheckpointStage,
        body: &[u8],
    ) -> Result<(), Error> {
        if !(1..=nddev_device_sync_domain::sync::MAX_PAGE_BYTES).contains(&body.len()) {
            return Err(Error::Invalid);
        }
        let key = self.checkpoint_key(stage).await?;
        let page: crate::sync3_wire::SyncDeltaPage =
            serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
        let head: u64 = page.head_seq.try_into().map_err(|_| Error::Invalid)?;
        let floor: u64 = page.floor_seq.try_into().map_err(|_| Error::Invalid)?;
        let next: u64 = page.next_after_seq.try_into().map_err(|_| Error::Invalid)?;
        nddev_device_sync_domain::sync::history::HistoryVersion {
            head,
            floor,
            base: floor,
        }
        .validate()
        .map_err(|_| Error::Invalid)?;
        if page.schema_version != 3
            || next > head
            || !page.has_more && next != head
            || page.has_more && next >= head
            || page.entries.len() > nddev_device_sync_domain::sync::MAX_PAGE_ITEMS
        {
            return Err(Error::Invalid);
        }
        let rows = page
            .entries
            .into_iter()
            .map(|r| Self::verify_row(&self.scope, &key, r))
            .collect::<Result<Vec<_>, _>>()?;
        self.checkpoint_key(stage).await?;
        self.journal
            .call(Command::StageDelta {
                guard: stage.guard.clone(),
                floor,
                rows,
                next,
                more: page.has_more,
            })
            .await?;
        Ok(())
    }
    pub async fn install_checkpoint(&self, stage: &CheckpointStage) -> Result<VaultView, Error> {
        self.checkpoint_key(stage).await?;
        self.journal
            .call(Command::InstallCheckpoint {
                guard: stage.guard.clone(),
            })
            .await?;
        self.view
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .catching_up = true;
        self.update_view().await
    }
    pub async fn discard_checkpoint(&self, stage: &CheckpointStage) -> Result<(), Error> {
        self.checkpoint_key(stage).await?;
        self.journal
            .call(Command::DiscardCheckpoint {
                guard: stage.guard.clone(),
            })
            .await?;
        Ok(())
    }
    pub(super) fn verify_versioned(
        scope: &Scope,
        key: &VaultKey,
        operation: &nddev_device_sync_domain::sync::history::VersionedOperation,
    ) -> Result<u64, Error> {
        let plaintext = key.decrypt_versioned(scope, operation)?;
        let o = &operation.operation;
        match o.entity_kind {
            EntityKind::VaultRecord => match operation.version {
                OperationVersion::V2 => {
                    let r: Record =
                        serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                    r.validate().map_err(|_| Error::Invalid)?;
                    Ok(r.resolved_through_seq)
                }
                OperationVersion::V3 { lifecycle, .. } => {
                    let r: Record3 =
                        serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                    r.validate().map_err(|_| Error::Invalid)?;
                    Ok(lifecycle.resolved_through_seq)
                }
            },
            EntityKind::ClipboardItem => {
                let t: nddev_device_sync_domain::clipboard::Text =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                t.validate().map_err(|_| Error::Invalid)?;
                Ok(operation.lifecycle().resolved_through_seq)
            }
            kind => {
                let snapshot: Snapshot =
                    serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
                snapshot
                    .validate(&o.device, kind, &o.entity_id)
                    .map_err(|_| Error::Invalid)?;
                Ok(operation.lifecycle().resolved_through_seq)
            }
        }
    }
}

pub(crate) struct VerifiedHistory {
    pub head: u64,
    pub floor: u64,
    pub after: u64,
    pub rows: Vec<RawRow>,
    pub next: u64,
    pub more: bool,
}
