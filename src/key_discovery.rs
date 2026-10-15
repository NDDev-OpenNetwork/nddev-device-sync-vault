//! Bounded public header projection for the caller-selected key discovery read.
//! No HTTP, fallback, writer-mode decision, key import or rotation occurs here.
use crate::{Error, codec, sync3_wire};
use nddev_device_sync_domain::sync::{
    MAX_PAGE_BYTES,
    history::{self, BaseProgress},
};
fn sequences(rows: &[sync3_wire::SyncRow]) -> Result<(Vec<u64>, Option<String>), Error> {
    let mut seqs = Vec::with_capacity(rows.len());
    let mut hint = None;
    for row in rows {
        let status = row.result_status.try_into().map_err(|_| Error::Invalid)?;
        let (operation, receipt) = codec::original_receipt(
            row.operation_body.as_bytes(),
            row.result_body.as_bytes(),
            status,
        )?;
        let seq = u64::try_from(row.server_seq).map_err(|_| Error::Invalid)?;
        if receipt.server_seq != seq {
            return Err(Error::Invalid);
        }
        if hint.is_none() {
            hint = Some(operation.operation.payload.key_id);
        }
        seqs.push(seq);
    }
    Ok((seqs, hint))
}
pub(crate) fn history_hint(body: &[u8], after: u64) -> Result<Option<String>, Error> {
    if !(1..=MAX_PAGE_BYTES).contains(&body.len()) {
        return Err(Error::Invalid);
    }
    let p: sync3_wire::SyncDeltaPage = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
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
        || p.entries.len() > 1
        || after < floor
        || next > head
        || p.has_more != (next < head)
    {
        return Err(Error::Invalid);
    }
    let (seqs, hint) = sequences(&p.entries)?;
    history::delta_progress(after, &seqs, next, p.has_more).map_err(|_| Error::Invalid)?;
    Ok(hint)
}
pub(crate) fn base_hint(body: &[u8], expected_base: u64) -> Result<Option<String>, Error> {
    if !(1..=MAX_PAGE_BYTES).contains(&body.len()) {
        return Err(Error::Invalid);
    }
    let p: sync3_wire::SyncBasePage = serde_json::from_slice(body).map_err(|_| Error::Invalid)?;
    let base = u64::try_from(p.base_seq).map_err(|_| Error::Invalid)?;
    let total = usize::try_from(p.total_members).map_err(|_| Error::Invalid)?;
    let next = u64::try_from(p.next_member_seq).map_err(|_| Error::Invalid)?;
    if p.schema_version != 3 || base != expected_base || p.entries.len() > 1 {
        return Err(Error::Invalid);
    }
    let (seqs, hint) = sequences(&p.entries)?;
    BaseProgress {
        base,
        total,
        received: 0,
        after_member: 0,
    }
    .advance(base, total, &seqs, next, p.has_more)
    .map_err(|_| Error::Invalid)?;
    Ok(hint)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn empty_verified_history_has_no_hint_but_expiry_is_not_empty_history() {
        let empty=br#"{"schema_version":3,"head_seq":0,"floor_seq":0,"entries":[],"next_after_seq":0,"has_more":false}"#;
        assert!(history_hint(empty, 0).unwrap().is_none());
        let expired =
            br#"{"schema_version":3,"error":"cursor_expired","head_seq":5,"floor_seq":3}"#;
        assert!(matches!(history_hint(expired, 0), Err(Error::Invalid)));
        assert!(matches!(base_hint(br#"{"schema_version":3,"base_seq":3,"total_members":0,"entries":[],"next_member_seq":0,"has_more":false}"#,4),Err(Error::Invalid)));
    }
    #[test]
    fn sparse_original_base_supplies_public_key_hint_without_skipping_normal_history() {
        use crate::crypto::{Scope, VaultKey};
        use nddev_device_sync_domain::{
            DeviceId,
            sync::{
                EncryptedPayload, EntityKind, Operation,
                history::{Lifecycle, VersionedOperation},
            },
        };
        let key = VaultKey::generate().unwrap();
        let scope = Scope {
            origin: "https://instance.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: "device".into(),
        };
        let raw = Operation {
            id: "hint".into(),
            device: DeviceId::new("device").unwrap(),
            entity_kind: EntityKind::VaultRecord,
            entity_id: "a".into(),
            base_revision: 0,
            idempotency_key: "hint".into(),
            payload: EncryptedPayload {
                key_id: key.id(),
                nonce: [0; 12],
                ciphertext: vec![],
            },
        };
        let mut op = VersionedOperation::qualify(
            raw,
            4,
            Lifecycle {
                resolved_through_seq: 0,
            },
        )
        .unwrap();
        op.operation.payload=key.encrypt_versioned(&scope,&op,br#"{"version":3,"deleted":false,"title":"Record","username":"","secret":"fixture"}"#).unwrap();
        let body = codec::versioned_body(&op).unwrap();
        let receipt=serde_json::json!({"operation_id":op.operation.id,"outcome":"applied","revision":1,"server_seq":5}).to_string();
        let row = serde_json::json!({"operation_body":String::from_utf8(body).unwrap(),"result_body":receipt,"result_status":201,"server_seq":5});
        let base=serde_json::to_vec(&serde_json::json!({"schema_version":3,"base_seq":5,"entries":[row.clone()],"total_members":1,"next_member_seq":5,"has_more":false})).unwrap();
        assert_eq!(base_hint(&base, 5).unwrap(), Some(key.id()));
        let page=serde_json::to_vec(&serde_json::json!({"schema_version":3,"head_seq":5,"floor_seq":0,"entries":[row],"next_after_seq":5,"has_more":false})).unwrap();
        assert!(matches!(history_hint(&page, 0), Err(Error::Invalid)));
        assert_eq!(history_hint(&page, 4).unwrap(), Some(key.id()));
    }
}
