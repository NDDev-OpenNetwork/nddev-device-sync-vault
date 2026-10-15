//! Encrypted catalog I/O for NdsClient's Core-owned observation use case.
//! Source observations are not authorization; the original Accounts fence and
//! selected encrypted record remain required through the durable enqueue.
use super::*;
use nddev_device_sync_accounts::LocalUseFence;
use nddev_device_sync_domain::repositories::catalog::observations::{
    Candidate, ObservationContext, ObservationKey, ObservedTarget, PublicationDecision,
    RepositoryObservation, TargetVersion,
};
use std::collections::BTreeMap;

pub(super) struct SourceGuard {
    pub(super) selection: CredentialSelection,
    pub(super) operation: Vec<u8>,
    pub(super) fence: Arc<LocalUseFence>,
    pub(super) cancellation: tokio_util::sync::CancellationToken,
}
impl SourceGuard {
    pub(super) fn check(&self) -> Result<(), Error> {
        if self.cancellation.is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// Opaque pre-provider read, owned by one caller lifetime. It contains no key or
/// plaintext credential and cannot be serialized into a new authorization.
pub struct RepositoryRead {
    source: SourceGuard,
    targets: BTreeMap<String, TargetVersion>,
    writer_mode: Option<replica::WriterMode>,
}
impl RepositoryRead {
    /// Mechanical stored IDs; Core owns canonical key decoding and capture.
    pub fn baselines(&self) -> Vec<(String, TargetVersion)> {
        self.targets
            .iter()
            .map(|(id, version)| (id.clone(), version.clone()))
            .collect()
    }
    /// Observed format fact, not a grant. Core still prepares every operation.
    pub fn writer_mode(&self) -> Option<replica::WriterMode> {
        self.writer_mode
    }
}

pub enum RepositoryPublication {
    Unchanged,
    Queued { operation_id: String },
    ReRead,
    SourceChanged,
}

/// A local keyset position, bound to the encrypted replica scope. It is not
/// transferable authorization and carries no provider cursor or credential.
#[derive(Clone)]
pub struct RepositoryCatalogCursor {
    scope: Scope,
    after: String,
}
pub struct RepositoryCatalogPage {
    pub observations: Vec<(ObservedTarget, u64)>,
    pub next: Option<RepositoryCatalogCursor>,
    pub observed_seq: u64,
    pub local_revision: u64,
}

fn decode_catalog_entity(
    scope: &Scope,
    key: &VaultKey,
    expected_id: &str,
    entity: crate::journal::Entity,
    history_cursor: u64,
) -> Result<(ObservedTarget, u64), Error> {
    let operation = codec::versioned(&entity.body)?;
    if operation.operation.entity_kind != EntityKind::RepositoryState
        || operation.operation.entity_id != expected_id
    {
        return Err(Error::Invalid);
    }
    let plaintext = key.decrypt_versioned(scope, &operation)?;
    let snapshot: Snapshot = serde_json::from_slice(&plaintext).map_err(|_| Error::Invalid)?;
    snapshot
        .validate(
            &operation.operation.device,
            EntityKind::RepositoryState,
            expected_id,
        )
        .map_err(|_| Error::Invalid)?;
    let State::Repository { observation } = snapshot.data else {
        return Err(Error::Invalid);
    };
    let version = TargetVersion {
        revision: entity.revision,
        next_base: entity.next_base,
        pending_id: entity.pending_id,
        conflicted: entity.conflicted,
    };
    version.validate().map_err(|_| Error::Invalid)?;
    Ok((
        ObservedTarget {
            key: observation.key(),
            version,
            value: Some(observation),
            history_cursor,
        },
        snapshot.observed_at_ms,
    ))
}

fn decode_target(
    scope: &Scope,
    key: &VaultKey,
    expected: &ObservationKey,
    target: crate::journal::ObservationTarget,
) -> Result<ObservedTarget, Error> {
    match target.effective {
        Some(entity) => {
            decode_catalog_entity(scope, key, &expected.entity_id(), entity, target.cursor)
                .map(|(value, _)| value)
        }
        None => Ok(ObservedTarget {
            key: expected.clone(),
            version: TargetVersion::absent(),
            value: None,
            history_cursor: target.cursor,
        }),
    }
}

impl VaultClient {
    /// Read saved facts without GitHub I/O or a selected GitHub credential.
    /// Native/browser authorization and the original local-use fence still apply.
    /// Pages are individually consistent local observations, not a frozen catalog
    /// snapshot or proof of current provider access.
    pub async fn repository_catalog_page(
        &self,
        after: Option<&RepositoryCatalogCursor>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<RepositoryCatalogPage, Error> {
        use nddev_device_sync_domain::repositories::catalog::{
            REPOSITORIES_PER_PAGE, observations::ObservationData,
        };
        let check = || {
            if cancellation.is_cancelled() {
                Err(Error::Cancelled)
            } else {
                Ok(())
            }
        };
        check()?;
        let _permit = self.admitted()?;
        if after.is_some_and(|cursor| cursor.scope != self.scope) {
            return Err(Error::Invalid);
        }
        let fence = self
            .identity
            .local_use_fence()
            .await
            .map_err(identity_failure)?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        check()?;
        let mut raw = match self
            .journal
            .call(crate::storage::Command::RepositoryPage {
                after: after.map_or_else(String::new, |cursor| cursor.after.clone()),
            })
            .await?
        {
            crate::storage::Reply::CatalogRows(value) => value,
            _ => return Err(Error::Invalid),
        };
        check()?;
        let more = raw.entries.len() > REPOSITORIES_PER_PAGE;
        raw.entries.truncate(REPOSITORIES_PER_PAGE);
        let next = if more {
            raw.entries.last().map(|(id, _)| RepositoryCatalogCursor {
                scope: self.scope.clone(),
                after: id.clone(),
            })
        } else {
            None
        };
        let mut observations = Vec::new();
        let mut owners = std::collections::BTreeSet::new();
        for (id, entity) in raw.entries {
            let value = decode_catalog_entity(&self.scope, &key, &id, entity, raw.cursor)?;
            let Some(RepositoryObservation {
                data: ObservationData::Repository { repository },
                ..
            }) = &value.0.value
            else {
                return Err(Error::Invalid);
            };
            owners.insert(ObservationKey::Owner(repository.owner_id).entity_id());
            observations.push(value);
        }
        let owner_rows = match self
            .journal
            .call(crate::storage::Command::RepositoryOwners {
                ids: owners.into_iter().collect(),
                expected: raw.local_revision,
            })
            .await?
        {
            crate::storage::Reply::CatalogRows(value) => value,
            _ => return Err(Error::Invalid),
        };
        check()?;
        for (id, entity) in owner_rows.entries {
            let value = decode_catalog_entity(&self.scope, &key, &id, entity, raw.cursor)?;
            if !matches!(
                &value.0.value,
                Some(RepositoryObservation {
                    data: ObservationData::Owner { .. },
                    ..
                })
            ) {
                return Err(Error::Invalid);
            }
            observations.push(value);
        }
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        check()?;
        Ok(RepositoryCatalogPage {
            observations,
            next,
            observed_seq: raw.cursor,
            local_revision: raw.local_revision,
        })
    }
    /// Capture local target metadata before GitHub I/O, without holding a store
    /// lock across that I/O. The caller supplies its original identity fence.
    pub async fn capture_repository_observations(
        &self,
        selection: CredentialSelection,
        fence: Arc<LocalUseFence>,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> Result<RepositoryRead, Error> {
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let _permit = self.admitted()?;
        selection.validate().map_err(|_| Error::Invalid)?;
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let key = self.key().await?.ok_or(Error::Locked)?;
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        let raw = match self
            .journal
            .call(crate::storage::Command::ObservationBaselines {
                selected: selection.clone(),
            })
            .await?
        {
            crate::storage::Reply::ObservationBaselines(value) => value,
            _ => return Err(Error::Invalid),
        };
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if self.read_record(&key, &raw.selected_operation)?.deleted() {
            return Err(Error::SelectionChanged);
        }
        let writer_mode = history_replica::facts(&raw.writer)?
            .confirmed
            .map(|v| v.mode);
        let mut targets = BTreeMap::new();
        for target in raw.targets {
            let version = TargetVersion {
                revision: target.revision,
                next_base: target.next_base,
                pending_id: target.pending_id,
                conflicted: target.conflicted,
            };
            version.validate().map_err(|_| Error::Invalid)?;
            if targets.insert(target.id, version).is_some() {
                return Err(Error::Invalid);
            }
        }
        self.identity
            .validate_local_use(&fence)
            .await
            .map_err(identity_failure)?;
        if cancellation.is_cancelled() {
            return Err(Error::Cancelled);
        }
        Ok(RepositoryRead {
            source: SourceGuard {
                selection,
                operation: raw.selected_operation,
                fence,
                cancellation,
            },
            targets,
            writer_mode,
        })
    }

    async fn validate_repository_read(&self, read: &RepositoryRead) -> Result<(), Error> {
        read.source.check()?;
        self.identity
            .validate_local_use(&read.source.fence)
            .await
            .map_err(identity_failure)?;
        read.source.check()?;
        let current = self
            .journal
            .entity("vault_record", read.source.selection.record_ref())
            .await?
            .ok_or(Error::SelectionChanged)?;
        if current.conflicted
            || current.revision != read.source.selection.revision()
            || current.pending_id.as_deref() != read.source.selection.pending_id()
            || current.body != read.source.operation
        {
            return Err(Error::SelectionChanged);
        }
        read.source.check()?;
        let result = self
            .identity
            .validate_local_use(&read.source.fence)
            .await
            .map_err(identity_failure);
        read.source.check()?;
        result
    }

    /// Read previous saved scope evidence under the original pre-provider guard.
    /// The result cannot replace that read's captured target version for writing.
    pub async fn repository_observation(
        &self,
        read: &RepositoryRead,
        key: &ObservationKey,
    ) -> Result<ObservedTarget, Error> {
        let _permit = self.admitted()?;
        self.repository_observation_inner(read, key).await
    }

    async fn repository_observation_inner(
        &self,
        read: &RepositoryRead,
        expected: &ObservationKey,
    ) -> Result<ObservedTarget, Error> {
        expected.validate().map_err(|_| Error::Invalid)?;
        self.validate_repository_read(read).await?;
        let key = self.key().await?.ok_or(Error::Locked)?;
        let target = match self
            .journal
            .call(crate::storage::Command::ObservationTarget {
                id: expected.entity_id(),
            })
            .await?
        {
            crate::storage::Reply::ObservationTarget(target) => target,
            _ => return Err(Error::Invalid),
        };
        let current = decode_target(&self.scope, &key, expected, target)?;
        self.validate_repository_read(read).await?;
        Ok(current)
    }

    /// Apply only a candidate captured by the original pre-provider read. Equal
    /// facts cause no encryption or journal write. A changed target must be read
    /// from the provider again; this API never rebases a candidate or resolves a
    /// conflict implicitly. A committed receipt is final even if its waiter ends.
    pub async fn publish_repository_observation(
        &self,
        read: &RepositoryRead,
        candidate: Candidate,
        active: Option<&ObservationContext>,
        observed_at_ms: u64,
    ) -> Result<RepositoryPublication, Error> {
        let _permit = self.admitted()?;
        read.source.check()?;
        if candidate.observation().source.context.selection != read.source.selection {
            return Ok(RepositoryPublication::SourceChanged);
        }
        let id = candidate.observation().key().entity_id();
        let expected = read
            .targets
            .get(&id)
            .cloned()
            .unwrap_or_else(TargetVersion::absent);
        if candidate.expected() != &expected {
            return Err(Error::Invalid);
        }
        let snapshot = Snapshot {
            schema_version: 2,
            observed_at_ms,
            data: State::Repository {
                observation: candidate.observation().clone(),
            },
        };
        snapshot
            .validate(
                &DeviceId::new(&self.scope.device).map_err(dependency)?,
                EntityKind::RepositoryState,
                &id,
            )
            .map_err(|_| Error::Invalid)?;
        let current = self
            .repository_observation_inner(read, &candidate.observation().key())
            .await?;
        let candidate = match candidate
            .decide(&current, active)
            .map_err(|_| Error::Invalid)?
        {
            PublicationDecision::Noop => return Ok(RepositoryPublication::Unchanged),
            PublicationDecision::ReRead => return Ok(RepositoryPublication::ReRead),
            PublicationDecision::SourceChanged => return Ok(RepositoryPublication::SourceChanged),
            PublicationDecision::Write(candidate) => candidate,
        };
        let expected = candidate.expected().clone();
        let id = candidate.observation().key().entity_id();
        let plaintext = Zeroizing::new(serde_json::to_vec(&snapshot).map_err(dependency)?);
        let operation_id = self
            .put_inner(
                EntityKind::RepositoryState,
                id,
                &plaintext,
                Some(Expected {
                    revision: expected.revision,
                    pending: expected.pending_id,
                    resolution: None,
                    observed_base: Some(expected.next_base),
                    observation: Some(SourceGuard {
                        selection: read.source.selection.clone(),
                        operation: read.source.operation.clone(),
                        fence: read.source.fence.clone(),
                        cancellation: read.source.cancellation.clone(),
                    }),
                }),
            )
            .await?;
        Ok(RepositoryPublication::Queued { operation_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nddev_device_sync_domain::{
        repositories::catalog::observations::{
            ObservationData, ObservationSource, RepositoryObservation,
        },
        repositories::catalog::{GithubAccountId, GithubOwner, GithubOwnerKind},
        sync::{
            EncryptedPayload, Operation,
            history::{Lifecycle, VersionedOperation},
        },
    };

    #[test]
    fn repository_decode_authenticates_scope_and_validates_the_bound_identity() {
        let key = VaultKey::generate().unwrap();
        let scope = Scope {
            origin: "https://catalog.example/".into(),
            tenant: "tenant".into(),
            user: "owner".into(),
            device: "device".into(),
        };
        let selected = CredentialSelection::new("credential".into(), 1, None).unwrap();
        let observation = RepositoryObservation {
            source: ObservationSource {
                context: ObservationContext {
                    principal: GithubAccountId::new(7).unwrap(),
                    selection: selected,
                    scan_id: "scan".into(),
                },
                page: Some(1),
            },
            data: ObservationData::Owner {
                owner: GithubOwner {
                    id: GithubAccountId::new(7).unwrap(),
                    kind: GithubOwnerKind::Organization,
                    login: "owned-organization".into(),
                },
            },
        };
        let expected = observation.key();
        let snapshot = Snapshot {
            schema_version: 2,
            observed_at_ms: 42,
            data: State::Repository { observation },
        };
        let mut operation = VersionedOperation::qualify(
            Operation {
                id: "observation".into(),
                device: DeviceId::new("device").unwrap(),
                entity_kind: EntityKind::RepositoryState,
                entity_id: expected.entity_id(),
                base_revision: 0,
                idempotency_key: "observation".into(),
                payload: EncryptedPayload {
                    key_id: key.id(),
                    nonce: [0; 12],
                    ciphertext: vec![],
                },
            },
            1,
            Lifecycle {
                resolved_through_seq: 0,
            },
        )
        .unwrap();
        operation.operation.payload = key
            .encrypt_versioned(&scope, &operation, &serde_json::to_vec(&snapshot).unwrap())
            .unwrap();
        let body = codec::versioned_body(&operation).unwrap();
        let target = || crate::journal::ObservationTarget {
            effective: Some(crate::journal::Entity {
                revision: 1,
                body: body.clone(),
                conflicted: false,
                server_seq: 2,
                pending_id: None,
                next_base: 1,
            }),
            cursor: 2,
        };
        let decoded = decode_target(&scope, &key, &expected, target()).unwrap();
        assert_eq!(decoded.history_cursor, 2);
        assert_eq!(decoded.value.unwrap().key(), expected);
        let (saved, observed_at_ms) = decode_catalog_entity(
            &scope,
            &key,
            &expected.entity_id(),
            target().effective.unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(observed_at_ms, 42);
        assert_eq!(saved.version.revision, 1);
        assert_eq!(saved.history_cursor, 2);
        assert!(matches!(
            decode_target(
                &scope,
                &key,
                &ObservationKey::Owner(GithubAccountId::new(8).unwrap()),
                target()
            ),
            Err(Error::Invalid)
        ));
        let mut foreign = scope.clone();
        foreign.user = "another-owner".into();
        assert!(matches!(
            decode_target(&foreign, &key, &expected, target()),
            Err(Error::Authentication)
        ));
        // Authentic encryption is insufficient: the decoded domain snapshot
        // must also be valid before it can become a semantic no-op or a fact.
        for invalid_time in [0, nddev_device_sync_domain::sync::MAX_REVISION + 1] {
            let mut invalid = snapshot.clone();
            invalid.observed_at_ms = invalid_time;
            operation.operation.payload = key
                .encrypt_versioned(&scope, &operation, &serde_json::to_vec(&invalid).unwrap())
                .unwrap();
            let mut invalid_target = target();
            invalid_target.effective.as_mut().unwrap().body =
                codec::versioned_body(&operation).unwrap();
            assert!(matches!(
                decode_target(&scope, &key, &expected, invalid_target),
                Err(Error::Invalid)
            ));
        }
    }
}
