//! Durable local acknowledgement, epoch retirement, and prefix compaction.
//!
//! The cursor transition is committed to the manifest before any segment is
//! removed or replaced. Transitional descriptors make every crash point
//! recoverable without treating an acknowledged segment as an unexplained gap.

use super::persistence::StoredRecord;
use super::{
    compaction, persistence, EpochPhase, ManifestSequence, SpoolManifest, UsageCursor,
    UsageSpoolError,
};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug)]
pub(super) struct PersistedAcknowledgement {
    pub(super) manifest: SpoolManifest,
    pub(super) manifest_bytes: u64,
    pub(super) removed_epochs: HashSet<Uuid>,
    pub(super) compacted_epochs: HashSet<Uuid>,
    pub(super) cleanup_error: Option<String>,
}

pub(super) async fn persist(
    directory: &Path,
    gateway_id: Uuid,
    manifest: &SpoolManifest,
    cursor: UsageCursor,
    retiring_epochs: &HashSet<Uuid>,
    first_retained: Option<&StoredRecord>,
) -> Result<PersistedAcknowledgement, UsageSpoolError> {
    let mut proposed = manifest.clone();
    proposed.acknowledge(cursor);
    persist_proposed(
        directory,
        gateway_id,
        manifest,
        proposed,
        retiring_epochs,
        first_retained,
    )
    .await
}

/// Reclaims closed segments during startup, before a new boot epoch is added.
///
/// Empty segments contain no evidence. Segments before an acknowledged cursor,
/// and the cursor's own segment when it is fully acknowledged, are safe to
/// retire. Runtime acknowledgement handles the same transition for old epochs;
/// this startup pass also collects a fully acknowledged final epoch from the
/// previous process.
pub(super) async fn reclaim_closed_epochs(
    directory: &Path,
    gateway_id: Uuid,
    manifest: &mut SpoolManifest,
    records: &[StoredRecord],
    last_sequences: &HashMap<Uuid, Option<u64>>,
) -> Result<bool, UsageSpoolError> {
    let mut retiring = last_sequences
        .iter()
        .filter_map(|(boot_epoch, sequence)| sequence.is_none().then_some(*boot_epoch))
        .collect::<HashSet<_>>();

    let mut first_retained = None;
    if let Some(cursor) = manifest.acknowledged_through() {
        if let Some(acknowledged_epoch) = manifest
            .epochs
            .iter()
            .position(|epoch| epoch.boot_epoch == cursor.boot_epoch)
        {
            retiring.extend(
                manifest.epochs[..acknowledged_epoch]
                    .iter()
                    .map(|epoch| epoch.boot_epoch),
            );
            if last_sequences.get(&cursor.boot_epoch) == Some(&Some(cursor.sequence)) {
                retiring.insert(cursor.boot_epoch);
            } else if manifest.epochs[acknowledged_epoch].first_sequence.0
                != cursor.sequence.checked_add(1).ok_or_else(|| {
                    UsageSpoolError::corrupt("usage acknowledgement sequence overflow")
                })?
            {
                first_retained = Some(
                    records
                        .iter()
                        .find(|record| record.cursor.boot_epoch == cursor.boot_epoch)
                        .ok_or_else(|| {
                            UsageSpoolError::corrupt(format!(
                                "acknowledged epoch {} has no retained compaction boundary",
                                cursor.boot_epoch
                            ))
                        })?,
                );
            }
        }
    }

    if retiring.is_empty() && first_retained.is_none() {
        return Ok(false);
    }

    let proposed = manifest.clone();
    let result = persist_proposed(
        directory,
        gateway_id,
        manifest,
        proposed,
        &retiring,
        first_retained,
    )
    .await?;
    *manifest = result.manifest;
    match result.cleanup_error {
        Some(reason) => Err(UsageSpoolError::Unavailable { reason }),
        None => Ok(true),
    }
}

async fn persist_proposed(
    directory: &Path,
    gateway_id: Uuid,
    current: &SpoolManifest,
    mut proposed: SpoolManifest,
    retiring_epochs: &HashSet<Uuid>,
    first_retained: Option<&StoredRecord>,
) -> Result<PersistedAcknowledgement, UsageSpoolError> {
    mark_retiring(&mut proposed, retiring_epochs)?;
    if let Some(record) = first_retained {
        let acknowledged = proposed.acknowledged_through().ok_or_else(|| {
            UsageSpoolError::corrupt("compaction requires an acknowledgement cursor")
        })?;
        let expected_sequence = acknowledged
            .sequence
            .checked_add(1)
            .ok_or_else(|| UsageSpoolError::corrupt("usage sequence overflow"))?;
        if record.cursor.boot_epoch != acknowledged.boot_epoch
            || record.cursor.sequence != expected_sequence
        {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} compaction boundary does not immediately follow acknowledgement {}",
                record.cursor.boot_epoch, acknowledged.sequence
            )));
        }
        let epoch = current
            .epochs
            .iter()
            .find(|epoch| epoch.boot_epoch == record.cursor.boot_epoch)
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "compaction selected unknown epoch {}",
                    record.cursor.boot_epoch
                ))
            })?;
        let prepared = compaction::prepare(directory, gateway_id, epoch, record).await?;
        if let Err(error) = mark_compacting(&mut proposed, &prepared) {
            compaction::abort(&prepared).await;
            return Err(error);
        }
    }
    commit_and_reconcile(directory, gateway_id, proposed).await
}

fn mark_retiring(
    manifest: &mut SpoolManifest,
    retiring_epochs: &HashSet<Uuid>,
) -> Result<(), UsageSpoolError> {
    for boot_epoch in retiring_epochs {
        let epoch = manifest
            .epochs
            .iter_mut()
            .find(|epoch| epoch.boot_epoch == *boot_epoch)
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "acknowledgement selected unknown epoch {boot_epoch} for retirement"
                ))
            })?;
        if epoch.phase != EpochPhase::Ready {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {boot_epoch} is not ready for retirement"
            )));
        }
        epoch.phase = EpochPhase::Retiring;
    }
    Ok(())
}

fn mark_compacting(
    manifest: &mut SpoolManifest,
    prepared: &compaction::PreparedCompaction,
) -> Result<(), UsageSpoolError> {
    let epoch = manifest
        .epochs
        .iter_mut()
        .find(|epoch| epoch.boot_epoch == prepared.boot_epoch)
        .ok_or_else(|| {
            UsageSpoolError::corrupt(format!(
                "compaction selected unknown epoch {}",
                prepared.boot_epoch
            ))
        })?;
    if epoch.phase != EpochPhase::Ready {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} is not ready for compaction",
            prepared.boot_epoch
        )));
    }
    epoch.first_sequence = ManifestSequence(prepared.first_sequence);
    epoch.compacted_last_sequence = ManifestSequence(prepared.last_sequence);
    epoch.phase = EpochPhase::Compacting;
    Ok(())
}

async fn commit_and_reconcile(
    directory: &Path,
    gateway_id: Uuid,
    proposed: SpoolManifest,
) -> Result<PersistedAcknowledgement, UsageSpoolError> {
    let prepared_bytes = match persistence::write_manifest(directory, &proposed).await {
        Ok(bytes) => bytes as u64,
        // The rename may have succeeded even when the following directory sync
        // failed. Keep the staging file so either the old ready manifest can
        // discard it or the new compacting manifest can publish it on restart.
        Err(error) => return Err(error),
    };
    let retiring = proposed
        .epochs
        .iter()
        .filter(|epoch| epoch.phase == EpochPhase::Retiring)
        .map(|epoch| (epoch.boot_epoch, epoch.file.clone()))
        .collect::<Vec<_>>();
    let compacting = proposed
        .epochs
        .iter()
        .filter(|epoch| epoch.phase == EpochPhase::Compacting)
        .cloned()
        .collect::<Vec<_>>();
    if retiring.is_empty() && compacting.is_empty() {
        return Ok(PersistedAcknowledgement {
            manifest: proposed,
            manifest_bytes: prepared_bytes,
            removed_epochs: HashSet::new(),
            compacted_epochs: HashSet::new(),
            cleanup_error: None,
        });
    }

    let mut removed_epochs = HashSet::new();
    let mut compacted_epochs = HashSet::new();
    for (boot_epoch, file) in &retiring {
        if let Err(error) = remove_segment(directory, file).await {
            return Ok(cleanup_pending(
                proposed,
                prepared_bytes,
                removed_epochs,
                compacted_epochs,
                error,
            ));
        }
        removed_epochs.insert(*boot_epoch);
    }
    if !retiring.is_empty() {
        if let Err(error) = persistence::sync_directory(directory).await {
            return Ok(cleanup_pending(
                proposed,
                prepared_bytes,
                removed_epochs,
                compacted_epochs,
                error,
            ));
        }
    }
    for epoch in &compacting {
        if let Err(error) = compaction::publish(directory, gateway_id, epoch).await {
            return Ok(cleanup_pending(
                proposed,
                prepared_bytes,
                removed_epochs,
                compacted_epochs,
                error,
            ));
        }
        compacted_epochs.insert(epoch.boot_epoch);
    }

    let mut finalized = proposed.clone();
    finalized
        .epochs
        .retain(|epoch| epoch.phase != EpochPhase::Retiring);
    for epoch in &mut finalized.epochs {
        if epoch.phase == EpochPhase::Compacting {
            epoch.phase = EpochPhase::Ready;
        }
    }
    match persistence::write_manifest(directory, &finalized).await {
        Ok(bytes) => Ok(PersistedAcknowledgement {
            manifest: finalized,
            manifest_bytes: bytes as u64,
            removed_epochs,
            compacted_epochs,
            cleanup_error: None,
        }),
        Err(error) => Ok(cleanup_pending(
            proposed,
            prepared_bytes,
            removed_epochs,
            compacted_epochs,
            error,
        )),
    }
}

async fn remove_segment(directory: &Path, file: &str) -> Result<(), UsageSpoolError> {
    let path = directory.join(file);
    match tokio::fs::symlink_metadata(&path).await {
        Ok(metadata) => persistence::validate_regular_file(&path, &metadata)?,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(UsageSpoolError::io(
                "inspect retiring epoch segment",
                path,
                source,
            ));
        }
    }
    tokio::fs::remove_file(&path)
        .await
        .map_err(|source| UsageSpoolError::io("remove acknowledged epoch segment", path, source))
}

fn cleanup_pending(
    manifest: SpoolManifest,
    manifest_bytes: u64,
    removed_epochs: HashSet<Uuid>,
    compacted_epochs: HashSet<Uuid>,
    error: UsageSpoolError,
) -> PersistedAcknowledgement {
    PersistedAcknowledgement {
        manifest,
        manifest_bytes,
        removed_epochs,
        compacted_epochs,
        cleanup_error: Some(format!(
            "usage acknowledgement is durable but epoch cleanup requires restart: {error}"
        )),
    }
}
