//! Durable local acknowledgement and epoch retirement.
//!
//! The cursor transition is committed to the manifest before any segment is
//! removed. `Retiring` descriptors make every crash point recoverable without
//! treating an acknowledged segment as an unexplained gap.

use super::{persistence, EpochPhase, SpoolManifest, UsageCursor, UsageSpoolError};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind;
use std::path::Path;
use uuid::Uuid;

#[derive(Debug)]
pub(super) struct PersistedAcknowledgement {
    pub(super) manifest: SpoolManifest,
    pub(super) manifest_bytes: u64,
    pub(super) removed_epochs: HashSet<Uuid>,
    pub(super) cleanup_error: Option<String>,
}

pub(super) async fn persist(
    directory: &Path,
    manifest: &SpoolManifest,
    cursor: UsageCursor,
    retiring_epochs: &HashSet<Uuid>,
) -> Result<PersistedAcknowledgement, UsageSpoolError> {
    let mut proposed = manifest.clone();
    proposed.acknowledge(cursor);
    mark_retiring(&mut proposed, retiring_epochs)?;
    commit_and_retire(directory, proposed).await
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
    manifest: &mut SpoolManifest,
    last_sequences: &HashMap<Uuid, u64>,
) -> Result<bool, UsageSpoolError> {
    let mut retiring = last_sequences
        .iter()
        .filter_map(|(boot_epoch, sequence)| (*sequence == 0).then_some(*boot_epoch))
        .collect::<HashSet<_>>();

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
            if last_sequences.get(&cursor.boot_epoch) == Some(&cursor.sequence) {
                retiring.insert(cursor.boot_epoch);
            }
        }
    }

    if retiring.is_empty() {
        return Ok(false);
    }

    let mut proposed = manifest.clone();
    mark_retiring(&mut proposed, &retiring)?;
    let result = commit_and_retire(directory, proposed).await?;
    *manifest = result.manifest;
    match result.cleanup_error {
        Some(reason) => Err(UsageSpoolError::Unavailable { reason }),
        None => Ok(true),
    }
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

async fn commit_and_retire(
    directory: &Path,
    proposed: SpoolManifest,
) -> Result<PersistedAcknowledgement, UsageSpoolError> {
    let prepared_bytes = persistence::write_manifest(directory, &proposed).await? as u64;
    let retiring = proposed
        .epochs
        .iter()
        .filter(|epoch| epoch.phase == EpochPhase::Retiring)
        .map(|epoch| (epoch.boot_epoch, epoch.file.clone()))
        .collect::<Vec<_>>();
    if retiring.is_empty() {
        return Ok(PersistedAcknowledgement {
            manifest: proposed,
            manifest_bytes: prepared_bytes,
            removed_epochs: HashSet::new(),
            cleanup_error: None,
        });
    }

    let mut removed_epochs = HashSet::new();
    for (boot_epoch, file) in &retiring {
        if let Err(error) = remove_segment(directory, file).await {
            return Ok(cleanup_pending(
                proposed,
                prepared_bytes,
                removed_epochs,
                error,
            ));
        }
        removed_epochs.insert(*boot_epoch);
    }
    if let Err(error) = persistence::sync_directory(directory).await {
        return Ok(cleanup_pending(
            proposed,
            prepared_bytes,
            removed_epochs,
            error,
        ));
    }

    let mut finalized = proposed.clone();
    finalized
        .epochs
        .retain(|epoch| epoch.phase != EpochPhase::Retiring);
    match persistence::write_manifest(directory, &finalized).await {
        Ok(bytes) => Ok(PersistedAcknowledgement {
            manifest: finalized,
            manifest_bytes: bytes as u64,
            removed_epochs,
            cleanup_error: None,
        }),
        Err(error) => Ok(cleanup_pending(
            proposed,
            prepared_bytes,
            removed_epochs,
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
    error: UsageSpoolError,
) -> PersistedAcknowledgement {
    PersistedAcknowledgement {
        manifest,
        manifest_bytes,
        removed_epochs,
        cleanup_error: Some(format!(
            "usage acknowledgement is durable but epoch cleanup requires restart: {error}"
        )),
    }
}
