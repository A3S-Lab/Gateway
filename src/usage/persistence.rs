use super::{
    EpochDescriptor, EpochPhase, ManifestSequence, SegmentHeader, SpoolManifest, UsageCursor,
    UsageSpoolError, UsageSpoolOptions, MANIFEST_SCHEMA, MANIFEST_SCHEMA_V1, MANIFEST_SCHEMA_V2,
    MAX_MANIFEST_BYTES, SEGMENT_SCHEMA,
};
use fs2::FileExt;
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub(super) struct StoredRecord {
    pub(super) cursor: UsageCursor,
    pub(super) event_id: Uuid,
    pub(super) payload_sha256: [u8; 32],
    pub(super) path: PathBuf,
    pub(super) offset: u64,
    pub(super) length: usize,
}

impl StoredRecord {
    pub(super) fn new(
        cursor: UsageCursor,
        event_id: Uuid,
        payload_sha256: [u8; 32],
        path: &Path,
        offset: u64,
        length: usize,
    ) -> Self {
        Self {
            cursor,
            event_id,
            payload_sha256,
            path: path.to_path_buf(),
            offset,
            length,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct IndexedEvent {
    pub(super) cursor: UsageCursor,
    pub(super) payload_sha256: [u8; 32],
}

#[derive(Debug)]
pub(super) struct OpenedSpool {
    pub(super) lock_file: std::fs::File,
    pub(super) current_file: tokio::fs::File,
    pub(super) current_path: PathBuf,
    pub(super) current_offset: u64,
    pub(super) boot_epoch: Uuid,
    pub(super) next_sequence: u64,
    pub(super) total_bytes: u64,
    pub(super) manifest: SpoolManifest,
    pub(super) manifest_bytes: u64,
    pub(super) epoch_bytes: HashMap<Uuid, u64>,
    pub(super) records: Vec<StoredRecord>,
    pub(super) events: HashMap<Uuid, IndexedEvent>,
}

pub(super) async fn open(options: &UsageSpoolOptions) -> Result<OpenedSpool, UsageSpoolError> {
    validate_options(options)?;
    prepare_directory(&options.directory).await?;
    let lock_file = acquire_lock(&options.directory).await?;
    cleanup_manifest_temps(&options.directory).await?;

    let (mut manifest, _) = load_or_create_manifest(&options.directory, options.gateway_id).await?;
    if manifest.schema != MANIFEST_SCHEMA {
        manifest.schema = MANIFEST_SCHEMA.to_string();
    }
    recover_manifest_epochs(&options.directory, &mut manifest).await?;
    validate_manifest(&manifest, options.gateway_id)?;

    let mut scanned =
        super::segments::scan(&options.directory, &manifest, options.gateway_id).await?;
    if super::acknowledgement::reclaim_closed_epochs(
        &options.directory,
        options.gateway_id,
        &mut manifest,
        &scanned.0,
        &scanned.4,
    )
    .await?
    {
        scanned = super::segments::scan(&options.directory, &manifest, options.gateway_id).await?;
    }
    let (records, events, segment_bytes, mut epoch_bytes, _) = scanned;
    validate_directory_contents(&options.directory, &manifest).await?;

    let current_manifest_bytes = manifest_bytes(&manifest)?;
    if current_manifest_bytes as u64 > options.max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes: current_manifest_bytes as u64,
            requested_bytes: 0,
            capacity_bytes: options.max_bytes,
        });
    }

    let retained_bytes = (current_manifest_bytes as u64)
        .checked_add(segment_bytes)
        .ok_or_else(|| UsageSpoolError::corrupt("usage spool byte count overflow"))?;
    if retained_bytes > options.max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes,
            requested_bytes: 0,
            capacity_bytes: options.max_bytes,
        });
    }

    // Shared with probe_activation: fixed sentinel sizes so clock digit width
    // cannot soft-open validate while open Full-fails.
    project_boot_epoch_capacity(
        &manifest,
        current_manifest_bytes,
        retained_bytes,
        options.max_bytes,
        options.gateway_id,
    )?;

    let boot_epoch = Uuid::new_v4();
    let created_at = chrono::Utc::now();
    let file_name = format!("epoch-{boot_epoch}.jsonl");
    let pending_name = format!(".{file_name}.pending");
    let final_path = options.directory.join(&file_name);
    let pending_path = options.directory.join(&pending_name);
    let header = SegmentHeader {
        schema: SEGMENT_SCHEMA.to_string(),
        gateway_id: options.gateway_id,
        boot_epoch,
        created_at,
        first_sequence: 1,
    };
    let header_bytes = encode_line(&header)?;

    manifest.epochs.push(EpochDescriptor {
        boot_epoch,
        created_at,
        file: file_name,
        first_sequence: ManifestSequence(1),
        compacted_last_sequence: ManifestSequence(0),
        phase: EpochPhase::Prepared,
    });

    write_new_file(&pending_path, &header_bytes).await?;
    if let Err(error) = write_manifest(&options.directory, &manifest).await {
        let _ = tokio::fs::remove_file(&pending_path).await;
        return Err(error);
    }
    tokio::fs::rename(&pending_path, &final_path)
        .await
        .map_err(|source| UsageSpoolError::io("publish epoch segment", &final_path, source))?;
    sync_directory(&options.directory).await?;

    let current_epoch = manifest
        .epochs
        .last_mut()
        .ok_or_else(|| UsageSpoolError::corrupt("new boot epoch disappeared from manifest"))?;
    current_epoch.phase = EpochPhase::Ready;
    write_manifest(&options.directory, &manifest).await?;
    let final_manifest_bytes = manifest_bytes(&manifest)? as u64;
    let total_bytes = segment_bytes
        .checked_add(header_bytes.len() as u64)
        .and_then(|bytes| bytes.checked_add(final_manifest_bytes))
        .ok_or_else(|| UsageSpoolError::corrupt("usage spool byte count overflow"))?;
    epoch_bytes.insert(boot_epoch, header_bytes.len() as u64);
    let current_file = secure_append_file(&final_path).await?;

    Ok(OpenedSpool {
        lock_file,
        current_file,
        current_path: final_path,
        current_offset: header_bytes.len() as u64,
        boot_epoch,
        next_sequence: 1,
        total_bytes,
        manifest,
        manifest_bytes: final_manifest_bytes,
        epoch_bytes,
        records,
        events,
    })
}

/// Non-mutating activation probe for `validate_activation`.
///
/// Inspects an existing spool directory and manifest without allocating a new
/// boot epoch (unlike [`open`]). Checks that match cold-start failure modes:
/// directory/manifest integrity, post-recovery epoch record scan, untracked
/// paths, retained capacity, and boot-epoch headroom. Recovery phases are
/// projected without renaming or deleting files.
///
/// When `probe_exclusive_lock` is true (cold-start / CLI validate / `Gateway::new`),
/// also ensures the directory can be created (same `create_dir_all` surface as
/// [`open`]), try-locks `.lock`, and releases it immediately so another live
/// Gateway cannot soft-open validate while `start` would fail with
/// [`UsageSpoolError::Locked`] or an unwritable spool parent.
/// Runtime re-validation after [`open`] must pass `probe_exclusive_lock = false`
/// because the calling process already holds the lock.
/// A missing directory is allowed on runtime re-validation — cold start creates it.
pub(super) fn probe_activation(
    options: &UsageSpoolOptions,
    probe_exclusive_lock: bool,
) -> Result<(), UsageSpoolError> {
    validate_options(options)?;
    let metadata = match std::fs::symlink_metadata(&options.directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if !probe_exclusive_lock {
                return Ok(());
            }
            // Cold-start: same create surface as open's prepare_directory, then
            // exclusive-lock contention / directory writability for boot epochs.
            prepare_directory_sync(&options.directory)?;
            let lock_file = acquire_lock_sync(&options.directory)?;
            drop(lock_file);
            probe_directory_writability_sync(&options.directory)?;
            return Ok(());
        }
        Err(source) => {
            return Err(UsageSpoolError::io(
                "inspect directory",
                &options.directory,
                source,
            ));
        }
    };
    validate_directory_metadata(&options.directory, &metadata)?;

    if probe_exclusive_lock {
        // Acquire and drop so validate fails closed on contention without
        // retaining the lock across Gateway::start's real open().
        let lock_file = acquire_lock_sync(&options.directory)?;
        drop(lock_file);
        // open always create_new's a boot-epoch segment (and may create
        // manifest.json). Lock open/create alone cannot soft-open a directory
        // that admits .lock but rejects new epoch files.
        probe_directory_writability_sync(&options.directory)?;
    }

    let manifest_path = options.directory.join("manifest.json");
    let manifest_meta = match std::fs::symlink_metadata(&manifest_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(UsageSpoolError::io("inspect file", &manifest_path, source));
        }
    };
    validate_regular_file(&manifest_path, &manifest_meta)?;
    if manifest_meta.len() > MAX_MANIFEST_BYTES as u64 {
        return Err(UsageSpoolError::corrupt(format!(
            "{} exceeds {} bytes",
            manifest_path.display(),
            MAX_MANIFEST_BYTES
        )));
    }
    let bytes = std::fs::read(&manifest_path)
        .map_err(|source| UsageSpoolError::io("read file", &manifest_path, source))?;
    let manifest: SpoolManifest = serde_json::from_slice(&bytes).map_err(|error| {
        UsageSpoolError::corrupt(format!(
            "manifest {} is invalid JSON: {error}",
            manifest_path.display()
        ))
    })?;
    validate_manifest(&manifest, options.gateway_id)?;

    // open recovers non-Ready phases, then scans. Project that post-recovery
    // file set without renaming or deleting, so a corrupt Prepared/Compacting
    // segment fails here the same way start fails, and a deleted Retiring
    // segment does not false-fail.
    let projected = project_recovered_spool(&options.directory, &manifest)?;
    let (records, _events, _total, epoch_bytes, last_sequences) = super::segments::scan_sync_at(
        &options.directory,
        &projected.manifest,
        options.gateway_id,
        &projected.paths,
    )?;

    // Same untracked-path gate as open after it deletes recovery artifacts.
    validate_directory_contents_sync(&options.directory, &manifest)?;

    // open reclaims empty / fully-acknowledged epochs and may compact a
    // partially acknowledged epoch before capacity and boot headroom. Project
    // that retirement / compacted size without mutating the spool.
    let capacity = project_reclaimed_capacity(
        &projected,
        &records,
        &epoch_bytes,
        &last_sequences,
        options.gateway_id,
    )?;
    if capacity.manifest_bytes as u64 > options.max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes: capacity.manifest_bytes as u64,
            requested_bytes: 0,
            capacity_bytes: options.max_bytes,
        });
    }
    let retained_bytes = (capacity.manifest_bytes as u64)
        .checked_add(capacity.segment_bytes)
        .ok_or_else(|| UsageSpoolError::corrupt("usage spool byte count overflow"))?;
    if retained_bytes > options.max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes,
            requested_bytes: 0,
            capacity_bytes: options.max_bytes,
        });
    }

    // Same boot-epoch headroom gate as open — retained-only fit is not enough;
    // cold start always allocates a new epoch header + larger manifest.
    project_boot_epoch_capacity(
        &capacity.manifest,
        capacity.manifest_bytes,
        retained_bytes,
        options.max_bytes,
        options.gateway_id,
    )?;

    Ok(())
}

struct ProjectedSpool {
    manifest: SpoolManifest,
    paths: HashMap<Uuid, PathBuf>,
}

struct ReclaimedCapacity {
    manifest: SpoolManifest,
    manifest_bytes: usize,
    segment_bytes: u64,
}

/// Non-mutating view of epochs [`reclaim_closed_epochs`] would drop or shrink
/// before the boot-epoch capacity check.
fn project_reclaimed_capacity(
    projected: &ProjectedSpool,
    records: &[StoredRecord],
    epoch_bytes: &HashMap<Uuid, u64>,
    last_sequences: &HashMap<Uuid, Option<u64>>,
    gateway_id: Uuid,
) -> Result<ReclaimedCapacity, UsageSpoolError> {
    let mut retiring = last_sequences
        .iter()
        .filter_map(|(boot_epoch, sequence)| sequence.is_none().then_some(*boot_epoch))
        .collect::<std::collections::HashSet<_>>();
    let mut first_retained = None;
    if let Some(cursor) = projected.manifest.acknowledged_through() {
        if let Some(acknowledged_epoch) = projected
            .manifest
            .epochs
            .iter()
            .position(|epoch| epoch.boot_epoch == cursor.boot_epoch)
        {
            retiring.extend(
                projected.manifest.epochs[..acknowledged_epoch]
                    .iter()
                    .map(|epoch| epoch.boot_epoch),
            );
            if last_sequences.get(&cursor.boot_epoch) == Some(&Some(cursor.sequence)) {
                retiring.insert(cursor.boot_epoch);
            } else if projected.manifest.epochs[acknowledged_epoch]
                .first_sequence
                .0
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

    let mut manifest = projected.manifest.clone();
    if let Some(record) = first_retained {
        let acknowledged = manifest.acknowledged_through().ok_or_else(|| {
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
        let last_sequence = match last_sequences.get(&record.cursor.boot_epoch) {
            Some(Some(sequence)) => *sequence,
            _ => {
                return Err(UsageSpoolError::corrupt(format!(
                    "compacted epoch {} is missing a scanned tail sequence",
                    record.cursor.boot_epoch
                )));
            }
        };
        let epoch = manifest
            .epochs
            .iter_mut()
            .find(|epoch| epoch.boot_epoch == record.cursor.boot_epoch)
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "compaction selected unknown epoch {}",
                    record.cursor.boot_epoch
                ))
            })?;
        epoch.first_sequence = ManifestSequence(record.cursor.sequence);
        epoch.compacted_last_sequence = ManifestSequence(last_sequence);
    }
    manifest
        .epochs
        .retain(|epoch| !retiring.contains(&epoch.boot_epoch));
    let compacted_epoch_bytes = if let Some(record) = first_retained {
        let source_bytes = epoch_bytes
            .get(&record.cursor.boot_epoch)
            .copied()
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "reclaimed capacity missing scanned bytes for epoch {}",
                    record.cursor.boot_epoch
                ))
            })?;
        if record.offset >= source_bytes {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} compaction boundary is outside the segment",
                record.cursor.boot_epoch
            )));
        }
        let epoch = manifest
            .epochs
            .iter()
            .find(|epoch| epoch.boot_epoch == record.cursor.boot_epoch)
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "compaction selected unknown epoch {}",
                    record.cursor.boot_epoch
                ))
            })?;
        let header = SegmentHeader {
            schema: SEGMENT_SCHEMA.to_string(),
            gateway_id,
            boot_epoch: epoch.boot_epoch,
            created_at: epoch.created_at,
            first_sequence: record.cursor.sequence,
        };
        let header_bytes = encode_line(&header)?;
        let projected = (header_bytes.len() as u64)
            .checked_add(source_bytes - record.offset)
            .ok_or_else(|| UsageSpoolError::corrupt("usage spool byte count overflow"))?;
        if projected >= source_bytes {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} compacted projection did not become smaller",
                record.cursor.boot_epoch
            )));
        }
        Some((record.cursor.boot_epoch, projected))
    } else {
        None
    };
    let mut segment_bytes = 0_u64;
    for epoch in &manifest.epochs {
        let bytes = compacted_epoch_bytes
            .and_then(|(boot_epoch, bytes)| (boot_epoch == epoch.boot_epoch).then_some(bytes))
            .or_else(|| epoch_bytes.get(&epoch.boot_epoch).copied())
            .ok_or_else(|| {
                UsageSpoolError::corrupt(format!(
                    "reclaimed capacity missing scanned bytes for epoch {}",
                    epoch.boot_epoch
                ))
            })?;
        segment_bytes = segment_bytes
            .checked_add(bytes)
            .ok_or_else(|| UsageSpoolError::corrupt("usage spool byte count overflow"))?;
    }
    Ok(ReclaimedCapacity {
        manifest_bytes: manifest_bytes(&manifest)?,
        manifest,
        segment_bytes,
    })
}

/// Non-mutating view of the spool [`recover_manifest_epochs`] would scan.
fn project_recovered_spool(
    directory: &Path,
    manifest: &SpoolManifest,
) -> Result<ProjectedSpool, UsageSpoolError> {
    let mut projected = manifest.clone();
    let mut paths = HashMap::new();
    let mut kept = Vec::new();
    for mut epoch in projected.epochs.drain(..) {
        let scan_path = match epoch.phase {
            EpochPhase::Retiring => {
                let path = directory.join(&epoch.file);
                match std::fs::symlink_metadata(&path) {
                    Ok(metadata) => validate_regular_file(&path, &metadata)?,
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(UsageSpoolError::io("inspect retiring epoch", &path, source));
                    }
                }
                continue;
            }
            EpochPhase::Prepared => match std::fs::symlink_metadata(directory.join(&epoch.file)) {
                Ok(metadata) => {
                    let path = directory.join(&epoch.file);
                    validate_regular_file(&path, &metadata)?;
                    path
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {
                    let pending = directory.join(format!(".{}.pending", epoch.file));
                    let metadata = std::fs::symlink_metadata(&pending).map_err(|source| {
                        UsageSpoolError::io("recover prepared epoch", &pending, source)
                    })?;
                    validate_regular_file(&pending, &metadata)?;
                    pending
                }
                Err(source) => {
                    let path = directory.join(&epoch.file);
                    return Err(UsageSpoolError::io("inspect prepared epoch", &path, source));
                }
            },
            EpochPhase::Compacting => {
                let compact = directory.join(format!(".{}.compact", epoch.file));
                match std::fs::symlink_metadata(&compact) {
                    Ok(metadata) => {
                        validate_regular_file(&compact, &metadata)?;
                        // publish removes the pre-compaction file only after it
                        // proves that file is a regular file. A directory here
                        // must fail validate the same way.
                        let final_path = directory.join(&epoch.file);
                        match std::fs::symlink_metadata(&final_path) {
                            Ok(final_metadata) => {
                                validate_regular_file(&final_path, &final_metadata)?;
                            }
                            Err(error) if error.kind() == ErrorKind::NotFound => {}
                            Err(source) => {
                                return Err(UsageSpoolError::io(
                                    "inspect pre-compaction epoch",
                                    &final_path,
                                    source,
                                ));
                            }
                        }
                        compact
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        let path = directory.join(&epoch.file);
                        let metadata = std::fs::symlink_metadata(&path).map_err(|source| {
                            UsageSpoolError::io("inspect pre-compaction epoch", &path, source)
                        })?;
                        validate_regular_file(&path, &metadata)?;
                        path
                    }
                    Err(source) => {
                        return Err(UsageSpoolError::io(
                            "inspect compacted epoch staging file",
                            &compact,
                            source,
                        ));
                    }
                }
            }
            EpochPhase::Ready => {
                let path = directory.join(&epoch.file);
                let metadata = std::fs::symlink_metadata(&path).map_err(|source| {
                    UsageSpoolError::io("inspect epoch segment", &path, source)
                })?;
                validate_regular_file(&path, &metadata)?;
                path
            }
        };
        // Prove the scan path is still a regular file (Prepared/Compacting
        // branches already validated; Ready did too — keep one gate for all).
        let metadata = std::fs::symlink_metadata(&scan_path)
            .map_err(|source| UsageSpoolError::io("inspect epoch segment", &scan_path, source))?;
        validate_regular_file(&scan_path, &metadata)?;
        epoch.phase = EpochPhase::Ready;
        paths.insert(epoch.boot_epoch, scan_path);
        kept.push(epoch);
    }
    projected.epochs = kept;
    Ok(ProjectedSpool {
        manifest: projected,
        paths,
    })
}

/// Non-mutating projection of the capacity check [`open`] performs before writing
/// a new boot epoch. Uses fixed sentinel UUID/timestamp so RFC3339 digit width
/// cannot soft-open validate while `open` Full-fails (or the reverse).
fn project_boot_epoch_capacity(
    manifest: &SpoolManifest,
    current_manifest_bytes: usize,
    retained_bytes: u64,
    max_bytes: u64,
    gateway_id: Uuid,
) -> Result<(), UsageSpoolError> {
    // Max-width RFC3339 with nanoseconds — live `Utc::now()` can serialize
    // shorter (no fractional seconds) and inflate headroom relative to open.
    let created_at = chrono::DateTime::parse_from_rfc3339("9999-12-31T23:59:59.999999999Z")
        .expect("fixed capacity-projection timestamp")
        .with_timezone(&chrono::Utc);
    let boot_epoch = Uuid::nil();
    let file_name = format!("epoch-{boot_epoch}.jsonl");
    let header = SegmentHeader {
        schema: SEGMENT_SCHEMA.to_string(),
        gateway_id,
        boot_epoch,
        created_at,
        first_sequence: 1,
    };
    let header_bytes = encode_line(&header)?;

    let mut projected = manifest.clone();
    projected.epochs.push(EpochDescriptor {
        boot_epoch,
        created_at,
        file: file_name,
        first_sequence: ManifestSequence(1),
        compacted_last_sequence: ManifestSequence(0),
        phase: EpochPhase::Prepared,
    });
    let prepared_manifest_bytes = manifest_bytes(&projected)?;
    projected
        .epochs
        .last_mut()
        .ok_or_else(|| UsageSpoolError::corrupt("projected boot epoch was not retained"))?
        .phase = EpochPhase::Ready;
    let ready_manifest_bytes = manifest_bytes(&projected)?;
    let projected_manifest_bytes = prepared_manifest_bytes.max(ready_manifest_bytes);

    let projected_bytes = retained_bytes
        .saturating_sub(current_manifest_bytes as u64)
        .saturating_add(projected_manifest_bytes as u64)
        .saturating_add(header_bytes.len() as u64);
    if projected_bytes > max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes,
            requested_bytes: projected_bytes.saturating_sub(retained_bytes),
            capacity_bytes: max_bytes,
        });
    }
    Ok(())
}

fn validate_directory_contents_sync(
    directory: &Path,
    manifest: &SpoolManifest,
) -> Result<(), UsageSpoolError> {
    let mut allowed = manifest
        .epochs
        .iter()
        .map(|epoch| epoch.file.as_str())
        .collect::<std::collections::HashSet<_>>();
    allowed.insert(".lock");
    allowed.insert("manifest.json");
    let entries = std::fs::read_dir(directory)
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?;
    for entry in entries {
        let entry =
            entry.map_err(|source| UsageSpoolError::io("list directory", directory, source))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if allowed.contains(name.as_ref()) {
            continue;
        }
        if is_spool_recovery_artifact(&name, manifest) {
            // open deletes these with remove_file before the untracked check.
            // A directory (or other non-file) makes that delete fail, so validate
            // must not treat the name alone as safe.
            let metadata = entry.metadata().map_err(|source| {
                UsageSpoolError::io("inspect recovery artifact", entry.path(), source)
            })?;
            if metadata.is_dir() {
                return Err(UsageSpoolError::io(
                    "remove recovery artifact",
                    entry.path(),
                    std::io::Error::new(
                        ErrorKind::IsADirectory,
                        "recovery artifact is a directory",
                    ),
                ));
            }
            continue;
        }
        return Err(UsageSpoolError::corrupt(format!(
            "directory contains untracked path {:?}",
            name
        )));
    }
    Ok(())
}

/// Names [`open`] removes before its untracked-path check: manifest staging,
/// unpublished epoch pending files, and known epoch pending/compact siblings.
fn is_spool_recovery_artifact(name: &str, manifest: &SpoolManifest) -> bool {
    if name.starts_with(".manifest-") && name.ends_with(".tmp") {
        return true;
    }
    if name.starts_with(".epoch-") && name.ends_with(".jsonl.pending") {
        return true;
    }
    manifest.epochs.iter().any(|epoch| {
        name == format!(".{}.pending", epoch.file) || name == format!(".{}.compact", epoch.file)
    })
}

fn validate_options(options: &UsageSpoolOptions) -> Result<(), UsageSpoolError> {
    if options.gateway_id.is_nil() {
        return Err(UsageSpoolError::InvalidOptions {
            reason: "gateway_id must not be the nil UUID".to_string(),
        });
    }
    if !options.directory.is_absolute() || options.directory.file_name().is_none() {
        return Err(UsageSpoolError::InvalidOptions {
            reason: "directory must be an absolute, non-root path".to_string(),
        });
    }
    if options.max_bytes == 0 {
        return Err(UsageSpoolError::InvalidOptions {
            reason: "max_bytes must be greater than zero".to_string(),
        });
    }
    Ok(())
}

async fn prepare_directory(directory: &Path) -> Result<(), UsageSpoolError> {
    let created = match tokio::fs::symlink_metadata(directory).await {
        Ok(metadata) => {
            validate_directory_metadata(directory, &metadata)?;
            false
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            tokio::fs::create_dir_all(directory)
                .await
                .map_err(|source| UsageSpoolError::io("create directory", directory, source))?;
            true
        }
        Err(source) => {
            return Err(UsageSpoolError::io("inspect directory", directory, source));
        }
    };
    if created {
        set_private_directory_permissions(directory).await?;
    }
    let metadata = tokio::fs::symlink_metadata(directory)
        .await
        .map_err(|source| UsageSpoolError::io("inspect directory", directory, source))?;
    validate_directory_metadata(directory, &metadata)
}

/// Sync create/inspect used by cold-start [`probe_activation`].
fn prepare_directory_sync(directory: &Path) -> Result<(), UsageSpoolError> {
    let created = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => {
            validate_directory_metadata(directory, &metadata)?;
            false
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            std::fs::create_dir_all(directory)
                .map_err(|source| UsageSpoolError::io("create directory", directory, source))?;
            true
        }
        Err(source) => {
            return Err(UsageSpoolError::io("inspect directory", directory, source));
        }
    };
    if created {
        set_private_directory_permissions_sync(directory)?;
    }
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|source| UsageSpoolError::io("inspect directory", directory, source))?;
    validate_directory_metadata(directory, &metadata)
}

fn validate_directory_metadata(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), UsageSpoolError> {
    if metadata.file_type().is_symlink() {
        return Err(UsageSpoolError::corrupt(format!(
            "directory {} must not be a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(UsageSpoolError::corrupt(format!(
            "{} is not a directory",
            path.display()
        )));
    }
    validate_private_permissions(path, metadata, true)
}

async fn acquire_lock(directory: &Path) -> Result<std::fs::File, UsageSpoolError> {
    let directory = directory.to_path_buf();
    tokio::task::spawn_blocking(move || acquire_lock_sync(&directory))
        .await
        .map_err(|error| UsageSpoolError::corrupt(format!("lock task failed: {error}")))?
}

fn acquire_lock_sync(directory: &Path) -> Result<std::fs::File, UsageSpoolError> {
    let path = directory.join(".lock");
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|source| UsageSpoolError::io("open lock file", &path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| UsageSpoolError::io("inspect lock file", &path, source))?;
    validate_regular_file(&path, &metadata)?;
    match file.try_lock_exclusive() {
        Ok(()) => Ok(file),
        Err(error) if is_lock_contended(&error) => Err(UsageSpoolError::Locked {
            directory: directory.to_path_buf(),
        }),
        Err(source) => Err(UsageSpoolError::io("lock directory", path, source)),
    }
}

/// Same create_new write surface as boot-epoch allocation in [`open`].
fn probe_directory_writability_sync(directory: &Path) -> Result<(), UsageSpoolError> {
    let probe = directory.join(format!(
        ".a3s-usage-spool-activation-probe.{}",
        Uuid::new_v4()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(&probe).and_then(|mut file| {
        file.write_all(b"ok")?;
        file.sync_all()
    }) {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(source) => {
            let _ = std::fs::remove_file(&probe);
            Err(UsageSpoolError::io(
                "write usage spool activation probe",
                &probe,
                source,
            ))
        }
    }
}

fn is_lock_contended(error: &std::io::Error) -> bool {
    let expected = fs2::lock_contended_error();
    match (error.raw_os_error(), expected.raw_os_error()) {
        (Some(actual), Some(expected)) => actual == expected,
        _ => error.kind() == expected.kind(),
    }
}

async fn load_or_create_manifest(
    directory: &Path,
    gateway_id: Uuid,
) -> Result<(SpoolManifest, usize), UsageSpoolError> {
    let path = directory.join("manifest.json");
    match read_bounded_file(&path, MAX_MANIFEST_BYTES).await {
        Ok(bytes) => {
            let manifest: SpoolManifest = serde_json::from_slice(&bytes).map_err(|error| {
                UsageSpoolError::corrupt(format!(
                    "manifest {} is invalid JSON: {error}",
                    path.display()
                ))
            })?;
            validate_manifest(&manifest, gateway_id)?;
            Ok((manifest, bytes.len()))
        }
        Err(UsageSpoolError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => {
            let manifest = SpoolManifest::new(gateway_id);
            let bytes = write_manifest(directory, &manifest).await?;
            Ok((manifest, bytes))
        }
        Err(error) => Err(error),
    }
}

fn validate_manifest(manifest: &SpoolManifest, gateway_id: Uuid) -> Result<(), UsageSpoolError> {
    if manifest.schema != MANIFEST_SCHEMA
        && manifest.schema != MANIFEST_SCHEMA_V2
        && manifest.schema != MANIFEST_SCHEMA_V1
    {
        return Err(UsageSpoolError::corrupt(format!(
            "unsupported manifest schema {:?}",
            manifest.schema
        )));
    }
    if manifest.gateway_id != gateway_id {
        return Err(UsageSpoolError::GatewayIdentityMismatch {
            expected_gateway_id: gateway_id,
            actual_gateway_id: manifest.gateway_id,
        });
    }
    let unacknowledged = super::unacknowledged_cursor();
    let cursor = manifest.acknowledged_through.0;
    if cursor != unacknowledged
        && (cursor.boot_epoch.is_nil() || cursor.sequence == 0 || cursor.sequence == u64::MAX)
    {
        return Err(UsageSpoolError::corrupt(
            "manifest contains an invalid acknowledgement cursor",
        ));
    }
    if manifest.schema == MANIFEST_SCHEMA_V1 && cursor != unacknowledged {
        return Err(UsageSpoolError::corrupt(
            "legacy manifest contains an acknowledgement cursor",
        ));
    }
    let acknowledged_epoch = (cursor != unacknowledged)
        .then(|| {
            manifest
                .epochs
                .iter()
                .position(|epoch| epoch.boot_epoch == cursor.boot_epoch)
        })
        .flatten();
    let mut epochs = std::collections::HashSet::new();
    let mut files = std::collections::HashSet::new();
    for (epoch_position, epoch) in manifest.epochs.iter().enumerate() {
        if epoch.boot_epoch.is_nil() || !epochs.insert(epoch.boot_epoch) {
            return Err(UsageSpoolError::corrupt(
                "manifest contains a nil or duplicate boot epoch",
            ));
        }
        let expected = format!("epoch-{}.jsonl", epoch.boot_epoch);
        if epoch.file != expected || !files.insert(epoch.file.as_str()) {
            return Err(UsageSpoolError::corrupt(format!(
                "manifest contains unsafe or duplicate epoch file {:?}",
                epoch.file
            )));
        }
        if epoch.first_sequence.0 == 0 || epoch.first_sequence.0 == u64::MAX {
            return Err(UsageSpoolError::corrupt(
                "manifest contains an invalid epoch first sequence",
            ));
        }
        if (epoch.first_sequence.0 == 1 && epoch.compacted_last_sequence.0 != 0)
            || (epoch.first_sequence.0 > 1
                && (epoch.compacted_last_sequence.0 < epoch.first_sequence.0
                    || epoch.compacted_last_sequence.0 == u64::MAX))
        {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} contains invalid compacted sequence bounds",
                epoch.boot_epoch
            )));
        }
        if epoch.first_sequence.0 > 1 {
            let acknowledgement_matches = if epoch.phase == EpochPhase::Retiring {
                acknowledged_epoch.is_some_and(|acknowledged_position| {
                    epoch_position < acknowledged_position
                        || (epoch_position == acknowledged_position
                            && cursor.sequence == epoch.compacted_last_sequence.0)
                })
            } else {
                cursor.boot_epoch == epoch.boot_epoch
                    && cursor.sequence.checked_add(1) == Some(epoch.first_sequence.0)
            };
            if !acknowledgement_matches {
                return Err(UsageSpoolError::corrupt(format!(
                    "epoch {} compacted prefix does not match the acknowledgement cursor",
                    epoch.boot_epoch
                )));
            }
        } else if epoch.phase == EpochPhase::Compacting {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} is compacting without compacted sequence bounds",
                epoch.boot_epoch
            )));
        }
        match manifest.schema.as_str() {
            MANIFEST_SCHEMA_V1
                if epoch.phase == EpochPhase::Retiring || epoch.phase == EpochPhase::Compacting =>
            {
                return Err(UsageSpoolError::corrupt(
                    "v1 manifest contains an unsupported epoch phase",
                ));
            }
            MANIFEST_SCHEMA_V2 if epoch.phase == EpochPhase::Compacting => {
                return Err(UsageSpoolError::corrupt(
                    "v2 manifest contains a compacting epoch",
                ));
            }
            MANIFEST_SCHEMA_V1 | MANIFEST_SCHEMA_V2
                if epoch.first_sequence.0 != 1 || epoch.compacted_last_sequence.0 != 0 =>
            {
                return Err(UsageSpoolError::corrupt(
                    "legacy manifest contains compacted epoch metadata",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

async fn recover_manifest_epochs(
    directory: &Path,
    manifest: &mut SpoolManifest,
) -> Result<(), UsageSpoolError> {
    let mut changed = false;
    let mut directory_changed = false;
    let mut retired = std::collections::HashSet::new();
    let gateway_id = manifest.gateway_id;
    for epoch in &mut manifest.epochs {
        let final_path = directory.join(&epoch.file);
        let pending_path = directory.join(format!(".{}.pending", epoch.file));
        match epoch.phase {
            EpochPhase::Prepared => {
                match tokio::fs::symlink_metadata(&final_path).await {
                    Ok(metadata) => validate_regular_file(&final_path, &metadata)?,
                    Err(error) if error.kind() == ErrorKind::NotFound => {
                        let pending_metadata = tokio::fs::symlink_metadata(&pending_path)
                            .await
                            .map_err(|source| {
                                UsageSpoolError::io("recover prepared epoch", &pending_path, source)
                            })?;
                        validate_regular_file(&pending_path, &pending_metadata)?;
                        tokio::fs::rename(&pending_path, &final_path)
                            .await
                            .map_err(|source| {
                                UsageSpoolError::io("publish prepared epoch", &final_path, source)
                            })?;
                        directory_changed = true;
                    }
                    Err(source) => {
                        return Err(UsageSpoolError::io(
                            "inspect prepared epoch",
                            &final_path,
                            source,
                        ));
                    }
                }
                epoch.phase = EpochPhase::Ready;
                changed = true;
            }
            EpochPhase::Ready => {}
            EpochPhase::Retiring => {
                match tokio::fs::symlink_metadata(&final_path).await {
                    Ok(metadata) => {
                        validate_regular_file(&final_path, &metadata)?;
                        tokio::fs::remove_file(&final_path)
                            .await
                            .map_err(|source| {
                                UsageSpoolError::io("recover retiring epoch", &final_path, source)
                            })?;
                        directory_changed = true;
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(source) => {
                        return Err(UsageSpoolError::io(
                            "inspect retiring epoch",
                            &final_path,
                            source,
                        ));
                    }
                }
                retired.insert(epoch.boot_epoch);
                changed = true;
            }
            EpochPhase::Compacting => {
                super::compaction::publish(directory, gateway_id, epoch).await?;
                epoch.phase = EpochPhase::Ready;
                changed = true;
            }
        }
        if tokio::fs::try_exists(&pending_path)
            .await
            .map_err(|source| UsageSpoolError::io("inspect pending epoch", &pending_path, source))?
        {
            tokio::fs::remove_file(&pending_path)
                .await
                .map_err(|source| {
                    UsageSpoolError::io("remove recovered pending epoch", &pending_path, source)
                })?;
            directory_changed = true;
        }
        super::compaction::remove_stale(directory, &epoch.file).await?;
    }
    if directory_changed {
        sync_directory(directory).await?;
    }
    manifest
        .epochs
        .retain(|epoch| !retired.contains(&epoch.boot_epoch));
    remove_unpublished_pending_epochs(directory, manifest).await?;
    if changed {
        write_manifest(directory, manifest).await?;
    }
    Ok(())
}

async fn remove_unpublished_pending_epochs(
    directory: &Path,
    manifest: &SpoolManifest,
) -> Result<(), UsageSpoolError> {
    let known = manifest
        .epochs
        .iter()
        .map(|epoch| format!(".{}.pending", epoch.file))
        .collect::<std::collections::HashSet<_>>();
    let mut entries = tokio::fs::read_dir(directory)
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".epoch-") && name.ends_with(".jsonl.pending") && !known.contains(&name)
        {
            tokio::fs::remove_file(entry.path())
                .await
                .map_err(|source| {
                    UsageSpoolError::io("remove unpublished epoch", entry.path(), source)
                })?;
        }
    }
    Ok(())
}

async fn validate_directory_contents(
    directory: &Path,
    manifest: &SpoolManifest,
) -> Result<(), UsageSpoolError> {
    let mut allowed = manifest
        .epochs
        .iter()
        .map(|epoch| epoch.file.as_str())
        .collect::<std::collections::HashSet<_>>();
    allowed.insert(".lock");
    allowed.insert("manifest.json");
    let mut entries = tokio::fs::read_dir(directory)
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?
    {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !allowed.contains(name.as_ref()) {
            return Err(UsageSpoolError::corrupt(format!(
                "directory contains untracked path {:?}",
                name
            )));
        }
    }
    Ok(())
}

async fn cleanup_manifest_temps(directory: &Path) -> Result<(), UsageSpoolError> {
    let mut entries = tokio::fs::read_dir(directory)
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?;
    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|source| UsageSpoolError::io("list directory", directory, source))?
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with(".manifest-") && name.ends_with(".tmp") {
            tokio::fs::remove_file(entry.path())
                .await
                .map_err(|source| {
                    UsageSpoolError::io("remove stale manifest staging file", entry.path(), source)
                })?;
        }
    }
    Ok(())
}

pub(super) fn manifest_bytes(manifest: &SpoolManifest) -> Result<usize, UsageSpoolError> {
    let mut bytes = serde_json::to_vec(manifest)
        .map_err(|error| UsageSpoolError::corrupt(format!("encode manifest: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UsageSpoolError::Full {
            retained_bytes: bytes.len() as u64,
            requested_bytes: 0,
            capacity_bytes: MAX_MANIFEST_BYTES as u64,
        });
    }
    Ok(bytes.len())
}

pub(super) async fn write_manifest(
    directory: &Path,
    manifest: &SpoolManifest,
) -> Result<usize, UsageSpoolError> {
    let path = directory.join("manifest.json");
    let temporary_path = directory.join(format!(".manifest-{}.tmp", Uuid::new_v4()));
    let mut bytes = serde_json::to_vec(manifest)
        .map_err(|error| UsageSpoolError::corrupt(format!("encode manifest: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(UsageSpoolError::Full {
            retained_bytes: bytes.len() as u64,
            requested_bytes: 0,
            capacity_bytes: MAX_MANIFEST_BYTES as u64,
        });
    }
    write_new_file(&temporary_path, &bytes).await?;
    if let Err(source) = tokio::fs::rename(&temporary_path, &path).await {
        let _ = tokio::fs::remove_file(&temporary_path).await;
        return Err(UsageSpoolError::io("publish manifest", path, source));
    }
    sync_directory(directory).await?;
    Ok(bytes.len())
}

async fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), UsageSpoolError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .await
        .map_err(|source| UsageSpoolError::io("create file", path, source))?;
    file.write_all(bytes)
        .await
        .map_err(|source| UsageSpoolError::io("write file", path, source))?;
    file.sync_all()
        .await
        .map_err(|source| UsageSpoolError::io("sync file", path, source))
}

async fn secure_append_file(path: &Path) -> Result<tokio::fs::File, UsageSpoolError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|source| UsageSpoolError::io("inspect epoch segment", path, source))?;
    validate_regular_file(path, &metadata)?;
    tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|source| UsageSpoolError::io("open epoch segment for append", path, source))
}

async fn read_bounded_file(path: &Path, limit: usize) -> Result<Vec<u8>, UsageSpoolError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|source| UsageSpoolError::io("inspect file", path, source))?;
    validate_regular_file(path, &metadata)?;
    if metadata.len() > limit as u64 {
        return Err(UsageSpoolError::corrupt(format!(
            "{} exceeds {} bytes",
            path.display(),
            limit
        )));
    }
    tokio::fs::read(path)
        .await
        .map_err(|source| UsageSpoolError::io("read file", path, source))
}

pub(super) fn validate_regular_file(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), UsageSpoolError> {
    if metadata.file_type().is_symlink() {
        return Err(UsageSpoolError::corrupt(format!(
            "{} must not be a symbolic link",
            path.display()
        )));
    }
    if !metadata.is_file() {
        return Err(UsageSpoolError::corrupt(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    validate_private_permissions(path, metadata, false)
}

#[cfg(unix)]
fn validate_private_permissions(
    path: &Path,
    metadata: &std::fs::Metadata,
    _directory: bool,
) -> Result<(), UsageSpoolError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(UsageSpoolError::corrupt(format!(
            "{} must not be accessible by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_permissions(
    _path: &Path,
    _metadata: &std::fs::Metadata,
    _directory: bool,
) -> Result<(), UsageSpoolError> {
    Ok(())
}

#[cfg(unix)]
async fn set_private_directory_permissions(path: &Path) -> Result<(), UsageSpoolError> {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .await
        .map_err(|source| UsageSpoolError::io("secure directory", path, source))
}

#[cfg(not(unix))]
async fn set_private_directory_permissions(_path: &Path) -> Result<(), UsageSpoolError> {
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions_sync(path: &Path) -> Result<(), UsageSpoolError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|source| UsageSpoolError::io("secure directory", path, source))
}

#[cfg(not(unix))]
fn set_private_directory_permissions_sync(_path: &Path) -> Result<(), UsageSpoolError> {
    Ok(())
}

#[cfg(unix)]
pub(super) async fn sync_directory(path: &Path) -> Result<(), UsageSpoolError> {
    tokio::fs::File::open(path)
        .await
        .map_err(|source| UsageSpoolError::io("open directory for sync", path, source))?
        .sync_all()
        .await
        .map_err(|source| UsageSpoolError::io("sync directory", path, source))
}

#[cfg(not(unix))]
pub(super) async fn sync_directory(_path: &Path) -> Result<(), UsageSpoolError> {
    Ok(())
}

pub(super) fn encode_line<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, UsageSpoolError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| UsageSpoolError::corrupt(format!("encode spool record: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub(super) fn decode_line<T: serde::de::DeserializeOwned>(
    line: &[u8],
    description: &str,
) -> Result<T, UsageSpoolError> {
    if line.last() != Some(&b'\n') {
        return Err(UsageSpoolError::corrupt(format!(
            "{description} is not newline terminated"
        )));
    }
    serde_json::from_slice(&line[..line.len() - 1]).map_err(|error| {
        UsageSpoolError::corrupt(format!("{description} is invalid JSON: {error}"))
    })
}
