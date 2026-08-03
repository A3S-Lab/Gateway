use super::{
    EpochDescriptor, EpochPhase, ManifestSequence, SegmentHeader, SpoolManifest, UsageCursor,
    UsageSpoolError, UsageSpoolOptions, MANIFEST_SCHEMA, MANIFEST_SCHEMA_V1, MANIFEST_SCHEMA_V2,
    MAX_MANIFEST_BYTES, SEGMENT_SCHEMA,
};
use fs2::FileExt;
use std::collections::HashMap;
use std::io::ErrorKind;
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
    let prepared_manifest_bytes = manifest_bytes(&manifest)?;
    manifest
        .epochs
        .last_mut()
        .ok_or_else(|| UsageSpoolError::corrupt("new boot epoch was not retained in manifest"))?
        .phase = EpochPhase::Ready;
    let ready_manifest_bytes = manifest_bytes(&manifest)?;
    manifest
        .epochs
        .last_mut()
        .ok_or_else(|| UsageSpoolError::corrupt("new boot epoch was not retained in manifest"))?
        .phase = EpochPhase::Prepared;
    let projected_manifest_bytes = prepared_manifest_bytes.max(ready_manifest_bytes);

    let projected_bytes = retained_bytes
        .saturating_sub(current_manifest_bytes as u64)
        .saturating_add(projected_manifest_bytes as u64)
        .saturating_add(header_bytes.len() as u64);
    if projected_bytes > options.max_bytes {
        return Err(UsageSpoolError::Full {
            retained_bytes,
            requested_bytes: projected_bytes.saturating_sub(retained_bytes),
            capacity_bytes: options.max_bytes,
        });
    }

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
    let final_manifest_bytes = ready_manifest_bytes as u64;
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
    let path = directory.join(".lock");
    let open_path = path.clone();
    let file = tokio::task::spawn_blocking(move || {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&open_path)
    })
    .await
    .map_err(|error| UsageSpoolError::corrupt(format!("lock task failed: {error}")))?
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
