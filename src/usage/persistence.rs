use super::{
    EpochDescriptor, EpochPhase, SegmentHeader, SpoolManifest, UsageCursor, UsageSpoolError,
    UsageSpoolOptions, LEGACY_MANIFEST_SCHEMA, MANIFEST_SCHEMA, MAX_MANIFEST_BYTES,
    MAX_RECORD_LINE_BYTES, SEGMENT_SCHEMA,
};
use fs2::FileExt;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
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
    if manifest.schema == LEGACY_MANIFEST_SCHEMA {
        manifest.schema = MANIFEST_SCHEMA.to_string();
    }
    recover_manifest_epochs(&options.directory, &mut manifest).await?;
    validate_manifest(&manifest, options.gateway_id)?;

    let mut scanned = scan_segments(&options.directory, &manifest, options.gateway_id).await?;
    if super::acknowledgement::reclaim_closed_epochs(&options.directory, &mut manifest, &scanned.4)
        .await?
    {
        scanned = scan_segments(&options.directory, &manifest, options.gateway_id).await?;
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
    };
    let header_bytes = encode_line(&header)?;

    manifest.epochs.push(EpochDescriptor {
        boot_epoch,
        created_at,
        file: file_name,
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
    if manifest.schema != MANIFEST_SCHEMA && manifest.schema != LEGACY_MANIFEST_SCHEMA {
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
    if manifest.schema == LEGACY_MANIFEST_SCHEMA && cursor != unacknowledged {
        return Err(UsageSpoolError::corrupt(
            "legacy manifest contains an acknowledgement cursor",
        ));
    }
    let mut epochs = std::collections::HashSet::new();
    let mut files = std::collections::HashSet::new();
    for epoch in &manifest.epochs {
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
        if manifest.schema == LEGACY_MANIFEST_SCHEMA && epoch.phase == EpochPhase::Retiring {
            return Err(UsageSpoolError::corrupt(
                "legacy manifest contains a retiring epoch",
            ));
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

async fn scan_segments(
    directory: &Path,
    manifest: &SpoolManifest,
    gateway_id: Uuid,
) -> Result<
    (
        Vec<StoredRecord>,
        HashMap<Uuid, IndexedEvent>,
        u64,
        HashMap<Uuid, u64>,
        HashMap<Uuid, u64>,
    ),
    UsageSpoolError,
> {
    let mut records = Vec::new();
    let mut events = HashMap::new();
    let mut total_bytes = 0_u64;
    let mut epoch_bytes = HashMap::new();
    let mut last_sequences = HashMap::new();
    let acknowledged = manifest.acknowledged_through();
    let acknowledged_epoch = acknowledged.and_then(|cursor| {
        manifest
            .epochs
            .iter()
            .position(|epoch| epoch.boot_epoch == cursor.boot_epoch)
    });
    let mut acknowledgement_found = acknowledged_epoch.is_none();

    for (epoch_index, epoch) in manifest.epochs.iter().enumerate() {
        if epoch.phase != EpochPhase::Ready {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} remained {:?} after recovery",
                epoch.boot_epoch, epoch.phase
            )));
        }
        let path = directory.join(&epoch.file);
        let metadata = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|source| UsageSpoolError::io("inspect epoch segment", &path, source))?;
        validate_regular_file(&path, &metadata)?;
        total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| UsageSpoolError::corrupt("segment byte count overflow"))?;
        epoch_bytes.insert(epoch.boot_epoch, metadata.len());
        let file = tokio::fs::File::open(&path)
            .await
            .map_err(|source| UsageSpoolError::io("open epoch segment", &path, source))?;
        let mut reader = BufReader::new(file);
        let mut offset = 0_u64;
        let mut line = Vec::new();
        let read = reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|source| UsageSpoolError::io("read epoch header", &path, source))?;
        if read == 0 || line.last() != Some(&b'\n') {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} has an incomplete header",
                epoch.boot_epoch
            )));
        }
        let header: SegmentHeader = decode_line(&line, "epoch header")?;
        validate_header(&header, epoch, gateway_id)?;
        offset += read as u64;

        let mut expected_sequence = 1_u64;
        loop {
            line.clear();
            let read = reader
                .read_until(b'\n', &mut line)
                .await
                .map_err(|source| UsageSpoolError::io("read epoch record", &path, source))?;
            if read == 0 {
                break;
            }
            if line.last() != Some(&b'\n') || line.len() > MAX_RECORD_LINE_BYTES {
                return Err(UsageSpoolError::corrupt(format!(
                    "epoch {} contains an incomplete or oversized record at byte {}",
                    epoch.boot_epoch, offset
                )));
            }
            let cursor = UsageCursor {
                boot_epoch: epoch.boot_epoch,
                sequence: expected_sequence,
            };
            let (record, _payload, digest) = super::record::decode(&line, gateway_id, cursor)?;
            if record.event_id.is_nil() {
                return Err(UsageSpoolError::corrupt(format!(
                    "epoch {} sequence {} has a nil event ID",
                    epoch.boot_epoch, expected_sequence
                )));
            }
            if events
                .insert(
                    record.event_id,
                    IndexedEvent {
                        cursor,
                        payload_sha256: digest,
                    },
                )
                .is_some()
            {
                return Err(UsageSpoolError::corrupt(format!(
                    "event {} appears more than once",
                    record.event_id
                )));
            }
            let retained = match (acknowledged, acknowledged_epoch) {
                (Some(_), Some(acknowledged_epoch)) if epoch_index < acknowledged_epoch => false,
                (Some(acknowledged), Some(acknowledged_epoch))
                    if epoch_index == acknowledged_epoch =>
                {
                    if cursor == acknowledged {
                        acknowledgement_found = true;
                    }
                    cursor.sequence > acknowledged.sequence
                }
                _ => true,
            };
            if retained {
                records.push(StoredRecord::new(
                    cursor,
                    record.event_id,
                    digest,
                    &path,
                    offset,
                    read,
                ));
            }
            offset += read as u64;
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| UsageSpoolError::corrupt("usage sequence overflow"))?;
        }
        if offset != metadata.len() {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} byte count does not match its file",
                epoch.boot_epoch
            )));
        }
        last_sequences.insert(epoch.boot_epoch, expected_sequence - 1);
    }
    if !acknowledgement_found {
        let cursor = acknowledged.ok_or_else(|| {
            UsageSpoolError::corrupt("acknowledgement scan lost its manifest cursor")
        })?;
        return Err(UsageSpoolError::corrupt(format!(
            "acknowledgement cursor {}/{} is not present in its epoch",
            cursor.boot_epoch, cursor.sequence
        )));
    }
    Ok((records, events, total_bytes, epoch_bytes, last_sequences))
}

fn validate_header(
    header: &SegmentHeader,
    epoch: &EpochDescriptor,
    gateway_id: Uuid,
) -> Result<(), UsageSpoolError> {
    if header.schema != SEGMENT_SCHEMA
        || header.gateway_id != gateway_id
        || header.boot_epoch != epoch.boot_epoch
        || header.created_at != epoch.created_at
    {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} header does not match its manifest descriptor",
            epoch.boot_epoch
        )));
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

fn encode_line<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, UsageSpoolError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| UsageSpoolError::corrupt(format!("encode spool record: {error}")))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn decode_line<T: serde::de::DeserializeOwned>(
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
