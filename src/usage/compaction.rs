//! Byte-preserving compaction for closed usage epochs.
//!
//! Record lines are copied exactly. Only the segment header changes to record
//! the first retained sequence. The manifest makes the Windows-compatible
//! remove-then-rename publication sequence recoverable at every crash point.

use super::persistence::{self, StoredRecord};
use super::{
    EpochDescriptor, ManifestSequence, SegmentHeader, UsageCursor, UsageSpoolError,
    MAX_RECORD_LINE_BYTES, SEGMENT_SCHEMA,
};
use std::collections::HashSet;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, SeekFrom};
use uuid::Uuid;

#[derive(Debug)]
pub(super) struct PreparedCompaction {
    pub(super) boot_epoch: Uuid,
    pub(super) first_sequence: u64,
    pub(super) last_sequence: u64,
    pending_path: PathBuf,
}

pub(super) async fn prepare(
    directory: &Path,
    gateway_id: Uuid,
    epoch: &EpochDescriptor,
    first_retained: &StoredRecord,
) -> Result<PreparedCompaction, UsageSpoolError> {
    if first_retained.cursor.boot_epoch != epoch.boot_epoch
        || first_retained.cursor.sequence <= epoch.first_sequence.0
    {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} received an invalid compaction boundary",
            epoch.boot_epoch
        )));
    }
    let source_path = directory.join(&epoch.file);
    if first_retained.path != source_path {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} compaction record belongs to a different segment",
            epoch.boot_epoch
        )));
    }
    let metadata = tokio::fs::symlink_metadata(&source_path)
        .await
        .map_err(|source| UsageSpoolError::io("inspect compacted epoch", &source_path, source))?;
    persistence::validate_regular_file(&source_path, &metadata)?;
    if first_retained.offset >= metadata.len() {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} compaction boundary is outside the segment",
            epoch.boot_epoch
        )));
    }

    let pending_path = pending_path(directory, &epoch.file);
    let header = SegmentHeader {
        schema: SEGMENT_SCHEMA.to_string(),
        gateway_id,
        boot_epoch: epoch.boot_epoch,
        created_at: epoch.created_at,
        first_sequence: first_retained.cursor.sequence,
    };
    let header = persistence::encode_line(&header)?;
    let mut output = create_private_file(&pending_path).await?;
    if let Err(error) = async {
        output.write_all(&header).await?;
        let mut source = tokio::fs::File::open(&source_path).await?;
        source.seek(SeekFrom::Start(first_retained.offset)).await?;
        let remaining = metadata.len() - first_retained.offset;
        let copied = tokio::io::copy(&mut source.take(remaining), &mut output).await?;
        if copied != remaining {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "compacted epoch copy was incomplete",
            ));
        }
        output.sync_all().await?;
        if output.metadata().await?.len() >= metadata.len() {
            return Err(std::io::Error::new(
                ErrorKind::InvalidData,
                "compacted epoch did not become smaller",
            ));
        }
        Ok(())
    }
    .await
    {
        let _ = tokio::fs::remove_file(&pending_path).await;
        return Err(UsageSpoolError::io(
            "prepare compacted epoch",
            pending_path,
            error,
        ));
    }
    drop(output);
    let mut compacted_epoch = epoch.clone();
    compacted_epoch.first_sequence = ManifestSequence(first_retained.cursor.sequence);
    compacted_epoch.compacted_last_sequence = ManifestSequence(0);
    let last_sequence =
        match validate_compacted_contents(&pending_path, &compacted_epoch, gateway_id).await {
            Ok(last_sequence) => last_sequence,
            Err(error) => {
                let _ = tokio::fs::remove_file(&pending_path).await;
                return Err(error);
            }
        };
    if let Err(error) = persistence::sync_directory(directory).await {
        let _ = tokio::fs::remove_file(&pending_path).await;
        return Err(error);
    }

    Ok(PreparedCompaction {
        boot_epoch: epoch.boot_epoch,
        first_sequence: first_retained.cursor.sequence,
        last_sequence,
        pending_path,
    })
}

pub(super) async fn publish(
    directory: &Path,
    gateway_id: Uuid,
    epoch: &EpochDescriptor,
) -> Result<(), UsageSpoolError> {
    let final_path = directory.join(&epoch.file);
    let pending_path = pending_path(directory, &epoch.file);
    match tokio::fs::symlink_metadata(&pending_path).await {
        Ok(metadata) => {
            persistence::validate_regular_file(&pending_path, &metadata)?;
            validate_compacted_contents(&pending_path, epoch, gateway_id).await?;
            match tokio::fs::symlink_metadata(&final_path).await {
                Ok(metadata) => {
                    persistence::validate_regular_file(&final_path, &metadata)?;
                    tokio::fs::remove_file(&final_path)
                        .await
                        .map_err(|source| {
                            UsageSpoolError::io("remove pre-compaction epoch", &final_path, source)
                        })?;
                    persistence::sync_directory(directory).await?;
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(UsageSpoolError::io(
                        "inspect pre-compaction epoch",
                        final_path,
                        source,
                    ));
                }
            }
            tokio::fs::rename(&pending_path, &final_path)
                .await
                .map_err(|source| {
                    UsageSpoolError::io("publish compacted epoch", &final_path, source)
                })?;
            persistence::sync_directory(directory).await
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {
            validate_compacted_contents(&final_path, epoch, gateway_id)
                .await
                .map(|_| ())
        }
        Err(source) => Err(UsageSpoolError::io(
            "inspect compacted epoch staging file",
            pending_path,
            source,
        )),
    }
}

async fn validate_compacted_contents(
    path: &Path,
    epoch: &EpochDescriptor,
    gateway_id: Uuid,
) -> Result<u64, UsageSpoolError> {
    super::segments::validate_header_file(path, epoch, gateway_id).await?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|source| UsageSpoolError::io("open compacted epoch", path, source))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let header_bytes = reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|source| UsageSpoolError::io("read compacted epoch header", path, source))?;
    if header_bytes == 0 || line.last() != Some(&b'\n') || line.len() > MAX_RECORD_LINE_BYTES {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} has an incomplete or oversized compacted header",
            epoch.boot_epoch
        )));
    }

    let mut expected_sequence = epoch.first_sequence.0;
    let mut event_ids = HashSet::new();
    let mut saw_record = false;
    loop {
        line.clear();
        let read = reader
            .read_until(b'\n', &mut line)
            .await
            .map_err(|source| UsageSpoolError::io("read compacted epoch record", path, source))?;
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') || line.len() > MAX_RECORD_LINE_BYTES {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} contains an incomplete or oversized compacted record",
                epoch.boot_epoch
            )));
        }
        let cursor = UsageCursor {
            boot_epoch: epoch.boot_epoch,
            sequence: expected_sequence,
        };
        let (record, _, _) = super::record::decode(&line, gateway_id, cursor)?;
        if record.event_id.is_nil() || !event_ids.insert(record.event_id) {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} compacted records contain a nil or duplicate event ID",
                epoch.boot_epoch
            )));
        }
        saw_record = true;
        expected_sequence = expected_sequence
            .checked_add(1)
            .ok_or_else(|| UsageSpoolError::corrupt("usage sequence overflow"))?;
    }
    if !saw_record {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} compacted segment contains no retained records",
            epoch.boot_epoch
        )));
    }
    let last_sequence = expected_sequence - 1;
    if epoch.compacted_last_sequence.0 != 0 && epoch.compacted_last_sequence.0 != last_sequence {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} compacted tail sequence does not match its manifest descriptor",
            epoch.boot_epoch
        )));
    }
    Ok(last_sequence)
}

pub(super) async fn abort(prepared: &PreparedCompaction) {
    let _ = tokio::fs::remove_file(&prepared.pending_path).await;
}

pub(super) async fn remove_stale(directory: &Path, file: &str) -> Result<(), UsageSpoolError> {
    let path = pending_path(directory, file);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(UsageSpoolError::io(
            "remove stale epoch compaction",
            path,
            source,
        )),
    }
}

fn pending_path(directory: &Path, file: &str) -> PathBuf {
    directory.join(format!(".{file}.compact"))
}

async fn create_private_file(path: &Path) -> Result<tokio::fs::File, UsageSpoolError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
    options
        .open(path)
        .await
        .map_err(|source| UsageSpoolError::io("create compacted epoch", path, source))
}
