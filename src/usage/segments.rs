//! Epoch segment validation and in-memory index reconstruction.

use super::persistence::{self, IndexedEvent, StoredRecord};
use super::{
    EpochDescriptor, EpochPhase, SegmentHeader, SpoolManifest, UsageCursor, UsageSpoolError,
    LEGACY_SEGMENT_SCHEMA, MAX_RECORD_LINE_BYTES, SEGMENT_SCHEMA,
};
use std::collections::HashMap;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, BufReader};
use uuid::Uuid;

pub(super) async fn scan(
    directory: &Path,
    manifest: &SpoolManifest,
    gateway_id: Uuid,
) -> Result<
    (
        Vec<StoredRecord>,
        HashMap<Uuid, IndexedEvent>,
        u64,
        HashMap<Uuid, u64>,
        HashMap<Uuid, Option<u64>>,
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
        persistence::validate_regular_file(&path, &metadata)?;
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
        if read == 0 || line.last() != Some(&b'\n') || line.len() > MAX_RECORD_LINE_BYTES {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} has an incomplete or oversized header",
                epoch.boot_epoch
            )));
        }
        let header: SegmentHeader = persistence::decode_line(&line, "epoch header")?;
        validate_header(&header, epoch, gateway_id)?;
        offset += read as u64;

        if acknowledged_epoch == Some(epoch_index)
            && acknowledged.and_then(|cursor| cursor.sequence.checked_add(1))
                == Some(epoch.first_sequence.0)
        {
            acknowledgement_found = true;
        }

        let mut expected_sequence = epoch.first_sequence.0;
        let mut saw_record = false;
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
            saw_record = true;
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
        last_sequences.insert(
            epoch.boot_epoch,
            saw_record.then_some(expected_sequence - 1),
        );
        if epoch.compacted_last_sequence.0 != 0
            && last_sequences.get(&epoch.boot_epoch) != Some(&Some(epoch.compacted_last_sequence.0))
        {
            return Err(UsageSpoolError::corrupt(format!(
                "epoch {} compacted tail does not match its manifest descriptor",
                epoch.boot_epoch
            )));
        }
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
    let schema_matches = match header.schema.as_str() {
        SEGMENT_SCHEMA => true,
        LEGACY_SEGMENT_SCHEMA => header.first_sequence == 1 && epoch.first_sequence.0 == 1,
        _ => false,
    };
    if !schema_matches
        || header.gateway_id != gateway_id
        || header.boot_epoch != epoch.boot_epoch
        || header.created_at != epoch.created_at
        || header.first_sequence != epoch.first_sequence.0
    {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} header does not match its manifest descriptor",
            epoch.boot_epoch
        )));
    }
    Ok(())
}

pub(super) async fn validate_header_file(
    path: &Path,
    epoch: &EpochDescriptor,
    gateway_id: Uuid,
) -> Result<(), UsageSpoolError> {
    let metadata = tokio::fs::symlink_metadata(path)
        .await
        .map_err(|source| UsageSpoolError::io("inspect epoch segment", path, source))?;
    persistence::validate_regular_file(path, &metadata)?;
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|source| UsageSpoolError::io("open epoch segment", path, source))?;
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    let read = reader
        .read_until(b'\n', &mut line)
        .await
        .map_err(|source| UsageSpoolError::io("read epoch header", path, source))?;
    if read == 0 || line.last() != Some(&b'\n') || line.len() > MAX_RECORD_LINE_BYTES {
        return Err(UsageSpoolError::corrupt(format!(
            "epoch {} has an incomplete or oversized header",
            epoch.boot_epoch
        )));
    }
    let header: SegmentHeader = persistence::decode_line(&line, "epoch header")?;
    validate_header(&header, epoch, gateway_id)
}
