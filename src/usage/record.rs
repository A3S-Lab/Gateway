//! Encoding, integrity validation, and byte-exact replay for spool records.

use super::persistence::StoredRecord;
use super::{
    PersistedRecord, UsageCursor, UsageSpoolError, UsageSpoolRecord, MAX_RECORD_LINE_BYTES,
    MAX_USAGE_EVENT_BYTES, RECORD_SCHEMA,
};
use base64::Engine;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};
use uuid::Uuid;

pub(super) fn encode(
    gateway_id: Uuid,
    cursor: UsageCursor,
    event_id: Uuid,
    payload: &[u8],
) -> Result<(Vec<u8>, [u8; 32]), UsageSpoolError> {
    let payload_sha256: [u8; 32] = Sha256::digest(payload).into();
    let record = PersistedRecord {
        schema: RECORD_SCHEMA.to_string(),
        gateway_id,
        boot_epoch: cursor.boot_epoch,
        sequence: cursor.sequence,
        event_id,
        payload_base64: base64::engine::general_purpose::STANDARD.encode(payload),
        payload_sha256: encode_digest(&payload_sha256),
    };
    let mut bytes = serde_json::to_vec(&record)
        .map_err(|error| UsageSpoolError::corrupt(format!("encode spool record: {error}")))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RECORD_LINE_BYTES {
        return Err(UsageSpoolError::EventTooLarge {
            actual_bytes: payload.len(),
            maximum_bytes: MAX_USAGE_EVENT_BYTES,
        });
    }
    Ok((bytes, payload_sha256))
}

pub(super) async fn read_batch(
    stored_records: &[StoredRecord],
    gateway_id: Uuid,
) -> Result<Vec<UsageSpoolRecord>, UsageSpoolError> {
    let mut records = Vec::with_capacity(stored_records.len());
    let mut file = None;
    let mut open_path = None;
    let mut file_offset = 0_u64;
    let mut line = Vec::new();

    for stored in stored_records {
        if open_path.as_deref() != Some(stored.path.as_path()) {
            file = Some(
                tokio::fs::File::open(&stored.path)
                    .await
                    .map_err(|source| {
                        UsageSpoolError::io("open epoch segment", &stored.path, source)
                    })?,
            );
            open_path = Some(stored.path.clone());
            file_offset = 0;
        }
        let file = file.as_mut().ok_or_else(|| {
            UsageSpoolError::corrupt("usage replay did not retain an open segment")
        })?;
        if file_offset != stored.offset {
            file.seek(SeekFrom::Start(stored.offset))
                .await
                .map_err(|source| {
                    UsageSpoolError::io("seek epoch segment", &stored.path, source)
                })?;
        }
        line.resize(stored.length, 0);
        file.read_exact(&mut line)
            .await
            .map_err(|source| UsageSpoolError::io("read epoch record", &stored.path, source))?;
        file_offset = stored
            .offset
            .checked_add(stored.length as u64)
            .ok_or_else(|| UsageSpoolError::corrupt("usage replay offset overflow"))?;

        let (record, payload, digest) = decode(&line, gateway_id, stored.cursor)?;
        if record.event_id != stored.event_id || digest != stored.payload_sha256 {
            return Err(UsageSpoolError::corrupt(format!(
                "record index mismatch at {}/{}",
                stored.cursor.boot_epoch, stored.cursor.sequence
            )));
        }
        records.push(UsageSpoolRecord {
            cursor: stored.cursor,
            event_id: stored.event_id,
            payload,
        });
    }
    Ok(records)
}

pub(super) fn decode(
    line: &[u8],
    gateway_id: Uuid,
    cursor: UsageCursor,
) -> Result<(PersistedRecord, Vec<u8>, [u8; 32]), UsageSpoolError> {
    if line.last() != Some(&b'\n') {
        return Err(UsageSpoolError::corrupt(
            "usage record is not newline terminated",
        ));
    }
    let record: PersistedRecord =
        serde_json::from_slice(&line[..line.len() - 1]).map_err(|error| {
            UsageSpoolError::corrupt(format!("usage record is invalid JSON: {error}"))
        })?;
    if record.schema != RECORD_SCHEMA
        || record.gateway_id != gateway_id
        || record.boot_epoch != cursor.boot_epoch
        || record.sequence != cursor.sequence
    {
        return Err(UsageSpoolError::corrupt(format!(
            "record at {}/{} does not match its segment position",
            cursor.boot_epoch, cursor.sequence
        )));
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(record.payload_base64.as_bytes())
        .map_err(|error| {
            UsageSpoolError::corrupt(format!(
                "record at {}/{} has invalid base64: {error}",
                cursor.boot_epoch, cursor.sequence
            ))
        })?;
    if payload.len() > MAX_USAGE_EVENT_BYTES {
        return Err(UsageSpoolError::corrupt(format!(
            "record at {}/{} exceeds the event limit",
            cursor.boot_epoch, cursor.sequence
        )));
    }
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let stored_digest = decode_digest(&record.payload_sha256)?;
    if digest != stored_digest {
        return Err(UsageSpoolError::corrupt(format!(
            "record at {}/{} failed its SHA-256 check",
            cursor.boot_epoch, cursor.sequence
        )));
    }
    Ok((record, payload, digest))
}

fn encode_digest(digest: &[u8; 32]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn decode_digest(value: &str) -> Result<[u8; 32], UsageSpoolError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UsageSpoolError::corrupt(
            "record SHA-256 must contain 64 hexadecimal digits",
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| UsageSpoolError::corrupt("record SHA-256 is invalid"))?;
    }
    Ok(digest)
}
