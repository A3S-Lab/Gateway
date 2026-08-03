//! Durable local usage spool substrate.
//!
//! This module owns the node-local append and replay boundary. It deliberately
//! does not define the A3S Cloud ingestion payload or acknowledgement wire
//! contract.

mod acknowledgement;
mod compaction;
mod lifecycle;
mod persistence;
mod record;
mod segments;
mod spool;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

pub(crate) use lifecycle::{track_usage_response, UsageRequestLifecycle, UsageTerminalOutcome};
pub(crate) use spool::{UsageReservation, UsageSpool};

pub(crate) const MAX_USAGE_EVENT_BYTES: usize = 64 * 1024;

const MANIFEST_SCHEMA_V1: &str = "a3s.gateway.usage-spool-manifest.v1";
const MANIFEST_SCHEMA_V2: &str = "a3s.gateway.usage-spool-manifest.v2";
const MANIFEST_SCHEMA: &str = "a3s.gateway.usage-spool-manifest.v3";
const LEGACY_SEGMENT_SCHEMA: &str = "a3s.gateway.usage-spool-segment.v1";
const SEGMENT_SCHEMA: &str = "a3s.gateway.usage-spool-segment.v2";
const RECORD_SCHEMA: &str = "a3s.gateway.usage-spool-record.v1";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_RECORD_LINE_BYTES: usize = 128 * 1024;
const MAX_REPLAY_BATCH_RECORDS: usize = 512;

#[derive(Debug, Clone)]
pub(crate) struct UsageSpoolOptions {
    pub(crate) directory: PathBuf,
    pub(crate) gateway_id: Uuid,
    pub(crate) max_bytes: u64,
}

/// Node-local position of one durable usage record.
///
/// This cursor describes Gateway spool ordering only. It is not the A3S Cloud
/// ingestion or acknowledgement wire contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsageSpoolCursor {
    /// UUID identifying the Gateway process boot that created the record.
    pub boot_epoch: Uuid,
    /// One-based, monotonically increasing position within the boot epoch.
    pub sequence: u64,
}

type UsageCursor = UsageSpoolCursor;

#[allow(dead_code)] // Consumed by the pending Cloud transport adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UsageSpoolRecord {
    pub(crate) cursor: UsageCursor,
    pub(crate) event_id: Uuid,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageSpoolStatus {
    pub gateway_id: Uuid,
    pub boot_epoch: Uuid,
    pub next_sequence: u64,
    /// Highest exact local record durably accepted by the acknowledgement boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_through: Option<UsageSpoolCursor>,
    /// Oldest record still eligible for replay.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_retained_cursor: Option<UsageSpoolCursor>,
    pub retained_records: u64,
    pub retained_bytes: u64,
    pub reserved_bytes: u64,
    pub capacity_bytes: u64,
    pub writable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[allow(dead_code)] // Returned to the pending Cloud transport adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UsageAcknowledgement {
    pub(crate) acknowledged_through: UsageCursor,
    pub(crate) newly_acknowledged_records: u64,
    pub(crate) reclaimed_bytes: u64,
    pub(crate) cleanup_pending: bool,
}

pub(crate) struct UsageAppendReceipt {
    completion: tokio::sync::oneshot::Receiver<std::result::Result<UsageCursor, String>>,
}

impl UsageAppendReceipt {
    pub(crate) async fn wait(self) -> Result<UsageCursor, UsageSpoolError> {
        self.completion
            .await
            .map_err(|_| UsageSpoolError::Unavailable {
                reason: "usage spool writer stopped before acknowledging an append".to_string(),
            })?
            .map_err(|reason| UsageSpoolError::Unavailable { reason })
    }
}

#[derive(Debug, Error)]
pub(crate) enum UsageSpoolError {
    #[error("invalid usage spool options: {reason}")]
    InvalidOptions { reason: String },
    #[error("usage spool directory {directory} is locked by another process")]
    Locked { directory: PathBuf },
    #[error(
        "usage spool belongs to Gateway {actual_gateway_id}, not configured Gateway {expected_gateway_id}"
    )]
    GatewayIdentityMismatch {
        expected_gateway_id: Uuid,
        actual_gateway_id: Uuid,
    },
    #[error("usage spool is corrupt: {reason}")]
    Corrupt { reason: String },
    #[error(
        "usage spool capacity exceeded: {retained_bytes} retained bytes + {requested_bytes} requested bytes > {capacity_bytes} bytes"
    )]
    Full {
        retained_bytes: u64,
        requested_bytes: u64,
        capacity_bytes: u64,
    },
    #[error("usage event is {actual_bytes} bytes; maximum is {maximum_bytes} bytes")]
    EventTooLarge {
        actual_bytes: usize,
        maximum_bytes: usize,
    },
    #[error("usage event {event_id} was already appended with different bytes")]
    EventConflict { event_id: Uuid },
    #[error("could not encode usage event: {reason}")]
    Encode { reason: String },
    #[error(
        "usage replay cursor {boot_epoch}/{sequence} is not retained and represents a visible gap"
    )]
    CursorGap { boot_epoch: Uuid, sequence: u64 },
    #[error("usage spool is unavailable until process restart: {reason}")]
    Unavailable { reason: String },
    #[error("could not {operation} usage spool path {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl UsageSpoolError {
    fn io(operation: &'static str, path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    fn corrupt(reason: impl Into<String>) -> Self {
        Self::Corrupt {
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpoolManifest {
    schema: String,
    gateway_id: Uuid,
    #[serde(default = "unacknowledged_manifest_cursor")]
    acknowledged_through: ManifestCursor,
    epochs: Vec<EpochDescriptor>,
}

impl SpoolManifest {
    fn new(gateway_id: Uuid) -> Self {
        Self {
            schema: MANIFEST_SCHEMA.to_string(),
            gateway_id,
            acknowledged_through: unacknowledged_manifest_cursor(),
            epochs: Vec::new(),
        }
    }

    fn acknowledged_through(&self) -> Option<UsageCursor> {
        (self.acknowledged_through.0 != unacknowledged_cursor())
            .then_some(self.acknowledged_through.0)
    }

    fn acknowledge(&mut self, cursor: UsageCursor) {
        self.acknowledged_through = ManifestCursor(cursor);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManifestCursor(UsageCursor);

impl Serialize for ManifestCursor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("ManifestCursor", 2)?;
        state.serialize_field("boot_epoch", &self.0.boot_epoch)?;
        state.serialize_field("sequence", &ManifestSequence(self.0.sequence))?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for ManifestCursor {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EncodedCursor {
            boot_epoch: Uuid,
            sequence: ManifestSequence,
        }

        let encoded = EncodedCursor::deserialize(deserializer)?;
        Ok(Self(UsageCursor {
            boot_epoch: encoded.boot_epoch,
            sequence: encoded.sequence.0,
        }))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ManifestSequence(u64);

impl Serialize for ManifestSequence {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{:016x}", self.0))
    }
}

impl<'de> Deserialize<'de> for ManifestSequence {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 16 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(
                "usage sequence must contain 16 hexadecimal digits",
            ));
        }
        u64::from_str_radix(&encoded, 16)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("usage sequence is invalid"))
    }
}

fn first_manifest_sequence() -> ManifestSequence {
    ManifestSequence(1)
}

fn zero_manifest_sequence() -> ManifestSequence {
    ManifestSequence(0)
}

fn unacknowledged_cursor() -> UsageCursor {
    // A real record can never use sequence u64::MAX.
    UsageCursor {
        boot_epoch: Uuid::nil(),
        sequence: u64::MAX,
    }
}

fn unacknowledged_manifest_cursor() -> ManifestCursor {
    // The fixed-width sequence keeps every acknowledgement representation
    // exactly the same size, so advancing the watermark cannot consume
    // unreserved spool capacity.
    ManifestCursor(unacknowledged_cursor())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochDescriptor {
    boot_epoch: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    file: String,
    #[serde(default = "first_manifest_sequence")]
    first_sequence: ManifestSequence,
    #[serde(default = "zero_manifest_sequence")]
    compacted_last_sequence: ManifestSequence,
    phase: EpochPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EpochPhase {
    Prepared,
    Ready,
    // The compact persisted name guarantees an acknowledgement manifest is
    // never larger than the ready manifest it replaces.
    #[serde(rename = "gc")]
    Retiring,
    // A compacted copy is durable and can replace the original segment.
    #[serde(rename = "cp")]
    Compacting,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentHeader {
    schema: String,
    gateway_id: Uuid,
    boot_epoch: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "first_sequence")]
    first_sequence: u64,
}

const fn first_sequence() -> u64 {
    1
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedRecord {
    schema: String,
    gateway_id: Uuid,
    boot_epoch: Uuid,
    sequence: u64,
    event_id: Uuid,
    payload_base64: String,
    payload_sha256: String,
}

#[cfg(test)]
mod acknowledgement_tests;
#[cfg(test)]
mod compaction_tests;
#[cfg(test)]
mod tests;
