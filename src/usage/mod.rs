//! Durable local usage spool substrate.
//!
//! This module owns the node-local append and replay boundary. It deliberately
//! does not define the A3S Cloud ingestion payload or acknowledgement wire
//! contract.

mod lifecycle;
mod persistence;
mod spool;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use thiserror::Error;
use uuid::Uuid;

pub(crate) use lifecycle::{track_usage_response, UsageRequestLifecycle, UsageTerminalOutcome};
pub(crate) use spool::{UsageReservation, UsageSpool};

pub(crate) const MAX_USAGE_EVENT_BYTES: usize = 64 * 1024;

const MANIFEST_SCHEMA: &str = "a3s.gateway.usage-spool-manifest.v1";
const SEGMENT_SCHEMA: &str = "a3s.gateway.usage-spool-segment.v1";
const RECORD_SCHEMA: &str = "a3s.gateway.usage-spool-record.v1";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_RECORD_LINE_BYTES: usize = 128 * 1024;
#[cfg(test)]
const MAX_REPLAY_BATCH_RECORDS: usize = 512;

#[derive(Debug, Clone)]
pub(crate) struct UsageSpoolOptions {
    pub(crate) directory: PathBuf,
    pub(crate) gateway_id: Uuid,
    pub(crate) max_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct UsageCursor {
    pub(crate) boot_epoch: Uuid,
    pub(crate) sequence: u64,
}

#[cfg(test)]
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
    pub retained_records: u64,
    pub retained_bytes: u64,
    pub reserved_bytes: u64,
    pub capacity_bytes: u64,
    pub writable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
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
    #[cfg(test)]
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
    epochs: Vec<EpochDescriptor>,
}

impl SpoolManifest {
    fn new(gateway_id: Uuid) -> Self {
        Self {
            schema: MANIFEST_SCHEMA.to_string(),
            gateway_id,
            epochs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EpochDescriptor {
    boot_epoch: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    file: String,
    phase: EpochPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum EpochPhase {
    Prepared,
    Ready,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SegmentHeader {
    schema: String,
    gateway_id: Uuid,
    boot_epoch: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
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
mod tests;
