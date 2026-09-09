//! Gateway→Cloud usage ingest batch / receipt contract.
//!
//! Wire schemas match A3S Cloud contracts (`a3s.gateway.usage-batch.v1` /
//! `a3s.gateway.usage-batch-receipt.v1`). Gateway owns the local spool and the
//! upload loop; Cloud owns the ledger. This module does not open sockets;
//! production HTTP wiring lives in `http_transport`.

use super::{
    UsageAcknowledgement, UsageSpool, UsageSpoolCursor, UsageSpoolError, UsageSpoolRecord,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Wire schema for one authenticated usage ingest batch from Gateway.
///
/// Must stay identical to Cloud's `INFERENCE_USAGE_BATCH_SCHEMA_V1`.
pub(crate) const USAGE_INGEST_BATCH_SCHEMA: &str = "a3s.gateway.usage-batch.v1";
/// Wire schema for Cloud's batch receipt (highest-contiguous ACK + gaps).
///
/// Must stay identical to Cloud's `INFERENCE_USAGE_RECEIPT_SCHEMA_V1`.
pub(crate) const USAGE_INGEST_ACK_SCHEMA: &str = "a3s.gateway.usage-batch-receipt.v1";

/// One durable spool record as carried in an ingest batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsageIngestRecord {
    pub cursor: UsageSpoolCursor,
    pub event_id: Uuid,
    pub payload_base64: String,
    pub payload_sha256: String,
}

impl UsageIngestRecord {
    pub(crate) fn from_spool_record(record: &UsageSpoolRecord) -> Self {
        let payload_sha256 = format!("{:x}", Sha256::digest(&record.payload));
        Self {
            cursor: record.cursor,
            event_id: record.event_id,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(&record.payload),
            payload_sha256,
        }
    }

    pub(crate) fn payload_bytes(&self) -> Result<Vec<u8>, UsageIngestError> {
        base64::engine::general_purpose::STANDARD
            .decode(self.payload_base64.as_bytes())
            .map_err(|error| UsageIngestError::Contract {
                reason: format!("usage event payload is invalid base64: {error}"),
            })
    }

    pub(crate) fn validate(&self) -> Result<(), UsageIngestError> {
        if self.event_id.is_nil() {
            return Err(UsageIngestError::Contract {
                reason: "usage event ID must not be the nil UUID".to_string(),
            });
        }
        if self.cursor.boot_epoch.is_nil()
            || self.cursor.sequence == 0
            || self.cursor.sequence == u64::MAX
        {
            return Err(UsageIngestError::Contract {
                reason: "usage event cursor is invalid".to_string(),
            });
        }
        let payload = self.payload_bytes()?;
        if self.payload_sha256.len() != 64
            || !self
                .payload_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self
                .payload_sha256
                .bytes()
                .any(|byte| byte.is_ascii_uppercase())
        {
            return Err(UsageIngestError::Contract {
                reason: "usage event payload SHA-256 must be 64 lowercase hex characters"
                    .to_string(),
            });
        }
        let expected = format!("{:x}", Sha256::digest(&payload));
        if self.payload_sha256 != expected {
            return Err(UsageIngestError::Contract {
                reason: "usage event payload SHA-256 does not match its bytes".to_string(),
            });
        }
        Ok(())
    }
}

/// Authenticated batch Gateway posts to Cloud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsageIngestBatch {
    pub schema: String,
    pub gateway_id: Uuid,
    pub batch_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<UsageSpoolCursor>,
    pub records: Vec<UsageIngestRecord>,
}

impl UsageIngestBatch {
    pub(crate) fn from_records(
        gateway_id: Uuid,
        after: Option<UsageSpoolCursor>,
        records: &[UsageSpoolRecord],
    ) -> Self {
        Self {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::new_v4(),
            after,
            records: records
                .iter()
                .map(UsageIngestRecord::from_spool_record)
                .collect(),
        }
    }

    pub(crate) fn highest_cursor(&self) -> Option<UsageSpoolCursor> {
        self.records.last().map(|record| record.cursor)
    }

    pub(crate) fn validate(&self) -> Result<(), UsageIngestError> {
        if self.schema != USAGE_INGEST_BATCH_SCHEMA {
            return Err(UsageIngestError::Contract {
                reason: format!("unexpected batch schema '{}'", self.schema),
            });
        }
        if self.gateway_id.is_nil() || self.batch_id.is_nil() {
            return Err(UsageIngestError::Contract {
                reason: "batch identity UUIDs must not be nil".to_string(),
            });
        }
        if self.records.is_empty() {
            return Err(UsageIngestError::Contract {
                reason: "usage batch must contain at least one record".to_string(),
            });
        }
        for record in &self.records {
            record.validate()?;
            if self.after == Some(record.cursor) {
                return Err(UsageIngestError::Contract {
                    reason: "usage batch repeats its after cursor".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Cloud response for one exact usage batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UsageIngestAck {
    pub schema: String,
    pub gateway_id: Uuid,
    pub batch_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledged_through: Option<UsageSpoolCursor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gaps: Vec<UsageSpoolCursor>,
}

impl UsageIngestAck {
    pub(crate) fn validate_against_batch(
        &self,
        batch: &UsageIngestBatch,
    ) -> Result<(), UsageIngestError> {
        batch.validate()?;
        if self.schema != USAGE_INGEST_ACK_SCHEMA {
            return Err(UsageIngestError::Contract {
                reason: format!("unexpected receipt schema '{}'", self.schema),
            });
        }
        if self.gateway_id != batch.gateway_id || self.batch_id != batch.batch_id {
            return Err(UsageIngestError::Contract {
                reason: "receipt changed batch identity".to_string(),
            });
        }
        if let Some(cursor) = self.acknowledged_through {
            if cursor.boot_epoch.is_nil() || cursor.sequence == 0 || cursor.sequence == u64::MAX {
                return Err(UsageIngestError::Contract {
                    reason: "receipt acknowledgement cursor is invalid".to_string(),
                });
            }
            if self.acknowledged_through != batch.after
                && !batch.records.iter().any(|record| record.cursor == cursor)
            {
                return Err(UsageIngestError::Contract {
                    reason: "receipt acknowledges a cursor outside its batch".to_string(),
                });
            }
            if let Some(highest) = batch.highest_cursor() {
                if cursor.boot_epoch == highest.boot_epoch && cursor.sequence > highest.sequence {
                    return Err(UsageIngestError::Contract {
                        reason: "receipt sequence exceeds the submitted batch tip".to_string(),
                    });
                }
            }
        }
        if self
            .acknowledged_through
            .is_some_and(|cursor| self.gaps.contains(&cursor))
        {
            return Err(UsageIngestError::Contract {
                reason: "receipt acknowledges a reported gap".to_string(),
            });
        }
        Ok(())
    }
}

/// Sink implemented by Cloud (or a local test double).
#[async_trait::async_trait]
pub(crate) trait UsageCloudTransport: Send + Sync {
    async fn submit_batch(
        &self,
        batch: UsageIngestBatch,
    ) -> Result<UsageIngestAck, UsageIngestError>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum UsageIngestError {
    #[error("usage ingest contract error: {reason}")]
    Contract { reason: String },
    #[allow(dead_code)] // Returned by production HTTP transport adapters.
    #[error("usage ingest transport error: {reason}")]
    Transport { reason: String },
    #[error(transparent)]
    Spool(#[from] UsageSpoolError),
}

/// Drives one read → submit → highest-contiguous local ACK cycle.
pub(crate) struct UsageCloudUploader {
    spool: Arc<UsageSpool>,
    gateway_id: Uuid,
    batch_limit: usize,
}

impl UsageCloudUploader {
    pub(crate) fn new(spool: Arc<UsageSpool>, gateway_id: Uuid, batch_limit: usize) -> Self {
        Self {
            spool,
            gateway_id,
            batch_limit: batch_limit.max(1),
        }
    }

    /// Upload one batch when records are pending. Returns `None` when idle or
    /// when Cloud accepted the batch without advancing the watermark.
    pub(crate) async fn upload_once<T: UsageCloudTransport + ?Sized>(
        &self,
        transport: &T,
    ) -> Result<Option<UsageAcknowledgement>, UsageIngestError> {
        let after = self.spool.status().acknowledged_through;
        let records = self.spool.read_batch(after, self.batch_limit).await?;
        if records.is_empty() {
            return Ok(None);
        }
        let batch = UsageIngestBatch::from_records(self.gateway_id, after, &records);
        batch.validate()?;
        let ack = transport.submit_batch(batch.clone()).await?;
        ack.validate_against_batch(&batch)?;
        let Some(cursor) = ack.acknowledged_through else {
            return Ok(None);
        };
        if Some(cursor) == after {
            return Ok(None);
        }
        let applied = self.spool.acknowledge(cursor).await?;
        Ok(Some(applied))
    }
}

/// Poll the local spool and upload batches until `shutdown` becomes true.
pub(crate) fn spawn_usage_cloud_uploader_loop<T>(
    uploader: UsageCloudUploader,
    transport: T,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()>
where
    T: UsageCloudTransport + 'static,
{
    const IDLE_POLL: Duration = Duration::from_secs(2);
    const ERROR_BACKOFF: Duration = Duration::from_secs(5);

    tokio::spawn(async move {
        loop {
            if *shutdown.borrow() {
                break;
            }
            match uploader.upload_once(&transport).await {
                Ok(Some(_)) => {
                    // Drain promptly while work remains.
                    continue;
                }
                Ok(None) => {
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(IDLE_POLL) => {}
                    }
                }
                Err(error) => {
                    tracing::warn!(error = %error, "Usage Cloud ingest upload failed");
                    tokio::select! {
                        _ = shutdown.changed() => {
                            if *shutdown.borrow() {
                                break;
                            }
                        }
                        _ = tokio::time::sleep(ERROR_BACKOFF) => {}
                    }
                }
            }
        }
        tracing::info!("Usage Cloud ingest uploader stopped");
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::{UsageSpoolOptions, MAX_USAGE_EVENT_BYTES};
    use std::sync::Mutex;

    fn tip_ack(batch: &UsageIngestBatch, index: usize) -> UsageIngestAck {
        let record = &batch.records[index];
        UsageIngestAck {
            schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
            gateway_id: batch.gateway_id,
            batch_id: batch.batch_id,
            acknowledged_through: Some(record.cursor),
            gaps: Vec::new(),
        }
    }

    struct RecordingTransport {
        acks_through_index: Mutex<usize>,
        submitted: Mutex<Vec<UsageIngestBatch>>,
    }

    impl RecordingTransport {
        fn new(acks_through_index: usize) -> Self {
            Self {
                acks_through_index: Mutex::new(acks_through_index),
                submitted: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl UsageCloudTransport for RecordingTransport {
        async fn submit_batch(
            &self,
            batch: UsageIngestBatch,
        ) -> Result<UsageIngestAck, UsageIngestError> {
            let index = *self.acks_through_index.lock().unwrap();
            if index >= batch.records.len() {
                return Err(UsageIngestError::Contract {
                    reason: "test ack index out of range".to_string(),
                });
            }
            let ack = tip_ack(&batch, index);
            self.submitted.lock().unwrap().push(batch);
            Ok(ack)
        }
    }

    async fn open_spool(directory: &std::path::Path, gateway_id: Uuid) -> Arc<UsageSpool> {
        Arc::new(
            UsageSpool::open(UsageSpoolOptions {
                directory: directory.join("usage"),
                gateway_id,
                max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
            })
            .await
            .unwrap(),
        )
    }

    async fn append_payload(spool: &UsageSpool, payload: &[u8]) {
        spool.append(Uuid::new_v4(), payload).await.unwrap();
    }

    #[tokio::test]
    async fn uploader_applies_highest_contiguous_ack_and_reclaims() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = open_spool(directory.path(), gateway_id).await;
        append_payload(&spool, br#"{"kind":"a"}"#).await;
        append_payload(&spool, br#"{"kind":"b"}"#).await;

        let transport = RecordingTransport::new(1); // ACK both records
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        let applied = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(applied.newly_acknowledged_records, 2);
        assert!(
            spool.status().retained_records < 2 || spool.status().acknowledged_through.is_some()
        );
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn uploader_rejects_ack_past_batch_tip() {
        let cursor = UsageSpoolCursor {
            boot_epoch: Uuid::new_v4(),
            sequence: 1,
        };
        let batch = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id: Uuid::new_v4(),
            batch_id: Uuid::new_v4(),
            after: None,
            records: vec![UsageIngestRecord {
                cursor,
                event_id: Uuid::new_v4(),
                payload_base64: base64::engine::general_purpose::STANDARD.encode([1_u8]),
                payload_sha256: format!("{:x}", Sha256::digest([1_u8])),
            }],
        };
        let ack = UsageIngestAck {
            schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
            gateway_id: batch.gateway_id,
            batch_id: batch.batch_id,
            acknowledged_through: Some(UsageSpoolCursor {
                boot_epoch: cursor.boot_epoch,
                sequence: 2,
            }),
            gaps: Vec::new(),
        };
        assert!(matches!(
            ack.validate_against_batch(&batch),
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[test]
    fn batch_schema_constants_match_cloud_contracts() {
        assert_eq!(USAGE_INGEST_BATCH_SCHEMA, "a3s.gateway.usage-batch.v1");
        assert_eq!(
            USAGE_INGEST_ACK_SCHEMA,
            "a3s.gateway.usage-batch-receipt.v1"
        );
        assert!(MAX_USAGE_EVENT_BYTES >= 1024);
    }

    #[test]
    fn record_rejects_tampered_payload_hash() {
        let mut record = UsageIngestRecord {
            cursor: UsageSpoolCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
            },
            event_id: Uuid::new_v4(),
            payload_base64: base64::engine::general_purpose::STANDARD.encode(b"ok"),
            payload_sha256: format!("{:x}", Sha256::digest(b"ok")),
        };
        record.validate().unwrap();
        record.payload_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".to_string();
        assert!(matches!(
            record.validate(),
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[test]
    fn receipt_rejects_batch_id_mismatch() {
        let cursor = UsageSpoolCursor {
            boot_epoch: Uuid::new_v4(),
            sequence: 1,
        };
        let batch = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id: Uuid::new_v4(),
            batch_id: Uuid::new_v4(),
            after: None,
            records: vec![UsageIngestRecord {
                cursor,
                event_id: Uuid::new_v4(),
                payload_base64: base64::engine::general_purpose::STANDARD.encode([1_u8]),
                payload_sha256: format!("{:x}", Sha256::digest([1_u8])),
            }],
        };
        let mut ack = tip_ack(&batch, 0);
        ack.batch_id = Uuid::new_v4();
        assert!(matches!(
            ack.validate_against_batch(&batch),
            Err(UsageIngestError::Contract { .. })
        ));
    }

    /// First principles: Cloud may ACK a prefix; the next upload must only send
    /// the unacked suffix (backlog drain), never re-send acknowledged records,
    /// and must carry `after` equal to the prior watermark.
    #[tokio::test]
    async fn prefix_ack_then_next_upload_drains_remaining_backlog() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = open_spool(directory.path(), gateway_id).await;
        append_payload(&spool, br#"{"kind":"a"}"#).await;
        append_payload(&spool, br#"{"kind":"b"}"#).await;
        append_payload(&spool, br#"{"kind":"c"}"#).await;

        let transport = RecordingTransport::new(0); // ACK only the first record
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        let first = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(first.newly_acknowledged_records, 1);
        assert_eq!(transport.submitted.lock().unwrap().len(), 1);
        assert_eq!(transport.submitted.lock().unwrap()[0].records.len(), 3);
        assert!(transport.submitted.lock().unwrap()[0].after.is_none());

        // Remaining backlog is two records; ACK the tip of that batch.
        *transport.acks_through_index.lock().unwrap() = 1;
        let second = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(second.newly_acknowledged_records, 2);
        let submitted = transport.submitted.lock().unwrap();
        assert_eq!(submitted.len(), 2);
        assert_eq!(submitted[1].records.len(), 2);
        assert_eq!(submitted[1].after, Some(submitted[0].records[0].cursor));
        drop(submitted);
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
    }

    /// Transport errors must not advance the watermark; a later success drains.
    #[tokio::test]
    async fn transport_failure_then_retry_preserves_unacked_backlog() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = open_spool(directory.path(), gateway_id).await;
        append_payload(&spool, br#"{"kind":"pending"}"#).await;

        struct FailThenSucceed {
            calls: Mutex<usize>,
        }

        #[async_trait::async_trait]
        impl UsageCloudTransport for FailThenSucceed {
            async fn submit_batch(
                &self,
                batch: UsageIngestBatch,
            ) -> Result<UsageIngestAck, UsageIngestError> {
                let mut calls = self.calls.lock().unwrap();
                *calls += 1;
                if *calls == 1 {
                    return Err(UsageIngestError::Transport {
                        reason: "simulated cloud unavailable".to_string(),
                    });
                }
                Ok(tip_ack(&batch, batch.records.len() - 1))
            }
        }

        let transport = FailThenSucceed {
            calls: Mutex::new(0),
        };
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        assert!(matches!(
            uploader.upload_once(&transport).await,
            Err(UsageIngestError::Transport { .. })
        ));
        assert!(spool.status().acknowledged_through.is_none());
        let applied = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(applied.newly_acknowledged_records, 1);
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
    }

    /// Duplicate delivery of an already-acked tip must not invent new work and
    /// must survive process restart from the durable spool directory.
    #[tokio::test]
    async fn duplicate_ack_and_process_restart_are_idempotent() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = open_spool(directory.path(), gateway_id).await;
        append_payload(&spool, br#"{"kind":"one"}"#).await;
        append_payload(&spool, br#"{"kind":"two"}"#).await;

        let transport = RecordingTransport::new(1);
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        assert_eq!(
            uploader
                .upload_once(&transport)
                .await
                .unwrap()
                .unwrap()
                .newly_acknowledged_records,
            2
        );
        // Idle: nothing left to upload.
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
        drop(uploader);
        drop(spool);

        // Process restart: reopen the same directory; watermark must hold.
        let spool = open_spool(directory.path(), gateway_id).await;
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
        assert!(spool.status().acknowledged_through.is_some());
    }

    /// Crash after a durable prefix ACK: reopen and finish the remaining suffix.
    #[tokio::test]
    async fn process_restart_resumes_after_persisted_prefix_ack() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        {
            let spool = open_spool(directory.path(), gateway_id).await;
            append_payload(&spool, br#"{"kind":"kept"}"#).await;
            append_payload(&spool, br#"{"kind":"pending"}"#).await;
            let transport = RecordingTransport::new(0);
            let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
            assert_eq!(
                uploader
                    .upload_once(&transport)
                    .await
                    .unwrap()
                    .unwrap()
                    .newly_acknowledged_records,
                1
            );
        }

        let spool = open_spool(directory.path(), gateway_id).await;
        let transport = RecordingTransport::new(0); // sole remaining record
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        let applied = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(applied.newly_acknowledged_records, 1);
        assert_eq!(transport.submitted.lock().unwrap()[0].records.len(), 1);
        assert!(uploader.upload_once(&transport).await.unwrap().is_none());
    }

    /// Empty acknowledgement advances nothing; gaps alone never invent a watermark.
    #[tokio::test]
    async fn receipt_without_ack_cursor_does_not_advance_watermark() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = open_spool(directory.path(), gateway_id).await;
        append_payload(&spool, br#"{"kind":"held"}"#).await;

        struct EmptyReceipt;
        #[async_trait::async_trait]
        impl UsageCloudTransport for EmptyReceipt {
            async fn submit_batch(
                &self,
                batch: UsageIngestBatch,
            ) -> Result<UsageIngestAck, UsageIngestError> {
                Ok(UsageIngestAck {
                    schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
                    gateway_id: batch.gateway_id,
                    batch_id: batch.batch_id,
                    acknowledged_through: None,
                    gaps: vec![batch.records[0].cursor],
                })
            }
        }

        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        assert!(uploader.upload_once(&EmptyReceipt).await.unwrap().is_none());
        assert!(spool.status().acknowledged_through.is_none());
    }
}
