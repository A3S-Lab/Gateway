//! Frozen Gateway→Cloud usage ingest batch / highest-contiguous-ACK contract.
//!
//! This module defines the local transport boundary Cloud must implement. It
//! does not open network sockets; production HTTP wiring remains a follow-on
//! once A3S Cloud publishes a compatible endpoint.

use super::{
    UsageAcknowledgement, UsageSpool, UsageSpoolCursor, UsageSpoolError, UsageSpoolRecord,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Wire schema for one authenticated usage ingest batch from Gateway.
pub(crate) const USAGE_INGEST_BATCH_SCHEMA: &str = "a3s.cloud.usage-ingest-batch.v1";
/// Wire schema for Cloud's highest-contiguous acknowledgement.
pub(crate) const USAGE_INGEST_ACK_SCHEMA: &str = "a3s.cloud.usage-ingest-ack.v1";

/// One durable spool record as carried in an ingest batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UsageIngestRecord {
    pub boot_epoch: Uuid,
    pub sequence: u64,
    pub event_id: Uuid,
    /// Exact lifecycle JSON bytes from the local spool (prompt-free).
    pub payload: Vec<u8>,
}

impl From<&UsageSpoolRecord> for UsageIngestRecord {
    fn from(record: &UsageSpoolRecord) -> Self {
        Self {
            boot_epoch: record.cursor.boot_epoch,
            sequence: record.cursor.sequence,
            event_id: record.event_id,
            payload: record.payload.clone(),
        }
    }
}

/// Authenticated batch Gateway posts to Cloud.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UsageIngestBatch {
    pub schema: String,
    pub gateway_id: Uuid,
    pub records: Vec<UsageIngestRecord>,
}

impl UsageIngestBatch {
    pub(crate) fn from_records(gateway_id: Uuid, records: &[UsageSpoolRecord]) -> Self {
        Self {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            records: records.iter().map(UsageIngestRecord::from).collect(),
        }
    }

    pub(crate) fn highest_cursor(&self) -> Option<UsageSpoolCursor> {
        self.records.last().map(|record| UsageSpoolCursor {
            boot_epoch: record.boot_epoch,
            sequence: record.sequence,
        })
    }
}

/// Cloud response: highest contiguous cursor accepted into the ledger path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct UsageIngestAck {
    pub schema: String,
    pub gateway_id: Uuid,
    pub acknowledged_through: UsageSpoolCursor,
}

impl UsageIngestAck {
    pub(crate) fn validate_against_batch(
        &self,
        batch: &UsageIngestBatch,
    ) -> Result<(), UsageIngestError> {
        if self.schema != USAGE_INGEST_ACK_SCHEMA {
            return Err(UsageIngestError::Contract {
                reason: format!("unexpected ack schema '{}'", self.schema),
            });
        }
        if self.gateway_id != batch.gateway_id {
            return Err(UsageIngestError::Contract {
                reason: "ack gateway_id does not match batch".to_string(),
            });
        }
        let Some(highest) = batch.highest_cursor() else {
            return Err(UsageIngestError::Contract {
                reason: "empty batch cannot be acknowledged".to_string(),
            });
        };
        if !batch.records.iter().any(|record| {
            record.boot_epoch == self.acknowledged_through.boot_epoch
                && record.sequence == self.acknowledged_through.sequence
        }) {
            return Err(UsageIngestError::Contract {
                reason: "ack cursor is not present in the submitted batch".to_string(),
            });
        }
        // Highest-contiguous: Cloud may ACK a prefix, never past the batch tip.
        if self.acknowledged_through.boot_epoch != highest.boot_epoch {
            return Err(UsageIngestError::Contract {
                reason: "ack boot_epoch does not match the batch tip epoch".to_string(),
            });
        }
        if self.acknowledged_through.sequence > highest.sequence {
            return Err(UsageIngestError::Contract {
                reason: "ack sequence exceeds the submitted batch tip".to_string(),
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

    /// Upload one batch when records are pending. Returns `None` when idle.
    pub(crate) async fn upload_once<T: UsageCloudTransport + ?Sized>(
        &self,
        transport: &T,
    ) -> Result<Option<UsageAcknowledgement>, UsageIngestError> {
        let after = self.spool.status().acknowledged_through;
        let records = self.spool.read_batch(after, self.batch_limit).await?;
        if records.is_empty() {
            return Ok(None);
        }
        let batch = UsageIngestBatch::from_records(self.gateway_id, &records);
        let ack = transport.submit_batch(batch.clone()).await?;
        ack.validate_against_batch(&batch)?;
        let applied = self.spool.acknowledge(ack.acknowledged_through).await?;
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
            let record = batch.records.get(index).ok_or(UsageIngestError::Contract {
                reason: "test ack index out of range".to_string(),
            })?;
            self.submitted.lock().unwrap().push(batch.clone());
            Ok(UsageIngestAck {
                schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
                gateway_id: batch.gateway_id,
                acknowledged_through: UsageSpoolCursor {
                    boot_epoch: record.boot_epoch,
                    sequence: record.sequence,
                },
            })
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
        let batch = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id: Uuid::new_v4(),
            records: vec![UsageIngestRecord {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
                event_id: Uuid::new_v4(),
                payload: vec![1],
            }],
        };
        let ack = UsageIngestAck {
            schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
            gateway_id: batch.gateway_id,
            acknowledged_through: UsageSpoolCursor {
                boot_epoch: batch.records[0].boot_epoch,
                sequence: 2,
            },
        };
        assert!(matches!(
            ack.validate_against_batch(&batch),
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[test]
    fn batch_schema_constants_are_stable() {
        assert_eq!(USAGE_INGEST_BATCH_SCHEMA, "a3s.cloud.usage-ingest-batch.v1");
        assert_eq!(USAGE_INGEST_ACK_SCHEMA, "a3s.cloud.usage-ingest-ack.v1");
        assert!(MAX_USAGE_EVENT_BYTES >= 1024);
    }

    /// First principles: Cloud may ACK a prefix; the next upload must only send
    /// the unacked suffix (backlog drain), never re-send acknowledged records.
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

        // Remaining backlog is two records; ACK the tip of that batch.
        *transport.acks_through_index.lock().unwrap() = 1;
        let second = uploader.upload_once(&transport).await.unwrap().unwrap();
        assert_eq!(second.newly_acknowledged_records, 2);
        assert_eq!(transport.submitted.lock().unwrap().len(), 2);
        assert_eq!(transport.submitted.lock().unwrap()[1].records.len(), 2);
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
                let tip = batch.records.last().unwrap();
                Ok(UsageIngestAck {
                    schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
                    gateway_id: batch.gateway_id,
                    acknowledged_through: UsageSpoolCursor {
                        boot_epoch: tip.boot_epoch,
                        sequence: tip.sequence,
                    },
                })
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
}
