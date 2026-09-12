//! Production-shaped Cloud usage-ledger semantics Gateway depends on.
//!
//! This is not a network endpoint and not a substitute for A3S Cloud. It encodes
//! the highest-contiguous acknowledgement / gap / event-id dedup rules from the
//! shared `a3s.gateway.usage-batch.v1` contract so Gateway can falsify its
//! uploader against ledger behavior before Cloud ships
//! `POST /v1/inference-control/usage-batches`.

use super::cloud_ingest::{
    UsageCloudTransport, UsageIngestAck, UsageIngestBatch, UsageIngestError,
    USAGE_INGEST_ACK_SCHEMA,
};
use super::UsageSpoolCursor;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Default)]
struct GatewayLedgerState {
    /// Highest contiguous cursor accepted into the ledger for this Gateway.
    watermark: Option<UsageSpoolCursor>,
    /// event_id → payload digest (lowercase hex) for idempotent dedup.
    events: HashMap<Uuid, String>,
}

/// In-memory Cloud ledger double implementing the frozen receipt contract.
#[derive(Debug, Default)]
pub(crate) struct InMemoryUsageLedger {
    gateways: Mutex<HashMap<Uuid, GatewayLedgerState>>,
}

impl InMemoryUsageLedger {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn watermark(&self, gateway_id: Uuid) -> Option<UsageSpoolCursor> {
        self.gateways
            .lock()
            .unwrap()
            .get(&gateway_id)
            .and_then(|state| state.watermark)
    }

    fn apply_batch(&self, batch: &UsageIngestBatch) -> Result<UsageIngestAck, UsageIngestError> {
        batch.validate()?;
        let mut gateways = self.gateways.lock().unwrap();
        let state = gateways.entry(batch.gateway_id).or_default();

        if batch.after != state.watermark {
            // Caller is not replaying from the ledger tip. Hold without
            // inventing contiguity. Only advertise a tip the receipt contract
            // allows (`after` or a cursor in this batch).
            let acknowledged_through = if state.watermark == batch.after
                || state
                    .watermark
                    .is_some_and(|tip| batch.records.iter().any(|record| record.cursor == tip))
            {
                state.watermark
            } else {
                batch.after
            };
            let ack = UsageIngestAck {
                schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
                gateway_id: batch.gateway_id,
                batch_id: batch.batch_id,
                acknowledged_through,
                gaps: Vec::new(),
            };
            ack.validate_against_batch(batch)?;
            return Ok(ack);
        }

        let mut acknowledged_through = state.watermark;
        let mut gaps = Vec::new();
        for record in &batch.records {
            let expected = match acknowledged_through {
                None => UsageSpoolCursor {
                    boot_epoch: record.cursor.boot_epoch,
                    sequence: 1,
                },
                Some(cursor) if cursor.boot_epoch == record.cursor.boot_epoch => UsageSpoolCursor {
                    boot_epoch: cursor.boot_epoch,
                    sequence: cursor.sequence.saturating_add(1),
                },
                Some(_) => record.cursor, // new boot epoch may start at any valid sequence
            };

            if record.cursor != expected
                && !(acknowledged_through.is_some_and(|cursor| {
                    cursor.boot_epoch != record.cursor.boot_epoch && record.cursor.sequence == 1
                }))
            {
                gaps.push(expected);
                break;
            }

            match state.events.get(&record.event_id) {
                Some(digest) if digest != &record.payload_sha256 => {
                    return Err(UsageIngestError::Contract {
                        reason: format!(
                            "usage event {} payload digest conflicts with the ledger",
                            record.event_id
                        ),
                    });
                }
                Some(_) => {
                    // Idempotent redelivery of an exact event.
                }
                None => {
                    state
                        .events
                        .insert(record.event_id, record.payload_sha256.clone());
                }
            }
            acknowledged_through = Some(record.cursor);
        }

        state.watermark = acknowledged_through;
        Ok(UsageIngestAck {
            schema: USAGE_INGEST_ACK_SCHEMA.to_string(),
            gateway_id: batch.gateway_id,
            batch_id: batch.batch_id,
            acknowledged_through,
            gaps,
        })
    }
}

#[async_trait::async_trait]
impl UsageCloudTransport for InMemoryUsageLedger {
    async fn submit_batch(
        &self,
        batch: UsageIngestBatch,
    ) -> Result<UsageIngestAck, UsageIngestError> {
        self.apply_batch(&batch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::cloud_ingest::{
        UsageCloudUploader, UsageIngestRecord, USAGE_INGEST_BATCH_SCHEMA,
    };
    use crate::usage::{UsageSpool, UsageSpoolOptions};
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    fn record(cursor: UsageSpoolCursor, event_id: Uuid, payload: &[u8]) -> UsageIngestRecord {
        UsageIngestRecord {
            cursor,
            event_id,
            payload_base64: base64::engine::general_purpose::STANDARD.encode(payload),
            payload_sha256: format!("{:x}", Sha256::digest(payload)),
        }
    }

    #[test]
    fn ledger_acks_contiguous_records_and_refuses_wrong_after() {
        let ledger = InMemoryUsageLedger::new();
        let gateway_id = Uuid::from_u128(2);
        let epoch = Uuid::from_u128(1);
        let first = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(3),
            after: None,
            records: vec![record(
                UsageSpoolCursor {
                    boot_epoch: epoch,
                    sequence: 1,
                },
                Uuid::from_u128(10),
                b"a",
            )],
        };
        let ack = ledger.apply_batch(&first).unwrap();
        assert_eq!(
            ack.acknowledged_through,
            Some(UsageSpoolCursor {
                boot_epoch: epoch,
                sequence: 1
            })
        );

        // Replay that ignores the watermark must not invent a lower tip.
        let wrong_after = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(5),
            after: None,
            records: vec![record(
                UsageSpoolCursor {
                    boot_epoch: epoch,
                    sequence: 1,
                },
                Uuid::from_u128(10),
                b"a",
            )],
        };
        let gap_ack = ledger.apply_batch(&wrong_after).unwrap();
        assert_eq!(
            gap_ack.acknowledged_through,
            Some(UsageSpoolCursor {
                boot_epoch: epoch,
                sequence: 1
            })
        );
        assert!(gap_ack.gaps.is_empty());
    }

    #[test]
    fn ledger_wrong_after_does_not_advertise_tip_outside_batch() {
        let ledger = InMemoryUsageLedger::new();
        let gateway_id = Uuid::from_u128(2);
        let epoch = Uuid::from_u128(1);
        let first = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(3),
            after: None,
            records: vec![
                record(
                    UsageSpoolCursor {
                        boot_epoch: epoch,
                        sequence: 1,
                    },
                    Uuid::from_u128(10),
                    b"a",
                ),
                record(
                    UsageSpoolCursor {
                        boot_epoch: epoch,
                        sequence: 2,
                    },
                    Uuid::from_u128(11),
                    b"b",
                ),
            ],
        };
        ledger.apply_batch(&first).unwrap();

        let narrow = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(5),
            after: None,
            records: vec![record(
                UsageSpoolCursor {
                    boot_epoch: epoch,
                    sequence: 1,
                },
                Uuid::from_u128(10),
                b"a",
            )],
        };
        let hold = ledger.apply_batch(&narrow).unwrap();
        hold.validate_against_batch(&narrow).unwrap();
        assert_eq!(hold.acknowledged_through, None);
        assert_eq!(
            ledger.watermark(gateway_id),
            Some(UsageSpoolCursor {
                boot_epoch: epoch,
                sequence: 2
            })
        );
    }

    #[tokio::test]
    async fn uploader_recovers_after_hold_when_full_window_includes_tip() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::from_u128(7);
        let spool = Arc::new(
            UsageSpool::open(UsageSpoolOptions {
                directory: directory.path().join("usage"),
                gateway_id,
                max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
            })
            .await
            .unwrap(),
        );
        let first_id = Uuid::from_u128(101);
        let second_id = Uuid::from_u128(102);
        spool.append(first_id, br#"{"kind":"a"}"#).await.unwrap();
        spool.append(second_id, br#"{"kind":"b"}"#).await.unwrap();

        let ledger = InMemoryUsageLedger::new();
        // Cloud already accepted both events (durable tip ahead of Gateway ACK).
        let seed = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(1),
            after: None,
            records: {
                let after = None;
                let records = spool.read_batch(after, 8).await.unwrap();
                UsageIngestBatch::from_records(gateway_id, after, &records).records
            },
        };
        ledger.apply_batch(&seed).unwrap();
        assert_eq!(
            ledger.watermark(gateway_id).map(|cursor| cursor.sequence),
            Some(2)
        );

        // Simulate a narrow wrong-after window that omits the durable tip.
        let narrow = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::from_u128(2),
            after: None,
            records: vec![seed.records[0].clone()],
        };
        let hold = ledger.apply_batch(&narrow).unwrap();
        assert_eq!(hold.acknowledged_through, None);

        // Full spool window includes the tip; uploader drains to Cloud watermark.
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        let applied = uploader.upload_once(&ledger).await.unwrap().unwrap();
        assert_eq!(applied.newly_acknowledged_records, 2);
        assert_eq!(
            spool.status().acknowledged_through,
            ledger.watermark(gateway_id)
        );
        assert!(uploader.upload_once(&ledger).await.unwrap().is_none());
    }

    #[test]
    fn ledger_rejects_event_id_payload_conflicts() {
        let ledger = InMemoryUsageLedger::new();
        let gateway_id = Uuid::new_v4();
        let epoch = Uuid::new_v4();
        let event_id = Uuid::new_v4();
        let cursor = UsageSpoolCursor {
            boot_epoch: epoch,
            sequence: 1,
        };
        let first = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::new_v4(),
            after: None,
            records: vec![record(cursor, event_id, b"one")],
        };
        ledger.apply_batch(&first).unwrap();

        let conflict = UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id: Uuid::new_v4(),
            after: Some(cursor),
            records: vec![record(
                UsageSpoolCursor {
                    boot_epoch: epoch,
                    sequence: 2,
                },
                event_id,
                b"other",
            )],
        };
        assert!(matches!(
            ledger.apply_batch(&conflict),
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[tokio::test]
    async fn uploader_drains_against_in_memory_cloud_ledger() {
        let directory = tempfile::tempdir().unwrap();
        let gateway_id = Uuid::new_v4();
        let spool = Arc::new(
            UsageSpool::open(UsageSpoolOptions {
                directory: directory.path().join("usage"),
                gateway_id,
                max_bytes: crate::config::MIN_USAGE_SPOOL_MAX_BYTES,
            })
            .await
            .unwrap(),
        );
        spool
            .append(Uuid::new_v4(), br#"{"kind":"a"}"#)
            .await
            .unwrap();
        spool
            .append(Uuid::new_v4(), br#"{"kind":"b"}"#)
            .await
            .unwrap();

        let ledger = InMemoryUsageLedger::new();
        let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
        let applied = uploader.upload_once(&ledger).await.unwrap().unwrap();
        assert_eq!(applied.newly_acknowledged_records, 2);
        assert_eq!(
            ledger.watermark(gateway_id),
            spool.status().acknowledged_through
        );
        assert!(uploader.upload_once(&ledger).await.unwrap().is_none());
    }

    #[test]
    fn ledger_types_are_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryUsageLedger>();
    }
}
