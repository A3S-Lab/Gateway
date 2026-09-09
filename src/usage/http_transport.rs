//! HTTP transport for the frozen Gateway→Cloud usage ingest contract.

use super::cloud_ingest::{
    UsageCloudTransport, UsageIngestAck, UsageIngestBatch, UsageIngestError,
    USAGE_INGEST_ACK_SCHEMA,
};
use reqwest::StatusCode;
use std::time::Duration;

/// Authenticated HTTPS client that posts usage batches to Cloud.
pub(crate) struct HttpUsageCloudTransport {
    client: reqwest::Client,
    endpoint: String,
    bearer_token: String,
}

impl HttpUsageCloudTransport {
    pub(crate) fn new(endpoint: String, bearer_token: String) -> Result<Self, UsageIngestError> {
        if endpoint.trim().is_empty() {
            return Err(UsageIngestError::Contract {
                reason: "usage ingest endpoint must not be empty".to_string(),
            });
        }
        if bearer_token.is_empty() {
            return Err(UsageIngestError::Contract {
                reason: "usage ingest bearer token must not be empty".to_string(),
            });
        }
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("a3s-gateway/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| UsageIngestError::Transport {
                reason: error.to_string(),
            })?;
        Ok(Self {
            client,
            endpoint,
            bearer_token,
        })
    }
}

#[async_trait::async_trait]
impl UsageCloudTransport for HttpUsageCloudTransport {
    async fn submit_batch(
        &self,
        batch: UsageIngestBatch,
    ) -> Result<UsageIngestAck, UsageIngestError> {
        let response = self
            .client
            .post(&self.endpoint)
            .bearer_auth(&self.bearer_token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&batch)
            .send()
            .await
            .map_err(|error| UsageIngestError::Transport {
                reason: error.to_string(),
            })?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| UsageIngestError::Transport {
                reason: error.to_string(),
            })?;
        if status != StatusCode::OK {
            return Err(UsageIngestError::Transport {
                reason: format!(
                    "usage ingest HTTP {} with {} response bytes",
                    status.as_u16(),
                    body.len()
                ),
            });
        }
        let ack: UsageIngestAck =
            serde_json::from_slice(&body).map_err(|error| UsageIngestError::Contract {
                reason: format!("invalid usage ingest receipt JSON: {error}"),
            })?;
        if ack.schema != USAGE_INGEST_ACK_SCHEMA {
            return Err(UsageIngestError::Contract {
                reason: format!("unexpected receipt schema '{}'", ack.schema),
            });
        }
        Ok(ack)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usage::cloud_ingest::{UsageIngestRecord, USAGE_INGEST_BATCH_SCHEMA};
    use crate::usage::UsageSpoolCursor;
    use base64::Engine;
    use sha2::{Digest, Sha256};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use uuid::Uuid;

    async fn spawn_raw_server(status_line: &str, body: &str) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let status_line = status_line.to_string();
        let body = body.to_string();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0_u8; 8192];
            let _ = stream.read(&mut buf).await;
            let response = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        address
    }

    fn sample_batch(gateway_id: Uuid, batch_id: Uuid, cursor: UsageSpoolCursor) -> UsageIngestBatch {
        let payload = br#"{"kind":"x"}"#;
        UsageIngestBatch {
            schema: USAGE_INGEST_BATCH_SCHEMA.to_string(),
            gateway_id,
            batch_id,
            after: None,
            records: vec![UsageIngestRecord {
                cursor,
                event_id: Uuid::new_v4(),
                payload_base64: base64::engine::general_purpose::STANDARD.encode(payload),
                payload_sha256: format!("{:x}", Sha256::digest(payload)),
            }],
        }
    }

    #[tokio::test]
    async fn http_transport_posts_batch_and_parses_receipt() {
        let gateway_id = Uuid::new_v4();
        let batch_id = Uuid::new_v4();
        let cursor = UsageSpoolCursor {
            boot_epoch: Uuid::new_v4(),
            sequence: 3,
        };
        let body = serde_json::json!({
            "schema": USAGE_INGEST_ACK_SCHEMA,
            "gateway_id": gateway_id,
            "batch_id": batch_id,
            "acknowledged_through": {
                "boot_epoch": cursor.boot_epoch,
                "sequence": cursor.sequence,
            }
        })
        .to_string();
        let address = spawn_raw_server("HTTP/1.1 200 OK", &body).await;
        let transport = HttpUsageCloudTransport::new(
            format!("http://{address}/v1/inference-control/usage-batches"),
            "test-token".into(),
        )
        .unwrap();
        let batch = sample_batch(gateway_id, batch_id, cursor);
        let ack = transport.submit_batch(batch.clone()).await.unwrap();
        ack.validate_against_batch(&batch).unwrap();
        assert_eq!(ack.acknowledged_through, Some(cursor));
    }

    #[tokio::test]
    async fn http_transport_rejects_non_ok_status_without_parsing_body() {
        let address = spawn_raw_server("HTTP/1.1 503 Service Unavailable", "not-json").await;
        let transport = HttpUsageCloudTransport::new(
            format!("http://{address}/v1/inference-control/usage-batches"),
            "test-token".into(),
        )
        .unwrap();
        let batch = sample_batch(
            Uuid::new_v4(),
            Uuid::new_v4(),
            UsageSpoolCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
            },
        );
        assert!(matches!(
            transport.submit_batch(batch).await,
            Err(UsageIngestError::Transport { .. })
        ));
    }

    #[tokio::test]
    async fn http_transport_rejects_malformed_receipt_json() {
        let address = spawn_raw_server("HTTP/1.1 200 OK", "{not-json").await;
        let transport = HttpUsageCloudTransport::new(
            format!("http://{address}/v1/inference-control/usage-batches"),
            "test-token".into(),
        )
        .unwrap();
        let batch = sample_batch(
            Uuid::new_v4(),
            Uuid::new_v4(),
            UsageSpoolCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
            },
        );
        assert!(matches!(
            transport.submit_batch(batch).await,
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[tokio::test]
    async fn http_transport_rejects_wrong_receipt_schema_and_unknown_fields() {
        let gateway_id = Uuid::new_v4();
        let batch_id = Uuid::new_v4();
        let wrong_schema = serde_json::json!({
            "schema": "a3s.cloud.usage-ingest-ack.v1",
            "gateway_id": gateway_id,
            "batch_id": batch_id,
        })
        .to_string();
        let address = spawn_raw_server("HTTP/1.1 200 OK", &wrong_schema).await;
        let transport = HttpUsageCloudTransport::new(
            format!("http://{address}/v1/inference-control/usage-batches"),
            "token".into(),
        )
        .unwrap();
        let batch = sample_batch(
            gateway_id,
            batch_id,
            UsageSpoolCursor {
                boot_epoch: Uuid::new_v4(),
                sequence: 1,
            },
        );
        assert!(matches!(
            transport.submit_batch(batch.clone()).await,
            Err(UsageIngestError::Contract { .. })
        ));

        let unknown_field = serde_json::json!({
            "schema": USAGE_INGEST_ACK_SCHEMA,
            "gateway_id": gateway_id,
            "batch_id": batch_id,
            "prompt": "must-not-pass",
        })
        .to_string();
        let address = spawn_raw_server("HTTP/1.1 200 OK", &unknown_field).await;
        let transport = HttpUsageCloudTransport::new(
            format!("http://{address}/v1/inference-control/usage-batches"),
            "token".into(),
        )
        .unwrap();
        assert!(matches!(
            transport.submit_batch(batch).await,
            Err(UsageIngestError::Contract { .. })
        ));
    }

    #[test]
    fn rejects_empty_endpoint_or_token() {
        assert!(HttpUsageCloudTransport::new(String::new(), "t".into()).is_err());
        assert!(HttpUsageCloudTransport::new("http://example".into(), String::new()).is_err());
    }
}
