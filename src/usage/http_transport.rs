//! HTTP transport for the frozen Gateway→Cloud usage ingest contract.

use super::cloud_ingest::{
    UsageCloudTransport, UsageIngestAck, UsageIngestBatch, UsageIngestError,
    USAGE_INGEST_ACK_SCHEMA,
};
use reqwest::StatusCode;
use std::path::Path;
use std::time::Duration;

/// How Gateway authenticates to Cloud usage ingest.
#[derive(Debug, Clone)]
pub(crate) enum UsageCloudAuth {
    /// Transitional bearer token (fixtures / migration). Prefer [`Self::Mtls`].
    Bearer { token: String },
    /// Node-control-compatible client certificate identity.
    Mtls {
        identity_pem: Vec<u8>,
        server_ca_pem: Vec<u8>,
    },
}

/// Authenticated HTTPS client that posts usage batches to Cloud.
pub(crate) struct HttpUsageCloudTransport {
    client: reqwest::Client,
    endpoint: String,
    auth: UsageCloudAuth,
}

impl HttpUsageCloudTransport {
    pub(crate) fn new(endpoint: String, bearer_token: String) -> Result<Self, UsageIngestError> {
        Self::with_auth(
            endpoint,
            UsageCloudAuth::Bearer {
                token: bearer_token,
            },
        )
    }

    pub(crate) fn with_mtls_files(
        endpoint: String,
        identity_file: &Path,
        server_ca_file: &Path,
    ) -> Result<Self, UsageIngestError> {
        let identity_pem =
            std::fs::read(identity_file).map_err(|error| UsageIngestError::Contract {
                reason: format!(
                    "could not read cloud ingest client identity {}: {error}",
                    identity_file.display()
                ),
            })?;
        let server_ca_pem =
            std::fs::read(server_ca_file).map_err(|error| UsageIngestError::Contract {
                reason: format!(
                    "could not read cloud ingest server CA {}: {error}",
                    server_ca_file.display()
                ),
            })?;
        Self::with_auth(
            endpoint,
            UsageCloudAuth::Mtls {
                identity_pem,
                server_ca_pem,
            },
        )
    }

    pub(crate) fn with_auth(
        endpoint: String,
        auth: UsageCloudAuth,
    ) -> Result<Self, UsageIngestError> {
        if endpoint.trim().is_empty() {
            return Err(UsageIngestError::Contract {
                reason: "usage ingest endpoint must not be empty".to_string(),
            });
        }
        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("a3s-gateway/", env!("CARGO_PKG_VERSION")))
            .redirect(reqwest::redirect::Policy::none())
            .referer(false);
        match &auth {
            UsageCloudAuth::Bearer { token } => {
                if token.is_empty() {
                    return Err(UsageIngestError::Contract {
                        reason: "usage ingest bearer token must not be empty".to_string(),
                    });
                }
            }
            UsageCloudAuth::Mtls {
                identity_pem,
                server_ca_pem,
            } => {
                if identity_pem.is_empty() {
                    return Err(UsageIngestError::Contract {
                        reason: "usage ingest mTLS client identity must not be empty".to_string(),
                    });
                }
                if server_ca_pem.is_empty() {
                    return Err(UsageIngestError::Contract {
                        reason: "usage ingest mTLS server CA must not be empty".to_string(),
                    });
                }
                let identity = reqwest::Identity::from_pem(identity_pem).map_err(|error| {
                    UsageIngestError::Contract {
                        reason: format!("usage ingest mTLS client identity is invalid: {error}"),
                    }
                })?;
                let roots =
                    reqwest::Certificate::from_pem_bundle(server_ca_pem).map_err(|error| {
                        UsageIngestError::Contract {
                            reason: format!("usage ingest mTLS server CA is invalid: {error}"),
                        }
                    })?;
                if roots.is_empty() {
                    return Err(UsageIngestError::Contract {
                        reason: "usage ingest mTLS server CA bundle is empty".to_string(),
                    });
                }
                builder = builder
                    .use_rustls_tls()
                    .tls_built_in_root_certs(false)
                    .identity(identity);
                for root in roots {
                    builder = builder.add_root_certificate(root);
                }
            }
        }
        let client = builder
            .build()
            .map_err(|error| UsageIngestError::Transport {
                reason: error.to_string(),
            })?;
        Ok(Self {
            client,
            endpoint,
            auth,
        })
    }
}

#[async_trait::async_trait]
impl UsageCloudTransport for HttpUsageCloudTransport {
    async fn submit_batch(
        &self,
        batch: UsageIngestBatch,
    ) -> Result<UsageIngestAck, UsageIngestError> {
        let mut request = self
            .client
            .post(&self.endpoint)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(&batch);
        if let UsageCloudAuth::Bearer { token } = &self.auth {
            request = request.bearer_auth(token);
        }
        let response = request
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

    fn sample_batch(
        gateway_id: Uuid,
        batch_id: Uuid,
        cursor: UsageSpoolCursor,
    ) -> UsageIngestBatch {
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

    #[test]
    fn rejects_empty_mtls_material() {
        assert!(HttpUsageCloudTransport::with_auth(
            "https://cloud.example/v1/inference-control/usage-batches".into(),
            UsageCloudAuth::Mtls {
                identity_pem: Vec::new(),
                server_ca_pem: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                    .to_vec(),
            },
        )
        .is_err());
        assert!(HttpUsageCloudTransport::with_auth(
            "https://cloud.example/v1/inference-control/usage-batches".into(),
            UsageCloudAuth::Mtls {
                identity_pem: b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n"
                    .to_vec(),
                server_ca_pem: Vec::new(),
            },
        )
        .is_err());
    }
}
