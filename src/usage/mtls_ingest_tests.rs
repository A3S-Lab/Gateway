//! First-principles mTLS usage-ingest recovery against a Cloud-shaped ledger.
//!
//! This is not a provisioned live Cloud deployment. It proves Gateway's mTLS
//! transport and uploader recover against a TLS endpoint that requires a client
//! certificate and speaks the frozen usage-batch / receipt contract.

use super::cloud_ingest::UsageCloudUploader;
use super::http_transport::HttpUsageCloudTransport;
use super::ledger_double::InMemoryUsageLedger;
use super::{UsageSpool, UsageSpoolOptions};
use crate::usage::cloud_ingest::{UsageCloudTransport, UsageIngestBatch, UsageIngestError};
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::io::BufReader;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const CA_CERT: &str = include_str!("../../tests/fixtures/usage_mtls_ca.pem");
const SERVER_CERT: &str = include_str!("../../tests/fixtures/usage_mtls_server.pem");
const SERVER_KEY: &str = include_str!("../../tests/fixtures/usage_mtls_server.key");
const CLIENT_CERT: &str = include_str!("../../tests/fixtures/usage_mtls_client.pem");
const CLIENT_KEY: &str = include_str!("../../tests/fixtures/usage_mtls_client.key");

struct UsageMtlsFixture {
    _dir: tempfile::TempDir,
    identity_file: std::path::PathBuf,
    server_ca_file: std::path::PathBuf,
    server_cert_pem: Vec<u8>,
    server_key_pem: Vec<u8>,
    client_ca_pem: Vec<u8>,
}

fn usage_mtls_fixture() -> UsageMtlsFixture {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let identity_file = dir.path().join("client-identity.pem");
    let server_ca_file = dir.path().join("server-ca.crt");
    std::fs::write(&server_ca_file, CA_CERT).unwrap();
    let mut identity = CLIENT_CERT.as_bytes().to_vec();
    identity.extend_from_slice(CLIENT_KEY.as_bytes());
    std::fs::write(&identity_file, &identity).unwrap();
    UsageMtlsFixture {
        identity_file,
        server_ca_file,
        server_cert_pem: SERVER_CERT.as_bytes().to_vec(),
        server_key_pem: SERVER_KEY.as_bytes().to_vec(),
        client_ca_pem: CA_CERT.as_bytes().to_vec(),
        _dir: dir,
    }
}

fn http11_mtls_acceptor(fixture: &UsageMtlsFixture) -> TlsAcceptor {
    let certs = rustls_pemfile::certs(&mut BufReader::new(fixture.server_cert_pem.as_slice()))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut BufReader::new(fixture.server_key_pem.as_slice()))
        .unwrap()
        .expect("server key");
    let mut roots = RootCertStore::empty();
    let client_cas = rustls_pemfile::certs(&mut BufReader::new(fixture.client_ca_pem.as_slice()))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .unwrap();
    roots.add_parsable_certificates(client_cas);
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .unwrap();
    let mut server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .unwrap();
    // Raw HTTP/1.1 fixture — do not advertise h2.
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(server_config))
}

async fn spawn_mtls_usage_ledger(
    fixture: &UsageMtlsFixture,
    fail_first: usize,
) -> (u16, Arc<AtomicUsize>, Arc<InMemoryUsageLedger>) {
    let acceptor = http11_mtls_acceptor(fixture);
    let ledger = Arc::new(InMemoryUsageLedger::new());
    let attempts = Arc::new(AtomicUsize::new(0));
    let attempts_for_task = attempts.clone();
    let ledger_for_task = ledger.clone();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let Ok(mut tls) = acceptor.accept(stream).await else {
                continue;
            };
            let attempt = attempts_for_task.fetch_add(1, Ordering::SeqCst) + 1;
            let mut buf = vec![0_u8; 32_768];
            let n = tls.read(&mut buf).await.unwrap_or(0);
            let request = &buf[..n];
            let request_text = String::from_utf8_lossy(request);
            assert!(
                !request_text.to_ascii_lowercase().contains("authorization:"),
                "mTLS usage ingest must not send bearer Authorization"
            );
            if attempt <= fail_first {
                let response =
                    "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = tls.write_all(response.as_bytes()).await;
                continue;
            }
            let body_start = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
                .unwrap_or(request.len());
            let batch: UsageIngestBatch = match serde_json::from_slice(&request[body_start..]) {
                Ok(batch) => batch,
                Err(_) => {
                    let response =
                        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls.write_all(response.as_bytes()).await;
                    continue;
                }
            };
            let ack = match ledger_for_task.submit_batch(batch).await {
                Ok(ack) => ack,
                Err(UsageIngestError::Contract { reason }) => {
                    let body = reason;
                    let response = format!(
                        "HTTP/1.1 409 Conflict\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = tls.write_all(response.as_bytes()).await;
                    continue;
                }
                Err(_) => {
                    let response =
                        "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    let _ = tls.write_all(response.as_bytes()).await;
                    continue;
                }
            };
            let body = serde_json::to_string(&ack).unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = tls.write_all(response.as_bytes()).await;
        }
    });
    (port, attempts, ledger)
}

#[tokio::test]
async fn mtls_transport_recovers_after_transient_cloud_failure() {
    let fixture = usage_mtls_fixture();
    let (port, attempts, ledger) = spawn_mtls_usage_ledger(&fixture, 1).await;
    let endpoint = format!("https://localhost:{port}/v1/inference-control/usage-batches");
    let transport = HttpUsageCloudTransport::with_mtls_files(
        endpoint,
        &fixture.identity_file,
        &fixture.server_ca_file,
    )
    .unwrap();

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
        .append(Uuid::new_v4(), br#"{"kind":"request_started"}"#)
        .await
        .unwrap();

    let uploader = UsageCloudUploader::new(spool.clone(), gateway_id, 8);
    let first = uploader.upload_once(&transport).await;
    assert!(first.is_err(), "expected first failure, got {first:?}");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let second = uploader.upload_once(&transport).await;
    assert!(
        second.is_ok(),
        "expected recovery, got {second:?}; attempts={}",
        attempts.load(Ordering::SeqCst)
    );
    assert!(attempts.load(Ordering::SeqCst) >= 2);
    assert_eq!(
        ledger.watermark(gateway_id).map(|cursor| cursor.sequence),
        Some(1)
    );
    assert!(spool.status().acknowledged_through.is_some());
}

#[tokio::test]
async fn bearer_transport_cannot_satisfy_mtls_required_usage_endpoint() {
    let fixture = usage_mtls_fixture();
    let (port, _, _) = spawn_mtls_usage_ledger(&fixture, 0).await;
    let endpoint = format!("https://localhost:{port}/v1/inference-control/usage-batches");
    let transport = HttpUsageCloudTransport::new(endpoint, "fixture-token".into()).unwrap();

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
        .append(Uuid::new_v4(), br#"{"kind":"request_started"}"#)
        .await
        .unwrap();
    let uploader = UsageCloudUploader::new(spool, gateway_id, 8);
    assert!(uploader.upload_once(&transport).await.is_err());
}
