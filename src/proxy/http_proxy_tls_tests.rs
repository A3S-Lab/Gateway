use super::*;
use crate::config::TlsConfig;
use crate::proxy::tls::build_tls_acceptor;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use rustls::{ClientConfig, RootCertStore};
use std::convert::Infallible;
use std::io::Cursor;
use std::path::PathBuf;
use tokio::net::TcpListener;

fn tls_fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tls")
        .join(name)
}

async fn spawn_tls_backend() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor = build_tls_acceptor(&TlsConfig {
        cert_file: tls_fixture("revision-1.crt").display().to_string(),
        key_file: tls_fixture("revision-1.key").display().to_string(),
        acme: false,
        min_version: "1.2".to_string(),
        acme_email: None,
        acme_domains: Vec::new(),
        acme_staging: false,
        acme_storage_path: None,
    })
    .unwrap();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let Ok(stream) = acceptor.accept(stream).await else {
            return;
        };
        let service = service_fn(|request: http::Request<hyper::body::Incoming>| async move {
            assert_eq!(request.uri().path(), "/secure");
            let version = if request.version() == http::Version::HTTP_2 {
                "h2"
            } else {
                "http/1.1"
            };
            Ok::<_, Infallible>(
                http::Response::builder()
                    .header("x-upstream-version", version)
                    .body(Full::new(Bytes::from_static(b"secure")))
                    .unwrap(),
            )
        });
        ServerBuilder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await
            .unwrap();
    });

    address
}

fn fixture_tls_client_config() -> ClientConfig {
    let ca = std::fs::read(tls_fixture("revision-1-ca.crt")).unwrap();
    let mut roots = RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut Cursor::new(ca)) {
        roots.add(certificate.unwrap()).unwrap();
    }

    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth()
}

#[tokio::test]
async fn forwards_https_backend_over_alpn_http2() {
    let backend_address = spawn_tls_backend().await;
    let backend = Arc::new(Backend::new(format!("https://{backend_address}"), 1));
    let proxy = HttpProxy::with_tls_config(Duration::from_secs(5), fixture_tls_client_config());

    let response = proxy
        .forward_streaming_response_with_options(
            &backend,
            &http::Method::GET,
            &"/secure".parse().unwrap(),
            &http::HeaderMap::new(),
            Bytes::new(),
            ForwardOptions::default(),
        )
        .await
        .unwrap();

    assert_eq!(response.status, http::StatusCode::OK);
    assert_eq!(response.headers["x-upstream-version"], "h2");
    assert_eq!(
        response.body.collect().await.unwrap().to_bytes(),
        Bytes::from_static(b"secure")
    );
}

#[tokio::test]
async fn rejects_an_untrusted_https_backend_certificate() {
    let backend_address = spawn_tls_backend().await;
    let backend = Arc::new(Backend::new(format!("https://{backend_address}"), 1));
    let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

    let error = proxy
        .forward_streaming_response_with_options(
            &backend,
            &http::Method::GET,
            &"/secure".parse().unwrap(),
            &http::HeaderMap::new(),
            Bytes::new(),
            ForwardOptions::default(),
        )
        .await
        .err()
        .expect("the private test CA must not be trusted by default");

    assert!(matches!(error, GatewayError::UpstreamTransport(_)));
    assert_eq!(backend.connections(), 0);
}
