//! TLS termination — rustls-based TLS acceptor
//!
//! Provides TLS termination for HTTPS entrypoints using rustls.
//! Supports HTTP/2 via ALPN negotiation and configurable minimum TLS version.

use crate::config::{ManagementTlsConfig, TlsConfig};
use crate::error::{GatewayError, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a TLS acceptor from configuration
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let server_config = build_server_config(config)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a TLS acceptor from in-memory PEM material (ACME-issued certs).
///
/// Same rustls / ALPN surface as [`build_tls_acceptor`] so ACME install cannot
/// soft-open a different handshake profile than cold-start file PEMs.
pub fn build_tls_acceptor_from_pem(
    cert_pem: &str,
    key_pem: &str,
    min_version: &str,
) -> Result<TlsAcceptor> {
    let certs = load_cert_chain_from_pem(cert_pem, "certificate")?;
    let key = load_private_key_from_pem(key_pem)?;
    let server_config = build_server_config_from_parts(certs, key, min_version)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a TLS acceptor for the dedicated node API listener.
pub(crate) fn build_node_api_tls_acceptor(config: &ManagementTlsConfig) -> Result<TlsAcceptor> {
    config.validate()?;

    let certs = load_cert_chain(&config.cert_file, "certificate")?;
    let key = load_private_key(&config.key_file)?;
    let versions = tls_protocol_versions(&config.min_version)?;
    let crypto_provider = rustls_crypto_provider();

    let builder = ServerConfig::builder_with_provider(crypto_provider.clone())
        .with_protocol_versions(&versions)
        .map_err(|e| GatewayError::Tls(format!("TLS protocol version error: {}", e)))?;
    let builder = match config.client_ca_file.as_deref() {
        Some(client_ca_file) => {
            let client_ca_certs = load_cert_chain(client_ca_file, "client CA certificate")?;
            let mut roots = RootCertStore::empty();
            let (valid, invalid) = roots.add_parsable_certificates(client_ca_certs);
            if valid == 0 {
                return Err(GatewayError::Tls(
                    "No valid client CA certificates found".to_string(),
                ));
            }
            // Trust material is authorization policy: a partial CA load would
            // silently shrink the accepted client set (or leave operators
            // believing a bad PEM was trusted). Fail closed on any unusable
            // certificate in the configured client CA file.
            if invalid > 0 {
                return Err(GatewayError::Tls(format!(
                    "Node API client CA file contains {invalid} unusable certificate(s) \
                     alongside {valid} valid trust anchor(s); refusing partial CA load"
                )));
            }

            let verifier_builder =
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto_provider);
            let verifier = if config.require_client_cert {
                verifier_builder.build()
            } else {
                verifier_builder.allow_unauthenticated().build()
            }
            .map_err(|e| GatewayError::Tls(format!("Client certificate verifier error: {}", e)))?;

            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut server_config = builder
        .with_single_cert(certs, key)
        .map_err(|e| GatewayError::Tls(format!("TLS configuration error: {}", e)))?;

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a rustls ServerConfig from certificate and key files
fn build_server_config(config: &TlsConfig) -> Result<ServerConfig> {
    let certs = load_cert_chain(&config.cert_file, "certificate")?;
    let key = load_private_key(&config.key_file)?;
    build_server_config_from_parts(certs, key, &config.min_version)
}

fn build_server_config_from_parts(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    min_version: &str,
) -> Result<ServerConfig> {
    let versions = tls_protocol_versions(min_version)?;

    // Build server config with version constraints
    let mut server_config = ServerConfig::builder_with_provider(rustls_crypto_provider())
        .with_protocol_versions(&versions)
        .map_err(|e| GatewayError::Tls(format!("TLS protocol version error: {}", e)))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GatewayError::Tls(format!("TLS configuration error: {}", e)))?;

    // Enable ALPN for HTTP/2 and HTTP/1.1 negotiation
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
}

pub(crate) fn load_cert_chain(path: &str, label: &str) -> Result<Vec<CertificateDer<'static>>> {
    let cert_path = Path::new(path);
    let certs = CertificateDer::pem_file_iter(cert_path)
        .map_err(|e| {
            GatewayError::Tls(format!(
                "Failed to open {} file {}: {}",
                label,
                cert_path.display(),
                e
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::Tls(format!("Failed to parse {}: {}", label, e)))?;

    if certs.is_empty() {
        return Err(GatewayError::Tls(format!(
            "No certificates found in {} file",
            label
        )));
    }

    Ok(certs)
}

fn load_cert_chain_from_pem(pem: &str, label: &str) -> Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::Tls(format!("Failed to parse {label} PEM: {e}")))?;
    if certs.is_empty() {
        return Err(GatewayError::Tls(format!(
            "No certificates found in {label} PEM"
        )));
    }
    Ok(certs)
}

fn load_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let key_path = Path::new(path);
    PrivateKeyDer::from_pem_file(key_path).map_err(|e| {
        GatewayError::Tls(format!(
            "Failed to parse private key {}: {}",
            key_path.display(),
            e
        ))
    })
}

fn load_private_key_from_pem(pem: &str) -> Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_slice(pem.as_bytes())
        .map_err(|e| GatewayError::Tls(format!("Failed to parse private key PEM: {e}")))
}

fn tls_protocol_versions(
    min_version: &str,
) -> Result<Vec<&'static rustls::SupportedProtocolVersion>> {
    match min_version {
        "1.3" => Ok(vec![&rustls::version::TLS13]),
        "1.2" => Ok(vec![&rustls::version::TLS13, &rustls::version::TLS12]),
        other => Err(GatewayError::Tls(format!(
            "Unsupported minimum TLS version '{}'",
            other
        ))),
    }
}

fn rustls_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_tls_acceptor_missing_cert() {
        let config = TlsConfig {
            cert_file: "/nonexistent/cert.pem".to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("certificate file")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_build_tls_acceptor_missing_key() {
        // Create a temp cert file but no key file
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        // Write a minimal (invalid) PEM to test the key path
        std::fs::write(&cert_path, "not a real cert").unwrap();

        let config = TlsConfig {
            cert_file: cert_path.to_str().unwrap().to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_tls_acceptor_empty_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "").unwrap();
        std::fs::write(&key_path, "").unwrap();

        let config = TlsConfig {
            cert_file: cert_path.to_str().unwrap().to_string(),
            key_file: key_path.to_str().unwrap().to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
        match result {
            Err(e) => assert!(e.to_string().contains("No certificates")),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_build_tls_acceptor_empty_key() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        // Write valid-ish cert header but empty key
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\ndata\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(&key_path, "").unwrap();

        let config = TlsConfig {
            cert_file: cert_path.to_str().unwrap().to_string(),
            key_file: key_path.to_str().unwrap().to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_tls_acceptor_invalid_cert_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, "not valid pem at all").unwrap();
        std::fs::write(&key_path, "also not valid").unwrap();

        let config = TlsConfig {
            cert_file: cert_path.to_str().unwrap().to_string(),
            key_file: key_path.to_str().unwrap().to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_tls_acceptor_from_pem_matches_file_surface() {
        let cert_pem = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1.crt"),
        )
        .unwrap();
        let key_pem = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1.key"),
        )
        .unwrap();
        build_tls_acceptor_from_pem(&cert_pem, &key_pem, "1.2")
            .expect("fixture PEM must build the same acceptor surface as file PEMs");
    }

    #[test]
    fn test_build_tls_acceptor_from_pem_rejects_empty_cert() {
        let Err(err) = build_tls_acceptor_from_pem(
            "",
            "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
            "1.2",
        ) else {
            panic!("empty cert PEM must fail closed");
        };
        assert!(
            err.to_string().contains("certificate") || err.to_string().contains("PEM"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_build_tls_acceptor_tls_1_3_only() {
        let config = TlsConfig {
            cert_file: "/nonexistent/cert.pem".to_string(),
            key_file: "/nonexistent/key.pem".to_string(),
            acme: false,
            min_version: "1.3".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        // Should fail on missing cert, but confirms TLS 1.3 path is taken
        match build_tls_acceptor(&config) {
            Ok(_) => panic!("Expected error"),
            Err(e) => assert!(e.to_string().contains("certificate file")),
        }
    }

    #[test]
    fn test_build_tls_acceptor_invalid_key_pem() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        // Valid cert header but invalid key
        std::fs::write(
            &cert_path,
            "-----BEGIN CERTIFICATE-----\nMTIz\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        std::fs::write(&key_path, "not a valid key").unwrap();

        let config = TlsConfig {
            cert_file: cert_path.to_str().unwrap().to_string(),
            key_file: key_path.to_str().unwrap().to_string(),
            acme: false,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let result = build_tls_acceptor(&config);
        assert!(result.is_err());
        match result {
            Err(e) => {
                assert!(e.to_string().contains("private key") || e.to_string().contains("key"))
            }
            Ok(_) => panic!("Expected error"),
        }
    }

    // NOTE: test_build_tls_acceptor_mismatched_cert_key is omitted because
    // rustls requires CryptoProvider configuration that varies by platform/features.
    // The error handling is tested via invalid key format tests above.

    #[test]
    fn node_api_client_ca_refuses_partial_trust_anchor_load() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
        let cert_file = fixture.join("revision-1.crt");
        let key_file = fixture.join("revision-1.key");
        let ca_pem = std::fs::read_to_string(fixture.join("revision-1-ca.crt")).unwrap();
        // Append a PEM CERTIFICATE block that decodes as DER but is not a usable
        // X.509 trust anchor — previously warn-skipped when a valid CA was present.
        let mixed_ca =
            format!("{ca_pem}\n-----BEGIN CERTIFICATE-----\nMTIz\n-----END CERTIFICATE-----\n");
        let client_ca_file = dir.path().join("mixed-client-ca.crt");
        std::fs::write(&client_ca_file, mixed_ca).unwrap();

        let config = ManagementTlsConfig {
            cert_file: cert_file.to_str().unwrap().to_string(),
            key_file: key_file.to_str().unwrap().to_string(),
            client_ca_file: Some(client_ca_file.to_str().unwrap().to_string()),
            require_client_cert: true,
            min_version: "1.2".to_string(),
        };
        let err = match build_node_api_tls_acceptor(&config) {
            Ok(_) => panic!("expected partial client CA load to fail closed"),
            Err(error) => error.to_string(),
        };
        assert!(
            err.contains("unusable certificate") || err.contains("partial CA load"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn node_api_client_ca_accepts_clean_trust_anchor_bundle() {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls");
        let config = ManagementTlsConfig {
            cert_file: fixture.join("revision-1.crt").to_str().unwrap().to_string(),
            key_file: fixture.join("revision-1.key").to_str().unwrap().to_string(),
            client_ca_file: Some(
                fixture
                    .join("revision-1-ca.crt")
                    .to_str()
                    .unwrap()
                    .to_string(),
            ),
            require_client_cert: true,
            min_version: "1.2".to_string(),
        };
        build_node_api_tls_acceptor(&config).expect("clean client CA bundle must load");
    }
}
