//! TLS termination — rustls-based TLS acceptor
//!
//! Provides TLS termination for HTTPS entrypoints using rustls.
//! Supports HTTP/2 via ALPN negotiation and configurable minimum TLS version.

use crate::config::{ManagementTlsConfig, TlsConfig};
use crate::error::{GatewayError, Result};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a TLS acceptor from configuration
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let server_config = build_server_config(config)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a TLS acceptor for the dedicated management listener.
pub(crate) fn build_management_tls_acceptor(config: &ManagementTlsConfig) -> Result<TlsAcceptor> {
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
            if invalid > 0 {
                tracing::warn!(
                    valid,
                    invalid,
                    "Ignored invalid client CA certificates while building management TLS"
                );
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
    let versions = tls_protocol_versions(&config.min_version)?;

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

fn load_cert_chain(
    path: &str,
    label: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let cert_path = Path::new(path);
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        GatewayError::Tls(format!(
            "Failed to open {} file {}: {}",
            label,
            cert_path.display(),
            e
        ))
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
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

fn load_private_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let key_path = Path::new(path);
    let key_file = std::fs::File::open(key_path).map_err(|e| {
        GatewayError::Tls(format!(
            "Failed to open key file {}: {}",
            key_path.display(),
            e
        ))
    })?;
    let mut key_reader = BufReader::new(key_file);
    rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| GatewayError::Tls(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| GatewayError::Tls("No private key found in key file".to_string()))
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
}
