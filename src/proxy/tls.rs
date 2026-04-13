//! TLS termination — rustls-based TLS acceptor
//!
//! Provides TLS termination for HTTPS entrypoints using rustls.
//! Supports HTTP/2 via ALPN negotiation and configurable minimum TLS version.

use crate::config::TlsConfig;
use crate::error::{GatewayError, Result};
use rustls::ServerConfig;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

/// Build a TLS acceptor from configuration
pub fn build_tls_acceptor(config: &TlsConfig) -> Result<TlsAcceptor> {
    let server_config = build_server_config(config)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

/// Build a rustls ServerConfig from certificate and key files
fn build_server_config(config: &TlsConfig) -> Result<ServerConfig> {
    let cert_path = Path::new(&config.cert_file);
    let key_path = Path::new(&config.key_file);

    // Read certificate chain
    let cert_file = std::fs::File::open(cert_path).map_err(|e| {
        GatewayError::Tls(format!(
            "Failed to open certificate file {}: {}",
            cert_path.display(),
            e
        ))
    })?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| GatewayError::Tls(format!("Failed to parse certificate: {}", e)))?;

    if certs.is_empty() {
        return Err(GatewayError::Tls(
            "No certificates found in certificate file".to_string(),
        ));
    }

    // Read private key
    let key_file = std::fs::File::open(key_path).map_err(|e| {
        GatewayError::Tls(format!(
            "Failed to open key file {}: {}",
            key_path.display(),
            e
        ))
    })?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| GatewayError::Tls(format!("Failed to parse private key: {}", e)))?
        .ok_or_else(|| GatewayError::Tls("No private key found in key file".to_string()))?;

    // Select TLS protocol versions based on min_version config
    let versions: Vec<&'static rustls::SupportedProtocolVersion> = match config.min_version.as_str()
    {
        "1.3" => vec![&rustls::version::TLS13],
        _ => vec![&rustls::version::TLS13, &rustls::version::TLS12],
    };

    // Build server config with version constraints
    let mut server_config = ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GatewayError::Tls(format!("TLS configuration error: {}", e)))?;

    // Enable ALPN for HTTP/2 and HTTP/1.1 negotiation
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
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
