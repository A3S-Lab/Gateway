//! Entrypoint configuration — network listeners

use serde::{Deserialize, Serialize};

/// Protocol type for an entrypoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// HTTP/HTTPS protocol (default)
    Http,
    /// Raw TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
}

impl Default for Protocol {
    fn default() -> Self {
        Self::Http
    }
}

/// Entrypoint configuration — a named network listener
///
/// # Example
///
/// ```toml
/// [entrypoints.websecure]
/// address = "0.0.0.0:443"
/// protocol = "http"
/// [entrypoints.websecure.tls]
/// cert_file = "/etc/certs/cert.pem"
/// key_file = "/etc/certs/key.pem"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntrypointConfig {
    /// Listen address in "host:port" format
    pub address: String,

    /// Protocol type (http, tcp, udp)
    #[serde(default)]
    pub protocol: Protocol,

    /// Optional TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

/// TLS configuration for an entrypoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate PEM file
    pub cert_file: String,

    /// Path to the private key PEM file
    pub key_file: String,

    /// Enable ACME/Let's Encrypt automatic certificate management
    #[serde(default)]
    pub acme: bool,

    /// Minimum TLS version (default: 1.2)
    #[serde(default = "default_min_tls_version")]
    pub min_version: String,
}

fn default_min_tls_version() -> String {
    "1.2".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_default() {
        assert_eq!(Protocol::default(), Protocol::Http);
    }

    #[test]
    fn test_protocol_serialization() {
        let json = serde_json::to_string(&Protocol::Tcp).unwrap();
        assert_eq!(json, "\"tcp\"");
        let parsed: Protocol = serde_json::from_str("\"udp\"").unwrap();
        assert_eq!(parsed, Protocol::Udp);
    }

    #[test]
    fn test_entrypoint_parse() {
        let toml = r#"
            address = "0.0.0.0:80"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.address, "0.0.0.0:80");
        assert_eq!(ep.protocol, Protocol::Http);
        assert!(ep.tls.is_none());
    }

    #[test]
    fn test_entrypoint_with_tls() {
        let toml = r#"
            address = "0.0.0.0:443"
            [tls]
            cert_file = "/etc/certs/cert.pem"
            key_file = "/etc/certs/key.pem"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        let tls = ep.tls.unwrap();
        assert_eq!(tls.cert_file, "/etc/certs/cert.pem");
        assert_eq!(tls.key_file, "/etc/certs/key.pem");
        assert!(!tls.acme);
        assert_eq!(tls.min_version, "1.2");
    }

    #[test]
    fn test_entrypoint_tcp_protocol() {
        let toml = r#"
            address = "0.0.0.0:9000"
            protocol = "tcp"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_entrypoint_udp_protocol() {
        let toml = r#"
            address = "0.0.0.0:9001"
            protocol = "udp"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
    }

    #[test]
    fn test_tls_acme_enabled() {
        let toml = r#"
            cert_file = "/tmp/cert.pem"
            key_file = "/tmp/key.pem"
            acme = true
            min_version = "1.3"
        "#;
        let tls: TlsConfig = toml::from_str(toml).unwrap();
        assert!(tls.acme);
        assert_eq!(tls.min_version, "1.3");
    }
}
