//! Entrypoint configuration — network listeners

use serde::{Deserialize, Serialize};

/// Protocol type for an entrypoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum Protocol {
    /// HTTP/HTTPS protocol (default)
    #[default]
    Http,
    /// Raw TCP protocol
    Tcp,
    /// UDP protocol
    Udp,
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

    /// Maximum concurrent TCP connections (for TCP entrypoints)
    #[serde(default)]
    pub max_connections: Option<u32>,

    /// IP allowlist for TCP entrypoints (CIDR or single IP)
    #[serde(default)]
    pub tcp_allowed_ips: Vec<String>,

    /// Session timeout for UDP entrypoints in seconds (default: 30)
    #[serde(default)]
    pub udp_session_timeout_secs: Option<u64>,

    /// Maximum concurrent UDP sessions (default: 10000)
    #[serde(default)]
    pub udp_max_sessions: Option<usize>,
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
    fn test_entrypoint_tcp_with_filter() {
        let toml = r#"
            address = "0.0.0.0:9000"
            protocol = "tcp"
            max_connections = 1000
            tcp_allowed_ips = ["10.0.0.0/8", "192.168.1.1"]
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.protocol, Protocol::Tcp);
        assert_eq!(ep.max_connections.unwrap(), 1000);
        assert_eq!(ep.tcp_allowed_ips.len(), 2);
    }

    #[test]
    fn test_entrypoint_defaults_no_tcp_filter() {
        let toml = r#"
            address = "0.0.0.0:80"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert!(ep.max_connections.is_none());
        assert!(ep.tcp_allowed_ips.is_empty());
    }

    #[test]
    fn test_entrypoint_udp_with_config() {
        let toml = r#"
            address = "0.0.0.0:9001"
            protocol = "udp"
            udp_session_timeout_secs = 60
            udp_max_sessions = 5000
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
        assert_eq!(ep.udp_session_timeout_secs, Some(60));
        assert_eq!(ep.udp_max_sessions, Some(5000));
    }

    #[test]
    fn test_entrypoint_udp_defaults() {
        let toml = r#"
            address = "0.0.0.0:9001"
            protocol = "udp"
        "#;
        let ep: EntrypointConfig = toml::from_str(toml).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
        assert!(ep.udp_session_timeout_secs.is_none());
        assert!(ep.udp_max_sessions.is_none());
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
