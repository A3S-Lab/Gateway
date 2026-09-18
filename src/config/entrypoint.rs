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
/// ```acl
/// entrypoints "websecure" {
///   address  = "0.0.0.0:443"
///   protocol = "http"
///   tls {
///     cert_file = "/etc/certs/cert.pem"
///     key_file  = "/etc/certs/key.pem"
///   }
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// Whether inbound X-Forwarded-* headers come from a trusted proxy.
    /// Defaults to false so clients cannot spoof their apparent identity.
    #[serde(default)]
    pub trust_forwarded_headers: bool,
}

impl EntrypointConfig {
    /// Create a new HTTP entrypoint with the given listen address.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            protocol: Protocol::Http,
            tls: None,
            max_connections: None,
            tcp_allowed_ips: vec![],
            udp_session_timeout_secs: None,
            udp_max_sessions: None,
            trust_forwarded_headers: false,
        }
    }

    /// Whether this listener can apply the new transport policy without
    /// releasing its bound socket.
    pub(crate) fn can_reconfigure_in_place_from(&self, current: &Self) -> bool {
        self.address == current.address && self.protocol == current.protocol
    }

    fn reject_field_for_other_protocol(
        &self,
        name: &str,
        set: bool,
        field: &str,
        protocol: &str,
    ) -> crate::error::Result<()> {
        if !set {
            return Ok(());
        }
        Err(crate::error::GatewayError::Config(format!(
            "Entrypoint '{name}' sets {field}, which applies only to protocol {protocol}"
        )))
    }

    /// Structural listener policy checks that must fail closed at
    /// `config validate`, not only when the listener binds.
    ///
    /// Does not load TLS PEM material from disk — missing files are an
    /// environment concern at start. Zero UDP budgets, invalid TCP CIDRs,
    /// and ACME without email are ACL-shape errors.
    pub(crate) fn validate_listener_policy(&self, name: &str) -> crate::error::Result<()> {
        use crate::error::GatewayError;

        // A declared control the listener never reads is a soft-open: the
        // operator believes the limit, allowlist, or TLS handshake is in force.
        match self.protocol {
            Protocol::Http => {
                self.reject_field_for_other_protocol(
                    name,
                    self.max_connections.is_some(),
                    "max_connections",
                    "tcp",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    !self.tcp_allowed_ips.is_empty(),
                    "tcp_allowed_ips",
                    "tcp",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    self.udp_session_timeout_secs.is_some(),
                    "udp_session_timeout_secs",
                    "udp",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    self.udp_max_sessions.is_some(),
                    "udp_max_sessions",
                    "udp",
                )?;
            }
            Protocol::Tcp => {
                self.reject_field_for_other_protocol(name, self.tls.is_some(), "tls", "http")?;
                self.reject_field_for_other_protocol(
                    name,
                    self.trust_forwarded_headers,
                    "trust_forwarded_headers",
                    "http",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    self.udp_session_timeout_secs.is_some(),
                    "udp_session_timeout_secs",
                    "udp",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    self.udp_max_sessions.is_some(),
                    "udp_max_sessions",
                    "udp",
                )?;
            }
            Protocol::Udp => {
                self.reject_field_for_other_protocol(name, self.tls.is_some(), "tls", "http")?;
                self.reject_field_for_other_protocol(
                    name,
                    self.trust_forwarded_headers,
                    "trust_forwarded_headers",
                    "http",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    self.max_connections.is_some(),
                    "max_connections",
                    "tcp",
                )?;
                self.reject_field_for_other_protocol(
                    name,
                    !self.tcp_allowed_ips.is_empty(),
                    "tcp_allowed_ips",
                    "tcp",
                )?;
            }
        }

        if let Some(tls) = &self.tls {
            tls.validate_listener_policy(name)?;
        }

        match self.protocol {
            Protocol::Http => Ok(()),
            Protocol::Tcp => {
                crate::middleware::TcpFilter::new(self.max_connections, &self.tcp_allowed_ips)
                    .map(|_| ())
                    .map_err(|error| {
                        GatewayError::Config(format!("Entrypoint '{name}' TCP filter: {error}"))
                    })
            }
            Protocol::Udp => {
                let timeout_secs = self.udp_session_timeout_secs.unwrap_or(30);
                let max_sessions = self.udp_max_sessions.unwrap_or(10_000);
                if timeout_secs == 0 {
                    return Err(GatewayError::Config(format!(
                        "Entrypoint '{name}': udp_session_timeout_secs must be greater than zero"
                    )));
                }
                if max_sessions == 0 {
                    return Err(GatewayError::Config(format!(
                        "Entrypoint '{name}': udp_max_sessions must be greater than zero"
                    )));
                }
                Ok(())
            }
        }
    }
}

/// TLS configuration for an entrypoint
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

    /// ACME contact email (required when acme = true)
    #[serde(default)]
    pub acme_email: Option<String>,

    /// ACME domains (required when acme = true; defaults to Host rules if empty)
    #[serde(default)]
    pub acme_domains: Vec<String>,

    /// Use ACME staging environment (default: false)
    #[serde(default)]
    pub acme_staging: bool,

    /// ACME certificate storage path (default: /etc/gateway/acme)
    #[serde(default)]
    pub acme_storage_path: Option<String>,
}

fn default_min_tls_version() -> String {
    "1.2".to_string()
}

impl TlsConfig {
    /// Structural TLS/ACME checks for `config validate`.
    pub(crate) fn validate_listener_policy(&self, entrypoint: &str) -> crate::error::Result<()> {
        use crate::error::GatewayError;

        if self.cert_file.trim().is_empty() {
            return Err(GatewayError::Config(format!(
                "Entrypoint '{entrypoint}' TLS cert_file must not be empty"
            )));
        }
        if self.key_file.trim().is_empty() {
            return Err(GatewayError::Config(format!(
                "Entrypoint '{entrypoint}' TLS key_file must not be empty"
            )));
        }
        if !matches!(self.min_version.as_str(), "1.2" | "1.3") {
            return Err(GatewayError::Config(format!(
                "Entrypoint '{entrypoint}' TLS min_version must be '1.2' or '1.3', got '{}'",
                self.min_version
            )));
        }
        if self.acme {
            let email = self.acme_email.as_deref().unwrap_or("").trim();
            if email.is_empty() {
                return Err(GatewayError::Config(format!(
                    "Entrypoint '{entrypoint}' TLS acme requires acme_email"
                )));
            }
        }
        Ok(())
    }
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
        let acl = r#"
            address = "0.0.0.0:80"
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.address, "0.0.0.0:80");
        assert_eq!(ep.protocol, Protocol::Http);
        assert!(ep.tls.is_none());
    }

    #[test]
    fn test_entrypoint_with_tls() {
        let acl = r#"
            address = "0.0.0.0:443"
            tls {
                cert_file = "/etc/certs/cert.pem"
                key_file  = "/etc/certs/key.pem"
            }
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        let tls = ep.tls.unwrap();
        assert_eq!(tls.cert_file, "/etc/certs/cert.pem");
        assert_eq!(tls.key_file, "/etc/certs/key.pem");
        assert!(!tls.acme);
        assert_eq!(tls.min_version, "1.2");
    }

    #[test]
    fn test_entrypoint_tcp_protocol() {
        let acl = r#"
            address  = "0.0.0.0:9000"
            protocol = "tcp"
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.protocol, Protocol::Tcp);
    }

    #[test]
    fn test_entrypoint_udp_protocol() {
        let acl = r#"
            address  = "0.0.0.0:9001"
            protocol = "udp"
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
    }

    #[test]
    fn test_entrypoint_tcp_with_filter() {
        let acl = r#"
            address         = "0.0.0.0:9000"
            protocol        = "tcp"
            max_connections  = 1000
            tcp_allowed_ips  = ["10.0.0.0/8", "192.168.1.1"]
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.protocol, Protocol::Tcp);
        assert_eq!(ep.max_connections.unwrap(), 1000);
        assert_eq!(ep.tcp_allowed_ips.len(), 2);
    }

    #[test]
    fn test_entrypoint_defaults_no_tcp_filter() {
        let acl = r#"
            address = "0.0.0.0:80"
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert!(ep.max_connections.is_none());
        assert!(ep.tcp_allowed_ips.is_empty());
    }

    #[test]
    fn test_entrypoint_udp_with_config() {
        let acl = r#"
            address                  = "0.0.0.0:9001"
            protocol                 = "udp"
            udp_session_timeout_secs = 60
            udp_max_sessions         = 5000
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
        assert_eq!(ep.udp_session_timeout_secs, Some(60));
        assert_eq!(ep.udp_max_sessions, Some(5000));
    }

    #[test]
    fn test_entrypoint_udp_defaults() {
        let acl = r#"
            address  = "0.0.0.0:9001"
            protocol = "udp"
        "#;
        let ep: EntrypointConfig = crate::config::acl::parse_entrypoint_body(acl).unwrap();
        assert_eq!(ep.protocol, Protocol::Udp);
        assert!(ep.udp_session_timeout_secs.is_none());
        assert!(ep.udp_max_sessions.is_none());
    }

    #[test]
    fn test_udp_entrypoint_can_reconfigure_on_the_same_socket() {
        let current = EntrypointConfig {
            address: "127.0.0.1:5353".to_string(),
            protocol: Protocol::Udp,
            udp_session_timeout_secs: Some(30),
            udp_max_sessions: Some(100),
            ..EntrypointConfig::new("127.0.0.1:5353")
        };
        let mut next = current.clone();
        next.udp_session_timeout_secs = Some(10);
        next.udp_max_sessions = Some(200);

        assert!(next.can_reconfigure_in_place_from(&current));

        next.address = "127.0.0.1:5354".to_string();
        assert!(!next.can_reconfigure_in_place_from(&current));
    }

    #[test]
    fn test_tls_acme_enabled() {
        let acl = r#"
            cert_file   = "/tmp/cert.pem"
            key_file    = "/tmp/key.pem"
            acme        = true
            min_version = "1.3"
        "#;
        let tls: TlsConfig = crate::config::acl::parse_tls_body(acl).unwrap();
        assert!(tls.acme);
        assert_eq!(tls.min_version, "1.3");
    }

    #[test]
    fn udp_zero_session_timeout_fails_listener_policy() {
        let ep = EntrypointConfig {
            protocol: Protocol::Udp,
            udp_session_timeout_secs: Some(0),
            ..EntrypointConfig::new("127.0.0.1:5353")
        };
        let err = ep.validate_listener_policy("dns").unwrap_err().to_string();
        assert!(
            err.contains("udp_session_timeout_secs"),
            "zero UDP timeout must fail closed: {err}"
        );
    }

    #[test]
    fn udp_zero_max_sessions_fails_listener_policy() {
        let ep = EntrypointConfig {
            protocol: Protocol::Udp,
            udp_max_sessions: Some(0),
            ..EntrypointConfig::new("127.0.0.1:5353")
        };
        let err = ep.validate_listener_policy("dns").unwrap_err().to_string();
        assert!(
            err.contains("udp_max_sessions"),
            "zero UDP sessions must fail closed: {err}"
        );
    }

    #[test]
    fn tcp_invalid_allowed_ip_fails_listener_policy() {
        let ep = EntrypointConfig {
            protocol: Protocol::Tcp,
            tcp_allowed_ips: vec!["not-a-cidr".to_string()],
            ..EntrypointConfig::new("127.0.0.1:9000")
        };
        let err = ep
            .validate_listener_policy("plain")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("TCP filter") || err.contains("IP"),
            "invalid TCP allowlist must fail closed: {err}"
        );
    }

    #[test]
    fn http_tcp_allowlist_is_not_a_silent_noop() {
        let ep = EntrypointConfig {
            tcp_allowed_ips: vec!["10.0.0.0/8".to_string()],
            ..EntrypointConfig::new("127.0.0.1:8080")
        };
        let err = ep.validate_listener_policy("web").unwrap_err().to_string();
        assert!(
            err.contains("tcp_allowed_ips") && err.contains("protocol tcp"),
            "{err}"
        );
    }

    #[test]
    fn tcp_tls_is_not_a_silent_noop() {
        let ep = EntrypointConfig {
            protocol: Protocol::Tcp,
            tls: Some(TlsConfig {
                cert_file: "cert.pem".to_string(),
                key_file: "key.pem".to_string(),
                acme: false,
                min_version: "1.2".to_string(),
                acme_email: None,
                acme_domains: vec![],
                acme_staging: false,
                acme_storage_path: None,
            }),
            ..EntrypointConfig::new("127.0.0.1:9000")
        };
        let err = ep
            .validate_listener_policy("plain")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tls") && err.contains("protocol http"),
            "{err}"
        );
    }

    #[test]
    fn acme_without_email_fails_listener_policy() {
        let tls = TlsConfig {
            cert_file: "/tmp/cert.pem".to_string(),
            key_file: "/tmp/key.pem".to_string(),
            acme: true,
            min_version: "1.2".to_string(),
            acme_email: None,
            acme_domains: vec![],
            acme_staging: false,
            acme_storage_path: None,
        };
        let err = tls
            .validate_listener_policy("websecure")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("acme_email"),
            "ACME without email must fail closed: {err}"
        );
    }
}
