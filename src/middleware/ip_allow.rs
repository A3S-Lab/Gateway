//! IP allow/block list middleware — restricts access by client IP
//!
//! Supports CIDR notation (e.g., "192.168.1.0/24") and single IPs.

use crate::config::MiddlewareConfig;
use crate::error::Result;
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use ipnet::IpNet;
use std::net::IpAddr;

/// IP allow list middleware
pub struct IpAllowMiddleware {
    /// Parsed CIDR networks
    networks: Vec<IpNet>,
    /// Single IP addresses (not CIDR)
    single_ips: Vec<IpAddr>,
}

impl IpAllowMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let mut networks = Vec::new();
        let mut single_ips = Vec::new();

        for entry in &config.allowed_ips {
            let trimmed = entry.trim();
            if trimmed.contains('/') {
                let net: IpNet = trimmed.parse().map_err(|e| {
                    crate::error::GatewayError::Config(format!("Invalid CIDR '{}': {}", trimmed, e))
                })?;
                networks.push(net);
            } else {
                let ip: IpAddr = trimmed.parse().map_err(|e| {
                    crate::error::GatewayError::Config(format!(
                        "Invalid IP address '{}': {}",
                        trimmed, e
                    ))
                })?;
                single_ips.push(ip);
            }
        }

        if networks.is_empty() && single_ips.is_empty() {
            return Err(crate::error::GatewayError::Config(
                "IP allow list middleware requires at least one allowed_ips entry".to_string(),
            ));
        }

        Ok(Self {
            networks,
            single_ips,
        })
    }

    /// Check if an IP address is allowed
    pub fn is_allowed(&self, ip: &str) -> bool {
        let parsed: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        // Check single IPs
        if self.single_ips.contains(&parsed) {
            return true;
        }

        // Check CIDR ranges
        for net in &self.networks {
            if net.contains(&parsed) {
                return true;
            }
        }

        false
    }
}

#[async_trait]
impl Middleware for IpAllowMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        if self.is_allowed(&ctx.client_ip) {
            Ok(None)
        } else {
            tracing::debug!(client_ip = ctx.client_ip, "IP not in allow list");
            Ok(Some(
                Response::builder()
                    .status(403)
                    .body(r#"{"error":"Forbidden"}"#.as_bytes().to_vec())
                    .unwrap(),
            ))
        }
    }

    fn name(&self) -> &str {
        "ip-allow"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn config_with_ips(ips: Vec<&str>) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "ip-allow".to_string(),
            allowed_ips: ips.into_iter().map(String::from).collect(),
            header: None,
            keys: vec![],
            value: None,
            username: None,
            password: None,
            rate: None,
            burst: None,
            allowed_origins: vec![],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            prefixes: vec![],
            max_retries: None,
            retry_interval_ms: None,
        }
    }

    #[test]
    fn test_ip_allow_name() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        assert_eq!(mw.name(), "ip-allow");
    }

    #[test]
    fn test_single_ip_allowed() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        assert!(mw.is_allowed("10.0.0.1"));
    }

    #[test]
    fn test_single_ip_denied() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        assert!(!mw.is_allowed("10.0.0.2"));
    }

    #[test]
    fn test_cidr_allowed() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["192.168.1.0/24"])).unwrap();
        assert!(mw.is_allowed("192.168.1.1"));
        assert!(mw.is_allowed("192.168.1.254"));
    }

    #[test]
    fn test_cidr_denied() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["192.168.1.0/24"])).unwrap();
        assert!(!mw.is_allowed("192.168.2.1"));
    }

    #[test]
    fn test_mixed_allow_list() {
        let mw =
            IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1", "172.16.0.0/12"])).unwrap();
        assert!(mw.is_allowed("10.0.0.1"));
        assert!(mw.is_allowed("172.20.5.10"));
        assert!(!mw.is_allowed("8.8.8.8"));
    }

    #[test]
    fn test_ipv6_single() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["::1"])).unwrap();
        assert!(mw.is_allowed("::1"));
        assert!(!mw.is_allowed("::2"));
    }

    #[test]
    fn test_ipv6_cidr() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["fd00::/8"])).unwrap();
        assert!(mw.is_allowed("fd00::1"));
        assert!(mw.is_allowed("fd12:3456::1"));
        assert!(!mw.is_allowed("2001:db8::1"));
    }

    #[test]
    fn test_invalid_ip_denied() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        assert!(!mw.is_allowed("not-an-ip"));
    }

    #[test]
    fn test_empty_list_rejected() {
        let config = config_with_ips(vec![]);
        let result = IpAllowMiddleware::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let config = config_with_ips(vec!["999.999.999.999/32"]);
        let result = IpAllowMiddleware::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_single_ip_rejected() {
        let config = config_with_ips(vec!["not-an-ip"]);
        let result = IpAllowMiddleware::new(&config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_request_allowed() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "10.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_request_denied() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1"])).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "192.168.1.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 403);
    }

    #[test]
    fn test_multiple_single_ips() {
        let mw = IpAllowMiddleware::new(&config_with_ips(vec!["10.0.0.1", "10.0.0.2", "10.0.0.3"]))
            .unwrap();
        assert!(mw.is_allowed("10.0.0.1"));
        assert!(mw.is_allowed("10.0.0.2"));
        assert!(mw.is_allowed("10.0.0.3"));
        assert!(!mw.is_allowed("10.0.0.4"));
    }
}
