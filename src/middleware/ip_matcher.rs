//! Shared IP matching — CIDR and single IP matching
//!
//! Extracted from `ip_allow.rs` for reuse in TCP filter and other IP-based
//! middleware. Supports IPv4/IPv6, CIDR notation, and single addresses.

use crate::error::{GatewayError, Result};
use ipnet::IpNet;
use std::net::IpAddr;

/// IP address matcher supporting CIDR ranges and single IPs
pub struct IpMatcher {
    networks: Vec<IpNet>,
    single_ips: Vec<IpAddr>,
}

impl IpMatcher {
    /// Parse a list of IP/CIDR entries into a matcher
    pub fn new(entries: &[String]) -> Result<Self> {
        let mut networks = Vec::new();
        let mut single_ips = Vec::new();

        for entry in entries {
            let trimmed = entry.trim();
            if trimmed.contains('/') {
                let net: IpNet = trimmed.parse().map_err(|e| {
                    GatewayError::Config(format!("Invalid CIDR '{}': {}", trimmed, e))
                })?;
                networks.push(net);
            } else {
                let ip: IpAddr = trimmed.parse().map_err(|e| {
                    GatewayError::Config(format!("Invalid IP address '{}': {}", trimmed, e))
                })?;
                single_ips.push(ip);
            }
        }

        Ok(Self {
            networks,
            single_ips,
        })
    }

    /// Check if an IP address string is allowed
    pub fn is_allowed(&self, ip: &str) -> bool {
        let parsed: IpAddr = match ip.parse() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        if self.single_ips.contains(&parsed) {
            return true;
        }

        for net in &self.networks {
            if net.contains(&parsed) {
                return true;
            }
        }

        false
    }

    /// Whether this matcher has any entries
    pub fn is_empty(&self) -> bool {
        self.networks.is_empty() && self.single_ips.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(ips: &[&str]) -> Vec<String> {
        ips.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_single_ip_match() {
        let m = IpMatcher::new(&entries(&["10.0.0.1"])).unwrap();
        assert!(m.is_allowed("10.0.0.1"));
        assert!(!m.is_allowed("10.0.0.2"));
    }

    #[test]
    fn test_cidr_match() {
        let m = IpMatcher::new(&entries(&["192.168.1.0/24"])).unwrap();
        assert!(m.is_allowed("192.168.1.1"));
        assert!(m.is_allowed("192.168.1.254"));
        assert!(!m.is_allowed("192.168.2.1"));
    }

    #[test]
    fn test_mixed_entries() {
        let m = IpMatcher::new(&entries(&["10.0.0.1", "172.16.0.0/12"])).unwrap();
        assert!(m.is_allowed("10.0.0.1"));
        assert!(m.is_allowed("172.20.5.10"));
        assert!(!m.is_allowed("8.8.8.8"));
    }

    #[test]
    fn test_ipv6() {
        let m = IpMatcher::new(&entries(&["::1", "fd00::/8"])).unwrap();
        assert!(m.is_allowed("::1"));
        assert!(m.is_allowed("fd12:3456::1"));
        assert!(!m.is_allowed("2001:db8::1"));
    }

    #[test]
    fn test_invalid_ip_not_allowed() {
        let m = IpMatcher::new(&entries(&["10.0.0.1"])).unwrap();
        assert!(!m.is_allowed("not-an-ip"));
    }

    #[test]
    fn test_empty_matcher() {
        let m = IpMatcher::new(&entries(&[])).unwrap();
        assert!(m.is_empty());
        assert!(!m.is_allowed("10.0.0.1"));
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        let result = IpMatcher::new(&entries(&["999.999.999.999/32"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_single_ip_rejected() {
        let result = IpMatcher::new(&entries(&["not-an-ip"]));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_empty_false() {
        let m = IpMatcher::new(&entries(&["10.0.0.1"])).unwrap();
        assert!(!m.is_empty());
    }
}
