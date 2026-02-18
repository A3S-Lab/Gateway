//! TCP connection filter — in-flight connection limits and IP allowlist
//!
//! Provides connection-level filtering for TCP entrypoints, enforcing
//! maximum concurrent connections and optional IP restrictions.

use crate::error::{GatewayError, Result};
use crate::middleware::ip_matcher::IpMatcher;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// RAII guard that decrements the connection counter on drop
#[derive(Debug)]
pub struct TcpPermit {
    counter: Arc<AtomicUsize>,
}

impl Drop for TcpPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

/// TCP connection filter with concurrent connection limit and IP allowlist
pub struct TcpFilter {
    ip_matcher: IpMatcher,
    max_connections: Option<u32>,
    current_connections: Arc<AtomicUsize>,
}

impl TcpFilter {
    /// Create a new TCP filter
    pub fn new(max_connections: Option<u32>, allowed_ips: &[String]) -> Result<Self> {
        let ip_matcher = IpMatcher::new(allowed_ips)?;
        Ok(Self {
            ip_matcher,
            max_connections,
            current_connections: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Check if a connection from the given address should be accepted.
    /// Returns a permit that must be held for the duration of the connection.
    pub fn check_connection(&self, addr: &str) -> Result<TcpPermit> {
        // Check IP allowlist (if configured)
        if !self.ip_matcher.is_empty() && !self.ip_matcher.is_allowed(addr) {
            return Err(GatewayError::MiddlewareRejected(format!(
                "TCP connection from {} denied by IP filter",
                addr
            )));
        }

        // Check connection limit
        if let Some(max) = self.max_connections {
            let current = self.current_connections.fetch_add(1, Ordering::SeqCst);
            if current >= max as usize {
                self.current_connections.fetch_sub(1, Ordering::SeqCst);
                return Err(GatewayError::MiddlewareRejected(format!(
                    "TCP connection limit reached ({}/{})",
                    current, max
                )));
            }
        } else {
            self.current_connections.fetch_add(1, Ordering::SeqCst);
        }

        Ok(TcpPermit {
            counter: self.current_connections.clone(),
        })
    }

    /// Current number of active connections
    #[allow(dead_code)]
    pub fn active_connections(&self) -> usize {
        self.current_connections.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_filter() {
        let filter = TcpFilter::new(None, &[]).unwrap();
        let permit = filter.check_connection("10.0.0.1").unwrap();
        assert_eq!(filter.active_connections(), 1);
        drop(permit);
        assert_eq!(filter.active_connections(), 0);
    }

    #[test]
    fn test_ip_allowed() {
        let ips = vec!["10.0.0.0/8".to_string()];
        let filter = TcpFilter::new(None, &ips).unwrap();
        assert!(filter.check_connection("10.0.0.1").is_ok());
    }

    #[test]
    fn test_ip_denied() {
        let ips = vec!["10.0.0.0/8".to_string()];
        let filter = TcpFilter::new(None, &ips).unwrap();
        let result = filter.check_connection("192.168.1.1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("denied"));
    }

    #[test]
    fn test_connection_limit() {
        let filter = TcpFilter::new(Some(2), &[]).unwrap();
        let p1 = filter.check_connection("10.0.0.1").unwrap();
        let p2 = filter.check_connection("10.0.0.2").unwrap();
        assert_eq!(filter.active_connections(), 2);

        // Third connection should be rejected
        let result = filter.check_connection("10.0.0.3");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("limit reached"));

        // Drop one permit, now a new connection should be allowed
        drop(p1);
        assert_eq!(filter.active_connections(), 1);
        let _p3 = filter.check_connection("10.0.0.3").unwrap();
        assert_eq!(filter.active_connections(), 2);
        drop(p2);
        drop(_p3);
    }

    #[test]
    fn test_permit_decrements_on_drop() {
        let filter = TcpFilter::new(Some(10), &[]).unwrap();
        {
            let _p = filter.check_connection("10.0.0.1").unwrap();
            assert_eq!(filter.active_connections(), 1);
        }
        assert_eq!(filter.active_connections(), 0);
    }

    #[test]
    fn test_combined_ip_and_limit() {
        let ips = vec!["10.0.0.0/8".to_string()];
        let filter = TcpFilter::new(Some(1), &ips).unwrap();

        // Allowed IP within limit
        let p = filter.check_connection("10.0.0.1").unwrap();
        assert_eq!(filter.active_connections(), 1);

        // Allowed IP but over limit
        let result = filter.check_connection("10.0.0.2");
        assert!(result.is_err());

        // Denied IP (doesn't count toward limit)
        drop(p);
        let result = filter.check_connection("192.168.1.1");
        assert!(result.is_err());
        assert_eq!(filter.active_connections(), 0);
    }

    #[test]
    fn test_no_ip_filter_accepts_all() {
        let filter = TcpFilter::new(Some(100), &[]).unwrap();
        assert!(filter.check_connection("1.2.3.4").is_ok());
        assert!(filter.check_connection("::1").is_ok());
    }

    #[test]
    fn test_invalid_ip_entries_rejected() {
        let ips = vec!["not-valid".to_string()];
        assert!(TcpFilter::new(None, &ips).is_err());
    }

    #[test]
    fn test_multiple_permits_concurrent() {
        let filter = TcpFilter::new(Some(5), &[]).unwrap();
        let permits: Vec<_> = (0..5)
            .map(|i| filter.check_connection(&format!("10.0.0.{}", i)).unwrap())
            .collect();
        assert_eq!(filter.active_connections(), 5);
        assert!(filter.check_connection("10.0.0.5").is_err());
        drop(permits);
        assert_eq!(filter.active_connections(), 0);
    }

    #[test]
    fn test_limit_one() {
        let filter = TcpFilter::new(Some(1), &[]).unwrap();
        let p = filter.check_connection("10.0.0.1").unwrap();
        assert!(filter.check_connection("10.0.0.2").is_err());
        drop(p);
        assert!(filter.check_connection("10.0.0.2").is_ok());
    }
}
