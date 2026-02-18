//! Traffic mirroring — copy a percentage of live traffic to a shadow backend
//!
//! Mirrors requests fire-and-forget: the shadow response is discarded and
//! never affects the primary request flow.

use crate::proxy::HttpProxy;
use crate::service::LoadBalancer;
use bytes::Bytes;
use std::sync::Arc;

/// Traffic mirror — sends a copy of requests to a shadow service
pub struct TrafficMirror {
    /// Shadow service load balancer
    shadow_lb: Arc<LoadBalancer>,
    /// Percentage of traffic to mirror (0–100)
    percentage: u8,
    /// HTTP proxy for forwarding mirrored requests
    proxy: Arc<HttpProxy>,
    /// Counter for deterministic percentage sampling
    counter: std::sync::atomic::AtomicU64,
}

impl TrafficMirror {
    /// Create a new traffic mirror
    pub fn new(shadow_lb: Arc<LoadBalancer>, percentage: u8, proxy: Arc<HttpProxy>) -> Self {
        Self {
            shadow_lb,
            percentage: percentage.min(100),
            proxy,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check if this request should be mirrored (based on percentage)
    pub fn should_mirror(&self) -> bool {
        if self.percentage == 0 {
            return false;
        }
        if self.percentage >= 100 {
            return true;
        }
        let count = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        (count % 100) < self.percentage as u64
    }

    /// Mirror a request to the shadow backend (fire-and-forget)
    ///
    /// Spawns an async task that sends the request to the shadow service.
    /// The response is discarded. Errors are logged but never propagated.
    pub fn mirror_request(
        &self,
        method: http::Method,
        uri: http::Uri,
        headers: http::HeaderMap,
        body: Bytes,
    ) {
        if !self.should_mirror() {
            return;
        }

        let backend = match self.shadow_lb.next_backend() {
            Some(b) => b,
            None => {
                tracing::debug!(
                    shadow_service = self.shadow_lb.name,
                    "No healthy shadow backend for mirroring"
                );
                return;
            }
        };

        let proxy = self.proxy.clone();
        let shadow_service = self.shadow_lb.name.clone();

        tokio::spawn(async move {
            match proxy.forward(&backend, &method, &uri, &headers, body).await {
                Ok(resp) => {
                    tracing::debug!(
                        shadow_service = shadow_service,
                        backend = backend.url,
                        status = resp.status.as_u16(),
                        "Mirror request completed"
                    );
                }
                Err(e) => {
                    tracing::debug!(
                        shadow_service = shadow_service,
                        backend = backend.url,
                        error = %e,
                        "Mirror request failed (ignored)"
                    );
                }
            }
        });
    }

    /// Get the configured percentage
    #[allow(dead_code)]
    pub fn percentage(&self) -> u8 {
        self.percentage
    }

    /// Get the shadow service name
    #[allow(dead_code)]
    pub fn shadow_service(&self) -> &str {
        &self.shadow_lb.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Strategy};

    fn make_lb(name: &str, urls: Vec<&str>) -> Arc<LoadBalancer> {
        let servers: Vec<ServerConfig> = urls
            .into_iter()
            .map(|u| ServerConfig {
                url: u.to_string(),
                weight: 1,
            })
            .collect();
        Arc::new(LoadBalancer::new(
            name.to_string(),
            Strategy::RoundRobin,
            &servers,
            None,
        ))
    }

    #[test]
    fn test_mirror_new() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 50, proxy);
        assert_eq!(mirror.percentage(), 50);
        assert_eq!(mirror.shadow_service(), "shadow");
    }

    #[test]
    fn test_mirror_percentage_clamped() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 200, proxy);
        assert_eq!(mirror.percentage(), 100);
    }

    #[test]
    fn test_should_mirror_zero() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 0, proxy);
        for _ in 0..100 {
            assert!(!mirror.should_mirror());
        }
    }

    #[test]
    fn test_should_mirror_100() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 100, proxy);
        for _ in 0..100 {
            assert!(mirror.should_mirror());
        }
    }

    #[test]
    fn test_should_mirror_50_percent() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 50, proxy);

        let mut mirrored = 0;
        for _ in 0..200 {
            if mirror.should_mirror() {
                mirrored += 1;
            }
        }
        // 50% of 200 = 100
        assert_eq!(mirrored, 100);
    }

    #[test]
    fn test_should_mirror_10_percent() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 10, proxy);

        let mut mirrored = 0;
        for _ in 0..100 {
            if mirror.should_mirror() {
                mirrored += 1;
            }
        }
        assert_eq!(mirrored, 10);
    }

    #[test]
    fn test_mirror_request_no_healthy_backend() {
        let lb = make_lb("shadow", vec!["http://shadow:8001"]);
        lb.backends()[0].set_healthy(false);
        let proxy = Arc::new(HttpProxy::new());
        let mirror = TrafficMirror::new(lb, 100, proxy);

        // Should not panic even with no healthy backends
        mirror.mirror_request(
            http::Method::GET,
            http::Uri::from_static("/test"),
            http::HeaderMap::new(),
            Bytes::new(),
        );
    }
}
