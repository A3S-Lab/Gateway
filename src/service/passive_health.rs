//! Passive health check — error-count based backend removal
//!
//! Monitors proxy responses and automatically marks backends as unhealthy
//! when they exceed a configurable error threshold within a time window.

use crate::service::Backend;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Passive health check configuration
#[derive(Debug, Clone)]
pub struct PassiveHealthConfig {
    /// Number of consecutive errors before marking unhealthy
    pub error_threshold: u32,
    /// Time window for counting errors
    pub window: Duration,
    /// HTTP status codes considered as errors (e.g., 500, 502, 503, 504)
    pub error_status_codes: Vec<u16>,
    /// Recovery time — how long to wait before re-enabling a backend
    pub recovery_time: Duration,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            error_threshold: 5,
            window: Duration::from_secs(30),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_secs(30),
        }
    }
}

/// Error record for a single backend
struct BackendErrors {
    /// Timestamps of recent errors within the window
    errors: Vec<Instant>,
    /// When the backend was marked unhealthy (if applicable)
    marked_unhealthy_at: Option<Instant>,
    /// Total error count (lifetime)
    total_errors: AtomicU64,
}

impl BackendErrors {
    fn new() -> Self {
        Self {
            errors: Vec::new(),
            marked_unhealthy_at: None,
            total_errors: AtomicU64::new(0),
        }
    }
}

/// Passive health checker — tracks errors per backend
pub struct PassiveHealthCheck {
    config: PassiveHealthConfig,
    /// Error tracking per backend URL
    backend_errors: RwLock<HashMap<String, BackendErrors>>,
}

impl PassiveHealthCheck {
    /// Create a new passive health checker
    pub fn new(config: PassiveHealthConfig) -> Self {
        Self {
            config,
            backend_errors: RwLock::new(HashMap::new()),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &PassiveHealthConfig {
        &self.config
    }

    /// Record a successful response for a backend
    pub fn record_success(&self, backend: &Arc<Backend>) {
        let mut errors = self.backend_errors.write().unwrap();
        if let Some(entry) = errors.get_mut(&backend.url) {
            // Check if recovery time has passed
            if let Some(marked_at) = entry.marked_unhealthy_at {
                if Instant::now().duration_since(marked_at) >= self.config.recovery_time {
                    backend.set_healthy(true);
                    entry.marked_unhealthy_at = None;
                    entry.errors.clear();
                    tracing::info!(
                        backend = backend.url,
                        "Backend recovered (passive health check)"
                    );
                }
            }
        }
    }

    /// Record an error response for a backend
    pub fn record_error(&self, backend: &Arc<Backend>, status_code: u16) {
        if !self.config.error_status_codes.contains(&status_code) {
            return;
        }

        let now = Instant::now();
        let mut errors = self.backend_errors.write().unwrap();
        let entry = errors
            .entry(backend.url.clone())
            .or_insert_with(BackendErrors::new);

        entry.total_errors.fetch_add(1, Ordering::Relaxed);

        // Already marked unhealthy, skip
        if entry.marked_unhealthy_at.is_some() {
            return;
        }

        // Add error timestamp
        entry.errors.push(now);

        // Prune errors outside the window
        let window_start = now - self.config.window;
        entry.errors.retain(|t| *t >= window_start);

        // Check threshold
        if entry.errors.len() >= self.config.error_threshold as usize {
            backend.set_healthy(false);
            entry.marked_unhealthy_at = Some(now);
            tracing::warn!(
                backend = backend.url,
                errors = entry.errors.len(),
                window_secs = self.config.window.as_secs(),
                "Backend marked unhealthy (passive health check)"
            );
        }
    }

    /// Check if a status code is considered an error
    pub fn is_error_status(&self, status_code: u16) -> bool {
        self.config.error_status_codes.contains(&status_code)
    }

    /// Get the total error count for a backend
    pub fn total_errors(&self, backend_url: &str) -> u64 {
        let errors = self.backend_errors.read().unwrap();
        errors
            .get(backend_url)
            .map(|e| e.total_errors.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    /// Get the recent error count (within window) for a backend
    pub fn recent_errors(&self, backend_url: &str) -> usize {
        let now = Instant::now();
        let errors = self.backend_errors.read().unwrap();
        errors
            .get(backend_url)
            .map(|e| {
                let window_start = now - self.config.window;
                e.errors.iter().filter(|t| **t >= window_start).count()
            })
            .unwrap_or(0)
    }

    /// Reset error tracking for a backend
    pub fn reset(&self, backend_url: &str) {
        let mut errors = self.backend_errors.write().unwrap();
        errors.remove(backend_url);
    }

    /// Reset all error tracking
    pub fn reset_all(&self) {
        let mut errors = self.backend_errors.write().unwrap();
        errors.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_backend(url: &str) -> Arc<Backend> {
        use crate::config::{ServerConfig, Strategy};
        use crate::service::LoadBalancer;

        let servers = vec![ServerConfig {
            url: url.to_string(),
            weight: 1,
        }];
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);
        lb.backends()[0].clone()
    }

    fn quick_config(threshold: u32) -> PassiveHealthConfig {
        PassiveHealthConfig {
            error_threshold: threshold,
            window: Duration::from_secs(60),
            error_status_codes: vec![500, 502, 503, 504],
            recovery_time: Duration::from_millis(100),
        }
    }

    // --- Config tests ---

    #[test]
    fn test_config_default() {
        let config = PassiveHealthConfig::default();
        assert_eq!(config.error_threshold, 5);
        assert_eq!(config.window, Duration::from_secs(30));
        assert_eq!(config.error_status_codes, vec![500, 502, 503, 504]);
        assert_eq!(config.recovery_time, Duration::from_secs(30));
    }

    // --- Construction ---

    #[test]
    fn test_new() {
        let phc = PassiveHealthCheck::new(PassiveHealthConfig::default());
        assert_eq!(phc.config().error_threshold, 5);
    }

    // --- Error recording ---

    #[test]
    fn test_record_error_below_threshold() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        let backend = make_backend("http://127.0.0.1:8001");

        phc.record_error(&backend, 500);
        phc.record_error(&backend, 502);

        assert!(backend.is_healthy());
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 2);
        assert_eq!(phc.recent_errors("http://127.0.0.1:8001"), 2);
    }

    #[test]
    fn test_record_error_reaches_threshold() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        let backend = make_backend("http://127.0.0.1:8001");

        phc.record_error(&backend, 500);
        phc.record_error(&backend, 502);
        phc.record_error(&backend, 503);

        assert!(!backend.is_healthy());
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 3);
    }

    #[test]
    fn test_record_error_non_error_status_ignored() {
        let phc = PassiveHealthCheck::new(quick_config(1));
        let backend = make_backend("http://127.0.0.1:8001");

        phc.record_error(&backend, 200);
        phc.record_error(&backend, 404);
        phc.record_error(&backend, 301);

        assert!(backend.is_healthy());
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 0);
    }

    #[test]
    fn test_is_error_status() {
        let phc = PassiveHealthCheck::new(PassiveHealthConfig::default());
        assert!(phc.is_error_status(500));
        assert!(phc.is_error_status(502));
        assert!(phc.is_error_status(503));
        assert!(phc.is_error_status(504));
        assert!(!phc.is_error_status(200));
        assert!(!phc.is_error_status(404));
        assert!(!phc.is_error_status(301));
    }

    // --- Recovery ---

    #[test]
    fn test_recovery_after_timeout() {
        let phc = PassiveHealthCheck::new(quick_config(2));
        let backend = make_backend("http://127.0.0.1:8001");

        // Trigger unhealthy
        phc.record_error(&backend, 500);
        phc.record_error(&backend, 500);
        assert!(!backend.is_healthy());

        // Wait for recovery time
        std::thread::sleep(Duration::from_millis(150));

        // Record success triggers recovery check
        phc.record_success(&backend);
        assert!(backend.is_healthy());
    }

    #[test]
    fn test_no_recovery_before_timeout() {
        let config = PassiveHealthConfig {
            error_threshold: 2,
            recovery_time: Duration::from_secs(60),
            ..quick_config(2)
        };
        let phc = PassiveHealthCheck::new(config);
        let backend = make_backend("http://127.0.0.1:8001");

        phc.record_error(&backend, 500);
        phc.record_error(&backend, 500);
        assert!(!backend.is_healthy());

        // Success before recovery time should not recover
        phc.record_success(&backend);
        assert!(!backend.is_healthy());
    }

    // --- Success recording ---

    #[test]
    fn test_record_success_no_errors() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        let backend = make_backend("http://127.0.0.1:8001");

        // Should not panic or change anything
        phc.record_success(&backend);
        assert!(backend.is_healthy());
    }

    // --- Reset ---

    #[test]
    fn test_reset_backend() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        let backend = make_backend("http://127.0.0.1:8001");

        phc.record_error(&backend, 500);
        phc.record_error(&backend, 500);
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 2);

        phc.reset("http://127.0.0.1:8001");
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 0);
        assert_eq!(phc.recent_errors("http://127.0.0.1:8001"), 0);
    }

    #[test]
    fn test_reset_all() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        let b1 = make_backend("http://127.0.0.1:8001");
        let b2 = make_backend("http://127.0.0.1:8002");

        phc.record_error(&b1, 500);
        phc.record_error(&b2, 500);

        phc.reset_all();
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 0);
        assert_eq!(phc.total_errors("http://127.0.0.1:8002"), 0);
    }

    // --- Multiple backends ---

    #[test]
    fn test_independent_backend_tracking() {
        let phc = PassiveHealthCheck::new(quick_config(2));
        let b1 = make_backend("http://127.0.0.1:8001");
        let b2 = make_backend("http://127.0.0.1:8002");

        phc.record_error(&b1, 500);
        phc.record_error(&b1, 500);
        phc.record_error(&b2, 500);

        assert!(!b1.is_healthy());
        assert!(b2.is_healthy());
        assert_eq!(phc.total_errors("http://127.0.0.1:8001"), 2);
        assert_eq!(phc.total_errors("http://127.0.0.1:8002"), 1);
    }

    // --- Unknown backend ---

    #[test]
    fn test_total_errors_unknown_backend() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        assert_eq!(phc.total_errors("http://unknown:8001"), 0);
    }

    #[test]
    fn test_recent_errors_unknown_backend() {
        let phc = PassiveHealthCheck::new(quick_config(3));
        assert_eq!(phc.recent_errors("http://unknown:8001"), 0);
    }
}
