//! Sticky sessions — cookie-based backend affinity
//!
//! Ensures that requests from the same client are routed to the same
//! backend server using a cookie-based session identifier.

use crate::service::Backend;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default sticky session TTL
const DEFAULT_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// Sticky session configuration
#[derive(Debug, Clone)]
pub struct StickyConfig {
    /// Cookie name for the sticky session
    pub cookie_name: String,
    /// Session TTL
    pub ttl: Duration,
    /// Maximum number of sessions to track
    pub max_sessions: usize,
}

impl Default for StickyConfig {
    fn default() -> Self {
        Self {
            cookie_name: "gateway_sticky".to_string(),
            ttl: DEFAULT_TTL,
            max_sessions: 100_000,
        }
    }
}

/// A sticky session binding
struct SessionBinding {
    /// Backend URL this session is bound to
    backend_url: String,
    /// Last access time
    last_access: Instant,
}

/// Sticky session manager — maps session IDs to backends
pub struct StickySessionManager {
    config: StickyConfig,
    /// session_id → backend binding
    sessions: RwLock<HashMap<String, SessionBinding>>,
}

impl StickySessionManager {
    /// Create a new sticky session manager
    pub fn new(config: StickyConfig) -> Self {
        Self {
            config,
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// Get the cookie name
    #[allow(dead_code)]
    pub fn cookie_name(&self) -> &str {
        &self.config.cookie_name
    }

    /// Get the TTL
    #[allow(dead_code)]
    pub fn ttl(&self) -> Duration {
        self.config.ttl
    }

    /// Look up the backend for a session ID
    pub fn get_backend(&self, session_id: &str) -> Option<String> {
        let mut sessions = self.sessions.write().unwrap();
        if let Some(binding) = sessions.get_mut(session_id) {
            if Instant::now().duration_since(binding.last_access) < self.config.ttl {
                binding.last_access = Instant::now();
                return Some(binding.backend_url.clone());
            }
            // Expired — remove it
            sessions.remove(session_id);
        }
        None
    }

    /// Bind a session to a backend
    pub fn bind(&self, session_id: String, backend_url: String) {
        let mut sessions = self.sessions.write().unwrap();

        // Evict if at capacity
        if sessions.len() >= self.config.max_sessions && !sessions.contains_key(&session_id) {
            self.evict_expired_locked(&mut sessions);
            // If still at capacity, remove oldest
            if sessions.len() >= self.config.max_sessions {
                if let Some(oldest_key) = sessions
                    .iter()
                    .min_by_key(|(_, v)| v.last_access)
                    .map(|(k, _)| k.clone())
                {
                    sessions.remove(&oldest_key);
                }
            }
        }

        sessions.insert(
            session_id,
            SessionBinding {
                backend_url,
                last_access: Instant::now(),
            },
        );
    }

    /// Remove a session binding
    pub fn unbind(&self, session_id: &str) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.remove(session_id);
    }

    /// Get the number of active sessions
    #[allow(dead_code)]
    pub fn session_count(&self) -> usize {
        let sessions = self.sessions.read().unwrap();
        sessions.len()
    }

    /// Evict expired sessions
    #[allow(dead_code)]
    pub fn evict_expired(&self) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        self.evict_expired_locked(&mut sessions)
    }

    fn evict_expired_locked(&self, sessions: &mut HashMap<String, SessionBinding>) -> usize {
        let before = sessions.len();
        let now = Instant::now();
        sessions.retain(|_, v| now.duration_since(v.last_access) < self.config.ttl);
        before - sessions.len()
    }

    /// Remove all sessions bound to a specific backend (e.g., when backend goes unhealthy)
    #[allow(dead_code)]
    pub fn remove_backend(&self, backend_url: &str) -> usize {
        let mut sessions = self.sessions.write().unwrap();
        let before = sessions.len();
        sessions.retain(|_, v| v.backend_url != backend_url);
        before - sessions.len()
    }

    /// Clear all sessions
    #[allow(dead_code)]
    pub fn clear(&self) {
        let mut sessions = self.sessions.write().unwrap();
        sessions.clear();
    }

    /// Select a backend: use sticky session if available, otherwise pick from load balancer
    /// and create a new binding.
    pub fn select_backend(
        &self,
        session_id: Option<&str>,
        backends: &[Arc<Backend>],
    ) -> Option<(Arc<Backend>, Option<String>)> {
        // Try sticky lookup
        if let Some(sid) = session_id {
            if let Some(url) = self.get_backend(sid) {
                // Find the matching backend
                if let Some(backend) = backends.iter().find(|b| b.url == url && b.is_healthy()) {
                    return Some((backend.clone(), None));
                }
                // Backend gone or unhealthy — remove stale binding
                self.unbind(sid);
            }
        }

        // Pick a healthy backend
        let healthy: Vec<_> = backends.iter().filter(|b| b.is_healthy()).collect();
        if healthy.is_empty() {
            return None;
        }

        // Simple selection: least connections among healthy
        let backend = healthy
            .iter()
            .min_by_key(|b| b.connections())
            .map(|b| (*b).clone())?;

        // Generate a new session ID if needed
        let new_session_id = if let Some(sid) = session_id {
            self.bind(sid.to_string(), backend.url.clone());
            None
        } else {
            let id = generate_session_id();
            self.bind(id.clone(), backend.url.clone());
            Some(id)
        };

        Some((backend, new_session_id))
    }

    /// Build a Set-Cookie header value for the sticky session
    pub fn build_cookie(&self, session_id: &str) -> String {
        format!(
            "{}={}; Path=/; Max-Age={}; HttpOnly; SameSite=Lax",
            self.config.cookie_name,
            session_id,
            self.config.ttl.as_secs()
        )
    }

    /// Extract session ID from a Cookie header value
    pub fn extract_session_id<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        let prefix = format!("{}=", self.config.cookie_name);
        for part in cookie_header.split(';') {
            let trimmed = part.trim();
            if let Some(value) = trimmed.strip_prefix(&prefix) {
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
        None
    }
}

/// Generate a random session ID
fn generate_session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ServerConfig, Strategy};
    use crate::service::LoadBalancer;

    fn make_backends(urls: &[&str]) -> Vec<Arc<Backend>> {
        let servers: Vec<ServerConfig> = urls
            .iter()
            .map(|u| ServerConfig {
                url: u.to_string(),
                weight: 1,
            })
            .collect();
        let lb = LoadBalancer::new("test".into(), Strategy::RoundRobin, &servers, None);
        lb.backends().to_vec()
    }

    fn default_manager() -> StickySessionManager {
        StickySessionManager::new(StickyConfig::default())
    }

    // --- Construction ---

    #[test]
    fn test_new() {
        let mgr = default_manager();
        assert_eq!(mgr.cookie_name(), "gateway_sticky");
        assert_eq!(mgr.ttl(), DEFAULT_TTL);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn test_custom_config() {
        let mgr = StickySessionManager::new(StickyConfig {
            cookie_name: "my_session".to_string(),
            ttl: Duration::from_secs(300),
            max_sessions: 500,
        });
        assert_eq!(mgr.cookie_name(), "my_session");
        assert_eq!(mgr.ttl(), Duration::from_secs(300));
    }

    // --- Bind and lookup ---

    #[test]
    fn test_bind_and_get() {
        let mgr = default_manager();
        mgr.bind("session-1".to_string(), "http://backend-a:8001".to_string());
        assert_eq!(
            mgr.get_backend("session-1"),
            Some("http://backend-a:8001".to_string())
        );
    }

    #[test]
    fn test_get_missing() {
        let mgr = default_manager();
        assert_eq!(mgr.get_backend("nonexistent"), None);
    }

    #[test]
    fn test_unbind() {
        let mgr = default_manager();
        mgr.bind("session-1".to_string(), "http://backend-a:8001".to_string());
        mgr.unbind("session-1");
        assert_eq!(mgr.get_backend("session-1"), None);
        assert_eq!(mgr.session_count(), 0);
    }

    // --- Expiry ---

    #[test]
    fn test_expired_session_removed() {
        let mgr = StickySessionManager::new(StickyConfig {
            ttl: Duration::from_millis(50),
            ..Default::default()
        });
        mgr.bind("session-1".to_string(), "http://backend:8001".to_string());
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(mgr.get_backend("session-1"), None);
    }

    #[test]
    fn test_evict_expired() {
        let mgr = StickySessionManager::new(StickyConfig {
            ttl: Duration::from_millis(50),
            ..Default::default()
        });
        mgr.bind("s1".to_string(), "http://a:8001".to_string());
        mgr.bind("s2".to_string(), "http://b:8002".to_string());
        std::thread::sleep(Duration::from_millis(100));
        let evicted = mgr.evict_expired();
        assert_eq!(evicted, 2);
        assert_eq!(mgr.session_count(), 0);
    }

    // --- Remove backend ---

    #[test]
    fn test_remove_backend() {
        let mgr = default_manager();
        mgr.bind("s1".to_string(), "http://a:8001".to_string());
        mgr.bind("s2".to_string(), "http://a:8001".to_string());
        mgr.bind("s3".to_string(), "http://b:8002".to_string());

        let removed = mgr.remove_backend("http://a:8001");
        assert_eq!(removed, 2);
        assert_eq!(mgr.session_count(), 1);
        assert_eq!(mgr.get_backend("s3"), Some("http://b:8002".to_string()));
    }

    // --- Clear ---

    #[test]
    fn test_clear() {
        let mgr = default_manager();
        mgr.bind("s1".to_string(), "http://a:8001".to_string());
        mgr.bind("s2".to_string(), "http://b:8002".to_string());
        mgr.clear();
        assert_eq!(mgr.session_count(), 0);
    }

    // --- Cookie ---

    #[test]
    fn test_build_cookie() {
        let mgr = default_manager();
        let cookie = mgr.build_cookie("abc-123");
        assert!(cookie.contains("gateway_sticky=abc-123"));
        assert!(cookie.contains("Path=/"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("SameSite=Lax"));
    }

    #[test]
    fn test_extract_session_id() {
        let mgr = default_manager();
        assert_eq!(
            mgr.extract_session_id("gateway_sticky=abc-123; other=val"),
            Some("abc-123")
        );
    }

    #[test]
    fn test_extract_session_id_only_cookie() {
        let mgr = default_manager();
        assert_eq!(mgr.extract_session_id("gateway_sticky=xyz"), Some("xyz"));
    }

    #[test]
    fn test_extract_session_id_not_found() {
        let mgr = default_manager();
        assert_eq!(mgr.extract_session_id("other=value"), None);
    }

    #[test]
    fn test_extract_session_id_empty_value() {
        let mgr = default_manager();
        assert_eq!(mgr.extract_session_id("gateway_sticky="), None);
    }

    // --- select_backend ---

    #[test]
    fn test_select_backend_no_session() {
        let mgr = default_manager();
        let backends = make_backends(&["http://a:8001", "http://b:8002"]);

        let result = mgr.select_backend(None, &backends);
        assert!(result.is_some());
        let (backend, new_id) = result.unwrap();
        assert!(new_id.is_some()); // New session created
        assert!(backend.url == "http://a:8001" || backend.url == "http://b:8002");
    }

    #[test]
    fn test_select_backend_with_existing_session() {
        let mgr = default_manager();
        let backends = make_backends(&["http://a:8001", "http://b:8002"]);

        mgr.bind("session-1".to_string(), "http://a:8001".to_string());
        let result = mgr.select_backend(Some("session-1"), &backends);
        assert!(result.is_some());
        let (backend, new_id) = result.unwrap();
        assert_eq!(backend.url, "http://a:8001");
        assert!(new_id.is_none()); // No new session needed
    }

    #[test]
    fn test_select_backend_stale_session() {
        let mgr = default_manager();
        let backends = make_backends(&["http://a:8001", "http://b:8002"]);

        // Bind to a backend that doesn't exist in the pool
        mgr.bind("session-1".to_string(), "http://gone:9999".to_string());
        let result = mgr.select_backend(Some("session-1"), &backends);
        assert!(result.is_some());
        // Should pick a new backend since the old one is gone
        let (_, new_id) = result.unwrap();
        assert!(new_id.is_none()); // Re-bound existing session ID
    }

    #[test]
    fn test_select_backend_no_healthy() {
        let mgr = default_manager();
        let backends = make_backends(&["http://a:8001"]);
        backends[0].set_healthy(false);

        let result = mgr.select_backend(None, &backends);
        assert!(result.is_none());
    }

    #[test]
    fn test_select_backend_unhealthy_sticky() {
        let mgr = default_manager();
        let backends = make_backends(&["http://a:8001", "http://b:8002"]);

        mgr.bind("session-1".to_string(), "http://a:8001".to_string());
        backends[0].set_healthy(false);

        // Should fall through to a healthy backend
        let result = mgr.select_backend(Some("session-1"), &backends);
        assert!(result.is_some());
        let (backend, _) = result.unwrap();
        assert_eq!(backend.url, "http://b:8002");
    }

    // --- Max sessions ---

    #[test]
    fn test_max_sessions_eviction() {
        let mgr = StickySessionManager::new(StickyConfig {
            max_sessions: 3,
            ttl: Duration::from_millis(50),
            ..Default::default()
        });

        mgr.bind("s1".to_string(), "http://a:8001".to_string());
        mgr.bind("s2".to_string(), "http://a:8001".to_string());
        mgr.bind("s3".to_string(), "http://a:8001".to_string());

        // Wait for expiry
        std::thread::sleep(Duration::from_millis(100));

        // This should trigger eviction of expired sessions
        mgr.bind("s4".to_string(), "http://a:8001".to_string());
        assert!(mgr.session_count() <= 3);
    }

    // --- generate_session_id ---

    #[test]
    fn test_generate_session_id_unique() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
    }
}
