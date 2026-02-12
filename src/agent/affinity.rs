//! Conversation affinity — sticky sessions for multi-turn AI conversations
//!
//! Ensures that messages within the same conversation are routed to the
//! same backend, maintaining context continuity for AI agents.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Affinity configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffinityConfig {
    /// How long an affinity binding stays active without new messages (seconds)
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,
    /// Header name to extract session/conversation ID from
    #[serde(default = "default_session_header")]
    pub session_header: String,
    /// Cookie name for session affinity (alternative to header)
    #[serde(default)]
    pub cookie_name: Option<String>,
}

fn default_ttl_secs() -> u64 {
    1800 // 30 minutes
}

fn default_session_header() -> String {
    "X-Conversation-Id".to_string()
}

impl Default for AffinityConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl_secs(),
            cookie_name: None,
            session_header: default_session_header(),
        }
    }
}

/// A single affinity binding — maps a conversation to a backend
#[derive(Debug, Clone)]
struct AffinityBinding {
    /// Backend URL this conversation is pinned to
    backend_url: String,
    /// Last time this binding was accessed
    last_access: Instant,
    /// TTL for this binding
    ttl: Duration,
}

impl AffinityBinding {
    fn new(backend_url: String, ttl: Duration) -> Self {
        Self {
            backend_url,
            last_access: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.last_access.elapsed() >= self.ttl
    }

    fn touch(&mut self) {
        self.last_access = Instant::now();
    }
}

/// Conversation affinity manager — maintains sticky session bindings
pub struct ConversationAffinity {
    config: AffinityConfig,
    /// Map of conversation_id → backend binding
    bindings: Arc<RwLock<HashMap<String, AffinityBinding>>>,
}

impl ConversationAffinity {
    /// Create a new affinity manager
    pub fn new(config: AffinityConfig) -> Self {
        Self {
            config,
            bindings: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Look up the backend for a conversation. Returns None if no binding exists or expired.
    pub fn get_backend(&self, conversation_id: &str) -> Option<String> {
        let mut bindings = self.bindings.write().unwrap();
        if let Some(binding) = bindings.get_mut(conversation_id) {
            if binding.is_expired() {
                bindings.remove(conversation_id);
                return None;
            }
            binding.touch();
            Some(binding.backend_url.clone())
        } else {
            None
        }
    }

    /// Bind a conversation to a backend
    pub fn bind(&self, conversation_id: &str, backend_url: &str) {
        let ttl = Duration::from_secs(self.config.ttl_secs);
        let binding = AffinityBinding::new(backend_url.to_string(), ttl);
        let mut bindings = self.bindings.write().unwrap();
        bindings.insert(conversation_id.to_string(), binding);
    }

    /// Remove a conversation binding
    pub fn unbind(&self, conversation_id: &str) {
        let mut bindings = self.bindings.write().unwrap();
        bindings.remove(conversation_id);
    }

    /// Get the number of active (non-expired) bindings
    pub fn active_count(&self) -> usize {
        let bindings = self.bindings.read().unwrap();
        bindings.values().filter(|b| !b.is_expired()).count()
    }

    /// Evict all expired bindings. Returns the number of evicted entries.
    pub fn evict_expired(&self) -> usize {
        let mut bindings = self.bindings.write().unwrap();
        let before = bindings.len();
        bindings.retain(|_, b| !b.is_expired());
        before - bindings.len()
    }

    /// Extract conversation ID from headers (checks configured header name)
    pub fn extract_conversation_id(&self, headers: &HashMap<String, String>) -> Option<String> {
        // Check header
        if let Some(id) = headers.get(&self.config.session_header) {
            if !id.is_empty() {
                return Some(id.clone());
            }
        }

        // Check cookie if configured
        if let Some(ref cookie_name) = self.config.cookie_name {
            if let Some(cookie_header) = headers.get("cookie") {
                return Self::extract_cookie_value(cookie_header, cookie_name);
            }
        }

        None
    }

    /// Parse a specific cookie value from a Cookie header
    fn extract_cookie_value(cookie_header: &str, name: &str) -> Option<String> {
        for part in cookie_header.split(';') {
            let trimmed = part.trim();
            if let Some(value) = trimmed.strip_prefix(name) {
                if let Some(value) = value.strip_prefix('=') {
                    let v = value.trim();
                    if !v.is_empty() {
                        return Some(v.to_string());
                    }
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_affinity() -> ConversationAffinity {
        ConversationAffinity::new(AffinityConfig::default())
    }

    // --- Config tests ---

    #[test]
    fn test_config_default() {
        let config = AffinityConfig::default();
        assert_eq!(config.ttl_secs, 1800);
        assert_eq!(config.session_header, "X-Conversation-Id");
        assert!(config.cookie_name.is_none());
    }

    #[test]
    fn test_config_serialization() {
        let config = AffinityConfig {
            ttl_secs: 3600,
            session_header: "X-Session".to_string(),
            cookie_name: Some("session_id".to_string()),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AffinityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ttl_secs, 3600);
        assert_eq!(parsed.session_header, "X-Session");
        assert_eq!(parsed.cookie_name, Some("session_id".to_string()));
    }

    // --- Bind and get tests ---

    #[test]
    fn test_bind_and_get() {
        let affinity = default_affinity();
        affinity.bind("conv-1", "http://backend-1:8080");
        assert_eq!(
            affinity.get_backend("conv-1"),
            Some("http://backend-1:8080".to_string())
        );
    }

    #[test]
    fn test_get_nonexistent() {
        let affinity = default_affinity();
        assert_eq!(affinity.get_backend("conv-999"), None);
    }

    #[test]
    fn test_bind_overwrites() {
        let affinity = default_affinity();
        affinity.bind("conv-1", "http://backend-1:8080");
        affinity.bind("conv-1", "http://backend-2:8080");
        assert_eq!(
            affinity.get_backend("conv-1"),
            Some("http://backend-2:8080".to_string())
        );
    }

    #[test]
    fn test_multiple_conversations() {
        let affinity = default_affinity();
        affinity.bind("conv-1", "http://backend-1:8080");
        affinity.bind("conv-2", "http://backend-2:8080");
        assert_eq!(
            affinity.get_backend("conv-1"),
            Some("http://backend-1:8080".to_string())
        );
        assert_eq!(
            affinity.get_backend("conv-2"),
            Some("http://backend-2:8080".to_string())
        );
    }

    // --- Unbind tests ---

    #[test]
    fn test_unbind() {
        let affinity = default_affinity();
        affinity.bind("conv-1", "http://backend-1:8080");
        affinity.unbind("conv-1");
        assert_eq!(affinity.get_backend("conv-1"), None);
    }

    #[test]
    fn test_unbind_nonexistent() {
        let affinity = default_affinity();
        affinity.unbind("conv-999"); // Should not panic
    }

    // --- Active count tests ---

    #[test]
    fn test_active_count_empty() {
        let affinity = default_affinity();
        assert_eq!(affinity.active_count(), 0);
    }

    #[test]
    fn test_active_count() {
        let affinity = default_affinity();
        affinity.bind("conv-1", "http://b1:8080");
        affinity.bind("conv-2", "http://b2:8080");
        assert_eq!(affinity.active_count(), 2);
    }

    // --- Expiration tests ---

    #[test]
    fn test_expired_binding_returns_none() {
        let config = AffinityConfig {
            ttl_secs: 0, // Expire immediately
            ..Default::default()
        };
        let affinity = ConversationAffinity::new(config);
        affinity.bind("conv-1", "http://backend:8080");
        // TTL is 0 seconds, so it should be expired
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert_eq!(affinity.get_backend("conv-1"), None);
    }

    #[test]
    fn test_evict_expired() {
        let config = AffinityConfig {
            ttl_secs: 0,
            ..Default::default()
        };
        let affinity = ConversationAffinity::new(config);
        affinity.bind("conv-1", "http://b1:8080");
        affinity.bind("conv-2", "http://b2:8080");
        std::thread::sleep(std::time::Duration::from_millis(10));
        let evicted = affinity.evict_expired();
        assert_eq!(evicted, 2);
        assert_eq!(affinity.active_count(), 0);
    }

    // --- Header extraction tests ---

    #[test]
    fn test_extract_conversation_id_from_header() {
        let affinity = default_affinity();
        let mut headers = HashMap::new();
        headers.insert("X-Conversation-Id".to_string(), "conv-123".to_string());
        assert_eq!(
            affinity.extract_conversation_id(&headers),
            Some("conv-123".to_string())
        );
    }

    #[test]
    fn test_extract_conversation_id_missing() {
        let affinity = default_affinity();
        let headers = HashMap::new();
        assert_eq!(affinity.extract_conversation_id(&headers), None);
    }

    #[test]
    fn test_extract_conversation_id_empty() {
        let affinity = default_affinity();
        let mut headers = HashMap::new();
        headers.insert("X-Conversation-Id".to_string(), "".to_string());
        assert_eq!(affinity.extract_conversation_id(&headers), None);
    }

    #[test]
    fn test_extract_conversation_id_from_cookie() {
        let config = AffinityConfig {
            cookie_name: Some("session_id".to_string()),
            ..Default::default()
        };
        let affinity = ConversationAffinity::new(config);
        let mut headers = HashMap::new();
        headers.insert(
            "cookie".to_string(),
            "other=abc; session_id=conv-456; foo=bar".to_string(),
        );
        assert_eq!(
            affinity.extract_conversation_id(&headers),
            Some("conv-456".to_string())
        );
    }

    #[test]
    fn test_header_takes_priority_over_cookie() {
        let config = AffinityConfig {
            cookie_name: Some("session_id".to_string()),
            ..Default::default()
        };
        let affinity = ConversationAffinity::new(config);
        let mut headers = HashMap::new();
        headers.insert("X-Conversation-Id".to_string(), "from-header".to_string());
        headers.insert("cookie".to_string(), "session_id=from-cookie".to_string());
        assert_eq!(
            affinity.extract_conversation_id(&headers),
            Some("from-header".to_string())
        );
    }

    // --- Cookie parsing tests ---

    #[test]
    fn test_extract_cookie_value() {
        assert_eq!(
            ConversationAffinity::extract_cookie_value("a=1; b=2; c=3", "b"),
            Some("2".to_string())
        );
    }

    #[test]
    fn test_extract_cookie_value_first() {
        assert_eq!(
            ConversationAffinity::extract_cookie_value("target=hello; other=world", "target"),
            Some("hello".to_string())
        );
    }

    #[test]
    fn test_extract_cookie_value_missing() {
        assert_eq!(
            ConversationAffinity::extract_cookie_value("a=1; b=2", "c"),
            None
        );
    }

    #[test]
    fn test_extract_cookie_value_empty() {
        assert_eq!(ConversationAffinity::extract_cookie_value("", "a"), None);
    }
}
