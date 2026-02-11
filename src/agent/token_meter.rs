//! Token metering — tracks and limits token usage per agent/user/session
//!
//! Provides token consumption tracking for AI agent workloads with
//! configurable limits at multiple granularity levels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Token usage record for a single metering window
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenUsage {
    /// Total tokens consumed in the current window
    pub tokens_used: u64,
    /// Window start time (unix timestamp ms)
    pub window_start_ms: u64,
    /// Window duration in seconds
    pub window_secs: u64,
}

/// Token limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenLimit {
    /// Maximum tokens per window
    pub max_tokens: u64,
    /// Window duration in seconds (default: 60 = per minute)
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

fn default_window_secs() -> u64 {
    60
}

/// Metering key — identifies who is being metered
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum MeterKey {
    /// Per-user metering
    User(String),
    /// Per-agent metering
    Agent(String),
    /// Per-session metering
    Session(String),
    /// Global metering
    Global,
}

impl std::fmt::Display for MeterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(id) => write!(f, "user:{}", id),
            Self::Agent(id) => write!(f, "agent:{}", id),
            Self::Session(id) => write!(f, "session:{}", id),
            Self::Global => write!(f, "global"),
        }
    }
}

/// Internal sliding window counter
#[derive(Debug)]
struct WindowCounter {
    tokens_used: u64,
    window_start: Instant,
    window_duration: Duration,
    max_tokens: u64,
}

impl WindowCounter {
    fn new(max_tokens: u64, window_secs: u64) -> Self {
        Self {
            tokens_used: 0,
            window_start: Instant::now(),
            window_duration: Duration::from_secs(window_secs),
            max_tokens,
        }
    }

    /// Reset the window if it has expired
    fn maybe_reset(&mut self) {
        if self.window_start.elapsed() >= self.window_duration {
            self.tokens_used = 0;
            self.window_start = Instant::now();
        }
    }

    /// Try to consume tokens. Returns Ok(remaining) or Err(tokens_over_limit)
    fn try_consume(&mut self, tokens: u64) -> Result<u64, u64> {
        self.maybe_reset();
        let new_total = self.tokens_used + tokens;
        if new_total > self.max_tokens {
            Err(new_total - self.max_tokens)
        } else {
            self.tokens_used = new_total;
            Ok(self.max_tokens - self.tokens_used)
        }
    }

    /// Get current usage without consuming
    fn current_usage(&mut self) -> u64 {
        self.maybe_reset();
        self.tokens_used
    }

    /// Get remaining tokens in current window
    fn remaining(&mut self) -> u64 {
        self.maybe_reset();
        self.max_tokens.saturating_sub(self.tokens_used)
    }
}

/// Token meter — tracks and enforces token usage limits
pub struct TokenMeter {
    /// Default limit applied to all keys without specific limits
    default_limit: TokenLimit,
    /// Per-key overrides
    key_limits: HashMap<String, TokenLimit>,
    /// Active counters (keyed by MeterKey display string)
    counters: Arc<RwLock<HashMap<String, WindowCounter>>>,
}

impl TokenMeter {
    /// Create a new token meter with a default limit
    pub fn new(default_limit: TokenLimit) -> Self {
        Self {
            default_limit,
            key_limits: HashMap::new(),
            counters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set a specific limit for a key pattern (e.g., "user:alice")
    pub fn set_limit(&mut self, key_pattern: &str, limit: TokenLimit) {
        self.key_limits.insert(key_pattern.to_string(), limit);
    }

    /// Try to record token usage. Returns Ok(remaining) or Err with overflow count.
    pub fn record(&self, key: &MeterKey, tokens: u64) -> Result<u64, u64> {
        let key_str = key.to_string();
        let limit = self.resolve_limit(&key_str);

        let mut counters = self.counters.write().unwrap();
        let counter = counters
            .entry(key_str)
            .or_insert_with(|| WindowCounter::new(limit.max_tokens, limit.window_secs));
        counter.try_consume(tokens)
    }

    /// Get current token usage for a key
    pub fn usage(&self, key: &MeterKey) -> u64 {
        let key_str = key.to_string();
        let mut counters = self.counters.write().unwrap();
        match counters.get_mut(&key_str) {
            Some(counter) => counter.current_usage(),
            None => 0,
        }
    }

    /// Get remaining tokens for a key
    pub fn remaining(&self, key: &MeterKey) -> u64 {
        let key_str = key.to_string();
        let limit = self.resolve_limit(&key_str);
        let mut counters = self.counters.write().unwrap();
        match counters.get_mut(&key_str) {
            Some(counter) => counter.remaining(),
            None => limit.max_tokens,
        }
    }

    /// Check if a key has budget for the given token count
    pub fn has_budget(&self, key: &MeterKey, tokens: u64) -> bool {
        self.remaining(key) >= tokens
    }

    /// Reset usage for a specific key
    pub fn reset(&self, key: &MeterKey) {
        let key_str = key.to_string();
        let mut counters = self.counters.write().unwrap();
        counters.remove(&key_str);
    }

    /// Resolve the effective limit for a key
    fn resolve_limit(&self, key_str: &str) -> &TokenLimit {
        self.key_limits.get(key_str).unwrap_or(&self.default_limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_meter() -> TokenMeter {
        TokenMeter::new(TokenLimit {
            max_tokens: 1000,
            window_secs: 60,
        })
    }

    // --- MeterKey tests ---

    #[test]
    fn test_meter_key_display() {
        assert_eq!(MeterKey::User("alice".into()).to_string(), "user:alice");
        assert_eq!(MeterKey::Agent("gpt4".into()).to_string(), "agent:gpt4");
        assert_eq!(MeterKey::Session("s1".into()).to_string(), "session:s1");
        assert_eq!(MeterKey::Global.to_string(), "global");
    }

    #[test]
    fn test_meter_key_equality() {
        assert_eq!(MeterKey::User("a".into()), MeterKey::User("a".into()));
        assert_ne!(MeterKey::User("a".into()), MeterKey::User("b".into()));
        assert_ne!(MeterKey::User("a".into()), MeterKey::Agent("a".into()));
    }

    // --- TokenLimit tests ---

    #[test]
    fn test_token_limit_serialization() {
        let limit = TokenLimit {
            max_tokens: 5000,
            window_secs: 120,
        };
        let json = serde_json::to_string(&limit).unwrap();
        let parsed: TokenLimit = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.max_tokens, 5000);
        assert_eq!(parsed.window_secs, 120);
    }

    #[test]
    fn test_token_limit_default_window() {
        let json = r#"{"max_tokens": 1000}"#;
        let limit: TokenLimit = serde_json::from_str(json).unwrap();
        assert_eq!(limit.window_secs, 60);
    }

    // --- Record and usage tests ---

    #[test]
    fn test_record_within_limit() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        let result = meter.record(&key, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 900); // 1000 - 100
    }

    #[test]
    fn test_record_accumulates() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        meter.record(&key, 300).unwrap();
        meter.record(&key, 200).unwrap();
        assert_eq!(meter.usage(&key), 500);
        assert_eq!(meter.remaining(&key), 500);
    }

    #[test]
    fn test_record_exceeds_limit() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        meter.record(&key, 900).unwrap();
        let result = meter.record(&key, 200);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 100); // 900 + 200 - 1000 = 100 over
    }

    #[test]
    fn test_record_exact_limit() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        let result = meter.record(&key, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    #[test]
    fn test_record_one_over_limit() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        let result = meter.record(&key, 1001);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), 1);
    }

    // --- Separate keys are independent ---

    #[test]
    fn test_separate_keys_independent() {
        let meter = default_meter();
        let alice = MeterKey::User("alice".into());
        let bob = MeterKey::User("bob".into());
        meter.record(&alice, 800).unwrap();
        assert_eq!(meter.usage(&alice), 800);
        assert_eq!(meter.usage(&bob), 0);
        assert_eq!(meter.remaining(&bob), 1000);
    }

    // --- has_budget tests ---

    #[test]
    fn test_has_budget_true() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        assert!(meter.has_budget(&key, 500));
    }

    #[test]
    fn test_has_budget_false() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        meter.record(&key, 900).unwrap();
        assert!(!meter.has_budget(&key, 200));
    }

    #[test]
    fn test_has_budget_exact() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        meter.record(&key, 500).unwrap();
        assert!(meter.has_budget(&key, 500));
        assert!(!meter.has_budget(&key, 501));
    }

    // --- Reset tests ---

    #[test]
    fn test_reset_clears_usage() {
        let meter = default_meter();
        let key = MeterKey::User("alice".into());
        meter.record(&key, 800).unwrap();
        assert_eq!(meter.usage(&key), 800);
        meter.reset(&key);
        assert_eq!(meter.usage(&key), 0);
        assert_eq!(meter.remaining(&key), 1000);
    }

    // --- Per-key limit override ---

    #[test]
    fn test_per_key_limit_override() {
        let mut meter = default_meter();
        meter.set_limit(
            "user:vip",
            TokenLimit {
                max_tokens: 5000,
                window_secs: 60,
            },
        );
        let vip = MeterKey::User("vip".into());
        let normal = MeterKey::User("normal".into());
        assert_eq!(meter.remaining(&vip), 5000);
        assert_eq!(meter.remaining(&normal), 1000);
    }

    #[test]
    fn test_per_key_limit_enforced() {
        let mut meter = default_meter();
        meter.set_limit(
            "agent:small",
            TokenLimit {
                max_tokens: 100,
                window_secs: 60,
            },
        );
        let key = MeterKey::Agent("small".into());
        let result = meter.record(&key, 150);
        assert!(result.is_err());
    }

    // --- Usage for unknown key ---

    #[test]
    fn test_usage_unknown_key() {
        let meter = default_meter();
        let key = MeterKey::Session("nonexistent".into());
        assert_eq!(meter.usage(&key), 0);
    }

    #[test]
    fn test_remaining_unknown_key() {
        let meter = default_meter();
        let key = MeterKey::Session("nonexistent".into());
        assert_eq!(meter.remaining(&key), 1000);
    }

    // --- Global key ---

    #[test]
    fn test_global_key() {
        let meter = default_meter();
        meter.record(&MeterKey::Global, 500).unwrap();
        assert_eq!(meter.usage(&MeterKey::Global), 500);
    }

    // --- TokenUsage serialization ---

    #[test]
    fn test_token_usage_serialization() {
        let usage = TokenUsage {
            tokens_used: 500,
            window_start_ms: 1700000000000,
            window_secs: 60,
        };
        let json = serde_json::to_string(&usage).unwrap();
        let parsed: TokenUsage = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tokens_used, 500);
        assert_eq!(parsed.window_start_ms, 1700000000000);
        assert_eq!(parsed.window_secs, 60);
    }
}
