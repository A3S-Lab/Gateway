//! Circuit breaker middleware — prevents cascading failures
//!
//! Implements the circuit breaker pattern with three states:
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Too many failures, requests are immediately rejected
//! - **HalfOpen**: After cooldown, allows a probe request to test recovery

use crate::error::Result;
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitState {
    /// Normal operation — requests pass through
    Closed,
    /// Too many failures — requests are rejected immediately
    Open,
    /// After cooldown — allows one probe request
    HalfOpen,
}

impl Default for CircuitState {
    fn default() -> Self {
        Self::Closed
    }
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open => write!(f, "open"),
            Self::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures to trip the circuit
    pub failure_threshold: u32,
    /// Duration the circuit stays open before transitioning to half-open
    pub cooldown: Duration,
    /// Number of successes in half-open state to close the circuit
    pub success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown: Duration::from_secs(30),
            success_threshold: 1,
        }
    }
}

/// Internal mutable state
#[derive(Debug)]
struct BreakerState {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_time: Option<Instant>,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_time: None,
        }
    }
}

/// Circuit breaker middleware
pub struct CircuitBreakerMiddleware {
    config: CircuitBreakerConfig,
    state: Arc<RwLock<BreakerState>>,
}

impl CircuitBreakerMiddleware {
    /// Create a new circuit breaker with the given config
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Arc::new(RwLock::new(BreakerState::new())),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Get the current circuit state
    pub fn current_state(&self) -> CircuitState {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        state.state
    }

    /// Record a successful request
    pub fn record_success(&self) {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        match state.state {
            CircuitState::Closed => {
                state.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                state.consecutive_successes += 1;
                if state.consecutive_successes >= self.config.success_threshold {
                    state.state = CircuitState::Closed;
                    state.consecutive_failures = 0;
                    state.consecutive_successes = 0;
                    state.last_failure_time = None;
                    tracing::info!("Circuit breaker closed — service recovered");
                }
            }
            CircuitState::Open => {
                // Should not happen, but reset if it does
                state.consecutive_failures = 0;
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        state.consecutive_successes = 0;
        state.consecutive_failures += 1;
        state.last_failure_time = Some(Instant::now());

        if state.state == CircuitState::HalfOpen {
            // Probe failed, re-open the circuit
            state.state = CircuitState::Open;
            tracing::warn!("Circuit breaker re-opened — probe request failed");
        } else if state.consecutive_failures >= self.config.failure_threshold {
            state.state = CircuitState::Open;
            tracing::warn!(
                failures = state.consecutive_failures,
                "Circuit breaker opened — threshold reached"
            );
        }
    }

    /// Check if request should be allowed through
    pub fn allow_request(&self) -> bool {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        match state.state {
            CircuitState::Closed => true,
            CircuitState::HalfOpen => true, // Allow probe request
            CircuitState::Open => false,
        }
    }

    /// Get failure count
    pub fn failure_count(&self) -> u32 {
        self.state.read().unwrap().consecutive_failures
    }

    /// Manually reset the circuit breaker
    pub fn reset(&self) {
        let mut state = self.state.write().unwrap();
        state.state = CircuitState::Closed;
        state.consecutive_failures = 0;
        state.consecutive_successes = 0;
        state.last_failure_time = None;
    }

    /// Check if cooldown has elapsed and transition from Open to HalfOpen (once)
    fn maybe_transition_to_half_open(&self, state: &mut BreakerState) {
        if state.state == CircuitState::Open {
            if let Some(last_failure) = state.last_failure_time {
                if last_failure.elapsed() >= self.config.cooldown {
                    state.state = CircuitState::HalfOpen;
                    // Only reset successes on first transition from Open → HalfOpen
                    state.consecutive_successes = 0;
                    // Clear last_failure_time so we don't re-enter this branch
                    state.last_failure_time = None;
                    tracing::info!("Circuit breaker half-open — allowing probe");
                }
            }
        }
    }
}

#[async_trait]
impl Middleware for CircuitBreakerMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        if self.allow_request() {
            Ok(None)
        } else {
            Ok(Some(
                Response::builder()
                    .status(503)
                    .body(
                        r#"{"error":"Service unavailable (circuit breaker open)"}"#
                            .as_bytes()
                            .to_vec(),
                    )
                    .unwrap(),
            ))
        }
    }

    fn name(&self) -> &str {
        "circuit-breaker"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_breaker() -> CircuitBreakerMiddleware {
        CircuitBreakerMiddleware::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown: Duration::from_millis(50),
            success_threshold: 1,
        })
    }

    // --- State tests ---

    #[test]
    fn test_circuit_state_default() {
        assert_eq!(CircuitState::default(), CircuitState::Closed);
    }

    #[test]
    fn test_circuit_state_display() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(CircuitState::Open.to_string(), "open");
        assert_eq!(CircuitState::HalfOpen.to_string(), "half-open");
    }

    #[test]
    fn test_circuit_state_serialization() {
        let json = serde_json::to_string(&CircuitState::Open).unwrap();
        assert_eq!(json, "\"open\"");
        let parsed: CircuitState = serde_json::from_str("\"closed\"").unwrap();
        assert_eq!(parsed, CircuitState::Closed);
    }

    // --- Initial state ---

    #[test]
    fn test_initial_state_closed() {
        let cb = fast_breaker();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[test]
    fn test_initial_allow_request() {
        let cb = fast_breaker();
        assert!(cb.allow_request());
    }

    // --- Failure threshold ---

    #[test]
    fn test_stays_closed_below_threshold() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn test_opens_at_threshold() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn test_failure_count() {
        let cb = fast_breaker();
        assert_eq!(cb.failure_count(), 0);
        cb.record_failure();
        assert_eq!(cb.failure_count(), 1);
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);
    }

    // --- Success resets failures ---

    #[test]
    fn test_success_resets_failure_count() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // --- Open → HalfOpen transition ---

    #[test]
    fn test_transitions_to_half_open_after_cooldown() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
    }

    // --- HalfOpen → Closed on success ---

    #[test]
    fn test_half_open_closes_on_success() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // --- HalfOpen → Open on failure ---

    #[test]
    fn test_half_open_reopens_on_failure() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    // --- Manual reset ---

    #[test]
    fn test_manual_reset() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.current_state(), CircuitState::Closed);
        assert!(cb.allow_request());
        assert_eq!(cb.failure_count(), 0);
    }

    // --- Default config ---

    #[test]
    fn test_default_config() {
        let config = CircuitBreakerConfig::default();
        assert_eq!(config.failure_threshold, 5);
        assert_eq!(config.cooldown, Duration::from_secs(30));
        assert_eq!(config.success_threshold, 1);
    }

    #[test]
    fn test_with_defaults() {
        let cb = CircuitBreakerMiddleware::with_defaults();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // --- Higher success threshold ---

    #[test]
    fn test_higher_success_threshold() {
        let cb = CircuitBreakerMiddleware::new(CircuitBreakerConfig {
            failure_threshold: 2,
            cooldown: Duration::from_millis(10),
            success_threshold: 3,
        });
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(20));

        // In half-open, need 3 successes
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // --- Middleware interface ---

    #[test]
    fn test_middleware_name() {
        let cb = fast_breaker();
        assert_eq!(cb.name(), "circuit-breaker");
    }

    #[tokio::test]
    async fn test_middleware_allows_when_closed() {
        let cb = fast_breaker();
        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = cb.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_middleware_rejects_when_open() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();

        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = cb.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 503);
    }
}
