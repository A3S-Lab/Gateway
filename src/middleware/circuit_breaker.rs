//! Circuit breaker middleware — prevents cascading failures
//!
//! Implements the circuit breaker pattern with three states:
//! - **Closed**: Normal operation, requests pass through
//! - **Open**: Too many failures, requests are immediately rejected
//! - **HalfOpen**: After cooldown, allows a probe request to test recovery

use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

static NEXT_CIRCUIT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy)]
struct CircuitAdmission {
    generation: u64,
    request_id: u64,
}

/// Request-local admission tokens copied through the WebSocket handshake
/// adapter and consumed by response observers. The vector permits a route to
/// contain more than one circuit-breaker instance without one extension value
/// overwriting another.
#[derive(Debug, Clone, Default)]
pub(crate) struct CircuitRequestTokens(Vec<(u64, CircuitAdmission)>);

impl CircuitRequestTokens {
    fn for_breaker(&self, breaker_id: u64) -> Option<CircuitAdmission> {
        self.0
            .iter()
            .find_map(|(id, admission)| (*id == breaker_id).then_some(*admission))
    }
}

/// Copy circuit admission metadata while preserving Hyper's private upgrade
/// extension on a WebSocket request.
pub(crate) fn copy_request_tokens(source: &http::Extensions, destination: &mut http::Extensions) {
    if let Some(tokens) = source.get::<CircuitRequestTokens>() {
        destination.insert(tokens.clone());
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum CircuitState {
    /// Normal operation — requests pass through
    #[default]
    Closed,
    /// Too many failures — requests are rejected immediately
    Open,
    /// After cooldown — allows one probe request
    HalfOpen,
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
    /// Admission epoch. It changes whenever the breaker changes generation,
    /// invalidating outcomes from requests admitted by an older epoch.
    generation: u64,
    next_request_id: u64,
    consecutive_failures: u32,
    consecutive_successes: u32,
    last_failure_time: Option<Instant>,
    probe_in_flight: bool,
    probe_request_id: Option<u64>,
    /// When the half-open probe lease was acquired. A request can be dropped
    /// before the response observer runs, so the lease must eventually expire
    /// instead of leaving the breaker permanently stuck in half-open.
    probe_started_at: Option<Instant>,
}

impl BreakerState {
    fn new() -> Self {
        Self {
            state: CircuitState::Closed,
            generation: 0,
            next_request_id: 1,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_failure_time: None,
            probe_in_flight: false,
            probe_request_id: None,
            probe_started_at: None,
        }
    }
}

/// Circuit breaker middleware
pub struct CircuitBreakerMiddleware {
    id: u64,
    config: CircuitBreakerConfig,
    state: Arc<RwLock<BreakerState>>,
}

impl CircuitBreakerMiddleware {
    /// Create a new circuit breaker with the given config
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            id: NEXT_CIRCUIT_ID.fetch_add(1, Ordering::Relaxed),
            config,
            state: Arc::new(RwLock::new(BreakerState::new())),
        }
    }

    /// Create a circuit breaker after validating externally supplied policy.
    pub fn try_new(config: CircuitBreakerConfig) -> Result<Self> {
        if config.failure_threshold == 0 {
            return Err(GatewayError::Config(
                "Circuit breaker failure_threshold must be greater than zero".to_string(),
            ));
        }
        if config.success_threshold == 0 {
            return Err(GatewayError::Config(
                "Circuit breaker success_threshold must be greater than zero".to_string(),
            ));
        }
        if config.cooldown.is_zero() {
            return Err(GatewayError::Config(
                "Circuit breaker cooldown must be greater than zero".to_string(),
            ));
        }
        Ok(Self::new(config))
    }

    /// Create with default configuration
    #[allow(dead_code)]
    pub fn with_defaults() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }

    /// Get the current circuit state
    #[allow(dead_code)]
    pub fn current_state(&self) -> CircuitState {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        self.expire_stale_probe(&mut state);
        state.state
    }

    /// Record a successful request
    pub fn record_success(&self) {
        self.record_success_inner(true, None);
    }

    /// Observe a response from a request that was admitted by the middleware.
    /// Unlike the compatibility-facing `record_success` method this does not
    /// transition an open circuit on its own, so late results from an older
    /// generation cannot become a half-open probe.
    fn observe_success(&self) {
        self.record_success_inner(false, None);
    }

    fn record_success_with_admission(&self, admission: CircuitAdmission) {
        self.record_success_inner(false, Some(admission));
    }

    fn record_success_inner(
        &self,
        allow_implicit_probe: bool,
        admission: Option<CircuitAdmission>,
    ) {
        let mut state = self.state.write().unwrap();
        if allow_implicit_probe {
            self.maybe_transition_to_half_open(&mut state);
        }
        self.expire_stale_probe(&mut state);
        if let Some(admission) = admission {
            if admission.generation != state.generation {
                return;
            }
            if state.state == CircuitState::HalfOpen
                && state.probe_request_id != Some(admission.request_id)
            {
                return;
            }
        }
        match state.state {
            CircuitState::Closed => {
                state.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                // Only a request admitted by allow_request() owns the probe
                // lease. A late success from a request admitted while the
                // circuit was closed must never close a newer half-open
                // generation.
                if !allow_implicit_probe && !state.probe_in_flight {
                    return;
                }
                state.probe_in_flight = false;
                state.probe_request_id = None;
                state.probe_started_at = None;
                state.consecutive_successes = state.consecutive_successes.saturating_add(1);
                if state.consecutive_successes >= self.config.success_threshold {
                    state.state = CircuitState::Closed;
                    advance_generation(&mut state);
                    state.consecutive_failures = 0;
                    state.consecutive_successes = 0;
                    state.last_failure_time = None;
                    tracing::info!("Circuit breaker closed — service recovered");
                }
            }
            CircuitState::Open => {
                // Ignore outcomes from requests admitted before the circuit
                // opened. Their result belongs to the old closed generation
                // and must not shorten the open cooldown.
            }
        }
    }

    /// Record a failed request
    pub fn record_failure(&self) {
        self.record_failure_inner(true, None);
    }

    /// Observe a pre-response failure from a request admitted by the
    /// middleware. This path deliberately ignores an already-open circuit and
    /// requires an explicit half-open probe lease.
    fn observe_failure(&self) {
        self.record_failure_inner(false, None);
    }

    fn record_failure_with_admission(&self, admission: CircuitAdmission) {
        self.record_failure_inner(false, Some(admission));
    }

    fn record_failure_inner(
        &self,
        allow_implicit_probe: bool,
        admission: Option<CircuitAdmission>,
    ) {
        let mut state = self.state.write().unwrap();
        if allow_implicit_probe {
            self.maybe_transition_to_half_open(&mut state);
        }
        self.expire_stale_probe(&mut state);
        if let Some(admission) = admission {
            if admission.generation != state.generation {
                return;
            }
            if state.state == CircuitState::HalfOpen
                && state.probe_request_id != Some(admission.request_id)
            {
                return;
            }
        }
        if state.state == CircuitState::Open {
            // Requests admitted before opening can finish after the state
            // transition. Do not let their late failures extend the cooldown.
            return;
        }
        if !allow_implicit_probe && state.state == CircuitState::HalfOpen && !state.probe_in_flight
        {
            // A late result from an abandoned/previous generation cannot be
            // used as the current probe outcome.
            return;
        }
        state.consecutive_successes = 0;
        state.probe_in_flight = false;
        state.probe_request_id = None;
        state.probe_started_at = None;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.last_failure_time = Some(Instant::now());

        if state.state == CircuitState::HalfOpen {
            // Probe failed, re-open the circuit
            state.state = CircuitState::Open;
            advance_generation(&mut state);
            tracing::warn!("Circuit breaker re-opened — probe request failed");
        } else if state.consecutive_failures >= self.config.failure_threshold {
            state.state = CircuitState::Open;
            advance_generation(&mut state);
            tracing::warn!(
                failures = state.consecutive_failures,
                "Circuit breaker opened — threshold reached"
            );
        }
    }

    /// Check if request should be allowed through
    pub fn allow_request(&self) -> bool {
        self.admit_request().is_some()
    }

    fn admit_request(&self) -> Option<CircuitAdmission> {
        let mut state = self.state.write().unwrap();
        self.maybe_transition_to_half_open(&mut state);
        self.expire_stale_probe(&mut state);
        let request_id = next_request_id(&mut state);
        match state.state {
            CircuitState::Closed => Some(CircuitAdmission {
                generation: state.generation,
                request_id,
            }),
            CircuitState::HalfOpen => {
                if state.probe_in_flight {
                    None
                } else {
                    state.probe_in_flight = true;
                    state.probe_request_id = Some(request_id);
                    state.probe_started_at = Some(Instant::now());
                    Some(CircuitAdmission {
                        generation: state.generation,
                        request_id,
                    })
                }
            }
            CircuitState::Open => None,
        }
    }

    /// Get failure count
    #[allow(dead_code)]
    pub fn failure_count(&self) -> u32 {
        self.state.read().unwrap().consecutive_failures
    }

    /// Manually reset the circuit breaker
    #[allow(dead_code)]
    pub fn reset(&self) {
        let mut state = self.state.write().unwrap();
        state.state = CircuitState::Closed;
        state.consecutive_failures = 0;
        state.consecutive_successes = 0;
        state.last_failure_time = None;
        state.probe_in_flight = false;
        state.probe_request_id = None;
        state.probe_started_at = None;
        advance_generation(&mut state);
    }

    /// Check if cooldown has elapsed and transition from Open to HalfOpen (once)
    fn maybe_transition_to_half_open(&self, state: &mut BreakerState) {
        if state.state == CircuitState::Open {
            if let Some(last_failure) = state.last_failure_time {
                if last_failure.elapsed() >= self.config.cooldown {
                    state.state = CircuitState::HalfOpen;
                    advance_generation(state);
                    // Only reset successes on first transition from Open → HalfOpen
                    state.consecutive_successes = 0;
                    state.probe_in_flight = false;
                    state.probe_request_id = None;
                    state.probe_started_at = None;
                    // Clear last_failure_time so we don't re-enter this branch
                    state.last_failure_time = None;
                    tracing::info!("Circuit breaker half-open — allowing probe");
                }
            }
        }
    }

    /// Expire a half-open probe that never reached an observer callback.
    ///
    /// The middleware API observes outcomes separately from admission, so a
    /// cancelled request cannot release its probe flag directly. Re-opening
    /// the circuit starts a fresh cooldown and also prevents a late outcome
    /// from an abandoned probe from closing a newer probe generation.
    fn expire_stale_probe(&self, state: &mut BreakerState) {
        if state.state != CircuitState::HalfOpen || !state.probe_in_flight {
            return;
        }
        let Some(started_at) = state.probe_started_at else {
            state.probe_in_flight = false;
            return;
        };
        // Keep the lease bounded even when an operator configures a very long
        // open cooldown. It is deliberately longer than the common request
        // timeout while still guaranteeing eventual progress.
        let lease = self
            .config
            .cooldown
            .max(Duration::from_secs(1))
            .min(Duration::from_secs(30));
        if started_at.elapsed() >= lease {
            state.state = CircuitState::Open;
            advance_generation(state);
            state.last_failure_time = Some(Instant::now());
            state.consecutive_successes = 0;
            state.probe_in_flight = false;
            state.probe_request_id = None;
            state.probe_started_at = None;
            tracing::warn!("Circuit breaker probe lease expired — restarting cooldown");
        }
    }
}

#[async_trait]
impl Middleware for CircuitBreakerMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let Some(admission) = self.admit_request() else {
            return Ok(Some(
                Response::builder()
                    .status(503)
                    .body(
                        r#"{"error":"Service unavailable (circuit breaker open)"}"#
                            .as_bytes()
                            .to_vec(),
                    )
                    .unwrap(),
            ));
        };

        let tokens = req
            .extensions
            .get_mut::<CircuitRequestTokens>()
            .map(|tokens| {
                tokens.0.push((self.id, admission));
            });
        if tokens.is_none() {
            req.extensions
                .insert(CircuitRequestTokens(vec![(self.id, admission)]));
        }
        Ok(None)
    }

    fn observe_upstream_response(&self, status: http::StatusCode) {
        if status.is_server_error() {
            self.observe_failure();
        } else {
            self.observe_success();
        }
    }

    fn observe_upstream_response_with_request(
        &self,
        request_extensions: &http::Extensions,
        status: http::StatusCode,
    ) {
        let Some(admission) = request_extensions
            .get::<CircuitRequestTokens>()
            .and_then(|tokens| tokens.for_breaker(self.id))
        else {
            self.observe_upstream_response(status);
            return;
        };
        if status.is_server_error() {
            self.record_failure_with_admission(admission);
        } else {
            self.record_success_with_admission(admission);
        }
    }

    fn observe_upstream_failure(&self) {
        self.observe_failure();
    }

    fn observe_upstream_failure_with_request(&self, request_extensions: &http::Extensions) {
        if let Some(admission) = request_extensions
            .get::<CircuitRequestTokens>()
            .and_then(|tokens| tokens.for_breaker(self.id))
        {
            self.record_failure_with_admission(admission);
        } else {
            self.observe_upstream_failure();
        }
    }

    fn name(&self) -> &str {
        "circuit-breaker"
    }
}

fn next_request_id(state: &mut BreakerState) -> u64 {
    let request_id = state.next_request_id;
    state.next_request_id = state.next_request_id.wrapping_add(1).max(1);
    request_id
}

fn advance_generation(state: &mut BreakerState) {
    state.generation = state.generation.wrapping_add(1);
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
        cb.observe_failure();
        cb.observe_success();
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

    #[test]
    fn half_open_allows_exactly_one_concurrent_probe() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));

        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());
        assert!(!cb.allow_request());

        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[test]
    fn abandoned_half_open_probe_restarts_cooldown() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        assert!(cb.allow_request());

        // Simulate a request being cancelled without invoking an observer.
        // The test lives in this module so it can model the passage of the
        // lease without sleeping for the production bound.
        {
            let mut state = cb.state.write().unwrap();
            state.probe_started_at = Some(Instant::now() - Duration::from_secs(2));
        }
        assert_eq!(cb.current_state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn late_closed_generation_outcomes_do_not_mutate_open_or_half_open_state() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        let opened_at = cb.state.read().unwrap().last_failure_time;

        // These represent requests that were admitted before the third
        // failure opened the circuit.
        cb.observe_failure();
        cb.observe_success();
        let state = cb.state.read().unwrap();
        assert_eq!(state.state, CircuitState::Open);
        assert_eq!(state.last_failure_time, opened_at);
        drop(state);

        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);
        // A result without a probe lease is still from the old generation.
        cb.observe_success();
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        assert!(cb.allow_request());
        cb.record_success();
        assert_eq!(cb.current_state(), CircuitState::Closed);
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
    fn invalid_zero_thresholds_and_cooldown_are_rejected() {
        for config in [
            CircuitBreakerConfig {
                failure_threshold: 0,
                ..CircuitBreakerConfig::default()
            },
            CircuitBreakerConfig {
                success_threshold: 0,
                ..CircuitBreakerConfig::default()
            },
            CircuitBreakerConfig {
                cooldown: Duration::ZERO,
                ..CircuitBreakerConfig::default()
            },
        ] {
            assert!(CircuitBreakerMiddleware::try_new(config).is_err());
        }
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

    #[tokio::test]
    async fn late_closed_generation_response_cannot_close_a_new_probe() {
        let cb = CircuitBreakerMiddleware::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(10),
            success_threshold: 1,
        });
        let context = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };

        let (mut old_parts, _) = http::Request::builder().body(()).unwrap().into_parts();
        assert!(cb
            .handle_request(&mut old_parts, &context)
            .await
            .unwrap()
            .is_none());
        cb.record_failure();
        assert_eq!(cb.current_state(), CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(20)).await;
        let (mut probe_parts, _) = http::Request::builder().body(()).unwrap().into_parts();
        assert!(cb
            .handle_request(&mut probe_parts, &context)
            .await
            .unwrap()
            .is_none());
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.observe_upstream_response_with_request(&old_parts.extensions, http::StatusCode::OK);
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        cb.observe_upstream_response_with_request(&probe_parts.extensions, http::StatusCode::OK);
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn request_tokens_support_multiple_half_open_successes() {
        let cb = CircuitBreakerMiddleware::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown: Duration::from_millis(10),
            success_threshold: 2,
        });
        let context = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        cb.record_failure();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let (mut first_parts, _) = http::Request::builder().body(()).unwrap().into_parts();
        assert!(cb
            .handle_request(&mut first_parts, &context)
            .await
            .unwrap()
            .is_none());
        cb.observe_upstream_response_with_request(&first_parts.extensions, http::StatusCode::OK);
        assert_eq!(cb.current_state(), CircuitState::HalfOpen);

        let (mut second_parts, _) = http::Request::builder().body(()).unwrap().into_parts();
        assert!(cb
            .handle_request(&mut second_parts, &context)
            .await
            .unwrap()
            .is_none());
        cb.observe_upstream_response_with_request(&second_parts.extensions, http::StatusCode::OK);
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    // --- Upstream outcome observation ---

    #[tokio::test]
    async fn test_upstream_success_resets_failures() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        cb.observe_upstream_response(http::StatusCode::OK);
        assert_eq!(cb.failure_count(), 0);
        assert_eq!(cb.current_state(), CircuitState::Closed);
    }

    #[tokio::test]
    async fn test_upstream_5xx_records_failure() {
        let cb = fast_breaker();
        cb.observe_upstream_response(http::StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(cb.failure_count(), 1);
    }

    #[tokio::test]
    async fn test_upstream_5xx_trips_breaker() {
        let cb = fast_breaker();
        cb.observe_upstream_response(http::StatusCode::SERVICE_UNAVAILABLE);
        cb.observe_upstream_response(http::StatusCode::SERVICE_UNAVAILABLE);
        cb.observe_upstream_response(http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(cb.current_state(), CircuitState::Open);
    }

    #[tokio::test]
    async fn test_upstream_4xx_is_success() {
        let cb = fast_breaker();
        cb.record_failure();
        cb.record_failure();

        cb.observe_upstream_response(http::StatusCode::NOT_FOUND);
        // 4xx counts as success — failure counter resets
        assert_eq!(cb.failure_count(), 0);
    }
}
