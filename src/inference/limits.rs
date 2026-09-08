//! Snapshot-backed local admission limits for managed inference grants.

use super::access_error::InferenceAccessError;
use crate::config::{InferenceConfig, InferenceLimitsConfig};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;

/// Immutable identity of one credential grant's local counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct InferenceGrantIdentity {
    pub(super) route_id: Uuid,
    pub(super) policy_revision: u64,
    pub(super) credential_id: Uuid,
    pub(super) credential_generation: u64,
}

/// Local limit state for every grant in one active inference projection.
pub(super) struct InferenceLimitStore {
    states: HashMap<InferenceGrantIdentity, Arc<InferenceGrantLimiter>>,
}

impl InferenceLimitStore {
    pub(super) fn new(policy: &InferenceConfig, previous: Option<&Self>) -> Self {
        let mut states = HashMap::new();
        for route in policy.routes.values() {
            for (credential_id, grant) in &route.grants {
                let identity = InferenceGrantIdentity {
                    route_id: route.route_id,
                    policy_revision: route.policy_revision,
                    credential_id: *credential_id,
                    credential_generation: grant.credential_generation,
                };
                let state = previous
                    .and_then(|previous| previous.states.get(&identity))
                    .filter(|state| state.limits == grant.limits)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(InferenceGrantLimiter::new(grant.limits.clone())));
                states.insert(identity, state);
            }
        }
        Self { states }
    }

    pub(super) fn try_admit(
        &self,
        identity: InferenceGrantIdentity,
        reserved_tokens: u64,
    ) -> Result<InferenceGrantAdmissionGuard, InferenceAccessError> {
        self.try_admit_at(identity, reserved_tokens, Instant::now())
    }

    fn try_admit_at(
        &self,
        identity: InferenceGrantIdentity,
        reserved_tokens: u64,
        now: Instant,
    ) -> Result<InferenceGrantAdmissionGuard, InferenceAccessError> {
        let state = self
            .states
            .get(&identity)
            .ok_or(InferenceAccessError::Unavailable)?
            .clone();
        state.try_admit(now, reserved_tokens)
    }
}

struct InferenceGrantLimiter {
    limits: InferenceLimitsConfig,
    requests: Mutex<RequestTokenBucket>,
    tokens: Mutex<TokenBudgetBucket>,
    in_flight: AtomicU64,
}

impl InferenceGrantLimiter {
    fn new(limits: InferenceLimitsConfig) -> Self {
        let now = Instant::now();
        Self {
            requests: Mutex::new(RequestTokenBucket::new(
                limits.requests_per_minute,
                limits.request_burst,
                now,
            )),
            tokens: Mutex::new(TokenBudgetBucket::new(limits.tokens_per_minute, now)),
            limits,
            in_flight: AtomicU64::new(0),
        }
    }

    fn try_admit(
        self: Arc<Self>,
        now: Instant,
        reserved_tokens: u64,
    ) -> Result<InferenceGrantAdmissionGuard, InferenceAccessError> {
        let retry_after_secs = {
            let mut requests = self.requests.lock().unwrap_or_else(PoisonError::into_inner);
            requests.try_acquire(now)
        };
        if let Err(retry_after_secs) = retry_after_secs {
            return Err(InferenceAccessError::RateLimited { retry_after_secs });
        }

        let token_retry_after = {
            let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
            tokens.try_reserve(now, reserved_tokens)
        };
        if let Err(retry_after_secs) = token_retry_after {
            return Err(InferenceAccessError::RateLimited { retry_after_secs });
        }

        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.limits.max_concurrent_requests {
                if reserved_tokens > 0 {
                    let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
                    tokens.refund(Instant::now(), reserved_tokens);
                }
                return Err(InferenceAccessError::ConcurrencyLimited);
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(InferenceGrantAdmissionGuard {
                        state: self,
                        reserved_tokens: AtomicU64::new(reserved_tokens),
                        reconciled: AtomicBool::new(false),
                    })
                }
                Err(observed) => current = observed,
            }
        }
    }
}

/// Drop guard for one request admitted against a credential grant.
///
/// The guard must live until the request or response stream reaches its
/// terminal boundary. It deliberately cannot be cloned.
///
/// Token budget: `reserved_tokens` are deducted at admit time. Call
/// [`reconcile_tokens`] when trusted usage is known; otherwise the reservation
/// remains charged (fail-closed under-billing protection).
pub(super) struct InferenceGrantAdmissionGuard {
    state: Arc<InferenceGrantLimiter>,
    reserved_tokens: AtomicU64,
    reconciled: AtomicBool,
}

impl InferenceGrantAdmissionGuard {
    /// Adjust the token budget from a reserved estimate to an observed total.
    pub(super) fn reconcile_tokens(&self, actual_tokens: u64) {
        if self
            .reconciled
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let reserved = self.reserved_tokens.swap(actual_tokens, Ordering::AcqRel);
        let mut tokens = self
            .state
            .tokens
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        tokens.reconcile(Instant::now(), reserved, actual_tokens);
    }
}

impl Drop for InferenceGrantAdmissionGuard {
    fn drop(&mut self) {
        let result =
            self.state
                .in_flight
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
        debug_assert!(result.is_ok(), "inference admission guard underflow");
    }
}

/// Exact rational token bucket for request admissions.
///
/// One request costs `NANOS_PER_MINUTE` units. A nanosecond of elapsed time
/// earns `requests_per_minute` units, avoiding floating-point drift.
struct RequestTokenBucket {
    requests_per_minute: u64,
    capacity: u128,
    available: u128,
    last_refill: Instant,
}

impl RequestTokenBucket {
    fn new(requests_per_minute: u64, burst: u64, now: Instant) -> Self {
        let capacity = u128::from(burst) * NANOS_PER_MINUTE;
        Self {
            requests_per_minute,
            capacity,
            available: capacity,
            last_refill: now,
        }
    }

    fn try_acquire(&mut self, now: Instant) -> Result<(), u64> {
        self.refill(now);
        if self.available >= NANOS_PER_MINUTE {
            self.available -= NANOS_PER_MINUTE;
            return Ok(());
        }
        if self.requests_per_minute == 0 {
            return Err(u64::MAX);
        }

        let missing = NANOS_PER_MINUTE - self.available;
        let units_per_second =
            u128::from(self.requests_per_minute).saturating_mul(NANOS_PER_SECOND);
        let seconds = ceil_div(missing, units_per_second).max(1);
        Err(u64::try_from(seconds).unwrap_or(u64::MAX))
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .checked_duration_since(self.last_refill)
            .unwrap_or(Duration::ZERO);
        let earned = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.requests_per_minute));
        self.available = self.available.saturating_add(earned).min(self.capacity);
        if now > self.last_refill {
            self.last_refill = now;
        }
    }
}

/// Exact rational token-budget bucket for model-token reservations.
///
/// Capacity equals one minute of `tokens_per_minute` (no separate burst knob).
/// One model token costs `NANOS_PER_MINUTE` units so refill math matches the
/// request bucket.
struct TokenBudgetBucket {
    tokens_per_minute: u64,
    capacity: u128,
    available: u128,
    last_refill: Instant,
}

impl TokenBudgetBucket {
    fn new(tokens_per_minute: u64, now: Instant) -> Self {
        let capacity = u128::from(tokens_per_minute).saturating_mul(NANOS_PER_MINUTE);
        Self {
            tokens_per_minute,
            capacity,
            available: capacity,
            last_refill: now,
        }
    }

    fn try_reserve(&mut self, now: Instant, tokens: u64) -> Result<(), u64> {
        if tokens == 0 {
            return Ok(());
        }
        self.refill(now);
        let cost = u128::from(tokens).saturating_mul(NANOS_PER_MINUTE);
        if self.available >= cost {
            self.available -= cost;
            return Ok(());
        }
        if self.tokens_per_minute == 0 {
            return Err(u64::MAX);
        }

        let missing = cost - self.available;
        let units_per_second = u128::from(self.tokens_per_minute).saturating_mul(NANOS_PER_SECOND);
        let seconds = ceil_div(missing, units_per_second).max(1);
        Err(u64::try_from(seconds).unwrap_or(u64::MAX))
    }

    fn refund(&mut self, now: Instant, tokens: u64) {
        if tokens == 0 {
            return;
        }
        self.refill(now);
        let credit = u128::from(tokens).saturating_mul(NANOS_PER_MINUTE);
        self.available = self.available.saturating_add(credit).min(self.capacity);
    }

    fn reconcile(&mut self, now: Instant, reserved: u64, actual: u64) {
        if actual == reserved {
            return;
        }
        if actual < reserved {
            self.refund(now, reserved - actual);
            return;
        }
        self.refill(now);
        let extra = actual - reserved;
        let cost = u128::from(extra).saturating_mul(NANOS_PER_MINUTE);
        self.available = self.available.saturating_sub(cost);
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now
            .checked_duration_since(self.last_refill)
            .unwrap_or(Duration::ZERO);
        let earned = elapsed
            .as_nanos()
            .saturating_mul(u128::from(self.tokens_per_minute));
        self.available = self.available.saturating_add(earned).min(self.capacity);
        if now > self.last_refill {
            self.last_refill = now;
        }
    }
}

fn ceil_div(numerator: u128, denominator: u128) -> u128 {
    numerator.div_ceil(denominator)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        InferenceCredentialConfig, InferenceEndpoint, InferenceGrantConfig, InferenceModelConfig,
        InferenceRouteConfig, InferenceTargetConfig,
    };
    use chrono::Utc;

    fn limits(
        max_concurrent_requests: u64,
        requests_per_minute: u64,
        burst: u64,
    ) -> InferenceLimitsConfig {
        InferenceLimitsConfig {
            max_concurrent_requests,
            requests_per_minute,
            request_burst: burst,
            tokens_per_minute: 10_000,
        }
    }

    fn limits_with_tpm(
        max_concurrent_requests: u64,
        requests_per_minute: u64,
        burst: u64,
        tokens_per_minute: u64,
    ) -> InferenceLimitsConfig {
        InferenceLimitsConfig {
            max_concurrent_requests,
            requests_per_minute,
            request_burst: burst,
            tokens_per_minute,
        }
    }

    fn policy(limits: InferenceLimitsConfig) -> (InferenceConfig, InferenceGrantIdentity) {
        let route_id = Uuid::new_v4();
        let credential_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let identity = InferenceGrantIdentity {
            route_id,
            policy_revision: 7,
            credential_id,
            credential_generation: 3,
        };
        let policy = InferenceConfig {
            expires_at: Utc::now() + chrono::Duration::hours(1),
            credentials: HashMap::from([(
                credential_id,
                InferenceCredentialConfig {
                    credential_id,
                    environment_id,
                    audience: "cloud-inference".into(),
                    prefix: "a3s_inf_abc12345".into(),
                    verifier_hash: String::new(),
                    generation: 3,
                    expires_at: Utc::now() + chrono::Duration::hours(1),
                    revoked: false,
                },
            )]),
            routes: HashMap::from([(
                route_id,
                InferenceRouteConfig {
                    route_id,
                    router: "inference".into(),
                    environment_id,
                    policy_revision: 7,
                    models: HashMap::from([(
                        "model".into(),
                        InferenceModelConfig {
                            model_id: Uuid::new_v4(),
                            targets: vec![InferenceTargetConfig {
                                target_id: Uuid::new_v4(),
                                service: "model".into(),
                                upstream_model: "model".into(),
                                priority: 0,
                                weight: 1,
                            }],
                            scheduling: None,
                        },
                    )]),
                    grants: HashMap::from([(
                        credential_id,
                        InferenceGrantConfig {
                            credential_generation: 3,
                            models: vec!["model".into()],
                            endpoints: vec![InferenceEndpoint::Models],
                            limits,
                        },
                    )]),
                },
            )]),
            workers: HashMap::new(),
        };
        (policy, identity)
    }

    #[test]
    fn request_bucket_enforces_burst_and_exact_refill() {
        let start = Instant::now();
        let mut bucket = RequestTokenBucket::new(60, 2, start);

        assert_eq!(bucket.try_acquire(start), Ok(()));
        assert_eq!(bucket.try_acquire(start), Ok(()));
        assert_eq!(bucket.try_acquire(start), Err(1));
        assert_eq!(
            bucket.try_acquire(start + Duration::from_millis(999)),
            Err(1)
        );
        assert_eq!(bucket.try_acquire(start + Duration::from_secs(1)), Ok(()));
    }

    #[test]
    fn request_bucket_reports_ceiling_retry_after() {
        let start = Instant::now();
        let mut bucket = RequestTokenBucket::new(10, 1, start);
        assert_eq!(bucket.try_acquire(start), Ok(()));
        assert_eq!(bucket.try_acquire(start), Err(6));
        assert_eq!(
            bucket.try_acquire(start + Duration::from_millis(1_500)),
            Err(5)
        );
    }

    #[test]
    fn request_bucket_defensively_rejects_a_zero_rate() {
        let start = Instant::now();
        let mut bucket = RequestTokenBucket::new(0, 0, start);

        assert_eq!(bucket.try_acquire(start), Err(u64::MAX));
    }

    #[test]
    fn token_budget_enforces_reservation_and_exact_refill() {
        let start = Instant::now();
        let mut bucket = TokenBudgetBucket::new(60, start);

        assert_eq!(bucket.try_reserve(start, 40), Ok(()));
        assert_eq!(bucket.try_reserve(start, 20), Ok(()));
        assert_eq!(bucket.try_reserve(start, 1), Err(1));
        assert_eq!(
            bucket.try_reserve(start + Duration::from_millis(999), 1),
            Err(1)
        );
        assert_eq!(bucket.try_reserve(start + Duration::from_secs(1), 1), Ok(()));
    }

    #[test]
    fn token_budget_reconcile_refunds_unused_reservation() {
        let start = Instant::now();
        let mut bucket = TokenBudgetBucket::new(100, start);
        assert_eq!(bucket.try_reserve(start, 80), Ok(()));
        bucket.reconcile(start, 80, 30);
        assert_eq!(bucket.try_reserve(start, 70), Ok(()));
    }

    #[test]
    fn token_budget_reconcile_charges_extra_tokens() {
        let start = Instant::now();
        let mut bucket = TokenBudgetBucket::new(100, start);
        assert_eq!(bucket.try_reserve(start, 40), Ok(()));
        bucket.reconcile(start, 40, 100);
        assert_eq!(bucket.try_reserve(start, 1), Err(1));
    }

    #[test]
    fn concurrency_is_held_until_each_guard_drops() {
        let (policy, identity) = policy(limits(2, 60, 60));
        let store = InferenceLimitStore::new(&policy, None);
        let first = store.try_admit(identity, 0).unwrap();
        let second = store.try_admit(identity, 0).unwrap();

        assert!(matches!(
            store.try_admit(identity, 0),
            Err(InferenceAccessError::ConcurrencyLimited)
        ));
        drop(first);
        assert!(store.try_admit(identity, 0).is_ok());
        drop(second);
    }

    #[test]
    fn concurrency_rejection_still_consumes_an_authorized_request_token() {
        let (policy, identity) = policy(limits(1, 2, 2));
        let store = InferenceLimitStore::new(&policy, None);
        let active = store.try_admit(identity, 0).unwrap();

        assert!(matches!(
            store.try_admit(identity, 0),
            Err(InferenceAccessError::ConcurrencyLimited)
        ));
        drop(active);
        assert!(matches!(
            store.try_admit(identity, 0),
            Err(InferenceAccessError::RateLimited { .. })
        ));
    }

    #[test]
    fn concurrency_rejection_refunds_token_reservation() {
        let (policy, identity) = policy(limits_with_tpm(1, 60, 60, 50));
        let store = InferenceLimitStore::new(&policy, None);
        let active = store.try_admit(identity, 10).unwrap();

        assert!(matches!(
            store.try_admit(identity, 40),
            Err(InferenceAccessError::ConcurrencyLimited)
        ));
        drop(active);
        assert!(store.try_admit(identity, 40).is_ok());
    }

    #[test]
    fn token_budget_blocks_admission_when_exhausted() {
        let (policy, identity) = policy(limits_with_tpm(8, 60, 60, 100));
        let store = InferenceLimitStore::new(&policy, None);
        let _first = store.try_admit(identity, 100).unwrap();
        assert!(matches!(
            store.try_admit(identity, 1),
            Err(InferenceAccessError::RateLimited { .. })
        ));
    }

    #[test]
    fn unreconciled_reservation_remains_charged_after_drop() {
        let (policy, identity) = policy(limits_with_tpm(8, 60, 60, 100));
        let store = InferenceLimitStore::new(&policy, None);
        let guard = store.try_admit(identity, 100).unwrap();
        drop(guard);
        assert!(matches!(
            store.try_admit(identity, 1),
            Err(InferenceAccessError::RateLimited { .. })
        ));
    }

    #[test]
    fn reconcile_after_admit_refunds_unused_tokens_for_later_requests() {
        let (policy, identity) = policy(limits_with_tpm(8, 60, 60, 100));
        let store = InferenceLimitStore::new(&policy, None);
        let guard = store.try_admit(identity, 100).unwrap();
        guard.reconcile_tokens(10);
        drop(guard);
        assert!(store.try_admit(identity, 90).is_ok());
    }

    #[test]
    fn identical_policy_refresh_reuses_rate_state() {
        let (mut policy, identity) = policy(limits(1, 1, 1));
        let previous = InferenceLimitStore::new(&policy, None);
        let active = previous.try_admit(identity, 0).unwrap();

        policy.expires_at += chrono::Duration::minutes(5);
        let refreshed = InferenceLimitStore::new(&policy, Some(&previous));
        assert!(matches!(
            refreshed.try_admit(identity, 0),
            Err(InferenceAccessError::RateLimited { .. })
        ));

        drop(active);
        assert!(matches!(
            refreshed.try_admit(identity, 0),
            Err(InferenceAccessError::RateLimited { .. })
        ));
    }

    #[test]
    fn identical_policy_refresh_preserves_active_concurrency() {
        let (mut policy, identity) = policy(limits(1, 60, 60));
        let previous = InferenceLimitStore::new(&policy, None);
        let active = previous.try_admit(identity, 0).unwrap();

        policy.expires_at += chrono::Duration::minutes(5);
        let refreshed = InferenceLimitStore::new(&policy, Some(&previous));
        assert!(matches!(
            refreshed.try_admit(identity, 0),
            Err(InferenceAccessError::ConcurrencyLimited)
        ));

        drop(active);
        assert!(refreshed.try_admit(identity, 0).is_ok());
    }

    #[test]
    fn changed_policy_identity_starts_new_limit_state() {
        let (mut policy, identity) = policy(limits(1, 1, 1));
        let previous = InferenceLimitStore::new(&policy, None);
        let _active = previous.try_admit(identity, 0).unwrap();

        let route = policy.routes.get_mut(&identity.route_id).unwrap();
        route.policy_revision += 1;
        let changed_identity = InferenceGrantIdentity {
            policy_revision: route.policy_revision,
            ..identity
        };
        let changed = InferenceLimitStore::new(&policy, Some(&previous));

        assert!(changed.try_admit(changed_identity, 0).is_ok());
    }

    #[test]
    fn admission_guard_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InferenceGrantAdmissionGuard>();
        assert_send_sync::<InferenceLimitStore>();
    }
}
