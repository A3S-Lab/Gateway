//! Snapshot-scoped hosted MCP request rate and concurrency admission.

use super::McpAccessError;
use crate::config::{McpConfig, McpLimitsConfig};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use uuid::Uuid;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const NANOS_PER_MINUTE: u128 = 60 * NANOS_PER_SECOND;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct McpGrantIdentity {
    pub(super) route_id: Uuid,
    pub(super) policy_revision: u64,
    pub(super) credential_id: Uuid,
    pub(super) credential_generation: u64,
}

pub(super) struct McpLimitStore {
    states: HashMap<McpGrantIdentity, Arc<McpGrantLimiter>>,
}

impl McpLimitStore {
    pub(super) fn new(policy: &McpConfig, previous: Option<&Self>) -> Self {
        let mut states = HashMap::new();
        for route in policy.routes.values() {
            for (credential_id, grant) in &route.grants {
                let identity = McpGrantIdentity {
                    route_id: route.route_id,
                    policy_revision: route.policy_revision,
                    credential_id: *credential_id,
                    credential_generation: grant.credential_generation,
                };
                let state = previous
                    .and_then(|previous| previous.states.get(&identity))
                    .filter(|state| state.limits == grant.limits)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(McpGrantLimiter::new(grant.limits.clone())));
                states.insert(identity, state);
            }
        }
        Self { states }
    }

    pub(super) fn try_admit(
        &self,
        identity: McpGrantIdentity,
    ) -> Result<McpAdmissionGuard, McpAccessError> {
        self.try_admit_at(identity, Instant::now())
    }

    fn try_admit_at(
        &self,
        identity: McpGrantIdentity,
        now: Instant,
    ) -> Result<McpAdmissionGuard, McpAccessError> {
        self.states
            .get(&identity)
            .ok_or(McpAccessError::Unavailable)?
            .clone()
            .try_admit(now)
    }
}

struct McpGrantLimiter {
    limits: McpLimitsConfig,
    requests: Mutex<RequestTokenBucket>,
    in_flight: AtomicU64,
}

impl McpGrantLimiter {
    fn new(limits: McpLimitsConfig) -> Self {
        Self {
            requests: Mutex::new(RequestTokenBucket::new(
                limits.requests_per_minute,
                limits.request_burst,
                Instant::now(),
            )),
            limits,
            in_flight: AtomicU64::new(0),
        }
    }

    fn try_admit(self: Arc<Self>, now: Instant) -> Result<McpAdmissionGuard, McpAccessError> {
        if let Err(retry_after_secs) = self
            .requests
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .try_acquire(now)
        {
            return Err(McpAccessError::RateLimited { retry_after_secs });
        }

        let mut current = self.in_flight.load(Ordering::Acquire);
        loop {
            if current >= self.limits.max_concurrent_requests {
                return Err(McpAccessError::ConcurrencyLimited);
            }
            match self.in_flight.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(McpAdmissionGuard { state: self }),
                Err(observed) => current = observed,
            }
        }
    }
}

/// Drop guard held until one admitted MCP request reaches a terminal path.
pub(crate) struct McpAdmissionGuard {
    state: Arc<McpGrantLimiter>,
}

impl Drop for McpAdmissionGuard {
    fn drop(&mut self) {
        let result =
            self.state
                .in_flight
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    current.checked_sub(1)
                });
        debug_assert!(result.is_ok(), "MCP admission guard underflow");
    }
}

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
        let seconds = missing.div_ceil(units_per_second).max(1);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;

    fn policy(limits: McpLimitsConfig) -> (McpConfig, McpGrantIdentity) {
        let mut policy = GatewayConfig::from_acl(include_str!(
            "../../tests/fixtures/mcp-modern-stateless-snapshot.acl"
        ))
        .unwrap()
        .mcp
        .unwrap();
        let route = policy.routes.values_mut().next().unwrap();
        let (credential_id, grant) = route.grants.iter_mut().next().unwrap();
        grant.limits = limits;
        let identity = McpGrantIdentity {
            route_id: route.route_id,
            policy_revision: route.policy_revision,
            credential_id: *credential_id,
            credential_generation: grant.credential_generation,
        };
        (policy, identity)
    }

    #[test]
    fn enforces_burst_and_concurrency_until_guards_drop() {
        let (policy, identity) = policy(McpLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 2,
            request_burst: 2,
        });
        let store = McpLimitStore::new(&policy, None);
        let active = store.try_admit(identity).unwrap();
        assert!(matches!(
            store.try_admit(identity),
            Err(McpAccessError::ConcurrencyLimited)
        ));
        drop(active);
        assert!(matches!(
            store.try_admit(identity),
            Err(McpAccessError::RateLimited { .. })
        ));
    }

    #[test]
    fn identical_snapshot_refresh_retains_limit_state() {
        let (mut policy, identity) = policy(McpLimitsConfig {
            max_concurrent_requests: 1,
            requests_per_minute: 1,
            request_burst: 1,
        });
        let previous = McpLimitStore::new(&policy, None);
        let active = previous.try_admit(identity).unwrap();
        policy.expires_at += chrono::Duration::minutes(5);
        let refreshed = McpLimitStore::new(&policy, Some(&previous));
        assert!(matches!(
            refreshed.try_admit(identity),
            Err(McpAccessError::RateLimited { .. })
        ));
        drop(active);
    }

    #[test]
    fn guard_and_store_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<McpAdmissionGuard>();
        assert_send_sync::<McpLimitStore>();
    }
}
