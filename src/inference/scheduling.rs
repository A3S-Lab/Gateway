//! Bounded model-pool admission and pure Power worker selection.

use super::InferenceAccessError;
use crate::config::{
    InferenceConfig, InferenceSchedulingConfig, InferenceWorkerConfig, ManagedTargetConfig,
    POWER_WORKER_OBSERVATION_SCHEMA,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

const CACHE_AFFINITY_LOAD_BAND_BASIS_POINTS: u64 = 1_000;
const UNCERTIFIED_LATENCY_SORT_VALUE: u64 = u64::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct InferencePoolIdentity {
    pub(super) route_id: Uuid,
    pub(super) model_id: Uuid,
}

/// Runtime pool states associated with one immutable scheduling projection.
pub(super) struct InferenceScheduler {
    pools: HashMap<InferencePoolIdentity, Arc<InferencePoolLimiter>>,
}

impl InferenceScheduler {
    pub(super) fn new(policy: &InferenceConfig, previous: Option<&Self>) -> Self {
        let mut pools = HashMap::new();
        for route in policy.routes.values() {
            for model in route.models.values() {
                let Some(scheduling) = &model.scheduling else {
                    continue;
                };
                let identity = InferencePoolIdentity {
                    route_id: route.route_id,
                    model_id: model.model_id,
                };
                let state = previous
                    .and_then(|previous| previous.pools.get(&identity))
                    .filter(|state| state.policy == *scheduling)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(InferencePoolLimiter::new(scheduling.clone())));
                pools.insert(identity, state);
            }
        }
        Self { pools }
    }

    pub(super) async fn admit(
        &self,
        identity: InferencePoolIdentity,
    ) -> Result<Option<InferencePoolAdmissionGuard>, InferenceAccessError> {
        let Some(pool) = self.pools.get(&identity) else {
            return Ok(None);
        };
        pool.clone().admit().await.map(Some)
    }
}

struct InferencePoolLimiter {
    policy: InferenceSchedulingConfig,
    active: Arc<Semaphore>,
    queued: Arc<Semaphore>,
}

impl InferencePoolLimiter {
    fn new(policy: InferenceSchedulingConfig) -> Self {
        let active_permits = usize::try_from(policy.max_concurrent_requests)
            .unwrap_or(Semaphore::MAX_PERMITS)
            .min(Semaphore::MAX_PERMITS);
        let queued_permits = usize::try_from(policy.max_queued_requests)
            .unwrap_or(Semaphore::MAX_PERMITS)
            .min(Semaphore::MAX_PERMITS);
        Self {
            active: Arc::new(Semaphore::new(active_permits)),
            queued: Arc::new(Semaphore::new(queued_permits)),
            policy,
        }
    }

    async fn admit(self: Arc<Self>) -> Result<InferencePoolAdmissionGuard, InferenceAccessError> {
        if let Ok(active) = self.active.clone().try_acquire_owned() {
            return Ok(InferencePoolAdmissionGuard { _active: active });
        }

        let queued = self
            .queued
            .clone()
            .try_acquire_owned()
            .map_err(|_| InferenceAccessError::PoolQueueFull)?;
        let active = tokio::time::timeout(
            Duration::from_millis(self.policy.queue_timeout_ms),
            self.active.clone().acquire_owned(),
        )
        .await
        .map_err(|_| InferenceAccessError::PoolQueueTimeout)?
        .map_err(|_| InferenceAccessError::Unavailable)?;
        drop(queued);
        Ok(InferencePoolAdmissionGuard { _active: active })
    }
}

/// Drop guard for one model-pool execution slot.
#[derive(Debug)]
pub(super) struct InferencePoolAdmissionGuard {
    _active: OwnedSemaphorePermit,
}

/// Request-time view of one configured service backend.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InferenceWorkerCandidate<'a> {
    pub(crate) target: Option<&'a ManagedTargetConfig>,
    pub(crate) healthy: bool,
    pub(crate) local_connections: u64,
}

pub(crate) struct InferenceWorkerSelectionRequest<'a, 'target> {
    pub(crate) target_id: Uuid,
    pub(crate) candidates: &'a [InferenceWorkerCandidate<'target>],
    pub(crate) now: DateTime<Utc>,
    pub(crate) routing_key: &'a [u8],
    pub(crate) cache_affinity_key: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InferenceWorkerSelection {
    pub(crate) index: usize,
    pub(crate) observation_generation: u64,
    pub(crate) active: u64,
    pub(crate) waiting: u64,
    pub(crate) pressure_basis_points: u64,
    pub(crate) cache_affinity_applied: bool,
}

struct EvaluatedWorker<'a> {
    index: usize,
    target: &'a ManagedTargetConfig,
    worker: &'a InferenceWorkerConfig,
    pressure_basis_points: u64,
    local_connections: u64,
}

impl EvaluatedWorker<'_> {
    fn base_score(&self) -> (u64, u64, u64, u16, u64) {
        (
            self.pressure_basis_points,
            self.worker.waiting,
            self.local_connections,
            self.worker.prompt_cache_pressure_basis_points,
            self.worker
                .certified_latency_ms
                .unwrap_or(UNCERTIFIED_LATENCY_SORT_VALUE),
        )
    }

    fn selection(&self, cache_affinity_applied: bool) -> InferenceWorkerSelection {
        InferenceWorkerSelection {
            index: self.index,
            observation_generation: self.worker.observation_generation,
            active: self.worker.active,
            waiting: self.worker.waiting,
            pressure_basis_points: self.pressure_basis_points,
            cache_affinity_applied,
        }
    }
}

pub(super) fn has_eligible_worker(
    workers: &HashMap<String, InferenceWorkerConfig>,
    scheduling: &InferenceSchedulingConfig,
    target_id: Uuid,
    candidates: &[InferenceWorkerCandidate<'_>],
    now: DateTime<Utc>,
) -> bool {
    candidates.iter().any(|candidate| {
        evaluate_candidate(workers, scheduling, target_id, candidate, 0, now).is_some()
    })
}

pub(super) fn select_worker(
    workers: &HashMap<String, InferenceWorkerConfig>,
    scheduling: &InferenceSchedulingConfig,
    target_id: Uuid,
    candidates: &[InferenceWorkerCandidate<'_>],
    now: DateTime<Utc>,
    routing_key: &[u8],
    cache_affinity_key: Option<&str>,
) -> Option<InferenceWorkerSelection> {
    let evaluated = candidates
        .iter()
        .enumerate()
        .filter_map(|(index, candidate)| {
            evaluate_candidate(workers, scheduling, target_id, candidate, index, now)
        })
        .collect::<Vec<_>>();
    if evaluated.is_empty() {
        return None;
    }

    if scheduling.prompt_cache_affinity {
        if let Some(affinity_key) = cache_affinity_key {
            let minimum_pressure = evaluated
                .iter()
                .map(|candidate| candidate.pressure_basis_points)
                .min()
                .unwrap_or_default();
            let minimum_waiting = evaluated
                .iter()
                .map(|candidate| candidate.worker.waiting)
                .min()
                .unwrap_or_default();
            if let Some(selected) = evaluated
                .iter()
                .filter(|candidate| {
                    candidate.worker.prompt_cache_supported
                        && candidate.pressure_basis_points
                            <= minimum_pressure
                                .saturating_add(CACHE_AFFINITY_LOAD_BAND_BASIS_POINTS)
                        && candidate.worker.waiting <= minimum_waiting.saturating_add(1)
                })
                .max_by_key(|candidate| rendezvous_rank(affinity_key.as_bytes(), candidate.target))
            {
                return Some(selected.selection(true));
            }
        }
    }

    let minimum_score = evaluated.iter().map(EvaluatedWorker::base_score).min()?;
    evaluated
        .iter()
        .filter(|candidate| candidate.base_score() == minimum_score)
        .max_by_key(|candidate| rendezvous_rank(routing_key, candidate.target))
        .map(|selected| selected.selection(false))
}

fn evaluate_candidate<'a>(
    workers: &'a HashMap<String, InferenceWorkerConfig>,
    scheduling: &InferenceSchedulingConfig,
    target_id: Uuid,
    candidate: &InferenceWorkerCandidate<'a>,
    index: usize,
    now: DateTime<Utc>,
) -> Option<EvaluatedWorker<'a>> {
    let target = candidate.target?;
    if !candidate.healthy || target.target_id != target_id {
        return None;
    }
    let worker = workers.get(&target.unit_id)?;
    if worker.target != *target
        || worker.schema != POWER_WORKER_OBSERVATION_SCHEMA
        || worker.expires_at <= now
        || !worker.ready_phases.contains(&scheduling.phase)
        || worker
            .active_limit
            .is_some_and(|limit| worker.active >= limit)
    {
        return None;
    }
    Some(EvaluatedWorker {
        index,
        target,
        worker,
        pressure_basis_points: admission_pressure_basis_points(worker),
        local_connections: candidate.local_connections,
    })
}

fn admission_pressure_basis_points(worker: &InferenceWorkerConfig) -> u64 {
    let demand = worker.active.saturating_add(worker.waiting);
    match worker.active_limit {
        Some(limit) if limit > 0 => u64::try_from(
            u128::from(demand)
                .saturating_mul(10_000)
                .checked_div(u128::from(limit))
                .unwrap_or(10_000)
                .min(10_000),
        )
        .unwrap_or(10_000),
        _ => demand.saturating_mul(100).min(10_000),
    }
}

fn rendezvous_rank(key: &[u8], target: &ManagedTargetConfig) -> u64 {
    let mut digest = Sha256::new();
    hash_part(&mut digest, b"a3s.gateway.worker-rendezvous.v1");
    hash_part(&mut digest, key);
    hash_part(&mut digest, target.target_id.as_bytes());
    hash_part(&mut digest, target.unit_id.as_bytes());
    hash_part(&mut digest, &target.generation.to_be_bytes());
    let output = digest.finalize();
    u64::from_be_bytes(output[..8].try_into().unwrap_or([0; 8]))
}

fn hash_part(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

#[cfg(test)]
#[path = "scheduling_tests.rs"]
mod tests;
