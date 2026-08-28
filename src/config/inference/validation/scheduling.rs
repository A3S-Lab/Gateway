//! Validation of Cloud-bound Power observations and model scheduling policy.

use super::config_error;
use crate::config::{
    GatewayConfig, InferencePhaseRole, InferenceRouteConfig, InferenceSchedulingConfig,
    InferenceTargetConfig, InferenceTransferHealth, InferenceWorkerConfig,
    POWER_WORKER_OBSERVATION_SCHEMA,
};
use crate::error::{GatewayError, Result};
use chrono::{DateTime, Utc};
use std::collections::{HashMap, HashSet};

const MAX_WORKER_OBSERVATION_AGE_SECONDS: i64 = 300;
const MAX_WORKER_CLOCK_SKEW_SECONDS: i64 = 30;
const MAX_POOL_CONCURRENT_REQUESTS: u64 = 100_000;
const MAX_POOL_QUEUED_REQUESTS: u64 = 100_000;
const MAX_POOL_QUEUE_TIMEOUT_MS: u64 = 300_000;
const MAX_DISTRIBUTED_EXECUTION_TIMEOUT_MS: u64 = 300_000;
const MAX_CERTIFIED_LATENCY_MS: u64 = 3_600_000;
const MAX_EXACT_ACL_INTEGER: u64 = (1_u64 << 53) - 1;

pub(super) fn validate_scheduling(
    route: &InferenceRouteConfig,
    alias: &str,
    scheduling: &InferenceSchedulingConfig,
) -> Result<()> {
    if scheduling.max_concurrent_requests == 0
        || scheduling.max_concurrent_requests > MAX_POOL_CONCURRENT_REQUESTS
        || scheduling.max_queued_requests > MAX_POOL_QUEUED_REQUESTS
        || scheduling.queue_timeout_ms == 0
        || scheduling.queue_timeout_ms > MAX_POOL_QUEUE_TIMEOUT_MS
    {
        return Err(config_error(format!(
            "inference model alias '{alias}' on route {} has invalid scheduling bounds",
            route.route_id
        )));
    }
    match scheduling.phase {
        InferencePhaseRole::Aggregated => {
            if scheduling.distributed_serving.is_some() {
                return Err(config_error(format!(
                    "inference model alias '{alias}' on route {} must not configure distributed_serving for aggregated dispatch",
                    route.route_id
                )));
            }
        }
        InferencePhaseRole::Decode => {
            let distributed = scheduling.distributed_serving.as_ref().ok_or_else(|| {
                config_error(format!(
                    "inference model alias '{alias}' on route {} requires distributed_serving for decode scheduling; scheduling without it supports only aggregated dispatch",
                    route.route_id
                ))
            })?;
            if !valid_environment_variable_name(&distributed.api_key_env) {
                return Err(config_error(format!(
                    "inference model alias '{alias}' on route {} has an invalid distributed_serving api_key_env",
                    route.route_id
                )));
            }
            if distributed.execution_timeout_ms == 0
                || distributed.execution_timeout_ms > MAX_DISTRIBUTED_EXECUTION_TIMEOUT_MS
            {
                return Err(config_error(format!(
                    "inference model alias '{alias}' on route {} has an invalid distributed execution timeout",
                    route.route_id
                )));
            }
        }
        InferencePhaseRole::Prefill => {
            return Err(config_error(format!(
                "inference model alias '{alias}' on route {} cannot expose prefill as a client-facing terminal phase",
                route.route_id
            )));
        }
    }
    Ok(())
}

pub(super) fn validate_scheduled_target(
    alias: &str,
    target: &InferenceTargetConfig,
    scheduling: &InferenceSchedulingConfig,
    gateway: &GatewayConfig,
    workers: &HashMap<String, InferenceWorkerConfig>,
    scheduled_workers: &mut HashSet<String>,
) -> Result<()> {
    let service = gateway.services.get(&target.service).ok_or_else(|| {
        config_error(format!(
            "inference target {} references unknown service '{}'",
            target.target_id, target.service
        ))
    })?;
    if !service.revisions.is_empty()
        || service.load_balancer.sticky.is_some()
        || service.failover.is_some()
    {
        return Err(config_error(format!(
            "scheduled inference service '{}' must use one explicit backend set without revisions, sticky routing, or service failover",
            target.service
        )));
    }
    if service.load_balancer.servers.is_empty() {
        return Err(config_error(format!(
            "scheduled inference target {} on model alias '{alias}' has no configured workers",
            target.target_id
        )));
    }

    let mut target_workers = Vec::with_capacity(service.load_balancer.servers.len());
    for server in &service.load_balancer.servers {
        let managed = server.target.as_ref().ok_or_else(|| {
            config_error(format!(
                "scheduled inference service '{}' contains an endpoint without managed target identity",
                target.service
            ))
        })?;
        if managed.target_id != target.target_id {
            return Err(config_error(format!(
                "scheduled inference service '{}' endpoint target {} does not match inference target {}",
                target.service, managed.target_id, target.target_id
            )));
        }
        let worker = workers.get(&managed.unit_id).ok_or_else(|| {
            config_error(format!(
                "scheduled inference endpoint {} / {} / generation {} has no worker observation",
                managed.target_id, managed.unit_id, managed.generation
            ))
        })?;
        if worker.target != *managed {
            return Err(config_error(format!(
                "worker observation for '{}' does not match the configured target generation",
                managed.unit_id
            )));
        }
        if !scheduled_workers.insert(managed.unit_id.clone()) {
            return Err(config_error(format!(
                "worker observation for '{}' is bound to more than one scheduled endpoint",
                managed.unit_id
            )));
        }
        target_workers.push(worker);
    }
    if scheduling.phase == InferencePhaseRole::Decode {
        validate_distributed_worker_pair(alias, target, &target_workers)?;
    }
    Ok(())
}

fn validate_distributed_worker_pair(
    alias: &str,
    target: &InferenceTargetConfig,
    workers: &[&InferenceWorkerConfig],
) -> Result<()> {
    let mut prefill_units = Vec::new();
    let mut decode_units = Vec::new();
    for worker in workers {
        let supports_prefill = worker.phases.contains(&InferencePhaseRole::Prefill);
        let supports_decode = worker.phases.contains(&InferencePhaseRole::Decode);
        if !supports_prefill && !supports_decode {
            return Err(config_error(format!(
                "distributed inference target {} on model alias '{alias}' contains worker '{}' without a prefill or decode capability",
                target.target_id, worker.target.unit_id
            )));
        }
        if !worker.state_transfer_capable
            || matches!(worker.transfer_health, InferenceTransferHealth::Unsupported)
        {
            return Err(config_error(format!(
                "distributed inference worker '{}' does not support state transfer",
                worker.target.unit_id
            )));
        }
        if worker
            .execution_profile_sha256
            .as_deref()
            .is_none_or(|digest| !valid_sha256(digest))
        {
            return Err(config_error(format!(
                "distributed inference worker '{}' has no valid execution profile SHA-256",
                worker.target.unit_id
            )));
        }
        if supports_prefill {
            prefill_units.push(worker.target.unit_id.as_str());
        }
        if supports_decode {
            decode_units.push(worker.target.unit_id.as_str());
        }
    }
    if !prefill_units
        .iter()
        .any(|prefill| decode_units.iter().any(|decode| prefill != decode))
    {
        return Err(config_error(format!(
            "distributed inference target {} on model alias '{alias}' requires distinct prefill and decode workers",
            target.target_id
        )));
    }
    Ok(())
}

pub(super) fn validate_worker(
    worker: &InferenceWorkerConfig,
    policy_expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<()> {
    worker.target.validate().map_err(|error| {
        config_error(format!(
            "inference worker '{}' has invalid target identity: {error}",
            worker.target.unit_id
        ))
    })?;
    if worker.schema != POWER_WORKER_OBSERVATION_SCHEMA {
        return Err(worker_error(
            worker,
            "uses an unsupported observation schema",
        ));
    }
    if worker.worker_epoch.is_nil()
        || worker.observation_generation == 0
        || worker.observation_generation > MAX_EXACT_ACL_INTEGER
    {
        return Err(worker_error(
            worker,
            "has an invalid epoch or observation generation",
        ));
    }
    if worker
        .execution_profile_sha256
        .as_deref()
        .is_some_and(|digest| !valid_sha256(digest))
    {
        return Err(worker_error(
            worker,
            "has an invalid execution profile SHA-256",
        ));
    }
    let validity = worker.expires_at - worker.observed_at;
    if validity <= chrono::Duration::zero()
        || validity > chrono::Duration::seconds(MAX_WORKER_OBSERVATION_AGE_SECONDS)
        || worker.expires_at > policy_expires_at
        || worker.expires_at <= now
        || worker.observed_at > now + chrono::Duration::seconds(MAX_WORKER_CLOCK_SKEW_SECONDS)
    {
        return Err(worker_error(worker, "has an invalid freshness window"));
    }
    validate_phase_set(worker, &worker.phases, "capability phases", false)?;
    validate_phase_set(worker, &worker.ready_phases, "ready phases", true)?;
    if worker
        .ready_phases
        .iter()
        .any(|phase| !worker.phases.contains(phase))
    {
        return Err(worker_error(
            worker,
            "advertises a ready phase outside its capabilities",
        ));
    }
    if worker.active > MAX_EXACT_ACL_INTEGER
        || worker.waiting > MAX_EXACT_ACL_INTEGER
        || worker.active_limit.is_some_and(|limit| {
            limit == 0 || limit > MAX_EXACT_ACL_INTEGER || worker.active > limit
        })
    {
        return Err(worker_error(worker, "has invalid admission counters"));
    }
    if worker.prompt_cache_entries > MAX_EXACT_ACL_INTEGER
        || worker.prompt_cache_capacity > MAX_EXACT_ACL_INTEGER
        || worker.prompt_cache_entries > worker.prompt_cache_capacity
        || worker.prompt_cache_pressure_basis_points > 10_000
        || worker.prompt_cache_pressure_basis_points
            != cache_pressure_basis_points(
                worker.prompt_cache_entries,
                worker.prompt_cache_capacity,
            )
        || worker.prompt_cache_capable != worker.prompt_cache_supported
        || (!worker.prompt_cache_capable
            && (worker.prompt_cache_entries != 0 || worker.prompt_cache_capacity != 0))
    {
        return Err(worker_error(
            worker,
            "has inconsistent prompt-cache pressure",
        ));
    }
    if worker.state_transfer_capable
        == matches!(worker.transfer_health, InferenceTransferHealth::Unsupported)
    {
        return Err(worker_error(worker, "has inconsistent transfer capability"));
    }
    if worker
        .certified_latency_ms
        .is_some_and(|latency| latency == 0 || latency > MAX_CERTIFIED_LATENCY_MS)
    {
        return Err(worker_error(worker, "has invalid certified latency"));
    }
    Ok(())
}

fn validate_phase_set(
    worker: &InferenceWorkerConfig,
    phases: &[InferencePhaseRole],
    label: &str,
    allow_empty: bool,
) -> Result<()> {
    if (!allow_empty && phases.is_empty())
        || phases.iter().copied().collect::<HashSet<_>>().len() != phases.len()
    {
        return Err(worker_error(
            worker,
            format!("has invalid or duplicate {label}"),
        ));
    }
    Ok(())
}

fn cache_pressure_basis_points(entries: u64, capacity: u64) -> u16 {
    if capacity == 0 {
        return if entries == 0 { 0 } else { 10_000 };
    }
    let pressure = u128::from(entries)
        .saturating_mul(10_000)
        .checked_div(u128::from(capacity))
        .unwrap_or(10_000)
        .min(10_000);
    u16::try_from(pressure).unwrap_or(10_000)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_environment_variable_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(
        bytes.next(),
        Some(b'A'..=b'Z') | Some(b'a'..=b'z') | Some(b'_')
    ) && value.len() <= 128
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn worker_error(worker: &InferenceWorkerConfig, message: impl std::fmt::Display) -> GatewayError {
    config_error(format!(
        "inference worker '{}' {message}",
        worker.target.unit_id
    ))
}
