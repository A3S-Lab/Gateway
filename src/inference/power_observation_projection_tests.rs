//! PW0 field-mapping lock: Power nested WorkerObservation → Gateway flat ACL.
//!
//! Cloud owns production projection and delivery. Gateway must accept the flat
//! shape that results from Power's nested observation bytes without inventing
//! a second dialect. This is not PW0 EXIT and not a capacity claim.

use crate::config::{
    GatewayConfig, InferencePhaseRole, InferenceSchedulingConfig, InferenceTransferHealth,
    InferenceWorkerConfig, ManagedTargetConfig, POWER_WORKER_OBSERVATION_SCHEMA,
};
use crate::inference::scheduling::{select_worker, InferenceWorkerCandidate};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use uuid::Uuid;

const TARGET_ID: &str = "66666666-6666-4666-8666-666666666666";
const WORKER_UNIT_ID: &str = "power-unit-1";
const WORKER_EPOCH: &str = "00000000-0000-0000-0000-000000000000";
const GATEWAY_ID: &str = "11111111-1111-4111-8111-111111111111";
const ENVIRONMENT_ID: &str = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL_ID: &str = "33333333-3333-4333-8333-333333333333";
const ROUTE_ID: &str = "44444444-4444-4444-8444-444444444444";
const MODEL_ID: &str = "55555555-5555-4555-8555-555555555555";
const VERIFIER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Nested Power observation wire shape (mirrors `a3s-power` serving observation).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerWorkerObservation {
    schema: String,
    worker_epoch: Uuid,
    observation_generation: u64,
    observed_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    capabilities: PowerWorkerCapabilities,
    ready_phases: Vec<String>,
    admission: PowerAdmissionObservation,
    prompt_cache: PowerPromptCacheObservation,
    transfer_health: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerWorkerCapabilities {
    phases: Vec<String>,
    prompt_cache: bool,
    state_transfer: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerAdmissionObservation {
    active_limit: Option<u64>,
    active: u64,
    waiting: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerPromptCacheObservation {
    supported: bool,
    entries: u64,
    capacity: u64,
    pressure_basis_points: u16,
}

fn power_contract_observation_json() -> &'static str {
    // Matches Power `contract_is_closed_and_contains_no_request_identity` values.
    r#"{
  "schema": "a3s.power.worker-observation.v1",
  "worker_epoch": "00000000-0000-0000-0000-000000000000",
  "observation_generation": 1,
  "observed_at": "2026-08-28T00:00:00Z",
  "expires_at": "2026-08-28T00:00:15Z",
  "capabilities": {
    "phases": ["aggregated"],
    "prompt_cache": true,
    "state_transfer": false
  },
  "ready_phases": ["aggregated"],
  "admission": {
    "active_limit": 8,
    "active": 2,
    "waiting": 1
  },
  "prompt_cache": {
    "supported": true,
    "entries": 2,
    "capacity": 8,
    "pressure_basis_points": 2500
  },
  "transfer_health": "unsupported"
}"#
}

fn phase_role(value: &str) -> InferencePhaseRole {
    match value {
        "aggregated" => InferencePhaseRole::Aggregated,
        "prefill" => InferencePhaseRole::Prefill,
        "decode" => InferencePhaseRole::Decode,
        other => panic!("unsupported Power serving phase {other}"),
    }
}

fn transfer_health(value: &str) -> InferenceTransferHealth {
    match value {
        "unsupported" => InferenceTransferHealth::Unsupported,
        "ready" => InferenceTransferHealth::Ready,
        "degraded" => InferenceTransferHealth::Degraded,
        "unavailable" => InferenceTransferHealth::Unavailable,
        other => panic!("unsupported Power transfer_health {other}"),
    }
}

fn project_power_observation(
    target: ManagedTargetConfig,
    observation: PowerWorkerObservation,
) -> InferenceWorkerConfig {
    InferenceWorkerConfig {
        target,
        schema: observation.schema,
        worker_epoch: observation.worker_epoch,
        execution_profile_sha256: None,
        observation_generation: observation.observation_generation,
        observed_at: observation.observed_at,
        expires_at: observation.expires_at,
        phases: observation
            .capabilities
            .phases
            .iter()
            .map(|phase| phase_role(phase))
            .collect(),
        prompt_cache_capable: observation.capabilities.prompt_cache,
        state_transfer_capable: observation.capabilities.state_transfer,
        ready_phases: observation
            .ready_phases
            .iter()
            .map(|phase| phase_role(phase))
            .collect(),
        active_limit: observation.admission.active_limit,
        active: observation.admission.active,
        waiting: observation.admission.waiting,
        prompt_cache_supported: observation.prompt_cache.supported,
        prompt_cache_entries: observation.prompt_cache.entries,
        prompt_cache_capacity: observation.prompt_cache.capacity,
        prompt_cache_pressure_basis_points: observation.prompt_cache.pressure_basis_points,
        transfer_health: transfer_health(&observation.transfer_health),
        certified_latency_ms: None,
    }
}

fn flat_worker_acl(worker: &InferenceWorkerConfig) -> String {
    let observed_at = worker.observed_at.to_rfc3339();
    let expires_at = worker.expires_at.to_rfc3339();
    let active_limit = worker
        .active_limit
        .map(|limit| format!("    active_limit = {limit}\n"))
        .unwrap_or_default();
    format!(
        r#"
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{GATEWAY_ID}" }}

entrypoints "web" {{ address = "127.0.0.1:8080" }}
routers "inference" {{
  rule = "Host(`models.example.com`) && PathPrefix(`/v1`)"
  service = "default-deny"
  entrypoints = ["web"]
}}
services "default-deny" {{
  load_balancer {{
    servers = [{{ url = "http://127.0.0.1:9000" }}]
  }}
}}
services "model-service" {{
  load_balancer {{
    servers {{
      url = "http://127.0.0.1:8000"
      target {{
        target_id = "{TARGET_ID}"
        unit_id = "{WORKER_UNIT_ID}"
        generation = 5
      }}
    }}
  }}
}}

inference {{
  tokenizer_revision = "a3s.gateway.tokenizer.v1"
  expires_at = "2099-01-01T00:00:00Z"

  credentials "{CREDENTIAL_ID}" {{
    environment_id = "{ENVIRONMENT_ID}"
    audience = "cloud-inference"
    prefix = "a3s_inf_abc12345"
    verifier_hash = "{VERIFIER_HASH}"
    generation = 7
    expires_at = "2098-12-31T23:00:00Z"
    revoked = false
  }}

  routes "{ROUTE_ID}" {{
    router = "inference"
    environment_id = "{ENVIRONMENT_ID}"
    policy_revision = 11

    models "chat-model" {{
      model_id = "{MODEL_ID}"
      targets "{TARGET_ID}" {{
        service = "model-service"
        upstream_model = "internal/model-v1"
        priority = 0
        weight = 100
      }}
      scheduling {{
        phase = "aggregated"
        max_concurrent_requests = 32
        max_queued_requests = 64
        queue_timeout_ms = 500
        prompt_cache_affinity = true
      }}
    }}

    grants "{CREDENTIAL_ID}" {{
      credential_generation = 7
      models = ["chat-model"]
      endpoints = ["models", "chat-completions", "embeddings"]
      limits {{
        max_concurrent_requests = 8
        requests_per_minute = 120
        request_burst = 16
        tokens_per_minute = 100000
      }}
    }}
  }}

  workers "{WORKER_UNIT_ID}" {{
    target_id = "{TARGET_ID}"
    generation = 5
    schema = "{}"
    worker_epoch = "{}"
    observation_generation = {}
    observed_at = "{observed_at}"
    expires_at = "{expires_at}"
    phases = ["aggregated"]
    prompt_cache_capable = {}
    state_transfer_capable = {}
    ready_phases = ["aggregated"]
{active_limit}    active = {}
    waiting = {}
    prompt_cache_supported = {}
    prompt_cache_entries = {}
    prompt_cache_capacity = {}
    prompt_cache_pressure_basis_points = {}
    transfer_health = "unsupported"
  }}
}}
"#,
        worker.schema,
        worker.worker_epoch,
        worker.observation_generation,
        worker.prompt_cache_capable,
        worker.state_transfer_capable,
        worker.active,
        worker.waiting,
        worker.prompt_cache_supported,
        worker.prompt_cache_entries,
        worker.prompt_cache_capacity,
        worker.prompt_cache_pressure_basis_points,
    )
}

#[test]
fn power_nested_observation_projects_into_gateway_flat_worker_and_schedules() {
    let nested: PowerWorkerObservation =
        serde_json::from_str(power_contract_observation_json()).unwrap();
    assert_eq!(nested.schema, POWER_WORKER_OBSERVATION_SCHEMA);

    let target = ManagedTargetConfig {
        target_id: Uuid::parse_str(TARGET_ID).unwrap(),
        unit_id: WORKER_UNIT_ID.to_string(),
        generation: 5,
    };
    let projected = project_power_observation(target.clone(), nested);

    assert_eq!(projected.schema, POWER_WORKER_OBSERVATION_SCHEMA);
    assert_eq!(
        projected.worker_epoch,
        Uuid::parse_str(WORKER_EPOCH).unwrap()
    );
    assert_eq!(projected.observation_generation, 1);
    assert_eq!(projected.phases, vec![InferencePhaseRole::Aggregated]);
    assert_eq!(projected.ready_phases, vec![InferencePhaseRole::Aggregated]);
    assert!(projected.prompt_cache_capable);
    assert!(!projected.state_transfer_capable);
    assert_eq!(projected.active_limit, Some(8));
    assert_eq!(projected.active, 2);
    assert_eq!(projected.waiting, 1);
    assert!(projected.prompt_cache_supported);
    assert_eq!(projected.prompt_cache_entries, 2);
    assert_eq!(projected.prompt_cache_capacity, 8);
    assert_eq!(projected.prompt_cache_pressure_basis_points, 2_500);
    assert_eq!(
        projected.transfer_health,
        InferenceTransferHealth::Unsupported
    );

    // Freshness for ACL validate/select uses wall clock; keep Power field map.
    let now = Utc::now();
    let mut live = projected.clone();
    live.observed_at = now - chrono::Duration::seconds(1);
    live.expires_at = now + chrono::Duration::seconds(14);

    let config = GatewayConfig::from_acl(&flat_worker_acl(&live)).unwrap();
    let accepted = config
        .inference
        .as_ref()
        .unwrap()
        .workers
        .get(WORKER_UNIT_ID)
        .unwrap();
    assert_eq!(accepted.schema, live.schema);
    assert_eq!(accepted.observation_generation, live.observation_generation);
    assert_eq!(accepted.active_limit, live.active_limit);
    assert_eq!(accepted.active, live.active);
    assert_eq!(accepted.waiting, live.waiting);
    assert_eq!(
        accepted.prompt_cache_pressure_basis_points,
        live.prompt_cache_pressure_basis_points
    );

    let workers = HashMap::from([(WORKER_UNIT_ID.to_string(), live)]);
    let scheduling = InferenceSchedulingConfig {
        phase: InferencePhaseRole::Aggregated,
        max_concurrent_requests: 32,
        max_queued_requests: 64,
        queue_timeout_ms: 500,
        prompt_cache_affinity: true,
        distributed_serving: None,
    };
    let selection = select_worker(
        &workers,
        &scheduling,
        target.target_id,
        &[InferenceWorkerCandidate {
            target: Some(&target),
            healthy: true,
            local_connections: 0,
        }],
        now,
        b"request",
        None,
    )
    .expect("projected Power observation must be selectable");
    assert_eq!(selection.index, 0);
    assert_eq!(selection.observation_generation, 1);
}
