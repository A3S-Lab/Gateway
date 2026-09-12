//! Cloud → Gateway worker ACL render-shape lock.
//!
//! Freezes the attribute order and RFC3339 micros formatting that Cloud's
//! `render_inference_worker_acl_blocks` emits, then proves Gateway accepts the
//! block. Not PW0 EXIT: EmptyInferenceWorkerAclProjectionPort still ships until
//! Power observation delivery fills projections in a provisioned deployment.

use crate::config::{GatewayConfig, POWER_WORKER_OBSERVATION_SCHEMA};
use chrono::{SecondsFormat, Utc};
use uuid::Uuid;

const GATEWAY_ID: &str = "11111111-1111-4111-8111-111111111111";
const ENVIRONMENT_ID: &str = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL_ID: &str = "33333333-3333-4333-8333-333333333333";
const ROUTE_ID: &str = "44444444-4444-4444-8444-444444444444";
const MODEL_ID: &str = "55555555-5555-4555-8555-555555555555";
const TARGET_ID: &str = "66666666-6666-4666-8666-666666666666";
const WORKER_UNIT_ID: &str = "power-unit-1";
const WORKER_EPOCH: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const VERIFIER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Mirror of Cloud `render_one_worker` for an aggregated projection.
fn cloud_shaped_aggregated_worker_block(
    observed_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
) -> String {
    let observed = observed_at.to_rfc3339_opts(SecondsFormat::Micros, true);
    let expires = expires_at.to_rfc3339_opts(SecondsFormat::Micros, true);
    format!(
        r#"
  workers "{WORKER_UNIT_ID}" {{
    target_id = "{TARGET_ID}"
    generation = 5
    schema = "{POWER_WORKER_OBSERVATION_SCHEMA}"
    worker_epoch = "{WORKER_EPOCH}"
    observation_generation = 9
    observed_at = "{observed}"
    expires_at = "{expires}"
    phases = ["aggregated"]
    prompt_cache_capable = true
    state_transfer_capable = false
    ready_phases = ["aggregated"]
    active_limit = 8
    active = 2
    waiting = 1
    prompt_cache_supported = true
    prompt_cache_entries = 2
    prompt_cache_capacity = 8
    prompt_cache_pressure_basis_points = 2500
    transfer_health = "unsupported"
    certified_latency_ms = 42
  }}
"#
    )
}

fn cloud_managed_shell_with_worker(worker_block: &str) -> String {
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
{worker_block}
}}
"#
    )
}

#[test]
fn cloud_rendered_aggregated_worker_acl_shape_is_accepted_by_gateway() {
    // Timestamps follow Cloud render formatting (RFC3339 micros, Zulu) while
    // remaining wall-clock fresh for Gateway validate_worker.
    let now = Utc::now();
    let observed_at = now - chrono::Duration::seconds(1);
    let expires_at = now + chrono::Duration::seconds(14);
    let worker_block = cloud_shaped_aggregated_worker_block(observed_at, expires_at);

    assert!(worker_block.contains(&format!(
        "schema = \"{POWER_WORKER_OBSERVATION_SCHEMA}\""
    )));
    assert!(worker_block.contains("phases = [\"aggregated\"]"));
    assert!(worker_block.contains("transfer_health = \"unsupported\""));
    assert!(worker_block.contains("certified_latency_ms = 42"));
    assert!(!worker_block.contains("execution_profile_sha256"));
    assert!(
        worker_block.contains(".000000Z") || worker_block.contains("Z\""),
        "Cloud render uses RFC3339 with explicit fractional seconds when present"
    );

    let config = GatewayConfig::from_acl(&cloud_managed_shell_with_worker(&worker_block)).unwrap();
    let worker = config
        .inference
        .as_ref()
        .unwrap()
        .workers
        .get(WORKER_UNIT_ID)
        .unwrap();
    assert_eq!(worker.schema, POWER_WORKER_OBSERVATION_SCHEMA);
    assert_eq!(
        worker.worker_epoch,
        Uuid::parse_str(WORKER_EPOCH).unwrap()
    );
    assert_eq!(worker.observation_generation, 9);
    assert_eq!(worker.active_limit, Some(8));
    assert_eq!(worker.certified_latency_ms, Some(42));
    assert_eq!(
        worker.target.target_id,
        Uuid::parse_str(TARGET_ID).unwrap()
    );
}
