//! I0.2c lifecycle payload lock: Gateway encode ↔ Cloud decode contract.
//!
//! Cloud ledger insertion runs `InferenceUsageLifecycleEventV1::decode` on every
//! spool payload. This module mirrors that contract without pulling Cloud as a
//! runtime dependency. Not provisioned enrolled-node EXIT.

use super::{
    encode, AttemptEvidence, LifecycleEvent, LifecycleEventKind, MeasurementCompleteness,
    RequestEvidence, UsageTerminalOutcome, LIFECYCLE_SCHEMA,
};
use crate::config::InferenceEndpoint;
use chrono::{DateTime, Utc};
use serde::Deserialize;
use uuid::Uuid;

const FORBIDDEN_PAYLOAD_KEYS: &[&str] = &[
    "prompt",
    "prompts",
    "messages",
    "input",
    "output",
    "response",
    "completion",
    "content",
    "authorization",
    "api_key",
    "secret",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum CloudEndpoint {
    Models,
    ChatCompletions,
    Completions,
    Embeddings,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CloudKind {
    RequestStarted,
    AttemptStarted,
    AttemptTerminal,
    RequestTerminal,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CloudOutcome {
    Succeeded,
    Failed,
    Fallback,
    Cancelled,
    Disconnected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum CloudMeasurement {
    Unknown,
    UpstreamUsage,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudRequest {
    request_id: Uuid,
    correlation_id: String,
    environment_id: Uuid,
    credential_id: Uuid,
    credential_generation: u64,
    route_id: Uuid,
    route_policy_revision: u64,
    endpoint: CloudEndpoint,
    model_alias: String,
    model_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudAttempt {
    attempt_id: Uuid,
    target_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CloudLifecycleEvent {
    schema: String,
    kind: CloudKind,
    occurred_at: DateTime<Utc>,
    request: CloudRequest,
    #[serde(default)]
    attempt: Option<CloudAttempt>,
    #[serde(default)]
    outcome: Option<CloudOutcome>,
    #[serde(default)]
    http_status: Option<u16>,
    #[serde(default)]
    duration_ms: Option<u64>,
    #[serde(default)]
    measurement_completeness: Option<CloudMeasurement>,
    #[serde(default)]
    total_tokens: Option<u64>,
}

fn reject_forbidden_keys(bytes: &[u8]) -> Result<(), String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("usage lifecycle event is invalid JSON: {error}"))?;
    reject_forbidden_value(&value, "")
}

fn reject_forbidden_value(value: &serde_json::Value, path: &str) -> Result<(), String> {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let lowered = key.to_ascii_lowercase();
                if FORBIDDEN_PAYLOAD_KEYS
                    .iter()
                    .any(|forbidden| lowered == *forbidden)
                {
                    return Err(format!(
                        "usage lifecycle forbids prompt or secret field {path}{key}"
                    ));
                }
                let next = if path.is_empty() {
                    format!("{key}.")
                } else {
                    format!("{path}{key}.")
                };
                reject_forbidden_value(child, &next)?;
            }
            Ok(())
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                reject_forbidden_value(child, &format!("{path}{index}."))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn require_none<T>(label: &str, value: Option<&T>) -> Result<(), String> {
    if value.is_some() {
        Err(format!(
            "usage lifecycle {label} must be absent for this kind"
        ))
    } else {
        Ok(())
    }
}

fn validate_uuid(label: &str, value: Uuid) -> Result<(), String> {
    if value.is_nil() {
        Err(format!("{label} is invalid"))
    } else {
        Ok(())
    }
}

fn cloud_decode(bytes: &[u8]) -> Result<CloudLifecycleEvent, String> {
    reject_forbidden_keys(bytes)?;
    let event: CloudLifecycleEvent = serde_json::from_slice(bytes)
        .map_err(|error| format!("usage lifecycle event is invalid JSON: {error}"))?;
    if event.schema != LIFECYCLE_SCHEMA {
        return Err(format!(
            "unsupported usage lifecycle schema {:?}",
            event.schema
        ));
    }
    validate_uuid("usage request ID", event.request.request_id)?;
    if event.request.correlation_id.is_empty() || event.request.correlation_id.len() > 256 {
        return Err("usage correlation ID is invalid".into());
    }
    validate_uuid("usage environment ID", event.request.environment_id)?;
    validate_uuid("usage credential ID", event.request.credential_id)?;
    if event.request.credential_generation == 0 || event.request.credential_generation == u64::MAX {
        return Err("usage credential generation is invalid".into());
    }
    validate_uuid("usage route ID", event.request.route_id)?;
    if event.request.route_policy_revision == 0 || event.request.route_policy_revision == u64::MAX {
        return Err("usage route policy revision is invalid".into());
    }
    if event.request.model_alias.is_empty() || event.request.model_alias.len() > 256 {
        return Err("usage model alias is invalid".into());
    }
    validate_uuid("usage model ID", event.request.model_id)?;
    match event.kind {
        CloudKind::RequestStarted => {
            require_none("attempt", event.attempt.as_ref())?;
            require_none("outcome", event.outcome.as_ref())?;
            require_none("http_status", event.http_status.as_ref())?;
            require_none("duration_ms", event.duration_ms.as_ref())?;
            require_none(
                "measurement_completeness",
                event.measurement_completeness.as_ref(),
            )?;
            require_none("total_tokens", event.total_tokens.as_ref())?;
        }
        CloudKind::AttemptStarted => {
            let attempt = event
                .attempt
                .as_ref()
                .ok_or_else(|| "attempt_started requires attempt evidence".to_string())?;
            validate_uuid("usage attempt ID", attempt.attempt_id)?;
            validate_uuid("usage target ID", attempt.target_id)?;
            require_none("outcome", event.outcome.as_ref())?;
            require_none("http_status", event.http_status.as_ref())?;
            require_none("duration_ms", event.duration_ms.as_ref())?;
            require_none(
                "measurement_completeness",
                event.measurement_completeness.as_ref(),
            )?;
            require_none("total_tokens", event.total_tokens.as_ref())?;
        }
        CloudKind::AttemptTerminal | CloudKind::RequestTerminal => {
            if matches!(event.kind, CloudKind::AttemptTerminal) {
                let attempt = event
                    .attempt
                    .as_ref()
                    .ok_or_else(|| "attempt_terminal requires attempt evidence".to_string())?;
                validate_uuid("usage attempt ID", attempt.attempt_id)?;
                validate_uuid("usage target ID", attempt.target_id)?;
            } else if let Some(attempt) = &event.attempt {
                validate_uuid("usage attempt ID", attempt.attempt_id)?;
                validate_uuid("usage target ID", attempt.target_id)?;
            }
            if event.outcome.is_none() {
                return Err("terminal usage lifecycle requires an outcome".into());
            }
            if event.duration_ms.is_none() {
                return Err("terminal usage lifecycle requires duration_ms".into());
            }
            if event.measurement_completeness.is_none() {
                return Err("terminal usage lifecycle requires measurement_completeness".into());
            }
            if event.total_tokens == Some(u64::MAX) {
                return Err("usage total_tokens sentinel is invalid".into());
            }
        }
    }
    let _ = event.occurred_at;
    Ok(event)
}

fn sample_request() -> RequestEvidence {
    RequestEvidence {
        request_id: Uuid::from_u128(1),
        correlation_id: "corr".into(),
        environment_id: Uuid::from_u128(2),
        credential_id: Uuid::from_u128(3),
        credential_generation: 1,
        route_id: Uuid::from_u128(4),
        route_policy_revision: 1,
        endpoint: InferenceEndpoint::ChatCompletions,
        model_alias: "alias".into(),
        model_id: Uuid::from_u128(5),
    }
}

fn sample_attempt() -> AttemptEvidence {
    AttemptEvidence {
        attempt_id: Uuid::from_u128(6),
        target_id: Uuid::from_u128(7),
    }
}

#[test]
fn lifecycle_schema_id_matches_cloud_contracts() {
    let cloud_source =
        include_str!("../../../../apps/cloud/crates/contracts/src/inference/lifecycle.rs");
    let cloud_schema = cloud_source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pub const INFERENCE_USAGE_LIFECYCLE_SCHEMA_V1: &str = \"")
                .and_then(|rest| rest.strip_suffix("\";"))
        })
        .expect("Cloud INFERENCE_USAGE_LIFECYCLE_SCHEMA_V1");
    assert_eq!(LIFECYCLE_SCHEMA, cloud_schema);
    assert_eq!(LIFECYCLE_SCHEMA, "a3s.gateway.usage-lifecycle.v1");
}

#[test]
fn gateway_lifecycle_encode_passes_cloud_decode_for_all_kinds() {
    let request = sample_request();
    let attempt = sample_attempt();

    let started = encode(&LifecycleEvent::request_started(&request)).unwrap();
    let decoded_started = cloud_decode(&started).expect("request_started");
    assert!(matches!(
        decoded_started.request.endpoint,
        CloudEndpoint::ChatCompletions
    ));

    let attempt_started = encode(&LifecycleEvent::attempt_started(&request, &attempt)).unwrap();
    cloud_decode(&attempt_started).expect("attempt_started");

    let attempt_terminal = encode(&LifecycleEvent::terminal(
        LifecycleEventKind::AttemptTerminal,
        &request,
        Some(&attempt),
        UsageTerminalOutcome::Failed,
        Some(503),
        12,
        None,
    ))
    .unwrap();
    let decoded_attempt = cloud_decode(&attempt_terminal).expect("attempt_terminal");
    assert!(matches!(
        decoded_attempt.measurement_completeness,
        Some(CloudMeasurement::Unknown)
    ));

    let request_terminal = encode(&LifecycleEvent::terminal(
        LifecycleEventKind::RequestTerminal,
        &request,
        None,
        UsageTerminalOutcome::Succeeded,
        Some(200),
        40,
        Some(128),
    ))
    .unwrap();
    let decoded_request = cloud_decode(&request_terminal).expect("request_terminal");
    assert!(matches!(
        decoded_request.measurement_completeness,
        Some(CloudMeasurement::UpstreamUsage)
    ));
    assert_eq!(decoded_request.total_tokens, Some(128));
}

#[test]
fn cloud_decode_rejects_forbidden_prompt_fields_on_gateway_shape() {
    let request = sample_request();
    let encoded = encode(&LifecycleEvent::request_started(&request)).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
    value["prompt"] = serde_json::json!("secret text");
    let tampered = serde_json::to_vec(&value).unwrap();
    let err = cloud_decode(&tampered).unwrap_err();
    assert!(err.contains("forbids prompt or secret field"));
}

#[test]
fn inference_endpoint_wire_values_match_cloud_usage_endpoint_v1() {
    // Cloud InferenceUsageEndpointV1 uses kebab-case; Gateway InferenceEndpoint
    // must emit the same wire strings inside lifecycle request evidence.
    for (endpoint, expected) in [
        (InferenceEndpoint::Models, "models"),
        (InferenceEndpoint::ChatCompletions, "chat-completions"),
        (InferenceEndpoint::Completions, "completions"),
        (InferenceEndpoint::Embeddings, "embeddings"),
    ] {
        let request = RequestEvidence {
            endpoint,
            ..sample_request()
        };
        let encoded = encode(&LifecycleEvent::request_started(&request)).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(value["request"]["endpoint"], expected);
        cloud_decode(&encoded).unwrap();
    }
}

#[test]
fn measurement_completeness_unknown_without_tokens_matches_cloud() {
    let request = sample_request();
    let event = LifecycleEvent::terminal(
        LifecycleEventKind::RequestTerminal,
        &request,
        None,
        UsageTerminalOutcome::Succeeded,
        Some(200),
        1,
        None,
    );
    assert!(matches!(
        event.measurement_completeness,
        Some(MeasurementCompleteness::Unknown)
    ));
    cloud_decode(&encode(&event).unwrap()).unwrap();
}
