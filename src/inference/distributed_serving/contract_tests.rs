use super::contract::*;
use serde_json::json;
use uuid::Uuid;

const EXECUTION_ID: &str = "11111111-1111-4111-8111-111111111111";
const WORKER_EPOCH: &str = "22222222-2222-4222-8222-222222222222";
const PROFILE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn decode_prepare_fixture_matches_power_v1_and_redacts_prompt_content() {
    let request = DecodePrepareRequest {
        schema: DISTRIBUTED_SERVING_SCHEMA,
        execution_id: Uuid::parse_str(EXECUTION_ID).unwrap(),
        worker_epoch: Uuid::parse_str(WORKER_EPOCH).unwrap(),
        execution_profile_sha256: PROFILE.to_string(),
        expires_at: "2026-08-28T12:00:30Z".parse().unwrap(),
        request: PhaseRequestPayload::ChatCompletions {
            body: json!({
                "model": "internal/model-v1",
                "messages": [{"role": "user", "content": "secret prompt"}],
                "stream": true
            }),
        },
    };
    let actual = serde_json::to_value(&request).unwrap();
    let expected: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/distributed-serving-v1/decode-prepare.json"
    ))
    .unwrap();
    assert_eq!(actual, expected);
    let debug = format!("{request:?}");
    assert!(!debug.contains("secret prompt"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn decode_stream_fixture_is_strict_and_bound_to_one_execution() {
    let binding = ProtocolBinding {
        execution_id: Uuid::parse_str(EXECUTION_ID).unwrap(),
        worker_epoch: Uuid::parse_str(WORKER_EPOCH).unwrap(),
        execution_profile_sha256: PROFILE.to_string(),
    };
    let frames =
        include_str!("../../../tests/fixtures/distributed-serving-v1/decode-stream.ndjson")
            .lines()
            .map(|line| serde_json::from_str::<DecodeStreamFrame>(line).unwrap())
            .collect::<Vec<_>>();
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(|frame| binding.matches_stream(frame)));
    assert!(matches!(frames[0].payload, DecodeStreamEvent::Ready));
    assert!(matches!(
        frames[1].payload,
        DecodeStreamEvent::Chunk { sequence: 0, .. }
    ));
    assert!(matches!(
        frames[2].payload,
        DecodeStreamEvent::Completed { sequence: 1 }
    ));
    let chunk_debug = format!("{:?}", frames[1].payload);
    assert!(!chunk_debug.contains("token"));
    assert!(chunk_debug.contains("[REDACTED]"));

    let mut unknown: serde_json::Value = serde_json::from_str(
        include_str!("../../../tests/fixtures/distributed-serving-v1/decode-stream.ndjson")
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap();
    unknown["unknown"] = json!(true);
    assert!(serde_json::from_value::<DecodeStreamFrame>(unknown).is_err());
}

#[test]
fn opaque_transfer_values_round_trip_without_becoming_loggable_domain_state() {
    let value = OpaqueTransferValue::from_value(json!({
        "binding": {"protocol": "ucx", "endpoint": "private"},
        "token": "sensitive"
    }));
    let encoded = serde_json::to_value(&value).unwrap();
    let decoded: OpaqueTransferValue = serde_json::from_value(encoded.clone()).unwrap();
    assert_eq!(serde_json::to_value(decoded).unwrap(), encoded);
    let debug = format!("{value:?}");
    assert!(!debug.contains("sensitive"));
    assert!(debug.contains("[REDACTED]"));
}

#[test]
fn recompute_reason_keeps_the_exact_power_wire_vocabulary() {
    let decision: PhaseDecision<()> = serde_json::from_value(json!({
        "decision": "recompute",
        "reason": "state-stale"
    }))
    .unwrap();
    assert_eq!(
        decision,
        PhaseDecision::Recompute {
            reason: RecomputeReason::Stale
        }
    );
    assert!(serde_json::from_value::<PhaseDecision<()>>(json!({
        "decision": "recompute",
        "reason": "stale"
    }))
    .is_err());
}

#[test]
fn contract_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DecodePrepareRequest>();
    assert_send_sync::<PrefillExecuteRequest>();
    assert_send_sync::<DecodeExecuteRequest>();
    assert_send_sync::<DecodeStreamFrame>();
    assert_send_sync::<ProtocolBinding>();
}
