use super::*;
use crate::config::GatewayConfig;

const GATEWAY_ID: &str = "11111111-1111-4111-8111-111111111111";
const ENVIRONMENT_ID: &str = "22222222-2222-4222-8222-222222222222";
const CREDENTIAL_ID: &str = "33333333-3333-4333-8333-333333333333";
const ROUTE_ID: &str = "44444444-4444-4444-8444-444444444444";
const MODEL_ID: &str = "55555555-5555-4555-8555-555555555555";
const TARGET_ID: &str = "66666666-6666-4666-8666-666666666666";
const VERIFIER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn valid_acl() -> String {
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
    servers = [{{ url = "http://127.0.0.1:8000" }}]
  }}
}}

inference {{
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
}}
"#
    )
}

#[test]
fn parses_and_validates_a_complete_inference_policy() {
    let config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    config.validate().unwrap();

    let inference = config.inference.unwrap();
    let credential_id = Uuid::parse_str(CREDENTIAL_ID).unwrap();
    let route_id = Uuid::parse_str(ROUTE_ID).unwrap();
    let credential = &inference.credentials[&credential_id];
    assert_eq!(credential.prefix, "a3s_inf_abc12345");
    assert_eq!(credential.verifier_hash(), VERIFIER_HASH);
    assert_eq!(credential.generation, 7);

    let route = &inference.routes[&route_id];
    assert_eq!(route.router, "inference");
    assert_eq!(route.policy_revision, 11);
    assert_eq!(route.models["chat-model"].targets.len(), 1);
    assert_eq!(
        route.grants[&credential_id].endpoints,
        vec![
            InferenceEndpoint::Models,
            InferenceEndpoint::ChatCompletions,
            InferenceEndpoint::Embeddings,
        ]
    );
}

#[test]
fn verifier_is_absent_from_debug_and_serialized_config_views() {
    let config = GatewayConfig::from_acl(&valid_acl()).unwrap();

    let debug = format!("{config:?}");
    let json = serde_json::to_string(&config).unwrap();

    assert!(!debug.contains(VERIFIER_HASH));
    assert!(debug.contains("<redacted>"));
    assert!(!json.contains(VERIFIER_HASH));
    assert!(!json.contains("\"verifier_hash\""));
    assert!(json.contains(CREDENTIAL_ID));
}

#[test]
fn rejects_unknown_or_plaintext_inference_fields() {
    for (needle, replacement) in [
        (
            "expires_at = \"2099-01-01T00:00:00Z\"",
            "expires_at = \"2099-01-01T00:00:00Z\"\n  unknown = true",
        ),
        (
            &format!("verifier_hash = \"{VERIFIER_HASH}\""),
            &format!(
                "verifier_hash = \"{VERIFIER_HASH}\"\n    plaintext_key = \"must-not-appear\""
            ),
        ),
    ] {
        let acl = valid_acl().replace(needle, replacement);
        let error = GatewayConfig::from_acl(&acl).unwrap_err();
        assert!(error.to_string().contains("Unknown inference"));
    }
}

#[test]
fn rejects_dynamic_or_unsafe_verifier_hashes() {
    let dynamic = valid_acl().replace(
        &format!("verifier_hash = \"{VERIFIER_HASH}\""),
        "verifier_hash = env(\"INFERENCE_VERIFIER_HASH\")",
    );
    let error = GatewayConfig::from_acl(&dynamic).unwrap_err();
    assert!(error.to_string().contains("literal string"));

    let replacements = [
        "$argon2i$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=19455,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=262145,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=19456,t=11,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=19456,t=2,p=5$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=19456,t=2,p=1$c2hvcnQ$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$c2hvcnQ".to_string(),
        format!(
            "$argon2id$v=19$m=19456,t=2,p=1${}$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "A".repeat(87)
        ),
        format!(
            "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA${}",
            "A".repeat(87)
        ),
    ];
    for replacement in replacements {
        let acl = valid_acl().replace(VERIFIER_HASH, &replacement);
        let config = GatewayConfig::from_acl(&acl).unwrap();
        let error = config.validate().unwrap_err();
        assert!(error.to_string().contains("verifier_hash"));
        assert!(!error.to_string().contains(&replacement));
    }
}

#[test]
fn rejects_duplicate_prefixes_and_target_identities() {
    let mut duplicate_prefix = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let inference = duplicate_prefix.inference.as_mut().unwrap();
    let credential_id = Uuid::parse_str(CREDENTIAL_ID).unwrap();
    let mut credential = inference.credentials[&credential_id].clone();
    credential.credential_id = Uuid::new_v4();
    inference
        .credentials
        .insert(credential.credential_id, credential);
    assert!(duplicate_prefix
        .validate()
        .unwrap_err()
        .to_string()
        .contains("prefix"));

    let mut duplicate_target = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let inference = duplicate_target.inference.as_mut().unwrap();
    let route_id = Uuid::parse_str(ROUTE_ID).unwrap();
    let targets = &mut inference
        .routes
        .get_mut(&route_id)
        .unwrap()
        .models
        .get_mut("chat-model")
        .unwrap()
        .targets;
    targets.push(targets[0].clone());
    assert!(duplicate_target
        .validate()
        .unwrap_err()
        .to_string()
        .contains("target IDs"));
}

#[test]
fn permits_revoked_credentials_only_after_grants_are_removed() {
    let mut config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let inference = config.inference.as_mut().unwrap();
    let credential_id = Uuid::parse_str(CREDENTIAL_ID).unwrap();
    inference
        .credentials
        .get_mut(&credential_id)
        .unwrap()
        .revoked = true;
    inference
        .routes
        .get_mut(&Uuid::parse_str(ROUTE_ID).unwrap())
        .unwrap()
        .grants
        .clear();

    config.validate().unwrap();
}

#[test]
fn inference_policy_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}

    assert_send_sync::<InferenceConfig>();
    assert_send_sync::<InferenceCredentialConfig>();
    assert_send_sync::<InferenceRouteConfig>();
    assert_send_sync::<InferenceGrantConfig>();
}

#[test]
fn rejects_unsafe_credential_and_grant_relationships() {
    let cases = [
        (
            "audience = \"cloud-inference\"",
            "audience = \"management\"",
            "unsupported audience",
        ),
        (
            "revoked = false",
            "revoked = true",
            "grants revoked credential",
        ),
        (
            "credential_generation = 7",
            "credential_generation = 6",
            "does not match credential",
        ),
        (
            &format!("environment_id = \"{ENVIRONMENT_ID}\"\n    policy_revision"),
            "environment_id = \"77777777-7777-4777-8777-777777777777\"\n    policy_revision",
            "belongs to another environment",
        ),
    ];

    for (needle, replacement, expected) in cases {
        let acl = valid_acl().replace(needle, replacement);
        let config = GatewayConfig::from_acl(&acl).unwrap();
        let error = config.validate().unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn rejects_invalid_routes_targets_and_limits() {
    let cases = [
        (
            "router = \"inference\"",
            "router = \"missing\"",
            "unknown router",
        ),
        (
            "service = \"model-service\"",
            "service = \"missing\"",
            "unknown service",
        ),
        ("priority = 0", "priority = 1", "contiguous from zero"),
        ("weight = 100", "weight = 0", "weight must be positive"),
        (
            "request_burst = 16",
            "request_burst = 121",
            "invalid limits",
        ),
        (
            "models = [\"chat-model\"]",
            "models = [\"unknown\"]",
            "unknown or duplicate model",
        ),
    ];

    for (needle, replacement, expected) in cases {
        let acl = valid_acl().replace(needle, replacement);
        let config = GatewayConfig::from_acl(&acl).unwrap();
        let error = config.validate().unwrap_err();
        assert!(
            error.to_string().contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn rejects_out_of_order_target_priorities() {
    let mut config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let route_id = Uuid::parse_str(ROUTE_ID).unwrap();
    let targets = &mut config
        .inference
        .as_mut()
        .unwrap()
        .routes
        .get_mut(&route_id)
        .unwrap()
        .models
        .get_mut("chat-model")
        .unwrap()
        .targets;
    targets[0].priority = 1;
    let mut fallback = targets[0].clone();
    fallback.target_id = Uuid::new_v4();
    fallback.priority = 0;
    targets.push(fallback);

    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("ordered by ascending priority"));
}

#[test]
fn inference_policy_requires_managed_mode_and_an_unexpired_window() {
    let standalone = valid_acl()
        .replace("cloud-managed", "standalone")
        .replace(&format!("managed {{ gateway_id = \"{GATEWAY_ID}\" }}"), "");
    let config = GatewayConfig::from_acl(&standalone).unwrap();
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("requires cloud-managed"));

    let expired = valid_acl().replace(
        "expires_at = \"2099-01-01T00:00:00Z\"",
        "expires_at = \"2020-01-01T00:00:00Z\"",
    );
    let config = GatewayConfig::from_acl(&expired).unwrap();
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("has expired"));
}
