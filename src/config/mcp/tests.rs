use super::*;
use crate::config::GatewayConfig;
use chrono::{TimeZone, Utc};
use sha2::{Digest, Sha256};

const GATEWAY_ID: &str = "11111111-1111-4111-8111-111111111111";
const ROUTE_ID: &str = "44444444-4444-4444-8444-444444444444";
const PROFILE_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_PROFILE_DIGEST: &str =
    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const VERIFIER_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn valid_acl() -> String {
    include_str!("../../../tests/fixtures/mcp-modern-stateless-snapshot.acl").to_string()
}

#[test]
fn parses_and_validates_complete_modern_mcp_projection() {
    let config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    config.validate().unwrap();

    let mcp = config.mcp.unwrap();
    assert_eq!(mcp.profiles.len(), 1);
    assert_eq!(
        mcp.profiles[PROFILE_DIGEST].protocol_versions,
        vec![MCP_PROTOCOL_VERSION]
    );
    let route_id = Uuid::parse_str(ROUTE_ID).unwrap();
    let route = &mcp.routes[&route_id];
    assert_eq!(route.profile_digest, PROFILE_DIGEST);
    assert_eq!(route.targets[0].generation, 3);
    assert_eq!(route.grants.len(), 1);
}

#[test]
fn imports_the_exact_cloud_owned_mcp01_gateway_fixture() {
    let bytes = include_bytes!("../../../tests/fixtures/mcp-modern-stateless-snapshot.acl");
    assert_eq!(
        format!("{:x}", Sha256::digest(bytes)),
        "a3c12ad36e8c2c06787ec1b42899fa5cea5a10f00ce2ab42c1abaddec50036a5"
    );
}

#[test]
fn accepts_the_same_closed_projection_in_standalone_mode() {
    let acl = valid_acl()
        .replace(
            r#"mode { kind = "cloud-managed" }"#,
            r#"mode { kind = "standalone" }"#,
        )
        .replace(&format!(r#"managed {{ gateway_id = "{GATEWAY_ID}" }}"#), "");
    let config = GatewayConfig::from_acl(&acl).unwrap();
    config.validate().unwrap();
}

#[test]
fn verifier_is_redacted_from_debug_and_serialized_views() {
    let config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let debug = format!("{config:?}");
    let json = serde_json::to_string(&config).unwrap();

    assert!(!debug.contains(VERIFIER_HASH));
    assert!(debug.contains("<redacted>"));
    assert!(!json.contains(VERIFIER_HASH));
}

#[test]
fn rejects_unknown_fields_during_acl_parse() {
    let acl = valid_acl().replace(
        "max_response_bytes = 8388608",
        "max_response_bytes = 8388608\n    legacy_sessions = true",
    );
    let error = GatewayConfig::from_acl(&acl).unwrap_err().to_string();
    assert!(error.contains("Unknown MCP service profile field"));
    assert!(error.contains("legacy_sessions"));
}

#[test]
fn rejects_legacy_versions_unsafe_paths_and_session_like_affinity() {
    let cases = [
        (
            r#"protocol_versions = ["2026-07-28"]"#,
            r#"protocol_versions = ["2025-06-18"]"#,
            "exactly protocol version",
        ),
        (
            r#"path = "/mcp""#,
            r#"path = "/mcp/*""#,
            "literal absolute path",
        ),
    ];
    for (needle, replacement, expected) in cases {
        let config = GatewayConfig::from_acl(&valid_acl().replace(needle, replacement)).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }

    let acl = valid_acl().replace(
        "stream_total_timeout = \"60m\"",
        "stream_total_timeout = \"60m\"\n    sticky { cookie = \"mcp-session\" }",
    );
    let config = GatewayConfig::from_acl(&acl).unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("cannot use sticky"));
}

#[test]
fn binds_the_profile_path_to_one_closed_exact_router_rule() {
    for rule in [
        "Host(`mcp.example.com`) && PathPrefix(`/mcp`)",
        "Host(`mcp.example.com`) && Path(`/other`)",
        "Host(`mcp.example.com`) && Path(`/mcp`) && Method(`POST`)",
        "Host(`mcp.example.com`) && Path(`/mcp`) && Headers(`x-mode`, `mcp`)",
    ] {
        let acl = valid_acl().replace("Host(`mcp.example.com`) && Path(`/mcp`)", rule);
        let error = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("exactly one Path(`/mcp`)"),
            "expected {rule:?} to fail, got {error}"
        );
    }
}

#[test]
fn rejects_mixed_profile_targets_and_profile_exceeding_bounds() {
    let mixed = valid_acl().replace(
        &format!("profile_digest = \"{PROFILE_DIGEST}\"\n      priority"),
        &format!("profile_digest = \"{OTHER_PROFILE_DIGEST}\"\n      priority"),
    );
    let error = GatewayConfig::from_acl(&mixed)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(error.contains("profile digest does not match route"));

    let oversized =
        valid_acl().replace("max_request_bytes = 524288", "max_request_bytes = 2097152");
    let error = GatewayConfig::from_acl(&oversized)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(error.contains("profile-exceeding byte bounds"));
}

#[test]
fn rejects_unsafe_origins_non_loopback_targets_and_missing_discovery() {
    let cases = [
        (
            "https://console.example.com",
            "http://console.example.com",
            "HTTPS origin",
        ),
        (
            "http://127.0.0.1:8000/",
            "http://10.0.0.8:8000/",
            "loopback HTTP port",
        ),
        (
            r#"methods = ["server/discover", "tools/list", "tools/call"]"#,
            r#"methods = ["tools/list", "tools/call"]"#,
            "mandatory server/discover",
        ),
    ];
    for (needle, replacement, expected) in cases {
        let config = GatewayConfig::from_acl(&valid_acl().replace(needle, replacement)).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(
            error.contains(expected),
            "expected {expected:?}, got {error}"
        );
    }
}

#[test]
fn rejects_legacy_and_server_to_client_methods_in_modern_grants() {
    for method in [
        "initialize",
        "notifications/initialized",
        "notifications/cancelled",
        "ping",
        "logging/setLevel",
        "resources/subscribe",
        "resources/unsubscribe",
        "roots/list",
        "sampling/createMessage",
        "elicitation/create",
    ] {
        let acl = valid_acl().replace(
            r#"methods = ["server/discover", "tools/list", "tools/call"]"#,
            &format!(r#"methods = ["server/discover", "tools/list", "tools/call", "{method}"]"#),
        );
        let error = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("invalid or duplicate method"),
            "expected {method:?} to be rejected, got {error}"
        );
    }
}

#[test]
fn rejects_subscription_grants_when_the_profile_disables_subscriptions() {
    let acl = valid_acl()
        .replace("subscriptions = true", "subscriptions = false")
        .replace(
            r#"methods = ["server/discover", "tools/list", "tools/call"]"#,
            r#"methods = ["server/discover", "tools/list", "tools/call", "subscriptions/listen"]"#,
        );
    let error = GatewayConfig::from_acl(&acl)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(error.contains("service profile disables subscriptions"));
}

#[test]
fn managed_expiry_must_equal_the_atomic_snapshot_expiry() {
    let config = GatewayConfig::from_acl(&valid_acl()).unwrap();
    let mcp = config.mcp.unwrap();
    let exact = Utc.with_ymd_and_hms(2099, 1, 1, 0, 0, 0).unwrap();
    mcp.validate_managed_expiry(exact).unwrap();
    assert!(mcp
        .validate_managed_expiry(exact - chrono::Duration::seconds(1))
        .unwrap_err()
        .contains("exactly match"));
}
