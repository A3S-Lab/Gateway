use super::GatewayMetrics;
use crate::config::{
    GatewayConfig, LoadBalancerConfig, ScalingConfig, ServerConfig, ServiceConfig, Strategy,
};
use crate::gateway::builders::build_scaling_state;
use crate::service::ServiceRegistry;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

fn service(url: &str) -> ServiceConfig {
    ServiceConfig {
        load_balancer: LoadBalancerConfig {
            strategy: Strategy::RoundRobin,
            request_timeout: "30s".to_string(),
            stream_idle_timeout: "5m".to_string(),
            stream_total_timeout: "60m".to_string(),
            servers: vec![ServerConfig {
                url: url.to_string(),
                weight: 1,
            }],
            health_check: None,
            sticky: None,
        },
        scaling: None,
        revisions: Vec::new(),
        rollout: None,
        mirror: None,
        failover: None,
    }
}

fn activate(
    metrics: &GatewayMetrics,
    services: HashMap<String, ServiceConfig>,
) -> Arc<ServiceRegistry> {
    let config = GatewayConfig {
        services,
        ..GatewayConfig::default()
    };
    let registry = Arc::new(ServiceRegistry::from_config(&config.services).unwrap());
    let prepared = metrics.prepare_telemetry(&config, registry.as_ref(), None, true);
    metrics.activate_telemetry(prepared);
    registry
}

#[test]
fn service_request_lifetime_is_drop_safe() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );

    let request = metrics
        .track_service_request("api", Instant::now())
        .expect("configured service must be tracked");
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_active_requests{service=\"api\"} 1"));

    drop(request);
    let output = metrics.render_prometheus();
    assert!(output.contains("gateway_service_active_requests{service=\"api\"} 0"));
    assert!(output.contains("gateway_service_request_duration_seconds_count{service=\"api\"} 1"));
}

#[test]
fn ttft_is_recorded_only_for_the_first_non_empty_chunk() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );

    let mut request = metrics
        .track_service_request("api", Instant::now())
        .expect("configured service must be tracked");
    request.record_ttft_once();
    request.record_ttft_once();
    drop(request);

    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_ttft_seconds_count{service=\"api\"} 1"));
}

#[test]
fn event_signals_are_unknown_until_observed() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );

    let before = metrics.render_prometheus();
    assert!(!before.contains(
        "gateway_service_telemetry_observation_timestamp_seconds{service=\"api\",signal=\"request_latency\"}"
    ));
    assert!(before.contains(
        "gateway_service_telemetry_observation_timestamp_seconds{service=\"api\",signal=\"active_requests\"}"
    ));

    drop(
        metrics
            .track_service_request("api", Instant::now())
            .unwrap(),
    );
    let after = metrics.render_prometheus();
    assert!(after.contains(
        "gateway_service_telemetry_observation_timestamp_seconds{service=\"api\",signal=\"request_latency\"}"
    ));
    assert!(after.contains(
        "gateway_service_telemetry_age_seconds{service=\"api\",signal=\"request_latency\"}"
    ));
}

#[test]
fn event_signal_age_increases_after_the_last_observation() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );
    drop(
        metrics
            .track_service_request("api", Instant::now())
            .unwrap(),
    );
    std::thread::sleep(std::time::Duration::from_millis(20));

    let output = metrics.render_prometheus();
    let age = output
        .lines()
        .find(|line| {
            line.starts_with(
                "gateway_service_telemetry_age_seconds{service=\"api\",signal=\"request_latency\"}",
            )
        })
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<f64>().ok())
        .expect("request-latency age sample");
    assert!(age >= 0.01, "expected a stale age, got {age}");
}

#[test]
fn unconfigured_labels_cannot_create_telemetry_series() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );

    assert!(metrics
        .track_service_request("attacker-controlled", Instant::now())
        .is_none());
    metrics.record_service_request("attacker-controlled");
    metrics.record_router_request("attacker-controlled");
    metrics.record_middleware_invocation("attacker-controlled");
    assert!(!metrics.render_prometheus().contains("attacker-controlled"));
}

#[test]
fn reload_removes_orphaned_service_series() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("old".to_string(), service("http://127.0.0.1:8000"))]),
    );
    metrics.record_service_request("old");
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_active_requests{service=\"old\"}"));

    activate(
        &metrics,
        HashMap::from([("new".to_string(), service("http://127.0.0.1:8001"))]),
    );
    let output = metrics.render_prometheus();
    assert!(!output.contains("service=\"old\""));
    assert!(!output.contains("gateway_service_requests_total{service=\"old\"}"));
    assert!(output.contains("gateway_service_active_requests{service=\"new\"}"));
}

#[test]
fn reload_preserves_in_flight_accounting_for_an_unchanged_service() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );
    let request = metrics
        .track_service_request("api", Instant::now())
        .unwrap();

    activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8001"))]),
    );
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_active_requests{service=\"api\"} 1"));

    drop(request);
    let output = metrics.render_prometheus();
    assert!(output.contains("gateway_service_active_requests{service=\"api\"} 0"));
    assert!(output.contains("gateway_service_request_duration_seconds_count{service=\"api\"} 1"));
}

#[test]
fn fallback_retargets_active_and_latency_accounting() {
    let metrics = GatewayMetrics::new();
    activate(
        &metrics,
        HashMap::from([
            ("primary".to_string(), service("http://127.0.0.1:8000")),
            ("fallback".to_string(), service("http://127.0.0.1:8001")),
        ]),
    );
    let mut request = metrics
        .track_service_request("primary", Instant::now())
        .unwrap();

    assert!(request.retarget("fallback"));
    let during = metrics.render_prometheus();
    assert!(during.contains("gateway_service_active_requests{service=\"primary\"} 0"));
    assert!(during.contains("gateway_service_active_requests{service=\"fallback\"} 1"));
    drop(request);

    let after = metrics.render_prometheus();
    assert!(after.contains("gateway_service_request_duration_seconds_count{service=\"primary\"} 1"));
    assert!(
        after.contains("gateway_service_request_duration_seconds_count{service=\"fallback\"} 1")
    );
}

#[test]
fn disabled_metrics_expose_no_service_telemetry() {
    let metrics = GatewayMetrics::new();
    let services = HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]);
    let registry = ServiceRegistry::from_config(&services).unwrap();
    let config = GatewayConfig {
        services,
        ..GatewayConfig::default()
    };
    let prepared = metrics.prepare_telemetry(&config, &registry, None, false);
    metrics.activate_telemetry(prepared);

    assert!(metrics
        .track_service_request("api", Instant::now())
        .is_none());
    assert!(!metrics
        .render_prometheus()
        .contains("gateway_service_active_requests"));
}

#[test]
fn prometheus_labels_are_escaped_and_backend_credentials_are_opaque() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_request("router\"\\\nname");
    metrics.record_backend_request("https://alice:super-secret@example.test/v1");
    metrics.record_backend_request("https://bob:different-secret@example.test/v2?token=hidden");

    let output = metrics.render_prometheus();
    assert!(output.contains("router=\"router\\\"\\\\\\nname\""));
    assert!(!output.contains("alice"));
    assert!(!output.contains("bob"));
    assert!(!output.contains("super-secret"));
    assert!(!output.contains("different-secret"));
    assert!(output.contains("gateway_backend_requests_total{backend_id=\"b_"));
    assert_eq!(metrics.snapshot().backend_requests.len(), 1);
    assert_eq!(
        metrics.snapshot().backend_requests.values().next(),
        Some(&2)
    );
}

#[test]
fn backend_pressure_uses_exact_live_backend_state() {
    let metrics = GatewayMetrics::new();
    let registry = activate(
        &metrics,
        HashMap::from([("api".to_string(), service("http://127.0.0.1:8000"))]),
    );
    let backend = registry.get("api").unwrap().backends()[0].clone();
    backend.inc_connections();
    backend.set_healthy(false);

    let output = metrics.render_prometheus();
    let labels = format!("{{service=\"api\",backend_id=\"{}\"}}", backend.metric_id());
    assert!(output.contains(&format!("gateway_backend_active_requests{labels} 1")));
    assert!(output.contains(&format!("gateway_backend_healthy{labels} 0")));
}

#[tokio::test]
async fn queue_depth_is_exported_from_the_exact_buffer() {
    let metrics = Arc::new(GatewayMetrics::new());
    let mut api = service("http://127.0.0.1:8000");
    api.scaling = Some(ScalingConfig {
        buffer_enabled: true,
        buffer_size: 1,
        buffer_timeout_secs: 60,
        ..ScalingConfig::default()
    });
    let config = GatewayConfig {
        services: HashMap::from([("api".to_string(), api)]),
        ..GatewayConfig::default()
    };

    let registry = ServiceRegistry::from_config(&config.services).unwrap();
    let scaling = build_scaling_state(&config).unwrap();
    let prepared = metrics.prepare_telemetry(&config, &registry, Some(scaling.as_ref()), true);
    metrics.activate_telemetry(prepared);

    let buffer = scaling.buffers["api"].clone();
    let waiting = {
        let buffer = buffer.clone();
        tokio::spawn(async move { buffer.wait_for_backend().await })
    };
    while buffer.queue_depth() == 0 {
        tokio::task::yield_now().await;
    }

    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_queue_depth{service=\"api\"} 1"));

    waiting.abort();
    let _ = waiting.await;
    assert_eq!(buffer.queue_depth(), 0);
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_queue_depth{service=\"api\"} 0"));
}
