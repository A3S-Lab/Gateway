use super::*;

#[test]
fn test_initial_state() {
    let metrics = GatewayMetrics::new();
    assert_eq!(metrics.total_requests(), 0);
    assert_eq!(metrics.active_connections(), 0);
}

#[test]
fn test_record_request_increments_total() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 100);
    metrics.record_request(404, 50);
    assert_eq!(metrics.total_requests(), 2);
}

#[test]
fn test_record_request_status_classes() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 0);
    metrics.record_request(201, 0);
    metrics.record_request(301, 0);
    metrics.record_request(400, 0);
    metrics.record_request(404, 0);
    metrics.record_request(500, 0);

    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.status_classes["2xx"], 2);
    assert_eq!(snapshot.status_classes["3xx"], 1);
    assert_eq!(snapshot.status_classes["4xx"], 2);
    assert_eq!(snapshot.status_classes["5xx"], 1);
}

#[test]
fn test_record_response_bytes() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 1000);
    metrics.record_request(200, 500);
    assert_eq!(metrics.snapshot().total_response_bytes, 1500);
}

#[test]
fn test_connections() {
    let metrics = GatewayMetrics::new();
    metrics.inc_connections();
    metrics.inc_connections();
    assert_eq!(metrics.active_connections(), 2);
    metrics.dec_connections();
    assert_eq!(metrics.active_connections(), 1);
}

#[test]
fn test_router_requests() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_request("api");
    metrics.record_router_request("api");
    metrics.record_router_request("web");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.router_requests["api"], 2);
    assert_eq!(snapshot.router_requests["web"], 1);
}

#[test]
fn test_backend_requests_are_opaque() {
    let metrics = GatewayMetrics::new();
    metrics.record_backend_request("http://b1:8080");
    metrics.record_backend_request("http://b2:8080");
    metrics.record_backend_request("http://b1:8080");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.backend_requests.len(), 2);
    assert!(snapshot.backend_requests.values().any(|count| *count == 2));
    assert!(snapshot.backend_requests.values().any(|count| *count == 1));
    assert!(snapshot
        .backend_requests
        .keys()
        .all(|key| key.starts_with("b_")));
}

#[test]
fn test_snapshot_serialization() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 100);
    metrics.inc_connections();
    let json = serde_json::to_string(&metrics.snapshot()).unwrap();
    let parsed: MetricsSnapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.total_requests, 1);
    assert_eq!(parsed.active_connections, 1);
}

#[test]
fn test_prometheus_format() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 1024);
    metrics.record_request(500, 0);
    metrics.inc_connections();

    let output = metrics.render_prometheus();
    assert!(output.contains("gateway_requests_total 2"));
    assert!(output.contains("gateway_responses_total{status_class=\"2xx\"} 1"));
    assert!(output.contains("gateway_responses_total{status_class=\"5xx\"} 1"));
    assert!(output.contains("gateway_response_bytes_total 1024"));
    assert!(output.contains("gateway_active_connections 1"));
}

#[test]
fn test_prometheus_format_with_routers() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_request("api-router");
    assert!(metrics
        .render_prometheus()
        .contains("gateway_router_requests_total{router=\"api-router\"} 1"));
}

#[test]
fn test_prometheus_format_with_backends() {
    let metrics = GatewayMetrics::new();
    metrics.record_backend_request("http://localhost:8080");
    let output = metrics.render_prometheus();
    assert!(output.contains("gateway_backend_requests_total{backend_id=\"b_"));
    assert!(!output.contains("http://localhost:8080"));
}

#[test]
fn test_prometheus_has_help_and_type() {
    let output = GatewayMetrics::new().render_prometheus();
    assert!(output.contains("# HELP gateway_requests_total"));
    assert!(output.contains("# TYPE gateway_requests_total counter"));
    assert!(output.contains("# TYPE gateway_active_connections gauge"));
}

#[test]
fn test_reset() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 100);
    metrics.record_router_request("api");
    metrics.inc_connections();
    metrics.reset();
    assert_eq!(metrics.total_requests(), 0);
    assert_eq!(metrics.active_connections(), 0);
    assert!(metrics.snapshot().router_requests.is_empty());
}

#[test]
fn test_default() {
    assert_eq!(GatewayMetrics::default().total_requests(), 0);
}

#[test]
fn test_unknown_status_class() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(100, 0);
    metrics.record_request(600, 0);
    assert_eq!(metrics.total_requests(), 2);
    assert_eq!(metrics.snapshot().status_classes["2xx"], 0);
}

#[test]
fn test_service_requests() {
    let metrics = GatewayMetrics::new();
    metrics.record_service_request("api-service");
    metrics.record_service_request("api-service");
    metrics.record_service_request("web-service");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.service_requests["api-service"], 2);
    assert_eq!(snapshot.service_requests["web-service"], 1);
}

#[test]
fn test_middleware_invocations() {
    let metrics = GatewayMetrics::new();
    metrics.record_middleware_invocation("rate-limit");
    metrics.record_middleware_invocation("rate-limit");
    metrics.record_middleware_invocation("auth");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.middleware_invocations["rate-limit"], 2);
    assert_eq!(snapshot.middleware_invocations["auth"], 1);
}

#[test]
fn test_router_latency() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_latency("api", 1500);
    metrics.record_router_latency("api", 2500);
    metrics.record_router_latency("web", 500);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.router_latency_us["api"], 4000);
    assert_eq!(snapshot.router_latency_us["web"], 500);
}

#[test]
fn test_router_errors() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_error("api");
    metrics.record_router_error("api");
    metrics.record_router_error("web");
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.router_errors["api"], 2);
    assert_eq!(snapshot.router_errors["web"], 1);
}

#[test]
fn test_service_errors() {
    let metrics = GatewayMetrics::new();
    metrics.record_service_error("backend");
    metrics.record_service_error("backend");
    assert_eq!(metrics.snapshot().service_errors["backend"], 2);
}

#[test]
fn test_prometheus_format_with_services() {
    let metrics = GatewayMetrics::new();
    metrics.record_service_request("api-svc");
    assert!(metrics
        .render_prometheus()
        .contains("gateway_service_requests_total{service=\"api-svc\"} 1"));
}

#[test]
fn test_prometheus_format_with_middleware() {
    let metrics = GatewayMetrics::new();
    metrics.record_middleware_invocation("cors");
    assert!(metrics
        .render_prometheus()
        .contains("gateway_middleware_invocations_total{middleware=\"cors\"} 1"));
}

#[test]
fn test_prometheus_format_with_latency() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_latency("api", 5000);
    assert!(metrics
        .render_prometheus()
        .contains("gateway_router_latency_microseconds_total{router=\"api\"} 5000"));
}

#[test]
fn test_prometheus_format_with_errors() {
    let metrics = GatewayMetrics::new();
    metrics.record_router_error("api");
    metrics.record_service_error("backend");
    let output = metrics.render_prometheus();
    assert!(output.contains("gateway_router_errors_total{router=\"api\"} 1"));
    assert!(output.contains("gateway_service_errors_total{service=\"backend\"} 1"));
}

#[test]
fn test_reset_clears_all() {
    let metrics = GatewayMetrics::new();
    metrics.record_request(200, 100);
    metrics.record_router_request("api");
    metrics.record_service_request("svc");
    metrics.record_middleware_invocation("auth");
    metrics.record_router_latency("api", 1000);
    metrics.record_router_error("api");
    metrics.record_service_error("svc");
    metrics.inc_connections();
    metrics.reset();
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.total_requests, 0);
    assert_eq!(snapshot.active_connections, 0);
    assert!(snapshot.router_requests.is_empty());
    assert!(snapshot.service_requests.is_empty());
    assert!(snapshot.middleware_invocations.is_empty());
    assert!(snapshot.router_latency_us.is_empty());
    assert!(snapshot.router_errors.is_empty());
    assert!(snapshot.service_errors.is_empty());
}
