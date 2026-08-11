use super::*;

// --- Entrypoint parsing ---

#[test]
fn test_parse_entrypoint_minimal() {
    let ep = parse_entrypoint_body(r#"address = "0.0.0.0:8080""#).unwrap();
    assert_eq!(ep.address, "0.0.0.0:8080");
    assert_eq!(ep.protocol, Protocol::Http);
    assert!(ep.tls.is_none());
}

#[test]
fn test_parse_entrypoint_tcp() {
    let ep = parse_entrypoint_body(
        r#"
        address  = "0.0.0.0:9000"
        protocol = "tcp"
        max_connections = 1000
        tcp_allowed_ips = ["10.0.0.0/8"]
    "#,
    )
    .unwrap();
    assert_eq!(ep.protocol, Protocol::Tcp);
    assert_eq!(ep.max_connections, Some(1000));
    assert_eq!(ep.tcp_allowed_ips, vec!["10.0.0.0/8"]);
}

#[test]
fn test_parse_entrypoint_udp() {
    let ep = parse_entrypoint_body(
        r#"
        address  = "0.0.0.0:5353"
        protocol = "udp"
        udp_session_timeout_secs = 60
        udp_max_sessions = 5000
    "#,
    )
    .unwrap();
    assert_eq!(ep.protocol, Protocol::Udp);
    assert_eq!(ep.udp_session_timeout_secs, Some(60));
    assert_eq!(ep.udp_max_sessions, Some(5000));
}

#[test]
fn test_parse_entrypoint_invalid_protocol() {
    let err = parse_entrypoint_body(
        r#"
        address  = "0.0.0.0:80"
        protocol = "grpc"
    "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Invalid entrypoint protocol"));
}

#[test]
fn test_parse_entrypoint_missing_address() {
    let err = parse_entrypoint_body(r#"protocol = "http""#).unwrap_err();
    assert!(err.to_string().contains("address"));
}

// --- TLS parsing ---

#[test]
fn test_parse_tls_minimal() {
    let tls = parse_tls_body(
        r#"
        cert_file = "/etc/certs/cert.pem"
        key_file  = "/etc/certs/key.pem"
    "#,
    )
    .unwrap();
    assert_eq!(tls.cert_file, "/etc/certs/cert.pem");
    assert_eq!(tls.key_file, "/etc/certs/key.pem");
    assert!(!tls.acme);
    assert_eq!(tls.min_version, "1.2");
}

#[test]
fn test_parse_tls_with_acme() {
    let tls = parse_tls_body(
        r#"
        cert_file     = "/etc/certs/cert.pem"
        key_file      = "/etc/certs/key.pem"
        acme          = true
        acme_email    = "admin@example.com"
        acme_domains  = ["example.com", "www.example.com"]
        acme_staging  = true
        acme_storage_path = "/var/acme"
        min_version   = "1.3"
    "#,
    )
    .unwrap();
    assert!(tls.acme);
    assert_eq!(tls.acme_email.as_deref(), Some("admin@example.com"));
    assert_eq!(tls.acme_domains, vec!["example.com", "www.example.com"]);
    assert!(tls.acme_staging);
    assert_eq!(tls.acme_storage_path.as_deref(), Some("/var/acme"));
    assert_eq!(tls.min_version, "1.3");
}

// --- Router parsing ---

#[test]
fn test_parse_router_minimal() {
    let r = parse_router_body(
        r#"
        rule    = "PathPrefix(`/api`)"
        service = "backend"
    "#,
    )
    .unwrap();
    assert_eq!(r.rule, "PathPrefix(`/api`)");
    assert_eq!(r.service, "backend");
    assert!(r.entrypoints.is_empty());
    assert!(r.middlewares.is_empty());
    assert_eq!(r.priority, 0);
}

#[test]
fn test_parse_router_full() {
    let r = parse_router_body(
        r#"
        rule        = "Host(`api.example.com`) && PathPrefix(`/v1`)"
        service     = "api-backend"
        entrypoints = ["websecure"]
        middlewares  = ["auth", "rate-limit"]
        priority    = 10
    "#,
    )
    .unwrap();
    assert_eq!(r.entrypoints, vec!["websecure"]);
    assert_eq!(r.middlewares, vec!["auth", "rate-limit"]);
    assert_eq!(r.priority, 10);
}

#[test]
fn test_parse_router_missing_rule() {
    let err = parse_router_body(r#"service = "backend""#).unwrap_err();
    assert!(err.to_string().contains("rule"));
}

#[test]
fn test_parse_router_missing_service() {
    let err = parse_router_body(r#"rule = "PathPrefix(`/`)" "#).unwrap_err();
    assert!(err.to_string().contains("service"));
}

// --- Service / LoadBalancer parsing ---

#[test]
fn test_parse_service_minimal() {
    let svc = parse_service_body(
        r#"
        load_balancer {
            servers = [{ url = "http://127.0.0.1:8001" }]
        }
    "#,
    )
    .unwrap();
    assert_eq!(svc.load_balancer.strategy, Strategy::RoundRobin);
    assert_eq!(svc.load_balancer.request_timeout, "30s");
    assert_eq!(svc.load_balancer.stream_idle_timeout, "5m");
    assert_eq!(svc.load_balancer.stream_total_timeout, "60m");
    assert_eq!(svc.load_balancer.servers.len(), 1);
    assert_eq!(svc.load_balancer.servers[0].url, "http://127.0.0.1:8001");
    assert_eq!(svc.load_balancer.servers[0].weight, 1);
}

#[test]
fn test_parse_service_all_strategies() {
    for (input, expected) in [
        ("round-robin", Strategy::RoundRobin),
        ("weighted", Strategy::Weighted),
        ("least-connections", Strategy::LeastConnections),
        ("random", Strategy::Random),
    ] {
        let svc = parse_service_body(&format!(
            r#"
            load_balancer {{
                strategy = "{input}"
                servers = [{{ url = "http://127.0.0.1:8001" }}]
            }}
        "#
        ))
        .unwrap();
        assert_eq!(svc.load_balancer.strategy, expected);
    }
}

#[test]
fn test_parse_service_invalid_strategy() {
    let err = parse_service_body(
        r#"
        load_balancer {
            strategy = "fastest"
            servers = [{ url = "http://127.0.0.1:8001" }]
        }
    "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("strategy"));
}

#[test]
fn test_parse_service_with_health_check() {
    let svc = parse_service_body(
        r#"
        load_balancer {
            servers = [{ url = "http://127.0.0.1:8001" }]
            health_check {
                path     = "/health"
                interval = "5s"
                timeout  = "2s"
                unhealthy_threshold = 5
                healthy_threshold   = 2
            }
        }
    "#,
    )
    .unwrap();
    let hc = svc.load_balancer.health_check.unwrap();
    assert_eq!(hc.path, "/health");
    assert_eq!(hc.interval, "5s");
    assert_eq!(hc.timeout, "2s");
    assert_eq!(hc.unhealthy_threshold, 5);
    assert_eq!(hc.healthy_threshold, 2);
}

#[test]
fn test_parse_service_with_sticky() {
    let svc = parse_service_body(
        r#"
        load_balancer {
            servers = [{ url = "http://127.0.0.1:8001" }]
            sticky { cookie = "srv_id" }
        }
    "#,
    )
    .unwrap();
    assert_eq!(svc.load_balancer.sticky.unwrap().cookie, "srv_id");
}

#[test]
fn test_parse_service_with_mirror() {
    let svc = parse_service_body(
        r#"
        load_balancer {
            servers = [{ url = "http://127.0.0.1:8001" }]
        }
        mirror {
            service    = "shadow"
            percentage = 5
        }
    "#,
    )
    .unwrap();
    let mirror = svc.mirror.unwrap();
    assert_eq!(mirror.service, "shadow");
    assert_eq!(mirror.percentage, 5);
}

#[test]
fn test_parse_service_with_failover() {
    let svc = parse_service_body(
        r#"
        load_balancer {
            servers = [{ url = "http://127.0.0.1:8001" }]
        }
        failover { service = "backup" }
    "#,
    )
    .unwrap();
    assert_eq!(svc.failover.unwrap().service, "backup");
}

#[test]
fn test_parse_server_with_weight() {
    let srv = parse_server_body(r#"url = "http://10.0.0.1:8080"; weight = 3"#).unwrap();
    assert_eq!(srv.url, "http://10.0.0.1:8080");
    assert_eq!(srv.weight, 3);
}

// --- Scaling / Revision / Rollout ---

#[test]
fn test_parse_scaling_defaults() {
    let sc = parse_scaling_body("").unwrap();
    assert_eq!(sc.min_replicas, 0);
    assert_eq!(sc.max_replicas, 10);
    assert_eq!(sc.container_concurrency, 0);
    assert!(!sc.buffer_enabled);
    assert_eq!(sc.executor, "box");
    assert_eq!(sc.executor_endpoint, "http://127.0.0.1:9090");
}

#[test]
fn test_parse_scaling_full() {
    let sc = parse_scaling_body(
        r#"
        min_replicas          = 1
        max_replicas          = 20
        container_concurrency = 50
        target_utilization    = 0.8
        scale_down_delay_secs = 120
        buffer_timeout_secs   = 15
        buffer_size           = 200
        buffer_enabled        = true
        executor              = "k8s"
        executor_endpoint     = "http://box.internal:9090"
    "#,
    )
    .unwrap();
    assert_eq!(sc.min_replicas, 1);
    assert_eq!(sc.max_replicas, 20);
    assert_eq!(sc.container_concurrency, 50);
    assert!((sc.target_utilization - 0.8).abs() < f64::EPSILON);
    assert_eq!(sc.scale_down_delay_secs, 120);
    assert_eq!(sc.buffer_timeout_secs, 15);
    assert_eq!(sc.buffer_size, 200);
    assert!(sc.buffer_enabled);
    assert_eq!(sc.executor, "k8s");
    assert_eq!(sc.executor_endpoint, "http://box.internal:9090");
}

#[test]
fn test_parse_revision() {
    let rev = parse_revision_body(
        r#"
        name            = "v1"
        traffic_percent = 80
        servers         = [{ url = "http://10.0.0.1:8080" }]
        strategy        = "least-connections"
    "#,
    )
    .unwrap();
    assert_eq!(rev.name, "v1");
    assert_eq!(rev.traffic_percent, 80);
    assert_eq!(rev.servers.len(), 1);
    assert_eq!(rev.strategy, Strategy::LeastConnections);
}

#[test]
fn test_parse_rollout() {
    let ro = parse_rollout_body(
        r#"
        from                 = "v1"
        to                   = "v2"
        step_percent         = 20
        step_interval_secs   = 120
        error_rate_threshold = 0.1
        latency_threshold_ms = 3000
    "#,
    )
    .unwrap();
    assert_eq!(ro.from, "v1");
    assert_eq!(ro.to, "v2");
    assert_eq!(ro.step_percent, 20);
    assert_eq!(ro.step_interval_secs, 120);
    assert!((ro.error_rate_threshold - 0.1).abs() < f64::EPSILON);
    assert_eq!(ro.latency_threshold_ms, 3000);
}

#[test]
fn test_parse_rollout_defaults() {
    let ro = parse_rollout_body(
        r#"
        from = "v1"
        to   = "v2"
    "#,
    )
    .unwrap();
    assert_eq!(ro.step_percent, 10);
    assert_eq!(ro.step_interval_secs, 60);
    assert!((ro.error_rate_threshold - 0.05).abs() < f64::EPSILON);
    assert_eq!(ro.latency_threshold_ms, 5000);
}

// --- Top-level config parsing ---

#[test]
fn test_parse_unknown_top_level_block() {
    let err = parse_gateway_config(r#"unknown_block "foo" { bar = "baz" }"#).unwrap_err();
    assert!(err.to_string().contains("Unknown top-level"));
}

#[test]
fn test_parse_empty_config() {
    let config = parse_gateway_config("").unwrap();
    assert!(config.entrypoints.is_empty());
    assert!(config.routers.is_empty());
    assert!(config.services.is_empty());
}

#[test]
fn test_parse_config_with_shutdown_timeout() {
    let config = parse_gateway_config(
        r#"
        shutdown_timeout_secs { shutdown_timeout_secs = 60 }
    "#,
    )
    .unwrap();
    assert_eq!(config.shutdown_timeout_secs, 60);
}

#[test]
fn test_parse_full_gateway_config() {
    let config = parse_gateway_config(
        r#"
        entrypoints "web" { address = "0.0.0.0:80" }
        entrypoints "secure" {
            address = "0.0.0.0:443"
            tls { cert_file = "/cert.pem"; key_file = "/key.pem" }
        }
        routers "api" {
            rule    = "PathPrefix(`/api`)"
            service = "backend"
        }
        services "backend" {
            load_balancer {
                strategy = "least-connections"
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
        middlewares "rl" { type = "rate-limit"; rate = 100; burst = 10 }
    "#,
    )
    .unwrap();
    assert_eq!(config.entrypoints.len(), 2);
    assert_eq!(config.routers.len(), 1);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.middlewares.len(), 1);
    assert!(config.entrypoints["secure"].tls.is_some());
    assert_eq!(
        config.services["backend"].load_balancer.strategy,
        Strategy::LeastConnections
    );
}

// --- ensure_acl_path ---

#[test]
fn test_ensure_acl_path_valid() {
    assert!(ensure_acl_path(Path::new("gateway.acl")).is_ok());
    assert!(ensure_acl_path(Path::new("/etc/gateway/config.acl")).is_ok());
}

#[test]
fn test_ensure_acl_path_invalid() {
    assert!(ensure_acl_path(Path::new("gateway.toml")).is_err());
    assert!(ensure_acl_path(Path::new("gateway")).is_err());
    assert!(ensure_acl_path(Path::new("gateway.yaml")).is_err());
}

// --- Providers parsing ---

#[test]
fn test_parse_unknown_provider() {
    let err = parse_gateway_config(
        r#"
        providers {
            consul {}
        }
    "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("Unknown providers"));
}

// --- Health check parsing ---

#[test]
fn test_parse_health_check_defaults() {
    let hc = parse_health_check_body(r#"path = "/healthz""#).unwrap();
    assert_eq!(hc.path, "/healthz");
    assert_eq!(hc.interval, "10s");
    assert_eq!(hc.timeout, "5s");
    assert_eq!(hc.unhealthy_threshold, 3);
    assert_eq!(hc.healthy_threshold, 1);
}

#[test]
fn test_parse_health_check_missing_path() {
    let err = parse_health_check_body(r#"interval = "5s""#).unwrap_err();
    assert!(err.to_string().contains("path"));
}

// --- Mirror parsing ---

#[test]
fn test_parse_mirror_default_percentage() {
    let m = parse_mirror_body(r#"service = "shadow""#).unwrap();
    assert_eq!(m.service, "shadow");
    assert_eq!(m.percentage, 100);
}

// --- Failover parsing ---

#[test]
fn test_parse_failover_missing_service() {
    let err = parse_failover_body("").unwrap_err();
    assert!(err.to_string().contains("service"));
}
