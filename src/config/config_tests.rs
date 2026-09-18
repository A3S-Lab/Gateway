use super::*;
use std::path::Path;

#[cfg(feature = "kube")]
fn lock_kubeconfig_env() -> std::sync::MutexGuard<'static, ()> {
    // All tests that mutate KUBECONFIG must share one lock — parallel tests
    // with separate mutexes race and soft-pass against each other's clusters.
    static KUBECONFIG_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    KUBECONFIG_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn test_default_config() {
    let config = GatewayConfig::default();
    assert_eq!(config.mode, OperatingMode::Standalone);
    assert_eq!(config.entrypoints.len(), 1);
    assert!(config.entrypoints.contains_key("web"));
    assert_eq!(config.entrypoints["web"].address, "0.0.0.0:80");
    assert!(config.routers.is_empty());
    assert!(config.services.is_empty());
    assert!(config.middlewares.is_empty());
}

#[test]
fn test_parse_minimal_config() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:8080"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    assert_eq!(config.entrypoints["web"].address, "0.0.0.0:8080");
}

#[test]
fn test_parse_full_config() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        entrypoints "websecure" {
            address = "0.0.0.0:443"
            tls {
                cert_file = "/etc/certs/cert.pem"
                key_file  = "/etc/certs/key.pem"
            }
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["web"]
            middlewares  = ["rate-limit"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
        middlewares "rate-limit" {
            type  = "rate-limit"
            rate  = 100
            burst = 50
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    assert_eq!(config.entrypoints.len(), 2);
    assert_eq!(config.routers.len(), 1);
    assert_eq!(config.services.len(), 1);
    assert_eq!(config.middlewares.len(), 1);
}

#[test]
fn test_validate_valid_config() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["web"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    assert!(config.validate().is_ok());
}

#[test]
fn test_validate_unknown_service() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "nonexistent"
            entrypoints = ["web"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("unknown or ambiguous target") && err.contains("nonexistent"),
        "unexpected validate error: {err}"
    );
}

#[test]
fn test_validate_mirror_and_failover_references() {
    let acl = r#"
        routers "api" {
            rule = "PathPrefix(`/`)"
            service = "backend"
        }
        services "backend" {
            load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
            mirror { service = "missing" }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let error = config.validate().unwrap_err();
    assert!(error
        .to_string()
        .contains("mirror references unknown service"));
}

#[test]
fn test_validate_mirror_percentage_bounds() {
    let acl = r#"
        routers "api" {
            rule = "PathPrefix(`/`)"
            service = "backend"
        }
        services "backend" {
            load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
            mirror { service = "shadow", percentage = 101 }
        }
        services "shadow" {
            load_balancer { servers = [{ url = "http://127.0.0.1:8002" }] }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("mirror percentage"));
    assert!(error.to_string().contains("at most 100"));
}

#[test]
fn mirror_target_must_speak_http() {
    let tcp_shadow = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
                mirror { service = "shadow" }
            }
            services "shadow" {
                load_balancer { servers = [{ url = "tcp://127.0.0.1:9000" }] }
            }
        "#,
    )
    .unwrap();
    let error = tcp_shadow.validate().unwrap_err().to_string();
    assert!(
        error.contains("mirror target") && error.contains("tcp://127.0.0.1:9000"),
        "unexpected validate error: {error}"
    );

    let h2c_revision = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
                mirror { service = "shadow" }
            }
            services "shadow" {
                load_balancer {}
                revisions "v1" {
                    traffic_percent = 100
                    servers = [{ url = "h2c://127.0.0.1:9000" }]
                }
            }
        "#,
    )
    .unwrap();
    let error = h2c_revision.validate().unwrap_err().to_string();
    assert!(
        error.contains("mirror target") && error.contains("h2c://127.0.0.1:9000"),
        "unexpected validate error: {error}"
    );

    let https_shadow = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
                mirror { service = "shadow" }
            }
            services "shadow" {
                load_balancer { servers = [{ url = "https://127.0.0.1:8443" }] }
            }
        "#,
    )
    .unwrap();
    https_shadow
        .validate()
        .expect("https shadow must accept HTTP mirror copies");
}

#[test]
fn test_validate_server_url_rejects_credentials() {
    let acl = r#"
        services "backend" {
            load_balancer { servers = [{ url = "http://user:pass@example.test:8001" }] }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("embedded credentials"));
}

#[test]
fn test_validate_server_url_rejects_unknown_scheme() {
    let error = super::validate_server_url("ftp://127.0.0.1:21").unwrap_err();
    assert!(
        error.contains("not a supported upstream"),
        "unexpected error: {error}"
    );
    for url in [
        "http://127.0.0.1:8001",
        "https://example.test",
        "h2c://127.0.0.1:50051",
        "ws://127.0.0.1:9000",
        "wss://example.test",
        "tcp://127.0.0.1:9000",
        "udp://127.0.0.1:9000",
    ] {
        super::validate_server_url(url).unwrap_or_else(|error| panic!("{url}: {error}"));
    }
    let missing_port = super::validate_server_url("tcp://127.0.0.1").unwrap_err();
    assert!(
        missing_port.contains("explicit port"),
        "unexpected error: {missing_port}"
    );
    let udp_missing_port = super::validate_server_url("udp://example.test").unwrap_err();
    assert!(
        udp_missing_port.contains("explicit port"),
        "unexpected error: {udp_missing_port}"
    );
}

#[test]
fn test_validate_rejects_duplicate_entrypoint_addresses() {
    let acl = r#"
        entrypoints "http" { address = "127.0.0.1:8080" }
        entrypoints "tcp" {
            address = "127.0.0.1:8080"
            protocol = "tcp"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("same listen address"));
}

#[test]
fn test_validate_rejects_management_listener_collision() {
    let acl = r#"
        entrypoints "web" { address = "127.0.0.1:9090" }
        management {
            enabled = true
            address = "127.0.0.1:9090"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("Management listener address"));
}

#[test]
fn test_validate_unknown_middleware() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["web"]
            middlewares  = ["nonexistent"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("unknown middleware"));
}

#[test]
fn router_middleware_on_non_http_entrypoint_is_not_a_silent_noop() {
    let tcp = GatewayConfig::from_acl(
        r#"
            entrypoints "db" {
                address = "127.0.0.1:5432"
                protocol = "tcp"
            }
            middlewares "auth" {
                type = "api-key"
                keys = ["secret"]
            }
            routers "db" {
                rule = "HostSNI(`*`)"
                service = "backend"
                entrypoints = ["db"]
                middlewares = ["auth"]
            }
            services "backend" {
                load_balancer { servers = [{ url = "tcp://127.0.0.1:5432" }] }
            }
        "#,
    )
    .unwrap();
    let error = tcp.validate().unwrap_err().to_string();
    assert!(
        error.contains("middleware") && error.contains("auth") && error.contains("tcp"),
        "unexpected validate error: {error}"
    );

    let udp = GatewayConfig::from_acl(
        r#"
            entrypoints "dns" {
                address = "127.0.0.1:5300"
                protocol = "udp"
            }
            middlewares "auth" {
                type = "api-key"
                keys = ["secret"]
            }
            routers "dns" {
                rule = "PathPrefix(`/`)"
                service = "backend"
                entrypoints = ["dns"]
                middlewares = ["auth"]
            }
            services "backend" {
                load_balancer { servers = [{ url = "udp://127.0.0.1:5300" }] }
            }
        "#,
    )
    .unwrap();
    let error = udp.validate().unwrap_err().to_string();
    assert!(
        error.contains("middleware") && error.contains("auth") && error.contains("udp"),
        "unexpected validate error: {error}"
    );

    let mixed = GatewayConfig::from_acl(
        r#"
            entrypoints "web" { address = "127.0.0.1:8080" }
            entrypoints "db" {
                address = "127.0.0.1:5432"
                protocol = "tcp"
            }
            middlewares "auth" {
                type = "api-key"
                keys = ["secret"]
            }
            routers "api" {
                rule = "PathPrefix(`/`)"
                service = "backend"
                entrypoints = ["web", "db"]
                middlewares = ["auth"]
            }
            services "backend" {
                load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
            }
        "#,
    )
    .unwrap();
    mixed
        .validate()
        .expect("middleware still applies when the router is also bound to http");

    let omitted = GatewayConfig::from_acl(
        r#"
            entrypoints "db" {
                address = "127.0.0.1:5433"
                protocol = "tcp"
            }
            middlewares "auth" {
                type = "api-key"
                keys = ["secret"]
            }
            routers "db" {
                rule = "PathPrefix(`/`)"
                service = "backend"
                middlewares = ["auth"]
            }
            services "backend" {
                load_balancer { servers = [{ url = "tcp://127.0.0.1:5432" }] }
            }
        "#,
    )
    .unwrap();
    let error = omitted.validate().unwrap_err().to_string();
    assert!(
        error.contains("middleware") && error.contains("auth") && error.contains("tcp"),
        "omitted entrypoint list must not skip the http-only middleware check: {error}"
    );

    let no_listeners = GatewayConfig::from_acl(
        r#"
            middlewares "auth" {
                type = "api-key"
                keys = ["secret"]
            }
            routers "api" {
                rule = "PathPrefix(`/`)"
                service = "backend"
                middlewares = ["auth"]
            }
            services "backend" {
                load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
            }
        "#,
    )
    .unwrap();
    no_listeners
        .validate()
        .expect("a router with no listeners yet is not a tcp/udp middleware soft-open");
}

#[test]
fn static_bundle_on_non_http_entrypoint_is_not_a_silent_noop() {
    let tcp = GatewayConfig::from_acl(
        r#"
            entrypoints "db" {
                address = "127.0.0.1:5432"
                protocol = "tcp"
            }
            routers "site" {
                rule = "HostSNI(`*`)"
                service = "web"
                entrypoints = ["db"]
            }
            static_bundles "web" {
                release_digest = "abc"
                object_namespace = "org/proj/rel"
                local_digest_store = "missing-store"
                manifest {
                    entry_document = "index.html"
                    entries "index.html" {
                        digest = "abc"
                        size = 1
                        media_type = "text/html"
                    }
                }
            }
        "#,
    )
    .unwrap();
    let error = tcp.validate().unwrap_err().to_string();
    assert!(
        error.contains("static bundle") && error.contains("tcp"),
        "unexpected validate error: {error}"
    );

    let omitted = GatewayConfig::from_acl(
        r#"
            entrypoints "dns" {
                address = "127.0.0.1:5300"
                protocol = "udp"
            }
            routers "site" {
                rule = "PathPrefix(`/`)"
                service = "web"
            }
            static_bundles "web" {
                release_digest = "abc"
                object_namespace = "org/proj/rel"
                local_digest_store = "missing-store"
                manifest {
                    entry_document = "index.html"
                    entries "index.html" {
                        digest = "abc"
                        size = 1
                        media_type = "text/html"
                    }
                }
            }
        "#,
    )
    .unwrap();
    let error = omitted.validate().unwrap_err().to_string();
    assert!(
        error.contains("static bundle") && error.contains("udp"),
        "omitted entrypoint list must not skip the static bundle protocol check: {error}"
    );
}

#[test]
fn test_validate_invalid_middleware_definition() {
    let acl = r#"
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            middlewares = ["broken"]
        }
        services "backend" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
        middlewares "broken" {
            type = "unknown-type"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Middleware 'broken'"));
    assert!(err.to_string().contains("Unknown middleware type"));
}

fn redis_middleware_config() -> GatewayConfig {
    GatewayConfig::from_acl(
        r#"
            middlewares "shared-limit" {
                type      = "rate-limit-redis"
                rate      = 200
                burst     = 100
                redis_url = "redis://127.0.0.1:6379"
            }
        "#,
    )
    .unwrap()
}

#[test]
fn validate_activation_fails_closed_when_forward_auth_unreachable() {
    let config = GatewayConfig::from_acl(
        r#"
            middlewares "gate" {
                type             = "forward-auth"
                forward_auth_url = "http://127.0.0.1:1/verify"
            }
        "#,
    )
    .unwrap();
    config
        .validate()
        .expect("structural validate must accept forward-auth URL shape");
    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("Middleware 'gate'")
            && (message.contains("auth service unreachable")
                || message.contains("forward-auth cannot activate")),
        "unreachable forward-auth must fail validate_activation: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn validate_activation_probes_reachable_forward_auth() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _mock = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let response =
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let auth_url = format!("http://127.0.0.1:{}/verify", address.port());
    crate::middleware::ForwardAuthMiddleware::probe_activation(&auth_url)
        .await
        .expect("mock auth must accept probe");

    let config = GatewayConfig::from_acl(&format!(
        r#"
            middlewares "gate" {{
                type             = "forward-auth"
                forward_auth_url = "{auth_url}"
            }}
        "#
    ))
    .unwrap();
    crate::validate_activation(&config).expect("reachable forward-auth must activate at validate");
}

#[cfg(not(feature = "redis"))]
#[test]
fn test_validate_rejects_redis_middleware_without_feature() {
    let err = redis_middleware_config().validate().unwrap_err();
    assert!(err.to_string().contains("Middleware 'shared-limit'"));
    assert!(err.to_string().contains("requires the 'redis' feature"));
}

#[cfg(feature = "redis")]
#[test]
fn test_validate_accepts_redis_middleware_with_feature() {
    redis_middleware_config().validate().unwrap();
}

#[cfg(feature = "redis")]
#[test]
fn validate_activation_fails_closed_when_redis_rate_limit_unreachable() {
    let config = GatewayConfig::from_acl(
        r#"
            middlewares "shared-limit" {
                type      = "rate-limit-redis"
                rate      = 200
                burst     = 100
                redis_url = "redis://127.0.0.1:1"
            }
        "#,
    )
    .unwrap();
    config
        .validate()
        .expect("structural validate must accept redis URL shape");
    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("Middleware 'shared-limit'")
            && (message.contains("Redis unreachable")
                || message.contains("rate-limit-redis cannot activate")),
        "unreachable Redis must fail validate_activation: {error}"
    );
}

#[cfg(feature = "redis")]
#[test]
fn validate_activation_skips_redis_probe_when_fail_open() {
    let config = GatewayConfig::from_acl(
        r#"
            middlewares "shared-limit" {
                type             = "rate-limit-redis"
                rate             = 200
                burst            = 100
                redis_url        = "redis://127.0.0.1:1"
                redis_fail_open  = true
            }
        "#,
    )
    .unwrap();
    config
        .validate()
        .expect("structural validate must accept redis_fail_open");
    crate::validate_activation(&config).expect(
        "redis_fail_open = true is an explicit degraded contract; validate must not require Redis",
    );
}

#[test]
fn test_validate_unknown_entrypoint() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["nonexistent"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("unknown entrypoint"));
}

#[test]
fn test_validate_empty_servers() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["web"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("no servers"));
}

#[test]
fn test_validate_allows_box_discovered_backends() {
    let acl = r#"
        entrypoints "web" {
            address = "127.0.0.1:8080"
        }
        routers "api" {
            rule        = "PathPrefix(`/`)"
            service     = "backend"
            entrypoints = ["web"]
        }
        services "backend" {
            load_balancer {
                strategy = "round-robin"
            }
            scaling {
                min_replicas          = 0
                max_replicas          = 2
                container_concurrency = 1
                executor              = "box"
                executor_endpoint     = "http://127.0.0.1:9090"
            }
        }
    "#;
    GatewayConfig::from_acl(acl).unwrap().validate().unwrap();
}

#[test]
fn test_validate_invalid_request_timeout() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
        routers "api" {
            rule        = "PathPrefix(`/api`)"
            service     = "backend"
            entrypoints = ["web"]
        }
        services "backend" {
            load_balancer {
                request_timeout = "never"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid request_timeout"));
}

#[test]
fn test_validate_invalid_stream_idle_timeout() {
    let acl = r#"
        services "backend" {
            load_balancer {
                stream_idle_timeout = "0s"
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid stream_idle_timeout"));
}

#[test]
fn test_validate_invalid_stream_total_timeout() {
    let acl = r#"
        services "backend" {
            load_balancer {
                stream_total_timeout = "forever"
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid stream_total_timeout"));
}

fn valid_health_check() -> HealthCheckConfig {
    HealthCheckConfig {
        path: "/health".to_string(),
        interval: "10s".to_string(),
        timeout: "5s".to_string(),
        unhealthy_threshold: 3,
        healthy_threshold: 1,
    }
}

fn assert_invalid_health_check(health_check: HealthCheckConfig, expected_detail: &str) {
    let mut config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
            }
        "#,
    )
    .unwrap();
    config
        .services
        .get_mut("backend")
        .unwrap()
        .load_balancer
        .health_check = Some(health_check);

    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("Invalid health_check for service 'backend'"));
    assert!(error.contains(expected_detail), "unexpected error: {error}");
}

#[test]
fn test_validate_rejects_invalid_health_check_settings() {
    let mut health_check = valid_health_check();
    health_check.interval = "sometimes".to_string();
    assert_invalid_health_check(health_check, "interval");

    let mut health_check = valid_health_check();
    health_check.timeout = "0s".to_string();
    assert_invalid_health_check(health_check, "timeout");

    let mut health_check = valid_health_check();
    health_check.path = "health".to_string();
    assert_invalid_health_check(health_check, "path");

    let mut health_check = valid_health_check();
    health_check.path = "//other-origin/health".to_string();
    assert_invalid_health_check(health_check, "origin-form");

    let mut health_check = valid_health_check();
    health_check.path = "/health#fragment".to_string();
    assert_invalid_health_check(health_check, "fragment");

    let mut health_check = valid_health_check();
    health_check.path = format!("/{}", "x".repeat(2048));
    assert_invalid_health_check(health_check, "at most");

    let mut health_check = valid_health_check();
    health_check.path = "/health\u{7f}".to_string();
    assert_invalid_health_check(health_check, "control");

    let mut health_check = valid_health_check();
    health_check.path = "/health check".to_string();
    assert_invalid_health_check(health_check, "whitespace");

    let mut health_check = valid_health_check();
    health_check.unhealthy_threshold = 0;
    assert_invalid_health_check(health_check, "unhealthy_threshold");

    let mut health_check = valid_health_check();
    health_check.healthy_threshold = 0;
    assert_invalid_health_check(health_check, "healthy_threshold");
}

#[test]
fn test_validate_rejects_health_check_without_probeable_servers() {
    let mut config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [
                        { url = "tcp://127.0.0.1:9000" },
                        { url = "h2c://127.0.0.1:50051" }
                    ]
                    health_check {
                        path = "/health"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("health_check") && error.contains("http:// or https://"),
        "unexpected validate error: {error}"
    );

    // Mixed pools soft-open: non-HTTP members stay default-healthy forever.
    config
        .services
        .get_mut("backend")
        .unwrap()
        .load_balancer
        .servers
        .push(crate::config::ServerConfig {
            url: "http://127.0.0.1:8001".to_string(),
            weight: 1,
            target: None,
        });
    let mixed = config.validate().unwrap_err().to_string();
    assert!(
        mixed.contains("health_check")
            && mixed.contains("tcp://127.0.0.1:9000")
            && mixed.contains("not http:// or https://"),
        "unexpected mixed-pool validate error: {mixed}"
    );
}

#[test]
fn test_validate_rejects_health_check_with_non_http_revision_servers() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    health_check {
                        path = "/health"
                    }
                }
                revisions "v1" {
                    traffic_percent = 100
                    servers = [
                        { url = "http://127.0.0.1:8001" },
                        { url = "tcp://127.0.0.1:9000" }
                    ]
                }
            }
        "#,
    )
    .unwrap();

    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("health_check")
            && error.contains("tcp://127.0.0.1:9000")
            && error.contains("not http:// or https://"),
        "unexpected validate error: {error}"
    );
}

#[test]
fn test_validate_accepts_health_check_with_revision_only_http_servers() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    health_check {
                        path = "/health"
                    }
                }
                revisions "v1" {
                    traffic_percent = 100
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
            }
        "#,
    )
    .unwrap();

    config
        .validate()
        .expect("revision-only http backends must satisfy health_check probeability");
}

#[test]
fn test_validate_rejects_tls_ca_file_without_https_servers() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                    servers = [{{ url = "http://127.0.0.1:8001" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("tls_ca_file") && error.contains("https://"),
        "unexpected validate error: {error}"
    );
}

#[test]
fn test_validate_accepts_tls_ca_file_with_revision_only_https_servers() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                }}
                revisions "v1" {{
                    traffic_percent = 100
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    config
        .validate()
        .expect("revision-only https backends must satisfy tls_ca_file");
}

#[test]
fn test_validate_rejects_invalid_sticky_cookie_name() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [{ url = "http://127.0.0.1:8001" }]
                    sticky {
                        cookie = "bad name"
                    }
                }
            }
        "#,
    )
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("sticky cookie") && error.contains("bad name"),
        "unexpected validate error: {error}"
    );
}

#[test]
fn test_validate_accepts_valid_sticky_cookie_name() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [{ url = "http://127.0.0.1:8001" }]
                    sticky {
                        cookie = "gateway_sticky"
                    }
                }
            }
        "#,
    )
    .unwrap();
    config
        .validate()
        .expect("valid sticky cookie name must validate");
}

#[test]
fn sticky_on_tcp_backends_is_not_a_silent_noop() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [{ url = "tcp://127.0.0.1:9000" }]
                    sticky { cookie = "gateway_sticky" }
                }
            }
        "#,
    )
    .unwrap();
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("sticky") && error.contains("tcp://127.0.0.1:9000"),
        "unexpected validate error: {error}"
    );

    let revision_only = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    sticky { cookie = "gateway_sticky" }
                }
                revisions "v1" {
                    traffic_percent = 100
                    servers = [{ url = "udp://127.0.0.1:9000" }]
                }
            }
        "#,
    )
    .unwrap();
    let error = revision_only.validate().unwrap_err().to_string();
    assert!(
        error.contains("sticky") && error.contains("udp://127.0.0.1:9000"),
        "unexpected validate error: {error}"
    );
}

#[cfg(feature = "kube")]
#[test]
fn test_validate_rejects_mixed_autoscaling_executors() {
    let acl = r#"
        services "box-service" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
            scaling {
                container_concurrency = 10
                executor              = "box"
            }
        }
        services "k8s-service" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8002" }]
            }
            scaling {
                container_concurrency = 10
                executor              = "k8s"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err
        .to_string()
        .contains("requires one executor across all active services"));
}

#[test]
fn test_validate_rejects_mixed_box_executor_endpoints() {
    let acl = r#"
        services "first" {
            load_balancer { servers = [{ url = "http://127.0.0.1:8001" }] }
            scaling {
                container_concurrency = 10
                executor_endpoint     = "http://127.0.0.1:9090"
            }
        }
        services "second" {
            load_balancer { servers = [{ url = "http://127.0.0.1:8002" }] }
            scaling {
                container_concurrency = 10
                executor_endpoint     = "http://127.0.0.1:9191"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("requires one executor_endpoint"));
}

#[test]
fn test_parse_invalid_acl() {
    let result = GatewayConfig::from_acl("{{{{ invalid");
    assert!(result.is_err());
}

#[test]
fn test_from_file_rejects_non_acl_extension() {
    let err = tokio_test::block_on(GatewayConfig::from_file("gateway.txt")).unwrap_err();
    assert!(err.to_string().contains(".acl extension"));
}

#[test]
fn test_management_config_acl_parsing() {
    let acl = r#"
        management {
            enabled        = true
            address        = "127.0.0.1:19090"
            path_prefix    = "/admin"
            auth_token_env = "ADMIN_TOKEN"
            allowed_ips    = ["127.0.0.1", "10.0.0.0/8"]
            tls {
                cert_file           = "/etc/a3s/admin.crt"
                key_file            = "/etc/a3s/admin.key"
                client_ca_file      = "/etc/a3s/admin-client-ca.crt"
                require_client_cert = true
                min_version         = "1.3"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    assert!(config.management.enabled);
    assert_eq!(config.management.address, "127.0.0.1:19090");
    assert_eq!(config.management.path_prefix, "/admin");
    assert_eq!(
        config.management.auth_token_env.as_deref(),
        Some("ADMIN_TOKEN")
    );
    assert_eq!(config.management.allowed_ips.len(), 2);
    assert_eq!(config.management.allowed_ips[1], "10.0.0.0/8");
    let tls = config.management.tls.unwrap();
    assert_eq!(tls.cert_file, "/etc/a3s/admin.crt");
    assert_eq!(tls.key_file, "/etc/a3s/admin.key");
    assert_eq!(
        tls.client_ca_file.as_deref(),
        Some("/etc/a3s/admin-client-ca.crt")
    );
    assert!(tls.require_client_cert);
    assert_eq!(tls.min_version, "1.3");
}

#[test]
fn test_management_config_defaults_to_local_allowlist() {
    let config = GatewayConfig::from_acl(
        r#"
        management {
            enabled = true
        }
    "#,
    )
    .unwrap();
    assert_eq!(config.management.allowed_ips, vec!["127.0.0.1", "::1"]);
}

#[test]
fn test_management_config_validate_path_prefix() {
    let acl = r#"
        management {
            enabled     = true
            path_prefix = "admin"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("path_prefix"));
}

#[test]
fn test_management_config_validate_allowed_ips() {
    let acl = r#"
        management {
            enabled     = true
            allowed_ips = ["not-an-ip"]
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("Invalid IP address"));
}

#[test]
fn test_management_config_rejects_empty_auth_token_env() {
    let config = GatewayConfig::from_acl(
        r#"
        management {
            enabled        = true
            auth_token_env = ""
            allowed_ips    = ["127.0.0.1"]
        }
    "#,
    )
    .unwrap();
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("auth_token_env"),
        "unexpected validate error: {err}"
    );
}

#[test]
fn test_management_config_rejects_empty_allowed_ips() {
    let config = GatewayConfig::from_acl(
        r#"
        management {
            enabled     = true
            allowed_ips = []
        }
    "#,
    )
    .unwrap();
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("allowed_ips"),
        "unexpected validate error: {err}"
    );
}

#[test]
fn test_management_config_validate_mtls_requires_client_ca() {
    let acl = r#"
        management {
            enabled = true
            tls {
                cert_file           = "/etc/a3s/admin.crt"
                key_file            = "/etc/a3s/admin.key"
                require_client_cert = true
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("client_ca_file"));
}

#[test]
fn test_management_config_rejects_client_ca_without_require_client_cert() {
    let acl = r#"
        management {
            enabled = true
            tls {
                cert_file      = "/etc/a3s/admin.crt"
                key_file       = "/etc/a3s/admin.key"
                client_ca_file = "/etc/a3s/admin-client-ca.crt"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("require_client_cert"),
        "unexpected validate error: {err}"
    );
}

#[test]
fn test_management_config_validate_tls_min_version() {
    let acl = r#"
        management {
            enabled = true
            tls {
                cert_file   = "/etc/a3s/admin.crt"
                key_file    = "/etc/a3s/admin.key"
                min_version = "1.1"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("min_version"));
}

#[test]
fn test_provider_config_default() {
    let provider = ProviderConfig::default();
    assert!(provider.file.is_none());
}

#[test]
fn test_file_provider_config() {
    let acl = r#"
        providers {
            file {
                watch     = true
                directory = "/etc/gateway/conf.d"
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let file = config.providers.file.unwrap();
    assert!(file.watch);
    assert_eq!(file.directory.unwrap(), "/etc/gateway/conf.d");
}

#[test]
fn test_discovery_config_acl_parsing() {
    let acl = r#"
        providers {
            discovery {
                poll_interval_secs = 15
                timeout_secs       = 3
                seeds = [
                    { url = "http://10.0.0.5:8080" },
                    { url = "http://10.0.0.6:8080" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let disc = config.providers.discovery.unwrap();
    assert_eq!(disc.seeds.len(), 2);
    assert_eq!(disc.seeds[0].url, "http://10.0.0.5:8080");
    assert_eq!(disc.seeds[1].url, "http://10.0.0.6:8080");
    assert_eq!(disc.poll_interval_secs, 15);
    assert_eq!(disc.timeout_secs, 3);
}

#[test]
fn test_discovery_config_defaults() {
    let acl = r#"
        providers {
            discovery {
                seeds = [
                    { url = "http://localhost:9000" }
                ]
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let disc = config.providers.discovery.unwrap();
    assert_eq!(disc.poll_interval_secs, 30);
    assert_eq!(disc.timeout_secs, 5);
}

#[test]
fn test_discovery_config_serialization_roundtrip() {
    let config = DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: "http://10.0.0.1:8080".to_string(),
        }],
        poll_interval_secs: 20,
        timeout_secs: 3,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: DiscoveryConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.seeds.len(), 1);
    assert_eq!(parsed.seeds[0].url, "http://10.0.0.1:8080");
    assert_eq!(parsed.poll_interval_secs, 20);
    assert_eq!(parsed.timeout_secs, 3);
}

// --- KubernetesProviderConfig ---

#[test]
fn test_kubernetes_config_default() {
    let config = KubernetesProviderConfig::default();
    assert!(config.namespace.is_empty());
    assert!(config.label_selector.is_empty());
    assert_eq!(config.watch_interval_secs, 30);
    assert!(!config.ingress_route_crd);
}

#[test]
fn test_kubernetes_config_acl_parsing() {
    let acl = r#"
        providers {
            kubernetes {
                namespace           = "production"
                label_selector      = "app=web"
                watch_interval_secs = 15
                ingress_route_crd   = true
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let k8s = config.providers.kubernetes.unwrap();
    assert_eq!(k8s.namespace, "production");
    assert_eq!(k8s.label_selector, "app=web");
    assert_eq!(k8s.watch_interval_secs, 15);
    assert!(k8s.ingress_route_crd);
}

#[test]
fn test_kubernetes_config_defaults_in_acl() {
    let acl = r#"
        providers {
            kubernetes {}
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let k8s = config.providers.kubernetes.unwrap();
    assert!(k8s.namespace.is_empty());
    assert_eq!(k8s.watch_interval_secs, 30);
}

#[test]
fn test_kubernetes_config_serialization_roundtrip() {
    let config = KubernetesProviderConfig {
        namespace: "staging".to_string(),
        label_selector: "tier=frontend".to_string(),
        watch_interval_secs: 60,
        ingress_route_crd: true,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: KubernetesProviderConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.namespace, "staging");
    assert_eq!(parsed.label_selector, "tier=frontend");
    assert_eq!(parsed.watch_interval_secs, 60);
    assert!(parsed.ingress_route_crd);
}

#[test]
fn test_provider_config_with_kubernetes() {
    let provider = ProviderConfig {
        file: None,
        discovery: None,
        kubernetes: Some(KubernetesProviderConfig::default()),
        docker: None,
    };
    assert!(provider.kubernetes.is_some());
}

// --- DockerProviderConfig ---

#[test]
fn test_docker_config_default() {
    let config = DockerProviderConfig::default();
    assert_eq!(config.host, "/var/run/docker.sock");
    assert_eq!(config.label_prefix, "a3s");
    assert_eq!(config.poll_interval_secs, 10);
}

#[test]
fn test_docker_config_acl_parsing() {
    let acl = r#"
        providers {
            docker {
                host                = "tcp://localhost:2375"
                label_prefix        = "myapp"
                poll_interval_secs  = 30
            }
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let docker = config.providers.docker.unwrap();
    assert_eq!(docker.host, "tcp://localhost:2375");
    assert_eq!(docker.label_prefix, "myapp");
    assert_eq!(docker.poll_interval_secs, 30);
}

#[test]
fn test_docker_config_defaults_in_acl() {
    let acl = r#"
        providers {
            docker {}
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    let docker = config.providers.docker.unwrap();
    assert_eq!(docker.host, "/var/run/docker.sock");
    assert_eq!(docker.label_prefix, "a3s");
    assert_eq!(docker.poll_interval_secs, 10);
}

#[test]
fn test_docker_config_absent_when_not_configured() {
    let acl = r#"
        entrypoints "web" {
            address = "0.0.0.0:80"
        }
    "#;
    let config = GatewayConfig::from_acl(acl).unwrap();
    assert!(config.providers.docker.is_none());
}

#[test]
fn test_docker_config_serialization_roundtrip() {
    let config = DockerProviderConfig {
        host: "tcp://docker-host:2375".to_string(),
        label_prefix: "traefik".to_string(),
        poll_interval_secs: 5,
    };
    let json = serde_json::to_string(&config).unwrap();
    let parsed: DockerProviderConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.host, "tcp://docker-host:2375");
    assert_eq!(parsed.label_prefix, "traefik");
    assert_eq!(parsed.poll_interval_secs, 5);
}

#[test]
fn test_validate_docker_provider_boundary() {
    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        poll_interval_secs: 0,
        ..DockerProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("Docker poll_interval_secs"));

    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: "https://docker.example".into(),
        ..DockerProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("tcp:// or http://"));

    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: "tcp://user:secret@docker.example:2375".into(),
        ..DockerProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("credentials"));
}

#[cfg(not(unix))]
#[test]
fn validate_rejects_docker_unix_socket_host_on_non_unix() {
    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: "/var/run/docker.sock".into(),
        ..DockerProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(
        error.to_string().contains("not supported on this platform"),
        "unix docker.host must fail validate on non-Unix: {error}"
    );
}

#[cfg(not(unix))]
#[test]
fn validate_accepts_docker_tcp_host_on_non_unix() {
    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: "tcp://127.0.0.1:2375".into(),
        ..DockerProviderConfig::default()
    });
    config
        .validate()
        .expect("tcp docker.host must validate on non-Unix");
}

#[test]
fn validate_activation_fails_closed_when_docker_daemon_unreachable() {
    let mut config = GatewayConfig::default();
    // Structural validate accepts a TCP URL; activation must probe the daemon.
    config.providers.docker = Some(DockerProviderConfig {
        host: "tcp://127.0.0.1:1".into(),
        poll_interval_secs: 60,
        ..DockerProviderConfig::default()
    });
    config
        .validate()
        .expect("tcp docker.host must pass structural validate");
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("Docker daemon unreachable")
            || error
                .to_string()
                .contains("providers.docker cannot activate"),
        "unreachable Docker daemon must fail validate_activation: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn validate_activation_probes_reachable_docker_daemon() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _mock = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let body = if request.contains("/_ping") { "OK" } else { "" };
                let status = if body.is_empty() {
                    "404 Not Found"
                } else {
                    "200 OK"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: format!("tcp://127.0.0.1:{}", address.port()),
        poll_interval_secs: 60,
        ..DockerProviderConfig::default()
    });
    // Warm the listen socket before the sync activation probe thread connects.
    crate::provider::docker::DockerProvider::new(config.providers.docker.clone().unwrap())
        .probe_activation()
        .await
        .expect("mock Docker daemon must accept /_ping");
    crate::validate_activation(&config).expect("reachable Docker /_ping must activate at validate");
}

#[cfg(not(unix))]
#[test]
fn default_docker_block_fails_validate_on_windows() {
    let config = GatewayConfig::from_acl(
        r#"
            providers {
                docker {}
            }
        "#,
    )
    .unwrap();
    let error = config.validate().unwrap_err();
    assert!(
        error.to_string().contains("not supported on this platform"),
        "empty docker {{}} defaults to a unix socket and must fail validate on Windows: {error}"
    );
}

#[cfg(unix)]
#[test]
fn validate_rejects_docker_unix_socket_host_when_path_missing() {
    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: "/tmp/a3s-gateway-missing-docker.sock".into(),
        ..DockerProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(
        error.to_string().contains("does not exist"),
        "missing docker unix socket must fail validate: {error}"
    );
}

#[cfg(unix)]
#[test]
fn validate_accepts_docker_unix_socket_host_when_path_exists() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("docker.sock");
    std::fs::write(&socket, b"").unwrap();
    let mut config = GatewayConfig::default();
    config.providers.docker = Some(DockerProviderConfig {
        host: socket.to_string_lossy().into_owned(),
        ..DockerProviderConfig::default()
    });
    config
        .validate()
        .expect("existing docker unix socket path must validate");
}

#[test]
fn test_validate_server_rejects_query_fragment_and_zero_weight() {
    for url in [
        "http://example.test:8000/?token=secret",
        "http://example.test:8000/#fragment",
    ] {
        let acl = format!(
            r#"
                services "backend" {{
                    load_balancer {{
                        servers = [{{ url = "{url}" }}]
                    }}
                }}
            "#
        );
        let error = GatewayConfig::from_acl(&acl)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(error.to_string().contains("query or fragment"));
    }

    let acl = r#"
        services "backend" {
            load_balancer {
                servers = [{ url = "http://example.test:8000", weight = 0 }]
            }
        }
    "#;
    let error = GatewayConfig::from_acl(acl)
        .unwrap()
        .validate()
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("weight must be greater than zero"));
}

#[test]
fn test_validate_udp_zero_timeout_fails_closed() {
    let acl = r#"
        entrypoints "dns" {
            address                  = "127.0.0.1:5353"
            protocol                 = "udp"
            udp_session_timeout_secs = 0
        }
    "#;
    let err = GatewayConfig::from_acl(acl)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("udp_session_timeout_secs"),
        "config validate must reject zero UDP timeout: {err}"
    );
}

#[test]
fn test_validate_acme_without_email_fails_closed() {
    let acl = r#"
        entrypoints "websecure" {
            address = "127.0.0.1:8443"
            tls {
                cert_file = "/tmp/cert.pem"
                key_file  = "/tmp/key.pem"
                acme      = true
            }
        }
    "#;
    let err = GatewayConfig::from_acl(acl)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("acme_email"),
        "config validate must reject ACME without email: {err}"
    );
}

#[test]
fn test_validate_discovery_rejects_duplicate_seeds() {
    let mut config = GatewayConfig::default();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![
            DiscoverySeedConfig {
                url: "http://discovery.example".to_string(),
            },
            DiscoverySeedConfig {
                url: "http://discovery.example".to_string(),
            },
        ],
        poll_interval_secs: 30,
        timeout_secs: 5,
    });
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("duplicated"));
}

#[test]
fn test_validate_discovery_rejects_empty_seeds() {
    let mut config = GatewayConfig::default();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![],
        poll_interval_secs: 30,
        timeout_secs: 5,
    });
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("at least one seed"),
        "unexpected validate error: {error}"
    );
}

#[test]
fn test_validate_activation_builds_discovery_http_client() {
    let mut config = GatewayConfig::default();
    config.providers.discovery = Some(DiscoveryConfig {
        seeds: vec![DiscoverySeedConfig {
            url: "http://127.0.0.1:9".to_string(),
        }],
        poll_interval_secs: 30,
        timeout_secs: 5,
    });
    crate::validate_activation(&config).expect(
        "validate_activation must share DiscoveryProvider::new client build with cold start",
    );
}

#[cfg(not(feature = "kube"))]
#[test]
fn test_validate_rejects_kubernetes_without_kube_feature() {
    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig::default());
    let error = config.validate().unwrap_err().to_string();
    assert!(
        error.contains("requires the 'kube' feature"),
        "unexpected validate error: {error}"
    );
}

#[cfg(feature = "kube")]
#[test]
fn test_validate_kubernetes_provider_interval() {
    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig {
        watch_interval_secs: 0,
        ..KubernetesProviderConfig::default()
    });
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("Kubernetes watch_interval_secs"));
}

#[cfg(feature = "kube")]
#[test]
fn validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable() {
    let _guard = lock_kubeconfig_env();
    let directory = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var(
        "KUBECONFIG",
        directory.path().join("missing-kubeconfig.yaml"),
    );
    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig::default());
    let error = crate::validate_activation(&config).unwrap_err();
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    assert!(
        error
            .to_string()
            .contains("Kubernetes client cannot activate"),
        "unusable kubeconfig must fail validate_activation: {error}"
    );
}

#[cfg(feature = "kube")]
#[test]
fn validate_activation_fails_closed_when_kubernetes_client_cannot_build() {
    let _guard = lock_kubeconfig_env();
    let directory = tempfile::tempdir().unwrap();
    // YAML parses (Kubeconfig::read Ok) but CA path is missing — Client::try_default
    // must fail; validate must not soft-open on parse alone.
    let kubeconfig = directory.path().join("broken-client.yaml");
    std::fs::write(
        &kubeconfig,
        format!(
            r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: {ca}
    server: https://127.0.0.1:6443
  name: broken
contexts:
- context:
    cluster: broken
    user: broken
  name: broken
current-context: broken
users:
- name: broken
  user:
    token: not-a-real-token
"#,
            ca = directory
                .path()
                .join("missing-ca.crt")
                .display()
                .to_string()
                .replace('\\', "/")
        ),
    )
    .unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var("KUBECONFIG", &kubeconfig);
    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig::default());
    let error = crate::validate_activation(&config).unwrap_err();
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    assert!(
        error
            .to_string()
            .contains("failed to create Kubernetes client"),
        "parseable kubeconfig with unusable CA must fail Client construction at validate: {error}"
    );
}

#[test]
fn validate_activation_probes_default_upstream_tls_clients() {
    // Empty ACL still activates the shared HTTP/gRPC TLS pools at validate —
    // same construction as build_runtime (no soft-open until first forward).
    crate::validate_activation(&GatewayConfig::default()).unwrap();
}

#[test]
fn validate_activation_probes_service_tls_ca_http_clients() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    // Full Hyper/rustls client build — not just PEM load — same as build_runtime.
    crate::validate_activation(&config).expect(
        "tls_ca_file services must activate HttpProxy::try_with_timeouts_and_ca_file at validate",
    );
}

#[test]
fn validate_activation_probes_service_tls_ca_grpc_clients() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    crate::validate_activation(&config)
        .expect("tls_ca_file services must activate GrpcProxy::try_with_ca_file at validate");
    let proxies = crate::gateway::builders::build_service_grpc_proxies(&config).unwrap();
    assert!(
        proxies.contains_key("backend"),
        "tls_ca_file must produce a per-service gRPC proxy"
    );
}

#[test]
fn validate_activation_probes_service_tls_ca_websocket_clients() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    crate::validate_activation(&config)
        .expect("tls_ca_file services must activate the WebSocket private trust store at validate");
    let configs = crate::gateway::builders::build_service_ws_tls_configs(&config).unwrap();
    assert!(
        configs.contains_key("backend"),
        "tls_ca_file must produce a per-service WebSocket TLS config"
    );
    let junk = tempfile::tempdir().unwrap();
    let junk_path = junk.path().join("not-a-cert.pem");
    std::fs::write(&junk_path, b"not a certificate").unwrap();
    let error = crate::proxy::websocket::private_ca_client_config(
        &junk_path.display().to_string().replace('\\', "/"),
    )
    .expect_err("unusable PEM must not build a WebSocket private trust store");
    assert!(
        error.contains("tls_ca_file") || error.contains("certificate"),
        "{error}"
    );
}

#[test]
fn validate_activation_fails_closed_on_unusable_service_tls_ca_for_grpc() {
    let directory = tempfile::tempdir().unwrap();
    let junk = directory.path().join("not-a-cert.pem");
    std::fs::write(&junk, b"not a certificate").unwrap();
    let junk_acl = junk.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{junk_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                }}
            }}
        "#
    ))
    .unwrap();
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("tls_ca_file")
            || error.to_string().contains("gRPC TLS")
            || error.to_string().contains("upstream TLS"),
        "unusable tls_ca_file must fail validate for gRPC/HTTP client build: {error}"
    );
}

#[test]
fn validate_activation_probes_health_check_http_clients() {
    let ca = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tls/revision-1-ca.crt");
    let ca_acl = ca.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{ca_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                    health_check {{
                        path = "/health"
                        interval = "10s"
                        timeout = "5s"
                    }}
                }}
            }}
        "#
    ))
    .unwrap();
    // Full prepare_health_checks path (registry + client), same as build_runtime.
    crate::validate_activation(&config)
        .expect("health_check + tls_ca_file must activate prepare_health_checks at validate");
}

#[test]
fn validate_activation_prepares_revision_health_checkers() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    health_check {
                        path = "/health"
                        interval = "1s"
                        timeout = "100ms"
                    }
                }
                revisions {
                    name = "v1"
                    traffic_percent = 100
                    servers = [{ url = "http://127.0.0.1:8001" }]
                }
            }
        "#,
    )
    .unwrap();
    crate::validate_activation(&config)
        .expect("revision-only health_check must prepare revision checkers at validate");
}

#[test]
fn validate_activation_fails_closed_on_invalid_health_check_interval() {
    let config = GatewayConfig::from_acl(
        r#"
            services "backend" {
                load_balancer {
                    servers = [{ url = "http://127.0.0.1:8001" }]
                    health_check {
                        path = "/health"
                        interval = "invalid"
                        timeout = "5s"
                    }
                }
            }
        "#,
    )
    .unwrap();
    // Structural validate may accept the string; activation must revalidate durations.
    let error = crate::validate_activation(&config).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Invalid health_check for service 'backend'"),
        "invalid health_check interval must fail validate_activation: {error}"
    );
}

#[test]
fn validate_activation_fails_closed_on_unusable_health_check_tls_ca() {
    let directory = tempfile::tempdir().unwrap();
    let junk = directory.path().join("not-a-cert.pem");
    std::fs::write(&junk, b"not a certificate").unwrap();
    let junk_acl = junk.display().to_string().replace('\\', "/");
    let config = GatewayConfig::from_acl(&format!(
        r#"
            services "backend" {{
                load_balancer {{
                    tls_ca_file = "{junk_acl}"
                    servers = [{{ url = "https://127.0.0.1:8443" }}]
                    health_check {{
                        path = "/health"
                        interval = "10s"
                        timeout = "5s"
                    }}
                }}
            }}
        "#
    ))
    .unwrap();
    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("tls_ca_file")
            || message.contains("health_check")
            || message.contains("health-check")
            || message.contains("upstream TLS")
            || message.contains("certificate"),
        "unusable tls_ca_file with health_check must fail validate_activation: {error}"
    );
}

#[test]
fn health_checker_probe_rejects_unusable_pem() {
    let directory = tempfile::tempdir().unwrap();
    let junk = directory.path().join("not-a-cert.pem");
    std::fs::write(&junk, b"not a certificate").unwrap();
    let error = crate::service::HealthChecker::probe_client_activation(
        std::time::Duration::from_secs(5),
        Some(junk.to_str().unwrap()),
    )
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("Failed to parse health-check tls_ca_file")
            && (error.contains("no certificates found") || error.contains("invalid certificate")),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_activation_fails_closed_when_box_scale_unreachable() {
    let config = GatewayConfig::from_acl(
        r#"
        services "api" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
            scaling {
                container_concurrency = 1
                executor              = "box"
                executor_endpoint     = "http://127.0.0.1:1"
                executor_timeout_secs = 2
            }
        }
        "#,
    )
    .unwrap();
    config
        .validate()
        .expect("structural validate must accept Box executor URL shape");
    let error = crate::validate_activation(&config).unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("Service 'api'")
            && (message.contains("Box scale executor cannot activate")
                || message.contains("Box scale API query failed")),
        "unreachable Box scale API must fail validate_activation: {error}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn validate_activation_probes_box_scale_http_client() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _mock = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0_u8; 4096];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let body = r#"{"replicas":0,"ready_replicas":0,"endpoints":[]}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            });
        }
    });

    let endpoint = format!("http://127.0.0.1:{}", address.port());
    crate::scaling::executor::probe_box_scale_activation(
        &endpoint,
        "api",
        std::time::Duration::from_secs(2),
    )
    .await
    .expect("mock Box scale API must accept GET /v1/scale/api");

    let config = GatewayConfig::from_acl(&format!(
        r#"
        services "api" {{
            load_balancer {{
                servers = [{{ url = "http://127.0.0.1:8001" }}]
            }}
            scaling {{
                container_concurrency = 1
                executor              = "box"
                executor_endpoint     = "{endpoint}"
                executor_timeout_secs = 2
            }}
        }}
        "#
    ))
    .unwrap();
    crate::validate_activation(&config)
        .expect("reachable Box scale observation must activate at validate");
}

#[cfg(feature = "kube")]
#[test]
fn validate_activation_fails_closed_when_k8s_autoscaler_kubeconfig_unusable() {
    let _guard = lock_kubeconfig_env();
    let directory = tempfile::tempdir().unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var(
        "KUBECONFIG",
        directory.path().join("missing-kubeconfig.yaml"),
    );
    // Active k8s autoscaler without providers.kubernetes still needs the client.
    let config = GatewayConfig::from_acl(
        r#"
        services "api" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
            scaling {
                container_concurrency = 1
                executor              = "k8s"
            }
        }
        "#,
    )
    .unwrap();
    assert!(config.providers.kubernetes.is_none());
    let error = crate::validate_activation(&config).unwrap_err();
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    assert!(
        error
            .to_string()
            .contains("Kubernetes client cannot activate"),
        "k8s autoscaler without providers.kubernetes must still fail validate_activation: {error}"
    );
}

#[cfg(feature = "kube")]
#[test]
fn validate_activation_fails_closed_when_k8s_scale_subresource_unreachable() {
    let _guard = lock_kubeconfig_env();
    let directory = tempfile::tempdir().unwrap();
    let kubeconfig = directory.path().join("unreachable-apiserver.yaml");
    std::fs::write(
        &kubeconfig,
        r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:1
  name: unreachable
contexts:
- context:
    cluster: unreachable
    user: unreachable
  name: unreachable
current-context: unreachable
users:
- name: unreachable
  user:
    token: not-a-real-token
"#,
    )
    .unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var("KUBECONFIG", &kubeconfig);
    let config = GatewayConfig::from_acl(
        r#"
        services "api" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
            scaling {
                container_concurrency = 1
                executor              = "k8s"
                executor_timeout_secs = 2
            }
        }
        "#,
    )
    .unwrap();
    let error = crate::validate_activation(&config).unwrap_err();
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    let message = error.to_string();
    assert!(
        message.contains("Service 'api'")
            && (message.contains("Kubernetes scale executor cannot activate")
                || message.contains("Failed to get Kubernetes Scale")),
        "unreachable Scale subresource must fail validate_activation: {error}"
    );
}

#[cfg(feature = "kube")]
#[tokio::test(flavor = "multi_thread")]
async fn validate_activation_probes_k8s_scale_subresource() {
    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    let _guard = lock_kubeconfig_env();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let path = request.uri().path().to_string();
                    let body = if path.ends_with("/deployments/api/scale") {
                        r#"{"apiVersion":"autoscaling/v1","kind":"Scale","metadata":{"name":"api","namespace":"default","resourceVersion":"1"},"spec":{"replicas":1},"status":{"replicas":1,"selector":"app=api"}}"#
                    } else {
                        r#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"unexpected path","code":404}"#
                    };
                    let status = if path.ends_with("/deployments/api/scale") {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .header(http::header::CONNECTION, "close")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let directory = tempfile::tempdir().unwrap();
    let kubeconfig = directory.path().join("mock-apiserver.yaml");
    std::fs::write(
        &kubeconfig,
        format!(
            r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:{}
  name: mock
contexts:
- context:
    cluster: mock
    user: mock
  name: mock
current-context: mock
users:
- name: mock
  user:
    token: not-a-real-token
"#,
            address.port()
        ),
    )
    .unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var("KUBECONFIG", &kubeconfig);

    crate::scaling::kubernetes_executor::probe_k8s_scale_activation(
        "default",
        "api",
        std::time::Duration::from_secs(2),
    )
    .await
    .expect("mock apiserver must serve Scale observation");

    let config = GatewayConfig::from_acl(
        r#"
        services "api" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
            scaling {
                container_concurrency = 1
                executor              = "k8s"
                executor_timeout_secs = 2
            }
        }
        "#,
    )
    .unwrap();
    let result = crate::validate_activation(&config);
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    result.expect("reachable k8s Scale observation must activate at validate");
}

#[cfg(feature = "kube")]
#[test]
fn validate_activation_fails_closed_when_kubernetes_ingress_list_unreachable() {
    let _guard = lock_kubeconfig_env();
    let directory = tempfile::tempdir().unwrap();
    let kubeconfig = directory.path().join("unreachable-ingress-list.yaml");
    std::fs::write(
        &kubeconfig,
        r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:1
  name: unreachable
contexts:
- context:
    cluster: unreachable
    user: unreachable
  name: unreachable
current-context: unreachable
users:
- name: unreachable
  user:
    token: not-a-real-token
"#,
    )
    .unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var("KUBECONFIG", &kubeconfig);
    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig {
        namespace: "default".into(),
        watch_interval_secs: 2,
        ..KubernetesProviderConfig::default()
    });
    let error = crate::validate_activation(&config).unwrap_err();
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    let message = error.to_string();
    assert!(
        message.contains("providers.kubernetes cannot activate")
            || message.contains("Failed to list K8s Ingresses"),
        "unreachable Ingress list must fail validate_activation: {error}"
    );
}

#[cfg(feature = "kube")]
#[tokio::test(flavor = "multi_thread")]
async fn validate_activation_probes_kubernetes_ingress_list() {
    use bytes::Bytes;
    use http::{Request, Response, StatusCode};
    use http_body_util::Full;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use std::convert::Infallible;
    use tokio::net::TcpListener;

    let _guard = lock_kubeconfig_env();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let _server = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let service = service_fn(|request: Request<Incoming>| async move {
                    let path = request.uri().path().to_string();
                    let (status, body) = if path.contains("/ingresses") {
                        (
                            StatusCode::OK,
                            r#"{"apiVersion":"networking.k8s.io/v1","kind":"IngressList","metadata":{"resourceVersion":"1"},"items":[]}"#,
                        )
                    } else {
                        (
                            StatusCode::NOT_FOUND,
                            r#"{"kind":"Status","apiVersion":"v1","status":"Failure","message":"unexpected path","code":404}"#,
                        )
                    };
                    Ok::<_, Infallible>(
                        Response::builder()
                            .status(status)
                            .header(http::header::CONTENT_TYPE, "application/json")
                            .header(http::header::CONNECTION, "close")
                            .body(Full::new(Bytes::from(body)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });

    let directory = tempfile::tempdir().unwrap();
    let kubeconfig = directory.path().join("mock-ingress-list.yaml");
    std::fs::write(
        &kubeconfig,
        format!(
            r#"
apiVersion: v1
kind: Config
clusters:
- cluster:
    server: http://127.0.0.1:{}
  name: mock
contexts:
- context:
    cluster: mock
    user: mock
  name: mock
current-context: mock
users:
- name: mock
  user:
    token: not-a-real-token
"#,
            address.port()
        ),
    )
    .unwrap();
    let previous = std::env::var_os("KUBECONFIG");
    std::env::set_var("KUBECONFIG", &kubeconfig);

    let mut config = GatewayConfig::default();
    config.providers.kubernetes = Some(KubernetesProviderConfig {
        namespace: "default".into(),
        watch_interval_secs: 2,
        ..KubernetesProviderConfig::default()
    });
    let result = crate::validate_activation(&config);
    match previous {
        Some(value) => std::env::set_var("KUBECONFIG", value),
        None => std::env::remove_var("KUBECONFIG"),
    }
    result.expect("reachable empty Ingress list must activate at validate");
}

#[test]
fn test_validate_acme_without_domains_fails_closed() {
    let acl = r#"
        entrypoints "websecure" {
            address = "127.0.0.1:8443"
            tls {
                cert_file  = "/tmp/cert.pem"
                key_file   = "/tmp/key.pem"
                acme       = true
                acme_email = "ops@example.com"
            }
        }
        routers "api" {
            rule        = "PathPrefix(`/`)"
            service     = "backend"
            entrypoints = ["websecure"]
        }
        services "backend" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
    "#;
    let err = GatewayConfig::from_acl(acl)
        .unwrap()
        .validate()
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("acme_domains") || err.contains("Host(`"),
        "config validate must reject ACME without domains: {err}"
    );
}

#[test]
fn test_validate_acme_with_host_router_domains_ok() {
    let acl = r#"
        entrypoints "websecure" {
            address = "127.0.0.1:8443"
            tls {
                cert_file  = "/tmp/cert.pem"
                key_file   = "/tmp/key.pem"
                acme       = true
                acme_email = "ops@example.com"
            }
        }
        routers "api" {
            rule        = "Host(`app.example.com`) && PathPrefix(`/`)"
            service     = "backend"
            entrypoints = ["websecure"]
        }
        services "backend" {
            load_balancer {
                servers = [{ url = "http://127.0.0.1:8001" }]
            }
        }
    "#;
    GatewayConfig::from_acl(acl).unwrap().validate().unwrap();
}

fn acme_entrypoint_config(storage_path: Option<String>) -> crate::config::EntrypointConfig {
    let mut entrypoint = crate::config::EntrypointConfig::new("127.0.0.1:8443".to_string());
    entrypoint.tls = Some(crate::config::TlsConfig {
        cert_file: "/tmp/cert.pem".to_string(),
        key_file: "/tmp/key.pem".to_string(),
        acme: true,
        min_version: "1.2".to_string(),
        acme_email: Some("ops@example.com".to_string()),
        acme_domains: vec!["app.example.com".to_string()],
        acme_staging: false,
        acme_storage_path: storage_path,
    });
    entrypoint
}

#[test]
fn test_validate_activation_builds_acme_manager_when_configured() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("acme");
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage.to_string_lossy().into_owned())),
    );
    crate::proxy::acme_manager::AcmeManager::validate_activation(&config)
        .expect("ACME activation must share AcmeManager::try_from_gateway_config with cold start");
    assert!(
        storage.is_dir(),
        "ACME activation probe must create the storage directory"
    );
}

#[test]
fn validate_activation_fails_closed_when_acme_storage_path_is_a_file() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("not-a-dir");
    std::fs::write(&storage, b"blocked").unwrap();
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage.to_string_lossy().into_owned())),
    );
    let error = crate::proxy::acme_manager::AcmeManager::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("not a directory"),
        "file-as-storage must fail ACME activation: {error}"
    );
}

#[test]
fn validate_activation_fails_closed_when_acme_storage_path_is_relative() {
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some("relative/acme".to_string())),
    );
    let error = crate::proxy::acme_manager::AcmeManager::validate_activation(&config).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("absolute normalized directory path"),
        "relative ACME storage must fail activation: {error}"
    );
}

#[test]
fn validate_activation_fails_closed_when_acme_account_key_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("acme");
    std::fs::create_dir_all(&storage).unwrap();
    std::fs::write(storage.join("account.key"), b"not-a-pkcs8-key").unwrap();
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage.to_string_lossy().into_owned())),
    );
    let error = crate::proxy::acme_manager::AcmeManager::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("account key")
            && (error.to_string().contains("unusable")
                || error.to_string().contains("PKCS#8")
                || error.to_string().contains("ECDSA")),
        "corrupt ACME account.key must fail activation: {error}"
    );
}

#[test]
fn validate_activation_accepts_usable_acme_account_key() {
    let directory = tempfile::tempdir().unwrap();
    let storage = directory.path().join("acme");
    std::fs::create_dir_all(&storage).unwrap();
    let key = crate::proxy::acme_account::AccountKey::generate().unwrap();
    std::fs::write(storage.join("account.key"), key.pkcs8_der()).unwrap();
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage.to_string_lossy().into_owned())),
    );
    crate::proxy::acme_manager::AcmeManager::validate_activation(&config)
        .expect("usable ACME account.key must pass activation");
}

#[test]
fn validate_activation_fails_closed_when_acme_stored_cert_pem_corrupt() {
    let directory = tempfile::tempdir().unwrap();
    let storage_path = directory.path().join("acme");
    std::fs::create_dir_all(&storage_path).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Valid expiry timestamp with unusable PEMs — the soft-open this closes.
    let info = crate::proxy::acme::CertInfo {
        domain: "app.example.com".to_string(),
        cert_pem: "-----BEGIN CERTIFICATE-----\nnot-a-cert\n-----END CERTIFICATE-----\n"
            .to_string(),
        key_pem: "-----BEGIN PRIVATE KEY-----\nnot-a-key\n-----END PRIVATE KEY-----\n".to_string(),
        expires_at: now + 90 * 86400,
        issued_at: now,
    };
    crate::proxy::acme::CertStorage::new(&storage_path)
        .save(&info)
        .unwrap();
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage_path.to_string_lossy().into_owned())),
    );
    let error = crate::proxy::acme_manager::AcmeManager::validate_activation(&config).unwrap_err();
    assert!(
        error.to_string().contains("unusable for TLS install")
            || error.to_string().contains("stored certificate"),
        "corrupt stored ACME cert PEM must fail activation: {error}"
    );
}

#[test]
fn validate_activation_accepts_usable_acme_stored_cert_pem() {
    let directory = tempfile::tempdir().unwrap();
    let storage_path = directory.path().join("acme");
    std::fs::create_dir_all(&storage_path).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cert_pem = include_str!("../../tests/fixtures/usage_mtls_server.pem");
    let key_pem = include_str!("../../tests/fixtures/usage_mtls_server.key");
    let info = crate::proxy::acme::CertInfo {
        domain: "app.example.com".to_string(),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
        expires_at: now + 90 * 86400,
        issued_at: now,
    };
    crate::proxy::acme::CertStorage::new(&storage_path)
        .save(&info)
        .unwrap();
    let mut config = GatewayConfig::default();
    config.entrypoints.insert(
        "websecure".to_string(),
        acme_entrypoint_config(Some(storage_path.to_string_lossy().into_owned())),
    );
    crate::proxy::acme_manager::AcmeManager::validate_activation(&config)
        .expect("usable stored ACME cert PEM must pass activation");
}
