use super::*;

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
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("unknown service"));
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
