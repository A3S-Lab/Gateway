//! Kubernetes Ingress provider — tests

use std::collections::HashMap;

use crate::config::{GatewayConfig, RouterConfig, Strategy};
use crate::provider::kubernetes::{
    build_rule_string, ingress_to_config, merge_k8s_config, parse_csv_annotation, IngressBackend,
    IngressHttp, IngressPath, IngressResource, IngressRule, IngressServicePort, IngressServiceRef,
    IngressSpec, IngressTls, ANN_ENTRYPOINTS, ANN_LISTEN, ANN_MIDDLEWARES, ANN_PRIORITY,
    ANN_PROTOCOL, ANN_STRATEGY,
};

fn make_ingress(
    name: &str,
    ns: &str,
    host: &str,
    path: &str,
    svc: &str,
    port: u16,
) -> IngressResource {
    IngressResource {
        name: name.to_string(),
        namespace: ns.to_string(),
        annotations: HashMap::new(),
        spec: IngressSpec {
            tls: vec![],
            rules: vec![IngressRule {
                host: host.to_string(),
                http: Some(IngressHttp {
                    paths: vec![IngressPath {
                        path: path.to_string(),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: IngressServiceRef {
                                name: svc.to_string(),
                                port: IngressServicePort {
                                    number: port,
                                    name: String::new(),
                                },
                            },
                        },
                    }],
                }),
            }],
        },
    }
}

// --- build_rule_string ---

#[test]
fn test_rule_host_only() {
    let rule = build_rule_string("api.example.com", "", "Prefix");
    assert_eq!(rule, "Host(`api.example.com`)");
}

#[test]
fn test_rule_path_only() {
    let rule = build_rule_string("", "/api", "Prefix");
    assert_eq!(rule, "PathPrefix(`/api`)");
}

#[test]
fn test_rule_host_and_path() {
    let rule = build_rule_string("api.example.com", "/v1", "Prefix");
    assert_eq!(rule, "Host(`api.example.com`) && PathPrefix(`/v1`)");
}

#[test]
fn test_rule_exact_path() {
    let rule = build_rule_string("", "/health", "Exact");
    assert_eq!(rule, "Path(`/health`)");
}

#[test]
fn test_rule_root_path_ignored() {
    let rule = build_rule_string("example.com", "/", "Prefix");
    assert_eq!(rule, "Host(`example.com`)");
}

#[test]
fn test_rule_empty_catchall() {
    let rule = build_rule_string("", "", "Prefix");
    assert_eq!(rule, "PathPrefix(`/`)");
}

// --- parse_csv_annotation ---

#[test]
fn test_parse_csv_empty() {
    let ann = HashMap::new();
    assert!(parse_csv_annotation(&ann, "key").is_empty());
}

#[test]
fn test_parse_csv_single() {
    let mut ann = HashMap::new();
    ann.insert("key".to_string(), "web".to_string());
    assert_eq!(parse_csv_annotation(&ann, "key"), vec!["web"]);
}

#[test]
fn test_parse_csv_multiple() {
    let mut ann = HashMap::new();
    ann.insert("key".to_string(), "web, websecure, tcp".to_string());
    assert_eq!(
        parse_csv_annotation(&ann, "key"),
        vec!["web", "websecure", "tcp"]
    );
}

// --- Strategy::from_str ---

#[test]
fn test_strategy_from_str_valid() {
    assert_eq!("round-robin".parse::<Strategy>(), Ok(Strategy::RoundRobin));
    assert_eq!("weighted".parse::<Strategy>(), Ok(Strategy::Weighted));
    assert_eq!(
        "least-connections".parse::<Strategy>(),
        Ok(Strategy::LeastConnections)
    );
    assert_eq!("random".parse::<Strategy>(), Ok(Strategy::Random));
}

#[test]
fn test_strategy_from_str_invalid() {
    assert!("unknown".parse::<Strategy>().is_err());
}

// --- ingress_to_config ---

#[test]
fn test_single_ingress_conversion() {
    let ingress = make_ingress(
        "my-app",
        "default",
        "app.example.com",
        "/api",
        "backend-svc",
        8080,
    );
    let config = ingress_to_config(&[ingress]);

    assert_eq!(config.routers.len(), 1);
    assert_eq!(config.services.len(), 1);

    let router = config.routers.get("default-my-app-backend-svc").unwrap();
    assert_eq!(router.rule, "Host(`app.example.com`) && PathPrefix(`/api`)");
    assert_eq!(router.service, "default-my-app-backend-svc");

    let svc = config.services.get("default-my-app-backend-svc").unwrap();
    assert_eq!(svc.load_balancer.servers.len(), 1);
    assert_eq!(
        svc.load_balancer.servers[0].url,
        "http://backend-svc.default.svc.cluster.local:8080"
    );
}

#[test]
fn test_multiple_ingresses() {
    let ingresses = vec![
        make_ingress("app1", "ns1", "a.example.com", "/", "svc-a", 80),
        make_ingress("app2", "ns2", "b.example.com", "/api", "svc-b", 3000),
    ];
    let config = ingress_to_config(&ingresses);
    assert_eq!(config.routers.len(), 2);
    assert_eq!(config.services.len(), 2);
    assert!(config.routers.contains_key("ns1-app1-svc-a"));
    assert!(config.routers.contains_key("ns2-app2-svc-b"));
}

#[test]
fn test_ingress_with_annotations() {
    let mut ingress = make_ingress("web", "prod", "web.example.com", "/", "web-svc", 80);
    ingress
        .annotations
        .insert(ANN_ENTRYPOINTS.to_string(), "web, websecure".to_string());
    ingress
        .annotations
        .insert(ANN_MIDDLEWARES.to_string(), "rate-limit, auth".to_string());
    ingress
        .annotations
        .insert(ANN_STRATEGY.to_string(), "least-connections".to_string());
    ingress
        .annotations
        .insert(ANN_PRIORITY.to_string(), "10".to_string());

    let config = ingress_to_config(&[ingress]);
    let router = config.routers.values().next().unwrap();
    assert_eq!(router.entrypoints, vec!["web", "websecure"]);
    assert_eq!(router.middlewares, vec!["rate-limit", "auth"]);
    assert_eq!(router.priority, 10);

    let svc = config.services.values().next().unwrap();
    assert_eq!(svc.load_balancer.strategy, Strategy::LeastConnections);
}

#[test]
fn test_ingress_default_port() {
    let ingress = make_ingress("app", "default", "example.com", "/", "svc", 0);
    let config = ingress_to_config(&[ingress]);
    let svc = config.services.values().next().unwrap();
    // Port 0 → default 80
    assert!(svc.load_balancer.servers[0].url.ends_with(":80"));
}

#[test]
fn test_ingress_no_rules() {
    let ingress = IngressResource {
        name: "empty".to_string(),
        namespace: "default".to_string(),
        annotations: HashMap::new(),
        spec: IngressSpec {
            tls: vec![],
            rules: vec![],
        },
    };
    let config = ingress_to_config(&[ingress]);
    assert!(config.routers.is_empty());
    assert!(config.services.is_empty());
}

#[test]
fn test_ingress_no_http() {
    let ingress = IngressResource {
        name: "no-http".to_string(),
        namespace: "default".to_string(),
        annotations: HashMap::new(),
        spec: IngressSpec {
            tls: vec![],
            rules: vec![IngressRule {
                host: "example.com".to_string(),
                http: None,
            }],
        },
    };
    let config = ingress_to_config(&[ingress]);
    assert!(config.routers.is_empty());
}

#[test]
fn test_ingress_multiple_paths() {
    let ingress = IngressResource {
        name: "multi".to_string(),
        namespace: "default".to_string(),
        annotations: HashMap::new(),
        spec: IngressSpec {
            tls: vec![],
            rules: vec![IngressRule {
                host: "example.com".to_string(),
                http: Some(IngressHttp {
                    paths: vec![
                        IngressPath {
                            path: "/api".to_string(),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: IngressServiceRef {
                                    name: "api-svc".to_string(),
                                    port: IngressServicePort {
                                        number: 8080,
                                        name: String::new(),
                                    },
                                },
                            },
                        },
                        IngressPath {
                            path: "/web".to_string(),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: IngressServiceRef {
                                    name: "web-svc".to_string(),
                                    port: IngressServicePort {
                                        number: 3000,
                                        name: String::new(),
                                    },
                                },
                            },
                        },
                    ],
                }),
            }],
        },
    };
    let config = ingress_to_config(&[ingress]);
    assert_eq!(config.routers.len(), 2);
    assert_eq!(config.services.len(), 2);
}

// --- merge_k8s_config ---

#[test]
fn test_merge_adds_new() {
    let base = GatewayConfig::default();
    let ingress = make_ingress("app", "default", "example.com", "/api", "svc", 80);
    let discovered = ingress_to_config(&[ingress]);
    let merged = merge_k8s_config(&base, &discovered);
    assert_eq!(merged.routers.len(), 1);
    assert_eq!(merged.services.len(), 1);
}

#[test]
fn test_merge_static_wins() {
    let mut base = GatewayConfig::default();
    base.routers.insert(
        "default-app-svc".to_string(),
        RouterConfig {
            rule: "Host(`static.example.com`)".to_string(),
            service: "static-svc".to_string(),
            entrypoints: vec![],
            middlewares: vec![],
            priority: 0,
        },
    );

    let ingress = make_ingress("app", "default", "dynamic.example.com", "/", "svc", 80);
    let discovered = ingress_to_config(&[ingress]);
    let merged = merge_k8s_config(&base, &discovered);

    // Static router should win
    let router = merged.routers.get("default-app-svc").unwrap();
    assert_eq!(router.rule, "Host(`static.example.com`)");
}

// --- TCP/UDP protocol support ---

#[test]
fn test_tcp_protocol_generates_entrypoint() {
    let mut ingress = make_ingress("redis", "default", "", "/", "redis-svc", 6379);
    ingress
        .annotations
        .insert(ANN_PROTOCOL.to_string(), "tcp".to_string());
    ingress
        .annotations
        .insert(ANN_LISTEN.to_string(), "0.0.0.0:6379".to_string());

    let config = ingress_to_config(&[ingress]);

    // Service should be created
    assert_eq!(config.services.len(), 1);
    assert!(config.services.contains_key("default-redis-redis-svc"));

    // TCP entrypoint should be generated
    assert_eq!(config.entrypoints.len(), 1);
    let ep = config
        .entrypoints
        .get("default-redis-redis-svc-tcp")
        .unwrap();
    assert_eq!(ep.address, "0.0.0.0:6379");
    assert_eq!(ep.protocol, crate::config::Protocol::Tcp);

    // No HTTP router
    assert!(config.routers.is_empty());
}

#[test]
fn test_udp_protocol_generates_entrypoint() {
    let mut ingress = make_ingress("dns", "kube-system", "", "/", "coredns", 53);
    ingress
        .annotations
        .insert(ANN_PROTOCOL.to_string(), "udp".to_string());
    ingress
        .annotations
        .insert(ANN_LISTEN.to_string(), "0.0.0.0:5353".to_string());

    let config = ingress_to_config(&[ingress]);

    assert_eq!(config.services.len(), 1);
    assert_eq!(config.entrypoints.len(), 1);
    let ep = config
        .entrypoints
        .get("kube-system-dns-coredns-udp")
        .unwrap();
    assert_eq!(ep.address, "0.0.0.0:5353");
    assert_eq!(ep.protocol, crate::config::Protocol::Udp);
    assert_eq!(ep.udp_session_timeout_secs, Some(30));
    assert!(config.routers.is_empty());
}

#[test]
fn test_tcp_without_listen_no_entrypoint() {
    let mut ingress = make_ingress("redis", "default", "", "/", "redis-svc", 6379);
    ingress
        .annotations
        .insert(ANN_PROTOCOL.to_string(), "tcp".to_string());
    // No ANN_LISTEN annotation

    let config = ingress_to_config(&[ingress]);

    // Service created, but no entrypoint and no router
    assert_eq!(config.services.len(), 1);
    assert!(config.entrypoints.is_empty());
    assert!(config.routers.is_empty());
}

#[test]
fn test_http_protocol_default_generates_router() {
    // No protocol annotation → defaults to http
    let ingress = make_ingress("web", "default", "web.example.com", "/", "web-svc", 80);
    let config = ingress_to_config(&[ingress]);

    assert_eq!(config.routers.len(), 1);
    assert!(config.entrypoints.is_empty());
}

#[test]
fn test_mixed_http_and_tcp_ingresses() {
    let http_ingress = make_ingress("web", "default", "web.example.com", "/api", "web-svc", 80);
    let mut tcp_ingress = make_ingress("redis", "default", "", "/", "redis-svc", 6379);
    tcp_ingress
        .annotations
        .insert(ANN_PROTOCOL.to_string(), "tcp".to_string());
    tcp_ingress
        .annotations
        .insert(ANN_LISTEN.to_string(), "0.0.0.0:6379".to_string());

    let config = ingress_to_config(&[http_ingress, tcp_ingress]);

    assert_eq!(config.services.len(), 2);
    assert_eq!(config.routers.len(), 1); // only HTTP
    assert_eq!(config.entrypoints.len(), 1); // only TCP
    assert!(config.routers.contains_key("default-web-web-svc"));
    assert!(config
        .entrypoints
        .contains_key("default-redis-redis-svc-tcp"));
}

// --- IngressResource serialization ---

#[test]
fn test_ingress_resource_serialization() {
    let ingress = make_ingress("test", "ns", "example.com", "/api", "svc", 8080);
    let json = serde_json::to_string(&ingress).unwrap();
    let parsed: IngressResource = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.name, "test");
    assert_eq!(parsed.namespace, "ns");
    assert_eq!(parsed.spec.rules.len(), 1);
}

#[test]
fn test_ingress_tls() {
    let ingress = IngressResource {
        name: "tls-app".to_string(),
        namespace: "default".to_string(),
        annotations: HashMap::new(),
        spec: IngressSpec {
            tls: vec![IngressTls {
                hosts: vec!["secure.example.com".to_string()],
                secret_name: "tls-secret".to_string(),
            }],
            rules: vec![IngressRule {
                host: "secure.example.com".to_string(),
                http: Some(IngressHttp {
                    paths: vec![IngressPath {
                        path: "/".to_string(),
                        path_type: "Prefix".to_string(),
                        backend: IngressBackend {
                            service: IngressServiceRef {
                                name: "secure-svc".to_string(),
                                port: IngressServicePort {
                                    number: 443,
                                    name: String::new(),
                                },
                            },
                        },
                    }],
                }),
            }],
        },
    };
    assert_eq!(ingress.spec.tls.len(), 1);
    assert_eq!(ingress.spec.tls[0].secret_name, "tls-secret");
}
