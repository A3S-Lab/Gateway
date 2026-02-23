//! Kubernetes Ingress provider
//!
//! Watches K8s `networking.k8s.io/v1/Ingress` resources and converts them
//! into gateway routing configuration (routers + services).
//!
//! Feature-gated behind `kube`. All conversion logic is pure and testable
//! without a real K8s cluster.

#![cfg_attr(not(feature = "kube"), allow(dead_code))]
use crate::config::{
    GatewayConfig, KubernetesProviderConfig, LoadBalancerConfig, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// -----------------------------------------------------------------------
// Ingress model — mirrors K8s networking.k8s.io/v1/Ingress
// Defined locally so conversion tests work without the `kube` feature.
// -----------------------------------------------------------------------

/// Simplified K8s Ingress representation for conversion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressResource {
    /// Ingress name
    pub name: String,
    /// Namespace
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Annotations (used for middleware, entrypoint config)
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Ingress spec
    pub spec: IngressSpec,
}

pub(crate) fn default_namespace() -> String {
    "default".to_string()
}

/// Ingress spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressSpec {
    /// TLS configuration
    #[serde(default)]
    pub tls: Vec<IngressTls>,
    /// Routing rules
    #[serde(default)]
    pub rules: Vec<IngressRule>,
}

/// Ingress TLS block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressTls {
    /// Hostnames covered by this TLS config
    #[serde(default)]
    pub hosts: Vec<String>,
    /// K8s Secret name containing the TLS cert
    #[serde(default)]
    pub secret_name: String,
}

/// Ingress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRule {
    /// Hostname (e.g., "api.example.com")
    #[serde(default)]
    pub host: String,
    /// HTTP routing paths
    #[serde(default)]
    pub http: Option<IngressHttp>,
}

/// HTTP section of an Ingress rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressHttp {
    /// Path rules
    pub paths: Vec<IngressPath>,
}

/// Individual path rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressPath {
    /// URL path (e.g., "/api")
    #[serde(default = "default_path")]
    pub path: String,
    /// Path type: Prefix, Exact, ImplementationSpecific
    #[serde(default = "default_path_type")]
    pub path_type: String,
    /// Backend service reference
    pub backend: IngressBackend,
}

fn default_path() -> String {
    "/".to_string()
}

fn default_path_type() -> String {
    "Prefix".to_string()
}

/// Backend service reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressBackend {
    /// Service reference
    pub service: IngressServiceRef,
}

/// Service reference in an Ingress backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressServiceRef {
    /// Service name
    pub name: String,
    /// Service port
    pub port: IngressServicePort,
}

/// Service port reference
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressServicePort {
    /// Port number
    #[serde(default)]
    pub number: u16,
    /// Named port (alternative to number)
    #[serde(default)]
    pub name: String,
}

// -----------------------------------------------------------------------
// Annotation keys
// -----------------------------------------------------------------------

/// Comma-separated list of entrypoint names
const ANN_ENTRYPOINTS: &str = "a3s-gateway.io/entrypoints";

/// Comma-separated list of middleware names
const ANN_MIDDLEWARES: &str = "a3s-gateway.io/middlewares";

/// Load balancing strategy override
const ANN_STRATEGY: &str = "a3s-gateway.io/strategy";

/// Router priority override
const ANN_PRIORITY: &str = "a3s-gateway.io/priority";

/// Annotation: protocol override (tcp, udp; default: http)
const ANN_PROTOCOL: &str = "a3s-gateway.io/protocol";

/// Annotation: listen address for TCP/UDP entrypoints
const ANN_LISTEN: &str = "a3s-gateway.io/listen";

// -----------------------------------------------------------------------
// Conversion: Ingress → GatewayConfig
// -----------------------------------------------------------------------

/// Convert a list of Ingress resources into a partial GatewayConfig
/// containing routers, services, and optionally TCP/UDP entrypoints.
pub fn ingress_to_config(ingresses: &[IngressResource]) -> GatewayConfig {
    let mut routers = HashMap::new();
    let mut services = HashMap::new();
    let mut entrypoints = HashMap::new();

    for ingress in ingresses {
        let ingress_entrypoints = parse_csv_annotation(&ingress.annotations, ANN_ENTRYPOINTS);
        let middlewares = parse_csv_annotation(&ingress.annotations, ANN_MIDDLEWARES);
        let strategy = ingress
            .annotations
            .get(ANN_STRATEGY)
            .and_then(|s| s.parse().ok())
            .unwrap_or(Strategy::RoundRobin);
        let priority = ingress
            .annotations
            .get(ANN_PRIORITY)
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0);

        // Check for TCP/UDP protocol override
        let protocol = ingress
            .annotations
            .get(ANN_PROTOCOL)
            .map(|s| s.as_str())
            .unwrap_or("http");
        let listen_addr = ingress.annotations.get(ANN_LISTEN);

        for rule in &ingress.spec.rules {
            let http = match &rule.http {
                Some(h) => h,
                None => continue,
            };

            for path in &http.paths {
                let svc_name = format!(
                    "{}-{}-{}",
                    ingress.namespace, ingress.name, path.backend.service.name
                );

                // Build service with backend URL
                let port = if path.backend.service.port.number > 0 {
                    path.backend.service.port.number
                } else {
                    80
                };
                let url = format!(
                    "http://{}.{}.svc.cluster.local:{}",
                    path.backend.service.name, ingress.namespace, port
                );

                services.insert(
                    svc_name.clone(),
                    ServiceConfig {
                        load_balancer: LoadBalancerConfig {
                            strategy: strategy.clone(),
                            servers: vec![ServerConfig { url, weight: 1 }],
                            health_check: None,
                            sticky: None,
                        },
                        scaling: None,
                        revisions: vec![],
                        rollout: None,
                        mirror: None,
                        failover: None,
                    },
                );

                match protocol {
                    "tcp" => {
                        if let Some(addr) = listen_addr {
                            entrypoints.insert(
                                format!("{}-tcp", svc_name),
                                crate::config::EntrypointConfig {
                                    address: addr.clone(),
                                    protocol: crate::config::Protocol::Tcp,
                                    tls: None,
                                    max_connections: None,
                                    tcp_allowed_ips: vec![],
                                    udp_session_timeout_secs: None,
                                    udp_max_sessions: None,
                                },
                            );
                        }
                    }
                    "udp" => {
                        if let Some(addr) = listen_addr {
                            entrypoints.insert(
                                format!("{}-udp", svc_name),
                                crate::config::EntrypointConfig {
                                    address: addr.clone(),
                                    protocol: crate::config::Protocol::Udp,
                                    tls: None,
                                    max_connections: None,
                                    tcp_allowed_ips: vec![],
                                    udp_session_timeout_secs: Some(30),
                                    udp_max_sessions: None,
                                },
                            );
                        }
                    }
                    _ => {
                        // HTTP — generate standard router
                        let rule_str = build_rule_string(&rule.host, &path.path, &path.path_type);
                        routers.insert(
                            svc_name.clone(),
                            RouterConfig {
                                rule: rule_str,
                                service: svc_name.clone(),
                                entrypoints: ingress_entrypoints.clone(),
                                middlewares: middlewares.clone(),
                                priority,
                            },
                        );
                    }
                }
            }
        }
    }

    GatewayConfig {
        entrypoints,
        routers,
        services,
        middlewares: HashMap::new(),
        providers: Default::default(),
        shutdown_timeout_secs: 30,
    }
}

/// Build a Traefik-style rule string from Ingress host + path
fn build_rule_string(host: &str, path: &str, path_type: &str) -> String {
    let mut parts = Vec::new();

    if !host.is_empty() {
        parts.push(format!("Host(`{}`)", host));
    }

    if !path.is_empty() && path != "/" {
        match path_type {
            "Exact" => parts.push(format!("Path(`{}`)", path)),
            _ => parts.push(format!("PathPrefix(`{}`)", path)),
        }
    }

    if parts.is_empty() {
        // Catch-all rule
        "PathPrefix(`/`)".to_string()
    } else {
        parts.join(" && ")
    }
}

/// Parse a comma-separated annotation value into a Vec<String>
fn parse_csv_annotation(annotations: &HashMap<String, String>, key: &str) -> Vec<String> {
    annotations
        .get(key)
        .map(|v| {
            v.split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Merge K8s-discovered config into a base config.
/// K8s-discovered routers/services are added; static config wins on name collisions.
pub fn merge_k8s_config(base: &GatewayConfig, discovered: &GatewayConfig) -> GatewayConfig {
    let mut merged = base.clone();

    for (name, router) in &discovered.routers {
        if !merged.routers.contains_key(name) {
            merged.routers.insert(name.clone(), router.clone());
        }
    }

    for (name, service) in &discovered.services {
        if !merged.services.contains_key(name) {
            merged.services.insert(name.clone(), service.clone());
        }
    }

    merged
}

// -----------------------------------------------------------------------
// K8s watcher — feature-gated behind `kube`
// -----------------------------------------------------------------------

/// Spawn a polling loop that watches K8s Ingress resources and sends
/// updated GatewayConfig on the provided channel.
#[cfg(feature = "kube")]
pub fn spawn_ingress_watch(
    config: KubernetesProviderConfig,
    base_config: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<GatewayConfig>,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;

    tokio::spawn(async move {
        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create K8s client for Ingress watcher");
                return;
            }
        };

        let interval = Duration::from_secs(config.watch_interval_secs);
        let mut last_hash: u64 = 0;

        loop {
            match poll_ingresses(&client, &config).await {
                Ok(ingresses) => {
                    let discovered = ingress_to_config(&ingresses);
                    let merged = merge_k8s_config(&base_config, &discovered);

                    // Simple change detection via hash of router+service keys
                    let hash = hash_config_keys(&merged);
                    if hash != last_hash {
                        last_hash = hash;
                        tracing::info!(
                            ingresses = ingresses.len(),
                            routers = merged.routers.len(),
                            services = merged.services.len(),
                            "K8s Ingress config updated"
                        );
                        if tx.send(merged).await.is_err() {
                            tracing::debug!("K8s Ingress watcher channel closed");
                            return;
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to poll K8s Ingresses");
                }
            }

            tokio::time::sleep(interval).await;
        }
    })
}

/// Poll K8s API for Ingress resources and convert to our model
#[cfg(feature = "kube")]
async fn poll_ingresses(
    client: &kube::Client,
    config: &crate::config::KubernetesProviderConfig,
) -> crate::error::Result<Vec<IngressResource>> {
    use crate::error::GatewayError;
    use k8s_openapi::api::networking::v1::Ingress;
    use kube::api::{Api, ListParams};

    let api: Api<Ingress> = if config.namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &config.namespace)
    };

    let mut lp = ListParams::default();
    if !config.label_selector.is_empty() {
        lp = lp.labels(&config.label_selector);
    }

    let list = api
        .list(&lp)
        .await
        .map_err(|e| GatewayError::Other(format!("Failed to list K8s Ingresses: {}", e)))?;

    let mut result = Vec::new();
    for ingress in list.items {
        if let Some(resource) = k8s_ingress_to_model(&ingress) {
            result.push(resource);
        }
    }

    Ok(result)
}

/// Convert a k8s-openapi Ingress into our local IngressResource model
#[cfg(feature = "kube")]
fn k8s_ingress_to_model(
    ingress: &k8s_openapi::api::networking::v1::Ingress,
) -> Option<IngressResource> {
    let meta = &ingress.metadata;
    let name = meta.name.clone().unwrap_or_default();
    let namespace = meta
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let annotations: HashMap<String, String> = meta
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();

    let spec = ingress.spec.as_ref()?;

    let tls = spec
        .tls
        .as_ref()
        .map(|tls_list| {
            tls_list
                .iter()
                .map(|t| IngressTls {
                    hosts: t.hosts.clone().unwrap_or_default(),
                    secret_name: t.secret_name.clone().unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default();

    let rules = spec
        .rules
        .as_ref()
        .map(|rule_list| {
            rule_list
                .iter()
                .map(|r| {
                    let http = r.http.as_ref().map(|h| IngressHttp {
                        paths: h
                            .paths
                            .iter()
                            .map(|p| {
                                let backend_svc = p
                                    .backend
                                    .service
                                    .as_ref()
                                    .map(|s| IngressServiceRef {
                                        name: s.name.clone(),
                                        port: s
                                            .port
                                            .as_ref()
                                            .map(|port| IngressServicePort {
                                                number: port.number.unwrap_or(0) as u16,
                                                name: port.name.clone().unwrap_or_default(),
                                            })
                                            .unwrap_or(IngressServicePort {
                                                number: 80,
                                                name: String::new(),
                                            }),
                                    })
                                    .unwrap_or(IngressServiceRef {
                                        name: String::new(),
                                        port: IngressServicePort {
                                            number: 80,
                                            name: String::new(),
                                        },
                                    });

                                IngressPath {
                                    path: p.path.clone().unwrap_or_else(|| "/".to_string()),
                                    path_type: p.path_type.clone(),
                                    backend: IngressBackend {
                                        service: backend_svc,
                                    },
                                }
                            })
                            .collect(),
                    });

                    IngressRule {
                        host: r.host.clone().unwrap_or_default(),
                        http,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    Some(IngressResource {
        name,
        namespace,
        annotations,
        spec: IngressSpec { tls, rules },
    })
}

/// Simple hash of config router+service keys for change detection
#[cfg(feature = "kube")]
fn hash_config_keys(config: &GatewayConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    let mut router_keys: Vec<&String> = config.routers.keys().collect();
    router_keys.sort();
    for k in &router_keys {
        k.hash(&mut hasher);
    }
    let mut svc_keys: Vec<&String> = config.services.keys().collect();
    svc_keys.sort();
    for k in &svc_keys {
        k.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
