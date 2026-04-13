//! Kubernetes Ingress provider
//!
//! Watches K8s `networking.k8s.io/v1/Ingress` resources and converts them
//! into gateway routing configuration (routers + services).
//!
//! Feature-gated behind `kube`. All conversion logic is pure and testable
//! without a real K8s cluster.

#![cfg_attr(not(feature = "kube"), allow(dead_code))]
#[cfg(feature = "kube")]
use crate::config::KubernetesProviderConfig;
use crate::config::{
    GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy,
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
pub(crate) const ANN_ENTRYPOINTS: &str = "a3s-gateway.io/entrypoints";

/// Comma-separated list of middleware names
pub(crate) const ANN_MIDDLEWARES: &str = "a3s-gateway.io/middlewares";

/// Load balancing strategy override
pub(crate) const ANN_STRATEGY: &str = "a3s-gateway.io/strategy";

/// Router priority override
pub(crate) const ANN_PRIORITY: &str = "a3s-gateway.io/priority";

/// Annotation: protocol override (tcp, udp; default: http)
pub(crate) const ANN_PROTOCOL: &str = "a3s-gateway.io/protocol";

/// Annotation: listen address for TCP/UDP entrypoints
pub(crate) const ANN_LISTEN: &str = "a3s-gateway.io/listen";

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
pub(crate) fn build_rule_string(host: &str, path: &str, path_type: &str) -> String {
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
pub(crate) fn parse_csv_annotation(annotations: &HashMap<String, String>, key: &str) -> Vec<String> {
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

