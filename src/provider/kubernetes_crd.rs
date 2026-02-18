//! Kubernetes IngressRoute CRD provider
//!
//! Custom `IngressRoute` CRD for advanced routing beyond standard K8s Ingress.
//! Provides a Traefik-style CRD that maps directly to gateway routing concepts.
//!
//! Feature-gated behind `kube`. Conversion logic is pure and testable
//! without a real K8s cluster.

#![cfg_attr(not(feature = "kube"), allow(dead_code))]
use crate::config::{
    GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// -----------------------------------------------------------------------
// IngressRoute CRD model
// -----------------------------------------------------------------------

/// IngressRoute custom resource — advanced routing configuration
///
/// # Example YAML
///
/// ```yaml
/// apiVersion: a3s-gateway.io/v1alpha1
/// kind: IngressRoute
/// metadata:
///   name: my-app
///   namespace: default
/// spec:
///   entrypoints:
///     - web
///     - websecure
///   routes:
///     - match: "Host(`app.example.com`) && PathPrefix(`/api`)"
///       middlewares:
///         - name: rate-limit
///       services:
///         - name: api-svc
///           port: 8080
///           weight: 1
///   tls:
///     secret_name: my-tls-secret
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteResource {
    /// Resource name
    pub name: String,
    /// Namespace
    #[serde(default = "super::kubernetes::default_namespace")]
    pub namespace: String,
    /// IngressRoute spec
    pub spec: IngressRouteSpec,
}

/// IngressRoute spec
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteSpec {
    /// Entrypoint names this route applies to
    #[serde(default)]
    pub entrypoints: Vec<String>,
    /// Route definitions
    #[serde(default)]
    pub routes: Vec<IngressRouteEntry>,
    /// TLS configuration
    #[serde(default)]
    pub tls: Option<IngressRouteTls>,
}

/// A single route entry in an IngressRoute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteEntry {
    /// Traefik-style match rule (e.g., "Host(`example.com`) && PathPrefix(`/api`)")
    #[serde(rename = "match")]
    pub match_rule: String,
    /// Priority (higher = matched first)
    #[serde(default)]
    pub priority: i32,
    /// Middleware references
    #[serde(default)]
    pub middlewares: Vec<IngressRouteMiddlewareRef>,
    /// Backend services
    #[serde(default)]
    pub services: Vec<IngressRouteServiceRef>,
}

/// Middleware reference in an IngressRoute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteMiddlewareRef {
    /// Middleware name
    pub name: String,
}

/// Service reference in an IngressRoute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteServiceRef {
    /// K8s Service name
    pub name: String,
    /// Service port
    #[serde(default = "default_port")]
    pub port: u16,
    /// Weight for load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// Load balancing strategy override
    #[serde(default)]
    pub strategy: Option<String>,
}

fn default_port() -> u16 {
    80
}

fn default_weight() -> u32 {
    1
}

/// TLS configuration for IngressRoute
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRouteTls {
    /// K8s Secret name containing the TLS certificate
    #[serde(default)]
    pub secret_name: String,
}

// -----------------------------------------------------------------------
// Conversion: IngressRoute → GatewayConfig
// -----------------------------------------------------------------------

/// Convert a list of IngressRoute resources into a partial GatewayConfig
pub fn ingress_routes_to_config(routes: &[IngressRouteResource]) -> GatewayConfig {
    let mut routers = HashMap::new();
    let mut services = HashMap::new();

    for ir in routes {
        let entrypoints = ir.spec.entrypoints.clone();

        for (idx, route) in ir.spec.routes.iter().enumerate() {
            let middlewares: Vec<String> = route.middlewares.iter().map(|m| m.name.clone()).collect();

            // Build a combined service from all backends in this route
            let svc_name = if route.services.len() == 1 {
                format!("{}-{}-{}", ir.namespace, ir.name, route.services[0].name)
            } else {
                format!("{}-{}-route-{}", ir.namespace, ir.name, idx)
            };

            let router_name = svc_name.clone();

            routers.insert(
                router_name,
                RouterConfig {
                    rule: route.match_rule.clone(),
                    service: svc_name.clone(),
                    entrypoints: entrypoints.clone(),
                    middlewares,
                    priority: route.priority,
                },
            );

            // Build service with all backends as servers
            let strategy = route
                .services
                .first()
                .and_then(|s| s.strategy.as_deref())
                .and_then(|s| s.parse().ok())
                .unwrap_or(Strategy::RoundRobin);

            let servers: Vec<ServerConfig> = route
                .services
                .iter()
                .map(|s| {
                    let port = if s.port > 0 { s.port } else { 80 };
                    ServerConfig {
                        url: format!(
                            "http://{}.{}.svc.cluster.local:{}",
                            s.name, ir.namespace, port
                        ),
                        weight: s.weight,
                    }
                })
                .collect();

            services.insert(
                svc_name,
                ServiceConfig {
                    load_balancer: LoadBalancerConfig {
                        strategy,
                        servers,
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
        }
    }

    GatewayConfig {
        entrypoints: HashMap::new(),
        routers,
        services,
        middlewares: HashMap::new(),
        providers: Default::default(),
        shutdown_timeout_secs: 30,
    }
}

// -----------------------------------------------------------------------
// K8s CRD watcher — feature-gated behind `kube`
// -----------------------------------------------------------------------

#[cfg(feature = "kube")]
pub fn spawn_crd_watch(
    config: crate::config::KubernetesProviderConfig,
    base_config: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<GatewayConfig>,
) -> tokio::task::JoinHandle<()> {
    use crate::provider::kubernetes::merge_k8s_config;
    use std::time::Duration;

    tokio::spawn(async move {
        let client = match kube::Client::try_default().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "Failed to create K8s client for CRD watcher");
                return;
            }
        };

        let interval = Duration::from_secs(config.watch_interval_secs);

        loop {
            match poll_ingress_routes(&client, &config).await {
                Ok(routes) => {
                    let discovered = ingress_routes_to_config(&routes);
                    let merged = merge_k8s_config(&base_config, &discovered);
                    if tx.send(merged).await.is_err() {
                        tracing::debug!("CRD watcher channel closed");
                        return;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to poll IngressRoute CRDs");
                }
            }

            tokio::time::sleep(interval).await;
        }
    })
}

/// Poll K8s API for IngressRoute CRDs
/// Note: This requires the CRD to be installed in the cluster.
/// For now, we use a ConfigMap-based approach as a fallback.
#[cfg(feature = "kube")]
async fn poll_ingress_routes(
    client: &kube::Client,
    config: &crate::config::KubernetesProviderConfig,
) -> crate::error::Result<Vec<IngressRouteResource>> {
    use k8s_openapi::api::core::v1::ConfigMap;
    use kube::api::{Api, ListParams};

    // Look for ConfigMaps with label "a3s-gateway.io/type=ingressroute"
    let api: Api<ConfigMap> = if config.namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &config.namespace)
    };

    let lp = ListParams::default().labels("a3s-gateway.io/type=ingressroute");
    let list = api.list(&lp).await.map_err(|e| {
        crate::error::GatewayError::Other(format!("Failed to list IngressRoute ConfigMaps: {}", e))
    })?;

    let mut result = Vec::new();
    for cm in list.items {
        if let Some(data) = &cm.data {
            if let Some(spec_json) = data.get("spec") {
                match serde_json::from_str::<IngressRouteResource>(spec_json) {
                    Ok(route) => result.push(route),
                    Err(e) => {
                        let name = cm.metadata.name.as_deref().unwrap_or("unknown");
                        tracing::warn!(
                            configmap = name,
                            error = %e,
                            "Failed to parse IngressRoute from ConfigMap"
                        );
                    }
                }
            }
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_route(
        name: &str,
        ns: &str,
        match_rule: &str,
        svc_name: &str,
        port: u16,
    ) -> IngressRouteResource {
        IngressRouteResource {
            name: name.to_string(),
            namespace: ns.to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec!["web".to_string()],
                routes: vec![IngressRouteEntry {
                    match_rule: match_rule.to_string(),
                    priority: 0,
                    middlewares: vec![],
                    services: vec![IngressRouteServiceRef {
                        name: svc_name.to_string(),
                        port,
                        weight: 1,
                        strategy: None,
                    }],
                }],
                tls: None,
            },
        }
    }

    // --- ingress_routes_to_config ---

    #[test]
    fn test_single_route_conversion() {
        let route = make_route("app", "default", "Host(`app.example.com`)", "api-svc", 8080);
        let config = ingress_routes_to_config(&[route]);

        assert_eq!(config.routers.len(), 1);
        assert_eq!(config.services.len(), 1);

        let router = config.routers.get("default-app-api-svc").unwrap();
        assert_eq!(router.rule, "Host(`app.example.com`)");
        assert_eq!(router.entrypoints, vec!["web"]);

        let svc = config.services.get("default-app-api-svc").unwrap();
        assert_eq!(svc.load_balancer.servers.len(), 1);
        assert_eq!(
            svc.load_balancer.servers[0].url,
            "http://api-svc.default.svc.cluster.local:8080"
        );
    }

    #[test]
    fn test_multiple_routes() {
        let routes = vec![
            make_route("app1", "ns1", "Host(`a.com`)", "svc-a", 80),
            make_route("app2", "ns2", "PathPrefix(`/api`)", "svc-b", 3000),
        ];
        let config = ingress_routes_to_config(&routes);
        assert_eq!(config.routers.len(), 2);
        assert_eq!(config.services.len(), 2);
    }

    #[test]
    fn test_route_with_middlewares() {
        let route = IngressRouteResource {
            name: "app".to_string(),
            namespace: "default".to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec!["websecure".to_string()],
                routes: vec![IngressRouteEntry {
                    match_rule: "Host(`secure.example.com`)".to_string(),
                    priority: 5,
                    middlewares: vec![
                        IngressRouteMiddlewareRef { name: "auth".to_string() },
                        IngressRouteMiddlewareRef { name: "rate-limit".to_string() },
                    ],
                    services: vec![IngressRouteServiceRef {
                        name: "secure-svc".to_string(),
                        port: 443,
                        weight: 1,
                        strategy: None,
                    }],
                }],
                tls: Some(IngressRouteTls {
                    secret_name: "tls-secret".to_string(),
                }),
            },
        };

        let config = ingress_routes_to_config(&[route]);
        let router = config.routers.values().next().unwrap();
        assert_eq!(router.middlewares, vec!["auth", "rate-limit"]);
        assert_eq!(router.entrypoints, vec!["websecure"]);
        assert_eq!(router.priority, 5);
    }

    #[test]
    fn test_route_with_multiple_backends() {
        let route = IngressRouteResource {
            name: "split".to_string(),
            namespace: "prod".to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec![],
                routes: vec![IngressRouteEntry {
                    match_rule: "Host(`app.com`)".to_string(),
                    priority: 0,
                    middlewares: vec![],
                    services: vec![
                        IngressRouteServiceRef {
                            name: "svc-v1".to_string(),
                            port: 8080,
                            weight: 3,
                            strategy: Some("weighted".to_string()),
                        },
                        IngressRouteServiceRef {
                            name: "svc-v2".to_string(),
                            port: 8080,
                            weight: 1,
                            strategy: None,
                        },
                    ],
                }],
                tls: None,
            },
        };

        let config = ingress_routes_to_config(&[route]);
        assert_eq!(config.services.len(), 1);

        let svc = config.services.get("prod-split-route-0").unwrap();
        assert_eq!(svc.load_balancer.servers.len(), 2);
        assert_eq!(svc.load_balancer.strategy, Strategy::Weighted);
        assert_eq!(svc.load_balancer.servers[0].weight, 3);
        assert_eq!(svc.load_balancer.servers[1].weight, 1);
    }

    #[test]
    fn test_route_with_strategy_override() {
        let route = IngressRouteResource {
            name: "app".to_string(),
            namespace: "default".to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec![],
                routes: vec![IngressRouteEntry {
                    match_rule: "Host(`app.com`)".to_string(),
                    priority: 0,
                    middlewares: vec![],
                    services: vec![IngressRouteServiceRef {
                        name: "svc".to_string(),
                        port: 80,
                        weight: 1,
                        strategy: Some("least-connections".to_string()),
                    }],
                }],
                tls: None,
            },
        };

        let config = ingress_routes_to_config(&[route]);
        let svc = config.services.values().next().unwrap();
        assert_eq!(svc.load_balancer.strategy, Strategy::LeastConnections);
    }

    #[test]
    fn test_empty_routes() {
        let config = ingress_routes_to_config(&[]);
        assert!(config.routers.is_empty());
        assert!(config.services.is_empty());
    }

    #[test]
    fn test_route_default_port() {
        let route = make_route("app", "default", "Host(`app.com`)", "svc", 0);
        let config = ingress_routes_to_config(&[route]);
        let svc = config.services.values().next().unwrap();
        assert!(svc.load_balancer.servers[0].url.ends_with(":80"));
    }

    // --- Serialization ---

    #[test]
    fn test_ingress_route_serialization() {
        let route = make_route("test", "ns", "Host(`test.com`)", "svc", 8080);
        let json = serde_json::to_string(&route).unwrap();
        let parsed: IngressRouteResource = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "test");
        assert_eq!(parsed.spec.routes.len(), 1);
        assert_eq!(parsed.spec.routes[0].match_rule, "Host(`test.com`)");
    }

    #[test]
    fn test_ingress_route_tls() {
        let route = IngressRouteResource {
            name: "tls-app".to_string(),
            namespace: "default".to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec!["websecure".to_string()],
                routes: vec![],
                tls: Some(IngressRouteTls {
                    secret_name: "my-cert".to_string(),
                }),
            },
        };
        assert_eq!(route.spec.tls.unwrap().secret_name, "my-cert");
    }

    // --- Strategy::from_str ---

    #[test]
    fn test_strategy_from_str_all() {
        assert_eq!("round-robin".parse::<Strategy>(), Ok(Strategy::RoundRobin));
        assert_eq!("weighted".parse::<Strategy>(), Ok(Strategy::Weighted));
        assert_eq!("random".parse::<Strategy>(), Ok(Strategy::Random));
        assert!("unknown".parse::<Strategy>().is_err());
    }

    #[test]
    fn test_multiple_routes_in_single_resource() {
        let route = IngressRouteResource {
            name: "multi".to_string(),
            namespace: "default".to_string(),
            spec: IngressRouteSpec {
                entrypoints: vec!["web".to_string()],
                routes: vec![
                    IngressRouteEntry {
                        match_rule: "PathPrefix(`/api`)".to_string(),
                        priority: 10,
                        middlewares: vec![],
                        services: vec![IngressRouteServiceRef {
                            name: "api-svc".to_string(),
                            port: 8080,
                            weight: 1,
                            strategy: None,
                        }],
                    },
                    IngressRouteEntry {
                        match_rule: "PathPrefix(`/web`)".to_string(),
                        priority: 5,
                        middlewares: vec![],
                        services: vec![IngressRouteServiceRef {
                            name: "web-svc".to_string(),
                            port: 3000,
                            weight: 1,
                            strategy: None,
                        }],
                    },
                ],
                tls: None,
            },
        };

        let config = ingress_routes_to_config(&[route]);
        assert_eq!(config.routers.len(), 2);
        assert_eq!(config.services.len(), 2);

        // First route has single service → named by service
        assert!(config.routers.contains_key("default-multi-api-svc"));
        assert!(config.routers.contains_key("default-multi-web-svc"));
    }
}
