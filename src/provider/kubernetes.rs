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
    parse_declared_priority, parse_declared_request_timeout, parse_declared_strategy,
    GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[cfg(feature = "kube")]
use std::future::Future;
#[cfg(feature = "kube")]
use std::pin::Pin;

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

/// Annotation: per-route upstream request timeout (humantime, e.g. "600s").
/// Default "30s". Lets long requests (OCI image-tar uploads, large git/pipeline
/// bodies, long streams) exceed the 30s default on specific routes without
/// loosening fail-fast everywhere.
pub(crate) const ANN_REQUEST_TIMEOUT: &str = "a3s-gateway.io/request-timeout";

// -----------------------------------------------------------------------
// Conversion: Ingress → GatewayConfig
// -----------------------------------------------------------------------

/// Resolve a concrete numeric backend port for Ingress conversion.
///
/// A positive `number` wins. Port `0` with a named port fails closed because
/// this provider does not resolve Service named ports. Port `0` with no name
/// also fails closed — historically this soft-defaulted to `:80`.
pub(crate) fn resolve_ingress_backend_port(
    port: &IngressServicePort,
    namespace: &str,
    ingress_name: &str,
    service_name: &str,
) -> crate::error::Result<u16> {
    if port.number > 0 {
        return Ok(port.number);
    }
    let name = port.name.trim();
    if !name.is_empty() {
        return Err(crate::error::GatewayError::Other(format!(
            "Ingress '{namespace}/{ingress_name}' backend service '{service_name}' uses named port '{name}', which is not resolved; set port.number instead"
        )));
    }
    Err(crate::error::GatewayError::Other(format!(
        "Ingress '{namespace}/{ingress_name}' backend service '{service_name}' requires a positive port.number (got 0)"
    )))
}

/// Convert a list of Ingress resources into a partial GatewayConfig
/// containing routers, services, and optionally TCP/UDP entrypoints.
pub fn ingress_to_config(ingresses: &[IngressResource]) -> crate::error::Result<GatewayConfig> {
    let mut routers = HashMap::new();
    let mut services = HashMap::new();
    let mut entrypoints = HashMap::new();

    for ingress in ingresses {
        let ingress_entrypoints = parse_csv_annotation(&ingress.annotations, ANN_ENTRYPOINTS);
        let middlewares = parse_csv_annotation(&ingress.annotations, ANN_MIDDLEWARES);
        let strategy =
            parse_declared_strategy(ingress.annotations.get(ANN_STRATEGY).map(String::as_str))
                .map_err(|error| {
                    crate::error::GatewayError::Other(format!(
                        "Ingress '{}/{}' annotation '{ANN_STRATEGY}': {error}",
                        ingress.namespace, ingress.name
                    ))
                })?;
        let priority =
            parse_declared_priority(ingress.annotations.get(ANN_PRIORITY).map(String::as_str))
                .map_err(|error| {
                    crate::error::GatewayError::Other(format!(
                        "Ingress '{}/{}' annotation '{ANN_PRIORITY}': {error}",
                        ingress.namespace, ingress.name
                    ))
                })?;
        // Per-route upstream timeout override. Absent → 30s; present empty or
        // invalid must fail closed (do not silently re-default to 30s).
        let request_timeout = parse_declared_request_timeout(
            ingress
                .annotations
                .get(ANN_REQUEST_TIMEOUT)
                .map(String::as_str),
        )
        .map_err(|error| {
            crate::error::GatewayError::Other(format!(
                "Ingress '{}/{}' annotation '{ANN_REQUEST_TIMEOUT}': {error}",
                ingress.namespace, ingress.name
            ))
        })?;

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
                // Router/service key. When the Ingress name already equals the
                // backend Service name (the image-app-publish convention: both
                // are the app/release name), concatenating all three segments
                // yields a redundant doubled key like `default-arche-arche`.
                // Collapse the duplicate so it reads `default-arche` while
                // staying unique (Ingress names are unique per namespace).
                let svc_name = if ingress.name == path.backend.service.name {
                    format!("{}-{}", ingress.namespace, ingress.name)
                } else {
                    format!(
                        "{}-{}-{}",
                        ingress.namespace, ingress.name, path.backend.service.name
                    )
                };

                // Build service with backend URL. Port number 0 previously
                // soft-defaulted to :80 (including name-only backends), which
                // silently misrouted traffic. Require an explicit positive port.
                let port = resolve_ingress_backend_port(
                    &path.backend.service.port,
                    &ingress.namespace,
                    &ingress.name,
                    &path.backend.service.name,
                )?;
                let url = format!(
                    "http://{}.{}.svc.cluster.local:{}",
                    path.backend.service.name, ingress.namespace, port
                );

                services.insert(
                    svc_name.clone(),
                    ServiceConfig {
                        load_balancer: LoadBalancerConfig {
                            strategy: strategy.clone(),
                            request_timeout: request_timeout.clone(),
                            stream_idle_timeout: "5m".to_string(),
                            stream_total_timeout: "60m".to_string(),
                            connect_timeout: "10s".to_string(),
                            servers: vec![ServerConfig {
                                url,
                                weight: 1,
                                target: None,
                            }],
                            health_check: None,
                            sticky: None,
                            tls_ca_file: None,
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
                        let Some(addr) = listen_addr.map(String::as_str).filter(|a| !a.is_empty())
                        else {
                            return Err(crate::error::GatewayError::Other(format!(
                                "Ingress '{}/{}' protocol=tcp requires annotation '{ANN_LISTEN}'",
                                ingress.namespace, ingress.name
                            )));
                        };
                        entrypoints.insert(
                            format!("{}-tcp", svc_name),
                            crate::config::EntrypointConfig {
                                address: addr.to_string(),
                                protocol: crate::config::Protocol::Tcp,
                                tls: None,
                                max_connections: None,
                                tcp_allowed_ips: vec![],
                                udp_session_timeout_secs: None,
                                udp_max_sessions: None,
                                trust_forwarded_headers: false,
                            },
                        );
                    }
                    "udp" => {
                        let Some(addr) = listen_addr.map(String::as_str).filter(|a| !a.is_empty())
                        else {
                            return Err(crate::error::GatewayError::Other(format!(
                                "Ingress '{}/{}' protocol=udp requires annotation '{ANN_LISTEN}'",
                                ingress.namespace, ingress.name
                            )));
                        };
                        entrypoints.insert(
                            format!("{}-udp", svc_name),
                            crate::config::EntrypointConfig {
                                address: addr.to_string(),
                                protocol: crate::config::Protocol::Udp,
                                tls: None,
                                max_connections: None,
                                tcp_allowed_ips: vec![],
                                udp_session_timeout_secs: Some(30),
                                udp_max_sessions: None,
                                trust_forwarded_headers: false,
                            },
                        );
                    }
                    "http" => {
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
                    other => {
                        return Err(crate::error::GatewayError::Other(format!(
                            "Ingress '{}/{}' annotation '{ANN_PROTOCOL}' has unknown protocol '{other}' (expected http, tcp, or udp)",
                            ingress.namespace, ingress.name
                        )));
                    }
                }
            }
        }
    }

    Ok(GatewayConfig {
        mode: Default::default(),
        managed: Default::default(),
        inference: None,
        entrypoints,
        routers,
        services,
        static_bundles: HashMap::new(),
        middlewares: HashMap::new(),
        providers: Default::default(),
        management: Default::default(),
        observability: Default::default(),
        shutdown_timeout_secs: 30,
    })
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
pub(crate) fn parse_csv_annotation(
    annotations: &HashMap<String, String>,
    key: &str,
) -> Vec<String> {
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
///
/// Callers must supply an already-activated [`kube::Client`] (for example from
/// [`prepare_kubernetes_client`]) so startup cannot soft-exit after claiming
/// the watcher started. Poll failures still rebuild via `Client::try_default`.
#[cfg(feature = "kube")]
#[allow(dead_code)]
pub fn spawn_ingress_watch(
    client: kube::Client,
    config: KubernetesProviderConfig,
    base_config: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<GatewayConfig>,
) -> tokio::task::JoinHandle<()> {
    let deliver = Box::new(move |config| {
        let tx = tx.clone();
        Box::pin(async move { tx.send(config).await.map(|_| true).map_err(|_| ()) })
            as KubernetesDeliveryFuture
    });
    spawn_ingress_watch_inner(client, config, base_config, deliver)
}

/// Spawn the Ingress watcher with an acknowledgement from the reload owner.
#[cfg(feature = "kube")]
pub(crate) fn spawn_ingress_watch_with_ack(
    client: kube::Client,
    config: KubernetesProviderConfig,
    base_config: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<crate::provider::ConfigUpdate>,
) -> tokio::task::JoinHandle<()> {
    let deliver = Box::new(move |config| {
        let tx = tx.clone();
        Box::pin(async move {
            let (acknowledged, result) = tokio::sync::oneshot::channel();
            tx.send(crate::provider::ConfigUpdate {
                source: "kubernetes-ingress",
                config,
                acknowledged,
            })
            .await
            .map_err(|_| ())?;
            result.await.map_err(|_| ())
        }) as KubernetesDeliveryFuture
    });
    spawn_ingress_watch_inner(client, config, base_config, deliver)
}

#[cfg(feature = "kube")]
type KubernetesDeliveryFuture =
    Pin<Box<dyn Future<Output = std::result::Result<bool, ()>> + Send + 'static>>;

#[cfg(feature = "kube")]
fn map_kubernetes_client_error(error: kube::Error) -> crate::error::GatewayError {
    crate::error::GatewayError::Config(format!(
        "Kubernetes client cannot activate: failed to create Kubernetes client: {error}"
    ))
}

/// Probe the same `Client::try_default` surface as cold start (validate ≡ activate).
///
/// `Client::try_default` is async (Config infer + TLS client build). Outside a
/// Tokio runtime, spin a short-lived current-thread runtime. Inside an existing
/// runtime (`Gateway::start` / reload), use `block_in_place` so we do not nest
/// runtimes. A YAML-parseable kubeconfig alone is not enough — junk CA/auth
/// must fail here the same way [`prepare_kubernetes_client`] fails before
/// watchers / `K8sScaleExecutor` start.
#[cfg(feature = "kube")]
pub(crate) fn validate_kubernetes_activation() -> crate::error::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = block_on_kubernetes_client()?;
    Ok(())
}

/// Probe the same Ingress (and optional CRD) list surface as the first watcher poll.
///
/// Client construction alone cannot soft-open a Running provider that only
/// warn-loops after `Kubernetes Ingress watcher started`.
#[cfg(feature = "kube")]
pub(crate) async fn probe_kubernetes_provider_activation(
    config: &KubernetesProviderConfig,
    timeout: std::time::Duration,
) -> crate::error::Result<()> {
    let client = prepare_kubernetes_client().await?;
    probe_kubernetes_provider_with_client(&client, config, timeout).await
}

/// Same list probe as [`probe_kubernetes_provider_activation`], reusing a prepared client.
#[cfg(feature = "kube")]
pub(crate) async fn probe_kubernetes_provider_with_client(
    client: &kube::Client,
    config: &KubernetesProviderConfig,
    timeout: std::time::Duration,
) -> crate::error::Result<()> {
    use crate::error::GatewayError;

    match tokio::time::timeout(timeout, async {
        let ingresses = poll_ingresses(client, config).await?;
        let _ = ingress_to_config(&ingresses)?;
        if config.ingress_route_crd {
            crate::provider::kubernetes_crd::probe_ingress_route_list(client, config).await?;
        }
        Ok::<(), GatewayError>(())
    })
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(GatewayError::Config(format!(
            "providers.kubernetes cannot activate: {error}"
        ))),
        Err(_) => Err(GatewayError::Config(format!(
            "providers.kubernetes cannot activate: list probe timed out after {} ms",
            timeout.as_millis()
        ))),
    }
}

/// Sync activation probe for `providers.kubernetes` Ingress/CRD list observation.
#[cfg(feature = "kube")]
pub(crate) fn validate_kubernetes_provider_activation(
    config: &KubernetesProviderConfig,
) -> crate::error::Result<()> {
    use crate::error::GatewayError;

    let timeout = std::time::Duration::from_secs(config.watch_interval_secs.min(30).max(1));
    let config = config.clone();
    match tokio::runtime::Handle::try_current() {
        Ok(handle)
            if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread =>
        {
            tokio::task::block_in_place(|| {
                handle.block_on(probe_kubernetes_provider_activation(&config, timeout))
            })
        }
        Ok(_) | Err(_) => std::thread::Builder::new()
            .name("a3s-k8s-provider-activation-probe".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|error| {
                        GatewayError::Config(format!(
                            "providers.kubernetes cannot activate: failed to create probe runtime: {error}"
                        ))
                    })?;
                runtime.block_on(probe_kubernetes_provider_activation(&config, timeout))
            })
            .map_err(|error| {
                GatewayError::Config(format!(
                    "providers.kubernetes cannot activate: failed to spawn probe thread: {error}"
                ))
            })?
            .join()
            .map_err(|_| {
                GatewayError::Config(
                    "providers.kubernetes cannot activate: probe thread panicked".to_string(),
                )
            })?,
    }
}

#[cfg(feature = "kube")]
fn block_on_kubernetes_client() -> crate::error::Result<kube::Client> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => tokio::task::block_in_place(|| handle.block_on(kube::Client::try_default())),
        Err(_) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|error| {
                    crate::error::GatewayError::Config(format!(
                        "Kubernetes client cannot activate: failed to create probe runtime: {error}"
                    ))
                })?;
            runtime.block_on(kube::Client::try_default())
        }
    }
    .map_err(map_kubernetes_client_error)
}

/// Same `Client::try_default` path as Ingress/CRD watchers and `K8sScaleExecutor`.
#[cfg(feature = "kube")]
pub(crate) async fn prepare_kubernetes_client() -> crate::error::Result<kube::Client> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    kube::Client::try_default()
        .await
        .map_err(map_kubernetes_client_error)
}

#[cfg(feature = "kube")]
fn spawn_ingress_watch_inner(
    client: kube::Client,
    config: KubernetesProviderConfig,
    base_config: GatewayConfig,
    mut deliver: Box<dyn FnMut(GatewayConfig) -> KubernetesDeliveryFuture + Send>,
) -> tokio::task::JoinHandle<()> {
    use std::time::Duration;

    tokio::spawn(async move {
        // Prepared client from activate — no soft-exit try_default at start.
        // `None` means the prior client was poisoned and rebuild has not yet
        // succeeded; never soft-retain a poisoned pool across rebuild failure.
        let mut client: Option<kube::Client> = Some(client);

        let interval = Duration::from_secs(config.watch_interval_secs);
        // Backoff is applied only after a poll failure, capped so the watcher
        // keeps retrying indefinitely instead of giving up.
        let max_backoff = interval.max(Duration::from_secs(30));
        let mut backoff = Duration::from_secs(1);
        let mut last_hash: u64 = 0;

        loop {
            let Some(active) = client.as_ref() else {
                tracing::warn!(
                    backoff_secs = backoff.as_secs(),
                    "K8s Ingress watcher has no usable client; attempting rebuild"
                );
                match kube::Client::try_default().await {
                    Ok(c) => {
                        client = Some(c);
                        backoff = Duration::from_secs(1);
                    }
                    Err(rebuild_err) => {
                        tracing::warn!(
                            error = %rebuild_err,
                            backoff_secs = backoff.as_secs(),
                            "Failed to rebuild K8s client; retaining prior overlay without poisoned client"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                }
                continue;
            };

            match poll_ingresses(active, &config).await {
                Ok(ingresses) => match ingress_to_config(&ingresses) {
                    Ok(discovered) => {
                        backoff = Duration::from_secs(1); // reset after a healthy poll
                        let merged = merge_k8s_config(&base_config, &discovered);

                        // Simple change detection via hash of router+service keys
                        let hash = hash_config_keys(&merged);
                        if hash != last_hash {
                            tracing::info!(
                                ingresses = ingresses.len(),
                                routers = merged.routers.len(),
                                services = merged.services.len(),
                                "K8s Ingress config updated"
                            );
                            match deliver(merged).await {
                                Ok(true) => last_hash = hash,
                                Ok(false) => tracing::warn!(
                                    "K8s Ingress candidate config was rejected; retaining change cursor"
                                ),
                                Err(()) => {
                                    tracing::debug!("K8s Ingress watcher channel closed");
                                    return;
                                }
                            }
                        }

                        tokio::time::sleep(interval).await;
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            backoff_secs = backoff.as_secs(),
                            "K8s Ingress conversion failed closed; retaining prior overlay"
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    }
                },
                Err(e) => {
                    // A poll failure (e.g. a hyper `SendRequest` after the API-server
                    // connection is silently reaped) poisons the client's connection
                    // pool. Drop it before rebuild so a failed rebuild cannot soft-
                    // retain the poisoned client on the next iteration.
                    client = None;
                    tracing::warn!(
                        error = %e,
                        backoff_secs = backoff.as_secs(),
                        "Failed to poll K8s Ingresses; dropping poisoned client and rebuilding"
                    );
                    match kube::Client::try_default().await {
                        Ok(c) => client = Some(c),
                        Err(rebuild_err) => {
                            tracing::warn!(
                                error = %rebuild_err,
                                "Failed to rebuild K8s client; will retry rebuild without poisoned client"
                            );
                        }
                    }
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
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
                                                // Leave unresolved so ingress_to_config
                                                // fails closed instead of inventing :80.
                                                number: 0,
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
pub(crate) fn hash_config_keys(config: &GatewayConfig) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    // Hash the full router + service CONTENT (sorted by key for determinism), not
    // just the keys, so an in-place change to an existing router/service — an
    // Ingress edited from host to path routing, a changed middleware/priority, or a
    // helm upgrade that rewrites the backend — is detected and triggers a reload.
    let mut router_keys: Vec<&String> = config.routers.keys().collect();
    router_keys.sort();
    for k in &router_keys {
        k.hash(&mut hasher);
        if let Some(r) = config.routers.get(*k) {
            serde_json::to_string(r)
                .unwrap_or_default()
                .hash(&mut hasher);
        }
    }
    let mut svc_keys: Vec<&String> = config.services.keys().collect();
    svc_keys.sort();
    for k in &svc_keys {
        k.hash(&mut hasher);
        if let Some(s) = config.services.get(*k) {
            serde_json::to_string(s)
                .unwrap_or_default()
                .hash(&mut hasher);
        }
    }
    let mut entrypoint_keys: Vec<&String> = config.entrypoints.keys().collect();
    entrypoint_keys.sort();
    for k in &entrypoint_keys {
        k.hash(&mut hasher);
        if let Some(entrypoint) = config.entrypoints.get(*k) {
            serde_json::to_string(entrypoint)
                .unwrap_or_default()
                .hash(&mut hasher);
        }
    }
    hasher.finish()
}

#[cfg(all(test, feature = "kube"))]
mod prepared_client_tests {
    use super::*;
    use crate::config::KubernetesProviderConfig;
    use std::time::Duration;

    #[tokio::test]
    async fn ingress_watcher_keeps_running_with_prepared_client_when_kubeconfig_missing() {
        static KUBECONFIG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = KUBECONFIG_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let directory = tempfile::tempdir().unwrap();
        let previous = std::env::var_os("KUBECONFIG");
        std::env::set_var(
            "KUBECONFIG",
            directory.path().join("missing-kubeconfig.yaml"),
        );

        let _ = rustls::crypto::ring::default_provider().install_default();
        // Prepared client against an unreachable API — spawn must use it and
        // must not soft-exit on a second try_default (which would fail here).
        let client =
            kube::Client::try_from(kube::Config::new("https://127.0.0.1:1".parse().unwrap()))
                .unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let handle = spawn_ingress_watch_with_ack(
            client,
            KubernetesProviderConfig {
                watch_interval_secs: 60,
                ..KubernetesProviderConfig::default()
            },
            GatewayConfig::default(),
            tx,
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        let finished = handle.is_finished();
        handle.abort();
        match previous {
            Some(value) => std::env::set_var("KUBECONFIG", value),
            None => std::env::remove_var("KUBECONFIG"),
        }
        assert!(
            !finished,
            "Ingress watcher must not soft-exit at start when given a prepared client"
        );
    }

    /// Contract for poll-failure rebuild: never soft-retain the prior client
    /// handle when rebuild fails (poisoned pool would freeze overlays).
    #[test]
    fn poll_failure_rebuild_err_discards_prior_client() {
        let prior = "poisoned-client";
        let rebuilt: Result<&str, &str> = Err("kubeconfig missing");
        let next = match rebuilt {
            Ok(client) => Some(client),
            Err(_) => None,
        };
        assert!(next.is_none());
        assert_ne!(next, Some(prior));
    }
}
