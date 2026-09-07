//! Docker provider — auto-discover services from running container labels
//!
//! Polls the Docker daemon (via Unix socket or TCP) for running containers
//! that have A3S routing labels, then translates their metadata into gateway
//! routing configuration.
//!
//! ## Label Format
//!
//! ```text
//! a3s.enable=true
//! a3s.router.rule=PathPrefix(`/api`)
//! a3s.router.entrypoints=web
//! a3s.router.middlewares=rate-limit
//! a3s.router.priority=10
//! a3s.service.port=8080
//! a3s.service.strategy=round-robin
//! a3s.service.weight=1
//! ```
//!
//! The label prefix defaults to `a3s` but is configurable via `DockerProviderConfig::label_prefix`.

use crate::config::{
    DockerProviderConfig, GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig,
    ServiceConfig, Strategy,
};
use crate::error::{GatewayError, Result};
use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

const MAX_DOCKER_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

// ── Docker API response types (minimal subset) ────────────────────────────────

/// A running container returned by `GET /containers/json`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerInfo {
    /// Full container ID
    pub id: String,
    /// Container names (each prefixed with `/`)
    pub names: Vec<String>,
    /// Container labels
    #[serde(default)]
    pub labels: HashMap<String, String>,
    /// Network settings including IP addresses
    pub network_settings: DockerNetworkSettings,
}

/// Network settings block in a container listing
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct DockerNetworkSettings {
    /// Per-network data (network name → info)
    #[serde(default)]
    pub networks: HashMap<String, DockerNetwork>,
}

/// Per-network entry inside `NetworkSettings.Networks`
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct DockerNetwork {
    /// IPv4 address assigned to the container on this network
    #[serde(rename = "IPAddress", default)]
    pub ip_address: String,
    /// IPv6 global address (fallback when `ip_address` is empty)
    #[serde(default)]
    pub global_i_pv6_address: String,
}

// ── DockerProvider ────────────────────────────────────────────────────────────

/// Docker provider — polls Docker API and converts container labels to gateway config
pub struct DockerProvider {
    config: DockerProviderConfig,
}

impl DockerProvider {
    /// Create a new Docker provider
    pub fn new(config: DockerProviderConfig) -> Self {
        Self { config }
    }

    /// Fetch the list of running containers from the Docker daemon
    pub async fn fetch_containers(&self) -> Result<Vec<ContainerInfo>> {
        let body = self.docker_get("/containers/json").await?;
        serde_json::from_slice::<Vec<ContainerInfo>>(&body)
            .map_err(|e| GatewayError::Other(format!("Docker API parse error: {}", e)))
    }

    /// Merge discovered containers into `base`, producing a new `GatewayConfig`.
    ///
    /// Containers without `<prefix>.enable=true` are ignored.
    /// Discovered services are added to (not replacing) the base services.
    /// A discovered router is generated when `<prefix>.router.rule` is present.
    pub fn generate_config(
        &self,
        containers: &[ContainerInfo],
        base: &GatewayConfig,
    ) -> GatewayConfig {
        let mut config = base.clone();
        let prefix = &self.config.label_prefix;

        // Docker does not promise a stable order for `/containers/json`.
        // Sort by immutable container identity before deriving a config so a
        // multi-network host cannot cause spurious reloads or winner changes
        // when two containers sanitize to the same service name.
        let mut ordered = containers.iter().collect::<Vec<_>>();
        ordered.sort_by(|left, right| {
            left.id
                .cmp(&right.id)
                .then_with(|| left.names.cmp(&right.names))
        });

        for container in ordered {
            // Skip containers that have not opted-in
            let enable_key = format!("{}.enable", prefix);
            if container.labels.get(&enable_key).map(|v| v.as_str()) != Some("true") {
                continue;
            }

            // Derive a stable service name from the first container name
            let svc_name = container
                .names
                .first()
                .map(|n| sanitize_name(n))
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| sanitize_name(&container.id[..12.min(container.id.len())]));
            if svc_name.is_empty() {
                tracing::warn!(container = %container.id, "Container has no usable service name — skipping");
                continue;
            }

            // Resolve the container's IP address
            let ip = resolve_ip(&container.network_settings);
            let ip = match ip.and_then(|ip| ip.parse::<std::net::IpAddr>().ok()) {
                Some(ip) => ip,
                None => {
                    tracing::warn!(container = svc_name, "No valid IP address found — skipping");
                    continue;
                }
            };

            // Require an explicit port label
            let port_key = format!("{}.service.port", prefix);
            let port = match container
                .labels
                .get(&port_key)
                .and_then(|p| p.parse::<u16>().ok())
            {
                Some(p @ 1..=u16::MAX) => p,
                Some(0) => {
                    tracing::warn!(
                        container = svc_name,
                        label = port_key,
                        "Port label must be between 1 and 65535 — skipping"
                    );
                    continue;
                }
                None => {
                    tracing::warn!(
                        container = svc_name,
                        label = port_key,
                        "Port label missing or invalid — skipping"
                    );
                    continue;
                }
            };

            // Parse optional service settings
            let strategy_key = format!("{}.service.strategy", prefix);
            let strategy = container
                .labels
                .get(&strategy_key)
                .and_then(|s| s.parse::<Strategy>().ok())
                .unwrap_or_default();

            let weight_key = format!("{}.service.weight", prefix);
            let weight = match container.labels.get(&weight_key) {
                None => 1,
                Some(raw) => match raw.parse::<u32>() {
                    Ok(weight) if weight > 0 => weight,
                    _ => {
                        tracing::warn!(
                            container = svc_name,
                            label = weight_key,
                            "Weight label must be a positive integer — skipping"
                        );
                        continue;
                    }
                },
            };

            // Operator-authored definitions are authoritative. A discovered
            // container may add a new service, but it must not replace an
            // existing service or router with the same key.
            if config.services.contains_key(&svc_name) {
                tracing::debug!(
                    service = svc_name,
                    "Static or earlier service wins over Docker discovery"
                );
                continue;
            }

            let host = match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            };

            // Build ServiceConfig
            let svc = ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: format!("http://{}:{}", host, port),
                        weight,
                        target: None,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            };
            config.services.insert(svc_name.clone(), svc);

            // Detect protocol override (default: http)
            let proto_key = format!("{}.protocol", prefix);
            let protocol_str = container
                .labels
                .get(&proto_key)
                .map(|s| s.as_str())
                .unwrap_or("http");

            match protocol_str {
                "tcp" => {
                    // Generate a TCP entrypoint and skip HTTP router generation.
                    let listen_key = format!("{}.entrypoint.address", prefix);
                    if let Some(listen_addr) = container.labels.get(&listen_key) {
                        config.entrypoints.insert(
                            format!("{}-tcp", svc_name),
                            crate::config::EntrypointConfig {
                                address: listen_addr.clone(),
                                protocol: crate::config::Protocol::Tcp,
                                tls: None,
                                max_connections: None,
                                tcp_allowed_ips: vec![],
                                udp_session_timeout_secs: None,
                                udp_max_sessions: None,
                                trust_forwarded_headers: false,
                            },
                        );
                        tracing::info!(
                            container = svc_name,
                            address = listen_addr,
                            "Docker: TCP entrypoint discovered"
                        );
                    }
                }
                "udp" => {
                    // Generate a UDP entrypoint.
                    let listen_key = format!("{}.entrypoint.address", prefix);
                    if let Some(listen_addr) = container.labels.get(&listen_key) {
                        config.entrypoints.insert(
                            format!("{}-udp", svc_name),
                            crate::config::EntrypointConfig {
                                address: listen_addr.clone(),
                                protocol: crate::config::Protocol::Udp,
                                tls: None,
                                max_connections: None,
                                tcp_allowed_ips: vec![],
                                udp_session_timeout_secs: Some(30),
                                udp_max_sessions: None,
                                trust_forwarded_headers: false,
                            },
                        );
                        tracing::info!(
                            container = svc_name,
                            address = listen_addr,
                            "Docker: UDP entrypoint discovered"
                        );
                    }
                }
                _ => {
                    // HTTP protocol — generate a standard router.
                    self.generate_http_router(&container.labels, prefix, &svc_name, &mut config);
                }
            }
        }

        config
    }

    /// Generate an HTTP router from container labels (extracted for clarity).
    fn generate_http_router(
        &self,
        labels: &HashMap<String, String>,
        prefix: &str,
        svc_name: &str,
        config: &mut GatewayConfig,
    ) {
        let rule_key = format!("{}.router.rule", prefix);
        if let Some(rule) = labels.get(&rule_key) {
            let ep_key = format!("{}.router.entrypoints", prefix);
            let entrypoints = labels
                .get(&ep_key)
                .map(|e| {
                    e.split(',')
                        .map(|s| s.trim().to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let mw_key = format!("{}.router.middlewares", prefix);
            let middlewares = labels
                .get(&mw_key)
                .map(|m| {
                    m.split(',')
                        .map(|s| s.trim().to_string())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let prio_key = format!("{}.router.priority", prefix);
            let priority = labels
                .get(&prio_key)
                .and_then(|p| p.parse::<i32>().ok())
                .unwrap_or(0);

            config
                .routers
                .entry(svc_name.to_string())
                .or_insert_with(|| RouterConfig {
                    rule: rule.clone(),
                    service: svc_name.to_string(),
                    entrypoints,
                    middlewares,
                    priority,
                });
        }
    }

    // ── Internal HTTP transport ───────────────────────────────────────────────

    /// Dispatch a GET request to the Docker API, choosing transport based on host scheme.
    async fn docker_get(&self, path: &str) -> Result<Bytes> {
        let host = &self.config.host;
        if host.starts_with("tcp://") || host.starts_with("http://") {
            self.docker_get_tcp(path).await
        } else {
            self.docker_get_unix(path).await
        }
    }

    /// TCP mode — use reqwest against a remote Docker host (`tcp://host:port`)
    async fn docker_get_tcp(&self, path: &str) -> Result<Bytes> {
        let base = self.config.host.replacen("tcp://", "http://", 1);
        let url = format!("{}/v1.41{}", base, path);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| GatewayError::Other(format!("Docker TCP client initialization: {e}")))?;
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| GatewayError::Other(format!("Docker TCP GET '{}': {}", url, e)))?;
        if !response.status().is_success() {
            return Err(GatewayError::Other(format!(
                "Docker TCP GET '{}' returned status {}",
                url,
                response.status()
            )));
        }
        collect_reqwest_body(response, &url).await
    }

    /// Unix socket mode — use hyper 1.x over a `tokio::net::UnixStream`
    #[cfg(unix)]
    async fn docker_get_unix(&self, path: &str) -> Result<Bytes> {
        use hyper::client::conn::http1;
        use hyper_util::rt::TokioIo;
        use tokio::net::UnixStream;

        let socket = self.config.host.clone();
        let stream = UnixStream::connect(&socket).await.map_err(|e| {
            GatewayError::Other(format!("Docker: cannot connect to '{}': {}", socket, e))
        })?;

        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::Builder::new()
            .handshake::<_, http_body_util::Empty<Bytes>>(io)
            .await
            .map_err(|e| GatewayError::Other(format!("Docker handshake: {}", e)))?;

        // Drive the connection in the background; errors are non-fatal here.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let uri = format!("/v1.41{}", path);
        let req = hyper::Request::get(&uri)
            .header("Host", "localhost")
            .body(http_body_util::Empty::<Bytes>::new())
            .map_err(|e| GatewayError::Other(format!("Docker request build: {}", e)))?;

        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| GatewayError::Other(format!("Docker send: {}", e)))?;
        let status = resp.status();
        let body = collect_hyper_body(resp.into_body(), &uri).await?;
        if !status.is_success() {
            return Err(GatewayError::Other(format!(
                "Docker Unix API GET '{}' returned status {}",
                uri, status
            )));
        }
        Ok(body)
    }

    /// Unix socket mode is not supported on non-Unix platforms.
    #[cfg(not(unix))]
    async fn docker_get_unix(&self, _path: &str) -> Result<Bytes> {
        Err(GatewayError::Other(
            "Docker Unix socket connections are not supported on this platform. \
             Set providers.docker.host to a TCP URL (e.g. tcp://localhost:2375)."
                .to_string(),
        ))
    }
}

async fn collect_reqwest_body(response: reqwest::Response, url: &str) -> Result<Bytes> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DOCKER_RESPONSE_BYTES as u64)
    {
        return Err(GatewayError::Other(format!(
            "Docker response '{}' exceeds the {} byte limit",
            url, MAX_DOCKER_RESPONSE_BYTES
        )));
    }
    let mut body = BytesMut::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk
            .map_err(|e| GatewayError::Other(format!("Docker response body '{}': {}", url, e)))?;
        if body.len().saturating_add(chunk.len()) > MAX_DOCKER_RESPONSE_BYTES {
            return Err(GatewayError::Other(format!(
                "Docker response '{}' exceeds the {} byte limit",
                url, MAX_DOCKER_RESPONSE_BYTES
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.freeze())
}

async fn collect_hyper_body<B>(mut body: B, path: &str) -> Result<Bytes>
where
    B: hyper::body::Body<Data = Bytes> + Unpin,
    B::Error: std::fmt::Display,
{
    use http_body_util::BodyExt;

    let mut bytes = BytesMut::new();
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(|e| GatewayError::Other(format!("Docker response body '{}': {}", path, e)))?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > MAX_DOCKER_RESPONSE_BYTES {
                return Err(GatewayError::Other(format!(
                    "Docker response '{}' exceeds the {} byte limit",
                    path, MAX_DOCKER_RESPONSE_BYTES
                )));
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes.freeze())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert a container name to a valid, lowercase service name.
///
/// Strips the leading `/` that Docker prepends and replaces characters
/// that are not alphanumeric, `.`, or `-` with `-`.
fn sanitize_name(name: &str) -> String {
    name.trim_start_matches('/')
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .to_lowercase()
}

/// Resolve the first non-empty IP address from a container's network settings.
fn resolve_ip(settings: &DockerNetworkSettings) -> Option<String> {
    let mut networks = settings.networks.iter().collect::<Vec<_>>();
    networks.sort_by(|left, right| left.0.cmp(right.0));
    for (_, net) in networks {
        if !net.ip_address.is_empty() {
            return Some(net.ip_address.clone());
        }
        if !net.global_i_pv6_address.is_empty() {
            return Some(net.global_i_pv6_address.clone());
        }
    }
    None
}

// ── Public spawn function ─────────────────────────────────────────────────────

/// Spawn the Docker provider polling loop.
///
/// The loop polls the Docker API every `config.poll_interval_secs` seconds.
/// When the derived config differs from the previous poll, it sends a new
/// `GatewayConfig` via `tx`. The caller is responsible for applying the
/// received config (e.g. calling `Gateway::reload()`).
///
/// The loop terminates automatically if `tx` is dropped.
#[allow(dead_code)]
pub fn spawn_docker_loop(
    config: DockerProviderConfig,
    base: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<GatewayConfig>,
) -> tokio::task::JoinHandle<()> {
    let deliver = Box::new(move |config| {
        let tx = tx.clone();
        Box::pin(async move { tx.send(config).await.map(|_| true).map_err(|_| ()) })
            as DockerDeliveryFuture
    });
    spawn_docker_loop_inner(config, base, deliver)
}

/// Spawn the Docker provider with reload acknowledgements.
pub(crate) fn spawn_docker_loop_with_ack(
    config: DockerProviderConfig,
    base: GatewayConfig,
    tx: tokio::sync::mpsc::Sender<crate::provider::ConfigUpdate>,
) -> tokio::task::JoinHandle<()> {
    let deliver = Box::new(move |config| {
        let tx = tx.clone();
        Box::pin(async move {
            let (acknowledged, result) = tokio::sync::oneshot::channel();
            tx.send(crate::provider::ConfigUpdate {
                source: "docker",
                config,
                acknowledged,
            })
            .await
            .map_err(|_| ())?;
            result.await.map_err(|_| ())
        }) as DockerDeliveryFuture
    });
    spawn_docker_loop_inner(config, base, deliver)
}

type DockerDeliveryFuture =
    Pin<Box<dyn Future<Output = std::result::Result<bool, ()>> + Send + 'static>>;

fn spawn_docker_loop_inner(
    config: DockerProviderConfig,
    base: GatewayConfig,
    mut deliver: Box<dyn FnMut(GatewayConfig) -> DockerDeliveryFuture + Send>,
) -> tokio::task::JoinHandle<()> {
    let interval = Duration::from_secs(config.poll_interval_secs.max(1));
    let provider = DockerProvider::new(config);

    tokio::spawn(async move {
        let mut last_json: Option<String> = None;
        let mut ticker = tokio::time::interval(interval);

        loop {
            ticker.tick().await;

            match provider.fetch_containers().await {
                Ok(containers) => {
                    let new_config = provider.generate_config(&containers, &base);

                    // Use serialised JSON as a cheap change detector.
                    let new_json = serde_json::to_string(&new_config).unwrap_or_default();
                    let changed = last_json.as_deref() != Some(new_json.as_str());

                    if changed {
                        tracing::debug!(
                            services = new_config.services.len(),
                            routers = new_config.routers.len(),
                            "Docker provider: config updated"
                        );
                        match deliver(new_config).await {
                            Ok(true) => last_json = Some(new_json),
                            Ok(false) => tracing::warn!(
                                "Docker provider: candidate config was rejected; retaining change cursor"
                            ),
                            Err(()) => {
                                tracing::debug!("Docker provider: receiver dropped, exiting loop");
                                break;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Docker provider: poll failed");
                }
            }
        }
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DockerProviderConfig, GatewayConfig};

    fn provider() -> DockerProvider {
        DockerProvider::new(DockerProviderConfig::default())
    }

    fn make_container(name: &str, ip: &str, labels: &[(&str, &str)]) -> ContainerInfo {
        let mut label_map = HashMap::new();
        for (k, v) in labels {
            label_map.insert(k.to_string(), v.to_string());
        }

        let mut networks = HashMap::new();
        networks.insert(
            "bridge".to_string(),
            DockerNetwork {
                ip_address: ip.to_string(),
                global_i_pv6_address: String::new(),
            },
        );

        ContainerInfo {
            id: "deadbeef123456789abc".to_string(),
            names: vec![format!("/{}", name)],
            labels: label_map,
            network_settings: DockerNetworkSettings { networks },
        }
    }

    // ── sanitize_name ─────────────────────────────────────────────────────────

    #[test]
    fn test_sanitize_strips_leading_slash() {
        assert_eq!(sanitize_name("/myapp"), "myapp");
    }

    #[test]
    fn test_sanitize_replaces_invalid_chars() {
        assert_eq!(sanitize_name("/my_app_v2"), "my-app-v2");
    }

    #[test]
    fn test_sanitize_lowercase() {
        assert_eq!(sanitize_name("/MyApp"), "myapp");
    }

    #[test]
    fn test_sanitize_preserves_dots_dashes() {
        assert_eq!(sanitize_name("/my-app.prod"), "my-app.prod");
    }

    // ── resolve_ip ────────────────────────────────────────────────────────────

    #[test]
    fn test_resolve_ip_returns_first_nonempty() {
        let mut networks = HashMap::new();
        networks.insert(
            "bridge".to_string(),
            DockerNetwork {
                ip_address: "172.17.0.2".to_string(),
                global_i_pv6_address: String::new(),
            },
        );
        let settings = DockerNetworkSettings { networks };
        assert_eq!(resolve_ip(&settings), Some("172.17.0.2".to_string()));
    }

    #[test]
    fn test_resolve_ip_falls_back_to_ipv6() {
        let mut networks = HashMap::new();
        networks.insert(
            "bridge".to_string(),
            DockerNetwork {
                ip_address: String::new(),
                global_i_pv6_address: "2001:db8::1".to_string(),
            },
        );
        let settings = DockerNetworkSettings { networks };
        assert_eq!(resolve_ip(&settings), Some("2001:db8::1".to_string()));
    }

    #[test]
    fn test_resolve_ip_returns_none_when_empty() {
        let settings = DockerNetworkSettings::default();
        assert!(resolve_ip(&settings).is_none());
    }

    #[test]
    fn test_resolve_ip_uses_deterministic_network_order() {
        let mut networks = HashMap::new();
        networks.insert(
            "z-last".to_string(),
            DockerNetwork {
                ip_address: "172.17.0.9".to_string(),
                global_i_pv6_address: String::new(),
            },
        );
        networks.insert(
            "a-first".to_string(),
            DockerNetwork {
                ip_address: "172.17.0.2".to_string(),
                global_i_pv6_address: String::new(),
            },
        );
        assert_eq!(
            resolve_ip(&DockerNetworkSettings { networks }),
            Some("172.17.0.2".into())
        );
    }

    // ── generate_config: skipping ─────────────────────────────────────────────

    #[test]
    fn test_skips_container_without_enable_label() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container("myapp", "172.17.0.2", &[("a3s.service.port", "8080")]);
        let config = p.generate_config(&[container], &base);
        assert!(config.services.is_empty());
    }

    #[test]
    fn test_skips_container_with_enable_false() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "myapp",
            "172.17.0.2",
            &[("a3s.enable", "false"), ("a3s.service.port", "8080")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.is_empty());
    }

    #[test]
    fn test_skips_container_without_port() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container("myapp", "172.17.0.2", &[("a3s.enable", "true")]);
        let config = p.generate_config(&[container], &base);
        assert!(config.services.is_empty());
    }

    #[test]
    fn test_skips_container_without_ip() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "myapp",
            "", // no IP
            &[("a3s.enable", "true"), ("a3s.service.port", "8080")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.is_empty());
    }

    // ── generate_config: service generation ──────────────────────────────────

    #[test]
    fn test_generates_service_from_enabled_container() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "myapp",
            "172.17.0.2",
            &[("a3s.enable", "true"), ("a3s.service.port", "8080")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.contains_key("myapp"));
        let svc = &config.services["myapp"];
        assert_eq!(svc.load_balancer.servers[0].url, "http://172.17.0.2:8080");
    }

    #[test]
    fn test_generates_service_with_custom_strategy() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "api",
            "172.17.0.5",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "9000"),
                ("a3s.service.strategy", "least-connections"),
                ("a3s.service.weight", "2"),
            ],
        );
        let config = p.generate_config(&[container], &base);
        let svc = &config.services["api"];
        assert_eq!(svc.load_balancer.strategy, Strategy::LeastConnections);
        assert_eq!(svc.load_balancer.servers[0].weight, 2);
    }

    #[test]
    fn test_generates_router_when_rule_label_present() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "api",
            "172.17.0.5",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "9000"),
                ("a3s.router.rule", "PathPrefix(`/api`)"),
                ("a3s.router.entrypoints", "web"),
                ("a3s.router.priority", "10"),
            ],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.routers.contains_key("api"));
        let router = &config.routers["api"];
        assert_eq!(router.rule, "PathPrefix(`/api`)");
        assert_eq!(router.service, "api");
        assert_eq!(router.entrypoints, vec!["web"]);
        assert_eq!(router.priority, 10);
    }

    #[test]
    fn test_no_router_without_rule_label() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "worker",
            "172.17.0.10",
            &[("a3s.enable", "true"), ("a3s.service.port", "5000")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.contains_key("worker"));
        assert!(!config.routers.contains_key("worker"));
    }

    #[test]
    fn test_multiple_containers_merged_into_config() {
        let p = provider();
        let base = GatewayConfig::default();
        let c1 = make_container(
            "api",
            "172.17.0.2",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "8080"),
                ("a3s.router.rule", "PathPrefix(`/api`)"),
            ],
        );
        let c2 = make_container(
            "web",
            "172.17.0.3",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "3000"),
                ("a3s.router.rule", "PathPrefix(`/`)"),
            ],
        );
        let config = p.generate_config(&[c1, c2], &base);
        assert_eq!(config.services.len(), 2);
        assert_eq!(config.routers.len(), 2);
    }

    #[test]
    fn test_discovered_services_merged_with_static() {
        let p = provider();
        let mut base = GatewayConfig::default();
        // Pre-seed a static service
        base.services.insert(
            "static-api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://10.0.0.1:9000".to_string(),
                        weight: 1,
                        target: None,
                    }],
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
        let container = make_container(
            "docker-api",
            "172.17.0.5",
            &[("a3s.enable", "true"), ("a3s.service.port", "8080")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.contains_key("static-api"));
        assert!(config.services.contains_key("docker-api"));
    }

    #[test]
    fn test_static_service_and_router_are_authoritative() {
        let p = provider();
        let mut base = GatewayConfig::default();
        base.services.insert(
            "api".to_string(),
            make_container_service("http://10.0.0.1:9000"),
        );
        base.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "Path(`/static`)".to_string(),
                service: "api".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 99,
            },
        );
        let container = make_container(
            "api",
            "172.17.0.5",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "8080"),
                ("a3s.router.rule", "Path(`/discovered`)"),
            ],
        );
        let config = p.generate_config(&[container], &base);
        assert_eq!(
            config.services["api"].load_balancer.servers[0].url,
            "http://10.0.0.1:9000"
        );
        assert_eq!(config.routers["api"].rule, "Path(`/static`)");
    }

    fn make_container_service(url: &str) -> ServiceConfig {
        ServiceConfig {
            load_balancer: LoadBalancerConfig {
                strategy: Strategy::RoundRobin,
                request_timeout: "30s".to_string(),
                stream_idle_timeout: "5m".to_string(),
                stream_total_timeout: "60m".to_string(),
                servers: vec![ServerConfig {
                    url: url.to_string(),
                    weight: 1,
                    target: None,
                }],
                health_check: None,
                sticky: None,
            },
            scaling: None,
            revisions: vec![],
            rollout: None,
            mirror: None,
            failover: None,
        }
    }

    #[test]
    fn test_ipv6_container_address_is_bracketed() {
        let p = provider();
        let container = make_container(
            "ipv6",
            "2001:db8::2",
            &[("a3s.enable", "true"), ("a3s.service.port", "8080")],
        );
        let config = p.generate_config(&[container], &GatewayConfig::default());
        assert_eq!(
            config.services["ipv6"].load_balancer.servers[0].url,
            "http://[2001:db8::2]:8080"
        );
    }

    #[test]
    fn test_custom_label_prefix() {
        let p = DockerProvider::new(DockerProviderConfig {
            host: "/var/run/docker.sock".to_string(),
            label_prefix: "myco".to_string(),
            poll_interval_secs: 10,
        });
        let base = GatewayConfig::default();
        let container = make_container(
            "app",
            "172.17.0.2",
            &[("myco.enable", "true"), ("myco.service.port", "4000")],
        );
        let config = p.generate_config(&[container], &base);
        assert!(config.services.contains_key("app"));
    }

    // ── generate_config: TCP/UDP protocol ──────────────────────────────────

    #[test]
    fn test_tcp_protocol_generates_entrypoint() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "redis",
            "172.17.0.10",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "6379"),
                ("a3s.protocol", "tcp"),
                ("a3s.entrypoint.address", "0.0.0.0:6379"),
            ],
        );
        let config = p.generate_config(&[container], &base);

        // Service should still be created
        assert!(config.services.contains_key("redis"));

        // TCP entrypoint should be generated
        assert!(config.entrypoints.contains_key("redis-tcp"));
        let ep = &config.entrypoints["redis-tcp"];
        assert_eq!(ep.address, "0.0.0.0:6379");
        assert_eq!(ep.protocol, crate::config::Protocol::Tcp);

        // No HTTP router should be generated
        assert!(!config.routers.contains_key("redis"));
    }

    #[test]
    fn test_udp_protocol_generates_entrypoint() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "dns",
            "172.17.0.11",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "53"),
                ("a3s.protocol", "udp"),
                ("a3s.entrypoint.address", "0.0.0.0:5353"),
            ],
        );
        let config = p.generate_config(&[container], &base);

        assert!(config.services.contains_key("dns"));
        assert!(config.entrypoints.contains_key("dns-udp"));
        let ep = &config.entrypoints["dns-udp"];
        assert_eq!(ep.address, "0.0.0.0:5353");
        assert_eq!(ep.protocol, crate::config::Protocol::Udp);
        assert_eq!(ep.udp_session_timeout_secs, Some(30));
        assert!(!config.routers.contains_key("dns"));
    }

    #[test]
    fn test_tcp_protocol_without_listen_address_no_entrypoint() {
        let p = provider();
        let mut base = GatewayConfig::default();
        base.entrypoints.clear();
        let container = make_container(
            "redis",
            "172.17.0.10",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "6379"),
                ("a3s.protocol", "tcp"),
                // No a3s.entrypoint.address
            ],
        );
        let config = p.generate_config(&[container], &base);

        // Service created, but no entrypoint and no router
        assert!(config.services.contains_key("redis"));
        assert!(config.entrypoints.is_empty());
        assert!(!config.routers.contains_key("redis"));
    }

    #[test]
    fn test_http_protocol_still_generates_router() {
        let p = provider();
        let mut base = GatewayConfig::default();
        base.entrypoints.clear();
        let container = make_container(
            "web",
            "172.17.0.5",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "8080"),
                ("a3s.protocol", "http"),
                ("a3s.router.rule", "Host(`web.local`)"),
            ],
        );
        let config = p.generate_config(&[container], &base);

        assert!(config.services.contains_key("web"));
        assert!(config.routers.contains_key("web"));
        assert!(config.entrypoints.is_empty());
    }

    #[test]
    fn test_mixed_protocols_in_multiple_containers() {
        let p = provider();
        let mut base = GatewayConfig::default();
        base.entrypoints.clear();
        let http_container = make_container(
            "api",
            "172.17.0.2",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "8080"),
                ("a3s.router.rule", "PathPrefix(`/api`)"),
            ],
        );
        let tcp_container = make_container(
            "redis",
            "172.17.0.3",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "6379"),
                ("a3s.protocol", "tcp"),
                ("a3s.entrypoint.address", "0.0.0.0:6379"),
            ],
        );
        let config = p.generate_config(&[http_container, tcp_container], &base);

        assert_eq!(config.services.len(), 2);
        assert_eq!(config.routers.len(), 1); // only HTTP
        assert_eq!(config.entrypoints.len(), 1); // only TCP
        assert!(config.routers.contains_key("api"));
        assert!(config.entrypoints.contains_key("redis-tcp"));
    }

    #[test]
    fn test_router_middlewares_split_on_comma() {
        let p = provider();
        let base = GatewayConfig::default();
        let container = make_container(
            "app",
            "172.17.0.2",
            &[
                ("a3s.enable", "true"),
                ("a3s.service.port", "8080"),
                ("a3s.router.rule", "PathPrefix(`/`)"),
                ("a3s.router.middlewares", "auth, rate-limit, cors"),
            ],
        );
        let config = p.generate_config(&[container], &base);
        let mws = &config.routers["app"].middlewares;
        assert_eq!(mws, &["auth", "rate-limit", "cors"]);
    }
}
