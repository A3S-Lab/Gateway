//! Node API for process-local health, metrics, version, and managed snapshots.
//!
//! The API runs on a dedicated listener and never intercepts user traffic.
//! Human-facing operations belong to A3S Cloud; this module exposes only the
//! bounded machine contract required to operate the Gateway data plane.

mod managed;

use crate::config::{GatewayConfig, ManagementConfig, ManagementTlsConfig};
use crate::error::{GatewayError, Result};
use crate::managed_snapshot::{ManagedSnapshotReloadCallback, ManagedSnapshotStore};
use crate::middleware::ip_matcher::IpMatcher;
use crate::observability::metrics::GatewayMetrics;
use crate::usage::UsageSpool;
use crate::{GatewayState, HealthStatus};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::Serialize;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

const MAX_NODE_API_TOKEN_BYTES: usize = 4 * 1024;

pub(super) type ResponseBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;

fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Shared state for the dedicated node API listener.
#[derive(Clone)]
pub(crate) struct NodeApiState {
    pub config: Arc<RwLock<GatewayConfig>>,
    pub lifecycle_state: Arc<RwLock<GatewayState>>,
    pub start_time: Instant,
    pub metrics: Arc<GatewayMetrics>,
    pub reload_managed_snapshot: Option<ManagedSnapshotReloadCallback>,
    pub managed_snapshots: Arc<ManagedSnapshotStore>,
    pub usage_spool: Arc<RwLock<Option<Arc<UsageSpool>>>>,
}

#[derive(Debug, Clone, Serialize)]
struct VersionInfo {
    name: &'static str,
    version: &'static str,
    api_version: &'static str,
}

impl VersionInfo {
    fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            api_version: "v1",
        }
    }
}

struct NodeApi {
    path_prefix: String,
    auth_token: Option<String>,
    ip_matcher: IpMatcher,
}

/// The complete policy used by one accepted node-API connection.
///
/// The listener socket is deliberately independent from this policy.  A
/// reload can therefore validate and publish authentication, IP, path, and
/// TLS changes without closing a bound port and without leaving a partially
/// committed management plane behind.
struct NodeApiPolicy {
    api: Arc<NodeApi>,
    tls_acceptor: Option<TlsAcceptor>,
    auth_enabled: bool,
    client_cert_required: bool,
    tls_identity: Option<ManagementTlsConfig>,
    transport_generation: u64,
}

/// Mutable control plane for a bound node-API listener.
#[derive(Clone)]
pub(crate) struct NodeApiListenerControl {
    policy: Arc<RwLock<Arc<NodeApiPolicy>>>,
}

/// A node-API policy prepared before the runtime transaction commits.
pub(crate) struct PreparedNodeApiReconfigure {
    policy: NodeApiPolicy,
    transport_changed: bool,
}

impl NodeApiListenerControl {
    fn snapshot(&self) -> Arc<NodeApiPolicy> {
        self.policy
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Build all fallible policy state before publishing any change.
    pub(crate) fn prepare_reconfigure(
        &self,
        config: &ManagementConfig,
    ) -> Result<PreparedNodeApiReconfigure> {
        let policy = build_policy(config)?;
        let current = self.snapshot();
        Ok(PreparedNodeApiReconfigure {
            transport_changed: current.tls_identity != policy.tls_identity,
            policy,
        })
    }

    /// Publish a previously prepared policy in one pointer replacement.
    pub(crate) fn commit(&self, mut prepared: PreparedNodeApiReconfigure) {
        let mut current = self
            .policy
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prepared.policy.transport_generation = if prepared.transport_changed {
            current.transport_generation.saturating_add(1)
        } else {
            current.transport_generation
        };
        *current = Arc::new(prepared.policy);
    }
}

/// Owned task and policy control for one bound node-API listener.
pub(crate) struct NodeApiListenerHandle {
    task: tokio::task::JoinHandle<()>,
    control: NodeApiListenerControl,
}

impl NodeApiListenerHandle {
    pub(crate) fn abort(&self) {
        self.task.abort();
    }

    pub(crate) fn into_task(self) -> tokio::task::JoinHandle<()> {
        self.task
    }

    pub(crate) fn control(&self) -> NodeApiListenerControl {
        self.control.clone()
    }
}

impl NodeApi {
    #[cfg(test)]
    fn new(path_prefix: impl Into<String>, auth_token: Option<String>) -> Self {
        Self::with_allowed_ips(path_prefix, auth_token, &[])
            .expect("empty node API IP allowlist must be valid")
    }

    fn with_allowed_ips(
        path_prefix: impl Into<String>,
        auth_token: Option<String>,
        allowed_ips: &[String],
    ) -> Result<Self> {
        Ok(Self {
            path_prefix: path_prefix.into(),
            auth_token,
            ip_matcher: IpMatcher::new(allowed_ips)?,
        })
    }

    fn matches(&self, path: &str) -> bool {
        path == self.path_prefix
            || path
                .strip_prefix(&self.path_prefix)
                .is_some_and(|rest| rest.starts_with('/'))
    }

    fn matches_subpath(&self, path: &str, subpath: &str) -> bool {
        let rest = if self.path_prefix == "/" {
            path
        } else {
            let Some(rest) = path.strip_prefix(&self.path_prefix) else {
                return false;
            };
            rest
        };
        rest == subpath || rest.strip_suffix('/') == Some(subpath)
    }

    fn authorize(&self, req: &Request<Incoming>) -> bool {
        let Some(expected) = &self.auth_token else {
            return true;
        };

        req.headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split_once(' '))
            .filter(|(scheme, token)| scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty())
            .is_some_and(|(_, token)| constant_time_eq(token.as_bytes(), expected.as_bytes()))
    }

    fn authorize_ip(&self, remote_addr: &SocketAddr) -> bool {
        self.ip_matcher.is_empty() || self.ip_matcher.is_allowed(&remote_addr.ip().to_string())
    }

    fn handle(&self, method: &Method, path: &str, state: &NodeApiState) -> NodeApiResponse {
        let Some(sub_path) = path.strip_prefix(&self.path_prefix) else {
            return NodeApiResponse::not_found();
        };

        match (method, sub_path) {
            (&Method::GET, "" | "/" | "/health" | "/health/") => {
                let metrics = state.metrics.snapshot();
                let (mode, gateway_id) = {
                    let config = state
                        .config
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    (config.mode, config.managed.gateway_id)
                };
                let health = HealthStatus {
                    state: state
                        .lifecycle_state
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone(),
                    mode,
                    gateway_id,
                    uptime_secs: state.start_time.elapsed().as_secs(),
                    active_connections: metrics.active_connections as usize,
                    total_requests: metrics.total_requests,
                    usage_spool: state
                        .usage_spool
                        .read()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .as_ref()
                        .map(|spool| spool.status()),
                };
                json_response(200, &health)
            }
            (&Method::GET, "/metrics" | "/metrics/") => NodeApiResponse {
                status: 200,
                content_type: "text/plain; version=0.0.4".to_string(),
                body: state.metrics.render_prometheus(),
            },
            (&Method::GET, "/version" | "/version/") => json_response(200, &VersionInfo::current()),
            _ => NodeApiResponse::not_found(),
        }
    }
}

/// Start the dedicated node API listener when enabled.
pub(crate) async fn start_node_api_listener(
    config: &ManagementConfig,
    state: NodeApiState,
) -> Result<Option<NodeApiListenerHandle>> {
    Ok(prepare_node_api_listener(config, state)
        .await?
        .map(PreparedNodeApiListener::spawn))
}

/// A node API listener that has already bound its socket.
///
/// Reload uses this to validate and reserve a new address before committing
/// traffic changes. The listener only starts accepting on `spawn`.
pub(crate) struct PreparedNodeApiListener {
    addr: SocketAddr,
    listener: TcpListener,
    control: NodeApiListenerControl,
    state: NodeApiState,
}

impl PreparedNodeApiListener {
    pub(crate) fn spawn(self) -> NodeApiListenerHandle {
        spawn_node_api_listener(self)
    }
}

pub(crate) async fn prepare_node_api_listener(
    config: &ManagementConfig,
    state: NodeApiState,
) -> Result<Option<PreparedNodeApiListener>> {
    let Some((addr, _)) = resolve_listener_options(config)? else {
        return Ok(None);
    };

    // Construct every policy component before binding or publishing the
    // listener. A malformed token, allowlist, or certificate must not create a
    // half-initialized management task.
    let policy = build_policy(config)?;
    let listener = TcpListener::bind(addr).await.map_err(|error| {
        GatewayError::Other(format!("Failed to bind node API listener {addr}: {error}"))
    })?;
    let control = NodeApiListenerControl {
        policy: Arc::new(RwLock::new(Arc::new(policy))),
    };

    Ok(Some(PreparedNodeApiListener {
        addr,
        listener,
        control,
        state,
    }))
}

fn build_policy(config: &ManagementConfig) -> Result<NodeApiPolicy> {
    let Some((_addr, auth_token)) = resolve_listener_options(config)? else {
        return Err(GatewayError::Config(
            "Cannot build a node API policy for a disabled listener".to_string(),
        ));
    };
    let tls_acceptor = config
        .tls
        .as_ref()
        .map(crate::proxy::tls::build_node_api_tls_acceptor)
        .transpose()?;
    let api = Arc::new(NodeApi::with_allowed_ips(
        config.path_prefix.clone(),
        auth_token,
        &config.allowed_ips,
    )?);
    Ok(NodeApiPolicy {
        api,
        tls_acceptor,
        auth_enabled: config.auth_token_env.is_some(),
        client_cert_required: config
            .tls
            .as_ref()
            .is_some_and(|tls| tls.require_client_cert),
        tls_identity: config.tls.clone(),
        transport_generation: 0,
    })
}

fn spawn_node_api_listener(prepared: PreparedNodeApiListener) -> NodeApiListenerHandle {
    let PreparedNodeApiListener {
        addr,
        listener,
        control,
        state,
    } = prepared;
    let state = Arc::new(state);
    let initial_policy = control.snapshot();

    tracing::info!(
        address = %addr,
        path_prefix = %initial_policy.api.path_prefix,
        auth = initial_policy.auth_enabled,
        tls = initial_policy.tls_acceptor.is_some(),
        client_cert_required = initial_policy.client_cert_required,
        "Node API listening"
    );

    let task_control = control.clone();
    let task = tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(%error, "Failed to accept node API connection");
                    continue;
                }
            };

            // Snapshot immediately after accept, rather than before waiting
            // for a connection. This prevents an idle listener from handing a
            // newly accepted connection an obsolete policy. If the policy
            // changes while the handshake is in flight, the request boundary
            // below rejects the connection instead of mixing TLS generations.
            let accepted_policy = task_control.snapshot();
            let tls_acceptor = accepted_policy.tls_acceptor.clone();
            let transport_generation = accepted_policy.transport_generation;
            let connection_control = task_control.clone();
            let state = state.clone();
            let tls_acceptor = tls_acceptor.clone();
            tokio::spawn(async move {
                if let Some(acceptor) = tls_acceptor {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let _ = auto::Builder::new(TokioExecutor::new())
                                .serve_connection(
                                    io,
                                    service_fn(move |request| {
                                        handle_node_api_request(
                                            request,
                                            remote_addr,
                                            connection_control.clone(),
                                            transport_generation,
                                            state.clone(),
                                        )
                                    }),
                                )
                                .await;
                        }
                        Err(error) => {
                            tracing::warn!(
                                %error,
                                %remote_addr,
                                "Node API TLS handshake rejected"
                            );
                        }
                    }
                } else {
                    let io = TokioIo::new(stream);
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            io,
                            service_fn(move |request| {
                                handle_node_api_request(
                                    request,
                                    remote_addr,
                                    connection_control.clone(),
                                    transport_generation,
                                    state.clone(),
                                )
                            }),
                        )
                        .await;
                }
            });
        }
    });
    NodeApiListenerHandle { task, control }
}

pub(crate) fn validate_node_api_listener_config(config: &ManagementConfig) -> Result<()> {
    if resolve_listener_options(config)?.is_some() {
        if let Some(tls) = &config.tls {
            tls.validate()?;
            crate::proxy::tls::build_node_api_tls_acceptor(tls)?;
        }
    }
    Ok(())
}

fn resolve_listener_options(
    config: &ManagementConfig,
) -> Result<Option<(SocketAddr, Option<String>)>> {
    if !config.enabled {
        return Ok(None);
    }

    let addr: SocketAddr = config.address.parse().map_err(|error| {
        GatewayError::Config(format!(
            "Invalid management.address '{}': {error}",
            config.address
        ))
    })?;
    IpMatcher::new(&config.allowed_ips)?;

    let auth_token = match &config.auth_token_env {
        Some(env_name) => Some(std::env::var(env_name).map_err(|_| {
            GatewayError::Config(format!(
                "Node API auth token environment variable '{env_name}' is not set"
            ))
        })?),
        None => None,
    };

    if let Some(token) = auth_token.as_ref() {
        if token.is_empty()
            || token.len() > MAX_NODE_API_TOKEN_BYTES
            || token.bytes().any(|byte| !byte.is_ascii_graphic())
        {
            return Err(GatewayError::Config(format!(
                "Node API auth token in environment variable '{}' must be non-empty, visible ASCII, and at most {} bytes",
                config.auth_token_env.as_deref().unwrap_or("<unknown>"),
                MAX_NODE_API_TOKEN_BYTES
            )));
        }
    }

    Ok(Some((addr, auth_token)))
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        difference |= usize::from(
            left.get(index).copied().unwrap_or_default()
                != right.get(index).copied().unwrap_or_default(),
        );
    }
    difference == 0
}

async fn handle_node_api_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    control: NodeApiListenerControl,
    accepted_transport_generation: u64,
    state: Arc<NodeApiState>,
) -> std::result::Result<Response<ResponseBody>, hyper::Error> {
    let policy = control.snapshot();
    if policy.transport_generation != accepted_transport_generation {
        tracing::warn!(
            %remote_addr,
            status = 421,
            "Node API connection uses a superseded TLS policy"
        );
        return Ok(transport_policy_changed_response());
    }
    let api = &policy.api;
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    if !api.matches(&path) {
        tracing::warn!(%remote_addr, %path, status = 404, "Node API path rejected");
        return Ok(response(
            404,
            "application/json",
            r#"{"error":"Not found"}"#,
        ));
    }

    if !api.authorize_ip(&remote_addr) {
        tracing::warn!(
            %remote_addr,
            %path,
            status = 403,
            "Node API client IP rejected"
        );
        return Ok(response(
            403,
            "application/json",
            r#"{"error":"Forbidden"}"#,
        ));
    }

    if !api.authorize(&req) {
        tracing::warn!(
            %remote_addr,
            %path,
            status = 401,
            "Node API bearer token rejected"
        );
        return Ok(response(
            401,
            "application/json",
            r#"{"error":"Unauthorized"}"#,
        ));
    }

    if req.method() == Method::POST && api.matches_subpath(&path, "/snapshots/apply") {
        return Ok(managed::handle_apply(req, remote_addr, &state).await);
    }
    if req.method() == Method::GET && api.matches_subpath(&path, "/snapshots/status") {
        return Ok(managed::handle_status(
            query.as_deref(),
            remote_addr,
            &state,
        ));
    }

    let node_response = api.handle(req.method(), &path, &state);
    if node_response.status == 404 {
        tracing::warn!(
            %remote_addr,
            method = %req.method(),
            %path,
            status = 404,
            "Unsupported node API endpoint rejected"
        );
    }
    Ok(response(
        node_response.status,
        &node_response.content_type,
        node_response.body,
    ))
}

fn transport_policy_changed_response() -> Response<ResponseBody> {
    let mut response = response(
        421,
        "application/json",
        r#"{"error":"Node API transport policy changed; reconnect required"}"#,
    );
    response.headers_mut().insert(
        hyper::header::CONNECTION,
        hyper::header::HeaderValue::from_static("close"),
    );
    response
}

fn response(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<ResponseBody> {
    let mut response = Response::new(full_body(body));
    *response.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::INTERNAL_SERVER_ERROR);
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_str(content_type)
            .unwrap_or_else(|_| http::HeaderValue::from_static("application/json")),
    );
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}

pub(super) fn json_http_response<T: Serialize>(status: u16, value: &T) -> Response<ResponseBody> {
    let body = serde_json::to_string_pretty(value).unwrap_or_default();
    response(status, "application/json", body)
}

pub(super) fn error_response(status: u16, message: impl AsRef<str>) -> Response<ResponseBody> {
    response(
        status,
        "application/json",
        format!(r#"{{"error":"{}"}}"#, escape_json_string(message.as_ref())),
    )
}

fn escape_json_string(value: &str) -> String {
    serde_json::to_string(value)
        .unwrap_or_else(|_| "\"internal error\"".to_string())
        .trim_matches('"')
        .to_string()
}

fn json_response<T: Serialize>(status: u16, value: &T) -> NodeApiResponse {
    let body = serde_json::to_string_pretty(value).unwrap_or_default();
    NodeApiResponse::json(status, body)
}

#[derive(Debug, Clone)]
struct NodeApiResponse {
    status: u16,
    content_type: String,
    body: String,
}

impl NodeApiResponse {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json".to_string(),
            body,
        }
    }

    fn not_found() -> Self {
        Self::json(404, r#"{"error":"Not found"}"#.to_string())
    }
}

#[cfg(test)]
mod tests;
