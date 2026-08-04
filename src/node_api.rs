//! Node API for process-local health, metrics, version, and managed snapshots.
//!
//! The API runs on a dedicated listener and never intercepts user traffic.
//! Human-facing operations belong to A3S Cloud; this module exposes only the
//! bounded machine contract required to operate the Gateway data plane.

mod managed;

use crate::config::{GatewayConfig, ManagementConfig};
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
        path.strip_prefix(&self.path_prefix)
            .is_some_and(|rest| rest == subpath || rest.strip_suffix('/') == Some(subpath))
    }

    fn authorize(&self, req: &Request<Incoming>) -> bool {
        let Some(expected) = &self.auth_token else {
            return true;
        };

        req.headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .is_some_and(|token| token == expected)
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
                    let config = state.config.read().unwrap();
                    (config.mode, config.managed.gateway_id)
                };
                let health = HealthStatus {
                    state: state.lifecycle_state.read().unwrap().clone(),
                    mode,
                    gateway_id,
                    uptime_secs: state.start_time.elapsed().as_secs(),
                    active_connections: metrics.active_connections as usize,
                    total_requests: metrics.total_requests,
                    usage_spool: state
                        .usage_spool
                        .read()
                        .unwrap()
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
) -> Result<Option<tokio::task::JoinHandle<()>>> {
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
    path_prefix: String,
    auth_token: Option<String>,
    allowed_ips: Vec<String>,
    auth_enabled: bool,
    tls_acceptor: Option<TlsAcceptor>,
    client_cert_required: bool,
    listener: TcpListener,
    state: NodeApiState,
}

impl PreparedNodeApiListener {
    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        spawn_node_api_listener(self)
    }
}

pub(crate) async fn prepare_node_api_listener(
    config: &ManagementConfig,
    state: NodeApiState,
) -> Result<Option<PreparedNodeApiListener>> {
    let Some((addr, auth_token)) = resolve_listener_options(config)? else {
        return Ok(None);
    };

    let listener = TcpListener::bind(addr).await.map_err(|error| {
        GatewayError::Other(format!("Failed to bind node API listener {addr}: {error}"))
    })?;
    let tls_acceptor = config
        .tls
        .as_ref()
        .map(crate::proxy::tls::build_node_api_tls_acceptor)
        .transpose()?;

    Ok(Some(PreparedNodeApiListener {
        addr,
        path_prefix: config.path_prefix.clone(),
        auth_token,
        allowed_ips: config.allowed_ips.clone(),
        auth_enabled: config.auth_token_env.is_some(),
        tls_acceptor,
        client_cert_required: config
            .tls
            .as_ref()
            .is_some_and(|tls| tls.require_client_cert),
        listener,
        state,
    }))
}

fn spawn_node_api_listener(prepared: PreparedNodeApiListener) -> tokio::task::JoinHandle<()> {
    let PreparedNodeApiListener {
        addr,
        path_prefix,
        auth_token,
        allowed_ips,
        auth_enabled,
        tls_acceptor,
        client_cert_required,
        listener,
        state,
    } = prepared;

    let api = match NodeApi::with_allowed_ips(path_prefix.clone(), auth_token, &allowed_ips) {
        Ok(api) => Arc::new(api),
        Err(error) => {
            return tokio::spawn(async move {
                tracing::error!(%error, "Node API listener was not started");
            });
        }
    };
    let state = Arc::new(state);

    tracing::info!(
        address = %addr,
        path_prefix,
        auth = auth_enabled,
        tls = tls_acceptor.is_some(),
        client_cert_required,
        "Node API listening"
    );

    tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::error!(%error, "Failed to accept node API connection");
                    continue;
                }
            };

            let api = api.clone();
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
                                            api.clone(),
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
                                    api.clone(),
                                    state.clone(),
                                )
                            }),
                        )
                        .await;
                }
            });
        }
    })
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

    Ok(Some((addr, auth_token)))
}

async fn handle_node_api_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    api: Arc<NodeApi>,
    state: Arc<NodeApiState>,
) -> std::result::Result<Response<ResponseBody>, hyper::Error> {
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

fn response(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .body(full_body(body))
        .unwrap()
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
