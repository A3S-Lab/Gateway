//! Dashboard API — optional dedicated management listener.
//! This module intentionally serves management traffic from a separate
//! listener. It never intercepts user traffic entrypoints.

mod managed;

use crate::config::{GatewayConfig, ManagementConfig};
use crate::error::{GatewayError, Result};
use crate::managed_snapshot::{ConfigReloadCallback, ManagedSnapshotStore};
use crate::middleware::ip_matcher::IpMatcher;
use crate::observability::metrics::GatewayMetrics;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

type ResponseBody = http_body_util::combinators::UnsyncBoxBody<Bytes, std::io::Error>;
pub(crate) type ManagementReloadCallback = ConfigReloadCallback;

fn full_body(bytes: impl Into<Bytes>) -> ResponseBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed_unsync()
}

/// Shared state for the dedicated management listener.
#[derive(Clone)]
pub(crate) struct DashboardState {
    pub config: Arc<RwLock<GatewayConfig>>,
    pub lifecycle_state: Arc<RwLock<GatewayState>>,
    pub start_time: Instant,
    pub metrics: Arc<GatewayMetrics>,
    pub service_registry: Arc<RwLock<Option<Arc<ServiceRegistry>>>>,
    pub audit_log: Arc<ManagementAuditLog>,
    pub reload_config: Option<ManagementReloadCallback>,
    pub reload_managed_snapshot: Option<ManagementReloadCallback>,
    pub managed_snapshots: Arc<ManagedSnapshotStore>,
}

const DEFAULT_AUDIT_LOG_CAPACITY: usize = 512;
const DEFAULT_AUDIT_EVENT_LIMIT: usize = 100;
const MAX_AUDIT_EVENT_LIMIT: usize = 500;
const MAX_CONFIG_BODY_BYTES: usize = 1024 * 1024;

/// Management listener audit event kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagementAuditEventKind {
    /// Request used a path that is not owned by the management API.
    NotFound,
    /// Request came from a source IP outside the management allowlist.
    IpRejected,
    /// Request failed bearer token authorization.
    AuthRejected,
    /// TLS or client certificate handshake failed.
    TlsRejected,
    /// ACL payload was validated through the management API.
    ConfigValidated,
    /// ACL payload was applied through the management API.
    ConfigReloaded,
    /// ACL payload was rejected by validation or reload.
    ConfigRejected,
    /// Gateway-native managed snapshot was applied.
    SnapshotApplied,
    /// Gateway-native managed snapshot replay was accepted without reloading.
    SnapshotReplayed,
    /// Gateway-native managed snapshot was rejected.
    SnapshotRejected,
}

impl std::fmt::Display for ManagementAuditEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::NotFound => "not-found",
            Self::IpRejected => "ip-rejected",
            Self::AuthRejected => "auth-rejected",
            Self::TlsRejected => "tls-rejected",
            Self::ConfigValidated => "config-validated",
            Self::ConfigReloaded => "config-reloaded",
            Self::ConfigRejected => "config-rejected",
            Self::SnapshotApplied => "snapshot-applied",
            Self::SnapshotReplayed => "snapshot-replayed",
            Self::SnapshotRejected => "snapshot-rejected",
        };
        write!(f, "{}", value)
    }
}

/// Recent management listener security event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagementAuditEvent {
    pub sequence: u64,
    pub timestamp: String,
    pub kind: ManagementAuditEventKind,
    pub remote_addr: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub reason: String,
}

#[derive(Debug)]
struct ManagementAuditLogState {
    next_sequence: u64,
    events: VecDeque<ManagementAuditEvent>,
}

/// In-memory ring buffer for management listener security events.
#[derive(Debug)]
pub struct ManagementAuditLog {
    capacity: usize,
    inner: RwLock<ManagementAuditLogState>,
}

impl Default for ManagementAuditLog {
    fn default() -> Self {
        Self::new(DEFAULT_AUDIT_LOG_CAPACITY)
    }
}

impl ManagementAuditLog {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: RwLock::new(ManagementAuditLogState {
                next_sequence: 1,
                events: VecDeque::new(),
            }),
        }
    }

    pub fn record(&self, mut event: ManagementAuditEvent) {
        let mut inner = self.inner.write().unwrap();
        event.sequence = inner.next_sequence;
        inner.next_sequence += 1;
        if inner.events.len() == self.capacity {
            inner.events.pop_front();
        }
        inner.events.push_back(event);
    }

    pub fn snapshot(&self, limit: usize) -> Vec<ManagementAuditEvent> {
        let limit = limit.min(MAX_AUDIT_EVENT_LIMIT);
        let inner = self.inner.read().unwrap();
        let start = inner.events.len().saturating_sub(limit);
        inner.events.iter().skip(start).cloned().collect()
    }

    fn record_event(
        &self,
        kind: ManagementAuditEventKind,
        remote_addr: Option<SocketAddr>,
        path: Option<String>,
        status: Option<u16>,
        reason: impl Into<String>,
    ) {
        self.record(ManagementAuditEvent {
            sequence: 0,
            timestamp: chrono::Utc::now().to_rfc3339(),
            kind,
            remote_addr: remote_addr.map(|addr| addr.to_string()),
            path,
            status,
            reason: reason.into(),
        });
    }
}

/// Route information for the management API.
#[derive(Debug, Clone, Serialize)]
pub struct RouteInfo {
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entrypoints: Vec<String>,
    pub middlewares: Vec<String>,
    pub priority: i32,
}

/// Service information with live backend health.
#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub strategy: String,
    pub backends_total: usize,
    pub backends_healthy: usize,
    pub backends: Vec<BackendInfo>,
}

/// Backend health snapshot.
#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub active_connections: usize,
}

/// Backend detail with owning service name.
#[derive(Debug, Clone, Serialize)]
pub struct BackendDetail {
    pub service: String,
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub active_connections: usize,
}

/// Gateway version information.
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub api_version: &'static str,
}

impl VersionInfo {
    pub(crate) fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
            api_version: "v1",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ConfigMutationResponse {
    valid: bool,
    reloaded: bool,
    message: String,
}

/// Dashboard API handler.
pub struct DashboardApi {
    path_prefix: String,
    auth_token: Option<String>,
    ip_matcher: IpMatcher,
}

impl DashboardApi {
    /// Create a new dashboard API with an optional bearer token.
    pub fn new(path_prefix: impl Into<String>, auth_token: Option<String>) -> Self {
        Self::with_allowed_ips(path_prefix, auth_token, &[])
            .expect("empty management IP allowlist must be valid")
    }

    /// Create a new dashboard API with an optional bearer token and IP allowlist.
    pub(crate) fn with_allowed_ips(
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

    /// Check if a request path matches the dashboard prefix.
    pub fn matches(&self, path: &str) -> bool {
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

    fn handle(&self, path: &str, query: Option<&str>, state: &DashboardState) -> DashboardResponse {
        let Some(sub_path) = path.strip_prefix(&self.path_prefix) else {
            return DashboardResponse::not_found("Not found");
        };

        match sub_path {
            "" | "/" | "/health" | "/health/" => {
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
                };
                json_response(200, &health)
            }
            "/metrics" | "/metrics/" => DashboardResponse {
                status: 200,
                content_type: "text/plain; version=0.0.4".to_string(),
                body: state.metrics.render_prometheus(),
            },
            "/config" | "/config/" => {
                let config = state.config.read().unwrap().clone();
                json_response(200, &config)
            }
            "/routes" | "/routes/" => json_response(200, &routes_snapshot(state)),
            "/services" | "/services/" => json_response(200, &services_snapshot(state)),
            "/backends" | "/backends/" => json_response(200, &backends_snapshot(state)),
            "/events" | "/events/" => json_response(
                200,
                &state
                    .audit_log
                    .snapshot(audit_event_limit_from_query(query)),
            ),
            "/version" | "/version/" => json_response(200, &VersionInfo::current()),
            s if s.starts_with("/routes/") => {
                let name = &s["/routes/".len()..].trim_end_matches('/');
                routes_snapshot(state)
                    .into_iter()
                    .find(|route| route.name == *name)
                    .map(|route| json_response(200, &route))
                    .unwrap_or_else(|| DashboardResponse::not_found("Route not found"))
            }
            s if s.starts_with("/services/") => {
                let name = &s["/services/".len()..].trim_end_matches('/');
                services_snapshot(state)
                    .into_iter()
                    .find(|svc| svc.name == *name)
                    .map(|svc| json_response(200, &svc))
                    .unwrap_or_else(|| DashboardResponse::not_found("Service not found"))
            }
            _ => DashboardResponse::not_found("Not found"),
        }
    }
}

/// Start the dedicated management listener when enabled.
pub(crate) async fn start_dashboard_listener(
    config: &ManagementConfig,
    state: DashboardState,
) -> Result<Option<tokio::task::JoinHandle<()>>> {
    Ok(prepare_dashboard_listener(config, state)
        .await?
        .map(PreparedDashboardListener::spawn))
}

/// Prepared management listener that has already bound its socket.
///
/// Reload uses this to validate and reserve a new management address before
/// committing traffic changes. The listener only starts accepting on `spawn`.
pub(crate) struct PreparedDashboardListener {
    addr: SocketAddr,
    path_prefix: String,
    auth_token: Option<String>,
    allowed_ips: Vec<String>,
    auth_enabled: bool,
    tls_acceptor: Option<TlsAcceptor>,
    client_cert_required: bool,
    listener: TcpListener,
    state: DashboardState,
}

impl PreparedDashboardListener {
    pub(crate) fn spawn(self) -> tokio::task::JoinHandle<()> {
        spawn_dashboard_listener(self)
    }
}

pub(crate) async fn prepare_dashboard_listener(
    config: &ManagementConfig,
    state: DashboardState,
) -> Result<Option<PreparedDashboardListener>> {
    let Some((addr, auth_token)) = resolve_listener_options(config)? else {
        return Ok(None);
    };

    let listener = TcpListener::bind(addr).await.map_err(|e| {
        GatewayError::Other(format!(
            "Failed to bind management listener {}: {}",
            addr, e
        ))
    })?;
    let tls_acceptor = config
        .tls
        .as_ref()
        .map(crate::proxy::tls::build_management_tls_acceptor)
        .transpose()?;

    Ok(Some(PreparedDashboardListener {
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

fn spawn_dashboard_listener(prepared: PreparedDashboardListener) -> tokio::task::JoinHandle<()> {
    let PreparedDashboardListener {
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

    let api = match DashboardApi::with_allowed_ips(path_prefix.clone(), auth_token, &allowed_ips) {
        Ok(api) => Arc::new(api),
        Err(e) => {
            return tokio::spawn(async move {
                tracing::error!(error = %e, "Management API listener was not started");
            });
        }
    };
    let state = Arc::new(state);

    tracing::info!(
        address = %addr,
        path_prefix = path_prefix,
        auth = auth_enabled,
        tls = tls_acceptor.is_some(),
        client_cert_required,
        "Management API listening"
    );

    tokio::spawn(async move {
        loop {
            let (stream, remote_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::error!(error = %e, "Failed to accept management connection");
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
                                    service_fn(move |req| {
                                        handle_dashboard_request(
                                            req,
                                            remote_addr,
                                            api.clone(),
                                            state.clone(),
                                        )
                                    }),
                                )
                                .await;
                        }
                        Err(e) => {
                            state.audit_log.record_event(
                                ManagementAuditEventKind::TlsRejected,
                                Some(remote_addr),
                                None,
                                None,
                                format!("Management TLS handshake failed: {}", e),
                            );
                            tracing::debug!(error = %e, "Management TLS handshake failed");
                        }
                    }
                } else {
                    let io = TokioIo::new(stream);
                    let _ = auto::Builder::new(TokioExecutor::new())
                        .serve_connection(
                            io,
                            service_fn(move |req| {
                                handle_dashboard_request(
                                    req,
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

pub(crate) fn validate_dashboard_listener_config(config: &ManagementConfig) -> Result<()> {
    if resolve_listener_options(config)?.is_some() {
        if let Some(tls) = &config.tls {
            tls.validate()?;
            crate::proxy::tls::build_management_tls_acceptor(tls)?;
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

    let addr: SocketAddr = config.address.parse().map_err(|e| {
        GatewayError::Config(format!(
            "Invalid management address '{}': {}",
            config.address, e
        ))
    })?;
    IpMatcher::new(&config.allowed_ips)?;

    let auth_token = match &config.auth_token_env {
        Some(env_name) => Some(std::env::var(env_name).map_err(|_| {
            GatewayError::Config(format!(
                "Management auth token environment variable '{}' is not set",
                env_name
            ))
        })?),
        None => None,
    };

    Ok(Some((addr, auth_token)))
}

async fn handle_dashboard_request(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    api: Arc<DashboardApi>,
    state: Arc<DashboardState>,
) -> std::result::Result<Response<ResponseBody>, hyper::Error> {
    let path = req.uri().path().to_string();
    let query = req.uri().query().map(str::to_string);
    if !api.matches(&path) {
        state.audit_log.record_event(
            ManagementAuditEventKind::NotFound,
            Some(remote_addr),
            Some(path),
            Some(404),
            "Path is outside the management API prefix",
        );
        return Ok(response(
            404,
            "application/json",
            r#"{"error":"Not found"}"#,
        ));
    }

    if !api.authorize_ip(&remote_addr) {
        state.audit_log.record_event(
            ManagementAuditEventKind::IpRejected,
            Some(remote_addr),
            Some(path),
            Some(403),
            "Remote address is not allowed by management.allowed_ips",
        );
        return Ok(response(
            403,
            "application/json",
            r#"{"error":"Forbidden"}"#,
        ));
    }

    if !api.authorize(&req) {
        state.audit_log.record_event(
            ManagementAuditEventKind::AuthRejected,
            Some(remote_addr),
            Some(path),
            Some(401),
            "Bearer token is missing or invalid",
        );
        return Ok(response(
            401,
            "application/json",
            r#"{"error":"Unauthorized"}"#,
        ));
    }

    if req.method() == Method::POST && api.matches(&path) {
        if api.matches_subpath(&path, "/snapshots/apply") {
            return Ok(managed::handle_apply(req, remote_addr, &state).await);
        }
        if api.matches_subpath(&path, "/config/validate") {
            return Ok(handle_config_validate(req, remote_addr, &state).await);
        }
        if api.matches_subpath(&path, "/config/reload") {
            return Ok(handle_config_reload(req, remote_addr, &state).await);
        }
    }
    if req.method() == Method::GET && api.matches_subpath(&path, "/snapshots/status") {
        return Ok(managed::handle_status(
            query.as_deref(),
            remote_addr,
            &state,
        ));
    }

    let dashboard_resp = api.handle(&path, query.as_deref(), &state);
    Ok(response(
        dashboard_resp.status,
        &dashboard_resp.content_type,
        dashboard_resp.body,
    ))
}

async fn handle_config_validate(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: &DashboardState,
) -> Response<ResponseBody> {
    match read_acl_body(req).await.and_then(validate_acl_payload) {
        Ok(()) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::ConfigValidated,
                Some(remote_addr),
                Some("/config/validate".to_string()),
                Some(200),
                "Configuration payload validated",
            );
            json_http_response(
                200,
                &ConfigMutationResponse {
                    valid: true,
                    reloaded: false,
                    message: "Configuration is valid".to_string(),
                },
            )
        }
        Err(err) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::ConfigRejected,
                Some(remote_addr),
                Some("/config/validate".to_string()),
                Some(400),
                err.to_string(),
            );
            error_response(400, err.to_string())
        }
    }
}

async fn handle_config_reload(
    req: Request<Incoming>,
    remote_addr: SocketAddr,
    state: &DashboardState,
) -> Response<ResponseBody> {
    let Some(reload_config) = &state.reload_config else {
        return error_response(503, "Management reload is not available");
    };

    let config = match read_acl_body(req).await.and_then(parse_validated_acl) {
        Ok(config) => config,
        Err(err) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::ConfigRejected,
                Some(remote_addr),
                Some("/config/reload".to_string()),
                Some(400),
                err.to_string(),
            );
            return error_response(400, err.to_string());
        }
    };

    match reload_config(config).await {
        Ok(()) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::ConfigReloaded,
                Some(remote_addr),
                Some("/config/reload".to_string()),
                Some(200),
                "Configuration payload reloaded",
            );
            json_http_response(
                200,
                &ConfigMutationResponse {
                    valid: true,
                    reloaded: true,
                    message: "Configuration reloaded".to_string(),
                },
            )
        }
        Err(err) => {
            state.audit_log.record_event(
                ManagementAuditEventKind::ConfigRejected,
                Some(remote_addr),
                Some("/config/reload".to_string()),
                Some(400),
                err.to_string(),
            );
            error_response(400, err.to_string())
        }
    }
}

async fn read_acl_body(req: Request<Incoming>) -> Result<String> {
    let body = Limited::new(req.into_body(), MAX_CONFIG_BODY_BYTES)
        .collect()
        .await
        .map_err(|_| {
            GatewayError::Config(format!(
                "Configuration payload exceeds {} bytes or could not be read",
                MAX_CONFIG_BODY_BYTES
            ))
        })?
        .to_bytes();
    String::from_utf8(body.to_vec())
        .map_err(|e| GatewayError::Config(format!("Configuration payload is not UTF-8: {}", e)))
}

fn validate_acl_payload(acl: String) -> Result<()> {
    parse_validated_acl(acl).map(|_| ())
}

fn parse_validated_acl(acl: String) -> Result<GatewayConfig> {
    let config = GatewayConfig::from_acl(&acl)?;
    config.validate()?;
    crate::entrypoint::validate_entrypoints(&config)?;
    validate_dashboard_listener_config(&config.management)?;
    Ok(config)
}

fn response(status: u16, content_type: &str, body: impl Into<Bytes>) -> Response<ResponseBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Cache-Control", "no-store")
        .body(full_body(body))
        .unwrap()
}

fn json_http_response<T: Serialize>(status: u16, value: &T) -> Response<ResponseBody> {
    let body = serde_json::to_string_pretty(value).unwrap_or_default();
    response(status, "application/json", body)
}

fn error_response(status: u16, message: impl AsRef<str>) -> Response<ResponseBody> {
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

fn json_response<T: Serialize>(status: u16, value: &T) -> DashboardResponse {
    let body = serde_json::to_string_pretty(value).unwrap_or_default();
    DashboardResponse::json(status, body)
}

fn routes_snapshot(state: &DashboardState) -> Vec<RouteInfo> {
    let config = state.config.read().unwrap();
    config
        .routers
        .iter()
        .map(|(name, route)| RouteInfo {
            name: name.clone(),
            rule: route.rule.clone(),
            service: route.service.clone(),
            entrypoints: route.entrypoints.clone(),
            middlewares: route.middlewares.clone(),
            priority: route.priority,
        })
        .collect()
}

fn services_snapshot(state: &DashboardState) -> Vec<ServiceInfo> {
    let config = state.config.read().unwrap();
    let registry = state.service_registry.read().unwrap();

    config
        .services
        .iter()
        .map(|(name, service)| {
            let backends = registry
                .as_ref()
                .and_then(|registry| registry.get(name))
                .map(|lb| {
                    lb.backends()
                        .iter()
                        .map(|backend| BackendInfo {
                            url: backend.url.clone(),
                            weight: backend.weight,
                            healthy: backend.is_healthy(),
                            active_connections: backend.connections(),
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();

            let backends_total = backends.len();
            let backends_healthy = backends.iter().filter(|backend| backend.healthy).count();

            ServiceInfo {
                name: name.clone(),
                strategy: format!("{:?}", service.load_balancer.strategy),
                backends_total,
                backends_healthy,
                backends,
            }
        })
        .collect()
}

fn backends_snapshot(state: &DashboardState) -> Vec<BackendDetail> {
    let registry = state.service_registry.read().unwrap();
    let Some(registry) = registry.as_ref() else {
        return Vec::new();
    };

    registry
        .iter()
        .flat_map(|(svc_name, lb)| {
            lb.backends().iter().map(move |backend| BackendDetail {
                service: svc_name.clone(),
                url: backend.url.clone(),
                weight: backend.weight,
                healthy: backend.is_healthy(),
                active_connections: backend.connections(),
            })
        })
        .collect()
}

fn audit_event_limit_from_query(query: Option<&str>) -> usize {
    query
        .and_then(|query| {
            query.split('&').find_map(|pair| {
                let (key, value) = pair.split_once('=')?;
                (key == "limit").then_some(value)
            })
        })
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.min(MAX_AUDIT_EVENT_LIMIT))
        .unwrap_or(DEFAULT_AUDIT_EVENT_LIMIT)
}

/// Response from the dashboard API.
#[derive(Debug, Clone)]
pub struct DashboardResponse {
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

impl DashboardResponse {
    fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json".to_string(),
            body,
        }
    }

    fn not_found(message: &str) -> Self {
        Self::json(404, format!(r#"{{"error":"{}"}}"#, message))
    }
}

#[cfg(test)]
mod tests;
