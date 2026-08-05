//! HTTP/HTTPS reverse proxy with streaming request and response forwarding.

use crate::error::{GatewayError, Result};
use crate::proxy::streaming::{checked_deadline, timeout_millis};
use crate::service::{Backend, BackendConnectionGuard};
use bytes::Bytes;
use http::uri::Authority;
use http_body_util::{BodyExt, Either, Full};
use hyper::body::Incoming;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

type ProxyRequestBody = Either<Full<Bytes>, Incoming>;
type ProxyClient = Client<HttpsConnector<HttpConnector>, ProxyRequestBody>;
const MAX_PROXY_CLIENT_SHARDS: usize = 16;

pub use crate::proxy::http_response_body::ProxyResponseBody;

/// Independent bounds for one ordinary HTTP upstream operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpTimeouts {
    first_response: Duration,
    idle: Duration,
    total: Duration,
}

impl HttpTimeouts {
    /// Create response-header, idle-body, and total-operation bounds.
    pub fn new(first_response: Duration, idle: Duration, total: Duration) -> Self {
        Self {
            first_response,
            idle,
            total,
        }
    }

    fn uniform(timeout: Duration) -> Self {
        Self::new(timeout, timeout, timeout)
    }
}

/// HTTP/HTTPS reverse proxy with a certificate-verifying connection pool.
pub struct HttpProxy {
    clients: std::result::Result<Box<[ProxyClient]>, String>,
    timeout: Duration,
}

impl HttpProxy {
    /// Create a new HTTP proxy with default settings
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    /// Create a new HTTP proxy with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            clients: build_default_clients(),
            timeout,
        }
    }

    #[cfg(test)]
    fn with_tls_config(timeout: Duration, tls_config: rustls::ClientConfig) -> Self {
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .wrap_connector(configured_http_connector());
        Self {
            clients: Ok(vec![build_client(connector)].into_boxed_slice()),
            timeout,
        }
    }

    /// Forward an HTTP request to the selected backend (buffered body).
    pub async fn forward(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
    ) -> Result<ProxyResponse> {
        self.do_forward_buffered(
            backend,
            method,
            uri,
            headers,
            full_request_body(body),
            ForwardOptions::default(),
        )
        .await
    }

    /// Forward a buffered request while relaying the upstream response body.
    pub async fn forward_streaming_response_with_options(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Bytes,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        self.do_forward_streaming(
            backend,
            method,
            uri,
            headers,
            full_request_body(body),
            options,
        )
        .await
    }

    /// Forward both the downstream request and upstream response without collection.
    pub async fn forward_streaming_exchange(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: Incoming,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        self.do_forward_streaming(
            backend,
            method,
            uri,
            headers,
            incoming_request_body(body),
            options,
        )
        .await
    }

    /// Forward an owned downstream request without cloning its method, URI, or headers.
    pub(crate) async fn forward_streaming_exchange_owned(
        &self,
        backend: &Arc<Backend>,
        request: OwnedStreamingRequest,
        options: ForwardOptions,
        prepared_forwarded: Option<&PreparedForwardedContext>,
    ) -> Result<StreamingProxyResponse> {
        let pending = self
            .send_owned_request(backend, request, options, prepared_forwarded)
            .await?;
        let body = ProxyResponseBody::new(
            pending.body,
            pending.connection,
            pending.operation_started_at,
            pending.timeouts.idle,
            pending.timeouts.total,
        )?;
        Ok(StreamingProxyResponse {
            status: pending.parts.status,
            headers: pending.parts.headers,
            body,
        })
    }

    async fn do_forward_buffered(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<ProxyResponse> {
        let pending = self
            .send_request(backend, method, uri, headers, body, options)
            .await?;
        let status = pending.parts.status;
        let body = ProxyResponseBody::new(
            pending.body,
            pending.connection,
            pending.operation_started_at,
            pending.timeouts.idle,
            pending.timeouts.total,
        )?;
        tokio::pin!(body);
        while let Some(frame) = body.as_mut().frame().await {
            frame.map_err(|error| {
                GatewayError::ServiceUnavailable(format!("Failed to read response: {error}"))
            })?;
        }

        Ok(ProxyResponse { status })
    }

    async fn do_forward_streaming(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<StreamingProxyResponse> {
        let pending = self
            .send_request(backend, method, uri, headers, body, options)
            .await?;
        let body = ProxyResponseBody::new(
            pending.body,
            pending.connection,
            pending.operation_started_at,
            pending.timeouts.idle,
            pending.timeouts.total,
        )?;
        Ok(StreamingProxyResponse {
            status: pending.parts.status,
            headers: pending.parts.headers,
            body,
        })
    }

    /// Send one request after constructing the complete upstream URI.
    async fn send_request(
        &self,
        backend: &Arc<Backend>,
        method: &http::Method,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        body: ProxyRequestBody,
        options: ForwardOptions,
    ) -> Result<PendingProxyResponse> {
        let request = build_upstream_request(backend, method, uri, headers, body, options.context)?;
        self.send_built_request(backend, request, options, None)
            .await
    }

    async fn send_owned_request(
        &self,
        backend: &Arc<Backend>,
        request: OwnedStreamingRequest,
        options: ForwardOptions,
        prepared_forwarded: Option<&PreparedForwardedContext>,
    ) -> Result<PendingProxyResponse> {
        let OwnedStreamingRequest {
            method,
            uri,
            headers,
            body,
        } = request;
        let request = build_upstream_request_owned(
            backend,
            method,
            uri,
            headers,
            incoming_request_body(body),
            options.context,
            prepared_forwarded,
        )?;
        self.send_built_request(backend, request, options, prepared_forwarded)
            .await
    }

    async fn send_built_request(
        &self,
        backend: &Arc<Backend>,
        request: http::Request<ProxyRequestBody>,
        options: ForwardOptions,
        prepared_forwarded: Option<&PreparedForwardedContext>,
    ) -> Result<PendingProxyResponse> {
        let clients = self.clients.as_ref().map_err(|error| {
            GatewayError::Tls(format!("Failed to initialize upstream TLS client: {error}"))
        })?;
        let client_shard = prepared_forwarded.map_or_else(
            || proxy_client_shard(options.context, clients.len()),
            |prepared| prepared.client_shard(clients.len()),
        );
        let client = &clients[client_shard];
        let timeouts = options
            .timeouts
            .unwrap_or_else(|| HttpTimeouts::uniform(self.timeout));
        let operation_started_at = Instant::now();
        let first_response_deadline = checked_deadline(
            operation_started_at,
            timeouts.first_response,
            "request_timeout",
        )?;
        let total_deadline =
            checked_deadline(operation_started_at, timeouts.total, "stream_total_timeout")?;
        let connection = backend.track_connection_on(client_shard);
        let response_deadline = first_response_deadline.min(total_deadline);
        let response = tokio::time::timeout_at(response_deadline, client.request(request))
            .await
            .map_err(|_| {
                let elapsed_bound = if total_deadline <= first_response_deadline {
                    timeouts.total
                } else {
                    timeouts.first_response
                };
                GatewayError::UpstreamTimeout(timeout_millis(elapsed_bound))
            })?
            .map_err(|error| classify_hyper_error(error, &backend.url))?;
        let (mut parts, body) = response.into_parts();
        parts.headers = filter_hop_by_hop_headers(parts.headers);
        Ok(PendingProxyResponse {
            parts,
            body,
            connection,
            operation_started_at,
            timeouts,
        })
    }
}

fn configured_http_connector() -> HttpConnector {
    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    connector.set_nodelay(true);
    // TCP keepalive 15s (was 90s): detect a dead upstream (e.g. a backend pod
    // terminated during a K8s rollout) and tear the socket down promptly.
    connector.set_keepalive(Some(Duration::from_secs(15)));
    connector.set_reuse_address(true);

    // pool_idle_timeout 5s (was 90s): hyper keys the idle connection pool by hostname,
    // NOT by resolved IP. When a backend pod rolls (Deployment rollout → new pod IP),
    // pooled keep-alive sockets to the OLD pod IP linger and get reused → SendRequest
    // fails → passive-health marks the backend unhealthy → the half-open recovery probe
    // reuses ANOTHER stale socket → permanent 503 "No healthy backends" until the gateway
    // is restarted. Evicting idle sockets after 5s (well under passive-health
    // recovery_time, 10s) guarantees the half-open probe opens a FRESH connection that
    // re-resolves DNS to the new pod IP — so the gateway self-heals after a rollout
    // instead of requiring a manual restart.
    connector
}

fn build_default_clients() -> std::result::Result<Box<[ProxyClient]>, String> {
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(Arc::new(rustls::crypto::ring::default_provider()))
        .map_err(|error| error.to_string())?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .wrap_connector(configured_http_connector());
    Ok((0..proxy_client_shard_count())
        .map(|_| build_client(connector.clone()))
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

fn build_client(connector: HttpsConnector<HttpConnector>) -> ProxyClient {
    Client::builder(TokioExecutor::new())
        .pool_idle_timeout(Duration::from_secs(5))
        .pool_max_idle_per_host(200)
        .build(connector)
}

fn proxy_client_shard_count() -> usize {
    std::thread::available_parallelism()
        .map_or(1, usize::from)
        .clamp(1, MAX_PROXY_CLIENT_SHARDS)
}

fn proxy_client_shard(context: Option<ForwardedContext>, shard_count: usize) -> usize {
    debug_assert!(shard_count > 0);
    if shard_count == 1 {
        return 0;
    }
    let Some(context) = context else {
        return 0;
    };

    (proxy_client_shard_hash(context) as usize) % shard_count
}

fn proxy_client_shard_hash(context: ForwardedContext) -> u64 {
    // Keep every downstream connection on one upstream pool while spreading
    // adjacent ephemeral ports across shards. This removes one shared pool
    // lock from the multi-worker HTTP/1.1 hot path without reducing keep-alive
    // reuse for any individual downstream connection.
    let mut hash = u64::from(context.remote_addr.port()).wrapping_add(0x9e37_79b9_7f4a_7c15);
    hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^= hash >> 31;
    hash
}

struct PendingProxyResponse {
    parts: http::response::Parts,
    body: Incoming,
    connection: BackendConnectionGuard,
    operation_started_at: Instant,
    timeouts: HttpTimeouts,
}

fn full_request_body(body: Bytes) -> ProxyRequestBody {
    Either::Left(Full::new(body))
}

fn incoming_request_body(body: Incoming) -> ProxyRequestBody {
    Either::Right(body)
}

fn build_upstream_request(
    backend: &Backend,
    method: &http::Method,
    uri: &http::Uri,
    headers: &http::HeaderMap,
    body: ProxyRequestBody,
    context: Option<ForwardedContext>,
) -> Result<http::Request<ProxyRequestBody>> {
    build_upstream_request_owned(
        backend,
        method.clone(),
        uri.clone(),
        headers.clone(),
        body,
        context,
        None,
    )
}

fn build_upstream_request_owned(
    backend: &Backend,
    method: http::Method,
    uri: http::Uri,
    headers: http::HeaderMap,
    body: ProxyRequestBody,
    context: Option<ForwardedContext>,
    prepared_forwarded: Option<&PreparedForwardedContext>,
) -> Result<http::Request<ProxyRequestBody>> {
    let upstream_uri = build_upstream_uri_owned(backend, uri)?;
    let forwarded = match prepared_forwarded {
        Some(prepared) => Some(PreparedForwardedHeaders::new_prepared(&headers, prepared)?),
        None => context
            .map(|context| PreparedForwardedHeaders::new(&headers, context))
            .transpose()?,
    };
    let mut upstream_headers = filter_hop_by_hop_headers(headers);
    if let Some(forwarded) = forwarded {
        forwarded.apply(&mut upstream_headers);
    }

    let mut request = http::Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = upstream_uri;
    *request.headers_mut() = upstream_headers;
    Ok(request)
}

/// Connection-stable forwarding values reused by ordinary HTTP requests.
pub(crate) struct PreparedForwardedContext {
    context: ForwardedContext,
    client_ip: http::HeaderValue,
    local_port: u16,
    local_port_header: http::HeaderValue,
    client_shard_hash: u64,
}

/// Owned ordinary request fields transferred into the allocation-free proxy path.
pub(crate) struct OwnedStreamingRequest {
    pub(crate) method: http::Method,
    pub(crate) uri: http::Uri,
    pub(crate) headers: http::HeaderMap,
    pub(crate) body: Incoming,
}

impl PreparedForwardedContext {
    pub(crate) fn new(context: ForwardedContext, local_port: u16) -> Result<Self> {
        Ok(Self {
            context,
            client_ip: generated_header_value(context.remote_addr.ip().to_string())?,
            local_port,
            local_port_header: generated_header_value(local_port.to_string())?,
            client_shard_hash: proxy_client_shard_hash(context),
        })
    }

    fn client_shard(&self, shard_count: usize) -> usize {
        debug_assert!(shard_count > 0);
        if shard_count == 1 {
            0
        } else {
            (self.client_shard_hash as usize) % shard_count
        }
    }

    #[cfg(test)]
    pub(crate) fn apply(&self, headers: &mut http::HeaderMap) -> Result<()> {
        PreparedForwardedHeaders::new_prepared(headers, self)?.apply(headers);
        Ok(())
    }
}

struct PreparedForwardedHeaders {
    forwarded_for: http::HeaderValue,
    forwarded_host: Option<http::HeaderValue>,
    forwarded_proto: http::HeaderValue,
    forwarded_port: http::HeaderValue,
}

impl PreparedForwardedHeaders {
    fn new(headers: &http::HeaderMap, context: ForwardedContext) -> Result<Self> {
        Ok(Self {
            forwarded_for: generated_header_value(forwarded_for_value(headers, context))?,
            forwarded_host: forwarded_host_value(headers)
                .map(generated_header_value)
                .transpose()?,
            forwarded_proto: http::HeaderValue::from_static(context.proto.as_str()),
            forwarded_port: generated_header_value(forwarded_port_value(headers, context))?,
        })
    }

    fn new_prepared(
        headers: &http::HeaderMap,
        prepared: &PreparedForwardedContext,
    ) -> Result<Self> {
        Ok(Self {
            forwarded_for: prepared_forwarded_for_value(headers, &prepared.client_ip)?,
            forwarded_host: prepared_forwarded_host_value(headers)?,
            forwarded_proto: http::HeaderValue::from_static(prepared.context.proto.as_str()),
            forwarded_port: prepared_forwarded_port_value(headers, prepared)?,
        })
    }

    fn apply(self, headers: &mut http::HeaderMap) {
        headers.insert(
            http::HeaderName::from_static("x-forwarded-for"),
            self.forwarded_for,
        );
        if let Some(host) = self.forwarded_host {
            headers.insert(http::HeaderName::from_static("x-forwarded-host"), host);
        } else {
            headers.remove(http::HeaderName::from_static("x-forwarded-host"));
        }
        headers.insert(
            http::HeaderName::from_static("x-forwarded-proto"),
            self.forwarded_proto,
        );
        headers.insert(
            http::HeaderName::from_static("x-forwarded-port"),
            self.forwarded_port,
        );
    }
}

fn prepared_forwarded_for_value(
    headers: &http::HeaderMap,
    client_ip: &http::HeaderValue,
) -> Result<http::HeaderValue> {
    match header_str(headers, "x-forwarded-for") {
        Some(existing) if !existing.trim().is_empty() => {
            let client_ip_text = client_ip.to_str().map_err(|error| {
                GatewayError::Config(format!("Prepared client IP header is invalid: {error}"))
            })?;
            generated_header_value(format!("{}, {}", existing.trim(), client_ip_text))
        }
        _ => Ok(client_ip.clone()),
    }
}

fn prepared_forwarded_host_value(headers: &http::HeaderMap) -> Result<Option<http::HeaderValue>> {
    let host_value = headers.get(http::header::HOST);
    let existing_value = headers.get("x-forwarded-host");
    let host = host_value.and_then(|value| value.to_str().ok());
    let existing = existing_value.and_then(|value| value.to_str().ok());

    match (existing, host) {
        (Some(existing), Some(host)) if !existing.trim().is_empty() => {
            generated_header_value(format!("{}, {}", existing.trim(), host.trim())).map(Some)
        }
        (_, Some(host)) if !host.trim().is_empty() => clone_trimmed_header(host_value, host),
        (Some(existing), _) if !existing.trim().is_empty() => {
            clone_trimmed_header(existing_value, existing)
        }
        _ => Ok(None),
    }
}

fn clone_trimmed_header(
    value: Option<&http::HeaderValue>,
    text: &str,
) -> Result<Option<http::HeaderValue>> {
    let trimmed = text.trim();
    match value {
        Some(value) if value.as_bytes() == trimmed.as_bytes() => Ok(Some(value.clone())),
        _ => generated_header_value(trimmed.to_string()).map(Some),
    }
}

fn prepared_forwarded_port_value(
    headers: &http::HeaderMap,
    prepared: &PreparedForwardedContext,
) -> Result<http::HeaderValue> {
    let host = header_str(headers, "host").or_else(|| header_str(headers, "x-forwarded-host"));
    match host
        .and_then(|value| value.trim().parse::<Authority>().ok())
        .and_then(|authority| authority.port_u16())
    {
        Some(port) if port == prepared.local_port => Ok(prepared.local_port_header.clone()),
        Some(port) => generated_header_value(port.to_string()),
        None => Ok(http::HeaderValue::from_static(
            prepared.context.proto.default_port(),
        )),
    }
}

fn generated_header_value(value: String) -> Result<http::HeaderValue> {
    http::HeaderValue::try_from(value).map_err(|error| {
        GatewayError::Config(format!("Failed to build forwarding header: {error}"))
    })
}

#[cfg(test)]
fn build_upstream_uri(backend: &Backend, uri: &http::Uri) -> Result<http::Uri> {
    build_upstream_uri_owned(backend, uri.clone())
}

fn build_upstream_uri_owned(backend: &Backend, uri: http::Uri) -> Result<http::Uri> {
    if let Some(base) = backend.http_base_uri().filter(|base| {
        base.authority().is_some()
            && base.scheme().is_some_and(|scheme| {
                scheme == &http::uri::Scheme::HTTP || scheme == &http::uri::Scheme::HTTPS
            })
            && (base.path().is_empty() || base.path() == "/")
            && base.query().is_none()
    }) {
        let mut parts = uri.into_parts();
        parts.scheme = base.scheme().cloned();
        parts.authority = base.authority().cloned();
        return http::Uri::from_parts(parts).map_err(|error| {
            GatewayError::Config(format!("Failed to build upstream URI: {error}"))
        });
    }

    let backend_url = backend.url.trim_end_matches('/');
    let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let mut upstream_uri = String::with_capacity(backend_url.len() + path_and_query.len());
    upstream_uri.push_str(backend_url);
    upstream_uri.push_str(path_and_query);
    upstream_uri
        .parse::<http::Uri>()
        .map_err(|error| GatewayError::Config(format!("Failed to build upstream URI: {error}")))
}

pub(crate) fn classify_hyper_error(
    e: hyper_util::client::legacy::Error,
    backend_url: &str,
) -> GatewayError {
    let msg = e.to_string();
    if msg.contains("connect") || msg.contains("Connection refused") || msg.contains("dns") {
        GatewayError::UpstreamTransport(format!("Cannot connect to backend {}: {}", backend_url, e))
    } else {
        GatewayError::UpstreamTransport(format!("Upstream request failed: {}", e))
    }
}

impl Default for HttpProxy {
    fn default() -> Self {
        Self::new()
    }
}

/// Scheme observed on the downstream gateway entrypoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardedProto {
    /// Plain HTTP traffic.
    Http,
    /// TLS-terminated HTTPS traffic.
    Https,
}

impl ForwardedProto {
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }

    fn default_port(self) -> &'static str {
        match self {
            Self::Http => "80",
            Self::Https => "443",
        }
    }
}

/// Downstream request context used to generate reverse-proxy forwarding headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ForwardedContext {
    /// Client socket address observed by the gateway.
    pub remote_addr: SocketAddr,
    /// Scheme observed by the gateway entrypoint.
    pub proto: ForwardedProto,
}

impl ForwardedContext {
    /// Create a new forwarding context.
    pub fn new(remote_addr: SocketAddr, proto: ForwardedProto) -> Self {
        Self { remote_addr, proto }
    }
}

/// Per-request HTTP proxy options.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardOptions {
    /// Downstream request context for X-Forwarded-* generation.
    pub context: Option<ForwardedContext>,
    /// Optional per-service response-header, idle-body, and total bounds.
    pub timeouts: Option<HttpTimeouts>,
}

/// Response from an upstream backend
#[derive(Debug)]
pub struct ProxyResponse {
    /// HTTP status code
    pub status: http::StatusCode,
}

/// Streaming response from an ordinary HTTP upstream.
pub struct StreamingProxyResponse {
    /// HTTP status returned by the upstream.
    pub status: http::StatusCode,
    /// End-to-end response headers.
    pub headers: http::HeaderMap,
    /// DATA and safe trailer frames with independent idle and total bounds.
    pub body: ProxyResponseBody,
}

/// Check if a header is a hop-by-hop header that should not be forwarded
pub(crate) fn is_hop_by_hop(name: &str) -> bool {
    // eq_ignore_ascii_case is zero-allocation; avoids to_lowercase() heap alloc per header
    name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("proxy-authenticate")
        || name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("te")
        || name.eq_ignore_ascii_case("trailer")
        || name.eq_ignore_ascii_case("trailers")
        || name.eq_ignore_ascii_case("transfer-encoding")
        || name.eq_ignore_ascii_case("upgrade")
}

/// Check both standard hop-by-hop fields and fields nominated by Connection.
pub(crate) fn is_hop_by_hop_header(
    headers: &http::HeaderMap,
    name: &http::header::HeaderName,
) -> bool {
    is_hop_by_hop(name.as_str()) || is_connection_scoped_header(headers, name)
}

/// Check whether any Connection field nominates this header for one hop only.
pub(crate) fn is_connection_scoped_header(
    headers: &http::HeaderMap,
    name: &http::header::HeaderName,
) -> bool {
    let expected = name.as_str().as_bytes();
    headers
        .get_all(http::header::CONNECTION)
        .iter()
        .any(|value| {
            value
                .as_bytes()
                .split(|byte| *byte == b',')
                .any(|option| option.trim_ascii().eq_ignore_ascii_case(expected))
        })
}

/// Remove hop-by-hop fields from an upstream or downstream header map.
pub(crate) fn filter_hop_by_hop_headers(mut headers: http::HeaderMap) -> http::HeaderMap {
    if !headers.keys().any(|name| is_hop_by_hop(name.as_str())) {
        return headers;
    }

    let connection_scoped = headers
        .get_all(http::header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|byte| *byte == b','))
        .filter_map(|option| http::header::HeaderName::from_bytes(option.trim_ascii()).ok())
        .collect::<Vec<_>>();

    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
    for name in connection_scoped {
        headers.remove(name);
    }

    headers
}

/// Check if a header is generated by the gateway for upstream requests.
pub(crate) fn is_forwarded_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("x-forwarded-for")
        || name.eq_ignore_ascii_case("x-forwarded-host")
        || name.eq_ignore_ascii_case("x-forwarded-proto")
        || name.eq_ignore_ascii_case("x-forwarded-port")
}

pub(crate) fn apply_forwarded_headers(
    mut builder: http::request::Builder,
    headers: &http::HeaderMap,
    context: ForwardedContext,
) -> http::request::Builder {
    builder = builder.header("x-forwarded-for", forwarded_for_value(headers, context));

    if let Some(host) = forwarded_host_value(headers) {
        builder = builder.header("x-forwarded-host", host);
    }

    builder = builder.header("x-forwarded-proto", context.proto.as_str());
    builder = builder.header("x-forwarded-port", forwarded_port_value(headers, context));
    builder
}

fn forwarded_for_value(headers: &http::HeaderMap, context: ForwardedContext) -> String {
    let client_ip = context.remote_addr.ip().to_string();
    match header_str(headers, "x-forwarded-for") {
        Some(existing) if !existing.trim().is_empty() => {
            format!("{}, {}", existing.trim(), client_ip)
        }
        _ => client_ip,
    }
}

fn forwarded_host_value(headers: &http::HeaderMap) -> Option<String> {
    let host = header_str(headers, "host");
    let existing = header_str(headers, "x-forwarded-host");

    match (existing, host) {
        (Some(existing), Some(host)) if !existing.trim().is_empty() => {
            Some(format!("{}, {}", existing.trim(), host.trim()))
        }
        (_, Some(host)) if !host.trim().is_empty() => Some(host.trim().to_string()),
        (Some(existing), _) if !existing.trim().is_empty() => Some(existing.trim().to_string()),
        _ => None,
    }
}

fn forwarded_port_value(headers: &http::HeaderMap, context: ForwardedContext) -> String {
    let default_port = context.proto.default_port();
    let host = header_str(headers, "host").or_else(|| header_str(headers, "x-forwarded-host"));

    host.and_then(|value| value.trim().parse::<Authority>().ok())
        .and_then(|authority| authority.port_u16())
        .map(|port| port.to_string())
        .unwrap_or_else(|| default_port.to_string())
}

fn header_str<'a>(headers: &'a http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

#[cfg(test)]
#[path = "http_proxy_tls_tests.rs"]
mod tls_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn client_pool_shards_distribute_adjacent_connections() {
        let mut seen = [false; 4];
        for port in (40_000..40_128).step_by(2) {
            let context = ForwardedContext::new(
                SocketAddr::from(([127, 0, 0, 1], port)),
                ForwardedProto::Http,
            );
            seen[proxy_client_shard(Some(context), seen.len())] = true;
        }

        assert!(seen.into_iter().all(|was_selected| was_selected));
        assert_eq!(proxy_client_shard(None, 4), 0);
        assert_eq!(
            proxy_client_shard(
                Some(ForwardedContext::new(
                    SocketAddr::from(([127, 0, 0, 1], 40_000)),
                    ForwardedProto::Http,
                )),
                1,
            ),
            0
        );
    }

    #[test]
    fn prepared_connection_reuses_client_pool_shard_hash() {
        let context = ForwardedContext::new(
            SocketAddr::from(([127, 0, 0, 1], 40_017)),
            ForwardedProto::Http,
        );
        let prepared = PreparedForwardedContext::new(context, 8080).unwrap();

        for shard_count in [1, 4, 16] {
            assert_eq!(
                prepared.client_shard(shard_count),
                proxy_client_shard(Some(context), shard_count)
            );
        }
    }

    /// Spawn a mock HTTP backend that returns a configurable response.
    async fn spawn_mock_backend(status: u16, body: &'static str, delay_ms: u64) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                let body = body.to_string();
                let status = status;
                let delay = delay_ms;
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    if delay > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                    }
                    let resp = format!(
                        "HTTP/1.1 {} OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                        status,
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(resp.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        });
        addr
    }

    /// Spawn a backend that captures one raw HTTP request and returns 200 OK.
    async fn spawn_capture_backend() -> (SocketAddr, tokio::sync::oneshot::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let _ = tx.send(request);

            let body = "ok";
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        (addr, rx)
    }

    fn captured_header(request: &str, name: &str) -> Option<String> {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    #[test]
    fn test_hop_by_hop_headers() {
        assert!(is_hop_by_hop("Connection"));
        assert!(is_hop_by_hop("connection"));
        assert!(is_hop_by_hop("Keep-Alive"));
        assert!(is_hop_by_hop("Transfer-Encoding"));
        assert!(is_hop_by_hop("Upgrade"));
        assert!(is_hop_by_hop("Proxy-Authorization"));
        assert!(is_hop_by_hop("Proxy-Connection"));
        assert!(is_hop_by_hop("Trailer"));

        assert!(!is_hop_by_hop("Content-Type"));
        assert!(!is_hop_by_hop("Authorization"));
        assert!(!is_hop_by_hop("X-Custom-Header"));
        assert!(!is_hop_by_hop("Host"));
    }

    #[test]
    fn builds_upstream_uri_by_reusing_the_request_path() {
        let backend = Backend::new("http://127.0.0.1:9000".to_string(), 1);
        let request_uri: http::Uri = "/v1/models?tenant=acme".parse().unwrap();

        let upstream = build_upstream_uri(&backend, &request_uri).unwrap();

        assert_eq!(upstream, "http://127.0.0.1:9000/v1/models?tenant=acme");
    }

    #[test]
    fn builds_upstream_uri_with_a_configured_base_path() {
        let backend = Backend::new("http://127.0.0.1:9000/api".to_string(), 1);
        let request_uri: http::Uri = "/v1/models?tenant=acme".parse().unwrap();

        let upstream = build_upstream_uri(&backend, &request_uri).unwrap();

        assert_eq!(upstream, "http://127.0.0.1:9000/api/v1/models?tenant=acme");
    }

    #[test]
    fn owned_request_builder_preserves_proxy_semantics() {
        let backend = Backend::new("http://127.0.0.1:9000".to_string(), 1);
        let method = http::Method::POST;
        let uri: http::Uri = "/v1/chat/completions?tenant=acme".parse().unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "api.example.com:8443".parse().unwrap());
        headers.insert(http::header::CONNECTION, "x-hop".parse().unwrap());
        headers.insert("x-hop", "remove-me".parse().unwrap());
        headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
        let context =
            ForwardedContext::new("198.51.100.7:54321".parse().unwrap(), ForwardedProto::Https);

        let borrowed = build_upstream_request(
            &backend,
            &method,
            &uri,
            &headers,
            full_request_body(Bytes::new()),
            Some(context),
        )
        .unwrap();
        let owned = build_upstream_request_owned(
            &backend,
            method,
            uri,
            headers,
            full_request_body(Bytes::new()),
            Some(context),
            None,
        )
        .unwrap();

        assert_eq!(owned.method(), borrowed.method());
        assert_eq!(owned.uri(), borrowed.uri());
        assert_eq!(owned.headers(), borrowed.headers());
        assert!(!owned.headers().contains_key("x-hop"));
        assert_eq!(
            owned.headers()["x-forwarded-for"],
            "192.0.2.1, 198.51.100.7"
        );
        assert_eq!(owned.headers()["x-forwarded-port"], "8443");
    }

    #[test]
    fn test_connection_nominated_headers_are_hop_by_hop() {
        let mut headers = http::HeaderMap::new();
        headers.append(
            http::header::CONNECTION,
            "keep-alive, X-First-Hop".parse().unwrap(),
        );
        headers.append(http::header::CONNECTION, "X-Second-Hop".parse().unwrap());
        headers.insert("X-First-Hop", "one".parse().unwrap());
        headers.insert("X-Second-Hop", "two".parse().unwrap());
        headers.insert("X-End-To-End", "preserved".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());

        assert!(is_hop_by_hop_header(
            &headers,
            &http::header::HeaderName::from_static("x-first-hop")
        ));
        assert!(is_hop_by_hop_header(
            &headers,
            &http::header::HeaderName::from_static("x-second-hop")
        ));

        let filtered = filter_hop_by_hop_headers(headers);
        assert!(!filtered.contains_key(http::header::CONNECTION));
        assert!(!filtered.contains_key("x-first-hop"));
        assert!(!filtered.contains_key("x-second-hop"));
        assert_eq!(filtered["x-end-to-end"], "preserved");
        assert_eq!(filtered.get_all(http::header::SET_COOKIE).iter().count(), 2);
    }

    #[test]
    fn end_to_end_only_headers_pass_through_unchanged() {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/json".parse().unwrap(),
        );
        headers.append(http::header::SET_COOKIE, "first=1".parse().unwrap());
        headers.append(http::header::SET_COOKIE, "second=2".parse().unwrap());
        let expected = headers.clone();

        assert_eq!(filter_hop_by_hop_headers(headers), expected);
    }

    #[test]
    fn test_forwarded_context_helpers() {
        let context =
            ForwardedContext::new("203.0.113.10:50123".parse().unwrap(), ForwardedProto::Https);
        assert_eq!(context.proto.as_str(), "https");
        assert_eq!(context.proto.default_port(), "443");
    }

    #[test]
    fn prepared_forwarded_context_preserves_header_semantics() {
        let context =
            ForwardedContext::new("203.0.113.10:50123".parse().unwrap(), ForwardedProto::Https);
        let prepared = PreparedForwardedContext::new(context, 8443).unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(http::header::HOST, "api.example.test:8443".parse().unwrap());

        prepared.apply(&mut headers).unwrap();
        assert_eq!(headers["x-forwarded-for"], "203.0.113.10");
        assert_eq!(headers["x-forwarded-host"], "api.example.test:8443");
        assert_eq!(headers["x-forwarded-proto"], "https");
        assert_eq!(headers["x-forwarded-port"], "8443");

        headers.insert("x-forwarded-for", "192.0.2.1".parse().unwrap());
        headers.insert("x-forwarded-host", "edge.example.test".parse().unwrap());
        prepared.apply(&mut headers).unwrap();
        assert_eq!(headers["x-forwarded-for"], "192.0.2.1, 203.0.113.10");
        assert_eq!(
            headers["x-forwarded-host"],
            "edge.example.test, api.example.test:8443"
        );
    }

    #[test]
    fn test_http_proxy_default() {
        let proxy = HttpProxy::default();
        assert_eq!(proxy.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_http_proxy_custom_timeout() {
        let proxy = HttpProxy::with_timeout(Duration::from_secs(60));
        assert_eq!(proxy.timeout, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_forward_with_options_uses_request_timeout() {
        let backend_addr = spawn_mock_backend(200, "slow", 200).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/slow".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
                ForwardOptions {
                    context: None,
                    timeouts: Some(HttpTimeouts::new(
                        Duration::from_millis(50),
                        Duration::from_secs(5),
                        Duration::from_secs(5),
                    )),
                },
            )
            .await;

        assert!(matches!(result, Err(GatewayError::UpstreamTimeout(50))));
    }

    #[test]
    fn test_proxy_response_fields() {
        let resp = ProxyResponse {
            status: http::StatusCode::OK,
        };
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_success() {
        let backend_addr = spawn_mock_backend(200, "hello world", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/test".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_404_response() {
        let backend_addr = spawn_mock_backend(404, "not found", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/missing".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_forward_500_response() {
        let backend_addr = spawn_mock_backend(500, "internal error", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/error".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_forward_connection_refused() {
        // Use a port that nothing is listening on
        let backend_addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/test".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_forward_with_headers() {
        let backend_addr = spawn_mock_backend(200, "ok", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("X-Custom-Header", "custom-value".parse().unwrap());
        headers.insert("Authorization", "Bearer token".parse().unwrap());
        // Connection header should be filtered (hop-by-hop)
        headers.insert("Connection", "close".parse().unwrap());

        let uri: http::Uri = "/headers".parse().unwrap();
        let result = proxy
            .forward(&backend, &http::Method::GET, &uri, &headers, Bytes::new())
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_forward_with_options_adds_forwarded_headers() {
        let (backend_addr, captured) = spawn_capture_backend().await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "api.example.test:8443".parse().unwrap());
        headers.insert("Connection", "close".parse().unwrap());

        let context =
            ForwardedContext::new("203.0.113.42:53100".parse().unwrap(), ForwardedProto::Https);
        let uri: http::Uri = "/headers?debug=true".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeouts: None,
                },
            )
            .await;

        assert!(result.is_ok());
        let request = captured.await.unwrap();
        assert_eq!(
            captured_header(&request, "x-forwarded-for").as_deref(),
            Some("203.0.113.42")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-host").as_deref(),
            Some("api.example.test:8443")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-proto").as_deref(),
            Some("https")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-port").as_deref(),
            Some("8443")
        );
        assert!(captured_header(&request, "connection").is_none());
    }

    #[tokio::test]
    async fn test_forward_with_options_appends_forwarded_for() {
        let (backend_addr, captured) = spawn_capture_backend().await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let mut headers = http::HeaderMap::new();
        headers.insert("Host", "api.example.test".parse().unwrap());
        headers.insert("X-Forwarded-For", "198.51.100.10".parse().unwrap());
        headers.insert("X-Forwarded-Proto", "https".parse().unwrap());

        let context =
            ForwardedContext::new("127.0.0.1:53101".parse().unwrap(), ForwardedProto::Http);
        let uri: http::Uri = "/chain".parse().unwrap();
        let result = proxy
            .forward_streaming_response_with_options(
                &backend,
                &http::Method::GET,
                &uri,
                &headers,
                Bytes::new(),
                ForwardOptions {
                    context: Some(context),
                    timeouts: None,
                },
            )
            .await;

        assert!(result.is_ok());
        let request = captured.await.unwrap();
        assert_eq!(
            captured_header(&request, "x-forwarded-for").as_deref(),
            Some("198.51.100.10, 127.0.0.1")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-proto").as_deref(),
            Some("http")
        );
        assert_eq!(
            captured_header(&request, "x-forwarded-port").as_deref(),
            Some("80")
        );
    }

    #[tokio::test]
    async fn test_forward_with_body() {
        let backend_addr = spawn_mock_backend(200, "received", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        let uri: http::Uri = "/upload".parse().unwrap();
        let body = Bytes::from("request body content");

        let result = proxy
            .forward(
                &backend,
                &http::Method::POST,
                &uri,
                &http::HeaderMap::new(),
                body,
            )
            .await;

        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_forward_path_and_query_preserved() {
        let backend_addr = spawn_mock_backend(200, "ok", 0).await;
        let backend = Arc::new(Backend::new(format!("http://{}", backend_addr), 1));
        let proxy = HttpProxy::with_timeout(Duration::from_secs(5));

        // Test path and query string are preserved
        let uri: http::Uri = "/api/items?id=123&filter=name".parse().unwrap();
        let result = proxy
            .forward(
                &backend,
                &http::Method::GET,
                &uri,
                &http::HeaderMap::new(),
                Bytes::new(),
            )
            .await;

        assert!(result.is_ok());
    }
}
