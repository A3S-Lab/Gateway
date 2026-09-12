//! Deterministic OpenAI-compatible streaming upstream for AI gateway benchmarks.

use std::convert::Infallible;
use std::error::Error;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use futures_util::stream;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::{Frame, Incoming};
use hyper::header::{CACHE_CONTROL, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ServerBuilder;
use rustls::ServerConfig;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

type BoxError = Box<dyn Error + Send + Sync>;
type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

static INSTANCE_ID: OnceLock<String> = OnceLock::new();

fn instance_id() -> &'static str {
    INSTANCE_ID
        .get()
        .map(String::as_str)
        .unwrap_or("default")
}

const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOKENS: usize = 4_096;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_FRAGMENTS_PER_EVENT: usize = 32;

static STREAMS_STARTED: AtomicU64 = AtomicU64::new(0);
static STREAMS_COMPLETED: AtomicU64 = AtomicU64::new(0);
static STREAMS_CLIENT_CANCELLED: AtomicU64 = AtomicU64::new(0);

struct ClientDisconnectProbe {
    finished: Arc<AtomicBool>,
}

impl Drop for ClientDisconnectProbe {
    fn drop(&mut self) {
        if !self.finished.load(Ordering::SeqCst) {
            STREAMS_CLIENT_CANCELLED.fetch_add(1, Ordering::SeqCst);
        }
    }
}

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Address used by both benchmark proxies as their shared upstream.
    #[arg(long, default_value = "127.0.0.1:18100")]
    address: SocketAddr,
    /// Stable identity stamped into every token event as `benchmark_instance`.
    /// Weighted-rollout uses distinct ids on stable vs canary listeners.
    #[arg(long, default_value = "default")]
    instance_id: String,
    /// Optional server certificate for HTTPS upstream lanes (pair with `--tls-key`).
    #[arg(long)]
    tls_cert: Option<PathBuf>,
    /// Optional private key for HTTPS upstream lanes (pair with `--tls-cert`).
    #[arg(long)]
    tls_key: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
enum UpstreamFault {
    #[serde(rename = "http-429")]
    Http429,
    #[serde(rename = "http-500")]
    Http500,
    #[serde(rename = "http-503")]
    Http503,
    #[serde(rename = "missing-done")]
    MissingDone,
    #[serde(rename = "reset-before-token")]
    ResetBeforeToken,
    #[serde(rename = "reset-after-token")]
    ResetAfterToken,
    #[serde(rename = "hold-first-token")]
    HoldFirstToken,
    #[serde(rename = "midstream-idle")]
    MidstreamIdle,
    #[serde(rename = "hold-headers")]
    HoldHeaders,
    #[serde(rename = "endless-stream")]
    EndlessStream,
    #[serde(rename = "malformed-sse")]
    MalformedSse,
}

impl UpstreamFault {
    const fn is_http_status_fault(self) -> bool {
        matches!(self, Self::Http429 | Self::Http500 | Self::Http503)
    }

    const fn is_hold_headers(self) -> bool {
        matches!(self, Self::HoldHeaders)
    }
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BenchmarkSettings {
    first_token_delay_ms: u64,
    token_interval_ms: u64,
    token_count: usize,
    /// Pack this many SSE token events into each upstream write frame.
    /// Default 1. The `stream-bursty` lane uses 8 so proxies must frame by
    /// event boundaries rather than treating one TCP/HTTP chunk as one token.
    tokens_per_write: usize,
    /// Split each SSE event (`data: …\n\n`) across this many write frames.
    /// Default 1. The `stream-fragmented` lane uses >1 so clients must reassemble
    /// incrementally. Mutually exclusive with `tokens_per_write > 1`.
    fragments_per_event: usize,
    /// Emit UTF-8 token text, multiline `data:` lines, and prefer mid-codepoint
    /// write cuts when `fragments_per_event > 1` (`stream-unicode`).
    unicode_payload: bool,
    /// Exact assistant/completion text byte length for `stream=false`
    /// (`json-large`). Omit or null for the default token-join body.
    #[serde(default)]
    response_bytes: Option<usize>,
    fault: Option<UpstreamFault>,
}

impl Default for BenchmarkSettings {
    fn default() -> Self {
        Self {
            first_token_delay_ms: 50,
            token_interval_ms: 10,
            token_count: 32,
            tokens_per_write: 1,
            fragments_per_event: 1,
            unicode_payload: false,
            response_bytes: None,
            fault: None,
        }
    }
}

impl BenchmarkSettings {
    fn validate(self) -> Result<Self, String> {
        if self.token_count == 0 || self.token_count > MAX_TOKENS {
            return Err(format!(
                "benchmark.token_count must be between 1 and {MAX_TOKENS}"
            ));
        }
        if self.tokens_per_write == 0 || self.tokens_per_write > self.token_count {
            return Err(
                "benchmark.tokens_per_write must be between 1 and token_count".to_string(),
            );
        }
        if self.fragments_per_event == 0 || self.fragments_per_event > MAX_FRAGMENTS_PER_EVENT {
            return Err(format!(
                "benchmark.fragments_per_event must be between 1 and {MAX_FRAGMENTS_PER_EVENT}"
            ));
        }
        if self.tokens_per_write > 1 && self.fragments_per_event > 1 {
            return Err(
                "benchmark.tokens_per_write and fragments_per_event cannot both exceed 1"
                    .to_string(),
            );
        }
        if self.unicode_payload && self.tokens_per_write > 1 {
            return Err(
                "benchmark.unicode_payload requires tokens_per_write = 1".to_string(),
            );
        }
        if self.first_token_delay_ms > MAX_DELAY_MS || self.token_interval_ms > MAX_DELAY_MS {
            return Err(format!(
                "benchmark delays must not exceed {MAX_DELAY_MS} milliseconds"
            ));
        }
        if let Some(bytes) = self.response_bytes {
            if bytes == 0 || bytes > MAX_RESPONSE_BYTES {
                return Err(format!(
                    "benchmark.response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
                ));
            }
            if self.fault.is_some() {
                return Err("benchmark.response_bytes cannot combine with fault".to_string());
            }
            if self.tokens_per_write != 1
                || self.fragments_per_event != 1
                || self.unicode_payload
            {
                return Err(
                    "benchmark.response_bytes cannot combine with SSE framing knobs".to_string(),
                );
            }
        }
        Ok(self)
    }
}

#[derive(Debug, Deserialize)]
struct CompletionRequest {
    model: String,
    #[serde(default)]
    stream: bool,
    #[serde(default)]
    benchmark: BenchmarkSettings,
}

/// Non-OpenAI SSE transport-control request (no chat/completions schema).
#[derive(Debug, Deserialize)]
struct SseTransportRequest {
    #[serde(default = "default_true")]
    stream: bool,
    /// Optional pad so body size can match OpenAI prompt lanes without OpenAI fields.
    #[serde(default)]
    pad: String,
    #[serde(default)]
    benchmark: BenchmarkSettings,
}

fn default_true() -> bool {
    true
}

fn build_tls_acceptor(cert_file: &PathBuf, key_file: &PathBuf) -> Result<TlsAcceptor, BoxError> {
    let cert_file_handle = std::fs::File::open(cert_file)
        .map_err(|error| format!("failed to open tls cert {}: {error}", cert_file.display()))?;
    let key_file_handle = std::fs::File::open(key_file)
        .map_err(|error| format!("failed to open tls key {}: {error}", key_file.display()))?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_file_handle))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("failed to parse tls cert: {error}"))?;
    if certs.is_empty() {
        return Err("tls cert contained no certificates".into());
    }
    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file_handle))
        .map_err(|error| format!("failed to parse tls key: {error}"))?
        .ok_or("tls key contained no private key")?;
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("tls protocol versions: {error}"))?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .map_err(|error| format!("invalid tls cert/key pair: {error}"))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    if args.instance_id.is_empty() || args.instance_id.len() > 64 {
        return Err("instance_id must contain between 1 and 64 bytes".into());
    }
    if args
        .instance_id
        .bytes()
        .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err("instance_id must be alphanumeric plus '-' or '_'".into());
    }
    let tls_acceptor = match (args.tls_cert.as_ref(), args.tls_key.as_ref()) {
        (None, None) => None,
        (Some(cert), Some(key)) => Some(build_tls_acceptor(cert, key)?),
        _ => {
            return Err("tls-cert and tls-key must be provided together".into());
        }
    };
    let _ = INSTANCE_ID.set(args.instance_id);
    let listener = TcpListener::bind(args.address).await?;
    println!(
        "ai benchmark upstream listening on {} instance={} tls={}",
        args.address,
        instance_id(),
        tls_acceptor.is_some()
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let serve = async {
                if let Some(acceptor) = tls_acceptor {
                    let tls_stream = acceptor.accept(stream).await?;
                    ServerBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(tls_stream), service_fn(handle_request))
                        .await
                        .map_err(|error| error.to_string())?;
                } else {
                    http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(TokioIo::new(stream), service_fn(handle_request))
                        .await
                        .map_err(|error| error.to_string())?;
                }
                Ok::<(), BoxError>(())
            };
            if let Err(error) = serve.await {
                eprintln!("ai benchmark upstream connection failed: {error}");
            }
        });
    }
}

async fn handle_request(request: Request<Incoming>) -> Result<Response<ResponseBody>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/health") => json_response(
            StatusCode::OK,
            json!({
                "status": "ok",
                "service": "a3s-ai-benchmark-upstream",
                "instance": instance_id(),
            }),
        ),
        (&Method::GET, "/benchmark/stats") => json_response(
            StatusCode::OK,
            json!({
                "streams_started": STREAMS_STARTED.load(Ordering::SeqCst),
                "streams_completed": STREAMS_COMPLETED.load(Ordering::SeqCst),
                "streams_client_cancelled": STREAMS_CLIENT_CANCELLED.load(Ordering::SeqCst),
                "instance": instance_id(),
            }),
        ),
        (&Method::POST, "/v1/chat/completions" | "/v1/completions") => {
            completion_response(request).await
        }
        (&Method::POST, "/benchmark/sse") => sse_transport_response(request).await,
        _ => json_response(
            StatusCode::NOT_FOUND,
            json!({"error": {"message": "benchmark route not found"}}),
        ),
    };
    Ok(response)
}

async fn sse_transport_response(request: Request<Incoming>) -> Response<ResponseBody> {
    let body = match http_body_util::Limited::new(request.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": {"message": format!("bounded request read failed: {error}")}}),
            );
        }
    };
    let request: SseTransportRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": format!("invalid benchmark request: {error}")}}),
            );
        }
    };
    // Pad is only for request-size parity with OpenAI lanes; content is ignored.
    let _pad_len = request.pad.len();
    let settings = match request.benchmark.validate() {
        Ok(settings) => settings,
        Err(message) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": message}}),
            );
        }
    };
    if !request.stream {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": {"message": "sse-transport requires stream=true"}}),
        );
    }
    if settings.response_bytes.is_some() {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": {"message": "benchmark.response_bytes is unsupported on /benchmark/sse"}}),
        );
    }
    match settings.fault {
        Some(fault) if fault.is_http_status_fault() => fault_response(fault),
        Some(fault) if fault.is_hold_headers() => {
            loop {
                sleep(Duration::from_secs(3600)).await;
            }
        }
        _ => streaming_response("/benchmark/sse".to_string(), "sse-transport".to_string(), settings),
    }
}

async fn completion_response(request: Request<Incoming>) -> Response<ResponseBody> {
    let path = request.uri().path().to_string();
    let body = match http_body_util::Limited::new(request.into_body(), MAX_REQUEST_BYTES)
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(error) => {
            return json_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({"error": {"message": format!("bounded request read failed: {error}")}}),
            );
        }
    };
    let request: CompletionRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": format!("invalid benchmark request: {error}")}}),
            );
        }
    };
    if request.model.is_empty() || request.model.len() > 255 {
        return json_response(
            StatusCode::BAD_REQUEST,
            json!({"error": {"message": "model must contain between 1 and 255 bytes"}}),
        );
    }
    let settings = match request.benchmark.validate() {
        Ok(settings) => settings,
        Err(message) => {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": message}}),
            );
        }
    };
    if request.stream {
        if settings.response_bytes.is_some() {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": "benchmark.response_bytes requires stream=false"}}),
            );
        }
        match settings.fault {
            Some(fault) if fault.is_http_status_fault() => fault_response(fault),
            Some(fault) if fault.is_hold_headers() => {
                loop {
                    sleep(Duration::from_secs(3600)).await;
                }
            }
            _ => streaming_response(path, request.model, settings),
        }
    } else {
        if settings.fault.is_some() {
            return json_response(
                StatusCode::BAD_REQUEST,
                json!({"error": {"message": "benchmark.fault requires stream=true"}}),
            );
        }
        non_streaming_response(path, request.model, settings)
    }
}

fn fault_response(fault: UpstreamFault) -> Response<ResponseBody> {
    let (status, message) = match fault {
        UpstreamFault::Http429 => (StatusCode::TOO_MANY_REQUESTS, "benchmark injected http-429"),
        UpstreamFault::Http500 => (StatusCode::INTERNAL_SERVER_ERROR, "benchmark injected http-500"),
        UpstreamFault::Http503 => (
            StatusCode::SERVICE_UNAVAILABLE,
            "benchmark injected http-503",
        ),
        UpstreamFault::MissingDone
        | UpstreamFault::ResetBeforeToken
        | UpstreamFault::ResetAfterToken
        | UpstreamFault::HoldFirstToken
        | UpstreamFault::MidstreamIdle
        | UpstreamFault::HoldHeaders
        | UpstreamFault::EndlessStream
        | UpstreamFault::MalformedSse => {
            unreachable!("non-HTTP status faults use streaming or hold-headers paths")
        }
    };
    let mut response = json_response(
        status,
        json!({"error": {"message": message, "type": "benchmark_fault"}}),
    );
    if matches!(fault, UpstreamFault::Http429) {
        response.headers_mut().insert(
            hyper::header::RETRY_AFTER,
            hyper::header::HeaderValue::from_static("1"),
        );
    }
    response
}

fn streaming_response(
    path: String,
    model: String,
    settings: BenchmarkSettings,
) -> Response<ResponseBody> {
    STREAMS_STARTED.fetch_add(1, Ordering::SeqCst);
    let finished = Arc::new(AtomicBool::new(false));
    let probe = ClientDisconnectProbe {
        finished: finished.clone(),
    };
    let events = stream::unfold((0_usize, 0_usize, probe), move |(sequence, frag_idx, probe)| {
        let path = path.clone();
        let model = model.clone();
        let finished = finished.clone();
        async move {
            let fault = settings.fault;
            if matches!(fault, Some(UpstreamFault::ResetBeforeToken)) {
                return None;
            }
            if matches!(fault, Some(UpstreamFault::ResetAfterToken)) && sequence >= 1 {
                return None;
            }
            // Transparent-relay probe: one well-framed SSE event with invalid JSON,
            // then end the body. The proxy must forward bytes without repairing them.
            if matches!(fault, Some(UpstreamFault::MalformedSse)) {
                if sequence == 0 && frag_idx == 0 {
                    return Some((
                        Ok::<_, Infallible>(Frame::data(Bytes::from_static(
                            b"data: {not-json\n\n",
                        ))),
                        (sequence + 1, 0, probe),
                    ));
                }
                return None;
            }
            if sequence > settings.token_count
                && !matches!(fault, Some(UpstreamFault::EndlessStream))
            {
                return None;
            }
            if sequence == settings.token_count
                && !matches!(fault, Some(UpstreamFault::EndlessStream))
            {
                if matches!(fault, Some(UpstreamFault::MissingDone)) {
                    return None;
                }
                if frag_idx == 0 {
                    finished.store(true, Ordering::SeqCst);
                    STREAMS_COMPLETED.fetch_add(1, Ordering::SeqCst);
                }
                let done = b"data: [DONE]\n\n";
                let (chunk, next_frag, event_done) =
                    take_sse_fragment(done, frag_idx, settings.fragments_per_event, false);
                let next = if event_done {
                    (sequence + 1, 0, probe)
                } else {
                    (sequence, next_frag, probe)
                };
                return Some((Ok::<_, Infallible>(Frame::data(chunk)), next));
            }
            // Idle-deadline faults: hold forever so the proxy stream_idle_timeout
            // (or nginx proxy_read_timeout) must cut the stream. The task is
            // cancelled when the connection drops.
            if frag_idx == 0 {
                if matches!(fault, Some(UpstreamFault::HoldFirstToken)) && sequence == 0 {
                    loop {
                        sleep(Duration::from_secs(3600)).await;
                    }
                }
                if matches!(fault, Some(UpstreamFault::MidstreamIdle)) && sequence == 1 {
                    loop {
                        sleep(Duration::from_secs(3600)).await;
                    }
                }
                let delay = if sequence == 0 {
                    settings.first_token_delay_ms
                } else {
                    settings.token_interval_ms
                };
                if delay != 0 {
                    sleep(Duration::from_millis(delay)).await;
                }
            }
            let per_write = settings.tokens_per_write.max(1);
            let end = (sequence + per_write).min(settings.token_count);
            let mut payload = String::new();
            for index in sequence..end {
                let event = token_event(&path, &model, index, settings.unicode_payload);
                let encoded =
                    serde_json::to_string(&event).expect("benchmark event must serialize");
                payload.push_str(&encode_sse_data(&encoded, settings.unicode_payload));
            }
            let (chunk, next_frag, event_done) = take_sse_fragment(
                payload.as_bytes(),
                frag_idx,
                settings.fragments_per_event,
                settings.unicode_payload,
            );
            let next = if event_done {
                (end, 0, probe)
            } else {
                (sequence, next_frag, probe)
            };
            Some((Ok(Frame::data(chunk)), next))
        }
    });
    let mut response = Response::new(StreamBody::new(events).boxed_unsync());
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("text/event-stream"),
    );
    response.headers_mut().insert(
        CACHE_CONTROL,
        hyper::header::HeaderValue::from_static("no-cache, no-transform"),
    );
    response.headers_mut().insert(
        "x-accel-buffering",
        hyper::header::HeaderValue::from_static("no"),
    );
    response
}

fn encode_sse_data(json: &str, multiline: bool) -> String {
    if !multiline {
        return format!("data: {json}\n\n");
    }
    // Split after the first JSON field so the load client must join multiline
    // `data:` lines before parsing (SSE multiline contract).
    if let Some(index) = json.find(',') {
        let (head, tail) = json.split_at(index + 1);
        format!("data: {head}\ndata: {}\n\n", tail.trim_start())
    } else {
        format!("data: {json}\n\n")
    }
}

/// Split one SSE event across `fragments` write frames (at least one byte each).
/// When `prefer_mid_utf8` is set, the first cut lands inside a multi-byte sequence
/// whenever the payload contains one.
fn take_sse_fragment(
    payload: &[u8],
    frag_idx: usize,
    fragments: usize,
    prefer_mid_utf8: bool,
) -> (Bytes, usize, bool) {
    if payload.is_empty() {
        return (Bytes::new(), frag_idx + 1, true);
    }
    let fragments = fragments.max(1).min(payload.len());
    if fragments == 1 {
        return (Bytes::copy_from_slice(payload), frag_idx + 1, true);
    }
    let cuts = fragment_cut_ends(payload, fragments, prefer_mid_utf8);
    let start = if frag_idx == 0 {
        0
    } else {
        cuts[frag_idx - 1]
    };
    let end = cuts[frag_idx];
    (
        Bytes::copy_from_slice(&payload[start..end]),
        frag_idx + 1,
        frag_idx + 1 >= cuts.len(),
    )
}

fn fragment_cut_ends(payload: &[u8], fragments: usize, prefer_mid_utf8: bool) -> Vec<usize> {
    let mut cuts = Vec::with_capacity(fragments);
    if prefer_mid_utf8 {
        if let Some(mid) = first_mid_utf8_cut(payload) {
            cuts.push(mid);
        }
    }
    let remaining = fragments.saturating_sub(cuts.len()).max(1);
    let start = cuts.last().copied().unwrap_or(0);
    let leftover = payload.len().saturating_sub(start);
    if leftover == 0 {
        if cuts.last().copied() != Some(payload.len()) {
            cuts.push(payload.len());
        }
        return cuts;
    }
    let chunk_size = leftover.div_ceil(remaining).max(1);
    let mut offset = start;
    while cuts.len() + 1 < fragments && offset + chunk_size < payload.len() {
        offset += chunk_size;
        cuts.push(offset);
    }
    cuts.push(payload.len());
    cuts
}

fn first_mid_utf8_cut(payload: &[u8]) -> Option<usize> {
    // Cut before a UTF-8 continuation byte so the previous frame ends mid-codepoint.
    payload
        .iter()
        .enumerate()
        .skip(1)
        .find_map(|(index, byte)| (*byte & 0xC0 == 0x80).then_some(index))
}

fn token_content(sequence: usize, unicode: bool) -> String {
    if unicode {
        format!("token-{sequence}-α-中-🚀")
    } else {
        format!("token-{sequence}")
    }
}

fn token_event(path: &str, model: &str, sequence: usize, unicode: bool) -> Value {
    let content = token_content(sequence, unicode);
    if path == "/benchmark/sse" {
        json!({
            "benchmark_sequence": sequence,
            "benchmark_instance": instance_id(),
            "content": content
        })
    } else if path == "/v1/completions" {
        json!({
            "id": "cmpl-a3s-ai-benchmark",
            "object": "text_completion",
            "created": 1_700_000_000_u64,
            "model": model,
            "benchmark_sequence": sequence,
            "benchmark_instance": instance_id(),
            "choices": [{
                "index": 0,
                "text": content,
                "logprobs": null,
                "finish_reason": null
            }]
        })
    } else {
        json!({
            "id": "chatcmpl-a3s-ai-benchmark",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000_u64,
            "model": model,
            "benchmark_sequence": sequence,
            "benchmark_instance": instance_id(),
            "choices": [{
                "index": 0,
                "delta": {"content": content},
                "finish_reason": null
            }]
        })
    }
}

fn non_streaming_response(
    path: String,
    model: String,
    settings: BenchmarkSettings,
) -> Response<ResponseBody> {
    let token_count = settings.token_count;
    let content = if let Some(bytes) = settings.response_bytes {
        "x".repeat(bytes)
    } else {
        (0..token_count)
            .map(|sequence| format!("token-{sequence}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let document = if path == "/v1/completions" {
        json!({
            "id": "cmpl-a3s-ai-benchmark",
            "object": "text_completion",
            "created": 1_700_000_000_u64,
            "model": model,
            "choices": [{"index": 0, "text": content, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": token_count, "total_tokens": token_count + 1}
        })
    } else {
        json!({
            "id": "chatcmpl-a3s-ai-benchmark",
            "object": "chat.completion",
            "created": 1_700_000_000_u64,
            "model": model,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 1, "completion_tokens": token_count, "total_tokens": token_count + 1}
        })
    };
    json_response(StatusCode::OK, document)
}

fn json_response(status: StatusCode, document: Value) -> Response<ResponseBody> {
    let mut response = Response::new(
        Full::new(Bytes::from(
            serde_json::to_vec(&document).expect("benchmark JSON must serialize"),
        ))
        .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_reject_unbounded_delays_and_token_counts() {
        assert!(BenchmarkSettings {
            token_count: 0,
            ..BenchmarkSettings::default()
        }
        .validate()
        .is_err());
        assert!(BenchmarkSettings {
            token_count: MAX_TOKENS + 1,
            ..BenchmarkSettings::default()
        }
        .validate()
        .is_err());
        assert!(BenchmarkSettings {
            first_token_delay_ms: MAX_DELAY_MS + 1,
            ..BenchmarkSettings::default()
        }
        .validate()
        .is_err());
        assert!(BenchmarkSettings {
            tokens_per_write: 2,
            fragments_per_event: 2,
            ..BenchmarkSettings::default()
        }
        .validate()
        .is_err());
        assert!(BenchmarkSettings {
            fragments_per_event: MAX_FRAGMENTS_PER_EVENT + 1,
            ..BenchmarkSettings::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn take_sse_fragment_splits_without_empty_chunks() {
        let payload = b"data: {\"benchmark_sequence\":0}\n\n";
        let mut frag = 0usize;
        let mut assembled = Vec::new();
        loop {
            let (chunk, next, done) = take_sse_fragment(payload, frag, 4, false);
            assert!(!chunk.is_empty());
            assembled.extend_from_slice(&chunk);
            if done {
                break;
            }
            frag = next;
        }
        assert_eq!(assembled.as_slice(), payload);
    }

    #[test]
    fn take_sse_fragment_can_cut_mid_utf8_codepoint() {
        let payload = "data: {\"t\":\"🚀\"}\n\n".as_bytes();
        let (first, _, done) = take_sse_fragment(payload, 0, 4, true);
        assert!(!done);
        assert!(!first.is_empty());
        // First frame ends inside the 4-byte rocket emoji when prefer_mid_utf8.
        assert!(
            first.last().is_some_and(|byte| *byte & 0x80 != 0),
            "expected a mid-UTF-8 cut on the first fragment"
        );
        let mut frag = 0usize;
        let mut assembled = Vec::new();
        loop {
            let (chunk, next, done) = take_sse_fragment(payload, frag, 4, true);
            assembled.extend_from_slice(&chunk);
            if done {
                break;
            }
            frag = next;
        }
        assert_eq!(assembled.as_slice(), payload);
        assert!(std::str::from_utf8(&assembled).is_ok());
    }

    #[test]
    fn encode_sse_data_multiline_joins_to_json() {
        let json = r#"{"benchmark_sequence":0,"x":1}"#;
        let encoded = encode_sse_data(json, true);
        assert!(encoded.starts_with("data: {\"benchmark_sequence\":0,"));
        assert!(encoded.contains("\ndata: "));
        assert!(encoded.ends_with("\n\n"));
    }

    #[test]
    fn token_events_carry_exact_monotonic_sequence() {
        let chat = token_event("/v1/chat/completions", "bench", 7, false);
        let completion = token_event("/v1/completions", "bench", 8, false);
        let transport = token_event("/benchmark/sse", "sse-transport", 3, false);
        assert_eq!(chat["benchmark_sequence"], 7);
        assert_eq!(chat["choices"][0]["delta"]["content"], "token-7");
        assert_eq!(completion["benchmark_sequence"], 8);
        assert_eq!(completion["choices"][0]["text"], "token-8");
        assert_eq!(transport["benchmark_sequence"], 3);
        assert_eq!(transport["content"], "token-3");
        assert!(transport.get("choices").is_none());
        let unicode = token_event("/v1/chat/completions", "bench", 1, true);
        assert_eq!(
            unicode["choices"][0]["delta"]["content"],
            "token-1-α-中-🚀"
        );
    }
}
