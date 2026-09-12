//! Streaming-aware OpenAI load client for reproducible AI gateway comparisons.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use futures_util::{stream, StreamExt};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONNECTION, CONTENT_TYPE};
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Barrier, Semaphore};
use tokio::time::{sleep, timeout, Instant};
use url::Url;

type BoxError = Box<dyn Error + Send + Sync>;

const MAX_TOKEN_COUNT: usize = 4_096;
const MAX_DELAY_MS: u64 = 60_000;
/// Allow building bodies at/over the Gateway OpenAI 8 MiB request ceiling.
const OPENAI_REQUEST_BODY_LIMIT: usize = 8 * 1024 * 1024;
const MAX_PROMPT_BYTES: usize = OPENAI_REQUEST_BODY_LIMIT + 1024 * 1024;

fn is_one(value: &usize) -> bool {
    *value == 1
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum Endpoint {
    Chat,
    Completions,
    /// Non-OpenAI SSE control path (`/benchmark/sse`) for transport isolation.
    SseTransport,
}

impl Endpoint {
    const fn path(self) -> &'static str {
        match self {
            Self::Chat => "/v1/chat/completions",
            Self::Completions => "/v1/completions",
            Self::SseTransport => "/benchmark/sse",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, ValueEnum, PartialEq, Eq)]
enum UpstreamFault {
    #[value(name = "http-429")]
    #[serde(rename = "http-429")]
    Http429,
    #[value(name = "http-500")]
    #[serde(rename = "http-500")]
    Http500,
    #[value(name = "http-503")]
    #[serde(rename = "http-503")]
    Http503,
    #[value(name = "missing-done")]
    #[serde(rename = "missing-done")]
    MissingDone,
    #[value(name = "reset-before-token")]
    #[serde(rename = "reset-before-token")]
    ResetBeforeToken,
    #[value(name = "reset-after-token")]
    #[serde(rename = "reset-after-token")]
    ResetAfterToken,
    #[value(name = "hold-first-token")]
    #[serde(rename = "hold-first-token")]
    HoldFirstToken,
    #[value(name = "midstream-idle")]
    #[serde(rename = "midstream-idle")]
    MidstreamIdle,
    #[value(name = "hold-headers")]
    #[serde(rename = "hold-headers")]
    HoldHeaders,
    #[value(name = "endless-stream")]
    #[serde(rename = "endless-stream")]
    EndlessStream,
    /// Well-framed SSE with invalid JSON payload; gateway must relay transparently.
    #[value(name = "malformed-sse")]
    #[serde(rename = "malformed-sse")]
    MalformedSse,
}

impl UpstreamFault {
    const fn status_code(self) -> Option<u16> {
        match self {
            Self::Http429 => Some(429),
            Self::Http500 => Some(500),
            Self::Http503 => Some(503),
            Self::MissingDone
            | Self::ResetBeforeToken
            | Self::ResetAfterToken
            | Self::HoldFirstToken
            | Self::MidstreamIdle
            | Self::HoldHeaders
            | Self::EndlessStream
            | Self::MalformedSse => None,
        }
    }

    const fn expects_stream_error(self) -> bool {
        matches!(
            self,
            Self::MissingDone
                | Self::ResetBeforeToken
                | Self::ResetAfterToken
                | Self::HoldFirstToken
                | Self::MidstreamIdle
                | Self::HoldHeaders
                | Self::EndlessStream
                | Self::MalformedSse
        )
    }

    /// Requires a successful SSE response that still fails client-side decoding.
    /// Distinguishes transparent relay from gateway-side rejection/5xx.
    const fn expects_transparent_relay(self) -> bool {
        matches!(self, Self::MalformedSse)
    }

    /// Exact token count when `Some`; `EndlessStream` uses a minimum instead.
    const fn exact_tokens(self, token_count: usize) -> Option<usize> {
        match self {
            Self::Http429
            | Self::Http500
            | Self::Http503
            | Self::ResetBeforeToken
            | Self::HoldFirstToken
            | Self::HoldHeaders
            | Self::MalformedSse => Some(0),
            Self::ResetAfterToken | Self::MidstreamIdle => Some(1),
            Self::MissingDone => Some(token_count),
            Self::EndlessStream => None,
        }
    }

    const fn min_tokens(self) -> usize {
        match self {
            Self::EndlessStream => 1,
            _ => 0,
        }
    }

    const fn as_str(self) -> &'static str {
        match self {
            Self::Http429 => "http-429",
            Self::Http500 => "http-500",
            Self::Http503 => "http-503",
            Self::MissingDone => "missing-done",
            Self::ResetBeforeToken => "reset-before-token",
            Self::ResetAfterToken => "reset-after-token",
            Self::HoldFirstToken => "hold-first-token",
            Self::MidstreamIdle => "midstream-idle",
            Self::HoldHeaders => "hold-headers",
            Self::EndlessStream => "endless-stream",
            Self::MalformedSse => "malformed-sse",
        }
    }
}

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Proxy origin, for example http://127.0.0.1:18101.
    #[arg(long)]
    target: String,
    #[arg(long, value_enum, default_value_t = Endpoint::Chat)]
    endpoint: Endpoint,
    #[arg(long, default_value = "bench")]
    model: String,
    #[arg(long, default_value_t = 16)]
    concurrency: usize,
    #[arg(long, default_value_t = 100)]
    requests: usize,
    #[arg(long, default_value_t = 16)]
    warmup_requests: usize,
    #[arg(long, default_value_t = 32)]
    token_count: usize,
    #[arg(long, default_value_t = 50)]
    first_token_delay_ms: u64,
    #[arg(long, default_value_t = 10)]
    token_interval_ms: u64,
    /// Pack this many SSE token events into each upstream write (default 1).
    /// Used by `stream-bursty` to prove event framing under multi-event chunks.
    #[arg(long, default_value_t = 1)]
    tokens_per_write: usize,
    /// Split each SSE event across this many upstream write frames (default 1).
    /// Used by `stream-fragmented` so clients must reassemble incrementally.
    #[arg(long, default_value_t = 1)]
    fragments_per_event: usize,
    /// Request UTF-8 token text, multiline SSE `data:` lines, and mid-codepoint
    /// write cuts (with `--fragments-per-event`). Used by `stream-unicode`.
    #[arg(long, default_value_t = false)]
    unicode_payload: bool,
    #[arg(long, default_value_t = 128)]
    prompt_bytes: usize,
    /// Pad the prompt so the serialized JSON body is exactly this many bytes.
    /// Used by `prompt-limit` / `prompt-over-limit` against the 8 MiB ceiling.
    #[arg(long)]
    target_body_bytes: Option<usize>,
    /// Advertise this `Content-Length` while sending a small JSON body. Used by
    /// `prompt-over-limit` so the proxy can reject before an 8 MiB upload.
    /// Requires `--accept-http-status` / `--require-all-rejections`.
    #[arg(long)]
    declare_content_length: Option<usize>,
    /// Split the request body across this many `Transfer-Encoding: chunked`
    /// frames (requires >= 2). Used by `chunked-upload`.
    #[arg(long)]
    chunked_upload_frames: Option<usize>,
    #[arg(long, default_value_t = 120)]
    request_timeout_seconds: u64,
    /// Request a non-streaming JSON completion (`stream=false`). Used by
    /// `json-short`; mutually exclusive with SSE framing and cancel/fault lanes.
    #[arg(long, default_value_t = false)]
    no_stream: bool,
    /// Exact assistant/completion content byte length for `--no-stream`
    /// (`json-large`). Upstream pads with `x` to this size.
    #[arg(long)]
    response_bytes: Option<usize>,
    /// Alternate long streams: every Nth measured request uses
    /// `--long-token-count` instead of `--token-count` (`mixed-short-long`).
    #[arg(long)]
    long_every: Option<usize>,
    /// Token count for long streams when `--long-every` is set.
    #[arg(long)]
    long_token_count: Option<usize>,
    /// Open-loop Poisson mean arrival rate (requests/second). Requires
    /// `--arrival-seed`. Replaces closed-loop worker pull with scheduled starts.
    #[arg(long)]
    poisson_arrival_rps: Option<f64>,
    /// Seed for Poisson inter-arrival sampling. Required with
    /// `--poisson-arrival-rps`; published beside the intended schedule.
    #[arg(long)]
    arrival_seed: Option<u64>,
    #[arg(long)]
    api_key: Option<String>,
    /// When set with `--api-key` and `--accept-http-status`, omit the API key
    /// header on request indices where `request_index % N == 0` so one batch
    /// mixes admitted streams with intentional auth rejections (api-key-auth).
    #[arg(long)]
    omit_api_key_every: Option<usize>,
    #[arg(long, default_value = "unspecified")]
    product: String,
    #[arg(long, default_value_t = 1)]
    trial: usize,
    #[arg(long)]
    output: PathBuf,
    /// Close the client after this many validated tokens (0 = before the first
    /// token). Omit to require a complete `[DONE]` stream.
    #[arg(long)]
    disconnect_after_tokens: Option<usize>,
    /// Sleep this many milliseconds after each validated token before reading
    /// further. Used by the `slow-reader` backpressure lane; omit for full-speed
    /// consumption.
    #[arg(long)]
    read_delay_ms: Option<u64>,
    /// After this many validated tokens, pause reading once for `--stall-ms`
    /// before continuing. Used by the `stalled-reader` idle lane; requires
    /// `--stall-ms`.
    #[arg(long)]
    stall_after_tokens: Option<usize>,
    /// Duration of the single mid-stream read stall. Requires
    /// `--stall-after-tokens`.
    #[arg(long)]
    stall_ms: Option<u64>,
    /// Inject a deterministic upstream fault via `benchmark.fault`. HTTP status
    /// faults expect that status; stream-truncation faults expect an incomplete
    /// SSE outcome. Warmup stays healthy.
    #[arg(long, value_enum)]
    upstream_fault: Option<UpstreamFault>,
    /// Expect a proxy-level failure before a successful SSE body (connect
    /// refused / upstream unreachable mapped by the proxy). Mutually exclusive
    /// with `--upstream-fault`. Warmup must be zero.
    #[arg(long, default_value_t = false)]
    expect_proxy_error: bool,
    /// Treat this HTTP status as an intentional admission rejection (e.g. 429
    /// from rate-limit) while still accepting complete SSE streams in the same
    /// batch. Mutually exclusive with `--upstream-fault` / `--expect-proxy-error`.
    /// Warmup must be zero. The measured batch must include at least one
    /// rejection and at least one admitted stream.
    #[arg(long)]
    accept_http_status: Option<u16>,
    /// With `--accept-http-status`, require every measured request to be that
    /// rejection (no admits). Used by `prompt-over-limit`.
    #[arg(long, default_value_t = false)]
    require_all_rejections: bool,
    /// Send a unique `Idempotency-Key` per request so POST streams become
    /// replayable under Gateway retry middleware (no-replay-after-token temptation).
    #[arg(long, default_value_t = false)]
    send_idempotency_key: bool,
    /// Disable HTTP keep-alive reuse (`Connection: close` + idle pool size 0).
    /// Used by `transport-churn`; omit for keep-alive reuse (`transport-keepalive`).
    #[arg(long, default_value_t = false)]
    force_connection_close: bool,
    /// Accept invalid TLS certificates (self-signed AI TLS fixtures).
    #[arg(long, default_value_t = false)]
    insecure_tls: bool,
    /// Prefer HTTP/2 (ALPN over HTTPS). Requires `--insecure-tls` for the
    /// checked-in self-signed TLS fixture lanes.
    #[arg(long, default_value_t = false)]
    http2: bool,
}

#[derive(Debug, Clone, Serialize)]
struct Scenario {
    endpoint: Endpoint,
    model: String,
    concurrency: usize,
    requests: usize,
    token_count: usize,
    first_token_delay_ms: u64,
    token_interval_ms: u64,
    #[serde(skip_serializing_if = "is_one")]
    tokens_per_write: usize,
    #[serde(skip_serializing_if = "is_one")]
    fragments_per_event: usize,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    unicode_payload: bool,
    prompt_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_body_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    declare_content_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    chunked_upload_frames: Option<usize>,
    request_timeout_seconds: u64,
    /// When false, measure a complete non-streaming JSON body (no SSE).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    no_stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    long_every: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    long_token_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    poisson_arrival_rps: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arrival_seed: Option<u64>,
    /// Intended open-loop start offsets (ms from batch epoch). Published so
    /// trials can be audited against the seeded Poisson schedule.
    #[serde(skip_serializing_if = "Option::is_none")]
    arrival_offsets_ms: Option<Vec<u64>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disconnect_after_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    read_delay_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stall_after_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stall_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_fault: Option<UpstreamFault>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expect_http_status: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    expect_stream_error: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    expect_proxy_error: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    accept_http_status: Option<u16>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    require_all_rejections: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    omit_api_key_every: Option<usize>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    send_idempotency_key: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    force_connection_close: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    insecure_tls: bool,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    http2: bool,
}

#[derive(Debug)]
struct RequestContext {
    url: String,
    scenario: Scenario,
    api_key: Option<String>,
    omit_api_key_every: Option<usize>,
    send_idempotency_key: bool,
    /// Warmup always completes the full stream at full read speed even when the
    /// measured batch exercises intentional cancellation, slow reading, or a
    /// mid-stream stall.
    allow_disconnect: bool,
    apply_read_delay: bool,
    apply_stall: bool,
    apply_upstream_fault: bool,
    apply_proxy_error: bool,
    apply_accept_http_status: bool,
}

#[derive(Debug, Serialize)]
struct StreamObservation {
    ttft_us: Option<u64>,
    e2e_us: u64,
    tpot_us: Option<u64>,
    itl_us: Vec<u64>,
    tokens: usize,
    cancelled: bool,
    faulted: bool,
    http_status: Option<u16>,
    instance: Option<String>,
}

#[derive(Debug, Serialize)]
struct Distribution {
    samples: usize,
    min_us: u64,
    mean_us: f64,
    p50_us: u64,
    p90_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

#[derive(Debug, Serialize)]
struct TrialMetrics {
    schema_version: &'static str,
    generated_at: String,
    product: String,
    trial: usize,
    target: String,
    scenario: Scenario,
    warmup_requests: usize,
    completed_requests: usize,
    failed_requests: usize,
    success_rate: f64,
    completed_tokens: usize,
    intentional_cancels: usize,
    intentional_faults: usize,
    measured_seconds: f64,
    streams_per_second: f64,
    token_goodput_per_second: f64,
    ttft: Option<Distribution>,
    inter_token_latency: Option<Distribution>,
    time_per_output_token: Option<Distribution>,
    end_to_end: Option<Distribution>,
    cancellation: Option<Distribution>,
    fault: Option<Distribution>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    instance_distribution: BTreeMap<String, usize>,
    error_samples: Vec<String>,
}

#[derive(Debug)]
struct BatchResult {
    elapsed: Duration,
    observations: Vec<Result<StreamObservation, String>>,
}

#[derive(Debug, PartialEq, Eq)]
enum SseEvent {
    Data(String),
}

#[derive(Debug, Default)]
struct SseDecoder {
    buffer: Vec<u8>,
    terminal_seen: bool,
}

impl SseDecoder {
    fn push(&mut self, bytes: &[u8]) -> Result<Vec<SseEvent>, String> {
        if self.terminal_seen && bytes.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err("received bytes after the terminal SSE marker".to_string());
        }
        self.buffer.extend_from_slice(bytes);
        let mut events = Vec::new();
        while let Some((index, boundary_length)) = find_event_boundary(&self.buffer) {
            let encoded = self.buffer[..index].to_vec();
            self.buffer.drain(..index + boundary_length);
            let event = std::str::from_utf8(&encoded)
                .map_err(|error| format!("SSE event is not valid UTF-8: {error}"))?;
            let mut data = Vec::new();
            for line in event.lines() {
                let line = line.trim_end_matches('\r');
                if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value));
                }
            }
            if data.is_empty() {
                continue;
            }
            let value = data.join("\n");
            if self.terminal_seen {
                return Err("received an SSE event after the terminal marker".to_string());
            }
            if value == "[DONE]" {
                self.terminal_seen = true;
            }
            events.push(SseEvent::Data(value));
        }
        Ok(events)
    }

    fn finish(self) -> Result<(), String> {
        if self.buffer.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err("stream ended with an incomplete SSE event".to_string());
        }
        if !self.terminal_seen {
            return Err("stream ended without exactly one [DONE] marker".to_string());
        }
        Ok(())
    }

    fn finish_without_terminal(self) -> Result<(), String> {
        if self.buffer.iter().any(|byte| !byte.is_ascii_whitespace()) {
            return Err("stream ended with an incomplete SSE event".to_string());
        }
        if self.terminal_seen {
            return Err("stream ended with an unexpected [DONE] marker".to_string());
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    validate_args(&args)?;
    let prompt_bytes = resolve_prompt_bytes(&args)?;
    let arrival_offsets_ms = match (args.poisson_arrival_rps, args.arrival_seed) {
        (Some(rate), Some(seed)) => Some(poisson_arrival_offsets_ms(args.requests, rate, seed)),
        (None, None) => None,
        _ => unreachable!("poisson_arrival_rps and arrival_seed validated together"),
    };
    let scenario = Scenario {
        endpoint: args.endpoint,
        model: args.model.clone(),
        concurrency: args.concurrency,
        requests: args.requests,
        token_count: args.token_count,
        first_token_delay_ms: args.first_token_delay_ms,
        token_interval_ms: args.token_interval_ms,
        tokens_per_write: args.tokens_per_write,
        fragments_per_event: args.fragments_per_event,
        unicode_payload: args.unicode_payload,
        prompt_bytes,
        target_body_bytes: args.target_body_bytes,
        declare_content_length: args.declare_content_length,
        chunked_upload_frames: args.chunked_upload_frames,
        request_timeout_seconds: args.request_timeout_seconds,
        no_stream: args.no_stream,
        response_bytes: args.response_bytes,
        long_every: args.long_every,
        long_token_count: args.long_token_count,
        poisson_arrival_rps: args.poisson_arrival_rps,
        arrival_seed: args.arrival_seed,
        arrival_offsets_ms,
        disconnect_after_tokens: args.disconnect_after_tokens,
        read_delay_ms: args.read_delay_ms,
        stall_after_tokens: args.stall_after_tokens,
        stall_ms: args.stall_ms,
        upstream_fault: args.upstream_fault,
        expect_http_status: args.upstream_fault.and_then(UpstreamFault::status_code),
        expect_stream_error: args
            .upstream_fault
            .is_some_and(UpstreamFault::expects_stream_error),
        expect_proxy_error: args.expect_proxy_error,
        accept_http_status: args.accept_http_status,
        require_all_rejections: args.require_all_rejections,
        omit_api_key_every: args.omit_api_key_every,
        send_idempotency_key: args.send_idempotency_key,
        force_connection_close: args.force_connection_close,
        insecure_tls: args.insecure_tls,
        http2: args.http2,
    };
    let origin = args.target.trim_end_matches('/');
    let measured_context = Arc::new(RequestContext {
        url: format!("{origin}{}", args.endpoint.path()),
        scenario: scenario.clone(),
        api_key: args.api_key.clone(),
        omit_api_key_every: args.omit_api_key_every,
        send_idempotency_key: args.send_idempotency_key,
        allow_disconnect: true,
        apply_read_delay: true,
        apply_stall: true,
        apply_upstream_fault: true,
        apply_proxy_error: true,
        apply_accept_http_status: true,
    });
    let pool_idle = if args.force_connection_close {
        0
    } else {
        args.concurrency
    };
    let mut client_builder = reqwest::Client::builder()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(pool_idle);
    if args.insecure_tls {
        client_builder = client_builder.danger_accept_invalid_certs(true);
    }
    if args.http2 {
        // Allow HTTP/2 via ALPN on HTTPS. Do not force prior knowledge (h2c).
    } else {
        client_builder = client_builder.http1_only();
    }
    let client = client_builder.build()?;

    if args.warmup_requests != 0 {
        let mut warmup_scenario = scenario.clone();
        // Mixed short/long is a measured-batch fairness lane; warmup stays short.
        warmup_scenario.long_every = None;
        warmup_scenario.long_token_count = None;
        // Open-loop Poisson is measured-batch only; warmup stays closed-loop.
        warmup_scenario.poisson_arrival_rps = None;
        warmup_scenario.arrival_seed = None;
        warmup_scenario.arrival_offsets_ms = None;
        let warmup_context = Arc::new(RequestContext {
            url: measured_context.url.clone(),
            scenario: warmup_scenario,
            api_key: args.api_key.clone(),
            omit_api_key_every: None,
            send_idempotency_key: args.send_idempotency_key,
            allow_disconnect: false,
            apply_read_delay: false,
            apply_stall: false,
            apply_upstream_fault: false,
            apply_proxy_error: false,
            apply_accept_http_status: false,
        });
        let warmup = execute_batch(
            client.clone(),
            warmup_context,
            args.warmup_requests,
            args.concurrency,
        )
        .await;
        if let Some(error) = warmup.observations.into_iter().find_map(Result::err) {
            return Err(format!("warmup stream failed: {error}").into());
        }
    }

    let batch = execute_batch(client, measured_context, args.requests, args.concurrency).await;
    let metrics = summarize_trial(&args, scenario, batch);
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_vec_pretty(&metrics)?)?;
    println!("{}", serde_json::to_string(&metrics)?);
    if metrics.failed_requests != 0 {
        return Err(format!(
            "{} of {} measured streams failed",
            metrics.failed_requests, args.requests
        )
        .into());
    }
    if !metrics.error_samples.is_empty() {
        return Err(format!(
            "trial reported {} error samples: {}",
            metrics.error_samples.len(),
            metrics.error_samples.first().cloned().unwrap_or_default()
        )
        .into());
    }
    if args.accept_http_status.is_some() {
        let admitted = metrics
            .completed_requests
            .saturating_sub(metrics.intentional_faults)
            .saturating_sub(metrics.intentional_cancels);
        if metrics.intentional_faults == 0 {
            return Err(
                "accept_http_status lane requires at least one intentional rejection".into(),
            );
        }
        if args.require_all_rejections {
            if admitted != 0 {
                return Err("require_all_rejections lane must not admit any streams".into());
            }
            if metrics.intentional_faults != args.requests {
                return Err(
                    "require_all_rejections lane requires every measured request to reject".into(),
                );
            }
        } else if admitted == 0 {
            return Err("accept_http_status lane requires at least one admitted stream".into());
        }
    }
    Ok(())
}

fn resolve_prompt_bytes(args: &Args) -> Result<usize, BoxError> {
    let Some(target) = args.target_body_bytes else {
        return Ok(args.prompt_bytes);
    };
    let sample = serialize_request_body(args, 1)?;
    let overhead = sample.len().saturating_sub(1);
    if target <= overhead {
        return Err(format!(
            "target_body_bytes {target} is too small for the JSON envelope ({overhead} bytes)"
        )
        .into());
    }
    let prompt_bytes = target - overhead;
    if prompt_bytes > MAX_PROMPT_BYTES {
        return Err(format!("resolved prompt bytes must not exceed {MAX_PROMPT_BYTES}").into());
    }
    let exact = serialize_request_body(args, prompt_bytes)?;
    if exact.len() != target {
        return Err(format!(
            "failed to hit target_body_bytes {target}: got {}",
            exact.len()
        )
        .into());
    }
    Ok(prompt_bytes)
}

fn serialize_request_body(args: &Args, prompt_bytes: usize) -> Result<Vec<u8>, BoxError> {
    let prompt = "p".repeat(prompt_bytes);
    let mut benchmark = json!({
        "first_token_delay_ms": args.first_token_delay_ms,
        "token_interval_ms": args.token_interval_ms,
        "token_count": args.token_count
    });
    if args.tokens_per_write != 1 {
        benchmark["tokens_per_write"] = json!(args.tokens_per_write);
    }
    if args.fragments_per_event != 1 {
        benchmark["fragments_per_event"] = json!(args.fragments_per_event);
    }
    if args.unicode_payload {
        benchmark["unicode_payload"] = json!(true);
    }
    let stream = !args.no_stream;
    let body = match args.endpoint {
        Endpoint::Chat => json!({
            "model": args.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": stream,
            "benchmark": benchmark
        }),
        Endpoint::Completions => json!({
            "model": args.model,
            "prompt": prompt,
            "stream": stream,
            "benchmark": benchmark
        }),
        Endpoint::SseTransport => json!({
            "stream": stream,
            "pad": prompt,
            "benchmark": benchmark
        }),
    };
    Ok(serde_json::to_vec(&body)?)
}

fn validate_args(args: &Args) -> Result<(), BoxError> {
    if args.concurrency == 0
        || args.requests == 0
        || args.token_count == 0
        || args.prompt_bytes == 0
        || args.request_timeout_seconds == 0
    {
        return Err(
            "concurrency, requests, token count, prompt bytes, and timeout must be positive".into(),
        );
    }
    if args.model.is_empty() || args.model.len() > 255 {
        return Err("model must contain between 1 and 255 bytes".into());
    }
    if args.token_count > MAX_TOKEN_COUNT {
        return Err(format!("token count must not exceed {MAX_TOKEN_COUNT}").into());
    }
    if args.tokens_per_write == 0 || args.tokens_per_write > args.token_count {
        return Err("tokens_per_write must be between 1 and token_count".into());
    }
    if args.fragments_per_event == 0 || args.fragments_per_event > 32 {
        return Err("fragments_per_event must be between 1 and 32".into());
    }
    if args.tokens_per_write > 1 && args.fragments_per_event > 1 {
        return Err("tokens_per_write and fragments_per_event cannot both exceed 1".into());
    }
    if args.unicode_payload && args.tokens_per_write > 1 {
        return Err("unicode_payload requires tokens_per_write = 1".into());
    }
    if args.unicode_payload && args.fragments_per_event < 2 {
        return Err("unicode_payload requires fragments_per_event >= 2 for mid-codepoint cuts".into());
    }
    if args.first_token_delay_ms > MAX_DELAY_MS || args.token_interval_ms > MAX_DELAY_MS {
        return Err(format!("token delays must not exceed {MAX_DELAY_MS} milliseconds").into());
    }
    if args.prompt_bytes > MAX_PROMPT_BYTES {
        return Err(format!("prompt bytes must not exceed {MAX_PROMPT_BYTES}").into());
    }
    if let Some(target) = args.target_body_bytes {
        if target == 0 || target > MAX_PROMPT_BYTES + 4096 {
            return Err(format!(
                "target_body_bytes must be between 1 and {}",
                MAX_PROMPT_BYTES + 4096
            )
            .into());
        }
        if args.unicode_payload {
            return Err("target_body_bytes cannot combine with unicode_payload".into());
        }
        if args.declare_content_length.is_some() {
            return Err("target_body_bytes cannot combine with declare_content_length".into());
        }
        if args.chunked_upload_frames.is_some() {
            return Err("target_body_bytes cannot combine with chunked_upload_frames".into());
        }
    }
    if let Some(declared) = args.declare_content_length {
        if declared <= OPENAI_REQUEST_BODY_LIMIT {
            return Err(format!(
                "declare_content_length must exceed {OPENAI_REQUEST_BODY_LIMIT}"
            )
            .into());
        }
        if args.accept_http_status.is_none() || !args.require_all_rejections {
            return Err(
                "declare_content_length requires --accept-http-status and --require-all-rejections"
                    .into(),
            );
        }
        if args.upstream_fault.is_some() || args.expect_proxy_error {
            return Err(
                "declare_content_length cannot combine with upstream_fault or expect_proxy_error"
                    .into(),
            );
        }
        if args.chunked_upload_frames.is_some() {
            return Err("declare_content_length cannot combine with chunked_upload_frames".into());
        }
    }
    if let Some(frames) = args.chunked_upload_frames {
        if frames < 2 || frames > 256 {
            return Err("chunked_upload_frames must be between 2 and 256".into());
        }
        if args.no_stream {
            return Err("chunked_upload_frames cannot combine with no_stream".into());
        }
    }
    if args.require_all_rejections && args.accept_http_status.is_none() {
        return Err("require_all_rejections requires --accept-http-status".into());
    }
    if args.no_stream {
        if matches!(args.endpoint, Endpoint::SseTransport) {
            return Err("sse-transport endpoint requires streaming (do not pass --no-stream)".into());
        }
        if args.tokens_per_write != 1
            || args.fragments_per_event != 1
            || args.unicode_payload
            || args.disconnect_after_tokens.is_some()
            || args.read_delay_ms.is_some()
            || args.stall_after_tokens.is_some()
            || args.upstream_fault.is_some()
            || args.expect_proxy_error
            || args.accept_http_status.is_some()
            || args.declare_content_length.is_some()
            || args.target_body_bytes.is_some()
            || args.send_idempotency_key
        {
            return Err(
                "no_stream cannot combine with SSE framing, cancel, fault, auth-mix, or body-ceiling lanes"
                    .into(),
            );
        }
        if args.first_token_delay_ms != 0 || args.token_interval_ms != 0 {
            return Err("no_stream requires first_token_delay_ms=0 and token_interval_ms=0".into());
        }
    }
    if let Some(bytes) = args.response_bytes {
        if !args.no_stream {
            return Err("response_bytes requires --no-stream".into());
        }
        if bytes == 0 || bytes > OPENAI_REQUEST_BODY_LIMIT {
            return Err(format!(
                "response_bytes must be between 1 and {OPENAI_REQUEST_BODY_LIMIT}"
            )
            .into());
        }
    }
    match (args.long_every, args.long_token_count) {
        (None, None) => {}
        (Some(every), Some(long_tokens)) => {
            if every < 2 {
                return Err("long_every must be at least 2".into());
            }
            if long_tokens <= args.token_count {
                return Err("long_token_count must exceed token_count".into());
            }
            if long_tokens > MAX_TOKEN_COUNT {
                return Err(format!("long_token_count must not exceed {MAX_TOKEN_COUNT}").into());
            }
            if args.requests < every {
                return Err("long_every requires requests >= long_every so both classes exist".into());
            }
            if args.no_stream
                || args.disconnect_after_tokens.is_some()
                || args.read_delay_ms.is_some()
                || args.stall_after_tokens.is_some()
                || args.upstream_fault.is_some()
                || args.expect_proxy_error
                || args.accept_http_status.is_some()
                || args.declare_content_length.is_some()
                || args.target_body_bytes.is_some()
                || args.response_bytes.is_some()
                || args.tokens_per_write != 1
                || args.fragments_per_event != 1
                || args.unicode_payload
            {
                return Err(
                    "long_every/long_token_count cannot combine with other injected or framing lanes"
                        .into(),
                );
            }
        }
        _ => {
            return Err("long_every and long_token_count must be set together".into());
        }
    }
    match (args.poisson_arrival_rps, args.arrival_seed) {
        (None, None) => {}
        (Some(rate), Some(_)) => {
            if !(rate.is_finite() && rate > 0.0 && rate <= 10_000.0) {
                return Err("poisson_arrival_rps must be finite and in (0, 10000]".into());
            }
            if args.requests < 2 {
                return Err("poisson_arrival_rps requires requests >= 2".into());
            }
            if args.no_stream
                || args.disconnect_after_tokens.is_some()
                || args.read_delay_ms.is_some()
                || args.stall_after_tokens.is_some()
                || args.upstream_fault.is_some()
                || args.expect_proxy_error
                || args.accept_http_status.is_some()
                || args.declare_content_length.is_some()
                || args.target_body_bytes.is_some()
                || args.response_bytes.is_some()
                || args.long_every.is_some()
            {
                return Err(
                    "poisson_arrival_rps cannot combine with injected, body-ceiling, or mixed lanes"
                        .into(),
                );
            }
        }
        _ => {
            return Err("poisson_arrival_rps and arrival_seed must be set together".into());
        }
    }
    let url = reqwest::Url::parse(&args.target)?;
    if !matches!(url.scheme(), "http" | "https") || url.cannot_be_a_base() {
        return Err("target must be an HTTP(S) origin".into());
    }
    if args.http2 {
        if url.scheme() != "https" {
            return Err("http2 requires an https target (TLS ALPN)".into());
        }
        if !args.insecure_tls {
            return Err("http2 AI TLS lanes require --insecure-tls for the self-signed fixture".into());
        }
    }
    if args.insecure_tls && url.scheme() != "https" {
        return Err("insecure_tls requires an https target".into());
    }
    if (args.http2 || args.insecure_tls)
        && (args.declare_content_length.is_some() || args.chunked_upload_frames.is_some())
    {
        return Err("TLS/http2 lanes cannot combine with raw declared-length or chunked-upload helpers".into());
    }
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("target must not contain credentials, a path, query, or fragment".into());
    }
    if args.product.is_empty() || args.trial == 0 {
        return Err("product must be non-empty and trial must be positive".into());
    }
    if let Some(disconnect_after) = args.disconnect_after_tokens {
        if disconnect_after > args.token_count {
            return Err(
                "disconnect_after_tokens must be less than or equal to token_count".into(),
            );
        }
    }
    if let Some(read_delay_ms) = args.read_delay_ms {
        if read_delay_ms == 0 || read_delay_ms > MAX_DELAY_MS {
            return Err(format!(
                "read_delay_ms must be between 1 and {MAX_DELAY_MS} milliseconds"
            )
            .into());
        }
        if args.disconnect_after_tokens.is_some() {
            return Err("read_delay_ms cannot combine with disconnect_after_tokens".into());
        }
    }
    match (args.stall_after_tokens, args.stall_ms) {
        (None, None) => {}
        (Some(after), Some(stall_ms)) => {
            if after == 0 || after >= args.token_count {
                return Err(
                    "stall_after_tokens must be between 1 and token_count - 1".into(),
                );
            }
            if stall_ms == 0 || stall_ms > MAX_DELAY_MS {
                return Err(format!(
                    "stall_ms must be between 1 and {MAX_DELAY_MS} milliseconds"
                )
                .into());
            }
            if args.disconnect_after_tokens.is_some() {
                return Err("stall cannot combine with disconnect_after_tokens".into());
            }
            if args.read_delay_ms.is_some() {
                return Err("stall cannot combine with read_delay_ms".into());
            }
        }
        _ => {
            return Err("stall_after_tokens and stall_ms must be set together".into());
        }
    }
    if let Some(fault) = args.upstream_fault {
        if args.disconnect_after_tokens.is_some()
            || args.read_delay_ms.is_some()
            || args.stall_after_tokens.is_some()
        {
            return Err(format!(
                "upstream_fault={} cannot combine with disconnect, read-delay, or stall lanes",
                fault.as_str()
            )
            .into());
        }
        if matches!(fault, UpstreamFault::ResetAfterToken) && args.token_count < 1 {
            return Err("reset-after-token requires token_count >= 1".into());
        }
        if matches!(fault, UpstreamFault::MissingDone) && args.token_count < 1 {
            return Err("missing-done requires token_count >= 1".into());
        }
        if matches!(fault, UpstreamFault::MidstreamIdle) && args.token_count < 2 {
            return Err("midstream-idle requires token_count >= 2".into());
        }
        if matches!(fault, UpstreamFault::EndlessStream) && args.token_count < 1 {
            return Err("endless-stream requires token_count >= 1".into());
        }
    }
    if args.expect_proxy_error {
        if args.upstream_fault.is_some() {
            return Err("expect_proxy_error cannot combine with upstream_fault".into());
        }
        if args.disconnect_after_tokens.is_some()
            || args.read_delay_ms.is_some()
            || args.stall_after_tokens.is_some()
        {
            return Err(
                "expect_proxy_error cannot combine with disconnect, read-delay, or stall lanes"
                    .into(),
            );
        }
        if args.warmup_requests != 0 {
            return Err("expect_proxy_error requires warmup_requests=0".into());
        }
    }
    if let Some(status) = args.accept_http_status {
        if !(400..600).contains(&status) {
            return Err("accept_http_status must be a 4xx or 5xx code".into());
        }
        if args.upstream_fault.is_some() || args.expect_proxy_error {
            return Err(
                "accept_http_status cannot combine with upstream_fault or expect_proxy_error"
                    .into(),
            );
        }
        if args.disconnect_after_tokens.is_some()
            || args.read_delay_ms.is_some()
            || args.stall_after_tokens.is_some()
        {
            return Err(
                "accept_http_status cannot combine with disconnect, read-delay, or stall lanes"
                    .into(),
            );
        }
        if args.warmup_requests != 0 {
            return Err("accept_http_status requires warmup_requests=0".into());
        }
    }
    if let Some(every) = args.omit_api_key_every {
        if every < 2 {
            return Err("omit_api_key_every must be at least 2".into());
        }
        if args.api_key.is_none() {
            return Err("omit_api_key_every requires --api-key".into());
        }
        if args.accept_http_status.is_none() {
            return Err("omit_api_key_every requires --accept-http-status".into());
        }
        if args.requests < every {
            return Err(
                "omit_api_key_every requires requests >= omit_api_key_every so both outcomes exist"
                    .into(),
            );
        }
    }
    Ok(())
}

async fn execute_batch(
    client: reqwest::Client,
    context: Arc<RequestContext>,
    request_count: usize,
    concurrency: usize,
) -> BatchResult {
    if request_count == 0 {
        return BatchResult {
            elapsed: Duration::ZERO,
            observations: Vec::new(),
        };
    }
    if context.scenario.arrival_offsets_ms.is_some() {
        return execute_poisson_batch(client, context, request_count, concurrency).await;
    }
    let worker_count = concurrency.min(request_count);
    let next_request = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(worker_count + 1));
    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let client = client.clone();
        let context = context.clone();
        let next_request = next_request.clone();
        let barrier = barrier.clone();
        workers.push(tokio::spawn(async move {
            barrier.wait().await;
            let mut observations = Vec::with_capacity(request_count.div_ceil(worker_count));
            loop {
                let request_index = next_request.fetch_add(1, Ordering::Relaxed);
                if request_index >= request_count {
                    break;
                }
                observations.push(
                    timeout(
                        Duration::from_secs(context.scenario.request_timeout_seconds),
                        measure_stream(&client, &context, request_index),
                    )
                    .await
                    .map_err(|_| {
                        format!(
                            "request {request_index} exceeded {} seconds",
                            context.scenario.request_timeout_seconds
                        )
                    })
                    .and_then(|result| result),
                );
            }
            observations
        }));
    }
    let started = Instant::now();
    barrier.wait().await;
    let mut observations = Vec::with_capacity(request_count);
    for worker in workers {
        match worker.await {
            Ok(mut worker_observations) => observations.append(&mut worker_observations),
            Err(error) => observations.push(Err(format!("load worker failed: {error}"))),
        }
    }
    BatchResult {
        elapsed: started.elapsed(),
        observations,
    }
}

/// Open-loop Poisson arrivals: each request sleeps until its seeded offset, then
/// acquires a concurrency permit. Do not rename fixed-rate closed-loop as Poisson.
async fn execute_poisson_batch(
    client: reqwest::Client,
    context: Arc<RequestContext>,
    request_count: usize,
    concurrency: usize,
) -> BatchResult {
    let offsets = context
        .scenario
        .arrival_offsets_ms
        .as_ref()
        .expect("poisson batch requires arrival_offsets_ms");
    if offsets.len() != request_count {
        return BatchResult {
            elapsed: Duration::ZERO,
            observations: vec![Err(format!(
                "arrival_offsets_ms length {} != request_count {request_count}",
                offsets.len()
            ))],
        };
    }
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let epoch = Instant::now();
    let mut workers = Vec::with_capacity(request_count);
    for (request_index, &offset_ms) in offsets.iter().enumerate() {
        let client = client.clone();
        let context = context.clone();
        let semaphore = semaphore.clone();
        workers.push(tokio::spawn(async move {
            let due = epoch + Duration::from_millis(offset_ms);
            let now = Instant::now();
            if due > now {
                sleep(due - now).await;
            }
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|error| format!("request {request_index} semaphore closed: {error}"))?;
            timeout(
                Duration::from_secs(context.scenario.request_timeout_seconds),
                measure_stream(&client, &context, request_index),
            )
            .await
            .map_err(|_| {
                format!(
                    "request {request_index} exceeded {} seconds",
                    context.scenario.request_timeout_seconds
                )
            })
            .and_then(|result| result)
        }));
    }
    let mut observations = Vec::with_capacity(request_count);
    for worker in workers {
        match worker.await {
            Ok(observation) => observations.push(observation),
            Err(error) => observations.push(Err(format!("load worker failed: {error}"))),
        }
    }
    BatchResult {
        elapsed: epoch.elapsed(),
        observations,
    }
}

/// Seeded exponential inter-arrivals → cumulative start offsets (ms), first at 0.
fn poisson_arrival_offsets_ms(requests: usize, rate_rps: f64, seed: u64) -> Vec<u64> {
    let mut rng = SplitMix64::new(seed);
    let mut offsets = Vec::with_capacity(requests);
    let mut elapsed_ms = 0.0_f64;
    for _ in 0..requests {
        let u = rng.next_unit_open01();
        elapsed_ms += -u.ln() / rate_rps * 1000.0;
        offsets.push(elapsed_ms.round() as u64);
    }
    let base = offsets.first().copied().unwrap_or(0);
    for offset in &mut offsets {
        *offset = offset.saturating_sub(base);
    }
    offsets
}

/// Minimal deterministic PRNG for reproducible Poisson schedules (no extra crate).
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    /// Uniform sample in (0, 1] for exponential inter-arrival transforms.
    fn next_unit_open01(&mut self) -> f64 {
        let bits = (self.next_u64() >> 11) | 1;
        (bits as f64) / ((1u64 << 53) as f64)
    }
}

fn effective_token_count(scenario: &Scenario, request_index: usize) -> usize {
    match (scenario.long_token_count, scenario.long_every) {
        (Some(long_tokens), Some(every)) if every > 0 && request_index % every == 0 => long_tokens,
        _ => scenario.token_count,
    }
}

fn mixed_request_counts(scenario: &Scenario) -> (usize, usize, usize) {
    let Some(every) = scenario.long_every else {
        return (scenario.requests, 0, scenario.requests * scenario.token_count);
    };
    let long_tokens = scenario
        .long_token_count
        .unwrap_or(scenario.token_count);
    let long_requests = (0..scenario.requests)
        .filter(|index| index % every == 0)
        .count();
    let short_requests = scenario.requests.saturating_sub(long_requests);
    let completed_tokens =
        short_requests * scenario.token_count + long_requests * long_tokens;
    (short_requests, long_requests, completed_tokens)
}

fn chunked_request_body(payload: Vec<u8>, frames: usize) -> reqwest::Body {
    let frames = frames.max(2);
    let chunk_size = (payload.len().max(1) + frames - 1) / frames;
    let chunks = payload
        .chunks(chunk_size.max(1))
        .map(|chunk| Ok::<_, std::io::Error>(bytes::Bytes::copy_from_slice(chunk)))
        .collect::<Vec<_>>();
    reqwest::Body::wrap_stream(stream::iter(chunks))
}

/// Advertise an over-limit `Content-Length` with no body, matching product
/// entrypoint coverage: reject before reading/uploading an 8 MiB payload.
async fn measure_declared_content_length(
    context: &RequestContext,
    request_index: usize,
) -> Result<StreamObservation, String> {
    let declared = context
        .scenario
        .declare_content_length
        .expect("declare_content_length checked by caller");
    let accepted = context.scenario.accept_http_status.ok_or_else(|| {
        format!("request {request_index} declare_content_length requires accept_http_status")
    })?;
    let url = Url::parse(&context.url)
        .map_err(|error| format!("request {request_index} invalid target URL: {error}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| format!("request {request_index} target URL missing host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| format!("request {request_index} target URL missing port"))?;
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let authority = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    let omit_api_key = context.apply_accept_http_status
        && context
            .omit_api_key_every
            .is_some_and(|every| request_index % every == 0);
    let started = Instant::now();
    let timeout_budget = Duration::from_secs(context.scenario.request_timeout_seconds);
    let mut stream = timeout(timeout_budget, TcpStream::connect((host, port)))
        .await
        .map_err(|_| format!("request {request_index} connect timed out"))?
        .map_err(|error| format!("request {request_index} connect failed: {error}"))?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: {authority}\r\nContent-Type: application/json\r\nContent-Length: {declared}\r\nAccept: text/event-stream\r\nx-a3s-benchmark-request: {request_index}\r\nConnection: close\r\n"
    );
    if let Some(api_key) = &context.api_key {
        if !omit_api_key {
            request.push_str(&format!("Authorization: Bearer {api_key}\r\n"));
        }
    }
    request.push_str("\r\n");
    timeout(timeout_budget, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| format!("request {request_index} write timed out"))?
        .map_err(|error| format!("request {request_index} write failed: {error}"))?;
    let _ = stream.shutdown().await;
    let mut response = Vec::new();
    timeout(timeout_budget, stream.read_to_end(&mut response))
        .await
        .map_err(|_| format!("request {request_index} read timed out"))?
        .map_err(|error| format!("request {request_index} read failed: {error}"))?;
    let response = String::from_utf8_lossy(&response);
    let status_line = response.lines().next().unwrap_or("");
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|token| token.parse::<u16>().ok())
        .ok_or_else(|| {
            format!(
                "request {request_index} failed to parse status from {}",
                bounded_text(status_line, 128)
            )
        })?;
    if status_code == accepted {
        return Ok(StreamObservation {
            ttft_us: None,
            e2e_us: elapsed_microseconds(started.elapsed()),
            tpot_us: None,
            itl_us: Vec::new(),
            tokens: 0,
            cancelled: false,
            faulted: true,
            http_status: Some(status_code),
            instance: None,
        });
    }
    Err(format!(
        "request {request_index} unexpected HTTP {status_code} (accept={accepted}): {}",
        bounded_text(&response, 512)
    ))
}

/// Non-streaming OpenAI JSON completion: one body, E2E only (no TTFT/ITL).
async fn measure_json_completion(
    client: &reqwest::Client,
    context: &RequestContext,
    request_index: usize,
) -> Result<StreamObservation, String> {
    let prompt = "p".repeat(context.scenario.prompt_bytes);
    let mut benchmark = json!({
        "first_token_delay_ms": context.scenario.first_token_delay_ms,
        "token_interval_ms": context.scenario.token_interval_ms,
        "token_count": context.scenario.token_count
    });
    if let Some(bytes) = context.scenario.response_bytes {
        benchmark["response_bytes"] = json!(bytes);
    }
    let body = match context.scenario.endpoint {
        Endpoint::Chat => json!({
            "model": context.scenario.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": false,
            "benchmark": benchmark
        }),
        Endpoint::Completions => json!({
            "model": context.scenario.model,
            "prompt": prompt,
            "stream": false,
            "benchmark": benchmark
        }),
        Endpoint::SseTransport => {
            return Err(format!(
                "request {request_index} sse-transport does not support non-streaming JSON"
            ));
        }
    };
    let started = Instant::now();
    let mut request = client
        .post(&context.url)
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .header("x-a3s-benchmark-request", request_index.to_string())
        .json(&body);
    if context.scenario.force_connection_close {
        request = request.header(CONNECTION, "close");
    }
    if let Some(api_key) = &context.api_key {
        request = request.header(AUTHORIZATION, format!("Bearer {api_key}"));
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("request {request_index} failed before headers: {error}"))?;
    let status = response.status();
    let status_code = status.as_u16();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read error body: {error}>"));
        return Err(format!(
            "request {request_index} unexpected HTTP {status}: {}",
            bounded_text(&body, 512)
        ));
    }
    let document: serde_json::Value = response
        .json()
        .await
        .map_err(|error| format!("request {request_index} invalid JSON body: {error}"))?;
    let content = document
        .pointer("/choices/0/message/content")
        .or_else(|| document.pointer("/choices/0/text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if let Some(bytes) = context.scenario.response_bytes {
        if content.len() != bytes {
            return Err(format!(
                "request {request_index} JSON content length {} != response_bytes {bytes}",
                content.len()
            ));
        }
        if content.bytes().any(|byte| byte != b'x') {
            return Err(format!(
                "request {request_index} JSON content is not the expected pad"
            ));
        }
    } else {
        let expected = (0..context.scenario.token_count)
            .map(|sequence| format!("token-{sequence}"))
            .collect::<Vec<_>>()
            .join(" ");
        if content != expected {
            return Err(format!(
                "request {request_index} JSON content mismatch: got {}",
                bounded_text(content, 128)
            ));
        }
    }
    Ok(StreamObservation {
        ttft_us: None,
        e2e_us: elapsed_microseconds(started.elapsed()),
        tpot_us: None,
        itl_us: Vec::new(),
        tokens: context.scenario.token_count,
        cancelled: false,
        faulted: false,
        http_status: Some(status_code),
        instance: None,
    })
}

fn stream_fault_observation(
    request_index: usize,
    context: &RequestContext,
    started: Instant,
    status_code: Option<u16>,
    token_times: &[Duration],
    _read_error: Option<String>,
) -> Result<StreamObservation, String> {
    let fault = context.scenario.upstream_fault;
    let tokens_ok = match fault.map(|fault| fault.exact_tokens(context.scenario.token_count)) {
        Some(Some(exact)) => token_times.len() == exact,
        Some(None) => {
            token_times.len() >= fault.map(UpstreamFault::min_tokens).unwrap_or(1)
        }
        None => token_times.is_empty(),
    };
    if !tokens_ok {
        return Err(format!(
            "request {request_index} returned {} tokens before stream fault (fault={:?})",
            token_times.len(),
            fault.map(UpstreamFault::as_str)
        ));
    }
    let ttft_us = token_times.first().copied().map(elapsed_microseconds);
    let itl_us = token_times
        .windows(2)
        .map(|pair| elapsed_microseconds(pair[1].saturating_sub(pair[0])))
        .collect::<Vec<_>>();
    let tpot_us = (token_times.len() > 1).then(|| {
        let elapsed = token_times[token_times.len() - 1].saturating_sub(token_times[0]);
        let intervals = u128::try_from(token_times.len() - 1).unwrap_or(u128::MAX);
        u64::try_from(elapsed.as_micros() / intervals)
            .unwrap_or(u64::MAX)
            .max(1)
    });
    Ok(StreamObservation {
        ttft_us,
        e2e_us: elapsed_microseconds(started.elapsed()),
        tpot_us,
        itl_us,
        tokens: token_times.len(),
        cancelled: false,
        faulted: true,
        http_status: status_code,
        instance: None,
    })
}

async fn measure_stream(
    client: &reqwest::Client,
    context: &RequestContext,
    request_index: usize,
) -> Result<StreamObservation, String> {
    if context.scenario.declare_content_length.is_some() {
        return measure_declared_content_length(context, request_index).await;
    }
    if context.scenario.no_stream {
        return measure_json_completion(client, context, request_index).await;
    }
    let prompt = "p".repeat(context.scenario.prompt_bytes);
    let token_count = effective_token_count(&context.scenario, request_index);
    let mut benchmark = json!({
        "first_token_delay_ms": context.scenario.first_token_delay_ms,
        "token_interval_ms": context.scenario.token_interval_ms,
        "token_count": token_count
    });
    if context.scenario.tokens_per_write != 1 {
        benchmark["tokens_per_write"] = json!(context.scenario.tokens_per_write);
    }
    if context.scenario.fragments_per_event != 1 {
        benchmark["fragments_per_event"] = json!(context.scenario.fragments_per_event);
    }
    if context.scenario.unicode_payload {
        benchmark["unicode_payload"] = json!(true);
    }
    if context.apply_upstream_fault {
        if let Some(fault) = context.scenario.upstream_fault {
            benchmark["fault"] = json!(fault.as_str());
        }
    }
    let body = match context.scenario.endpoint {
        Endpoint::Chat => json!({
            "model": context.scenario.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": true,
            "benchmark": benchmark
        }),
        Endpoint::Completions => json!({
            "model": context.scenario.model,
            "prompt": prompt,
            "stream": true,
            "benchmark": benchmark
        }),
        Endpoint::SseTransport => json!({
            "stream": true,
            "pad": prompt,
            "benchmark": benchmark
        }),
    };
    let started = Instant::now();
    let mut request = client
        .post(&context.url)
        .header(ACCEPT, "text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .header("x-a3s-benchmark-request", request_index.to_string());
    if context.scenario.force_connection_close {
        request = request.header(CONNECTION, "close");
    }
    request = match context.scenario.chunked_upload_frames {
        Some(frames) => {
            let payload = serde_json::to_vec(&body).map_err(|error| {
                format!("request {request_index} failed to serialize body: {error}")
            })?;
            request.body(chunked_request_body(payload, frames))
        }
        None => request.json(&body),
    };
    let omit_api_key = context.apply_accept_http_status
        && context
            .omit_api_key_every
            .is_some_and(|every| request_index % every == 0);
    if let Some(api_key) = &context.api_key {
        if !omit_api_key {
            request = request.header(AUTHORIZATION, format!("Bearer {api_key}"));
        }
    }
    if context.send_idempotency_key {
        request = request.header("Idempotency-Key", format!("bench-{request_index}"));
    }
    let expect_proxy_error =
        context.apply_proxy_error && context.scenario.expect_proxy_error;
    let response = match request.send().await {
        Ok(response) => response,
        Err(_error) if expect_proxy_error => {
            return Ok(StreamObservation {
                ttft_us: None,
                e2e_us: elapsed_microseconds(started.elapsed()),
                tpot_us: None,
                itl_us: Vec::new(),
                tokens: 0,
                cancelled: false,
                faulted: true,
                http_status: None,
                instance: None,
            });
        }
        Err(error) => {
            return Err(format!(
                "request {request_index} failed before headers: {error}"
            ));
        }
    };
    let status = response.status();
    let status_code = status.as_u16();
    if expect_proxy_error {
        if status.is_server_error() {
            let _ = response.bytes().await;
            return Ok(StreamObservation {
                ttft_us: None,
                e2e_us: elapsed_microseconds(started.elapsed()),
                tpot_us: None,
                itl_us: Vec::new(),
                tokens: 0,
                cancelled: false,
                faulted: true,
                http_status: Some(status_code),
                instance: None,
            });
        }
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read error body: {error}>"));
        return Err(format!(
            "request {request_index} expected proxy error, got {status}: {}",
            bounded_text(&body, 512)
        ));
    }
    if let Some(expected) = context
        .apply_upstream_fault
        .then_some(context.scenario.expect_http_status)
        .flatten()
    {
        if status_code == expected {
            let _ = response.bytes().await;
            return Ok(StreamObservation {
                ttft_us: None,
                e2e_us: elapsed_microseconds(started.elapsed()),
                tpot_us: None,
                itl_us: Vec::new(),
                tokens: 0,
                cancelled: false,
                faulted: true,
                http_status: Some(status_code),
                instance: None,
            });
        }
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read error body: {error}>"));
        return Err(format!(
            "request {request_index} expected HTTP {expected}, got {status}: {}",
            bounded_text(&body, 512)
        ));
    }
    if let Some(accepted) = context
        .apply_accept_http_status
        .then_some(context.scenario.accept_http_status)
        .flatten()
    {
        if status_code == accepted {
            let _ = response.bytes().await;
            return Ok(StreamObservation {
                ttft_us: None,
                e2e_us: elapsed_microseconds(started.elapsed()),
                tpot_us: None,
                itl_us: Vec::new(),
                tokens: 0,
                cancelled: false,
                faulted: true,
                http_status: Some(status_code),
                instance: None,
            });
        }
        if !status.is_success() {
            let body = response
                .text()
                .await
                .unwrap_or_else(|error| format!("<failed to read error body: {error}>"));
            return Err(format!(
                "request {request_index} unexpected HTTP {status} (accept={accepted}): {}",
                bounded_text(&body, 512)
            ));
        }
    }
    let expect_stream_error =
        context.apply_upstream_fault && context.scenario.expect_stream_error;
    let transparent_malformed = context.apply_upstream_fault
        && context
            .scenario
            .upstream_fault
            .is_some_and(UpstreamFault::expects_transparent_relay);
    if expect_stream_error && !status.is_success() {
        if transparent_malformed {
            return Err(format!(
                "request {request_index} malformed-sse requires transparent 2xx SSE relay, got {status}"
            ));
        }
        let _ = response.bytes().await;
        return Ok(StreamObservation {
            ttft_us: None,
            e2e_us: elapsed_microseconds(started.elapsed()),
            tpot_us: None,
            itl_us: Vec::new(),
            tokens: 0,
            cancelled: false,
            faulted: true,
            http_status: Some(status_code),
            instance: None,
        });
    }
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|error| format!("<failed to read error body: {error}>"));
        return Err(format!(
            "request {request_index} returned {status}: {}",
            bounded_text(&body, 512)
        ));
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
    {
        return Err(format!(
            "request {request_index} returned non-SSE content type {content_type:?}"
        ));
    }

    let mut decoder = SseDecoder::default();
    let mut stream = response.bytes_stream();
    let mut token_times = Vec::with_capacity(token_count);
    let mut expected_sequence = 0_usize;
    let mut stream_instance: Option<String> = None;
    let mut done_at = None;
    let disconnect_after = context
        .allow_disconnect
        .then_some(context.scenario.disconnect_after_tokens)
        .flatten();
    if disconnect_after == Some(0) {
        drop(stream);
        return Ok(StreamObservation {
            ttft_us: None,
            e2e_us: elapsed_microseconds(started.elapsed()),
            tpot_us: None,
            itl_us: Vec::new(),
            tokens: 0,
            cancelled: true,
            faulted: false,
            http_status: Some(status_code),
            instance: None,
        });
    }
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) if expect_stream_error => {
                return stream_fault_observation(
                    request_index,
                    context,
                    started,
                    Some(status_code),
                    &token_times,
                    Some(format!("stream read aborted: {error}")),
                );
            }
            Err(error) => {
                return Err(format!(
                    "request {request_index} failed while reading the stream: {error}"
                ));
            }
        };
        for event in decoder.push(&chunk)? {
            let SseEvent::Data(data) = event;
            if data == "[DONE]" {
                if done_at.replace(started.elapsed()).is_some() {
                    return Err(format!(
                        "request {request_index} returned more than one [DONE] marker"
                    ));
                }
                continue;
            }
            if done_at.is_some() {
                return Err(format!(
                    "request {request_index} returned a token after [DONE]"
                ));
            }
            let document: serde_json::Value = match serde_json::from_str(&data) {
                Ok(document) => document,
                Err(_error) if transparent_malformed => {
                    return Ok(StreamObservation {
                        ttft_us: None,
                        e2e_us: elapsed_microseconds(started.elapsed()),
                        tpot_us: None,
                        itl_us: Vec::new(),
                        tokens: 0,
                        cancelled: false,
                        faulted: true,
                        http_status: Some(status_code),
                        instance: None,
                    });
                }
                Err(error) => {
                    return Err(format!(
                        "request {request_index} returned invalid token JSON: {error}"
                    ));
                }
            };
            let sequence = document
                .get("benchmark_sequence")
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                .ok_or_else(|| {
                    format!("request {request_index} token has no valid benchmark_sequence")
                })?;
            if sequence != expected_sequence {
                return Err(format!(
                    "request {request_index} token sequence {sequence} did not match {expected_sequence}"
                ));
            }
            if context.scenario.unicode_payload {
                let expected = format!("token-{sequence}-α-中-🚀");
                let actual = document
                    .pointer("/choices/0/delta/content")
                    .or_else(|| document.pointer("/choices/0/text"))
                    .or_else(|| document.get("content"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                if actual != expected {
                    return Err(format!(
                        "request {request_index} unicode token content mismatch: got {actual:?}"
                    ));
                }
            }
            if let Some(instance) = document
                .get("benchmark_instance")
                .and_then(serde_json::Value::as_str)
            {
                match stream_instance.as_deref() {
                    None => stream_instance = Some(instance.to_string()),
                    Some(existing) if existing == instance => {}
                    Some(existing) => {
                        return Err(format!(
                            "request {request_index} switched benchmark_instance from {existing} to {instance}"
                        ));
                    }
                }
            }
            expected_sequence += 1;
            token_times.push(started.elapsed());
            if disconnect_after == Some(token_times.len()) {
                drop(stream);
                let ttft_us = elapsed_microseconds(token_times[0]);
                let itl_us = token_times
                    .windows(2)
                    .map(|pair| elapsed_microseconds(pair[1].saturating_sub(pair[0])))
                    .collect::<Vec<_>>();
                let tpot_us = (token_times.len() > 1).then(|| {
                    let elapsed = token_times[token_times.len() - 1].saturating_sub(token_times[0]);
                    let intervals = u128::try_from(token_times.len() - 1).unwrap_or(u128::MAX);
                    u64::try_from(elapsed.as_micros() / intervals)
                        .unwrap_or(u64::MAX)
                        .max(1)
                });
                return Ok(StreamObservation {
                    ttft_us: Some(ttft_us),
                    e2e_us: elapsed_microseconds(started.elapsed()),
                    tpot_us,
                    itl_us,
                    tokens: token_times.len(),
                    cancelled: true,
                    faulted: false,
                    http_status: Some(status_code),
                    instance: stream_instance,
                });
            }
            if context.apply_read_delay {
                if let Some(delay_ms) = context.scenario.read_delay_ms {
                    sleep(Duration::from_millis(delay_ms)).await;
                }
            }
            if context.apply_stall
                && context.scenario.stall_after_tokens == Some(token_times.len())
            {
                if let Some(stall_ms) = context.scenario.stall_ms {
                    sleep(Duration::from_millis(stall_ms)).await;
                }
            }
        }
    }
    if disconnect_after.is_some() {
        return Err(format!(
            "request {request_index} completed before the intentional disconnect point"
        ));
    }
    if expect_stream_error {
        if done_at.is_some() {
            return Err(format!(
                "request {request_index} completed with [DONE] despite expected stream fault"
            ));
        }
        decoder.finish_without_terminal().map_err(|error| {
            format!("request {request_index} stream fault framing error: {error}")
        })?;
        return stream_fault_observation(
            request_index,
            context,
            started,
            Some(status_code),
            &token_times,
            None,
        );
    }
    decoder.finish()?;
    let done_at =
        done_at.ok_or_else(|| format!("request {request_index} completed without [DONE]"))?;
    if token_times.len() != token_count {
        return Err(format!(
            "request {request_index} returned {} tokens, expected {token_count}",
            token_times.len()
        ));
    }
    let ttft_us = elapsed_microseconds(token_times[0]);
    let e2e_us = elapsed_microseconds(done_at);
    let itl_us = token_times
        .windows(2)
        .map(|pair| elapsed_microseconds(pair[1].saturating_sub(pair[0])))
        .collect::<Vec<_>>();
    let tpot_us = (token_times.len() > 1).then(|| {
        let elapsed = token_times[token_times.len() - 1].saturating_sub(token_times[0]);
        let intervals = u128::try_from(token_times.len() - 1).unwrap_or(u128::MAX);
        u64::try_from(elapsed.as_micros() / intervals)
            .unwrap_or(u64::MAX)
            .max(1)
    });
    Ok(StreamObservation {
        ttft_us: Some(ttft_us),
        e2e_us,
        tpot_us,
        itl_us,
        tokens: token_times.len(),
        cancelled: false,
        faulted: false,
        http_status: Some(status_code),
        instance: stream_instance,
    })
}

fn summarize_trial(args: &Args, scenario: Scenario, batch: BatchResult) -> TrialMetrics {
    let mut ttft = Vec::new();
    let mut e2e = Vec::new();
    let mut tpot = Vec::new();
    let mut itl = Vec::new();
    let mut cancellation = Vec::new();
    let mut fault = Vec::new();
    let mut completed_tokens = 0_usize;
    let mut intentional_cancels = 0_usize;
    let mut intentional_faults = 0_usize;
    let mut completed_requests = 0_usize;
    let mut errors = Vec::new();
    let mut instance_distribution = BTreeMap::<String, usize>::new();
    let expect_fault =
        scenario.upstream_fault.is_some() || scenario.expect_proxy_error;
    let expect_cancel = scenario.disconnect_after_tokens.is_some();
    let accept_status = scenario.accept_http_status;
    let mixed = scenario.long_every.is_some();
    let long_tokens = scenario.long_token_count.unwrap_or(scenario.token_count);
    let (expected_short, expected_long, expected_completed_tokens) =
        mixed_request_counts(&scenario);
    let mut short_obs = 0_usize;
    let mut long_obs = 0_usize;
    for observation in batch.observations {
        match observation {
            Ok(observation) => {
                let tokens_ok = if accept_status.is_some() {
                    if observation.faulted {
                        observation.tokens == 0
                            && observation.http_status == accept_status
                    } else {
                        observation.tokens == scenario.token_count
                    }
                } else {
                    match scenario.upstream_fault {
                        Some(fault) => match fault.exact_tokens(scenario.token_count) {
                            Some(exact) => observation.tokens == exact,
                            None => observation.tokens >= fault.min_tokens(),
                        },
                        None if scenario.expect_proxy_error => observation.tokens == 0,
                        None if mixed => {
                            observation.tokens == long_tokens
                                || observation.tokens == scenario.token_count
                        }
                        None => {
                            observation.tokens
                                == scenario
                                    .disconnect_after_tokens
                                    .unwrap_or(scenario.token_count)
                        }
                    }
                };
                let cancel_ok = observation.cancelled == expect_cancel;
                let fault_ok = if accept_status.is_some() {
                    if observation.faulted {
                        observation.http_status == accept_status && observation.tokens == 0
                    } else {
                        !observation.cancelled
                    }
                } else {
                    observation.faulted == expect_fault
                };
                let status_ok = match scenario.expect_http_status {
                    Some(expected) => observation.http_status == Some(expected),
                    None if scenario.expect_proxy_error => {
                        observation.http_status.is_none()
                            || observation
                                .http_status
                                .is_some_and(|code| (500..600).contains(&code))
                    }
                    None if accept_status.is_some() => {
                        observation.http_status == accept_status
                            || observation
                                .http_status
                                .is_some_and(|code| (200..300).contains(&code))
                    }
                    None => true,
                };
                if !tokens_ok || !cancel_ok || !fault_ok || !status_ok {
                    if errors.len() < 20 {
                        errors.push(format!(
                            "stream outcome mismatch: tokens={} cancelled={} faulted={} status={:?} (expect_fault={expect_fault} cancelled={expect_cancel} status={:?})",
                            observation.tokens,
                            observation.cancelled,
                            observation.faulted,
                            observation.http_status,
                            scenario.expect_http_status
                        ));
                    }
                    continue;
                }
                if mixed {
                    if observation.tokens == long_tokens {
                        long_obs += 1;
                    } else {
                        short_obs += 1;
                    }
                }
                if let Some(instance) = observation.instance.as_ref() {
                    *instance_distribution.entry(instance.clone()).or_default() += 1;
                }
                completed_requests += 1;
                completed_tokens += observation.tokens;
                if observation.faulted {
                    intentional_faults += 1;
                    fault.push(observation.e2e_us);
                } else if observation.cancelled {
                    intentional_cancels += 1;
                    cancellation.push(observation.e2e_us);
                    if let Some(value) = observation.ttft_us {
                        ttft.push(value);
                    }
                    if let Some(value) = observation.tpot_us {
                        tpot.push(value);
                    }
                    itl.extend(observation.itl_us);
                } else {
                    e2e.push(observation.e2e_us);
                    if let Some(value) = observation.ttft_us {
                        ttft.push(value);
                    }
                    if let Some(value) = observation.tpot_us {
                        tpot.push(value);
                    }
                    itl.extend(observation.itl_us);
                }
            }
            Err(error) => {
                if errors.len() < 20 {
                    errors.push(error);
                }
            }
        }
    }
    if mixed
        && errors.is_empty()
        && (short_obs != expected_short
            || long_obs != expected_long
            || completed_tokens != expected_completed_tokens)
    {
        errors.push(format!(
            "mixed short/long mismatch: got short={short_obs} long={long_obs} tokens={completed_tokens}; expected short={expected_short} long={expected_long} tokens={expected_completed_tokens}"
        ));
    }
    let failed_requests = args.requests.saturating_sub(completed_requests);
    let measured_seconds = batch.elapsed.as_secs_f64();
    TrialMetrics {
        schema_version: "a3s.gateway.ai-comparison.trial.v1",
        generated_at: chrono::Utc::now().to_rfc3339(),
        product: args.product.clone(),
        trial: args.trial,
        target: args.target.clone(),
        scenario,
        warmup_requests: args.warmup_requests,
        completed_requests,
        failed_requests,
        success_rate: completed_requests as f64 / args.requests as f64,
        completed_tokens,
        intentional_cancels,
        intentional_faults,
        measured_seconds,
        streams_per_second: rate(completed_requests, measured_seconds),
        token_goodput_per_second: rate(completed_tokens, measured_seconds),
        ttft: Distribution::from_samples(ttft),
        inter_token_latency: Distribution::from_samples(itl),
        time_per_output_token: Distribution::from_samples(tpot),
        end_to_end: Distribution::from_samples(e2e),
        cancellation: Distribution::from_samples(cancellation),
        fault: Distribution::from_samples(fault),
        instance_distribution,
        error_samples: errors,
    }
}

impl Distribution {
    fn from_samples(mut values: Vec<u64>) -> Option<Self> {
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        let sum = values.iter().map(|value| *value as f64).sum::<f64>();
        Some(Self {
            samples: values.len(),
            min_us: values[0],
            mean_us: sum / values.len() as f64,
            p50_us: percentile(&values, 0.50),
            p90_us: percentile(&values, 0.90),
            p95_us: percentile(&values, 0.95),
            p99_us: percentile(&values, 0.99),
            max_us: values[values.len() - 1],
        })
    }
}

fn find_event_boundary(bytes: &[u8]) -> Option<(usize, usize)> {
    let lf = bytes.windows(2).position(|window| window == b"\n\n");
    let crlf = bytes.windows(4).position(|window| window == b"\r\n\r\n");
    match (lf, crlf) {
        (Some(left), Some(right)) if left <= right => Some((left, 2)),
        (Some(_), Some(right)) => Some((right, 4)),
        (Some(index), None) => Some((index, 2)),
        (None, Some(index)) => Some((index, 4)),
        (None, None) => None,
    }
}

fn percentile(values: &[u64], quantile: f64) -> u64 {
    let rank = (values.len() as f64 * quantile).ceil() as usize;
    values[rank.saturating_sub(1).min(values.len() - 1)]
}

fn elapsed_microseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros())
        .unwrap_or(u64::MAX)
        .max(1)
}

fn rate(count: usize, seconds: f64) -> f64 {
    if seconds > 0.0 {
        count as f64 / seconds
    } else {
        0.0
    }
}

fn bounded_text(value: &str, limit: usize) -> &str {
    let mut end = value.len().min(limit);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_handles_fragmented_lf_and_crlf_events() {
        let mut decoder = SseDecoder::default();
        assert!(decoder.push(b"data: {\"benchmark_").unwrap().is_empty());
        assert_eq!(
            decoder
                .push(b"sequence\":0}\r\n\r\ndata: [DONE]\n\n")
                .unwrap(),
            vec![
                SseEvent::Data("{\"benchmark_sequence\":0}".to_string()),
                SseEvent::Data("[DONE]".to_string())
            ]
        );
        decoder.finish().expect("complete terminal stream");
    }

    #[test]
    fn decoder_rejects_incomplete_or_post_terminal_data() {
        let mut incomplete = SseDecoder::default();
        incomplete.push(b"data: partial").unwrap();
        assert!(incomplete.finish().is_err());

        let mut terminal = SseDecoder::default();
        terminal.push(b"data: [DONE]\n\n").unwrap();
        assert!(terminal.push(b"data: late\n\n").is_err());
    }

    #[test]
    fn distribution_uses_nearest_rank_percentiles() {
        let distribution = Distribution::from_samples((1..=100).rev().collect()).unwrap();
        assert_eq!(distribution.samples, 100);
        assert_eq!(distribution.p50_us, 50);
        assert_eq!(distribution.p90_us, 90);
        assert_eq!(distribution.p95_us, 95);
        assert_eq!(distribution.p99_us, 99);
    }

    #[test]
    fn bounded_text_preserves_utf8_boundaries() {
        assert_eq!(bounded_text("éclair", 1), "");
        assert_eq!(bounded_text("éclair", 2), "é");
    }
}
