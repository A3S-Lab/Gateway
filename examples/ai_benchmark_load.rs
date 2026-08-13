//! Streaming-aware OpenAI load client for reproducible AI gateway comparisons.

use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use futures_util::StreamExt;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Barrier;
use tokio::time::{timeout, Instant};

type BoxError = Box<dyn Error + Send + Sync>;

const MAX_TOKEN_COUNT: usize = 4_096;
const MAX_DELAY_MS: u64 = 60_000;
const MAX_PROMPT_BYTES: usize = 7 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
enum Endpoint {
    Chat,
    Completions,
}

impl Endpoint {
    const fn path(self) -> &'static str {
        match self {
            Self::Chat => "/v1/chat/completions",
            Self::Completions => "/v1/completions",
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
    #[arg(long, default_value_t = 128)]
    prompt_bytes: usize,
    #[arg(long, default_value_t = 120)]
    request_timeout_seconds: u64,
    #[arg(long)]
    api_key: Option<String>,
    #[arg(long, default_value = "unspecified")]
    product: String,
    #[arg(long, default_value_t = 1)]
    trial: usize,
    #[arg(long)]
    output: PathBuf,
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
    prompt_bytes: usize,
    request_timeout_seconds: u64,
}

#[derive(Debug)]
struct RequestContext {
    url: String,
    scenario: Scenario,
    api_key: Option<String>,
}

#[derive(Debug)]
struct StreamObservation {
    ttft_us: u64,
    e2e_us: u64,
    tpot_us: Option<u64>,
    itl_us: Vec<u64>,
    tokens: usize,
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
    measured_seconds: f64,
    streams_per_second: f64,
    token_goodput_per_second: f64,
    ttft: Option<Distribution>,
    inter_token_latency: Option<Distribution>,
    time_per_output_token: Option<Distribution>,
    end_to_end: Option<Distribution>,
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
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    validate_args(&args)?;
    let scenario = Scenario {
        endpoint: args.endpoint,
        model: args.model.clone(),
        concurrency: args.concurrency,
        requests: args.requests,
        token_count: args.token_count,
        first_token_delay_ms: args.first_token_delay_ms,
        token_interval_ms: args.token_interval_ms,
        prompt_bytes: args.prompt_bytes,
        request_timeout_seconds: args.request_timeout_seconds,
    };
    let origin = args.target.trim_end_matches('/');
    let context = Arc::new(RequestContext {
        url: format!("{origin}{}", args.endpoint.path()),
        scenario: scenario.clone(),
        api_key: args.api_key.clone(),
    });
    let client = reqwest::Client::builder()
        .http1_only()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(args.concurrency)
        .build()?;

    if args.warmup_requests != 0 {
        let warmup = execute_batch(
            client.clone(),
            context.clone(),
            args.warmup_requests,
            args.concurrency,
        )
        .await;
        if let Some(error) = warmup.observations.into_iter().find_map(Result::err) {
            return Err(format!("warmup stream failed: {error}").into());
        }
    }

    let batch = execute_batch(client, context, args.requests, args.concurrency).await;
    let metrics = summarize_trial(&args, scenario, batch);
    if let Some(parent) = args.output.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.output, serde_json::to_vec_pretty(&metrics)?)?;
    println!("{}", serde_json::to_string(&metrics)?);
    if metrics.failed_requests == 0 {
        Ok(())
    } else {
        Err(format!(
            "{} of {} measured streams failed",
            metrics.failed_requests, args.requests
        )
        .into())
    }
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
    if args.first_token_delay_ms > MAX_DELAY_MS || args.token_interval_ms > MAX_DELAY_MS {
        return Err(format!("token delays must not exceed {MAX_DELAY_MS} milliseconds").into());
    }
    if args.prompt_bytes > MAX_PROMPT_BYTES {
        return Err(format!("prompt bytes must not exceed {MAX_PROMPT_BYTES}").into());
    }
    let url = reqwest::Url::parse(&args.target)?;
    if !matches!(url.scheme(), "http" | "https") || url.cannot_be_a_base() {
        return Err("target must be an HTTP(S) origin".into());
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
            let mut observations = Vec::new();
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

async fn measure_stream(
    client: &reqwest::Client,
    context: &RequestContext,
    request_index: usize,
) -> Result<StreamObservation, String> {
    let prompt = "p".repeat(context.scenario.prompt_bytes);
    let body = match context.scenario.endpoint {
        Endpoint::Chat => json!({
            "model": context.scenario.model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": true,
            "benchmark": {
                "first_token_delay_ms": context.scenario.first_token_delay_ms,
                "token_interval_ms": context.scenario.token_interval_ms,
                "token_count": context.scenario.token_count
            }
        }),
        Endpoint::Completions => json!({
            "model": context.scenario.model,
            "prompt": prompt,
            "stream": true,
            "benchmark": {
                "first_token_delay_ms": context.scenario.first_token_delay_ms,
                "token_interval_ms": context.scenario.token_interval_ms,
                "token_count": context.scenario.token_count
            }
        }),
    };
    let started = Instant::now();
    let mut request = client
        .post(&context.url)
        .header(ACCEPT, "text/event-stream")
        .header(CONTENT_TYPE, "application/json")
        .header("x-a3s-benchmark-request", request_index.to_string())
        .json(&body);
    if let Some(api_key) = &context.api_key {
        request = request.header(AUTHORIZATION, format!("Bearer {api_key}"));
    }
    let response = request
        .send()
        .await
        .map_err(|error| format!("request {request_index} failed before headers: {error}"))?;
    let status = response.status();
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
    let mut token_times = Vec::with_capacity(context.scenario.token_count);
    let mut expected_sequence = 0_usize;
    let mut done_at = None;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            format!("request {request_index} failed while reading the stream: {error}")
        })?;
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
            let document: serde_json::Value = serde_json::from_str(&data).map_err(|error| {
                format!("request {request_index} returned invalid token JSON: {error}")
            })?;
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
            expected_sequence += 1;
            token_times.push(started.elapsed());
        }
    }
    decoder.finish()?;
    let done_at =
        done_at.ok_or_else(|| format!("request {request_index} completed without [DONE]"))?;
    if token_times.len() != context.scenario.token_count {
        return Err(format!(
            "request {request_index} returned {} tokens, expected {}",
            token_times.len(),
            context.scenario.token_count
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
        ttft_us,
        e2e_us,
        tpot_us,
        itl_us,
        tokens: token_times.len(),
    })
}

fn summarize_trial(args: &Args, scenario: Scenario, batch: BatchResult) -> TrialMetrics {
    let mut ttft = Vec::new();
    let mut e2e = Vec::new();
    let mut tpot = Vec::new();
    let mut itl = Vec::new();
    let mut completed_tokens = 0_usize;
    let mut errors = Vec::new();
    for observation in batch.observations {
        match observation {
            Ok(observation) => {
                ttft.push(observation.ttft_us);
                e2e.push(observation.e2e_us);
                if let Some(value) = observation.tpot_us {
                    tpot.push(value);
                }
                itl.extend(observation.itl_us);
                completed_tokens += observation.tokens;
            }
            Err(error) => {
                if errors.len() < 20 {
                    errors.push(error);
                }
            }
        }
    }
    let completed_requests = ttft.len();
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
        measured_seconds,
        streams_per_second: rate(completed_requests, measured_seconds),
        token_goodput_per_second: rate(completed_tokens, measured_seconds),
        ttft: Distribution::from_samples(ttft),
        inter_token_latency: Distribution::from_samples(itl),
        time_per_output_token: Distribution::from_samples(tpot),
        end_to_end: Distribution::from_samples(e2e),
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
