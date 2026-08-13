//! Deterministic OpenAI-compatible streaming upstream for AI gateway benchmarks.

use std::convert::Infallible;
use std::error::Error;
use std::net::SocketAddr;
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
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::time::sleep;

type BoxError = Box<dyn Error + Send + Sync>;
type ResponseBody = UnsyncBoxBody<Bytes, Infallible>;

const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_TOKENS: usize = 4_096;
const MAX_DELAY_MS: u64 = 60_000;

#[derive(Debug, Parser)]
#[command(version)]
struct Args {
    /// Address used by both benchmark proxies as their shared upstream.
    #[arg(long, default_value = "127.0.0.1:18100")]
    address: SocketAddr,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BenchmarkSettings {
    first_token_delay_ms: u64,
    token_interval_ms: u64,
    token_count: usize,
}

impl Default for BenchmarkSettings {
    fn default() -> Self {
        Self {
            first_token_delay_ms: 50,
            token_interval_ms: 10,
            token_count: 32,
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
        if self.first_token_delay_ms > MAX_DELAY_MS || self.token_interval_ms > MAX_DELAY_MS {
            return Err(format!(
                "benchmark delays must not exceed {MAX_DELAY_MS} milliseconds"
            ));
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

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let args = Args::parse();
    let listener = TcpListener::bind(args.address).await?;
    println!("ai benchmark upstream listening on {}", args.address);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let connection = http1::Builder::new()
                .keep_alive(true)
                .serve_connection(TokioIo::new(stream), service_fn(handle_request));
            if let Err(error) = connection.await {
                eprintln!("ai benchmark upstream connection failed: {error}");
            }
        });
    }
}

async fn handle_request(request: Request<Incoming>) -> Result<Response<ResponseBody>, Infallible> {
    let response = match (request.method(), request.uri().path()) {
        (&Method::GET, "/health") => json_response(
            StatusCode::OK,
            json!({"status": "ok", "service": "a3s-ai-benchmark-upstream"}),
        ),
        (&Method::POST, "/v1/chat/completions" | "/v1/completions") => {
            completion_response(request).await
        }
        _ => json_response(
            StatusCode::NOT_FOUND,
            json!({"error": {"message": "benchmark route not found"}}),
        ),
    };
    Ok(response)
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
        streaming_response(path, request.model, settings)
    } else {
        non_streaming_response(path, request.model, settings.token_count)
    }
}

fn streaming_response(
    path: String,
    model: String,
    settings: BenchmarkSettings,
) -> Response<ResponseBody> {
    let events = stream::unfold(0_usize, move |sequence| {
        let path = path.clone();
        let model = model.clone();
        async move {
            if sequence > settings.token_count {
                return None;
            }
            if sequence == settings.token_count {
                return Some((
                    Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"data: [DONE]\n\n"))),
                    sequence + 1,
                ));
            }
            let delay = if sequence == 0 {
                settings.first_token_delay_ms
            } else {
                settings.token_interval_ms
            };
            if delay != 0 {
                sleep(Duration::from_millis(delay)).await;
            }
            let event = token_event(&path, &model, sequence);
            let encoded = serde_json::to_string(&event).expect("benchmark event must serialize");
            let payload = Bytes::from(format!("data: {encoded}\n\n"));
            Some((Ok(Frame::data(payload)), sequence + 1))
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

fn token_event(path: &str, model: &str, sequence: usize) -> Value {
    if path == "/v1/completions" {
        json!({
            "id": "cmpl-a3s-ai-benchmark",
            "object": "text_completion",
            "created": 1_700_000_000_u64,
            "model": model,
            "benchmark_sequence": sequence,
            "choices": [{
                "index": 0,
                "text": format!("token-{sequence}"),
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
            "choices": [{
                "index": 0,
                "delta": {"content": format!("token-{sequence}")},
                "finish_reason": null
            }]
        })
    }
}

fn non_streaming_response(
    path: String,
    model: String,
    token_count: usize,
) -> Response<ResponseBody> {
    let content = (0..token_count)
        .map(|sequence| format!("token-{sequence}"))
        .collect::<Vec<_>>()
        .join(" ");
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
    }

    #[test]
    fn token_events_carry_exact_monotonic_sequence() {
        let chat = token_event("/v1/chat/completions", "bench", 7);
        let completion = token_event("/v1/completions", "bench", 8);
        assert_eq!(chat["benchmark_sequence"], 7);
        assert_eq!(chat["choices"][0]["delta"]["content"], "token-7");
        assert_eq!(completion["benchmark_sequence"], 8);
        assert_eq!(completion["choices"][0]["text"], "token-8");
    }
}
