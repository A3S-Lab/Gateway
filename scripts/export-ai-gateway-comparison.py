#!/usr/bin/env python3
"""Export repeated token-aware A3S Gateway and NGINX AI benchmark trials."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path
from typing import Any


TRIAL_SCHEMA = "a3s.gateway.ai-comparison.trial.v1"
OUTPUT_SCHEMA = "a3s.gateway.ai-comparison.v1"
PRODUCTS = ("a3s-gateway", "nginx")
PROFILE_DETAILS = {
    "stream-overhead-c1": (
        "Streaming overhead, C1",
        "Zero-delay 32-token chat stream at concurrency 1",
    ),
    "stream-overhead-c64": (
        "Streaming overhead, C64",
        "Zero-delay 32-token chat streams at concurrency 64",
    ),
    "sse-transport-c1": (
        "SSE transport control, C1",
        "Non-OpenAI /benchmark/sse zero-delay 32-token stream at concurrency 1",
    ),
    "sse-transport-c64": (
        "SSE transport control, C64",
        "Non-OpenAI /benchmark/sse zero-delay 32-token streams at concurrency 64",
    ),
    "stream-paced-c16": (
        "Paced chat stream, C16",
        "50 ms first token and 10 ms cadence at concurrency 16",
    ),
    "stream-paced-c64": (
        "Paced chat stream, C64",
        "50 ms first token and 10 ms cadence at concurrency 64",
    ),
    "stream-long-output": (
        "Long output stream",
        "256-token chat streams for cadence drift and sustained goodput",
    ),
    "completions-paced-c16": (
        "Paced completions, C16",
        "Legacy completions SSE path with the paced C16 schedule",
    ),
    "prompt-32k": (
        "32 KiB prompt",
        "32 KiB chat prompt with a paced token stream",
    ),
    "disk-spill": (
        "Client-body disk spill",
        "32 KiB prompt with NGINX 16 KiB buffer + recorded temp volume; A3S in-memory validation",
    ),
    "gateway-restart": (
        "Proxy process restart",
        "Kill and restart product with same standalone ACL/conf; recovery_ms to /health then paced streams",
    ),
    "prompt-1k": (
        "1 KiB prompt",
        "1 KiB chat prompt with a paced token stream",
    ),
    "prompt-256k": (
        "256 KiB prompt",
        "256 KiB chat prompt with a paced token stream",
    ),
    "prompt-1m": (
        "1 MiB prompt",
        "1 MiB chat prompt with a paced token stream",
    ),
    "prompt-limit": (
        "Exact 8 MiB body limit",
        "Serialized JSON body equals OpenAI/Gateway ceiling; complete stream",
    ),
    "prompt-over-limit": (
        "Over 8 MiB body limit",
        "Declared Content-Length one past ceiling → HTTP 413 before body; upstream idle",
    ),
    "json-short": (
        "Non-streaming JSON short",
        "stream=false chat completion; E2E latency only (no TTFT/ITL)",
    ),
    "json-large": (
        "Non-streaming JSON large",
        "stream=false with multi-MiB padded completion body; E2E relay cost",
    ),
    "chunked-upload": (
        "Chunked request upload",
        "OpenAI JSON body sent with Transfer-Encoding: chunked across many frames",
    ),
    "request-buffering-on": (
        "Request buffering on",
        "Chunked OpenAI upload with NGINX proxy_request_buffering on (A3S validation unchanged)",
    ),
    "request-buffering-off": (
        "Request buffering off",
        "Same chunked schedule with NGINX proxy_request_buffering off (A3S validation unchanged)",
    ),
    "thundering-herd": (
        "Thundering herd release",
        "Barrier-synchronized release of 256 concurrent short streams",
    ),
    "concurrency-sweep-c1": (
        "Concurrency sweep C1",
        "Fixed 8-token zero-delay streams at 1 active client (sweep baseline)",
    ),
    "concurrency-sweep-c4": (
        "Concurrency sweep C4",
        "Same short-stream workload at 4 active clients",
    ),
    "concurrency-sweep-c16": (
        "Concurrency sweep C16",
        "Same short-stream workload at 16 active clients",
    ),
    "concurrency-sweep-c64": (
        "Concurrency sweep C64",
        "Same short-stream workload at 64 active clients",
    ),
    "concurrency-sweep-c256": (
        "Concurrency sweep C256",
        "Same short-stream workload at 256 active clients",
    ),
    "concurrency-sweep-c1024": (
        "Concurrency sweep C1024",
        "Same short-stream workload at 1,024 active clients (dedicated-runner capacity)",
    ),
    "mixed-short-long": (
        "Mixed short/long streams",
        "90% 16-token and 10% 1,024-token streams in one batch (HOL/fairness)",
    ),
    "steady-arrival": (
        "Poisson steady arrivals",
        "Seeded open-loop exponential inter-arrivals; concurrency is max in-flight",
    ),
    "transport-keepalive": (
        "Transport keep-alive reuse",
        "Short zero-delay streams with HTTP/1.1 connection pool reuse",
    ),
    "transport-churn": (
        "Transport connection churn",
        "Same short-stream workload with Connection: close and no idle pool",
    ),
    "transport-tls-http1": (
        "TLS termination HTTP/1.1",
        "Downstream HTTPS/1.1 to Gateway; plain HTTP upstream; self-signed fixture",
    ),
    "transport-tls-http2": (
        "TLS termination HTTP/2",
        "Downstream HTTPS with HTTP/2 ALPN; plain HTTP upstream; self-signed fixture",
    ),
    "transport-ipv6": (
        "IPv6 loopback transport",
        "Short zero-delay streams over [::1] end-to-end (client, proxy, upstream)",
    ),
    "transport-upstream-tls": (
        "Upstream TLS with private CA",
        "Plain HTTP downstream; HTTPS upstream verified via tls_ca_file / proxy_ssl CA",
    ),
    "disconnect-before-token": (
        "Disconnect before first token",
        "Client closes after headers and before the first SSE token",
    ),
    "disconnect-after-token": (
        "Disconnect after first token",
        "Client closes after one validated token to measure post-commit cancel",
    ),
    "slow-reader": (
        "Slow reader backpressure",
        "Client sleeps after each token slower than upstream cadence",
    ),
    "stalled-reader": (
        "Stalled reader idle window",
        "Client pauses reading once mid-stream then resumes to [DONE]",
    ),
    "http-503": (
        "Upstream HTTP 503",
        "Deterministic service-unavailable fault before any token",
    ),
    "http-500": (
        "Upstream HTTP 500",
        "Deterministic internal-server-error before any token; batch stays under passive-health threshold so samples remain 500",
    ),
    "http-429": (
        "Upstream HTTP 429",
        "Deterministic rate-limit fault with Retry-After before any token",
    ),
    "missing-done": (
        "Missing [DONE] marker",
        "Upstream ends the SSE body after all tokens without a terminal marker",
    ),
    "reset-before-token": (
        "Reset before first token",
        "Upstream closes the SSE body before the first token event",
    ),
    "reset-after-token": (
        "Reset after first token",
        "Upstream closes the SSE body after one validated token",
    ),
    "malformed-sse": (
        "Malformed SSE JSON event",
        "Well-framed SSE with invalid JSON; client detects transparent relay",
    ),
    "first-token-timeout": (
        "First-token idle timeout",
        "Upstream holds before the first token until stream_idle_timeout fires",
    ),
    "midstream-idle": (
        "Midstream idle timeout",
        "Upstream pauses after token 1 until stream_idle_timeout fires",
    ),
    "connect-refused": (
        "Upstream connect refused",
        "Proxy maps a closed upstream port to a stable client error",
    ),
    "connect-timeout": (
        "Upstream connect timeout",
        "Blackhole upstream dial waits until connect_timeout fires",
    ),
    "headers-timeout": (
        "Upstream headers timeout",
        "Upstream accepts then holds headers until request_timeout fires",
    ),
    "total-timeout": (
        "Stream total timeout",
        "Endless token stream until stream_total_timeout cuts the body",
    ),
    "telemetry-on": (
        "Observability enabled",
        "Paced C16 chat stream with metrics, access log, and tracing on",
    ),
    "telemetry-off": (
        "Observability disabled",
        "Matching paced C16 chat stream on the default fixture (no extra telemetry)",
    ),
    "fallback": (
        "Primary failure then failover",
        "Dead primary quarantined; complete-stream recovery via failover/backup",
    ),
    "stream-bursty": (
        "Bursty SSE framing",
        "Eight token events per upstream write; count events not chunks",
    ),
    "stream-fragmented": (
        "Fragmented SSE framing",
        "Each event split across four write frames; incremental reassembly",
    ),
    "stream-unicode": (
        "Unicode SSE framing",
        "UTF-8 content, multiline data lines, mid-codepoint write cuts",
    ),
    "weighted-rollout": (
        "Weighted stable/canary split",
        "90/10 revision weights; trial records instance_distribution",
    ),
    "rate-limit": (
        "Per-client rate limit",
        "Mixed admit and HTTP 429 under token-bucket / limit_req",
    ),
    "api-key-auth": (
        "API key admission",
        "Mixed admit and HTTP 401; every other request omits Authorization",
    ),
    "no-replay-after-token": (
        "No mid-stream failover replay",
        "Primary resets after token 1; backup streams_started must not rise",
    ),
}
# Policy lanes without a pinned NGINX-equivalent module in this suite.
A3S_ONLY_PROFILES = frozenset(
    {
        "telemetry-on",
        "telemetry-off",
        "api-key-auth",
    }
)
DISTRIBUTIONS = (
    "ttft",
    "inter_token_latency",
    "time_per_output_token",
    "end_to_end",
)
DISTRIBUTION_FIELDS = (
    "min_us",
    "mean_us",
    "p50_us",
    "p90_us",
    "p95_us",
    "p99_us",
    "max_us",
)
RATE_FIELDS = (
    "streams_per_second",
    "token_goodput_per_second",
)


def finite_positive(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value > 0
    )


def positive_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def validate_scenario(scenario: object, path: Path) -> dict[str, Any]:
    if not isinstance(scenario, dict):
        raise ValueError(f"{path} scenario must be an object")
    required_positive = (
        "concurrency",
        "requests",
        "token_count",
        "prompt_bytes",
        "request_timeout_seconds",
    )
    for field in required_positive:
        if not positive_integer(scenario.get(field)):
            raise ValueError(f"{path} scenario has invalid {field}")
    for field in ("first_token_delay_ms", "token_interval_ms"):
        value = scenario.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"{path} scenario has invalid {field}")
    if scenario.get("endpoint") not in {"chat", "completions", "sse-transport"}:
        raise ValueError(f"{path} scenario has an invalid endpoint")
    model = scenario.get("model")
    if not isinstance(model, str) or not model:
        raise ValueError(f"{path} scenario has an invalid model")
    if scenario.get("endpoint") == "sse-transport" and scenario.get("no_stream"):
        raise ValueError(f"{path} sse-transport cannot set no_stream")
    disconnect_after = scenario.get("disconnect_after_tokens")
    if disconnect_after is not None and (
        not isinstance(disconnect_after, int)
        or isinstance(disconnect_after, bool)
        or disconnect_after < 0
        or disconnect_after > scenario["token_count"]
    ):
        raise ValueError(f"{path} scenario has an invalid disconnect_after_tokens")
    read_delay_ms = scenario.get("read_delay_ms")
    if read_delay_ms is not None and (
        not isinstance(read_delay_ms, int)
        or isinstance(read_delay_ms, bool)
        or read_delay_ms < 1
    ):
        raise ValueError(f"{path} scenario has an invalid read_delay_ms")
    if disconnect_after is not None and read_delay_ms is not None:
        raise ValueError(
            f"{path} scenario cannot combine disconnect_after_tokens with read_delay_ms"
        )
    stall_after = scenario.get("stall_after_tokens")
    stall_ms = scenario.get("stall_ms")
    if (stall_after is None) != (stall_ms is None):
        raise ValueError(
            f"{path} scenario must set stall_after_tokens and stall_ms together"
        )
    if stall_after is not None:
        if (
            not isinstance(stall_after, int)
            or isinstance(stall_after, bool)
            or stall_after < 1
            or stall_after >= scenario["token_count"]
        ):
            raise ValueError(f"{path} scenario has an invalid stall_after_tokens")
        if (
            not isinstance(stall_ms, int)
            or isinstance(stall_ms, bool)
            or stall_ms < 1
        ):
            raise ValueError(f"{path} scenario has an invalid stall_ms")
        if disconnect_after is not None:
            raise ValueError(
                f"{path} scenario cannot combine stall with disconnect_after_tokens"
            )
        if read_delay_ms is not None:
            raise ValueError(f"{path} scenario cannot combine stall with read_delay_ms")
    no_stream = bool(scenario.get("no_stream"))
    if no_stream:
        if scenario.get("first_token_delay_ms") != 0 or scenario.get("token_interval_ms") != 0:
            raise ValueError(f"{path} no_stream requires zero token delays")
        if disconnect_after is not None or read_delay_ms is not None or stall_after is not None:
            raise ValueError(f"{path} no_stream cannot combine with cancel/backpressure lanes")
        if scenario.get("tokens_per_write", 1) not in (None, 1) or scenario.get(
            "fragments_per_event", 1
        ) not in (None, 1):
            raise ValueError(f"{path} no_stream cannot combine with SSE framing knobs")
        if scenario.get("unicode_payload"):
            raise ValueError(f"{path} no_stream cannot combine with unicode_payload")
        if scenario.get("target_body_bytes") is not None or scenario.get(
            "declare_content_length"
        ) is not None:
            raise ValueError(f"{path} no_stream cannot combine with body-ceiling lanes")
        if scenario.get("chunked_upload_frames") is not None:
            raise ValueError(f"{path} no_stream cannot combine with chunked_upload_frames")
        response_bytes = scenario.get("response_bytes")
        if response_bytes is not None:
            if (
                not isinstance(response_bytes, int)
                or isinstance(response_bytes, bool)
                or response_bytes < 1
            ):
                raise ValueError(f"{path} scenario has an invalid response_bytes")
    elif scenario.get("response_bytes") is not None:
        raise ValueError(f"{path} response_bytes requires no_stream")
    long_every = scenario.get("long_every")
    long_token_count = scenario.get("long_token_count")
    if (long_every is None) != (long_token_count is None):
        raise ValueError(f"{path} long_every and long_token_count must be set together")
    if long_every is not None:
        if (
            not isinstance(long_every, int)
            or isinstance(long_every, bool)
            or long_every < 2
        ):
            raise ValueError(f"{path} scenario has an invalid long_every")
        if (
            not isinstance(long_token_count, int)
            or isinstance(long_token_count, bool)
            or long_token_count <= scenario["token_count"]
        ):
            raise ValueError(f"{path} scenario has an invalid long_token_count")
        if scenario["requests"] < long_every:
            raise ValueError(f"{path} long_every requires requests >= long_every")
        if no_stream or disconnect_after is not None or read_delay_ms is not None or stall_after is not None:
            raise ValueError(f"{path} mixed short/long cannot combine with other injected lanes")
    poisson_rps = scenario.get("poisson_arrival_rps")
    arrival_seed = scenario.get("arrival_seed")
    arrival_offsets = scenario.get("arrival_offsets_ms")
    if (poisson_rps is None) != (arrival_seed is None):
        raise ValueError(f"{path} poisson_arrival_rps and arrival_seed must be set together")
    if poisson_rps is not None:
        if not isinstance(poisson_rps, (int, float)) or isinstance(poisson_rps, bool):
            raise ValueError(f"{path} scenario has an invalid poisson_arrival_rps")
        if not (0.0 < float(poisson_rps) <= 10000.0):
            raise ValueError(f"{path} scenario has an invalid poisson_arrival_rps")
        if (
            not isinstance(arrival_seed, int)
            or isinstance(arrival_seed, bool)
            or arrival_seed < 0
        ):
            raise ValueError(f"{path} scenario has an invalid arrival_seed")
        if not isinstance(arrival_offsets, list) or len(arrival_offsets) != scenario["requests"]:
            raise ValueError(f"{path} arrival_offsets_ms must list one offset per request")
        if any(
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or offset < 0
            for offset in arrival_offsets
        ):
            raise ValueError(f"{path} arrival_offsets_ms must be non-negative integers")
        if arrival_offsets and arrival_offsets[0] != 0:
            raise ValueError(f"{path} arrival_offsets_ms must start at 0")
        if no_stream or disconnect_after is not None or read_delay_ms is not None or stall_after is not None:
            raise ValueError(f"{path} poisson arrivals cannot combine with other injected lanes")
        if long_every is not None:
            raise ValueError(f"{path} poisson arrivals cannot combine with mixed short/long")
    elif arrival_offsets is not None:
        raise ValueError(f"{path} arrival_offsets_ms requires poisson_arrival_rps")
    chunked_frames = scenario.get("chunked_upload_frames")
    if chunked_frames is not None:
        if (
            not isinstance(chunked_frames, int)
            or isinstance(chunked_frames, bool)
            or chunked_frames < 2
            or chunked_frames > 256
        ):
            raise ValueError(f"{path} scenario has an invalid chunked_upload_frames")
        if scenario.get("declare_content_length") is not None or scenario.get(
            "target_body_bytes"
        ) is not None:
            raise ValueError(
                f"{path} chunked_upload_frames cannot combine with body-ceiling lanes"
            )
    upstream_fault = scenario.get("upstream_fault")
    expect_http_status = scenario.get("expect_http_status")
    expect_stream_error = bool(scenario.get("expect_stream_error"))
    expect_proxy_error = bool(scenario.get("expect_proxy_error"))
    http_faults = {"http-429", "http-500", "http-503"}
    http_fault_status = {"http-429": 429, "http-500": 500, "http-503": 503}
    stream_faults = {
        "missing-done",
        "reset-before-token",
        "reset-after-token",
        "hold-first-token",
        "midstream-idle",
        "hold-headers",
        "endless-stream",
        "malformed-sse",
    }
    if expect_proxy_error:
        if upstream_fault is not None:
            raise ValueError(
                f"{path} expect_proxy_error cannot combine with upstream_fault"
            )
        if expect_http_status is not None or expect_stream_error:
            raise ValueError(
                f"{path} expect_proxy_error must omit HTTP/stream fault expectations"
            )
        if disconnect_after is not None or read_delay_ms is not None or stall_after is not None:
            raise ValueError(
                f"{path} expect_proxy_error cannot combine with other injected lanes"
            )
        if no_stream:
            raise ValueError(f"{path} expect_proxy_error cannot combine with no_stream")
    elif upstream_fault is not None:
        if no_stream:
            raise ValueError(f"{path} upstream_fault cannot combine with no_stream")
        if upstream_fault not in http_faults | stream_faults:
            raise ValueError(f"{path} scenario has an invalid upstream_fault")
        if upstream_fault in http_faults:
            expected_status = http_fault_status[upstream_fault]
            if expect_http_status != expected_status:
                raise ValueError(
                    f"{path} scenario expect_http_status must match upstream_fault"
                )
            if expect_stream_error:
                raise ValueError(
                    f"{path} HTTP fault lanes must not set expect_stream_error"
                )
        else:
            if expect_http_status is not None:
                raise ValueError(
                    f"{path} stream fault lanes must omit expect_http_status"
                )
            if not expect_stream_error:
                raise ValueError(
                    f"{path} stream fault lanes must set expect_stream_error"
                )
            if upstream_fault == "reset-after-token" and scenario["token_count"] < 1:
                raise ValueError(f"{path} reset-after-token requires token_count >= 1")
            if upstream_fault == "midstream-idle" and scenario["token_count"] < 2:
                raise ValueError(f"{path} midstream-idle requires token_count >= 2")
            if upstream_fault == "missing-done" and scenario["token_count"] < 1:
                raise ValueError(f"{path} missing-done requires token_count >= 1")
            if upstream_fault == "endless-stream" and scenario["token_count"] < 1:
                raise ValueError(f"{path} endless-stream requires token_count >= 1")
        if disconnect_after is not None or read_delay_ms is not None or stall_after is not None:
            raise ValueError(
                f"{path} scenario cannot combine upstream_fault with other injected lanes"
            )
    elif expect_http_status is not None or expect_stream_error:
        raise ValueError(
            f"{path} scenario fault expectations require upstream_fault"
        )
    return scenario


def validate_distribution(
    value: object,
    expected_samples: int,
    name: str,
    path: Path,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{path} is missing {name}")
    if value.get("samples") != expected_samples:
        raise ValueError(
            f"{path} {name} has {value.get('samples')} samples; "
            f"expected {expected_samples}"
        )
    for field in DISTRIBUTION_FIELDS:
        if not finite_positive(value.get(field)):
            raise ValueError(f"{path} {name}.{field} is not finite and positive")
    ordered = [
        value["min_us"],
        value["p50_us"],
        value["p90_us"],
        value["p95_us"],
        value["p99_us"],
        value["max_us"],
    ]
    if ordered != sorted(ordered):
        raise ValueError(f"{path} {name} percentiles are not monotonic")
    return value


def read_trial(path: Path, product: str, trial_index: int) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object")
    if payload.get("schema_version") != TRIAL_SCHEMA:
        raise ValueError(f"{path} has an unsupported trial schema")
    if payload.get("product") != product:
        raise ValueError(f"{path} product does not match {product}")
    if payload.get("trial") != trial_index:
        raise ValueError(f"{path} trial does not match {trial_index}")

    scenario = validate_scenario(payload.get("scenario"), path)
    requests = scenario["requests"]
    token_count = scenario["token_count"]
    disconnect_after = scenario.get("disconnect_after_tokens")
    upstream_fault = scenario.get("upstream_fault")
    expect_proxy_error = bool(scenario.get("expect_proxy_error"))
    min_tokens_only = False
    mixed_total_tokens = None
    mixed_itl_samples = None
    long_every = scenario.get("long_every")
    long_token_count = scenario.get("long_token_count")
    if upstream_fault == "missing-done":
        expected_tokens_per_request = token_count
    elif upstream_fault in {"reset-after-token", "midstream-idle"}:
        expected_tokens_per_request = 1
    elif upstream_fault == "endless-stream":
        expected_tokens_per_request = 1
        min_tokens_only = True
    elif upstream_fault is not None or expect_proxy_error:
        expected_tokens_per_request = 0
    elif disconnect_after is not None:
        expected_tokens_per_request = disconnect_after
    elif long_every is not None:
        long_requests = sum(1 for index in range(requests) if index % long_every == 0)
        short_requests = requests - long_requests
        mixed_total_tokens = (
            short_requests * token_count + long_requests * long_token_count
        )
        mixed_itl_samples = short_requests * max(token_count - 1, 0) + long_requests * max(
            long_token_count - 1, 0
        )
        expected_tokens_per_request = None
    else:
        expected_tokens_per_request = token_count
    if payload.get("completed_requests") != requests:
        raise ValueError(f"{path} did not complete every measured request")
    if payload.get("failed_requests") != 0 or payload.get("success_rate") != 1.0:
        raise ValueError(f"{path} did not achieve a 100% valid stream rate")
    completed_tokens = payload.get("completed_tokens")
    if min_tokens_only:
        if (
            not isinstance(completed_tokens, int)
            or isinstance(completed_tokens, bool)
            or completed_tokens < requests * expected_tokens_per_request
        ):
            raise ValueError(f"{path} completed-token count is inconsistent")
    elif mixed_total_tokens is not None:
        if completed_tokens != mixed_total_tokens:
            raise ValueError(f"{path} completed-token count is inconsistent")
    elif completed_tokens != requests * expected_tokens_per_request:
        raise ValueError(f"{path} completed-token count is inconsistent")
    if payload.get("error_samples") != []:
        raise ValueError(f"{path} contains benchmark errors")
    if not finite_positive(payload.get("measured_seconds")):
        raise ValueError(f"{path} measured interval is invalid")
    if not finite_positive(payload.get("streams_per_second")):
        raise ValueError(f"{path} has invalid streams_per_second")
    if upstream_fault is not None or expect_proxy_error:
        goodput = payload.get("token_goodput_per_second")
        if goodput is None or (
            not isinstance(goodput, (int, float))
            or isinstance(goodput, bool)
            or not math.isfinite(goodput)
            or goodput < 0
        ):
            raise ValueError(f"{path} has invalid token_goodput_per_second")
        if expected_tokens_per_request == 0 and goodput != 0:
            raise ValueError(f"{path} zero-token fault lanes must report zero token goodput")
        if expected_tokens_per_request > 0 and not finite_positive(goodput):
            raise ValueError(f"{path} token-bearing fault lanes need positive token goodput")
        if payload.get("intentional_faults") != requests:
            raise ValueError(f"{path} did not fault every measured request")
        if payload.get("intentional_cancels") not in (None, 0):
            raise ValueError(f"{path} reported unexpected intentional cancels")
        validate_distribution(payload.get("fault"), requests, "fault", path)
        for name in (
            "ttft",
            "inter_token_latency",
            "time_per_output_token",
            "end_to_end",
            "cancellation",
        ):
            if payload.get(name) is not None:
                raise ValueError(f"{path} must omit {name} for intentional fault lanes")
        return payload
    if disconnect_after is None:
        if not finite_positive(payload.get("token_goodput_per_second")):
            raise ValueError(f"{path} has invalid token_goodput_per_second")
    elif payload.get("token_goodput_per_second") is None or (
        not isinstance(payload.get("token_goodput_per_second"), (int, float))
        or isinstance(payload.get("token_goodput_per_second"), bool)
        or not math.isfinite(payload["token_goodput_per_second"])
        or payload["token_goodput_per_second"] < 0
    ):
        raise ValueError(f"{path} has invalid token_goodput_per_second")

    if payload.get("intentional_faults") not in (None, 0):
        raise ValueError(f"{path} reported unexpected intentional faults")
    if payload.get("fault") is not None:
        raise ValueError(f"{path} reported unexpected fault latency")

    no_stream = bool(scenario.get("no_stream"))
    if disconnect_after is None:
        validate_distribution(payload.get("end_to_end"), requests, "end_to_end", path)
        if payload.get("intentional_cancels") not in (None, 0):
            raise ValueError(f"{path} reported unexpected intentional cancels")
        if payload.get("cancellation") is not None:
            raise ValueError(f"{path} reported unexpected cancellation latency")
        if no_stream:
            for name in ("ttft", "inter_token_latency", "time_per_output_token"):
                if payload.get(name) is not None:
                    raise ValueError(f"{path} must omit {name} for no_stream lanes")
        else:
            validate_distribution(payload.get("ttft"), requests, "ttft", path)
            if mixed_itl_samples is not None:
                if mixed_itl_samples > 0:
                    validate_distribution(
                        payload.get("inter_token_latency"),
                        mixed_itl_samples,
                        "inter_token_latency",
                        path,
                    )
                    validate_distribution(
                        payload.get("time_per_output_token"),
                        requests,
                        "time_per_output_token",
                        path,
                    )
                elif payload.get("inter_token_latency") is not None or payload.get(
                    "time_per_output_token"
                ) is not None:
                    raise ValueError(f"{path} has unexpected single-token latency samples")
            elif token_count > 1:
                validate_distribution(
                    payload.get("inter_token_latency"),
                    requests * (token_count - 1),
                    "inter_token_latency",
                    path,
                )
                validate_distribution(
                    payload.get("time_per_output_token"),
                    requests,
                    "time_per_output_token",
                    path,
                )
            elif payload.get("inter_token_latency") is not None or payload.get(
                "time_per_output_token"
            ) is not None:
                raise ValueError(f"{path} has unexpected single-token latency samples")
    else:
        if payload.get("intentional_cancels") != requests:
            raise ValueError(f"{path} did not cancel every measured request")
        validate_distribution(
            payload.get("cancellation"), requests, "cancellation", path
        )
        if disconnect_after == 0:
            if payload.get("ttft") is not None:
                raise ValueError(f"{path} must omit ttft for pre-token disconnect")
            if payload.get("end_to_end") is not None:
                raise ValueError(
                    f"{path} must omit end_to_end for intentional disconnect lanes"
                )
            if payload.get("inter_token_latency") is not None or payload.get(
                "time_per_output_token"
            ) is not None:
                raise ValueError(f"{path} has unexpected latency samples")
        else:
            validate_distribution(payload.get("ttft"), requests, "ttft", path)
            if payload.get("end_to_end") is not None:
                raise ValueError(
                    f"{path} must omit end_to_end for intentional disconnect lanes"
                )
            if disconnect_after > 1:
                validate_distribution(
                    payload.get("inter_token_latency"),
                    requests * (disconnect_after - 1),
                    "inter_token_latency",
                    path,
                )
                validate_distribution(
                    payload.get("time_per_output_token"),
                    requests,
                    "time_per_output_token",
                    path,
                )
            elif payload.get("inter_token_latency") is not None or payload.get(
                "time_per_output_token"
            ) is not None:
                raise ValueError(f"{path} has unexpected single-token latency samples")

    recovery = payload.get("restart_recovery_ms")
    if recovery is not None and (
        not isinstance(recovery, int)
        or isinstance(recovery, bool)
        or recovery < 0
    ):
        raise ValueError(f"{path} restart_recovery_ms must be a non-negative int")

    return payload


def aggregate_trials(trials: list[dict[str, Any]]) -> dict[str, Any]:
    distributions: dict[str, Any] = {}
    for name in DISTRIBUTIONS + ("cancellation", "fault"):
        values = [trial.get(name) for trial in trials]
        if values[0] is None:
            if any(value is not None for value in values):
                raise ValueError(f"{name} presence changed between trials")
            distributions[name] = None
            continue
        if any(value is None for value in values):
            raise ValueError(f"{name} presence changed between trials")
        sample_counts = {value["samples"] for value in values}
        if len(sample_counts) != 1:
            raise ValueError(f"{name} sample counts changed between trials")
        distributions[name] = {
            "samples_per_trial": sample_counts.pop(),
            **{
                field: statistics.median(value[field] for value in values)
                for field in DISTRIBUTION_FIELDS
            },
        }
    return {
        "success_rate": statistics.median(
            trial["success_rate"] for trial in trials
        ),
        **{
            field: statistics.median(trial[field] for trial in trials)
            for field in RATE_FIELDS
        },
        **distributions,
        **(
            {
                "restart_recovery_ms": statistics.median(
                    trial["restart_recovery_ms"] for trial in trials
                )
            }
            if all("restart_recovery_ms" in trial for trial in trials)
            else {}
        ),
    }


def relative_position(a3s: float, nginx: float, lower_is_preferred: bool) -> str:
    ratio = a3s / nginx
    if 0.97 < ratio < 1.03:
        return "within_threshold"
    if lower_is_preferred:
        return "a3s_lower" if ratio < 1 else "nginx_lower"
    return "a3s_higher" if ratio > 1 else "nginx_higher"


def compare(a3s: dict[str, Any], nginx: dict[str, Any]) -> dict[str, Any]:
    latency_ratios: dict[str, float] = {}
    positions: dict[str, str] = {
        "token_goodput": relative_position(
            a3s["token_goodput_per_second"],
            nginx["token_goodput_per_second"],
            False,
        ),
        "stream_rate": relative_position(
            a3s["streams_per_second"], nginx["streams_per_second"], False
        ),
    }
    for distribution in DISTRIBUTIONS:
        for percentile in ("p50_us", "p99_us"):
            if a3s[distribution] is None or nginx[distribution] is None:
                continue
            metric = f"{distribution}_{percentile.removesuffix('_us')}"
            latency_ratios[f"a3s_to_nginx_{metric}_ratio"] = (
                a3s[distribution][percentile] / nginx[distribution][percentile]
            )
            positions[metric] = relative_position(
                a3s[distribution][percentile],
                nginx[distribution][percentile],
                True,
            )
    return {
        "a3s_to_nginx_token_goodput_ratio": (
            a3s["token_goodput_per_second"] / nginx["token_goodput_per_second"]
        ),
        "a3s_to_nginx_stream_rate_ratio": (
            a3s["streams_per_second"] / nginx["streams_per_second"]
        ),
        **latency_ratios,
        "positions": positions,
    }


def parse_profiles(value: str) -> list[str]:
    profiles = [item.strip() for item in value.split(",") if item.strip()]
    if not profiles:
        raise argparse.ArgumentTypeError("at least one profile is required")
    if len(set(profiles)) != len(profiles):
        raise argparse.ArgumentTypeError("profile IDs must be unique")
    unknown = [profile for profile in profiles if profile not in PROFILE_DETAILS]
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown profile IDs: {unknown}")
    return profiles


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profiles", type=parse_profiles, required=True)
    parser.add_argument("--trials", type=int, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--cpu-model", required=True)
    parser.add_argument("--logical-cpus", type=int, required=True)
    parser.add_argument("--memory-mib", type=int, required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--a3s-version", required=True)
    parser.add_argument("--nginx-version", required=True)
    parser.add_argument("--upstream-version", required=True)
    parser.add_argument("--load-version", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.trials < 1:
        raise ValueError("trials must be positive")

    profiles: dict[str, Any] = {}
    for profile_id in args.profiles:
        products: dict[str, Any] = {}
        expected_scenario = None
        product_ids = (
            ("a3s-gateway",)
            if profile_id in A3S_ONLY_PROFILES
            else PRODUCTS
        )
        for product in product_ids:
            trials = [
                read_trial(
                    args.input / f"{profile_id}-{product}-{index}.json",
                    product,
                    index,
                )
                for index in range(1, args.trials + 1)
            ]
            for trial in trials:
                scenario = trial["scenario"]
                if expected_scenario is None:
                    expected_scenario = scenario
                elif scenario != expected_scenario:
                    raise ValueError(
                        f"{profile_id} did not use an identical scenario in every trial"
                    )
                if profile_id == "gateway-restart" and "restart_recovery_ms" not in trial:
                    raise ValueError(
                        f"{profile_id} trial for {product} is missing restart_recovery_ms"
                    )
            products[product] = {
                "trials": trials,
                "median": aggregate_trials(trials),
            }

        label, workload = PROFILE_DETAILS[profile_id]
        a3s = products["a3s-gateway"]["median"]
        if profile_id in A3S_ONLY_PROFILES:
            profiles[profile_id] = {
                "label": label,
                "workload": workload,
                "capability_alignment": "a3s_policy_absolute_nginx_unsupported",
                "scenario": expected_scenario,
                "products": products,
                "comparison": {
                    "nginx_capability": "unsupported",
                    "reason": (
                        "No pinned NGINX-equivalent observability module is "
                        "configured in this suite; report A3S absolute medians only."
                    ),
                },
            }
        else:
            nginx = products["nginx"]["median"]
            if profile_id.startswith("sse-transport-"):
                capability_alignment = "streaming_transport_control"
            elif profile_id.startswith("request-buffering-"):
                capability_alignment = "nginx_request_buffering_dimension"
            elif profile_id == "disk-spill":
                capability_alignment = "nginx_client_body_disk_spill"
            elif profile_id == "gateway-restart":
                capability_alignment = "proxy_process_restart_recovery"
            else:
                capability_alignment = "a3s_openai_validation_vs_nginx_transport"
            profiles[profile_id] = {
                "label": label,
                "workload": workload,
                "capability_alignment": capability_alignment,
                "scenario": expected_scenario,
                "products": products,
                "comparison": compare(a3s, nginx),
            }

    payload = {
        "schema_version": OUTPUT_SCHEMA,
        "commit": args.commit,
        "run_url": args.run_url,
        "generated_at": args.generated_at,
        "environment": {
            "runner_image": args.runner_image,
            "cpu_model": args.cpu_model,
            "logical_cpus": args.logical_cpus,
            "memory_mib": args.memory_mib,
            "kernel": args.kernel,
        },
        "versions": {
            "a3s_gateway": args.a3s_version,
            "nginx": args.nginx_version,
            "deterministic_upstream": args.upstream_version,
            "streaming_load_client": args.load_version,
        },
        "methodology": {
            "scope": (
                "Same-host OpenAI-compatible streaming comparison against one "
                "deterministic upstream. A3S performs bounded OpenAI JSON/model "
                "validation; NGINX is a transport-only baseline."
            ),
            "trials": args.trials,
            "aggregation": (
                "Median of repeated trials; A3S and NGINX execution order alternates "
                "by trial for every profile. Every raw trial remains embedded."
            ),
            "clock": "Load-generator monotonic clock; stored latency unit is microseconds.",
            "token_definition": (
                "One decoded non-terminal SSE data event with the next exact "
                "benchmark_sequence value; network chunks are never counted as tokens."
            ),
            "correctness_gate": (
                "100% HTTP success, SSE content type, exact monotonic sequence, exact "
                "token count, one [DONE] marker, and no post-terminal bytes."
            ),
            "nginx_streaming": (
                "HTTP/1.1 upstream keep-alive, response buffering/cache/compression "
                "disabled, request buffering enabled with a 512 KiB client-body "
                "buffer for the core prompt profiles, and 120-second timeouts."
            ),
            "threshold": "Ratios within 3% are marked within threshold.",
        },
        "profiles": profiles,
        "limitations": [
            "GitHub-hosted runners are shared regression infrastructure, not a controlled capacity lab.",
            "The synthetic upstream isolates Gateway transport and request-processing behavior; it does not represent model compute time or quality.",
            "A3S OpenAI validation and NGINX transport-only forwarding are customer-visible product paths but are not policy-capability equivalent.",
            "Policy lanes such as telemetry-on report A3S absolute medians and mark NGINX unsupported unless a pinned equivalent module is supplied.",
            "Cold A3S Box/Sandbox lifecycle and dedicated real-model evidence are separate benchmark lanes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    summary: dict[str, Any] = {}
    for profile_id, profile in profiles.items():
        entry: dict[str, Any] = {
            "a3s": profile["products"]["a3s-gateway"]["median"],
            "comparison": profile["comparison"],
        }
        if "nginx" in profile["products"]:
            entry["nginx"] = profile["products"]["nginx"]["median"]
        summary[profile_id] = entry
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        message = (
            str(error)
            .replace("%", "%25")
            .replace("\r", "%0D")
            .replace("\n", "%0A")
        )
        print(
            "::error file=scripts/export-ai-gateway-comparison.py,"
            f"title=AI comparison export failed::{message}",
            file=sys.stderr,
        )
        raise
