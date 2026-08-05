#!/usr/bin/env python3
"""Export repeated multi-protocol runs as one proxy comparison matrix."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from pathlib import Path


PROFILE_SPECS = (
    {
        "id": "http1-small",
        "label": "HTTP/1.1",
        "traffic": "http",
        "unit": "requests/s",
        "generator": "oha",
        "alignment": "equivalent",
        "workload": "GET, keep-alive, 42-byte JSON response",
    },
    {
        "id": "https-http1",
        "label": "HTTPS · HTTP/1.1",
        "traffic": "encrypted-http",
        "unit": "requests/s",
        "generator": "oha",
        "alignment": "equivalent",
        "workload": "GET, downstream TLS termination, keep-alive",
    },
    {
        "id": "https-http2",
        "label": "HTTPS · HTTP/2",
        "traffic": "multiplexed-http",
        "unit": "requests/s",
        "generator": "oha",
        "alignment": "equivalent",
        "workload": "GET, downstream TLS termination, 4 connections × 16 streams",
    },
    {
        "id": "grpc-unary",
        "label": "gRPC unary",
        "traffic": "grpc",
        "unit": "requests/s",
        "generator": "oha",
        "alignment": "equivalent",
        "workload": "Empty unary message, downstream HTTP/2 TLS, h2c upstream",
    },
    {
        "id": "sse-finite",
        "label": "SSE",
        "traffic": "server-streaming",
        "unit": "streams/s",
        "generator": "oha",
        "alignment": "equivalent",
        "workload": "Finite three-event stream, HTTP/1.1, buffering disabled",
    },
    {
        "id": "websocket-echo",
        "label": "WebSocket",
        "traffic": "bidirectional-message",
        "unit": "messages/s",
        "generator": "protocol-load",
        "alignment": "equivalent",
        "workload": "64 persistent connections, 32-byte binary echo",
    },
    {
        "id": "tcp-echo",
        "label": "TCP",
        "traffic": "layer-4-stream",
        "unit": "round trips/s",
        "generator": "protocol-load",
        "alignment": "equivalent",
        "workload": "64 persistent connections, 32-byte echo",
    },
    {
        "id": "udp-echo",
        "label": "UDP",
        "traffic": "layer-4-datagram",
        "unit": "round trips/s",
        "generator": "protocol-load",
        "alignment": "equivalent",
        "workload": "64 connected sockets, 32-byte datagram echo",
    },
    {
        "id": "openai-json",
        "label": "OpenAI JSON",
        "traffic": "ai-request",
        "unit": "requests/s",
        "generator": "oha",
        "alignment": "a3s_feature_enabled_vs_nginx_transport",
        "workload": "Chat Completions JSON validation and forwarding",
    },
    {
        "id": "openai-stream",
        "label": "OpenAI stream",
        "traffic": "ai-streaming",
        "unit": "streams/s",
        "generator": "oha",
        "alignment": "a3s_feature_enabled_vs_nginx_transport",
        "workload": "Completions JSON stream detection and finite SSE forwarding",
    },
)

METRICS = (
    "operations_per_second",
    "average_latency_us",
    "p50_latency_us",
    "p90_latency_us",
    "p99_latency_us",
)


def parse_oha(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    summary = payload["summary"]
    percentiles = payload["latencyPercentiles"]
    metrics = {
        "success_rate": float(summary["successRate"]),
        "operations_per_second": float(summary["requestsPerSec"]),
        "average_latency_us": float(summary["average"]) * 1_000_000,
        "p50_latency_us": float(percentiles["p50"]) * 1_000_000,
        "p90_latency_us": float(percentiles["p90"]) * 1_000_000,
        "p99_latency_us": float(percentiles["p99"]) * 1_000_000,
    }
    validate_trial(metrics, path)
    return metrics


def parse_protocol_load(path: Path) -> dict[str, float]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError(f"{path} has an unsupported protocol-load schema")
    metrics = {
        "success_rate": float(payload["success_rate"]),
        **{metric: float(payload[metric]) for metric in METRICS},
    }
    validate_trial(metrics, path)
    return metrics


def validate_trial(metrics: dict[str, float], path: Path) -> None:
    if not all(math.isfinite(value) and value > 0 for value in metrics.values()):
        raise ValueError(f"{path} contains a non-positive or non-finite metric")
    if metrics["success_rate"] < 0.999:
        raise ValueError(f"{path} success rate is below 99.9%")


def median_metrics(
    paths: list[Path], generator: str
) -> tuple[list[dict[str, float]], dict[str, float]]:
    parser = parse_oha if generator == "oha" else parse_protocol_load
    trials = [parser(path) for path in paths]
    medians = {
        key: statistics.median(trial[key] for trial in trials) for key in trials[0]
    }
    return trials, medians


def relative_position(a3s: float, nginx: float, lower_is_preferred: bool) -> str:
    ratio = a3s / nginx
    if 0.97 < ratio < 1.03:
        return "within_threshold"
    if lower_is_preferred:
        return "a3s_lower" if ratio < 1 else "nginx_lower"
    return "a3s_higher" if ratio > 1 else "nginx_higher"


def comparison(a3s: dict[str, float], nginx: dict[str, float]) -> dict[str, object]:
    return {
        "a3s_to_nginx_throughput_ratio": (
            a3s["operations_per_second"] / nginx["operations_per_second"]
        ),
        "a3s_to_nginx_p50_latency_ratio": (
            a3s["p50_latency_us"] / nginx["p50_latency_us"]
        ),
        "a3s_to_nginx_p90_latency_ratio": (
            a3s["p90_latency_us"] / nginx["p90_latency_us"]
        ),
        "a3s_to_nginx_p99_latency_ratio": (
            a3s["p99_latency_us"] / nginx["p99_latency_us"]
        ),
        "positions": {
            "throughput": relative_position(
                a3s["operations_per_second"],
                nginx["operations_per_second"],
                False,
            ),
            "p50_latency": relative_position(
                a3s["p50_latency_us"], nginx["p50_latency_us"], True
            ),
            "p90_latency": relative_position(
                a3s["p90_latency_us"], nginx["p90_latency_us"], True
            ),
            "p99_latency": relative_position(
                a3s["p99_latency_us"], nginx["p99_latency_us"], True
            ),
        },
    }


def compatibility_metrics(metrics: dict[str, float]) -> dict[str, float]:
    """Keep the HTTP/1.1 top-level shape readable by older site clients."""
    return {
        "success_rate": metrics["success_rate"],
        "requests_per_second": metrics["operations_per_second"],
        "average_latency_us": metrics["average_latency_us"],
        "p50_latency_us": metrics["p50_latency_us"],
        "p90_latency_us": metrics["p90_latency_us"],
        "p99_latency_us": metrics["p99_latency_us"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    parser.add_argument("--oha-version", required=True)
    parser.add_argument("--trials", type=int, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--warmup-seconds", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    parser.add_argument("--http2-connections", type=int, required=True)
    parser.add_argument("--http2-parallel", type=int, required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    profiles: dict[str, dict[str, object]] = {}

    for spec in PROFILE_SPECS:
        proxies: dict[str, dict[str, object]] = {}
        for proxy in ("a3s-gateway", "nginx"):
            paths = [
                args.input / f"{spec['id']}-{proxy}-{index}.json"
                for index in range(1, args.trials + 1)
            ]
            missing = [str(path) for path in paths if not path.is_file()]
            if missing:
                raise FileNotFoundError(f"missing trial files: {missing}")
            trials, medians = median_metrics(paths, str(spec["generator"]))
            proxies[proxy] = {"trials": trials, "median": medians}

        a3s = proxies["a3s-gateway"]["median"]
        nginx = proxies["nginx"]["median"]
        assert isinstance(a3s, dict) and isinstance(nginx, dict)
        profiles[str(spec["id"])] = {
            "label": spec["label"],
            "traffic": spec["traffic"],
            "unit": spec["unit"],
            "load_generator": spec["generator"],
            "capability_alignment": spec["alignment"],
            "workload": spec["workload"],
            "proxies": proxies,
            "comparison": comparison(a3s, nginx),
        }

    http1 = profiles["http1-small"]
    http1_proxies = http1["proxies"]
    assert isinstance(http1_proxies, dict)
    compatibility_proxies = {
        proxy: {
            "trials": [
                compatibility_metrics(trial)
                for trial in result["trials"]
            ],
            "median": compatibility_metrics(result["median"]),
        }
        for proxy, result in http1_proxies.items()
    }

    payload = {
        "schema_version": 3,
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
            "load_generators": {
                "oha": args.oha_version,
                "protocol_load": f"a3s-gateway {args.commit[:8]}",
            },
        },
        "methodology": {
            "scope": (
                "Same-host comparison across every traffic type supported by the "
                "Gateway data plane: HTTP/1.1, HTTPS, HTTP/2, gRPC, SSE, WebSocket, "
                "TCP, UDP, OpenAI JSON, and OpenAI streaming."
            ),
            "trials": args.trials,
            "duration_seconds_per_trial": args.duration_seconds,
            "warmup_seconds": args.warmup_seconds,
            "connections": args.connections,
            "http2_concurrency": {
                "connections": args.http2_connections,
                "parallel_streams_per_connection": args.http2_parallel,
            },
            "aggregation": (
                "Median of repeated trials. Product order alternates on each trial "
                "for every traffic profile."
            ),
            "threshold": (
                "Ratios within 3% are marked within threshold; other results state "
                "which measured value is higher or which latency is lower."
            ),
        },
        "profiles": profiles,
        "proxies": compatibility_proxies,
        "comparison": http1["comparison"],
        "limitations": [
            "GitHub-hosted runners are shared infrastructure, not a controlled bare-metal lab.",
            "Each fixture is a small synthetic same-host workload; absolute rates do not predict an upstream-dominated production deployment.",
            "OpenAI profiles enable Gateway JSON and stream detection while NGINX remains a transport-only baseline, so those rows measure feature cost rather than equivalent policy capability.",
            "The matrix compares the checked-in A3S release profile with the Ubuntu-packaged NGINX build; it is not a universal product ranking.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    summary = {
        profile_id: {
            "a3s": profile["proxies"]["a3s-gateway"]["median"],
            "nginx": profile["proxies"]["nginx"]["median"],
            "ratios": profile["comparison"],
        }
        for profile_id, profile in profiles.items()
    }
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
            f"::error file=scripts/export-proxy-comparison.py,"
            f"title=Comparison export failed::{message}",
            file=sys.stderr,
        )
        raise
