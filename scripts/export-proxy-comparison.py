#!/usr/bin/env python3
"""Export repeated wrk runs as a machine-readable proxy comparison."""

from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from pathlib import Path


DURATION_UNITS_US = {
    "ns": 0.001,
    "us": 1.0,
    "µs": 1.0,
    "ms": 1_000.0,
    "s": 1_000_000.0,
}


def duration_us(value: str, unit: str) -> float:
    return float(value) * DURATION_UNITS_US[unit]


def parse_wrk(path: Path) -> dict[str, float]:
    content = path.read_text(encoding="utf-8")
    average = re.search(r"^\s*Latency\s+([0-9.]+)(ns|us|µs|ms|s)\s", content, re.MULTILINE)
    requests = re.search(r"^Requests/sec:\s+([0-9.]+)\s*$", content, re.MULTILINE)
    if not average or not requests:
        raise ValueError(f"cannot parse wrk summary from {path}")

    result = {
        "requests_per_second": float(requests.group(1)),
        "average_latency_us": duration_us(average.group(1), average.group(2)),
    }
    for percentile in (50, 90, 99):
        match = re.search(
            rf"^\s*{percentile}%\s+([0-9.]+)(ns|us|µs|ms|s)\s*$",
            content,
            re.MULTILINE,
        )
        if not match:
            raise ValueError(f"wrk output {path} is missing P{percentile}")
        result[f"p{percentile}_latency_us"] = duration_us(match.group(1), match.group(2))
    return result


def median_metrics(paths: list[Path]) -> tuple[list[dict[str, float]], dict[str, float]]:
    trials = [parse_wrk(path) for path in paths]
    medians = {
        key: statistics.median(trial[key] for trial in trials)
        for key in trials[0]
    }
    return trials, medians


def metric_verdict(a3s: float, nginx: float, lower_is_better: bool) -> str:
    ratio = a3s / nginx
    if lower_is_better:
        ratio = 1 / ratio
    if ratio >= 1.03:
        return "better"
    if ratio <= 0.97:
        return "worse"
    return "similar"


def finite_positive_metrics(metrics: dict[str, float]) -> bool:
    return all(math.isfinite(value) and value > 0 for value in metrics.values())


def main() -> int:
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
    parser.add_argument("--trials", type=int, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--threads", type=int, required=True)
    parser.add_argument("--connections", type=int, required=True)
    args = parser.parse_args()

    proxies: dict[str, dict[str, object]] = {}
    for proxy in ("a3s-gateway", "nginx"):
        paths = [args.input / f"{proxy}-{index}.txt" for index in range(1, args.trials + 1)]
        if not all(path.is_file() for path in paths):
            raise FileNotFoundError(f"missing one or more {proxy} trial files")
        trials, medians = median_metrics(paths)
        if not finite_positive_metrics(medians):
            raise ValueError(f"{proxy} contains an invalid median")
        proxies[proxy] = {"trials": trials, "median": medians}

    a3s = proxies["a3s-gateway"]["median"]
    nginx = proxies["nginx"]["median"]
    assert isinstance(a3s, dict) and isinstance(nginx, dict)
    verdicts = {
        "throughput": metric_verdict(a3s["requests_per_second"], nginx["requests_per_second"], False),
        "p50_latency": metric_verdict(a3s["p50_latency_us"], nginx["p50_latency_us"], True),
        "p90_latency": metric_verdict(a3s["p90_latency_us"], nginx["p90_latency_us"], True),
        "p99_latency": metric_verdict(a3s["p99_latency_us"], nginx["p99_latency_us"], True),
    }

    payload = {
        "schema_version": 1,
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
            "load_generator": "wrk from Ubuntu 24.04",
        },
        "methodology": {
            "scope": "Same-host HTTP/1.1 keep-alive reverse proxy comparison; one route, one shared local NGINX upstream, a 42-byte JSON body, no TLS, no middleware, and access logs disabled.",
            "trials": args.trials,
            "duration_seconds_per_trial": args.duration_seconds,
            "threads": args.threads,
            "connections": args.connections,
            "aggregation": "Median of repeated trials; order alternates between products.",
            "threshold": "A metric is better or worse at a difference of at least 3%; otherwise it is similar.",
        },
        "proxies": proxies,
        "comparison": {
            "a3s_to_nginx_throughput_ratio": a3s["requests_per_second"] / nginx["requests_per_second"],
            "a3s_to_nginx_p50_latency_ratio": a3s["p50_latency_us"] / nginx["p50_latency_us"],
            "a3s_to_nginx_p90_latency_ratio": a3s["p90_latency_us"] / nginx["p90_latency_us"],
            "a3s_to_nginx_p99_latency_ratio": a3s["p99_latency_us"] / nginx["p99_latency_us"],
            "verdicts": verdicts,
        },
        "limitations": [
            "The GitHub-hosted runner is shared infrastructure and not a controlled bare-metal lab.",
            "This workload measures a small HTTP response and does not represent TLS, streaming, gRPC, WebSocket, AI policy, or upstream-dominated latency.",
            "The result compares the checked-in A3S release profile with the Ubuntu-packaged NGINX build; it is not a universal product ranking.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"medians": {name: value["median"] for name, value in proxies.items()}, "verdicts": verdicts}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
