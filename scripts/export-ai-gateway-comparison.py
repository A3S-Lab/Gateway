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
    "prompt-256k": (
        "256 KiB prompt",
        "256 KiB chat prompt with a paced token stream",
    ),
}
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
    if scenario.get("endpoint") not in {"chat", "completions"}:
        raise ValueError(f"{path} scenario has an invalid endpoint")
    model = scenario.get("model")
    if not isinstance(model, str) or not model:
        raise ValueError(f"{path} scenario has an invalid model")
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
    if payload.get("completed_requests") != requests:
        raise ValueError(f"{path} did not complete every measured request")
    if payload.get("failed_requests") != 0 or payload.get("success_rate") != 1.0:
        raise ValueError(f"{path} did not achieve a 100% valid stream rate")
    if payload.get("completed_tokens") != requests * token_count:
        raise ValueError(f"{path} completed-token count is inconsistent")
    if payload.get("error_samples") != []:
        raise ValueError(f"{path} contains benchmark errors")
    if not finite_positive(payload.get("measured_seconds")):
        raise ValueError(f"{path} measured interval is invalid")
    for field in RATE_FIELDS:
        if not finite_positive(payload.get(field)):
            raise ValueError(f"{path} has invalid {field}")

    validate_distribution(payload.get("ttft"), requests, "ttft", path)
    validate_distribution(payload.get("end_to_end"), requests, "end_to_end", path)
    if token_count > 1:
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
        raise ValueError(f"{path} single-token stream must not publish ITL or TPOT")
    return payload


def aggregate_trials(trials: list[dict[str, Any]]) -> dict[str, Any]:
    distributions: dict[str, Any] = {}
    for name in DISTRIBUTIONS:
        values = [trial[name] for trial in trials]
        if values[0] is None:
            distributions[name] = None
            continue
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
        for product in PRODUCTS:
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
            products[product] = {
                "trials": trials,
                "median": aggregate_trials(trials),
            }

        label, workload = PROFILE_DETAILS[profile_id]
        a3s = products["a3s-gateway"]["median"]
        nginx = products["nginx"]["median"]
        profiles[profile_id] = {
            "label": label,
            "workload": workload,
            "capability_alignment": "a3s_openai_validation_vs_nginx_transport",
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
            "Cold A3S Box/Sandbox lifecycle and dedicated real-model evidence are separate benchmark lanes.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                profile_id: {
                    "a3s": profile["products"]["a3s-gateway"]["median"],
                    "nginx": profile["products"]["nginx"]["median"],
                    "comparison": profile["comparison"],
                }
                for profile_id, profile in profiles.items()
            },
            indent=2,
        )
    )
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
