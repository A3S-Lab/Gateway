#!/usr/bin/env python3
"""Export Criterion estimates and the runner identity as stable website JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


EXPECTED_COUNTS = {
    "router_match": 9,
    "middleware_pipeline": 4,
    "acl_parse": 3,
}

GROUP_ORDER = {name: index for index, name in enumerate(EXPECTED_COUNTS)}
SCENARIO_ORDER = {
    "highest_priority_match": 0,
    "lowest_priority_match": 1,
    "no_match": 2,
    "process_request": 0,
    "services": 0,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--criterion-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-url", required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--runner-image", required=True)
    parser.add_argument("--cpu-model", required=True)
    parser.add_argument("--logical-cpus", type=int, required=True)
    parser.add_argument("--memory-mib", type=int, required=True)
    parser.add_argument("--kernel", required=True)
    parser.add_argument("--rustc", required=True)
    return parser.parse_args()


def load_results(root: Path) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for estimate_path in root.glob("*/*/*/new/estimates.json"):
        relative = estimate_path.relative_to(root)
        group, scenario, parameter = relative.parts[:3]
        if group not in EXPECTED_COUNTS:
            continue

        try:
            parameter_value = int(parameter)
        except ValueError as error:
            raise ValueError(f"non-numeric benchmark parameter: {relative}") from error

        estimates = json.loads(estimate_path.read_text(encoding="utf-8"))
        median = estimates["median"]
        confidence = median["confidence_interval"]
        median_ns = float(median["point_estimate"])
        results.append(
            {
                "group": group,
                "scenario": scenario,
                "parameter": parameter_value,
                "median_ns": round(median_ns, 3),
                "ci95_lower_ns": round(float(confidence["lower_bound"]), 3),
                "ci95_upper_ns": round(float(confidence["upper_bound"]), 3),
                "operations_per_second": round(1_000_000_000 / median_ns),
            }
        )

    counts = {
        group: sum(result["group"] == group for result in results)
        for group in EXPECTED_COUNTS
    }
    if counts != EXPECTED_COUNTS:
        raise ValueError(
            f"incomplete Criterion export: expected {EXPECTED_COUNTS}, found {counts}"
        )

    results.sort(
        key=lambda result: (
            GROUP_ORDER[str(result["group"])],
            SCENARIO_ORDER.get(str(result["scenario"]), 99),
            int(result["parameter"]),
        )
    )
    return results


def format_duration(nanoseconds: float) -> str:
    if nanoseconds < 1_000:
        return f"{nanoseconds:.1f} ns"
    if nanoseconds < 1_000_000:
        return f"{nanoseconds / 1_000:.2f} µs"
    return f"{nanoseconds / 1_000_000:.2f} ms"


def write_markdown(path: Path, payload: dict[str, object]) -> None:
    lines = [
        "## A3S Gateway Criterion baseline",
        "",
        f"Commit: `{payload['commit']}`",
        "",
        "| Group | Scenario | Size | Median | 95% CI |",
        "| --- | --- | ---: | ---: | ---: |",
    ]
    for result in payload["results"]:
        lines.append(
            "| {group} | {scenario} | {parameter} | {median} | {lower}–{upper} |".format(
                **result,
                median=format_duration(float(result["median_ns"])),
                lower=format_duration(float(result["ci95_lower_ns"])),
                upper=format_duration(float(result["ci95_upper_ns"])),
            )
        )
    lines.extend(
        [
            "",
            "> In-process microbenchmarks on a shared GitHub-hosted runner. "
            "They exclude sockets, TLS, upstream latency, and client overhead.",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    results = load_results(args.criterion_root)
    payload: dict[str, object] = {
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
            "rustc": args.rustc,
        },
        "methodology": {
            "framework": "Criterion 0.5.1",
            "sample_size": 100,
            "warm_up_seconds": 2,
            "measurement_seconds": 5,
            "scope": "In-process operations; excludes sockets, TLS, upstream, and client overhead.",
        },
        "results": results,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    if args.markdown_output:
        write_markdown(args.markdown_output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
