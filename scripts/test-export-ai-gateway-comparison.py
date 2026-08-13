#!/usr/bin/env python3
"""Unit coverage for the token-aware AI comparison exporter."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


SCRIPT = Path(__file__).with_name("export-ai-gateway-comparison.py")
RUNNER = Path(__file__).with_name("run-ai-gateway-comparison.sh")
FIXTURE_ROOT = SCRIPT.parent.parent / "benchmarks" / "ai-gateway-comparison"
SPEC = importlib.util.spec_from_file_location("ai_comparison_exporter", SCRIPT)
assert SPEC and SPEC.loader
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


def distribution(samples: int, base: int) -> dict[str, int | float]:
    return {
        "samples": samples,
        "min_us": base,
        "mean_us": base + 5.0,
        "p50_us": base + 4,
        "p90_us": base + 8,
        "p95_us": base + 9,
        "p99_us": base + 10,
        "max_us": base + 11,
    }


def trial_payload(product: str, trial: int) -> dict[str, object]:
    requests = 4
    tokens = 4
    product_offset = 0 if product == "a3s-gateway" else 100
    trial_offset = trial * 10
    base = 100 + product_offset + trial_offset
    goodput = 1100.0 - product_offset + trial_offset
    return {
        "schema_version": EXPORTER.TRIAL_SCHEMA,
        "generated_at": "2026-08-13T00:00:00Z",
        "product": product,
        "trial": trial,
        "target": "http://127.0.0.1:18101",
        "scenario": {
            "endpoint": "chat",
            "model": "bench",
            "concurrency": 2,
            "requests": requests,
            "token_count": tokens,
            "first_token_delay_ms": 50,
            "token_interval_ms": 10,
            "prompt_bytes": 1024,
            "request_timeout_seconds": 120,
        },
        "warmup_requests": 2,
        "completed_requests": requests,
        "failed_requests": 0,
        "success_rate": 1.0,
        "completed_tokens": requests * tokens,
        "measured_seconds": 1.0,
        "streams_per_second": goodput / tokens,
        "token_goodput_per_second": goodput,
        "ttft": distribution(requests, base),
        "inter_token_latency": distribution(requests * (tokens - 1), base + 20),
        "time_per_output_token": distribution(requests, base + 30),
        "end_to_end": distribution(requests, base + 40),
        "error_samples": [],
    }


class ExporterTests(unittest.TestCase):
    def test_fixtures_preserve_the_streaming_fairness_contract(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        nginx = (FIXTURE_ROOT / "nginx.conf").read_text(encoding="utf-8")
        gateway = (FIXTURE_ROOT / "gateway.acl").read_text(encoding="utf-8")
        self.assertIn("trial % 2", runner)
        self.assertIn("proxy_buffering off;", nginx)
        self.assertIn("proxy_request_buffering on;", nginx)
        self.assertIn('proxy_set_header Connection "";', nginx)
        self.assertIn("client_body_buffer_size 512k;", nginx)
        self.assertIn("client_max_body_size 8m;", nginx)
        self.assertIn('stream_idle_timeout  = "120s"', gateway)
        self.assertIn('stream_total_timeout = "120s"', gateway)

    def test_trial_validation_rejects_silent_token_loss(self) -> None:
        payload = trial_payload("a3s-gateway", 1)
        payload["completed_tokens"] = 15
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trial.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "completed-token"):
                EXPORTER.read_trial(path, "a3s-gateway", 1)

    def test_trial_validation_rejects_inconsistent_distribution_counts(self) -> None:
        payload = trial_payload("nginx", 1)
        payload["inter_token_latency"]["samples"] = 11
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trial.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "expected 12"):
                EXPORTER.read_trial(path, "nginx", 1)

    def test_relative_positions_keep_the_three_percent_neutral_band(self) -> None:
        self.assertEqual(
            EXPORTER.relative_position(102.0, 100.0, False),
            "within_threshold",
        )
        self.assertEqual(
            EXPORTER.relative_position(90.0, 100.0, True),
            "a3s_lower",
        )

    def test_main_embeds_raw_trials_and_median_token_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for product in EXPORTER.PRODUCTS:
                for trial in (1, 2):
                    path = root / f"stream-paced-c16-{product}-{trial}.json"
                    path.write_text(
                        json.dumps(trial_payload(product, trial)), encoding="utf-8"
                    )
            output = root / "ai-comparison.json"
            argv = [
                str(SCRIPT),
                "--input",
                str(root),
                "--output",
                str(output),
                "--profiles",
                "stream-paced-c16",
                "--trials",
                "2",
                "--commit",
                "a" * 40,
                "--run-url",
                "https://github.com/A3S-Lab/Gateway/actions/runs/1",
                "--generated-at",
                "2026-08-13T00:00:00Z",
                "--runner-image",
                "ubuntu-24.04",
                "--cpu-model",
                "test",
                "--logical-cpus",
                "4",
                "--memory-mib",
                "16000",
                "--kernel",
                "Linux",
                "--a3s-version",
                "a3s-gateway 1.0.13",
                "--nginx-version",
                "nginx/1.26.0",
                "--upstream-version",
                "ai_benchmark_upstream 1.0.13",
                "--load-version",
                "ai_benchmark_load 1.0.13",
            ]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                self.assertEqual(EXPORTER.main(), 0)
            result = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(result["schema_version"], EXPORTER.OUTPUT_SCHEMA)
        profile = result["profiles"]["stream-paced-c16"]
        self.assertEqual(len(profile["products"]["a3s-gateway"]["trials"]), 2)
        self.assertEqual(
            profile["products"]["a3s-gateway"]["median"]["ttft"]["p50_us"],
            119,
        )
        self.assertGreater(
            profile["comparison"]["a3s_to_nginx_token_goodput_ratio"], 1
        )
        self.assertEqual(
            profile["comparison"]["positions"]["ttft_p50"], "a3s_lower"
        )


if __name__ == "__main__":
    unittest.main()
