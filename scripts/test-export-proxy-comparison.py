#!/usr/bin/env python3
"""Unit coverage for the multi-protocol comparison exporter."""

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


SCRIPT = Path(__file__).with_name("export-proxy-comparison.py")
RUNNER = Path(__file__).with_name("run-proxy-comparison.sh")
NGINX_FIXTURE = SCRIPT.parent.parent / "benchmarks" / "proxy-comparison" / "nginx-gateway.conf"
SPEC = importlib.util.spec_from_file_location("proxy_exporter", SCRIPT)
assert SPEC and SPEC.loader
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class ExporterTests(unittest.TestCase):
    def test_http2_trials_drain_without_nginx_connection_rotation(self) -> None:
        runner = RUNNER.read_text(encoding="utf-8")
        nginx = NGINX_FIXTURE.read_text(encoding="utf-8")
        self.assertIn("--wait-ongoing-requests-after-deadline", runner)
        self.assertIn("keepalive_requests 1000000;", nginx)

    def test_parses_oha_seconds_as_microseconds(self) -> None:
        payload = {
            "summary": {
                "successRate": 1.0,
                "requestsPerSec": 1234.5,
                "average": 0.0015,
            },
            "latencyPercentiles": {
                "p50": 0.001,
                "p90": 0.002,
                "p99": 0.003,
            },
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oha.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            metrics = EXPORTER.parse_oha(path)
        self.assertEqual(metrics["operations_per_second"], 1234.5)
        self.assertEqual(metrics["average_latency_us"], 1500.0)
        self.assertEqual(metrics["p99_latency_us"], 3000.0)

    def test_parses_protocol_load_metrics(self) -> None:
        payload = {
            "schema_version": 1,
            "success_rate": 1.0,
            "operations_per_second": 500.0,
            "average_latency_us": 120.0,
            "p50_latency_us": 100.0,
            "p90_latency_us": 200.0,
            "p99_latency_us": 400.0,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protocol.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            metrics = EXPORTER.parse_protocol_load(path)
        self.assertEqual(metrics["operations_per_second"], 500.0)

    def test_reports_neutral_relative_positions(self) -> None:
        self.assertEqual(
            EXPORTER.relative_position(102.0, 100.0, False),
            "within_threshold",
        )
        self.assertEqual(
            EXPORTER.relative_position(110.0, 100.0, False),
            "a3s_higher",
        )
        self.assertEqual(
            EXPORTER.relative_position(110.0, 100.0, True),
            "nginx_lower",
        )

    def test_main_exports_every_traffic_profile(self) -> None:
        oha = {
            "summary": {
                "successRate": 1.0,
                "requestsPerSec": 1000.0,
                "average": 0.001,
            },
            "latencyPercentiles": {
                "p50": 0.0008,
                "p90": 0.0015,
                "p99": 0.002,
            },
        }
        protocol = {
            "schema_version": 1,
            "success_rate": 1.0,
            "operations_per_second": 1000.0,
            "average_latency_us": 1000.0,
            "p50_latency_us": 800.0,
            "p90_latency_us": 1500.0,
            "p99_latency_us": 2000.0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for spec in EXPORTER.PROFILE_SPECS:
                payload = oha if spec["generator"] == "oha" else protocol
                for proxy in ("a3s-gateway", "nginx"):
                    for trial in (1, 2):
                        path = root / f"{spec['id']}-{proxy}-{trial}.json"
                        path.write_text(json.dumps(payload), encoding="utf-8")
            output = root / "comparison.json"
            argv = [
                str(SCRIPT),
                "--input",
                str(root),
                "--output",
                str(output),
                "--commit",
                "a" * 40,
                "--run-url",
                "https://github.com/A3S-Lab/Gateway/actions/runs/1",
                "--generated-at",
                "2026-08-05T00:00:00Z",
                "--runner-image",
                "ubuntu24",
                "--cpu-model",
                "test",
                "--logical-cpus",
                "4",
                "--memory-mib",
                "16000",
                "--kernel",
                "Linux",
                "--a3s-version",
                "a3s-gateway 1.0.12",
                "--nginx-version",
                "nginx/1.24.0",
                "--oha-version",
                "oha 1.15.0",
                "--trials",
                "2",
                "--duration-seconds",
                "10",
                "--warmup-seconds",
                "2",
                "--connections",
                "64",
                "--http2-connections",
                "4",
                "--http2-parallel",
                "16",
            ]
            with patch.object(sys, "argv", argv), redirect_stdout(io.StringIO()):
                self.assertEqual(EXPORTER.main(), 0)
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["schema_version"], 3)
        self.assertEqual(result["methodology"]["warmup_seconds"], 2)
        self.assertIn(
            "keepalive_requests",
            result["methodology"]["completion_policy"],
        )
        self.assertEqual(
            set(result["profiles"]),
            {spec["id"] for spec in EXPORTER.PROFILE_SPECS},
        )


if __name__ == "__main__":
    unittest.main()
