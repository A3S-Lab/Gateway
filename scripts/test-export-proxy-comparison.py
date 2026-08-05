#!/usr/bin/env python3
"""Unit coverage for the multi-protocol comparison exporter."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("export-proxy-comparison.py")
SPEC = importlib.util.spec_from_file_location("proxy_exporter", SCRIPT)
assert SPEC and SPEC.loader
EXPORTER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXPORTER)


class ExporterTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
