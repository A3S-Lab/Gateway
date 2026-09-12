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

    def test_trial_validation_rejects_combined_disconnect_and_read_delay(self) -> None:
        payload = trial_payload("a3s-gateway", 1)
        payload["scenario"]["disconnect_after_tokens"] = 1
        payload["scenario"]["read_delay_ms"] = 50
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trial.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "cannot combine"):
                EXPORTER.read_trial(path, "a3s-gateway", 1)

    def test_prompt_limit_lanes_use_target_body_bytes(self) -> None:
        self.assertIn("prompt-limit", EXPORTER.PROFILE_DETAILS)
        self.assertIn("prompt-over-limit", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("prompt-limit)", runner)
        self.assertIn("prompt-over-limit)", runner)
        self.assertIn("target_body_bytes=", runner)
        self.assertIn("--target-body-bytes", runner)
        self.assertIn("declare_content_length=", runner)
        self.assertIn("--declare-content-length", runner)
        self.assertIn("require_all_rejections=1", runner)
        self.assertIn("--require-all-rejections", runner)
        self.assertIn("accept_http_status=413", runner)
        load = (SCRIPT.parent.parent / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("target_body_bytes", load)
        self.assertIn("declare_content_length", load)
        self.assertIn("measure_declared_content_length", load)
        self.assertIn("require_all_rejections", load)
        self.assertIn("OPENAI_REQUEST_BODY_LIMIT", load)

    def test_thundering_and_mixed_lanes(self) -> None:
        self.assertIn("thundering-herd", EXPORTER.PROFILE_DETAILS)
        self.assertIn("mixed-short-long", EXPORTER.PROFILE_DETAILS)
        self.assertIn("steady-arrival", EXPORTER.PROFILE_DETAILS)
        for point in (
            "concurrency-sweep-c1",
            "concurrency-sweep-c4",
            "concurrency-sweep-c16",
            "concurrency-sweep-c64",
            "concurrency-sweep-c256",
            "concurrency-sweep-c1024",
        ):
            self.assertIn(point, EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("concurrency-sweep", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("thundering-herd)", runner)
        self.assertIn("mixed-short-long)", runner)
        self.assertIn("steady-arrival)", runner)
        self.assertIn("concurrency-sweep)", runner)
        self.assertIn("concurrency-sweep-c1|concurrency-sweep-c4", runner)
        self.assertIn("concurrency=256", runner)
        self.assertIn("long_every=10", runner)
        self.assertIn("long_token_count=1024", runner)
        self.assertIn("poisson_arrival_rps=32", runner)
        self.assertIn("arrival_seed=20260912", runner)
        self.assertIn("--long-every", runner)
        self.assertIn("--long-token-count", runner)
        self.assertIn("--poisson-arrival-rps", runner)
        self.assertIn("--arrival-seed", runner)
        load = (SCRIPT.parent.parent / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("long_every", load)
        self.assertIn("effective_token_count", load)
        self.assertIn("mixed_request_counts", load)
        self.assertIn("poisson_arrival_offsets_ms", load)
        self.assertIn("execute_poisson_batch", load)
        self.assertIn("stream-overhead-c1", EXPORTER.PROFILE_DETAILS)
        self.assertIn("sse-transport-c1", EXPORTER.PROFILE_DETAILS)
        self.assertIn("sse-transport-c64", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("sse-transport-c1", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("sse-transport-c1)", runner)
        self.assertIn("sse-transport-c64)", runner)
        self.assertIn("endpoint=sse-transport", runner)
        self.assertIn("SseTransport", load)
        self.assertIn("/benchmark/sse", load)
        upstream = (SCRIPT.parent.parent / "examples" / "ai_benchmark_upstream.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("/benchmark/sse", upstream)
        self.assertIn("SseTransportRequest", upstream)
        self.assertIn("request-buffering-on", EXPORTER.PROFILE_DETAILS)
        self.assertIn("request-buffering-off", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("request-buffering-on", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("request-buffering-on)", runner)
        self.assertIn("request-buffering-off)", runner)
        self.assertIn("request_buffering_off_fixture=1", runner)
        self.assertIn("nginx-request-buffering-off.conf", runner)
        self.assertTrue(
            (FIXTURE_ROOT / "nginx-request-buffering-off.conf").is_file(),
            "nginx-request-buffering-off.conf missing",
        )
        nginx_buf_off = (FIXTURE_ROOT / "nginx-request-buffering-off.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("proxy_request_buffering off", nginx_buf_off)
        nginx_default = (FIXTURE_ROOT / "nginx.conf").read_text(encoding="utf-8")
        self.assertIn("proxy_request_buffering on", nginx_default)
        self.assertIn("disk-spill", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("disk-spill", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("disk-spill)", runner)
        self.assertIn("disk_spill_fixture=1", runner)
        self.assertIn("ensure_ai_disk_spill_volume", runner)
        self.assertIn("nginx-disk-spill.conf", runner)
        self.assertTrue(
            (FIXTURE_ROOT / "nginx-disk-spill.conf").is_file(),
            "nginx-disk-spill.conf missing",
        )
        nginx_disk = (FIXTURE_ROOT / "nginx-disk-spill.conf").read_text(encoding="utf-8")
        self.assertIn("client_body_buffer_size 16k", nginx_disk)
        self.assertIn("client_body_temp_path /tmp/a3s-ai-bench-client-body", nginx_disk)
        self.assertIn("disk-spill-volume.txt", runner)
        self.assertIn("gateway-restart", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("gateway-restart", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("gateway-restart)", runner)
        self.assertIn("gateway_restart_fixture=1", runner)
        self.assertIn("restart_proxy_product", runner)
        self.assertIn("restart_recovery_ms", runner)
        exporter_src = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("restart_recovery_ms", exporter_src)
        self.assertIn("proxy_process_restart_recovery", exporter_src)
        self.assertIn("transport-keepalive", EXPORTER.PROFILE_DETAILS)
        self.assertIn("transport-churn", EXPORTER.PROFILE_DETAILS)
        self.assertIn("transport-keepalive)", runner)
        self.assertIn("transport-churn)", runner)
        self.assertIn("force_connection_close=1", runner)
        self.assertIn("--force-connection-close", runner)
        self.assertIn("force_connection_close", load)
        self.assertIn("transport-tls-http1", EXPORTER.PROFILE_DETAILS)
        self.assertIn("transport-tls-http2", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("transport-tls-http1", EXPORTER.A3S_ONLY_PROFILES)
        self.assertNotIn("transport-tls-http2", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("transport-tls-http1)", runner)
        self.assertIn("transport-tls-http2)", runner)
        self.assertIn("gateway-tls.acl", runner)
        self.assertIn("nginx-tls.conf", runner)
        self.assertIn("ensure_ai_tls_material", runner)
        self.assertIn("--insecure-tls", runner)
        self.assertIn("--http2", runner)
        self.assertIn("insecure_tls", load)
        self.assertTrue(
            (FIXTURE_ROOT / "gateway-tls.acl").is_file(),
            "gateway-tls.acl missing",
        )
        self.assertTrue((FIXTURE_ROOT / "nginx-tls.conf").is_file())
        self.assertTrue((FIXTURE_ROOT / "certs" / "bench.crt").is_file())
        self.assertTrue((FIXTURE_ROOT / "certs" / "bench.key").is_file())
        nginx_tls = (FIXTURE_ROOT / "nginx-tls.conf").read_text(encoding="utf-8")
        self.assertIn("ssl_certificate", nginx_tls)
        self.assertIn("ssl http2", nginx_tls)
        self.assertIn("transport-ipv6", EXPORTER.PROFILE_DETAILS)
        self.assertIn("transport-ipv6)", runner)
        self.assertIn("transport-upstream-tls", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("transport-upstream-tls", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("transport-upstream-tls)", runner)
        self.assertIn("gateway-upstream-tls.acl", runner)
        self.assertIn("nginx-upstream-tls.conf", runner)
        self.assertIn("ensure_ai_upstream_tls_material", runner)
        self.assertIn("tls_ca_file", runner)
        self.assertTrue(
            (FIXTURE_ROOT / "gateway-upstream-tls.acl").is_file(),
            "gateway-upstream-tls.acl missing",
        )
        self.assertTrue((FIXTURE_ROOT / "nginx-upstream-tls.conf").is_file())
        gateway_upstream_tls = (FIXTURE_ROOT / "gateway-upstream-tls.acl").read_text(
            encoding="utf-8"
        )
        self.assertIn("tls_ca_file", gateway_upstream_tls)
        self.assertIn("https://127.0.0.1:18100", gateway_upstream_tls)
        nginx_upstream_tls = (FIXTURE_ROOT / "nginx-upstream-tls.conf").read_text(
            encoding="utf-8"
        )
        self.assertIn("proxy_ssl_trusted_certificate", nginx_upstream_tls)
        self.assertIn("proxy_ssl_verify on", nginx_upstream_tls)
        upstream = (SCRIPT.parent.parent / "examples" / "ai_benchmark_upstream.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("tls_cert", upstream)
        self.assertIn("tls_key", upstream)
        self.assertIn("gateway-ipv6.acl", runner)
        self.assertIn("nginx-ipv6.conf", runner)
        self.assertIn("[::1]:18100", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-ipv6.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-ipv6.conf").is_file())
        ipv6_acl = (FIXTURE_ROOT / "gateway-ipv6.acl").read_text(encoding="utf-8")
        self.assertIn("[::1]:18101", ipv6_acl)
        self.assertIn("http://[::1]:18100", ipv6_acl)

    def test_prompt_1k_and_json_large_lanes(self) -> None:
        self.assertIn("prompt-1k", EXPORTER.PROFILE_DETAILS)
        self.assertIn("json-large", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("prompt-1k)", runner)
        self.assertIn("json-large)", runner)
        self.assertIn("prompt_bytes=1024", runner)
        self.assertIn("response_bytes=", runner)
        self.assertIn("--response-bytes", runner)
        load = (SCRIPT.parent.parent / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("response_bytes", load)
        upstream = (
            SCRIPT.parent.parent / "examples" / "ai_benchmark_upstream.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("response_bytes", upstream)

    def test_chunked_upload_lane_is_registered(self) -> None:
        self.assertIn("chunked-upload", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("chunked-upload)", runner)
        self.assertIn("chunked_upload_frames=16", runner)
        self.assertIn("--chunked-upload-frames", runner)
        load = (SCRIPT.parent.parent / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("chunked_upload_frames", load)
        self.assertIn("chunked_request_body", load)

    def test_prompt_1m_profile_is_registered(self) -> None:
        self.assertIn("prompt-1m", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("prompt-1m)", runner)
        self.assertIn("prompt_bytes=1048576", runner)

    def test_json_short_lane_uses_no_stream(self) -> None:
        self.assertIn("json-short", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("json-short)", runner)
        self.assertIn("no_stream=1", runner)
        self.assertIn("--no-stream", runner)
        load = (SCRIPT.parent.parent / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("no_stream", load)
        self.assertIn("measure_json_completion", load)

    def test_slow_reader_profile_is_registered(self) -> None:
        self.assertIn("slow-reader", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("slow-reader)", runner)
        self.assertIn("--read-delay-ms", runner)

    def test_stalled_reader_profile_is_registered(self) -> None:
        self.assertIn("stalled-reader", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("stalled-reader)", runner)
        self.assertIn("--stall-after-tokens", runner)
        self.assertIn("--stall-ms", runner)

    def test_http_fault_profiles_are_registered(self) -> None:
        self.assertIn("http-503", EXPORTER.PROFILE_DETAILS)
        self.assertIn("http-500", EXPORTER.PROFILE_DETAILS)
        self.assertIn("http-429", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("http-503)", runner)
        self.assertIn("http-500)", runner)
        self.assertIn("http-429)", runner)
        self.assertIn("--upstream-fault", runner)
        self.assertIn("upstream_fault=http-500", runner)

    def test_stream_truncation_profiles_are_registered(self) -> None:
        for profile in (
            "missing-done",
            "reset-before-token",
            "reset-after-token",
            "malformed-sse",
        ):
            self.assertIn(profile, EXPORTER.PROFILE_DETAILS)
            self.assertIn(f"{profile})", RUNNER.read_text(encoding="utf-8"))
        self.assertIn("malformed-sse", RUNNER.read_text(encoding="utf-8"))

    def test_idle_timeout_profiles_use_short_fixtures(self) -> None:
        self.assertIn("first-token-timeout", EXPORTER.PROFILE_DETAILS)
        self.assertIn("midstream-idle", EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("gateway-timeout.acl", runner)
        self.assertIn("nginx-timeout.conf", runner)
        self.assertIn("hold-first-token", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-timeout.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-timeout.conf").is_file())

    def test_connect_and_bound_timeout_profiles_are_registered(self) -> None:
        for profile in (
            "connect-refused",
            "connect-timeout",
            "headers-timeout",
            "total-timeout",
        ):
            self.assertIn(profile, EXPORTER.PROFILE_DETAILS)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("connect-refused)", runner)
        self.assertIn("connect-timeout)", runner)
        self.assertIn("headers-timeout)", runner)
        self.assertIn("total-timeout)", runner)
        self.assertIn("--expect-proxy-error", runner)
        self.assertIn("hold-headers", runner)
        self.assertIn("endless-stream", runner)
        self.assertIn("gateway-refused.acl", runner)
        self.assertIn("nginx-refused.conf", runner)
        self.assertIn("gateway-blackhole.acl", runner)
        self.assertIn("nginx-blackhole.conf", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-refused.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-refused.conf").is_file())
        self.assertTrue((FIXTURE_ROOT / "gateway-blackhole.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-blackhole.conf").is_file())

    def test_telemetry_on_is_a3s_only_policy_lane(self) -> None:
        self.assertIn("telemetry-on", EXPORTER.PROFILE_DETAILS)
        self.assertIn("telemetry-off", EXPORTER.PROFILE_DETAILS)
        self.assertIn("telemetry-on", EXPORTER.A3S_ONLY_PROFILES)
        self.assertIn("telemetry-off", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("telemetry-on)", runner)
        self.assertIn("telemetry-off)", runner)
        self.assertIn("gateway-telemetry.acl", runner)
        self.assertIn("a3s_only=1", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-telemetry.acl").is_file())

    def test_fallback_is_dual_product_recovery_lane(self) -> None:
        self.assertIn("fallback", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("fallback", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("fallback)", runner)
        self.assertIn("fallback_fixture=1", runner)
        self.assertIn("trip_fallback_quarantine", runner)
        self.assertIn("gateway-fallback.acl", runner)
        self.assertIn("nginx-fallback.conf", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-fallback.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-fallback.conf").is_file())
        acl = (FIXTURE_ROOT / "gateway-fallback.acl").read_text(encoding="utf-8")
        self.assertIn("failover", acl)
        self.assertIn("18199", acl)
        self.assertIn("ai-benchmark-backup", acl)
        nginx = (FIXTURE_ROOT / "nginx-fallback.conf").read_text(encoding="utf-8")
        self.assertIn("backup", nginx)
        self.assertIn("max_fails=5", nginx)

    def test_stream_bursty_uses_tokens_per_write(self) -> None:
        self.assertIn("stream-bursty", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("stream-bursty", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("stream-bursty)", runner)
        self.assertIn("tokens_per_write=8", runner)
        self.assertIn("--tokens-per-write", runner)

    def test_stream_fragmented_uses_fragments_per_event(self) -> None:
        self.assertIn("stream-fragmented", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("stream-fragmented", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("stream-fragmented)", runner)
        self.assertIn("fragments_per_event=4", runner)
        self.assertIn("--fragments-per-event", runner)
        gateway_root = SCRIPT.parent.parent
        load = (gateway_root / "examples" / "ai_benchmark_load.rs").read_text(
            encoding="utf-8"
        )
        upstream = (gateway_root / "examples" / "ai_benchmark_upstream.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("fragments_per_event", load)
        self.assertIn("fragments_per_event", upstream)
        self.assertIn("take_sse_fragment", upstream)

    def test_stream_unicode_uses_utf8_multiline_and_mid_codepoint_cuts(self) -> None:
        self.assertIn("stream-unicode", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("stream-unicode", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("stream-unicode)", runner)
        self.assertIn("unicode_payload=1", runner)
        self.assertIn("--unicode-payload", runner)
        gateway_root = SCRIPT.parent.parent
        upstream = (gateway_root / "examples" / "ai_benchmark_upstream.rs").read_text(
            encoding="utf-8"
        )
        self.assertIn("unicode_payload", upstream)
        self.assertIn("first_mid_utf8_cut", upstream)
        self.assertIn("encode_sse_data", upstream)

    def test_weighted_rollout_uses_revision_fixtures(self) -> None:
        self.assertIn("weighted-rollout", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("weighted-rollout", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("weighted-rollout)", runner)
        self.assertIn("weighted_fixture=1", runner)
        self.assertIn("gateway-weighted.acl", runner)
        self.assertIn("nginx-weighted.conf", runner)
        self.assertIn("--instance-id stable", runner)
        self.assertIn("--instance-id canary", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-weighted.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-weighted.conf").is_file())
        acl = (FIXTURE_ROOT / "gateway-weighted.acl").read_text(encoding="utf-8")
        self.assertIn('revision "stable"', acl)
        self.assertIn("traffic_percent = 90", acl)
        self.assertIn("18110", acl)
        nginx = (FIXTURE_ROOT / "nginx-weighted.conf").read_text(encoding="utf-8")
        self.assertIn("weight=9", nginx)
        self.assertIn("weight=1", nginx)

    def test_rate_limit_is_dual_product_policy_lane(self) -> None:
        self.assertIn("rate-limit", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("rate-limit", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("rate-limit)", runner)
        self.assertIn("ratelimit_fixture=1", runner)
        self.assertIn("--accept-http-status", runner)
        self.assertIn("gateway-ratelimit.acl", runner)
        self.assertIn("nginx-ratelimit.conf", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-ratelimit.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-ratelimit.conf").is_file())
        acl = (FIXTURE_ROOT / "gateway-ratelimit.acl").read_text(encoding="utf-8")
        self.assertIn('type  = "rate-limit"', acl)
        nginx = (FIXTURE_ROOT / "nginx-ratelimit.conf").read_text(encoding="utf-8")
        self.assertIn("limit_req", nginx)
        self.assertIn("limit_req_status 429", nginx)

    def test_api_key_auth_is_a3s_only_policy_lane(self) -> None:
        self.assertIn("api-key-auth", EXPORTER.PROFILE_DETAILS)
        self.assertIn("api-key-auth", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("api-key-auth)", runner)
        self.assertIn("apikey_fixture=1", runner)
        self.assertIn("a3s_only=1", runner)
        self.assertIn("--omit-api-key-every", runner)
        self.assertIn("gateway-apikey.acl", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-apikey.acl").is_file())
        acl = (FIXTURE_ROOT / "gateway-apikey.acl").read_text(encoding="utf-8")
        self.assertIn('type   = "api-key"', acl)
        self.assertIn("Authorization", acl)
        self.assertIn("Bearer bench-secret", acl)
        self.assertIn('Path(`/health`)', acl)
        self.assertIn("priority    = 100", acl)

    def test_no_replay_after_token_is_dual_product_stream_safety_lane(self) -> None:
        self.assertIn("no-replay-after-token", EXPORTER.PROFILE_DETAILS)
        self.assertNotIn("no-replay-after-token", EXPORTER.A3S_ONLY_PROFILES)
        runner = RUNNER.read_text(encoding="utf-8")
        self.assertIn("no-replay-after-token)", runner)
        self.assertIn("noreplay_fixture=1", runner)
        self.assertIn("send_idempotency_key=1", runner)
        self.assertIn("--send-idempotency-key", runner)
        self.assertIn("gateway-noreplay.acl", runner)
        self.assertIn("nginx-noreplay.conf", runner)
        self.assertIn("18110/benchmark/stats", runner)
        self.assertTrue((FIXTURE_ROOT / "gateway-noreplay.acl").is_file())
        self.assertTrue((FIXTURE_ROOT / "nginx-noreplay.conf").is_file())
        acl = (FIXTURE_ROOT / "gateway-noreplay.acl").read_text(encoding="utf-8")
        self.assertIn("failover", acl)
        self.assertIn('type              = "retry"', acl)
        self.assertIn("18110", acl)
        nginx = (FIXTURE_ROOT / "nginx-noreplay.conf").read_text(encoding="utf-8")
        self.assertIn("backup", nginx)
        self.assertIn("proxy_next_upstream", nginx)

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
                "a3s-gateway 9.8.7-test",
                "--nginx-version",
                "nginx/1.26.0",
                "--upstream-version",
                "ai_benchmark_upstream 9.8.7-test",
                "--load-version",
                "ai_benchmark_load 9.8.7-test",
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
