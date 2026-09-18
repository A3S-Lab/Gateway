#!/usr/bin/env python3
"""Fail-closed tests for soak envelope_status=published gates."""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "soak-gateway.py"


def load_soak():
    spec = importlib.util.spec_from_file_location("soak_gateway", MODULE_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


soak = load_soak()


def with_env(env: dict[str, str | None], fn):
    old = {k: os.environ.get(k) for k in env}
    try:
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        return fn()
    finally:
        for k, prev in old.items():
            if prev is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prev


def test_smoke_and_lab_need_no_pins():
    assert soak.validate_envelope_status("smoke-only", 30) == []
    assert soak.validate_envelope_status("lab-extended", 120) == []


def test_published_refuses_without_dedicated_flag():
    def run():
        errs = soak.validate_envelope_status("published", 7200)
        assert any("DEDICATED_RUNNER" in e for e in errs), errs

    with_env(
        {
            "A3S_GATEWAY_DEDICATED_RUNNER": None,
            "A3S_GATEWAY_HW_CPU_MODEL": "Intel Xeon",
            "A3S_GATEWAY_HW_MEMORY_GB": "64",
            "A3S_GATEWAY_HW_HOST": "bench-1",
        },
        run,
    )


def test_published_refuses_short_duration():
    def run():
        errs = soak.validate_envelope_status("published", 120)
        assert any("duration>=" in e for e in errs), errs

    with_env(
        {
            "A3S_GATEWAY_DEDICATED_RUNNER": "1",
            "A3S_GATEWAY_HW_CPU_MODEL": "Intel Xeon",
            "A3S_GATEWAY_HW_MEMORY_GB": "64",
            "A3S_GATEWAY_HW_HOST": "bench-1",
        },
        run,
    )


def test_published_refuses_lowered_floor():
    def run():
        errs = soak.validate_envelope_status("published", 7200)
        assert any("cannot be below 7200" in e for e in errs), errs

    with_env(
        {
            "A3S_GATEWAY_DEDICATED_RUNNER": "1",
            "A3S_GATEWAY_HW_CPU_MODEL": "Intel Xeon",
            "A3S_GATEWAY_HW_MEMORY_GB": "64",
            "A3S_GATEWAY_HW_HOST": "bench-1",
            "A3S_GATEWAY_PUBLISH_MIN_DURATION": "30",
        },
        run,
    )


def test_failed_published_run_is_not_named_published():
    status, prefix = soak.published_artifact("published", False)
    assert status == "publish-refused", status
    assert prefix == "publish-refused", prefix
    status, prefix = soak.published_artifact("published", True)
    assert status == "published" and prefix == "published"
    status, prefix = soak.published_artifact("lab-extended", False)
    assert status == "lab-extended" and prefix == "lab"
    status, prefix = soak.published_artifact("smoke-only", True)
    assert status == "smoke-only" and prefix == "smoke"
    refused = soak.refuse_mismatched_artifact_name(
        Path("benchmarks/soak/results/published-http-json.json"),
        "publish-refused",
    )
    assert refused and "published artifact name" in refused, refused
    assert (
        soak.refuse_mismatched_artifact_name(
            Path("published-http-json.json"), "published"
        )
        is None
    )


def test_published_sha_comes_from_the_binary():
    clean = "a3s-gateway 1.1.1 " + ("b" * 40)
    assert soak.git_sha_from_version(clean) == "b" * 40
    assert soak.published_version_identity_error(clean) is None
    assert soak.git_sha_from_version(clean + "-dirty") is None
    assert "dirty" in (soak.published_version_identity_error(clean + "-dirty") or "")
    assert soak.git_sha_from_version("a3s-gateway 1.1.1") is None
    assert "embedded" in (soak.published_version_identity_error("a3s-gateway 1.1.1") or "")


def test_published_without_identity_is_refused():
    assert soak.published_identity_error(None, None)
    assert soak.published_identity_error("a3s-gateway 1.1.1", "abc")
    assert soak.published_identity_error("a3s-gateway 1.1.1", "A" * 40)
    assert soak.published_identity_error("", "a" * 40)
    assert soak.published_identity_error("a3s-gateway 1.1.1", "a" * 40) is None


def test_published_accepts_complete_pins():
    def run():
        errs = soak.validate_envelope_status("published", 7200)
        assert errs == [], errs

    with_env(
        {
            "A3S_GATEWAY_DEDICATED_RUNNER": "1",
            "A3S_GATEWAY_HW_CPU_MODEL": "Intel Xeon",
            "A3S_GATEWAY_HW_MEMORY_GB": "64",
            "A3S_GATEWAY_HW_HOST": "bench-1",
        },
        run,
    )


def main() -> int:
    test_smoke_and_lab_need_no_pins()
    test_published_refuses_without_dedicated_flag()
    test_published_refuses_short_duration()
    test_published_refuses_lowered_floor()
    test_failed_published_run_is_not_named_published()
    test_published_sha_comes_from_the_binary()
    test_published_without_identity_is_refused()
    test_published_accepts_complete_pins()
    print("test_soak_envelope_status: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
