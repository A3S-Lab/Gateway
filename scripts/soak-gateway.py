#!/usr/bin/env python3
"""Core Gateway HTTP / SSE / OpenAI-shaped soak harness (Enterprise GA capacity gate).

Spins a local upstream, a temporary ACL, and a3s-gateway, then drives load.
Smoke and lab-extended runs prove the harness; they are not published
dedicated-hardware capacity envelopes. See docs/ops/capacity-and-soak.md.

OpenAI-shaped profiles proxy `/v1/chat/completions` to a deterministic local
upstream (standalone PathPrefix). They do not invent cloud-managed inference
policy (EXIT with Cloud).
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen

OPENAI_JSON_BODY = json.dumps(
    {
        "id": "chatcmpl-soak",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "soak-ok"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
).encode()

OPENAI_SSE_BODY = (
    b'data: {"id":"chatcmpl-soak","object":"chat.completion.chunk",'
    b'"choices":[{"index":0,"delta":{"content":"soak"},"finish_reason":null}]}\n\n'
    b"data: [DONE]\n\n"
)

OPENAI_REQUEST = json.dumps(
    {
        "model": "soak-model",
        "messages": [{"role": "user", "content": "ping"}],
        "stream": False,
    }
).encode()

OPENAI_STREAM_REQUEST = json.dumps(
    {
        "model": "soak-model",
        "messages": [{"role": "user", "content": "ping"}],
        "stream": True,
    }
).encode()


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, *_args):
        return


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/sse"):
            body = b"data: one\n\ndata: two\n\ndata: done\n\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b'{"ok":true,"soak":"http-json"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length else b""
        if self.path.startswith("/v1/chat/completions"):
            stream = False
            # Prefer Accept / simple body peek via Content-Type only; clients set stream in JSON.
            # Harness always sends stream=true for openai-sse profile.
            if b'"stream": true' in _ or b'"stream":true' in _:
                stream = True
            if stream:
                body = OPENAI_SSE_BODY
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            body = OPENAI_JSON_BODY
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, *_args):
        return

    def handle_error(self, *_args):
        return


def write_acl(path: Path, gateway_port: int, upstream_port: int) -> None:
    path.write_text(
        f"""mode {{ kind = "standalone" }}

entrypoints "web" {{
  address = "127.0.0.1:{gateway_port}"
}}

routers "soak" {{
  rule        = "PathPrefix(`/`)"
  service     = "soak"
  entrypoints = ["web"]
}}

services "soak" {{
  load_balancer {{
    strategy             = "round-robin"
    request_timeout      = "30s"
    stream_idle_timeout  = "30s"
    stream_total_timeout = "60s"
    servers = [{{ url = "http://127.0.0.1:{upstream_port}" }}]
  }}
}}

observability {{
  metrics_enabled    = false
  access_log_enabled = false
  tracing_enabled    = false
}}
""",
        encoding="utf-8",
    )


def wait_listen(port: int, proc: subprocess.Popen, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            err = ""
            if proc.stderr:
                err = proc.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"gateway exited during startup, rc={proc.returncode}: {err[-2000:]}"
            )
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("gateway never accepted connections")


def rss_kb(pid: int) -> int | None:
    if os.name == "nt":
        try:
            out = subprocess.check_output(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    f"(Get-Process -Id {pid}).WorkingSet64 / 1KB",
                ],
                text=True,
                stderr=subprocess.DEVNULL,
            )
            return int(float(out.strip()))
        except Exception:
            return None
    try:
        out = subprocess.check_output(["ps", "-o", "rss=", "-p", str(pid)], text=True)
        return int(out.strip())
    except Exception:
        return None


def drive(profile: str, port: int, duration: float, concurrency: int) -> dict[str, int]:
    stop = time.time() + duration
    counts = {"ok": 0, "err": 0}
    lock = threading.Lock()

    def worker() -> None:
        local_ok = 0
        local_err = 0
        while time.time() < stop:
            try:
                if profile == "sse-finite":
                    req = Request(f"http://127.0.0.1:{port}/sse", method="GET")
                elif profile == "openai-json":
                    req = Request(
                        f"http://127.0.0.1:{port}/v1/chat/completions",
                        data=OPENAI_REQUEST,
                        method="POST",
                        headers={"Content-Type": "application/json"},
                    )
                elif profile == "openai-sse":
                    req = Request(
                        f"http://127.0.0.1:{port}/v1/chat/completions",
                        data=OPENAI_STREAM_REQUEST,
                        method="POST",
                        headers={"Content-Type": "application/json"},
                    )
                else:
                    req = Request(f"http://127.0.0.1:{port}/soak", method="GET")
                with urlopen(req, timeout=10) as resp:
                    body = resp.read()
                    if resp.status == 200 and body:
                        if profile == "openai-sse" and b"[DONE]" not in body:
                            local_err += 1
                        elif profile == "openai-json" and b"soak-ok" not in body:
                            local_err += 1
                        else:
                            local_ok += 1
                    else:
                        local_err += 1
            except Exception:
                local_err += 1
        with lock:
            counts["ok"] += local_ok
            counts["err"] += local_err

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return counts


def gateway_version(bin_path: Path) -> str | None:
    try:
        out = subprocess.check_output(
            [str(bin_path), "--version"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        return out.strip() or None
    except Exception:
        return None


def git_sha() -> str | None:
    for key in ("GITHUB_SHA", "A3S_GATEWAY_GIT_SHA"):
        value = os.environ.get(key)
        if value:
            return value[:40]
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        return out.strip() or None
    except Exception:
        return None


def validate_envelope_status(status: str, duration: float) -> list[str]:
    """Fail closed before claiming published dedicated-hardware envelopes."""
    if status != "published":
        return []
    errors: list[str] = []
    if os.environ.get("A3S_GATEWAY_DEDICATED_RUNNER") != "1":
        errors.append(
            "published requires A3S_GATEWAY_DEDICATED_RUNNER=1 "
            "(refuse developer/CI hosts as dedicated)"
        )
    publish_floor = 7200.0
    try:
        requested = float(os.environ.get("A3S_GATEWAY_PUBLISH_MIN_DURATION", "7200"))
    except ValueError:
        errors.append("A3S_GATEWAY_PUBLISH_MIN_DURATION must be a number")
        return errors
    if requested < publish_floor:
        errors.append(
            "A3S_GATEWAY_PUBLISH_MIN_DURATION cannot be below 7200s "
            "(refuse lowering the publish floor)"
        )
    min_duration = max(publish_floor, requested)
    if duration + 1e-9 < min_duration:
        errors.append(
            f"published requires duration>={min_duration:.0f}s "
            f"(got {duration:.0f}s); A3S_GATEWAY_PUBLISH_MIN_DURATION may only raise the floor"
        )
    if not os.environ.get("A3S_GATEWAY_HW_CPU_MODEL", "").strip():
        errors.append("published requires A3S_GATEWAY_HW_CPU_MODEL")
    mem = os.environ.get("A3S_GATEWAY_HW_MEMORY_GB", "").strip()
    if not mem:
        errors.append("published requires A3S_GATEWAY_HW_MEMORY_GB")
    else:
        try:
            if float(mem) <= 0:
                errors.append("A3S_GATEWAY_HW_MEMORY_GB must be > 0")
        except ValueError:
            errors.append("A3S_GATEWAY_HW_MEMORY_GB must be a number")
    if not os.environ.get("A3S_GATEWAY_HW_HOST", "").strip():
        errors.append("published requires A3S_GATEWAY_HW_HOST")
    return errors


def published_artifact(status: str, passed: bool) -> tuple[str, str]:
    """Return (envelope_status, filename prefix).

    A failed run must not be named published. The 2h gate is meaningless if a
    failing soak still lands a published artifact.
    """
    if status == "published" and not passed:
        return "publish-refused", "publish-refused"
    if status == "published":
        return "published", "published"
    if status == "lab-extended":
        return "lab-extended", "lab"
    return "smoke-only", "smoke"


_EMBEDDED_SHA = re.compile(r"(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])")


def git_sha_from_version(version: str | None) -> str | None:
    """Return the commit embedded in `a3s-gateway --version`, if it is clean."""
    if published_version_identity_error(version) is not None:
        return None
    match = _EMBEDDED_SHA.search(str(version or ""))
    return match.group(1) if match else None


def published_version_identity_error(version: str | None) -> str | None:
    """Refuse a published envelope whose binary does not name a clean commit.

    Working-tree `git rev-parse` and `GITHUB_SHA` are not the measured binary.
    """
    text = str(version or "").strip()
    if not text:
        return "published envelope requires gateway --version"
    if "-dirty" in text:
        return "published envelope refuses a dirty build"
    if _EMBEDDED_SHA.search(text) is None:
        return (
            "published envelope requires a 40-char lowercase git sha "
            "embedded in gateway --version"
        )
    return None


def published_identity_error(version: str | None, git_sha_value: str | None) -> str | None:
    """A published envelope must name the measured binary and the exact commit.

    Smoke and lab results may omit these. A passing published run without them
    is not a capacity envelope.
    """
    if not str(version or "").strip():
        return "published envelope requires gateway --version"
    text = str(git_sha_value or "")
    if len(text) != 40 or any(ch not in "0123456789abcdef" for ch in text):
        return "published envelope requires a 40-char lowercase git sha"
    return None


def refuse_mismatched_artifact_name(path: Path, envelope_status: str) -> str | None:
    """Refuse writing a non-published result under a published-* filename."""
    if envelope_status != "published" and path.name.startswith("published-"):
        return (
            f"refuse: {path.name} is a published artifact name but "
            f"envelope_status={envelope_status}"
        )
    return None


def hardware_pins() -> dict:
    mem_raw = os.environ.get("A3S_GATEWAY_HW_MEMORY_GB", "").strip()
    memory_gb = None
    if mem_raw:
        try:
            memory_gb = float(mem_raw)
        except ValueError:
            memory_gb = None
    return {
        "host": os.environ.get("A3S_GATEWAY_HW_HOST") or platform.node(),
        "cpu_model": os.environ.get("A3S_GATEWAY_HW_CPU_MODEL")
        or (platform.processor() or None),
        "cpu_cores": os.cpu_count(),
        "memory_gb": memory_gb,
        "os": platform.system().lower(),
        "kernel": platform.release(),
        "dedicated_runner": os.environ.get("A3S_GATEWAY_DEDICATED_RUNNER") == "1",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", required=True, help="Path to a3s-gateway binary")
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--concurrency", type=int, default=16)
    parser.add_argument(
        "--profile",
        choices=("http-json", "sse-finite", "openai-json", "openai-sse"),
        default="http-json",
    )
    parser.add_argument(
        "--envelope-status",
        choices=("smoke-only", "lab-extended", "published"),
        default="smoke-only",
    )
    parser.add_argument("--out", default="")
    args = parser.parse_args()

    publish_errors = validate_envelope_status(args.envelope_status, args.duration)
    if publish_errors:
        for err in publish_errors:
            print(f"soak-gateway: refuse published: {err}", file=sys.stderr)
        return 2

    bin_path = Path(args.bin)
    if not bin_path.is_file():
        print(f"soak-gateway: binary not found: {bin_path}", file=sys.stderr)
        return 2

    up = QuietThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    upstream_port = up.server_address[1]
    threading.Thread(target=up.serve_forever, daemon=True).start()

    gateway_port = free_port()
    tmp = Path(tempfile.mkdtemp(prefix="a3s-soak-"))
    acl = tmp / "soak.acl"
    write_acl(acl, gateway_port, upstream_port)

    proc = subprocess.Popen(
        [str(bin_path), "--config", str(acl), "--log-level", "error"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    fail_reasons: list[str] = []
    rss_samples: list[int] = []
    counts = {"ok": 0, "err": 0}
    crashed = False
    try:
        wait_listen(gateway_port, proc)

        def run_load() -> None:
            counts.update(
                drive(args.profile, gateway_port, args.duration, args.concurrency)
            )

        load = threading.Thread(target=run_load)
        load.start()
        stop = time.time() + args.duration
        while time.time() < stop:
            if proc.poll() is not None:
                crashed = True
                fail_reasons.append(f"gateway crashed rc={proc.returncode}")
                break
            sample = rss_kb(proc.pid)
            if sample is not None and sample > 0:
                rss_samples.append(sample)
            time.sleep(1)
        load.join()
    except Exception as exc:
        fail_reasons.append(str(exc))
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(5)
            except Exception:
                proc.kill()
        up.shutdown()

    if counts["ok"] == 0:
        fail_reasons.append("no successful requests")
    if counts["ok"] > 0 and counts["err"] > max(1, int(counts["ok"] * 0.01)):
        fail_reasons.append(f"high error rate ({counts['err']}/{counts['ok']})")

    steady = rss_samples[3:] or rss_samples
    rss_min = min(steady) if steady else None
    rss_max = max(steady) if steady else None
    growth = (rss_max / rss_min) if rss_min and rss_max and rss_min > 0 else None
    if growth is not None and growth > 1.5:
        fail_reasons.append(f"RSS grew {growth:.2f}x")

    seen: set[str] = set()
    unique_fails: list[str] = []
    for reason in fail_reasons:
        if reason not in seen:
            seen.add(reason)
            unique_fails.append(reason)
    fail_reasons = unique_fails
    passed = not fail_reasons and not crashed
    version = gateway_version(bin_path)
    if args.envelope_status == "published":
        sha = git_sha_from_version(version)
        if passed:
            identity = published_version_identity_error(version)
            if identity:
                fail_reasons.append(identity)
                passed = False
    else:
        sha = git_sha()

    rps = counts["ok"] / args.duration if args.duration > 0 else 0.0
    hardware = hardware_pins()
    envelope_status, artifact_prefix = published_artifact(args.envelope_status, passed)
    if envelope_status == "published":
        hardware["dedicated_runner"] = True

    result = {
        "schema": "a3s.gateway.soak-result.v1",
        "envelope_status": envelope_status,
        "profile": args.profile,
        "duration_secs": args.duration,
        "concurrency": args.concurrency,
        "hardware": hardware,
        "gateway": {
            "version": version,
            "git_sha": sha,
            "features": [],
            "bin": str(bin_path),
        },
        "requests": {**counts, "ok_per_sec": round(rps, 2)},
        "rss_kb": {
            "min": rss_min,
            "max": rss_max,
            "growth": growth,
            "samples": len(steady),
        },
        "pass": passed,
        "fail_reasons": fail_reasons,
    }

    out = (
        Path(args.out)
        if args.out
        else Path("benchmarks/soak/results") / f"{artifact_prefix}-{args.profile}.json"
    )
    mismatch = refuse_mismatched_artifact_name(out, envelope_status)
    if mismatch:
        print(f"soak-gateway: {mismatch}", file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    print(
        f"soak-gateway: profile={args.profile} duration={args.duration:.0f}s "
        f"concurrency={args.concurrency} status={envelope_status}"
    )
    print(f"  requests: ok={counts['ok']} err={counts['err']} ok/s={rps:.1f}")
    print(f"  rss_kb: min={rss_min} max={rss_max} growth={growth}")
    print(f"  result: {out}")
    print(f"  pass: {passed}")
    if fail_reasons:
        for reason in fail_reasons:
            print(f"  FAIL: {reason}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
