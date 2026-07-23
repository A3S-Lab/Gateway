"""Black-box Gateway and upstream fixtures for official OpenAI SDK tests."""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import os
import signal
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

from fake_backend import FakeOpenAIBackend


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TEST_API_KEY = "a3s_inf_abc12345" + ("a" * 64)
TEST_ADMIN_TOKEN = "a3s-gateway-openai-sdk-conformance"

GATEWAY_ID = "11111111-1111-4111-8111-111111111111"
ENVIRONMENT_ID = "22222222-2222-4222-8222-222222222222"
CREDENTIAL_ID = "33333333-3333-4333-8333-333333333333"
ROUTE_ID = "44444444-4444-4444-8444-444444444444"
MODEL_ID = "55555555-5555-4555-8555-555555555555"
TARGET_ID = "66666666-6666-4666-8666-666666666666"
VERIFIER_HASH = (
    "$argon2id$v=19$m=19456,t=2,p=1$YTNzLXNkay1jb25mb3JtYW5jZQ"
    "$A3fZyCzw3dvKpZt3PJbaA33sEbzatWO8+9JD/OaGuEM"
)


class GatewayHarness:
    """A real Gateway process configured through its managed snapshot API."""

    def __init__(self, shutdown_timeout_secs: int = 2) -> None:
        self.shutdown_timeout_secs = shutdown_timeout_secs
        self.backend = FakeOpenAIBackend()
        self.process: Optional[asyncio.subprocess.Process] = None
        self.traffic_port = 0
        self.management_port = 0
        self._temporary_directory: Optional[tempfile.TemporaryDirectory[str]] = None
        self._stdout = ""
        self._stderr = ""

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.traffic_port}/v1"

    async def start(self) -> None:
        await self.backend.start()
        self.traffic_port = _unused_tcp_port()
        self.management_port = _unused_tcp_port()

        now = datetime.now(timezone.utc).replace(microsecond=0)
        issued_at = now - timedelta(seconds=1)
        expires_at = now + timedelta(minutes=15)
        expires_at_text = expires_at.isoformat().replace("+00:00", "Z")
        bootstrap_acl = self._bootstrap_acl()
        snapshot_acl = self._snapshot_acl(expires_at_text)

        self._temporary_directory = tempfile.TemporaryDirectory(
            prefix="a3s-gateway-openai-sdk-"
        )
        config_path = Path(self._temporary_directory.name) / "gateway.acl"
        config_path.write_text(bootstrap_acl, encoding="utf-8")

        binary = Path(
            os.environ.get(
                "A3S_GATEWAY_BINARY",
                REPOSITORY_ROOT / "target" / "debug" / "a3s-gateway",
            )
        )
        if not binary.is_file():
            raise RuntimeError(
                f"Gateway binary not found at {binary}; run cargo build --bin a3s-gateway"
            )

        environment = os.environ.copy()
        environment["A3S_GATEWAY_CONFORMANCE_ADMIN_TOKEN"] = TEST_ADMIN_TOKEN
        self.process = await asyncio.create_subprocess_exec(
            str(binary),
            "--config",
            str(config_path),
            "--log-level",
            "warn",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )

        await self._wait_for_management()
        digest = "sha256:" + hashlib.sha256(snapshot_acl.encode()).hexdigest()
        envelope = {
            "schema": "a3s.gateway.managed-snapshot.v1",
            "gateway_id": GATEWAY_ID,
            "revision": 1,
            "expected_revision": None,
            "snapshot_digest": digest,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
            "acl": snapshot_acl,
        }
        headers = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.post(
                self._management_url("/snapshots/apply"),
                headers=headers,
                json=envelope,
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"managed snapshot apply failed: {response.status_code} {response.text}"
                )

            status = await client.get(
                self._management_url("/snapshots/status"),
                headers=headers,
                params={
                    "gateway_id": GATEWAY_ID,
                    "revision": "1",
                    "snapshot_digest": digest,
                },
            )
            status.raise_for_status()
            if status.json().get("ready") is not True:
                raise RuntimeError(
                    f"managed snapshot did not become ready: {status.text}"
                )

    def signal_shutdown(self) -> None:
        if self.process is None or self.process.returncode is not None:
            raise RuntimeError("Gateway process is not running")
        self.process.send_signal(signal.SIGINT)

    async def wait_for_exit(self, timeout: float = 5) -> int:
        if self.process is None:
            raise RuntimeError("Gateway process was not started")
        try:
            return await asyncio.wait_for(self.process.wait(), timeout)
        except asyncio.TimeoutError as error:
            raise AssertionError(
                f"Gateway did not exit within {timeout} seconds"
            ) from error

    async def wait_for_listener_closed(self, timeout: float = 2) -> None:
        deadline = asyncio.get_running_loop().time() + timeout
        while asyncio.get_running_loop().time() < deadline:
            try:
                _, writer = await asyncio.open_connection(
                    "127.0.0.1",
                    self.traffic_port,
                )
            except OSError:
                return
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            await asyncio.sleep(0.02)
        raise AssertionError("Gateway traffic listener remained open during drain")

    async def close(self) -> None:
        if self.process is not None and self.process.returncode is None:
            self.process.send_signal(signal.SIGINT)
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except asyncio.TimeoutError:
                self.process.kill()
                await self.process.wait()

        if self.process is not None:
            if self.process.stdout is not None:
                self._stdout = (await self.process.stdout.read()).decode(
                    errors="replace"
                )
            if self.process.stderr is not None:
                self._stderr = (await self.process.stderr.read()).decode(
                    errors="replace"
                )

        await self.backend.close()
        if self._temporary_directory is not None:
            self._temporary_directory.cleanup()
            self._temporary_directory = None

    def process_diagnostics(self) -> str:
        return f"stdout:\n{self._stdout}\nstderr:\n{self._stderr}"

    async def _wait_for_management(self) -> None:
        headers = {"Authorization": f"Bearer {TEST_ADMIN_TOKEN}"}
        async with httpx.AsyncClient(timeout=0.2) as client:
            for _ in range(100):
                if self.process is not None and self.process.returncode is not None:
                    await self.close()
                    raise RuntimeError(
                        "Gateway exited before management became ready\n"
                        + self.process_diagnostics()
                    )
                try:
                    response = await client.get(
                        self._management_url("/health"),
                        headers=headers,
                    )
                    if response.status_code == 200:
                        return
                except httpx.HTTPError:
                    pass
                await asyncio.sleep(0.05)
        raise RuntimeError("Gateway management listener did not become ready")

    def _management_url(self, suffix: str) -> str:
        return f"http://127.0.0.1:{self.management_port}/api/gateway{suffix}"

    def _bootstrap_acl(self) -> str:
        return f"""
mode {{ kind = "cloud-managed" }}
managed {{ gateway_id = "{GATEWAY_ID}" }}

entrypoints "web" {{ address = "127.0.0.1:{self.traffic_port}" }}

management {{
  enabled = true
  address = "127.0.0.1:{self.management_port}"
  path_prefix = "/api/gateway"
  auth_token_env = "A3S_GATEWAY_CONFORMANCE_ADMIN_TOKEN"
  allowed_ips = ["127.0.0.1"]
}}

observability {{
  metrics_enabled = false
  access_log_enabled = false
  tracing_enabled = false
}}

shutdown_timeout_secs {{
  shutdown_timeout_secs = {self.shutdown_timeout_secs}
}}
""".lstrip()

    def _snapshot_acl(self, expires_at: str) -> str:
        backend_host, backend_port = self.backend.address
        return (
            self._bootstrap_acl()
            + f"""
routers "inference" {{
  rule = "PathPrefix(`/v1`)"
  service = "default-service"
  entrypoints = ["web"]
}}

services "default-service" {{
  load_balancer {{
    request_timeout = "2s"
    servers = [{{ url = "http://127.0.0.1:9", weight = 1 }}]
  }}
}}

services "model-service" {{
  load_balancer {{
    request_timeout = "2s"
    servers = [{{ url = "http://{backend_host}:{backend_port}", weight = 1 }}]
  }}
}}

inference {{
  expires_at = "{expires_at}"

  credentials "{CREDENTIAL_ID}" {{
    environment_id = "{ENVIRONMENT_ID}"
    audience = "cloud-inference"
    prefix = "a3s_inf_abc12345"
    verifier_hash = "{VERIFIER_HASH}"
    generation = 1
    expires_at = "{expires_at}"
    revoked = false
  }}

  routes "{ROUTE_ID}" {{
    router = "inference"
    environment_id = "{ENVIRONMENT_ID}"
    policy_revision = 1

    models "sdk-model" {{
      model_id = "{MODEL_ID}"
      targets "{TARGET_ID}" {{
        service = "model-service"
        upstream_model = "internal-conformance-model"
        priority = 0
        weight = 1
      }}
    }}

    grants "{CREDENTIAL_ID}" {{
      credential_generation = 1
      models = ["sdk-model"]
      endpoints = ["models", "chat-completions", "completions", "embeddings"]
      limits {{
        max_concurrent_requests = 1
        requests_per_minute = 120
        request_burst = 16
        tokens_per_minute = 100000
      }}
    }}
  }}
}}
"""
        )


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])
