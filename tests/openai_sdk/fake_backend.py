"""Controllable OpenAI HTTP/SSE upstream for SDK conformance tests."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class CapturedRequest:
    """One request received by the fake OpenAI upstream."""

    method: str
    path: str
    headers: Dict[str, str]
    body: Dict[str, Any]


@dataclass
class StreamScenario:
    """Coordination points for one named streaming request."""

    started: asyncio.Event = field(default_factory=asyncio.Event)
    disconnected: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    requests: List[CapturedRequest] = field(default_factory=list)


class FakeOpenAIBackend:
    """Minimal HTTP/1.1 OpenAI upstream with controllable SSE lifetimes."""

    def __init__(self) -> None:
        self._server: Optional[asyncio.AbstractServer] = None
        self._writers: Set[asyncio.StreamWriter] = set()
        self._scenarios: Dict[str, StreamScenario] = {}

    @property
    def address(self) -> Tuple[str, int]:
        if self._server is None or not self._server.sockets:
            raise RuntimeError("fake upstream is not running")
        host, port = self._server.sockets[0].getsockname()[:2]
        return str(host), int(port)

    def scenario(self, name: str) -> StreamScenario:
        return self._scenarios.setdefault(name, StreamScenario())

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._handle_connection,
            "127.0.0.1",
            0,
        )

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        writers = list(self._writers)
        for writer in writers:
            writer.close()
        for writer in writers:
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self._writers.add(writer)
        try:
            request = await self._read_request(reader)
            stream = bool(request.body.get("stream"))
            scenario_name = self._scenario_name(request)
            scenario = self.scenario(scenario_name)
            scenario.requests.append(request)

            if not stream:
                await self._write_json_response(writer, request)
                return

            await self._write_stream_headers(writer)
            await self._write_sse_chunk(
                writer,
                self._stream_content_chunk(request.path, "hello"),
            )
            scenario.started.set()

            if scenario_name in {"done", "chat-usage", "completion-usage"}:
                await self._write_sse_chunk(
                    writer,
                    self._stream_content_chunk(request.path, " world"),
                )
                await self._write_sse_chunk(
                    writer,
                    self._stream_finish_chunk(request.path),
                )
                if scenario_name.endswith("-usage"):
                    await self._write_sse_chunk(
                        writer,
                        self._stream_usage_chunk(request.path),
                    )
                await self._write_sse_chunk(writer, "[DONE]")
                await reader.read()
            elif scenario_name == "graceful":
                await scenario.release.wait()
                await self._write_sse_chunk(
                    writer,
                    self._stream_content_chunk(request.path, " world"),
                )
                await self._write_sse_chunk(
                    writer,
                    self._stream_finish_chunk(request.path),
                )
                await self._write_sse_chunk(writer, "[DONE]")
                writer.write(b"0\r\n\r\n")
                await writer.drain()
            elif scenario_name in {"disconnect", "cancel", "forced"}:
                await reader.read()
            else:
                raise RuntimeError(f"unknown streaming scenario: {scenario_name}")

            scenario.disconnected.set()
        except (asyncio.IncompleteReadError, ConnectionError, BrokenPipeError):
            for scenario in self._scenarios.values():
                if scenario.started.is_set() and not scenario.disconnected.is_set():
                    scenario.disconnected.set()
        finally:
            self._writers.discard(writer)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    @staticmethod
    async def _read_request(reader: asyncio.StreamReader) -> CapturedRequest:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        if "content-length" in headers:
            body_bytes = await reader.readexactly(int(headers["content-length"]))
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            body_bytes = await FakeOpenAIBackend._read_chunked_body(reader)
        else:
            body_bytes = b""

        body = json.loads(body_bytes) if body_bytes else {}
        return CapturedRequest(method=method, path=path, headers=headers, body=body)

    @staticmethod
    async def _read_chunked_body(reader: asyncio.StreamReader) -> bytes:
        body = bytearray()
        while True:
            size_line = await reader.readline()
            size = int(size_line.split(b";", 1)[0].strip(), 16)
            if size == 0:
                while await reader.readline() not in {b"\r\n", b"\n", b""}:
                    pass
                return bytes(body)
            body.extend(await reader.readexactly(size))
            await reader.readexactly(2)

    @staticmethod
    def _scenario_name(request: CapturedRequest) -> str:
        if request.path == "/v1/chat/completions":
            messages = request.body.get("messages")
            if isinstance(messages, list) and messages:
                content = messages[0].get("content")
                if isinstance(content, str):
                    return content
            return "chat"
        if request.path == "/v1/completions":
            prompt = request.body.get("prompt")
            return prompt if isinstance(prompt, str) else "completion"
        if request.path == "/v1/embeddings":
            return "embedding"
        return "unknown"

    @staticmethod
    async def _write_json_response(
        writer: asyncio.StreamWriter,
        request: CapturedRequest,
    ) -> None:
        if request.path == "/v1/chat/completions":
            document = {
                "id": "chatcmpl-a3s-conformance",
                "object": "chat.completion",
                "created": 1_700_000_000,
                "model": "internal-conformance-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "hello world"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 2,
                    "total_tokens": 3,
                },
            }
        elif request.path == "/v1/completions":
            document = {
                "id": "cmpl-a3s-conformance",
                "object": "text_completion",
                "created": 1_700_000_000,
                "model": "internal-conformance-model",
                "choices": [
                    {
                        "index": 0,
                        "text": "hello world",
                        "logprobs": None,
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 1,
                    "completion_tokens": 2,
                    "total_tokens": 3,
                },
            }
        elif request.path == "/v1/embeddings":
            embedding: Any = [0.25, -0.5, 0.75]
            if request.body.get("encoding_format") == "base64":
                embedding = base64.b64encode(
                    struct.pack("<3f", 0.25, -0.5, 0.75)
                ).decode()
            document = {
                "object": "list",
                "data": [
                    {
                        "object": "embedding",
                        "embedding": embedding,
                        "index": 0,
                    }
                ],
                "model": "internal-conformance-model",
                "usage": {"prompt_tokens": 1, "total_tokens": 1},
            }
        else:
            raise RuntimeError(f"unsupported upstream path: {request.path}")

        body = json.dumps(document, separators=(",", ":")).encode()
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode()
            + b"Connection: close\r\n\r\n"
            + body
        )
        await writer.drain()

    @staticmethod
    async def _write_stream_headers(writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"Connection: close\r\n\r\n"
        )
        await writer.drain()

    @staticmethod
    async def _write_sse_chunk(
        writer: asyncio.StreamWriter,
        event: Any,
    ) -> None:
        data = (
            event
            if isinstance(event, str)
            else json.dumps(event, separators=(",", ":"))
        )
        payload = f"data: {data}\n\n".encode()
        writer.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
        await writer.drain()

    @staticmethod
    def _stream_content_chunk(path: str, content: str) -> Dict[str, Any]:
        if path == "/v1/completions":
            return {
                "id": "cmpl-a3s-conformance",
                "object": "text_completion",
                "created": 1_700_000_000,
                "model": "internal-conformance-model",
                "choices": [
                    {
                        "index": 0,
                        "text": content,
                        "logprobs": None,
                        "finish_reason": None,
                    }
                ],
            }
        return {
            "id": "chatcmpl-a3s-conformance",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "internal-conformance-model",
            "choices": [
                {
                    "index": 0,
                    "delta": {"content": content},
                    "finish_reason": None,
                }
            ],
        }

    @staticmethod
    def _stream_finish_chunk(path: str) -> Dict[str, Any]:
        if path == "/v1/completions":
            return {
                "id": "cmpl-a3s-conformance",
                "object": "text_completion",
                "created": 1_700_000_000,
                "model": "internal-conformance-model",
                "choices": [
                    {
                        "index": 0,
                        "text": "",
                        "logprobs": None,
                        "finish_reason": "stop",
                    }
                ],
            }
        return {
            "id": "chatcmpl-a3s-conformance",
            "object": "chat.completion.chunk",
            "created": 1_700_000_000,
            "model": "internal-conformance-model",
            "choices": [
                {
                    "index": 0,
                    "delta": {},
                    "finish_reason": "stop",
                }
            ],
        }

    @staticmethod
    def _stream_usage_chunk(path: str) -> Dict[str, Any]:
        return {
            "id": (
                "cmpl-a3s-conformance"
                if path == "/v1/completions"
                else "chatcmpl-a3s-conformance"
            ),
            "object": (
                "text_completion"
                if path == "/v1/completions"
                else "chat.completion.chunk"
            ),
            "created": 1_700_000_000,
            "model": "internal-conformance-model",
            "choices": [],
            "usage": {
                "prompt_tokens": 1,
                "completion_tokens": 2,
                "total_tokens": 3,
            },
        }
