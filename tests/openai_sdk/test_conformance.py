"""Official openai-python conformance tests for the managed inference path."""

from __future__ import annotations

import asyncio
import unittest
import uuid
from typing import List, Optional

import httpx
from openai import AsyncOpenAI, AuthenticationError, NotFoundError

from harness import GatewayHarness, TEST_API_KEY


class OpenAISDKConformanceTests(unittest.IsolatedAsyncioTestCase):
    """Exercise public SDK behavior against a real Gateway process."""

    harness: Optional[GatewayHarness]
    client: Optional[AsyncOpenAI]

    async def asyncSetUp(self) -> None:
        self.harness = None
        self.client = None

    async def asyncTearDown(self) -> None:
        if self.client is not None:
            await self.client.close()
        if self.harness is not None:
            await self.harness.close()

    async def start_gateway(self, shutdown_timeout_secs: int = 2) -> None:
        self.harness = GatewayHarness(shutdown_timeout_secs)
        try:
            await self.harness.start()
        except BaseException:
            await self.harness.close()
            raise
        self.client = AsyncOpenAI(
            api_key=TEST_API_KEY,
            base_url=self.harness.base_url,
            max_retries=0,
            timeout=5,
        )

    async def test_models_non_streaming_and_done_framing(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        models = await self.client.models.list()
        self.assertEqual([model.id for model in models.data], ["sdk-model"])

        completion = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "non-stream"}],
        )
        self.assertEqual(completion.choices[0].message.content, "hello world")

        request = self.harness.backend.scenario("non-stream").requests[0]
        self.assertEqual(request.path, "/v1/chat/completions")
        self.assertEqual(request.body["model"], "internal-conformance-model")
        self.assertNotIn("authorization", request.headers)
        self.assertEqual(uuid.UUID(request.headers["x-request-id"]).version, 4)
        self.assertEqual(uuid.UUID(request.headers["x-a3s-attempt-id"]).version, 4)

        scenario = self.harness.backend.scenario("done")
        stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "done"}],
            stream=True,
        )

        async def collect() -> str:
            parts: List[str] = []
            async for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    parts.append(content)
            await stream.close()
            return "".join(parts)

        content = await asyncio.wait_for(collect(), 2)
        self.assertEqual(content, "hello world")
        await asyncio.wait_for(scenario.disconnected.wait(), 2)

        stream_request = scenario.requests[0]
        self.assertEqual(stream_request.body["model"], "internal-conformance-model")
        self.assertIs(stream_request.body["stream"], True)

    async def test_sdk_disconnect_releases_upstream_and_admission(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        scenario = self.harness.backend.scenario("disconnect")
        stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "disconnect"}],
            stream=True,
        )
        first = await asyncio.wait_for(stream.__anext__(), 2)
        self.assertEqual(first.choices[0].delta.content, "hello")

        await stream.close()
        await asyncio.wait_for(scenario.disconnected.wait(), 2)

        models = await self.client.models.list()
        self.assertEqual([model.id for model in models.data], ["sdk-model"])

    async def test_legacy_completions_and_embeddings_endpoint_matrix(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        completion = await self.client.completions.create(
            model="sdk-model",
            prompt="legacy-non-stream",
        )
        self.assertEqual(completion.choices[0].text, "hello world")
        self.assertEqual(completion.usage.total_tokens, 3)

        completion_request = self.harness.backend.scenario(
            "legacy-non-stream"
        ).requests[0]
        self.assertEqual(completion_request.path, "/v1/completions")
        self.assertEqual(
            completion_request.body["model"],
            "internal-conformance-model",
        )
        self.assertNotIn("authorization", completion_request.headers)

        embedding = await self.client.embeddings.create(
            model="sdk-model",
            input=["hello"],
        )
        self.assertEqual(embedding.data[0].embedding, [0.25, -0.5, 0.75])
        self.assertEqual(embedding.usage.prompt_tokens, 1)
        self.assertEqual(embedding.usage.total_tokens, 1)

        embedding_request = self.harness.backend.scenario("embedding").requests[0]
        self.assertEqual(embedding_request.path, "/v1/embeddings")
        self.assertEqual(
            embedding_request.body["model"],
            "internal-conformance-model",
        )
        self.assertEqual(embedding_request.body["encoding_format"], "base64")
        self.assertNotIn("authorization", embedding_request.headers)

    async def test_chat_and_completion_stream_usage_chunks(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        chat_scenario = self.harness.backend.scenario("chat-usage")
        chat_stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "chat-usage"}],
            stream=True,
            stream_options={"include_usage": True},
        )
        chat_parts: List[str] = []
        chat_usage = None
        async for chunk in chat_stream:
            if chunk.choices:
                content = chunk.choices[0].delta.content
                if content:
                    chat_parts.append(content)
            if chunk.usage is not None:
                chat_usage = chunk.usage
        await chat_stream.close()

        self.assertEqual("".join(chat_parts), "hello world")
        self.assertIsNotNone(chat_usage)
        assert chat_usage is not None
        self.assertEqual(chat_usage.prompt_tokens, 1)
        self.assertEqual(chat_usage.completion_tokens, 2)
        self.assertEqual(chat_usage.total_tokens, 3)
        await asyncio.wait_for(chat_scenario.disconnected.wait(), 2)
        self.assertEqual(
            chat_scenario.requests[0].body["stream_options"],
            {"include_usage": True},
        )

        completion_scenario = self.harness.backend.scenario("completion-usage")
        completion_stream = await self.client.completions.create(
            model="sdk-model",
            prompt="completion-usage",
            stream=True,
            stream_options={"include_usage": True},
        )
        completion_parts: List[str] = []
        completion_usage = None
        async for chunk in completion_stream:
            if chunk.choices:
                completion_parts.append(chunk.choices[0].text)
            if chunk.usage is not None:
                completion_usage = chunk.usage
        await completion_stream.close()

        self.assertEqual("".join(completion_parts), "hello world")
        self.assertIsNotNone(completion_usage)
        assert completion_usage is not None
        self.assertEqual(completion_usage.prompt_tokens, 1)
        self.assertEqual(completion_usage.completion_tokens, 2)
        self.assertEqual(completion_usage.total_tokens, 3)
        await asyncio.wait_for(completion_scenario.disconnected.wait(), 2)
        self.assertEqual(
            completion_scenario.requests[0].body["stream_options"],
            {"include_usage": True},
        )

    async def test_sdk_parses_stable_authentication_and_grant_errors(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        invalid_client = AsyncOpenAI(
            api_key=TEST_API_KEY[:-1] + "b",
            base_url=self.harness.base_url,
            max_retries=0,
            timeout=5,
        )
        try:
            with self.assertRaises(AuthenticationError) as authentication:
                await invalid_client.models.list()
            self.assertEqual(authentication.exception.status_code, 401)
            self.assertEqual(authentication.exception.code, "invalid_api_key")
        finally:
            await invalid_client.close()

        with self.assertRaises(NotFoundError) as grant:
            await self.client.chat.completions.create(
                model="ungranted-model",
                messages=[{"role": "user", "content": "must-not-dispatch"}],
            )
        self.assertEqual(grant.exception.status_code, 404)
        self.assertEqual(grant.exception.code, "not_found")
        self.assertEqual(
            self.harness.backend.scenario("must-not-dispatch").requests,
            [],
        )

    async def test_cancelled_sdk_consumer_releases_upstream_and_admission(self) -> None:
        await self.start_gateway()
        assert self.harness is not None
        assert self.client is not None

        scenario = self.harness.backend.scenario("cancel")
        stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "cancel"}],
            stream=True,
        )
        first = await asyncio.wait_for(stream.__anext__(), 2)
        self.assertEqual(first.choices[0].delta.content, "hello")

        blocked_read = asyncio.create_task(stream.__anext__())
        await asyncio.sleep(0.05)
        self.assertFalse(blocked_read.done())
        blocked_read.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await blocked_read
        await stream.close()

        await asyncio.wait_for(scenario.disconnected.wait(), 2)
        models = await self.client.models.list()
        self.assertEqual([model.id for model in models.data], ["sdk-model"])

    async def test_graceful_drain_completes_active_sdk_stream(self) -> None:
        await self.start_gateway(shutdown_timeout_secs=2)
        assert self.harness is not None
        assert self.client is not None

        scenario = self.harness.backend.scenario("graceful")
        stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "graceful"}],
            stream=True,
        )
        first = await asyncio.wait_for(stream.__anext__(), 2)
        self.assertEqual(first.choices[0].delta.content, "hello")

        self.harness.signal_shutdown()
        await self.harness.wait_for_listener_closed()
        scenario.release.set()

        parts = ["hello"]
        async for chunk in stream:
            content = chunk.choices[0].delta.content
            if content:
                parts.append(content)
        await stream.close()

        self.assertEqual("".join(parts), "hello world")
        self.assertEqual(await self.harness.wait_for_exit(), 0)

    async def test_forced_drain_terminates_blocked_sdk_stream(self) -> None:
        await self.start_gateway(shutdown_timeout_secs=0)
        assert self.harness is not None
        assert self.client is not None

        scenario = self.harness.backend.scenario("forced")
        stream = await self.client.chat.completions.create(
            model="sdk-model",
            messages=[{"role": "user", "content": "forced"}],
            stream=True,
        )
        first = await asyncio.wait_for(stream.__anext__(), 2)
        self.assertEqual(first.choices[0].delta.content, "hello")

        blocked_read = asyncio.create_task(stream.__anext__())
        self.harness.signal_shutdown()
        self.assertEqual(await self.harness.wait_for_exit(), 0)

        with self.assertRaises(httpx.RemoteProtocolError):
            await asyncio.wait_for(blocked_read, 2)
        await stream.close()
        await asyncio.wait_for(scenario.disconnected.wait(), 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
