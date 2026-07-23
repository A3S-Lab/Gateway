# Official OpenAI SDK conformance

This suite runs the pinned official Python SDK against a real
`a3s-gateway` process. It applies a complete inference policy through the
native managed snapshot API and uses a controllable HTTP/SSE upstream.

The cases cover:

- model listing and non-streaming response parsing;
- stable authentication and grant error parsing;
- request rewriting and credential stripping;
- SSE framing and `[DONE]` termination while the upstream remains open;
- explicit SDK stream close and cancelled asynchronous consumers;
- graceful completion inside the configured drain deadline; and
- forced termination at a zero-second drain deadline.

Run it from the Gateway repository:

```bash
cargo build --locked --bin a3s-gateway
python -m pip install --requirement tests/openai_sdk/requirements.txt
python tests/openai_sdk/test_conformance.py
```
