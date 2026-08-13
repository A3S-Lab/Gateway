# Multimodal adaptation for text-only models

Status: design proposal. No released Gateway version implements this behavior.

## Decision

A3S Gateway can make an OpenAI-compatible text model **multimodal-assisted**, but
it cannot make the model intrinsically multimodal. An opt-in adapter can resolve
image, audio, or video inputs, call a bounded vision/OCR/ASR service, convert the
result into provenance-bearing text, and then dispatch that text to the selected
text model. The conversion is lossy, adds work before the first downstream token,
and cannot guarantee the quality of a native multimodal model.

The product language must therefore remain **multimodal adaptation**, not “any
text LLM becomes multimodal.” A useful result also depends on the text model's
context window, instruction following, language support, and the adapter model.

## What Qwen-MM-Plugins demonstrates

[Qwen-MM-Plugins](https://github.com/QwenLM/Qwen-MM-Plugins/tree/58c3e39722747e8ea4a156171966ff5714ea2a03)
uses two complementary patterns:

- local `Skill` and MCP tools let a capable agent harness read or render media;
- API-backed tools such as `vision_chat` call a multimodal model and return its
  answer as text that a text-only agent model can consume.

The first pattern still requires the harness/model to understand an MCP image
content block. The second pattern is the one a gateway can generalize: a
specialized model interprets the media before a text model receives a bounded
text representation. Qwen-MM-Plugins is an agent-harness integration, not a
transparent OpenAI request proxy, so A3S should reuse the architectural lesson
rather than embed its Python/MCP runtime in the Gateway data plane.

## Current Gateway boundary

The current Gateway:

- recognizes bounded JSON on `/v1/chat/completions`, `/v1/completions`, and
  `/v1/embeddings`, plus `GET /v1/models`;
- preserves unknown OpenAI JSON fields for ordinary proxying, so multimodal
  content already passes through unchanged when the selected upstream natively
  supports it;
- parses the complete managed request only to authorize an external model alias,
  select a target, and rewrite the upstream model; and
- gives request middleware mutable HTTP parts but no request-body transformation
  hook.

Consequently, multimodal adaptation does not belong in the current generic
middleware trait. Its safe insertion point is the native inference path after
authentication and bounded JSON validation, but before the first target-model
attempt is prepared. This preserves one authorization decision, one replayable
request document, pre-response fallback semantics, and accurate end-to-end TTFT.

## Proposed request path

```text
OpenAI client
  -> authenticate and admit request
  -> validate mixed text/media content
  -> fetch and decode media within policy
  -> call modality adapters in parallel within a shared deadline
  -> validate canonical evidence and record provenance
  -> rewrite media parts to clearly delimited, untrusted evidence text
  -> select and call the text-model target
  -> stream the original OpenAI-compatible response unchanged
```

Native multimodal targets bypass adaptation. Adaptation is enabled only by an
explicit model policy; the Gateway must never infer it from an upstream error or
silently remove media. If the adapter fails, the request fails before the text
model starts.

### Canonical evidence

An adapter should return a versioned structure, not free-form prompt fragments:

```json
{
  "schema": "a3s.multimodal-evidence.v1",
  "items": [
    {
      "index": 0,
      "media_type": "image/png",
      "sha256": "...",
      "adapter_model": "...",
      "adapter_revision": "...",
      "description": "...",
      "extracted_text": "...",
      "confidence": null,
      "truncated": false
    }
  ]
}
```

The Gateway validates and deterministically serializes this structure into the
downstream conversation. Extracted text remains untrusted input: a delimiter is
useful provenance, not a prompt-injection security boundary. Raw media, prompts,
descriptions, and model responses must stay out of logs and snapshot state.

## Two complementary integration modes

| Workload | Best integration | Reason |
| --- | --- | --- |
| Existing OpenAI client calling a text-only model alias | Gateway adaptation | Preserves one API surface and applies centrally governed media policy |
| Agent that can choose OCR, grounding, caption, or video tools | Skill/MCP in the agent harness | The agent can select the capability and iterate on tool output |
| Upstream already supports the supplied media parts | Transparent Gateway pass-through | Avoids a lossy and slower conversion |

Gateway adaptation must not turn the data plane into an MCP orchestrator. Agent
tool choice, working context, and multi-step reasoning remain agent-runtime
responsibilities.

## Policy contract to freeze before implementation

A future complete ACL or Cloud snapshot would need a versioned adapter profile
referenced by a model alias. At minimum it must bound:

- allowed modalities and MIME types;
- item count, encoded bytes, decoded pixels, duration, and extracted-text size;
- HTTPS origin allowlists, redirect behavior, and object-reference schemes;
- adapter service, model/revision, operation (caption, OCR, ASR, grounding, or
  fused video understanding), and prompt-template revision;
- fetch, decode, adapter, and whole-preprocessing deadlines;
- preprocessing concurrency and cost/token budgets; and
- failure policy, evidence retention, and cache policy.

The schema must be closed and atomically activated. Adapter services and text
targets must both be present in the same validated snapshot; local health may
suppress either but cannot invent a replacement.

## Safety and privacy requirements

1. Accept no `file:` path from a remote client. HTTPS fetches must reject loopback,
   link-local, private, metadata-service, and disallowed resolved addresses on
   every connection and redirect to prevent SSRF and DNS rebinding.
2. Sniff content rather than trusting extensions or `Content-Type`; reject archive,
   decompression, image-pixel, media-duration, and polyglot bombs within fixed
   byte and CPU limits.
3. Propagate cancellation to fetches and adapter calls. Bound every queue and
   preserve backpressure.
4. Do not retry or select another adapter after the text-model response starts.
   Never fall back by stripping media.
5. Treat OCR, captions, transcripts, EXIF, filenames, and remote metadata as
   attacker-controlled prompt content.
6. Keep provider credentials out of ACL snapshots and never forward client or
   adapter authorization headers across trust boundaries.
7. Record only bounded operational metadata: media digest, sizes, adapter
   identity/revision, timings, truncation, error class, and usage counters.
8. Start with derived-evidence caching disabled. Any later cache must key on the
   media digest plus adapter model, revision, prompt revision, and parameters,
   and must have explicit encryption, tenancy, retention, and erasure rules.

## Latency and observability contract

Preprocessing is part of the user-visible request. Published metrics must not
label the text-model's first token as end-to-end TTFT without including all work
before dispatch.

```text
TTFT_e2e = T_auth + T_fetch + T_decode + T_adapter + T_rewrite
           + T_target_queue + T_target_first_token
```

The Gateway should expose each bounded phase in internal metrics and tracing,
while access logs retain only terminal timings and opaque identities. Token
stream correctness, ITL, TPOT, end-to-end latency, completed-token goodput, and
disconnect behavior remain measured exactly as in the existing AI comparison.
Adapter usage is a separate child attempt so cost is not attributed to the text
model alone.

## Multimodal benchmark backlog

These lanes extend the existing 59-scenario AI gateway plan. Each scenario runs
native-multimodal pass-through and adapted text-model variants where meaningful;
NGINX remains a transport-only baseline, not a quality baseline.

| Group | Scenarios | Required evidence |
| --- | --- | --- |
| Images | caption, object counting, spatial VQA, dense OCR, rotated OCR, chart/table reading, screenshots, multi-image comparison, transparent/animated formats | task accuracy, provenance, adapter tokens, phase timings |
| Documents | single page, long PDF, mixed text/image pages, scan quality, page selection, repeated media, 32/256 KiB surrounding prompt | OCR quality, truncation, ordering, context expansion |
| Audio | clean/noisy ASR, multilingual speech, timestamps, long audio, silence, unsupported codec | WER or exact fixture text, duration, cancellation, TTFT breakdown |
| Video | sampled frames, scene change, temporal question, audio/video fusion, long video, corrupt container | task score, selected frames, duration, memory bound |
| OpenAI protocol | HTTPS URL, data URL, multiple content parts, streaming/non-streaming, tools, JSON mode, unknown fields, native-target bypass | byte-valid request/response, SSE order and `[DONE]`, field preservation |
| Load | 1/4/16/64 concurrency, one/many media items, cold/warm resolver, slow origin, slow adapter, large adapter output | queue time, TTFT/ITL/TPOT/E2E, goodput, memory and CPU |
| Recovery | origin 404/timeout, MIME mismatch, adapter 429/5xx/timeout, unhealthy adapter, text-target failure, client disconnect in each phase, reload during preprocessing | stable error, cancellation, no leaked admission, exact active revision |
| Security | loopback/private/metadata URLs, redirect pivot, DNS rebinding, oversized data URL, decompression/pixel bomb, EXIF/OCR prompt injection, cross-tenant cache probe | fail-closed result, zero forbidden egress, bounded labels and logs |
| Quality comparison | text+caption, text+OCR, text+grounding, native multimodal, task-specific adapter | accuracy/faithfulness, hallucination rate, cost, TTFT; no universal claim |

Raw media fixtures must be license-compatible and digest-pinned. Quality scores,
adapter/model versions, prompts, sampling parameters, hardware, and every raw
trial must be published alongside aggregate medians.

## Delivery gates

- **MM0 — contract:** threat model, canonical evidence schema, policy schema,
  stable errors, and deterministic fixtures.
- **MM1 — image/OCR prototype:** opt-in chat-completions adapter with HTTPS and
  data-URL bounds, no cache, exact protocol and cancellation tests.
- **MM2 — operational proof:** managed snapshot compatibility, usage child
  attempts, fault injection, load matrix, and public TTFT decomposition.
- **MM3 — modality expansion:** audio and video only after duration, decoding,
  quality, privacy, and cost gates pass independently.

No phase is complete merely because a demo returns a plausible answer. A phase
ships only when failure, recovery, security, quality, and token-stream evidence
are reproducible.

## Non-goals

- Claiming that a text-only model has learned visual or audio representations.
- Hiding adapter latency, usage, truncation, or model identity.
- In-process Python, dynamic plugin, or arbitrary MCP execution in Gateway.
- Storing media or derived prompt content in Cloud, access logs, or usage state.
- Automatic media removal, unbounded conversion, or fallback after response start.
