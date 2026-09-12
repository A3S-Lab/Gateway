# AI Gateway comparison plan

This suite compares A3S Gateway with an NGINX reverse-proxy baseline using
AI inference traffic rather than generic short HTTP responses. The primary
signals are time to first token (TTFT), inter-token latency (ITL), time per
output token (TPOT), end-to-end latency, completed-token goodput, and stream
correctness under concurrency and failure.

The existing `benchmarks/proxy-comparison` suite remains the protocol and
small-response baseline. Its finite OpenAI rows measure request-validation
cost, but their immediate fixed responses cannot represent model-serving
latency or token delivery quality.

## Comparison lanes

Results must identify one of these lanes. Ratios from different lanes must
never be presented as capability-equivalent.

1. **OpenAI wire path** — both products forward the same OpenAI-compatible
   request to the same deterministic upstream. A3S performs its bounded JSON
   and model validation; NGINX performs transport-only forwarding. This is the
   customer-visible product overhead, not a policy-equivalent comparison.
2. **Streaming transport control** — a non-OpenAI SSE route isolates HTTP
   relay cost. It is the control needed to distinguish generic streaming
   overhead from A3S OpenAI request processing.
3. **AI policy path** — A3S enables model aliases, identity, admission,
   fallback, telemetry, or rollout policy. Standard NGINX has no native
   equivalent; report A3S absolute measurements and mark the NGINX capability
   as unavailable unless the exact external modules and configuration are
   supplied and versioned.
4. **Inference lifecycle** — A3S Box/Sandbox scale-to-zero, cold start,
   recovery, and isolation are measured end to end. A static NGINX upstream is
   a control for warm relay latency, not an equivalent lifecycle manager.

## Metric contract

All timestamps use the load generator's monotonic clock. An OpenAI token is a
successfully decoded non-terminal SSE `data:` event carrying one benchmark
sequence number; HTTP chunks and TCP packets are not tokens.

| Metric | Definition |
| --- | --- |
| TTFT | Request start through receipt and decode of the first token event. Includes connection reuse, request upload, Gateway queueing, and upstream first-token delay. |
| ITL | Interval between adjacent decoded token events for one stream. Publish pooled and per-request P50/P90/P95/P99. |
| TPOT | Per completed stream, `(last_token - first_token) / (token_count - 1)`. |
| E2E | Request start through validated `[DONE]` receipt or complete non-streaming body. |
| Token goodput | Validated output tokens from successfully completed streams divided by the measured wall interval. |
| Stream rate | Successfully completed streams divided by the measured wall interval. |
| Correctness | Status, content type, strictly increasing sequence, exact token count, one terminal marker, and no bytes after terminal. |
| Cancellation propagation | Client cancellation through upstream disconnect observation. |
| Resource cost | Proxy CPU time, maximum RSS, file descriptors, connections, and context switches normalized by completed tokens. |

Every latency distribution publishes sample count, minimum, mean, P50, P90,
P95, P99, and maximum. A trial is invalid if any stream is silently truncated,
duplicated, reordered, or counted after `[DONE]`. Errors remain in the result;
they are never removed from latency or goodput interpretation.

## Scenario matrix

The six matrices below define 59 named scenarios, with transport and deployment
variants treated as explicit dimensions rather than additional cherry-picked
headlines.

The first deterministic upstream accepts explicit first-token delay, token
cadence, token count, prompt size, and both supported completion endpoints.
Later fault/framing milestones add event grouping, fragmentation, response
size, cancellation observation, and failure-stage controls. Real-model lanes
reuse the same client and schema so synthetic and hardware evidence remain
comparable.

### Streaming latency and framing

| ID | Workload | Required reading |
| --- | --- | --- |
| `stream-overhead-c1` | 1 client, zero upstream delay, 32 tokens | Minimum proxy TTFT/ITL overhead |
| `stream-overhead-c64` | 64 clients, zero delay, 32 tokens | Scheduler and connection-pool tail |
| `stream-paced-c16` | 50 ms first token, 10 ms cadence, 32 tokens | Added TTFT and cadence distortion |
| `stream-paced-c64` | Same pacing at 64 clients | P95/P99 under normal multiplexing |
| `stream-long-output` | 256 and 1,024 tokens | Long-stream drift and goodput |
| `stream-bursty` | 8 token events per upstream write | SSE framing without treating chunks as tokens |
| `stream-fragmented` | One event split across several writes | Incremental parser correctness |
| `stream-unicode` | UTF-8, multiline data, and split code points | Byte-boundary correctness |
| `stream-chat` | `/v1/chat/completions`, `stream=true` | Chat delta path |
| `stream-completions` | `/v1/completions`, `stream=true` | Legacy completion path |

### Prompt and response shape

| ID | Workload | Required reading |
| --- | --- | --- |
| `prompt-1k` | 1 KiB JSON prompt | Small-request baseline |
| `prompt-32k` | 32 KiB prompt | Common long-context upload |
| `prompt-256k` | 256 KiB prompt | Validation and allocation pressure |
| `prompt-1m` | 1 MiB prompt | Large-context tail latency |
| `prompt-limit` | Exactly the A3S body limit | Boundary success and memory ceiling |
| `prompt-over-limit` | Declared length past limit | Early 413, no body read, no upstream work |
| `json-short` | Non-streaming short completion | Normal JSON E2E |
| `json-large` | Multi-MiB completion or embedding | Response relay and memory behavior |
| `chunked-upload` | Unknown content length in many chunks | Request streaming/buffering behavior |

### Concurrency, queueing, and backpressure

| ID | Workload | Required reading |
| --- | --- | --- |
| `concurrency-sweep` | 1/4/16/64/256/1,024 active streams | Saturation curve and knee |
| `mixed-short-long` | 90% 16-token, 10% 1,024-token streams | Head-of-line and fairness |
| `slow-reader` | Client reads slower than token cadence | Backpressure and bounded memory |
| `stalled-reader` | Client stops reading for a fixed window | Idle handling and unaffected-peer tail |
| `disconnect-before-token` | Client closes before first token | Upstream cancellation and slot release |
| `disconnect-after-token` | Client closes after token 1 or N | Post-commit cancellation behavior |
| `thundering-herd` | Simultaneous release of 256+ requests | Queueing, admission, and cold-start collapse |
| `steady-arrival` | Poisson arrivals below/at/above capacity | Queue delay and overload stability |

### Failure and timeout semantics

| ID | Injected condition | Required reading |
| --- | --- | --- |
| `connect-refused` | No upstream listener | Error latency and stable mapping |
| `connect-timeout` | Unreachable upstream | Bounded connect deadline |
| `headers-timeout` | Accept without response headers | Request deadline |
| `first-token-timeout` | Headers then no token | TTFT/idle deadline |
| `midstream-idle` | Pause after token N | Stream idle timeout |
| `total-timeout` | Continuous tokens beyond total limit | Absolute lifetime bound |
| `reset-before-token` | Upstream reset before first event | Retry/fallback eligibility |
| `reset-after-token` | Reset after visible output | No unsafe replay or duplicated tokens |
| `http-429` | Retry-After response | Status preservation/admission behavior |
| `http-500-503` | Retryable server failures | Retry budget and fallback |
| `malformed-sse` | Invalid framing or JSON event | Transparent relay versus validation contract |
| `missing-done` | EOF without terminal marker | Incomplete-stream accounting |

### AI policy and routing

| ID | A3S feature | Baseline interpretation |
| --- | --- | --- |
| `model-alias` | External alias to internal service | NGINX requires custom routing logic |
| `many-models` | 10/100/1,000 aliases | Routing lookup and reload scale |
| `api-key-auth` | Valid and invalid principals | NGINX only comparable with pinned auth module |
| `rate-limit` | Per-principal request/token admission | Rejection accuracy and overhead |
| `concurrency-limit` | Per-model active generation bound | Queue fairness and release on cancel |
| `fallback` | Primary failure before first token | Recovery TTFT and chosen backend |
| `no-replay-after-token` | Primary failure after output starts | Stream safety |
| `weighted-rollout` | Stable/canary model split | Distribution accuracy and latency |
| `telemetry-on-off` | Metrics/access log/tracing toggles | Observability cost by token |
| `wire-policy` | Optional request/response inspection | Explicit feature-cost lane |

### Lifecycle and isolation

| ID | Workload | Required reading |
| --- | --- | --- |
| `warm-sandbox` | Ready A3S Box Sandbox | Warm TTFT versus static NGINX |
| `cold-sandbox` | Scale from zero | Cold TTFT broken into queue/start/first token |
| `cold-herd` | Many requests for one zero replica model | Single-flight activation and fan-out |
| `multi-model-cold` | Independent cold models | Isolation and parallel activation |
| `idle-scale-down` | Warm, idle, then request | Scale-down correctness and next cold TTFT |
| `sandbox-restart` | Workload exits between requests | Recovery latency and generation fencing |
| `gateway-restart` | Gateway restarts with desired state | Reconciliation and request availability |
| `box-owner-death` | Box/OCI owner termination | Cleanup, recovery, and next-generation TTFT |
| `private-network` | Loopback-only model server | Real Gateway → Box → OCI relay |
| `resource-isolation` | CPU/memory constrained Sandbox | Tail behavior without cross-tenant leakage |

### Transport and deployment variants

Run the core profiles over downstream HTTP/1.1, downstream HTTP/2, TLS
termination, upstream TLS, keep-alive reuse, forced connection churn, IPv4,
IPv6 where available, and same-host versus network-separated upstreams. These
are dimensions, not separate cherry-picked headline results.

## NGINX baseline contract

The checked-in NGINX configuration is versioned with every result and must:

- use the same upstream address, request corpus, connection policy, and
  measurement order as A3S;
- disable response buffering (`proxy_buffering off`) and compression for
  token-stream profiles;
- state whether request buffering is enabled. Both settings are measured for
  large/chunked prompts because A3S intentionally performs bounded OpenAI JSON
  validation;
- keep the core prompt sweep within the checked-in 512 KiB client-body buffer.
  Disk-spill profiles use a dedicated writable volume (`disk-spill` /
  `nginx-disk-spill.conf`, recorded in `disk-spill-volume.txt`) and report it
  separately;
- use HTTP/1.1 upstream keep-alive with the `Connection` header cleared;
- set connect, send, and read timeouts to the scenario contract;
- disable access logs during latency trials, then measure logging as its own
  feature-cost profile;
- record NGINX, kernel, runner, CPU, memory, Gateway, upstream, and load-tool
  versions in the artifact.

Relevant directive semantics are pinned to the official NGINX documentation:
[`proxy_buffering`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffering),
[`proxy_request_buffering`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_request_buffering),
[`proxy_read_timeout`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout),
and [`proxy_next_upstream`](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_next_upstream).

## Statistical and publication rules

- Warm both products, alternate product order per trial, and use at least five
  trials for published AI latency results.
- Keep upstream delays deterministic and store the intended schedule beside
  observed timings. Use seeded randomized arrivals and publish the seed.
- Publish P50/P90/P95/P99, sample counts, errors, and every raw trial. Do not
  publish only the better product's best run.
- Shared GitHub runners are regression evidence only. Capacity or marketing
  claims require a dedicated, pinned runner and repeated runs on different
  days.
- Real-model results must record model digest, serving engine, accelerator,
  precision/quantization, prompt/output tokenization, batch policy, and engine
  scheduler settings.
- A result is comparable only when both products meet the correctness and
  success-rate gates. Unsupported capabilities are reported as unsupported,
  not as zero throughput.

## Automation tiers

1. **PR smoke (under 5 minutes):** build the deterministic upstream and load
   client; run one short streaming profile through both products; validate the
   JSON schema and exact token sequence.
2. **Main baseline:** run core TTFT/ITL profiles, prompt-size sweep, concurrency
   sweep through 64 clients, non-streaming JSON, and cancellation smoke.
3. **Nightly stress/fault:** high concurrency, mixed workloads, slow readers,
   timeout/reset matrix, policy features, resource capture, and 15+ minute
   steady-state trials.
4. **Dedicated inference runner:** vLLM/TGI/llama.cpp or another pinned real
   engine, fixed model artifacts, dedicated CPU/GPU, network-separated and
   A3S Box/Sandbox cold-start lanes.

## Implemented baseline

The repository now owns a deterministic OpenAI-compatible upstream, a
streaming-aware Rust load client, A3S and NGINX fixtures, a repeated-trial
runner, and a strict exporter. Run the release-profile baseline on Linux with:

```bash
cargo build --locked --release --bin a3s-gateway \
  --example ai_benchmark_upstream --example ai_benchmark_load
bash scripts/run-ai-gateway-comparison.sh
```

`AI_BENCH_PROFILES`, `AI_BENCH_TRIALS`, `AI_BENCH_OUTPUT`, and
`AI_BENCH_EXPORT` can narrow a smoke run or redirect its artifacts. The runner
currently automates zero-delay and paced concurrency lanes, long output,
Chat/Completions parity, and 32/256 KiB prompts. Opt-in `sse-transport-c1` /
`sse-transport-c64` use the same C1/C64 zero-delay schedule as
`stream-overhead-*` against non-OpenAI `POST /benchmark/sse`, isolating generic
SSE relay cost from A3S OpenAI JSON validation. Opt-in cancellation smoke
profiles `disconnect-before-token` and `disconnect-after-token` exercise
client close before/after the first token (`--disconnect-after-tokens`); the
deterministic upstream exposes `/benchmark/stats` client-cancel counters.
Opt-in `slow-reader` applies `--read-delay-ms` after each validated token so
the client consumes slower than upstream cadence (complete-stream gates still
apply). Opt-in `stalled-reader` pauses once via `--stall-after-tokens` /
`--stall-ms`, then resumes to `[DONE]`. Opt-in `http-503` / `http-500` /
`http-429` inject `--upstream-fault` so the deterministic upstream returns that
status before any token; the load client records fault latency with
complete-stream gates disabled for those lanes. `http-500` keeps concurrency
and request count under Gateway's default passive-health error threshold so
recorded statuses stay upstream 500 rather than gateway quarantine 503
(`http-503` can share that shape). Opt-in `missing-done`,
`reset-before-token`, and
`reset-after-token` truncate the SSE body without `[DONE]` after 0, 1, or all
tokens. Opt-in `malformed-sse` emits one well-framed SSE event with invalid
JSON; the load client requires a 2xx `text/event-stream` response then
records the decode failure so transparent relay is distinguished from
gateway-side rejection. Opt-in `first-token-timeout` / `midstream-idle` switch the runner onto
`gateway-timeout.acl` and `nginx-timeout.conf` (2s idle / 3s request+total)
while upstream holds forever via `hold-first-token` / `midstream-idle` faults;
default fixtures stay at 120s so complete-stream medians are not poisoned.
Opt-in `headers-timeout` / `total-timeout` reuse those short fixtures with
`hold-headers` (no response headers) and `endless-stream` (tokens without
`[DONE]` until `stream_total_timeout`). Opt-in `connect-refused` points both
proxies at a closed port via `gateway-refused.acl` / `nginx-refused.conf` and
records proxy-error latency (`--expect-proxy-error`, warmup 0). Opt-in
`connect-timeout` uses `gateway-blackhole.acl` / `nginx-blackhole.conf`
(TEST-NET-3 `203.0.113.1`) with service `connect_timeout = "2s"` so dial is
bounded independently of `request_timeout`. Opt-in `telemetry-on` switches
onto `gateway-telemetry.acl` (metrics, access log, and tracing enabled) for
the paced C16 workload and records A3S absolute medians only—NGINX is marked
unsupported for that policy lane unless a pinned equivalent module is
supplied. Opt-in `telemetry-off` runs the matching paced C16 schedule on the
default fixture (observability left off) so feature-cost deltas vs
`telemetry-on` stay A3S-only absolute. Opt-in `fallback` switches onto `gateway-fallback.acl` /
`nginx-fallback.conf`: primary points at a closed port; the runner trips
Gateway passive health (and NGINX `max_fails`) quarantine before each trial,
then the measured complete-stream batch (`warmup_requests=0`) recovers through
service `failover` / upstream `backup`. `http-503` / `http-500` also exercise
Gateway passive-health quarantine; the runner waits for half-open recovery
before the next profile instead of disabling health checks. Opt-in `stream-bursty` packs eight SSE token events into each upstream write
(`--tokens-per-write 8`) so proxies and the load client must frame by event
boundaries rather than treating one chunk as one token. Opt-in
`stream-fragmented` splits each SSE event across four upstream write frames
(`--fragments-per-event 4`) so proxies and the load client must reassemble
events incrementally. Opt-in `stream-unicode` enables UTF-8 token text,
multiline SSE `data:` lines, and mid-codepoint write cuts
(`--unicode-payload` with `--fragments-per-event 4`) so byte-boundary
correctness is proven end-to-end. Opt-in `prompt-limit` pads the serialized chat body to exactly 8 MiB via
`--target-body-bytes` (Gateway OpenAI ceiling and NGINX `client_max_body_size 8m`)
and must complete the stream. Opt-in `prompt-over-limit` advertises
`--declare-content-length` one byte past the ceiling (no body upload), expects
HTTP 413 via `--accept-http-status` / `--require-all-rejections`, and asserts
upstream `/benchmark/stats` `streams_started` does not rise. Opt-in `json-short`
uses `--no-stream` for a complete non-streaming JSON chat body (E2E only; no
TTFT/ITL). Opt-in `prompt-1m` is a paced complete-stream lane with a 1 MiB
prompt (`prompt_bytes=1048576`). Opt-in `chunked-upload` sends the OpenAI JSON
body with `--chunked-upload-frames` (`Transfer-Encoding: chunked`). Opt-in
`request-buffering-on` / `request-buffering-off` reuse that chunked schedule
while varying only NGINX `proxy_request_buffering` (`nginx.conf` vs
`nginx-request-buffering-off.conf`); A3S stays on `gateway.acl` bounded OpenAI
validation for both. Opt-in `disk-spill` reuses the paced 32 KiB prompt schedule
with `nginx-disk-spill.conf` (`client_body_buffer_size 16k` +
`client_body_temp_path /tmp/a3s-ai-bench-client-body`); the runner creates that
volume and records it in `AI_BENCH_OUTPUT/disk-spill-volume.txt`. Opt-in
`gateway-restart` kills and restarts the product under test with the same
standalone `gateway.acl` / `nginx.conf` desired state, records
`restart_recovery_ms` (kill → `/health`), then measures paced complete-stream
availability (`warmup_requests=0`). This is process-restart reconciliation, not
Cloud managed-snapshot EXIT (covered separately by Gateway integration tests).
Opt-in
`prompt-1k` is the small paced-prompt baseline. Opt-in `json-large` uses
`--no-stream --response-bytes` for a multi-MiB padded completion body. Do not
invent standalone `concurrency-limit` from `container_concurrency` alone—that
arms Box/k8s autoscaler preparation (EXIT with Box), not a noop executor.
Opt-in `thundering-herd` barrier-releases 256 concurrent short streams; opt-in
`mixed-short-long` uses `--long-every` / `--long-token-count` for a 90/10 mix.
Opt-in `steady-arrival` uses seeded Poisson open-loop arrivals
(`--poisson-arrival-rps` / `--arrival-seed`) with published
`arrival_offsets_ms` — not a fixed-rate closed-loop lane renamed as Poisson.
Opt-in `concurrency-sweep` expands to six fixed-workload points
(`concurrency-sweep-c1` … `c1024`) so only concurrency changes; do not rename a
single-C lane as a sweep. High points (256/1024) stay out of the default CSV
until dedicated-runner capacity evidence. Opt-in `transport-keepalive` /
`transport-churn` compare the same short-stream workload with HTTP/1.1 pool
reuse versus `--force-connection-close` (Connection: close, idle pool 0). Opt-in
`transport-tls-http1` / `transport-tls-http2` terminate TLS on both products
(`gateway-tls.acl` / `nginx-tls.conf` + checked-in self-signed certs) with plain HTTP upstream;
load client uses `--insecure-tls` and optional `--http2` ALPN. Dual-product via
`nginx-tls.conf` (cert material copied to `/tmp/a3s-ai-bench-*.pem`). Opt-in
`transport-upstream-tls` keeps plain HTTP downstream and verifies HTTPS
upstreams with Gateway `load_balancer.tls_ca_file` and NGINX
`proxy_ssl_trusted_certificate` against the private test CA (no production
skip-verify). Opt-in `transport-ipv6`
runs the same short-stream workload over `[::1]` end-to-end
(`gateway-ipv6.acl` / `nginx-ipv6.conf` + upstream on `[::1]:18100`). `wire-policy` stays on the separate `wire`/sentry feature path. `model-alias` /
`many-models` remain Cloud-managed inference EXIT work—not inventable in
standalone AI fixtures. Opt-in
`weighted-rollout` switches onto `gateway-weighted.acl` /
`nginx-weighted.conf` (90/10 stable:canary via Gateway `revision` weights and
NGINX upstream `weight`); dual upstreams stamp `benchmark_instance` and the
load client records `instance_distribution`. Opt-in `rate-limit` switches onto
`gateway-ratelimit.acl` / `nginx-ratelimit.conf` (token-bucket / `limit_req`)
and uses `--accept-http-status 429` so one batch mixes admitted SSE streams
with intentional 429 rejections. Opt-in `api-key-auth` switches onto
`gateway-apikey.acl` (Authorization Bearer gate) and mixes valid-key admits
with omitted-key HTTP 401s via `--api-key` / `--omit-api-key-every 2` /
`--accept-http-status 401`; NGINX is A3S-only for that policy lane until a
pinned auth module is supplied. Opt-in `no-replay-after-token` switches onto
`gateway-noreplay.acl` / `nginx-noreplay.conf` (primary + failover/backup,
Gateway retry + `Idempotency-Key`, NGINX `proxy_next_upstream`), injects
`reset-after-token`, and asserts the canary upstream
`/benchmark/stats` `streams_started` counter does not rise—proving mid-stream
primary failure does not open a second upstream for the same request. Keep
framing/fault/policy/fallback/weighted/rate-limit/api-key-auth/
no-replay-after-token/stream-fragmented/stream-unicode/prompt-limit/
prompt-over-limit/json-short/prompt-1m/chunked-upload/prompt-1k/json-large/
thundering-herd/mixed-short-long/steady-arrival/concurrency-sweep/transport-keepalive/transport-churn/transport-tls-http1/transport-tls-http2/transport-ipv6/transport-upstream-tls/sse-transport-c1/sse-transport-c64/request-buffering-on/request-buffering-off/disk-spill/gateway-restart/http-500/telemetry-off lanes out of the
default published CSV until dedicated-runner evidence justifies mixing them
with complete-stream medians. It emits a separate versioned
`website/assets/ai-gateway-comparison.json`; the existing protocol artifact
stays intact so protocol RPS and AI token-latency claims cannot be mixed.

Main-branch publication runs every core profile for five alternating A3S and
NGINX trials, rejects any incomplete or misordered token stream, validates the
exported site artifact, and publishes the raw trials plus medians at
[`ai-gateway-comparison.json`](https://a3s-lab.github.io/Gateway/assets/ai-gateway-comparison.json).
