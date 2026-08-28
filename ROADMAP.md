# A3S Gateway Roadmap

## Product boundary

A3S Gateway is the **AI Native Traffic Layer**. It owns the local data plane:

- HTTP/1.1, HTTP/2, SSE, WebSocket, gRPC, TCP, UDP, and TLS;
- routing, middleware, balancing, health, failover, and streaming bounds;
- validation and atomic activation of complete ACL or Cloud snapshots;
- local OpenAI-compatible authorization and model dispatch;
- node-local telemetry and a bounded durable usage spool; and
- a machine-only Node API for health, metrics, version, and managed snapshots.

A3S Cloud owns human operations, tenants, credentials, deployment, placement,
desired replicas, production rollout, audit views, and the long-term usage
ledger. Gateway does not provide an operator web platform.

The governed Agent Runtime plan preserves this boundary: Gateway may enforce
public ingress and emit bounded demand/usage evidence, but it does not proxy
ordinary Agent egress, inject Agent credentials, transform Tool results,
decide idle suspension, or own checkpoint state. See the
[cross-repository platform roadmap](https://github.com/A3S-Lab/a3s/blob/main/docs/agent-runtime-platform-roadmap.md).

## Product maturity

The current `v1.1.1` release is a **Production Candidate**. The core data
plane is suitable for controlled production use when operators validate their
own capacity envelope, retain a tested rollback path, and monitor the Node API
and exported telemetry. It is not yet positioned as a universal NGINX
replacement or as Enterprise GA for every managed topology.

| Dimension | Current posture | Promotion gate |
| --- | --- | --- |
| Core data plane | Production-capable | Keep protocol, reload, failure, and bounded-drain regressions green across every supported platform |
| Standalone operations | Production Candidate | Add dedicated-hardware soak evidence, documented capacity envelopes, and repeatable fault-injection recovery evidence |
| Cloud-managed operations | H0.2 verified; integration hardening | Extend the verified exact-apply, recovery, certificate/target replacement, replica-local readiness, and version-compatibility contract into independently placed H0.3 topology and H0.4 production HA |
| Enterprise assurance | Pre-GA | Complete a published threat model, independent security review, long-duration reliability evidence, and operator runbooks |
| Product evidence | Public baseline available | Add representative production case studies without turning synthetic benchmarks into capacity promises |

Maturity is promoted by evidence, not by a calendar date. A release can add
features without changing this posture when the corresponding recovery,
security, or operating proof remains open.

## Operating modes

| Mode | Desired-state owner | Allowed behavior |
| --- | --- | --- |
| `standalone` | Local ACL | Local routes, services, middleware, providers, static revision weights, mirroring, and opt-in experimental scaling |
| `cloud-managed` | A3S Cloud | One complete identity-, revision-, digest-, CAS-, and expiry-bound snapshot; local mutation sources, rollout, and autoscaling are rejected |

Changing modes requires a process restart. A rejected or stale snapshot leaves
the prior validated runtime active.

## Current state

| Area | Status | Evidence |
| --- | --- | --- |
| Core proxy data plane | Available | Full-duplex HTTP and gRPC, SSE, WebSocket, TCP/UDP, TLS, safe trailers, hop-by-hop isolation, backpressure, independent first-response/idle/total bounds, and bounded drain |
| Routing and middleware | Available | Precompiled route rules and pipelines; built-in ACL policy; typed Rust `MiddlewareRegistry`; startup and reload fail closed |
| Health and balancing | Available | Four balancing strategies, active/passive health, circuit state, sticky sessions, failover, mirroring, and static revision weights |
| Configuration lifecycle | Available | Serialized startup/reload/shutdown, listener reconciliation, atomic snapshot swap, exact readiness, prior-runtime retention, and optional durable managed-state recovery |
| Managed target delivery (`H0.2`) | Verified jointly | Released Gateway v1.0.14 and pinned A3S Cloud clean-host gates cover exact apply/ACK, process loss, redelivery, conflict/expiry rejection, certificate and target-generation replacement, independent replica readiness, and management-protocol compatibility |
| Managed Runtime Service routes | Gateway foundation available | Embedded hosts have a durable exact-generation loopback overlay with Gateway-path health, admission closure, accepted-stream drain, receipt-owned removal, reload/snapshot preservation, and restart replay. Production A3S Use/Code provider composition and cross-platform real-process qualification remain open. |
| Managed OpenAI paths | Gateway foundation available | Models, chat completions, completions, embeddings, grants, rewriting, RPM/burst/concurrency admission, request/attempt identity, health-aware targets, and pre-response fallback |
| Multimodal adaptation | Design only; unavailable | Native multimodal upstreams pass content through unchanged. The proposed opt-in path uses bounded VLM/OCR/ASR evidence before text-model dispatch and requires independent security, quality, latency, and recovery gates |
| Observability | Available | Terminal JSON access logs, W3C/B3 trace intake, W3C propagation, Prometheus metrics, service latency/TTFT/pressure signals, and bounded labels |
| Usage spool | Gateway local foundation available | Prompt-free request/attempt lifecycle records, integrity, bounded capacity, restart recovery, ordered replay, contiguous acknowledgement, reclamation, and compaction |
| Standalone autoscaling | Experimental | Box v1 desired-state recovery, ready endpoint discovery, scale-from-zero routing, deterministic operation identity, Kubernetes resource-version CAS, and ambiguous-result/process recovery are covered by local, real-Gateway, real-Kubernetes, and exact-revision real Linux Box Sandbox fixtures; real MicroVM workload conformance remains open |
| Automatic gradual rollout | Unavailable | `rollout {}` is rejected; use explicit static revision weights |
| Same-host traffic performance | Measured | Three alternating trials across HTTP/1.1, HTTPS, HTTP/2, gRPC, SSE, WebSocket, TCP, UDP, OpenAI JSON, and OpenAI streaming; every published median has 100% success and includes throughput plus average/P50/P90/P99 latency; feature-free HTTP, SSE, and standalone OpenAI traffic share one route-bound Hyper pool |
| AI token-streaming performance | Measured | Five alternating A3S/NGINX trials across eight OpenAI-compatible pacing, concurrency, output-length, endpoint, and prompt-size profiles; every valid trial requires exact ordered tokens and publishes TTFT, ITL, TPOT, E2E, stream rate, and token goodput |
| Cross-platform installation | Available | Checksum-verified macOS, Linux, and Windows installers plus release archives, Cargo, Homebrew, Docker, and Helm |
| Versioned documentation | Available | The `v1.1` stable channel documents released 1.1.x behavior; `next` is an explicitly non-release development channel with route and section-parity checks |

## Outcome roadmap

### Production Candidate baseline - current

- Keep the released protocol, policy, streaming, health, reload, telemetry, and
  delivery behavior covered by cross-platform CI and public evidence.
- Keep install artifacts, checksums, container images, Homebrew, Cargo, and
  documentation aligned with the same release.
- Treat the ten-profile same-host comparison as regression evidence, not a
  capacity forecast or a claim that every path outperforms NGINX.
- Keep the eight-profile token-aware AI comparison reproducible, publish all
  five alternating trials, and separate feature-on A3S OpenAI validation from
  NGINX's transport-only baseline.

### Managed deployment proof - current and next

- Keep the completed `H0.2` exact-revision Cloud/Gateway gate green; its
  evidence covers process loss, redelivery, stale/conflicting/expired state,
  certificate and target replacement, independent replicas, and protocol
  compatibility.
- Close `I0.2b` and `I0.2c` jointly with compatible A3S Cloud revisions,
  including expiry, revocation, fallback, usage gaps, and reconciliation.
- Prove bounded drain, node loss, rolling replacement, and version skew across
  independently placed Gateway replicas for `H0.3` and production HA for
  `H0.4`.

### Enterprise GA - promotion gate

- Publish dedicated-hardware capacity envelopes and long-duration soak results
  for representative HTTP, streaming, and model workloads.
- Exercise listener, upstream, controller, disk, and network failures through
  repeatable fault-injection suites and operator runbooks.
- Complete the Gateway threat model, an independent security review, and
  remediation evidence for release and managed-operation paths.
- Document at least one representative production adoption with topology,
  workload, operating bounds, and recovery outcomes.

### AI protocol expansion - future

- Evaluate opt-in multimodal adaptation only under the closed contract in
  [`docs/multimodal-adaptation.md`](docs/multimodal-adaptation.md). A specialist
  VLM/OCR/ASR service may produce bounded provenance-bearing text for a
  text-only target; this is lossy preprocessing, not intrinsic multimodality.
- Keep native multimodal pass-through as the preferred path when an upstream
  already supports the client's media content.
- Admit native MCP or remote Agent traffic only after identity, authorization,
  session, cancellation, drain, discovery, telemetry, and compatibility
  contracts are versioned and testable.
- Keep A2A outside committed delivery until the same contract and recovery
  bar can be met.

## Open work

### Performance

- Keep the unified HTTP/SSE/OpenAI relay and low-allocation standalone OpenAI
  validation path covered by protocol and request-validation regressions.
- Profile the remaining scheduler and upstream-pool acquisition costs on
  dedicated hardware before changing correctness or lifecycle semantics.
- Keep the ten-profile same-host matrix reproducible, publish raw trials, and
  treat runs on different hosted-runner CPU models as separate snapshots.
- Keep the token-aware AI matrix centered on TTFT, ITL, TPOT, E2E latency,
  correctness, and completed-token goodput; extend its implemented core with
  framing, cancellation, backpressure, fault, policy, and Sandbox lifecycle
  lanes from the checked-in scenario plan.
- Extend the plan with the multimodal image, document, audio, video, protocol,
  load, recovery, security, and quality lanes defined in the design proposal.
  Publish media-fetch, decode, adapter, rewrite, and target-first-token timing
  separately; NGINX remains a transport baseline rather than a quality baseline.
- Add dedicated-runner and real-model variants with pinned model, serving
  engine, accelerator, tokenizer, batching, network, and Sandbox revisions
  before making capacity claims.
- Add regression thresholds only after stable dedicated-runner evidence exists.

The current matrix, environment, versions, and individual trials are published
in [`performance-comparison.json`](website/assets/performance-comparison.json).
The token-aware AI artifact is published separately at
[`ai-gateway-comparison.json`](https://a3s-lab.github.io/Gateway/assets/ai-gateway-comparison.json),
and its full scenario backlog and fairness contract live in
[`benchmarks/ai-gateway-comparison`](benchmarks/ai-gateway-comparison/README.md).

### `H0.2` — managed target delivery

Complete. Gateway snapshot validation, atomic activation, exact readiness,
replay, rejection retention, TLS replacement, target-generation identity, and
durable restart recovery are covered locally. The pinned A3S Cloud clean-host
gate adds process loss before acknowledgement, exact redelivery, certificate
and target replacement, independent replica journals/readiness, rollout
thresholds, and management-protocol compatibility against a released Gateway
revision. See the [E0 conformance record](docs/cloud-managed-e0-conformance.md)
for the exact revisions, runs, acceptance matrix, and remaining H0.3/H0.4
boundary.

### `I0.2b` — inference authorization

The four OpenAI-compatible request paths and local grant enforcement are
available in Gateway. The remaining cross-product work is:

- trusted tokenizer/input/output accounting;
- per-grant token reservation, budget enforcement, and reconciliation;
- the matching Cloud policy compiler; and
- joint expiry, revocation, fallback, and mixed-version conformance.

### `I0.2c` — usage delivery

The local spool and acknowledgement engine are available. Remaining work:

- freeze the authenticated Cloud batch/highest-contiguous-ACK contract;
- connect the production uploader and explicit gap reconciliation;
- ingest request/attempt records into the Cloud ledger; and
- prove crash, replay, duplicate delivery, and backlog recovery end to end.

The local spool is not the long-term ledger. Cloud owns deduplication,
retention, aggregation, showback, and billing data.

### `H0.3` to `H0.5` — production topology

- Extend the typed target identity now retained by each managed backend and
  exposed as a stable opaque telemetry ID across cluster-private multi-node
  routing. Legacy managed snapshots without the optional identity remain valid
  for rolling replacement.
- Prove target removal before workload termination and bounded connection drain.
- Complete mixed-version rolling replacement, node-loss, revision-skew, and
  degraded-readiness evidence across multiple Gateway replicas.
- Add trusted token throughput and provider-native capacity signals only after
  their source contracts close.
- Keep managed replica and rollout decisions in A3S Cloud.

### `I0.3` to `I0.5` — intelligent distributed inference routing

- Consume only complete, expiring Cloud/Edge target and scheduling snapshots;
  do not introduce an llm-d control plane, Kubernetes `InferencePool`, or a
  second endpoint-discovery authority.
- Apply one closed request-scoped filter/score/pick pipeline over eligible
  Power endpoints using rollout generation, phase role, local concurrency,
  age-bounded queue/cache observations, and optional certified latency signals.
- Support explicit credential- and model-scoped prompt-cache affinity without
  persisting or tokenizing prompts. Precise prefix indexing remains unavailable
  until a privacy-reviewed Power/model contract exists.
- Own bounded in-memory pool-defense flow control, priority/fairness dispatch,
  cancellation and drain while leaving backend execution admission in Power.
- Select compatible decode and optional prefill endpoints from one exact
  deployment generation. Gateway never reads, stores, transfers, or validates
  KV bytes; Power owns the typed state-transfer result.
- Emit complete, cardinality-bounded scheduling evidence for Cloud's sole
  Workloads autoscaler. Managed Gateway health and pressure may suppress an
  endpoint but never change desired replicas or placement.

### Standalone scaling

- Keep the Kubernetes Scale adapter covered against a digest-pinned real
  cluster, including resource-version conflict, scale convergence, and
  controller-recreation evidence.
- Keep Box endpoint relays covered against a real Linux Sandbox at exact
  Gateway, Box, and OCI Runtime revisions, including scale-from-zero traffic
  through the runtime-owned relay and compare-and-set relay retirement.
- Validate the same endpoint relay against a real MicroVM workload on an
  enabled hardware runner. A skipped or simulated KVM job is not hardware
  evidence; the v1 API, pre-termination endpoint withdrawal, bounded relay
  drain, ambiguous mutation, and Gateway process-restart paths remain covered
  locally.
- Keep deterministic operation identity, Kubernetes resource-version CAS, and
  ambiguous-result/process-restart reconciliation covered by real-process
  regressions.
- Keep this feature opt-in and isolated from `cloud-managed` mode.

### `A0` and `C0` — future AI protocols

Native MCP or remote Agent traffic is planned only after a versioned contract
defines identity, authorization, session affinity, resumption, cancellation,
drain, discovery, bounds, telemetry, and mixed-version recovery. A2A has no
committed Gateway milestone.

### `MM0` to `MM3` — multimodal adaptation

The design is documented, but no adapter is shipped. Contract and threat-model
work (`MM0`) precedes an image/OCR prototype (`MM1`), operational proof (`MM2`),
and any audio/video expansion (`MM3`). The complete policy must bind modality,
origin, size, duration, adapter model/revision, deadline, concurrency, usage,
and failure behavior. Adapter failure is explicit before text-model dispatch;
Gateway never silently strips media. See
[`docs/multimodal-adaptation.md`](docs/multimodal-adaptation.md).

### `AR0.6` — bounded wake-on-ingress support

Gateway work begins only after Cloud freezes a complete, expiry-bound wake
contract and Runtime/Box prove pause/resume recovery. Gateway may then:

- detect demand for a currently suspended exact target generation;
- emit one deduplicated, bounded wake signal through the existing managed
  control integration;
- buffer only explicitly eligible requests within fixed byte and time limits;
- reject non-replayable or expired demand without retrying after upstream
  response start; and
- retain request-path telemetry without creating desired state.

Gateway never invokes Box or Runtime directly, starts a replica, selects an
idle policy, stores wake operations, or turns local health into a scale
decision. Wake-on-ingress remains unavailable until the exact Cloud, Runtime,
Box, and Gateway recovery gate passes.

## Architecture invariants

1. Authorized traffic never requires a synchronous Cloud API or database call.
2. Managed configuration is complete, canonical, versioned, digest-addressed,
   expiry-bound, and atomically applied.
3. Rejected, partial, conflicting, or stale state cannot replace the active
   runtime.
4. Gateway selects only targets and weights present in the active snapshot;
   local health may suppress a target but cannot add one.
5. Retry and fallback stop after an upstream response starts.
6. Streaming preserves backpressure and has separate first-response, idle, and
   total bounds.
7. Gateway does not persist prompts, responses, provider secrets, or plaintext
   inference credentials.
8. Desired replicas, placement, and production rollout remain Cloud decisions.
9. Ordinary Agent outbound traffic, credential injection, context capture, and
   Tool-result transformation never enter Gateway.
10. Multimodal adaptation, if enabled in a future release, is explicit,
    provenance-bearing, bounded, and completed before text-model dispatch; it
    is never presented as a native capability of the selected text model.
11. Exact cache contents and KV/recurrent state remain Power/model facts.
    Gateway may retain only bounded, expiring scheduling observations and
    opaque affinity identities for the active snapshot.

## Definition of done

A roadmap item is complete when:

- standalone and cloud-managed validation remain isolated;
- ACL fields use `a3s-acl` and have canonical parse and compatibility tests;
- protocol behavior passes real client/upstream success, failure, timeout,
  disconnect, reload, and recovery fixtures;
- rejected and replayed snapshots preserve one exact active revision;
- process loss does not duplicate controller decisions or lose acknowledged
  durable state;
- secrets and model content stay out of logs, traces, state, and Cloud events;
- metrics remain within a documented label-cardinality budget;
- formatting, Clippy, focused tests, integration tests, and documentation checks
  pass; and
- cross-product work records compatible Gateway and Cloud revisions in
  `compat/cloud-stack.acl`.

## Non-goals

- An operator UI or Cloud-equivalent control plane inside Gateway.
- Tenant, credential, deployment, audit, usage-ledger, or billing databases.
- Production placement, rollout, or autoscaling decisions in managed mode.
- Plaintext provider credentials in ACL snapshots.
- Cloud calls on the live request path.
- Unbounded buffering or retry after response start.
- Protocol claims without real conformance and recovery evidence.
- An Agent egress proxy, brokered-Secret authority, idle/autoscaling
  controller, Tool-result compressor, or Agent checkpoint store.
