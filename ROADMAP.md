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

The current `v1.0.13` release is a **Production Candidate**. The core data
plane is suitable for controlled production use when operators validate their
own capacity envelope, retain a tested rollback path, and monitor the Node API
and exported telemetry. It is not yet positioned as a universal NGINX
replacement or as Enterprise GA for every managed topology.

| Dimension | Current posture | Promotion gate |
| --- | --- | --- |
| Core data plane | Production-capable | Keep protocol, reload, failure, and bounded-drain regressions green across every supported platform |
| Standalone operations | Production Candidate | Add dedicated-hardware soak evidence, documented capacity envelopes, and repeatable fault-injection recovery evidence |
| Cloud-managed operations | Integration hardening | Complete loss, replay, expiry, revocation, mixed-version, and multi-replica conformance with A3S Cloud |
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
| Managed OpenAI paths | Gateway foundation available | Models, chat completions, completions, embeddings, grants, rewriting, RPM/burst/concurrency admission, request/attempt identity, health-aware targets, and pre-response fallback |
| Observability | Available | Terminal JSON access logs, W3C/B3 trace intake, W3C propagation, Prometheus metrics, service latency/TTFT/pressure signals, and bounded labels |
| Usage spool | Gateway local foundation available | Prompt-free request/attempt lifecycle records, integrity, bounded capacity, restart recovery, ordered replay, contiguous acknowledgement, reclamation, and compaction |
| Standalone autoscaling | Experimental | Box v1 desired-state recovery, ready endpoint discovery, scale-from-zero routing, deterministic operation identity, Kubernetes resource-version CAS, and ambiguous-result/process recovery are covered by local and real-Gateway fixtures; real-cluster and Linux Box workload conformance remain open |
| Automatic gradual rollout | Unavailable | `rollout {}` is rejected; use explicit static revision weights |
| Same-host traffic performance | Measured | Three alternating trials across HTTP/1.1, HTTPS, HTTP/2, gRPC, SSE, WebSocket, TCP, UDP, OpenAI JSON, and OpenAI streaming; every published median has 100% success and includes throughput plus average/P50/P90/P99 latency; feature-free HTTP, SSE, and standalone OpenAI traffic share one route-bound Hyper pool |
| Cross-platform installation | Available | Checksum-verified macOS, Linux, and Windows installers plus release archives, Cargo, Homebrew, Docker, and Helm |
| Versioned documentation | Available | The `v1.0` stable channel documents released 1.0.x behavior; `next` is an explicitly non-release development channel with route and section-parity checks |

## Outcome roadmap

### Production Candidate baseline - current

- Keep the released protocol, policy, streaming, health, reload, telemetry, and
  delivery behavior covered by cross-platform CI and public evidence.
- Keep install artifacts, checksums, container images, Homebrew, Cargo, and
  documentation aligned with the same release.
- Treat the ten-profile same-host comparison as regression evidence, not a
  capacity forecast or a claim that every path outperforms NGINX.

### Managed deployment proof - next

- Close `H0.2`, `I0.2b`, and `I0.2c` jointly with compatible A3S Cloud
  revisions.
- Prove process loss, redelivery, stale and conflicting state, expiry,
  revocation, usage gaps, and certificate replacement end to end.
- Prove bounded drain, node loss, rolling replacement, and version skew across
  multiple Gateway replicas.

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
- Add workload variants for payload size, upstream latency, connection count,
  and longer-lived streams without treating them as new protocol support.
- Add regression thresholds only after stable dedicated-runner evidence exists.

The current matrix, environment, versions, and individual trials are published
in [`performance-comparison.json`](website/assets/performance-comparison.json).

### `H0.2` — managed target delivery

Gateway snapshot validation, exact readiness, replay, rejection retention, and
durable restart recovery are available. Joint Gateway + Cloud evidence remains
open for:

- process loss before and after apply;
- redelivery, stale revision, digest conflict, and expiry;
- certificate replacement and target-generation changes; and
- mixed Gateway versions receiving the same desired state.

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

- Bind cluster-private upstream identity to an applied target generation.
- Prove target removal before workload termination and bounded connection drain.
- Complete mixed-version rolling replacement, node-loss, revision-skew, and
  degraded-readiness evidence across multiple Gateway replicas.
- Add trusted token throughput and provider-native capacity signals only after
  their source contracts close.
- Keep managed replica and rollout decisions in A3S Cloud.

### Standalone scaling

- Validate the Kubernetes Scale adapter against a real cluster.
- Validate Box endpoint relays against real Linux Sandbox and MicroVM
  workloads; the v1 API, dynamic Gateway routing, pre-termination endpoint
  withdrawal, bounded relay drain, ambiguous mutation, and Gateway
  process-restart recovery paths are covered locally.
- Keep deterministic operation identity, Kubernetes resource-version CAS, and
  ambiguous-result/process-restart reconciliation covered by real-process
  regressions.
- Keep this feature opt-in and isolated from `cloud-managed` mode.

### `A0` and `C0` — future AI protocols

Native MCP or remote Agent traffic is planned only after a versioned contract
defines identity, authorization, session affinity, resumption, cancellation,
drain, discovery, bounds, telemetry, and mixed-version recovery. A2A has no
committed Gateway milestone.

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
