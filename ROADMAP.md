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
| Standalone autoscaling | Experimental | Local and Kubernetes Scale adapters exist; real-cluster/Box conformance, versioned idempotency, and real control-plane recovery remain open |
| Automatic gradual rollout | Unavailable | `rollout {}` is rejected; use explicit static revision weights |
| Same-host HTTP performance | Measured | Five alternating trials report 40,887 req/s for A3S and 55,913 req/s for NGINX; the measured A3S/NGINX throughput ratio is 73.1% |
| Cross-platform installation | Available | Checksum-verified macOS, Linux, and Windows installers plus release archives, Cargo, Homebrew, Docker, and Helm |

## Open work

### Performance

- Profile the remaining scheduler and upstream-pool acquisition costs on
  dedicated hardware before changing correctness or lifecycle semantics.
- Keep the same-host small-response profile reproducible, publish raw trials,
  and treat runs on different hosted-runner CPU models as separate snapshots.
- Add separate TLS, HTTP/2, streaming, gRPC, and upstream-dominated profiles
  before drawing conclusions outside the current HTTP/1.1 workload.
- Add regression thresholds only after stable dedicated-runner evidence exists.

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
- Close the Box Scale API contract and real executor recovery path.
- Add versioned idempotency for ambiguous scale mutations.
- Keep this feature opt-in and isolated from `cloud-managed` mode.

### `A0` and `C0` — future AI protocols

Native MCP or remote Agent traffic is planned only after a versioned contract
defines identity, authorization, session affinity, resumption, cancellation,
drain, discovery, bounds, telemetry, and mixed-version recovery. A2A has no
committed Gateway milestone.

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
