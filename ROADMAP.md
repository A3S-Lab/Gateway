# A3S Gateway Roadmap

## 1. Product position

**A3S Gateway is the AI traffic and protocol data plane for standalone and A3S
Cloud-managed deployments.**

It is a small, ACL-configured binary that accepts traffic, enforces one complete
local policy snapshot, selects an allowed healthy endpoint, and faithfully
relays long-lived AI protocols. It is not a tenant database, workload
orchestrator, production autoscaler, or management control plane.

The authoritative cross-product ownership and coordinated roadmap live in the
A3S Cloud
[product roadmap](https://github.com/A3S-Lab/Cloud/blob/main/ROADMAP.md).
This document narrows that plan to work owned by the Gateway repository. It
uses the existing Cloud `E0`, `H0`, `I0`, `C0`, and `A0` gates rather than
creating a competing milestone scheme.

The roadmap is gate-driven, not date-driven. A capability is:

- **Verified** only after its real protocol, failure, recovery, and
  cross-repository exit evidence passes;
- **Experimental** when code exists but production evidence is incomplete; or
- **Planned** until its named gate passes.

## 2. Product modes

### 2.1 Standalone

The operator-owned ACL configuration is the desired-state authority. Gateway
may load it at startup, watch files, or use an explicitly configured local
provider. The operator or an external orchestrator owns backend lifecycle,
placement, and production rollout.

Static routing, transport, health suppression, load balancing, mirroring, and
revision weights belong in this mode. Local scaling and automated rollout must
remain labeled experimental until their complete executor, measurement,
failure, and recovery gates pass.

### 2.2 Cloud-managed

A3S Cloud PostgreSQL state is the desired-state authority. Cloud compiles one
complete, versioned ACL snapshot for a logical Gateway scope and delivers it
through the outbound node agent. Gateway validates and atomically applies the
snapshot, then exposes the exact applied revision and digest for
acknowledgement.

A minimal node-local bootstrap ACL may bind the process, management listener,
identity, and Cloud-delivery settings. It cannot define or mutate managed
traffic routes, target sets, rollout, or scaling policy.

Managed mode must reject:

- local file, DNS, Docker, Kubernetes, or discovery providers that can change
  the target set;
- a Gateway-owned autoscaling controller;
- a Gateway-owned rollout controller; and
- partial or stale mutation that does not identify the complete expected
  snapshot.

Gateway may immediately suppress an unhealthy endpoint, open a circuit, or
drain a connection according to the applied policy. It may not add an endpoint,
change desired weights, create a replica, or promote a revision. Cloud remains
the sole authority for those decisions.

## 3. Scope

Gateway owns:

- HTTP/1.1, HTTP/2, SSE, WebSocket, gRPC, TCP, UDP, and TLS;
- host, path, method, header, and SNI routing;
- streaming, connection lifetime, timeout, retry-before-response, and drain;
- active and passive endpoint health and local circuit state;
- load balancing within the complete allowed target set;
- validation and atomic application of ACL snapshots;
- applied revision, readiness, endpoint health, and bounded telemetry output;
- native OpenAI model dispatch and cached authorization at `I0.2b`; and
- a durable local usage spool and ordered upload at `I0.2c`.

Gateway does not own:

- organizations, projects, environments, users, memberships, or durable
  grants;
- applications, Agents, MCP assets, models, providers, deployments, or
  credential catalogs;
- plaintext inference or provider credential storage;
- desired replica count, placement, production rollout, or production
  autoscaling in managed mode;
- durable operation history, usage aggregation, showback, or billing; or
- a second Cloud UI, scheduler, or business API.

## 4. Current capability truth

The plan starts from the implementation, not from prior marketing claims.

| Area | Current state | Product decision |
| --- | --- | --- |
| HTTP, SSE, WebSocket, gRPC, TCP, UDP, TLS, bounded graceful drain, routing, load balancing, health, and atomic reload | Available; shutdown closes listeners before drain, tracks long-lived work, force-cancels at the configured deadline, and does not report `Stopped` before task cleanup | Preserve and continuously regress, including the pinned official OpenAI Python SDK four-endpoint gate |
| Static revision traffic weights and mirroring | Available | Keep as data-plane policy execution |
| Local scale-to-zero and autoscaling | Experimental: the live loop observes healthy backends, active operations, and queue depth; executor selection fails closed; current replicas come from the selected executor before the first decision; queries and mutations are time-bounded; ambiguous failures force reconciliation before retry; accepted results alone advance replica state; and controller replacement occurs after runtime commit. The Kubernetes adapter uses the standard Deployment `Scale` subresource, fails closed on invalid or mismatched replica responses, passes a real-client local API wire/recreated-controller fixture, and passes real-Gateway process loss/restart against the stateful local API without a duplicate patch. Box and real-cluster Kubernetes end-to-end conformance, versioned idempotent operations, and recovery against a real executor/control plane remain open | Remove from top-level product promises; keep standalone-only until separately certified |
| Gradual rollout | Configuration and controller types exist, but no runtime loop drives the controller | Treat as unavailable; reject it in managed mode and do not advertise automatic rollback |
| Structured JSON access logging | Available: no-route, middleware, HTTP success/error, gRPC, SSE, and WebSocket paths enqueue one terminal entry; streaming guards emit on completion, disconnect, or drop; managed inference entries carry bounded request/attempt and snapshot identities | Preserve the terminal-path regression suite and keep serialization off the request hot path |
| Wire firewall | Optional, separate, single-upstream local proxy with opaque protocol semantics | Keep explicitly separate from the normal router, native MCP, and Cloud inference dispatch |
| Explicit Cloud-managed operating mode | Available: ACL defaults to `standalone`; `cloud-managed` rejects dynamic providers, local scaling, and local rollout; mode changes require restart; configuration and health status expose the active mode | Preserve the mode-isolation regression suite |
| Gateway-native managed snapshot foundation | Available when bootstrap ACL sets `managed.gateway_id`: exact ACL digest, revision CAS, 24-hour maximum validity, idempotent replay, bounded rejection status, exact-selector readiness, prior-runtime retention, opt-in durable restart recovery through `managed.state_file`, same-address HTTP/TLS, TCP, or UDP policy replacement, and real-binary managed TLS HTTP/SSE/WebSocket conformance across rejection, process loss, recovery, and replay | Wire Cloud to the native endpoint and add joint certificate/target-generation evidence before closing `H0.2` |
| Closed OpenAI request profile | Available: exact endpoint/method matching, fixed 8 MiB JSON collection, bounded model-field validation, byte-preserving ordinary forwarding, and stable request errors | Preserve ordinary proxy semantics outside the closed endpoint set |
| Managed inference policy contract | Gateway foundation available: a strict, expiring ACL projection validates credential verifiers, environment-scoped routes, ordered model targets, generation-bound grants, and per-Gateway limits as part of one atomic managed snapshot | Add the matching Cloud compiler and joint snapshot evidence before closing the contract |
| Snapshot-backed OpenAI model dispatch and Cloud authorization | Gateway request-path foundation available: policy-bound routers authenticate locally, enforce endpoint/model grants and per-grant RPM/burst/concurrency admission, strip credentials, list granted models, select healthy weighted targets, attach Gateway-owned request/attempt identities, fall back to lower priorities only before an upstream response starts, bound stream cancellation without a Cloud request, and pass pinned official OpenAI Python SDK conformance | Add token-budget enforcement, the Cloud compiler, and joint evidence before closing `I0.2b` |
| Durable request/attempt usage spool | Planned for `I0.2c` | Gateway owns local durability; Cloud owns ingestion and the ledger |
| Native MCP or agent-protocol data plane | Planned only against a closed `A0`/`C0` contract | Do not infer protocol support from the wire firewall |

README, examples, package metadata, and release notes must follow this table.
An implementation detail or unit-tested controller is not an available product
capability without a live integration and recovery path.

## 5. Architecture invariants

1. Gateway is never synchronously dependent on the Cloud API, PostgreSQL, or a
   worker for an authorized request.
2. Managed configuration is complete, versioned, canonical, digest-addressed,
   and atomically applied.
3. Rejected, partial, conflicting, or stale snapshots leave the prior proven
   snapshot active.
4. An expiring authorization snapshot fails closed after expiry; Gateway does
   not call Cloud per request to compensate.
5. Gateway selects only endpoints and weights present in the applied snapshot.
   Local health may remove an endpoint temporarily but can never add one.
6. Retry and fallback occur only before the first response byte. Every attempt
   has a stable identity.
7. Streaming paths preserve backpressure and have independent connection,
   first-byte, idle-stream, and total-operation bounds.
8. Production desired replica count and rollout are Cloud decisions. Gateway
   metrics are observations, never direct desired-state mutations.
9. Gateway does not persist prompts, responses, provider secrets, or plaintext
   inference keys.
10. Standalone and managed behavior have separate validation and conformance
    fixtures so one mode cannot silently enable the other's control loops.

## 6. Delivery plan

### 6.1 Core data-plane maintenance

Standalone Gateway remains a first-class product. Continue to improve protocol
correctness, TLS, static routing, middleware enforcement, load balancing,
health, graceful drain, atomic reload, observability, security, and measured
hot-path performance without requiring Cloud.

New transport capabilities such as HTTP/3 or cache mechanics belong in Gateway
only after their own real-client, failure, reload, and resource-bound tests
pass. Cloud may later project versioned policy for them, but it does not
reimplement their mechanics.

This lane does not grow a tenant model, workload scheduler, deployment engine,
or production autoscaler. A standalone extension must also preserve managed
mode isolation.

### 6.2 Baseline correction before `I0.2b`

This work makes the current surface truthful and prepares the managed contract;
it does not create a new product milestone.

1. **Complete (2026-07-23):** add an explicit `standalone` /
   `cloud-managed` operating-mode contract to ACL validation, configuration
   serialization, runtime health, and the Management API.
2. **Complete (2026-07-23):** in managed mode, reject file, discovery,
   Kubernetes, and Docker providers plus service-level rollout and
   autoscaling. Reject mode changes through every hot-reload path while
   preserving the prior configuration and lifecycle state.
3. **Gateway foundation complete (2026-07-23):** opt-in managed mutation
   requires stable Gateway identity, complete revision/CAS, exact ACL digest,
   and bounded validity. The Management API retains one applied record and one
   rejection, and readiness requires an exact identity/revision/digest query.
   An optional absolute `managed.state_file` adds an atomic write-ahead journal,
   fail-closed recovery, and idempotent redelivery across Gateway process
   restart. Cross-repository delivery evidence remains an `H0.2` exit gate.
4. **Complete (2026-07-23):** wire structured access-log entries into the
   background task for successful, proxy-error, no-route,
   middleware-rejection, gRPC, SSE, and WebSocket paths. Streaming and upgraded
   sessions emit through drop-safe terminal guards.
5. **Experimental foundation complete (2026-07-24):** the standalone
   autoscaler measures live healthy backends, active operations, and buffered
   queue depth. Executor selection rejects unknown, unavailable, and mixed
   backends without fallback; Kubernetes client initialization plus every
   replica query and scale call are bounded. A new or recreated controller
   obtains the authoritative current count from the selected executor before
   deciding. Explicit rejection retains the known count, while a failed or
   timed-out mutation clears it and requires reconciliation before retry.
   Prepared controllers start only after startup or reload commits, with the
   superseded task aborted and joined first. The Kubernetes adapter reads and
   merge-patches `/apis/apps/v1/namespaces/{namespace}/deployments/{name}/scale`
   rather than the full Deployment, rejects missing, negative, overflowing, or
   mismatched desired counts, and passes a real kube-client fixture for wire
   shape, API errors, ambiguous mutation recovery, and controller recreation.
   A real Gateway binary fixture additionally applies one Scale patch whose
   response is lost, reconciles the applied count, forces process loss, and
   proves that restart queries Scale before deciding without issuing a second
   patch. These fixtures use a stateful local API, not a real Kubernetes
   control plane or executor. Keep the feature experimental until the Box and
   Kubernetes adapters pass real end-to-end conformance, scale operations have
   a versioned idempotency contract, and recovery against a real executor
   passes. The existing Box HTTP adapter does not yet have an authoritative Box
   Scale API contract.
6. Keep the inert rollout block unavailable. If standalone rollout is later
   implemented, give it a separate explicit opt-in and never enable it in
   managed mode.
7. **Gateway fixtures complete (2026-07-23):** maintain ACL parsing,
   serialization, Management API health, mode isolation, rejected raw reload,
   exact replay, stale revision, digest conflict, identity/CAS mismatch,
   expiry, invalid ACL, failed bind, exact readiness, and prior-runtime
   retention tests. Durable restart, interrupted-prepare recovery, corrupt
   journal, real storage-failure, same-address TLS certificate replacement,
   TCP listener-policy, and UDP policy/target-replacement fixtures are
   available. Add joint Cloud delivery fixtures before closing `H0.2`.
8. Update public documentation and examples so only verified behavior is shown
   as available.

### 6.3 `H0.2`: managed target-set foundation

Gateway work:

- **Foundation available:** accept a complete ACL snapshot with stable Gateway
  identity, revision/CAS, exact digest, and validity capped at 24 hours.
- **Available:** validate managed-mode isolation and reject local mutation
  sources or control loops.
- **Available:** apply runtime-only changes atomically, preserve unchanged
  listeners, and pre-bind supported new-address HTTP, TCP, and UDP listener
  changes. Same-name, same-address HTTP/TLS, TCP, and UDP listener policy
  changes are pre-validated and committed without releasing the socket. UDP
  sessions are retired at snapshot cutover so a superseded target is not
  selected for later datagrams.
- **Available:** report exact applied or rejected status without claiming Cloud
  operation success.
- **Available:** when `managed.state_file` is configured, atomically journal
  prepared and applied records, restore the exact unexpired snapshot before
  readiness after restart, and fail closed on corrupt or mismatched state.
- **Available:** keep the prior snapshot on validation, supported bind/reload,
  same-address certificate, TCP policy, or UDP policy validation, and storage
  failure. Joint Cloud certificate convergence evidence remains open.
- **Available:** expose readiness only for an exact Gateway
  identity/revision/digest selector while the applied snapshot is unexpired.
- **Gateway real-binary fixture available (2026-07-24):** apply one managed TLS
  snapshot containing hostname/path routes, multiple services, and two targets;
  exercise HTTP, SSE, and WebSocket traffic; reject an invalid successor while
  retaining the prior protocols and exact readiness; force process loss;
  recover the durable revision and digest; and accept exact replay without a
  second mutation.

Joint exit evidence must include process death before and after apply,
redelivery, stale revisions, digest conflict, certificate replacement, and a
target that changes generation. No stale target may become active.

### 6.4 `I0.2b`: OpenAI data plane and authorization

Implement one native inference-dispatch stage in the ordinary HTTP pipeline:

- **Request-profile foundation complete (2026-07-23):** match only
  `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/completions`, and
  `POST /v1/embeddings`. For the POST endpoints, require `application/json`,
  collect and parse once under the fixed 8 MiB limit, require a bounded string
  `model` field, forward valid bytes unchanged, and return stable
  OpenAI-compatible request errors. Non-matching method/path combinations
  retain ordinary proxy behavior.
- **Gateway policy-contract foundation complete (2026-07-23):** accept the
  complete inference projection only through an expiring managed snapshot whose
  envelope and policy expiry match exactly. Strictly validate literal bounded
  Argon2id verifier metadata, credential generations and revocation, route and
  environment ownership, ordered target priorities and weights, model/endpoint
  grants, and positive local limits. Reject plaintext or unknown fields and
  omit verifier hashes from Gateway configuration and debug views.
- **Gateway authorization and dispatch foundation complete (2026-07-23):**
  close policy-bound routers to the four exact OpenAI methods and paths;
  authenticate Bearer inference keys before middleware and body collection
  through a two-permit off-runtime Argon2id boundary; cache only successful
  token digests for one exact snapshot; recheck expiry after slow work; strip
  credentials; enforce route, endpoint, generation, revocation, and model
  grants; return a sorted grant-filtered model list; and route aliases through
  the first healthy target priority with deterministic weighted selection and
  `upstream_model` rewriting.
- **Gateway request and concurrency admission complete (2026-07-23):** enforce
  each immutable grant's sustained RPM and burst through an exact integer token
  bucket, enforce its concurrent request cap through a terminal-lifetime guard,
  retain unchanged counter state across snapshot refresh, cover the local
  model catalog and invocation paths, and return stable OpenAI-compatible
  `429` responses with `Retry-After`. SSE retains concurrency until completion
  or disconnect. Invalid credentials, grant misses, and malformed model
  requests are rejected before admission.
- **Gateway request and attempt identity foundation complete (2026-07-23):**
  replace client request and attempt headers after credential and endpoint
  authorization, keep one Gateway UUIDv4 request ID across native, proxied,
  error, and SSE responses, create one UUIDv4 attempt ID only after concrete
  backend selection, forward both IDs upstream, and emit bounded route-policy,
  endpoint, model, target, and trace-correlation context without credentials or
  request/response bodies. Local model catalogs and pre-dispatch rejections
  have no attempt identity.
- **Gateway pre-response fallback foundation complete (2026-07-23):** retain
  one validated replayable request until an upstream response starts; move
  only to a lower target priority after connection failure or first-response
  timeout; preserve the request ID while assigning a new attempt ID; and never
  replay after an upstream status or response-body failure. Apply the same
  boundary to SSE, enforce the service timeout while waiting for response
  headers, and release backend connection accounting when a stream completes
  or is cancelled.
- **Gateway bounded-drain foundation complete (2026-07-23):** close HTTP, TCP,
  and UDP listeners before drain; gracefully stop HTTP/1.1 and HTTP/2
  keep-alive admission; track HTTP, SSE, WebSocket, and TCP work; immediately
  retire UDP sessions; use the configured process deadline; and force-cancel
  and join remaining work with drop-safe downstream and backend accounting.
- **Gateway official SDK conformance complete (2026-07-24; transport baseline
  2026-07-23):** recognize
  completion `stream: true` without requiring an SSE `Accept` header and run
  pinned `openai-python` 2.47.0 against a real Gateway binary configured through
  the managed snapshot API. Cover the exact Models, Chat Completions,
  Completions, and Embeddings matrix; typed non-streaming responses; the SDK
  default base64 embedding path; model rewriting; credential stripping; stable
  authentication and grant errors; chat and legacy completion usage chunks;
  SSE `[DONE]` while the upstream remains open; downstream close; asynchronous
  cancellation; admission release; graceful drain; and zero-deadline forced
  drain. Usage-chunk relay does not close the separate token-budget or durable
  usage contracts.
- enforce per-grant token-budget policy locally after the tokenizer,
  input/output accounting, reservation, and reconciliation contract closes;

Do not implement inference dispatch as a sidecar, a separate port, or a call to
the Cloud API.

### 6.5 `I0.2c`: durable usage and rollout execution

Gateway work:

- append `request_started` and `attempt_started` before upstream dispatch;
- append terminal success, failure, fallback, cancellation, or disconnect
  outcomes;
- persist a Gateway identity, boot epoch, monotonic sequence, and bounded
  retention;
- batch and replay records until Cloud acknowledges the highest contiguous
  sequence;
- expose gaps and backpressure instead of silently dropping auditable usage;
- fail closed when a route requires auditable usage and the spool is
  unavailable or full; and
- apply Cloud-published prior/candidate weights while Cloud alone evaluates and
  promotes the rollout.

The spool is not the long-term ledger. Cloud owns deduplication, gap state,
retention policy, request/attempt tables, rollups, and showback.

### 6.6 `A0` and `C0`: Agent and MCP traffic

Management MCP belongs to Cloud `C0`; it invokes the same authorized commands
and queries as REST and CLI. Gateway adds a native MCP or agent-protocol data
plane only when `A0` and `C0` provide a closed identity, session, route, and
deployment contract.

Any such profile must specify:

- transport and protocol versions;
- session affinity, resumption, cancellation, and drain;
- tenant and resource authorization;
- request and response bounds;
- tool or capability discovery;
- telemetry and audit correlation; and
- crash, reconnect, and mixed-version behavior.

A2A and additional protocol claims remain uncommitted until assigned to an
existing product gate with real conformance evidence.

### 6.7 `H0.3` through `I0.5`: production scale

For `H0.3`, support identity-bound cluster-private upstreams, independently
placed Gateway scopes, bounded drain, and target removal before Runtime stop.

For `H0.4`, support replicated Gateway deployment, per-instance exact-revision
readiness, mixed-version snapshot compatibility, graceful replacement, and
explicit degraded outcomes. No global atomic reload is assumed.

For `H0.5`, emit complete and age-stamped queue, active-request, latency, TTFT,
token-throughput, and backend-pressure signals required by Cloud. Managed mode
still contains no scaling evaluator. Bounded cold-start buffering is enabled
only by an applied Cloud policy whose timeout, capacity, and failure behavior
have passed the gate.

For `I0.5`, prove Gateway process and node loss, revision skew, authorization
expiry, quota-provider loss, usage backlog, cache pressure, protocol load, and
disaster recovery against published limits.

## 7. Recommended merge order

1. **Complete (2026-07-23):** product-mode types, validation fixtures, and
   management status.
2. **Complete (2026-07-23):** managed-mode rejection of local mutation sources
   and control loops.
3. **Complete (2026-07-23):** access-log emission and
   protocol-terminal-path tests.
4. **Gateway real-binary foundation complete (2026-07-24):** managed TLS
   HTTP/SSE/WebSocket, multi-service/multi-target, rejection retention, process
   loss, durable recovery, and exact replay. Cross-version delivery,
   certificate convergence, and target-generation fixtures with Cloud remain
   open.
5. **Complete (2026-07-23):** inference-dispatch request parser, closed
   endpoint matcher, fixed 8 MiB body collection, bounded model-field
   validation, and stable error contract.
6. **Gateway foundation complete (2026-07-23):** strict managed inference
   policy contract, atomic expiry binding, verifier redaction, referential
   validation, and resource bounds.
7. **Gateway foundation complete (2026-07-23):** snapshot-backed inference-key
   authentication, endpoint/model grants, filtered model listing, credential
   stripping, health-aware target routing, and upstream model rewriting.
8. **Gateway request/concurrency foundation complete (2026-07-23):** per-grant
   RPM, burst, concurrency, reload-state retention, and streaming-lifetime
   enforcement. Token-budget enforcement remains open.
9. **Gateway request/attempt identity foundation complete (2026-07-23):**
   Gateway-owned request and concrete upstream-attempt UUIDs, response and
   upstream headers, bounded snapshot/access-log context, spoofing replacement,
   and SSE lifetime coverage.
10. **Gateway pre-response fallback foundation complete (2026-07-23):**
    response-start-aware HTTP and SSE fallback, stable request identity,
    per-attempt identity, first-response timeout, and stream connection
    lifecycle.
11. **Gateway bounded-drain foundation complete (2026-07-23):** configured
    shutdown deadline, protocol-aware HTTP drain, tracked upgraded and transport
    relays, forced cancellation, joined cleanup, and listener/accounting
    release.
12. **Gateway official SDK conformance complete (2026-07-24):** JSON-selected
    OpenAI streaming plus real-client four-endpoint, usage-chunk, `[DONE]`,
    disconnect, cancellation, graceful-drain, and forced-drain evidence.
13. Durable spool, sequence protocol, replay, backpressure, and Cloud ingestion
   conformance.
14. Replicated readiness, private upstream identity, mixed-version rollout, and
    HA/load gates.
15. Native MCP or agent-protocol work only after its `A0`/`C0` contract is
    accepted.

Each merge should be the smallest vertical behavior that produces usable
evidence. Compatibility types may land earlier, but they do not make a product
capability available.

## 8. Definition of done

A Gateway slice is complete only when:

- standalone and managed validation both pass;
- public documentation and examples match the verified state;
- every new ACL field uses `a3s-acl` and has canonical parse, validation, and
  compatibility tests;
- successful, rejected, stale, replayed, and conflicting snapshot cases
  preserve one exact active revision;
- protocol behavior passes real client and upstream conformance, including
  streaming and disconnects;
- process death and restart do not create a second controller decision, lose an
  acknowledged state, or silently drop required usage;
- secrets, prompts, and responses do not appear in Gateway state, logs, traces,
  or Cloud-bound events;
- metrics obey a documented label-cardinality budget;
- focused formatting, tests, Clippy, and documentation checks pass in the
  Gateway workspace; and
- the joint release gate records compatible Gateway and Cloud revisions.

## 9. Non-goals

- A Cloud-equivalent control plane inside Gateway.
- Production workload creation, placement, rollout, or autoscaling in managed
  mode.
- A tenant, model, provider, credential, usage-ledger, or billing database.
- Plaintext provider credentials in ACL snapshots.
- Cloud API calls on the live request path.
- Unbounded buffering or retry after response bytes have reached the client.
- Protocol compatibility claims based only on accepting arbitrary HTTP bytes.
