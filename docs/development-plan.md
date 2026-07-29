# A3S Gateway Development Plan

## 1. Scope and authority

**Status as of 2026-07-30.**

The root [roadmap](../ROADMAP.md) owns Gateway capability truth and its place
in the A3S Cloud portfolio. This plan owns dependency order, implementation
slices, verification, and release evidence for Gateway sub-gate `MCP0.4`.

The cross-product `MCP0.1` contract and public gate state are owned by the A3S
Cloud roadmap. Runtime owns `MCP0.2`, Cloud owns `MCP0.3`, Gateway owns
`MCP0.4`, and no repository alone can close joint gates `MCP0.5` or `MCP0.6`.

## 2. Delivery objective

Serve one immutable, Box-hosted MCP AssetRelease through the ordinary Gateway
HTTP pipeline using modern MCP revision `2026-07-28`:

```text
client POST
  -> Gateway validates Origin, bounds, JSON-RPC, per-request metadata,
     and mirrored headers
  -> Gateway authenticates and authorizes from one applied ACL snapshot
  -> Gateway selects one healthy exact-profile Runtime endpoint
  -> Gateway dispatches once
  -> hosted server returns JSON or request-scoped SSE
  -> Gateway streams with backpressure, cancellation, telemetry, and drain
```

The capability remains planned until the real client/server and
cross-repository gates pass.

Implementation checkpoint (2026-07-30): `G-MCP00` through `G-MCP04` have
Gateway-local foundation evidence. The native route validates and authorizes,
selects only a healthy exact-profile target, and performs exactly one
dispatch. Discovery JSON is relayed unchanged, response metadata and byte/time
bounds are closed, notification `202` and ordered subscription events pass
through, and SSE retains admission until downstream close.
`G-MCP05`/`G-MCP06` protocol and real-server evidence are the active slices;
this is still not a product availability claim.

## 3. Responsibility boundary

Gateway owns:

- modern MCP Streamable HTTP ingress and response framing;
- request bounds, Origin validation, header/body consistency, and stable
  transport errors;
- request-level authentication and method/name authorization from local ACL
  policy;
- healthy selection within the complete allowed target set;
- request-scoped JSON/SSE forwarding, cancellation, timeouts, and drain;
- exact applied-policy readiness and bounded request-path telemetry; and
- standalone and Cloud-managed protocol conformance.

Gateway does not own:

- MCP assets, release admission, tool catalogs, tenants, grants, desired
  replicas, placement, rollout, or autoscaling;
- Runtime Unit lifecycle, endpoint invention, or provider recovery;
- a protocol session or sticky-affinity store;
- a Cloud call on the request path;
- server tools, prompts, resources, discovery identity, or application state;
  or
- automatic replay after upstream dispatch begins.

The hosted server remains the MCP server of record. Gateway forwards
`server/discover` and may verify its shape in conformance tests, but does not
synthesize or merge it.

## 4. Protocol baseline

The initial gate supports only the modern protocol era:

- revision `2026-07-28`;
- one POST endpoint;
- one JSON-RPC request or notification per HTTP request;
- required per-request protocol version and client capabilities, plus validated
  recommended `clientInfo` that is never trusted as an authenticated identity;
- required `MCP-Protocol-Version`, `Mcp-Method`, and applicable `Mcp-Name`
  headers;
- immediate JSON or request-scoped SSE;
- long-lived `subscriptions/listen` on its own response stream; and
- cancellation by closing the request's SSE stream.

The initial gate does not support `initialize`, protocol sessions,
`Mcp-Session-Id`, GET streams, DELETE session termination, sticky routing, or
`Last-Event-ID` resumption. Dual-era compatibility is a separate future gate.

Protocol references:

- [MCP versioning and compatibility, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
- [MCP Streamable HTTP, revision 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP server discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover)

## 5. Dependencies

| Dependency | Required contract |
| --- | --- |
| Cloud `MCP0.1` | Canonical immutable MCP Service-profile ACL, separate route-policy projection, protocol versions, profile and snapshot digests, path, authentication/grants, limits, errors, telemetry budget, and joint fixture |
| Runtime `MCP0.2` | Distinct Unit identity per replica and exact generation/profile-bound typed TCP endpoint evidence |
| Cloud `MCP0.3` | Complete managed ACL snapshot with exact target set, release/profile digest, policy expiry, authorization material, and rollout weights |
| Cloud `H0.2` | Native managed snapshot apply, exact readiness, prior-revision retention, and generation-bound target projection |
| Gateway foundations | HTTP/SSE pipeline, bounded body collection, managed snapshot journal, health selection, identity, access-log terminal guards, and bounded drain |

`MCP0.4` may build standalone fixtures after `MCP0.1`, but the product claim
waits for all dependencies and joint `MCP0.5`.

## 6. Architecture plan

### 6.1 Closed ACL projections

Add a closed immutable MCP Service-profile projection and a separate mutable
route-policy projection to Gateway's existing ACL model. Both standalone files
and Cloud-managed snapshots use the same `a3s-acl` parser, canonicalization,
and validation. The complete snapshot digest binds both.

The projection contains:

- exact supported modern versions, one literal POST path, and immutable
  release/semantics-profile identities;
- separate route-policy identity, allowed origins, and request authentication;
- optional bounded method/name grants;
- body, header, response, rate, concurrency, first-response, stream-idle,
  stream-total, and drain bounds;
- complete targets with Unit, generation, endpoint, health, priority/weight,
  and profile digest;
- telemetry/cardinality policy and snapshot expiry; and
- no plaintext credentials.

Validation rejects unknown fields, empty target sets where policy requires
availability, mixed profile digests, duplicate targets, unsafe paths/origins,
unbounded limits, sticky policy, legacy sessions, and incompatible protocol
versions. Rejection keeps the prior runtime active.

### 6.2 Request pipeline

The MCP stage is part of the ordinary HTTP listener and executes in this order:

| Step | Action | Failure boundary |
| --- | --- | --- |
| 1 | Match an applied MCP route by listener/host/path/POST | Non-matching traffic keeps ordinary Gateway semantics |
| 2 | Validate Origin, content type, Accept, and declared header/body size bounds | Reject before authentication or body work |
| 3 | Authenticate locally against bounded snapshot policy and recheck expiry | No Cloud call; denied requests have no body parse, target, or attempt |
| 4 | Collect once and parse one bounded JSON-RPC message | Stable bounded request error |
| 5 | Validate `_meta` plus mirrored protocol/method/name headers | Reject before body-derived policy, telemetry labels, or upstream work |
| 6 | Enforce method/name grants, rate, and concurrency | Release guards on every terminal path |
| 7 | Select one healthy exact-profile target | No session or sticky key |
| 8 | Create attempt identity and begin upstream dispatch | Hard no-replay boundary starts |
| 9 | Relay JSON, `202`, or request-scoped SSE with backpressure | Downstream close cancels upstream work |
| 10 | Emit one redacted terminal result and release accounting | No body, arguments, or credentials in telemetry |

Header names compare case-insensitively; method/name values compare according
to the protocol. `Mcp-Name` sentinel encoding is decoded before body
comparison. A mismatch returns HTTP `400` and the modern `HeaderMismatch`
contract before dispatch.

Unrecognized `Mcp-Param-*` headers are forwarded without becoming policy
inputs. Gateway may recognize one only when the applied Cloud projection
contains a bounded schema path tied to the exact profile digest; it then
decodes and validates the value against the parsed body before use. Gateway
never fetches `tools/list` or another schema on the request path.

### 6.3 Dispatch and retry rule

Modern stateless MCP is not automatically idempotent.

| Point of failure | Gateway action |
| --- | --- |
| No target selected or target becomes unhealthy before dispatch | Select another eligible target within the same snapshot |
| Connection attempt is proven to have sent no request bytes | A later slice may reselect only with explicit transport evidence and contract coverage; default is fail |
| Upstream dispatch has begun | Never replay or fall back |
| Upstream returns status, headers, JSON, or SSE bytes | Relay the result; never replay |
| Downstream disconnects | Cancel upstream work and emit one cancelled terminal result |

The default single-attempt rule applies to `tools/call`, discovery, list/read
methods, extensions, and unknown methods. A future idempotency extension needs
its own immutable profile field, request identity, mixed-version behavior, and
real duplicate-suppression gate.

### 6.4 Discovery and replica consistency

`server/discover` is routed like any other authorized request. Gateway does not
cache or synthesize its result in `MCP0.4`.

Cloud must publish only targets with one semantics-profile digest for a logical
MCP route. Gateway validates that invariant during snapshot apply. Distinct
AssetReleases may coexist only in a Cloud-declared rollout with the same
profile digest. A contract-changing rollout becomes a separately proven
route/profile revision and acknowledged cutover; it is not represented as
mixed discovery results behind one route.

### 6.5 Streaming, cancellation, and drain

- Preserve request-scoped SSE event order and backpressure.
- Forward immediate JSON and notification `202` responses without wrapping.
- Disable intermediary buffering where required by the upstream response.
- Bound first response, idle stream, total stream, and process drain
  independently.
- Treat client closure as request cancellation and stop upstream work as soon
  as practical.
- Keep `subscriptions/listen` alive only within the explicit policy and send no
  independent Gateway-generated MCP message.
- Do not resume streams from `Last-Event-ID`.
- On reload, old in-flight work retains its immutable policy guard while new
  requests use the new snapshot.
- On shutdown, close admission, drain bounded streams, force-cancel at the
  deadline, join tasks, and release all backend/admission accounting.

### 6.6 Security and telemetry

- Validate Origin before expensive work and return `403` for an invalid
  present Origin.
- Authenticate every request; no prior request or connection establishes
  authorization.
- Reject expired or incomplete security policy and recheck expiry after slow
  work.
- Strip ingress authorization and replace correlation headers before proxying.
- In `MCP0.5`, forward no ad hoc user, tenant, project, or grant identity to the
  server; authorization is service-level at Gateway. A later delegated-caller
  mode requires the versioned signed assertion owned by `MCP0.6`/`C0.3`.
- Never log or persist credentials, client capability payloads, tool
  arguments, resource URIs or contents, prompts, or responses.
- Allow only bounded route, method, explicitly allowlisted non-sensitive
  tool/prompt name, outcome, target, and opaque identity labels. Resource URIs
  are never labels. Prune labels on snapshot replacement.
- Preserve one request identity and one concrete attempt identity; a
  pre-dispatch rejection has no attempt.
- Keep Gateway telemetry and bounded conformance evidence as request-path
  observations, not a durable business ledger. Per-request Cloud audit
  ingestion waits for the shared ordered/acknowledged `MCP0.6`/`C0.3` contract
  and must not create an MCP-specific spool.

## 7. Task graph

| ID | Status | Task | Depends on | Completion evidence |
| --- | --- | --- | --- | --- |
| `G-MCP00` | Foundation complete (2026-07-30) | Import and freeze `MCP0.1` fixtures and error contracts | None | Exact Cloud/Runtime/Gateway fixture revisions and golden cases recorded |
| `G-MCP01` | Foundation complete (2026-07-30) | Add closed ACL types, canonicalization, validation, and managed-snapshot compatibility | `G-MCP00` | Golden parse/round-trip/rejection/retention tests; request path remains fail-closed |
| `G-MCP02` | Foundation complete (2026-07-30) | Add bounded JSON-RPC, per-request metadata, and mirrored-header validation | `G-MCP01` | Golden valid/malformed/mismatch/version/name/encoding cases |
| `G-MCP03` | Foundation complete (2026-07-30) | Add local authentication, method/name authorization, expiry, admission, and credential stripping | `G-MCP02` | Denial, revocation/expiry, reload retention, and no-upstream-work tests |
| `G-MCP04` | Foundation complete (2026-07-30) | Add exact-profile target selection and single-attempt dispatch | `G-MCP02`, `G-MCP03` | No-session/sticky and injected ambiguous-failure no-duplicate tests |
| `G-MCP05` | Foundation in progress | Forward discovery and ordinary JSON/notification responses | `G-MCP04` | Discovery identity/capabilities and empty notification `202` pass-through fixtures exist; real-server evidence remains |
| `G-MCP06` | Foundation in progress | Add request-scoped SSE, subscriptions, disconnect cancellation, and bounds | `G-MCP04` | Ordered subscription events and SSE admission-through-close fixtures exist; timeout, reload, and drain evidence remain |
| `G-MCP07` | Planned | Add snapshot reload, process drain, and exact readiness behavior | `G-MCP05`, `G-MCP06` | Prior-route retention, in-flight policy, graceful/forced drain, and restart tests |
| `G-MCP08` | Planned | Add redacted access logs, metrics, traces, and request/attempt correlation | `G-MCP03`-`G-MCP07` | Terminal-path and cardinality-budget tests with payload/secret scan |
| `G-MCP09` | Planned | Run standalone real-client/real-server conformance | `G-MCP01`-`G-MCP08` | Pinned modern client matrix against a real Gateway binary |
| `G-MCP10` | Planned | Run Cloud-managed exact-snapshot conformance | `G-MCP09`, Cloud `MCP0.3` | Apply/reject/replay/restart/expiry and target-generation evidence |
| `G-MCP11` | Planned | Run fault, security, load, and soak campaigns | `G-MCP10` | Process loss, malformed traffic, slow streams, cancellation, leak, and limit evidence |
| `G-MCP12` | Planned | Audit and close `MCP0.4` | `G-MCP00`-`G-MCP11` | Every Gateway criterion maps to exact-SHA evidence and joint `MCP0.5` input |

## 8. Work packages

### Package A: Contract without availability (`G-MCP00`-`G-MCP01`)

Land compatibility types and rejection fixtures first. No README capability
claim or live request-path dispatch is enabled in this package.

### Package B: Safe unary path (`G-MCP02`-`G-MCP05`)

Deliver body/header validation, local authorization, exact target selection,
single-attempt dispatch, discovery forwarding, and immediate JSON behavior.
Every rejection before dispatch proves zero upstream calls.

### Package C: Long-lived behavior (`G-MCP06`-`G-MCP08`)

Deliver request-scoped SSE, subscriptions, cancellation, independent bounds,
reload/drain semantics, and redacted terminal telemetry without a second
listener or proxy implementation.

### Package D: Release proof (`G-MCP09`-`G-MCP12`)

Run real binaries and clients in standalone and Cloud-managed modes, inject
failure at every transition, publish limits, and provide the exact evidence
bundle consumed by Cloud `MCP0.5`.

## 9. Verification matrix

| Layer | Mandatory cases |
| --- | --- |
| ACL | Canonical round trip, unknown field, invalid version/path/origin/bound, mixed digest, duplicate target, legacy/sticky rejection, prior-snapshot retention |
| Parser | JSON-RPC shape, one-message rule, `_meta`, header omission/mismatch, case rules, Base64 sentinel, body/header limits, unsupported version |
| Security | Origin, missing/invalid/revoked/expired credential, grant miss, forged headers, slow-auth expiry, credential stripping, absence of unsigned caller identity upstream, and cross-tenant opaque IDs |
| Routing | Zero/one/many healthy targets, profile/generation mismatch, health suppression, deterministic selection, no session/sticky state |
| Replay safety | Failure before selection, before dispatch, during write, after server execution, before response, and during SSE; no duplicate dispatch after the hard boundary |
| Protocol | `server/discover`, tools list/call, resources/prompts fixture methods, notification `202`, method-not-found, immediate JSON, progress SSE, `subscriptions/listen` |
| Lifetime | First-response/idle/total bounds, downstream disconnect, upstream close, reload, graceful drain, forced drain, task/accounting release |
| Recovery | Rejected snapshot, exact replay, stale revision, process loss, journal recovery, target generation change, policy expiry |
| Observability | One terminal result, request/attempt identity, fixed label budget, removed-label pruning, no sensitive bodies or credentials |
| Joint | Real Cloud snapshot, Runtime/Box endpoint, Gateway binary, modern client, hosted fixture, rollout, rollback, stop, and cleanup at exact revisions |

## 10. Release gates

Gateway `MCP0.4` is complete only when:

1. every `G-MCP00` through `G-MCP12` task has authoritative evidence;
2. standalone and Cloud-managed behavior pass independently;
3. all product configuration is canonical ACL parsed and generated with
   `a3s-acl`;
4. modern MCP requests never create protocol sessions or sticky state;
5. mirrored headers are never trusted before body validation;
6. no injected post-dispatch ambiguity produces a second upstream call;
7. discovery and application responses come from the hosted server;
8. request-scoped SSE, subscription, disconnect, reload, and drain accounting
   return to baseline;
9. logs, state, telemetry, and evidence contain no credentials or sensitive
   MCP payloads;
10. format, tests, Clippy, documentation, security, load, and leak gates pass;
    and
11. the joint bundle records compatible Cloud, Runtime, Box, Gateway, client,
    and server fixture revisions.

Passing an ordinary HTTP proxy test, the optional wire firewall, a parser unit
test, or a mock upstream is not MCP conformance.

## 11. Non-goals

- Implementing a Cloud control plane, asset catalog, scheduler, rollout
  evaluator, or autoscaler in Gateway.
- Adding MCP to the optional wire firewall instead of the ordinary pipeline.
- Supporting the legacy initialization/session era in the first gate.
- Caching or merging discovery/tool catalogs on the live path.
- Persisting tool state, prompts, resources, responses, or protocol sessions.
- Retrying `tools/call` because the transport is stateless.
- Calling Cloud, Runtime, or a schema registry synchronously per request.
- Forwarding raw client bearer credentials or inventing unsigned caller
  identity headers for the hosted server.
