# Cloud-managed E0 conformance

Status: **verified** on 2026-08-13.

This record closes the Gateway side of the A3S Cloud E0 route-publication
gate. It certifies the exact boundary between A3S Cloud, which owns desired
state and certificate lifecycle, and A3S Gateway, which validates and applies
one complete snapshot before reporting exact readiness.

## Certified revisions

- Gateway release [`v1.0.14`](https://github.com/A3S-Lab/Gateway/releases/tag/v1.0.14)
  at `fc8aa2584a6591120197c9585fcf79c3faa09c15`. It contains the
  generation-bound target implementation at
  [`e928967`](https://github.com/A3S-Lab/Gateway/commit/e92896769953aee28ef69261f77265e427f9d396).
- Cloud H0.2 merge
  [`5a090d1`](https://github.com/A3S-Lab/Cloud/commit/5a090d1cf87b2319bd99cffc0777f59e486430d8),
  including the final clean-host fix at
  [`d40effb`](https://github.com/A3S-Lab/Cloud/commit/d40effb73a0f0b23b4fe8856820cd9359e1c57c7).
- Gateway release-commit
  [CI run 31671953440](https://github.com/A3S-Lab/Gateway/actions/runs/31671953440)
  and Cloud H0.2
  [E0 clean-host run 30182939128](https://github.com/A3S-Lab/Cloud/actions/runs/30182939128)
  completed successfully.

The Cloud gate builds the exact Gateway target commit above rather than a
mock parser or acknowledgement. That commit is now part of the released
Gateway binary.

## Acceptance matrix

| Contract | Gateway evidence | Joint Cloud/Gateway evidence |
| --- | --- | --- |
| Host, path, multi-service, multi-target, TLS, HTTP, SSE, and WebSocket | `tests/managed_protocol_recovery.rs` runs the real Gateway binary and exercises the complete protocol matrix. | The clean-host and pinned-Gateway gates publish and serve the Cloud-compiled route over real TLS. |
| Bounded untrusted snapshot validation | `src/managed_snapshot.rs`, parser regressions, and real Node API tests reject malformed, stale, conflicting, expired, or digest-tampered input without replacing live state. | Cloud rejects incomplete, ambiguous, mixed-revision, mixed-port, and unknown management-protocol projections before activation. |
| Atomic validate/install/reload | `tests/managed_snapshot.rs` and `tests/managed_listener_reload.rs` prove prior-route and prior-certificate retention across parse, bind, reload, and journal failures. | A Route becomes active only after exact per-member acknowledgement satisfies the Cloud rollout policy. |
| Exact revision and digest acknowledgement | Gateway readiness requires the exact Gateway ID, positive revision, and canonical snapshot digest; replay is idempotent and a conflicting digest fails closed. | Agent death after native apply but before Cloud acknowledgement is recovered by exact command redelivery without another Gateway apply. |
| Certificate lifecycle | Gateway atomically installs supplied TLS material, retains the last valid certificate on failure, exposes applied expiry, and reports actionable rejection reasons. | Cloud owns issuance, renewal, revocation, expiry, and convergence status. Its H0.2 gate proves same-policy renewal, independent certificate replacement, superseded-CA rejection, and retryable failure state. |
| Restart, replay, and replica independence | `tests/managed_protocol_recovery.rs` and `tests/managed_replica_readiness.rs` prove durable restart recovery, exact replay, revision skew, rejected-successor retention, and independent readiness. | Two real Gateways keep independent native journals, continue serving through peer loss, and converge without one replica acknowledging another replica's state. |
| Generation-bound replacement | Managed targets bind the Cloud target ID, Runtime Unit, and positive generation into an opaque stable backend identity. | The pinned-Gateway fixture replaces certificate and target generation, removes superseded material, and recovers only the replacement after restart. |
| Version compatibility | Legacy snapshots without optional target identity remain valid for rolling replacement; unknown or inconsistent managed fields fail closed. | Cloud selects the advertised management protocol and request/status schemas, accepts only the closed legacy fallback, and rejects unsupported tuples before mutation. |

## Ownership boundary after E0

E0 and managed target delivery `H0.2` are complete. This does not promote the
whole managed product to Enterprise GA. Independently placed multi-node
topology, node-loss and rolling-replacement operations remain `H0.3`; control
plane and Gateway high availability remain `H0.4`; managed inference policy
and usage delivery remain `I0.2b` and `I0.2c`.

Gateway deliberately does not become a certificate authority, scheduler,
tenant store, rollout controller, or long-term usage ledger. Those states stay
with A3S Cloud; Gateway's machine Node API reports only local health and exact
applied snapshot evidence.
