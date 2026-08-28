# Distributed inference routing

Status: Gateway and Power foundation. This revision schedules complete requests
across aggregated Power workers. Prefill/decode disaggregation and KV-state
transfer are not enabled.

## Ownership

Distributed inference is an interaction between existing bounded contexts, not
a new control plane:

| Component | Owns | Does not own |
| --- | --- | --- |
| A3S Cloud | Desired replicas and placement; exact target, Runtime unit, and generation identity; collection and certification of expiring Power observations; snapshot publication | Per-request routing and model execution |
| A3S Gateway | Credential and grant enforcement; model-pool admission; target policy; worker filter/score/pick; scoped cache affinity; pre-response retry; bounded scheduling evidence | Desired replicas, placement, prompt storage, KV bytes, and backend execution admission |
| A3S Power | Model execution; local admission; phase readiness; prompt-cache state; worker epoch and observation generation; future typed state transfer | Fleet placement and client traffic policy |

There is no separate llm-d-style A3S subproject. A separate service would add a
second discovery and scheduling authority without introducing an independent
business invariant or lifecycle. Cloud remains the sole control plane, Gateway
remains the request scheduler, and Power remains the execution plane.

## Snapshot contract

Cloud publishes the worker projection as part of the same immutable Gateway
policy that binds a service backend to `target_id`, `unit_id`, and `generation`.
Gateway accepts only the Power schema
`a3s.power.worker-observation.v1`.

The relevant ACL shape is:

```acl
services "model-service" {
  load_balancer {
    servers {
      url = "http://127.0.0.1:8000"
      target {
        target_id = "66666666-6666-4666-8666-666666666666"
        unit_id = "power-unit-1"
        generation = 5
      }
    }
  }
}

inference {
  expires_at = "<policy RFC3339 expiry>"

  workers "power-unit-1" {
    target_id = "66666666-6666-4666-8666-666666666666"
    generation = 5
    schema = "a3s.power.worker-observation.v1"
    worker_epoch = "77777777-7777-4777-8777-777777777777"
    observation_generation = 9
    observed_at = "<fresh RFC3339 observation time>"
    expires_at = "<RFC3339 time no more than 300 seconds later>"
    phases = ["aggregated"]
    prompt_cache_capable = true
    state_transfer_capable = false
    ready_phases = ["aggregated"]
    active_limit = 8
    active = 2
    waiting = 1
    prompt_cache_supported = true
    prompt_cache_entries = 2
    prompt_cache_capacity = 8
    prompt_cache_pressure_basis_points = 2500
    transfer_health = "unsupported"
    certified_latency_ms = 42
  }

  routes "44444444-4444-4444-8444-444444444444" {
    router = "inference"
    environment_id = "22222222-2222-4222-8222-222222222222"
    policy_revision = 11

    models "chat-model" {
      model_id = "55555555-5555-4555-8555-555555555555"
      targets "66666666-6666-4666-8666-666666666666" {
        service = "model-service"
        upstream_model = "internal/model-v1"
        priority = 0
        weight = 100
      }
      scheduling {
        phase = "aggregated"
        max_concurrent_requests = 32
        max_queued_requests = 64
        queue_timeout_ms = 500
        prompt_cache_affinity = true
      }
    }

    # credentials and grants use the existing managed-inference contract
  }
}
```

The observation is a complete, short-lived projection rather than a patch.
Gateway rejects the snapshot if identity binding, freshness, phases, admission
counters, cache pressure, transfer capability, or certified latency is
inconsistent. Scheduled services must contain only explicit managed endpoints;
service revisions, sticky sessions, and generic failover are rejected because
they would create a second selection path.

## Request path

1. Gateway authenticates the inference credential and checks the model grant.
2. A fair Tokio semaphore admits at most `max_concurrent_requests`. At most
   `max_queued_requests` wait until `queue_timeout_ms`; cancellation releases
   queue capacity immediately. Pool state survives compatible snapshot refresh.
3. Existing target priority and weight select a Cloud-defined target group.
4. Gateway filters workers that are unhealthy, incorrectly bound, expired, not
   ready for the requested phase, or at their Power-reported active limit.
5. The remaining workers are ordered by admission pressure, waiting requests,
   Gateway-local connections, prompt-cache pressure, and optional
   Cloud-certified latency. Deterministic rendezvous hashing breaks exact ties.
6. If prompt-cache affinity is enabled, a cache-capable worker may be selected
   within a 1,000-basis-point admission-pressure band and one waiting request of
   the least-loaded candidate.
7. A transport failure before an upstream response retries another worker in
   the same exact target and generation. Only after that worker set is exhausted
   does the existing higher-priority fallback path advance.
8. Both the grant and pool permits remain held until the response body or stream
   reaches its terminal boundary.

A full waiting room returns HTTP `429` with `pool_queue_full`. A queue deadline
returns HTTP `429` with `pool_queue_timeout`. No queue or worker-selection
failure changes Cloud's desired replica count.

## Cache-affinity privacy

Gateway accepts an optional OpenAI `prompt_cache_key` only when it is a non-empty
bounded identifier without surrounding whitespace or control characters. The
raw value is never forwarded. Gateway hashes it with the credential ID, model
ID, and endpoint under a versioned domain and forwards only an opaque
`a3s-gw-pcache-v1:` key. This prevents affinity from crossing tenants, models,
or endpoint classes and does not require Gateway to store prompts or prefixes.

## Current boundary

- Only `phase = "aggregated"` is accepted.
- Gateway does not read, store, validate, or transfer KV state.
- Power currently reports state transfer as unsupported.
- Prefill/decode selection remains closed until Power exposes a typed transfer
  contract and Cloud can prove one compatible deployment generation.
- Certified latency is optional and must come from Cloud; Gateway does not make
  unbounded active probes.
- Worker observations expire at request time, so a stale snapshot fails closed
  even if it was valid when activated.
