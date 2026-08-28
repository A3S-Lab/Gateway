# Distributed inference routing

Status: Gateway and Power data-plane implementation. Gateway can schedule an
aggregated Power worker or orchestrate a distinct prefill/decode pair. Cloud
publication, mixed-version qualification, and engine-specific state-transfer
evidence remain open.

## Ownership and bounded contexts

Distributed inference is an interaction between existing bounded contexts,
not a fourth service:

| Component | Owns | Does not own |
| --- | --- | --- |
| A3S Cloud | Desired replicas and placement; exact target, Runtime unit, and generation identity; collection and certification of expiring Power observations; immutable snapshot publication | Per-request routing, prompt data, and model execution |
| A3S Gateway | Credential and grant enforcement; model-pool admission; target policy; worker-pair selection; scoped cache affinity; pre-response fallback; Power protocol orchestration; OpenAI response translation | Desired replicas, placement, KV bytes, and backend execution admission |
| A3S Power | Model execution; local admission; phase readiness; prompt-cache state; worker epoch and execution profile; state-transfer target/source production and consumption | Fleet placement, client authorization, and public traffic policy |

There is no separate llm-d-style A3S subproject. A separate service would add
a second discovery and scheduling authority without an independent business
invariant or lifecycle. Cloud remains the control plane, Gateway remains the
request and orchestration plane, and Power remains the execution plane.

## Snapshot contract

Cloud publishes workers in the same immutable Gateway policy that binds every
service endpoint to `target_id`, `unit_id`, and `generation`. Gateway accepts
only `a3s.power.worker-observation.v1` observations. A distributed worker also
has a Power boot epoch and the lowercase SHA-256 digest of its immutable
execution profile.

The abbreviated ACL shape is:

```acl
services "model-service" {
  load_balancer {
    servers {
      url = "https://power-prefill.internal:8443"
      target {
        target_id = "66666666-6666-4666-8666-666666666666"
        unit_id = "power-prefill-1"
        generation = 5
      }
    }
    servers {
      url = "https://power-decode.internal:8443"
      target {
        target_id = "66666666-6666-4666-8666-666666666666"
        unit_id = "power-decode-1"
        generation = 5
      }
    }
  }
}

inference {
  expires_at = "<policy RFC3339 expiry>"

  workers "power-prefill-1" {
    target_id = "66666666-6666-4666-8666-666666666666"
    generation = 5
    schema = "a3s.power.worker-observation.v1"
    worker_epoch = "77777777-7777-4777-8777-777777777777"
    execution_profile_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    observation_generation = 9
    observed_at = "<fresh RFC3339 observation time>"
    expires_at = "<RFC3339 time no more than 300 seconds later>"
    phases = ["prefill"]
    prompt_cache_capable = true
    state_transfer_capable = true
    ready_phases = ["prefill"]
    active_limit = 8
    active = 1
    waiting = 0
    prompt_cache_supported = true
    prompt_cache_entries = 2
    prompt_cache_capacity = 8
    prompt_cache_pressure_basis_points = 2500
    transfer_health = "ready"
  }

  workers "power-decode-1" {
    target_id = "66666666-6666-4666-8666-666666666666"
    generation = 5
    schema = "a3s.power.worker-observation.v1"
    worker_epoch = "88888888-8888-4888-8888-888888888888"
    execution_profile_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    observation_generation = 12
    observed_at = "<fresh RFC3339 observation time>"
    expires_at = "<RFC3339 time no more than 300 seconds later>"
    phases = ["decode"]
    prompt_cache_capable = false
    state_transfer_capable = true
    ready_phases = ["decode"]
    active_limit = 8
    active = 2
    waiting = 0
    prompt_cache_supported = false
    prompt_cache_entries = 0
    prompt_cache_capacity = 0
    prompt_cache_pressure_basis_points = 0
    transfer_health = "ready"
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
        phase = "decode"
        max_concurrent_requests = 32
        max_queued_requests = 64
        queue_timeout_ms = 500
        prompt_cache_affinity = true
        distributed_serving {
          api_key_env = "A3S_POWER_DISTRIBUTED_API_KEY"
          execution_timeout_ms = 30000
        }
      }
    }

    # Credentials and grants use the existing managed-inference contract.
  }
}
```

`api_key_env` names a process environment variable; the secret itself is not
accepted in ACL or a Cloud snapshot. Gateway resolves every distinct name when
building a runtime snapshot and rejects activation if a credential is missing
or unsafe. Distributed models can be granted models, chat-completions, and
completions endpoints, but not embeddings.

The observation is a complete, short-lived projection rather than a patch.
Gateway rejects inconsistent identity, freshness, phases, profile hashes,
admission counters, cache pressure, transfer capability, or latency. Scheduled
services must contain one explicit managed backend set; revisions, sticky
sessions, and generic service failover are rejected because they would create
a second worker-selection path.

## Request and orchestration path

1. Gateway authenticates the inference credential, checks the endpoint/model
   grant, validates the bounded OpenAI JSON body, and rewrites only the model
   and scoped prompt-cache key.
2. A fair Tokio semaphore admits at most `max_concurrent_requests`. At most
   `max_queued_requests` wait until `queue_timeout_ms`; cancellation releases
   queue capacity immediately.
3. Existing target priority and weight select one Cloud-defined target.
4. Gateway filters exact-generation workers that are unhealthy, stale, not
   ready for the required role, at their active limit, unable to transfer
   state, or missing an execution-profile binding.
5. Gateway selects a decode worker and a distinct prefill worker. Decode uses
   load and deterministic rendezvous ranking. Only prefill may apply scoped
   prompt-cache affinity inside the bounded load band.
6. Gateway calls Power's authenticated internal protocol in this exact order:
   `decode/prepare`, `prefill/execute`, then `decode/execute`. The target and
   source values are opaque JSON capabilities; Gateway relays them but never
   interprets, stores, or logs them.
7. Every response must match the attempt ID, Power worker epoch, and execution
   profile digest selected from the snapshot. Gateway validates incremental
   NDJSON event order and converts it to buffered OpenAI JSON or OpenAI SSE.
   Power protocol frames never reach the client.
8. A retryable failure before downstream response headers excludes both worker
   units and selects another pair in the same exact target. Only after that
   worker set is exhausted may normal target-priority fallback advance. No
   fallback occurs after an SSE response starts.
9. Gateway sends bounded abort cleanup to both workers on success, failure, or
   downstream cancellation. Grant, pool, and exact-generation drain guards
   remain held through the downstream response lifetime.

Aggregated scheduling remains available with `phase = "aggregated"` and no
`distributed_serving` block.

## Protocol and resource bounds

- internal requests: at most 8 MiB;
- phase JSON responses: at most 256 KiB;
- NDJSON frame line: at most 1 MiB;
- pre-response decode stream: at most 1 MiB before `ready`;
- buffered decoded stream: at most 16 MiB;
- end-to-end execution deadline: 1 to 300,000 ms;
- cleanup deadline: two seconds, independent of the execution deadline;
- redirects: disabled; endpoints must be HTTP(S) URLs without userinfo;
- bearer credentials: non-empty visible ASCII, at most 4 KiB.

Power's protocol schemas are
`a3s.power.distributed-serving.v1` and
`a3s.power.distributed-serving-stream.v1`. Gateway accepts only the exact
contract and treats unknown fields, status/decision mismatches, binding drift,
out-of-order events, and premature stream termination as failures.

## Cache-affinity privacy

Gateway accepts `prompt_cache_key` only as a non-empty bounded identifier
without surrounding whitespace or control characters. The raw value is never
forwarded. Gateway hashes it with credential ID, model ID, and endpoint under a
versioned domain and forwards only an opaque `a3s-gw-pcache-v1:` value. This
prevents affinity crossing tenants, models, or endpoint classes and does not
require Gateway to retain prompts or prefixes.

## Remaining boundary

- Cloud must publish the new profile-bound worker fields and distributed
  scheduling block through its production snapshot compiler.
- Gateway, Cloud, and Power still need mixed-version, node-loss, stale-epoch,
  profile-rollover, and multi-replica conformance evidence.
- Engine-specific KV transfer adapters and performance evidence must prove that
  Power's opaque target/source handles remain bounded, authenticated, and
  usable across the intended topology.
- Certified latency remains optional and Cloud-owned; Gateway does not perform
  unbounded active probes or alter desired replicas and placement.
