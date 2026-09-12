# First-principles Gateway test plan

This plan lists **invariants** Gateway must prove locally. Tests exist to
falsify the invariant, not to mirror a particular Cloud fixture or CI job.
Do not add assertions that encode incidental timings, hostnames, or Cloud
ledger shapes unless those are frozen contracts in-repo.

## Product boundary

| Must hold | Must never hold |
| --- | --- |
| Fail closed on invalid/expired/revoked policy | Soft-open on parse errors |
| Atomic snapshot activation with prior runtime retained | Partial apply of a managed snapshot |
| Prompt-free usage lifecycle bytes only | Prompt text in spool or ingest |
| Gateway owns request routing and local admission | Gateway owns Cloud placement/replicas |
| Provisional tokenizer is revisioned and deterministic | Tokenizer pretends to be billing-grade |
| Dual-track I0: scheduled models require Power worker observations | Claiming scheduled inference available from an empty worker map |

## Dual-track `I0` — empty workers fail closed

1. **No observation, no schedule** — a model with `scheduling` and managed
   endpoint identity but an empty `workers` map fails validation with
   `no worker observation`.
2. **No endpoints, no schedule** — a scheduled model whose service has zero
   servers fails validation with `no configured workers`.
3. **Empty-worker successor retention** — a ready scheduled snapshot is not
   replaced by a later revision that drops worker observations; apply returns
   rejected while the prior identity stays ready.
4. **Expired observations at request time** — after a ready scheduled runtime
   is live, if every Power observation expires, chat completions fail closed
   with `authorization_unavailable` and never contact upstream.
5. **Schema id lock** — `POWER_WORKER_OBSERVATION_SCHEMA` equals Power's
   `WORKER_OBSERVATION_SCHEMA` (`a3s.power.worker-observation.v1`).
6. **Nested→flat projection lock** — Power's nested `WorkerObservation` JSON
   (capabilities/admission/prompt_cache) projects into Gateway's flat
   `InferenceWorkerConfig` ACL fields; the projected worker validates and is
   selectable. Cloud still owns production delivery.
7. **Cloud worker ACL render-shape lock** — Cloud's aggregated worker block
   attribute order (including RFC3339 micros timestamps and optional
   `certified_latency_ms`) is accepted by Gateway managed ACL parse/validate.
8. **Tokenizer revision lock** — Gateway `INFERENCE_TOKENIZER_REVISION` equals
   Cloud `INFERENCE_TOKENIZER_REVISION_V1` (`a3s.gateway.tokenizer.v1`).

Evidence: `src/config/inference/tests.rs`
(`scheduled_models_fail_closed_when_worker_observations_are_absent`,
`scheduled_models_fail_closed_when_service_has_no_configured_workers`),
`src/managed_snapshot/tests.rs`
(`empty_worker_successor_is_rejected_with_prior_scheduled_runtime_retained`),
`src/entrypoint/inference_scheduling_tests.rs`
(`expired_worker_observations_fail_closed_without_upstream_contact`),
`src/inference/power_observation_contract_tests.rs`,
`src/inference/power_observation_projection_tests.rs`
(`power_nested_observation_projects_into_gateway_flat_worker_and_schedules`),
`src/inference/cloud_worker_acl_render_contract_tests.rs`
(`cloud_rendered_aggregated_worker_acl_shape_is_accepted_by_gateway`),
`src/inference/tokenizer_revision_contract_tests.rs`.

Still **out of Gateway EXIT**: Cloud/Power `PW0` observation delivery that
fills the worker projection in a provisioned deployment. Cloud has landed the
typed batch + projection brick, node-control HTTP accept, durable Postgres
observation storage/projection, Fleet negotiation of the Power batch schema,
  a node-agent shipper, and a collector that binds live Power `/health` worker
  facts to Cloud-owned targets (skips when absent — no inventing). Local joint
evidence covers authenticated accept → worker ACL projection → managed
snapshot `workers` compile, and Cloud admission of RuntimeApply → collector
targets (`admit_power_worker_observation_target`). Node-agent durable
`PowerObservationTargetStore`, collector loop (empty store stays idle), and
Fleet `PowerWorkerObservationBind`/`Unbind` commands land (no inventing).
Fleet `FleetPowerWorkerObservationCommandService` admits healthy Power
RuntimeApply evidence into bind drafts when callers supply the Cloud-owned
binding. Power Service profile on Box, Workloads/Inference callers that hold
those bindings, and BX0+PW0 provisioned deployment remain open. Cloud now
also freezes `power_worker_observation_target_binding_from_compiled_spec`,
Inference bind-queue + empty binding store, and Workloads after-Ready
`IDeploymentPowerObservationBinder` (NotRequired when no Cloud-owned
binding is stored). Cloud also freezes `CloudPowerServiceProfileV1` and
Inference `PowerServiceProfileCompiler` (compile+attach). Power Service
profile deployment through Workloads/Box, and provisioned BX0+PW0 delivery,
remain EXIT-open.

## `I0.2b` — inference authorization

1. **Authenticate before body spend** — missing/malformed/wrong credentials fail
   without upstream contact.
2. **Grant surface** — ungranted endpoint/model pairs deny; `/v1/models` lists
   only granted models.
3. **Policy expiry** — expired at request start and after body collection both
   fail closed.
4. **Credential/revocation expiry** — revoked or expired credentials fail closed
   on the request path without contacting upstream.
5. **Credential-projection snapshot succession** — a later managed snapshot that
   revokes a projected key (and clears its grants) or rotates verifier+generation
   must atomically replace the prior ready identity; stale CAS / unknown
   `tokenizer_revision` successors reject while the prior runtime stays ready;
   post-succession requests with the prior bearer never contact upstream.
5b. **Grant/target succession without revoke** — a later managed snapshot may
   keep the same authenticatable credential while withdrawing grants or
   removing targets; the prior ready identity is replaced atomically; requests
   for withdrawn models never contact upstream; remaining fallback targets are
   the only dispatch surface after target-set succession.
6. **RPM / burst / concurrency** — admission returns stable errors with
   `Retry-After` where specified; permits are not leaked on cancel
   (including client abort before the upstream response starts, and SSE
   response drop after headers).
7. **`tokens_per_minute`** — reserve with `a3s.gateway.tokenizer.v1`, reconcile
   from observed OpenAI `usage` when present; never invent Cloud billing totals.
8. **Tokenizer revision ACL freeze** — managed `inference` blocks must declare
   `tokenizer_revision = "a3s.gateway.tokenizer.v1"`; missing or unknown
   revisions fail closed at parse (and again at validate for programmatic
   policy).
9. **Fallback** — weighted pick then priority fallback; zero-weight runtime
   state rejects without panic.
10. **Observed usage on spool** — when upstream JSON carries `usage.total_tokens`,
   the request-terminal lifecycle event records
   `measurement_completeness=upstream_usage` and that total without prompts or
   credentials.

Evidence: `src/inference/authorization_tests.rs`,
`src/entrypoint/inference_tests.rs` (including
`client_abort_before_upstream_response_releases_concurrency_permit` and
`openai_stream_field_selects_sse_without_an_accept_header`),
`src/entrypoint/inference_usage_tests.rs`,
`src/entrypoint/inference_fallback_tests.rs` (target-set succession under
fallback), `src/managed_snapshot/tests.rs` (credential successor / grant
successor / CAS / tokenizer rejection / empty-worker successor),
`src/inference/tokenizer.rs`,
`src/inference/token_reconcile.rs`, `src/inference/limits.rs`,
`src/config/inference/tests.rs`.

## `I0.2c` — usage delivery (Gateway-local)

1. **Batch schema freeze** — `a3s.gateway.usage-batch.v1` /
   `a3s.gateway.usage-batch-receipt.v1` stay aligned with Cloud contracts
   (`batch_id`, nested `cursor`, `payload_base64`, `payload_sha256`), including
   a monorepo `include_str` lock against
   `apps/cloud/crates/contracts/src/inference/usage.rs`.
2. **Integrity fail-closed** — tampered payload hash and receipt `batch_id`
   mismatch are rejected before any local watermark move.
3. **Contiguous spool order** — within one boot epoch, record sequences must be
   contiguous and the first record must immediately follow `after` when set;
   Cloud golden JSON for `a3s.gateway.usage-batch.v1` must decode and validate.
4. **Highest-contiguous ACK** — receipt may ACK a prefix of the submitted
   batch (or the batch `after`); never a cursor outside the batch; never a gap.
5. **Backlog drain** — after a prefix ACK, the next upload contains only the
   unacked suffix and carries `after` equal to the prior watermark.
6. **Transport failure** — failed submit does not advance the watermark; retry
   drains the same backlog.
7. **Idempotent restart** — after a full ACK, process restart uploads nothing.
8. **Crash after prefix ACK** — reopen the durable spool and finish the suffix.
9. **HTTP transport** — empty endpoint/token fail closed; non-OK status,
   malformed JSON, wrong schema, and unknown receipt fields fail closed before
   spool acknowledge.
10. **Empty receipt** — missing `acknowledged_through` advances nothing.
11. **Wrong-after tip contract** — Cloud/ledger doubles never advertise a tip
    outside the submitted batch; a fuller spool window that includes the tip
    recovers (uploader drains to the durable watermark).
12. **Lifecycle payload lock** — Gateway-encoded `a3s.gateway.usage-lifecycle.v1`
    events for all four kinds decode under Cloud's validation rules (schema id
    `include_str` lock, kebab-case endpoints, forbidden prompt/secret keys,
    terminal measurement completeness). Evidence:
    `src/usage/lifecycle_contract_tests.rs`.

Evidence: `src/usage/cloud_ingest.rs`, `src/usage/http_transport.rs`,
`src/usage/ledger_double.rs`, `src/usage/mtls_ingest_tests.rs`,
`src/usage/lifecycle.rs`, `src/usage/lifecycle_contract_tests.rs`,
`docs/usage-cloud-ingest.md`.

Cloud has shipped `POST /v1/inference-control/usage-batches` (Postgres ledger +
node-control mTLS; migrations `192`/`193`/`194` including request-fact and
daily-rollup projection). Gateway-local evidence includes mTLS recovery against a
Cloud-shaped TLS ledger. Cross-repository live HTTPS evidence lives in Cloud's
`enrolled_node_mtls_posts_usage_batches_over_live_node_control_https`. Still
**out of Gateway EXIT** until operators prove recovery against a provisioned
Cloud deployment with a real enrolled node identity; authorized showback HTTP
over rollups remains Cloud `I0.2e`.

## `I0.3` — distributed inference (Gateway-local)

1. **Aggregated worker dispatch** — schedule only from exact Cloud target
   generations and age-bounded Power observations; never invent placement.
2. **P/D pair orchestration** — select distinct compatible prefill/decode
   workers; bind attempt/epoch/profile; relay opaque handles only.
3. **Pre-response fallback** — retryable pre-response failure excludes the
   pair; started streams are never replayed.
4. **Rolling snapshot** — in-flight work can drain on a profile-less snapshot
   while new requests move atomically to a profile-bound P/D snapshot.
5. **Reject-and-fallback** — unsupported schema, stale epoch, and profile
   rollover exclude the exact pair before client response.
6. **Distributed-serving schema lock** — Gateway
   `DISTRIBUTED_SERVING_SCHEMA` / `DISTRIBUTED_SERVING_STREAM_SCHEMA` equal
   Power's constants (`gateway_and_power_share_distributed_serving_schema_ids`).

Evidence: `src/inference/scheduling*.rs`,
`src/inference/distributed_serving/`, `src/entrypoint/protocol/distributed_handler.rs`,
`docs/distributed-inference-routing.md`.

Still **out of Gateway scope**: Cloud publication, multi-replica cross-product
evidence, real engine state-transfer, and autoscaling (Gateway never changes
desired replicas).

## Data plane (regression bar)

Keep protocol, reload, drain, and managed-snapshot suites green locally
(`cargo test --lib` and focused `tests/*.rs` when touching those paths). Prefer
real listeners and fail-closed config checks over mocks that cannot reject.

### `H0.3` local note

Cloud `ManagedTargetConfig` backends own exact-generation admission. On runtime
replace, generations present in the previous snapshot but absent from the next
close admission (`retire_absent_managed_target_generations`). In-flight guards
retain the retired backend until the response finishes; new admits select only
the successor generation.

Evidence:
- `src/service/load_balancer/tests.rs`
  (`cloud_managed_target_backends_own_exact_generation_admission`,
  `retired_generation_stays_closed_while_successor_admits`)
- `tests/managed_target_generation_drain.rs`
  (`generation_bump_keeps_inflight_on_retired_target_while_new_requests_use_successor`,
  `generation_bump_preserves_inflight_sse_on_retired_target`)
- `tests/managed_replica_readiness.rs`
  (`replicated_gateways_skew_managed_target_generations_independently` —
  generation skew plus peer survival across advanced-replica node-loss and
  journal recovery)

Still **open for EXIT**: Cloud-orchestrated multi-replica rolling replacement,
node-loss, and mixed-version joint gates against a provisioned control plane.
Local independent journals + generation skew + peer traffic under local
node-loss are Gateway-proven.

## Explicit non-goals (reject overfit)

- Tuning assertions to current MicroVM latency noise.
- Special-casing emoji/billing tokenizers beyond the frozen v1 rules.
- Claiming `VIA_BOX` / Cloud EXIT / LOOP from Gateway unit tests.
- Using CI status as proof of an invariant (run the local command that owns it).
