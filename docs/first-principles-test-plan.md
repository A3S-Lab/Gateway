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
   rejected while the prior identity stays ready, and the live listener keeps
   routing to the prior scheduled upstream.
3b. **Stale-worker successor retention** — a ready scheduled snapshot is not
   replaced by a later revision whose workers already fail the freshness
   window; apply returns rejected (`freshness`) while the prior identity stays
   ready, and the live listener keeps routing to the prior scheduled upstream.
4. **Expired observations at request time** — after a ready scheduled runtime
   is live, if every Power observation expires, chat completions fail closed
   with `authorization_unavailable` and never contact upstream.
5. **Schema id lock** — `POWER_WORKER_OBSERVATION_SCHEMA` equals Power's
   `WORKER_OBSERVATION_SCHEMA` (`a3s.power.worker-observation.v1`), locked via
   `tests/fixtures/contracts/power_worker_observation.rs`.
6. **Nested→flat projection lock** — Power's nested `WorkerObservation` JSON
   (capabilities/admission/prompt_cache) projects into Gateway's flat
   `InferenceWorkerConfig` ACL fields; the projected worker validates and is
   selectable. Cloud still owns production delivery.
7. **Cloud worker ACL render-shape lock** — Cloud's aggregated worker block
   attribute order (including RFC3339 micros timestamps and optional
   `certified_latency_ms`) is accepted by Gateway managed ACL parse/validate.
8. **Tokenizer revision lock** — Gateway `INFERENCE_TOKENIZER_REVISION` equals
   Cloud `INFERENCE_TOKENIZER_REVISION_V1` (`a3s.gateway.tokenizer.v1`), locked
   via `tests/fixtures/contracts/cloud_tokenizer_revision.rs`.
9. **Shared aggregated target aliases** — chat and embeddings (or other aliases)
   may share one managed `target_id` / Power `unit_id`; one observation still
   cannot bind two distinct target IDs.

Evidence: `src/config/inference/tests.rs`
(`scheduled_models_fail_closed_when_worker_observations_are_absent`,
`scheduled_models_fail_closed_when_service_has_no_configured_workers`,
`permits_shared_aggregated_target_across_model_aliases`),
`src/managed_snapshot/tests.rs`
(`empty_worker_successor_is_rejected_with_prior_scheduled_runtime_retained`,
`stale_worker_successor_is_rejected_with_prior_scheduled_runtime_retained`),
`src/entrypoint/inference_scheduling_tests.rs`
(`managed_snapshot_apply_empty_worker_successor_retains_prior_scheduled_routing_on_listener`,
`managed_snapshot_apply_stale_worker_successor_retains_prior_scheduled_routing_on_listener`,
`expired_worker_observations_fail_closed_without_upstream_contact`),
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
   Live-listener evidence via `ManagedSnapshotStore::apply` + reload:
   `entrypoint::inference_tests::managed_snapshot_apply_credential_successor_revokes_prior_key_without_upstream`
   (revoke) and
   `managed_snapshot_apply_credential_generation_bump_invalidates_prior_bearer_without_upstream`
   (verifier+generation rotate; new bearer admitted).
   Live-listener reject-and-retain evidence:
   `managed_snapshot_apply_unknown_tokenizer_successor_retains_prior_routing_on_listener`
   (unknown `tokenizer_revision`; prior routing retained) and
   `managed_snapshot_apply_stale_cas_successor_retains_prior_routing_on_listener`
   (stale `expected_revision` CAS `409`; prior routing retained even when the
   rejected ACL would revoke the live credential). Companions: store-only
   `managed_snapshot::tests::credential_successor_snapshot_revokes_prior_key_atomically`,
   `unknown_tokenizer_revision_successor_is_rejected_with_prior_runtime_retained`,
   and `expected_revision_cas_rejects_stale_credential_bearing_successor`;
   `runtime.replace` shortcuts
   `credential_successor_runtime_revokes_prior_key_without_upstream` and
   `credential_generation_bump_invalidates_prior_authenticated_generation`.
5b. **Grant/target succession without revoke** — a later managed snapshot may
   keep the same authenticatable credential while withdrawing grants or
   removing targets; the prior ready identity is replaced atomically; requests
   for withdrawn models never contact upstream; remaining fallback targets are
   the only dispatch surface after target-set succession. Live-listener evidence
   via `ManagedSnapshotStore::apply` + reload:
   `entrypoint::inference_tests::managed_snapshot_apply_grant_successor_denies_withdrawn_model_without_upstream`
   (grant withdraw) and
   `entrypoint::inference_fallback_tests::managed_snapshot_apply_target_successor_routes_only_to_remaining_fallback_without_primary`
   (target-set withdraw). Companions: store-only
   `managed_snapshot::tests::grant_successor_snapshot_clears_grants_without_revoking_credential`
   and `target_successor_snapshot_withdraws_primary_with_fallback_retained`;
   `runtime.replace` shortcuts
   `grant_successor_runtime_denies_prior_model_without_upstream` and
   `target_successor_runtime_routes_only_to_remaining_fallback_without_primary`.
6. **RPM / burst / concurrency** — admission returns stable errors with
   `Retry-After` where specified; permits are not leaked on cancel
   (including client abort before the upstream response starts, and SSE
   response drop after headers). Evidence:
   `client_abort_before_upstream_response_releases_concurrency_permit` and
   `managed_sse_client_drop_after_headers_releases_concurrency_permit`
   (aggregated path; P/D sibling
   `managed_distributed_sse_client_cancel_aborts_both_workers_and_releases_concurrency`).
   Model-pool scheduling likewise fails closed:
   `pool_queue_full` when the bounded wait queue is disabled,
   `pool_queue_timeout` when `queue_timeout_ms` elapses while the active slot
   is held, queue capacity is released when a waiting client aborts, and a
   mid-stream SSE abort releases the scheduling active slot
   (`managed_inference_pool_rejects_when_its_bounded_queue_is_disabled`,
   `managed_inference_pool_rejects_when_queue_deadline_elapses`,
   `managed_inference_pool_releases_queue_slot_when_waiting_client_aborts`,
   `managed_inference_pool_releases_active_slot_when_streaming_client_aborts`).
7. **`tokens_per_minute`** — reserve with `a3s.gateway.tokenizer.v1`, reconcile
   from observed OpenAI `usage` when present (JSON and completed SSE,
   including after bodies larger than the JSON prefix observe budget for both
   surfaces); never invent Cloud billing totals. Evidence includes
   `managed_json_upstream_usage_reconciles_token_budget_for_follow_up_request`,
   `managed_json_persists_upstream_usage_after_body_exceeds_json_prefix_budget`,
   `managed_json_without_usage_keeps_provisional_token_reservation_charged`,
   `managed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request`,
   and the complementary
   `managed_sse_without_usage_keeps_provisional_token_reservation_charged`
   (JSON without usage is no longer only implied by
   `managed_inference_enforces_tokens_per_minute_reservation`).
8. **Tokenizer revision ACL freeze** — managed `inference` blocks must declare
   `tokenizer_revision = "a3s.gateway.tokenizer.v1"`; missing or unknown
   revisions fail closed at parse (and again at validate for programmatic
   policy).
9. **Fallback** — weighted pick then priority fallback; zero-weight runtime
   state rejects without panic.
10. **Observed usage on spool** — when upstream JSON or a completed SSE stream
   carries `usage.total_tokens` (including usage on the **last** SSE event or
   trailing JSON `usage` object after a body larger than the JSON prefix
   observe budget), the request-terminal lifecycle event records
   `measurement_completeness=upstream_usage` and that total without prompts or
   credentials.

Evidence: `src/inference/authorization_tests.rs`,
`src/entrypoint/inference_tests.rs` (including
`client_abort_before_upstream_response_releases_concurrency_permit`,
`managed_sse_client_drop_after_headers_releases_concurrency_permit`, and
`openai_stream_field_selects_sse_without_an_accept_header`),
`src/entrypoint/inference_scheduling_tests.rs` (including
`managed_inference_pool_rejects_when_its_bounded_queue_is_disabled`,
`managed_inference_pool_rejects_when_queue_deadline_elapses`,
`managed_inference_pool_releases_queue_slot_when_waiting_client_aborts`, and
`managed_inference_pool_releases_active_slot_when_streaming_client_aborts`),
`src/entrypoint/inference_usage_tests.rs` (including
`managed_inference_persists_upstream_usage_on_request_terminal`,
`managed_sse_persists_upstream_usage_on_request_terminal`,
`managed_sse_persists_upstream_usage_after_body_exceeds_json_prefix_budget`,
`managed_json_upstream_usage_reconciles_token_budget_for_follow_up_request`,
`managed_json_persists_upstream_usage_after_body_exceeds_json_prefix_budget`,
`managed_json_without_usage_keeps_provisional_token_reservation_charged`,
`managed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request`, and
`managed_sse_without_usage_keeps_provisional_token_reservation_charged`),
`src/entrypoint/inference_fallback_tests.rs` (target-set succession under
fallback), `src/entrypoint/inference_scheduling_tests.rs` (empty-worker
successor retention on the live listener), `src/managed_snapshot/tests.rs`
(credential successor / grant successor / target-set successor / CAS /
tokenizer rejection / empty-worker successor / stale-worker successor),
`src/inference/tokenizer.rs`,
`src/inference/token_reconcile.rs`, `src/inference/limits.rs`,
`src/config/inference/tests.rs`.

## `I0.2c` — usage delivery (Gateway-local)

1. **Batch schema freeze** — `a3s.gateway.usage-batch.v1` /
   `a3s.gateway.usage-batch-receipt.v1` stay aligned with Cloud contracts
   (`batch_id`, nested `cursor`, `payload_base64`, `payload_sha256`), including
   an `include_str` lock against the Cloud contract source vendored at
   `tests/fixtures/contracts/cloud_usage.rs` (standalone Gateway CI must not
   require the monorepo Cloud checkout).
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
    `include_str` lock against `tests/fixtures/contracts/cloud_lifecycle.rs`,
    kebab-case endpoints, forbidden prompt/secret keys, terminal measurement
    completeness). Evidence: `src/usage/lifecycle_contract_tests.rs`.

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
4. **Rolling snapshot** — in-flight work can drain on the prior snapshot while
   new requests move atomically to the successor. Evidence:
   `rolling_snapshot_moves_new_requests_to_distributed_workers_without_rebinding_inflight_v1`
   (aggregated buffered JSON → P/D),
   `rolling_snapshot_drains_inflight_aggregated_sse_while_new_requests_use_pd_snapshot`
   (aggregated OpenAI SSE → P/D),
   `rolling_snapshot_drains_inflight_pd_sse_while_new_requests_use_successor_pd_snapshot`
   (profile-bound P/D SSE → successor P/D), and
   `rolling_snapshot_drains_inflight_pd_json_while_new_requests_use_successor_pd_snapshot`
   (profile-bound P/D buffered JSON → successor P/D).
5. **Reject-and-fallback** — unsupported schema, stale epoch, and profile
   rollover exclude the exact pair before client response.
6. **Distributed-serving schema lock** — Gateway
   `DISTRIBUTED_SERVING_SCHEMA` / `DISTRIBUTED_SERVING_STREAM_SCHEMA` equal
   Power's constants (`gateway_and_power_share_distributed_serving_schema_ids`).
7. **Observed usage on P/D OpenAI surfaces** — buffered JSON includes Power-
   derived `usage`; streaming emits a terminal OpenAI `usage` SSE chunk before
   `[DONE]` so I0.2b spool metering and `tokens_per_minute` reconcile apply on
   both surfaces; streaming and buffered JSON without Power tokens omit `usage`
   and keep the provisional reservation charged. Evidence:
   `managed_distributed_json_persists_upstream_usage_on_request_terminal`,
   `managed_distributed_sse_persists_upstream_usage_on_request_terminal`,
   `managed_distributed_json_upstream_usage_reconciles_token_budget_for_follow_up_request`,
   `managed_distributed_sse_upstream_usage_reconciles_token_budget_for_follow_up_request`,
   `managed_distributed_sse_without_usage_keeps_provisional_token_reservation_charged`,
   `managed_distributed_json_without_usage_keeps_provisional_token_reservation_charged`,
   `buffered_translation_omits_usage_when_power_reports_no_tokens`,
   and `streaming_translation_emits_openai_sse_and_rejects_endpoint_confusion`.
8. **Client cancel mid-stream** — dropping the downstream SSE body after headers
   aborts both Power workers and releases grant concurrency without waiting for
   upstream completion; usage spool records `disconnected` terminals. Evidence:
   `managed_distributed_sse_client_cancel_aborts_both_workers_and_releases_concurrency`,
   `managed_distributed_sse_client_cancel_persists_terminal_disconnect_outcomes`.
9. **Stream idle timeout mid-stream** — after response headers, P/D SSE applies
   the same `stream_idle_timeout` / `stream_total_timeout` bounds as aggregated
   HTTP proxy bodies; idle silence fails closed, aborts both Power workers,
   releases grant concurrency, and persists usage-spool `failed` terminals.
   Evidence:
   `managed_distributed_sse_idle_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`
   (P/D) and
   `managed_sse_idle_timeout_releases_admission_and_persists_failed_terminals`
   (aggregated).
10. **Stream total timeout on an active stream** — after headers, Power may keep
    dripping chunks often enough that idle never fires; `stream_total_timeout`
    (from request start) still fails closed with dual abort, grant concurrency
    release, and usage-spool `failed` terminals. Evidence:
    `managed_distributed_sse_total_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`
    (P/D) and
    `managed_sse_total_timeout_releases_admission_and_persists_failed_terminals`
    (aggregated dripping upstream).
11. **Execution timeout before headers** — hung Power `decode/prepare` (or later
    pre-response phase) past `distributed_serving.execution_timeout_ms` returns
    `504` / `distributed_inference_timeout` without starting SSE, aborts both
    workers, releases grant concurrency, and persists usage-spool `failed`
    terminals. Evidence:
    `managed_distributed_execution_timeout_aborts_both_workers_releases_admission_and_persists_failed_terminals`.

Evidence: `src/inference/scheduling*.rs`,
`src/inference/distributed_serving/`, `src/entrypoint/protocol/distributed_handler.rs`,
`src/entrypoint/inference_distributed_tests.rs`,
`docs/distributed-inference-routing.md`.

Still **out of Gateway scope**: Cloud publication, multi-replica cross-product
evidence, real engine state-transfer, and autoscaling (Gateway never changes
desired replicas).

## Data plane (regression bar)

Keep protocol, reload, drain, and managed-snapshot suites green locally
(`cargo test --lib` and focused `tests/*.rs` when touching those paths). Prefer
real listeners and fail-closed config checks over mocks that cannot reject.

Managed Runtime Service `drain_managed_service` hides the exact generation then
waits on `BackendConnectionGuard` release. Evidence:
`managed_service::tests::lifecycle::drain_hides_then_waits_for_the_exact_admitted_stream`
(HTTP response body),
`managed_service::tests::lifecycle::drain_hides_then_waits_for_the_exact_admitted_sse_stream`
(SSE / `Accept: text/event-stream` via `handle_sse_dispatch`),
`managed_service::tests::lifecycle::drain_hides_then_waits_for_the_exact_admitted_websocket`
(WebSocket relay after upgrade), and
`managed_service::tests::lifecycle::drain_hides_then_waits_for_the_exact_admitted_grpc_stream`
(gRPC response body on the live private entrypoint). Process restart while
`Draining` keeps the route hidden and the original drain key replayable
(`restart_preserves_draining_route_for_exact_drain_replay`).
`Gateway::with_managed_service_state` probes an existing state file at construct
(JSON/schema/permissions/record consistency) and exclusive owner-lock
contention (try-lock + drop), so corrupt, inconsistent, or already-owned state
fails before `start`
(`corrupt_managed_service_state_fails_gateway_construct_closed`,
`retiring_state_without_the_exact_drain_key_fails_construct_closed`,
`one_gateway_exclusively_owns_the_managed_service_state`,
`with_managed_service_state_fails_construct_when_owner_lock_held`).
Construct also validates overlay composition against the base ACL, so a Ready
binding whose entrypoint was removed or that conflicts with a maximum-priority
base router fails before `start`
(`ready_binding_missing_entrypoint_fails_gateway_construct_closed`,
`ready_binding_max_priority_base_router_fails_gateway_construct_closed`).
Construct probe shares `validate_runtime_activation` with start/reload so
composed Ready overlays that carry host-owned generation targets remain
activate-aligned in standalone
(`ready_binding_with_targets_starts_gateway_closed_aligned`). Raw operator ACL
cannot claim reserved Managed Service middleware or service name prefixes
(`validate_activation_rejects_reserved_managed_service_middleware_name`,
`validate_activation_rejects_reserved_managed_service_name_prefix`).
On non-Unix platforms, Docker Unix socket hosts (including the default from an
empty `docker {}` block) fail at validate instead of soft-opening a never-
working provider
(`validate_rejects_docker_unix_socket_host_on_non_unix`,
`validate_accepts_docker_tcp_host_on_non_unix`,
`default_docker_block_fails_validate_on_windows`).
`providers.docker` also probes Docker `/_ping` at `validate_activation` and
cold start (same transport as the poll loop) so a present socket path or
parseable TCP URL cannot soft-open a forever-warn poller
(`validate_activation_fails_closed_when_docker_daemon_unreachable`,
`validate_activation_probes_reachable_docker_daemon`,
`test_gateway_start_tracks_docker_provider_handles`).
Fail-closed `rate-limit-redis` middlewares probe the same multiplexed Redis
connect + `PING` at `validate_activation` as the first rate-limit request, so a
present `redis_url` cannot soft-open Running and only 503 on traffic; explicit
`redis_fail_open = true` skips the probe
(`validate_activation_fails_closed_when_redis_rate_limit_unreachable`,
`validate_activation_skips_redis_probe_when_fail_open`,
`probe_activation_rejects_unreachable_redis`,
`validate_skips_fail_open_middlewares` with `--features redis`).
On the live listener (with `--features redis`), unreachable Redis returns
`{"error":"Distributed rate limiter unavailable"}` with `503` and never
contacts upstream; explicit `redis_fail_open = true` still reaches upstream
(`entrypoint::tests::rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact`,
`entrypoint::tests::rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable`).
`forward-auth` middlewares probe the same HTTP connect surface at
`validate_activation` as the first auth request (any HTTP response counts as
reachable) so a present `forward_auth_url` cannot soft-open Running and only
502 on traffic
(`validate_activation_fails_closed_when_forward_auth_unreachable`,
`validate_activation_probes_reachable_forward_auth`,
`probe_activation_rejects_unreachable_auth_service`,
`probe_activation_accepts_reachable_auth_service`).
On the live listener, unreachable auth returns
`{"error":"Auth service unavailable"}` with `502` and never contacts upstream;
a non-2xx auth decision short-circuits with the auth status and also never
contacts upstream
(`entrypoint::tests::forward_auth_unreachable_returns_502_on_listener_without_upstream_contact`,
`entrypoint::tests::forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact`).

Sticky session cookies pin live-listener traffic to the bound backend: the first
response emits `Set-Cookie`, and subsequent requests carrying that cookie stay
on the same upstream — including WebSocket upgrades (`101` + `Set-Cookie`).
Evidence:
`entrypoint::tests::sticky_session_cookie_pins_backend_on_listener`,
`entrypoint::tests::sticky_session_cookie_pins_websocket_backend_on_listener`.

Configured traffic mirroring copies a buffered request body to the shadow
service on the live listener without changing the primary response. Evidence:
`entrypoint::tests::traffic_mirror_copies_buffered_request_to_shadow_on_listener`.
An unreachable shadow does not fail or block the primary response. Evidence:
`entrypoint::tests::traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener`.
Standalone Box autoscaling probes the same `GET /v1/scale/{service}`
observation at `validate_activation` as the first autoscaler reconcile
(bounded by `executor_timeout_secs`) so a present `executor_endpoint` cannot
soft-open a Running autoscaler that only errors on the first tick
(`validate_activation_fails_closed_when_box_scale_unreachable`,
`validate_activation_probes_box_scale_http_client`,
`probe_box_scale_activation_rejects_unreachable_executor`).
Standalone `scaling.executor = "k8s"` probes the same Deployment Scale
`get_scale` observation at `validate_activation` as the first autoscaler
reconcile (after `Client::try_default`, bounded by `executor_timeout_secs`) so a
usable kubeconfig alone cannot soft-open a Running k8s autoscaler that only
errors on the first tick
(`validate_activation_fails_closed_when_k8s_scale_subresource_unreachable`,
`validate_activation_probes_k8s_scale_subresource` with `--features kube`).
`providers.kubernetes` also probes the same Ingress list (and optional
IngressRoute ConfigMap list) at `validate_activation` and cold start as the
first watcher poll, so a buildable client cannot soft-open a forever-warn
provider after logging watcher start
(`validate_activation_fails_closed_when_kubernetes_ingress_list_unreachable`,
`validate_activation_probes_kubernetes_ingress_list` with `--features kube`).
Labeled IngressRoute ConfigMaps (`a3s-gateway.io/type=ingressroute`) fail closed
when `data` / `data.spec` is missing or unparseable — one bad ConfigMap rejects
the whole poll (no warn-and-skip partial overlay)
(`parse_ingress_route_configmap_spec_rejects_malformed_json`,
`parse_ingress_route_configmap_spec_rejects_wrong_shape`,
`ingress_route_from_configmap_data_rejects_missing_data`,
`ingress_route_from_configmap_data_rejects_missing_spec`).
Declared load-balancing `strategy` on Docker labels, Ingress annotations, and
IngressRoute backends fails closed when present but invalid (absent still
defaults to RoundRobin); conversion errors retain the prior overlay and are
probed at Kubernetes activation
(`parse_declared_strategy_rejects_unknown`,
`generate_config_fails_closed_on_invalid_strategy_label`,
`ingress_to_config_fails_closed_on_invalid_strategy_annotation`,
`ingress_routes_to_config_fails_closed_on_invalid_backend_strategy`).
Docker containers with `enable=true` fail closed when IP is missing/invalid,
`service.port` is missing/invalid/zero, or `service.weight` is non-positive —
no warn-and-skip partial overlay
(`generate_config_fails_closed_on_missing_port_label`,
`generate_config_fails_closed_on_invalid_port_label`,
`generate_config_fails_closed_on_missing_or_invalid_ip`,
`generate_config_fails_closed_on_invalid_weight_label`). Non-opt-in containers
(`enable` absent/`false`) still skip silently.
Declared `protocol=tcp|udp` without a listen address
(`entrypoint.address` / `a3s-gateway.io/listen`) fails closed on Docker and
Kubernetes Ingress conversion; unknown protocol values no longer soft-default
to HTTP
(`generate_config_fails_closed_on_tcp_protocol_without_listen_address`,
`generate_config_fails_closed_on_udp_protocol_without_listen_address`,
`generate_config_fails_closed_on_unknown_protocol_label`,
`ingress_to_config_fails_closed_on_tcp_without_listen`,
`ingress_to_config_fails_closed_on_udp_without_listen`,
`ingress_to_config_fails_closed_on_unknown_protocol_annotation`).
Declared router `priority` on Docker labels and Ingress annotations fails closed
when present but empty or non-integer (absent still defaults to `0`); invalid
values must not soft-pin the router at priority `0`
(`parse_declared_priority_rejects_non_integer`,
`generate_config_fails_closed_on_invalid_priority_label`,
`ingress_to_config_fails_closed_on_invalid_priority_annotation`).
Kubernetes Ingress backends require a positive `port.number`: `0` no longer
soft-defaults to `:80`, and name-only ports fail closed (this provider does
not resolve Service named ports)
(`ingress_to_config_fails_closed_on_zero_backend_port`,
`ingress_to_config_fails_closed_on_named_backend_port_without_number`,
`ingress_to_config_uses_explicit_backend_port`).
Declared Ingress `a3s-gateway.io/request-timeout` fails closed when present but
empty or unparseable (absent still defaults to `30s`); empty whitespace must
not soft-default back to `30s`
(`parse_declared_request_timeout_rejects_empty`,
`ingress_to_config_fails_closed_on_empty_request_timeout_annotation`,
`ingress_to_config_fails_closed_on_invalid_request_timeout_annotation`).
Operator/config hot reload restarts dynamic providers and the ACME manager when
`providers.*` or the ACME activation fingerprint changes, so newly added or
removed providers activate without a process restart; dynamic overlay applies
do not restart those loops
(`reload_adding_discovery_starts_poll_loop`,
`reload_removing_docker_aborts_provider_handles`,
`reload_disabling_acme_aborts_manager`).

Passive health half-open recovery re-enables a blacklisted backend after
`recovery_time` so traffic can probe again without a Gateway restart. Evidence:
`entrypoint::tests::passive_health_half_open_recovery_readmits_traffic_after_recovery_time`
(and unit `test_recover_expired_reenables_after_recovery_time`).
If the probe still fails, the same error threshold re-blacklists the backend and
the listener fails closed with `{"error":"No healthy backends"}` again — without
a Gateway restart. Evidence:
`entrypoint::tests::passive_health_half_open_still_broken_reblacklists_after_threshold`
(and unit `test_recover_expired_still_broken_reblacklists_after_threshold`).

Circuit-breaker middleware half-open recovery is observable on the live listener:
after `failure_threshold` upstream 5xx responses the circuit opens with
`{"error":"Service unavailable (circuit breaker open)"}`; after `cooldown_secs`
a single probe may close the circuit on success, or re-open it when the upstream
is still failing. Evidence:
`entrypoint::tests::circuit_breaker_half_open_probe_closes_after_success_on_listener`,
`entrypoint::tests::circuit_breaker_half_open_still_failing_reopens_on_listener`.

Active health checks evict and re-admit backends on the live listener: after
probe failures the data plane fails closed with
`{"error":"No healthy backends"}`, and after probe success traffic is
re-admitted without a Gateway restart. Evidence:
`entrypoint::tests::active_health_check_evicts_backend_on_listener_then_readmits_when_healthy`.
The same contract holds for revision-only pools when
`prepare_health_checks` receives `revision_routers` (matching cold start /
`validate_activation`): Evidence:
`entrypoint::tests::active_health_check_evicts_revision_only_backend_on_listener_then_readmits_when_healthy`.

Configured service failover routes live listener traffic to the backup pool when
the primary has zero healthy backends (no Gateway restart). Evidence:
`entrypoint::tests::failover_routes_to_backup_on_listener_when_primary_unhealthy`.

Applied managed-snapshot validity is a data-plane admission boundary: after
`expires_at`, the live HTTP listener returns `503` with
`Managed snapshot expired` and does not forward to upstream. Evidence:
`entrypoint::tests::managed_snapshot_expiry_rejects_new_requests_on_the_listener_with_503`
(flag-only companion:
`managed_runtime_stops_admitting_traffic_at_snapshot_expiry`).
TCP and UDP listeners obey the same gate: after expiry, new TCP accepts are
dropped without upstream contact and new UDP datagrams are discarded without a
response. Evidence:
`entrypoint::tests::managed_snapshot_expiry_rejects_new_tcp_connections_without_upstream`,
`entrypoint::tests::managed_snapshot_expiry_rejects_new_udp_datagrams_without_upstream`.

Aggregated OpenAI SSE after headers honors independent `stream_idle_timeout`
and `stream_total_timeout` bounds: idle silence and active-drip total expiry
both fail closed, release grant concurrency / backend guards, and persist
usage-spool `failed` terminals
(`managed_sse_idle_timeout_releases_admission_and_persists_failed_terminals`,
`managed_sse_total_timeout_releases_admission_and_persists_failed_terminals`).

`Host(...)` routing and access-log authority must prefer the request URI
authority (HTTP/2 `:authority`) over the `Host` header. Evidence:
`entrypoint::tests::request_host_authority_prefers_uri_authority_then_host_header`,
`http2_host_router_matches_uri_authority_when_host_header_is_absent`,
`http2_host_router_misses_when_uri_authority_does_not_match`.

TCP entrypoints with pure `HostSNI(...)` routers compile a dedicated SNI table
and match after a bounded ClientHello peek. When the SNI table is empty
(PathPrefix-only TCP), Gateway skips the peek entirely so server-first plain
TCP is not stalled by a ClientHello wait. Evidence:
`tests/tcp_hostsni.rs`
(`tcp_entrypoint_routes_by_hostsni_from_client_hello`,
`tcp_hostsni_miss_does_not_select_a_backend`,
`tcp_pathprefix_only_relays_server_first_without_clienthello_peek_wait`).

`config validate` fails closed on structural listener policy (zero UDP session
budgets, invalid TCP allowlists, `acme = true` without `acme_email`, ACME
without resolvable domains, and `providers.kubernetes` without the `kube`
feature), and `validate_activation` also loads non-ACME entrypoint TLS PEM
material, prepares the node API listener (auth token env + management TLS),
builds the managed usage Cloud ingest transport (bearer env + mTLS PEM),
and runs `validate_managed_bootstrap` so a cloud-managed ACL with
`managed.gateway_id` cannot soft-open inline traffic that only
`Gateway::new` used to reject, and builds the discovery HTTP client via
`DiscoveryProvider::new` so discovery cannot soft-open until provider start,
and probes an existing `managed.state_file` journal with the same recovery
checks as cold start, and probes an existing usage spool directory/manifest without allocating a
new boot epoch — including untracked paths, retained capacity vs `max_bytes`,
insufficient headroom for the mandatory new boot epoch (manifest growth + epoch
header), and declared epoch file usability — so validate cannot pass when
`Gateway::start` would fail `UsageSpool::open`
(`load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem`,
`load_merged_gateway_config_fails_closed_when_management_token_env_unset`,
`validate_activation_fails_closed_when_usage_cloud_ingest_bearer_env_unset`,
`validate_activation_fails_closed_when_usage_cloud_ingest_mtls_identity_missing`,
`validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic`,
`test_validate_activation_builds_discovery_http_client`,
`validate_activation_fails_closed_on_corrupt_managed_snapshot_journal`,
`gateway_new_fails_closed_on_a_usage_spool_identity_mismatch`,
`probe_activation_rejects_untracked_paths_like_open`,
`probe_activation_rejects_retained_bytes_over_capacity_like_open`,
`probe_activation_rejects_missing_boot_epoch_headroom_like_open`,
`probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open`,
`probe_activation_projects_partial_ack_compaction_before_capacity_like_open`,
`probe_activation_write_probe_leaves_no_untracked_artifact`,
`probe_activation_fails_closed_when_usage_spool_directory_is_not_writable`,
`validate_activation_fails_closed_when_usage_spool_directory_is_not_writable`,
`validate_activation_fails_closed_when_usage_spool_has_untracked_file`,
`validate_activation_fails_closed_when_usage_spool_epoch_record_corrupt`,
`probe_activation_fails_closed_when_ready_epoch_record_is_corrupt`,
`probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt`,
`probe_activation_accepts_deleted_retiring_epoch_like_open`,
`probe_activation_fails_closed_when_recovery_artifact_is_a_directory`,
`probe_activation_fails_closed_when_compacting_epoch_final_is_a_directory`,
`standalone_missing_digest_object_in_local_store_fails_validate`,
`validate_activation_fails_closed_when_static_bundle_object_digest_mismatches`,
`validate_activation_fails_closed_when_distributed_serving_api_key_env_unset`,
`validate_activation_fails_closed_when_distributed_serving_api_key_invalid`).
Fails closed when standalone `local_digest_store` is missing sealed digest
objects, and resolves Power `distributed_serving.api_key_env` credentials the
same way as `build_runtime` (unset **and** present-but-invalid values fail
composed-runtime activation via the shared Power credential probe, not only
the helper).
`Gateway::with_managed_service_state` probes existing Managed Service state at
construct (including exclusive owner-lock contention)
(`corrupt_managed_service_state_fails_gateway_construct_closed`,
`retiring_state_without_the_exact_drain_key_fails_construct_closed`,
`ready_binding_missing_entrypoint_fails_gateway_construct_closed`,
`ready_binding_max_priority_base_router_fails_gateway_construct_closed`,
`one_gateway_exclusively_owns_the_managed_service_state`,
`with_managed_service_state_fails_construct_when_owner_lock_held`).
Cross-platform real OS-process qualification binds health and private traffic
through Gateway to a child upstream binary, then drain + remove hide the route
(`real_os_process_upstream_survives_bind_health_traffic_drain_remove`); restart
restores the durable route and exact-generation rebind preserves identity
(`real_os_process_upstream_restart_restores_route_and_replay_preserves_identity`);
drain waits on admitted SSE / WebSocket / gRPC streams against child fixtures are
`real_os_process_upstream_{sse,websocket,grpc}_drain_waits_for_admitted_stream`
(`tests/managed_runtime_real_process.rs`; Windows + Unix).
`Gateway::with_middlewares` / construct compiles router pipelines with the same
`build_pipeline_cache` as cold start so ACL retry plus a custom
`Middleware::retry_policy` cannot soft-open `Created` until start/reload
(`with_middlewares_fails_closed_on_dual_retry_with_custom_policy`,
`build_pipeline_cache_rejects_acl_retry_plus_custom_retry_policy`).
After Managed Service / managed-snapshot composition, start and hot reload run
`validate_runtime_activation` on the effective config (bootstrap-empty-traffic
rules skipped so legitimate composed traffic is not rejected). Host-owned
Managed Service overlays keep generation-bound targets in standalone; raw ACL
cannot claim reserved Managed Service names
(`ready_binding_with_targets_starts_gateway_closed_aligned`,
`validate_activation_rejects_reserved_managed_service_middleware_name`,
`validate_activation_rejects_reserved_managed_service_name_prefix`).
ACME manager creation is shared between `validate_activation` and start via
`AcmeManager::try_from_gateway_config`, including an absolute writable storage
directory probe, PKCS#8 parse of a present `account.key`, and rustls PEM
installability of any present domain certificates
(`CertStorage::probe_activation`,
`CertStorage::probe_existing_domain_certificates`) so relative paths, file
paths, unwritable stores, corrupt account material, and Valid-but-unusable
stored PEMs fail before the renewal warn-loop
(`test_validate_activation_builds_acme_manager_when_configured`,
`validate_activation_fails_closed_when_acme_storage_path_is_a_file`,
`validate_activation_fails_closed_when_acme_storage_path_is_relative`,
`validate_activation_fails_closed_when_acme_account_key_corrupt`,
`validate_activation_accepts_usable_acme_account_key`,
`validate_activation_fails_closed_when_acme_stored_cert_pem_corrupt`,
`validate_activation_accepts_usable_acme_stored_cert_pem`); ACME
manager creation failure aborts startup before
`Running` instead of soft-continuing. When ACME is active, the manager's
`ChallengeStore` is attached to `GatewayRuntime` and HTTP-01 tokens are served
on `/.well-known/acme-challenge/*` before route match
(`acme_http01_challenge_is_served_from_runtime_store_before_routes`).
Issued and previously stored certificates are hot-installed onto live HTTPS
listeners (`build_tls_acceptor_from_pem`,
`acme_certificate_install_hot_swaps_live_https_acceptor`,
`activate_stored_certificate_loads_from_storage`);
`start_acme_manager` / `restart_acme_manager` fail closed on
`activate_stored_certificate` before spawning the renewal task
(`activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem`).
Operator/config reload also restarts the
ACME manager when its activation fingerprint changes
(`reload_disabling_acme_aborts_manager`).
With the `kube` feature, Kubernetes client activation runs the same
`Client::try_default` surface as cold start whenever a client would be built —
`providers.kubernetes` watchers **or** standalone `scaling.executor = "k8s"` —
so a YAML-parseable kubeconfig with a missing CA or broken auth fails at
`validate_activation` (not only missing-file kubeconfig reads)
(`validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable`,
`validate_activation_fails_closed_when_kubernetes_client_cannot_build`,
`validate_activation_fails_closed_when_k8s_autoscaler_kubeconfig_unusable`).
Cold start still awaits `prepare_kubernetes_client` before spawning watchers /
constructing `K8sScaleExecutor`.
Ingress/CRD spawn receives that prepared client (no second soft-exit
`try_default` after "watcher started"); poll failures still rebuild
(`ingress_watcher_keeps_running_with_prepared_client_when_kubeconfig_missing`).
Standalone Box autoscaling builds the scale HTTP client at
`validate_activation` and `prepare_autoscaler` via `BoxScaleExecutor::try_new`
so a client that cannot initialize fails closed instead of soft-opening a
Running autoscaler that only errors on the first tick
(`box_executor_client_initialization_failure_is_explicit`,
`validate_activation_probes_box_scale_http_client`).
Default upstream HTTP and gRPC TLS clients activate at
`validate_activation` / `build_runtime` via `HttpProxy::try_with_timeouts` and
`GrpcProxy::try_new` (no deferred construction `Result` until first forward)
(`try_with_timeouts_activates_default_upstream_tls_client`,
`grpc_proxy_try_new_activates_tls_client`,
`validate_activation_probes_default_upstream_tls_clients`).
Per-service `tls_ca_file` proxies use the same `build_service_http_proxies`,
`build_service_grpc_proxies`, and `build_service_ws_tls_configs` construction
at validate (not PEM-only), matching cold start; gRPC dispatch uses
`grpc_proxy_for` and WebSocket upgrades use `ws_tls_for` so private CA applies
to application/grpc and WebSocket as well as HTTP. Failover dispatch uses the
backup service's TLS client when the selected backend belongs to that pool.
HTTP, gRPC, and WebSocket forwards reject `tcp`/`udp` (and other non-matching)
backend schemes instead of prefixing `http://` or `ws://` onto them.
TCP and UDP dial the parsed host:port, including default 443/80 and IPv6
brackets, instead of the raw URL tail. Dial refusal is an upstream transport
failure, so passive health can eject the backend; local admission still cannot.
Listener fields the selected protocol does not enforce fail at validate, so an
HTTP `tcp_allowed_ips` or a TCP `tls` block cannot look enabled while the
listener ignores them. Sticky cookies on a `tcp://` or `udp://` pool fail the
same way: those listeners never honor `Set-Cookie`. A mirror target that
cannot speak `http` or `https` fails at validate, because discarded HTTP
copy errors are not a working shadow. Router middleware bound only to TCP or
UDP listeners fails the same way, including an omitted entrypoint list when
every configured listener is non-HTTP. That chain runs only on HTTP. A
static bundle routed only through those listeners fails the same way: object
bytes are served on HTTP, and the raw listener drops the connection. An
inference route bound only to those listeners fails too, because model
admission never sees the HTTP body.
(`inference_route_on_non_http_entrypoint_is_not_a_silent_noop`,
`static_bundle_on_non_http_entrypoint_is_not_a_silent_noop`,
`router_middleware_on_non_http_entrypoint_is_not_a_silent_noop`,
`mirror_target_must_speak_http`,
`sticky_on_tcp_backends_is_not_a_silent_noop`,
`test_extract_address_https_default_port_and_ignored_path`,
`dial_failure_marks_backend_unhealthy_but_admission_does_not`,
`http_tcp_allowlist_is_not_a_silent_noop`,
`tcp_tls_is_not_a_silent_noop`,
`failover_backend_uses_backup_upstream_tls_service`,
`http_forward_rejects_non_http_backend_scheme`,
`test_normalized_grpc_backend_rejects_non_grpc_scheme`,
`test_build_ws_url_rejects_non_websocket_scheme`,
`validate_activation_probes_service_tls_ca_http_clients`,
`validate_activation_probes_service_tls_ca_grpc_clients`,
`validate_activation_probes_service_tls_ca_websocket_clients`,
`validate_activation_fails_closed_on_unusable_service_tls_ca_for_grpc`,
`grpc_proxy_try_with_ca_file_activates_private_trust_store`,
`grpc_proxy_try_with_ca_file_rejects_unusable_pem`).
Active health checks activate at `validate_activation` via the same
`ServiceRegistry::from_config` + `build_scaling_state` +
`prepare_health_checks` path as cold start (service pools and revision
routers; private CA via `Certificate::from_pem_bundle`, rejecting empty/junk
PEM; invalid durations fail closed)
(`validate_activation_probes_health_check_http_clients`,
`validate_activation_prepares_revision_health_checkers`,
`validate_activation_fails_closed_on_invalid_health_check_interval`,
`health_checker_probe_rejects_unusable_pem`).
On Unix, Docker Unix socket hosts must exist at validate
(`validate_rejects_docker_unix_socket_host_when_path_missing`,
`validate_accepts_docker_unix_socket_host_when_path_exists`); activation also
requires a reachable Docker daemon via `/_ping`
(`validate_activation_fails_closed_when_docker_daemon_unreachable`,
`validate_activation_probes_reachable_docker_daemon`). Mirror/failover runtime build fails closed
on registry skew instead of warn-skipping HA policy
(`build_mirror_failover_fails_closed_when_mirror_target_missing_from_registry`,
`build_mirror_failover_fails_closed_when_failover_target_missing_from_registry`).
Node API `client_ca_file` refuses a partial trust-anchor load: any unusable
certificate alongside valid anchors fails closed instead of warn-skipping
(`node_api_client_ca_refuses_partial_trust_anchor_load`,
`node_api_client_ca_accepts_clean_trust_anchor_bundle`).
Node API TLS `client_ca_file` without `require_client_cert = true` is rejected
so optional client auth cannot soft-open mTLS
(`test_management_config_rejects_client_ca_without_require_client_cert`).
CLI run fails closed when `--config` is missing (no empty default listener).
`providers.file.directory` is merged at CLI cold start and `validate` (not only
after a hot-reload event), including when `watch = false`; a missing conf.d
path fails closed
(`load_merged_gateway_config_merges_directory_from_root_acl`,
`load_merged_gateway_config_fails_closed_when_directory_missing`,
`load_config_fails_closed_when_configured_directory_is_missing`,
`watch_fails_closed_when_configured_directory_is_missing`); enabling
`providers.file.watch` also probes the same notify watcher attach at
`load_merged_gateway_config` / `validate` and aborts startup if the watcher
cannot start
(`load_merged_gateway_config_probes_file_watch_when_enabled`,
`probe_file_watch_activation_rejects_missing_directory`,
`probe_file_watch_activation_accepts_existing_paths`);
path-aware construct (`Gateway::new_at_path` /
`validate_activation_at_path`) attaches the root ACL parent watch surface
(`validate_activation_at_path_attaches_config_parent_watch`,
`gateway_new_at_path_fails_closed_when_config_parent_missing`);
`load_merged_gateway_config` rejects non-`.acl` root paths with the same
extension gate as conf.d merge
(`test_load_config_rejects_non_acl_main_extension`).
Enabled `management` requires a non-empty `auth_token_env` and at least one
`allowed_ips` entry so the node API cannot soft-open without bearer auth or
to any client IP (`test_management_config_rejects_empty_auth_token_env`,
`test_management_config_rejects_empty_allowed_ips`).
`health_check` requires every configured service and revision server to use
`http://` or `https://` so active probes cannot soft-open as a no-op on
tcp/h2c/udp members (or revision-only pools)
(`test_validate_rejects_health_check_without_probeable_servers`,
`test_validate_rejects_health_check_with_non_http_revision_servers`,
`test_validate_accepts_health_check_with_revision_only_http_servers`).
`tls_ca_file` HTTPS detection includes revision servers so private CA policy
matches revision-only HTTPS pools
(`test_validate_accepts_tls_ca_file_with_revision_only_https_servers`,
`test_validate_rejects_tls_ca_file_without_https_servers`).
Standalone `static_bundles.local_digest_store` must exist as a directory at
validate (`standalone_missing_local_digest_store_directory_fails_validate`).
`providers.discovery` requires at least one seed URL so an empty seed list
cannot soft-open as a no-op provider
(`test_validate_discovery_rejects_empty_seeds`). Discovery HTTP client
construction failure aborts Gateway start rather than polling with a missing
client (`discovery_provider_new_requires_buildable_http_client`).
Successful upstream responses and proxy-failure decoration paths fail closed when response-phase middleware
cannot apply declared policy (HTTP/SSE/gRPC/distributed/native); the
unpolicied upstream or error body is not returned
(`entrypoint::tests::response_middleware_error_fails_closed_instead_of_returning_upstream_body`,
`entrypoint::tests::response_middleware_error_fails_closed_on_proxy_failure`,
`entrypoint::tests::response_middleware_error_fails_closed_on_sse_listener_without_upstream_body`,
`entrypoint::tests::response_middleware_error_fails_closed_on_grpc_listener_without_upstream_stream`,
`entrypoint::inference_distributed_tests::response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body`,
`entrypoint::inference_distributed_tests::response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body`,
`entrypoint::inference_tests::response_middleware_error_fails_closed_on_native_models_listener_without_policy_body`).
Sticky session `cookie` names must be valid cookie-name tokens at validate and
build time so affinity cannot soft-skip `Set-Cookie`
(`test_validate_rejects_invalid_sticky_cookie_name`,
`build_sticky_managers_fails_closed_on_invalid_cookie_name`).
Evidence:
`config::config_tests::test_validate_udp_zero_timeout_fails_closed`,
`config::config_tests::test_validate_acme_without_email_fails_closed`,
`config::config_tests::test_validate_acme_without_domains_fails_closed`,
`config::config_tests::test_validate_acme_with_host_router_domains_ok`,
`config::config_tests::test_validate_rejects_kubernetes_without_kube_feature`,
`config::entrypoint::tests::udp_zero_session_timeout_fails_listener_policy`,
`config::entrypoint::tests::udp_zero_max_sessions_fails_listener_policy`,
`config::entrypoint::tests::tcp_invalid_allowed_ip_fails_listener_policy`,
`config::entrypoint::tests::acme_without_email_fails_listener_policy`.

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
  `generation_bump_preserves_inflight_sse_on_retired_target`,
  `generation_bump_preserves_inflight_websocket_on_retired_target`,
  `generation_bump_preserves_inflight_grpc_on_retired_target`,
  `generation_bump_preserves_inflight_tcp_on_retired_target`,
  `generation_bump_preserves_inflight_udp_session_on_retired_target`)
- `tests/managed_replica_readiness.rs`
  (`replicated_gateways_skew_managed_target_generations_independently` —
  generation skew plus peer survival across advanced-replica node-loss and
  journal recovery)

Still **open for EXIT**: Cloud-orchestrated multi-replica rolling replacement,
node-loss, and mixed-version joint gates against a provisioned control plane.
Local independent journals + generation skew + peer traffic under local
node-loss are Gateway-proven.

## `WEB0.4` — static object target (Gateway foundation)

1. **Path normalize once** — reject absolute paths, `..`, backslashes, NULs,
   empty segments, and ambiguous percent-encoding before object access.
2. **Sealed manifest** — `a3s.gateway.static-bundle-manifest.v1` requires
   lowercase SHA-256 digests, a present entry document, optional SPA fallback
   that exists in entries, and ASCII case-fold uniqueness.
3. **Manifest select before GET** — missing assets fail closed; selection never
   silently substitutes SPA fallback. SPA eligibility excludes extension-bearing
   paths and the reserved first-segment `/api` namespace (ASCII
   case-insensitive) so same-origin API routes never soft-200 as `index.html`.
4. **Digest/size admit** — object bytes enter cache/response only when size and
   digest match the manifest entry.
5. **No credentials in snapshot** — field names that smuggle object endpoints or
   secrets are rejected.
6. **Read-only port** — local fixture authority supports digest-bound `HEAD`/
   `GET` only (no list/write/delete). HTTP `HEAD` verifies via port `head`
   without admitting object bytes; HTTP `GET` admits through port `get`.
7. **ACL + dispatch** — `static_bundles` parse/validate; routers may target a
   bundle; request path runs router middleware first, then serves GET/HEAD with
   `nosniff`, SPA eligibility, and standalone `local_digest_store`. Standalone
   fails closed when any bundle omits `local_digest_store`; cloud-managed
   forbids that field and rejects every `static_bundles` entry until Cloud
   `WEB0.1` provides object authority (`standalone_static_bundle_without_local_digest_store_fails_validate`,
   `cloud_managed_static_bundles_without_object_authority_fail_validate`).
8. **Bounded admitted cache** — snapshot-local LRU keyed by namespace / release /
   sealed manifest fingerprint / path / encoding; insert only after digest/size
   admit; purged by runtime replacement on reload while retained runtime `Arc`s
   keep draining the prior release (real-listener evidence:
   `static_bundle_listener_drains_inflight_get_across_runtime_replace`).
9. **Conditional + single range** — digest-strong `ETag` / `If-None-Match` 304;
   single `bytes=` range 206/416; `If-Range` strong-match only; multipart
   ranges ignored.
10. **Sealed content encoding** — manifest `content_encoding` becomes
    `Content-Encoding` and cache-key namespace; no `Accept-Encoding`
    negotiation.
11. **No response transforms** — static `Cache-Control` includes `no-transform`
    so `compress` and similar middleware cannot rewrite admitted bytes or the
    digest-strong `ETag`.

Evidence: `src/static_object/`, `src/config/static_bundle.rs`,
`entrypoint::tests::static_bundle_listener_serves_get_spa_and_honors_middleware`
(middleware, SPA, `If-None-Match` 304, single-byte `Range` 206, strong
`If-Range` hit→206 / miss→200, sealed `Content-Encoding`),
`entrypoint::tests::static_bundle_listener_preserves_sealed_bytes_under_compress`,
`entrypoint::tests::static_bundle_listener_drains_inflight_get_across_runtime_replace`,
`static_object::serve::tests::spa_fallback_never_masks_missing_assets_or_posts`,
`static_object::serve::tests::spa_fallback_eligibility_rejects_api_namespace`,
`static_object::serve::tests::head_verifies_via_port_head_without_authority_get`,
`static_object::serve::tests::sealed_content_encoding_is_emitted_without_accept_encoding_negotiation`,
`static_object::cache::tests::content_encoding_is_part_of_the_cache_key_namespace`,
`docs/static-object-target.md`.

Still **unavailable for production Cloud delivery**: Cloud object-authority
adapters and `WEB0.1` managed ACL fixtures.

## Enterprise GA ops evidence (fault injection)

Operator runbooks and a curated automated suite live under `docs/ops/` and
`scripts/run-fault-injection-suite.{sh,ps1}`. The suite owns the five failure
classes (listener, upstream, controller, disk, network) by selecting existing
live-listener / `validate_activation` tests — not by inventing Cloud EXIT
fixtures. Running the suite is the local proof for the fault-injection gate;
CI green alone is not a substitute. Threat model:
`docs/threat-model.md`. Capacity/soak harness:
`docs/ops/capacity-and-soak.md` and `scripts/soak-gateway.py` (smoke results
are `envelope_status: smoke-only`). Gate tracker:
`docs/ops/enterprise-ga-checklist.md`. CI job `enterprise-ga-smoke` runs the
fault-injection suite and short soak smokes. Remaining GA gates (independent
review, dedicated-hardware published envelopes, filled production adoption
case study) are outside this section.

## Explicit non-goals (reject overfit)

- Tuning assertions to current MicroVM latency noise.
- Special-casing emoji/billing tokenizers beyond the frozen v1 rules.
- Claiming `VIA_BOX` / Cloud EXIT / LOOP from Gateway unit tests.
- Using CI status as proof of an invariant (run the local command that owns it).
- Claiming Enterprise GA from authored docs alone without independent review,
  soak envelopes, and a production adoption case study.
