# Fault-injection suite

Repeatable, local evidence that Gateway fails closed or recovers for the five
Enterprise GA failure classes: **listener**, **upstream**, **controller**,
**disk**, and **network**.

This suite reuses live-listener and `validate_activation` regressions already
owned in-tree. It does **not** invent Cloud EXIT fixtures, dedicated-hardware
soak results, or iptables partitions that are non-portable.

## How to run

From the Gateway crate root (`crates/gateway`):

```bash
# Unix
./scripts/run-fault-injection-suite.sh

# Windows PowerShell
./scripts/run-fault-injection-suite.ps1
```

The default suite always builds with `--features kube,redis,wire` so Kubernetes
controller and Redis network fail-closed cases are part of the promotion gate.
`check-fault-suite-inventory.py` refuses docs that drop that feature claim while
runners still require it. Redis cases target an unreachable URL
(`127.0.0.1:1`); a live Redis server is not required. CI job `enterprise-ga-smoke`
runs this suite on both `ubuntu-latest` and `windows-latest`, plus Managed Runtime
real OS-process evidence (`scripts/run-managed-runtime-evidence.{sh,ps1}`).

Pass criteria: every selected test exits 0. A non-zero suite exit means the
failure-class contract regressed; do not ship that revision as Production
Candidate evidence. `scripts/check-fault-suite-inventory.py` refuses silent
drift when an in-tree `validate_activation_fails_closed_*` /
`probe_activation_fails_closed_*` / `validate_activation_rejects_*` /
`load_merged_gateway_config_fails_closed_*` /
`with_middlewares_fails_closed_*` /
`probe_activation_(rejects|projects|accepts)_*_like_open`
/ `probe_activation_(rejects_unreachable|accepts_reachable)_*`
test is missing from both runners' FILTER lists (exact membership, not
substring; sh≡ps1 filter sets must match), and also
requires curated non-auto-discovered regressions listed in the matrix
(ACME listener cases, CLI `load_merged` / `Gateway::new_at_path` path
regressions, the full response-middleware fail-closed family, `forward_auth`
live-listener proofs, Redis fail-closed/`redis_fail_open` twins,
sticky/mirror balancing proofs, Upstream half-open/circuit/failover/active-
health proofs, Disk construct-path / corrupt Managed Service state /
permissions / write-probe hygiene regressions) so they cannot soft-open out of
`enterprise-ga-smoke`. The same verifier refuses the opposite soft-open: every
full test name claimed in this page's Automated evidence matrix (and
distributed listener bullets) must appear in both runners, and every filter
listed in those runners must be auto-discovered or in `REQUIRED_CURATED` (no
unprotected orphans). Every non-auto
filter currently listed in both suite runners is also in `REQUIRED_CURATED`. Managed Runtime OS-process cases
are similarly inventory-protected by
`scripts/check-managed-runtime-evidence-inventory.py` (every
`real_os_process_upstream_*` in `tests/managed_runtime_real_process.rs` must
appear in both `run-managed-runtime-evidence.*` FILTER lists and this page;
docs claims and runner orphans are refused; sh≡ps1 FILTER sets must match);
`check-enterprise-ga-status.py` invokes both inventory verifiers when
fault-injection is Landed.

## Managed Runtime (complementary evidence)

Cross-platform OS-process bind → health → traffic → drain → remove proofs live
in `tests/managed_runtime_real_process.rs` and are promoted through
`scripts/run-managed-runtime-evidence.{sh,ps1}` (not Cloud EXIT fixtures):

- `real_os_process_upstream_survives_bind_health_traffic_drain_remove`
- `real_os_process_upstream_restart_restores_route_and_replay_preserves_identity`
- `real_os_process_upstream_sse_drain_waits_for_admitted_stream`
- `real_os_process_upstream_websocket_drain_waits_for_admitted_stream`
- `real_os_process_upstream_grpc_drain_waits_for_admitted_stream`

## Failure-class matrix

| Class | Operator symptom | Expected Gateway behavior | Automated evidence |
| --- | --- | --- | --- |
| Listener / middleware | Auth or response policy errors | Fail closed; never leak upstream body or soft-open | `response_middleware_error_fails_closed_instead_of_returning_upstream_body`, `response_middleware_error_fails_closed_on_proxy_failure`, `response_middleware_error_fails_closed_on_sse_listener_without_upstream_body`, `response_middleware_error_fails_closed_on_grpc_listener_without_upstream_stream`, `forward_auth_unreachable_returns_502_on_listener_without_upstream_contact`, `forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact`, `udp_zero_session_timeout_fails_listener_policy`, `udp_zero_max_sessions_fails_listener_policy`, `tcp_invalid_allowed_ip_fails_listener_policy`, `acme_without_email_fails_listener_policy`, `managed_snapshot_expiry_rejects_new_requests_on_the_listener_with_503`, `managed_snapshot_expiry_rejects_new_tcp_connections_without_upstream`, `managed_snapshot_expiry_rejects_new_udp_datagrams_without_upstream`, `credential_successor_runtime_revokes_prior_key_without_upstream`, `grant_successor_runtime_denies_prior_model_without_upstream`, `managed_snapshot_apply_grant_successor_denies_withdrawn_model_without_upstream`, `managed_snapshot_apply_credential_successor_revokes_prior_key_without_upstream`, `managed_snapshot_apply_credential_generation_bump_invalidates_prior_bearer_without_upstream`, `managed_inference_fails_closed_before_dispatch_when_usage_capacity_is_full`, `managed_inference_policy_expiry_fails_closed_at_request_time`, `managed_inference_revoked_or_expired_credentials_fail_closed_without_upstream`, `fail_closed_blocks_escalation_in_upstream_response`, `blocks_escalation_on_response_when_fail_closed`, `acme_http01_challenge_is_served_from_runtime_store_before_routes`, `acme_certificate_install_hot_swaps_live_https_acceptor` |
| Upstream | Backend 5xx / blackhole / circuit | Evict, failover, half-open recovery without process restart | `passive_health_half_open_recovery_readmits_traffic_after_recovery_time`, `passive_health_half_open_still_broken_reblacklists_after_threshold`, `circuit_breaker_half_open_probe_closes_after_success_on_listener`, `circuit_breaker_half_open_still_failing_reopens_on_listener`, `failover_routes_to_backup_on_listener_when_primary_unhealthy`, `active_health_check_evicts_backend_on_listener_then_readmits_when_healthy`, `active_health_check_evicts_revision_only_backend_on_listener_then_readmits_when_healthy`, `active_health_redirect_does_not_follow_or_mark_healthy`, `sticky_session_cookie_pins_backend_on_listener`, `sticky_session_cookie_pins_websocket_backend_on_listener`, `build_sticky_managers_fails_closed_on_invalid_cookie_name`, `traffic_mirror_copies_buffered_request_to_shadow_on_listener`, `traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener`, `build_mirror_failover_fails_closed_when_mirror_target_missing_from_registry`, `build_mirror_failover_fails_closed_when_failover_target_missing_from_registry` |
| Controller / providers | Docker/K8s/Box/ACME/TLS/auth/health-check/Power/file-watch deps unusable or reachable | `validate_activation` rejects unusable deps; probes reachable deps before Running; prior runtime retained on reject | `validate_activation_fails_closed_when_docker_daemon_unreachable`, `validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable`, `validate_activation_fails_closed_when_kubernetes_client_cannot_build`, `validate_activation_fails_closed_when_kubernetes_ingress_list_unreachable`, `validate_activation_fails_closed_when_k8s_autoscaler_kubeconfig_unusable`, `validate_activation_fails_closed_when_k8s_scale_subresource_unreachable`, `validate_activation_fails_closed_when_box_scale_unreachable`, `probe_box_scale_activation_rejects_unreachable_executor`, `validate_activation_fails_closed_on_unusable_service_tls_ca_for_grpc`, `validate_activation_fails_closed_on_unusable_health_check_tls_ca`, `validate_activation_fails_closed_on_invalid_health_check_interval`, `validate_activation_fails_closed_when_forward_auth_unreachable`, `probe_activation_rejects_unreachable_auth_service`, `probe_activation_accepts_reachable_auth_service`, `validate_activation_probes_reachable_forward_auth`, `validate_activation_probes_reachable_docker_daemon`, `validate_activation_probes_box_scale_http_client`, `validate_activation_probes_k8s_scale_subresource`, `validate_activation_probes_kubernetes_ingress_list`, `validate_activation_probes_default_upstream_tls_clients`, `validate_activation_probes_service_tls_ca_http_clients`, `validate_activation_probes_service_tls_ca_grpc_clients`, `validate_activation_probes_health_check_http_clients`, `validate_activation_prepares_revision_health_checkers`, `validate_activation_probes_file_watch_notify_when_enabled`, `validate_activation_at_path_attaches_config_parent_watch`, `validate_activation_accepts_usable_acme_account_key`, `validate_activation_accepts_usable_acme_stored_cert_pem`, `test_validate_activation_builds_discovery_http_client`, `test_validate_activation_builds_acme_manager_when_configured`, `load_merged_gateway_config_probes_file_watch_when_enabled`, `probe_file_watch_activation_accepts_existing_paths`, `validate_activation_fails_closed_when_acme_storage_path_is_a_file`, `validate_activation_fails_closed_when_acme_storage_path_is_relative`, `validate_activation_fails_closed_when_acme_account_key_corrupt`, `validate_activation_fails_closed_when_acme_stored_cert_pem_corrupt`, `activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem`, `validate_activation_fails_closed_when_file_watch_directory_missing`, `probe_file_watch_activation_rejects_missing_directory`, `load_config_fails_closed_when_configured_directory_is_missing`, `watch_fails_closed_when_configured_directory_is_missing`, `load_merged_gateway_config_fails_closed_when_directory_missing`, `gateway_new_at_path_fails_closed_when_config_parent_missing`, `load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem`, `load_merged_gateway_config_fails_closed_when_management_token_env_unset`, `with_middlewares_fails_closed_on_dual_retry_with_custom_policy`, `generate_config_fails_closed_on_missing_port_label`, `generate_config_fails_closed_on_invalid_port_label`, `generate_config_fails_closed_on_missing_or_invalid_ip`, `generate_config_fails_closed_on_invalid_weight_label`, `generate_config_fails_closed_on_invalid_strategy_label`, `generate_config_fails_closed_on_invalid_priority_label`, `generate_config_fails_closed_on_tcp_protocol_without_listen_address`, `generate_config_fails_closed_on_udp_protocol_without_listen_address`, `generate_config_fails_closed_on_unknown_protocol_label`, `ingress_to_config_fails_closed_on_invalid_strategy_annotation`, `ingress_to_config_fails_closed_on_invalid_priority_annotation`, `ingress_to_config_fails_closed_on_empty_request_timeout_annotation`, `ingress_to_config_fails_closed_on_invalid_request_timeout_annotation`, `ingress_to_config_fails_closed_on_zero_backend_port`, `ingress_to_config_fails_closed_on_named_backend_port_without_number`, `ingress_to_config_fails_closed_on_tcp_without_listen`, `ingress_to_config_fails_closed_on_udp_without_listen`, `ingress_to_config_fails_closed_on_unknown_protocol_annotation`, `ingress_routes_to_config_fails_closed_on_invalid_backend_strategy`, `validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic`, `validate_activation_rejects_reserved_managed_service_middleware_name`, `validate_activation_rejects_reserved_managed_service_name_prefix`, `scheduled_models_fail_closed_when_worker_observations_are_absent`, `scheduled_models_fail_closed_when_service_has_no_configured_workers`, `scheduled_models_fail_closed_without_exact_managed_endpoint_ownership`, `expired_worker_observations_fail_closed_without_upstream_contact`, `validate_activation_fails_closed_when_distributed_serving_api_key_env_unset`, `validate_activation_fails_closed_when_distributed_serving_api_key_invalid`, `default_docker_block_fails_validate_on_windows` (Windows), `validate_rejects_docker_unix_socket_host_on_non_unix` (Windows), `validate_rejects_docker_unix_socket_host_when_path_missing` (Unix), `test_validate_udp_zero_timeout_fails_closed`, `test_validate_acme_without_email_fails_closed`, `test_validate_acme_without_domains_fails_closed`, `node_api_client_ca_refuses_partial_trust_anchor_load`, `test_management_config_rejects_client_ca_without_require_client_cert`, `test_management_config_rejects_empty_allowed_ips`, `test_management_config_rejects_empty_auth_token_env`, `test_validate_rejects_health_check_without_probeable_servers`, `test_validate_rejects_health_check_with_non_http_revision_servers`, `test_validate_rejects_tls_ca_file_without_https_servers`, `test_validate_rejects_invalid_sticky_cookie_name`, `test_validate_discovery_rejects_empty_seeds`, `test_validate_discovery_rejects_duplicate_seeds`, `discovery_provider_new_requires_buildable_http_client`, `test_load_config_rejects_non_acl_main_extension`, `health_checker_probe_rejects_unusable_pem`, `grpc_proxy_try_with_ca_file_rejects_unusable_pem`, `reload_disabling_acme_aborts_manager`, `reload_rejects_standalone_to_cloud_managed_transition` |
| Disk | Usage spool / managed journal / Managed Service state / static digest store corrupt, untracked, locked, mismatched, unwritable parent, or unwritable spool directory | Fail closed at validate/construct or refuse insecure permissions | `validate_activation_fails_closed_when_usage_spool_has_untracked_file`, `validate_activation_fails_closed_when_usage_spool_locked`, `probe_activation_fails_closed_when_exclusive_lock_is_held`, `validate_activation_fails_closed_when_usage_spool_parent_unusable`, `probe_activation_fails_closed_when_spool_parent_is_not_a_directory`, `validate_activation_fails_closed_when_usage_spool_directory_is_not_writable` (Unix), `probe_activation_fails_closed_when_usage_spool_directory_is_not_writable` (Unix), `validate_activation_fails_closed_when_usage_spool_epoch_record_corrupt`, `probe_activation_fails_closed_when_ready_epoch_record_is_corrupt`, `validate_activation_fails_closed_when_usage_spool_prepared_epoch_corrupt`, `probe_activation_fails_closed_when_prepared_epoch_record_is_corrupt`, `validate_activation_fails_closed_when_usage_spool_recovery_artifact_is_a_directory`, `probe_activation_fails_closed_when_recovery_artifact_is_a_directory`, `probe_activation_fails_closed_when_compacting_epoch_final_is_a_directory`, `probe_activation_rejects_retained_bytes_over_capacity_like_open`, `probe_activation_rejects_missing_boot_epoch_headroom_like_open`, `probe_activation_rejects_untracked_paths_like_open`, `probe_activation_accepts_deleted_retiring_epoch_like_open`, `probe_activation_write_probe_leaves_no_untracked_artifact`, `probe_activation_projects_empty_epoch_reclaim_before_capacity_like_open`, `probe_activation_projects_partial_ack_compaction_before_capacity_like_open`, `validate_activation_fails_closed_when_usage_cloud_ingest_bearer_env_unset`, `validate_activation_fails_closed_when_usage_cloud_ingest_mtls_identity_missing`, `validate_activation_fails_closed_on_corrupt_managed_snapshot_journal`, `validate_activation_fails_closed_when_managed_snapshot_journal_parent_unusable`, `validate_activation_fails_closed_when_static_bundle_object_digest_mismatches`, `standalone_missing_digest_object_in_local_store_fails_validate`, `standalone_missing_local_digest_store_directory_fails_validate`, `standalone_static_bundle_without_local_digest_store_fails_validate`, `cloud_managed_static_bundles_without_object_authority_fail_validate`, `spa_fallback_never_masks_missing_assets_or_posts`, `spa_fallback_eligibility_rejects_api_namespace`, `head_verifies_via_port_head_without_authority_get`, `static_bundle_listener_preserves_sealed_bytes_under_compress`, `static_bundle_listener_drains_inflight_get_across_runtime_replace`, `sealed_content_encoding_is_emitted_without_accept_encoding_negotiation`, `gateway_new_fails_closed_on_a_usage_spool_identity_mismatch`, `with_managed_service_state_fails_construct_when_owner_lock_held`, `corrupt_managed_service_state_fails_gateway_construct_closed`, `linked_managed_service_state_fails_gateway_construct_closed` (Unix), `broadly_readable_managed_service_state_fails_gateway_construct_closed` (Unix), `ready_binding_missing_entrypoint_fails_gateway_construct_closed`, `ready_binding_max_priority_base_router_fails_gateway_construct_closed`, `retiring_state_without_the_exact_drain_key_fails_construct_closed`, `spool_storage_is_private_and_insecure_permissions_fail_closed` (Unix only; skipped on Windows runners) |
| Network | Redis / distributed dependency unreachable | Listener returns `503`/`502` without contacting primary upstream when required; explicit `redis_fail_open` still reaches upstream | `rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact`, `rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable`, `validate_activation_fails_closed_when_redis_rate_limit_unreachable`, `probe_activation_rejects_unreachable_redis`, `validate_activation_skips_redis_probe_when_fail_open` (default suite features include `redis`) |

Distributed / native OpenAI response-middleware fail-closed cases are additional
listener evidence:

- `response_middleware_error_fails_closed_on_distributed_json_listener_without_power_body`
- `response_middleware_error_fails_closed_on_distributed_sse_listener_without_power_body`
- `response_middleware_error_fails_closed_on_native_models_listener_without_policy_body`

## Out of scope (do not fake)

- ACME directory / CA network reachability at validate (would require live
  Internet or a pinned ACME peer; storage + client construction already fail
  closed). Power worker endpoint connect at validate (workers are observation-
  delivered at request time; credential activation is covered).
- Cloud-orchestrated multi-replica rolling / node-loss EXIT (`H0.3`/`H0.4`)
- Power `PW0` observation delivery, Box `BX0`, Cloud `WEB0.1`
- Long-duration dedicated-hardware soak and published capacity envelopes
- Independent security review sign-off

See runbooks under [`runbooks/`](runbooks/) for human recovery steps that
mirror this matrix.
