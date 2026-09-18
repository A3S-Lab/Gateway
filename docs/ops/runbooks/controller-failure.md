# Runbook: controller / provider failure

## Detect

- Startup or reload rejects with Docker daemon unreachable, unusable
  kubeconfig / unbuildable kube client, unreachable Ingress list or Scale
  subresource, unreachable Box scale API, unusable upstream TLS CA for gRPC,
  invalid active health-check intervals, ACME storage path errors (file or
  relative path), or forbidden mode transitions.
- Dynamic providers stop updating overlays; prior validated runtime should
  remain serving. After an Ingress/CRD poll failure the watcher drops the
  poisoned kube client and rebuilds; rebuild failure retains the prior overlay
  without reusing the poisoned pool.

## Contain

1. Do not force-delete the running process to “clear” a bad provider — retain
   the last good runtime.
2. Block Cloud↔standalone mode flips; they require a process restart by design.

## Recover

1. Repair the provider dependency (Docker API, kubeconfig, ACME directory).
2. Re-apply ACL or managed snapshot; `validate_activation` must pass before
   listeners adopt the new desired state.
3. Confirm provider poll loops restart after a successful reload when providers
   were added or removed.

## Verify

- Suite: `validate_activation_fails_closed_when_docker_daemon_unreachable`,
  `validate_activation_fails_closed_when_kubernetes_kubeconfig_unusable`,
  `validate_activation_fails_closed_when_kubernetes_client_cannot_build`,
  `validate_activation_fails_closed_when_kubernetes_ingress_list_unreachable`,
  `validate_activation_fails_closed_when_k8s_autoscaler_kubeconfig_unusable`,
  `validate_activation_fails_closed_when_k8s_scale_subresource_unreachable`,
  `validate_activation_fails_closed_when_box_scale_unreachable`,
  `probe_box_scale_activation_rejects_unreachable_executor`,
  `validate_activation_fails_closed_on_unusable_service_tls_ca_for_grpc`,
  `validate_activation_fails_closed_on_unusable_health_check_tls_ca`,
  `validate_activation_fails_closed_on_invalid_health_check_interval`,
  `validate_activation_fails_closed_when_forward_auth_unreachable`,
  `probe_activation_rejects_unreachable_auth_service`,
  `probe_activation_accepts_reachable_auth_service`,
  `validate_activation_probes_reachable_forward_auth`,
  `validate_activation_probes_reachable_docker_daemon`,
  `validate_activation_probes_box_scale_http_client`,
  `validate_activation_probes_k8s_scale_subresource`,
  `validate_activation_probes_kubernetes_ingress_list`,
  `validate_activation_probes_default_upstream_tls_clients`,
  `validate_activation_probes_service_tls_ca_http_clients`,
  `validate_activation_probes_service_tls_ca_grpc_clients`,
  `validate_activation_probes_health_check_http_clients`,
  `validate_activation_prepares_revision_health_checkers`,
  `validate_activation_probes_file_watch_notify_when_enabled`,
  `validate_activation_at_path_attaches_config_parent_watch`,
  `validate_activation_accepts_usable_acme_account_key`,
  `validate_activation_accepts_usable_acme_stored_cert_pem`,
  `test_validate_activation_builds_discovery_http_client`,
  `test_validate_activation_builds_acme_manager_when_configured`,
  `load_merged_gateway_config_probes_file_watch_when_enabled`,
  `probe_file_watch_activation_accepts_existing_paths`,
  `validate_activation_fails_closed_when_acme_storage_path_is_a_file`,
  `validate_activation_fails_closed_when_acme_storage_path_is_relative`,
  `validate_activation_fails_closed_when_acme_account_key_corrupt`,
  `validate_activation_fails_closed_when_acme_stored_cert_pem_corrupt`,
  `activate_stored_certificate_fails_closed_when_sink_rejects_unusable_pem`,
  `validate_activation_fails_closed_when_file_watch_directory_missing`,
  `probe_file_watch_activation_rejects_missing_directory`,
  `load_config_fails_closed_when_configured_directory_is_missing`,
  `watch_fails_closed_when_configured_directory_is_missing`,
  `load_merged_gateway_config_fails_closed_when_directory_missing`,
  `gateway_new_at_path_fails_closed_when_config_parent_missing`,
  `load_merged_gateway_config_fails_closed_on_missing_entrypoint_tls_pem`,
  `load_merged_gateway_config_fails_closed_when_management_token_env_unset`,
  `with_middlewares_fails_closed_on_dual_retry_with_custom_policy`,
  `generate_config_fails_closed_on_missing_port_label`,
  `generate_config_fails_closed_on_invalid_port_label`,
  `generate_config_fails_closed_on_missing_or_invalid_ip`,
  `generate_config_fails_closed_on_invalid_weight_label`,
  `generate_config_fails_closed_on_invalid_strategy_label`,
  `generate_config_fails_closed_on_invalid_priority_label`,
  `generate_config_fails_closed_on_tcp_protocol_without_listen_address`,
  `generate_config_fails_closed_on_udp_protocol_without_listen_address`,
  `generate_config_fails_closed_on_unknown_protocol_label`,
  `ingress_to_config_fails_closed_on_invalid_strategy_annotation`,
  `ingress_to_config_fails_closed_on_invalid_priority_annotation`,
  `ingress_to_config_fails_closed_on_empty_request_timeout_annotation`,
  `ingress_to_config_fails_closed_on_invalid_request_timeout_annotation`,
  `ingress_to_config_fails_closed_on_zero_backend_port`,
  `ingress_to_config_fails_closed_on_named_backend_port_without_number`,
  `ingress_to_config_fails_closed_on_tcp_without_listen`,
  `ingress_to_config_fails_closed_on_udp_without_listen`,
  `ingress_to_config_fails_closed_on_unknown_protocol_annotation`,
  `ingress_routes_to_config_fails_closed_on_invalid_backend_strategy`,
  `validate_activation_rejects_cloud_managed_bootstrap_with_inline_traffic`,
  `validate_activation_rejects_reserved_managed_service_middleware_name`,
  `validate_activation_rejects_reserved_managed_service_name_prefix`,
  `scheduled_models_fail_closed_when_worker_observations_are_absent`,
  `scheduled_models_fail_closed_when_service_has_no_configured_workers`,
  `scheduled_models_fail_closed_without_exact_managed_endpoint_ownership`,
  `expired_worker_observations_fail_closed_without_upstream_contact`,
  `validate_activation_fails_closed_when_distributed_serving_api_key_env_unset`,
  `validate_activation_fails_closed_when_distributed_serving_api_key_invalid`,
  `test_validate_udp_zero_timeout_fails_closed`,
  `test_validate_acme_without_email_fails_closed`,
  `test_validate_acme_without_domains_fails_closed`,
  `default_docker_block_fails_validate_on_windows`,
  `validate_rejects_docker_unix_socket_host_on_non_unix`,
  `validate_rejects_docker_unix_socket_host_when_path_missing`,
  `node_api_client_ca_refuses_partial_trust_anchor_load`,
  `test_management_config_rejects_client_ca_without_require_client_cert`,
  `test_management_config_rejects_empty_allowed_ips`,
  `test_management_config_rejects_empty_auth_token_env`,
  `test_validate_rejects_health_check_without_probeable_servers`,
  `test_validate_rejects_health_check_with_non_http_revision_servers`,
  `test_validate_rejects_tls_ca_file_without_https_servers`,
  `test_validate_rejects_invalid_sticky_cookie_name`,
  `test_validate_discovery_rejects_empty_seeds`,
  `test_validate_discovery_rejects_duplicate_seeds`,
  `discovery_provider_new_requires_buildable_http_client`,
  `test_load_config_rejects_non_acl_main_extension`,
  `health_checker_probe_rejects_unusable_pem`,
  `grpc_proxy_try_with_ca_file_rejects_unusable_pem`,
  `reload_disabling_acme_aborts_manager`,
  `reload_rejects_standalone_to_cloud_managed_transition`.
- Node API version/health stable; routes still serve prior config until the new
  activation succeeds.
