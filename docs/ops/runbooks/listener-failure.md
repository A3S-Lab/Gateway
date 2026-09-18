# Runbook: listener / middleware failure

## Detect

- Clients see `502` from `forward-auth` when the auth service is down, or
  middleware/policy errors instead of a successful upstream body.
- Access logs show middleware failures; Node API `GET /health` still answers if
  the process is up.

## Contain

1. Stop rolling new ACL/snapshot changes that touch the failing middleware.
2. If `forward-auth` is the cause, keep Gateway running — it already fails
   closed without contacting the primary upstream.

## Recover

1. Restore the auth/policy dependency or remove the middleware from the route
   via a validated ACL reload.
2. Confirm reload succeeds; a rejected reload leaves the prior runtime active.

## Verify

- Run the listener slice of
  [`../fault-injection.md`](../fault-injection.md)
  (`response_middleware_error_fails_closed_*`,
  `forward_auth_unreachable_returns_502_on_listener_without_upstream_contact`,
  `forward_auth_deny_returns_auth_status_on_listener_without_upstream_contact`,
  `udp_zero_session_timeout_fails_listener_policy`,
  `udp_zero_max_sessions_fails_listener_policy`,
  `tcp_invalid_allowed_ip_fails_listener_policy`,
  `acme_without_email_fails_listener_policy`,
  `managed_snapshot_expiry_rejects_new_requests_on_the_listener_with_503`,
  `managed_snapshot_expiry_rejects_new_tcp_connections_without_upstream`,
  `managed_snapshot_expiry_rejects_new_udp_datagrams_without_upstream`,
  `credential_successor_runtime_revokes_prior_key_without_upstream`,
  `grant_successor_runtime_denies_prior_model_without_upstream`,
  `managed_snapshot_apply_grant_successor_denies_withdrawn_model_without_upstream`,
  `managed_snapshot_apply_credential_successor_revokes_prior_key_without_upstream`,
  `managed_snapshot_apply_credential_generation_bump_invalidates_prior_bearer_without_upstream`,
  `managed_inference_fails_closed_before_dispatch_when_usage_capacity_is_full`,
  `managed_inference_policy_expiry_fails_closed_at_request_time`,
  `managed_inference_revoked_or_expired_credentials_fail_closed_without_upstream`,
  `fail_closed_blocks_escalation_in_upstream_response`,
  `blocks_escalation_on_response_when_fail_closed`,
  `acme_http01_challenge_is_served_from_runtime_store_before_routes`,
  `acme_certificate_install_hot_swaps_live_https_acceptor`).
- Spot-check a granted route returns `200` only after the dependency is healthy.
