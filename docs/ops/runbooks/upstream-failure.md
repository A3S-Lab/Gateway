# Runbook: upstream failure

## Detect

- Elevated 5xx / timeouts toward a service; passive health or circuit breaker
  metrics show eviction; sticky clients may pin a bad backend until recovery.

## Contain

1. Prefer pool failover / revision weights over killing the Gateway process.
2. Do not lower health thresholds ad hoc in production without a rollback ACL.

## Recover

1. Fix or replace the unhealthy upstream.
2. Wait for passive `recovery_time` / circuit half-open probe success — Gateway
   re-admits without a process restart when probes succeed.
3. If the primary pool is gone, confirm failover backup receives traffic.

## Verify

- Suite: `passive_health_half_open_*`, `circuit_breaker_half_open_*`,
  `failover_routes_to_backup_on_listener_when_primary_unhealthy`,
  `active_health_check_evicts_*`,
  `active_health_redirect_does_not_follow_or_mark_healthy`,
  `build_sticky_managers_fails_closed_on_invalid_cookie_name`,
  `traffic_mirror_copies_buffered_request_to_shadow_on_listener`,
  `traffic_mirror_primary_still_succeeds_when_shadow_unreachable_on_listener`,
  `build_mirror_failover_fails_closed_when_mirror_target_missing_from_registry`,
  `build_mirror_failover_fails_closed_when_failover_target_missing_from_registry`.
- Synthetic request to the service path succeeds; error rate returns to baseline.
