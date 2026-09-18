# Runbook: network / dependency partition

## Detect

- Redis-backed rate limit returns `503` when Redis is unreachable (unless
  explicit `redis_fail_open`).
- Activation fails when Redis rate-limit URL is configured but unreachable.
- Clients may see auth `502` when forward-auth is partitioned (see listener
  runbook).

## Contain

1. Prefer fail-closed behavior; do not enable `redis_fail_open` during an
   incident unless product policy explicitly accepts bypass.
2. Isolate whether the partition is Redis, auth, or upstream DNS.

## Recover

1. Restore network path / Redis / auth endpoint.
2. Reload only if activation previously failed; a live listener already applies
   fail-closed responses without a restart.

## Verify

- Suite (default, `--features kube,redis,wire`):
  `validate_activation_fails_closed_when_redis_rate_limit_unreachable`,
  `probe_activation_rejects_unreachable_redis`,
  `rate_limit_redis_unreachable_returns_503_on_listener_without_upstream_contact`,
  `rate_limit_redis_fail_open_reaches_upstream_on_listener_when_redis_unreachable`,
  `validate_activation_fails_closed_when_forward_auth_unreachable`,
  `probe_activation_rejects_unreachable_auth_service`,
  `probe_activation_accepts_reachable_auth_service`,
  `validate_activation_probes_reachable_forward_auth`,
  `validate_activation_skips_redis_probe_when_fail_open`.
- Confirm rate-limited routes recover to expected allow/deny behavior.
