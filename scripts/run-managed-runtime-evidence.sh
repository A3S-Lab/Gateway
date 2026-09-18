#!/usr/bin/env bash
# Cross-platform Managed Runtime Service real OS-process evidence used by
# Enterprise GA smoke. Not Cloud EXIT; not a published capacity envelope.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

FILTERS=(
  real_os_process_upstream_survives_bind_health_traffic_drain_remove
  real_os_process_upstream_restart_restores_route_and_replay_preserves_identity
  real_os_process_upstream_sse_drain_waits_for_admitted_stream
  real_os_process_upstream_websocket_drain_waits_for_admitted_stream
  real_os_process_upstream_grpc_drain_waits_for_admitted_stream
)

echo "managed-runtime: running ${#FILTERS[@]} real OS-process cases"
failed=0
for filter in "${FILTERS[@]}"; do
  echo "managed-runtime: case $filter"
  output="$(mktemp)"
  set +e
  cargo test --locked --test managed_runtime_real_process "$filter" -- --nocapture >"$output" 2>&1
  status=$?
  set -e
  cat "$output"
  if (( status != 0 )); then
    echo "managed-runtime: FAIL $filter (cargo exit $status)" >&2
    failed=1
  elif grep -q 'running 0 tests' "$output"; then
    echo "managed-runtime: FAIL $filter (no tests matched filter)" >&2
    failed=1
  fi
  rm -f "$output"
done

if (( failed != 0 )); then
  echo "managed-runtime: suite failed" >&2
  exit 1
fi
echo "managed-runtime: OK"
