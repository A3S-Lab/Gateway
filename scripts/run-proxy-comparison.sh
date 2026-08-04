#!/usr/bin/env bash
set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_root="$repository_root/benchmarks/proxy-comparison"
output_root="${PROXY_BENCH_OUTPUT:-$repository_root/target/proxy-comparison}"
trials="${PROXY_BENCH_TRIALS:-5}"
duration_seconds="${PROXY_BENCH_DURATION_SECONDS:-15}"
threads="${PROXY_BENCH_THREADS:-4}"
connections="${PROXY_BENCH_CONNECTIONS:-64}"
mkdir -p "$output_root"

upstream_pid=""
a3s_pid=""
nginx_pid=""

cleanup() {
  for process_id in "$a3s_pid" "$nginx_pid" "$upstream_pid"; do
    if [[ -n "$process_id" ]] && kill -0 "$process_id" 2>/dev/null; then
      kill "$process_id" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

wait_for_endpoint() {
  local url="$1"
  for _ in $(seq 1 100); do
    if curl --fail --silent --output /dev/null "$url"; then
      return 0
    fi
    sleep 0.1
  done
  echo "endpoint did not become ready: $url" >&2
  return 1
}

nginx -c "$fixture_root/nginx-upstream.conf" -g 'daemon off;' >"$output_root/upstream.log" 2>&1 &
upstream_pid=$!
nginx -c "$fixture_root/nginx-gateway.conf" -g 'daemon off;' >"$output_root/nginx.log" 2>&1 &
nginx_pid=$!
"$repository_root/target/release/a3s-gateway" --config "$fixture_root/gateway.acl" >"$output_root/a3s-gateway.log" 2>&1 &
a3s_pid=$!

wait_for_endpoint "http://127.0.0.1:18080/benchmark"
wait_for_endpoint "http://127.0.0.1:18081/benchmark"
wait_for_endpoint "http://127.0.0.1:18082/benchmark"

wrk -t2 -c32 -d5s "http://127.0.0.1:18081/benchmark" >/dev/null
wrk -t2 -c32 -d5s "http://127.0.0.1:18082/benchmark" >/dev/null

for trial in $(seq 1 "$trials"); do
  if (( trial % 2 == 1 )); then
    order=(a3s-gateway nginx)
  else
    order=(nginx a3s-gateway)
  fi
  for proxy in "${order[@]}"; do
    if [[ "$proxy" == "a3s-gateway" ]]; then
      port=18081
    else
      port=18082
    fi
    wrk -t"$threads" -c"$connections" -d"${duration_seconds}s" --latency \
      "http://127.0.0.1:${port}/benchmark" >"$output_root/$proxy-$trial.txt"
    sleep 1
  done
done

python3 "$repository_root/scripts/export-proxy-comparison.py" \
  --input "$output_root" \
  --output "$repository_root/website/assets/performance-comparison.json" \
  --commit "${GITHUB_SHA:-$(git -C "$repository_root" rev-parse HEAD)}" \
  --run-url "${RUN_URL:-local}" \
  --generated-at "${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
  --runner-image "${RUNNER_IMAGE:-local}" \
  --cpu-model "${CPU_MODEL:-unknown}" \
  --logical-cpus "${LOGICAL_CPUS:-$(nproc)}" \
  --memory-mib "${MEMORY_MIB:-0}" \
  --kernel "${KERNEL_VERSION:-$(uname -srmo)}" \
  --a3s-version "$("$repository_root/target/release/a3s-gateway" --version)" \
  --nginx-version "$(nginx -v 2>&1)" \
  --trials "$trials" \
  --duration-seconds "$duration_seconds" \
  --threads "$threads" \
  --connections "$connections"
