#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_root="$repository_root/benchmarks/ai-gateway-comparison"
output_root="${AI_BENCH_OUTPUT:-$repository_root/target/ai-gateway-comparison}"
export_path="${AI_BENCH_EXPORT:-$repository_root/website/assets/ai-gateway-comparison.json}"
trials="${AI_BENCH_TRIALS:-5}"
profile_csv="${AI_BENCH_PROFILES:-stream-overhead-c1,stream-overhead-c64,stream-paced-c16,stream-paced-c64,stream-long-output,completions-paced-c16,prompt-32k,prompt-256k}"
batch_timeout_seconds="${AI_BENCH_BATCH_TIMEOUT_SECONDS:-300}"
binary_root="${AI_BENCH_BINARY_ROOT:-$repository_root/target/release}"
upstream_binary="$binary_root/examples/ai_benchmark_upstream"
load_binary="$binary_root/examples/ai_benchmark_load"
gateway_binary="$binary_root/a3s-gateway"

IFS=',' read -r -a profiles <<<"$profile_csv"
mkdir -p "$output_root"

upstream_pid=""
a3s_pid=""
nginx_pid=""
load_log=""
benchmark_stage="initialization"

cleanup() {
  for process_id in "$a3s_pid" "$nginx_pid" "$upstream_pid"; do
    if [[ -n "$process_id" ]] && kill -0 "$process_id" 2>/dev/null; then
      kill "$process_id" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT

report_failure() {
  local status="$1"
  local line="$2"
  trap - ERR
  set +e
  printf '::error file=scripts/run-ai-gateway-comparison.sh,line=%s,title=AI gateway benchmark failed::stage=%s; exit=%s\n' \
    "$line" "$benchmark_stage" "$status"
  for log in \
    "$load_log" \
    "$output_root/a3s-gateway.log" \
    "$output_root/nginx.log" \
    "$output_root/upstream.log"; do
    if [[ -n "$log" && -s "$log" ]]; then
      printf '\n===== %s (last 60 lines) =====\n' "$(basename "$log")"
      tail -n 60 "$log"
    fi
  done
}
trap 'report_failure "$?" "$LINENO"' ERR

require_positive_integer() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "$name must be a positive integer, got: $value" >&2
    return 1
  fi
}

require_binary() {
  local path="$1"
  if [[ ! -x "$path" ]]; then
    echo "required executable is missing: $path" >&2
    return 1
  fi
}

assert_process_running() {
  local process_id="$1"
  local name="$2"
  if ! kill -0 "$process_id" 2>/dev/null; then
    echo "$name exited before its readiness check completed" >&2
    return 1
  fi
}

wait_for_endpoint() {
  local url="$1"
  for _ in $(seq 1 150); do
    if curl --fail --silent --output /dev/null "$url"; then
      return 0
    fi
    sleep 0.1
  done
  echo "endpoint did not become ready: $url" >&2
  return 1
}

configure_profile() {
  local profile="$1"
  endpoint=chat
  model=bench
  request_timeout_seconds=120
  case "$profile" in
    stream-overhead-c1)
      concurrency=1
      requests=128
      warmup_requests=8
      token_count=32
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1024
      ;;
    stream-overhead-c64)
      concurrency=64
      requests=256
      warmup_requests=64
      token_count=32
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1024
      ;;
    stream-paced-c16)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      ;;
    stream-paced-c64)
      concurrency=64
      requests=128
      warmup_requests=64
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      ;;
    stream-long-output)
      concurrency=16
      requests=32
      warmup_requests=16
      token_count=256
      first_token_delay_ms=50
      token_interval_ms=2
      prompt_bytes=1024
      ;;
    completions-paced-c16)
      endpoint=completions
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      ;;
    prompt-32k)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=32768
      ;;
    prompt-256k)
      concurrency=8
      requests=32
      warmup_requests=8
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=262144
      ;;
    *)
      echo "unsupported AI benchmark profile: $profile" >&2
      return 1
      ;;
  esac
}

product_port() {
  if [[ "$1" == "a3s-gateway" ]]; then
    printf '18101'
  else
    printf '18102'
  fi
}

run_profile() {
  local profile="$1"
  local product="$2"
  local trial="$3"
  local output="$output_root/${profile}-${product}-${trial}.json"
  local port
  port=$(product_port "$product")
  configure_profile "$profile"
  load_log="$output_root/${profile}-${product}-${trial}.log"
  timeout "${batch_timeout_seconds}s" "$load_binary" \
    --target "http://127.0.0.1:${port}" \
    --endpoint "$endpoint" \
    --model "$model" \
    --concurrency "$concurrency" \
    --requests "$requests" \
    --warmup-requests "$warmup_requests" \
    --token-count "$token_count" \
    --first-token-delay-ms "$first_token_delay_ms" \
    --token-interval-ms "$token_interval_ms" \
    --prompt-bytes "$prompt_bytes" \
    --request-timeout-seconds "$request_timeout_seconds" \
    --product "$product" \
    --trial "$trial" \
    --output "$output" \
    >"$load_log" 2>&1
}

require_positive_integer AI_BENCH_TRIALS "$trials"
require_positive_integer AI_BENCH_BATCH_TIMEOUT_SECONDS "$batch_timeout_seconds"
if (( ${#profiles[@]} == 0 )); then
  echo "AI_BENCH_PROFILES must contain at least one profile" >&2
  exit 1
fi
for profile in "${profiles[@]}"; do
  configure_profile "$profile"
done
require_binary "$gateway_binary"
require_binary "$upstream_binary"
require_binary "$load_binary"
command -v curl >/dev/null
command -v nginx >/dev/null
command -v python3 >/dev/null
command -v timeout >/dev/null

benchmark_stage="validate A3S Gateway fixture"
"$gateway_binary" validate --config "$fixture_root/gateway.acl"
benchmark_stage="validate NGINX fixture"
nginx -t -c "$fixture_root/nginx.conf"

benchmark_stage="start deterministic OpenAI-compatible upstream"
"$upstream_binary" >"$output_root/upstream.log" 2>&1 &
upstream_pid=$!
assert_process_running "$upstream_pid" "deterministic upstream"
wait_for_endpoint "http://127.0.0.1:18100/health"

benchmark_stage="start A3S Gateway"
"$gateway_binary" --config "$fixture_root/gateway.acl" --log-level warn \
  >"$output_root/a3s-gateway.log" 2>&1 &
a3s_pid=$!
assert_process_running "$a3s_pid" "A3S Gateway"

benchmark_stage="start NGINX"
nginx -c "$fixture_root/nginx.conf" -g 'daemon off;' \
  >"$output_root/nginx.log" 2>&1 &
nginx_pid=$!
assert_process_running "$nginx_pid" "NGINX"

benchmark_stage="wait for proxy health routes"
wait_for_endpoint "http://127.0.0.1:18101/health"
wait_for_endpoint "http://127.0.0.1:18102/health"

for trial in $(seq 1 "$trials"); do
  if (( trial % 2 == 1 )); then
    order=(a3s-gateway nginx)
  else
    order=(nginx a3s-gateway)
  fi
  for profile in "${profiles[@]}"; do
    for product in "${order[@]}"; do
      benchmark_stage="measure ${profile} trial ${trial} through ${product}"
      echo "running $profile trial $trial through $product"
      run_profile "$profile" "$product" "$trial"
      sleep 0.25
    done
  done
done

profile_argument=$(IFS=,; printf '%s' "${profiles[*]}")
benchmark_stage="export token-aware AI comparison"
python3 "$repository_root/scripts/export-ai-gateway-comparison.py" \
  --input "$output_root" \
  --output "$export_path" \
  --profiles "$profile_argument" \
  --trials "$trials" \
  --commit "${GITHUB_SHA:-$(git -C "$repository_root" rev-parse HEAD)}" \
  --run-url "${RUN_URL:-local}" \
  --generated-at "${GENERATED_AT:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
  --runner-image "${RUNNER_IMAGE:-local}" \
  --cpu-model "${CPU_MODEL:-unknown}" \
  --logical-cpus "${LOGICAL_CPUS:-$(nproc)}" \
  --memory-mib "${MEMORY_MIB:-0}" \
  --kernel "${KERNEL_VERSION:-$(uname -srmo)}" \
  --a3s-version "$("$gateway_binary" --version)" \
  --nginx-version "$(nginx -v 2>&1)" \
  --upstream-version "$("$upstream_binary" --version)" \
  --load-version "$("$load_binary" --version)"
