#!/usr/bin/env bash
set -Eeuo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_root="$repository_root/benchmarks/proxy-comparison"
output_root="${PROXY_BENCH_OUTPUT:-$repository_root/target/proxy-comparison}"
trials="${PROXY_BENCH_TRIALS:-3}"
duration_seconds="${PROXY_BENCH_DURATION_SECONDS:-10}"
warmup_seconds="${PROXY_BENCH_WARMUP_SECONDS:-2}"
connections="${PROXY_BENCH_CONNECTIONS:-64}"
http2_connections="${PROXY_BENCH_HTTP2_CONNECTIONS:-4}"
http2_parallel="${PROXY_BENCH_HTTP2_PARALLEL:-16}"
certificate=/tmp/a3s-benchmark-cert.pem
private_key=/tmp/a3s-benchmark-key.pem
grpc_request="$output_root/grpc-request.bin"
profiles=(
  http1-small
  https-http1
  https-http2
  grpc-unary
  sse-finite
  websocket-echo
  tcp-echo
  udp-echo
  openai-json
  openai-stream
)
mkdir -p "$output_root"

upstream_pid=""
protocol_upstream_pid=""
a3s_pid=""
nginx_pid=""
benchmark_stage="initialization"

cleanup() {
  for process_id in "$a3s_pid" "$nginx_pid" "$protocol_upstream_pid" "$upstream_pid"; do
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
  printf '::error file=scripts/run-proxy-comparison.sh,line=%s,title=Protocol benchmark failed::stage=%s; exit=%s\n' \
    "$line" "$benchmark_stage" "$status"
  for log in \
    "$output_root/a3s-gateway.log" \
    "$output_root/nginx.log" \
    "$output_root/protocol-upstream.log" \
    "$output_root/upstream.log"; do
    if [[ -s "$log" ]]; then
      printf '\n===== %s (last 40 lines) =====\n' "$(basename "$log")"
      tail -n 40 "$log"
    fi
  done
}
trap 'report_failure "$?" "$LINENO"' ERR

wait_for_endpoint() {
  local url="$1"
  shift
  for _ in $(seq 1 100); do
    if curl --fail --silent --output /dev/null "$@" "$url"; then
      return 0
    fi
    sleep 0.1
  done
  echo "endpoint did not become ready: $url" >&2
  return 1
}

wait_for_tcp() {
  local port="$1"
  for _ in $(seq 1 100); do
    if timeout 1 bash -c "exec 3<>/dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  echo "TCP port did not become ready: $port" >&2
  return 1
}

proxy_port() {
  local proxy="$1"
  local a3s_port="$2"
  local nginx_port="$3"
  if [[ "$proxy" == "a3s-gateway" ]]; then
    printf '%s' "$a3s_port"
  else
    printf '%s' "$nginx_port"
  fi
}

validate_oha_result() {
  local output="$1"
  local profile="$2"
  local proxy="$3"
  python3 - "$output" "$profile" "$proxy" <<'PY'
import json
import sys

path, profile, proxy = sys.argv[1:]
try:
    payload = json.load(open(path, encoding="utf-8"))
    success_rate = float(payload["summary"]["successRate"])
except Exception as error:
    message = f"{profile} through {proxy} produced invalid oha JSON: {error}"
else:
    if success_rate >= 0.999:
        raise SystemExit(0)
    details = {
        "success_rate": success_rate,
        "status_codes": payload.get("statusCodeDistribution", {}),
        "errors": payload.get("errorDistribution", {}),
    }
    message = (
        f"{profile} through {proxy} did not reach 99.9% success: "
        f"{json.dumps(details, separators=(',', ':'))}"
    )

escaped = message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
print(f"::error title=Protocol profile returned errors::{escaped}", file=sys.stderr)
raise SystemExit(1)
PY
}

run_oha_profile() {
  local profile="$1"
  local proxy="$2"
  local output="$3"
  local seconds="$4"
  local plain_port
  local tls_port
  plain_port=$(proxy_port "$proxy" 18081 18082)
  tls_port=$(proxy_port "$proxy" 18443 18444)
  local common=(
    --no-tui
    --output-format json
    --output "$output"
    -z "${seconds}s"
  )

  case "$profile" in
    http1-small)
      oha "${common[@]}" -c "$connections" --http-version 1.1 \
        "http://127.0.0.1:${plain_port}/benchmark"
      ;;
    https-http1)
      oha "${common[@]}" -c "$connections" --http-version 1.1 --insecure \
        "https://127.0.0.1:${tls_port}/benchmark"
      ;;
    https-http2)
      oha "${common[@]}" -c "$http2_connections" -p "$http2_parallel" \
        --http2 --insecure "https://127.0.0.1:${tls_port}/benchmark"
      ;;
    grpc-unary)
      oha "${common[@]}" -c "$http2_connections" -p "$http2_parallel" \
        --http2 --insecure -m POST -T application/grpc -H "TE: trailers" \
        -D "$grpc_request" \
        "https://127.0.0.1:${tls_port}/grpc.echo.Echo/Unary"
      ;;
    sse-finite)
      oha "${common[@]}" -c "$connections" --http-version 1.1 \
        -A text/event-stream "http://127.0.0.1:${plain_port}/events"
      ;;
    openai-json)
      oha "${common[@]}" -c "$connections" --http-version 1.1 \
        -m POST -T application/json \
        -d '{"model":"bench","messages":[{"role":"user","content":"ping"}],"stream":false}' \
        "http://127.0.0.1:${plain_port}/v1/chat/completions"
      ;;
    openai-stream)
      oha "${common[@]}" -c "$connections" --http-version 1.1 \
        -m POST -T application/json \
        -d '{"model":"bench","prompt":"ping","stream":true}' \
        "http://127.0.0.1:${plain_port}/v1/completions"
      ;;
    *)
      echo "unsupported oha profile: $profile" >&2
      return 1
      ;;
  esac

  validate_oha_result "$output" "$profile" "$proxy"
}

run_protocol_profile() {
  local profile="$1"
  local proxy="$2"
  local output="$3"
  local seconds="$4"
  local protocol
  local target

  case "$profile" in
    websocket-echo)
      protocol=websocket
      target="ws://127.0.0.1:$(proxy_port "$proxy" 18081 18082)/socket"
      ;;
    tcp-echo)
      protocol=tcp
      target="127.0.0.1:$(proxy_port "$proxy" 19081 19083)"
      ;;
    udp-echo)
      protocol=udp
      target="127.0.0.1:$(proxy_port "$proxy" 19082 19084)"
      ;;
    *)
      echo "unsupported protocol-load profile: $profile" >&2
      return 1
      ;;
  esac

  timeout "$((seconds + 30))s" \
    "$repository_root/target/release/examples/protocol_benchmark_load" \
      --protocol "$protocol" \
      --target "$target" \
      --connections "$connections" \
      --duration-seconds "$seconds" \
      --payload-bytes 32 \
      --output "$output"
}

run_profile() {
  local profile="$1"
  local proxy="$2"
  local output="$3"
  local seconds="$4"
  case "$profile" in
    websocket-echo|tcp-echo|udp-echo)
      run_protocol_profile "$profile" "$proxy" "$output" "$seconds"
      ;;
    *)
      run_oha_profile "$profile" "$proxy" "$output" "$seconds"
      ;;
  esac
}

benchmark_stage="generate TLS fixture"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout "$private_key" \
  -out "$certificate" >/dev/null 2>&1
printf '\x00\x00\x00\x00\x00' >"$grpc_request"

benchmark_stage="validate A3S Gateway configuration"
"$repository_root/target/release/a3s-gateway" validate \
  --config "$fixture_root/gateway.acl"
benchmark_stage="validate NGINX upstream configuration"
nginx -t -c "$fixture_root/nginx-upstream.conf"
benchmark_stage="validate NGINX gateway configuration"
nginx -t -c "$fixture_root/nginx-gateway.conf"

benchmark_stage="start benchmark upstreams"
nginx -c "$fixture_root/nginx-upstream.conf" -g 'daemon off;' \
  >"$output_root/upstream.log" 2>&1 &
upstream_pid=$!
"$repository_root/target/release/examples/protocol_benchmark_upstream" \
  >"$output_root/protocol-upstream.log" 2>&1 &
protocol_upstream_pid=$!

benchmark_stage="wait for benchmark upstreams"
wait_for_endpoint "http://127.0.0.1:18080/benchmark"
wait_for_tcp 18090
wait_for_tcp 18091
wait_for_tcp 18093

benchmark_stage="start A3S Gateway and NGINX"
nginx -c "$fixture_root/nginx-gateway.conf" -g 'daemon off;' \
  >"$output_root/nginx.log" 2>&1 &
nginx_pid=$!
"$repository_root/target/release/a3s-gateway" --config "$fixture_root/gateway.acl" \
  >"$output_root/a3s-gateway.log" 2>&1 &
a3s_pid=$!

benchmark_stage="wait for A3S Gateway and NGINX"
wait_for_endpoint "http://127.0.0.1:18081/benchmark"
wait_for_endpoint "http://127.0.0.1:18082/benchmark"
wait_for_endpoint "https://127.0.0.1:18443/benchmark" --insecure
wait_for_endpoint "https://127.0.0.1:18444/benchmark" --insecure
wait_for_tcp 19081
wait_for_tcp 19083

for profile in "${profiles[@]}"; do
  benchmark_stage="warm up ${profile} through A3S Gateway"
  run_profile "$profile" a3s-gateway \
    "$output_root/warmup-${profile}-a3s-gateway.json" "$warmup_seconds"
  benchmark_stage="warm up ${profile} through NGINX"
  run_profile "$profile" nginx \
    "$output_root/warmup-${profile}-nginx.json" "$warmup_seconds"
done

for trial in $(seq 1 "$trials"); do
  if (( trial % 2 == 1 )); then
    order=(a3s-gateway nginx)
  else
    order=(nginx a3s-gateway)
  fi
  for profile in "${profiles[@]}"; do
    for proxy in "${order[@]}"; do
      benchmark_stage="measure ${profile} trial ${trial} through ${proxy}"
      echo "running $profile trial $trial for $proxy"
      run_profile "$profile" "$proxy" \
        "$output_root/${profile}-${proxy}-${trial}.json" "$duration_seconds"
      sleep 1
    done
  done
done

benchmark_stage="export multi-protocol comparison"
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
  --oha-version "$(oha --version)" \
  --trials "$trials" \
  --duration-seconds "$duration_seconds" \
  --warmup-seconds "$warmup_seconds" \
  --connections "$connections" \
  --http2-connections "$http2_connections" \
  --http2-parallel "$http2_parallel"
