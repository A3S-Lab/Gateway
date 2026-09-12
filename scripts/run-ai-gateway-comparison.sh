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

IFS=',' read -r -a raw_profiles <<<"$profile_csv"
# Expand meta profile names into concrete measurement points. Do not treat a
# single concurrency as a "sweep".
profiles=()
for profile in "${raw_profiles[@]}"; do
  case "$profile" in
    concurrency-sweep)
      profiles+=(
        concurrency-sweep-c1
        concurrency-sweep-c4
        concurrency-sweep-c16
        concurrency-sweep-c64
        concurrency-sweep-c256
        concurrency-sweep-c1024
      )
      ;;
    *)
      profiles+=("$profile")
      ;;
  esac
done
mkdir -p "$output_root"

upstream_pid=""
canary_upstream_pid=""
ipv6_upstream_pid=""
upstream_tls_mode=0
tls_upstream_cert="$repository_root/tests/fixtures/tls/revision-1.crt"
tls_upstream_key="$repository_root/tests/fixtures/tls/revision-1.key"
tls_upstream_ca="$repository_root/tests/fixtures/tls/revision-1-ca.crt"
a3s_pid=""
nginx_pid=""
load_log=""
benchmark_stage="initialization"

cleanup() {
  for process_id in "$a3s_pid" "$nginx_pid" "$upstream_pid" "$canary_upstream_pid" "$ipv6_upstream_pid"; do
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
  local excerpt
  trap - ERR
  set +e
  printf '::error file=scripts/run-ai-gateway-comparison.sh,line=%s,title=AI gateway benchmark failed::stage=%s; exit=%s\n' \
    "$line" "$benchmark_stage" "$status"
  for log in \
    "$load_log" \
    "$output_root/a3s-gateway.log" \
    "$output_root/nginx.log" \
    "$output_root/upstream.log" \
    "$output_root/upstream-canary.log"; do
    if [[ -n "$log" && -s "$log" ]]; then
      printf '\n===== %s (last 60 lines) =====\n' "$(basename "$log")"
      tail -n 60 "$log"
      excerpt="$(tail -n 20 "$log")"
      excerpt="${excerpt//'%'/'%25'}"
      excerpt="${excerpt//$'\r'/'%0D'}"
      excerpt="${excerpt//$'\n'/'%0A'}"
      printf '::error title=%s tail::%s\n' "$(basename "$log")" "$excerpt"
    fi
  done
  exit "$status"
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
  shift
  for _ in $(seq 1 150); do
    if curl --fail --silent --output /dev/null "$@" "$url"; then
      return 0
    fi
    sleep 0.1
  done
  echo "endpoint did not become ready: $url" >&2
  return 1
}

# After HTTP 5xx fault lanes, Gateway passive health may quarantine the shared
# upstream. Wait for half-open recovery plus one healthy chat stream before the
# next profile so later lanes are not poisoned. Do not disable passive health.
wait_for_fault_lane_recovery() {
  local product="$1"
  local port
  port=$(product_port "$product")
  local url="http://127.0.0.1:${port}/v1/chat/completions"
  local body='{"model":"bench","messages":[{"role":"user","content":"p"}],"stream":true,"benchmark":{"first_token_delay_ms":0,"token_interval_ms":0,"token_count":1}}'
  local _
  for _ in $(seq 1 60); do
    if curl --fail --silent --show-error \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data "$body" \
      --max-time 5 \
      "$url" >/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  echo "proxy did not recover a healthy upstream after fault lane: $product" >&2
  return 1
}

# Trip primary quarantine so FailoverSelector / nginx backup can serve the
# measured complete-stream batch. Failures are expected until failover engages;
# success ends the trip. Re-run before every trial (half-open recovery is 10s).
trip_fallback_quarantine() {
  local product="$1"
  local port
  port=$(product_port "$product")
  local url="http://127.0.0.1:${port}/v1/chat/completions"
  local body='{"model":"bench","messages":[{"role":"user","content":"p"}],"stream":true,"benchmark":{"first_token_delay_ms":0,"token_interval_ms":0,"token_count":1}}'
  local _
  for _ in $(seq 1 24); do
    if curl --fail --silent --show-error \
      -H 'Content-Type: application/json' \
      -H 'Accept: text/event-stream' \
      --data "$body" \
      --max-time 5 \
      "$url" >/dev/null; then
      return 0
    fi
  done
  echo "fallback quarantine did not engage a healthy backup for: $product" >&2
  return 1
}

configure_profile() {
  local profile="$1"
  endpoint=chat
  model=bench
  request_timeout_seconds=120
  disconnect_after_tokens=""
  read_delay_ms=""
  stall_after_tokens=""
  stall_ms=""
  upstream_fault=""
  tokens_per_write=1
  fragments_per_event=1
  unicode_payload=0
  no_stream=0
  long_every=""
  long_token_count=""
  poisson_arrival_rps=""
  arrival_seed=""
  response_bytes=""
  target_body_bytes=""
  declare_content_length=""
  chunked_upload_frames=""
  require_all_rejections=0
  timeout_fixture=0
  refused_fixture=0
  blackhole_fixture=0
  telemetry_fixture=0
  fallback_fixture=0
  weighted_fixture=0
  ratelimit_fixture=0
  apikey_fixture=0
  noreplay_fixture=0
  request_buffering_off_fixture=0
  disk_spill_fixture=0
  gateway_restart_fixture=0
  a3s_only=0
  expect_proxy_error=0
  accept_http_status=""
  api_key=""
  omit_api_key_every=""
  send_idempotency_key=0
  force_connection_close=0
  tls_fixture=0
  upstream_tls_fixture=0
  ipv6_fixture=0
  use_http2=0
  target_scheme=http
  target_host=127.0.0.1
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
    sse-transport-c1)
      # Same C1 schedule as stream-overhead-c1 on /benchmark/sse (no OpenAI JSON).
      endpoint=sse-transport
      concurrency=1
      requests=128
      warmup_requests=8
      token_count=32
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1024
      ;;
    sse-transport-c64)
      # Same C64 schedule as stream-overhead-c64 on /benchmark/sse (no OpenAI JSON).
      endpoint=sse-transport
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
    disk-spill)
      # Same paced 32 KiB prompt as prompt-32k; NGINX uses a 16 KiB client body
      # buffer and a dedicated temp volume so the body spills to disk. A3S stays
      # on in-memory OpenAI validation (gateway.acl).
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=32768
      disk_spill_fixture=1
      ;;
    gateway-restart)
      # Kill and restart the product under test with the same standalone
      # ACL/conf (desired state), record kill→/health recovery_ms, then measure
      # paced complete-stream availability. Not Cloud managed-snapshot EXIT.
      concurrency=16
      requests=64
      warmup_requests=0
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      gateway_restart_fixture=1
      ;;
    prompt-1k)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
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
    prompt-1m)
      concurrency=4
      requests=16
      warmup_requests=4
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1048576
      ;;
    prompt-limit)
      # Exact OpenAI/Gateway 8 MiB body ceiling must still complete the stream.
      # Serialize large bodies: concurrent 8 MiB uploads flake on client send.
      concurrency=1
      requests=4
      warmup_requests=0
      token_count=4
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1
      target_body_bytes=$((8 * 1024 * 1024))
      ;;
    prompt-over-limit)
      # Declared Content-Length one byte past the 8 MiB ceiling → 413 before
      # body read (matches entrypoint unit coverage); no upstream work.
      concurrency=8
      requests=32
      warmup_requests=0
      token_count=4
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1
      declare_content_length=$((8 * 1024 * 1024 + 1))
      accept_http_status=413
      require_all_rejections=1
      ;;
    json-short)
      # Non-streaming JSON chat completion; E2E only (no TTFT/ITL).
      concurrency=16
      requests=64
      warmup_requests=8
      token_count=16
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1024
      no_stream=1
      ;;
    json-large)
      # Multi-MiB non-streaming completion body relay (E2E only).
      concurrency=4
      requests=16
      warmup_requests=2
      token_count=1
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      no_stream=1
      response_bytes=$((2 * 1024 * 1024))
      ;;
    chunked-upload)
      # Unknown content length: OpenAI JSON body split across chunked frames.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=32768
      chunked_upload_frames=16
      ;;
    request-buffering-on)
      # Same chunked-upload schedule; NGINX keeps proxy_request_buffering on
      # (default nginx.conf). A3S OpenAI validation path is unchanged.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=32768
      chunked_upload_frames=16
      ;;
    request-buffering-off)
      # Same schedule as request-buffering-on; NGINX streams the request body
      # with proxy_request_buffering off. A3S still uses gateway.acl validation.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=32768
      chunked_upload_frames=16
      request_buffering_off_fixture=1
      ;;
    thundering-herd)
      # Synchronized barrier release of many concurrent streams (load client
      # Barrier already gates worker start).
      concurrency=256
      requests=256
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      ;;
    concurrency-sweep-c1|concurrency-sweep-c4|concurrency-sweep-c16|concurrency-sweep-c64|concurrency-sweep-c256|concurrency-sweep-c1024)
      # Fixed short-stream workload; only concurrency changes so the saturation
      # curve is comparable. Meta name `concurrency-sweep` expands to all six.
      concurrency="${profile##*-c}"
      if (( concurrency < 32 )); then
        requests=32
      else
        requests=$concurrency
      fi
      if (( concurrency < 8 )); then
        warmup_requests=$concurrency
      else
        warmup_requests=8
      fi
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      ;;
    mixed-short-long)
      # 90% short (16 tokens) / 10% long (1024 tokens) in one batch.
      concurrency=64
      requests=100
      warmup_requests=16
      token_count=16
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=1024
      long_every=10
      long_token_count=1024
      ;;
    steady-arrival)
      # Seeded Poisson open-loop arrivals (not fixed-rate renamed). Concurrency
      # is max in-flight; schedule + seed are published in the trial scenario.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=16
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=512
      poisson_arrival_rps=32
      arrival_seed=20260912
      ;;
    transport-keepalive)
      # Explicit keep-alive reuse dimension (default pool). Pair with
      # transport-churn; do not claim HTTP/2 or TLS from this lane.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      ;;
    transport-churn)
      # Same short-stream workload with Connection: close and idle pool size 0.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      force_connection_close=1
      ;;
    transport-tls-http1)
      # Downstream TLS termination, HTTP/1.1; upstream stays plain HTTP.
      # Dual-product via gateway-tls.acl / nginx-tls.conf.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      tls_fixture=1
      target_scheme=https
      ;;
    transport-tls-http2)
      # Downstream TLS + HTTP/2 ALPN; same short-stream workload as http1 lane.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      tls_fixture=1
      use_http2=1
      target_scheme=https
      ;;
    transport-ipv6)
      # Same short-stream workload over IPv6 loopback end-to-end (not mixed v4/v6).
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      ipv6_fixture=1
      target_host="[::1]"
      ;;
    transport-upstream-tls)
      # Plain HTTP downstream; HTTPS upstream verified with tls_ca_file / nginx
      # proxy_ssl_trusted_certificate (private CA). No production skip-verify.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_tls_fixture=1
      ;;
    disconnect-before-token)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      disconnect_after_tokens=0
      ;;
    disconnect-after-token)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      disconnect_after_tokens=1
      ;;
    slow-reader)
      # Client sleep after each token exceeds upstream cadence so the proxy
      # must apply backpressure without dropping completed-stream correctness.
      concurrency=16
      requests=32
      warmup_requests=8
      token_count=16
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      read_delay_ms=50
      ;;
    stalled-reader)
      # Pause reading once mid-stream, then resume to [DONE], so idle handling
      # and peer isolation can be measured without incomplete-stream mixing.
      concurrency=16
      requests=32
      warmup_requests=8
      token_count=16
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      stall_after_tokens=4
      stall_ms=500
      ;;
    http-503)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_fault=http-503
      ;;
    http-500)
      # Upstream 500 trips passive health (default threshold 5). Keep the batch
      # under that threshold so samples stay upstream 500 — not gateway
      # "No healthy backends" 503 (unlike http-503, where both look like 503).
      concurrency=1
      requests=4
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_fault=http-500
      ;;
    http-429)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_fault=http-429
      ;;
    missing-done)
      concurrency=8
      requests=32
      warmup_requests=8
      token_count=8
      first_token_delay_ms=5
      token_interval_ms=5
      prompt_bytes=256
      upstream_fault=missing-done
      ;;
    reset-before-token)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_fault=reset-before-token
      ;;
    reset-after-token)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=5
      token_interval_ms=5
      prompt_bytes=256
      upstream_fault=reset-after-token
      ;;
    malformed-sse)
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      upstream_fault=malformed-sse
      ;;
    first-token-timeout)
      concurrency=8
      requests=16
      warmup_requests=4
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=15
      upstream_fault=hold-first-token
      timeout_fixture=1
      ;;
    midstream-idle)
      concurrency=8
      requests=16
      warmup_requests=4
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=15
      upstream_fault=midstream-idle
      timeout_fixture=1
      ;;
    headers-timeout)
      concurrency=8
      requests=16
      warmup_requests=4
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=15
      upstream_fault=hold-headers
      timeout_fixture=1
      ;;
    total-timeout)
      concurrency=4
      requests=8
      warmup_requests=2
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=20
      prompt_bytes=256
      request_timeout_seconds=15
      upstream_fault=endless-stream
      timeout_fixture=1
      ;;
    connect-refused)
      concurrency=8
      requests=32
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=10
      expect_proxy_error=1
      refused_fixture=1
      ;;
    connect-timeout)
      concurrency=4
      requests=8
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=15
      expect_proxy_error=1
      blackhole_fixture=1
      ;;
    telemetry-on)
      # Same paced C16 schedule as stream-paced-c16, with observability enabled.
      # NGINX has no pinned equivalent module in this suite (A3S-only absolute).
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      telemetry_fixture=1
      a3s_only=1
      ;;
    telemetry-off)
      # Matching paced C16 schedule with observability disabled (default fixture).
      # Pair with telemetry-on for feature-cost deltas; A3S-only absolute.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=50
      token_interval_ms=10
      prompt_bytes=1024
      a3s_only=1
      ;;
    fallback)
      # Primary closed port; runner trips passive health / nginx max_fails,
      # then measured complete-stream batch recovers via failover/backup.
      concurrency=8
      requests=32
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      request_timeout_seconds=30
      fallback_fixture=1
      ;;
    stream-bursty)
      # Eight SSE token events per upstream write; client must count events,
      # not HTTP chunks. Dual-product complete-stream lane.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      tokens_per_write=8
      ;;
    stream-fragmented)
      # Each SSE event split across four write frames; incremental reassembly.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=32
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      fragments_per_event=4
      ;;
    stream-unicode)
      # UTF-8 content, multiline data lines, mid-codepoint write cuts.
      concurrency=16
      requests=64
      warmup_requests=16
      token_count=16
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      fragments_per_event=4
      unicode_payload=1
      ;;
    weighted-rollout)
      # Static 90/10 stable:canary revision split; load records instance_distribution.
      concurrency=16
      requests=200
      warmup_requests=20
      token_count=4
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      weighted_fixture=1
      ;;
    rate-limit)
      # Token-bucket / limit_req mixed admit+429; prove rejection accuracy.
      concurrency=16
      requests=64
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      ratelimit_fixture=1
      accept_http_status=429
      ;;
    api-key-auth)
      # Authorization Bearer gate; mix valid key with omitted key → 401.
      # A3S-only until NGINX ships a pinned auth module equivalent.
      concurrency=16
      requests=64
      warmup_requests=0
      token_count=8
      first_token_delay_ms=0
      token_interval_ms=0
      prompt_bytes=256
      apikey_fixture=1
      a3s_only=1
      api_key=bench-secret
      omit_api_key_every=2
      accept_http_status=401
      ;;
    no-replay-after-token)
      # Primary resets after token 1; failover/backup + retry must not open a
      # second upstream stream for the same request (stream safety).
      concurrency=8
      requests=32
      warmup_requests=0
      token_count=8
      first_token_delay_ms=5
      token_interval_ms=5
      prompt_bytes=256
      noreplay_fixture=1
      upstream_fault=reset-after-token
      send_idempotency_key=1
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

proxy_fixture_mode="normal"

stop_proxies() {
  for process_id in "$a3s_pid" "$nginx_pid"; do
    if [[ -n "$process_id" ]] && kill -0 "$process_id" 2>/dev/null; then
      kill "$process_id" 2>/dev/null || true
    fi
  done
  wait 2>/dev/null || true
  a3s_pid=""
  nginx_pid=""
}

now_ms() {
  python3 -c 'import time; print(int(time.time() * 1000))'
}

# Kill and restart one proxy process with the default standalone fixture.
# Prints recovery milliseconds from kill start until /health is ready.
restart_proxy_product() {
  local product="$1"
  local started ready recovery_ms
  # Lifecycle lane pins the default desired-state fixtures; other modes have
  # their own transport/policy semantics and must not share this path.
  if [[ "$proxy_fixture_mode" != "normal" ]]; then
    echo "gateway-restart requires the normal proxy fixture, got: $proxy_fixture_mode" >&2
    return 1
  fi
  started=$(now_ms)
  if [[ "$product" == "a3s-gateway" ]]; then
    if [[ -n "$a3s_pid" ]]; then
      kill "$a3s_pid" 2>/dev/null || true
      wait "$a3s_pid" 2>/dev/null || true
      a3s_pid=""
    fi
    benchmark_stage="restart A3S Gateway (normal)"
    "$gateway_binary" --config "$fixture_root/gateway.acl" --log-level warn \
      >"$output_root/a3s-gateway.log" 2>&1 &
    a3s_pid=$!
    assert_process_running "$a3s_pid" "A3S Gateway"
    wait_for_endpoint "http://127.0.0.1:18101/health"
  else
    if [[ -n "$nginx_pid" ]]; then
      kill "$nginx_pid" 2>/dev/null || true
      wait "$nginx_pid" 2>/dev/null || true
      nginx_pid=""
    fi
    benchmark_stage="restart NGINX (normal)"
    nginx -c "$fixture_root/nginx.conf" -g 'daemon off;' \
      >"$output_root/nginx.log" 2>&1 &
    nginx_pid=$!
    assert_process_running "$nginx_pid" "NGINX"
    wait_for_endpoint "http://127.0.0.1:18102/health"
  fi
  ready=$(now_ms)
  recovery_ms=$((ready - started))
  if (( recovery_ms < 0 )); then
    echo "gateway-restart recovery clock went backwards" >&2
    return 1
  fi
  printf '%s' "$recovery_ms"
}

# Copy self-signed AI TLS material to the shared /tmp paths referenced by
# nginx-tls.conf (and optional absolute-path consumers). Idempotent.
ensure_ai_tls_material() {
  cp -f "$fixture_root/certs/bench.crt" /tmp/a3s-ai-bench-cert.pem
  cp -f "$fixture_root/certs/bench.key" /tmp/a3s-ai-bench-key.pem
}

# Create the NGINX client-body spill volume referenced by nginx-disk-spill.conf
# and record its absolute path beside trial artifacts for fairness audits.
ensure_ai_disk_spill_volume() {
  local volume="${AI_BENCH_DISK_SPILL_VOLUME:-/tmp/a3s-ai-bench-client-body}"
  mkdir -p "$volume"
  # nginx levels 1 2 expect the path to exist and be writable.
  printf '%s\n' "$volume" >"$output_root/disk-spill-volume.txt"
}

# Copy private upstream CA material for NGINX proxy_ssl_trusted_certificate.
ensure_ai_upstream_tls_material() {
  cp -f "$tls_upstream_ca" /tmp/a3s-ai-upstream-ca.pem
}

start_stable_upstream() {
  local tls="$1"
  if [[ -n "$upstream_pid" ]] && kill -0 "$upstream_pid" 2>/dev/null; then
    kill "$upstream_pid" 2>/dev/null || true
    wait "$upstream_pid" 2>/dev/null || true
    upstream_pid=""
  fi
  if [[ "$tls" == "1" ]]; then
    ensure_ai_upstream_tls_material
    benchmark_stage="start TLS upstream (stable)"
    "$upstream_binary" --address 127.0.0.1:18100 --instance-id stable \
      --tls-cert "$tls_upstream_cert" --tls-key "$tls_upstream_key" \
      >"$output_root/upstream.log" 2>&1 &
    upstream_pid=$!
    assert_process_running "$upstream_pid" "deterministic upstream TLS (stable)"
    wait_for_endpoint "https://127.0.0.1:18100/health" --insecure
    upstream_tls_mode=1
  else
    benchmark_stage="start plain upstream (stable)"
    "$upstream_binary" --address 127.0.0.1:18100 --instance-id stable \
      >"$output_root/upstream.log" 2>&1 &
    upstream_pid=$!
    assert_process_running "$upstream_pid" "deterministic upstream (stable)"
    wait_for_endpoint "http://127.0.0.1:18100/health"
    upstream_tls_mode=0
  fi
}

ensure_upstream_tls_mode() {
  local want="$1"
  if [[ "$upstream_tls_mode" == "$want" ]]; then
    return 0
  fi
  # Proxies pin keep-alive to the previous upstream scheme; recycle them after
  # flipping the stable listener between plain HTTP and HTTPS.
  stop_proxies
  proxy_fixture_mode=""
  start_stable_upstream "$want"
}

start_proxies() {
  local mode="$1"
  local gateway_config nginx_config
  if [[ "$mode" == "timeout" ]]; then
    gateway_config="$fixture_root/gateway-timeout.acl"
    nginx_config="$fixture_root/nginx-timeout.conf"
  elif [[ "$mode" == "refused" ]]; then
    gateway_config="$fixture_root/gateway-refused.acl"
    nginx_config="$fixture_root/nginx-refused.conf"
  elif [[ "$mode" == "blackhole" ]]; then
    gateway_config="$fixture_root/gateway-blackhole.acl"
    nginx_config="$fixture_root/nginx-blackhole.conf"
  elif [[ "$mode" == "telemetry" ]]; then
    gateway_config="$fixture_root/gateway-telemetry.acl"
    nginx_config="$fixture_root/nginx.conf"
  elif [[ "$mode" == "fallback" ]]; then
    gateway_config="$fixture_root/gateway-fallback.acl"
    nginx_config="$fixture_root/nginx-fallback.conf"
  elif [[ "$mode" == "weighted" ]]; then
    gateway_config="$fixture_root/gateway-weighted.acl"
    nginx_config="$fixture_root/nginx-weighted.conf"
  elif [[ "$mode" == "ratelimit" ]]; then
    gateway_config="$fixture_root/gateway-ratelimit.acl"
    nginx_config="$fixture_root/nginx-ratelimit.conf"
  elif [[ "$mode" == "apikey" ]]; then
    gateway_config="$fixture_root/gateway-apikey.acl"
    nginx_config="$fixture_root/nginx.conf"
  elif [[ "$mode" == "noreplay" ]]; then
    gateway_config="$fixture_root/gateway-noreplay.acl"
    nginx_config="$fixture_root/nginx-noreplay.conf"
  elif [[ "$mode" == "tls" ]]; then
    ensure_ai_tls_material
    gateway_config="$fixture_root/gateway-tls.acl"
    nginx_config="$fixture_root/nginx-tls.conf"
  elif [[ "$mode" == "ipv6" ]]; then
    gateway_config="$fixture_root/gateway-ipv6.acl"
    nginx_config="$fixture_root/nginx-ipv6.conf"
  elif [[ "$mode" == "upstream-tls" ]]; then
    ensure_ai_upstream_tls_material
    gateway_config="$fixture_root/gateway-upstream-tls.acl"
    nginx_config="$fixture_root/nginx-upstream-tls.conf"
  elif [[ "$mode" == "request-buffering-off" ]]; then
    gateway_config="$fixture_root/gateway.acl"
    nginx_config="$fixture_root/nginx-request-buffering-off.conf"
  elif [[ "$mode" == "disk-spill" ]]; then
    ensure_ai_disk_spill_volume
    gateway_config="$fixture_root/gateway.acl"
    nginx_config="$fixture_root/nginx-disk-spill.conf"
  else
    gateway_config="$fixture_root/gateway.acl"
    nginx_config="$fixture_root/nginx.conf"
  fi
  benchmark_stage="start A3S Gateway ($mode)"
  "$gateway_binary" --config "$gateway_config" --log-level warn \
    >"$output_root/a3s-gateway.log" 2>&1 &
  a3s_pid=$!
  assert_process_running "$a3s_pid" "A3S Gateway"
  benchmark_stage="start NGINX ($mode)"
  nginx -c "$nginx_config" -g 'daemon off;' \
    >"$output_root/nginx.log" 2>&1 &
  nginx_pid=$!
  assert_process_running "$nginx_pid" "NGINX"
  if [[ "$mode" == "tls" ]]; then
    wait_for_endpoint "https://127.0.0.1:18101/health" --insecure
    wait_for_endpoint "https://127.0.0.1:18102/health" --insecure
  elif [[ "$mode" == "ipv6" ]]; then
    wait_for_endpoint "http://[::1]:18101/health"
    wait_for_endpoint "http://[::1]:18102/health"
  else
    wait_for_endpoint "http://127.0.0.1:18101/health"
    wait_for_endpoint "http://127.0.0.1:18102/health"
  fi
  proxy_fixture_mode="$mode"
}

ensure_proxy_fixture() {
  local want="$1"
  if [[ "$proxy_fixture_mode" == "$want" ]]; then
    return 0
  fi
  stop_proxies
  start_proxies "$want"
}

run_profile() {
  local profile="$1"
  local product="$2"
  local trial="$3"
  local output="$output_root/${profile}-${product}-${trial}.json"
  local port
  port=$(product_port "$product")
  configure_profile "$profile"
  if [[ "$blackhole_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture blackhole
  elif [[ "$refused_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture refused
  elif [[ "$timeout_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture timeout
  elif [[ "$telemetry_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture telemetry
  elif [[ "$fallback_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture fallback
  elif [[ "$weighted_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture weighted
  elif [[ "$ratelimit_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture ratelimit
  elif [[ "$apikey_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture apikey
  elif [[ "$noreplay_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture noreplay
  elif [[ "$tls_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture tls
  elif [[ "$upstream_tls_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 1
    ensure_proxy_fixture upstream-tls
  elif [[ "$ipv6_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture ipv6
  elif [[ "$request_buffering_off_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture request-buffering-off
  elif [[ "$disk_spill_fixture" == "1" ]]; then
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture disk-spill
  else
    ensure_upstream_tls_mode 0
    ensure_proxy_fixture normal
  fi
  restart_recovery_ms=""
  if [[ "$gateway_restart_fixture" == "1" ]]; then
    # Proxies must already be on the normal fixture; restart only the product
    # under test so the peer keeps serving other trials' warm state.
    restart_recovery_ms=$(restart_proxy_product "$product")
  fi
  if [[ "$fallback_fixture" == "1" ]]; then
    trip_fallback_quarantine "$product"
  fi
  canary_streams_before=""
  primary_streams_before=""
  if [[ "$noreplay_fixture" == "1" ]]; then
    canary_streams_before=$(curl --fail --silent "http://127.0.0.1:18110/benchmark/stats" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["streams_started"])')
  fi
  if [[ -n "$declare_content_length" && -n "$accept_http_status" && "$require_all_rejections" == "1" ]]; then
    primary_streams_before=$(curl --fail --silent "http://127.0.0.1:18100/benchmark/stats" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["streams_started"])')
  fi
  load_log="$output_root/${profile}-${product}-${trial}.log"
  load_args=(
    --target "${target_scheme}://${target_host}:${port}"
    --endpoint "$endpoint"
    --model "$model"
    --concurrency "$concurrency"
    --requests "$requests"
    --warmup-requests "$warmup_requests"
    --token-count "$token_count"
    --first-token-delay-ms "$first_token_delay_ms"
    --token-interval-ms "$token_interval_ms"
    --prompt-bytes "$prompt_bytes"
    --request-timeout-seconds "$request_timeout_seconds"
    --product "$product"
    --trial "$trial"
    --output "$output"
  )
  if [[ "$tokens_per_write" != "1" ]]; then
    load_args+=(--tokens-per-write "$tokens_per_write")
  fi
  if [[ "$fragments_per_event" != "1" ]]; then
    load_args+=(--fragments-per-event "$fragments_per_event")
  fi
  if [[ "$unicode_payload" == "1" ]]; then
    load_args+=(--unicode-payload)
  fi
  if [[ -n "$target_body_bytes" ]]; then
    load_args+=(--target-body-bytes "$target_body_bytes")
  fi
  if [[ -n "$declare_content_length" ]]; then
    load_args+=(--declare-content-length "$declare_content_length")
  fi
  if [[ "$no_stream" == "1" ]]; then
    load_args+=(--no-stream)
  fi
  if [[ -n "$response_bytes" ]]; then
    load_args+=(--response-bytes "$response_bytes")
  fi
  if [[ -n "$chunked_upload_frames" ]]; then
    load_args+=(--chunked-upload-frames "$chunked_upload_frames")
  fi
  if [[ -n "$long_every" ]]; then
    load_args+=(--long-every "$long_every")
  fi
  if [[ -n "$long_token_count" ]]; then
    load_args+=(--long-token-count "$long_token_count")
  fi
  if [[ -n "$poisson_arrival_rps" ]]; then
    load_args+=(--poisson-arrival-rps "$poisson_arrival_rps")
  fi
  if [[ -n "$arrival_seed" ]]; then
    load_args+=(--arrival-seed "$arrival_seed")
  fi
  if [[ "$require_all_rejections" == "1" ]]; then
    load_args+=(--require-all-rejections)
  fi
  if [[ -n "$disconnect_after_tokens" ]]; then
    load_args+=(--disconnect-after-tokens "$disconnect_after_tokens")
  fi
  if [[ -n "$read_delay_ms" ]]; then
    load_args+=(--read-delay-ms "$read_delay_ms")
  fi
  if [[ -n "$stall_after_tokens" ]]; then
    load_args+=(--stall-after-tokens "$stall_after_tokens")
  fi
  if [[ -n "$stall_ms" ]]; then
    load_args+=(--stall-ms "$stall_ms")
  fi
  if [[ -n "$upstream_fault" ]]; then
    load_args+=(--upstream-fault "$upstream_fault")
  fi
  if [[ "$expect_proxy_error" == "1" ]]; then
    load_args+=(--expect-proxy-error)
  fi
  if [[ -n "$accept_http_status" ]]; then
    load_args+=(--accept-http-status "$accept_http_status")
  fi
  if [[ -n "$api_key" ]]; then
    load_args+=(--api-key "$api_key")
  fi
  if [[ -n "$omit_api_key_every" ]]; then
    load_args+=(--omit-api-key-every "$omit_api_key_every")
  fi
  if [[ "$send_idempotency_key" == "1" ]]; then
    load_args+=(--send-idempotency-key)
  fi
  if [[ "$force_connection_close" == "1" ]]; then
    load_args+=(--force-connection-close)
  fi
  if [[ "$tls_fixture" == "1" ]]; then
    load_args+=(--insecure-tls)
  fi
  if [[ "$use_http2" == "1" ]]; then
    load_args+=(--http2)
  fi
  timeout "${batch_timeout_seconds}s" "$load_binary" "${load_args[@]}" \
    >"$load_log" 2>&1
  if [[ -n "$restart_recovery_ms" ]]; then
    python3 - "$output" "$restart_recovery_ms" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
recovery_ms = int(sys.argv[2])
payload = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(payload, dict):
    raise SystemExit(f"{path} must contain a JSON object")
payload["restart_recovery_ms"] = recovery_ms
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
  fi
  if [[ "$noreplay_fixture" == "1" ]]; then
    canary_streams_after=$(curl --fail --silent "http://127.0.0.1:18110/benchmark/stats" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["streams_started"])')
    if [[ "$canary_streams_after" != "$canary_streams_before" ]]; then
      echo "no-replay-after-token violated: canary streams_started ${canary_streams_before} -> ${canary_streams_after}" >&2
      return 1
    fi
  fi
  if [[ -n "$primary_streams_before" ]]; then
    primary_streams_after=$(curl --fail --silent "http://127.0.0.1:18100/benchmark/stats" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["streams_started"])')
    if [[ "$primary_streams_after" != "$primary_streams_before" ]]; then
      echo "prompt-over-limit violated: upstream streams_started ${primary_streams_before} -> ${primary_streams_after}" >&2
      return 1
    fi
  fi
  # Fault lanes that surface as gateway 5xx can quarantine the shared upstream
  # via passive health. Recover before the next profile; do not disable health.
  if [[ "$upstream_fault" == "http-503" || "$upstream_fault" == "http-500" || "$upstream_fault" == "hold-headers" ]]; then
    wait_for_fault_lane_recovery "$product"
  fi
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
"$gateway_binary" validate --config "$fixture_root/gateway-timeout.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-refused.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-blackhole.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-telemetry.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-fallback.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-weighted.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-ratelimit.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-apikey.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-noreplay.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-tls.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-ipv6.acl"
"$gateway_binary" validate --config "$fixture_root/gateway-upstream-tls.acl"
benchmark_stage="validate NGINX fixture"
ensure_ai_tls_material
ensure_ai_upstream_tls_material
nginx -t -c "$fixture_root/nginx.conf"
nginx -t -c "$fixture_root/nginx-timeout.conf"
nginx -t -c "$fixture_root/nginx-refused.conf"
nginx -t -c "$fixture_root/nginx-blackhole.conf"
nginx -t -c "$fixture_root/nginx-fallback.conf"
nginx -t -c "$fixture_root/nginx-weighted.conf"
nginx -t -c "$fixture_root/nginx-ratelimit.conf"
nginx -t -c "$fixture_root/nginx-noreplay.conf"
nginx -t -c "$fixture_root/nginx-tls.conf"
nginx -t -c "$fixture_root/nginx-ipv6.conf"
nginx -t -c "$fixture_root/nginx-upstream-tls.conf"
nginx -t -c "$fixture_root/nginx-request-buffering-off.conf"
ensure_ai_disk_spill_volume
nginx -t -c "$fixture_root/nginx-disk-spill.conf"

benchmark_stage="start deterministic OpenAI-compatible upstreams"
start_stable_upstream 0
"$upstream_binary" --address 127.0.0.1:18110 --instance-id canary \
  >"$output_root/upstream-canary.log" 2>&1 &
canary_upstream_pid=$!
assert_process_running "$canary_upstream_pid" "deterministic upstream (canary)"
"$upstream_binary" --address '[::1]:18100' --instance-id ipv6 \
  >"$output_root/upstream-ipv6.log" 2>&1 &
ipv6_upstream_pid=$!
assert_process_running "$ipv6_upstream_pid" "deterministic upstream (ipv6)"
wait_for_endpoint "http://127.0.0.1:18110/health"
wait_for_endpoint "http://[::1]:18100/health"

start_proxies normal

for trial in $(seq 1 "$trials"); do
  if (( trial % 2 == 1 )); then
    order=(a3s-gateway nginx)
  else
    order=(nginx a3s-gateway)
  fi
  for profile in "${profiles[@]}"; do
    configure_profile "$profile"
    if [[ "$a3s_only" == "1" ]]; then
      products=(a3s-gateway)
    else
      products=("${order[@]}")
    fi
    for product in "${products[@]}"; do
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
