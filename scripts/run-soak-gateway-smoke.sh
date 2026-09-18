#!/usr/bin/env bash
# Short smoke soak for the capacity/soak harness (not a published envelope).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${1:-./target/debug/a3s-gateway}"
if [[ ! -x "$BIN" && ! -f "$BIN" ]]; then
  echo "building a3s-gateway..."
  cargo build --bin a3s-gateway
  BIN=./target/debug/a3s-gateway
fi

DUR="${A3S_GATEWAY_SOAK_DURATION:-30}"
HTTP_C="${A3S_GATEWAY_SOAK_CONCURRENCY_HTTP:-16}"
SSE_C="${A3S_GATEWAY_SOAK_CONCURRENCY_SSE:-8}"

python3 scripts/soak-gateway.py --bin "$BIN" --profile http-json --duration "$DUR" --concurrency "$HTTP_C" --envelope-status smoke-only
python3 scripts/soak-gateway.py --bin "$BIN" --profile sse-finite --duration "$DUR" --concurrency "$SSE_C" --envelope-status smoke-only
python3 scripts/soak-gateway.py --bin "$BIN" --profile openai-json --duration "$DUR" --concurrency "$HTTP_C" --envelope-status smoke-only
python3 scripts/soak-gateway.py --bin "$BIN" --profile openai-sse --duration "$DUR" --concurrency "$SSE_C" --envelope-status smoke-only
echo "soak-gateway smoke: OK"
