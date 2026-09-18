#!/usr/bin/env bash
# Lab-extended soak (default 120s). Not a dedicated-hardware published envelope.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="${1:-./target/debug/a3s-gateway}"
if [[ ! -x "$BIN" && ! -f "$BIN" ]]; then
  echo "building a3s-gateway..."
  cargo build --bin a3s-gateway
  BIN=./target/debug/a3s-gateway
fi

DUR="${A3S_GATEWAY_SOAK_DURATION:-120}"
C="${A3S_GATEWAY_SOAK_CONCURRENCY:-8}"

for profile in http-json sse-finite openai-json openai-sse; do
  python3 scripts/soak-gateway.py \
    --bin "$BIN" \
    --profile "$profile" \
    --duration "$DUR" \
    --concurrency "$C" \
    --envelope-status lab-extended
done
echo "soak-gateway lab-extended: OK"
