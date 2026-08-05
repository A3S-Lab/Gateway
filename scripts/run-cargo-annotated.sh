#!/usr/bin/env bash
set -euo pipefail

output_file=$(mktemp)
cleanup() {
  rm -f "$output_file"
}
trap cleanup EXIT

set +e
"$@" 2>&1 | tee "$output_file"
status=${PIPESTATUS[0]}
set -e

if (( status != 0 )); then
  summary=$({ grep -E '^(error(\[[^]]+\])?:|[[:space:]]*-->|[[:space:]]*= (help|note):)' "$output_file" || true; } \
    | tail -n 40 \
    | tr '\n' ' ' \
    | sed -e 's/%/%25/g' -e 's/\r/%0D/g' -e 's/\n/%0A/g')
  if [[ -z "$summary" ]]; then
    summary="Cargo command failed with exit code $status: $*"
  fi
  echo "::error title=Rust compiler failure::$summary"
fi

exit "$status"
