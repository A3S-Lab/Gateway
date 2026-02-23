#!/usr/bin/env bash
# Sets up the path-dependency layout required by a3s-gateway.
#
# Expected caller CWD: repo root (where gateway/ was checked out).
# After this script the layout is:
#
#   gateway/     ← the gateway repo (checkout target)
#   common/      ← crates/common  (from monorepo sparse-checkout)
#   updater/     ← crates/updater (from monorepo sparse-checkout)
#
# gateway/Cargo.toml resolves ../common and ../updater correctly.

set -euo pipefail

MONOREPO_DIR="${1:-_monorepo}"

mv "${MONOREPO_DIR}/crates/common"  common
mv "${MONOREPO_DIR}/crates/updater" updater
rm -rf "${MONOREPO_DIR}"
