#!/usr/bin/env bash
# Setup workspace context for building a3s-gateway standalone.
#
# Gateway depends on two path crates from the a3s monorepo:
#   ../common   → a3s-common
#   ../updater  → a3s-updater
#
# Before: ./ = Gateway repo root
# After:  ./ = workspace root with crates/gateway/, crates/common/, crates/updater/

set -euo pipefail

TMPDIR="$(mktemp -d)"
cp -a . "$TMPDIR/gateway"

# Clean current directory (except .git)
find . -maxdepth 1 ! -name '.' ! -name '.git' -exec rm -rf {} +

mkdir -p crates
cp -a "$TMPDIR/gateway/." crates/gateway/
rm -rf "$TMPDIR"

# Fetch common and updater from the monorepo via sparse-checkout
git clone --depth=1 --filter=blob:none --sparse \
  https://github.com/A3S-Lab/a3s.git _monorepo
(cd _monorepo && git sparse-checkout set crates/common crates/updater)
cp -a _monorepo/crates/common  crates/common
cp -a _monorepo/crates/updater crates/updater
rm -rf _monorepo

cat > Cargo.toml << 'EOF'
[workspace]
resolver = "2"
members = [
    "crates/gateway",
    "crates/common",
    "crates/updater",
]

[profile.release]
opt-level = "z"
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
EOF

echo "Workspace ready. Gateway at: crates/gateway/"
