#!/usr/bin/env bash
# Setup workspace context for building a3s-gateway standalone.
#
# Gateway depends on path crates:
#   ../acl      → a3s-acl (separate repo: A3S-Lab/ACL)
#   ../updater  → a3s-updater (separate repo: A3S-Lab/Updater)
#
# Before: ./ = Gateway repo root
# After:  ./ = workspace root with crates/gateway/, crates/acl/, crates/updater/

set -euo pipefail

TMPDIR="$(mktemp -d)"
cp -a . "$TMPDIR/gateway"

# Clean current directory (except .git)
find . -maxdepth 1 ! -name '.' ! -name '.git' -exec rm -rf {} +

mkdir -p crates
cp -a "$TMPDIR/gateway/." crates/gateway/
rm -rf "$TMPDIR"

# Clone dependency repos:
# - a3s-acl: separate repo (submodule in monorepo)
# - a3s-updater: local crate in monorepo (not a submodule)
AUTH_PREFIX=""
if [ -n "${GH_TOKEN:-}" ]; then
  AUTH_PREFIX="x-access-token:${GH_TOKEN}@"
fi
git clone --depth=1 "https://${AUTH_PREFIX}github.com/A3S-Lab/ACL.git" crates/acl

# Fetch updater from monorepo via sparse-checkout (it's NOT a submodule)
git clone --depth=1 --filter=blob:none --sparse \
  "https://${AUTH_PREFIX}github.com/A3S-Lab/a3s.git" _monorepo
(cd _monorepo && git sparse-checkout set crates/updater)
cp -a _monorepo/crates/updater crates/updater
rm -rf _monorepo

cat > Cargo.toml << 'EOF'
[workspace]
resolver = "2"
members = [
    "crates/gateway",
    "crates/acl",
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
