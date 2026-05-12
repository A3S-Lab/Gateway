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

# Clone dependency repos directly (they are submodules in the monorepo)
git clone --depth=1 https://github.com/A3S-Lab/ACL.git crates/acl
git clone --depth=1 https://github.com/A3S-Lab/Updater.git crates/updater

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
