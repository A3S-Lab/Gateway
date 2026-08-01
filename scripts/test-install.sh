#!/usr/bin/env bash

set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/a3s-gateway-installer-test.XXXXXX")
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$fixture_root"
}
trap cleanup EXIT

version="9.8.7-test"
platform="linux-x86_64-musl"
archive="a3s-gateway-${version}-${platform}.tar.gz"
release_dir="$fixture_root/download/v${version}"
install_dir="$fixture_root/install"
port_file="$fixture_root/port"
mkdir -p "$release_dir" "$fixture_root/archive"
printf '{"tag_name":"v%s"}\n' "$version" > "$fixture_root/latest.json"

cat > "$fixture_root/archive/a3s-gateway" <<EOF
#!/bin/sh
printf '%s\n' 'a3s-gateway ${version}'
EOF
chmod 755 "$fixture_root/archive/a3s-gateway"
tar -czf "$release_dir/$archive" -C "$fixture_root/archive" a3s-gateway

if command -v sha256sum >/dev/null 2>&1; then
  archive_sha=$(sha256sum "$release_dir/$archive" | awk '{print $1}')
else
  archive_sha=$(shasum -a 256 "$release_dir/$archive" | awk '{print $1}')
fi
printf '%s  %s\n' "$archive_sha" "$archive" > "$release_dir/$archive.sha256"

python3 - "$fixture_root" "$port_file" <<'PY' &
import functools
import http.server
import pathlib
import sys


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass


handler = functools.partial(QuietHandler, directory=sys.argv[1])
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
pathlib.Path(sys.argv[2]).write_text(str(server.server_port), encoding="utf-8")
server.serve_forever()
PY
server_pid=$!

for _attempt in {1..50}; do
  [[ -s "$port_file" ]] && break
  sleep 0.1
done
[[ -s "$port_file" ]] || { echo "test server did not start" >&2; exit 1; }
port=$(<"$port_file")
releases_url="http://127.0.0.1:${port}/download"

installer_output=$(A3S_GATEWAY_RELEASES_URL="$releases_url" \
  A3S_GATEWAY_PLATFORM="$platform" \
  A3S_GATEWAY_ALLOW_INSECURE=1 \
  sh "$repository_root/install.sh" \
    --version "$version" \
    --install-dir "$install_dir" \
    --no-modify-path)

grep -F "verified SHA-256" <<<"$installer_output" >/dev/null
grep -F "installed a3s-gateway ${version}" <<<"$installer_output" >/dev/null
[[ -x "$install_dir/a3s-gateway" ]]
[[ "$("$install_dir/a3s-gateway" --version)" == "a3s-gateway ${version}" ]]

latest_install_dir="$fixture_root/install-latest"
A3S_GATEWAY_RELEASES_URL="$releases_url" \
  A3S_GATEWAY_LATEST_API_URL="http://127.0.0.1:${port}/latest.json" \
  A3S_GATEWAY_PLATFORM="$platform" \
  A3S_GATEWAY_ALLOW_INSECURE=1 \
  sh "$repository_root/install.sh" \
    --install-dir "$latest_install_dir" \
    --no-modify-path >/dev/null
[[ "$("$latest_install_dir/a3s-gateway" --version)" == "a3s-gateway ${version}" ]]

installed_sha_before=$(if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$install_dir/a3s-gateway" | awk '{print $1}'
else
  shasum -a 256 "$install_dir/a3s-gateway" | awk '{print $1}'
fi)
printf '%064d  %s\n' 0 "$archive" > "$release_dir/$archive.sha256"

if A3S_GATEWAY_RELEASES_URL="$releases_url" \
  A3S_GATEWAY_PLATFORM="$platform" \
  A3S_GATEWAY_ALLOW_INSECURE=1 \
  sh "$repository_root/install.sh" \
    --version "$version" \
    --install-dir "$install_dir" \
    --no-modify-path >/dev/null 2>&1; then
  echo "installer accepted a damaged checksum" >&2
  exit 1
fi

installed_sha_after=$(if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$install_dir/a3s-gateway" | awk '{print $1}'
else
  shasum -a 256 "$install_dir/a3s-gateway" | awk '{print $1}'
fi)
[[ "$installed_sha_before" == "$installed_sha_after" ]]

if A3S_GATEWAY_PLATFORM="plan9-mips" sh "$repository_root/install.sh" \
  --version "$version" --install-dir "$install_dir" --no-modify-path >/dev/null 2>&1; then
  echo "installer accepted an unsupported platform" >&2
  exit 1
fi

sh "$repository_root/install.sh" --help | grep -F -- "--install-dir" >/dev/null
echo "POSIX installer tests passed."
