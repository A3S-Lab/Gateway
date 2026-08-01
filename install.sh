#!/bin/sh

set -eu
umask 077

PROGRAM="a3s-gateway"
REPOSITORY="A3S-Lab/Gateway"
RELEASES_URL="${A3S_GATEWAY_RELEASES_URL:-https://github.com/${REPOSITORY}/releases/download}"
LATEST_API_URL="${A3S_GATEWAY_LATEST_API_URL:-https://api.github.com/repos/${REPOSITORY}/releases/latest}"
VERSION="${A3S_GATEWAY_VERSION:-}"
INSTALL_DIR="${A3S_GATEWAY_INSTALL_DIR:-}"
PLATFORM_OVERRIDE="${A3S_GATEWAY_PLATFORM:-}"
NO_MODIFY_PATH="${A3S_GATEWAY_NO_MODIFY_PATH:-0}"
ALLOW_INSECURE="${A3S_GATEWAY_ALLOW_INSECURE:-0}"
TEMP_DIR=""
PENDING_BINARY=""

usage() {
  cat <<'USAGE'
Install the latest A3S Gateway release for macOS or Linux.

Usage:
  install.sh [options]

Options:
  --version <version>     Install an exact version instead of the latest release.
  --install-dir <path>    Install directory (default: $HOME/.local/bin).
  --no-modify-path        Do not add the default install directory to a shell profile.
  -h, --help              Show this help.

Environment overrides:
  A3S_GATEWAY_VERSION
  A3S_GATEWAY_INSTALL_DIR
  A3S_GATEWAY_NO_MODIFY_PATH=1
USAGE
}

log() {
  printf '%s\n' "a3s-gateway installer: $*"
}

fail() {
  printf '%s\n' "a3s-gateway installer: error: $*" >&2
  exit 1
}

cleanup() {
  if [ -n "$PENDING_BINARY" ] && [ -e "$PENDING_BINARY" ]; then
    rm -f "$PENDING_BINARY"
  fi
  if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
    rm -rf "$TEMP_DIR"
  fi
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      [ "$#" -ge 2 ] || fail "--version requires a value"
      VERSION=$2
      shift 2
      ;;
    --install-dir)
      [ "$#" -ge 2 ] || fail "--install-dir requires a value"
      INSTALL_DIR=$2
      shift 2
      ;;
    --no-modify-path)
      NO_MODIFY_PATH=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown option: $1"
      ;;
  esac
done

command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v tar >/dev/null 2>&1 || fail "tar is required"
command -v mktemp >/dev/null 2>&1 || fail "mktemp is required"

download() {
  url=$1
  destination=$2
  case "$url" in
    https://*)
      curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
        --retry 3 --connect-timeout 15 --max-time 300 \
        --header 'Accept: application/vnd.github+json' \
        --header 'User-Agent: a3s-gateway-installer' \
        --output "$destination" "$url"
      ;;
    *)
      [ "$ALLOW_INSECURE" = "1" ] || fail "refusing non-HTTPS download URL: $url"
      curl --fail --location --silent --show-error --retry 3 \
        --connect-timeout 15 --max-time 300 --output "$destination" "$url"
      ;;
  esac
}

sha256_file() {
  target=$1
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$target" | awk '{print $NF}'
  else
    fail "sha256sum, shasum, or openssl is required to verify the release"
  fi
}

detect_platform() {
  if [ -n "$PLATFORM_OVERRIDE" ]; then
    platform=$PLATFORM_OVERRIDE
  else
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
      Darwin) os=darwin ;;
      Linux) os=linux ;;
      *) fail "unsupported operating system: $os" ;;
    esac
    case "$arch" in
      x86_64 | amd64) arch=x86_64 ;;
      arm64 | aarch64) arch=arm64 ;;
      *) fail "unsupported architecture: $arch" ;;
    esac
    if [ "$os" = "linux" ]; then
      platform="linux-${arch}-musl"
    else
      platform="darwin-${arch}"
    fi
  fi

  case "$platform" in
    darwin-arm64 | darwin-x86_64 | linux-arm64 | linux-arm64-musl | linux-x86_64 | linux-x86_64-musl)
      printf '%s\n' "$platform"
      ;;
    *)
      fail "unsupported release platform: $platform"
      ;;
  esac
}

ensure_default_path() {
  case ":${PATH:-}:" in
    *":${INSTALL_DIR}:"*) return ;;
  esac

  if [ "$NO_MODIFY_PATH" = "1" ]; then
    log "${INSTALL_DIR} is not on PATH; add it before invoking ${PROGRAM} by name"
    return
  fi

  if [ -z "${HOME:-}" ]; then
    log "${INSTALL_DIR} is not on PATH and HOME is unavailable; add it manually"
    return
  fi

  default_dir="${HOME}/.local/bin"
  if [ "$INSTALL_DIR" != "$default_dir" ]; then
    log "custom install directory is not on PATH: ${INSTALL_DIR}"
    return
  fi

  shell_name=$(basename "${SHELL:-sh}")
  case "$shell_name" in
    zsh) profile="${HOME}/.zshrc" ;;
    bash)
      if [ "$(uname -s)" = "Darwin" ]; then
        profile="${HOME}/.bash_profile"
      else
        profile="${HOME}/.bashrc"
      fi
      ;;
    sh | dash | ksh) profile="${HOME}/.profile" ;;
    *)
      log "${INSTALL_DIR} is not on PATH; add it to your ${shell_name} configuration"
      return
      ;;
  esac

  # HOME and PATH must expand when the user's shell reads the profile.
  # shellcheck disable=SC2016
  path_line='export PATH="$HOME/.local/bin:$PATH"'
  if [ ! -f "$profile" ] || ! grep -F "$path_line" "$profile" >/dev/null 2>&1; then
    {
      printf '\n%s\n' '# Added by A3S Gateway installer'
      printf '%s\n' "$path_line"
    } >> "$profile"
    log "added ${INSTALL_DIR} to PATH in ${profile}; open a new shell to use it"
  fi
}

if [ -z "$INSTALL_DIR" ]; then
  [ -n "${HOME:-}" ] || fail "HOME is not set; pass --install-dir explicitly"
  INSTALL_DIR="${HOME}/.local/bin"
fi

TEMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/a3s-gateway-install.XXXXXX")

if [ -z "$VERSION" ]; then
  release_json="${TEMP_DIR}/release.json"
  log "resolving the latest stable release"
  download "$LATEST_API_URL" "$release_json"
  tag=$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$release_json" | sed -n '1p')
  [ -n "$tag" ] || fail "latest release response did not contain tag_name"
  VERSION=${tag#v}
else
  VERSION=${VERSION#v}
fi

case "$VERSION" in
  "" | *[!0-9A-Za-z.+-]*) fail "invalid version: $VERSION" ;;
esac

PLATFORM=$(detect_platform)
ARCHIVE="${PROGRAM}-${VERSION}-${PLATFORM}.tar.gz"
TAG="v${VERSION}"
ARCHIVE_URL="${RELEASES_URL%/}/${TAG}/${ARCHIVE}"
CHECKSUM_URL="${ARCHIVE_URL}.sha256"
ARCHIVE_PATH="${TEMP_DIR}/${ARCHIVE}"
CHECKSUM_PATH="${ARCHIVE_PATH}.sha256"
EXTRACT_DIR="${TEMP_DIR}/extract"

log "downloading ${ARCHIVE}"
download "$ARCHIVE_URL" "$ARCHIVE_PATH"
download "$CHECKSUM_URL" "$CHECKSUM_PATH"

EXPECTED=$(awk 'NR == 1 { print $1 }' "$CHECKSUM_PATH" | tr '[:upper:]' '[:lower:]')
case "$EXPECTED" in
  "" | *[!0-9a-f]*) fail "release checksum is not hexadecimal" ;;
esac
[ "${#EXPECTED}" -eq 64 ] || fail "release checksum must contain 64 hexadecimal characters"
ACTUAL=$(sha256_file "$ARCHIVE_PATH" | tr '[:upper:]' '[:lower:]')
[ "$ACTUAL" = "$EXPECTED" ] || fail "SHA-256 mismatch for ${ARCHIVE}"
log "verified SHA-256 ${ACTUAL}"

mkdir -p "$EXTRACT_DIR"
EXTRACTED_BINARY="${EXTRACT_DIR}/${PROGRAM}"
ARCHIVE_ENTRIES="${TEMP_DIR}/archive-entries.txt"
tar -tzf "$ARCHIVE_PATH" > "$ARCHIVE_ENTRIES" || fail "release archive is not a valid tar.gz file"
ENTRY_COUNT=$(awk -v program="$PROGRAM" '$0 == program { count++ } END { print count + 0 }' "$ARCHIVE_ENTRIES")
[ "$ENTRY_COUNT" -eq 1 ] || fail "archive must contain exactly one root ${PROGRAM} entry"
if ! tar -xOf "$ARCHIVE_PATH" "$PROGRAM" > "$EXTRACTED_BINARY"; then
  fail "archive does not contain ${PROGRAM}"
fi
[ -f "$EXTRACTED_BINARY" ] && [ ! -L "$EXTRACTED_BINARY" ] || fail "archive does not contain a regular ${PROGRAM} binary"
chmod 755 "$EXTRACTED_BINARY"

REPORTED_VERSION=$("$EXTRACTED_BINARY" --version 2>&1) || fail "downloaded binary did not start"
[ "$REPORTED_VERSION" = "${PROGRAM} ${VERSION}" ] || fail "downloaded binary reported an unexpected version: $REPORTED_VERSION"

mkdir -p "$INSTALL_DIR"
DESTINATION="${INSTALL_DIR}/${PROGRAM}"
[ ! -d "$DESTINATION" ] || fail "installation destination is a directory: $DESTINATION"
PENDING_BINARY=$(mktemp "${INSTALL_DIR}/.${PROGRAM}.install.XXXXXX")
cp "$EXTRACTED_BINARY" "$PENDING_BINARY"
chmod 755 "$PENDING_BINARY"
mv -f "$PENDING_BINARY" "$DESTINATION"
PENDING_BINARY=""

ensure_default_path
log "installed ${REPORTED_VERSION} at ${DESTINATION}"
