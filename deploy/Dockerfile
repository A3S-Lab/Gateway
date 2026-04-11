# Multi-platform OCI image for a3s-gateway
# Supports: linux/amd64, linux/arm64, darwin/arm64
#
# Usage:
#   docker buildx build --platform linux/amd64,linux/arm64,darwin/arm64 \
#     -t ghcr.io/a3s-lab/gateway:latest -f deploy/Dockerfile --push .
#
# Note: darwin/arm64 is a macOS binary for Docker Desktop on Apple Silicon.
#       For native macOS, use Homebrew: brew install a3s-lab/tap/a3s-gateway

# ── Linux: Alpine-based minimal image ────────────────────────────────────────────
FROM alpine:3 AS base
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

# ── Linux amd64 ────────────────────────────────────────────────────────────────
FROM base AS linux-amd64
COPY dist/a3s-gateway /usr/local/bin/a3s-gateway
USER gateway
ENTRYPOINT ["a3s-gateway"]

# ── Linux arm64 ────────────────────────────────────────────────────────────────
FROM base AS linux-arm64
COPY dist/a3s-gateway /usr/local/bin/a3s-gateway
USER gateway
ENTRYPOINT ["a3s-gateway"]

# ── macOS arm64 (Apple Silicon) ───────────────────────────────────────────────
# Packaged as standalone binary for Docker Desktop on Apple Silicon
FROM scratch AS darwin-arm64
COPY dist/a3s-gateway /a3s-gateway
ENTRYPOINT ["/a3s-gateway"]
