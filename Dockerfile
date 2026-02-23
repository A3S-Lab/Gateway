# Build context must be the parent crates/ directory:
#   docker build -f gateway/Dockerfile -t a3s-gateway:latest .
# (run from crates/)
#
# ── Stage 1: Builder ────────────────────────────────────────────────────────
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev cmake make perl g++ linux-headers

WORKDIR /build

# Copy path dependencies first (matches Cargo.toml path = "../updater")
COPY updater/ /updater/

# Copy gateway manifests for dependency caching
COPY gateway/Cargo.toml gateway/Cargo.lock ./

# Warm up dependency compilation with a stub binary
RUN mkdir -p src && \
    echo 'fn main(){}' > src/main.rs && \
    touch src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the real binary
COPY gateway/src/ src/
RUN touch src/main.rs src/lib.rs && cargo build --release

# ── Stage 2: Minimal runtime ─────────────────────────────────────────────────
FROM alpine:3

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

COPY --from=builder /build/target/release/a3s-gateway /usr/local/bin/a3s-gateway

USER gateway

EXPOSE 80 443 8080

ENTRYPOINT ["a3s-gateway"]
