# ── Stage 1: Builder ────────────────────────────────────────────────────────
# rust:alpine produces a musl-linked binary; the final image needs no glibc.
FROM rust:alpine AS builder

# Build-time deps:
#   musl-dev   — C standard library headers + static libc for musl targets
#   cmake/make — required by aws-lc-sys (ring's crypto backend)
#   perl        — aws-lc-sys build script
#   g++         — C++ toolchain for aws-lc-sys
RUN apk add --no-cache musl-dev cmake make perl g++ linux-headers

WORKDIR /build

# Copy manifests first so dependency compilation is cached when only src changes.
COPY Cargo.toml Cargo.lock ./

# Compile dependencies with a stub binary so the layer is cached independently.
RUN mkdir -p src && \
    echo 'fn main(){}' > src/main.rs && \
    touch src/lib.rs && \
    cargo build --release 2>/dev/null || true && \
    rm -rf src

# Build the real binary.
COPY src/ src/
RUN touch src/main.rs src/lib.rs && cargo build --release

# ── Stage 2: Minimal runtime ─────────────────────────────────────────────────
FROM alpine:3

# ca-certificates — required for outbound TLS (ACME, Cloudflare/Route53 APIs)
# tzdata          — time-zone data for chrono
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

COPY --from=builder /build/target/release/a3s-gateway /usr/local/bin/a3s-gateway

# Drop root before starting the process
USER gateway

# HTTP / HTTPS / admin
EXPOSE 80 443 8080

ENTRYPOINT ["a3s-gateway"]
