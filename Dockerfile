# a3s-gateway OCI runtime image
#
# Multi-stage build that accepts a pre-built musl binary.
# Build context must be the monorepo root.
#
# Build example:
#   docker build -f crates/gateway/Dockerfile \
#     --build-arg BINARY_URL=https://github.com/A3S-Lab/a3s/releases/download/v0.2.3/a3s-gateway \
#     -t a3s-gateway:latest .

# ── Stage 1: Runtime ─────────────────────────────────────────────────────────
FROM alpine:3

ARG BINARY_NAME=a3s-gateway
ENV BINARY_NAME=${BINARY_NAME}

# Install CA certificates for HTTPS and set timezone data
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S gateway && adduser -S gateway -G gateway

WORKDIR /

# Copy the pre-built binary
COPY --chmod=755 ${BINARY_NAME} /usr/local/bin/${BINARY_NAME}

# Switch to non-root user
USER gateway

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -qO- http://localhost:8080/health || exit 1

EXPOSE 80 443 8080

ENTRYPOINT ["a3s-gateway"]
