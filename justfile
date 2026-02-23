# A3S Gateway - Justfile

default:
    @just --list

# ============================================================================
# Build
# ============================================================================

# Debug build
build:
    cargo build

# Optimised release build (LTO + strip — matches CI profile)
release:
    cargo build --release

# Build with all optional features (redis, kube)
build-all:
    cargo build --all-features

# ============================================================================
# Test
# ============================================================================

# Run all unit tests with a clean summary
test:
    #!/usr/bin/env bash
    set -euo pipefail
    BOLD='\033[1m'; GREEN='\033[0;32m'; RED='\033[0;31m'
    YELLOW='\033[0;33m'; DIM='\033[2m'; RESET='\033[0m'

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo -e "${BOLD}  A3S Gateway — Test Suite${RESET}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""

    output=$(cargo test --lib 2>&1)
    echo "$output"

    result=$(echo "$output" | grep -E "^test result:" | tail -1)
    passed=$(echo "$result" | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' || echo 0)
    failed=$(echo "$result" | grep -oE '[0-9]+ failed' | grep -oE '[0-9]+' || echo 0)
    ignored=$(echo "$result" | grep -oE '[0-9]+ ignored' | grep -oE '[0-9]+' || echo 0)

    echo ""
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    if [ "$failed" -gt 0 ]; then
        echo -e "  ${RED}${BOLD}✗ FAILED${RESET}  ${GREEN}$passed passed${RESET}  ${RED}$failed failed${RESET}  ${YELLOW}$ignored ignored${RESET}"
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
        echo ""
        exit 1
    else
        echo -e "  ${GREEN}${BOLD}✓ PASSED${RESET}  ${GREEN}$passed passed${RESET}  ${YELLOW}$ignored ignored${RESET}"
        echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    fi
    echo ""

# Run tests with all optional features
test-all:
    cargo test --all-features --lib

# Run a specific test by name
test-one TEST:
    cargo test {{TEST}} -- --nocapture

# Run tests for a specific module (e.g. `just test-mod proxy::acme_dns`)
test-mod MOD:
    cargo test --lib -- {{MOD}}

# ============================================================================
# Code Quality
# ============================================================================

# Format code
fmt:
    cargo fmt --all

# Check formatting (non-destructive)
fmt-check:
    cargo fmt --all -- --check

# Lint (clippy)
lint:
    cargo clippy --all-targets -- -D warnings

# Lint with all features
lint-all:
    cargo clippy --all-features --all-targets -- -D warnings

# Full CI gate (fmt + lint + test) — must pass before tagging a release
ci: fmt-check lint test

# ============================================================================
# Versioning
# ============================================================================

# Show current version
version:
    @grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)".*/\1/'

# ============================================================================
# Utilities
# ============================================================================

# Fast compile check (no codegen)
check:
    cargo check --all-features

# Clean build artefacts
clean:
    cargo clean

# Generate and open docs
doc:
    cargo doc --no-deps --open

# Update all dependencies
update:
    cargo update
