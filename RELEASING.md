# Releasing a3s-gateway

## Pre-release Checklist

1. [ ] All tests pass: `cargo test --locked --all-features`
2. [ ] No clippy warnings: `cargo clippy --locked --all-features -- -D warnings`
3. [ ] Benchmarks compile: `cargo bench --locked --no-run`
4. [ ] Docs build clean: `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
5. [ ] MSRV check: `cargo +1.88 check --locked --all-features`
6. [ ] `CHANGELOG.md` has an entry for the new version
7. [ ] `Cargo.toml` version matches target
8. [ ] `deploy/helm/a3s-gateway/Chart.yaml` version and appVersion updated
9. [ ] All registry dependencies, including the pinned `a3s-sentry`, are published
10. [ ] `cargo publish --locked --dry-run` passes
11. [ ] Tag pushed: `git tag v<VERSION>` → release workflow handles the rest

## Release Process

```bash
# 1. Update version
# Edit Cargo.toml: version = "X.Y.Z"
# Edit deploy/helm/a3s-gateway/Chart.yaml: version + appVersion

# 2. Update CHANGELOG.md
# Move [Unreleased] items to [X.Y.Z] - YYYY-MM-DD

# 3. Commit and tag
git add -A
git commit -m "release: v<VERSION>"
git tag v<VERSION>
git push origin main --tags

# 4. CI handles: crates.io publish, GitHub Release, OCI image, and Homebrew formula
```

## MSRV Policy

The Minimum Supported Rust Version may advance in minor releases, maintaining
at least a 3 stable-version lag behind the latest Rust release.
