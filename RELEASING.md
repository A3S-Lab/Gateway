# Releasing a3s-gateway

## Pre-release Checklist

1. [ ] All tests pass: `cargo test --all-features`
2. [ ] No clippy warnings: `cargo clippy --all-features -- -D warnings`
3. [ ] Benchmarks compile: `cargo bench --no-run`
4. [ ] Docs build clean: `RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps`
5. [ ] MSRV check: `cargo +1.82 check --all-features`
6. [ ] `CHANGELOG.md` has an entry for the new version
7. [ ] `Cargo.toml` version matches target
8. [ ] `deploy/helm/a3s-gateway/Chart.yaml` version and appVersion updated
9. [ ] `cargo publish --dry-run` passes
10. [ ] Tag pushed: `git tag v<VERSION>` → release workflow handles the rest

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

# 4. CI handles: crates.io publish, GitHub Release, Docker image, Helm chart
```

## MSRV Policy

The Minimum Supported Rust Version may advance in minor releases, maintaining
at least a 3 stable-version lag behind the latest Rust release.
