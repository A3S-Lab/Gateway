# Releasing a3s-gateway

## Pre-release Checklist

1. [ ] All tests pass: `cargo test --locked --all-features`
2. [ ] No clippy warnings: `cargo clippy --locked --all-features -- -D warnings`
3. [ ] Benchmarks compile: `cargo bench --locked --no-run --all-features`
4. [ ] Docs build clean: `RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps`
5. [ ] MSRV check: `cargo +1.88 check --locked --all-features`
6. [ ] Official OpenAI SDK conformance passes using the real-binary commands in
   [`tests/openai_sdk/README.md`](tests/openai_sdk/README.md)
7. [ ] `CHANGELOG.md` has a dated entry for the new version
8. [ ] `Cargo.toml` version matches target
9. [ ] `deploy/helm/a3s-gateway/Chart.yaml` version and appVersion match target
10. [ ] All registry dependencies, including the pinned `a3s-sentry`, are published
11. [ ] `cargo publish --locked --dry-run` passes
12. [ ] `bash scripts/test-install.sh` passes
13. [ ] CI `Installer / Windows` passes the Windows Rust/SDK tests, installer
    contracts, and ARM64 build
14. [ ] The exact release commit has a successful main-branch `Performance
    Baseline`, including the five-trial/eight-profile AI token-streaming matrix
    with 100% correctness for both A3S Gateway and NGINX
15. [ ] The published AI artifact reports the exact release commit and passes
    `website/scripts/check_site.py`
16. [ ] Tag pushed: `git tag v<VERSION>` → release workflow handles the rest

## Release Process

```bash
# 1. Update version
# Edit Cargo.toml: version = "X.Y.Z"
# Edit deploy/helm/a3s-gateway/Chart.yaml: version + appVersion

# 2. Update CHANGELOG.md
# Move [Unreleased] items to [X.Y.Z] - YYYY-MM-DD

# 3. Commit and push main first
git add -A
git commit -m "release: v<VERSION>"
git push origin HEAD:main

# 4. Wait for the exact commit's full CI and Performance Baseline to succeed.
#    Verify the published AI JSON points to that commit and contains all raw
#    trials with zero correctness failures.

# 5. Tag only the already-green main commit
git tag v<VERSION>
git push origin v<VERSION>

# 6. The release workflow reuses the complete CI workflow, verifies tag,
#    Cargo, Helm, changelog, and exact-commit performance evidence, and builds
#    every release target. Only then may it publish crates.io, release archives,
#    OCI images, and the Homebrew formula.
```

The tag workflow deliberately calls [the same CI workflow](.github/workflows/ci.yml)
used by `main` and pull requests. Crates.io publication waits for the complete
macOS, Linux, and Windows build matrix, so a platform packaging failure cannot
leave the registry ahead of the downloadable release.

Tags are intentionally pushed after—not together with—the main commit. This
gives the long-running AI matrix a stable exact SHA to certify and prevents a
tag workflow from publishing a release whose token-streaming evidence belongs
to an earlier commit.

## MSRV Policy

The Minimum Supported Rust Version may advance in minor releases, maintaining
at least a 3 stable-version lag behind the latest Rust release.
