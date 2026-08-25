#[test]
fn crate_publication_is_source_bound_tested_and_idempotent() {
    let workflow = include_str!("../.github/workflows/publish-crate.yml");

    assert!(workflow.contains("- \"publish/gateway-crate/v*\""));
    assert!(workflow.contains("git merge-base --is-ancestor \"$GITHUB_SHA\""));
    assert!(workflow.contains("cargo metadata --locked --no-deps"));
    assert!(workflow.contains("components: rustfmt"));
    assert!(workflow.contains("cargo test --locked --lib managed_service"));
    assert!(workflow.contains("cargo publish --locked --dry-run"));
    assert!(workflow.contains("already exists; skipping upload"));
    assert!(workflow.contains("cargo publish --locked"));
    assert!(workflow.contains("cargo info \"a3s-gateway@$VERSION\""));

    for action in workflow.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("- uses: ")
            .filter(|value| !value.starts_with("./"))
    }) {
        let (_, revision) = action
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("publisher action has no revision: {action}"));
        assert!(
            revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "publisher action must use an immutable commit SHA: {action}"
        );
    }
}

#[test]
fn patch_release_metadata_is_synchronized() {
    let manifest = include_str!("../Cargo.toml");
    let chart = include_str!("../deploy/helm/a3s-gateway/Chart.yaml");
    let changelog = include_str!("../CHANGELOG.md");
    let roadmap = include_str!("../ROADMAP.md");

    assert!(manifest.contains("version = \"1.1.1\""));
    assert!(chart.contains("version: 1.1.1"));
    assert!(chart.contains("appVersion: \"1.1.1\""));
    assert!(changelog.contains("## [1.1.1] - 2026-08-25"));
    assert!(roadmap.contains("current `v1.1.1` release"));
}
