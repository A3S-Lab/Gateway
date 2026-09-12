//! Billing tokenizer revision lock between Gateway ACL and Cloud contracts.
//!
//! Dual-track billing alignment requires the same frozen revision id. This is
//! not a claim that the provisional tokenizer is billing-grade. The Cloud
//! source is vendored under `tests/fixtures/contracts/` so standalone Gateway
//! CI can compile without the monorepo checkout.

#[test]
fn gateway_and_cloud_share_the_same_inference_tokenizer_revision() {
    let cloud_source = include_str!("../../tests/fixtures/contracts/cloud_tokenizer_revision.rs");
    let cloud_revision = cloud_source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pub const INFERENCE_TOKENIZER_REVISION_V1: &str = \"")
                .and_then(|rest| rest.strip_suffix("\";"))
        })
        .expect("Cloud INFERENCE_TOKENIZER_REVISION_V1 constant");
    assert_eq!(
        crate::config::INFERENCE_TOKENIZER_REVISION,
        cloud_revision,
        "Gateway and Cloud must agree on a3s.gateway.tokenizer.v1"
    );
}
