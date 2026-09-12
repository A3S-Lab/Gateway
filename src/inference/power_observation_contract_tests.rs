//! PW0 / I0.2b joint schema lock between Gateway ACL projections and Power.
//!
//! The Power source is vendored under `tests/fixtures/contracts/` so standalone
//! Gateway CI can compile without the monorepo checkout. This is not PW0
//! provisioned delivery EXIT.

#[test]
fn gateway_and_power_share_the_same_worker_observation_schema_id() {
    let power_source = include_str!("../../tests/fixtures/contracts/power_worker_observation.rs");
    let power_schema = power_source
        .lines()
        .find_map(|line| {
            line.trim()
                .strip_prefix("pub const WORKER_OBSERVATION_SCHEMA: &str = \"")
                .and_then(|rest| rest.strip_suffix("\";"))
        })
        .expect("Power WORKER_OBSERVATION_SCHEMA constant");
    assert_eq!(
        crate::config::POWER_WORKER_OBSERVATION_SCHEMA,
        power_schema,
        "Gateway and Power must agree on a3s.power.worker-observation schema id"
    );
}
