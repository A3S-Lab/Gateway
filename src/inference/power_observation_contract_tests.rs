//! PW0 / I0.2b joint schema lock between Gateway ACL projections and Power.

#[test]
fn gateway_and_power_share_the_same_worker_observation_schema_id() {
    // Cloud projects Power observations into Gateway ACL. The schema id must
    // stay identical so Dual-track I0 cannot silently accept a divergent
    // observation dialect. This is a monorepo contract lock, not a capacity
    // claim and not a substitute for provisioned PW0 delivery EXIT.
    let power_source = include_str!("../../../power/src/serving/observation.rs");
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
