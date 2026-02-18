//! Gradual rollout — shifts traffic between revisions with safety checks

#![allow(dead_code)]
use crate::config::RolloutConfig;
use crate::scaling::revision::RevisionRouter;
use serde::{Deserialize, Serialize};

/// State of a gradual rollout
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RolloutState {
    /// Rollout has not started yet
    Pending,
    /// Rollout is in progress, traffic shifted to `current_percent`
    InProgress { current_percent: u32 },
    /// Rollout completed successfully
    Completed,
    /// Rollout was rolled back due to safety thresholds
    RolledBack,
}

impl std::fmt::Display for RolloutState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::InProgress { current_percent } => {
                write!(f, "in_progress({}%)", current_percent)
            }
            Self::Completed => write!(f, "completed"),
            Self::RolledBack => write!(f, "rolled_back"),
        }
    }
}

/// Controller for a gradual rollout between two revisions
pub struct RolloutController {
    config: RolloutConfig,
    state: RolloutState,
}

impl RolloutController {
    /// Create a new rollout controller
    pub fn new(config: RolloutConfig) -> Self {
        Self {
            config,
            state: RolloutState::Pending,
        }
    }

    /// Current rollout state
    pub fn state(&self) -> &RolloutState {
        &self.state
    }

    /// Configuration
    pub fn config(&self) -> &RolloutConfig {
        &self.config
    }

    /// Advance the rollout by one step.
    ///
    /// Checks the observed error rate and latency against thresholds.
    /// If thresholds are exceeded, the rollout is rolled back.
    /// Otherwise, traffic is shifted by `step_percent`.
    ///
    /// Returns the new state after advancement.
    pub fn advance(
        &mut self,
        error_rate: f64,
        latency_p99_ms: u64,
        router: &RevisionRouter,
    ) -> RolloutState {
        // If already completed or rolled back, do nothing
        if self.state == RolloutState::Completed || self.state == RolloutState::RolledBack {
            return self.state.clone();
        }

        // Check safety thresholds
        if error_rate > self.config.error_rate_threshold {
            tracing::warn!(
                from = self.config.from,
                to = self.config.to,
                error_rate = error_rate,
                threshold = self.config.error_rate_threshold,
                "Rollout error threshold exceeded, rolling back"
            );
            self.rollback(router);
            return self.state.clone();
        }

        if latency_p99_ms > self.config.latency_threshold_ms {
            tracing::warn!(
                from = self.config.from,
                to = self.config.to,
                latency_p99_ms = latency_p99_ms,
                threshold = self.config.latency_threshold_ms,
                "Rollout latency threshold exceeded, rolling back"
            );
            self.rollback(router);
            return self.state.clone();
        }

        // Compute current "to" percentage
        let current_to_pct = match &self.state {
            RolloutState::Pending => 0,
            RolloutState::InProgress { current_percent } => *current_percent,
            _ => return self.state.clone(),
        };

        let new_to_pct = (current_to_pct + self.config.step_percent).min(100);
        let new_from_pct = 100u32.saturating_sub(new_to_pct);

        router.set_traffic(&self.config.from, new_from_pct, &self.config.to, new_to_pct);

        if new_to_pct >= 100 {
            self.state = RolloutState::Completed;
            tracing::info!(
                from = self.config.from,
                to = self.config.to,
                "Rollout completed"
            );
        } else {
            self.state = RolloutState::InProgress {
                current_percent: new_to_pct,
            };
            tracing::info!(
                from = self.config.from,
                to = self.config.to,
                to_percent = new_to_pct,
                "Rollout advanced"
            );
        }

        self.state.clone()
    }

    /// Roll back to the original revision
    fn rollback(&mut self, router: &RevisionRouter) {
        router.set_traffic(&self.config.from, 100, &self.config.to, 0);
        self.state = RolloutState::RolledBack;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RevisionConfig, ServerConfig, Strategy};

    fn make_router() -> RevisionRouter {
        let configs = vec![
            RevisionConfig {
                name: "v1".into(),
                traffic_percent: 100,
                servers: vec![ServerConfig {
                    url: "http://a:8001".into(),
                    weight: 1,
                }],
                strategy: Strategy::RoundRobin,
            },
            RevisionConfig {
                name: "v2".into(),
                traffic_percent: 0,
                servers: vec![ServerConfig {
                    url: "http://b:8001".into(),
                    weight: 1,
                }],
                strategy: Strategy::RoundRobin,
            },
        ];
        RevisionRouter::from_config("svc", &configs)
    }

    fn make_rollout_config() -> RolloutConfig {
        RolloutConfig {
            from: "v1".into(),
            to: "v2".into(),
            step_percent: 10,
            step_interval_secs: 60,
            error_rate_threshold: 0.05,
            latency_threshold_ms: 5000,
        }
    }

    #[test]
    fn test_initial_state_is_pending() {
        let controller = RolloutController::new(make_rollout_config());
        assert_eq!(*controller.state(), RolloutState::Pending);
    }

    #[test]
    fn test_advance_one_step() {
        let router = make_router();
        let mut controller = RolloutController::new(make_rollout_config());

        let state = controller.advance(0.0, 100, &router);
        assert_eq!(
            state,
            RolloutState::InProgress {
                current_percent: 10
            }
        );

        let v1 = router.get_revision("v1").unwrap();
        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v1.traffic_percent(), 90);
        assert_eq!(v2.traffic_percent(), 10);
    }

    #[test]
    fn test_advance_to_completion() {
        let router = make_router();
        let mut controller = RolloutController::new(make_rollout_config());

        // Advance 10 steps to reach 100%
        for i in 1..=10 {
            let state = controller.advance(0.0, 100, &router);
            if i < 10 {
                assert_eq!(
                    state,
                    RolloutState::InProgress {
                        current_percent: i * 10
                    }
                );
            } else {
                assert_eq!(state, RolloutState::Completed);
            }
        }

        let v1 = router.get_revision("v1").unwrap();
        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v1.traffic_percent(), 0);
        assert_eq!(v2.traffic_percent(), 100);
    }

    #[test]
    fn test_rollback_on_high_error_rate() {
        let router = make_router();
        let mut controller = RolloutController::new(make_rollout_config());

        // Advance once
        controller.advance(0.0, 100, &router);
        assert_eq!(
            *controller.state(),
            RolloutState::InProgress {
                current_percent: 10
            }
        );

        // Trigger rollback with high error rate
        let state = controller.advance(0.10, 100, &router);
        assert_eq!(state, RolloutState::RolledBack);

        let v1 = router.get_revision("v1").unwrap();
        let v2 = router.get_revision("v2").unwrap();
        assert_eq!(v1.traffic_percent(), 100);
        assert_eq!(v2.traffic_percent(), 0);
    }

    #[test]
    fn test_rollback_on_high_latency() {
        let router = make_router();
        let mut controller = RolloutController::new(make_rollout_config());

        controller.advance(0.0, 100, &router);

        let state = controller.advance(0.0, 6000, &router);
        assert_eq!(state, RolloutState::RolledBack);
    }

    #[test]
    fn test_no_op_after_completion() {
        let router = make_router();
        let config = RolloutConfig {
            step_percent: 100,
            ..make_rollout_config()
        };
        let mut controller = RolloutController::new(config);

        let state = controller.advance(0.0, 100, &router);
        assert_eq!(state, RolloutState::Completed);

        // Should not change
        let state = controller.advance(0.0, 100, &router);
        assert_eq!(state, RolloutState::Completed);
    }

    #[test]
    fn test_no_op_after_rollback() {
        let router = make_router();
        let mut controller = RolloutController::new(make_rollout_config());

        let state = controller.advance(0.10, 100, &router);
        assert_eq!(state, RolloutState::RolledBack);

        let state = controller.advance(0.0, 100, &router);
        assert_eq!(state, RolloutState::RolledBack);
    }

    #[test]
    fn test_rollout_state_display() {
        assert_eq!(RolloutState::Pending.to_string(), "pending");
        assert_eq!(
            RolloutState::InProgress {
                current_percent: 30
            }
            .to_string(),
            "in_progress(30%)"
        );
        assert_eq!(RolloutState::Completed.to_string(), "completed");
        assert_eq!(RolloutState::RolledBack.to_string(), "rolled_back");
    }

    #[test]
    fn test_rollout_state_serialization() {
        let state = RolloutState::InProgress {
            current_percent: 40,
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: RolloutState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, state);
    }

    #[test]
    fn test_large_step_clamps_to_100() {
        let router = make_router();
        let config = RolloutConfig {
            step_percent: 75,
            ..make_rollout_config()
        };
        let mut controller = RolloutController::new(config);

        // First step: 75%
        let state = controller.advance(0.0, 100, &router);
        assert_eq!(
            state,
            RolloutState::InProgress {
                current_percent: 75
            }
        );

        // Second step: 75+75=150 -> clamped to 100 -> Completed
        let state = controller.advance(0.0, 100, &router);
        assert_eq!(state, RolloutState::Completed);
    }
}
