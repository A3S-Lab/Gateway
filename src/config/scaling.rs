//! Scaling configuration — concurrency, buffering, revisions, and gradual rollout

use serde::{Deserialize, Serialize};

use crate::error::{GatewayError, Result};

/// Scaling configuration for a service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingConfig {
    /// Minimum number of replicas (default: 0, enables scale-to-zero)
    #[serde(default)]
    pub min_replicas: u32,

    /// Maximum number of replicas (default: 10)
    #[serde(default = "default_max_replicas")]
    pub max_replicas: u32,

    /// Maximum concurrent requests per container (default: 0 = unlimited)
    #[serde(default)]
    pub container_concurrency: u32,

    /// Target utilization ratio (0.0..=1.0) for autoscaling decisions (default: 0.7)
    #[serde(default = "default_target_utilization")]
    pub target_utilization: f64,

    /// Seconds to wait after last request before scaling down (default: 300)
    #[serde(default = "default_scale_down_delay")]
    pub scale_down_delay_secs: u64,

    /// Seconds a buffered request waits for a backend during scale-from-zero (default: 30)
    #[serde(default = "default_buffer_timeout")]
    pub buffer_timeout_secs: u64,

    /// Maximum number of requests to buffer during scale-from-zero (default: 100)
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Whether scale-from-zero buffering is enabled (default: false)
    #[serde(default)]
    pub buffer_enabled: bool,

    /// Scale executor type: "box" (default) or "k8s"
    #[serde(default = "default_executor")]
    pub executor: String,
}

impl Default for ScalingConfig {
    fn default() -> Self {
        Self {
            min_replicas: 0,
            max_replicas: default_max_replicas(),
            container_concurrency: 0,
            target_utilization: default_target_utilization(),
            scale_down_delay_secs: default_scale_down_delay(),
            buffer_timeout_secs: default_buffer_timeout(),
            buffer_size: default_buffer_size(),
            buffer_enabled: false,
            executor: default_executor(),
        }
    }
}

/// Revision configuration — a named set of backends with a traffic share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevisionConfig {
    /// Revision name (e.g., "v1", "v2")
    pub name: String,

    /// Percentage of traffic routed to this revision (0..=100)
    #[serde(default = "default_traffic_percent")]
    pub traffic_percent: u32,

    /// Backend server URLs for this revision
    #[serde(default)]
    pub servers: Vec<super::ServerConfig>,

    /// Load balancing strategy for this revision (default: round-robin)
    #[serde(default)]
    pub strategy: super::Strategy,
}

/// Gradual rollout configuration — shifts traffic from one revision to another
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolloutConfig {
    /// Source revision name
    pub from: String,

    /// Target revision name
    pub to: String,

    /// Traffic percentage to shift per step (default: 10)
    #[serde(default = "default_step_percent")]
    pub step_percent: u32,

    /// Seconds between each rollout step (default: 60)
    #[serde(default = "default_step_interval")]
    pub step_interval_secs: u64,

    /// Error rate threshold (0.0..=1.0) that triggers rollback (default: 0.05)
    #[serde(default = "default_error_rate_threshold")]
    pub error_rate_threshold: f64,

    /// P99 latency in milliseconds that triggers rollback (default: 5000)
    #[serde(default = "default_latency_threshold")]
    pub latency_threshold_ms: u64,
}

fn default_max_replicas() -> u32 {
    10
}

fn default_target_utilization() -> f64 {
    0.7
}

fn default_scale_down_delay() -> u64 {
    300
}

fn default_buffer_timeout() -> u64 {
    30
}

fn default_buffer_size() -> usize {
    100
}

fn default_executor() -> String {
    "box".to_string()
}

fn default_traffic_percent() -> u32 {
    100
}

fn default_step_percent() -> u32 {
    10
}

fn default_step_interval() -> u64 {
    60
}

fn default_error_rate_threshold() -> f64 {
    0.05
}

fn default_latency_threshold() -> u64 {
    5000
}

/// Validate scaling-related configuration for a service
pub fn validate_scaling(
    service_name: &str,
    scaling: Option<&ScalingConfig>,
    revisions: &[RevisionConfig],
    rollout: Option<&RolloutConfig>,
) -> Result<()> {
    if let Some(sc) = scaling {
        if sc.min_replicas > sc.max_replicas {
            return Err(GatewayError::Config(format!(
                "Service '{}': min_replicas ({}) must be <= max_replicas ({})",
                service_name, sc.min_replicas, sc.max_replicas
            )));
        }
        if sc.target_utilization <= 0.0 || sc.target_utilization > 1.0 {
            return Err(GatewayError::Config(format!(
                "Service '{}': target_utilization ({}) must be in (0.0, 1.0]",
                service_name, sc.target_utilization
            )));
        }
    }

    if !revisions.is_empty() {
        let total: u32 = revisions.iter().map(|r| r.traffic_percent).sum();
        if total != 100 {
            return Err(GatewayError::Config(format!(
                "Service '{}': revision traffic percentages sum to {}, must be 100",
                service_name, total
            )));
        }
    }

    if let Some(ro) = rollout {
        if revisions.is_empty() {
            return Err(GatewayError::Config(format!(
                "Service '{}': rollout requires at least one revision",
                service_name
            )));
        }
        let has_from = revisions.iter().any(|r| r.name == ro.from);
        let has_to = revisions.iter().any(|r| r.name == ro.to);
        if !has_from {
            return Err(GatewayError::Config(format!(
                "Service '{}': rollout 'from' revision '{}' not found",
                service_name, ro.from
            )));
        }
        if !has_to {
            return Err(GatewayError::Config(format!(
                "Service '{}': rollout 'to' revision '{}' not found",
                service_name, ro.to
            )));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scaling_config_defaults() {
        let sc = ScalingConfig::default();
        assert_eq!(sc.min_replicas, 0);
        assert_eq!(sc.max_replicas, 10);
        assert_eq!(sc.container_concurrency, 0);
        assert!((sc.target_utilization - 0.7).abs() < f64::EPSILON);
        assert_eq!(sc.scale_down_delay_secs, 300);
        assert_eq!(sc.buffer_timeout_secs, 30);
        assert_eq!(sc.buffer_size, 100);
        assert!(!sc.buffer_enabled);
        assert_eq!(sc.executor, "box");
    }

    #[test]
    fn test_scaling_config_parse_toml() {
        let toml = r#"
            min_replicas = 1
            max_replicas = 20
            container_concurrency = 50
            target_utilization = 0.8
            scale_down_delay_secs = 120
            buffer_timeout_secs = 15
            buffer_size = 200
            buffer_enabled = true
            executor = "k8s"
        "#;
        let sc: ScalingConfig = toml::from_str(toml).unwrap();
        assert_eq!(sc.min_replicas, 1);
        assert_eq!(sc.max_replicas, 20);
        assert_eq!(sc.container_concurrency, 50);
        assert!((sc.target_utilization - 0.8).abs() < f64::EPSILON);
        assert_eq!(sc.scale_down_delay_secs, 120);
        assert_eq!(sc.buffer_timeout_secs, 15);
        assert_eq!(sc.buffer_size, 200);
        assert!(sc.buffer_enabled);
        assert_eq!(sc.executor, "k8s");
    }

    #[test]
    fn test_scaling_config_parse_minimal_toml() {
        let toml = "";
        let sc: ScalingConfig = toml::from_str(toml).unwrap();
        assert_eq!(sc.min_replicas, 0);
        assert_eq!(sc.max_replicas, 10);
        assert_eq!(sc.container_concurrency, 0);
        assert!(!sc.buffer_enabled);
        assert_eq!(sc.executor, "box");
    }

    #[test]
    fn test_validate_min_greater_than_max() {
        let sc = ScalingConfig {
            min_replicas: 5,
            max_replicas: 2,
            ..ScalingConfig::default()
        };
        let err = validate_scaling("svc", Some(&sc), &[], None).unwrap_err();
        assert!(err.to_string().contains("min_replicas"));
    }

    #[test]
    fn test_validate_utilization_zero() {
        let sc = ScalingConfig {
            target_utilization: 0.0,
            ..ScalingConfig::default()
        };
        let err = validate_scaling("svc", Some(&sc), &[], None).unwrap_err();
        assert!(err.to_string().contains("target_utilization"));
    }

    #[test]
    fn test_validate_utilization_over_one() {
        let sc = ScalingConfig {
            target_utilization: 1.5,
            ..ScalingConfig::default()
        };
        let err = validate_scaling("svc", Some(&sc), &[], None).unwrap_err();
        assert!(err.to_string().contains("target_utilization"));
    }

    #[test]
    fn test_validate_utilization_exactly_one() {
        let sc = ScalingConfig {
            target_utilization: 1.0,
            ..ScalingConfig::default()
        };
        assert!(validate_scaling("svc", Some(&sc), &[], None).is_ok());
    }

    #[test]
    fn test_revision_config_parse() {
        let toml = r#"
            name = "v1"
            traffic_percent = 90
            strategy = "round-robin"
            [[servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let rev: RevisionConfig = toml::from_str(toml).unwrap();
        assert_eq!(rev.name, "v1");
        assert_eq!(rev.traffic_percent, 90);
        assert_eq!(rev.servers.len(), 1);
    }

    #[test]
    fn test_rollout_config_parse() {
        let toml = r#"
            from = "v1"
            to = "v2"
            step_percent = 5
            step_interval_secs = 30
            error_rate_threshold = 0.1
            latency_threshold_ms = 3000
        "#;
        let ro: RolloutConfig = toml::from_str(toml).unwrap();
        assert_eq!(ro.from, "v1");
        assert_eq!(ro.to, "v2");
        assert_eq!(ro.step_percent, 5);
        assert_eq!(ro.step_interval_secs, 30);
        assert!((ro.error_rate_threshold - 0.1).abs() < f64::EPSILON);
        assert_eq!(ro.latency_threshold_ms, 3000);
    }

    #[test]
    fn test_rollout_config_defaults() {
        let toml = r#"
            from = "v1"
            to = "v2"
        "#;
        let ro: RolloutConfig = toml::from_str(toml).unwrap();
        assert_eq!(ro.step_percent, 10);
        assert_eq!(ro.step_interval_secs, 60);
        assert!((ro.error_rate_threshold - 0.05).abs() < f64::EPSILON);
        assert_eq!(ro.latency_threshold_ms, 5000);
    }

    #[test]
    fn test_validate_revisions_sum_not_100() {
        let revisions = vec![
            RevisionConfig {
                name: "v1".into(),
                traffic_percent: 60,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
            RevisionConfig {
                name: "v2".into(),
                traffic_percent: 30,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
        ];
        let err = validate_scaling("svc", None, &revisions, None).unwrap_err();
        assert!(err.to_string().contains("sum to 90"));
    }

    #[test]
    fn test_validate_revisions_sum_100() {
        let revisions = vec![
            RevisionConfig {
                name: "v1".into(),
                traffic_percent: 70,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
            RevisionConfig {
                name: "v2".into(),
                traffic_percent: 30,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
        ];
        assert!(validate_scaling("svc", None, &revisions, None).is_ok());
    }

    #[test]
    fn test_validate_rollout_missing_from() {
        let revisions = vec![RevisionConfig {
            name: "v2".into(),
            traffic_percent: 100,
            servers: vec![],
            strategy: super::super::Strategy::default(),
        }];
        let rollout = RolloutConfig {
            from: "v1".into(),
            to: "v2".into(),
            step_percent: 10,
            step_interval_secs: 60,
            error_rate_threshold: 0.05,
            latency_threshold_ms: 5000,
        };
        let err = validate_scaling("svc", None, &revisions, Some(&rollout)).unwrap_err();
        assert!(err.to_string().contains("'from' revision 'v1' not found"));
    }

    #[test]
    fn test_validate_rollout_no_revisions() {
        let rollout = RolloutConfig {
            from: "v1".into(),
            to: "v2".into(),
            step_percent: 10,
            step_interval_secs: 60,
            error_rate_threshold: 0.05,
            latency_threshold_ms: 5000,
        };
        let err = validate_scaling("svc", None, &[], Some(&rollout)).unwrap_err();
        assert!(err.to_string().contains("requires at least one revision"));
    }

    #[test]
    fn test_validate_all_valid() {
        let sc = ScalingConfig {
            min_replicas: 1,
            max_replicas: 10,
            container_concurrency: 10,
            buffer_enabled: true,
            ..ScalingConfig::default()
        };
        let revisions = vec![
            RevisionConfig {
                name: "v1".into(),
                traffic_percent: 80,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
            RevisionConfig {
                name: "v2".into(),
                traffic_percent: 20,
                servers: vec![],
                strategy: super::super::Strategy::default(),
            },
        ];
        let rollout = RolloutConfig {
            from: "v1".into(),
            to: "v2".into(),
            step_percent: 10,
            step_interval_secs: 60,
            error_rate_threshold: 0.05,
            latency_threshold_ms: 5000,
        };
        assert!(validate_scaling("svc", Some(&sc), &revisions, Some(&rollout)).is_ok());
    }

    #[test]
    fn test_scaling_config_serialization_roundtrip() {
        let sc = ScalingConfig {
            min_replicas: 2,
            max_replicas: 50,
            container_concurrency: 100,
            target_utilization: 0.8,
            scale_down_delay_secs: 60,
            buffer_timeout_secs: 10,
            buffer_size: 50,
            buffer_enabled: true,
            executor: "k8s".into(),
        };
        let json = serde_json::to_string(&sc).unwrap();
        let parsed: ScalingConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.min_replicas, 2);
        assert_eq!(parsed.max_replicas, 50);
        assert_eq!(parsed.container_concurrency, 100);
        assert!((parsed.target_utilization - 0.8).abs() < f64::EPSILON);
        assert_eq!(parsed.scale_down_delay_secs, 60);
        assert!(parsed.buffer_enabled);
        assert_eq!(parsed.executor, "k8s");
    }

    #[test]
    fn test_backward_compat_no_new_fields() {
        // Old config without new fields should still parse with defaults
        let toml = r#"
            container_concurrency = 50
            buffer_timeout_secs = 15
            buffer_size = 200
            buffer_enabled = true
        "#;
        let sc: ScalingConfig = toml::from_str(toml).unwrap();
        assert_eq!(sc.min_replicas, 0);
        assert_eq!(sc.max_replicas, 10);
        assert!((sc.target_utilization - 0.7).abs() < f64::EPSILON);
        assert_eq!(sc.scale_down_delay_secs, 300);
        assert_eq!(sc.executor, "box");
    }
}
