//! Service configuration — upstream backends and load balancing

use serde::{Deserialize, Serialize};

/// Load balancing strategy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[derive(Default)]
pub enum Strategy {
    /// Distribute requests evenly across all servers
    #[default]
    RoundRobin,
    /// Distribute based on server weights
    Weighted,
    /// Route to the server with fewest active connections
    LeastConnections,
    /// Random server selection
    Random,
}


impl std::str::FromStr for Strategy {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim() {
            "round-robin" => Ok(Self::RoundRobin),
            "weighted" => Ok(Self::Weighted),
            "least-connections" => Ok(Self::LeastConnections),
            "random" => Ok(Self::Random),
            other => Err(format!("unknown strategy: {}", other)),
        }
    }
}

/// Service configuration — defines an upstream backend group
///
/// # Example
///
/// ```toml
/// [services.backend.load_balancer]
/// strategy = "round-robin"
/// [[services.backend.load_balancer.servers]]
/// url = "http://127.0.0.1:8001"
/// weight = 1
/// [[services.backend.load_balancer.servers]]
/// url = "http://127.0.0.1:8002"
/// weight = 2
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceConfig {
    /// Load balancer configuration
    pub load_balancer: LoadBalancerConfig,

    /// Autoscaling configuration
    #[serde(default)]
    pub scaling: Option<super::scaling::ScalingConfig>,

    /// Revision-based traffic splitting
    #[serde(default)]
    pub revisions: Vec<super::scaling::RevisionConfig>,

    /// Gradual rollout configuration
    #[serde(default)]
    pub rollout: Option<super::scaling::RolloutConfig>,

    /// Traffic mirroring — copy a percentage of traffic to a shadow service
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,

    /// Failover — fallback to a secondary service when primary is fully unhealthy
    #[serde(default)]
    pub failover: Option<FailoverConfig>,
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    /// Balancing strategy
    #[serde(default)]
    pub strategy: Strategy,

    /// Backend servers
    #[serde(default)]
    pub servers: Vec<ServerConfig>,

    /// Health check configuration
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,

    /// Sticky session configuration (cookie name)
    #[serde(default)]
    pub sticky: Option<StickyConfig>,
}

/// Individual backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server URL (e.g., "http://127.0.0.1:8001" or "h2c://127.0.0.1:50051")
    pub url: String,

    /// Server weight for weighted load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,
}

fn default_weight() -> u32 {
    1
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// HTTP path to probe (e.g., "/health")
    pub path: String,

    /// Check interval (e.g., "10s", "30s")
    #[serde(default = "default_interval")]
    pub interval: String,

    /// Timeout for each health check request
    #[serde(default = "default_timeout")]
    pub timeout: String,

    /// Number of consecutive failures before marking unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Number of consecutive successes before marking healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

fn default_interval() -> String {
    "10s".to_string()
}

fn default_timeout() -> String {
    "5s".to_string()
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    1
}

/// Sticky session configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickyConfig {
    /// Cookie name for session affinity
    pub cookie: String,
}

/// Traffic mirroring configuration — copy a percentage of live traffic
/// to a shadow backend for testing without affecting the primary response.
///
/// # Example
///
/// ```toml
/// [services.backend.mirror]
/// service = "shadow-backend"
/// percentage = 10
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Target shadow service name (must exist in services)
    pub service: String,

    /// Percentage of traffic to mirror (0–100, default: 100)
    #[serde(default = "default_mirror_percentage")]
    pub percentage: u8,
}

fn default_mirror_percentage() -> u8 {
    100
}

/// Failover configuration — automatic fallback to a secondary backend pool
/// when the primary service has zero healthy backends.
///
/// # Example
///
/// ```toml
/// [services.backend.failover]
/// service = "backup-backend"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    /// Fallback service name (must exist in services)
    pub service: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_default() {
        assert_eq!(Strategy::default(), Strategy::RoundRobin);
    }

    #[test]
    fn test_strategy_serialization() {
        let json = serde_json::to_string(&Strategy::LeastConnections).unwrap();
        assert_eq!(json, "\"least-connections\"");
        let parsed: Strategy = serde_json::from_str("\"weighted\"").unwrap();
        assert_eq!(parsed, Strategy::Weighted);
    }

    #[test]
    fn test_service_parse() {
        let toml = r#"
            [load_balancer]
            strategy = "round-robin"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8002"
            weight = 2
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        assert_eq!(svc.load_balancer.strategy, Strategy::RoundRobin);
        assert_eq!(svc.load_balancer.servers.len(), 2);
        assert_eq!(svc.load_balancer.servers[0].weight, 1); // default
        assert_eq!(svc.load_balancer.servers[1].weight, 2);
    }

    #[test]
    fn test_service_with_health_check() {
        let toml = r#"
            [load_balancer]
            strategy = "least-connections"
            [load_balancer.health_check]
            path = "/health"
            interval = "5s"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        let hc = svc.load_balancer.health_check.unwrap();
        assert_eq!(hc.path, "/health");
        assert_eq!(hc.interval, "5s");
        assert_eq!(hc.timeout, "5s"); // default
        assert_eq!(hc.unhealthy_threshold, 3); // default
        assert_eq!(hc.healthy_threshold, 1); // default
    }

    #[test]
    fn test_service_with_sticky() {
        let toml = r#"
            [load_balancer]
            [load_balancer.sticky]
            cookie = "session_id"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        let sticky = svc.load_balancer.sticky.unwrap();
        assert_eq!(sticky.cookie, "session_id");
    }

    #[test]
    fn test_server_default_weight() {
        let toml = r#"
            url = "http://127.0.0.1:8001"
        "#;
        let server: ServerConfig = toml::from_str(toml).unwrap();
        assert_eq!(server.weight, 1);
    }

    #[test]
    fn test_health_check_defaults() {
        let toml = r#"
            path = "/ping"
        "#;
        let hc: HealthCheckConfig = toml::from_str(toml).unwrap();
        assert_eq!(hc.interval, "10s");
        assert_eq!(hc.timeout, "5s");
        assert_eq!(hc.unhealthy_threshold, 3);
        assert_eq!(hc.healthy_threshold, 1);
    }

    #[test]
    fn test_strategy_all_variants() {
        for (input, expected) in [
            ("\"round-robin\"", Strategy::RoundRobin),
            ("\"weighted\"", Strategy::Weighted),
            ("\"least-connections\"", Strategy::LeastConnections),
            ("\"random\"", Strategy::Random),
        ] {
            let parsed: Strategy = serde_json::from_str(input).unwrap();
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn test_strategy_from_str() {
        assert_eq!("round-robin".parse::<Strategy>(), Ok(Strategy::RoundRobin));
        assert_eq!("weighted".parse::<Strategy>(), Ok(Strategy::Weighted));
        assert_eq!("least-connections".parse::<Strategy>(), Ok(Strategy::LeastConnections));
        assert_eq!("random".parse::<Strategy>(), Ok(Strategy::Random));
        assert!("invalid".parse::<Strategy>().is_err());
    }

    // --- MirrorConfig ---

    #[test]
    fn test_mirror_config_parse() {
        let toml = r#"
            service = "shadow"
            percentage = 25
        "#;
        let mirror: MirrorConfig = toml::from_str(toml).unwrap();
        assert_eq!(mirror.service, "shadow");
        assert_eq!(mirror.percentage, 25);
    }

    #[test]
    fn test_mirror_config_default_percentage() {
        let toml = r#"
            service = "shadow"
        "#;
        let mirror: MirrorConfig = toml::from_str(toml).unwrap();
        assert_eq!(mirror.percentage, 100);
    }

    #[test]
    fn test_service_with_mirror() {
        let toml = r#"
            [load_balancer]
            strategy = "round-robin"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"

            [mirror]
            service = "shadow-backend"
            percentage = 10
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        let mirror = svc.mirror.unwrap();
        assert_eq!(mirror.service, "shadow-backend");
        assert_eq!(mirror.percentage, 10);
    }

    // --- FailoverConfig ---

    #[test]
    fn test_failover_config_parse() {
        let toml = r#"
            service = "backup"
        "#;
        let failover: FailoverConfig = toml::from_str(toml).unwrap();
        assert_eq!(failover.service, "backup");
    }

    #[test]
    fn test_service_with_failover() {
        let toml = r#"
            [load_balancer]
            strategy = "round-robin"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"

            [failover]
            service = "backup-pool"
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        let failover = svc.failover.unwrap();
        assert_eq!(failover.service, "backup-pool");
    }

    #[test]
    fn test_service_no_mirror_no_failover() {
        let toml = r#"
            [load_balancer]
            strategy = "round-robin"
            [[load_balancer.servers]]
            url = "http://127.0.0.1:8001"
        "#;
        let svc: ServiceConfig = toml::from_str(toml).unwrap();
        assert!(svc.mirror.is_none());
        assert!(svc.failover.is_none());
    }
}
