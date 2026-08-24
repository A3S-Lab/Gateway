//! Service configuration — upstream backends and load balancing

use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_REQUEST_TIMEOUT: &str = "30s";
const DEFAULT_STREAM_IDLE_TIMEOUT: &str = "5m";
const DEFAULT_STREAM_TOTAL_TIMEOUT: &str = "60m";
const MAX_MANAGED_TARGET_UNIT_ID_BYTES: usize = 512;
const MAX_EXACT_ACL_INTEGER: u64 = (1_u64 << 53) - 1;

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
/// ```acl
/// services "backend" {
///   load_balancer {
///     strategy             = "round-robin"
///     request_timeout      = "30s"
///     stream_idle_timeout  = "5m"
///     stream_total_timeout = "60m"
///     servers {
///       url    = "http://127.0.0.1:8001"
///       weight = 1
///     }
///     servers {
///       url    = "http://127.0.0.1:8002"
///       weight = 2
///     }
///   }
/// }
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

    /// Gradual rollout syntax retained for an explicit unsupported-feature error
    #[serde(default)]
    pub rollout: Option<super::scaling::RolloutConfig>,

    /// Traffic mirroring — copy a percentage of traffic to a shadow service
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,

    /// Failover — fallback to a secondary service when primary is fully unhealthy
    #[serde(default)]
    pub failover: Option<FailoverConfig>,
}

impl ServiceConfig {
    /// Whether this service obtains live upstreams from the standalone Box
    /// executor instead of requiring a configured server at startup.
    pub(crate) fn uses_box_endpoint_discovery(&self) -> bool {
        self.scaling
            .as_ref()
            .is_some_and(|scaling| scaling.executor == "box" && scaling.container_concurrency > 0)
    }
}

/// Load balancer configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancerConfig {
    /// Balancing strategy
    #[serde(default)]
    pub strategy: Strategy,

    /// Maximum time to wait for upstream response headers.
    #[serde(default = "default_request_timeout")]
    pub request_timeout: String,

    /// Maximum silence between upstream streaming response chunks.
    #[serde(default = "default_stream_idle_timeout")]
    pub stream_idle_timeout: String,

    /// Maximum lifetime of one upstream streaming operation.
    #[serde(default = "default_stream_total_timeout")]
    pub stream_total_timeout: String,

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

pub(crate) fn default_request_timeout() -> String {
    DEFAULT_REQUEST_TIMEOUT.to_string()
}

pub(crate) fn default_stream_idle_timeout() -> String {
    DEFAULT_STREAM_IDLE_TIMEOUT.to_string()
}

pub(crate) fn default_stream_total_timeout() -> String {
    DEFAULT_STREAM_TOTAL_TIMEOUT.to_string()
}

/// Parse a human-readable duration string used by service-level timeouts.
pub(crate) fn parse_duration(value: &str) -> std::result::Result<Duration, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("duration cannot be empty".to_string());
    }

    let (digits, multiplier) = if let Some(raw) = trimmed.strip_suffix("ms") {
        (raw, DurationUnit::Millis)
    } else if let Some(raw) = trimmed.strip_suffix('s') {
        (raw, DurationUnit::Seconds)
    } else if let Some(raw) = trimmed.strip_suffix('m') {
        (raw, DurationUnit::Minutes)
    } else {
        (trimmed, DurationUnit::Seconds)
    };

    let amount = digits
        .trim()
        .parse::<u64>()
        .map_err(|_| format!("invalid duration '{}'", value))?;
    if amount == 0 {
        return Err("duration must be greater than zero".to_string());
    }

    Ok(match multiplier {
        DurationUnit::Millis => Duration::from_millis(amount),
        DurationUnit::Seconds => Duration::from_secs(amount),
        DurationUnit::Minutes => Duration::from_secs(
            amount
                .checked_mul(60)
                .ok_or_else(|| format!("duration '{}' is too large", value))?,
        ),
    })
}

enum DurationUnit {
    Millis,
    Seconds,
    Minutes,
}

/// Individual backend server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Server URL (for example, `http://127.0.0.1:8001`,
    /// `https://api.example.com`, or `h2c://127.0.0.1:50051`).
    pub url: String,

    /// Server weight for weighted load balancing (default: 1)
    #[serde(default = "default_weight")]
    pub weight: u32,

    /// Optional managed identity for the exact upstream generation.
    ///
    /// This remains optional so standalone configurations and older managed
    /// snapshots retain their existing behavior. When present, validation
    /// requires `cloud-managed` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<ManagedTargetConfig>,
}

/// Managed-control-plane identity of one configured upstream generation.
///
/// The endpoint URL is intentionally not part of this value. Cloud may replace
/// an endpoint while retaining logical target fields, and telemetry must never
/// expose credentials or private network coordinates from a URL.
/// User-authored ACL values remain restricted to `cloud-managed` mode. The
/// programmatic Managed Service overlay also uses this closed identity for
/// host-owned private Runtime generations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedTargetConfig {
    /// Stable logical target selected by the managed snapshot.
    pub target_id: uuid::Uuid,

    /// Provider-neutral Runtime unit identity.
    pub unit_id: String,

    /// Positive Runtime generation for the unit.
    pub generation: u64,
}

impl ManagedTargetConfig {
    pub(crate) fn validate(&self) -> std::result::Result<(), String> {
        if self.target_id.is_nil() {
            return Err("target_id must not be the nil UUID".to_string());
        }
        if self.generation == 0 {
            return Err("generation must be greater than zero".to_string());
        }
        if self.generation > MAX_EXACT_ACL_INTEGER {
            return Err(format!(
                "generation must not exceed the exact ACL integer limit {MAX_EXACT_ACL_INTEGER}"
            ));
        }
        if self.unit_id.is_empty()
            || self.unit_id.len() > MAX_MANAGED_TARGET_UNIT_ID_BYTES
            || self.unit_id.trim() != self.unit_id
            || self.unit_id.chars().any(char::is_whitespace)
            || self.unit_id.chars().any(char::is_control)
        {
            return Err(format!(
                "unit_id must be a canonical non-empty value without whitespace or control characters and at most {MAX_MANAGED_TARGET_UNIT_ID_BYTES} bytes"
            ));
        }
        Ok(())
    }
}

fn default_weight() -> u32 {
    1
}

/// Health check configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// Absolute HTTP path to probe (e.g., "/health")
    pub path: String,

    /// Positive check interval (e.g., "10s", "30s")
    #[serde(default = "default_interval")]
    pub interval: String,

    /// Positive timeout for each health check request
    #[serde(default = "default_timeout")]
    pub timeout: String,

    /// Positive number of consecutive failures before marking unhealthy
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,

    /// Positive number of consecutive successes before marking healthy
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
}

impl HealthCheckConfig {
    pub(crate) fn validate_and_parse_durations(
        &self,
    ) -> std::result::Result<(Duration, Duration), String> {
        if self.path.is_empty() {
            return Err("path cannot be empty".to_string());
        }
        if !self.path.starts_with('/') {
            return Err(format!("path '{}' must begin with '/'", self.path));
        }
        if self.unhealthy_threshold == 0 {
            return Err("unhealthy_threshold must be greater than zero".to_string());
        }
        if self.healthy_threshold == 0 {
            return Err("healthy_threshold must be greater than zero".to_string());
        }

        let interval =
            parse_duration(&self.interval).map_err(|error| format!("invalid interval: {error}"))?;
        let timeout =
            parse_duration(&self.timeout).map_err(|error| format!("invalid timeout: {error}"))?;
        Ok((interval, timeout))
    }
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
/// ```acl
/// services "backend" {
///   mirror {
///     service    = "shadow-backend"
///     percentage = 10
///   }
/// }
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
/// ```acl
/// services "backend" {
///   failover {
///     service = "backup-backend"
///   }
/// }
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
        let acl = r#"
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" },
                    { url = "http://127.0.0.1:8002", weight = 2 }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        assert_eq!(svc.load_balancer.strategy, Strategy::RoundRobin);
        assert_eq!(svc.load_balancer.request_timeout, "30s");
        assert_eq!(svc.load_balancer.stream_idle_timeout, "5m");
        assert_eq!(svc.load_balancer.stream_total_timeout, "60m");
        assert_eq!(svc.load_balancer.servers.len(), 2);
        assert_eq!(svc.load_balancer.servers[0].weight, 1); // default
        assert_eq!(svc.load_balancer.servers[1].weight, 2);
    }

    #[test]
    fn test_service_with_request_timeout() {
        let acl = r#"
            load_balancer {
                strategy        = "round-robin"
                request_timeout = "750ms"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        assert_eq!(svc.load_balancer.request_timeout, "750ms");
        assert_eq!(
            parse_duration(&svc.load_balancer.request_timeout).unwrap(),
            Duration::from_millis(750)
        );
    }

    #[test]
    fn test_service_with_stream_timeouts() {
        let acl = r#"
            load_balancer {
                stream_idle_timeout  = "750ms"
                stream_total_timeout = "2m"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        assert_eq!(svc.load_balancer.stream_idle_timeout, "750ms");
        assert_eq!(svc.load_balancer.stream_total_timeout, "2m");
        assert_eq!(
            parse_duration(&svc.load_balancer.stream_idle_timeout).unwrap(),
            Duration::from_millis(750)
        );
        assert_eq!(
            parse_duration(&svc.load_balancer.stream_total_timeout).unwrap(),
            Duration::from_secs(120)
        );
    }

    #[test]
    fn test_stream_timeout_serde_defaults_and_roundtrip() {
        let parsed: LoadBalancerConfig = serde_json::from_str(r#"{"servers":[]}"#).unwrap();
        assert_eq!(parsed.request_timeout, "30s");
        assert_eq!(parsed.stream_idle_timeout, "5m");
        assert_eq!(parsed.stream_total_timeout, "60m");

        let serialized = serde_json::to_value(parsed).unwrap();
        assert_eq!(serialized["stream_idle_timeout"], "5m");
        assert_eq!(serialized["stream_total_timeout"], "60m");
    }

    #[test]
    fn test_service_with_health_check() {
        let acl = r#"
            load_balancer {
                strategy = "least-connections"
                health_check {
                    path     = "/health"
                    interval = "5s"
                }
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        let hc = svc.load_balancer.health_check.unwrap();
        assert_eq!(hc.path, "/health");
        assert_eq!(hc.interval, "5s");
        assert_eq!(hc.timeout, "5s"); // default
        assert_eq!(hc.unhealthy_threshold, 3); // default
        assert_eq!(hc.healthy_threshold, 1); // default
    }

    #[test]
    fn test_service_with_sticky() {
        let acl = r#"
            load_balancer {
                sticky {
                    cookie = "session_id"
                }
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        let sticky = svc.load_balancer.sticky.unwrap();
        assert_eq!(sticky.cookie, "session_id");
    }

    #[test]
    fn test_server_default_weight() {
        let acl = r#"
            url = "http://127.0.0.1:8001"
        "#;
        let server: ServerConfig = crate::config::acl::parse_server_body(acl).unwrap();
        assert_eq!(server.weight, 1);
        assert!(server.target.is_none());
    }

    #[test]
    fn test_server_managed_target_parse() {
        let target_id = uuid::Uuid::new_v4();
        let acl = format!(
            r#"
            url = "http://127.0.0.1:8001"
            target = {{
                target_id = "{target_id}"
                unit_id = "workload:018f:revision:0190"
                generation = 7
            }}
            "#
        );

        let server: ServerConfig = crate::config::acl::parse_server_body(&acl).unwrap();
        let target = server.target.expect("typed managed target");
        assert_eq!(target.target_id, target_id);
        assert_eq!(target.unit_id, "workload:018f:revision:0190");
        assert_eq!(target.generation, 7);
    }

    #[test]
    fn test_server_managed_target_block_parse() {
        let target_id = uuid::Uuid::new_v4();
        let acl = format!(
            r#"
            url = "http://127.0.0.1:8001"
            target {{
                target_id = "{target_id}"
                unit_id = "workload:018f:revision:0190"
                generation = 7
            }}
            "#
        );

        let server: ServerConfig = crate::config::acl::parse_server_body(&acl).unwrap();
        assert_eq!(server.target.expect("target block").target_id, target_id);
    }

    #[test]
    fn test_server_managed_target_is_complete_and_closed() {
        let target_id = uuid::Uuid::new_v4();
        let missing_unit = format!(
            r#"
            url = "http://127.0.0.1:8001"
            target = {{ target_id = "{target_id}", generation = 1 }}
            "#
        );
        let error = crate::config::acl::parse_server_body(&missing_unit).unwrap_err();
        assert!(error.to_string().contains("unit_id"));

        let unknown_field = format!(
            r#"
            url = "http://127.0.0.1:8001"
            target = {{
                target_id = "{target_id}"
                unit_id = "workload:018f:revision:0190"
                generation = 1
                endpoint = "http://credential-bearing.example"
            }}
            "#
        );
        let error = crate::config::acl::parse_server_body(&unknown_field).unwrap_err();
        assert!(error
            .to_string()
            .contains("Unknown managed target field 'endpoint'"));

        let duplicate = format!(
            r#"
            url = "http://127.0.0.1:8001"
            target = {{
                target_id = "{target_id}"
                unit_id = "workload:018f:revision:0190"
                generation = 1
            }}
            target {{
                target_id = "{target_id}"
                unit_id = "workload:018f:revision:0190"
                generation = 1
            }}
            "#
        );
        let error = crate::config::acl::parse_server_body(&duplicate).unwrap_err();
        assert!(error.to_string().contains("duplicate managed target"));
    }

    #[test]
    fn test_health_check_defaults() {
        let acl = r#"
            path = "/ping"
        "#;
        let hc: HealthCheckConfig = crate::config::acl::parse_health_check_body(acl).unwrap();
        assert_eq!(hc.interval, "10s");
        assert_eq!(hc.timeout, "5s");
        assert_eq!(hc.unhealthy_threshold, 3);
        assert_eq!(hc.healthy_threshold, 1);
    }

    #[test]
    fn test_parse_duration_units() {
        assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
        assert_eq!(parse_duration("30").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn test_parse_duration_rejects_invalid_values() {
        assert!(parse_duration("").is_err());
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("abc").is_err());
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
        assert_eq!(
            "least-connections".parse::<Strategy>(),
            Ok(Strategy::LeastConnections)
        );
        assert_eq!("random".parse::<Strategy>(), Ok(Strategy::Random));
        assert!("invalid".parse::<Strategy>().is_err());
    }

    // --- MirrorConfig ---

    #[test]
    fn test_mirror_config_parse() {
        let acl = r#"
            service    = "shadow"
            percentage = 25
        "#;
        let mirror: MirrorConfig = crate::config::acl::parse_mirror_body(acl).unwrap();
        assert_eq!(mirror.service, "shadow");
        assert_eq!(mirror.percentage, 25);
    }

    #[test]
    fn test_mirror_config_default_percentage() {
        let acl = r#"
            service = "shadow"
        "#;
        let mirror: MirrorConfig = crate::config::acl::parse_mirror_body(acl).unwrap();
        assert_eq!(mirror.percentage, 100);
    }

    #[test]
    fn test_service_with_mirror() {
        let acl = r#"
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
            mirror {
                service    = "shadow-backend"
                percentage = 10
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        let mirror = svc.mirror.unwrap();
        assert_eq!(mirror.service, "shadow-backend");
        assert_eq!(mirror.percentage, 10);
    }

    // --- FailoverConfig ---

    #[test]
    fn test_failover_config_parse() {
        let acl = r#"
            service = "backup"
        "#;
        let failover: FailoverConfig = crate::config::acl::parse_failover_body(acl).unwrap();
        assert_eq!(failover.service, "backup");
    }

    #[test]
    fn test_service_with_failover() {
        let acl = r#"
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
            failover {
                service = "backup-pool"
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        let failover = svc.failover.unwrap();
        assert_eq!(failover.service, "backup-pool");
    }

    #[test]
    fn test_service_no_mirror_no_failover() {
        let acl = r#"
            load_balancer {
                strategy = "round-robin"
                servers = [
                    { url = "http://127.0.0.1:8001" }
                ]
            }
        "#;
        let svc: ServiceConfig = crate::config::acl::parse_service_body(acl).unwrap();
        assert!(svc.mirror.is_none());
        assert!(svc.failover.is_none());
    }
}
