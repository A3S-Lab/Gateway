//! Dashboard API — serves gateway status, metrics, and management endpoints
//!
//! Extracted from `gateway.rs` to keep the orchestrator focused on lifecycle.

use crate::gateway::Gateway;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// Route information for the management API
#[derive(Debug, Clone, Serialize)]
pub struct RouteInfo {
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entrypoints: Vec<String>,
    pub middlewares: Vec<String>,
    pub priority: i32,
}

/// Service information with live backend health
#[derive(Debug, Clone, Serialize)]
pub struct ServiceInfo {
    pub name: String,
    pub strategy: String,
    pub backends_total: usize,
    pub backends_healthy: usize,
    pub backends: Vec<BackendInfo>,
}

/// Backend health snapshot
#[derive(Debug, Clone, Serialize)]
pub struct BackendInfo {
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub active_connections: usize,
}

/// Backend detail with owning service name (for flat /backends listing)
#[derive(Debug, Clone, Serialize)]
pub struct BackendDetail {
    pub service: String,
    pub url: String,
    pub weight: u32,
    pub healthy: bool,
    pub active_connections: usize,
}

/// Gateway version information
#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
}

impl VersionInfo {
    pub(crate) fn current() -> Self {
        Self {
            name: env!("CARGO_PKG_NAME"),
            version: env!("CARGO_PKG_VERSION"),
        }
    }
}

// ---------------------------------------------------------------------------
// Dashboard API handler
// ---------------------------------------------------------------------------

/// Dashboard API — serves gateway status and metrics
pub struct DashboardApi {
    /// Path prefix for the dashboard
    pub path_prefix: String,
}

impl DashboardApi {
    /// Create a new dashboard API
    pub fn new(path_prefix: impl Into<String>) -> Self {
        Self {
            path_prefix: path_prefix.into(),
        }
    }

    /// Check if a request path matches the dashboard
    pub fn matches(&self, path: &str) -> bool {
        path.starts_with(&self.path_prefix)
    }

    /// Handle a dashboard API request
    pub fn handle(&self, path: &str, gateway: &Gateway) -> Option<DashboardResponse> {
        let sub_path = path.strip_prefix(&self.path_prefix)?;

        match sub_path {
            "/health" | "/health/" => {
                let health = gateway.health();
                let body = serde_json::to_string_pretty(&health).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            "/metrics" | "/metrics/" => {
                let _snapshot = gateway.metrics().snapshot();
                let body = gateway.metrics().render_prometheus();
                Some(DashboardResponse {
                    status: 200,
                    content_type: "text/plain; version=0.0.4".to_string(),
                    body,
                })
            }
            "/config" | "/config/" => {
                let config = gateway.config();
                let body = serde_json::to_string_pretty(&config).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            "/routes" | "/routes/" => {
                let routes = gateway.routes_snapshot();
                let body = serde_json::to_string_pretty(&routes).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            "/services" | "/services/" => {
                let services = gateway.services_snapshot();
                let body = serde_json::to_string_pretty(&services).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            "/backends" | "/backends/" => {
                let backends = gateway.backends_snapshot();
                let body = serde_json::to_string_pretty(&backends).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            "/version" | "/version/" => {
                let version = VersionInfo::current();
                let body = serde_json::to_string_pretty(&version).unwrap_or_default();
                Some(DashboardResponse::json(200, body))
            }
            s if s.starts_with("/routes/") => {
                let name = &s["/routes/".len()..].trim_end_matches('/');
                let routes = gateway.routes_snapshot();
                match routes.into_iter().find(|r| r.name == *name) {
                    Some(route) => {
                        let body = serde_json::to_string_pretty(&route).unwrap_or_default();
                        Some(DashboardResponse::json(200, body))
                    }
                    None => Some(DashboardResponse::not_found("Route not found")),
                }
            }
            s if s.starts_with("/services/") => {
                let name = &s["/services/".len()..].trim_end_matches('/');
                let services = gateway.services_snapshot();
                match services.into_iter().find(|svc| svc.name == *name) {
                    Some(svc) => {
                        let body = serde_json::to_string_pretty(&svc).unwrap_or_default();
                        Some(DashboardResponse::json(200, body))
                    }
                    None => Some(DashboardResponse::not_found("Service not found")),
                }
            }
            _ => Some(DashboardResponse::not_found("Not found")),
        }
    }
}

/// Response from the dashboard API
#[derive(Debug, Clone)]
pub struct DashboardResponse {
    /// HTTP status code
    pub status: u16,
    /// Content-Type header
    pub content_type: String,
    /// Response body
    pub body: String,
}

impl DashboardResponse {
    pub(crate) fn json(status: u16, body: String) -> Self {
        Self {
            status,
            content_type: "application/json".to_string(),
            body,
        }
    }

    pub(crate) fn not_found(message: &str) -> Self {
        Self::json(404, format!(r#"{{"error":"{}"}}"#, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GatewayConfig, LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy,
    };
    use crate::router::RouterTable;
    use crate::service::ServiceRegistry;
    use std::sync::Arc;

    fn minimal_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.routers.clear();
        config.services.clear();
        config.middlewares.clear();
        config
    }

    fn full_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "backend".to_string(),
                entrypoints: vec!["web".to_string()],
                middlewares: vec![],
                priority: 0,
            },
        );
        config.services.insert(
            "backend".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".to_string(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        config
    }

    /// Build a Gateway with live_registry and live_router_table populated
    fn gateway_with_live_data() -> Gateway {
        let config = full_config();
        let gw = Gateway::new(config.clone()).unwrap();

        let rt = RouterTable::from_config(&config.routers).unwrap();
        let reg = ServiceRegistry::from_config(&config.services).unwrap();
        gw.set_live_data(Arc::new(rt), Arc::new(reg));

        gw
    }

    // --- DashboardApi ---

    #[test]
    fn test_dashboard_matches() {
        let api = DashboardApi::new("/api/gateway");
        assert!(api.matches("/api/gateway/health"));
        assert!(api.matches("/api/gateway/metrics"));
        assert!(!api.matches("/other/path"));
    }

    #[test]
    fn test_dashboard_health() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/api/gateway/health", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("json"));
        assert!(resp.body.contains("Created"));
    }

    #[test]
    fn test_dashboard_metrics() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/api/gateway/metrics", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.content_type.contains("text/plain"));
    }

    #[test]
    fn test_dashboard_config() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/api/gateway/config", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("entrypoints"));
    }

    #[test]
    fn test_dashboard_not_found() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/api/gateway/unknown", &gw).unwrap();
        assert_eq!(resp.status, 404);
    }

    #[test]
    fn test_dashboard_no_match() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/other/path", &gw);
        assert!(resp.is_none());
    }

    #[test]
    fn test_dashboard_routes_endpoint() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/routes", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("api"));
        assert!(resp.body.contains("PathPrefix"));
    }

    #[test]
    fn test_dashboard_routes_trailing_slash() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/routes/", &gw).unwrap();
        assert_eq!(resp.status, 200);
    }

    #[test]
    fn test_dashboard_route_by_name() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/routes/api", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("backend"));
    }

    #[test]
    fn test_dashboard_route_by_name_not_found() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/routes/nonexistent", &gw).unwrap();
        assert_eq!(resp.status, 404);
        assert!(resp.body.contains("Route not found"));
    }

    #[test]
    fn test_dashboard_services_endpoint() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/services", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("backend"));
        assert!(resp.body.contains("backends_healthy"));
    }

    #[test]
    fn test_dashboard_service_by_name() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/services/backend", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("http://127.0.0.1:8001"));
    }

    #[test]
    fn test_dashboard_service_by_name_not_found() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api
            .handle("/api/gateway/services/nonexistent", &gw)
            .unwrap();
        assert_eq!(resp.status, 404);
        assert!(resp.body.contains("Service not found"));
    }

    #[test]
    fn test_dashboard_backends_endpoint() {
        let api = DashboardApi::new("/api/gateway");
        let gw = gateway_with_live_data();
        let resp = api.handle("/api/gateway/backends", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("http://127.0.0.1:8001"));
        assert!(resp.body.contains("\"service\""));
    }

    #[test]
    fn test_dashboard_version_endpoint() {
        let api = DashboardApi::new("/api/gateway");
        let gw = Gateway::new(minimal_config()).unwrap();
        let resp = api.handle("/api/gateway/version", &gw).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.body.contains("a3s-gateway"));
        assert!(resp.body.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn test_version_info() {
        let v = VersionInfo::current();
        assert_eq!(v.name, "a3s-gateway");
        assert!(!v.version.is_empty());
    }

    #[test]
    fn test_dashboard_response_helpers() {
        let resp = DashboardResponse::json(200, "{}".to_string());
        assert_eq!(resp.status, 200);
        assert_eq!(resp.content_type, "application/json");

        let resp = DashboardResponse::not_found("gone");
        assert_eq!(resp.status, 404);
        assert!(resp.body.contains("gone"));
    }
}
