//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::Result;
use crate::observability::metrics::GatewayMetrics;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

/// The main Gateway — coordinates all components
pub struct Gateway {
    /// Current configuration
    config: Arc<RwLock<GatewayConfig>>,
    /// Gateway runtime state
    state: Arc<RwLock<GatewayState>>,
    /// Start time
    start_time: Instant,
    /// Shutdown flag
    shutdown: Arc<AtomicBool>,
    /// Metrics collector
    metrics: Arc<GatewayMetrics>,
    /// Active entrypoint task handles
    handles: RwLock<Vec<tokio::task::JoinHandle<()>>>,
}

impl Gateway {
    /// Create a new gateway from configuration
    pub fn new(config: GatewayConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(GatewayState::Created)),
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(GatewayMetrics::new()),
            handles: RwLock::new(Vec::new()),
        })
    }

    /// Start the gateway — binds listeners and begins accepting connections
    pub async fn start(&self) -> Result<()> {
        self.set_state(GatewayState::Starting);

        let config = self.config.read().unwrap().clone();

        // Build router table
        let router_table = RouterTable::from_config(&config.routers)?;
        tracing::info!(routes = router_table.len(), "Router table compiled");

        // Build service registry
        let service_registry = ServiceRegistry::from_config(&config.services)?;
        tracing::info!(services = service_registry.len(), "Services registered");

        // Start health checks
        service_registry.start_health_checks(&config.services).await;

        // Build shared state
        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table: Arc::new(router_table),
            service_registry: Arc::new(service_registry),
            middleware_configs: Arc::new(config.middlewares.clone()),
            http_proxy: Arc::new(HttpProxy::new()),
        });

        // Start all entrypoints
        let new_handles = entrypoint::start_entrypoints(&config, gw_state).await?;
        tracing::info!(entrypoints = new_handles.len(), "Entrypoints started");

        let mut handles = self.handles.write().unwrap();
        *handles = new_handles;

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway is running");

        Ok(())
    }

    /// Reload configuration without stopping the gateway
    pub async fn reload(&self, new_config: GatewayConfig) -> Result<()> {
        new_config.validate()?;
        self.set_state(GatewayState::Reloading);

        tracing::info!("Reloading gateway configuration");

        // Build new components
        let router_table = RouterTable::from_config(&new_config.routers)?;
        let service_registry = ServiceRegistry::from_config(&new_config.services)?;
        service_registry
            .start_health_checks(&new_config.services)
            .await;

        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table: Arc::new(router_table),
            service_registry: Arc::new(service_registry),
            middleware_configs: Arc::new(new_config.middlewares.clone()),
            http_proxy: Arc::new(HttpProxy::new()),
        });

        // Stop old entrypoints
        {
            let mut handles = self.handles.write().unwrap();
            for handle in handles.drain(..) {
                handle.abort();
            }
        }

        // Start new entrypoints
        let new_handles = entrypoint::start_entrypoints(&new_config, gw_state).await?;
        {
            let mut handles = self.handles.write().unwrap();
            *handles = new_handles;
        }

        // Update stored config
        {
            let mut config = self.config.write().unwrap();
            *config = new_config;
        }

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway configuration reloaded");

        Ok(())
    }

    /// Initiate graceful shutdown
    pub async fn shutdown(&self) {
        if self.shutdown.swap(true, Ordering::SeqCst) {
            return; // Already shutting down
        }

        self.set_state(GatewayState::Stopping);
        tracing::info!("Gateway shutting down");

        // Abort all entrypoint tasks
        let mut handles = self.handles.write().unwrap();
        for handle in handles.drain(..) {
            handle.abort();
        }

        self.set_state(GatewayState::Stopped);
        tracing::info!("Gateway stopped");
    }

    /// Wait for a shutdown signal (Ctrl+C)
    pub async fn wait_for_shutdown(&self) {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        self.shutdown().await;
    }

    /// Get the current gateway state
    pub fn state(&self) -> GatewayState {
        self.state.read().unwrap().clone()
    }

    /// Get a health status snapshot
    pub fn health(&self) -> HealthStatus {
        HealthStatus {
            state: self.state(),
            uptime_secs: self.start_time.elapsed().as_secs(),
            active_connections: self.metrics.snapshot().active_connections as usize,
            total_requests: self.metrics.snapshot().total_requests,
        }
    }

    /// Get the metrics collector
    pub fn metrics(&self) -> &Arc<GatewayMetrics> {
        &self.metrics
    }

    /// Get the current configuration
    pub fn config(&self) -> GatewayConfig {
        self.config.read().unwrap().clone()
    }

    /// Check if the gateway is running
    pub fn is_running(&self) -> bool {
        self.state() == GatewayState::Running
    }

    /// Check if shutdown has been requested
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn set_state(&self, new_state: GatewayState) {
        let mut state = self.state.write().unwrap();
        tracing::debug!(from = %*state, to = %new_state, "State transition");
        *state = new_state;
    }
}

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
                Some(DashboardResponse {
                    status: 200,
                    content_type: "application/json".to_string(),
                    body,
                })
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
                Some(DashboardResponse {
                    status: 200,
                    content_type: "application/json".to_string(),
                    body,
                })
            }
            _ => Some(DashboardResponse {
                status: 404,
                content_type: "application/json".to_string(),
                body: r#"{"error":"Not found"}"#.to_string(),
            }),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancerConfig, RouterConfig, ServerConfig, ServiceConfig, Strategy};

    fn minimal_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.routers.clear();
        config.services.clear();
        config.middlewares.clear();
        config
    }

    #[allow(dead_code)]
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
            },
        );
        config
    }

    // --- Gateway construction ---

    #[test]
    fn test_gateway_new() {
        let gw = Gateway::new(minimal_config()).unwrap();
        assert_eq!(gw.state(), GatewayState::Created);
        assert!(!gw.is_running());
        assert!(!gw.is_shutdown());
    }

    #[test]
    fn test_gateway_new_invalid_config() {
        let mut config = minimal_config();
        config.routers.insert(
            "bad".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "nonexistent".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );
        let result = Gateway::new(config);
        assert!(result.is_err());
    }

    // --- Health ---

    #[test]
    fn test_gateway_health() {
        let gw = Gateway::new(minimal_config()).unwrap();
        let health = gw.health();
        assert_eq!(health.state, GatewayState::Created);
        assert_eq!(health.total_requests, 0);
    }

    // --- Config ---

    #[test]
    fn test_gateway_config() {
        let config = minimal_config();
        let gw = Gateway::new(config.clone()).unwrap();
        let retrieved = gw.config();
        assert_eq!(retrieved.entrypoints.len(), config.entrypoints.len());
    }

    // --- Metrics ---

    #[test]
    fn test_gateway_metrics() {
        let gw = Gateway::new(minimal_config()).unwrap();
        let metrics = gw.metrics();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_requests, 0);
    }

    // --- State transitions ---

    #[test]
    fn test_state_transitions() {
        let gw = Gateway::new(minimal_config()).unwrap();
        assert_eq!(gw.state(), GatewayState::Created);

        gw.set_state(GatewayState::Starting);
        assert_eq!(gw.state(), GatewayState::Starting);

        gw.set_state(GatewayState::Running);
        assert!(gw.is_running());

        gw.set_state(GatewayState::Stopping);
        assert!(!gw.is_running());

        gw.set_state(GatewayState::Stopped);
        assert_eq!(gw.state(), GatewayState::Stopped);
    }

    // --- Shutdown ---

    #[tokio::test]
    async fn test_gateway_shutdown() {
        let gw = Gateway::new(minimal_config()).unwrap();
        assert!(!gw.is_shutdown());
        gw.shutdown().await;
        assert!(gw.is_shutdown());
        assert_eq!(gw.state(), GatewayState::Stopped);
    }

    #[tokio::test]
    async fn test_gateway_double_shutdown() {
        let gw = Gateway::new(minimal_config()).unwrap();
        gw.shutdown().await;
        gw.shutdown().await; // Should not panic
        assert_eq!(gw.state(), GatewayState::Stopped);
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
}
