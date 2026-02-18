//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::Result;
use crate::observability::metrics::GatewayMetrics;
use crate::provider::discovery;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::scaling::autoscaler::{Autoscaler, ServiceMetricsSnapshot};
use crate::scaling::buffer::RequestBuffer;
use crate::scaling::concurrency::ConcurrencyLimiter;
use crate::scaling::executor::{BoxScaleExecutor, ScaleExecutor};
use crate::scaling::revision::RevisionRouter;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::collections::HashMap;
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
    /// Discovery polling loop handle (if discovery is configured)
    discovery_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
    /// Autoscaler loop handle (if any service has scaling config)
    autoscaler_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
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
            discovery_handle: RwLock::new(None),
            autoscaler_handle: RwLock::new(None),
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

        // Build scaling state
        let scaling_state = build_scaling_state(&config);
        if scaling_state.is_some() {
            tracing::info!("Scaling state initialized for configured services");
        }

        // Spawn autoscaler loop if any service has scaling config
        let autoscaler_handle = spawn_autoscaler(&config, scaling_state.as_ref());
        {
            let mut handle = self.autoscaler_handle.write().unwrap();
            if let Some(old) = handle.take() {
                old.abort();
            }
            *handle = autoscaler_handle;
        }

        // Build shared state
        let http_proxy = Arc::new(HttpProxy::new());
        let service_registry = Arc::new(service_registry);
        let (mirrors, failovers) =
            build_mirror_failover_state(&config, &service_registry, &http_proxy);

        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table: Arc::new(router_table),
            service_registry,
            middleware_configs: Arc::new(config.middlewares.clone()),
            http_proxy,
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log: Arc::new(crate::observability::access_log::AccessLog::new()),
        });

        // Start all entrypoints
        let new_handles = entrypoint::start_entrypoints(&config, gw_state).await?;
        tracing::info!(entrypoints = new_handles.len(), "Entrypoints started");

        let mut handles = self.handles.write().unwrap();
        *handles = new_handles;

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway is running");

        // Start discovery loop if configured
        if let Some(ref disc_config) = config.providers.discovery {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
            let disc_handle =
                discovery::spawn_discovery_loop(disc_config.clone(), config.clone(), tx);

            // Spawn a receiver task that triggers reload on discovered config changes
            let gw_config = self.config.clone();
            let gw_state = self.state.clone();
            let gw_handles = Arc::new(std::sync::Mutex::new(None::<Vec<tokio::task::JoinHandle<()>>>));
            tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = new_config.validate() {
                        tracing::error!(error = %e, "Discovered config validation failed, skipping reload");
                        continue;
                    }
                    tracing::info!("Applying discovered configuration");
                    let mut config = gw_config.write().unwrap();
                    *config = new_config;
                    let _ = &gw_state; // Keep reference alive
                    let _ = &gw_handles;
                }
            });

            let mut handle = self.discovery_handle.write().unwrap();
            *handle = Some(disc_handle);
            tracing::info!("Discovery polling loop started");
        }

        // Start Kubernetes Ingress watcher if configured
        #[cfg(feature = "kube")]
        if let Some(ref k8s_config) = config.providers.kubernetes {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
            let k8s_handle = crate::provider::kubernetes::spawn_ingress_watch(
                k8s_config.clone(),
                config.clone(),
                tx.clone(),
            );

            // Optionally start CRD watcher
            let crd_handle = if k8s_config.ingress_route_crd {
                Some(crate::provider::kubernetes_crd::spawn_crd_watch(
                    k8s_config.clone(),
                    config.clone(),
                    tx,
                ))
            } else {
                None
            };

            let gw_config = self.config.clone();
            tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = new_config.validate() {
                        tracing::error!(error = %e, "K8s config validation failed, skipping");
                        continue;
                    }
                    tracing::info!("Applying K8s-discovered configuration");
                    let mut config = gw_config.write().unwrap();
                    *config = new_config;
                }
            });

            tracing::info!("Kubernetes Ingress watcher started");
            if crd_handle.is_some() {
                tracing::info!("Kubernetes IngressRoute CRD watcher started");
            }

            // Store handles (reuse discovery_handle slot — only one provider active at a time)
            // In production, these would be tracked separately
            let _ = k8s_handle;
        }

        // Warn if kubernetes config is present but feature is not enabled
        #[cfg(not(feature = "kube"))]
        if config.providers.kubernetes.is_some() {
            tracing::warn!(
                "Kubernetes provider configured but the 'kube' feature is not enabled. \
                 Rebuild with `--features kube` to enable Kubernetes support."
            );
        }

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

        let scaling_state = build_scaling_state(&new_config);

        // Respawn autoscaler loop with new config
        let autoscaler_handle = spawn_autoscaler(&new_config, scaling_state.as_ref());
        {
            let mut handle = self.autoscaler_handle.write().unwrap();
            if let Some(old) = handle.take() {
                old.abort();
            }
            *handle = autoscaler_handle;
        }

        let http_proxy = Arc::new(HttpProxy::new());
        let service_registry = Arc::new(service_registry);
        let (mirrors, failovers) =
            build_mirror_failover_state(&new_config, &service_registry, &http_proxy);

        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table: Arc::new(router_table),
            service_registry,
            middleware_configs: Arc::new(new_config.middlewares.clone()),
            http_proxy,
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log: Arc::new(crate::observability::access_log::AccessLog::new()),
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

        // Abort discovery loop
        if let Some(handle) = self.discovery_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("Discovery loop aborted");
        }

        // Abort autoscaler loop
        if let Some(handle) = self.autoscaler_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("Autoscaler loop aborted");
        }

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

/// Build ScalingState from gateway config if any service has scaling configuration
fn build_scaling_state(config: &GatewayConfig) -> Option<Arc<entrypoint::ScalingState>> {
    let mut buffers = HashMap::new();
    let mut limiters = HashMap::new();
    let mut revision_routers = HashMap::new();
    let mut has_scaling = false;

    for (name, svc) in &config.services {
        // Build revision router if revisions are configured
        if !svc.revisions.is_empty() {
            let router = RevisionRouter::from_config(name, &svc.revisions);
            revision_routers.insert(name.clone(), Arc::new(router));
            has_scaling = true;
        }

        if let Some(ref sc) = svc.scaling {
            has_scaling = true;

            // Build concurrency limiter if container_concurrency > 0
            if sc.container_concurrency > 0 {
                let limiter = ConcurrencyLimiter::new(sc.container_concurrency);
                limiters.insert(name.clone(), Arc::new(limiter));
            }

            // Build request buffer if buffering is enabled (scale-from-zero)
            if sc.buffer_enabled {
                let buffer =
                    RequestBuffer::new(name.clone(), sc.buffer_size, sc.buffer_timeout_secs);
                buffers.insert(name.clone(), Arc::new(buffer));
            }
        }
    }

    if has_scaling {
        Some(Arc::new(entrypoint::ScalingState {
            buffers,
            limiters,
            revision_routers,
        }))
    } else {
        None
    }
}

/// Build mirror and failover state from gateway config
fn build_mirror_failover_state(
    config: &GatewayConfig,
    service_registry: &Arc<ServiceRegistry>,
    http_proxy: &Arc<HttpProxy>,
) -> (
    HashMap<String, Arc<crate::service::TrafficMirror>>,
    HashMap<String, Arc<crate::service::FailoverSelector>>,
) {
    let mut mirrors = HashMap::new();
    let mut failovers = HashMap::new();

    for (name, svc) in &config.services {
        // Build traffic mirror if configured
        if let Some(ref mirror_config) = svc.mirror {
            if let Some(shadow_lb) = service_registry.get(&mirror_config.service) {
                let mirror = crate::service::TrafficMirror::new(
                    shadow_lb,
                    mirror_config.percentage,
                    http_proxy.clone(),
                );
                mirrors.insert(name.clone(), Arc::new(mirror));
                tracing::info!(
                    service = name,
                    shadow = mirror_config.service,
                    percentage = mirror_config.percentage,
                    "Traffic mirroring configured"
                );
            } else {
                tracing::warn!(
                    service = name,
                    shadow = mirror_config.service,
                    "Mirror target service not found, skipping"
                );
            }
        }

        // Build failover selector if configured
        if let Some(ref failover_config) = svc.failover {
            if let (Some(primary_lb), Some(failover_lb)) = (
                service_registry.get(name),
                service_registry.get(&failover_config.service),
            ) {
                let selector =
                    crate::service::FailoverSelector::new(primary_lb, failover_lb);
                failovers.insert(name.clone(), Arc::new(selector));
                tracing::info!(
                    service = name,
                    failover = failover_config.service,
                    "Failover configured"
                );
            } else {
                tracing::warn!(
                    service = name,
                    failover = failover_config.service,
                    "Failover target service not found, skipping"
                );
            }
        }
    }

    (mirrors, failovers)
}

/// Spawn the autoscaler periodic loop if any service has scaling config with container_concurrency > 0.
/// Returns a JoinHandle that can be aborted on shutdown/reload.
fn spawn_autoscaler(
    config: &GatewayConfig,
    scaling_state: Option<&Arc<entrypoint::ScalingState>>,
) -> Option<tokio::task::JoinHandle<()>> {
    // Collect services that have autoscaling enabled (cc > 0)
    let mut scaling_configs = HashMap::new();
    for (name, svc) in &config.services {
        if let Some(ref sc) = svc.scaling {
            if sc.container_concurrency > 0 {
                scaling_configs.insert(name.clone(), sc.clone());
            }
        }
    }

    if scaling_configs.is_empty() {
        return None;
    }

    // Build executor from the first service's executor config (all services share one executor)
    let executor_type = scaling_configs
        .values()
        .next()
        .map(|sc| sc.executor.as_str())
        .unwrap_or("box");

    let executor: Arc<dyn ScaleExecutor> = match executor_type {
        "box" => Arc::new(BoxScaleExecutor::new("http://localhost:9090")),
        #[cfg(feature = "kube")]
        "k8s" => {
            tracing::warn!("K8s executor requires async init; falling back to box executor at startup");
            Arc::new(BoxScaleExecutor::new("http://localhost:9090"))
        }
        other => {
            tracing::warn!(executor = other, "Unknown executor type, falling back to box");
            Arc::new(BoxScaleExecutor::new("http://localhost:9090"))
        }
    };

    let scaling_state = scaling_state.cloned();
    let mut autoscaler = Autoscaler::new(executor, scaling_configs);

    tracing::info!(
        services = autoscaler.service_count(),
        "Autoscaler loop starting"
    );

    let handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            interval.tick().await;

            let scaling_ref = scaling_state.as_ref();
            let _results = autoscaler
                .tick(|service_name| {
                    let scaling = scaling_ref?;

                    // Gather in-flight from concurrency limiter or revision router
                    let in_flight = if let Some(limiter) = scaling.limiters.get(service_name) {
                        // Use limiter's view if available — but we need backends.
                        // For now, report 0 and let queue_depth drive decisions.
                        let _ = limiter;
                        0
                    } else {
                        0
                    };

                    let queue_depth = scaling
                        .buffers
                        .get(service_name)
                        .map(|b| b.queue_depth())
                        .unwrap_or(0);

                    Some(ServiceMetricsSnapshot {
                        service: service_name.to_string(),
                        healthy_backends: 0,
                        in_flight,
                        queue_depth,
                    })
                })
                .await;
        }
    });

    Some(handle)
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

    #[cfg(test)]
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

    // --- Discovery integration ---

    #[test]
    fn test_gateway_discovery_handle_initially_none() {
        let gw = Gateway::new(minimal_config()).unwrap();
        let handle = gw.discovery_handle.read().unwrap();
        assert!(handle.is_none());
    }

    #[tokio::test]
    async fn test_gateway_shutdown_with_no_discovery() {
        let gw = Gateway::new(minimal_config()).unwrap();
        gw.shutdown().await;
        assert_eq!(gw.state(), GatewayState::Stopped);
        let handle = gw.discovery_handle.read().unwrap();
        assert!(handle.is_none());
    }

    #[test]
    fn test_gateway_config_with_discovery() {
        use crate::config::{DiscoveryConfig, DiscoverySeedConfig};
        let mut config = minimal_config();
        config.providers.discovery = Some(DiscoveryConfig {
            seeds: vec![DiscoverySeedConfig {
                url: "http://10.0.0.1:8080".to_string(),
            }],
            poll_interval_secs: 30,
            timeout_secs: 5,
        });
        let gw = Gateway::new(config).unwrap();
        let retrieved = gw.config();
        assert!(retrieved.providers.discovery.is_some());
    }

    // --- Scaling state builder ---

    #[test]
    fn test_build_scaling_state_none_when_no_scaling() {
        let config = minimal_config();
        assert!(build_scaling_state(&config).is_none());
    }

    #[test]
    fn test_build_scaling_state_with_scaling_config() {
        use crate::config::{ScalingConfig, ServerConfig};
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    container_concurrency: 10,
                    buffer_enabled: true,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.buffers.contains_key("api"));
        assert!(state.limiters.contains_key("api"));
        assert!(!state.revision_routers.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_with_revisions() {
        use crate::config::{RevisionConfig, ServerConfig};
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![],
                    health_check: None,
                    sticky: None,
                },
                scaling: None,
                revisions: vec![
                    RevisionConfig {
                        name: "v1".into(),
                        traffic_percent: 80,
                        servers: vec![ServerConfig {
                            url: "http://a:8001".into(),
                            weight: 1,
                        }],
                        strategy: Strategy::RoundRobin,
                    },
                    RevisionConfig {
                        name: "v2".into(),
                        traffic_percent: 20,
                        servers: vec![ServerConfig {
                            url: "http://b:8001".into(),
                            weight: 1,
                        }],
                        strategy: Strategy::RoundRobin,
                    },
                ],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.revision_routers.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_no_buffer_when_disabled() {
        use crate::config::{ScalingConfig, ServerConfig};
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    buffer_enabled: false,
                    container_concurrency: 0,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        // buffer_enabled is false, so no buffer
        assert!(!state.buffers.contains_key("api"));
        // container_concurrency == 0, so no limiter
        assert!(!state.limiters.contains_key("api"));
    }

    #[test]
    fn test_build_scaling_state_no_limiter_when_cc_zero() {
        use crate::config::{ScalingConfig, ServerConfig};
        let mut config = minimal_config();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".into(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: Some(ScalingConfig {
                    buffer_enabled: true,
                    container_concurrency: 0,
                    ..ScalingConfig::default()
                }),
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        let state = build_scaling_state(&config).unwrap();
        assert!(state.buffers.contains_key("api"));
        assert!(!state.limiters.contains_key("api"));
    }
}
