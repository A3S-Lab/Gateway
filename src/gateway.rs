//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

pub(crate) mod builders;

use crate::config::GatewayConfig;
use crate::dashboard::{BackendDetail, BackendInfo, RouteInfo, ServiceInfo};
use crate::entrypoint;
use crate::error::Result;
use crate::observability::metrics::GatewayMetrics;
use crate::provider::discovery;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use self::builders::{
    build_mirror_failover_state, build_passive_health, build_pipeline_cache, build_scaling_state,
    build_sticky_managers, spawn_autoscaler, spawn_log_task,
};

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
    /// Live service registry (updated on start/reload for dashboard API)
    live_registry: RwLock<Option<Arc<ServiceRegistry>>>,
    /// Live router table (updated on start/reload for dashboard API)
    live_router_table: RwLock<Option<Arc<RouterTable>>>,
    /// ACME certificate manager handle (if any entrypoint has acme = true)
    acme_handle: RwLock<Option<tokio::task::JoinHandle<()>>>,
    /// Shutdown signal sender for graceful drain
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl Gateway {
    /// Create a new gateway from configuration
    pub fn new(config: GatewayConfig) -> Result<Self> {
        config.validate()?;

        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(GatewayState::Created)),
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(GatewayMetrics::new()),
            handles: RwLock::new(Vec::new()),
            discovery_handle: RwLock::new(None),
            autoscaler_handle: RwLock::new(None),
            live_registry: RwLock::new(None),
            live_router_table: RwLock::new(None),
            acme_handle: RwLock::new(None),
            shutdown_tx,
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
        let router_table = Arc::new(router_table);
        let (mirrors, failovers) =
            build_mirror_failover_state(&config, &service_registry, &http_proxy);

        // Store live references for the dashboard API
        *self.live_registry.write().unwrap() = Some(service_registry.clone());
        *self.live_router_table.write().unwrap() = Some(router_table.clone());

        let middleware_configs = Arc::new(config.middlewares.clone());
        let pipeline_cache = Arc::new(build_pipeline_cache(&config, &middleware_configs));

        let access_log = Arc::new(crate::observability::access_log::AccessLog::new());
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
        spawn_log_task(log_rx, access_log.clone());

        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table,
            service_registry,
            middleware_configs,
            pipeline_cache,
            http_proxy,
            grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log,
            log_tx,
            sticky_managers: build_sticky_managers(&config),
            passive_health: build_passive_health(&config),
            metrics: self.metrics.clone(),
        });

        // Start all entrypoints
        let new_handles =
            entrypoint::start_entrypoints(&config, gw_state, self.shutdown_tx.subscribe()).await?;
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
            let gw_handles = Arc::new(std::sync::Mutex::new(
                None::<Vec<tokio::task::JoinHandle<()>>>,
            ));
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
            drop(k8s_handle);
        }

        // Warn if kubernetes config is present but feature is not enabled
        #[cfg(not(feature = "kube"))]
        if config.providers.kubernetes.is_some() {
            tracing::warn!(
                "Kubernetes provider configured but the 'kube' feature is not enabled. \
                 Rebuild with `--features kube` to enable Kubernetes support."
            );
        }

        // Start Docker provider loop if configured
        if let Some(ref docker_config) = config.providers.docker {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
            let docker_handle = crate::provider::docker::spawn_docker_loop(
                docker_config.clone(),
                config.clone(),
                tx,
            );

            let gw_config = self.config.clone();
            tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = new_config.validate() {
                        tracing::error!(
                            error = %e,
                            "Docker-discovered config validation failed, skipping"
                        );
                        continue;
                    }
                    tracing::info!("Applying Docker-discovered configuration");
                    let mut config = gw_config.write().unwrap();
                    *config = new_config;
                }
            });

            // Store the handle (slot shared with discovery; both can coexist at runtime)
            let mut handle = self.discovery_handle.write().unwrap();
            if handle.is_none() {
                *handle = Some(docker_handle);
            }
            tracing::info!("Docker provider polling loop started");
        }

        // Start ACME certificate manager if any entrypoint has acme = true.
        let acme_tls = config
            .entrypoints
            .values()
            .find_map(|ep| ep.tls.as_ref().filter(|t| t.acme));
        if let Some(tls) = acme_tls {
            let email = tls.acme_email.clone().unwrap_or_default();
            if email.is_empty() {
                tracing::warn!("ACME enabled but acme_email is not set, skipping ACME manager");
            } else {
                let domains = if tls.acme_domains.is_empty() {
                    // Collect Host() domains from all routers as fallback
                    config
                        .routers
                        .values()
                        .filter_map(|r| {
                            r.rule
                                .strip_prefix("Host(`")
                                .and_then(|s| s.split('`').next())
                                .map(|s| s.to_string())
                        })
                        .collect()
                } else {
                    tls.acme_domains.clone()
                };

                let storage_path = tls
                    .acme_storage_path
                    .as_deref()
                    .unwrap_or("/etc/gateway/acme");

                let acme_config = crate::proxy::acme::AcmeConfig {
                    email,
                    domains,
                    staging: tls.acme_staging,
                    storage_path: std::path::PathBuf::from(storage_path),
                    ..Default::default()
                };

                let challenges = std::sync::Arc::new(crate::proxy::acme::ChallengeStore::new());
                match crate::proxy::acme_manager::AcmeManager::new(acme_config, challenges) {
                    Ok(manager) => {
                        let handle = tokio::spawn(manager.run());
                        let mut acme = self.acme_handle.write().unwrap();
                        if let Some(old) = acme.take() {
                            old.abort();
                        }
                        *acme = Some(handle);
                        tracing::info!("ACME certificate manager started");
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to create ACME manager");
                    }
                }
            }
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
        let router_table = Arc::new(router_table);
        let (mirrors, failovers) =
            build_mirror_failover_state(&new_config, &service_registry, &http_proxy);

        // Update live references for the dashboard API
        *self.live_registry.write().unwrap() = Some(service_registry.clone());
        *self.live_router_table.write().unwrap() = Some(router_table.clone());

        let middleware_configs = Arc::new(new_config.middlewares.clone());
        let pipeline_cache = Arc::new(build_pipeline_cache(&new_config, &middleware_configs));

        let access_log = Arc::new(crate::observability::access_log::AccessLog::new());
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
        spawn_log_task(log_rx, access_log.clone());

        let gw_state = Arc::new(entrypoint::GatewayState {
            router_table,
            service_registry,
            middleware_configs,
            pipeline_cache,
            http_proxy,
            grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log,
            log_tx,
            sticky_managers: build_sticky_managers(&new_config),
            passive_health: build_passive_health(&new_config),
            metrics: self.metrics.clone(),
        });

        // Stop old entrypoints
        {
            let mut handles = self.handles.write().unwrap();
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
        // Yield to let the runtime drop the old listeners and release sockets
        tokio::task::yield_now().await;

        // Start new entrypoints
        let new_handles =
            entrypoint::start_entrypoints(&new_config, gw_state, self.shutdown_tx.subscribe())
                .await?;
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

        // Signal all entrypoints to stop accepting new connections.
        let _ = self.shutdown_tx.send(true);

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

        // Abort ACME manager loop
        if let Some(handle) = self.acme_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("ACME manager aborted");
        }

        // Wait for entrypoint tasks to drain connections (with timeout).
        let timeout_secs = self.config.read().unwrap().shutdown_timeout_secs;
        let drain_timeout = Duration::from_secs(timeout_secs);
        let mut handles: Vec<tokio::task::JoinHandle<()>> =
            self.handles.write().unwrap().drain(..).collect();

        let drain_deadline = tokio::time::Instant::now() + drain_timeout;
        for handle in &mut handles {
            let remaining = drain_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                handle.abort();
            } else {
                tokio::select! {
                    _ = handle => {}
                    _ = tokio::time::sleep(remaining) => {
                        tracing::warn!("Graceful drain timeout reached, aborting remaining entrypoints");
                        break;
                    }
                }
            }
        }
        // Force-abort any remaining handles.
        for handle in handles {
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

    /// Set live router table and service registry (for testing dashboard without binding ports)
    #[cfg(test)]
    pub(crate) fn set_live_data(
        &self,
        router_table: Arc<RouterTable>,
        registry: Arc<ServiceRegistry>,
    ) {
        *self.live_router_table.write().unwrap() = Some(router_table);
        *self.live_registry.write().unwrap() = Some(registry);
    }

    /// Snapshot of all routes for the management API
    pub fn routes_snapshot(&self) -> Vec<RouteInfo> {
        let table = self.live_router_table.read().unwrap();
        match table.as_ref() {
            Some(rt) => rt
                .routes_info()
                .into_iter()
                .map(|r| RouteInfo {
                    name: r.name,
                    rule: r.rule,
                    service: r.service,
                    entrypoints: r.entrypoints,
                    middlewares: r.middlewares,
                    priority: r.priority,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Snapshot of all services with live backend health for the management API
    pub fn services_snapshot(&self) -> Vec<ServiceInfo> {
        let registry = self.live_registry.read().unwrap();
        let config = self.config.read().unwrap();
        match registry.as_ref() {
            Some(reg) => reg
                .iter()
                .map(|(name, lb)| {
                    let backends: Vec<BackendInfo> = lb
                        .backends()
                        .iter()
                        .map(|b| BackendInfo {
                            url: b.url.clone(),
                            weight: b.weight,
                            healthy: b.is_healthy(),
                            active_connections: b.connections(),
                        })
                        .collect();
                    let strategy = config
                        .services
                        .get(name)
                        .map(|s| format!("{:?}", s.load_balancer.strategy))
                        .unwrap_or_default();
                    ServiceInfo {
                        name: name.clone(),
                        strategy,
                        backends_total: lb.total_count(),
                        backends_healthy: lb.healthy_count(),
                        backends,
                    }
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Flat list of all backends across all services
    pub fn backends_snapshot(&self) -> Vec<BackendDetail> {
        let registry = self.live_registry.read().unwrap();
        match registry.as_ref() {
            Some(reg) => reg
                .iter()
                .flat_map(|(svc_name, lb)| {
                    lb.backends().iter().map(move |b| BackendDetail {
                        service: svc_name.clone(),
                        url: b.url.clone(),
                        weight: b.weight,
                        healthy: b.is_healthy(),
                        active_connections: b.connections(),
                    })
                })
                .collect(),
            None => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.routers.clear();
        config.services.clear();
        config.middlewares.clear();
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
        use crate::config::RouterConfig;
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
}
