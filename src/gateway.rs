//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

use crate::config::GatewayConfig;
use crate::dashboard::{BackendDetail, BackendInfo, RouteInfo, ServiceInfo};
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
use crate::service::passive_health::{PassiveHealthCheck, PassiveHealthConfig};
use crate::service::sticky::{StickyConfig, StickySessionManager};
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

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
                let selector = crate::service::FailoverSelector::new(primary_lb, failover_lb);
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
            tracing::warn!(
                "K8s executor requires async init; falling back to box executor at startup"
            );
            Arc::new(BoxScaleExecutor::new("http://localhost:9090"))
        }
        other => {
            tracing::warn!(
                executor = other,
                "Unknown executor type, falling back to box"
            );
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

/// Spawn a background task that drains the access log channel and serializes entries.
/// This keeps JSON serialization and tracing off the request hot path.
fn spawn_log_task(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<crate::observability::access_log::AccessLogEntry>,
    access_log: Arc<crate::observability::access_log::AccessLog>,
) {
    tokio::spawn(async move {
        while let Some(entry) = rx.recv().await {
            access_log.record(&entry);
        }
    });
}

/// Pre-compile middleware pipelines for all routers — avoids per-request Pipeline::from_config.
fn build_pipeline_cache(
    config: &GatewayConfig,
    middleware_configs: &Arc<HashMap<String, crate::config::MiddlewareConfig>>,
) -> HashMap<String, Arc<crate::middleware::Pipeline>> {
    config
        .routers
        .iter()
        .filter_map(|(name, router)| {
            crate::middleware::Pipeline::from_config(&router.middlewares, middleware_configs)
                .ok()
                .map(|pipeline| (name.clone(), Arc::new(pipeline)))
        })
        .collect()
}

/// Build sticky session managers for services that have a sticky cookie configured.
fn build_sticky_managers(config: &GatewayConfig) -> HashMap<String, Arc<StickySessionManager>> {
    config
        .services
        .iter()
        .filter_map(|(name, svc)| {
            svc.load_balancer.sticky.as_ref().map(|sticky_cfg| {
                let sc = StickyConfig {
                    cookie_name: sticky_cfg.cookie.clone(),
                    ..StickyConfig::default()
                };
                (name.clone(), Arc::new(StickySessionManager::new(sc)))
            })
        })
        .collect()
}

/// Build passive health checkers for every configured service (always-on, default settings).
fn build_passive_health(config: &GatewayConfig) -> HashMap<String, Arc<PassiveHealthCheck>> {
    config
        .services
        .keys()
        .map(|name| {
            (
                name.clone(),
                Arc::new(PassiveHealthCheck::new(PassiveHealthConfig::default())),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{LoadBalancerConfig, RouterConfig, ServiceConfig, Strategy};

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

    // --- DashboardApi tests moved to dashboard.rs ---

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
