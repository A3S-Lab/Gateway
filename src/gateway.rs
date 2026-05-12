//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

pub(crate) mod builders;

use crate::config::GatewayConfig;
use crate::dashboard::{ManagementAuditLog, ManagementReloadCallback};
use crate::entrypoint;
use crate::error::Result;
use crate::observability::metrics::GatewayMetrics;
use crate::provider::discovery;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::collections::HashSet;
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
    handles: Arc<RwLock<entrypoint::EntryPointHandles>>,
    /// Hot-swappable runtime snapshot shared by active entrypoints.
    runtime: Arc<RwLock<Option<entrypoint::GatewayRuntime>>>,
    /// Discovery polling loop handle (if discovery is configured)
    discovery_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Provider watcher and receiver task handles.
    provider_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// Autoscaler loop handle (if any service has scaling config)
    autoscaler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Live service registry for the dedicated management API.
    live_registry: Arc<RwLock<Option<Arc<ServiceRegistry>>>>,
    /// Dedicated management API listener handle.
    management_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Recent management listener security events.
    management_audit_log: Arc<ManagementAuditLog>,
    /// ACME certificate manager handle (if any entrypoint has acme = true)
    acme_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal sender for graceful drain
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone)]
struct GatewayReloadHandle {
    config: Arc<RwLock<GatewayConfig>>,
    state: Arc<RwLock<GatewayState>>,
    start_time: Instant,
    metrics: Arc<GatewayMetrics>,
    handles: Arc<RwLock<entrypoint::EntryPointHandles>>,
    runtime: Arc<RwLock<Option<entrypoint::GatewayRuntime>>>,
    autoscaler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    live_registry: Arc<RwLock<Option<Arc<ServiceRegistry>>>>,
    management_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    management_audit_log: Arc<ManagementAuditLog>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

struct BuiltRuntime {
    state: Arc<entrypoint::GatewayState>,
    service_registry: Arc<ServiceRegistry>,
    autoscaler_handle: Option<tokio::task::JoinHandle<()>>,
}

enum PreparedManagementReload {
    Unchanged,
    Disable,
    RestartSameAddress,
    SwapPrepared(Option<Box<crate::dashboard::PreparedDashboardListener>>),
}

async fn build_runtime(
    config: &GatewayConfig,
    metrics: Arc<GatewayMetrics>,
) -> Result<BuiltRuntime> {
    let router_table = RouterTable::from_config(&config.routers)?;
    tracing::info!(routes = router_table.len(), "Router table compiled");

    let service_registry = ServiceRegistry::from_config(&config.services)?;
    tracing::info!(services = service_registry.len(), "Services registered");
    service_registry.start_health_checks(&config.services).await;

    let scaling_state = build_scaling_state(config);
    if scaling_state.is_some() {
        tracing::info!("Scaling state initialized for configured services");
    }

    let autoscaler_handle = spawn_autoscaler(config, scaling_state.as_ref());
    let http_proxy = Arc::new(HttpProxy::new());
    let service_registry = Arc::new(service_registry);
    let router_table = Arc::new(router_table);
    let (mirrors, failovers) = build_mirror_failover_state(config, &service_registry, &http_proxy);

    let middleware_configs = Arc::new(config.middlewares.clone());
    let pipeline_cache = Arc::new(build_pipeline_cache(config, &middleware_configs));

    let access_log = Arc::new(crate::observability::access_log::AccessLog::new());
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
    spawn_log_task(log_rx, access_log.clone());

    Ok(BuiltRuntime {
        state: Arc::new(entrypoint::GatewayState {
            router_table,
            service_registry: service_registry.clone(),
            middleware_configs,
            pipeline_cache,
            http_proxy,
            grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log,
            log_tx,
            sticky_managers: build_sticky_managers(config),
            passive_health: build_passive_health(config),
            metrics,
            metrics_enabled: config.observability.metrics_enabled,
            access_log_enabled: config.observability.access_log_enabled,
            tracing_enabled: config.observability.tracing_enabled,
        }),
        service_registry,
        autoscaler_handle,
    })
}

fn replace_autoscaler(
    target: &Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    next: Option<tokio::task::JoinHandle<()>>,
) {
    let mut handle = target.write().unwrap();
    if let Some(old) = handle.take() {
        old.abort();
    }
    *handle = next;
}

fn abort_handle(handle: Option<tokio::task::JoinHandle<()>>) {
    if let Some(handle) = handle {
        handle.abort();
    }
}

fn entrypoints_support_hot_swap(old_config: &GatewayConfig, new_config: &GatewayConfig) -> bool {
    old_config.entrypoints == new_config.entrypoints
        && !entrypoints_include_udp(old_config)
        && !entrypoints_include_udp(new_config)
}

fn entrypoints_support_incremental_restart(
    old_config: &GatewayConfig,
    new_config: &GatewayConfig,
) -> bool {
    !entrypoints_include_udp(old_config) && !entrypoints_include_udp(new_config)
}

fn entrypoints_include_udp(config: &GatewayConfig) -> bool {
    config
        .entrypoints
        .values()
        .any(|entrypoint| entrypoint.protocol == crate::config::Protocol::Udp)
}

impl GatewayReloadHandle {
    async fn reload(&self, new_config: GatewayConfig, source: &str) -> Result<()> {
        new_config.validate()?;
        entrypoint::validate_entrypoints(&new_config)?;
        self.set_state(GatewayState::Reloading);

        tracing::info!(source = source, "Reloading gateway configuration");
        let old_config = self.config.read().unwrap().clone();

        let built = match build_runtime(&new_config, self.metrics.clone()).await {
            Ok(runtime) => runtime,
            Err(err) => {
                self.set_state(GatewayState::Running);
                return Err(err);
            }
        };

        let management_reload = match self
            .prepare_management_reload(&old_config, &new_config)
            .await
        {
            Ok(prepared) => prepared,
            Err(err) => {
                abort_handle(built.autoscaler_handle);
                self.set_state(GatewayState::Running);
                return Err(err);
            }
        };

        if entrypoints_support_hot_swap(&old_config, &new_config) {
            let current_runtime = { self.runtime.read().unwrap().clone() };
            if let Some(runtime) = current_runtime {
                runtime.replace(built.state.clone());
            } else {
                *self.runtime.write().unwrap() =
                    Some(entrypoint::GatewayRuntime::new(built.state.clone()));
            }
            tracing::info!(
                source = source,
                "Runtime state hot-swapped without rebinding ports"
            );
        } else if entrypoints_support_incremental_restart(&old_config, &new_config) {
            let runtime = self
                .runtime
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| entrypoint::GatewayRuntime::new(built.state.clone()));
            if let Err(err) = self
                .restart_entrypoints_incrementally(
                    &old_config,
                    &new_config,
                    runtime.clone(),
                    built.state.clone(),
                    source,
                )
                .await
            {
                abort_handle(built.autoscaler_handle);
                self.set_state(GatewayState::Running);
                return Err(err);
            }
            *self.runtime.write().unwrap() = Some(runtime);
        } else {
            let runtime = entrypoint::GatewayRuntime::new(built.state.clone());
            {
                let mut handles = self.handles.write().unwrap();
                for (_, handle) in handles.drain() {
                    handle.abort();
                }
            }
            tokio::task::yield_now().await;

            let new_handles = match entrypoint::start_entrypoints(
                &new_config,
                runtime.clone(),
                self.shutdown_tx.subscribe(),
            )
            .await
            {
                Ok(handles) => handles,
                Err(err) => {
                    abort_handle(built.autoscaler_handle);
                    self.set_state(GatewayState::Running);
                    return Err(err);
                }
            };
            {
                let mut handles = self.handles.write().unwrap();
                *handles = new_handles;
            }
            *self.runtime.write().unwrap() = Some(runtime);
            tracing::info!(
                source = source,
                "Entrypoints restarted after configuration change"
            );
        }

        if let Err(err) = self
            .commit_management_reload(&new_config, management_reload)
            .await
        {
            abort_handle(built.autoscaler_handle);
            self.set_state(GatewayState::Running);
            return Err(err);
        }

        *self.live_registry.write().unwrap() = Some(built.service_registry.clone());
        replace_autoscaler(&self.autoscaler_handle, built.autoscaler_handle);

        {
            let mut config = self.config.write().unwrap();
            *config = new_config;
        }

        self.set_state(GatewayState::Running);
        tracing::info!(source = source, "Gateway configuration reloaded");

        Ok(())
    }

    fn set_state(&self, new_state: GatewayState) {
        let mut state = self.state.write().unwrap();
        tracing::debug!(from = %*state, to = %new_state, "State transition");
        *state = new_state;
    }
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
            handles: Arc::new(RwLock::new(entrypoint::EntryPointHandles::new())),
            runtime: Arc::new(RwLock::new(None)),
            discovery_handle: Arc::new(RwLock::new(None)),
            provider_handles: Arc::new(RwLock::new(Vec::new())),
            autoscaler_handle: Arc::new(RwLock::new(None)),
            live_registry: Arc::new(RwLock::new(None)),
            management_handle: Arc::new(RwLock::new(None)),
            management_audit_log: Arc::new(ManagementAuditLog::default()),
            acme_handle: Arc::new(RwLock::new(None)),
            shutdown_tx,
        })
    }

    /// Start the gateway — binds listeners and begins accepting connections
    pub async fn start(&self) -> Result<()> {
        self.set_state(GatewayState::Starting);

        let config = self.config.read().unwrap().clone();

        let built = build_runtime(&config, self.metrics.clone()).await?;
        replace_autoscaler(&self.autoscaler_handle, built.autoscaler_handle);
        *self.live_registry.write().unwrap() = Some(built.service_registry.clone());
        let runtime = entrypoint::GatewayRuntime::new(built.state.clone());

        // Start all entrypoints
        let new_handles =
            entrypoint::start_entrypoints(&config, runtime.clone(), self.shutdown_tx.subscribe())
                .await?;
        tracing::info!(entrypoints = new_handles.len(), "Entrypoints started");

        {
            let mut handles = self.handles.write().unwrap();
            *handles = new_handles;
        }
        *self.runtime.write().unwrap() = Some(runtime);

        self.start_management_listener(&config).await?;

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway is running");

        // Start discovery loop if configured
        if let Some(ref disc_config) = config.providers.discovery {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
            let disc_handle =
                discovery::spawn_discovery_loop(disc_config.clone(), config.clone(), tx);

            let reload = self.reload_handle();
            let receiver_handle = tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = reload.reload(new_config, "discovery").await {
                        tracing::error!(
                            error = %e,
                            "Discovered config reload failed, keeping current configuration"
                        );
                    }
                }
            });
            self.provider_handles.write().unwrap().push(receiver_handle);

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

            let reload = self.reload_handle();
            let receiver_handle = tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = reload.reload(new_config, "kubernetes").await {
                        tracing::error!(
                            error = %e,
                            "K8s-discovered config reload failed, keeping current configuration"
                        );
                    }
                }
            });

            tracing::info!("Kubernetes Ingress watcher started");
            if crd_handle.is_some() {
                tracing::info!("Kubernetes IngressRoute CRD watcher started");
            }

            let mut provider_handles = self.provider_handles.write().unwrap();
            provider_handles.push(k8s_handle);
            if let Some(handle) = crd_handle {
                provider_handles.push(handle);
            }
            provider_handles.push(receiver_handle);
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

            let reload = self.reload_handle();
            let receiver_handle = tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(e) = reload.reload(new_config, "docker").await {
                        tracing::error!(
                            error = %e,
                            "Docker-discovered config reload failed, keeping current configuration"
                        );
                    }
                }
            });

            let mut provider_handles = self.provider_handles.write().unwrap();
            provider_handles.push(docker_handle);
            provider_handles.push(receiver_handle);
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
        self.reload_handle().reload(new_config, "manual").await
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

        // Abort provider watcher/receiver loops.
        let provider_handles: Vec<_> = self.provider_handles.write().unwrap().drain(..).collect();
        for handle in provider_handles {
            handle.abort();
        }

        // Abort autoscaler loop
        if let Some(handle) = self.autoscaler_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("Autoscaler loop aborted");
        }

        if let Some(handle) = self.management_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("Management API listener aborted");
        }

        // Abort ACME manager loop
        if let Some(handle) = self.acme_handle.write().unwrap().take() {
            handle.abort();
            tracing::debug!("ACME manager aborted");
        }

        // Wait for entrypoint tasks to drain connections (with timeout).
        let timeout_secs = self.config.read().unwrap().shutdown_timeout_secs;
        let drain_timeout = Duration::from_secs(timeout_secs);
        let mut handles: Vec<tokio::task::JoinHandle<()>> = self
            .handles
            .write()
            .unwrap()
            .drain()
            .map(|(_, handle)| handle)
            .collect();

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

    fn reload_handle(&self) -> GatewayReloadHandle {
        GatewayReloadHandle {
            config: self.config.clone(),
            state: self.state.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            handles: self.handles.clone(),
            runtime: self.runtime.clone(),
            autoscaler_handle: self.autoscaler_handle.clone(),
            live_registry: self.live_registry.clone(),
            management_handle: self.management_handle.clone(),
            management_audit_log: self.management_audit_log.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    async fn start_management_listener(&self, config: &GatewayConfig) -> Result<()> {
        let state = crate::dashboard::DashboardState {
            config: self.config.clone(),
            lifecycle_state: self.state.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            service_registry: self.live_registry.clone(),
            audit_log: self.management_audit_log.clone(),
            reload_config: Some(self.management_reload_callback()),
        };
        let handle = crate::dashboard::start_dashboard_listener(&config.management, state).await?;
        *self.management_handle.write().unwrap() = handle;
        Ok(())
    }

    fn management_reload_callback(&self) -> ManagementReloadCallback {
        let reload = self.reload_handle();
        Arc::new(move |config| {
            let reload = reload.clone();
            Box::pin(async move { reload.reload(config, "management-api").await })
        })
    }
}

impl GatewayReloadHandle {
    async fn prepare_management_reload(
        &self,
        old_config: &GatewayConfig,
        new_config: &GatewayConfig,
    ) -> Result<PreparedManagementReload> {
        if old_config.management == new_config.management {
            return Ok(PreparedManagementReload::Unchanged);
        }

        crate::dashboard::validate_dashboard_listener_config(&new_config.management)?;

        if !new_config.management.enabled {
            return Ok(PreparedManagementReload::Disable);
        }

        let same_address = old_config.management.enabled
            && old_config.management.address == new_config.management.address;
        if same_address {
            return Ok(PreparedManagementReload::RestartSameAddress);
        }

        let prepared = crate::dashboard::prepare_dashboard_listener(
            &new_config.management,
            self.dashboard_state(),
        )
        .await?;
        Ok(PreparedManagementReload::SwapPrepared(
            prepared.map(Box::new),
        ))
    }

    async fn commit_management_reload(
        &self,
        config: &GatewayConfig,
        prepared: PreparedManagementReload,
    ) -> Result<()> {
        match prepared {
            PreparedManagementReload::Unchanged => Ok(()),
            PreparedManagementReload::Disable => {
                if let Some(handle) = self.management_handle.write().unwrap().take() {
                    handle.abort();
                }
                Ok(())
            }
            PreparedManagementReload::RestartSameAddress => {
                self.restart_management_listener(config).await
            }
            PreparedManagementReload::SwapPrepared(prepared) => {
                let new_handle = prepared.map(|listener| (*listener).spawn());
                let old_handle = {
                    let mut handle = self.management_handle.write().unwrap();
                    let old = handle.take();
                    *handle = new_handle;
                    old
                };
                if let Some(handle) = old_handle {
                    handle.abort();
                }
                Ok(())
            }
        }
    }

    async fn restart_entrypoints_incrementally(
        &self,
        old_config: &GatewayConfig,
        new_config: &GatewayConfig,
        runtime: entrypoint::GatewayRuntime,
        new_state: Arc<entrypoint::GatewayState>,
        source: &str,
    ) -> Result<()> {
        let restart_names: HashSet<String> = new_config
            .entrypoints
            .iter()
            .filter(|(name, entrypoint)| old_config.entrypoints.get(*name) != Some(*entrypoint))
            .map(|(name, _)| name.clone())
            .collect();
        let removed_names: HashSet<String> = old_config
            .entrypoints
            .keys()
            .filter(|name| !new_config.entrypoints.contains_key(*name))
            .cloned()
            .collect();

        let restart_addresses: HashSet<String> = restart_names
            .iter()
            .filter_map(|name| new_config.entrypoints.get(name))
            .map(|entrypoint| entrypoint.address.clone())
            .collect();
        let pre_abort_names: Vec<String> = old_config
            .entrypoints
            .iter()
            .filter(|(name, entrypoint)| {
                (restart_names.contains(*name) || removed_names.contains(*name))
                    && restart_addresses.contains(&entrypoint.address)
            })
            .map(|(name, _)| name.clone())
            .collect();

        let mut pre_aborted = Vec::new();
        {
            let mut handles = self.handles.write().unwrap();
            for name in &pre_abort_names {
                if let Some(handle) = handles.remove(name) {
                    pre_aborted.push(handle);
                }
            }
        }
        for handle in pre_aborted {
            handle.abort();
        }
        if !pre_abort_names.is_empty() {
            tokio::task::yield_now().await;
        }

        let mut staged_config = new_config.clone();
        staged_config
            .entrypoints
            .retain(|name, _| restart_names.contains(name));
        let new_handles = entrypoint::start_entrypoints(
            &staged_config,
            runtime.clone(),
            self.shutdown_tx.subscribe(),
        )
        .await?;

        runtime.replace(new_state);

        let mut stale_handles = Vec::new();
        {
            let mut handles = self.handles.write().unwrap();
            for name in restart_names.iter().chain(removed_names.iter()) {
                if let Some(handle) = handles.remove(name) {
                    stale_handles.push(handle);
                }
            }
            for (name, handle) in new_handles {
                if let Some(old_handle) = handles.insert(name, handle) {
                    stale_handles.push(old_handle);
                }
            }
        }
        for handle in stale_handles {
            handle.abort();
        }

        tracing::info!(
            source = source,
            restarted = restart_names.len(),
            removed = removed_names.len(),
            "Entrypoints incrementally reconciled"
        );

        Ok(())
    }

    async fn restart_management_listener(&self, config: &GatewayConfig) -> Result<()> {
        crate::dashboard::validate_dashboard_listener_config(&config.management)?;

        let old_management = self.config.read().unwrap().management.clone();
        let same_address = old_management.enabled
            && config.management.enabled
            && old_management.address == config.management.address;

        if same_address {
            let old_handle = { self.management_handle.write().unwrap().take() };
            if let Some(handle) = old_handle {
                handle.abort();
                tokio::task::yield_now().await;
            }

            let handle = crate::dashboard::start_dashboard_listener(
                &config.management,
                self.dashboard_state(),
            )
            .await?;
            *self.management_handle.write().unwrap() = handle;
            return Ok(());
        }

        let new_handle =
            crate::dashboard::start_dashboard_listener(&config.management, self.dashboard_state())
                .await?;
        let old_handle = {
            let mut handle = self.management_handle.write().unwrap();
            let old = handle.take();
            *handle = new_handle;
            old
        };
        if let Some(handle) = old_handle {
            handle.abort();
        }
        Ok(())
    }

    fn dashboard_state(&self) -> crate::dashboard::DashboardState {
        crate::dashboard::DashboardState {
            config: self.config.clone(),
            lifecycle_state: self.state.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            service_registry: self.live_registry.clone(),
            audit_log: self.management_audit_log.clone(),
            reload_config: Some(self.management_reload_callback()),
        }
    }

    fn management_reload_callback(&self) -> crate::dashboard::ManagementReloadCallback {
        let reload = self.clone();
        Arc::new(move |config| {
            let reload = reload.clone();
            Box::pin(async move { reload.reload(config, "management-api").await })
        })
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

    #[test]
    fn test_entrypoints_support_hot_swap_for_unchanged_http_entrypoints() {
        use crate::config::{EntrypointConfig, Protocol};

        let mut old_config = minimal_config();
        old_config.entrypoints.insert(
            "web".to_string(),
            EntrypointConfig {
                address: "127.0.0.1:8080".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
            },
        );
        let new_config = old_config.clone();

        assert!(entrypoints_support_hot_swap(&old_config, &new_config));
    }

    #[test]
    fn test_entrypoints_do_not_hot_swap_udp_entrypoints() {
        use crate::config::{EntrypointConfig, Protocol};

        let mut old_config = minimal_config();
        old_config.entrypoints.insert(
            "dns".to_string(),
            EntrypointConfig {
                address: "127.0.0.1:5353".to_string(),
                protocol: Protocol::Udp,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
            },
        );
        let new_config = old_config.clone();

        assert!(!entrypoints_support_hot_swap(&old_config, &new_config));
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
        assert!(gw.provider_handles.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_gateway_shutdown_with_no_discovery() {
        let gw = Gateway::new(minimal_config()).unwrap();
        gw.shutdown().await;
        assert_eq!(gw.state(), GatewayState::Stopped);
        let handle = gw.discovery_handle.read().unwrap();
        assert!(handle.is_none());
        assert!(gw.provider_handles.read().unwrap().is_empty());
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

    #[tokio::test]
    async fn test_gateway_start_tracks_docker_provider_handles() {
        use crate::config::DockerProviderConfig;

        let mut config = minimal_config();
        config.entrypoints.clear();
        config.providers.docker = Some(DockerProviderConfig {
            poll_interval_secs: 60,
            ..DockerProviderConfig::default()
        });

        let gw = Gateway::new(config).unwrap();
        gw.start().await.unwrap();
        assert!(gw.provider_handles.read().unwrap().len() >= 2);

        gw.shutdown().await;
        assert!(gw.provider_handles.read().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_reload_handle_updates_live_components() {
        use crate::config::{LoadBalancerConfig, ServerConfig, ServiceConfig, Strategy};

        let mut initial = minimal_config();
        initial.entrypoints.clear();
        let gw = Gateway::new(initial).unwrap();
        let mut config = minimal_config();
        config.entrypoints.clear();
        config.services.insert(
            "api".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8080".to_string(),
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

        gw.reload_handle().reload(config, "test").await.unwrap();

        assert!(gw.is_running());
        assert!(gw.config().services.contains_key("api"));
    }
}
