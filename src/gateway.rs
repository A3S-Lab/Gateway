//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

mod autoscaling;
pub(crate) mod builders;
mod managed_service;
#[cfg(test)]
mod mode_tests;
mod startup;

use crate::config::GatewayConfig;
use crate::entrypoint;
use crate::error::{GatewayError, Result};
use crate::managed_service::{ManagedServiceStore, MANAGED_SERVICE_MIDDLEWARE_NAME};
use crate::managed_snapshot::{ManagedSnapshotReloadCallback, ManagedSnapshotStore};
use crate::middleware::MiddlewareRegistry;
use crate::observability::metrics::GatewayMetrics;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::{Backend, HealthCheckTasks, PreparedHealthChecks, ServiceRegistry};
use crate::usage::UsageSpool;
use crate::{GatewayState, HealthStatus};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use std::time::{Duration, Instant};

use self::autoscaling::{prepare_autoscaler, PreparedAutoscaler};
use self::builders::{
    build_mirror_failover_state, build_passive_health, build_pipeline_cache, build_route_plans,
    build_scaling_state, build_sticky_managers, spawn_log_task,
};

#[cfg(not(windows))]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}

#[cfg(windows)]
async fn wait_for_shutdown_signal() -> std::io::Result<()> {
    let mut ctrl_c = tokio::signal::windows::ctrl_c()?;
    let mut ctrl_break = tokio::signal::windows::ctrl_break()?;
    tokio::select! {
        _ = ctrl_c.recv() => {}
        _ = ctrl_break.recv() => {}
    }
    Ok(())
}

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
    /// Programmatic middleware instances available to every runtime snapshot.
    middleware_registry: Arc<MiddlewareRegistry>,
    /// Serializes start, reload, and shutdown lifecycle transactions.
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    /// Discovery polling loop handle (if discovery is configured)
    discovery_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Provider watcher and receiver task handles.
    provider_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
    /// Autoscaler loop handle (if any service has scaling config)
    autoscaler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Active health-check tasks owned by the committed runtime snapshot.
    health_check_tasks: Arc<RwLock<HealthCheckTasks>>,
    /// Dedicated node API listener handle.
    node_api_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Gateway-native applied and rejected managed snapshot metadata.
    managed_snapshots: Arc<ManagedSnapshotStore>,
    /// Optional durable overlay for exact-generation private Runtime routes.
    managed_services: Option<Arc<ManagedServiceStore>>,
    /// Hidden backends retained weakly while admitted calls drain.
    managed_service_drains: Arc<RwLock<BTreeMap<String, Weak<Backend>>>>,
    /// Node-local durable usage spool, initialized before listeners.
    usage_spool: Arc<RwLock<Option<Arc<UsageSpool>>>>,
    /// ACME certificate manager handle (if any entrypoint has acme = true)
    acme_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    /// Shutdown signal sender for graceful drain
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

#[derive(Clone)]
struct GatewayReloadHandle {
    config: Arc<RwLock<GatewayConfig>>,
    state: Arc<RwLock<GatewayState>>,
    shutdown: Arc<AtomicBool>,
    start_time: Instant,
    metrics: Arc<GatewayMetrics>,
    handles: Arc<RwLock<entrypoint::EntryPointHandles>>,
    runtime: Arc<RwLock<Option<entrypoint::GatewayRuntime>>>,
    middleware_registry: Arc<MiddlewareRegistry>,
    lifecycle_lock: Arc<tokio::sync::Mutex<()>>,
    autoscaler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    health_check_tasks: Arc<RwLock<HealthCheckTasks>>,
    node_api_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    managed_snapshots: Arc<ManagedSnapshotStore>,
    managed_services: Option<Arc<ManagedServiceStore>>,
    usage_spool: Arc<RwLock<Option<Arc<UsageSpool>>>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

struct BuiltRuntime {
    state: Arc<entrypoint::GatewayState>,
    autoscaler: Option<PreparedAutoscaler>,
    health_checks: PreparedHealthChecks,
    telemetry: crate::observability::metrics::PreparedTelemetry,
}

enum PreparedNodeApiReload {
    Unchanged,
    Disable,
    RestartSameAddress,
    SwapPrepared(Option<Box<crate::node_api::PreparedNodeApiListener>>),
}

async fn build_runtime(
    config: &GatewayConfig,
    metrics: Arc<GatewayMetrics>,
    middleware_registry: &MiddlewareRegistry,
    previous_inference_authorizer: Option<&crate::inference::InferenceAuthorizer>,
    usage_spool: Option<Arc<UsageSpool>>,
) -> Result<BuiltRuntime> {
    let router_table = RouterTable::from_config(&config.routers)?;
    tracing::info!(routes = router_table.len(), "Router table compiled");
    let pipeline_cache = build_pipeline_cache(config, &config.middlewares, middleware_registry)?;

    let service_registry = ServiceRegistry::from_config(&config.services)?;
    tracing::info!(services = service_registry.len(), "Services registered");
    let health_checks = service_registry.prepare_health_checks(&config.services)?;
    let passive_health = build_passive_health(config);
    let route_plans = build_route_plans(
        config,
        &router_table,
        &pipeline_cache,
        &service_registry,
        &passive_health,
    )?;

    let scaling_state = build_scaling_state(config);
    if scaling_state.is_some() {
        tracing::info!("Scaling state initialized for configured services");
    }

    let http_proxy = Arc::new(HttpProxy::new());
    let service_registry = Arc::new(service_registry);
    let autoscaler = prepare_autoscaler(config, scaling_state.as_ref(), &service_registry).await?;
    let telemetry = metrics.prepare_telemetry(
        config,
        service_registry.as_ref(),
        scaling_state.as_deref(),
        config.observability.metrics_enabled,
    );
    let router_table = Arc::new(router_table);
    let (mirrors, failovers) = build_mirror_failover_state(config, &service_registry, &http_proxy);

    let access_log = Arc::new(crate::observability::access_log::AccessLog::new());
    let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
    spawn_log_task(log_rx, access_log.clone());

    Ok(BuiltRuntime {
        state: Arc::new(entrypoint::GatewayState {
            router_table,
            route_plans,
            service_registry: service_registry.clone(),
            inference_authorizer: config
                .inference
                .as_ref()
                .map(|policy| {
                    crate::inference::InferenceAuthorizer::with_previous(
                        policy,
                        previous_inference_authorizer,
                    )
                })
                .map(Arc::new),
            usage_spool,
            http_proxy,
            grpc_proxy: Arc::new(crate::proxy::grpc::GrpcProxy::new()),
            scaling: scaling_state,
            mirrors,
            failovers,
            access_log,
            log_tx,
            sticky_managers: build_sticky_managers(config),
            passive_health,
            metrics,
            shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
            metrics_enabled: config.observability.metrics_enabled,
            access_log_enabled: config.observability.access_log_enabled,
            tracing_enabled: config.observability.tracing_enabled,
        }),
        autoscaler,
        health_checks,
        telemetry,
    })
}

async fn replace_autoscaler(
    target: &Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    next: Option<PreparedAutoscaler>,
) {
    let old = target.write().unwrap().take();
    if let Some(old) = old {
        old.abort();
        let _ = old.await;
    }
    *target.write().unwrap() = next.map(PreparedAutoscaler::start);
}

async fn replace_health_checks(target: &Arc<RwLock<HealthCheckTasks>>, next: PreparedHealthChecks) {
    let old = {
        let mut active = target.write().unwrap();
        std::mem::take(&mut *active)
    };
    old.shutdown().await;
    *target.write().unwrap() = next.start();
}

fn ensure_lifecycle_operation(
    state: &Arc<RwLock<GatewayState>>,
    shutdown: &AtomicBool,
    required: GatewayState,
    operation: &str,
) -> Result<()> {
    let current = state.read().unwrap().clone();
    if shutdown.load(Ordering::SeqCst) {
        return Err(GatewayError::Other(format!(
            "Gateway cannot {operation} after shutdown was requested (state: {current})"
        )));
    }
    if current != required {
        return Err(GatewayError::Other(format!(
            "Gateway cannot {operation} while lifecycle state is {current}; expected {required}"
        )));
    }
    Ok(())
}

fn entrypoints_support_hot_swap(old_config: &GatewayConfig, new_config: &GatewayConfig) -> bool {
    old_config.entrypoints == new_config.entrypoints
        && !entrypoints_include_udp(old_config)
        && !entrypoints_include_udp(new_config)
}

fn entrypoints_include_udp(config: &GatewayConfig) -> bool {
    config
        .entrypoints
        .values()
        .any(|entrypoint| entrypoint.protocol == crate::config::Protocol::Udp)
}

impl GatewayReloadHandle {
    async fn reload(&self, new_config: GatewayConfig, source: &str) -> Result<()> {
        self.reload_with_previous(new_config, source)
            .await
            .map(|_| ())
    }

    async fn reload_with_previous(
        &self,
        new_config: GatewayConfig,
        source: &str,
    ) -> Result<GatewayConfig> {
        self.reload_inner(Some(new_config), source).await
    }

    async fn reload_inner(
        &self,
        new_config: Option<GatewayConfig>,
        source: &str,
    ) -> Result<GatewayConfig> {
        let _lifecycle = self.lifecycle_lock.lock().await;
        self.reload_locked(new_config, source).await
    }

    async fn reload_locked(
        &self,
        new_config: Option<GatewayConfig>,
        source: &str,
    ) -> Result<GatewayConfig> {
        ensure_lifecycle_operation(&self.state, &self.shutdown, GatewayState::Running, "reload")?;
        let old_config = self.config.read().unwrap().clone();
        let new_config = new_config.unwrap_or_else(|| old_config.clone());
        if source != "managed-snapshot"
            && !source.starts_with("managed-service-")
            && old_config.mode == crate::config::OperatingMode::CloudManaged
            && old_config.managed.gateway_id.is_some()
        {
            return Err(GatewayError::Config(
                "Gateway-native managed snapshots must be applied through /snapshots/apply"
                    .to_string(),
            ));
        }
        let custom_middlewares = self.middleware_registry.names();
        new_config
            .validate_reload_from_with_custom_middlewares(&old_config, &custom_middlewares)?;
        if let Some(store) = &self.managed_services {
            store.validate_base_reload(&old_config, &new_config)?;
        }
        if source == "managed-snapshot" {
            new_config.validate_managed_snapshot_reload_from(&old_config)?;
        }
        let old_runtime_config = self.effective_config(&old_config)?;
        let new_runtime_config = self.effective_config(&new_config)?;
        entrypoint::validate_entrypoints(&new_runtime_config)?;
        self.set_state(GatewayState::Reloading);

        tracing::info!(source = source, "Reloading gateway configuration");

        let previous_inference_authorizer = self
            .runtime
            .read()
            .unwrap()
            .as_ref()
            .and_then(|runtime| runtime.load().inference_authorizer.clone());
        let usage_spool = self.usage_spool.read().unwrap().clone();
        let built = match build_runtime(
            &new_runtime_config,
            self.metrics.clone(),
            self.middleware_registry.as_ref(),
            previous_inference_authorizer.as_deref(),
            usage_spool,
        )
        .await
        {
            Ok(runtime) => runtime,
            Err(err) => {
                self.set_state(GatewayState::Running);
                return Err(err);
            }
        };

        let node_api_reload = match self.prepare_node_api_reload(&old_config, &new_config).await {
            Ok(prepared) => prepared,
            Err(err) => {
                self.set_state(GatewayState::Running);
                return Err(err);
            }
        };

        if entrypoints_support_hot_swap(&old_runtime_config, &new_runtime_config) {
            let current_runtime = { self.runtime.read().unwrap().clone() };
            self.metrics.activate_telemetry(built.telemetry.clone());
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
        } else {
            let runtime = self
                .runtime
                .read()
                .unwrap()
                .clone()
                .unwrap_or_else(|| entrypoint::GatewayRuntime::new(built.state.clone()));
            if let Err(err) = self
                .restart_entrypoints_incrementally(
                    &old_runtime_config,
                    &new_runtime_config,
                    runtime.clone(),
                    built.state.clone(),
                    built.telemetry.clone(),
                    source,
                )
                .await
            {
                self.set_state(GatewayState::Running);
                return Err(err);
            }
            *self.runtime.write().unwrap() = Some(runtime);
        }

        if let Err(err) = self
            .commit_node_api_reload(&new_config, node_api_reload)
            .await
        {
            self.set_state(GatewayState::Running);
            return Err(err);
        }

        {
            let mut config = self.config.write().unwrap();
            *config = new_config;
        }
        replace_health_checks(&self.health_check_tasks, built.health_checks).await;
        replace_autoscaler(&self.autoscaler_handle, built.autoscaler).await;

        self.set_state(GatewayState::Running);
        tracing::info!(source = source, "Gateway configuration reloaded");

        Ok(old_config)
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
        Self::with_middlewares(config, MiddlewareRegistry::new())
    }

    /// Create a gateway with programmatically registered custom middleware.
    ///
    /// Router ACL references custom middleware by the stable name used in the
    /// registry. A custom name cannot also have an ACL middleware definition.
    /// The registry remains fixed while configuration snapshots may reload.
    pub fn with_middlewares(
        config: GatewayConfig,
        middleware_registry: MiddlewareRegistry,
    ) -> Result<Self> {
        Self::with_components(config, middleware_registry, None)
    }

    fn with_components(
        config: GatewayConfig,
        middleware_registry: MiddlewareRegistry,
        managed_services: Option<Arc<ManagedServiceStore>>,
    ) -> Result<Self> {
        if managed_services.is_some()
            && middleware_registry.contains(MANAGED_SERVICE_MIDDLEWARE_NAME)
        {
            return Err(GatewayError::Config(format!(
                "Custom middleware name '{MANAGED_SERVICE_MIDDLEWARE_NAME}' is reserved for Managed Services"
            )));
        }
        config.validate_with_custom_middlewares(&middleware_registry.names())?;
        config.validate_managed_bootstrap()?;
        let managed_snapshots = Arc::new(ManagedSnapshotStore::new(
            config.managed.gateway_id,
            config.managed.state_file.clone(),
        ));

        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            state: Arc::new(RwLock::new(GatewayState::Created)),
            start_time: Instant::now(),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(GatewayMetrics::new()),
            handles: Arc::new(RwLock::new(entrypoint::EntryPointHandles::new())),
            runtime: Arc::new(RwLock::new(None)),
            middleware_registry: Arc::new(middleware_registry),
            lifecycle_lock: Arc::new(tokio::sync::Mutex::new(())),
            discovery_handle: Arc::new(RwLock::new(None)),
            provider_handles: Arc::new(RwLock::new(Vec::new())),
            autoscaler_handle: Arc::new(RwLock::new(None)),
            health_check_tasks: Arc::new(RwLock::new(HealthCheckTasks::default())),
            node_api_handle: Arc::new(RwLock::new(None)),
            managed_snapshots,
            managed_services,
            managed_service_drains: Arc::new(RwLock::new(BTreeMap::new())),
            usage_spool: Arc::new(RwLock::new(None)),
            acme_handle: Arc::new(RwLock::new(None)),
            shutdown_tx,
        })
    }

    /// Reload configuration while the gateway is running.
    ///
    /// Reload is serialized with startup and shutdown and is rejected in every
    /// lifecycle state other than [`GatewayState::Running`].
    pub async fn reload(&self, new_config: GatewayConfig) -> Result<()> {
        self.reload_handle().reload(new_config, "manual").await
    }

    /// Initiate graceful shutdown.
    ///
    /// Concurrent calls are idempotent and each waits until the gateway reaches
    /// [`GatewayState::Stopped`]. Once requested, startup and reload are rejected.
    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        let _lifecycle = self.lifecycle_lock.lock().await;
        if self.state() == GatewayState::Stopped {
            return;
        }

        self.set_state(GatewayState::Stopping);
        tracing::info!("Gateway shutting down");

        // Signal all entrypoints to stop accepting new connections.
        let _ = self.shutdown_tx.send(true);

        let mut background_handles = Vec::new();

        // Stop discovery and provider loops.
        if let Some(handle) = self.discovery_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Discovery loop aborted");
        }
        background_handles.extend(self.provider_handles.write().unwrap().drain(..));

        // Stop the autoscaler, node API listener, and ACME manager.
        if let Some(handle) = self.autoscaler_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Autoscaler loop aborted");
        }

        if let Some(handle) = self.node_api_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Node API listener aborted");
        }

        if let Some(handle) = self.acme_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("ACME manager aborted");
        }
        for handle in &background_handles {
            handle.abort();
        }
        for handle in background_handles {
            let _ = handle.await;
        }

        let health_checks = {
            let mut active = self.health_check_tasks.write().unwrap();
            std::mem::take(&mut *active)
        };
        health_checks.shutdown().await;

        // Entrypoints enforce the shared runtime drain deadline, force-cancel
        // their remaining child tasks, and join them before returning.
        let handles: Vec<tokio::task::JoinHandle<()>> = self
            .handles
            .write()
            .unwrap()
            .drain()
            .map(|(_, handle)| handle.into_task())
            .collect();
        for handle in handles {
            let _ = handle.await;
        }
        let usage_spool = self.usage_spool.read().unwrap().clone();
        if let Some(usage_spool) = usage_spool {
            usage_spool.shutdown().await;
        }
        if let Some(store) = &self.managed_services {
            store.release_lock();
        }

        self.set_state(GatewayState::Stopped);
        tracing::info!("Gateway stopped");
    }

    /// Wait for Ctrl+C, or Ctrl+Break on Windows, and shut down gracefully.
    pub async fn wait_for_shutdown(&self) {
        wait_for_shutdown_signal()
            .await
            .expect("Failed to listen for a shutdown signal");
        self.shutdown().await;
    }

    /// Get the current gateway state
    pub fn state(&self) -> GatewayState {
        self.state.read().unwrap().clone()
    }

    /// Get a health status snapshot
    pub fn health(&self) -> HealthStatus {
        let (mode, gateway_id) = {
            let config = self.config.read().unwrap();
            (config.mode, config.managed.gateway_id)
        };
        HealthStatus {
            state: self.state(),
            mode,
            gateway_id,
            uptime_secs: self.start_time.elapsed().as_secs(),
            active_connections: self.metrics.snapshot().active_connections as usize,
            total_requests: self.metrics.snapshot().total_requests,
            usage_spool: self
                .usage_spool
                .read()
                .unwrap()
                .as_ref()
                .map(|spool| spool.status()),
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
            shutdown: self.shutdown.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            handles: self.handles.clone(),
            runtime: self.runtime.clone(),
            middleware_registry: self.middleware_registry.clone(),
            lifecycle_lock: self.lifecycle_lock.clone(),
            autoscaler_handle: self.autoscaler_handle.clone(),
            health_check_tasks: self.health_check_tasks.clone(),
            node_api_handle: self.node_api_handle.clone(),
            managed_snapshots: self.managed_snapshots.clone(),
            managed_services: self.managed_services.clone(),
            usage_spool: self.usage_spool.clone(),
            shutdown_tx: self.shutdown_tx.clone(),
        }
    }

    async fn start_node_api_listener(&self, config: &GatewayConfig) -> Result<()> {
        let state = crate::node_api::NodeApiState {
            config: self.config.clone(),
            lifecycle_state: self.state.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            reload_managed_snapshot: Some(self.managed_snapshot_reload_callback()),
            managed_snapshots: self.managed_snapshots.clone(),
            usage_spool: self.usage_spool.clone(),
        };
        let handle = crate::node_api::start_node_api_listener(&config.management, state).await?;
        *self.node_api_handle.write().unwrap() = handle;
        Ok(())
    }

    fn managed_snapshot_reload_callback(&self) -> ManagedSnapshotReloadCallback {
        let reload = self.reload_handle();
        Arc::new(move |config| {
            let reload = reload.clone();
            Box::pin(async move {
                reload
                    .reload_with_previous(config, "managed-snapshot")
                    .await
            })
        })
    }
}

impl GatewayReloadHandle {
    async fn prepare_node_api_reload(
        &self,
        old_config: &GatewayConfig,
        new_config: &GatewayConfig,
    ) -> Result<PreparedNodeApiReload> {
        if old_config.management == new_config.management {
            return Ok(PreparedNodeApiReload::Unchanged);
        }

        crate::node_api::validate_node_api_listener_config(&new_config.management)?;

        if !new_config.management.enabled {
            return Ok(PreparedNodeApiReload::Disable);
        }

        let same_address = old_config.management.enabled
            && old_config.management.address == new_config.management.address;
        if same_address {
            return Ok(PreparedNodeApiReload::RestartSameAddress);
        }

        let prepared = crate::node_api::prepare_node_api_listener(
            &new_config.management,
            self.node_api_state(),
        )
        .await?;
        Ok(PreparedNodeApiReload::SwapPrepared(prepared.map(Box::new)))
    }

    async fn commit_node_api_reload(
        &self,
        config: &GatewayConfig,
        prepared: PreparedNodeApiReload,
    ) -> Result<()> {
        match prepared {
            PreparedNodeApiReload::Unchanged => Ok(()),
            PreparedNodeApiReload::Disable => {
                if let Some(handle) = self.node_api_handle.write().unwrap().take() {
                    handle.abort();
                }
                Ok(())
            }
            PreparedNodeApiReload::RestartSameAddress => {
                self.restart_node_api_listener(config).await
            }
            PreparedNodeApiReload::SwapPrepared(prepared) => {
                let new_handle = prepared.map(|listener| (*listener).spawn());
                let old_handle = {
                    let mut handle = self.node_api_handle.write().unwrap();
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
        telemetry: crate::observability::metrics::PreparedTelemetry,
        source: &str,
    ) -> Result<()> {
        let changed_names: HashSet<String> = new_config
            .entrypoints
            .iter()
            .filter(|(name, entrypoint)| old_config.entrypoints.get(*name) != Some(*entrypoint))
            .map(|(name, _)| name.clone())
            .collect();
        let mut reconfigure_names: HashSet<String> = changed_names
            .iter()
            .filter(|name| {
                old_config
                    .entrypoints
                    .get(*name)
                    .zip(new_config.entrypoints.get(*name))
                    .is_some_and(|(old, new)| new.can_reconfigure_in_place_from(old))
            })
            .cloned()
            .collect();
        reconfigure_names.extend(
            new_config
                .entrypoints
                .iter()
                .filter_map(|(name, entrypoint)| {
                    old_config
                        .entrypoints
                        .get(name)
                        .filter(|active| {
                            entrypoint.protocol == crate::config::Protocol::Udp
                                && entrypoint.can_reconfigure_in_place_from(active)
                        })
                        .map(|_| name.clone())
                }),
        );
        let restart_names: HashSet<String> = changed_names
            .difference(&reconfigure_names)
            .cloned()
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
        let conflicting_names: Vec<String> = old_config
            .entrypoints
            .iter()
            .filter(|(name, entrypoint)| {
                (restart_names.contains(*name) || removed_names.contains(*name))
                    && restart_addresses.contains(&entrypoint.address)
            })
            .map(|(name, _)| name.clone())
            .collect();
        if !conflicting_names.is_empty() {
            return Err(GatewayError::Config(format!(
                "Cannot atomically replace entrypoint listener(s) {} because the target address is still bound; preserve the listener name, address, and protocol for in-place reconfiguration or move to a new address",
                conflicting_names.join(", ")
            )));
        }

        let prepared_reconfigures: Vec<entrypoint::PreparedEntrypointReconfigure> = {
            let handles = self.handles.read().unwrap();
            reconfigure_names
                .iter()
                .map(|name| {
                    let handle = handles.get(name).ok_or_else(|| {
                        GatewayError::Other(format!(
                            "Active entrypoint '{}' has no listener handle",
                            name
                        ))
                    })?;
                    let config = new_config.entrypoints.get(name).ok_or_else(|| {
                        GatewayError::Config(format!(
                            "Reloaded entrypoint '{}' has no configuration",
                            name
                        ))
                    })?;
                    handle.prepare_reconfigure(config)
                })
                .collect::<Result<Vec<_>>>()?
        };

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

        for prepared in prepared_reconfigures {
            prepared.commit();
        }
        self.metrics.activate_telemetry(telemetry);
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
            reconfigured = reconfigure_names.len(),
            restarted = restart_names.len(),
            removed = removed_names.len(),
            "Entrypoints incrementally reconciled"
        );

        Ok(())
    }

    async fn restart_node_api_listener(&self, config: &GatewayConfig) -> Result<()> {
        crate::node_api::validate_node_api_listener_config(&config.management)?;

        let old_management = self.config.read().unwrap().management.clone();
        let same_address = old_management.enabled
            && config.management.enabled
            && old_management.address == config.management.address;

        if same_address {
            let old_handle = { self.node_api_handle.write().unwrap().take() };
            if let Some(handle) = old_handle {
                handle.abort();
                tokio::task::yield_now().await;
            }

            let handle =
                crate::node_api::start_node_api_listener(&config.management, self.node_api_state())
                    .await?;
            *self.node_api_handle.write().unwrap() = handle;
            return Ok(());
        }

        let new_handle =
            crate::node_api::start_node_api_listener(&config.management, self.node_api_state())
                .await?;
        let old_handle = {
            let mut handle = self.node_api_handle.write().unwrap();
            let old = handle.take();
            *handle = new_handle;
            old
        };
        if let Some(handle) = old_handle {
            handle.abort();
        }
        Ok(())
    }

    fn node_api_state(&self) -> crate::node_api::NodeApiState {
        crate::node_api::NodeApiState {
            config: self.config.clone(),
            lifecycle_state: self.state.clone(),
            start_time: self.start_time,
            metrics: self.metrics.clone(),
            reload_managed_snapshot: Some(self.managed_snapshot_reload_callback()),
            managed_snapshots: self.managed_snapshots.clone(),
            usage_spool: self.usage_spool.clone(),
        }
    }

    fn managed_snapshot_reload_callback(&self) -> ManagedSnapshotReloadCallback {
        let reload = self.clone();
        Arc::new(move |config| {
            let reload = reload.clone();
            Box::pin(async move {
                reload
                    .reload_with_previous(config, "managed-snapshot")
                    .await
            })
        })
    }
}

#[cfg(test)]
mod tests;
