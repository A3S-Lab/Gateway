//! Gateway orchestrator — high-level coordinator for all gateway components
//!
//! Ties together configuration, entrypoints, routers, services, middleware,
//! observability, and hot reload into a single manageable unit.

mod autoscaling;
pub(crate) mod builders;
#[cfg(test)]
mod mode_tests;
mod startup;

use crate::config::GatewayConfig;
use crate::dashboard::{ManagementAuditLog, ManagementReloadCallback};
use crate::entrypoint;
use crate::error::{GatewayError, Result};
use crate::managed_snapshot::{ManagedSnapshotReloadCallback, ManagedSnapshotStore};
use crate::observability::metrics::GatewayMetrics;
use crate::proxy::HttpProxy;
use crate::router::RouterTable;
use crate::service::ServiceRegistry;
use crate::{GatewayState, HealthStatus};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use self::autoscaling::{prepare_autoscaler, PreparedAutoscaler};
use self::builders::{
    build_mirror_failover_state, build_passive_health, build_pipeline_cache, build_scaling_state,
    build_sticky_managers, spawn_log_task,
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
    /// Serializes complete reload transactions across every reload source.
    reload_lock: Arc<tokio::sync::Mutex<()>>,
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
    /// Gateway-native applied and rejected managed snapshot metadata.
    managed_snapshots: Arc<ManagedSnapshotStore>,
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
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    autoscaler_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    live_registry: Arc<RwLock<Option<Arc<ServiceRegistry>>>>,
    management_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
    management_audit_log: Arc<ManagementAuditLog>,
    managed_snapshots: Arc<ManagedSnapshotStore>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

struct BuiltRuntime {
    state: Arc<entrypoint::GatewayState>,
    service_registry: Arc<ServiceRegistry>,
    autoscaler: Option<PreparedAutoscaler>,
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
    previous_inference_authorizer: Option<&crate::inference::InferenceAuthorizer>,
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

    let http_proxy = Arc::new(HttpProxy::new());
    let service_registry = Arc::new(service_registry);
    let autoscaler = prepare_autoscaler(config, scaling_state.as_ref(), &service_registry).await?;
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
            shutdown_timeout: Duration::from_secs(config.shutdown_timeout_secs),
            metrics_enabled: config.observability.metrics_enabled,
            access_log_enabled: config.observability.access_log_enabled,
            tracing_enabled: config.observability.tracing_enabled,
        }),
        service_registry,
        autoscaler,
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
        let _reload = self.reload_lock.lock().await;
        let old_config = self.config.read().unwrap().clone();
        if source != "managed-snapshot"
            && old_config.mode == crate::config::OperatingMode::CloudManaged
            && old_config.managed.gateway_id.is_some()
        {
            return Err(GatewayError::Config(
                "Gateway-native managed snapshots must be applied through /snapshots/apply"
                    .to_string(),
            ));
        }
        new_config.validate_reload_from(&old_config)?;
        if source == "managed-snapshot" {
            new_config.validate_managed_snapshot_reload_from(&old_config)?;
        }
        entrypoint::validate_entrypoints(&new_config)?;
        self.set_state(GatewayState::Reloading);

        tracing::info!(source = source, "Reloading gateway configuration");

        let previous_inference_authorizer = self
            .runtime
            .read()
            .unwrap()
            .as_ref()
            .and_then(|runtime| runtime.load().inference_authorizer.clone());
        let built = match build_runtime(
            &new_config,
            self.metrics.clone(),
            previous_inference_authorizer.as_deref(),
        )
        .await
        {
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
        } else {
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
                self.set_state(GatewayState::Running);
                return Err(err);
            }
            *self.runtime.write().unwrap() = Some(runtime);
        }

        if let Err(err) = self
            .commit_management_reload(&new_config, management_reload)
            .await
        {
            self.set_state(GatewayState::Running);
            return Err(err);
        }

        *self.live_registry.write().unwrap() = Some(built.service_registry.clone());

        {
            let mut config = self.config.write().unwrap();
            *config = new_config;
        }
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
        config.validate()?;
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
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            discovery_handle: Arc::new(RwLock::new(None)),
            provider_handles: Arc::new(RwLock::new(Vec::new())),
            autoscaler_handle: Arc::new(RwLock::new(None)),
            live_registry: Arc::new(RwLock::new(None)),
            management_handle: Arc::new(RwLock::new(None)),
            management_audit_log: Arc::new(ManagementAuditLog::default()),
            managed_snapshots,
            acme_handle: Arc::new(RwLock::new(None)),
            shutdown_tx,
        })
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

        let mut background_handles = Vec::new();

        // Stop discovery and provider loops.
        if let Some(handle) = self.discovery_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Discovery loop aborted");
        }
        background_handles.extend(self.provider_handles.write().unwrap().drain(..));

        // Stop the autoscaler, management listener, and ACME manager.
        if let Some(handle) = self.autoscaler_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Autoscaler loop aborted");
        }

        if let Some(handle) = self.management_handle.write().unwrap().take() {
            background_handles.push(handle);
            tracing::debug!("Management API listener aborted");
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
            reload_lock: self.reload_lock.clone(),
            autoscaler_handle: self.autoscaler_handle.clone(),
            live_registry: self.live_registry.clone(),
            management_handle: self.management_handle.clone(),
            management_audit_log: self.management_audit_log.clone(),
            managed_snapshots: self.managed_snapshots.clone(),
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
            reload_managed_snapshot: Some(self.managed_snapshot_reload_callback()),
            managed_snapshots: self.managed_snapshots.clone(),
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
            reload_managed_snapshot: Some(self.managed_snapshot_reload_callback()),
            managed_snapshots: self.managed_snapshots.clone(),
        }
    }

    fn management_reload_callback(&self) -> crate::dashboard::ManagementReloadCallback {
        let reload = self.clone();
        Arc::new(move |config| {
            let reload = reload.clone();
            Box::pin(async move { reload.reload(config, "management-api").await })
        })
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
