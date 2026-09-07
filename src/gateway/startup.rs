//! Gateway startup and durable managed-snapshot recovery.

use super::{
    build_runtime, ensure_lifecycle_operation, entrypoint, replace_autoscaler,
    replace_health_checks, Gateway,
};
use crate::config::GatewayConfig;
use crate::error::Result;
use crate::provider::{self, discovery};
use crate::usage::{UsageSpool, UsageSpoolOptions};
use crate::GatewayState;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;

/// Serializes updates from every dynamic provider and composes them as source
/// overlays. Providers poll independently, but the runtime must see one
/// deterministic snapshot; otherwise a stale Docker candidate can erase a
/// route just discovered by Kubernetes (or vice versa).
#[derive(Clone)]
struct DynamicConfigCoordinator {
    state: Arc<tokio::sync::Mutex<DynamicConfigState>>,
}

#[derive(Clone)]
struct DynamicConfigState {
    overlays: BTreeMap<String, DynamicConfigOverlay>,
    /// The static/operator snapshot used as the baseline for newly observed
    /// provider candidates. It is updated after every accepted composition.
    base: GatewayConfig,
    /// Last fully composed snapshot. Differences here that appear before a
    /// provider update are operator edits and must not be reintroduced by a
    /// stale provider candidate.
    last_effective: GatewayConfig,
    /// Provider-independent keys explicitly removed by an operator. A stale
    /// provider snapshot must not resurrect these keys.
    tombstones: DynamicConfigTombstones,
    /// Baseline each provider used when it produced its candidate. Providers
    /// currently receive the startup snapshot, so this lets us distinguish
    /// inherited static entries from genuinely discovered entries.
    source_bases: BTreeMap<String, GatewayConfig>,
}

#[derive(Clone, Default)]
struct DynamicConfigTombstones {
    entrypoints: HashSet<String>,
    routers: HashSet<String>,
    services: HashSet<String>,
    middlewares: HashSet<String>,
}

#[derive(Clone, Default)]
struct DynamicConfigOverlay {
    entrypoints: HashMap<String, crate::config::EntrypointConfig>,
    routers: HashMap<String, crate::config::RouterConfig>,
    services: HashMap<String, crate::config::ServiceConfig>,
    middlewares: HashMap<String, crate::config::MiddlewareConfig>,
}

impl DynamicConfigCoordinator {
    fn new(base: GatewayConfig) -> Self {
        Self {
            state: Arc::new(tokio::sync::Mutex::new(DynamicConfigState {
                overlays: BTreeMap::new(),
                base: base.clone(),
                last_effective: base,
                tombstones: DynamicConfigTombstones::default(),
                source_bases: BTreeMap::new(),
            })),
        }
    }

    async fn apply(
        &self,
        reload: &super::GatewayReloadHandle,
        source: &str,
        candidate: GatewayConfig,
    ) -> bool {
        let mut state = self.state.lock().await;
        let previous_state = state.clone();
        let previous = previous_state
            .overlays
            .get(source)
            .cloned()
            .unwrap_or_default();
        let source_base = previous_state
            .source_bases
            .get(source)
            .cloned()
            .unwrap_or_else(|| previous_state.base.clone());
        let mut next_state = previous_state.clone();
        next_state
            .source_bases
            .entry(source.to_string())
            .or_insert_with(|| source_base.clone());
        let result = reload
            .reload_dynamic(source, |current| {
                let mut base = current.clone();
                let mut next_overlays = previous_state.overlays.clone();
                let mut tombstones = previous_state.tombstones.clone();

                record_manual_removals(&previous_state.last_effective, current, &mut tombstones);

                // Remove only values still equal to the last accepted provider
                // value. If an operator/file reload changed one of these keys,
                // that value is retained as an explicit override.
                for (overlay_source, overlay) in &previous_state.overlays {
                    overlay.remove_owned(&mut base, current);
                    if let Some(next_overlay) = next_overlays.get_mut(overlay_source) {
                        next_overlay.retain_owned(current);
                    }
                }

                let next_overlay = DynamicConfigOverlay::from_candidate(
                    &candidate,
                    &source_base,
                    &base,
                    &previous,
                    &tombstones,
                );
                next_overlays.insert(source.to_string(), next_overlay);
                let composed = compose_dynamic_config(base.clone(), &next_overlays);
                next_state.overlays = next_overlays;
                next_state.base = base;
                next_state.last_effective = composed.clone();
                next_state.tombstones = tombstones;
                composed
            })
            .await;

        match result {
            Ok(()) => {
                *state = next_state;
                true
            }
            Err(error) => {
                tracing::error!(
                    source,
                    error = %error,
                    "Dynamic provider candidate was rejected; retaining its previous overlay"
                );
                false
            }
        }
    }
}

impl Default for DynamicConfigState {
    fn default() -> Self {
        Self::new(GatewayConfig::default())
    }
}

impl DynamicConfigState {
    fn new(base: GatewayConfig) -> Self {
        Self {
            overlays: BTreeMap::new(),
            last_effective: base.clone(),
            base,
            tombstones: DynamicConfigTombstones::default(),
            source_bases: BTreeMap::new(),
        }
    }
}

impl Default for DynamicConfigCoordinator {
    fn default() -> Self {
        Self::new(GatewayConfig::default())
    }
}

impl DynamicConfigOverlay {
    fn from_candidate(
        candidate: &GatewayConfig,
        source_base: &GatewayConfig,
        base: &GatewayConfig,
        previous: &Self,
        tombstones: &DynamicConfigTombstones,
    ) -> Self {
        Self {
            entrypoints: collect_overlay(
                &candidate.entrypoints,
                &source_base.entrypoints,
                &base.entrypoints,
                &previous.entrypoints,
                &tombstones.entrypoints,
            ),
            routers: collect_overlay(
                &candidate.routers,
                &source_base.routers,
                &base.routers,
                &previous.routers,
                &tombstones.routers,
            ),
            services: collect_overlay(
                &candidate.services,
                &source_base.services,
                &base.services,
                &previous.services,
                &tombstones.services,
            ),
            middlewares: collect_overlay(
                &candidate.middlewares,
                &source_base.middlewares,
                &base.middlewares,
                &previous.middlewares,
                &tombstones.middlewares,
            ),
        }
    }

    fn remove_owned(&self, base: &mut GatewayConfig, current: &GatewayConfig) {
        remove_matching(
            &mut base.entrypoints,
            &self.entrypoints,
            &current.entrypoints,
        );
        remove_matching(&mut base.routers, &self.routers, &current.routers);
        remove_matching(&mut base.services, &self.services, &current.services);
        remove_matching(
            &mut base.middlewares,
            &self.middlewares,
            &current.middlewares,
        );
    }

    fn retain_owned(&mut self, current: &GatewayConfig) {
        self.entrypoints.retain(|name, value| {
            current
                .entrypoints
                .get(name)
                .is_some_and(|current| serialized_equal(current, value))
        });
        self.routers.retain(|name, value| {
            current
                .routers
                .get(name)
                .is_some_and(|current| serialized_equal(current, value))
        });
        self.services.retain(|name, value| {
            current
                .services
                .get(name)
                .is_some_and(|current| serialized_equal(current, value))
        });
        self.middlewares.retain(|name, value| {
            current
                .middlewares
                .get(name)
                .is_some_and(|current| serialized_equal(current, value))
        });
    }
}

fn collect_overlay<T: Clone + serde::Serialize>(
    candidate: &HashMap<String, T>,
    source_base: &HashMap<String, T>,
    base: &HashMap<String, T>,
    previous: &HashMap<String, T>,
    tombstones: &HashSet<String>,
) -> HashMap<String, T> {
    candidate
        .iter()
        .filter(|(name, value)| {
            if tombstones.contains(*name) || base.contains_key(*name) {
                return false;
            }
            previous.contains_key(*name)
                || source_base
                    .get(*name)
                    .is_none_or(|source_value| !serialized_equal(*value, source_value))
        })
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

fn remove_matching<T: serde::Serialize>(
    base: &mut HashMap<String, T>,
    owned: &HashMap<String, T>,
    current: &HashMap<String, T>,
) {
    for (name, old_value) in owned {
        let still_owned = current
            .get(name)
            .is_some_and(|current_value| serialized_equal(current_value, old_value));
        if still_owned || !current.contains_key(name) {
            base.remove(name);
        }
    }
}

fn record_manual_removals(
    previous: &GatewayConfig,
    current: &GatewayConfig,
    tombstones: &mut DynamicConfigTombstones,
) {
    record_manual_removals_for_map(
        &previous.entrypoints,
        &current.entrypoints,
        &mut tombstones.entrypoints,
    );
    record_manual_removals_for_map(&previous.routers, &current.routers, &mut tombstones.routers);
    record_manual_removals_for_map(
        &previous.services,
        &current.services,
        &mut tombstones.services,
    );
    record_manual_removals_for_map(
        &previous.middlewares,
        &current.middlewares,
        &mut tombstones.middlewares,
    );
}

fn record_manual_removals_for_map<T>(
    previous: &HashMap<String, T>,
    current: &HashMap<String, T>,
    tombstones: &mut HashSet<String>,
) {
    for name in previous.keys().filter(|name| !current.contains_key(*name)) {
        tombstones.insert(name.clone());
    }
}

fn serialized_equal<T: serde::Serialize>(left: &T, right: &T) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn compose_dynamic_config(
    mut base: GatewayConfig,
    overlays: &BTreeMap<String, DynamicConfigOverlay>,
) -> GatewayConfig {
    for overlay in overlays.values() {
        insert_overlay(&mut base.entrypoints, &overlay.entrypoints);
        insert_overlay(&mut base.routers, &overlay.routers);
        insert_overlay(&mut base.services, &overlay.services);
        insert_overlay(&mut base.middlewares, &overlay.middlewares);
    }
    base
}

fn insert_overlay<T: Clone>(target: &mut HashMap<String, T>, overlay: &HashMap<String, T>) {
    for (name, value) in overlay {
        target.entry(name.clone()).or_insert_with(|| value.clone());
    }
}

impl Gateway {
    /// Start the gateway — binds listeners and begins accepting connections.
    ///
    /// Startup is accepted only from [`GatewayState::Created`] and is serialized
    /// with reload and shutdown. A stopped gateway cannot be restarted.
    pub async fn start(&self) -> Result<()> {
        let _lifecycle = self.lifecycle_lock.lock().await;
        ensure_lifecycle_operation(&self.state, &self.shutdown, GatewayState::Created, "start")?;
        self.set_state(GatewayState::Starting);

        let bootstrap_config = self.config.read().unwrap().clone();
        if let Err(error) = self.open_usage_spool(&bootstrap_config).await {
            self.set_state(GatewayState::Created);
            return Err(error);
        }
        if let Some(store) = &self.managed_services {
            if let Err(error) = store.load().await {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        }
        let recovery = match self
            .managed_snapshots
            .load_recovery(chrono::Utc::now())
            .await
        {
            Ok(recovery) => recovery,
            Err(error) => {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        };
        let base_config = recovery
            .as_ref()
            .map(|recovery| recovery.config.clone())
            .unwrap_or_else(|| bootstrap_config.clone());
        if recovery.is_some() {
            if let Err(error) = base_config
                .validate_reload_from(&bootstrap_config)
                .and_then(|()| base_config.validate_managed_snapshot_reload_from(&bootstrap_config))
            {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        }
        let runtime_config = match self.effective_config(&base_config) {
            Ok(config) => config,
            Err(error) => {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        };
        if let Err(error) = entrypoint::validate_entrypoints(&runtime_config) {
            self.set_state(GatewayState::Created);
            return Err(error);
        }

        let usage_spool = self.usage_spool.read().unwrap().clone();
        let built = match build_runtime(
            &runtime_config,
            self.metrics.clone(),
            self.middleware_registry.as_ref(),
            None,
            usage_spool,
        )
        .await
        {
            Ok(built) => built,
            Err(error) => {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        };
        let runtime = entrypoint::GatewayRuntime::new(built.state.clone())
            .with_managed_snapshot_store(self.managed_snapshots.clone());
        let previous_telemetry = self.metrics.activate_telemetry(built.telemetry.clone());

        let new_handles = match entrypoint::start_entrypoints(
            &runtime_config,
            runtime.clone(),
            self.shutdown_tx.subscribe(),
        )
        .await
        {
            Ok(handles) => handles,
            Err(error) => {
                self.metrics.activate_telemetry(previous_telemetry);
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        };
        tracing::info!(entrypoints = new_handles.len(), "Entrypoints started");

        if let Some(recovery) = recovery {
            if let Err(error) = self
                .managed_snapshots
                .complete_recovery(recovery, chrono::Utc::now())
                .await
            {
                for (_, handle) in new_handles {
                    handle.abort();
                }
                self.metrics.activate_telemetry(previous_telemetry);
                self.set_state(GatewayState::Created);
                return Err(error);
            }
            *self.config.write().unwrap() = base_config.clone();
            tracing::info!("Durable managed snapshot recovered");
        }

        {
            let mut handles = self.handles.write().unwrap();
            *handles = new_handles;
        }
        *self.runtime.write().unwrap() = Some(runtime);
        if let Err(error) = self.start_node_api_listener(&base_config).await {
            for (_, handle) in self.handles.write().unwrap().drain() {
                handle.abort();
            }
            *self.runtime.write().unwrap() = None;
            self.metrics.activate_telemetry(previous_telemetry);
            self.set_state(GatewayState::Created);
            return Err(error);
        }
        replace_health_checks(&self.health_check_tasks, built.health_checks).await;
        replace_autoscaler(&self.autoscaler_handle, built.autoscaler).await;

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway is running");

        self.start_dynamic_providers(&base_config);
        self.start_acme_manager(&base_config);
        Ok(())
    }

    async fn open_usage_spool(&self, config: &GatewayConfig) -> Result<()> {
        let Some(spool_config) = &config.managed.usage_spool else {
            return Ok(());
        };
        if self.usage_spool.read().unwrap().is_some() {
            return Ok(());
        }
        let gateway_id = config.managed.gateway_id.ok_or_else(|| {
            crate::error::GatewayError::Config(
                "managed.usage_spool requires managed.gateway_id".to_string(),
            )
        })?;
        let spool = UsageSpool::open(UsageSpoolOptions {
            directory: spool_config.directory.clone(),
            gateway_id,
            max_bytes: spool_config.max_bytes,
        })
        .await
        .map_err(|error| {
            crate::error::GatewayError::Other(format!(
                "Durable usage spool could not start: {error}"
            ))
        })?;
        *self.usage_spool.write().unwrap() = Some(std::sync::Arc::new(spool));
        Ok(())
    }

    fn start_dynamic_providers(&self, config: &GatewayConfig) {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<provider::ConfigUpdate>(8);
        let coordinator = DynamicConfigCoordinator::new(config.clone());
        let reload = self.reload_handle();
        let receiver_coordinator = coordinator.clone();
        let receiver_handle = tokio::spawn(async move {
            while let Some(update) = rx.recv().await {
                let accepted = receiver_coordinator
                    .apply(&reload, update.source, update.config)
                    .await;
                let _ = update.acknowledged.send(accepted);
            }
        });
        self.provider_handles.write().unwrap().push(receiver_handle);

        if let Some(ref disc_config) = config.providers.discovery {
            let disc_handle = discovery::spawn_discovery_loop_with_ack(
                disc_config.clone(),
                config.clone(),
                tx.clone(),
            );

            let mut handle = self.discovery_handle.write().unwrap();
            *handle = Some(disc_handle);
            tracing::info!("Discovery polling loop started");
        }

        self.start_kubernetes_provider(config, tx.clone());

        if let Some(ref docker_config) = config.providers.docker {
            let docker_handle = crate::provider::docker::spawn_docker_loop_with_ack(
                docker_config.clone(),
                config.clone(),
                tx.clone(),
            );

            let mut provider_handles = self.provider_handles.write().unwrap();
            provider_handles.push(docker_handle);
            tracing::info!("Docker provider polling loop started");
        }
    }

    #[cfg(feature = "kube")]
    fn start_kubernetes_provider(
        &self,
        config: &GatewayConfig,
        tx: tokio::sync::mpsc::Sender<provider::ConfigUpdate>,
    ) {
        let Some(k8s_config) = config.providers.kubernetes.as_ref() else {
            return;
        };
        let k8s_handle = crate::provider::kubernetes::spawn_ingress_watch_with_ack(
            k8s_config.clone(),
            config.clone(),
            tx.clone(),
        );
        let crd_handle = k8s_config.ingress_route_crd.then(|| {
            crate::provider::kubernetes_crd::spawn_crd_watch_with_ack(
                k8s_config.clone(),
                config.clone(),
                tx,
            )
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
    }

    #[cfg(not(feature = "kube"))]
    fn start_kubernetes_provider(
        &self,
        config: &GatewayConfig,
        _tx: tokio::sync::mpsc::Sender<provider::ConfigUpdate>,
    ) {
        if config.providers.kubernetes.is_some() {
            tracing::warn!(
                "Kubernetes provider configured but the 'kube' feature is not enabled. \
                 Rebuild with `--features kube` to enable Kubernetes support."
            );
        }
    }

    fn start_acme_manager(&self, config: &GatewayConfig) {
        let acme_tls = config
            .entrypoints
            .values()
            .find_map(|entrypoint| entrypoint.tls.as_ref().filter(|tls| tls.acme));
        let Some(tls) = acme_tls else {
            return;
        };
        let email = tls.acme_email.clone().unwrap_or_default();
        if email.is_empty() {
            tracing::warn!("ACME enabled but acme_email is not set, skipping ACME manager");
            return;
        }

        let domains = if tls.acme_domains.is_empty() {
            config
                .routers
                .values()
                .filter_map(|router| {
                    router
                        .rule
                        .strip_prefix("Host(`")
                        .and_then(|rule| rule.split('`').next())
                        .map(str::to_string)
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
            Err(error) => {
                tracing::error!(error = %error, "Failed to create ACME manager");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn router(service: &str) -> crate::config::RouterConfig {
        crate::config::RouterConfig {
            rule: format!("PathPrefix(`/{service}`)"),
            service: service.to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: Vec::new(),
            priority: 0,
        }
    }

    #[test]
    fn dynamic_provider_overlays_are_composed() {
        let base = GatewayConfig::default();
        let mut docker_config = base.clone();
        docker_config
            .routers
            .insert("docker-api".to_string(), router("docker-api"));
        let mut kubernetes_config = base.clone();
        kubernetes_config
            .routers
            .insert("k8s-api".to_string(), router("k8s-api"));

        let mut overlays = BTreeMap::new();
        overlays.insert(
            "docker".to_string(),
            DynamicConfigOverlay::from_candidate(
                &docker_config,
                &base,
                &base,
                &DynamicConfigOverlay::default(),
                &DynamicConfigTombstones::default(),
            ),
        );
        overlays.insert(
            "kubernetes-ingress".to_string(),
            DynamicConfigOverlay::from_candidate(
                &kubernetes_config,
                &base,
                &base,
                &DynamicConfigOverlay::default(),
                &DynamicConfigTombstones::default(),
            ),
        );

        let merged = compose_dynamic_config(base, &overlays);
        assert!(merged.routers.contains_key("docker-api"));
        assert!(merged.routers.contains_key("k8s-api"));
    }

    #[test]
    fn static_entries_win_over_provider_candidates() {
        let mut base = GatewayConfig::default();
        base.routers.insert("shared".to_string(), router("static"));
        let mut candidate = base.clone();
        candidate
            .routers
            .insert("shared".to_string(), router("provider"));

        let overlay = DynamicConfigOverlay::from_candidate(
            &candidate,
            &base,
            &base,
            &DynamicConfigOverlay::default(),
            &DynamicConfigTombstones::default(),
        );
        assert!(!overlay.routers.contains_key("shared"));
        let mut overlays = BTreeMap::new();
        overlays.insert("docker".to_string(), overlay);
        let merged = compose_dynamic_config(base, &overlays);
        assert_eq!(merged.routers["shared"].service, "static");
    }

    #[test]
    fn changed_manual_value_is_not_removed_as_provider_owned() {
        let base = GatewayConfig::default();
        let mut current = base.clone();
        current
            .routers
            .insert("api".to_string(), router("provider-v1"));
        let old_overlay = DynamicConfigOverlay::from_candidate(
            &current,
            &base,
            &base,
            &DynamicConfigOverlay::default(),
            &DynamicConfigTombstones::default(),
        );
        current
            .routers
            .insert("api".to_string(), router("operator"));
        let mut stripped = current.clone();
        old_overlay.remove_owned(&mut stripped, &current);
        assert_eq!(stripped.routers["api"].service, "operator");
    }

    #[test]
    fn stale_provider_candidate_cannot_resurrect_manual_removal() {
        let base = GatewayConfig::default();
        let mut old_candidate = base.clone();
        old_candidate
            .routers
            .insert("discovered".to_string(), router("discovered"));
        let previous = DynamicConfigOverlay::from_candidate(
            &old_candidate,
            &base,
            &base,
            &DynamicConfigOverlay::default(),
            &DynamicConfigTombstones::default(),
        );

        let mut current = compose_dynamic_config(
            base.clone(),
            &BTreeMap::from([("discovery".to_string(), previous.clone())]),
        );
        current.routers.remove("discovered");
        let mut tombstones = DynamicConfigTombstones::default();
        record_manual_removals(&old_candidate, &current, &mut tombstones);
        let mut stripped = current.clone();
        previous.remove_owned(&mut stripped, &current);
        let mut next = previous.clone();
        next.retain_owned(&current);

        let replacement = DynamicConfigOverlay::from_candidate(
            &old_candidate,
            &base,
            &stripped,
            &previous,
            &tombstones,
        );
        assert!(!replacement.routers.contains_key("discovered"));
        assert!(!next.routers.contains_key("discovered"));
    }

    #[test]
    fn stale_candidate_does_not_reclaim_a_removed_static_key() {
        let mut base = GatewayConfig::default();
        base.routers.insert("static".to_string(), router("static"));
        let mut current = base.clone();
        current.routers.remove("static");
        let mut tombstones = DynamicConfigTombstones::default();
        record_manual_removals(&base, &current, &mut tombstones);

        let overlay = DynamicConfigOverlay::from_candidate(
            &base,
            &base,
            &current,
            &DynamicConfigOverlay::default(),
            &tombstones,
        );
        assert!(!overlay.routers.contains_key("static"));
    }
}
