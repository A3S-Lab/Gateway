//! Gateway startup and durable managed-snapshot recovery.

use super::{build_runtime, entrypoint, replace_autoscaler, Gateway};
use crate::config::GatewayConfig;
use crate::error::Result;
use crate::provider::discovery;
use crate::GatewayState;

impl Gateway {
    /// Start the gateway — binds listeners and begins accepting connections.
    pub async fn start(&self) -> Result<()> {
        self.set_state(GatewayState::Starting);

        let bootstrap_config = self.config.read().unwrap().clone();
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
        let config = recovery
            .as_ref()
            .map(|recovery| recovery.config.clone())
            .unwrap_or_else(|| bootstrap_config.clone());
        if recovery.is_some() {
            if let Err(error) = config
                .validate_reload_from(&bootstrap_config)
                .and_then(|()| config.validate_managed_snapshot_reload_from(&bootstrap_config))
                .and_then(|()| entrypoint::validate_entrypoints(&config))
            {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        }

        let built = match build_runtime(&config, self.metrics.clone(), None).await {
            Ok(built) => built,
            Err(error) => {
                self.set_state(GatewayState::Created);
                return Err(error);
            }
        };
        let runtime = entrypoint::GatewayRuntime::new(built.state.clone());

        let new_handles = match entrypoint::start_entrypoints(
            &config,
            runtime.clone(),
            self.shutdown_tx.subscribe(),
        )
        .await
        {
            Ok(handles) => handles,
            Err(error) => {
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
                self.set_state(GatewayState::Created);
                return Err(error);
            }
            *self.config.write().unwrap() = config.clone();
            tracing::info!("Durable managed snapshot recovered");
        }

        {
            let mut handles = self.handles.write().unwrap();
            *handles = new_handles;
        }
        *self.runtime.write().unwrap() = Some(runtime);
        *self.live_registry.write().unwrap() = Some(built.service_registry.clone());

        if let Err(error) = self.start_management_listener(&config).await {
            for (_, handle) in self.handles.write().unwrap().drain() {
                handle.abort();
            }
            *self.runtime.write().unwrap() = None;
            *self.live_registry.write().unwrap() = None;
            self.set_state(GatewayState::Created);
            return Err(error);
        }
        replace_autoscaler(&self.autoscaler_handle, built.autoscaler).await;

        self.set_state(GatewayState::Running);
        tracing::info!("Gateway is running");

        self.start_dynamic_providers(&config);
        self.start_acme_manager(&config);
        Ok(())
    }

    fn start_dynamic_providers(&self, config: &GatewayConfig) {
        if let Some(ref disc_config) = config.providers.discovery {
            let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
            let disc_handle =
                discovery::spawn_discovery_loop(disc_config.clone(), config.clone(), tx);

            let reload = self.reload_handle();
            let receiver_handle = tokio::spawn(async move {
                while let Some(new_config) = rx.recv().await {
                    if let Err(error) = reload.reload(new_config, "discovery").await {
                        tracing::error!(
                            error = %error,
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

        self.start_kubernetes_provider(config);

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
                    if let Err(error) = reload.reload(new_config, "docker").await {
                        tracing::error!(
                            error = %error,
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
    }

    #[cfg(feature = "kube")]
    fn start_kubernetes_provider(&self, config: &GatewayConfig) {
        let Some(k8s_config) = config.providers.kubernetes.as_ref() else {
            return;
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<GatewayConfig>(1);
        let k8s_handle = crate::provider::kubernetes::spawn_ingress_watch(
            k8s_config.clone(),
            config.clone(),
            tx.clone(),
        );
        let crd_handle = k8s_config.ingress_route_crd.then(|| {
            crate::provider::kubernetes_crd::spawn_crd_watch(k8s_config.clone(), config.clone(), tx)
        });

        let reload = self.reload_handle();
        let receiver_handle = tokio::spawn(async move {
            while let Some(new_config) = rx.recv().await {
                if let Err(error) = reload.reload(new_config, "kubernetes").await {
                    tracing::error!(
                        error = %error,
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

    #[cfg(not(feature = "kube"))]
    fn start_kubernetes_provider(&self, config: &GatewayConfig) {
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
