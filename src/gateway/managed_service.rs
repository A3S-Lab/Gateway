use super::Gateway;
use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use crate::managed_service::{
    ManagedServiceBinding, ManagedServiceBindingIdentity, ManagedServiceBindingRequest,
    ManagedServiceStatus, StoredManagedServiceBinding,
};
use crate::middleware::MiddlewareRegistry;
use crate::service::Backend;
use crate::GatewayState;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

impl Gateway {
    /// Create a Gateway with a durable exact-generation Runtime route overlay.
    pub fn with_managed_service_state(
        config: GatewayConfig,
        state_file: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::with_middlewares_and_managed_service_state(
            config,
            MiddlewareRegistry::new(),
            state_file,
        )
    }

    /// Create a Gateway with custom middleware and durable Runtime routes.
    pub fn with_middlewares_and_managed_service_state(
        config: GatewayConfig,
        middleware_registry: MiddlewareRegistry,
        state_file: impl Into<PathBuf>,
    ) -> Result<Self> {
        let store = Arc::new(crate::managed_service::ManagedServiceStore::new(
            state_file.into(),
        )?);
        validate_separate_state_paths(&config, store.path())?;
        Self::with_components(config, middleware_registry, Some(store))
    }

    /// Idempotently bind and health-verify one exact private Runtime route.
    pub async fn bind_managed_service(
        &self,
        request: ManagedServiceBindingRequest,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<ManagedServiceBinding> {
        self.ensure_managed_service_operation("bind")?;
        ensure_before_deadline(deadline, "bind")?;
        let store = self.managed_service_store()?;
        let (record, binding, committed_base) = {
            let _lifecycle = self.lifecycle_lock.lock().await;
            self.ensure_managed_service_operation("bind")?;
            ensure_before_deadline(deadline, "bind")?;
            let base = self.config();
            let (record, replayed) = store.prepare_bind(request, &base).await?;
            if self.exact_backend(&record)?.is_none() {
                self.reload_handle()
                    .reload_locked(None, "managed-service-bind")
                    .await?;
            }
            let committed_base = self.config();
            let binding = record.binding(&committed_base, replayed)?;
            (record, binding, committed_base)
        };
        self.verify_managed_service_health(&record, &committed_base, deadline)
            .await?;
        let _lifecycle = self.lifecycle_lock.lock().await;
        self.ensure_managed_service_operation("commit readiness for")?;
        ensure_before_deadline(deadline, "commit Managed Service readiness")?;
        store.mark_ready(binding.identity()).await?;
        ensure_before_deadline(deadline, "commit Managed Service readiness")?;
        Ok(binding)
    }

    /// Hide one exact route and wait for every admitted upstream operation.
    pub async fn drain_managed_service(
        &self,
        identity: &ManagedServiceBindingIdentity,
        operation_key: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        self.ensure_managed_service_operation("drain")?;
        ensure_before_deadline(deadline, "drain")?;
        let store = self.managed_service_store()?;
        let (record, backend) = {
            let _lifecycle = self.lifecycle_lock.lock().await;
            self.ensure_managed_service_operation("drain")?;
            ensure_before_deadline(deadline, "drain")?;
            let record = store.begin_drain(identity, operation_key).await?;
            let backend = self.managed_service_drain_backend(&record)?;
            if let Some(backend) = &backend {
                backend.close_managed_admission();
            }
            self.reload_handle()
                .reload_locked(None, "managed-service-drain")
                .await?;
            (record, backend)
        };
        ensure_before_deadline(deadline, "drain")?;
        if let Some(backend) = backend {
            backend.wait_for_managed_drain(deadline).await?;
        }
        let _lifecycle = self.lifecycle_lock.lock().await;
        self.ensure_managed_service_operation("commit drain for")?;
        ensure_before_deadline(deadline, "commit Managed Service drain")?;
        store.finish_drain(identity).await?;
        self.managed_service_drains
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&record.binding_id);
        ensure_before_deadline(deadline, "commit Managed Service drain")
    }

    /// Remove one already-drained receipt-owned route record.
    pub async fn remove_managed_service(
        &self,
        identity: &ManagedServiceBindingIdentity,
        operation_key: &str,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        self.ensure_managed_service_operation("remove")?;
        ensure_before_deadline(deadline, "remove")?;
        let _lifecycle = self.lifecycle_lock.lock().await;
        self.ensure_managed_service_operation("remove")?;
        ensure_before_deadline(deadline, "remove")?;
        self.managed_service_store()?
            .remove(identity, operation_key)
            .await?;
        ensure_before_deadline(deadline, "remove")
    }

    /// Read bounded state for one exact receipt identity.
    pub fn managed_service_status(
        &self,
        identity: &ManagedServiceBindingIdentity,
    ) -> Result<Option<ManagedServiceStatus>> {
        self.managed_service_store()?.status(identity)
    }

    pub(crate) fn effective_config(&self, base: &GatewayConfig) -> Result<GatewayConfig> {
        match &self.managed_services {
            Some(store) => store.effective_config(base),
            None => Ok(base.clone()),
        }
    }

    fn managed_service_store(&self) -> Result<&Arc<crate::managed_service::ManagedServiceStore>> {
        self.managed_services.as_ref().ok_or_else(|| {
            GatewayError::Config(
                "Managed Service lifecycle requires Gateway::with_managed_service_state"
                    .to_string(),
            )
        })
    }

    fn ensure_managed_service_operation(&self, operation: &str) -> Result<()> {
        if self.state() != GatewayState::Running || self.is_shutdown() {
            return Err(GatewayError::Other(format!(
                "Gateway cannot {operation} a Managed Service while lifecycle state is {}",
                self.state()
            )));
        }
        self.managed_service_store().map(|_| ())
    }

    fn exact_backend(&self, record: &StoredManagedServiceBinding) -> Result<Option<Arc<Backend>>> {
        let Some(runtime) = self
            .runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
        else {
            return Ok(None);
        };
        let state = runtime.load();
        let Some(load_balancer) = state.service_registry.get(&record.service_name()) else {
            return Ok(None);
        };
        let backends = load_balancer.backends();
        let exact = backends
            .iter()
            .filter(|backend| backend.managed_target() == Some(record.request.target()))
            .cloned()
            .collect::<Vec<_>>();
        match exact.as_slice() {
            [] => {
                if backends.is_empty() {
                    Ok(None)
                } else {
                    Err(GatewayError::Other(
                        "Managed Service runtime contains a different exact generation".to_string(),
                    ))
                }
            }
            [backend] => Ok(Some(backend.clone())),
            _ => Err(GatewayError::Other(
                "Managed Service runtime contains duplicate exact-generation backends".to_string(),
            )),
        }
    }

    fn managed_service_drain_backend(
        &self,
        record: &StoredManagedServiceBinding,
    ) -> Result<Option<Arc<Backend>>> {
        let retained = self
            .managed_service_drains
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&record.binding_id)
            .and_then(std::sync::Weak::upgrade);
        if let Some(backend) = retained {
            if backend.managed_target() != Some(record.request.target()) {
                return Err(GatewayError::Other(
                    "Retained Managed Service drain owns a different exact generation".to_string(),
                ));
            }
            return Ok(Some(backend));
        }

        let backend = self.exact_backend(record)?;
        if let Some(backend) = &backend {
            self.managed_service_drains
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(record.binding_id.clone(), Arc::downgrade(backend));
        }
        Ok(backend)
    }

    async fn verify_managed_service_health(
        &self,
        record: &StoredManagedServiceBinding,
        base: &GatewayConfig,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<()> {
        let endpoint = record.health_endpoint(base)?;
        let timeout = Duration::from_millis(record.request.health().timeout_ms());
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .build()
            .map_err(|error| {
                GatewayError::Other(format!(
                    "Could not initialize Managed Service health client: {error}"
                ))
            })?;
        let mut consecutive_successes = 0_u32;
        loop {
            if self.is_shutdown() {
                return Err(GatewayError::Other(
                    "Gateway shutdown interrupted Managed Service health verification".to_string(),
                ));
            }
            ensure_before_deadline(deadline, "verify Managed Service health")?;
            let probe = client.get(&endpoint).send();
            let result = match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, probe)
                    .await
                    .map_err(|_| deadline_error("verify Managed Service health"))?,
                None => probe.await,
            };
            if result.is_ok_and(|response| response.status().is_success()) {
                consecutive_successes += 1;
                if consecutive_successes >= record.request.health().success_threshold() {
                    return Ok(());
                }
            } else {
                consecutive_successes = 0;
            }
            let interval = Duration::from_millis(record.request.health().interval_ms());
            match deadline {
                Some(deadline) => tokio::time::timeout_at(deadline, tokio::time::sleep(interval))
                    .await
                    .map_err(|_| deadline_error("verify Managed Service health"))?,
                None => tokio::time::sleep(interval).await,
            }
        }
    }
}

impl super::GatewayReloadHandle {
    pub(super) fn effective_config(&self, base: &GatewayConfig) -> Result<GatewayConfig> {
        match &self.managed_services {
            Some(store) => store.effective_config(base),
            None => Ok(base.clone()),
        }
    }
}

fn ensure_before_deadline(deadline: Option<tokio::time::Instant>, operation: &str) -> Result<()> {
    if deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now()) {
        return Err(deadline_error(operation));
    }
    Ok(())
}

fn deadline_error(operation: &str) -> GatewayError {
    GatewayError::ServiceUnavailable(format!(
        "Managed Service deadline elapsed while attempting to {operation}"
    ))
}

fn validate_separate_state_paths(config: &GatewayConfig, path: &std::path::Path) -> Result<()> {
    if config.managed.state_file.as_ref().is_some_and(|snapshot| {
        path == snapshot || path.starts_with(snapshot) || snapshot.starts_with(path)
    }) || config.managed.usage_spool.as_ref().is_some_and(|spool| {
        path.starts_with(&spool.directory) || spool.directory.starts_with(path)
    }) {
        return Err(GatewayError::Config(
            "Managed Service state must use a path separate from snapshot and usage state"
                .to_string(),
        ));
    }
    Ok(())
}
