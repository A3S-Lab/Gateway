use super::model::{
    apply_overlay, status, validate_operation_key, ManagedServiceBindingIdentity,
    ManagedServiceBindingRequest, ManagedServicePhase, ManagedServiceStatus,
    StoredManagedServiceBinding,
};
use super::persistence;
use crate::config::GatewayConfig;
use crate::error::{GatewayError, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::sync::Mutex;

const MAX_BINDINGS: usize = 1024;

pub(crate) struct ManagedServiceStore {
    path: PathBuf,
    mutation: Mutex<()>,
    owner_lock: RwLock<Option<std::fs::File>>,
    bindings: RwLock<BTreeMap<String, StoredManagedServiceBinding>>,
}

impl ManagedServiceStore {
    pub(crate) fn new(path: PathBuf) -> Result<Self> {
        Ok(Self {
            path: persistence::validate_path(path)?,
            mutation: Mutex::new(()),
            owner_lock: RwLock::new(None),
            bindings: RwLock::new(BTreeMap::new()),
        })
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }

    pub(crate) async fn load(&self) -> Result<()> {
        let _mutation = self.mutation.lock().await;
        if self
            .owner_lock
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none()
        {
            let owner_lock = persistence::acquire_lock(&self.path).await?;
            *self
                .owner_lock
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(owner_lock);
        }
        let records = persistence::read(&self.path).await?;
        if records.len() > MAX_BINDINGS {
            return Err(store_error(format!(
                "Managed Service state contains more than {MAX_BINDINGS} bindings"
            )));
        }
        let mut binding_ids = BTreeSet::new();
        let mut operation_keys = BTreeSet::new();
        let mut loaded = BTreeMap::new();
        for record in records {
            record.validate()?;
            if !binding_ids.insert(record.binding_id.clone())
                || !operation_keys.insert(record.request.idempotency_key().to_string())
                || loaded.insert(record.binding_id.clone(), record).is_some()
            {
                return Err(store_error(
                    "Managed Service state contains duplicate binding identity".to_string(),
                ));
            }
        }
        *self.write_bindings() = loaded;
        Ok(())
    }

    pub(crate) fn release_lock(&self) {
        self.owner_lock
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
    }

    pub(crate) fn effective_config(&self, base: &GatewayConfig) -> Result<GatewayConfig> {
        let mut effective = base.clone();
        let records = self.read_bindings().values().cloned().collect::<Vec<_>>();
        apply_overlay(&mut effective, records.into_iter())?;
        Ok(effective)
    }

    pub(crate) fn validate_base_reload(
        &self,
        current: &GatewayConfig,
        candidate: &GatewayConfig,
    ) -> Result<()> {
        for binding in self.read_bindings().values() {
            let name = binding.request.entrypoint();
            if current.entrypoints.get(name) != candidate.entrypoints.get(name) {
                return Err(GatewayError::Config(format!(
                    "Managed Service entrypoint '{name}' cannot change until every binding that owns it is removed"
                )));
            }
        }
        Ok(())
    }

    pub(crate) async fn prepare_bind(
        &self,
        request: ManagedServiceBindingRequest,
        base: &GatewayConfig,
    ) -> Result<(StoredManagedServiceBinding, bool)> {
        request.validate()?;
        let candidate = StoredManagedServiceBinding::new(request)?;
        let _mutation = self.mutation.lock().await;
        if let Some(existing) = self.read_bindings().get(&candidate.binding_id).cloned() {
            if existing.request_digest != candidate.request_digest
                || existing.request.idempotency_key() != candidate.request.idempotency_key()
            {
                return Err(store_error(
                    "Managed Service idempotency key was replayed with a different exact binding identity"
                        .to_string(),
                ));
            }
            if !existing.phase.is_routable() {
                return Err(store_error(
                    "Managed Service binding is already retiring and cannot be rebound".to_string(),
                ));
            }
            return Ok((existing, true));
        }

        let mut next = self.read_bindings().clone();
        if next.len() >= MAX_BINDINGS {
            return Err(store_error(format!(
                "Managed Service state is limited to {MAX_BINDINGS} bindings"
            )));
        }
        next.insert(candidate.binding_id.clone(), candidate.clone());
        validate_effective(base, &next)?;
        self.persist_and_replace(next).await?;
        Ok((candidate, false))
    }

    pub(crate) async fn mark_ready(
        &self,
        identity: &ManagedServiceBindingIdentity,
    ) -> Result<StoredManagedServiceBinding> {
        self.update_exact(identity, |binding| {
            if !binding.phase.is_routable() {
                return Err(store_error(
                    "Managed Service binding became non-routable before readiness commit"
                        .to_string(),
                ));
            }
            binding.phase = ManagedServicePhase::Ready;
            binding.drain_operation_key = None;
            Ok(())
        })
        .await
    }

    pub(crate) async fn begin_drain(
        &self,
        identity: &ManagedServiceBindingIdentity,
        operation_key: &str,
    ) -> Result<StoredManagedServiceBinding> {
        validate_operation_key(operation_key)?;
        self.update_exact(identity, |binding| {
            match binding.phase {
                ManagedServicePhase::Binding | ManagedServicePhase::Ready => {
                    binding.phase = ManagedServicePhase::Draining;
                    binding.drain_operation_key = Some(operation_key.to_string());
                }
                ManagedServicePhase::Draining | ManagedServicePhase::Drained
                    if binding.drain_operation_key.as_deref() == Some(operation_key) => {}
                ManagedServicePhase::Draining | ManagedServicePhase::Drained => {
                    return Err(store_error(
                        "Managed Service drain operation key was replayed with a different identity"
                            .to_string(),
                    ));
                }
            }
            Ok(())
        })
        .await
    }

    pub(crate) async fn finish_drain(
        &self,
        identity: &ManagedServiceBindingIdentity,
    ) -> Result<StoredManagedServiceBinding> {
        self.update_exact(identity, |binding| {
            if binding.phase != ManagedServicePhase::Draining
                && binding.phase != ManagedServicePhase::Drained
            {
                return Err(store_error(
                    "Managed Service drain completion requires hidden route state".to_string(),
                ));
            }
            binding.phase = ManagedServicePhase::Drained;
            Ok(())
        })
        .await
    }

    pub(crate) async fn remove(
        &self,
        identity: &ManagedServiceBindingIdentity,
        operation_key: &str,
    ) -> Result<()> {
        validate_operation_key(operation_key)?;
        let binding_id = identity.binding_id()?.to_string();
        let _mutation = self.mutation.lock().await;
        let Some(existing) = self.read_bindings().get(&binding_id).cloned() else {
            return Ok(());
        };
        ensure_exact(&existing, identity)?;
        if existing.phase != ManagedServicePhase::Drained {
            return Err(store_error(
                "Managed Service removal requires the exact binding to be drained first"
                    .to_string(),
            ));
        }
        let mut next = self.read_bindings().clone();
        next.remove(&binding_id);
        self.persist_and_replace(next).await
    }

    pub(crate) fn status(
        &self,
        identity: &ManagedServiceBindingIdentity,
    ) -> Result<Option<ManagedServiceStatus>> {
        let binding_id = identity.binding_id()?;
        let Some(binding) = self.read_bindings().get(binding_id).cloned() else {
            return Ok(None);
        };
        ensure_exact(&binding, identity)?;
        Ok(Some(status(&binding)))
    }

    async fn update_exact(
        &self,
        identity: &ManagedServiceBindingIdentity,
        update: impl FnOnce(&mut StoredManagedServiceBinding) -> Result<()>,
    ) -> Result<StoredManagedServiceBinding> {
        let binding_id = identity.binding_id()?.to_string();
        let _mutation = self.mutation.lock().await;
        let mut next = self.read_bindings().clone();
        let binding = next
            .get_mut(&binding_id)
            .ok_or_else(|| store_error("Managed Service binding does not exist".to_string()))?;
        ensure_exact(binding, identity)?;
        update(binding)?;
        binding.validate()?;
        let updated = binding.clone();
        self.persist_and_replace(next).await?;
        Ok(updated)
    }

    async fn persist_and_replace(
        &self,
        next: BTreeMap<String, StoredManagedServiceBinding>,
    ) -> Result<()> {
        persistence::write(&self.path, next.values().cloned().collect()).await?;
        *self.write_bindings() = next;
        Ok(())
    }

    fn read_bindings(&self) -> RwLockReadGuard<'_, BTreeMap<String, StoredManagedServiceBinding>> {
        self.bindings
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn write_bindings(
        &self,
    ) -> RwLockWriteGuard<'_, BTreeMap<String, StoredManagedServiceBinding>> {
        self.bindings
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn validate_effective(
    base: &GatewayConfig,
    bindings: &BTreeMap<String, StoredManagedServiceBinding>,
) -> Result<()> {
    let mut config = base.clone();
    apply_overlay(&mut config, bindings.values().cloned())
}

fn ensure_exact(
    binding: &StoredManagedServiceBinding,
    identity: &ManagedServiceBindingIdentity,
) -> Result<()> {
    if binding.identity() != *identity {
        return Err(store_error(
            "Managed Service receipt does not own this exact generation".to_string(),
        ));
    }
    Ok(())
}

fn store_error(message: String) -> GatewayError {
    GatewayError::Other(message)
}
