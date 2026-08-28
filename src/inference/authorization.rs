//! Snapshot-backed inference-key authentication and grant authorization.

use super::access_error::InferenceAccessError;
use super::limits::{InferenceGrantAdmissionGuard, InferenceGrantIdentity, InferenceLimitStore};
use super::scheduling::{
    has_eligible_worker, select_worker, select_worker_pair, InferencePoolAdmissionGuard,
    InferencePoolIdentity, InferenceScheduler, InferenceWorkerPairSelection,
    InferenceWorkerPairSelectionRequest, InferenceWorkerSelection, InferenceWorkerSelectionRequest,
};
use super::{InferenceRequestIdentity, InferenceWorkerCandidate, OpenAiRequestProfile};
use crate::config::{
    InferenceConfig, InferenceCredentialConfig, InferenceDistributedServingConfig,
    InferenceEndpoint, InferenceGrantConfig, InferenceModelConfig, InferenceRouteConfig,
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use http::header::AUTHORIZATION;
use http::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::Semaphore;
use uuid::Uuid;

const MAX_INFERENCE_KEY_BYTES: usize = 512;
const MAX_PARALLEL_ARGON2_VERIFICATIONS: usize = 2;

#[cfg(test)]
#[derive(Clone)]
struct VerificationCompletionGate {
    completed: std::sync::mpsc::Sender<()>,
    release: Arc<std::sync::Barrier>,
}

/// Runtime view of one complete inference authorization snapshot.
///
/// The authorizer owns no plaintext credentials. Successful verification is
/// cached by a SHA-256 digest for the lifetime of this exact runtime snapshot;
/// reload replaces the authorizer and therefore invalidates the cache.
pub(crate) struct InferenceAuthorizer {
    policy: InferenceConfig,
    routes_by_router: HashMap<String, Uuid>,
    credentials_by_prefix: HashMap<String, Uuid>,
    prefix_lengths: Vec<usize>,
    verified: Mutex<HashMap<[u8; 32], CachedCredential>>,
    verification_permits: Arc<Semaphore>,
    #[cfg(test)]
    verification_completion_gate: Option<VerificationCompletionGate>,
    target_counters: Mutex<HashMap<TargetCounterKey, u64>>,
    limits: InferenceLimitStore,
    scheduler: InferenceScheduler,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CachedCredential {
    credential_id: Uuid,
    generation: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct TargetCounterKey {
    route_id: Uuid,
    model_id: Uuid,
    priority: u32,
}

/// Authenticated route and credential identity retained for grant checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedInference {
    route_id: Uuid,
    environment_id: Uuid,
    credential_id: Uuid,
    credential_generation: u64,
}

/// Drop guard retaining both credential-grant and model-pool admission.
pub(crate) struct InferenceAdmissionGuard {
    _grant: InferenceGrantAdmissionGuard,
    _pool: Option<InferencePoolAdmissionGuard>,
}

impl AuthenticatedInference {
    pub(crate) fn environment_id(self) -> Uuid {
        self.environment_id
    }

    pub(crate) fn credential_id(self) -> Uuid {
        self.credential_id
    }

    pub(crate) fn credential_generation(self) -> u64 {
        self.credential_generation
    }
}

/// One authorized model target selected from the active snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferenceDispatchTarget {
    pub(crate) model_id: Uuid,
    pub(crate) target_id: Uuid,
    pub(crate) priority: u32,
    pub(crate) service: String,
    pub(crate) upstream_model: String,
}

impl InferenceAuthorizer {
    #[cfg(test)]
    pub(crate) fn new(policy: &InferenceConfig) -> Self {
        Self::with_previous(policy, None)
    }

    /// Build a new exact-snapshot authorizer while retaining counters for
    /// unchanged immutable grant identities.
    pub(crate) fn with_previous(policy: &InferenceConfig, previous: Option<&Self>) -> Self {
        let routes_by_router = policy
            .routes
            .values()
            .map(|route| (route.router.clone(), route.route_id))
            .collect();
        let credentials_by_prefix = policy
            .credentials
            .values()
            .map(|credential| (credential.prefix.clone(), credential.credential_id))
            .collect::<HashMap<_, _>>();
        let mut prefix_lengths = credentials_by_prefix
            .keys()
            .map(String::len)
            .collect::<Vec<_>>();
        prefix_lengths.sort_unstable();
        prefix_lengths.dedup();
        prefix_lengths.reverse();

        Self {
            policy: policy.clone(),
            routes_by_router,
            credentials_by_prefix,
            prefix_lengths,
            verified: Mutex::new(HashMap::new()),
            verification_permits: Arc::new(Semaphore::new(MAX_PARALLEL_ARGON2_VERIFICATIONS)),
            #[cfg(test)]
            verification_completion_gate: None,
            target_counters: Mutex::new(HashMap::new()),
            limits: InferenceLimitStore::new(policy, previous.map(|previous| &previous.limits)),
            scheduler: InferenceScheduler::new(
                policy,
                previous.map(|previous| &previous.scheduler),
            ),
        }
    }

    /// Whether this exact router is owned by the native inference policy.
    pub(crate) fn owns_router(&self, router: &str) -> bool {
        self.routes_by_router.contains_key(router)
    }

    /// Create one Gateway-owned identity after endpoint authorization.
    pub(crate) fn request_identity(
        &self,
        authenticated: AuthenticatedInference,
        profile: OpenAiRequestProfile,
        correlation_id: String,
        now: DateTime<Utc>,
    ) -> Result<InferenceRequestIdentity, InferenceAccessError> {
        let (route, grant) = self.grant(authenticated, now)?;
        let endpoint = endpoint(profile);
        if !grant.endpoints.contains(&endpoint) {
            return Err(InferenceAccessError::Denied);
        }
        Ok(InferenceRequestIdentity::new(
            correlation_id,
            route.route_id,
            route.policy_revision,
            endpoint,
        ))
    }

    /// Authenticate an inference key and enforce its route and endpoint grant.
    pub(crate) async fn authenticate(
        &self,
        router: &str,
        profile: OpenAiRequestProfile,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedInference, InferenceAccessError> {
        if self.policy.expires_at <= now {
            return Err(InferenceAccessError::Unavailable);
        }
        let route = self.route(router)?;
        let token = bearer_token(headers)?;
        let credential = self.credential_for_token(token)?;
        if credential.revoked || credential.expires_at <= now {
            return Err(InferenceAccessError::Unauthorized);
        }

        self.verify_token(token, credential).await?;
        let verified_at = Utc::now();
        if self.policy.expires_at <= verified_at {
            return Err(InferenceAccessError::Unavailable);
        }
        if credential.revoked || credential.expires_at <= verified_at {
            return Err(InferenceAccessError::Unauthorized);
        }
        let grant = route
            .grants
            .get(&credential.credential_id)
            .ok_or(InferenceAccessError::Denied)?;
        if credential.environment_id != route.environment_id
            || grant.credential_generation != credential.generation
            || !grant.endpoints.contains(&endpoint(profile))
        {
            return Err(InferenceAccessError::Denied);
        }

        Ok(AuthenticatedInference {
            route_id: route.route_id,
            environment_id: route.environment_id,
            credential_id: credential.credential_id,
            credential_generation: credential.generation,
        })
    }

    /// Return the deterministic model aliases visible to one credential.
    pub(crate) fn allowed_models(
        &self,
        authenticated: AuthenticatedInference,
        now: DateTime<Utc>,
    ) -> Result<Vec<String>, InferenceAccessError> {
        let (route, grant) = self.grant(authenticated, now)?;
        let mut models = grant
            .models
            .iter()
            .filter(|alias| route.models.contains_key(alias.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        models.sort_unstable();
        models.dedup();
        Ok(models)
    }

    /// Admit one granted endpoint request against its local RPM and
    /// concurrency limits.
    pub(crate) fn admit_request(
        &self,
        authenticated: AuthenticatedInference,
        now: DateTime<Utc>,
    ) -> Result<InferenceAdmissionGuard, InferenceAccessError> {
        let grant = self.admit_grant_request(authenticated, now)?;
        Ok(InferenceAdmissionGuard {
            _grant: grant,
            _pool: None,
        })
    }

    fn admit_grant_request(
        &self,
        authenticated: AuthenticatedInference,
        now: DateTime<Utc>,
    ) -> Result<InferenceGrantAdmissionGuard, InferenceAccessError> {
        let (route, grant) = self.grant(authenticated, now)?;
        self.limits.try_admit(InferenceGrantIdentity {
            route_id: route.route_id,
            policy_revision: route.policy_revision,
            credential_id: authenticated.credential_id,
            credential_generation: grant.credential_generation,
        })
    }

    /// Enforce a model grant before charging and admitting an invocation.
    pub(crate) async fn admit_model(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
    ) -> Result<InferenceAdmissionGuard, InferenceAccessError> {
        let (route, model) = self.granted_model(authenticated, alias, now)?;
        let pool = self
            .scheduler
            .admit(InferencePoolIdentity {
                route_id: route.route_id,
                model_id: model.model_id,
            })
            .await?;
        let grant = self.admit_grant_request(authenticated, Utc::now())?;
        Ok(InferenceAdmissionGuard {
            _grant: grant,
            _pool: pool,
        })
    }

    pub(crate) fn model_uses_worker_scheduling(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
    ) -> Result<bool, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, now)?;
        Ok(model.scheduling.is_some())
    }

    pub(crate) fn distributed_serving_config(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<InferenceDistributedServingConfig>, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, now)?;
        Ok(model
            .scheduling
            .as_ref()
            .and_then(|scheduling| scheduling.distributed_serving.clone()))
    }

    pub(crate) fn has_eligible_worker(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        target_id: Uuid,
        candidates: &[InferenceWorkerCandidate<'_>],
        now: DateTime<Utc>,
    ) -> Result<bool, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, now)?;
        let Some(scheduling) = &model.scheduling else {
            return Ok(false);
        };
        Ok(has_eligible_worker(
            &self.policy.workers,
            scheduling,
            target_id,
            candidates,
            now,
        ))
    }

    pub(crate) fn has_eligible_worker_pair(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        target_id: Uuid,
        candidates: &[InferenceWorkerCandidate<'_>],
        now: DateTime<Utc>,
        routing_key: &[u8],
    ) -> Result<bool, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, now)?;
        let Some(scheduling) = &model.scheduling else {
            return Ok(false);
        };
        Ok(select_worker_pair(
            &self.policy.workers,
            scheduling,
            target_id,
            candidates,
            now,
            routing_key,
            None,
        )
        .is_some())
    }

    pub(crate) fn select_worker(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        request: InferenceWorkerSelectionRequest<'_, '_>,
    ) -> Result<InferenceWorkerSelection, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, request.now)?;
        let scheduling = model
            .scheduling
            .as_ref()
            .ok_or(InferenceAccessError::Unavailable)?;
        select_worker(
            &self.policy.workers,
            scheduling,
            request.target_id,
            request.candidates,
            request.now,
            request.routing_key,
            request.cache_affinity_key,
        )
        .ok_or(InferenceAccessError::Unavailable)
    }

    pub(crate) fn select_worker_pair(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        request: InferenceWorkerPairSelectionRequest<'_, '_>,
    ) -> Result<InferenceWorkerPairSelection, InferenceAccessError> {
        let (_, model) = self.granted_model(authenticated, alias, request.now)?;
        let scheduling = model
            .scheduling
            .as_ref()
            .ok_or(InferenceAccessError::Unavailable)?;
        select_worker_pair(
            &self.policy.workers,
            scheduling,
            request.target_id,
            request.candidates,
            request.now,
            request.routing_key,
            request.cache_affinity_key,
        )
        .ok_or(InferenceAccessError::Unavailable)
    }

    /// Select one available target at or after the requested priority.
    ///
    /// A caller advances `minimum_priority` only after a concrete upstream
    /// attempt fails before any client response. Targets in the failed
    /// priority group are therefore never retried implicitly.
    pub(crate) fn select_target_from_priority<F>(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        minimum_priority: u32,
        now: DateTime<Utc>,
        mut service_is_available: F,
    ) -> Result<InferenceDispatchTarget, InferenceAccessError>
    where
        F: FnMut(&str, Uuid) -> bool,
    {
        let (route, model) = self.granted_model(authenticated, alias, now)?;

        let mut offset = 0;
        while offset < model.targets.len() {
            let priority = model.targets[offset].priority;
            let end = model.targets[offset..]
                .iter()
                .position(|target| target.priority != priority)
                .map_or(model.targets.len(), |relative| offset + relative);
            if priority < minimum_priority {
                offset = end;
                continue;
            }
            let available = model.targets[offset..end]
                .iter()
                .filter(|target| service_is_available(&target.service, target.target_id))
                .collect::<Vec<_>>();
            if !available.is_empty() {
                let total_weight = available
                    .iter()
                    .map(|target| u64::from(target.weight))
                    .sum::<u64>();
                if total_weight == 0 {
                    return Err(InferenceAccessError::Unavailable);
                }
                let key = TargetCounterKey {
                    route_id: route.route_id,
                    model_id: model.model_id,
                    priority,
                };
                let selected_weight = {
                    let mut counters = self
                        .target_counters
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    let counter = counters.entry(key).or_default();
                    let selected = *counter % total_weight;
                    *counter = counter.wrapping_add(1);
                    selected
                };
                let mut cumulative = 0_u64;
                for target in available {
                    cumulative += u64::from(target.weight);
                    if selected_weight < cumulative {
                        return Ok(InferenceDispatchTarget {
                            model_id: model.model_id,
                            target_id: target.target_id,
                            priority,
                            service: target.service.clone(),
                            upstream_model: target.upstream_model.clone(),
                        });
                    }
                }
                return Err(InferenceAccessError::Unavailable);
            }
            offset = end;
        }

        Err(InferenceAccessError::Unavailable)
    }

    fn granted_model(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
    ) -> Result<(&InferenceRouteConfig, &InferenceModelConfig), InferenceAccessError> {
        let (route, grant) = self.grant(authenticated, now)?;
        if !grant.models.iter().any(|model| model == alias) {
            return Err(InferenceAccessError::Denied);
        }
        let model = route
            .models
            .get(alias)
            .ok_or(InferenceAccessError::Denied)?;
        Ok((route, model))
    }

    fn route(&self, router: &str) -> Result<&InferenceRouteConfig, InferenceAccessError> {
        let route_id = self
            .routes_by_router
            .get(router)
            .ok_or(InferenceAccessError::Unavailable)?;
        self.policy
            .routes
            .get(route_id)
            .ok_or(InferenceAccessError::Unavailable)
    }

    fn grant(
        &self,
        authenticated: AuthenticatedInference,
        now: DateTime<Utc>,
    ) -> Result<(&InferenceRouteConfig, &InferenceGrantConfig), InferenceAccessError> {
        if self.policy.expires_at <= now {
            return Err(InferenceAccessError::Unavailable);
        }
        let route = self
            .policy
            .routes
            .get(&authenticated.route_id)
            .ok_or(InferenceAccessError::Unavailable)?;
        let credential = self
            .policy
            .credentials
            .get(&authenticated.credential_id)
            .ok_or(InferenceAccessError::Unavailable)?;
        let grant = route
            .grants
            .get(&authenticated.credential_id)
            .ok_or(InferenceAccessError::Denied)?;
        if credential.revoked || credential.expires_at <= now {
            return Err(InferenceAccessError::Unauthorized);
        }
        if credential.environment_id != route.environment_id
            || credential.generation != authenticated.credential_generation
            || grant.credential_generation != authenticated.credential_generation
        {
            return Err(InferenceAccessError::Denied);
        }
        Ok((route, grant))
    }

    fn credential_for_token(
        &self,
        token: &str,
    ) -> Result<&InferenceCredentialConfig, InferenceAccessError> {
        if !valid_inference_key(token) {
            return Err(InferenceAccessError::Unauthorized);
        }
        for length in &self.prefix_lengths {
            if token.len() <= *length {
                continue;
            }
            let Some(prefix) = token.get(..*length) else {
                return Err(InferenceAccessError::Unauthorized);
            };
            let Some(credential_id) = self.credentials_by_prefix.get(prefix) else {
                continue;
            };
            return self
                .policy
                .credentials
                .get(credential_id)
                .ok_or(InferenceAccessError::Unavailable);
        }
        Err(InferenceAccessError::Unauthorized)
    }

    async fn verify_token(
        &self,
        token: &str,
        credential: &InferenceCredentialConfig,
    ) -> Result<(), InferenceAccessError> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        {
            let cache = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
            if cache.get(&digest)
                == Some(&CachedCredential {
                    credential_id: credential.credential_id,
                    generation: credential.generation,
                })
            {
                return Ok(());
            }
        }

        let permit = self
            .verification_permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| InferenceAccessError::Unavailable)?;
        #[cfg(test)]
        let completion_gate = self.verification_completion_gate.clone();
        let candidate = token.to_owned();
        let verifier_hash = credential.verifier_hash().to_owned();
        let verified = tokio::task::spawn_blocking(move || {
            // Blocking tasks cannot be canceled after they start. Keep the
            // permit here so a disconnected caller cannot release capacity
            // while its Argon2 work is still consuming memory.
            let _permit = permit;
            let parsed =
                PasswordHash::new(&verifier_hash).map_err(|_| InferenceAccessError::Unavailable)?;
            let verified = Argon2::default()
                .verify_password(candidate.as_bytes(), &parsed)
                .is_ok();
            #[cfg(test)]
            if let Some(gate) = completion_gate {
                gate.completed
                    .send(())
                    .map_err(|_| InferenceAccessError::Unavailable)?;
                gate.release.wait();
            }
            Ok::<_, InferenceAccessError>(verified)
        })
        .await
        .map_err(|_| InferenceAccessError::Unavailable)??;
        if !verified {
            return Err(InferenceAccessError::Unauthorized);
        }

        let mut cache = self.verified.lock().unwrap_or_else(PoisonError::into_inner);
        if cache.len() < self.policy.credentials.len() {
            cache.insert(
                digest,
                CachedCredential {
                    credential_id: credential.credential_id,
                    generation: credential.generation,
                },
            );
        }
        Ok(())
    }
}

fn endpoint(profile: OpenAiRequestProfile) -> InferenceEndpoint {
    match profile {
        OpenAiRequestProfile::Models => InferenceEndpoint::Models,
        OpenAiRequestProfile::ChatCompletions => InferenceEndpoint::ChatCompletions,
        OpenAiRequestProfile::Completions => InferenceEndpoint::Completions,
        OpenAiRequestProfile::Embeddings => InferenceEndpoint::Embeddings,
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, InferenceAccessError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(InferenceAccessError::Unauthorized)?;
    if values.next().is_some() {
        return Err(InferenceAccessError::Unauthorized);
    }
    let value = value
        .to_str()
        .map_err(|_| InferenceAccessError::Unauthorized)?;
    let (scheme, token) = value
        .split_once(' ')
        .ok_or(InferenceAccessError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(InferenceAccessError::Unauthorized);
    }
    Ok(token)
}

fn valid_inference_key(token: &str) -> bool {
    token.len() <= MAX_INFERENCE_KEY_BYTES
        && token.starts_with("a3s_inf_")
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}
#[cfg(test)]
#[path = "authorization_tests.rs"]
mod tests;
