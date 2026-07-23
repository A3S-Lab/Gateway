//! Snapshot-backed inference-key authentication and grant authorization.

use super::access_error::InferenceAccessError;
use super::limits::{InferenceGrantIdentity, InferenceLimitStore};
use super::{InferenceAdmissionGuard, OpenAiRequestProfile};
use crate::config::{
    InferenceConfig, InferenceCredentialConfig, InferenceEndpoint, InferenceGrantConfig,
    InferenceModelConfig, InferenceRouteConfig,
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
    target_counters: Mutex<HashMap<TargetCounterKey, u64>>,
    limits: InferenceLimitStore,
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
    credential_id: Uuid,
    credential_generation: u64,
}

/// One authorized model target selected from the active snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InferenceDispatchTarget {
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
            target_counters: Mutex::new(HashMap::new()),
            limits: InferenceLimitStore::new(policy, previous.map(|previous| &previous.limits)),
        }
    }

    /// Whether this exact router is owned by the native inference policy.
    pub(crate) fn owns_router(&self, router: &str) -> bool {
        self.routes_by_router.contains_key(router)
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
        let (route, grant) = self.grant(authenticated, now)?;
        self.limits.try_admit(InferenceGrantIdentity {
            route_id: route.route_id,
            policy_revision: route.policy_revision,
            credential_id: authenticated.credential_id,
            credential_generation: grant.credential_generation,
        })
    }

    /// Enforce a model grant before charging and admitting an invocation.
    pub(crate) fn admit_model(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
    ) -> Result<InferenceAdmissionGuard, InferenceAccessError> {
        self.granted_model(authenticated, alias, now)?;
        self.admit_request(authenticated, now)
    }

    /// Select one available target from the first non-empty priority group.
    pub(crate) fn select_target<F>(
        &self,
        authenticated: AuthenticatedInference,
        alias: &str,
        now: DateTime<Utc>,
        mut service_is_available: F,
    ) -> Result<InferenceDispatchTarget, InferenceAccessError>
    where
        F: FnMut(&str) -> bool,
    {
        let (route, model) = self.granted_model(authenticated, alias, now)?;

        let mut offset = 0;
        while offset < model.targets.len() {
            let priority = model.targets[offset].priority;
            let end = model.targets[offset..]
                .iter()
                .position(|target| target.priority != priority)
                .map_or(model.targets.len(), |relative| offset + relative);
            let available = model.targets[offset..end]
                .iter()
                .filter(|target| service_is_available(&target.service))
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
        let candidate = token.to_owned();
        let verifier_hash = credential.verifier_hash().to_owned();
        let verified = tokio::task::spawn_blocking(move || {
            // Blocking tasks cannot be canceled after they start. Keep the
            // permit here so a disconnected caller cannot release capacity
            // while its Argon2 work is still consuming memory.
            let _permit = permit;
            let parsed =
                PasswordHash::new(&verifier_hash).map_err(|_| InferenceAccessError::Unavailable)?;
            Ok::<_, InferenceAccessError>(
                Argon2::default()
                    .verify_password(candidate.as_bytes(), &parsed)
                    .is_ok(),
            )
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
mod tests {
    use super::*;
    use crate::config::{
        InferenceGrantConfig, InferenceLimitsConfig, InferenceModelConfig, InferenceTargetConfig,
    };
    use argon2::password_hash::{PasswordHasher, SaltString};
    use http::header::CONTENT_TYPE;
    use http::StatusCode;
    use std::collections::HashMap;

    const PREFIX: &str = "a3s_inf_abc12345";

    fn key(character: char) -> String {
        format!("{PREFIX}{}", character.to_string().repeat(64))
    }

    fn verifier(secret: &str) -> String {
        let salt = SaltString::encode_b64(b"a3s-gateway-test").unwrap();
        Argon2::default()
            .hash_password(secret.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn policy(secret: &str) -> (InferenceConfig, Uuid, Uuid) {
        let credential_id = Uuid::new_v4();
        let environment_id = Uuid::new_v4();
        let route_id = Uuid::new_v4();
        let credential = InferenceCredentialConfig {
            credential_id,
            environment_id,
            audience: "cloud-inference".into(),
            prefix: PREFIX.into(),
            verifier_hash: verifier(secret),
            generation: 4,
            expires_at: Utc::now() + chrono::Duration::hours(1),
            revoked: false,
        };
        let grant = InferenceGrantConfig {
            credential_generation: 4,
            models: vec!["beta".into(), "alpha".into()],
            endpoints: vec![
                InferenceEndpoint::Models,
                InferenceEndpoint::ChatCompletions,
            ],
            limits: InferenceLimitsConfig {
                max_concurrent_requests: 2,
                requests_per_minute: 60,
                request_burst: 2,
                tokens_per_minute: 10_000,
            },
        };
        let models = ["alpha", "beta"]
            .into_iter()
            .map(|alias| {
                (
                    alias.to_string(),
                    InferenceModelConfig {
                        model_id: Uuid::new_v4(),
                        targets: vec![InferenceTargetConfig {
                            target_id: Uuid::new_v4(),
                            service: "model".into(),
                            upstream_model: alias.into(),
                            priority: 0,
                            weight: 1,
                        }],
                    },
                )
            })
            .collect();
        let route = InferenceRouteConfig {
            route_id,
            router: "inference".into(),
            environment_id,
            policy_revision: 9,
            models,
            grants: HashMap::from([(credential_id, grant)]),
        };
        (
            InferenceConfig {
                expires_at: Utc::now() + chrono::Duration::hours(1),
                credentials: HashMap::from([(credential_id, credential)]),
                routes: HashMap::from([(route_id, route)]),
            },
            credential_id,
            route_id,
        )
    }

    fn bearer(secret: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {secret}").parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn authenticates_and_enforces_endpoint_and_model_grants() {
        let secret = key('a');
        let (policy, credential_id, route_id) = policy(&secret);
        let authorizer = InferenceAuthorizer::new(&policy);
        let authenticated = authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::ChatCompletions,
                &bearer(&secret),
                Utc::now(),
            )
            .await
            .unwrap();

        assert_eq!(authenticated.credential_id, credential_id);
        assert_eq!(authenticated.route_id, route_id);
        assert!(authorizer
            .select_target(authenticated, "alpha", Utc::now(), |_| true)
            .is_ok());
        assert_eq!(
            authorizer
                .allowed_models(authenticated, Utc::now())
                .unwrap(),
            vec!["alpha", "beta"]
        );
        assert_eq!(
            authorizer.select_target(authenticated, "gamma", Utc::now(), |_| true),
            Err(InferenceAccessError::Denied)
        );
        assert_eq!(
            authorizer.allowed_models(authenticated, policy.expires_at),
            Err(InferenceAccessError::Unavailable)
        );
        assert_eq!(
            authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Embeddings,
                    &bearer(&secret),
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Denied)
        );
    }

    #[tokio::test]
    async fn selects_weighted_targets_then_falls_back_by_priority() {
        let secret = key('a');
        let (mut policy, _, route_id) = policy(&secret);
        policy
            .routes
            .get_mut(&route_id)
            .unwrap()
            .models
            .get_mut("alpha")
            .unwrap()
            .targets = vec![
            InferenceTargetConfig {
                target_id: Uuid::new_v4(),
                service: "primary-a".into(),
                upstream_model: "internal-a".into(),
                priority: 0,
                weight: 1,
            },
            InferenceTargetConfig {
                target_id: Uuid::new_v4(),
                service: "primary-b".into(),
                upstream_model: "internal-b".into(),
                priority: 0,
                weight: 3,
            },
            InferenceTargetConfig {
                target_id: Uuid::new_v4(),
                service: "fallback".into(),
                upstream_model: "internal-fallback".into(),
                priority: 1,
                weight: 1,
            },
        ];
        let authorizer = InferenceAuthorizer::new(&policy);
        let authenticated = authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::ChatCompletions,
                &bearer(&secret),
                Utc::now(),
            )
            .await
            .unwrap();

        let selected = (0..4)
            .map(|_| {
                authorizer
                    .select_target(authenticated, "alpha", Utc::now(), |_| true)
                    .unwrap()
                    .service
            })
            .collect::<Vec<_>>();
        assert_eq!(
            selected,
            vec!["primary-a", "primary-b", "primary-b", "primary-b"]
        );

        let fallback = authorizer
            .select_target(authenticated, "alpha", Utc::now(), |service| {
                service == "fallback"
            })
            .unwrap();
        assert_eq!(fallback.service, "fallback");
        assert_eq!(fallback.upstream_model, "internal-fallback");
        assert_eq!(
            authorizer.select_target(authenticated, "alpha", Utc::now(), |_| false),
            Err(InferenceAccessError::Unavailable)
        );
    }

    #[tokio::test]
    async fn rejects_zero_weight_runtime_state_without_panicking() {
        let secret = key('a');
        let (mut policy, _, route_id) = policy(&secret);
        policy
            .routes
            .get_mut(&route_id)
            .unwrap()
            .models
            .get_mut("alpha")
            .unwrap()
            .targets[0]
            .weight = 0;
        let authorizer = InferenceAuthorizer::new(&policy);
        let authenticated = authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::ChatCompletions,
                &bearer(&secret),
                Utc::now(),
            )
            .await
            .unwrap();

        assert_eq!(
            authorizer.select_target(authenticated, "alpha", Utc::now(), |_| true),
            Err(InferenceAccessError::Unavailable)
        );
    }

    #[tokio::test]
    async fn rejects_missing_malformed_unknown_and_wrong_credentials() {
        let secret = key('a');
        let (policy, _, _) = policy(&secret);
        let authorizer = InferenceAuthorizer::new(&policy);
        let mut duplicate = bearer(&secret);
        duplicate.append(AUTHORIZATION, "Bearer duplicate".parse().unwrap());

        for headers in [
            HeaderMap::new(),
            HeaderMap::from_iter([(AUTHORIZATION, "Basic abc".parse().unwrap())]),
            HeaderMap::from_iter([(
                AUTHORIZATION,
                format!("Bearer a3s_inf_unknown{}", "x".repeat(64))
                    .parse()
                    .unwrap(),
            )]),
            bearer(&key('b')),
            duplicate,
        ] {
            assert_eq!(
                authorizer
                    .authenticate(
                        "inference",
                        OpenAiRequestProfile::ChatCompletions,
                        &headers,
                        Utc::now(),
                    )
                    .await,
                Err(InferenceAccessError::Unauthorized)
            );
        }
        assert_eq!(
            authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Embeddings,
                    &bearer(&key('b')),
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Unauthorized)
        );
    }

    #[tokio::test]
    async fn bounds_parallel_argon2_verification() {
        let secret = key('a');
        let (policy, _, _) = policy(&secret);
        let authorizer = InferenceAuthorizer::new(&policy);
        let first = bearer(&key('b'));
        let second = bearer(&key('c'));
        let third = bearer(&key('d'));

        let (first, second, third) = tokio::join!(
            authorizer.authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &first,
                Utc::now(),
            ),
            authorizer.authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &second,
                Utc::now(),
            ),
            authorizer.authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &third,
                Utc::now(),
            ),
        );
        let results = [first, second, third];

        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(InferenceAccessError::Unauthorized))
                .count(),
            MAX_PARALLEL_ARGON2_VERIFICATIONS
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(InferenceAccessError::Unavailable))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn canceled_callers_keep_argon2_permits_until_work_finishes() {
        let secret = key('a');
        let (policy, _, _) = policy(&secret);
        let authorizer = Arc::new(InferenceAuthorizer::new(&policy));

        let first_authorizer = authorizer.clone();
        let first = tokio::spawn(async move {
            first_authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Models,
                    &bearer(&key('b')),
                    Utc::now(),
                )
                .await
        });
        let second_authorizer = authorizer.clone();
        let second = tokio::spawn(async move {
            second_authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Models,
                    &bearer(&key('c')),
                    Utc::now(),
                )
                .await
        });

        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while authorizer.verification_permits.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        first.abort();
        second.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(second.await.unwrap_err().is_cancelled());

        assert_eq!(
            authorizer
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Models,
                    &bearer(&key('d')),
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Unavailable)
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while authorizer.verification_permits.available_permits()
                != MAX_PARALLEL_ARGON2_VERIFICATIONS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn policy_credential_and_revocation_expiry_fail_closed() {
        let secret = key('a');
        let (mut expired_policy, _, _) = policy(&secret);
        expired_policy.expires_at = Utc::now() - chrono::Duration::seconds(1);
        assert_eq!(
            InferenceAuthorizer::new(&expired_policy)
                .authenticate(
                    "inference",
                    OpenAiRequestProfile::Models,
                    &bearer(&secret),
                    Utc::now(),
                )
                .await,
            Err(InferenceAccessError::Unavailable)
        );

        for revoked in [false, true] {
            let (mut policy, credential_id, _) = policy(&secret);
            let credential = policy.credentials.get_mut(&credential_id).unwrap();
            credential.revoked = revoked;
            if !revoked {
                credential.expires_at = Utc::now() - chrono::Duration::seconds(1);
            }
            assert_eq!(
                InferenceAuthorizer::new(&policy)
                    .authenticate(
                        "inference",
                        OpenAiRequestProfile::Models,
                        &bearer(&secret),
                        Utc::now(),
                    )
                    .await,
                Err(InferenceAccessError::Unauthorized)
            );
        }

        let (mut policy, credential_id, _) = policy(&secret);
        let expires_at = Utc::now() + chrono::Duration::minutes(1);
        policy
            .credentials
            .get_mut(&credential_id)
            .unwrap()
            .expires_at = expires_at;
        let authorizer = InferenceAuthorizer::new(&policy);
        let authenticated = authorizer
            .authenticate(
                "inference",
                OpenAiRequestProfile::Models,
                &bearer(&secret),
                Utc::now(),
            )
            .await
            .unwrap();
        assert_eq!(
            authorizer.allowed_models(authenticated, expires_at),
            Err(InferenceAccessError::Unauthorized)
        );
    }

    #[test]
    fn access_errors_are_stable_and_do_not_contain_credentials() {
        let secret = key('a');
        for (error, status) in [
            (InferenceAccessError::Unauthorized, StatusCode::UNAUTHORIZED),
            (InferenceAccessError::Denied, StatusCode::NOT_FOUND),
            (
                InferenceAccessError::Unavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                InferenceAccessError::RateLimited {
                    retry_after_secs: 17,
                },
                StatusCode::TOO_MANY_REQUESTS,
            ),
            (
                InferenceAccessError::ConcurrencyLimited,
                StatusCode::TOO_MANY_REQUESTS,
            ),
        ] {
            let response = error.into_response();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
            assert!(!response
                .body()
                .windows(secret.len())
                .any(|part| part == secret.as_bytes()));
        }

        let response = InferenceAccessError::RateLimited {
            retry_after_secs: 17,
        }
        .into_response();
        assert_eq!(response.headers()["retry-after"], "17");
        let response = InferenceAccessError::ConcurrencyLimited.into_response();
        assert_eq!(response.headers()["retry-after"], "1");
    }

    #[test]
    fn authorization_types_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        assert_send_sync::<InferenceAuthorizer>();
        assert_send_sync::<AuthenticatedInference>();
        assert_send_sync::<InferenceDispatchTarget>();
    }
}
