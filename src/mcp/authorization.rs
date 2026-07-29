//! Snapshot-backed hosted MCP authentication and grant authorization.

use super::limits::{McpGrantIdentity, McpLimitStore};
use super::{McpAccessError, McpAdmissionGuard};
use crate::config::{McpConfig, McpCredentialConfig, McpGrantConfig, McpRouteConfig};
use crate::service::{Backend, ServiceRegistry};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{DateTime, Utc};
use http::header::{AUTHORIZATION, COOKIE, ORIGIN, PROXY_AUTHORIZATION};
use http::HeaderMap;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::Semaphore;
use url::Url;
use uuid::Uuid;

const MAX_MCP_CREDENTIAL_BYTES: usize = 512;
const MAX_PARALLEL_ARGON2_VERIFICATIONS: usize = 2;

/// Immutable request bounds selected only from one applied route/profile pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct McpIngressPolicy {
    path: String,
    max_header_bytes: u64,
    max_request_bytes: u64,
    protocol_versions: Vec<String>,
}

impl McpIngressPolicy {
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    pub(crate) const fn max_header_bytes(&self) -> u64 {
        self.max_header_bytes
    }

    pub(crate) const fn max_request_bytes(&self) -> u64 {
        self.max_request_bytes
    }

    pub(crate) fn protocol_versions(&self) -> &[String] {
        &self.protocol_versions
    }
}

/// Authenticated route and credential identity retained for post-parse grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticatedMcp {
    route_id: Uuid,
    credential_id: Uuid,
    credential_generation: u64,
}

/// One exact Runtime target selected from the authenticated route snapshot.
#[derive(Debug, Clone)]
pub(crate) struct McpDispatchTarget {
    target_id: Uuid,
    service_name: String,
    backend: Arc<Backend>,
    first_response_timeout: Duration,
    stream_idle_timeout: Duration,
    stream_total_timeout: Duration,
    max_response_header_bytes: u64,
    max_response_bytes: u64,
    request_sse: bool,
}

impl McpDispatchTarget {
    pub(crate) const fn target_id(&self) -> Uuid {
        self.target_id
    }

    pub(crate) fn service_name(&self) -> &str {
        &self.service_name
    }

    pub(crate) fn backend(&self) -> &Arc<Backend> {
        &self.backend
    }

    pub(crate) const fn first_response_timeout(&self) -> Duration {
        self.first_response_timeout
    }

    pub(crate) const fn stream_idle_timeout(&self) -> Duration {
        self.stream_idle_timeout
    }

    pub(crate) const fn stream_total_timeout(&self) -> Duration {
        self.stream_total_timeout
    }

    pub(crate) const fn max_response_bytes(&self) -> u64 {
        self.max_response_bytes
    }

    pub(crate) const fn max_response_header_bytes(&self) -> u64 {
        self.max_response_header_bytes
    }

    pub(crate) const fn request_sse(&self) -> bool {
        self.request_sse
    }

    #[cfg(test)]
    pub(crate) fn test_target(request_sse: bool, max_response_bytes: u64) -> Self {
        Self {
            target_id: Uuid::nil(),
            service_name: "test".to_owned(),
            backend: Arc::new(Backend::new("http://127.0.0.1:1/".to_owned(), 1)),
            first_response_timeout: Duration::from_secs(1),
            stream_idle_timeout: Duration::from_secs(1),
            stream_total_timeout: Duration::from_secs(1),
            max_response_header_bytes: 128,
            max_response_bytes,
            request_sse,
        }
    }
}

/// Runtime view of one complete, expiring MCP authorization snapshot.
///
/// Plaintext credentials are never retained. Successful Argon2 verification
/// is cached only by SHA-256 token digest for this exact runtime snapshot.
pub(crate) struct McpAuthorizer {
    policy: McpConfig,
    routes_by_router: HashMap<String, Uuid>,
    credentials_by_prefix: HashMap<String, Uuid>,
    prefix_lengths: Vec<usize>,
    verified: Mutex<HashMap<[u8; 32], CachedCredential>>,
    verification_permits: Arc<Semaphore>,
    limits: McpLimitStore,
    selection_counters: HashMap<Uuid, Arc<AtomicU64>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct CachedCredential {
    credential_id: Uuid,
    generation: u64,
}

impl McpAuthorizer {
    #[cfg(test)]
    pub(crate) fn new(policy: &McpConfig) -> Self {
        Self::with_previous(policy, None)
    }

    /// Build a new exact-snapshot authorizer and retain only unchanged grant
    /// limiter state. Credential verification caches never cross snapshots.
    pub(crate) fn with_previous(policy: &McpConfig, previous: Option<&Self>) -> Self {
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
        let selection_counters = policy
            .routes
            .iter()
            .map(|(route_id, route)| {
                let counter = previous
                    .and_then(|previous| {
                        (previous.policy.routes.get(route_id) == Some(route))
                            .then(|| previous.selection_counters.get(route_id))
                            .flatten()
                    })
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
                (*route_id, counter)
            })
            .collect();

        Self {
            policy: policy.clone(),
            routes_by_router,
            credentials_by_prefix,
            prefix_lengths,
            verified: Mutex::new(HashMap::new()),
            verification_permits: Arc::new(Semaphore::new(MAX_PARALLEL_ARGON2_VERIFICATIONS)),
            limits: McpLimitStore::new(policy, previous.map(|previous| &previous.limits)),
            selection_counters,
        }
    }

    pub(crate) fn owns_router(&self, router: &str) -> bool {
        self.routes_by_router.contains_key(router)
    }

    /// Remove bearer/cookie material and unsigned caller identity before any
    /// later upstream dispatch. Gateway-owned request/attempt headers are
    /// attached only at the dispatch boundary.
    pub(crate) fn strip_ingress_credentials(headers: &mut HeaderMap) {
        for name in [
            AUTHORIZATION.as_str(),
            PROXY_AUTHORIZATION.as_str(),
            COOKIE.as_str(),
            "x-api-key",
            "x-forwarded-user",
            "x-auth-request-user",
            "x-auth-request-email",
            "x-a3s-user-id",
            "x-a3s-tenant-id",
            "x-a3s-project-id",
            "x-a3s-grant-id",
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-forwarded-port",
        ] {
            headers.remove(name);
        }
    }

    /// Select immutable ingress bounds and validate browser Origin before any
    /// credential verification or body work.
    pub(crate) fn ingress_policy(
        &self,
        router: &str,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Result<McpIngressPolicy, McpAccessError> {
        let route = self.route(router, now)?;
        validate_origin(headers, &route.allowed_origins)?;
        let profile = self
            .policy
            .profiles
            .get(&route.profile_digest)
            .ok_or(McpAccessError::Unavailable)?;
        Ok(McpIngressPolicy {
            path: profile.path.clone(),
            max_header_bytes: route.max_header_bytes,
            max_request_bytes: route.max_request_bytes,
            protocol_versions: profile.protocol_versions.clone(),
        })
    }

    /// Authenticate locally from the applied snapshot. This intentionally does
    /// not trust mirrored method/name headers and performs no body work.
    pub(crate) async fn authenticate(
        &self,
        router: &str,
        headers: &HeaderMap,
        now: DateTime<Utc>,
    ) -> Result<AuthenticatedMcp, McpAccessError> {
        let route = self.route(router, now)?;
        let token = bearer_token(headers)?;
        let credential = self.credential_for_token(token)?;
        if credential.revoked || credential.expires_at <= now {
            return Err(McpAccessError::Unauthorized);
        }

        self.verify_token(token, credential).await?;
        let verified_at = Utc::now();
        if self.policy.expires_at <= verified_at {
            return Err(McpAccessError::Unavailable);
        }
        if credential.revoked || credential.expires_at <= verified_at {
            return Err(McpAccessError::Unauthorized);
        }
        let grant = route
            .grants
            .get(&credential.credential_id)
            .ok_or(McpAccessError::Denied)?;
        if credential.environment_id != route.environment_id
            || grant.credential_generation != credential.generation
        {
            return Err(McpAccessError::Denied);
        }

        Ok(AuthenticatedMcp {
            route_id: route.route_id,
            credential_id: credential.credential_id,
            credential_generation: credential.generation,
        })
    }

    /// Recheck expiry, authorize parsed body-derived method/name values, and
    /// hold local rate/concurrency admission until the returned guard drops.
    pub(crate) fn authorize_and_admit(
        &self,
        authenticated: AuthenticatedMcp,
        method: &str,
        name: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<McpAdmissionGuard, McpAccessError> {
        let (route, grant) = self.grant(authenticated, now)?;
        if !grant.methods.iter().any(|allowed| allowed == method) {
            return Err(McpAccessError::Denied);
        }
        if matches!(method, "tools/call" | "prompts/get")
            && !grant.names.is_empty()
            && !name.is_some_and(|name| grant.names.iter().any(|allowed| allowed == name))
        {
            return Err(McpAccessError::Denied);
        }
        self.limits.try_admit(McpGrantIdentity {
            route_id: route.route_id,
            policy_revision: route.policy_revision,
            credential_id: authenticated.credential_id,
            credential_generation: authenticated.credential_generation,
        })
    }

    /// Select one healthy target from the exact authenticated route. Only the
    /// lowest priority containing an eligible target participates; weights
    /// apply inside that priority. There is deliberately no sticky, failover,
    /// scaling, or ordinary-router fallback path.
    pub(crate) fn select_target(
        &self,
        authenticated: AuthenticatedMcp,
        services: &ServiceRegistry,
        now: DateTime<Utc>,
    ) -> Result<McpDispatchTarget, McpAccessError> {
        let (route, _) = self.grant(authenticated, now)?;
        let profile = self
            .policy
            .profiles
            .get(&route.profile_digest)
            .ok_or(McpAccessError::Unavailable)?;
        let selected_priority = route
            .targets
            .iter()
            .filter(|target| target.profile_digest == route.profile_digest)
            .filter(|target| exact_healthy_backend(target, services).is_some())
            .map(|target| target.priority)
            .min()
            .ok_or(McpAccessError::DataPlaneUnavailable)?;
        let total_weight = route
            .targets
            .iter()
            .filter(|target| target.priority == selected_priority)
            .filter(|target| target.profile_digest == route.profile_digest)
            .filter(|target| exact_healthy_backend(target, services).is_some())
            .try_fold(0_u64, |total, target| {
                total.checked_add(u64::from(target.weight))
            })
            .filter(|total| *total > 0)
            .ok_or(McpAccessError::Unavailable)?;
        let counter = self
            .selection_counters
            .get(&route.route_id)
            .ok_or(McpAccessError::Unavailable)?
            .fetch_add(1, Ordering::Relaxed);
        let mut slot = counter % total_weight;
        let (target, backend) = route
            .targets
            .iter()
            .filter(|target| target.priority == selected_priority)
            .filter(|target| target.profile_digest == route.profile_digest)
            .filter_map(|target| {
                exact_healthy_backend(target, services).map(|backend| (target, backend))
            })
            .find(|(target, _)| {
                let weight = u64::from(target.weight);
                if slot < weight {
                    true
                } else {
                    slot -= weight;
                    false
                }
            })
            .ok_or(McpAccessError::Unavailable)?;

        Ok(McpDispatchTarget {
            target_id: target.target_id,
            service_name: target.service.clone(),
            backend,
            first_response_timeout: parse_runtime_duration(&route.first_response_timeout)?,
            stream_idle_timeout: parse_runtime_duration(&route.stream_idle_timeout)?,
            stream_total_timeout: parse_runtime_duration(&route.stream_total_timeout)?,
            max_response_header_bytes: route.max_header_bytes,
            max_response_bytes: route.max_response_bytes.min(profile.max_response_bytes),
            request_sse: profile.request_sse,
        })
    }

    fn route(&self, router: &str, now: DateTime<Utc>) -> Result<&McpRouteConfig, McpAccessError> {
        if self.policy.expires_at <= now {
            return Err(McpAccessError::Unavailable);
        }
        let route_id = self
            .routes_by_router
            .get(router)
            .ok_or(McpAccessError::Unavailable)?;
        self.policy
            .routes
            .get(route_id)
            .ok_or(McpAccessError::Unavailable)
    }

    fn grant(
        &self,
        authenticated: AuthenticatedMcp,
        now: DateTime<Utc>,
    ) -> Result<(&McpRouteConfig, &McpGrantConfig), McpAccessError> {
        if self.policy.expires_at <= now {
            return Err(McpAccessError::Unavailable);
        }
        let route = self
            .policy
            .routes
            .get(&authenticated.route_id)
            .ok_or(McpAccessError::Unavailable)?;
        let credential = self
            .policy
            .credentials
            .get(&authenticated.credential_id)
            .ok_or(McpAccessError::Unavailable)?;
        let grant = route
            .grants
            .get(&authenticated.credential_id)
            .ok_or(McpAccessError::Denied)?;
        if credential.revoked || credential.expires_at <= now {
            return Err(McpAccessError::Unauthorized);
        }
        if credential.environment_id != route.environment_id
            || credential.generation != authenticated.credential_generation
            || grant.credential_generation != authenticated.credential_generation
        {
            return Err(McpAccessError::Denied);
        }
        Ok((route, grant))
    }

    fn credential_for_token(&self, token: &str) -> Result<&McpCredentialConfig, McpAccessError> {
        if !valid_mcp_credential(token) {
            return Err(McpAccessError::Unauthorized);
        }
        for length in &self.prefix_lengths {
            if token.len() <= *length {
                continue;
            }
            let Some(prefix) = token.get(..*length) else {
                return Err(McpAccessError::Unauthorized);
            };
            let Some(credential_id) = self.credentials_by_prefix.get(prefix) else {
                continue;
            };
            return self
                .policy
                .credentials
                .get(credential_id)
                .ok_or(McpAccessError::Unavailable);
        }
        Err(McpAccessError::Unauthorized)
    }

    async fn verify_token(
        &self,
        token: &str,
        credential: &McpCredentialConfig,
    ) -> Result<(), McpAccessError> {
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
            .map_err(|_| McpAccessError::Unavailable)?;
        let candidate = token.to_owned();
        let verifier_hash = credential.verifier_hash().to_owned();
        let verified = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let parsed =
                PasswordHash::new(&verifier_hash).map_err(|_| McpAccessError::Unavailable)?;
            Ok::<_, McpAccessError>(
                Argon2::default()
                    .verify_password(candidate.as_bytes(), &parsed)
                    .is_ok(),
            )
        })
        .await
        .map_err(|_| McpAccessError::Unavailable)??;
        if !verified {
            return Err(McpAccessError::Unauthorized);
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

fn exact_healthy_backend(
    target: &crate::config::McpTargetConfig,
    services: &ServiceRegistry,
) -> Option<Arc<Backend>> {
    let service = services.get(&target.service)?;
    let [backend] = service.backends() else {
        return None;
    };
    if !backend.is_healthy()
        || Url::parse(&backend.url).ok()? != Url::parse(&target.endpoint).ok()?
    {
        return None;
    }
    Some(backend.clone())
}

fn parse_runtime_duration(value: &str) -> Result<Duration, McpAccessError> {
    crate::config::parse_service_duration(value).map_err(|_| McpAccessError::Unavailable)
}

fn validate_origin(headers: &HeaderMap, allowed_origins: &[String]) -> Result<(), McpAccessError> {
    let mut values = headers.get_all(ORIGIN).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(McpAccessError::InvalidOrigin);
    }
    let candidate = value
        .to_str()
        .ok()
        .and_then(normalize_origin)
        .ok_or(McpAccessError::InvalidOrigin)?;
    if allowed_origins
        .iter()
        .filter_map(|origin| normalize_origin(origin))
        .any(|allowed| allowed == candidate)
    {
        Ok(())
    } else {
        Err(McpAccessError::InvalidOrigin)
    }
}

fn normalize_origin(value: &str) -> Option<String> {
    let parsed = Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, McpAccessError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(McpAccessError::Unauthorized)?;
    if values.next().is_some() {
        return Err(McpAccessError::Unauthorized);
    }
    let value = value.to_str().map_err(|_| McpAccessError::Unauthorized)?;
    let (scheme, token) = value.split_once(' ').ok_or(McpAccessError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
    {
        return Err(McpAccessError::Unauthorized);
    }
    Ok(token)
}

fn valid_mcp_credential(token: &str) -> bool {
    token.len() <= MAX_MCP_CREDENTIAL_BYTES
        && token.starts_with("a3s_mcp_")
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/' | b'=')
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GatewayConfig;
    use crate::service::ServiceRegistry;
    use argon2::password_hash::{PasswordHasher, SaltString};
    use http::HeaderValue;

    const TOKEN: &str = "a3s_mcp_abc12345abcdefghijklmnopqrstuvwxyz012345";

    fn policy() -> McpConfig {
        let mut policy = GatewayConfig::from_acl(include_str!(
            "../../tests/fixtures/mcp-modern-stateless-snapshot.acl"
        ))
        .unwrap()
        .mcp
        .unwrap();
        let salt = SaltString::encode_b64(b"a3s-mcp-auth-test").unwrap();
        let verifier = Argon2::default()
            .hash_password(TOKEN.as_bytes(), &salt)
            .unwrap()
            .to_string();
        let credential = policy.credentials.values_mut().next().unwrap();
        credential.verifier_hash = verifier;
        policy
    }

    fn authenticated(policy: &McpConfig) -> AuthenticatedMcp {
        let route = policy.routes.values().next().unwrap();
        let credential = policy.credentials.values().next().unwrap();
        AuthenticatedMcp {
            route_id: route.route_id,
            credential_id: credential.credential_id,
            credential_generation: credential.generation,
        }
    }

    fn headers(token: &str, origin: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        if let Some(origin) = origin {
            headers.insert(ORIGIN, HeaderValue::from_str(origin).unwrap());
        }
        headers
    }

    #[tokio::test]
    async fn authenticates_locally_and_authorizes_body_derived_method_and_name() {
        let authorizer = McpAuthorizer::new(&policy());
        let headers = headers(TOKEN, Some("https://console.example.com"));
        let ingress = authorizer
            .ingress_policy("mcp", &headers, Utc::now())
            .unwrap();
        assert_eq!(ingress.max_header_bytes(), 32_768);
        assert_eq!(ingress.max_request_bytes(), 524_288);
        assert_eq!(ingress.protocol_versions(), ["2026-07-28"]);

        let authenticated = authorizer
            .authenticate("mcp", &headers, Utc::now())
            .await
            .unwrap();
        let admission = authorizer
            .authorize_and_admit(authenticated, "tools/call", Some("weather"), Utc::now())
            .unwrap();
        drop(admission);
    }

    #[tokio::test]
    async fn rejects_origin_and_credentials_without_using_request_metadata() {
        let authorizer = McpAuthorizer::new(&policy());
        let invalid_origin = headers(TOKEN, Some("https://attacker.example"));
        assert!(matches!(
            authorizer.ingress_policy("mcp", &invalid_origin, Utc::now()),
            Err(McpAccessError::InvalidOrigin)
        ));

        let invalid_token = headers(
            "a3s_mcp_abc12345wrongwrongwrongwrong",
            Some("https://console.example.com"),
        );
        assert!(matches!(
            authorizer
                .authenticate("mcp", &invalid_token, Utc::now())
                .await,
            Err(McpAccessError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn denies_ungranted_method_and_non_resource_name() {
        let authorizer = McpAuthorizer::new(&policy());
        let headers = headers(TOKEN, None);
        let authenticated = authorizer
            .authenticate("mcp", &headers, Utc::now())
            .await
            .unwrap();
        assert!(matches!(
            authorizer.authorize_and_admit(
                authenticated,
                "prompts/get",
                Some("weather"),
                Utc::now()
            ),
            Err(McpAccessError::Denied)
        ));
        assert!(matches!(
            authorizer.authorize_and_admit(
                authenticated,
                "tools/call",
                Some("private-tool"),
                Utc::now()
            ),
            Err(McpAccessError::Denied)
        ));
    }

    #[tokio::test]
    async fn rechecks_snapshot_and_credential_expiry() {
        let mut expired_policy = policy();
        expired_policy.expires_at = Utc::now() - chrono::Duration::seconds(1);
        let expired = McpAuthorizer::new(&expired_policy);
        let request_headers = headers(TOKEN, None);
        assert!(matches!(
            expired.ingress_policy("mcp", &request_headers, Utc::now()),
            Err(McpAccessError::Unavailable)
        ));

        let mut expired_credential_policy = policy();
        expired_credential_policy
            .credentials
            .values_mut()
            .next()
            .unwrap()
            .expires_at = Utc::now() - chrono::Duration::seconds(1);
        let expired_credential = McpAuthorizer::new(&expired_credential_policy);
        assert!(matches!(
            expired_credential
                .authenticate("mcp", &request_headers, Utc::now())
                .await,
            Err(McpAccessError::Unauthorized)
        ));
    }

    #[test]
    fn strips_credentials_and_unsigned_caller_identity() {
        let mut headers = headers(TOKEN, None);
        for name in [
            "cookie",
            "proxy-authorization",
            "x-api-key",
            "x-forwarded-user",
            "x-auth-request-user",
            "x-auth-request-email",
            "x-a3s-user-id",
            "x-a3s-tenant-id",
            "x-a3s-project-id",
            "x-a3s-grant-id",
        ] {
            headers.insert(
                http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_static("untrusted"),
            );
        }
        McpAuthorizer::strip_ingress_credentials(&mut headers);
        for name in [
            "authorization",
            "cookie",
            "proxy-authorization",
            "x-api-key",
            "x-forwarded-user",
            "x-auth-request-user",
            "x-auth-request-email",
            "x-a3s-user-id",
            "x-a3s-tenant-id",
            "x-a3s-project-id",
            "x-a3s-grant-id",
        ] {
            assert!(!headers.contains_key(name));
        }
    }

    #[test]
    fn selects_only_exact_healthy_targets_at_the_lowest_available_priority() {
        let mut gateway = GatewayConfig::from_acl(include_str!(
            "../../tests/fixtures/mcp-modern-stateless-snapshot.acl"
        ))
        .unwrap();
        let mut policy = gateway.mcp.take().unwrap();
        let route = policy.routes.values_mut().next().unwrap();
        let primary_id = route.targets[0].target_id;
        let mut fallback = route.targets[0].clone();
        fallback.target_id = Uuid::parse_str("88888888-8888-4888-8888-888888888888").unwrap();
        fallback.node_id = Uuid::parse_str("99999999-9999-4999-8999-999999999999").unwrap();
        fallback.unit_id = "workload:mcp-weather:replica:2".to_owned();
        fallback.generation = 4;
        fallback.service = "mcp-target-2".to_owned();
        fallback.endpoint = "http://127.0.0.1:8001/".to_owned();
        fallback.priority = 1;
        let fallback_id = fallback.target_id;
        route.targets.push(fallback);

        let mut fallback_service = gateway.services["mcp-target-1"].clone();
        fallback_service.load_balancer.servers[0].url = "http://127.0.0.1:8001/".to_owned();
        gateway
            .services
            .insert("mcp-target-2".to_owned(), fallback_service);
        let services = ServiceRegistry::from_config(&gateway.services).unwrap();
        let identity = authenticated(&policy);
        let authorizer = McpAuthorizer::new(&policy);

        assert_eq!(
            authorizer
                .select_target(identity, &services, Utc::now())
                .unwrap()
                .target_id(),
            primary_id
        );
        services.get("mcp-target-1").unwrap().backends()[0].set_healthy(false);
        let selected = authorizer
            .select_target(identity, &services, Utc::now())
            .unwrap();
        assert_eq!(selected.target_id(), fallback_id);
        assert_eq!(selected.service_name(), "mcp-target-2");
        assert_eq!(selected.backend().url, "http://127.0.0.1:8001/");
        assert_eq!(selected.first_response_timeout(), Duration::from_secs(30));
        assert_eq!(selected.stream_idle_timeout(), Duration::from_secs(120));
        assert_eq!(selected.stream_total_timeout(), Duration::from_secs(1_800));
        assert_eq!(selected.max_response_header_bytes(), 32_768);
        assert_eq!(selected.max_response_bytes(), 4_194_304);
    }

    #[test]
    fn target_selection_fails_closed_on_runtime_registry_drift() {
        let mut gateway = GatewayConfig::from_acl(include_str!(
            "../../tests/fixtures/mcp-modern-stateless-snapshot.acl"
        ))
        .unwrap();
        let policy = gateway.mcp.take().unwrap();
        gateway
            .services
            .get_mut("mcp-target-1")
            .unwrap()
            .load_balancer
            .servers[0]
            .url = "http://127.0.0.1:8999/".to_owned();
        let services = ServiceRegistry::from_config(&gateway.services).unwrap();
        let authorizer = McpAuthorizer::new(&policy);

        assert!(matches!(
            authorizer.select_target(authenticated(&policy), &services, Utc::now()),
            Err(McpAccessError::DataPlaneUnavailable)
        ));
    }

    #[test]
    fn unchanged_snapshot_refresh_retains_weighted_selection_position() {
        let policy = policy();
        let first = McpAuthorizer::new(&policy);
        let route_id = *policy.routes.keys().next().unwrap();
        let refreshed = McpAuthorizer::with_previous(&policy, Some(&first));
        assert!(Arc::ptr_eq(
            first.selection_counters.get(&route_id).unwrap(),
            refreshed.selection_counters.get(&route_id).unwrap()
        ));

        let mut changed_policy = policy.clone();
        changed_policy
            .routes
            .get_mut(&route_id)
            .unwrap()
            .policy_revision += 1;
        let changed = McpAuthorizer::with_previous(&changed_policy, Some(&refreshed));
        assert!(!Arc::ptr_eq(
            refreshed.selection_counters.get(&route_id).unwrap(),
            changed.selection_counters.get(&route_id).unwrap()
        ));
    }
}
