use crate::config::{
    default_request_timeout, default_stream_idle_timeout, default_stream_total_timeout,
    GatewayConfig, HealthCheckConfig, LoadBalancerConfig, ManagedTargetConfig, MiddlewareConfig,
    RouterConfig, ServerConfig, ServiceConfig, Strategy,
};
use crate::error::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

pub(super) const STATE_SCHEMA: &str = "a3s.gateway.managed-service-state.v1";
pub(super) const REQUEST_SCHEMA: &str = "a3s.gateway.managed-service-binding.v1";
const ENDPOINT_PREFIX: &str = "gateway:managed-services/";
const ROUTE_PREFIX: &str = "/_a3s/runtime";
pub(crate) const MANAGED_SERVICE_MIDDLEWARE_NAME: &str = "a3s-managed-services-strip-v1";
pub(crate) const MANAGED_SERVICE_NAME_PREFIX: &str = "a3s-managed-service-";
const MAX_EXACT_JSON_INTEGER: u64 = (1_u64 << 53) - 1;

/// HTTP health contract for one private Runtime Service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedServiceHealthCheck {
    path: String,
    interval_ms: u64,
    timeout_ms: u64,
    success_threshold: u32,
    failure_threshold: u32,
}

impl ManagedServiceHealthCheck {
    pub fn new(
        path: impl Into<String>,
        interval_ms: u64,
        timeout_ms: u64,
        success_threshold: u32,
        failure_threshold: u32,
    ) -> Result<Self> {
        let health = Self {
            path: path.into(),
            interval_ms,
            timeout_ms,
            success_threshold,
            failure_threshold,
        };
        health.validate()?;
        Ok(health)
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn interval_ms(&self) -> u64 {
        self.interval_ms
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn success_threshold(&self) -> u32 {
        self.success_threshold
    }

    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    fn validate(&self) -> Result<()> {
        validate_http_path(&self.path, "health path")?;
        if self.interval_ms == 0
            || self.timeout_ms == 0
            || self.interval_ms > MAX_EXACT_JSON_INTEGER
            || self.timeout_ms > MAX_EXACT_JSON_INTEGER
            || self.success_threshold == 0
            || self.failure_threshold == 0
        {
            return Err(input_error(
                "Managed Service health timing and thresholds must be positive bounded values",
            ));
        }
        Ok(())
    }
}

/// Complete immutable request for one exact Gateway binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedServiceBindingRequest {
    schema: String,
    idempotency_key: String,
    entrypoint: String,
    target: ManagedTargetConfig,
    upstream: SocketAddr,
    service_path: String,
    health: ManagedServiceHealthCheck,
}

impl ManagedServiceBindingRequest {
    pub fn new(
        idempotency_key: impl Into<String>,
        entrypoint: impl Into<String>,
        target: ManagedTargetConfig,
        upstream: SocketAddr,
        service_path: impl Into<String>,
        health: ManagedServiceHealthCheck,
    ) -> Result<Self> {
        let request = Self {
            schema: REQUEST_SCHEMA.to_string(),
            idempotency_key: idempotency_key.into(),
            entrypoint: entrypoint.into(),
            target,
            upstream,
            service_path: service_path.into(),
            health,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    pub fn entrypoint(&self) -> &str {
        &self.entrypoint
    }

    pub fn target(&self) -> &ManagedTargetConfig {
        &self.target
    }

    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    pub fn service_path(&self) -> &str {
        &self.service_path
    }

    pub fn health(&self) -> &ManagedServiceHealthCheck {
        &self.health
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.schema != REQUEST_SCHEMA {
            return Err(input_error("Unsupported Managed Service binding schema"));
        }
        validate_digest(&self.idempotency_key, "idempotency key")?;
        if !valid_name(&self.entrypoint) {
            return Err(input_error(
                "Managed Service entrypoint names must be portable bounded identifiers",
            ));
        }
        self.target.validate().map_err(input_error)?;
        if !self.upstream.ip().is_loopback() || self.upstream.port() == 0 {
            return Err(input_error(
                "Managed Service upstreams must be positive loopback TCP sockets",
            ));
        }
        validate_http_path(&self.service_path, "service path")?;
        self.health.validate()
    }

    pub(super) fn request_digest(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| {
            GatewayError::Other(format!(
                "Could not encode Managed Service binding identity: {error}"
            ))
        })?;
        Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
    }
}

/// Durable lifecycle phase of a managed binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ManagedServicePhase {
    Binding,
    Ready,
    Draining,
    Drained,
}

impl ManagedServicePhase {
    pub(super) fn is_routable(self) -> bool {
        matches!(self, Self::Binding | Self::Ready)
    }
}

/// Receipt identity required for drain and removal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedServiceBindingIdentity {
    endpoint_ref: String,
    target: ManagedTargetConfig,
}

impl ManagedServiceBindingIdentity {
    pub fn new(endpoint_ref: impl Into<String>, target: ManagedTargetConfig) -> Result<Self> {
        let identity = Self {
            endpoint_ref: endpoint_ref.into(),
            target,
        };
        identity.binding_id()?;
        identity.target.validate().map_err(input_error)?;
        Ok(identity)
    }

    pub fn endpoint_ref(&self) -> &str {
        &self.endpoint_ref
    }

    pub fn target(&self) -> &ManagedTargetConfig {
        &self.target
    }

    pub(super) fn binding_id(&self) -> Result<&str> {
        binding_id_from_endpoint_ref(&self.endpoint_ref)
    }
}

/// Ready or replayed private Gateway endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedServiceBinding {
    identity: ManagedServiceBindingIdentity,
    endpoint: String,
    replayed: bool,
}

impl ManagedServiceBinding {
    pub fn identity(&self) -> &ManagedServiceBindingIdentity {
        &self.identity
    }

    pub fn endpoint_ref(&self) -> &str {
        self.identity.endpoint_ref()
    }

    /// Private loopback URL for trusted host composition.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

/// Bounded status for one exact binding identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManagedServiceStatus {
    identity: ManagedServiceBindingIdentity,
    phase: ManagedServicePhase,
}

impl ManagedServiceStatus {
    pub fn identity(&self) -> &ManagedServiceBindingIdentity {
        &self.identity
    }

    pub fn phase(&self) -> ManagedServicePhase {
        self.phase
    }

    pub fn ready(&self) -> bool {
        self.phase == ManagedServicePhase::Ready
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StoredManagedServiceBinding {
    pub schema: String,
    pub binding_id: String,
    pub request_digest: String,
    pub request: ManagedServiceBindingRequest,
    pub phase: ManagedServicePhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drain_operation_key: Option<String>,
}

impl StoredManagedServiceBinding {
    pub(super) fn new(request: ManagedServiceBindingRequest) -> Result<Self> {
        request.validate()?;
        let binding = Self {
            schema: STATE_SCHEMA.to_string(),
            binding_id: binding_id(&request.idempotency_key),
            request_digest: request.request_digest()?,
            request,
            phase: ManagedServicePhase::Binding,
            drain_operation_key: None,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(super) fn validate(&self) -> Result<()> {
        self.request.validate()?;
        validate_digest(&self.request_digest, "request digest")?;
        if self.schema != STATE_SCHEMA
            || self.binding_id != binding_id(self.request.idempotency_key())
            || self.request_digest != self.request.request_digest()?
            || self
                .drain_operation_key
                .as_deref()
                .is_some_and(|key| validate_digest(key, "drain operation key").is_err())
            || match self.phase {
                ManagedServicePhase::Binding | ManagedServicePhase::Ready => {
                    self.drain_operation_key.is_some()
                }
                ManagedServicePhase::Draining | ManagedServicePhase::Drained => {
                    self.drain_operation_key.is_none()
                }
            }
        {
            return Err(input_error(
                "Durable Managed Service binding identity is inconsistent",
            ));
        }
        Ok(())
    }

    pub(crate) fn identity(&self) -> ManagedServiceBindingIdentity {
        ManagedServiceBindingIdentity {
            endpoint_ref: endpoint_ref(&self.binding_id),
            target: self.request.target.clone(),
        }
    }

    pub(crate) fn binding(
        &self,
        config: &GatewayConfig,
        replayed: bool,
    ) -> Result<ManagedServiceBinding> {
        Ok(ManagedServiceBinding {
            identity: self.identity(),
            endpoint: endpoint_url(
                config,
                &self.request,
                &self.binding_id,
                self.request.service_path(),
            )?,
            replayed,
        })
    }

    pub(crate) fn health_endpoint(&self, config: &GatewayConfig) -> Result<String> {
        endpoint_url(
            config,
            &self.request,
            &self.binding_id,
            self.request.health.path(),
        )
    }

    pub(crate) fn service_name(&self) -> String {
        format!("{MANAGED_SERVICE_NAME_PREFIX}{}", self.binding_id)
    }

    fn router_name(&self) -> String {
        format!("a3s-managed-router-{}", self.binding_id)
    }
}

pub(super) fn validate_operation_key(key: &str) -> Result<()> {
    validate_digest(key, "operation key")
}

pub(super) fn apply_overlay(
    config: &mut GatewayConfig,
    bindings: impl Iterator<Item = StoredManagedServiceBinding>,
) -> Result<()> {
    let active = bindings
        .filter(|binding| binding.phase.is_routable())
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(());
    }
    for binding in &active {
        binding.validate()?;
        let entrypoint = validate_private_entrypoint(config, binding.request.entrypoint())?;
        if entrypoint == binding.request.upstream() {
            return Err(input_error(
                "Managed Service upstream must not be its Gateway entrypoint",
            ));
        }
        if config.routers.values().any(|router| {
            router.priority == i32::MAX
                && (router.entrypoints.is_empty()
                    || router
                        .entrypoints
                        .iter()
                        .any(|entrypoint| entrypoint == binding.request.entrypoint()))
        }) {
            return Err(input_error(format!(
                "Managed Service entrypoint '{}' cannot contain another maximum-priority router",
                binding.request.entrypoint()
            )));
        }
    }
    if config
        .middlewares
        .contains_key(MANAGED_SERVICE_MIDDLEWARE_NAME)
    {
        return Err(conflict_error(MANAGED_SERVICE_MIDDLEWARE_NAME));
    }
    config.middlewares.insert(
        MANAGED_SERVICE_MIDDLEWARE_NAME.to_string(),
        MiddlewareConfig {
            middleware_type: "strip-prefix".to_string(),
            prefixes: vec![format!("{ROUTE_PREFIX}/*")],
            ..MiddlewareConfig::default()
        },
    );

    for binding in active {
        let service_name = binding.service_name();
        let router_name = binding.router_name();
        if config.services.contains_key(&service_name) {
            return Err(conflict_error(&service_name));
        }
        if config.routers.contains_key(&router_name) {
            return Err(conflict_error(&router_name));
        }
        config.services.insert(
            service_name.clone(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: default_request_timeout(),
                    stream_idle_timeout: default_stream_idle_timeout(),
                    stream_total_timeout: default_stream_total_timeout(),
                    servers: vec![ServerConfig {
                        url: format!("http://{}", binding.request.upstream()),
                        weight: 1,
                        target: Some(binding.request.target().clone()),
                    }],
                    health_check: Some(HealthCheckConfig {
                        path: binding.request.health.path().to_string(),
                        interval: format!("{}ms", binding.request.health.interval_ms()),
                        timeout: format!("{}ms", binding.request.health.timeout_ms()),
                        unhealthy_threshold: binding.request.health.failure_threshold(),
                        healthy_threshold: binding.request.health.success_threshold(),
                    }),
                    sticky: None,
                },
                scaling: None,
                revisions: Vec::new(),
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        config.routers.insert(
            router_name,
            RouterConfig {
                rule: format!("PathPrefix(`{ROUTE_PREFIX}/{}/`)", binding.binding_id),
                service: service_name,
                entrypoints: vec![binding.request.entrypoint().to_string()],
                middlewares: vec![MANAGED_SERVICE_MIDDLEWARE_NAME.to_string()],
                priority: i32::MAX,
            },
        );
    }
    // The base ACL is validated before it reaches this closed overlay. Do not
    // re-run public ACL mode validation here: `ServerConfig::target` remains a
    // Cloud-only ACL field, while this programmatic host-owned overlay also
    // needs exact-generation identity in standalone A3S Code hosts. Every
    // injected router, service, middleware, endpoint, health contract, and
    // target above is constructed and validated from the durable request.
    Ok(())
}

fn validate_private_entrypoint(config: &GatewayConfig, name: &str) -> Result<SocketAddr> {
    let entrypoint = config.entrypoints.get(name).ok_or_else(|| {
        input_error(format!(
            "Managed Service entrypoint '{name}' is not configured"
        ))
    })?;
    if entrypoint.protocol != crate::config::Protocol::Http || entrypoint.tls.is_some() {
        return Err(input_error(
            "Managed Services require a cleartext private HTTP entrypoint",
        ));
    }
    let address = entrypoint.address.parse::<SocketAddr>().map_err(|error| {
        input_error(format!(
            "Managed Service entrypoint '{name}' has an invalid socket: {error}"
        ))
    })?;
    if !address.ip().is_loopback() || address.port() == 0 {
        return Err(input_error(
            "Managed Services require a positive loopback Gateway entrypoint",
        ));
    }
    Ok(address)
}

fn endpoint_url(
    config: &GatewayConfig,
    request: &ManagedServiceBindingRequest,
    binding_id: &str,
    path: &str,
) -> Result<String> {
    let address = validate_private_entrypoint(config, request.entrypoint())?;
    Ok(format!("http://{address}{ROUTE_PREFIX}/{binding_id}{path}"))
}

fn binding_id(key: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"a3s-gateway-managed-service-v1");
    digest.update([0]);
    digest.update(key.as_bytes());
    format!("{:x}", digest.finalize())
}

fn endpoint_ref(binding_id: &str) -> String {
    format!("{ENDPOINT_PREFIX}{binding_id}")
}

fn binding_id_from_endpoint_ref(endpoint_ref: &str) -> Result<&str> {
    let Some(value) = endpoint_ref.strip_prefix(ENDPOINT_PREFIX) else {
        return Err(input_error(
            "Managed Service endpoint references use gateway:managed-services/<sha256>",
        ));
    };
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(input_error("Managed Service endpoint reference is invalid"));
    }
    Ok(value)
}

fn validate_digest(value: &str, label: &str) -> Result<()> {
    let valid = value.strip_prefix("sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    });
    if !valid {
        return Err(input_error(format!(
            "Managed Service {label} must use canonical sha256:<hex>"
        )));
    }
    Ok(())
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn validate_http_path(value: &str, label: &str) -> Result<()> {
    let valid_uri_path = value
        .parse::<http::uri::PathAndQuery>()
        .is_ok_and(|path| path.query().is_none() && path.path() == value);
    if !valid_uri_path
        || !value.starts_with('/')
        || value.len() > 1024
        || value.contains("//")
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || matches!(byte, b'?' | b'#' | b'\\'))
        || value
            .split('/')
            .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(input_error(format!(
            "Managed Service {label} must be a canonical absolute HTTP path"
        )));
    }
    Ok(())
}

fn input_error(message: impl Into<String>) -> GatewayError {
    GatewayError::Config(message.into())
}

fn conflict_error(name: &str) -> GatewayError {
    input_error(format!(
        "Base Gateway configuration conflicts with reserved Managed Service object '{name}'"
    ))
}

pub(super) fn status(binding: &StoredManagedServiceBinding) -> ManagedServiceStatus {
    ManagedServiceStatus {
        identity: binding.identity(),
        phase: binding.phase,
    }
}
