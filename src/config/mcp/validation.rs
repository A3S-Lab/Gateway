//! Referential, security, and resource-bound validation for hosted MCP policy.

use super::{
    McpConfig, McpCredentialConfig, McpGrantConfig, McpLimitsConfig, McpRouteConfig,
    McpServiceProfileConfig, McpTargetConfig, MCP_CREDENTIAL_AUDIENCE, MCP_PROTOCOL_VERSION,
};
use crate::config::{GatewayConfig, OperatingMode};
use crate::error::{GatewayError, Result};
use argon2::password_hash::PasswordHash;
use chrono::{DateTime, Utc};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::time::Duration;
use url::Url;
use uuid::Uuid;

const MAX_PROFILES: usize = 1_000;
const MAX_CREDENTIALS: usize = 10_000;
const MAX_ROUTES: usize = 1_000;
const MAX_TARGETS_PER_ROUTE: usize = 64;
const MAX_GRANTS_PER_ROUTE: usize = 10_000;
const MAX_METHODS_PER_GRANT: usize = 256;
const MAX_NAMES_PER_GRANT: usize = 1_000;
const MAX_ALLOWED_ORIGINS: usize = 256;
const MAX_TELEMETRY_NAMES: usize = 256;
const MAX_HEADER_BYTES: u64 = 128 * 1024;
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONCURRENT_REQUESTS: u64 = 100_000;
const MAX_REQUESTS_PER_MINUTE: u64 = 10_000_000;
const MAX_VERIFIER_BYTES: usize = 512;
const MIN_ARGON2_MEMORY_KIB: u32 = 19_456;
const MAX_ARGON2_MEMORY_KIB: u32 = 262_144;
const MIN_ARGON2_ITERATIONS: u32 = 2;
const MAX_ARGON2_ITERATIONS: u32 = 10;
const MAX_ARGON2_LANES: u32 = 4;
const MIN_ARGON2_SALT_ENCODED_LEN: usize = 22;
const MAX_ARGON2_SALT_ENCODED_LEN: usize = 86;
const MIN_ARGON2_OUTPUT_ENCODED_LEN: usize = 43;
const MAX_ARGON2_OUTPUT_ENCODED_LEN: usize = 86;

impl McpConfig {
    pub(in crate::config) fn validate(
        &self,
        gateway: &GatewayConfig,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if gateway.mode == OperatingMode::CloudManaged && gateway.managed.gateway_id.is_none() {
            return Err(config_error(
                "MCP policy in cloud-managed mode requires managed.gateway_id",
            ));
        }
        if self.expires_at <= now {
            return Err(config_error("MCP route policy has expired"));
        }
        if self.profiles.is_empty() || self.profiles.len() > MAX_PROFILES {
            return Err(config_error(format!(
                "MCP policy must contain 1 to {MAX_PROFILES} service profiles"
            )));
        }
        if self.routes.is_empty() || self.routes.len() > MAX_ROUTES {
            return Err(config_error(format!(
                "MCP policy must contain 1 to {MAX_ROUTES} routes"
            )));
        }
        if self.credentials.len() > MAX_CREDENTIALS {
            return Err(config_error(format!(
                "MCP policy exceeds the {MAX_CREDENTIALS} credential limit"
            )));
        }

        for (digest, profile) in &self.profiles {
            validate_profile(digest, profile)?;
        }

        let mut prefixes = HashSet::new();
        for (credential_id, credential) in &self.credentials {
            if *credential_id != credential.credential_id {
                return Err(config_error(format!(
                    "MCP credential map key {credential_id} does not match credential_id {}",
                    credential.credential_id
                )));
            }
            validate_credential(credential)?;
            if !prefixes.insert(credential.prefix.as_str()) {
                return Err(config_error(format!(
                    "MCP credential prefix '{}' is not unique",
                    credential.prefix
                )));
            }
        }
        let mut ordered_prefixes = prefixes.into_iter().collect::<Vec<_>>();
        ordered_prefixes.sort_unstable();
        if ordered_prefixes
            .windows(2)
            .any(|pair| pair[1].starts_with(pair[0]))
        {
            return Err(config_error("MCP credential prefixes must not overlap"));
        }

        let inference_routers = gateway
            .inference
            .as_ref()
            .map(|policy| {
                policy
                    .routes
                    .values()
                    .map(|route| route.router.as_str())
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();
        let mut routers = HashSet::new();
        let mut target_ids = HashSet::new();
        let mut runtime_targets = HashSet::new();
        for (route_id, route) in &self.routes {
            if *route_id != route.route_id {
                return Err(config_error(format!(
                    "MCP route map key {route_id} does not match route_id {}",
                    route.route_id
                )));
            }
            validate_route(
                route,
                gateway,
                &self.profiles,
                &self.credentials,
                &inference_routers,
                &mut routers,
                &mut target_ids,
                &mut runtime_targets,
            )?;
        }
        Ok(())
    }

    pub(crate) fn validate_managed_expiry(
        &self,
        managed_expires_at: DateTime<Utc>,
    ) -> std::result::Result<(), String> {
        if self.expires_at != managed_expires_at {
            return Err(
                "MCP route policy expires_at must exactly match the managed snapshot expiry"
                    .to_string(),
            );
        }
        Ok(())
    }
}

fn validate_profile(map_digest: &str, profile: &McpServiceProfileConfig) -> Result<()> {
    validate_digest("MCP service profile", map_digest)?;
    validate_digest("MCP service profile", &profile.profile_digest)?;
    if map_digest != profile.profile_digest {
        return Err(config_error(format!(
            "MCP service profile map key {map_digest} does not match profile_digest {}",
            profile.profile_digest
        )));
    }
    if profile.protocol_versions != [MCP_PROTOCOL_VERSION] {
        return Err(config_error(format!(
            "MCP service profile {map_digest} must support exactly protocol version {MCP_PROTOCOL_VERSION}"
        )));
    }
    validate_literal_path(&profile.path)?;
    if profile.subscriptions && !profile.request_sse {
        return Err(config_error(format!(
            "MCP service profile {map_digest} cannot support subscriptions without request-scoped SSE"
        )));
    }
    if profile.max_request_bytes == 0
        || profile.max_request_bytes > MAX_REQUEST_BYTES
        || profile.max_response_bytes == 0
        || profile.max_response_bytes > MAX_RESPONSE_BYTES
    {
        return Err(config_error(format!(
            "MCP service profile {map_digest} has invalid request or response byte bounds"
        )));
    }
    Ok(())
}

fn validate_credential(credential: &McpCredentialConfig) -> Result<()> {
    if credential.credential_id.is_nil() || credential.environment_id.is_nil() {
        return Err(config_error(
            "MCP credential and environment IDs must not be nil",
        ));
    }
    if credential.audience != MCP_CREDENTIAL_AUDIENCE {
        return Err(config_error(format!(
            "MCP credential {} has unsupported audience '{}'",
            credential.credential_id, credential.audience
        )));
    }
    if credential.generation == 0 {
        return Err(config_error(format!(
            "MCP credential {} generation must be positive",
            credential.credential_id
        )));
    }
    validate_credential_prefix(&credential.prefix)?;
    validate_argon2id_verifier(credential.verifier_hash())?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_route<'a>(
    route: &'a McpRouteConfig,
    gateway: &'a GatewayConfig,
    profiles: &'a HashMap<String, McpServiceProfileConfig>,
    credentials: &'a HashMap<Uuid, McpCredentialConfig>,
    inference_routers: &HashSet<&'a str>,
    routers: &mut HashSet<&'a str>,
    target_ids: &mut HashSet<Uuid>,
    runtime_targets: &mut HashSet<(Uuid, &'a str, u64)>,
) -> Result<()> {
    if route.route_id.is_nil() || route.environment_id.is_nil() {
        return Err(config_error(
            "MCP route and environment IDs must not be nil",
        ));
    }
    if route.policy_revision == 0 {
        return Err(config_error(format!(
            "MCP route {} policy_revision must be positive",
            route.route_id
        )));
    }
    validate_name("MCP router", &route.router, 255)?;
    let router = gateway.routers.get(&route.router).ok_or_else(|| {
        config_error(format!(
            "MCP route {} references unknown router '{}'",
            route.route_id, route.router
        ))
    })?;
    if !routers.insert(route.router.as_str()) {
        return Err(config_error(format!(
            "Gateway router '{}' is bound to more than one MCP route",
            route.router
        )));
    }
    if inference_routers.contains(route.router.as_str()) {
        return Err(config_error(format!(
            "Gateway router '{}' cannot be bound to both MCP and inference policy",
            route.router
        )));
    }
    if !router.middlewares.is_empty() {
        return Err(config_error(format!(
            "MCP router '{}' cannot use generic middlewares; authentication and limits belong to the MCP route policy",
            route.router
        )));
    }

    let profile = profiles.get(&route.profile_digest).ok_or_else(|| {
        config_error(format!(
            "MCP route {} references unknown service profile '{}'",
            route.route_id, route.profile_digest
        ))
    })?;
    let rule = crate::router::Rule::parse(&router.rule).map_err(|error| {
        config_error(format!(
            "MCP router '{}' has an invalid rule: {error}",
            route.router
        ))
    })?;
    if rule.closed_exact_endpoint_path() != Some(profile.path.as_str()) {
        return Err(config_error(format!(
            "MCP router '{}' must use exactly one Path(`{}`) matcher with at most one Host matcher and no PathPrefix, Method, or Headers matchers",
            route.router, profile.path
        )));
    }
    validate_route_bounds(route, profile)?;
    validate_origins(route)?;
    validate_names(
        "MCP telemetry name",
        &route.telemetry_names,
        MAX_TELEMETRY_NAMES,
    )?;

    if route.targets.is_empty() || route.targets.len() > MAX_TARGETS_PER_ROUTE {
        return Err(config_error(format!(
            "MCP route {} must contain 1 to {MAX_TARGETS_PER_ROUTE} targets",
            route.route_id
        )));
    }
    if route.grants.is_empty() || route.grants.len() > MAX_GRANTS_PER_ROUTE {
        return Err(config_error(format!(
            "MCP route {} must contain 1 to {MAX_GRANTS_PER_ROUTE} grants",
            route.route_id
        )));
    }
    validate_targets(route, gateway, target_ids, runtime_targets)?;
    for (credential_id, grant) in &route.grants {
        validate_grant(route, profile, *credential_id, grant, credentials)?;
    }
    Ok(())
}

fn validate_route_bounds(route: &McpRouteConfig, profile: &McpServiceProfileConfig) -> Result<()> {
    if route.max_header_bytes == 0
        || route.max_header_bytes > MAX_HEADER_BYTES
        || route.max_request_bytes == 0
        || route.max_request_bytes > profile.max_request_bytes
        || route.max_response_bytes == 0
        || route.max_response_bytes > profile.max_response_bytes
    {
        return Err(config_error(format!(
            "MCP route {} has invalid or profile-exceeding byte bounds",
            route.route_id
        )));
    }
    let first = parse_bounded_duration(
        route.route_id,
        "first_response_timeout",
        &route.first_response_timeout,
        Duration::from_secs(5 * 60),
    )?;
    let idle = parse_bounded_duration(
        route.route_id,
        "stream_idle_timeout",
        &route.stream_idle_timeout,
        Duration::from_secs(60 * 60),
    )?;
    let total = parse_bounded_duration(
        route.route_id,
        "stream_total_timeout",
        &route.stream_total_timeout,
        Duration::from_secs(24 * 60 * 60),
    )?;
    parse_bounded_duration(
        route.route_id,
        "drain_timeout",
        &route.drain_timeout,
        Duration::from_secs(10 * 60),
    )?;
    if first > total || idle > total {
        return Err(config_error(format!(
            "MCP route {} stream_total_timeout must cover first-response and idle timeouts",
            route.route_id
        )));
    }
    Ok(())
}

fn validate_origins(route: &McpRouteConfig) -> Result<()> {
    if route.allowed_origins.len() > MAX_ALLOWED_ORIGINS {
        return Err(config_error(format!(
            "MCP route {} exceeds the {MAX_ALLOWED_ORIGINS} allowed-origin limit",
            route.route_id
        )));
    }
    let mut normalized = HashSet::new();
    for origin in &route.allowed_origins {
        let parsed = Url::parse(origin).map_err(|_| {
            config_error(format!(
                "MCP route {} contains invalid allowed origin '{origin}'",
                route.route_id
            ))
        })?;
        let loopback = parsed
            .host_str()
            .and_then(|host| host.parse::<IpAddr>().ok())
            .is_some_and(|address| address.is_loopback());
        if !matches!(parsed.scheme(), "http" | "https")
            || (parsed.scheme() == "http" && !loopback)
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.path() != "/"
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(config_error(format!(
                "MCP route {} allowed origin '{origin}' must be an HTTPS origin or loopback HTTP origin without credentials, path, query, or fragment",
                route.route_id
            )));
        }
        let key = format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or_default(),
            parsed
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        if !normalized.insert(key) {
            return Err(config_error(format!(
                "MCP route {} contains duplicate allowed origins",
                route.route_id
            )));
        }
    }
    Ok(())
}

fn validate_targets<'a>(
    route: &'a McpRouteConfig,
    gateway: &'a GatewayConfig,
    target_ids: &mut HashSet<Uuid>,
    runtime_targets: &mut HashSet<(Uuid, &'a str, u64)>,
) -> Result<()> {
    let mut priorities = BTreeSet::new();
    let mut weight_by_priority = HashMap::<u32, u64>::new();
    let mut previous_priority = None;
    let mut services = HashSet::new();
    for target in &route.targets {
        validate_target_identity(route, target, target_ids, runtime_targets)?;
        if target.profile_digest != route.profile_digest {
            return Err(config_error(format!(
                "MCP target {} profile digest does not match route {}",
                target.target_id, route.route_id
            )));
        }
        validate_name("MCP target service", &target.service, 255)?;
        if !services.insert(target.service.as_str()) {
            return Err(config_error(format!(
                "MCP route {} reuses target service '{}'",
                route.route_id, target.service
            )));
        }
        validate_target_service(route, target, gateway)?;
        if target.weight == 0 {
            return Err(config_error(format!(
                "MCP target {} weight must be positive",
                target.target_id
            )));
        }
        if previous_priority.is_some_and(|previous| target.priority < previous) {
            return Err(config_error(format!(
                "MCP route {} targets must be ordered by ascending priority",
                route.route_id
            )));
        }
        previous_priority = Some(target.priority);
        priorities.insert(target.priority);
        let total = weight_by_priority.entry(target.priority).or_default();
        *total = total.checked_add(u64::from(target.weight)).ok_or_else(|| {
            config_error(format!(
                "MCP target priority {} weight overflows",
                target.priority
            ))
        })?;
        if *total > u64::from(u32::MAX) {
            return Err(config_error(format!(
                "MCP target priority {} total weight exceeds u32",
                target.priority
            )));
        }
    }
    if priorities
        .iter()
        .copied()
        .enumerate()
        .any(|(expected, actual)| usize::try_from(actual) != Ok(expected))
    {
        return Err(config_error(format!(
            "MCP route {} target priorities must be contiguous from zero",
            route.route_id
        )));
    }
    Ok(())
}

fn validate_target_identity<'a>(
    route: &McpRouteConfig,
    target: &'a McpTargetConfig,
    target_ids: &mut HashSet<Uuid>,
    runtime_targets: &mut HashSet<(Uuid, &'a str, u64)>,
) -> Result<()> {
    if target.target_id.is_nil()
        || target.node_id.is_nil()
        || target.asset_release_id.is_nil()
        || !target_ids.insert(target.target_id)
    {
        return Err(config_error(format!(
            "MCP target IDs must be non-nil and globally unique; invalid target {}",
            target.target_id
        )));
    }
    validate_name("MCP Runtime unit_id", &target.unit_id, 512)?;
    if target.generation == 0 {
        return Err(config_error(format!(
            "MCP target {} Runtime generation must be positive",
            target.target_id
        )));
    }
    if !runtime_targets.insert((target.node_id, target.unit_id.as_str(), target.generation)) {
        return Err(config_error(format!(
            "MCP route {} contains a duplicate Runtime target observation",
            route.route_id
        )));
    }
    Ok(())
}

fn validate_target_service(
    route: &McpRouteConfig,
    target: &McpTargetConfig,
    gateway: &GatewayConfig,
) -> Result<()> {
    let service = gateway.services.get(&target.service).ok_or_else(|| {
        config_error(format!(
            "MCP target {} references unknown service '{}'",
            target.target_id, target.service
        ))
    })?;
    if service.load_balancer.sticky.is_some()
        || service.scaling.is_some()
        || !service.revisions.is_empty()
        || service.rollout.is_some()
        || service.mirror.is_some()
        || service.failover.is_some()
        || service.load_balancer.servers.len() != 1
    {
        return Err(config_error(format!(
            "MCP target {} service '{}' must contain exactly one server and cannot use sticky, scaling, revisions, rollout, mirror, or failover behavior",
            target.target_id, target.service
        )));
    }
    let endpoint = validate_loopback_endpoint(route.route_id, &target.endpoint)?;
    let server = Url::parse(&service.load_balancer.servers[0].url).map_err(|_| {
        config_error(format!(
            "MCP target {} service '{}' contains an invalid server URL",
            target.target_id, target.service
        ))
    })?;
    if server != endpoint {
        return Err(config_error(format!(
            "MCP target {} endpoint does not exactly match its service server",
            target.target_id
        )));
    }
    Ok(())
}

fn validate_loopback_endpoint(route_id: Uuid, endpoint: &str) -> Result<Url> {
    let parsed = Url::parse(endpoint).map_err(|_| {
        config_error(format!(
            "MCP route {route_id} contains invalid target endpoint '{endpoint}'"
        ))
    })?;
    let loopback = parsed
        .host_str()
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback());
    if parsed.scheme() != "http"
        || !loopback
        || parsed.port().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(config_error(format!(
            "MCP route {route_id} target endpoint must be an explicit loopback HTTP port without credentials, path, query, or fragment"
        )));
    }
    Ok(parsed)
}

fn validate_grant(
    route: &McpRouteConfig,
    profile: &McpServiceProfileConfig,
    credential_id: Uuid,
    grant: &McpGrantConfig,
    credentials: &HashMap<Uuid, McpCredentialConfig>,
) -> Result<()> {
    let credential = credentials.get(&credential_id).ok_or_else(|| {
        config_error(format!(
            "MCP route {} grant references unknown credential {credential_id}",
            route.route_id
        ))
    })?;
    if credential.environment_id != route.environment_id {
        return Err(config_error(format!(
            "MCP route {} grant credential {credential_id} belongs to another environment",
            route.route_id
        )));
    }
    if credential.revoked {
        return Err(config_error(format!(
            "MCP route {} grants revoked credential {credential_id}",
            route.route_id
        )));
    }
    if grant.credential_generation == 0 || grant.credential_generation != credential.generation {
        return Err(config_error(format!(
            "MCP route {} grant does not match credential {credential_id} generation",
            route.route_id
        )));
    }
    if grant.methods.is_empty() || grant.methods.len() > MAX_METHODS_PER_GRANT {
        return Err(config_error(format!(
            "MCP route {} grant for credential {credential_id} must contain 1 to {MAX_METHODS_PER_GRANT} methods",
            route.route_id
        )));
    }
    let mut methods = HashSet::new();
    for method in &grant.methods {
        if !methods.insert(method) || !valid_method(method) {
            return Err(config_error(format!(
                "MCP route {} grant for credential {credential_id} contains an invalid or duplicate method '{method}'",
                route.route_id
            )));
        }
    }
    if !grant
        .methods
        .iter()
        .any(|method| method == "server/discover")
    {
        return Err(config_error(format!(
            "MCP route {} grant for credential {credential_id} must allow mandatory server/discover",
            route.route_id
        )));
    }
    if grant
        .methods
        .iter()
        .any(|method| method == "subscriptions/listen")
        && !profile.subscriptions
    {
        return Err(config_error(format!(
            "MCP route {} grant for credential {credential_id} cannot allow subscriptions/listen when the service profile disables subscriptions",
            route.route_id
        )));
    }
    validate_names("MCP grant name", &grant.names, MAX_NAMES_PER_GRANT)?;
    validate_limits(route.route_id, credential_id, &grant.limits)
}

fn validate_limits(route_id: Uuid, credential_id: Uuid, limits: &McpLimitsConfig) -> Result<()> {
    if limits.max_concurrent_requests == 0
        || limits.max_concurrent_requests > MAX_CONCURRENT_REQUESTS
        || limits.requests_per_minute == 0
        || limits.requests_per_minute > MAX_REQUESTS_PER_MINUTE
        || limits.request_burst == 0
        || limits.request_burst > limits.requests_per_minute
    {
        return Err(config_error(format!(
            "MCP route {route_id} grant for credential {credential_id} has invalid limits"
        )));
    }
    Ok(())
}

fn validate_names(context: &str, names: &[String], maximum: usize) -> Result<()> {
    if names.len() > maximum {
        return Err(config_error(format!(
            "{context} list exceeds the {maximum}-entry limit"
        )));
    }
    let mut unique = HashSet::new();
    for name in names {
        if !unique.insert(name)
            || validate_name(context, name, 255).is_err()
            || name.contains("://")
            || name.starts_with('/')
        {
            return Err(config_error(format!(
                "{context} '{name}' is invalid, duplicate, or resource-like"
            )));
        }
    }
    Ok(())
}

fn validate_name(context: &str, value: &str, maximum: usize) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(config_error(format!(
            "{context} must contain 1 to {maximum} trimmed non-control bytes"
        )));
    }
    Ok(())
}

fn valid_method(method: &str) -> bool {
    !method.is_empty()
        && method.len() <= 255
        && !legacy_or_wrong_direction_method(method)
        && method.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        })
}

fn legacy_or_wrong_direction_method(method: &str) -> bool {
    matches!(
        method,
        "initialize"
            | "notifications/initialized"
            | "notifications/cancelled"
            | "ping"
            | "logging/setLevel"
            | "resources/subscribe"
            | "resources/unsubscribe"
            | "roots/list"
            | "sampling/createMessage"
            | "elicitation/create"
    )
}

fn validate_literal_path(path: &str) -> Result<()> {
    if path.is_empty()
        || path.len() > 1_024
        || !path.starts_with('/')
        || path.starts_with("//")
        || path.contains(['?', '#', '%', '*', '{', '}', '`'])
        || path.split('/').any(|segment| matches!(segment, "." | ".."))
        || path
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(config_error(
            "MCP service profile path must be one literal absolute path without wildcards, encoding, query, fragment, whitespace, or dot segments",
        ));
    }
    Ok(())
}

fn parse_bounded_duration(
    route_id: Uuid,
    field: &str,
    value: &str,
    maximum: Duration,
) -> Result<Duration> {
    let duration = crate::config::parse_service_duration(value).map_err(|error| {
        config_error(format!("MCP route {route_id} has invalid {field}: {error}"))
    })?;
    if duration > maximum {
        return Err(config_error(format!(
            "MCP route {route_id} {field} exceeds its bounded maximum"
        )));
    }
    Ok(duration)
}

fn validate_digest(context: &str, digest: &str) -> Result<()> {
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return Err(config_error(format!(
            "{context} digest must use sha256:<hex>"
        )));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(config_error(format!(
            "{context} digest must contain 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

fn validate_credential_prefix(prefix: &str) -> Result<()> {
    let Some(suffix) = prefix.strip_prefix("a3s_mcp_") else {
        return Err(config_error(
            "MCP credential prefix must start with 'a3s_mcp_'",
        ));
    };
    if suffix.len() < 8
        || suffix.len() > 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(config_error(
            "MCP credential prefix suffix must contain 8 to 32 lowercase ASCII letters or digits",
        ));
    }
    Ok(())
}

fn validate_argon2id_verifier(verifier_hash: &str) -> Result<()> {
    if verifier_hash.is_empty() || verifier_hash.len() > MAX_VERIFIER_BYTES {
        return Err(config_error(format!(
            "MCP credential verifier_hash must contain 1 to {MAX_VERIFIER_BYTES} bytes"
        )));
    }
    PasswordHash::new(verifier_hash)
        .map_err(|_| config_error("MCP credential verifier_hash is not a valid PHC string"))?;

    let parts = verifier_hash.split('$').collect::<Vec<_>>();
    if parts.len() != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
        return Err(config_error(
            "MCP credential verifier_hash must use Argon2id PHC version 19",
        ));
    }
    let mut memory = None;
    let mut iterations = None;
    let mut lanes = None;
    for parameter in parts[3].split(',') {
        let (name, value) = parameter.split_once('=').ok_or_else(|| {
            config_error("MCP credential verifier_hash has invalid Argon2id parameters")
        })?;
        let value = value.parse::<u32>().map_err(|_| {
            config_error("MCP credential verifier_hash has invalid Argon2id parameters")
        })?;
        match name {
            "m" if memory.replace(value).is_none() => {}
            "t" if iterations.replace(value).is_none() => {}
            "p" if lanes.replace(value).is_none() => {}
            _ => {
                return Err(config_error(
                    "MCP credential verifier_hash must contain exactly m, t, and p parameters",
                ));
            }
        }
    }
    let (Some(memory), Some(iterations), Some(lanes)) = (memory, iterations, lanes) else {
        return Err(config_error(
            "MCP credential verifier_hash must contain m, t, and p parameters",
        ));
    };
    if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&memory)
        || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&iterations)
        || !(1..=MAX_ARGON2_LANES).contains(&lanes)
        || !(MIN_ARGON2_SALT_ENCODED_LEN..=MAX_ARGON2_SALT_ENCODED_LEN).contains(&parts[4].len())
        || !(MIN_ARGON2_OUTPUT_ENCODED_LEN..=MAX_ARGON2_OUTPUT_ENCODED_LEN)
            .contains(&parts[5].len())
    {
        return Err(config_error(
            "MCP credential verifier_hash uses unsupported Argon2id cost, salt, or output bounds",
        ));
    }
    Ok(())
}

fn config_error(message: impl Into<String>) -> GatewayError {
    GatewayError::Config(message.into())
}
