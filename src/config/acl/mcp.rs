//! Strict ACL parser for hosted modern MCP profiles and route policy.

use super::{bool_attr, children, config_error, type_error, u32_attr, u64_attr};
use crate::config::{
    McpConfig, McpCredentialConfig, McpGrantConfig, McpLimitsConfig, McpRouteConfig,
    McpServiceProfileConfig, McpTargetConfig,
};
use crate::error::Result;
use a3s_acl::{Block, Value};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;

pub(super) fn parse_mcp_block(block: &Block) -> Result<McpConfig> {
    ensure_shape(
        block,
        "policy",
        0,
        &["expires_at"],
        &["profiles", "credentials", "routes"],
    )?;
    let expires_at = required_timestamp_attr(block, "expires_at")?;
    let mut profiles = HashMap::new();
    let mut credentials = HashMap::new();
    let mut routes = HashMap::new();

    for child in &block.blocks {
        match child.name.as_str() {
            "profiles" => {
                let profile = parse_profile(child)?;
                if profiles
                    .insert(profile.profile_digest.clone(), profile)
                    .is_some()
                {
                    return Err(config_error("Duplicate MCP service profile digest"));
                }
            }
            "credentials" => {
                let credential = parse_credential(child)?;
                if credentials
                    .insert(credential.credential_id, credential)
                    .is_some()
                {
                    return Err(config_error("Duplicate MCP credential ID"));
                }
            }
            "routes" => {
                let route = parse_route(child)?;
                if routes.insert(route.route_id, route).is_some() {
                    return Err(config_error("Duplicate MCP route ID"));
                }
            }
            _ => unreachable!("MCP policy shape was validated"),
        }
    }

    Ok(McpConfig {
        expires_at,
        profiles,
        credentials,
        routes,
    })
}

fn parse_profile(block: &Block) -> Result<McpServiceProfileConfig> {
    ensure_shape(
        block,
        "service profile",
        1,
        &[
            "protocol_versions",
            "path",
            "request_sse",
            "subscriptions",
            "max_request_bytes",
            "max_response_bytes",
        ],
        &[],
    )?;
    Ok(McpServiceProfileConfig {
        profile_digest: single_label(block, "service profile")?.to_string(),
        protocol_versions: required_literal_string_list_attr(block, "protocol_versions")?,
        path: required_literal_string_attr(block, "path")?,
        request_sse: required_bool_attr(block, "request_sse")?,
        subscriptions: required_bool_attr(block, "subscriptions")?,
        max_request_bytes: required_u64_attr(block, "max_request_bytes")?,
        max_response_bytes: required_u64_attr(block, "max_response_bytes")?,
    })
}

fn parse_credential(block: &Block) -> Result<McpCredentialConfig> {
    ensure_shape(
        block,
        "credential",
        1,
        &[
            "environment_id",
            "audience",
            "prefix",
            "verifier_hash",
            "generation",
            "expires_at",
            "revoked",
        ],
        &[],
    )?;
    Ok(McpCredentialConfig {
        credential_id: uuid_label(block, "credential")?,
        environment_id: required_uuid_attr(block, "environment_id")?,
        audience: required_literal_string_attr(block, "audience")?,
        prefix: required_literal_string_attr(block, "prefix")?,
        verifier_hash: required_literal_string_attr(block, "verifier_hash")?,
        generation: required_u64_attr(block, "generation")?,
        expires_at: required_timestamp_attr(block, "expires_at")?,
        revoked: required_bool_attr(block, "revoked")?,
    })
}

fn parse_route(block: &Block) -> Result<McpRouteConfig> {
    ensure_shape(
        block,
        "route",
        1,
        &[
            "router",
            "environment_id",
            "policy_revision",
            "profile_digest",
            "allowed_origins",
            "max_header_bytes",
            "max_request_bytes",
            "max_response_bytes",
            "first_response_timeout",
            "stream_idle_timeout",
            "stream_total_timeout",
            "drain_timeout",
            "telemetry_names",
        ],
        &["targets", "grants"],
    )?;
    let route_id = uuid_label(block, "route")?;
    let mut targets = Vec::new();
    let mut grants = HashMap::new();
    for child in &block.blocks {
        match child.name.as_str() {
            "targets" => targets.push(parse_target(child)?),
            "grants" => {
                let credential_id = uuid_label(child, "grant credential")?;
                let grant = parse_grant(child)?;
                if grants.insert(credential_id, grant).is_some() {
                    return Err(config_error(format!(
                        "Duplicate MCP grant credential ID {credential_id}"
                    )));
                }
            }
            _ => unreachable!("MCP route shape was validated"),
        }
    }

    Ok(McpRouteConfig {
        route_id,
        router: required_literal_string_attr(block, "router")?,
        environment_id: required_uuid_attr(block, "environment_id")?,
        policy_revision: required_u64_attr(block, "policy_revision")?,
        profile_digest: required_literal_string_attr(block, "profile_digest")?,
        allowed_origins: required_literal_string_list_attr(block, "allowed_origins")?,
        max_header_bytes: required_u64_attr(block, "max_header_bytes")?,
        max_request_bytes: required_u64_attr(block, "max_request_bytes")?,
        max_response_bytes: required_u64_attr(block, "max_response_bytes")?,
        first_response_timeout: required_literal_string_attr(block, "first_response_timeout")?,
        stream_idle_timeout: required_literal_string_attr(block, "stream_idle_timeout")?,
        stream_total_timeout: required_literal_string_attr(block, "stream_total_timeout")?,
        drain_timeout: required_literal_string_attr(block, "drain_timeout")?,
        telemetry_names: required_literal_string_list_attr(block, "telemetry_names")?,
        targets,
        grants,
    })
}

fn parse_target(block: &Block) -> Result<McpTargetConfig> {
    ensure_shape(
        block,
        "target",
        1,
        &[
            "node_id",
            "asset_release_id",
            "unit_id",
            "generation",
            "service",
            "endpoint",
            "profile_digest",
            "priority",
            "weight",
        ],
        &[],
    )?;
    Ok(McpTargetConfig {
        target_id: uuid_label(block, "target")?,
        node_id: required_uuid_attr(block, "node_id")?,
        asset_release_id: required_uuid_attr(block, "asset_release_id")?,
        unit_id: required_literal_string_attr(block, "unit_id")?,
        generation: required_u64_attr(block, "generation")?,
        service: required_literal_string_attr(block, "service")?,
        endpoint: required_literal_string_attr(block, "endpoint")?,
        profile_digest: required_literal_string_attr(block, "profile_digest")?,
        priority: required_u32_attr(block, "priority")?,
        weight: required_u32_attr(block, "weight")?,
    })
}

fn parse_grant(block: &Block) -> Result<McpGrantConfig> {
    ensure_shape(
        block,
        "grant",
        1,
        &["credential_generation", "methods", "names"],
        &["limits"],
    )?;
    let limits = children(block, &["limits"]);
    if limits.len() != 1 {
        return Err(config_error("MCP grant requires exactly one limits block"));
    }
    Ok(McpGrantConfig {
        credential_generation: required_u64_attr(block, "credential_generation")?,
        methods: required_literal_string_list_attr(block, "methods")?,
        names: required_literal_string_list_attr(block, "names")?,
        limits: parse_limits(limits[0])?,
    })
}

fn parse_limits(block: &Block) -> Result<McpLimitsConfig> {
    ensure_shape(
        block,
        "limits",
        0,
        &[
            "max_concurrent_requests",
            "requests_per_minute",
            "request_burst",
        ],
        &[],
    )?;
    Ok(McpLimitsConfig {
        max_concurrent_requests: required_u64_attr(block, "max_concurrent_requests")?,
        requests_per_minute: required_u64_attr(block, "requests_per_minute")?,
        request_burst: required_u64_attr(block, "request_burst")?,
    })
}

fn ensure_shape(
    block: &Block,
    context: &str,
    label_count: usize,
    allowed_attributes: &[&str],
    allowed_blocks: &[&str],
) -> Result<()> {
    if block.labels.len() != label_count {
        return Err(config_error(format!(
            "MCP {context} block requires exactly {label_count} label(s)"
        )));
    }
    for attribute in block.attributes.keys() {
        if !allowed_attributes.contains(&attribute.as_str()) {
            return Err(config_error(format!(
                "Unknown MCP {context} field '{attribute}'"
            )));
        }
    }
    for child in &block.blocks {
        if !allowed_blocks.contains(&child.name.as_str()) {
            return Err(config_error(format!(
                "Unknown MCP {context} block '{}'",
                child.name
            )));
        }
    }
    Ok(())
}

fn single_label<'a>(block: &'a Block, context: &str) -> Result<&'a str> {
    block
        .labels
        .first()
        .map(String::as_str)
        .ok_or_else(|| config_error(format!("MCP {context} block requires exactly one label")))
}

fn uuid_label(block: &Block, context: &str) -> Result<Uuid> {
    let label = single_label(block, context)?;
    Uuid::parse_str(label)
        .map_err(|error| config_error(format!("Invalid MCP {context} ID '{label}': {error}")))
}

fn required_literal_string_attr(block: &Block, key: &str) -> Result<String> {
    match block.attributes.get(key) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(_) => Err(type_error(key, "literal string")),
        None => Err(config_error(format!("{} block requires {key}", block.name))),
    }
}

fn required_literal_string_list_attr(block: &Block, key: &str) -> Result<Vec<String>> {
    match block.attributes.get(key) {
        Some(Value::List(values)) => values
            .iter()
            .map(|value| match value {
                Value::String(value) => Ok(value.clone()),
                _ => Err(type_error(key, "list of literal strings")),
            })
            .collect(),
        Some(Value::String(value)) => Ok(vec![value.clone()]),
        Some(_) => Err(type_error(key, "list of literal strings")),
        None => Err(config_error(format!("{} block requires {key}", block.name))),
    }
}

fn required_uuid_attr(block: &Block, key: &str) -> Result<Uuid> {
    let value = required_literal_string_attr(block, key)?;
    Uuid::parse_str(&value)
        .map_err(|error| config_error(format!("Invalid MCP {key} '{value}': {error}")))
}

fn required_timestamp_attr(block: &Block, key: &str) -> Result<DateTime<Utc>> {
    let value = required_literal_string_attr(block, key)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| config_error(format!("Invalid MCP {key} '{value}': {error}")))
}

fn required_bool_attr(block: &Block, key: &str) -> Result<bool> {
    bool_attr(block, &[key])?
        .ok_or_else(|| config_error(format!("{} block requires {key}", block.name)))
}

fn required_u32_attr(block: &Block, key: &str) -> Result<u32> {
    u32_attr(block, &[key])?
        .ok_or_else(|| config_error(format!("{} block requires {key}", block.name)))
}

fn required_u64_attr(block: &Block, key: &str) -> Result<u64> {
    u64_attr(block, &[key])?
        .ok_or_else(|| config_error(format!("{} block requires {key}", block.name)))
}
