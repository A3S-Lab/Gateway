//! Strict ACL parser for Cloud-managed inference policy.

use super::{bool_attr, children, config_error, type_error, u32_attr, u64_attr};
use crate::config::{
    InferenceConfig, InferenceCredentialConfig, InferenceEndpoint, InferenceGrantConfig,
    InferenceLimitsConfig, InferenceModelConfig, InferenceRouteConfig, InferenceTargetConfig,
};
use crate::error::Result;
use a3s_acl::{Block, Value};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;

pub(super) fn parse_inference_block(block: &Block) -> Result<InferenceConfig> {
    ensure_shape(
        block,
        "policy",
        0,
        &["expires_at"],
        &["credentials", "routes"],
    )?;
    let expires_at = required_timestamp_attr(block, "expires_at")?;

    let mut credentials = HashMap::new();
    let mut routes = HashMap::new();
    for child in &block.blocks {
        match child.name.as_str() {
            "credentials" => {
                let credential = parse_credential(child)?;
                if credentials
                    .insert(credential.credential_id, credential)
                    .is_some()
                {
                    return Err(config_error("Duplicate inference credential ID"));
                }
            }
            "routes" => {
                let route = parse_route(child)?;
                if routes.insert(route.route_id, route).is_some() {
                    return Err(config_error("Duplicate inference route ID"));
                }
            }
            _ => unreachable!("inference shape was validated"),
        }
    }

    Ok(InferenceConfig {
        expires_at,
        credentials,
        routes,
    })
}

fn parse_credential(block: &Block) -> Result<InferenceCredentialConfig> {
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
    Ok(InferenceCredentialConfig {
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

fn parse_route(block: &Block) -> Result<InferenceRouteConfig> {
    ensure_shape(
        block,
        "route",
        1,
        &["router", "environment_id", "policy_revision"],
        &["models", "grants"],
    )?;
    let route_id = uuid_label(block, "route")?;
    let mut models = HashMap::new();
    let mut grants = HashMap::new();
    for child in &block.blocks {
        match child.name.as_str() {
            "models" => {
                let (alias, model) = parse_model(child)?;
                if models.insert(alias.clone(), model).is_some() {
                    return Err(config_error(format!(
                        "Duplicate inference model alias '{alias}'"
                    )));
                }
            }
            "grants" => {
                let credential_id = uuid_label(child, "grant credential")?;
                let grant = parse_grant(child)?;
                if grants.insert(credential_id, grant).is_some() {
                    return Err(config_error(format!(
                        "Duplicate inference grant credential ID {credential_id}"
                    )));
                }
            }
            _ => unreachable!("inference route shape was validated"),
        }
    }

    Ok(InferenceRouteConfig {
        route_id,
        router: required_literal_string_attr(block, "router")?,
        environment_id: required_uuid_attr(block, "environment_id")?,
        policy_revision: required_u64_attr(block, "policy_revision")?,
        models,
        grants,
    })
}

fn parse_model(block: &Block) -> Result<(String, InferenceModelConfig)> {
    ensure_shape(block, "model", 1, &["model_id"], &["targets"])?;
    let alias = block.labels[0].clone();
    let mut targets = Vec::new();
    for target in &block.blocks {
        targets.push(parse_target(target)?);
    }
    Ok((
        alias,
        InferenceModelConfig {
            model_id: required_uuid_attr(block, "model_id")?,
            targets,
        },
    ))
}

fn parse_target(block: &Block) -> Result<InferenceTargetConfig> {
    ensure_shape(
        block,
        "target",
        1,
        &["service", "upstream_model", "priority", "weight"],
        &[],
    )?;
    Ok(InferenceTargetConfig {
        target_id: uuid_label(block, "target")?,
        service: required_literal_string_attr(block, "service")?,
        upstream_model: required_literal_string_attr(block, "upstream_model")?,
        priority: required_u32_attr(block, "priority")?,
        weight: required_u32_attr(block, "weight")?,
    })
}

fn parse_grant(block: &Block) -> Result<InferenceGrantConfig> {
    ensure_shape(
        block,
        "grant",
        1,
        &["credential_generation", "models", "endpoints"],
        &["limits"],
    )?;
    let limits = children(block, &["limits"]);
    if limits.len() != 1 {
        return Err(config_error(
            "Inference grant requires exactly one limits block",
        ));
    }
    let endpoints = required_literal_string_list_attr(block, "endpoints")?
        .into_iter()
        .map(|endpoint| InferenceEndpoint::from_str(&endpoint).map_err(config_error))
        .collect::<Result<Vec<_>>>()?;
    Ok(InferenceGrantConfig {
        credential_generation: required_u64_attr(block, "credential_generation")?,
        models: required_literal_string_list_attr(block, "models")?,
        endpoints,
        limits: parse_limits(limits[0])?,
    })
}

fn parse_limits(block: &Block) -> Result<InferenceLimitsConfig> {
    ensure_shape(
        block,
        "limits",
        0,
        &[
            "max_concurrent_requests",
            "requests_per_minute",
            "request_burst",
            "tokens_per_minute",
        ],
        &[],
    )?;
    Ok(InferenceLimitsConfig {
        max_concurrent_requests: required_u64_attr(block, "max_concurrent_requests")?,
        requests_per_minute: required_u64_attr(block, "requests_per_minute")?,
        request_burst: required_u64_attr(block, "request_burst")?,
        tokens_per_minute: required_u64_attr(block, "tokens_per_minute")?,
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
            "Inference {context} block requires exactly {label_count} label(s)"
        )));
    }
    for attribute in block.attributes.keys() {
        if !allowed_attributes.contains(&attribute.as_str()) {
            return Err(config_error(format!(
                "Unknown inference {context} field '{attribute}'"
            )));
        }
    }
    for child in &block.blocks {
        if !allowed_blocks.contains(&child.name.as_str()) {
            return Err(config_error(format!(
                "Unknown inference {context} block '{}'",
                child.name
            )));
        }
    }
    Ok(())
}

fn uuid_label(block: &Block, context: &str) -> Result<Uuid> {
    Uuid::parse_str(&block.labels[0]).map_err(|error| {
        config_error(format!(
            "Invalid inference {context} ID '{}': {error}",
            block.labels[0]
        ))
    })
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
        .map_err(|error| config_error(format!("Invalid inference {key} '{value}': {error}")))
}

fn required_timestamp_attr(block: &Block, key: &str) -> Result<DateTime<Utc>> {
    let value = required_literal_string_attr(block, key)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|timestamp| timestamp.with_timezone(&Utc))
        .map_err(|error| config_error(format!("Invalid inference {key} '{value}': {error}")))
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
