//! ACL configuration parser for A3S Gateway.

use super::{
    default_management_allowed_ips, default_shutdown_timeout, DiscoveryConfig, DiscoverySeedConfig,
    DockerProviderConfig, EntrypointConfig, FailoverConfig, FileProviderConfig, GatewayConfig,
    HealthCheckConfig, KubernetesProviderConfig, LoadBalancerConfig, ManagementConfig,
    ManagementTlsConfig, MiddlewareConfig, MirrorConfig, Protocol, ProviderConfig, RevisionConfig,
    RolloutConfig, ScalingConfig, ServerConfig, ServiceConfig, StickyConfig, Strategy, TlsConfig,
};
use crate::error::{GatewayError, Result};
use a3s_acl::{parse_acl, Block, Value};
use std::collections::HashMap;
use std::path::Path;

pub(crate) fn parse_gateway_config(content: &str) -> Result<GatewayConfig> {
    let doc = parse_acl(content)
        .map_err(|e| GatewayError::Config(format!("Failed to parse ACL config: {}", e)))?;

    let mut config = GatewayConfig {
        entrypoints: HashMap::new(),
        routers: HashMap::new(),
        services: HashMap::new(),
        middlewares: HashMap::new(),
        providers: ProviderConfig::default(),
        management: ManagementConfig::default(),
        shutdown_timeout_secs: default_shutdown_timeout(),
    };

    for block in &doc.blocks {
        match block.name.as_str() {
            "entrypoint" | "entrypoints" => {
                let name = label_or_string_attr(block, &["name"])?;
                config
                    .entrypoints
                    .insert(name, parse_entrypoint_block(block)?);
            }
            "router" | "routers" => {
                let name = label_or_string_attr(block, &["name"])?;
                config.routers.insert(name, parse_router_block(block)?);
            }
            "service" | "services" => {
                let name = label_or_string_attr(block, &["name"])?;
                config.services.insert(name, parse_service_block(block)?);
            }
            "middleware" | "middlewares" => {
                let name = label_or_string_attr(block, &["name"])?;
                config
                    .middlewares
                    .insert(name, parse_middleware_block(block)?);
            }
            "providers" => {
                config.providers = parse_providers_block(block)?;
            }
            "management" => {
                config.management = parse_management_block(block)?;
            }
            "shutdown_timeout_secs" => {
                if let Some(value) = u64_attr(block, &["shutdown_timeout_secs"])? {
                    config.shutdown_timeout_secs = value;
                }
            }
            other => {
                return Err(config_error(format!(
                    "Unknown top-level ACL block '{}'",
                    other
                )));
            }
        }
    }

    Ok(config)
}

pub(crate) fn ensure_acl_path(path: &Path) -> Result<()> {
    if path.extension().is_none_or(|ext| ext != "acl") {
        return Err(config_error("Gateway config files must use .acl extension"));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn parse_entrypoint_body(content: &str) -> Result<EntrypointConfig> {
    let block = parse_single_block("entrypoints", "test", content)?;
    parse_entrypoint_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_tls_body(content: &str) -> Result<TlsConfig> {
    let block = parse_single_block("tls", "test", content)?;
    parse_tls_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_middleware_body(content: &str) -> Result<MiddlewareConfig> {
    let block = parse_single_block("middlewares", "test", content)?;
    parse_middleware_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_router_body(content: &str) -> Result<super::RouterConfig> {
    let block = parse_single_block("routers", "test", content)?;
    parse_router_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_service_body(content: &str) -> Result<ServiceConfig> {
    let block = parse_single_block("services", "test", content)?;
    parse_service_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_server_body(content: &str) -> Result<ServerConfig> {
    let block = parse_single_block("servers", "test", content)?;
    parse_server_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_health_check_body(content: &str) -> Result<HealthCheckConfig> {
    let block = parse_single_block("health_check", "test", content)?;
    parse_health_check_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_mirror_body(content: &str) -> Result<MirrorConfig> {
    let block = parse_single_block("mirror", "test", content)?;
    parse_mirror_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_failover_body(content: &str) -> Result<FailoverConfig> {
    let block = parse_single_block("failover", "test", content)?;
    parse_failover_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_scaling_body(content: &str) -> Result<ScalingConfig> {
    let block = parse_single_block("scaling", "test", content)?;
    parse_scaling_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_revision_body(content: &str) -> Result<RevisionConfig> {
    let wrapped = format!("revisions {{\n{content}\n}}\n");
    let doc = parse_acl(&wrapped)
        .map_err(|e| GatewayError::Config(format!("Failed to parse ACL config: {}", e)))?;
    let block = doc
        .blocks
        .into_iter()
        .next()
        .ok_or_else(|| config_error("ACL parser produced an empty document"))?;
    parse_revision_block(&block)
}

#[cfg(test)]
pub(crate) fn parse_rollout_body(content: &str) -> Result<RolloutConfig> {
    let block = parse_single_block("rollout", "test", content)?;
    parse_rollout_block(&block)
}

#[cfg(test)]
fn parse_single_block(kind: &str, label: &str, content: &str) -> Result<Block> {
    let wrapped = format!("{kind} \"{label}\" {{\n{content}\n}}\n");
    let doc = parse_acl(&wrapped)
        .map_err(|e| GatewayError::Config(format!("Failed to parse ACL config: {}", e)))?;
    doc.blocks
        .into_iter()
        .next()
        .ok_or_else(|| config_error("ACL parser produced an empty document"))
}

fn parse_entrypoint_block(block: &Block) -> Result<EntrypointConfig> {
    let protocol = match string_attr(block, &["protocol"])? {
        Some(value) => match value.as_str() {
            "http" => Protocol::Http,
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => {
                return Err(config_error(format!(
                    "Invalid entrypoint protocol '{}'",
                    other
                )))
            }
        },
        None => Protocol::Http,
    };

    Ok(EntrypointConfig {
        address: required_string_attr(block, &["address"])?,
        protocol,
        tls: child(block, "tls").map(parse_tls_block).transpose()?,
        max_connections: u32_attr(block, &["max_connections"])?,
        tcp_allowed_ips: string_list_attr(block, &["tcp_allowed_ips"])?,
        udp_session_timeout_secs: u64_attr(block, &["udp_session_timeout_secs"])?,
        udp_max_sessions: usize_attr(block, &["udp_max_sessions"])?,
    })
}

fn parse_tls_block(block: &Block) -> Result<TlsConfig> {
    Ok(TlsConfig {
        cert_file: string_attr(block, &["cert_file"])?.unwrap_or_default(),
        key_file: string_attr(block, &["key_file"])?.unwrap_or_default(),
        acme: bool_attr(block, &["acme"])?.unwrap_or(false),
        min_version: string_attr(block, &["min_version"])?.unwrap_or_else(|| "1.2".to_string()),
        acme_email: string_attr(block, &["acme_email"])?,
        acme_domains: string_list_attr(block, &["acme_domains"])?,
        acme_staging: bool_attr(block, &["acme_staging"])?.unwrap_or(false),
        acme_storage_path: string_attr(block, &["acme_storage_path"])?,
    })
}

fn parse_router_block(block: &Block) -> Result<super::RouterConfig> {
    Ok(super::RouterConfig {
        rule: required_string_attr(block, &["rule"])?,
        service: required_string_attr(block, &["service"])?,
        entrypoints: string_list_attr(block, &["entrypoints"])?,
        middlewares: string_list_attr(block, &["middlewares"])?,
        priority: i32_attr(block, &["priority"])?.unwrap_or(0),
    })
}

fn parse_service_block(block: &Block) -> Result<ServiceConfig> {
    let load_balancer = match child(block, "load_balancer") {
        Some(lb) => parse_load_balancer_block(lb)?,
        None => LoadBalancerConfig {
            strategy: Strategy::RoundRobin,
            request_timeout: "30s".to_string(),
            servers: vec![],
            health_check: None,
            sticky: None,
        },
    };

    Ok(ServiceConfig {
        load_balancer,
        scaling: child(block, "scaling")
            .map(parse_scaling_block)
            .transpose()?,
        revisions: parse_revisions(block)?,
        rollout: child(block, "rollout")
            .map(parse_rollout_block)
            .transpose()?,
        mirror: child(block, "mirror").map(parse_mirror_block).transpose()?,
        failover: child(block, "failover")
            .map(parse_failover_block)
            .transpose()?,
    })
}

fn parse_load_balancer_block(block: &Block) -> Result<LoadBalancerConfig> {
    let strategy = match string_attr(block, &["strategy"])? {
        Some(value) => parse_strategy(&value)?,
        None => Strategy::RoundRobin,
    };

    Ok(LoadBalancerConfig {
        strategy,
        request_timeout: string_attr(block, &["request_timeout"])?
            .unwrap_or_else(|| "30s".to_string()),
        servers: parse_servers(block)?,
        health_check: child(block, "health_check")
            .map(parse_health_check_block)
            .transpose()?,
        sticky: child(block, "sticky").map(parse_sticky_block).transpose()?,
    })
}

fn parse_server_block(block: &Block) -> Result<ServerConfig> {
    Ok(ServerConfig {
        url: required_string_attr(block, &["url"])?,
        weight: u32_attr(block, &["weight"])?.unwrap_or(1),
    })
}

fn parse_server_value(value: &Value) -> Result<ServerConfig> {
    let fields = object_fields(value, "servers item")?;
    Ok(ServerConfig {
        url: required_object_string_attr(fields, &["url"])?,
        weight: object_u32_attr(fields, &["weight"])?.unwrap_or(1),
    })
}

fn parse_health_check_block(block: &Block) -> Result<HealthCheckConfig> {
    Ok(HealthCheckConfig {
        path: required_string_attr(block, &["path"])?,
        interval: string_attr(block, &["interval"])?.unwrap_or_else(|| "10s".to_string()),
        timeout: string_attr(block, &["timeout"])?.unwrap_or_else(|| "5s".to_string()),
        unhealthy_threshold: u32_attr(block, &["unhealthy_threshold"])?.unwrap_or(3),
        healthy_threshold: u32_attr(block, &["healthy_threshold"])?.unwrap_or(1),
    })
}

fn parse_sticky_block(block: &Block) -> Result<StickyConfig> {
    Ok(StickyConfig {
        cookie: required_string_attr(block, &["cookie"])?,
    })
}

fn parse_mirror_block(block: &Block) -> Result<MirrorConfig> {
    Ok(MirrorConfig {
        service: required_string_attr(block, &["service"])?,
        percentage: u8_attr(block, &["percentage"])?.unwrap_or(100),
    })
}

fn parse_failover_block(block: &Block) -> Result<FailoverConfig> {
    Ok(FailoverConfig {
        service: required_string_attr(block, &["service"])?,
    })
}

fn parse_scaling_block(block: &Block) -> Result<ScalingConfig> {
    let mut config = ScalingConfig::default();
    if let Some(value) = u32_attr(block, &["min_replicas"])? {
        config.min_replicas = value;
    }
    if let Some(value) = u32_attr(block, &["max_replicas"])? {
        config.max_replicas = value;
    }
    if let Some(value) = u32_attr(block, &["container_concurrency"])? {
        config.container_concurrency = value;
    }
    if let Some(value) = f64_attr(block, &["target_utilization"])? {
        config.target_utilization = value;
    }
    if let Some(value) = u64_attr(block, &["scale_down_delay_secs"])? {
        config.scale_down_delay_secs = value;
    }
    if let Some(value) = u64_attr(block, &["buffer_timeout_secs"])? {
        config.buffer_timeout_secs = value;
    }
    if let Some(value) = usize_attr(block, &["buffer_size"])? {
        config.buffer_size = value;
    }
    if let Some(value) = bool_attr(block, &["buffer_enabled"])? {
        config.buffer_enabled = value;
    }
    if let Some(value) = string_attr(block, &["executor"])? {
        config.executor = value;
    }
    Ok(config)
}

fn parse_revisions(block: &Block) -> Result<Vec<RevisionConfig>> {
    let mut revisions = Vec::new();

    if let Some(value) = attr(block, &["revisions"]) {
        match value {
            Value::List(items) => {
                for item in items {
                    revisions.push(parse_revision_value(item)?);
                }
            }
            Value::Object(_) => revisions.push(parse_revision_value(value)?),
            _ => return Err(config_error("revisions must be a list of objects")),
        }
    }

    for child in children(block, &["revision", "revisions"]) {
        revisions.push(parse_revision_block(child)?);
    }

    Ok(revisions)
}

fn parse_revision_block(block: &Block) -> Result<RevisionConfig> {
    let name = match block.labels.first() {
        Some(label) => label.clone(),
        None => string_attr(block, &["name"])?
            .ok_or_else(|| config_error("revision block requires a label or name attribute"))?,
    };

    let strategy = match string_attr(block, &["strategy"])? {
        Some(value) => parse_strategy(&value)?,
        None => Strategy::RoundRobin,
    };

    Ok(RevisionConfig {
        name,
        traffic_percent: u32_attr(block, &["traffic_percent"])?.unwrap_or(100),
        servers: parse_servers(block)?,
        strategy,
    })
}

fn parse_revision_value(value: &Value) -> Result<RevisionConfig> {
    let fields = object_fields(value, "revisions item")?;
    let strategy = match object_string_attr(fields, &["strategy"])? {
        Some(value) => parse_strategy(&value)?,
        None => Strategy::RoundRobin,
    };
    Ok(RevisionConfig {
        name: required_object_string_attr(fields, &["name"])?,
        traffic_percent: object_u32_attr(fields, &["traffic_percent"])?.unwrap_or(100),
        servers: object_servers(fields)?,
        strategy,
    })
}

fn parse_rollout_block(block: &Block) -> Result<RolloutConfig> {
    Ok(RolloutConfig {
        from: required_string_attr(block, &["from"])?,
        to: required_string_attr(block, &["to"])?,
        step_percent: u32_attr(block, &["step_percent"])?.unwrap_or(10),
        step_interval_secs: u64_attr(block, &["step_interval_secs"])?.unwrap_or(60),
        error_rate_threshold: f64_attr(block, &["error_rate_threshold"])?.unwrap_or(0.05),
        latency_threshold_ms: u64_attr(block, &["latency_threshold_ms"])?.unwrap_or(5000),
    })
}

fn parse_middleware_block(block: &Block) -> Result<MiddlewareConfig> {
    Ok(MiddlewareConfig {
        middleware_type: required_string_attr(block, &["type"])?,
        header: string_attr(block, &["header"])?,
        keys: string_list_attr(block, &["keys"])?,
        value: string_attr(block, &["value"])?,
        username: string_attr(block, &["username"])?,
        password: string_attr(block, &["password"])?,
        rate: u64_attr(block, &["rate"])?,
        burst: u64_attr(block, &["burst"])?,
        allowed_origins: string_list_attr(block, &["allowed_origins"])?,
        allowed_methods: string_list_attr(block, &["allowed_methods"])?,
        allowed_headers: string_list_attr(block, &["allowed_headers"])?,
        max_age: u64_attr(block, &["max_age"])?,
        request_headers: string_map_attr(block, "request_headers")?,
        response_headers: string_map_attr(block, "response_headers")?,
        prefixes: string_list_attr(block, &["prefixes"])?,
        max_retries: u32_attr(block, &["max_retries"])?,
        retry_interval_ms: u64_attr(block, &["retry_interval_ms"])?,
        allowed_ips: string_list_attr(block, &["allowed_ips"])?,
        forward_auth_url: string_attr(block, &["forward_auth_url"])?,
        forward_auth_response_headers: string_list_attr(block, &["forward_auth_response_headers"])?,
        redis_url: string_attr(block, &["redis_url"])?,
        max_body_bytes: u64_attr(block, &["max_body_bytes"])?,
        failure_threshold: u32_attr(block, &["failure_threshold"])?,
        cooldown_secs: u64_attr(block, &["cooldown_secs"])?,
        success_threshold: u32_attr(block, &["success_threshold"])?,
    })
}

fn parse_providers_block(block: &Block) -> Result<ProviderConfig> {
    let mut providers = ProviderConfig::default();
    for child in &block.blocks {
        match child.name.as_str() {
            "file" => providers.file = Some(parse_file_provider_block(child)?),
            "discovery" => providers.discovery = Some(parse_discovery_block(child)?),
            "kubernetes" => providers.kubernetes = Some(parse_kubernetes_block(child)?),
            "docker" => providers.docker = Some(parse_docker_block(child)?),
            other => {
                return Err(config_error(format!(
                    "Unknown providers ACL block '{}'",
                    other
                )));
            }
        }
    }
    Ok(providers)
}

fn parse_management_block(block: &Block) -> Result<ManagementConfig> {
    let auth_token_env = match string_attr(block, &["auth_token_env"])? {
        Some(value) if value.is_empty() => None,
        Some(value) => Some(value),
        None => Some("A3S_GATEWAY_ADMIN_TOKEN".to_string()),
    };

    Ok(ManagementConfig {
        enabled: bool_attr(block, &["enabled"])?.unwrap_or(false),
        address: string_attr(block, &["address"])?.unwrap_or_else(|| "127.0.0.1:9090".to_string()),
        path_prefix: string_attr(block, &["path_prefix"])?
            .unwrap_or_else(|| "/api/gateway".to_string()),
        auth_token_env,
        allowed_ips: if attr(block, &["allowed_ips"]).is_some() {
            string_list_attr(block, &["allowed_ips"])?
        } else {
            default_management_allowed_ips()
        },
        tls: child(block, "tls")
            .map(parse_management_tls_block)
            .transpose()?,
    })
}

fn parse_management_tls_block(block: &Block) -> Result<ManagementTlsConfig> {
    Ok(ManagementTlsConfig {
        cert_file: required_string_attr(block, &["cert_file"])?,
        key_file: required_string_attr(block, &["key_file"])?,
        client_ca_file: string_attr(block, &["client_ca_file"])?,
        require_client_cert: bool_attr(block, &["require_client_cert"])?.unwrap_or(false),
        min_version: string_attr(block, &["min_version"])?.unwrap_or_else(|| "1.2".to_string()),
    })
}

fn parse_file_provider_block(block: &Block) -> Result<FileProviderConfig> {
    Ok(FileProviderConfig {
        watch: bool_attr(block, &["watch"])?.unwrap_or(true),
        directory: string_attr(block, &["directory"])?,
    })
}

fn parse_discovery_block(block: &Block) -> Result<DiscoveryConfig> {
    let mut seeds = Vec::new();
    if let Some(value) = attr(block, &["seeds"]) {
        match value {
            Value::List(items) => {
                for item in items {
                    let fields = object_fields(item, "seeds item")?;
                    seeds.push(DiscoverySeedConfig {
                        url: required_object_string_attr(fields, &["url"])?,
                    });
                }
            }
            Value::Object(fields) => seeds.push(DiscoverySeedConfig {
                url: required_object_string_attr(fields, &["url"])?,
            }),
            _ => return Err(config_error("seeds must be a list of objects")),
        }
    }
    for seed in children(block, &["seed", "seeds"]) {
        seeds.push(DiscoverySeedConfig {
            url: required_string_attr(seed, &["url"])?,
        });
    }

    Ok(DiscoveryConfig {
        seeds,
        poll_interval_secs: u64_attr(block, &["poll_interval_secs"])?.unwrap_or(30),
        timeout_secs: u64_attr(block, &["timeout_secs"])?.unwrap_or(5),
    })
}

fn parse_kubernetes_block(block: &Block) -> Result<KubernetesProviderConfig> {
    Ok(KubernetesProviderConfig {
        namespace: string_attr(block, &["namespace"])?.unwrap_or_default(),
        label_selector: string_attr(block, &["label_selector"])?.unwrap_or_default(),
        watch_interval_secs: u64_attr(block, &["watch_interval_secs"])?.unwrap_or(30),
        ingress_route_crd: bool_attr(block, &["ingress_route_crd"])?.unwrap_or(false),
    })
}

fn parse_docker_block(block: &Block) -> Result<DockerProviderConfig> {
    Ok(DockerProviderConfig {
        host: string_attr(block, &["host"])?.unwrap_or_else(|| "/var/run/docker.sock".to_string()),
        label_prefix: string_attr(block, &["label_prefix"])?.unwrap_or_else(|| "a3s".to_string()),
        poll_interval_secs: u64_attr(block, &["poll_interval_secs"])?.unwrap_or(10),
    })
}

fn parse_servers(block: &Block) -> Result<Vec<ServerConfig>> {
    let mut servers = Vec::new();

    if let Some(value) = attr(block, &["servers"]) {
        match value {
            Value::List(items) => {
                for item in items {
                    servers.push(parse_server_value(item)?);
                }
            }
            Value::Object(_) => servers.push(parse_server_value(value)?),
            _ => return Err(config_error("servers must be a list of objects")),
        }
    }

    for child in children(block, &["server", "servers"]) {
        servers.push(parse_server_block(child)?);
    }

    Ok(servers)
}

fn object_servers(fields: &[(String, Value)]) -> Result<Vec<ServerConfig>> {
    match object_attr(fields, &["servers"]) {
        Some(Value::List(items)) => items.iter().map(parse_server_value).collect(),
        Some(Value::Object(_)) => object_attr(fields, &["servers"])
            .map(parse_server_value)
            .transpose()?
            .map(|server| vec![server])
            .ok_or_else(|| config_error("servers object is missing")),
        Some(_) => Err(config_error("servers must be a list of objects")),
        None => Ok(vec![]),
    }
}

fn string_map_attr(block: &Block, key: &str) -> Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    if let Some(value) = attr(block, &[key]) {
        match value {
            Value::Object(fields) => {
                for (field_key, field_value) in fields {
                    map.insert(field_key.clone(), value_to_string(field_value, field_key)?);
                }
            }
            Value::List(items) => {
                for item in items {
                    let fields = object_fields(item, key)?;
                    let name = required_object_string_attr(fields, &["name", "key", "header"])?;
                    let value = required_object_string_attr(fields, &["value"])?;
                    map.insert(name, value);
                }
            }
            _ => return Err(config_error(format!("{} must be an object or list", key))),
        }
    }

    for group in children(block, &[key]) {
        for item in &group.blocks {
            let name = match item.labels.first() {
                Some(label) => label.clone(),
                None => string_attr(item, &["name", "key", "header"])?
                    .ok_or_else(|| config_error(format!("{} item requires a name", key)))?,
            };
            let value = required_string_attr(item, &["value"])?;
            map.insert(name, value);
        }
    }

    Ok(map)
}

fn parse_strategy(value: &str) -> Result<Strategy> {
    value
        .parse::<Strategy>()
        .map_err(|e| config_error(format!("Invalid strategy '{}': {}", value, e)))
}

fn child<'a>(block: &'a Block, name: &str) -> Option<&'a Block> {
    block.blocks.iter().find(|child| child.name == name)
}

fn children<'a>(block: &'a Block, names: &[&str]) -> Vec<&'a Block> {
    block
        .blocks
        .iter()
        .filter(|child| names.iter().any(|name| child.name == *name))
        .collect()
}

fn attr<'a>(block: &'a Block, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| block.attributes.get(*key))
}

fn object_attr<'a>(fields: &'a [(String, Value)], keys: &[&str]) -> Option<&'a Value> {
    keys.iter().find_map(|key| {
        fields
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    })
}

fn label_or_string_attr(block: &Block, keys: &[&str]) -> Result<String> {
    match block.labels.first() {
        Some(label) => Ok(label.clone()),
        None => string_attr(block, keys)?.ok_or_else(|| {
            config_error(format!(
                "{} block requires a label or {} attribute",
                block.name,
                keys.join("/")
            ))
        }),
    }
}

fn required_string_attr(block: &Block, keys: &[&str]) -> Result<String> {
    string_attr(block, keys)?
        .ok_or_else(|| config_error(format!("{} block requires {}", block.name, keys.join("/"))))
}

fn string_attr(block: &Block, keys: &[&str]) -> Result<Option<String>> {
    attr(block, keys)
        .map(|value| value_to_string(value, keys[0]))
        .transpose()
}

fn string_list_attr(block: &Block, keys: &[&str]) -> Result<Vec<String>> {
    match attr(block, keys) {
        Some(Value::List(items)) => items
            .iter()
            .map(|value| value_to_string(value, keys[0]))
            .collect(),
        Some(value) => Ok(vec![value_to_string(value, keys[0])?]),
        None => Ok(vec![]),
    }
}

fn bool_attr(block: &Block, keys: &[&str]) -> Result<Option<bool>> {
    attr(block, keys)
        .map(|value| match value {
            Value::Bool(value) => Ok(*value),
            _ => Err(type_error(keys[0], "boolean")),
        })
        .transpose()
}

fn f64_attr(block: &Block, keys: &[&str]) -> Result<Option<f64>> {
    attr(block, keys)
        .map(|value| match value {
            Value::Number(value) => Ok(*value),
            _ => Err(type_error(keys[0], "number")),
        })
        .transpose()
}

fn i32_attr(block: &Block, keys: &[&str]) -> Result<Option<i32>> {
    attr(block, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_i32(n, keys[0])))
        .transpose()
}

fn u8_attr(block: &Block, keys: &[&str]) -> Result<Option<u8>> {
    attr(block, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_u8(n, keys[0])))
        .transpose()
}

fn u32_attr(block: &Block, keys: &[&str]) -> Result<Option<u32>> {
    attr(block, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_u32(n, keys[0])))
        .transpose()
}

fn u64_attr(block: &Block, keys: &[&str]) -> Result<Option<u64>> {
    attr(block, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_u64(n, keys[0])))
        .transpose()
}

fn usize_attr(block: &Block, keys: &[&str]) -> Result<Option<usize>> {
    attr(block, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_usize(n, keys[0])))
        .transpose()
}

fn object_string_attr(fields: &[(String, Value)], keys: &[&str]) -> Result<Option<String>> {
    object_attr(fields, keys)
        .map(|value| value_to_string(value, keys[0]))
        .transpose()
}

fn required_object_string_attr(fields: &[(String, Value)], keys: &[&str]) -> Result<String> {
    object_string_attr(fields, keys)?
        .ok_or_else(|| config_error(format!("object requires {}", keys.join("/"))))
}

fn object_u32_attr(fields: &[(String, Value)], keys: &[&str]) -> Result<Option<u32>> {
    object_attr(fields, keys)
        .map(|value| number_to_i64(value, keys[0]).and_then(|n| range_u32(n, keys[0])))
        .transpose()
}

fn object_fields<'a>(value: &'a Value, name: &str) -> Result<&'a [(String, Value)]> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err(config_error(format!("{} must be an object", name))),
    }
}

fn value_to_string(value: &Value, key: &str) -> Result<String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Call(name, args) if name == "env" => {
            let var_name = args
                .first()
                .ok_or_else(|| config_error(format!("{} env() requires a variable name", key)))
                .and_then(|arg| value_to_string(arg, key))?;
            std::env::var(&var_name).map_err(|_| {
                config_error(format!(
                    "{} references missing environment variable {}",
                    key, var_name
                ))
            })
        }
        Value::Call(name, _) => Err(config_error(format!(
            "{} uses unsupported function {}()",
            key, name
        ))),
        _ => Err(type_error(key, "string")),
    }
}

fn number_to_i64(value: &Value, key: &str) -> Result<i64> {
    match value {
        Value::Number(value) if value.fract() == 0.0 => Ok(*value as i64),
        Value::Number(_) => Err(config_error(format!("{} must be an integer", key))),
        _ => Err(type_error(key, "number")),
    }
}

fn range_i32(value: i64, key: &str) -> Result<i32> {
    i32::try_from(value).map_err(|_| config_error(format!("{} is out of range", key)))
}

fn range_u8(value: i64, key: &str) -> Result<u8> {
    u8::try_from(value).map_err(|_| config_error(format!("{} is out of range", key)))
}

fn range_u32(value: i64, key: &str) -> Result<u32> {
    u32::try_from(value).map_err(|_| config_error(format!("{} is out of range", key)))
}

fn range_u64(value: i64, key: &str) -> Result<u64> {
    u64::try_from(value).map_err(|_| config_error(format!("{} is out of range", key)))
}

fn range_usize(value: i64, key: &str) -> Result<usize> {
    usize::try_from(value).map_err(|_| config_error(format!("{} is out of range", key)))
}

fn type_error(key: &str, expected: &str) -> GatewayError {
    config_error(format!("{} must be a {}", key, expected))
}

fn config_error(message: impl Into<String>) -> GatewayError {
    GatewayError::Config(message.into())
}
