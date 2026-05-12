use clap::{Args, Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// A3S Gateway — AI-native API gateway
#[derive(Parser)]
#[command(name = "a3s-gateway", version, about)]
struct Cli {
    /// Path to configuration file (.acl)
    #[arg(short, long, default_value = "gateway.acl")]
    config: String,

    /// Override listen address (e.g., 0.0.0.0:8080)
    #[arg(short, long)]
    listen: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Update a3s-gateway to the latest version
    Update,
    /// Validate a configuration file without starting the gateway
    Validate {
        /// Path to configuration file to validate
        #[arg(short, long, default_value = "gateway.acl")]
        config: String,
    },
    /// Inspect ACL configuration from the CLI
    Config {
        /// Path to configuration file to inspect
        #[arg(short, long, default_value = "gateway.acl")]
        config: String,
        #[command(subcommand)]
        command: ConfigCommands,
    },
    /// Inspect a running management listener
    Management {
        #[command(subcommand)]
        command: ManagementCommands,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Print a compact configuration summary
    Summary,
    /// List configured entrypoints
    Entrypoints,
    /// List configured routers
    Routes,
    /// List configured services and backend counts
    Services,
    /// List configured middleware names
    Middlewares,
    /// List enabled providers
    Providers,
    /// Print the parsed configuration as JSON
    Json,
}

#[derive(Subcommand)]
enum ManagementCommands {
    /// Fetch recent management security audit events
    Events {
        #[command(flatten)]
        api: ManagementApiArgs,

        /// Maximum number of events to fetch.
        #[arg(long, default_value_t = 100)]
        limit: usize,

        /// Print raw JSON instead of tab-separated rows.
        #[arg(long)]
        json: bool,
    },
    /// Validate an ACL file through the management API
    Validate {
        /// ACL configuration file to validate.
        #[arg(short, long)]
        file: String,

        #[command(flatten)]
        api: ManagementApiArgs,

        /// Print raw JSON response.
        #[arg(long)]
        json: bool,
    },
    /// Reload the gateway with an ACL file through the management API
    Reload {
        /// ACL configuration file to apply.
        #[arg(short, long)]
        file: String,

        #[command(flatten)]
        api: ManagementApiArgs,

        /// Print raw JSON response.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args, Clone)]
struct ManagementApiArgs {
    /// Base management API URL, without endpoint suffix.
    #[arg(long, default_value = "http://127.0.0.1:9090/api/gateway")]
    url: String,

    /// Bearer token value. If omitted, A3S_GATEWAY_ADMIN_TOKEN is used when present.
    #[arg(long)]
    token: Option<String>,

    /// Environment variable containing the bearer token.
    #[arg(long)]
    token_env: Option<String>,

    /// PEM CA certificate used to verify the management listener.
    #[arg(long)]
    ca_cert: Option<String>,

    /// PEM client certificate for mTLS.
    #[arg(long)]
    client_cert: Option<String>,

    /// PEM client private key for mTLS.
    #[arg(long)]
    client_key: Option<String>,

    /// Disable TLS certificate verification. Use only for local diagnostics.
    #[arg(long)]
    insecure: bool,
}

#[tokio::main]
async fn main() -> a3s_gateway::Result<()> {
    let cli = Cli::parse();

    // Handle update subcommand early
    if matches!(cli.command, Some(Commands::Update)) {
        return a3s_updater::run_update(&a3s_updater::UpdateConfig {
            binary_name: "a3s-gateway",
            crate_name: "a3s-gateway",
            current_version: env!("CARGO_PKG_VERSION"),
            github_owner: "A3S-Lab",
            github_repo: "Gateway",
        })
        .await
        .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()));
    }

    // Handle validate subcommand
    if let Some(Commands::Validate {
        config: config_path,
    }) = &cli.command
    {
        return validate_config(config_path).await;
    }

    if let Some(Commands::Config {
        config: config_path,
        command,
    }) = &cli.command
    {
        return inspect_config(config_path, command).await;
    }

    if let Some(Commands::Management { command }) = &cli.command {
        return inspect_management(command).await;
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    tracing::info!("A3S Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let mut config = if std::path::Path::new(&cli.config).exists() {
        tracing::info!(config = cli.config, "Loading configuration");
        a3s_gateway::config::GatewayConfig::from_file(&cli.config).await?
    } else {
        tracing::warn!("Config file not found, using defaults");
        a3s_gateway::config::GatewayConfig::default()
    };

    // Override listen address if provided
    if let Some(listen) = &cli.listen {
        config.entrypoints.insert(
            "web".to_string(),
            a3s_gateway::config::EntrypointConfig::new(listen),
        );
    }

    // Create and start the gateway
    let gateway = Arc::new(a3s_gateway::Gateway::new(config.clone())?);
    gateway.start().await?;

    tracing::info!("Gateway ready — press Ctrl+C to stop");

    // Start hot reload watcher if configured
    if let Some(ref file_config) = config.providers.file {
        if file_config.watch {
            let watcher = a3s_gateway::provider::FileWatcher::new(&cli.config);
            let watcher = if let Some(ref dir) = file_config.directory {
                watcher.with_directory(dir)
            } else {
                watcher
            };

            match watcher.watch() {
                Ok(rx) => {
                    let gw = gateway.clone();
                    tokio::spawn(async move {
                        while let Ok(event) = rx.recv() {
                            match event.config {
                                Ok(new_config) => {
                                    tracing::info!(
                                        path = %event.trigger_path.display(),
                                        "Config change detected, reloading"
                                    );
                                    if let Err(e) = gw.reload(new_config).await {
                                        tracing::error!(error = %e, "Hot reload failed");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        error = %e,
                                        path = %event.trigger_path.display(),
                                        "Config reload failed, keeping current config"
                                    );
                                }
                            }
                        }
                    });
                    tracing::info!("Hot reload enabled");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to start file watcher, hot reload disabled");
                }
            }
        }
    }

    // Wait for shutdown signal
    gateway.wait_for_shutdown().await;

    Ok(())
}

async fn inspect_config(path: &str, command: &ConfigCommands) -> a3s_gateway::Result<()> {
    let config = load_validated_config(path).await?;

    match command {
        ConfigCommands::Summary => print!("{}", render_config_summary(&config)),
        ConfigCommands::Entrypoints => print!("{}", render_entrypoints(&config)),
        ConfigCommands::Routes => print!("{}", render_routes(&config)),
        ConfigCommands::Services => print!("{}", render_services(&config)),
        ConfigCommands::Middlewares => print!("{}", render_middlewares(&config)),
        ConfigCommands::Providers => print!("{}", render_providers(&config)),
        ConfigCommands::Json => {
            let json = serde_json::to_string_pretty(&config)
                .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
            println!("{}", json);
        }
    }

    Ok(())
}

async fn inspect_management(command: &ManagementCommands) -> a3s_gateway::Result<()> {
    match command {
        ManagementCommands::Events { api, limit, json } => {
            let events =
                fetch_management_events(ManagementEventsRequest { api, limit: *limit }).await?;

            if *json {
                let body = serde_json::to_string_pretty(&events)
                    .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
                println!("{}", body);
            } else {
                print!("{}", render_management_events(&events));
            }
        }
        ManagementCommands::Validate { file, api, json } => {
            let acl = std::fs::read_to_string(file).map_err(|e| {
                a3s_gateway::GatewayError::Other(format!(
                    "Failed to read management validation file {}: {}",
                    file, e
                ))
            })?;
            let response =
                post_management_config(api, "config/validate", acl, "validation").await?;
            print_management_mutation_response(&response, *json)?;
        }
        ManagementCommands::Reload { file, api, json } => {
            let acl = std::fs::read_to_string(file).map_err(|e| {
                a3s_gateway::GatewayError::Other(format!(
                    "Failed to read management reload file {}: {}",
                    file, e
                ))
            })?;
            let response = post_management_config(api, "config/reload", acl, "reload").await?;
            print_management_mutation_response(&response, *json)?;
        }
    }

    Ok(())
}

struct ManagementEventsRequest<'a> {
    api: &'a ManagementApiArgs,
    limit: usize,
}

async fn fetch_management_events(
    request: ManagementEventsRequest<'_>,
) -> a3s_gateway::Result<Vec<a3s_gateway::dashboard::ManagementAuditEvent>> {
    let client = build_management_http_client(request.api)?;
    let endpoint =
        management_endpoint_url(&request.api.url, &format!("events?limit={}", request.limit));
    let response = send_management_request(client.get(endpoint), request.api)
        .await?
        .json::<Vec<a3s_gateway::dashboard::ManagementAuditEvent>>()
        .await
        .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;

    Ok(response)
}

async fn post_management_config(
    api: &ManagementApiArgs,
    endpoint: &str,
    acl: String,
    action: &str,
) -> a3s_gateway::Result<serde_json::Value> {
    let client = build_management_http_client(api)?;
    let url = management_endpoint_url(&api.url, endpoint);
    send_management_request(
        client
            .post(url)
            .body(acl)
            .header("Content-Type", "text/plain"),
        api,
    )
    .await?
    .json::<serde_json::Value>()
    .await
    .map_err(|e| {
        a3s_gateway::GatewayError::Other(format!(
            "Failed to parse management {} response: {}",
            action, e
        ))
    })
}

fn build_management_http_client(api: &ManagementApiArgs) -> a3s_gateway::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if api.insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(path) = api.ca_cert.as_deref() {
        let pem = std::fs::read(path).map_err(|e| {
            a3s_gateway::GatewayError::Other(format!(
                "Failed to read management CA certificate {}: {}",
                path, e
            ))
        })?;
        let cert = reqwest::Certificate::from_pem(&pem)
            .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
        builder = builder.add_root_certificate(cert);
    }
    match (api.client_cert.as_deref(), api.client_key.as_deref()) {
        (Some(cert_path), Some(key_path)) => {
            let mut pem = std::fs::read(cert_path).map_err(|e| {
                a3s_gateway::GatewayError::Other(format!(
                    "Failed to read management client certificate {}: {}",
                    cert_path, e
                ))
            })?;
            let key = std::fs::read(key_path).map_err(|e| {
                a3s_gateway::GatewayError::Other(format!(
                    "Failed to read management client key {}: {}",
                    key_path, e
                ))
            })?;
            pem.extend_from_slice(&key);
            let identity = reqwest::Identity::from_pem(&pem)
                .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
            builder = builder.identity(identity);
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(a3s_gateway::GatewayError::Other(
                "Both --client-cert and --client-key are required for mTLS".to_string(),
            ));
        }
        (None, None) => {}
    }

    builder
        .build()
        .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))
}

async fn send_management_request(
    request: reqwest::RequestBuilder,
    api: &ManagementApiArgs,
) -> a3s_gateway::Result<reqwest::Response> {
    let mut request = request;
    if let Some(token) = management_bearer_token(api.token.as_deref(), api.token_env.as_deref()) {
        request = request.bearer_auth(token);
    }

    let response = request
        .send()
        .await
        .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(a3s_gateway::GatewayError::Other(format!(
            "Management events request failed with {}: {}",
            status, body
        )));
    }

    Ok(response)
}

fn management_endpoint_url(base_url: &str, endpoint: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), endpoint)
}

fn print_management_mutation_response(
    response: &serde_json::Value,
    json: bool,
) -> a3s_gateway::Result<()> {
    if json {
        let body = serde_json::to_string_pretty(response)
            .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()))?;
        println!("{}", body);
    } else if let Some(message) = response.get("message").and_then(|value| value.as_str()) {
        println!("{}", message);
    } else {
        println!("Success");
    }
    Ok(())
}

fn management_bearer_token(token: Option<&str>, token_env: Option<&str>) -> Option<String> {
    match (token, token_env) {
        (Some(token), _) => Some(token.to_string()),
        (None, Some(env)) => std::env::var(env).ok(),
        (None, None) => std::env::var("A3S_GATEWAY_ADMIN_TOKEN").ok(),
    }
}

fn render_management_events(events: &[a3s_gateway::dashboard::ManagementAuditEvent]) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    for event in events {
        writeln!(
            &mut out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            event.sequence,
            event.timestamp,
            event.kind,
            event
                .status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "-".to_string()),
            event.remote_addr.as_deref().unwrap_or("-"),
            event.path.as_deref().unwrap_or("-"),
            event.reason
        )
        .unwrap();
    }
    out
}

async fn load_validated_config(
    path: &str,
) -> a3s_gateway::Result<a3s_gateway::config::GatewayConfig> {
    let config = a3s_gateway::config::GatewayConfig::from_file(path).await?;
    config.validate()?;
    Ok(config)
}

fn render_config_summary(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    writeln!(&mut out, "Configuration summary").unwrap();
    writeln!(&mut out, "  Entrypoints: {}", config.entrypoints.len()).unwrap();
    writeln!(&mut out, "  Routers:     {}", config.routers.len()).unwrap();
    writeln!(&mut out, "  Services:    {}", config.services.len()).unwrap();
    writeln!(&mut out, "  Middlewares: {}", config.middlewares.len()).unwrap();
    writeln!(
        &mut out,
        "  Providers:   {}",
        provider_names(config).join(", ")
    )
    .unwrap();
    writeln!(
        &mut out,
        "  Management:  {}",
        if config.management.enabled {
            config.management.address.as_str()
        } else {
            "disabled"
        }
    )
    .unwrap();
    out
}

fn render_entrypoints(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let mut entrypoints: Vec<_> = config.entrypoints.iter().collect();
    entrypoints.sort_by_key(|(k, _)| (*k).clone());
    for (name, entrypoint) in entrypoints {
        writeln!(
            &mut out,
            "{}\t{}\t{:?}",
            name, entrypoint.address, entrypoint.protocol
        )
        .unwrap();
    }
    out
}

fn render_routes(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let mut routers: Vec<_> = config.routers.iter().collect();
    routers.sort_by_key(|(k, _)| (*k).clone());
    for (name, router) in routers {
        writeln!(
            &mut out,
            "{}\tservice={}\trule={}\tentrypoints={}",
            name,
            router.service,
            router.rule,
            router.entrypoints.join(",")
        )
        .unwrap();
    }
    out
}

fn render_services(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let mut services: Vec<_> = config.services.iter().collect();
    services.sort_by_key(|(k, _)| (*k).clone());
    for (name, service) in services {
        let base_backends = service.load_balancer.servers.len();
        let revision_backends: usize = service
            .revisions
            .iter()
            .map(|revision| revision.servers.len())
            .sum();
        writeln!(
            &mut out,
            "{}\tbase_backends={}\trevision_backends={}\tstrategy={:?}",
            name, base_backends, revision_backends, service.load_balancer.strategy
        )
        .unwrap();
    }
    out
}

fn render_middlewares(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let mut middlewares: Vec<_> = config.middlewares.keys().collect();
    middlewares.sort();
    for name in middlewares {
        writeln!(&mut out, "{}", name).unwrap();
    }
    out
}

fn render_providers(config: &a3s_gateway::config::GatewayConfig) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    for name in provider_names(config) {
        writeln!(&mut out, "{}", name).unwrap();
    }
    out
}

fn provider_names(config: &a3s_gateway::config::GatewayConfig) -> Vec<&'static str> {
    let mut providers = Vec::new();
    if config.providers.file.is_some() {
        providers.push("file");
    }
    if config.providers.discovery.is_some() {
        providers.push("discovery");
    }
    if config.providers.kubernetes.is_some() {
        providers.push("kubernetes");
    }
    if config.providers.docker.is_some() {
        providers.push("docker");
    }
    if providers.is_empty() {
        providers.push("none");
    }
    providers
}

/// Validate a configuration file and print diagnostics
async fn validate_config(path: &str) -> a3s_gateway::Result<()> {
    use std::path::Path;

    let config_path = Path::new(path);
    if !config_path.exists() {
        eprintln!("✗ Config file not found: {}", path);
        std::process::exit(1);
    }

    // Parse
    let config = match a3s_gateway::config::GatewayConfig::from_file(path).await {
        Ok(c) => {
            println!("✓ Config parsed successfully ({})", path);
            c
        }
        Err(e) => {
            eprintln!("✗ Parse error: {}", e);
            std::process::exit(1);
        }
    };

    // Validate
    if let Err(e) = config.validate() {
        eprintln!("✗ Validation error: {}", e);
        std::process::exit(1);
    }

    // Print summary
    println!("✓ Configuration is valid");
    println!();
    println!("  Entrypoints: {}", config.entrypoints.len());
    let mut entrypoints: Vec<_> = config.entrypoints.iter().collect();
    entrypoints.sort_by_key(|(k, _)| (*k).clone());
    for (name, ep) in entrypoints {
        println!("    - {} → {} ({:?})", name, ep.address, ep.protocol);
    }
    println!("  Routers:     {}", config.routers.len());
    let mut routers: Vec<_> = config.routers.iter().collect();
    routers.sort_by_key(|(k, _)| (*k).clone());
    for (name, router) in routers {
        println!(
            "    - {} → service:{} rule:{}",
            name, router.service, router.rule
        );
    }
    println!("  Services:    {}", config.services.len());
    let mut services: Vec<_> = config.services.iter().collect();
    services.sort_by_key(|(k, _)| (*k).clone());
    for (name, svc) in services {
        println!(
            "    - {} ({} backends, strategy: {:?})",
            name,
            svc.load_balancer.servers.len(),
            svc.load_balancer.strategy
        );
    }
    println!("  Middlewares:  {}", config.middlewares.len());
    let mut middlewares: Vec<_> = config.middlewares.keys().collect();
    middlewares.sort();
    for name in middlewares {
        println!("    - {}", name);
    }

    // Provider info
    if config.providers.file.is_some() {
        println!("  Provider:    file (hot reload)");
    }
    if config.providers.discovery.is_some() {
        println!("  Provider:    discovery (health-based)");
    }
    if config.providers.kubernetes.is_some() {
        println!("  Provider:    kubernetes");
    }
    if config.providers.docker.is_some() {
        println!("  Provider:    docker");
    }
    if config.management.enabled {
        println!(
            "  Management:  {}{}",
            config.management.address, config.management.path_prefix
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use a3s_gateway::config::{
        EntrypointConfig, GatewayConfig, LoadBalancerConfig, Protocol, RouterConfig, ServerConfig,
        ServiceConfig, Strategy,
    };
    use std::collections::HashMap;

    fn config_fixture() -> GatewayConfig {
        let mut config = GatewayConfig::default();
        config.entrypoints.insert(
            "admin".to_string(),
            EntrypointConfig {
                address: "127.0.0.1:9000".to_string(),
                protocol: Protocol::Http,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
            },
        );
        config.routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "backend".to_string(),
                entrypoints: vec!["web".to_string()],
                middlewares: vec![],
                priority: 0,
            },
        );
        config.services.insert(
            "backend".to_string(),
            ServiceConfig {
                load_balancer: LoadBalancerConfig {
                    strategy: Strategy::RoundRobin,
                    request_timeout: "30s".to_string(),
                    servers: vec![ServerConfig {
                        url: "http://127.0.0.1:8001".to_string(),
                        weight: 1,
                    }],
                    health_check: None,
                    sticky: None,
                },
                scaling: None,
                revisions: vec![],
                rollout: None,
                mirror: None,
                failover: None,
            },
        );
        config.middlewares = HashMap::new();
        config
    }

    #[test]
    fn test_render_config_summary() {
        let config = config_fixture();
        let summary = render_config_summary(&config);
        assert!(summary.contains("Entrypoints: 2"));
        assert!(summary.contains("Routers:     1"));
        assert!(summary.contains("Services:    1"));
    }

    #[test]
    fn test_render_routes_and_services() {
        let config = config_fixture();
        assert!(render_routes(&config).contains("service=backend"));
        assert!(render_services(&config).contains("base_backends=1"));
    }

    #[test]
    fn test_provider_names_none() {
        let config = config_fixture();
        assert_eq!(provider_names(&config), vec!["none"]);
    }

    #[test]
    fn test_render_management_events() {
        let event = a3s_gateway::dashboard::ManagementAuditEvent {
            sequence: 1,
            timestamp: "2026-05-09T00:00:00Z".to_string(),
            kind: a3s_gateway::dashboard::ManagementAuditEventKind::AuthRejected,
            remote_addr: Some("127.0.0.1:50000".to_string()),
            path: Some("/api/gateway/health".to_string()),
            status: Some(401),
            reason: "Bearer token is missing or invalid".to_string(),
        };

        let output = render_management_events(&[event]);
        assert!(output.contains("auth-rejected"));
        assert!(output.contains("401"));
    }
}
