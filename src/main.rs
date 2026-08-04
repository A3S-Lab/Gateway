mod coding_agent_cli;

use clap::{Parser, Subcommand};
use coding_agent_cli::{operate_agent, operate_skill, AgentCommands, SkillCommands};
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
    /// Discover and run native coding-agent CLIs
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    /// Discover, inspect, and run standard SKILL.md packages
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
    /// Run the inline LLM/MCP wire firewall — mask secrets + run a3s-sentry's detectors on the wire
    #[cfg(feature = "wire")]
    Wire {
        /// Listen address for the wire proxy.
        #[arg(long, default_value = "127.0.0.1:9877")]
        listen: String,
        /// Upstream provider origin to forward to (e.g. https://api.anthropic.com).
        #[arg(long)]
        upstream: String,
        /// a3s-sentry ACL config (file path or inline) — rules / L2 / L3 / fail-mode for the gate.
        /// Empty = built-in rules, fail-open (masking always on; malice escalates to L2).
        #[arg(long, default_value = "")]
        sentry_config: String,
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

#[tokio::main]
async fn main() -> a3s_gateway::Result<()> {
    // rustls 0.23 with both `aws-lc-rs` and `ring` in the dep graph refuses to
    // auto-pick a CryptoProvider; install `ring` explicitly so kube-rs/reqwest
    // TLS clients don't panic on first use.
    let _ = rustls::crypto::ring::default_provider().install_default();

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

    if let Some(Commands::Agent { command }) = &cli.command {
        return operate_agent(command).await;
    }

    if let Some(Commands::Skill { command }) = &cli.command {
        return operate_skill(command).await;
    }

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    tracing::info!("A3S Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Inline wire firewall — a self-contained proxy, not part of the routing pipeline.
    #[cfg(feature = "wire")]
    if let Some(Commands::Wire {
        listen,
        upstream,
        sentry_config,
    }) = &cli.command
    {
        let gate = Arc::new(a3s_gateway::wire::WireGate::from_acl(sentry_config)?);
        let addr = listen.parse().map_err(|e| {
            a3s_gateway::GatewayError::Config(format!("bad --listen `{listen}`: {e}"))
        })?;
        tracing::info!(listen = %listen, upstream = %upstream, "Starting a3s inline wire firewall");
        return a3s_gateway::wire::serve(addr, gate, Arc::new(upstream.clone()))
            .await
            .map_err(|e| a3s_gateway::GatewayError::Other(e.to_string()));
    }

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
        "  Node API:    {}",
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
            "  Node API:     {}{}",
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
                    stream_idle_timeout: "5m".to_string(),
                    stream_total_timeout: "60m".to_string(),
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
}
