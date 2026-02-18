use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// A3S Gateway — AI-native API gateway
#[derive(Parser)]
#[command(name = "a3s-gateway", version, about)]
struct Cli {
    /// Path to configuration file (.hcl)
    #[arg(short, long, default_value = "gateway.hcl")]
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
        #[arg(short, long, default_value = "gateway.hcl")]
        config: String,
    },
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
    if let Some(Commands::Validate { config: config_path }) = &cli.command {
        return validate_config(config_path).await;
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
            a3s_gateway::config::EntrypointConfig {
                address: listen.clone(),
                protocol: a3s_gateway::config::Protocol::Http,
                tls: None,
                max_connections: None,
                tcp_allowed_ips: vec![],
                udp_session_timeout_secs: None,
                udp_max_sessions: None,
            },
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
    for (name, ep) in &config.entrypoints {
        println!("    - {} → {} ({:?})", name, ep.address, ep.protocol);
    }
    println!("  Routers:     {}", config.routers.len());
    for (name, router) in &config.routers {
        println!("    - {} → service:{} rule:{}", name, router.service, router.rule);
    }
    println!("  Services:    {}", config.services.len());
    for (name, svc) in &config.services {
        println!(
            "    - {} ({} backends, strategy: {:?})",
            name,
            svc.load_balancer.servers.len(),
            svc.load_balancer.strategy
        );
    }
    println!("  Middlewares:  {}", config.middlewares.len());
    for name in config.middlewares.keys() {
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

    Ok(())
}
