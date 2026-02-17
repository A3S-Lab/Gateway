use clap::{Parser, Subcommand};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

/// A3S Gateway — AI-native API gateway
#[derive(Parser)]
#[command(name = "a3s-gateway", version, about)]
struct Cli {
    /// Path to configuration file (supports .toml and .hcl)
    #[arg(short, long, default_value = "gateway.toml")]
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        .await;
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
