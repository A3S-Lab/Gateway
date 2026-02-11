use clap::Parser;
use tracing_subscriber::EnvFilter;

/// A3S Gateway — AI-native API gateway
#[derive(Parser)]
#[command(name = "a3s-gateway", version, about)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "gateway.toml")]
    config: String,

    /// Override listen address (e.g., 0.0.0.0:8080)
    #[arg(short, long)]
    listen: Option<String>,

    /// Log level (trace, debug, info, warn, error)
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cli.log_level)),
        )
        .init();

    tracing::info!("A3S Gateway v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = if std::path::Path::new(&cli.config).exists() {
        tracing::info!(config = cli.config, "Loading configuration");
        a3s_gateway::config::GatewayConfig::from_file(&cli.config).await?
    } else {
        tracing::warn!("Config file not found, using defaults");
        a3s_gateway::config::GatewayConfig::default()
    };

    // Validate configuration
    config.validate()?;

    // Build router table
    let router_table = a3s_gateway::router::RouterTable::from_config(&config.routers)?;
    tracing::info!(routes = router_table.len(), "Router table compiled");

    // Build service registry
    let service_registry =
        a3s_gateway::service::ServiceRegistry::from_config(&config.services)?;
    tracing::info!(services = service_registry.len(), "Services registered");

    // Start health checks
    service_registry.start_health_checks(&config.services).await;

    // Log entrypoints
    for (name, ep) in &config.entrypoints {
        tracing::info!(
            entrypoint = name,
            address = ep.address,
            tls = ep.tls.is_some(),
            "Entrypoint configured"
        );
    }

    tracing::info!("Gateway ready — press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down...");

    Ok(())
}
