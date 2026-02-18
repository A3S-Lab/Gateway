//! # A3S Gateway
//!
//! An AI-native API gateway that combines Traefik-style reverse proxy capabilities with
//! AI agent routing and orchestration for the A3S ecosystem.
//!
//! ## Architecture
//!
//! ```text
//! Entrypoint → Router → Middleware Pipeline → Service (Load Balancer) → Backend
//! ```
//!
//! ## Core Features
//!
//! - **Multi-protocol**: HTTP/HTTPS, WebSocket, SSE/Streaming, TCP
//! - **Dynamic Routing**: Traefik-style rule engine (`Host()`, `PathPrefix()`, `Headers()`)
//! - **Load Balancing**: Round-robin, weighted, least-connections
//! - **Middleware Pipeline**: Auth, rate-limit, CORS, headers, strip-prefix
//! - **Health Checks**: Active HTTP probes with automatic backend removal
//! - **Hot Reload**: File-watch based configuration reload without restart
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use a3s_gateway::{Gateway, config::GatewayConfig};
//!
//! #[tokio::main]
//! async fn main() -> a3s_gateway::Result<()> {
//!     let config = GatewayConfig::from_file("gateway.hcl").await?;
//!     let gateway = Gateway::new(config).await?;
//!     gateway.run().await?;
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod dashboard;
pub(crate) mod entrypoint;
pub mod error;
pub mod gateway;
pub(crate) mod middleware;
pub(crate) mod observability;
pub mod provider;
pub(crate) mod proxy;
pub(crate) mod router;
pub(crate) mod scaling;
pub(crate) mod service;

// Re-export main types
pub use error::{GatewayError, Result};
pub use gateway::Gateway;
pub use provider::discovery::{DiscoveredService, DiscoveryProvider, ServiceMetadata};

use serde::{Deserialize, Serialize};

/// Gateway runtime state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[derive(Default)]
pub enum GatewayState {
    /// Gateway has been created but not yet started
    #[default]
    Created,
    /// Gateway is initializing listeners and loading configuration
    Starting,
    /// Gateway is actively accepting and proxying requests
    Running,
    /// Gateway is reloading configuration without downtime
    Reloading,
    /// Gateway is draining connections and shutting down
    Stopping,
    /// Gateway has fully stopped
    Stopped,
}


impl std::fmt::Display for GatewayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Created => write!(f, "created"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Reloading => write!(f, "reloading"),
            Self::Stopping => write!(f, "stopping"),
            Self::Stopped => write!(f, "stopped"),
        }
    }
}

/// Gateway health status snapshot
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStatus {
    /// Current gateway state
    pub state: GatewayState,
    /// Uptime in seconds since gateway started
    pub uptime_secs: u64,
    /// Number of active connections
    pub active_connections: usize,
    /// Total requests handled since start
    pub total_requests: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gateway_state_default() {
        let state = GatewayState::default();
        assert_eq!(state, GatewayState::Created);
    }

    #[test]
    fn test_gateway_state_display() {
        assert_eq!(GatewayState::Created.to_string(), "created");
        assert_eq!(GatewayState::Starting.to_string(), "starting");
        assert_eq!(GatewayState::Running.to_string(), "running");
        assert_eq!(GatewayState::Reloading.to_string(), "reloading");
        assert_eq!(GatewayState::Stopping.to_string(), "stopping");
        assert_eq!(GatewayState::Stopped.to_string(), "stopped");
    }

    #[test]
    fn test_gateway_state_equality() {
        assert_eq!(GatewayState::Running, GatewayState::Running);
        assert_ne!(GatewayState::Running, GatewayState::Stopped);
    }

    #[test]
    fn test_gateway_state_serialization() {
        let state = GatewayState::Running;
        let json = serde_json::to_string(&state).unwrap();
        let parsed: GatewayState = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, GatewayState::Running);
    }

    #[test]
    fn test_health_status_default() {
        let health = HealthStatus::default();
        assert_eq!(health.state, GatewayState::Created);
        assert_eq!(health.uptime_secs, 0);
        assert_eq!(health.active_connections, 0);
        assert_eq!(health.total_requests, 0);
    }

    #[test]
    fn test_health_status_serialization() {
        let health = HealthStatus {
            state: GatewayState::Running,
            uptime_secs: 3600,
            active_connections: 42,
            total_requests: 10000,
        };
        let json = serde_json::to_string(&health).unwrap();
        let parsed: HealthStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.state, GatewayState::Running);
        assert_eq!(parsed.uptime_secs, 3600);
        assert_eq!(parsed.active_connections, 42);
        assert_eq!(parsed.total_requests, 10000);
    }

    #[test]
    fn test_health_status_clone() {
        let health = HealthStatus {
            state: GatewayState::Running,
            uptime_secs: 100,
            active_connections: 5,
            total_requests: 500,
        };
        let cloned = health.clone();
        assert_eq!(cloned.state, health.state);
        assert_eq!(cloned.uptime_secs, health.uptime_secs);
    }
}
