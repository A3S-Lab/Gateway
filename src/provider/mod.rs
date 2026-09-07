//! Configuration providers — dynamic config loading and hot reload
//!
//! Watches configuration files for changes and triggers reload
//! without restarting the gateway. Supports DNS, health-based service discovery,
//! Docker container labels, and Kubernetes Ingress/CRD providers.

pub mod discovery;
pub(crate) mod dns;
pub(crate) mod docker;
pub mod file_watcher;
pub(crate) mod kubernetes;
pub(crate) mod kubernetes_crd;
#[cfg(test)]
pub(crate) mod kubernetes_tests;

pub use discovery::{DiscoveredService, DiscoveryProvider, ServiceMetadata};
pub use file_watcher::FileWatcher;

/// Candidate configuration sent by a dynamic provider.
///
/// The receiver acknowledges whether the candidate was accepted by the
/// runtime reload transaction. Providers must update their change-detection
/// cursor only after an affirmative acknowledgement, otherwise one rejected
/// candidate can permanently prevent convergence.
#[derive(Debug)]
pub(crate) struct ConfigUpdate {
    /// Stable provider identity used to keep dynamic source overlays separate.
    pub(crate) source: &'static str,
    pub(crate) config: crate::config::GatewayConfig,
    pub(crate) acknowledged: tokio::sync::oneshot::Sender<bool>,
}
