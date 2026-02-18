//! Configuration providers — dynamic config loading and hot reload
//!
//! Watches configuration files for changes and triggers reload
//! without restarting the gateway. Supports DNS, health-based service discovery,
//! and Kubernetes Ingress/CRD providers.

pub mod discovery;
pub(crate) mod dns;
pub mod file_watcher;
pub(crate) mod kubernetes;
pub(crate) mod kubernetes_crd;

pub use discovery::{DiscoveredService, DiscoveryProvider, ServiceMetadata};
pub use file_watcher::FileWatcher;
