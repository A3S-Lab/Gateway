//! Configuration providers — dynamic config loading and hot reload
//!
//! Watches configuration files for changes and triggers reload
//! without restarting the gateway. Supports DNS and health-based service discovery.

pub mod discovery;
pub mod dns;
pub mod file_watcher;

pub use discovery::DiscoveryProvider;
pub use dns::DnsResolver;
pub use file_watcher::FileWatcher;
