//! Configuration providers — dynamic config loading and hot reload
//!
//! Watches configuration files for changes and triggers reload
//! without restarting the gateway. Supports DNS service discovery.

pub mod dns;
pub mod file_watcher;

pub use dns::DnsResolver;
pub use file_watcher::FileWatcher;
