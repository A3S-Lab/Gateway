//! Configuration providers — dynamic config loading and hot reload
//!
//! Watches configuration files for changes and triggers reload
//! without restarting the gateway.

pub mod file_watcher;

pub use file_watcher::FileWatcher;
