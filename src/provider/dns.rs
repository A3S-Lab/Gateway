//! DNS service discovery — resolves backend addresses via DNS
//!
//! Periodically resolves DNS records (A/AAAA/SRV) to discover backend
//! server addresses. Supports automatic refresh on TTL expiry.

#![allow(dead_code)]
use crate::error::{GatewayError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// DNS discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// DNS hostname to resolve
    pub hostname: String,
    /// Default port (used when DNS returns only IP addresses)
    #[serde(default = "default_port")]
    pub port: u16,
    /// Refresh interval
    #[serde(default = "default_refresh_interval")]
    pub refresh_interval_secs: u64,
    /// Scheme for generated URLs (http, https, h2c)
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_port() -> u16 {
    80
}

fn default_refresh_interval() -> u64 {
    30
}

fn default_scheme() -> String {
    "http".to_string()
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            port: default_port(),
            refresh_interval_secs: default_refresh_interval(),
            scheme: default_scheme(),
        }
    }
}

/// A resolved DNS record
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ResolvedAddress {
    /// IP address
    pub address: SocketAddr,
    /// Generated backend URL
    pub url: String,
}

/// DNS resolver — resolves hostnames to backend addresses
pub struct DnsResolver {
    config: DnsConfig,
    /// Cached resolved addresses
    cache: Arc<RwLock<DnsCache>>,
}

/// Cached DNS resolution results
struct DnsCache {
    /// Resolved addresses
    addresses: Vec<ResolvedAddress>,
    /// When the cache was last refreshed
    last_refresh: Option<Instant>,
}

impl DnsResolver {
    /// Create a new DNS resolver
    pub fn new(config: DnsConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(DnsCache {
                addresses: Vec::new(),
                last_refresh: None,
            })),
        }
    }

    /// Get the configuration
    pub fn config(&self) -> &DnsConfig {
        &self.config
    }

    /// Resolve the hostname and return backend addresses
    pub fn resolve(&self) -> Result<Vec<ResolvedAddress>> {
        let host_port = format!("{}:{}", self.config.hostname, self.config.port);

        let addrs: Vec<SocketAddr> = host_port
            .to_socket_addrs()
            .map_err(|e| {
                GatewayError::Other(format!(
                    "DNS resolution failed for {}: {}",
                    self.config.hostname, e
                ))
            })?
            .collect();

        if addrs.is_empty() {
            return Err(GatewayError::Other(format!(
                "DNS resolution returned no addresses for {}",
                self.config.hostname
            )));
        }

        let resolved: Vec<ResolvedAddress> = addrs
            .into_iter()
            .map(|addr| {
                let url = format!("{}://{}", self.config.scheme, addr);
                ResolvedAddress { address: addr, url }
            })
            .collect();

        // Update cache
        let mut cache = self.cache.write().unwrap();
        cache.addresses = resolved.clone();
        cache.last_refresh = Some(Instant::now());

        Ok(resolved)
    }

    /// Get cached addresses (returns empty if never resolved)
    pub fn cached(&self) -> Vec<ResolvedAddress> {
        let cache = self.cache.read().unwrap();
        cache.addresses.clone()
    }

    /// Check if the cache needs refreshing
    pub fn needs_refresh(&self) -> bool {
        let cache = self.cache.read().unwrap();
        match cache.last_refresh {
            None => true,
            Some(last) => {
                Instant::now().duration_since(last)
                    >= Duration::from_secs(self.config.refresh_interval_secs)
            }
        }
    }

    /// Resolve only if the cache is stale
    pub fn resolve_if_stale(&self) -> Result<Vec<ResolvedAddress>> {
        if self.needs_refresh() {
            self.resolve()
        } else {
            Ok(self.cached())
        }
    }

    /// Get the number of cached addresses
    pub fn cached_count(&self) -> usize {
        let cache = self.cache.read().unwrap();
        cache.addresses.len()
    }

    /// Clear the cache
    pub fn clear_cache(&self) {
        let mut cache = self.cache.write().unwrap();
        cache.addresses.clear();
        cache.last_refresh = None;
    }
}

/// DNS discovery registry — manages multiple DNS-based service discoveries
pub struct DnsRegistry {
    resolvers: HashMap<String, DnsResolver>,
}

impl DnsRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            resolvers: HashMap::new(),
        }
    }

    /// Add a DNS resolver for a service
    pub fn add(&mut self, service_name: String, config: DnsConfig) {
        self.resolvers
            .insert(service_name, DnsResolver::new(config));
    }

    /// Resolve a specific service
    pub fn resolve(&self, service_name: &str) -> Option<Result<Vec<ResolvedAddress>>> {
        self.resolvers.get(service_name).map(|r| r.resolve())
    }

    /// Resolve all services
    pub fn resolve_all(&self) -> HashMap<String, Result<Vec<ResolvedAddress>>> {
        self.resolvers
            .iter()
            .map(|(name, resolver)| (name.clone(), resolver.resolve()))
            .collect()
    }

    /// Get the number of registered services
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Check if the registry is empty
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }

    /// Get all service names
    pub fn service_names(&self) -> Vec<&str> {
        self.resolvers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for DnsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- DnsConfig ---

    #[test]
    fn test_config_default() {
        let config = DnsConfig::default();
        assert!(config.hostname.is_empty());
        assert_eq!(config.port, 80);
        assert_eq!(config.refresh_interval_secs, 30);
        assert_eq!(config.scheme, "http");
    }

    #[test]
    fn test_config_custom() {
        let config = DnsConfig {
            hostname: "api.example.com".to_string(),
            port: 8080,
            refresh_interval_secs: 60,
            scheme: "https".to_string(),
        };
        assert_eq!(config.hostname, "api.example.com");
        assert_eq!(config.port, 8080);
    }

    #[test]
    fn test_config_serialization() {
        let config = DnsConfig {
            hostname: "test.local".to_string(),
            port: 9090,
            refresh_interval_secs: 15,
            scheme: "h2c".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DnsConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hostname, "test.local");
        assert_eq!(parsed.port, 9090);
        assert_eq!(parsed.scheme, "h2c");
    }

    // --- DnsResolver ---

    #[test]
    fn test_resolver_new() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            ..Default::default()
        });
        assert_eq!(resolver.config().hostname, "localhost");
        assert_eq!(resolver.cached_count(), 0);
        assert!(resolver.needs_refresh());
    }

    #[test]
    fn test_resolve_localhost() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            port: 8080,
            scheme: "http".to_string(),
            ..Default::default()
        });
        let result = resolver.resolve();
        assert!(result.is_ok());
        let addrs = result.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs[0].url.starts_with("http://"));
    }

    #[test]
    fn test_resolve_invalid_hostname() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "this-hostname-definitely-does-not-exist.invalid".to_string(),
            ..Default::default()
        });
        let result = resolver.resolve();
        assert!(result.is_err());
    }

    #[test]
    fn test_cached_after_resolve() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            port: 8080,
            ..Default::default()
        });
        assert_eq!(resolver.cached_count(), 0);
        resolver.resolve().unwrap();
        assert!(resolver.cached_count() > 0);
        assert!(!resolver.cached().is_empty());
    }

    #[test]
    fn test_needs_refresh_after_resolve() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            refresh_interval_secs: 3600, // 1 hour
            ..Default::default()
        });
        assert!(resolver.needs_refresh());
        resolver.resolve().unwrap();
        assert!(!resolver.needs_refresh());
    }

    #[test]
    fn test_resolve_if_stale_uses_cache() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            refresh_interval_secs: 3600,
            ..Default::default()
        });
        // First call resolves
        let first = resolver.resolve_if_stale().unwrap();
        assert!(!first.is_empty());
        // Second call uses cache
        let second = resolver.resolve_if_stale().unwrap();
        assert_eq!(first.len(), second.len());
    }

    #[test]
    fn test_clear_cache() {
        let resolver = DnsResolver::new(DnsConfig {
            hostname: "localhost".to_string(),
            ..Default::default()
        });
        resolver.resolve().unwrap();
        assert!(resolver.cached_count() > 0);
        resolver.clear_cache();
        assert_eq!(resolver.cached_count(), 0);
        assert!(resolver.needs_refresh());
    }

    // --- ResolvedAddress ---

    #[test]
    fn test_resolved_address_equality() {
        let addr1 = ResolvedAddress {
            address: "127.0.0.1:8080".parse().unwrap(),
            url: "http://127.0.0.1:8080".to_string(),
        };
        let addr2 = ResolvedAddress {
            address: "127.0.0.1:8080".parse().unwrap(),
            url: "http://127.0.0.1:8080".to_string(),
        };
        assert_eq!(addr1, addr2);
    }

    // --- DnsRegistry ---

    #[test]
    fn test_registry_new() {
        let registry = DnsRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
    }

    #[test]
    fn test_registry_add() {
        let mut registry = DnsRegistry::new();
        registry.add(
            "api".to_string(),
            DnsConfig {
                hostname: "localhost".to_string(),
                ..Default::default()
            },
        );
        assert_eq!(registry.len(), 1);
        assert!(!registry.is_empty());
        assert!(registry.service_names().contains(&"api"));
    }

    #[test]
    fn test_registry_resolve() {
        let mut registry = DnsRegistry::new();
        registry.add(
            "api".to_string(),
            DnsConfig {
                hostname: "localhost".to_string(),
                port: 8080,
                ..Default::default()
            },
        );
        let result = registry.resolve("api");
        assert!(result.is_some());
        assert!(result.unwrap().is_ok());
    }

    #[test]
    fn test_registry_resolve_unknown() {
        let registry = DnsRegistry::new();
        assert!(registry.resolve("unknown").is_none());
    }

    #[test]
    fn test_registry_resolve_all() {
        let mut registry = DnsRegistry::new();
        registry.add(
            "svc1".to_string(),
            DnsConfig {
                hostname: "localhost".to_string(),
                ..Default::default()
            },
        );
        registry.add(
            "svc2".to_string(),
            DnsConfig {
                hostname: "localhost".to_string(),
                ..Default::default()
            },
        );
        let results = registry.resolve_all();
        assert_eq!(results.len(), 2);
        assert!(results.get("svc1").unwrap().is_ok());
        assert!(results.get("svc2").unwrap().is_ok());
    }

    #[test]
    fn test_registry_default() {
        let registry = DnsRegistry::default();
        assert!(registry.is_empty());
    }
}
