//! Router — rule-based request matching engine
//!
//! Supports Traefik-style rule expressions:
//! - `Host(`domain`)` — match by hostname
//! - `PathPrefix(`/path`)` — match by path prefix
//! - `Path(`/exact`)` — match exact path
//! - `Headers(`key`, `value`)` — match by header
//! - `Method(`GET`)` — match by HTTP method
//! - `&&` — combine matchers with AND

mod rule;
pub mod tcp;

pub use rule::Rule;

use crate::config::RouterConfig;
use crate::error::{GatewayError, Result};
use http::HeaderMap;
use std::collections::HashMap;

/// A resolved route — the result of matching a request against all routers
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Router name that matched
    pub router_name: String,
    /// Target service name
    pub service_name: String,
    /// Middleware names to apply (in order)
    pub middlewares: Vec<String>,
}

/// Router table — holds all compiled routing rules
pub struct RouterTable {
    /// Compiled routes sorted by priority (lower = higher priority)
    routes: Vec<CompiledRoute>,
}

/// A compiled route with pre-parsed rule
struct CompiledRoute {
    name: String,
    /// Original rule expression string (for display in management API)
    rule_expr: String,
    rule: Rule,
    service: String,
    entrypoints: Vec<String>,
    middlewares: Vec<String>,
    priority: i32,
}

impl RouterTable {
    /// Build a router table from configuration
    pub fn from_config(routers: &HashMap<String, RouterConfig>) -> Result<Self> {
        let mut routes: Vec<CompiledRoute> = Vec::new();

        for (name, config) in routers {
            let rule = Rule::parse(&config.rule).map_err(|e| {
                GatewayError::Config(format!(
                    "Router '{}': invalid rule '{}': {}",
                    name, config.rule, e
                ))
            })?;

            routes.push(CompiledRoute {
                name: name.clone(),
                rule_expr: config.rule.clone(),
                rule,
                service: config.service.clone(),
                entrypoints: config.entrypoints.clone(),
                middlewares: config.middlewares.clone(),
                priority: config.priority,
            });
        }

        // Sort by priority (lower = higher priority)
        routes.sort_by_key(|r| r.priority);

        Ok(Self { routes })
    }

    /// Match an incoming request against all routes
    ///
    /// Returns the first matching route (by priority order).
    pub fn match_request(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        entrypoint: &str,
    ) -> Option<ResolvedRoute> {
        for route in &self.routes {
            // Filter by entrypoint if specified
            if !route.entrypoints.is_empty() && !route.entrypoints.iter().any(|ep| ep == entrypoint)
            {
                continue;
            }

            if route.rule.matches(host, path, method, headers) {
                return Some(ResolvedRoute {
                    router_name: route.name.clone(),
                    service_name: route.service.clone(),
                    middlewares: route.middlewares.clone(),
                });
            }
        }
        None
    }

    /// Number of compiled routes
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table is empty
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    /// Return metadata for all compiled routes (for the management API)
    pub fn routes_info(&self) -> Vec<RouteInfoSnapshot> {
        self.routes
            .iter()
            .map(|r| RouteInfoSnapshot {
                name: r.name.clone(),
                rule: r.rule_expr.clone(),
                service: r.service.clone(),
                entrypoints: r.entrypoints.clone(),
                middlewares: r.middlewares.clone(),
                priority: r.priority,
            })
            .collect()
    }
}

/// Snapshot of a compiled route for the management API
#[derive(Debug, Clone)]
pub struct RouteInfoSnapshot {
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entrypoints: Vec<String>,
    pub middlewares: Vec<String>,
    pub priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_routers() -> HashMap<String, RouterConfig> {
        let mut routers = HashMap::new();
        routers.insert(
            "api".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/api`)".to_string(),
                service: "backend".to_string(),
                entrypoints: vec!["web".to_string()],
                middlewares: vec!["auth".to_string()],
                priority: 0,
            },
        );
        routers.insert(
            "health".to_string(),
            RouterConfig {
                rule: "Path(`/health`)".to_string(),
                service: "health-svc".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: -1, // higher priority
            },
        );
        routers
    }

    #[test]
    fn test_router_table_build() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_router_table_match_path() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        let result = table.match_request(None, "/api/users", "GET", &headers, "web");
        assert!(result.is_some());
        let route = result.unwrap();
        assert_eq!(route.service_name, "backend");
        assert_eq!(route.middlewares, vec!["auth"]);
    }

    #[test]
    fn test_router_table_match_exact_path() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        let result = table.match_request(None, "/health", "GET", &headers, "web");
        assert!(result.is_some());
        assert_eq!(result.unwrap().service_name, "health-svc");
    }

    #[test]
    fn test_router_table_no_match() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        let result = table.match_request(None, "/unknown", "GET", &headers, "web");
        assert!(result.is_none());
    }

    #[test]
    fn test_router_table_entrypoint_filter() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        // "api" router only listens on "web" entrypoint
        let result = table.match_request(None, "/api/users", "GET", &headers, "other");
        assert!(result.is_none());
    }

    #[test]
    fn test_router_table_priority_order() {
        let routers = make_routers();
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        // /health matches both "health" (priority -1) and could match others
        // health has higher priority (lower number)
        let result = table.match_request(None, "/health", "GET", &headers, "web");
        assert!(result.is_some());
        assert_eq!(result.unwrap().router_name, "health");
    }

    #[test]
    fn test_router_table_empty() {
        let routers = HashMap::new();
        let table = RouterTable::from_config(&routers).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_router_table_invalid_rule() {
        let mut routers = HashMap::new();
        routers.insert(
            "bad".to_string(),
            RouterConfig {
                rule: "InvalidMatcher(`test`)".to_string(),
                service: "svc".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );
        let result = RouterTable::from_config(&routers);
        assert!(result.is_err());
    }
}
