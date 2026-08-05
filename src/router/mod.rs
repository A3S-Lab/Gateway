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

use rule::strip_host_port;
pub use rule::Rule;

use crate::config::RouterConfig;
use crate::error::{GatewayError, Result};
use http::HeaderMap;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

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
    /// Compiled routes sorted by effective priority descending
    /// (higher wins; default priority = rule string length, Traefik-style).
    routes: Vec<CompiledRoute>,
    /// Exact-host routes keyed by a lowercase host without a port.
    host_routes: HashMap<String, Vec<usize>>,
    /// Routes without a Host matcher, in global priority order.
    generic_routes: Vec<usize>,
}

/// A compiled route with pre-parsed rule
struct CompiledRoute {
    resolved: Arc<ResolvedRoute>,
    rule: Rule,
    entrypoints: Vec<String>,
    /// Effective ordering weight: the explicit `priority` when set (`> 0`),
    /// otherwise the rule string length so more-specific (longer) and
    /// host-qualified rules outrank the host-less catch-all. Higher wins.
    effective_priority: i64,
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

            // Traefik-style effective priority: an explicit positive `priority`
            // always wins; otherwise fall back to the rule string length so that
            // more-specific (longer) and host-qualified rules outrank the
            // host-less catch-all `PathPrefix(`/`)` instead of losing to it.
            let effective_priority = if config.priority > 0 {
                config.priority as i64
            } else {
                config.rule.len() as i64
            };

            routes.push(CompiledRoute {
                resolved: Arc::new(ResolvedRoute {
                    router_name: name.clone(),
                    service_name: config.service.clone(),
                    middlewares: config.middlewares.clone(),
                }),
                rule,
                entrypoints: config.entrypoints.clone(),
                effective_priority,
            });
        }

        // Highest effective priority wins (match_request returns the first match).
        // Tie-break by name for deterministic ordering across HashMap iteration.
        routes.sort_by(|a, b| {
            b.effective_priority
                .cmp(&a.effective_priority)
                .then_with(|| a.resolved.router_name.cmp(&b.resolved.router_name))
        });

        let mut host_routes: HashMap<String, Vec<usize>> = HashMap::new();
        let mut generic_routes = Vec::new();
        for (index, route) in routes.iter().enumerate() {
            if let Some(host) = route.rule.host_hint() {
                host_routes
                    .entry(host.to_ascii_lowercase())
                    .or_default()
                    .push(index);
            } else {
                generic_routes.push(index);
            }
        }

        Ok(Self {
            routes,
            host_routes,
            generic_routes,
        })
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
        self.matching_route(host, path, method, headers, entrypoint)
            .map(|route| route.as_ref().clone())
    }

    /// Match without reallocating immutable route metadata on the data path.
    pub(crate) fn match_request_cached(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        entrypoint: &str,
    ) -> Option<Arc<ResolvedRoute>> {
        self.matching_route(host, path, method, headers, entrypoint)
            .cloned()
    }

    fn matching_route(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        entrypoint: &str,
    ) -> Option<&Arc<ResolvedRoute>> {
        if self.host_routes.is_empty() {
            return self.match_indices(
                &self.generic_routes,
                host,
                path,
                method,
                headers,
                entrypoint,
            );
        }

        let host_routes = host.and_then(|host| {
            let host = strip_host_port(host);
            let normalized = if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
                Cow::Owned(host.to_ascii_lowercase())
            } else {
                Cow::Borrowed(host)
            };
            self.host_routes.get(normalized.as_ref())
        });
        let Some(host_routes) = host_routes else {
            return self.match_indices(
                &self.generic_routes,
                host,
                path,
                method,
                headers,
                entrypoint,
            );
        };

        let mut host_index = 0;
        let mut generic_index = 0;
        while host_index < host_routes.len() || generic_index < self.generic_routes.len() {
            let route_index = match (
                host_routes.get(host_index),
                self.generic_routes.get(generic_index),
            ) {
                (Some(host_route), Some(generic_route)) if host_route < generic_route => {
                    host_index += 1;
                    *host_route
                }
                (Some(_), Some(generic_route)) => {
                    generic_index += 1;
                    *generic_route
                }
                (Some(host_route), None) => {
                    host_index += 1;
                    *host_route
                }
                (None, Some(generic_route)) => {
                    generic_index += 1;
                    *generic_route
                }
                (None, None) => break,
            };
            if self.route_matches(route_index, host, path, method, headers, entrypoint) {
                return Some(&self.routes[route_index].resolved);
            }
        }
        None
    }

    fn match_indices(
        &self,
        indices: &[usize],
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        entrypoint: &str,
    ) -> Option<&Arc<ResolvedRoute>> {
        indices.iter().find_map(|index| {
            self.route_matches(*index, host, path, method, headers, entrypoint)
                .then_some(&self.routes[*index].resolved)
        })
    }

    fn route_matches(
        &self,
        index: usize,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
        entrypoint: &str,
    ) -> bool {
        let route = &self.routes[index];
        (route.entrypoints.is_empty() || route.entrypoints.iter().any(|ep| ep == entrypoint))
            && route.rule.matches(host, path, method, headers)
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
    fn cached_matches_reuse_resolved_route_metadata() {
        let table = RouterTable::from_config(&make_routers()).unwrap();
        let headers = http::HeaderMap::new();

        let first = table
            .match_request_cached(None, "/api/one", "GET", &headers, "web")
            .unwrap();
        let second = table
            .match_request_cached(None, "/api/two", "GET", &headers, "web")
            .unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(first.router_name, "api");
        assert_eq!(first.service_name, "backend");
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

        // Only "health" (Path(`/health`)) matches the exact path `/health`;
        // "api" (PathPrefix(`/api`)) does not, so "health" is selected.
        let result = table.match_request(None, "/health", "GET", &headers, "web");
        assert!(result.is_some());
        assert_eq!(result.unwrap().router_name, "health");
    }

    #[test]
    fn test_router_table_specific_beats_catchall() {
        // A host-less catch-all `PathPrefix(`/`)` must NOT swallow a request that a
        // more-specific router also matches; the longer rule wins by default.
        let mut routers = HashMap::new();
        routers.insert(
            "catchall".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/`)".to_string(),
                service: "web".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );
        routers.insert(
            "app".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/apps/dr-test`)".to_string(),
                service: "deep-research".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        // Specific path wins for its own prefix...
        let r = table
            .match_request(None, "/apps/dr-test/", "GET", &headers, "web")
            .unwrap();
        assert_eq!(r.service_name, "deep-research");
        // ...catch-all still serves everything else.
        let r = table
            .match_request(None, "/other", "GET", &headers, "web")
            .unwrap();
        assert_eq!(r.service_name, "web");
    }

    #[test]
    fn test_router_table_explicit_priority_wins() {
        // An explicit positive priority overrides the rule-length default, even
        // when a competing rule is longer/more-specific.
        let mut routers = HashMap::new();
        routers.insert(
            "long".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/a/very/long/specific/path`)".to_string(),
                service: "long".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 0,
            },
        );
        routers.insert(
            "high".to_string(),
            RouterConfig {
                rule: "PathPrefix(`/a`)".to_string(),
                service: "high".to_string(),
                entrypoints: vec![],
                middlewares: vec![],
                priority: 1000,
            },
        );
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = http::HeaderMap::new();

        let r = table
            .match_request(None, "/a/very/long/specific/path", "GET", &headers, "web")
            .unwrap();
        assert_eq!(r.service_name, "high");
    }

    #[test]
    fn host_index_preserves_global_priority_and_generic_fallback() {
        let routers = HashMap::from([
            (
                "generic".to_string(),
                RouterConfig {
                    rule: "PathPrefix(`/`)".to_string(),
                    service: "generic".to_string(),
                    entrypoints: vec!["web".to_string()],
                    middlewares: vec![],
                    priority: 100,
                },
            ),
            (
                "host".to_string(),
                RouterConfig {
                    rule: "Host(`api.example.com`) && PathPrefix(`/v1`)".to_string(),
                    service: "host".to_string(),
                    entrypoints: vec!["web".to_string()],
                    middlewares: vec![],
                    priority: 200,
                },
            ),
        ]);
        let table = RouterTable::from_config(&routers).unwrap();
        let headers = HeaderMap::new();

        let host = table
            .match_request(
                Some("API.EXAMPLE.COM:8443"),
                "/v1/models",
                "GET",
                &headers,
                "web",
            )
            .unwrap();
        assert_eq!(host.router_name, "host");

        let generic = table
            .match_request(
                Some("unknown.example.com"),
                "/v1/models",
                "GET",
                &headers,
                "web",
            )
            .unwrap();
        assert_eq!(generic.router_name, "generic");
    }

    #[test]
    fn generic_route_can_outrank_an_indexed_host_route() {
        let routers = HashMap::from([
            (
                "generic".to_string(),
                RouterConfig {
                    rule: "PathPrefix(`/`)".to_string(),
                    service: "generic".to_string(),
                    entrypoints: vec![],
                    middlewares: vec![],
                    priority: 300,
                },
            ),
            (
                "host".to_string(),
                RouterConfig {
                    rule: "Host(`api.example.com`)".to_string(),
                    service: "host".to_string(),
                    entrypoints: vec![],
                    middlewares: vec![],
                    priority: 200,
                },
            ),
        ]);
        let table = RouterTable::from_config(&routers).unwrap();

        let route = table
            .match_request(
                Some("api.example.com"),
                "/",
                "GET",
                &HeaderMap::new(),
                "web",
            )
            .unwrap();
        assert_eq!(route.router_name, "generic");
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
