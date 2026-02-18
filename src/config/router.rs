//! Router configuration — request matching rules

use serde::{Deserialize, Serialize};

/// Router configuration — matches requests to services
///
/// # Example
///
/// ```hcl
/// routers "api" {
///   rule        = "Host(`api.example.com`) && PathPrefix(`/v1`)"
///   service     = "api-backend"
///   entrypoints = ["websecure"]
///   middlewares  = ["auth", "rate-limit"]
///   priority    = 10
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterConfig {
    /// Matching rule expression (Traefik-style)
    ///
    /// Supported matchers:
    /// - `Host(`domain`)` — match by hostname
    /// - `PathPrefix(`/path`)` — match by path prefix
    /// - `Path(`/exact`)` — match exact path
    /// - `Headers(`key`, `value`)` — match by header
    /// - `Method(`GET`)` — match by HTTP method
    /// - `&&` — combine matchers with AND
    pub rule: String,

    /// Target service name
    pub service: String,

    /// Entrypoints this router listens on (empty = all)
    #[serde(default)]
    pub entrypoints: Vec<String>,

    /// Middleware chain to apply (in order)
    #[serde(default)]
    pub middlewares: Vec<String>,

    /// Priority (lower = higher priority, default = 0)
    #[serde(default)]
    pub priority: i32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_parse_minimal() {
        let hcl = r#"
            rule = "PathPrefix(`/api`)"
            service = "backend"
        "#;
        let router: RouterConfig = hcl::from_str(hcl).unwrap();
        assert_eq!(router.rule, "PathPrefix(`/api`)");
        assert_eq!(router.service, "backend");
        assert!(router.entrypoints.is_empty());
        assert!(router.middlewares.is_empty());
        assert_eq!(router.priority, 0);
    }

    #[test]
    fn test_router_parse_full() {
        let hcl = r#"
            rule = "Host(`api.example.com`) && PathPrefix(`/v1`)"
            service = "api-backend"
            entrypoints = ["websecure"]
            middlewares = ["auth", "rate-limit"]
            priority = 10
        "#;
        let router: RouterConfig = hcl::from_str(hcl).unwrap();
        assert_eq!(router.rule, "Host(`api.example.com`) && PathPrefix(`/v1`)");
        assert_eq!(router.service, "api-backend");
        assert_eq!(router.entrypoints, vec!["websecure"]);
        assert_eq!(router.middlewares, vec!["auth", "rate-limit"]);
        assert_eq!(router.priority, 10);
    }

    #[test]
    fn test_router_serialization_roundtrip() {
        let router = RouterConfig {
            rule: "Path(`/health`)".to_string(),
            service: "health-svc".to_string(),
            entrypoints: vec!["web".to_string()],
            middlewares: vec![],
            priority: 5,
        };
        let json = serde_json::to_string(&router).unwrap();
        let parsed: RouterConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.rule, router.rule);
        assert_eq!(parsed.service, router.service);
        assert_eq!(parsed.priority, router.priority);
    }

    #[test]
    fn test_router_default_values() {
        let hcl = r#"
            rule = "Host(`test.com`)"
            service = "test"
        "#;
        let router: RouterConfig = hcl::from_str(hcl).unwrap();
        assert!(router.entrypoints.is_empty());
        assert!(router.middlewares.is_empty());
        assert_eq!(router.priority, 0);
    }
}
