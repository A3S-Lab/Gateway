//! Strip prefix middleware — remove path prefixes before forwarding

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;

/// Strip prefix middleware
pub struct StripPrefixMiddleware {
    prefixes: Vec<String>,
    configuration_error: Option<String>,
}

impl StripPrefixMiddleware {
    /// Create a new strip prefix middleware from configuration.
    ///
    /// Invalid prefixes are retained as a deferred error for compatibility
    /// with the historical infallible constructor. Configuration-driven
    /// callers should use [`Self::try_new`].
    pub fn new(config: &MiddlewareConfig) -> Self {
        match Self::try_new(config) {
            Ok(middleware) => middleware,
            Err(error) => Self {
                prefixes: Vec::new(),
                configuration_error: Some(error.to_string()),
            },
        }
    }

    /// Create and validate a strip-prefix middleware.
    pub fn try_new(config: &MiddlewareConfig) -> Result<Self> {
        for prefix in &config.prefixes {
            validate_prefix(prefix)?;
        }
        Ok(Self {
            prefixes: config.prefixes.clone(),
            configuration_error: None,
        })
    }

    fn ensure_valid(&self) -> Result<()> {
        if let Some(error) = &self.configuration_error {
            return Err(GatewayError::Config(format!(
                "strip-prefix middleware configuration is invalid: {error}"
            )));
        }
        Ok(())
    }
}

fn validate_prefix(prefix: &str) -> Result<()> {
    if prefix.contains('*') && !prefix.ends_with("/*") {
        return Err(GatewayError::Config(format!(
            "strip-prefix wildcard entry '{prefix}' must end with '/*'"
        )));
    }
    let base = prefix.strip_suffix("/*").unwrap_or(prefix);
    if base.is_empty()
        || !base.starts_with('/')
        || base.starts_with("//")
        || base.contains('?')
        || base.contains('#')
        || base.chars().any(char::is_control)
        || base.chars().any(char::is_whitespace)
    {
        return Err(GatewayError::Config(format!(
            "strip-prefix entry '{prefix}' must be an origin-form path"
        )));
    }
    if prefix.ends_with("/*") && base == "/" {
        return Err(GatewayError::Config(
            "strip-prefix wildcard base must contain a path segment".to_string(),
        ));
    }
    Ok(())
}

#[async_trait]
impl Middleware for StripPrefixMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        self.ensure_valid()?;
        let path = req.uri.path().to_string();

        // Determine how many leading characters of the path to strip. A prefix
        // ending in `/*` is a single-segment wildcard: `/apps/*` matches
        // `/apps/<id>/...` and strips `/apps/<id>`, so ONE middleware can serve
        // every dynamically-named workload without a per-workload config entry.
        let mut stripped_len: Option<usize> = None;
        for prefix in &self.prefixes {
            if let Some(base) = prefix.strip_suffix("/*") {
                let base_slash = format!("{base}/");
                if let Some(rest) = path.strip_prefix(&base_slash) {
                    let seg = rest.split('/').next().unwrap_or("");
                    if seg.is_empty() {
                        continue;
                    }
                    stripped_len = Some(base_slash.len() + seg.len());
                    break;
                }
            } else if path == *prefix
                || (prefix.ends_with('/') && path.starts_with(prefix.as_str()))
                || (!prefix.ends_with('/')
                    && path.starts_with(prefix.as_str())
                    && path.as_bytes().get(prefix.len()) == Some(&b'/'))
            {
                stripped_len = Some(prefix.len());
                break;
            }
        }

        let Some(strip) = stripped_len else {
            return Ok(None);
        };

        let remainder = &path[strip..];
        let new_path = if remainder.is_empty() || !remainder.starts_with('/') {
            format!("/{remainder}")
        } else {
            remainder.to_string()
        };

        // Rebuild URI with the stripped path, preserving scheme/authority/query.
        let mut builder = http::Uri::builder();
        if let Some(scheme) = req.uri.scheme() {
            builder = builder.scheme(scheme.clone());
        }
        if let Some(authority) = req.uri.authority() {
            builder = builder.authority(authority.clone());
        }
        let pq = if let Some(query) = req.uri.query() {
            format!("{new_path}?{query}")
        } else {
            new_path
        };
        req.uri = builder.path_and_query(pq).build().map_err(|error| {
            GatewayError::Config(format!(
                "strip-prefix middleware produced an invalid URI: {error}"
            ))
        })?;

        Ok(None)
    }

    fn name(&self) -> &str {
        "strip-prefix"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config(prefixes: Vec<&str>) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "strip-prefix".to_string(),
            prefixes: prefixes.into_iter().map(String::from).collect(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_strip_prefix() {
        let config = make_config(vec!["/api/v1"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/v1/users")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/users");
    }

    #[tokio::test]
    async fn test_strip_prefix_exact() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/");
    }

    #[tokio::test]
    async fn test_strip_prefix_no_match() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/other/path")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/other/path");
    }

    #[tokio::test]
    async fn test_strip_prefix_requires_a_path_segment_boundary() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::try_new(&config).unwrap();

        let (mut parts, _) = Request::builder()
            .uri("/apix/users")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/apix/users");
    }

    #[tokio::test]
    async fn test_strip_prefix_preserves_query() {
        let config = make_config(vec!["/api"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/users?page=1")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/users");
        assert_eq!(parts.uri.query(), Some("page=1"));
    }

    #[tokio::test]
    async fn test_strip_prefix_first_match_wins() {
        let config = make_config(vec!["/api", "/api/v1"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/api/v1/users")
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/v1/users");
    }

    #[tokio::test]
    async fn test_strip_prefix_wildcard_segment() {
        // `/apps/*` strips the literal base plus exactly one dynamic segment, so a
        // single middleware serves every `/apps/<id>/...` workload.
        let config = make_config(vec!["/apps/*"]);
        let mw = StripPrefixMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .uri("/apps/owner-pkg-abc/api/public/meta?x=1")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert_eq!(parts.uri.path(), "/api/public/meta");
        assert_eq!(parts.uri.query(), Some("x=1"));

        // The app root maps to "/".
        let (mut p2, _) = Request::builder()
            .uri("/apps/xyz")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_request(&mut p2, &make_ctx()).await.unwrap();
        assert_eq!(p2.uri.path(), "/");

        // A path outside /apps is left untouched.
        let (mut p3, _) = Request::builder()
            .uri("/other/path")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_request(&mut p3, &make_ctx()).await.unwrap();
        assert_eq!(p3.uri.path(), "/other/path");

        // A wildcard requires one non-empty dynamic segment.
        let (mut p4, _) = Request::builder()
            .uri("/apps/")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_request(&mut p4, &make_ctx()).await.unwrap();
        assert_eq!(p4.uri.path(), "/apps/");
    }

    #[test]
    fn test_strip_prefix_name() {
        let config = make_config(vec![]);
        let mw = StripPrefixMiddleware::new(&config);
        assert_eq!(mw.name(), "strip-prefix");
    }

    #[test]
    fn invalid_prefixes_are_rejected() {
        for prefix in ["api", "//api", "/api?x=1", "/api#frag", "/apps/*/"] {
            let config = make_config(vec![prefix]);
            assert!(
                StripPrefixMiddleware::try_new(&config).is_err(),
                "prefix should be rejected: {prefix}"
            );
        }
    }
}
