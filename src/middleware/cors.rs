//! CORS middleware — Cross-Origin Resource Sharing

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, ORIGIN, VARY};
use http::Response;

/// CORS middleware
pub struct CorsMiddleware {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    max_age: u64,
    configuration_error: Option<String>,
}

impl CorsMiddleware {
    /// Create a new CORS middleware from configuration.
    ///
    /// The infallible constructor is retained for callers that construct
    /// middleware directly. Invalid values become a deferred error surfaced
    /// by request/response processing; [`Self::try_new`] should be used by
    /// configuration-driven construction.
    pub fn new(config: &MiddlewareConfig) -> Self {
        match Self::try_new(config) {
            Ok(middleware) => middleware,
            Err(error) => Self {
                allowed_origins: Vec::new(),
                allowed_methods: Vec::new(),
                allowed_headers: Vec::new(),
                max_age: 0,
                configuration_error: Some(error.to_string()),
            },
        }
    }

    /// Create a CORS middleware and validate all values before startup.
    pub fn try_new(config: &MiddlewareConfig) -> Result<Self> {
        let allowed_origins = if config.allowed_origins.is_empty() {
            vec!["*".to_string()]
        } else {
            config.allowed_origins.clone()
        };
        let allowed_methods = if config.allowed_methods.is_empty() {
            vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "OPTIONS".to_string(),
            ]
        } else {
            config.allowed_methods.clone()
        };
        let allowed_headers = if config.allowed_headers.is_empty() {
            vec!["Content-Type".to_string(), "Authorization".to_string()]
        } else {
            config.allowed_headers.clone()
        };

        validate_origins(&allowed_origins)?;
        validate_methods(&allowed_methods)?;
        validate_headers(&allowed_headers)?;

        Ok(Self {
            allowed_origins,
            allowed_methods,
            allowed_headers,
            max_age: config.max_age.unwrap_or(86400),
            configuration_error: None,
        })
    }

    fn ensure_valid(&self) -> Result<()> {
        if let Some(error) = &self.configuration_error {
            return Err(GatewayError::Config(format!(
                "cors middleware configuration is invalid: {error}"
            )));
        }
        Ok(())
    }

    fn origin_allowed(&self, origin: &str) -> bool {
        self.allowed_origins.iter().any(|o| o == "*" || o == origin)
    }
}

#[async_trait]
impl Middleware for CorsMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        self.ensure_valid()?;
        // Handle preflight OPTIONS request
        if req.method == http::Method::OPTIONS {
            let origin = req
                .headers
                .get("Origin")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("*");

            if !self.origin_allowed(origin) {
                return Ok(Some(
                    Response::builder()
                        .status(403)
                        .body(b"Origin not allowed".to_vec())
                        .map_err(|error| {
                            GatewayError::Other(format!(
                                "failed to build CORS rejection response: {error}"
                            ))
                        })?,
                ));
            }

            let response = Response::builder()
                .status(204)
                .header("Access-Control-Allow-Origin", origin)
                .header(
                    "Access-Control-Allow-Methods",
                    self.allowed_methods.join(", "),
                )
                .header(
                    "Access-Control-Allow-Headers",
                    self.allowed_headers.join(", "),
                )
                .header("Access-Control-Max-Age", self.max_age.to_string())
                .body(Vec::new())
                .map_err(|error| {
                    GatewayError::Config(format!(
                        "cors middleware generated an invalid preflight response: {error}"
                    ))
                })?;

            return Ok(Some(response));
        }

        Ok(None)
    }

    async fn handle_response(&self, resp: &mut http::response::Parts) -> Result<()> {
        self.ensure_valid()?;
        // Preserve the legacy direct-call behavior for callers that do not
        // have request headers. The request-aware hook below is used by the
        // gateway pipeline and reflects the actual origin.
        if let Some(origin) = self.allowed_origins.first() {
            resp.headers.insert(
                ACCESS_CONTROL_ALLOW_ORIGIN,
                HeaderValue::from_str(origin).map_err(|error| {
                    GatewayError::Config(format!(
                        "cors middleware generated an invalid origin header: {error}"
                    ))
                })?,
            );
        }
        Ok(())
    }

    async fn handle_response_with_request(
        &self,
        request_headers: &http::HeaderMap,
        resp: &mut http::response::Parts,
    ) -> Result<()> {
        self.ensure_valid()?;
        let Some(raw_origin) = request_headers.get(ORIGIN) else {
            return Ok(());
        };
        let Ok(origin) = raw_origin.to_str() else {
            resp.headers.remove(ACCESS_CONTROL_ALLOW_ORIGIN);
            return Ok(());
        };
        if !self.origin_allowed(origin) {
            resp.headers.remove(ACCESS_CONTROL_ALLOW_ORIGIN);
            return Ok(());
        }

        // Echo an explicitly allowed origin. This is required when more than
        // one origin is configured; returning the first configured origin
        // would make valid callers fail CORS and can poison shared caches.
        let response_origin = if self.allowed_origins.iter().any(|item| item == "*") {
            "*"
        } else {
            origin
        };
        resp.headers.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(response_origin).map_err(|error| {
                GatewayError::Config(format!(
                    "cors middleware generated an invalid origin header: {error}"
                ))
            })?,
        );
        if response_origin != "*" && !header_contains_token(&resp.headers, VARY, "Origin") {
            resp.headers
                .append(VARY, HeaderValue::from_static("Origin"));
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "cors"
    }
}

fn validate_origins(origins: &[String]) -> Result<()> {
    for origin in origins {
        if origin == "*" {
            continue;
        }
        if origin.is_empty() || origin.chars().any(char::is_whitespace) {
            return Err(GatewayError::Config(format!(
                "cors allowed origin '{origin}' must be non-empty and contain no whitespace"
            )));
        }
        HeaderValue::from_str(origin).map_err(|error| {
            GatewayError::Config(format!(
                "cors allowed origin '{origin}' is not a valid header value: {error}"
            ))
        })?;
    }
    Ok(())
}

fn validate_methods(methods: &[String]) -> Result<()> {
    for method in methods {
        if method.parse::<http::Method>().is_err() {
            return Err(GatewayError::Config(format!(
                "cors allowed method '{method}' is invalid"
            )));
        }
    }
    Ok(())
}

fn validate_headers(headers: &[String]) -> Result<()> {
    for header in headers {
        if header == "*" {
            continue;
        }
        HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            GatewayError::Config(format!(
                "cors allowed header '{header}' is invalid: {error}"
            ))
        })?;
    }
    Ok(())
}

fn header_contains_token(headers: &http::HeaderMap, name: HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value
            .to_str()
            .ok()
            .into_iter()
            .flat_map(|value| value.split(','))
            .any(|item| item.trim().eq_ignore_ascii_case(token))
    })
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

    fn make_config() -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "cors".to_string(),
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            max_age: Some(3600),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_cors_preflight_allowed() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://example.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        let resp = result.unwrap();
        assert_eq!(resp.status(), 204);
        assert!(resp.headers().contains_key("Access-Control-Allow-Origin"));
        assert!(resp.headers().contains_key("Access-Control-Allow-Methods"));
    }

    #[tokio::test]
    async fn test_cors_preflight_denied() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://evil.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 403);
    }

    #[tokio::test]
    async fn test_cors_non_preflight_passthrough() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _) = Request::builder()
            .method("GET")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_cors_wildcard_origin() {
        let mut config = make_config();
        config.allowed_origins = vec!["*".to_string()];
        let mw = CorsMiddleware::new(&config);

        let (mut parts, _) = Request::builder()
            .method("OPTIONS")
            .header("Origin", "https://anything.com")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 204);
    }

    #[tokio::test]
    async fn test_cors_response_headers() {
        let mw = CorsMiddleware::new(&make_config());
        let (mut parts, _body) = Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();

        mw.handle_response(&mut parts).await.unwrap();
        assert!(parts.headers.contains_key("Access-Control-Allow-Origin"));
    }

    #[test]
    fn test_cors_defaults() {
        let mut config = make_config();
        config.allowed_origins = vec![];
        config.allowed_methods = vec![];
        config.allowed_headers = vec![];
        config.max_age = None;

        let mw = CorsMiddleware::new(&config);
        assert_eq!(mw.allowed_origins, vec!["*"]);
        assert_eq!(mw.allowed_methods.len(), 5);
        assert_eq!(mw.allowed_headers.len(), 2);
        assert_eq!(mw.max_age, 86400);
    }

    #[test]
    fn test_cors_name() {
        let mw = CorsMiddleware::new(&make_config());
        assert_eq!(mw.name(), "cors");
    }

    #[test]
    fn invalid_cors_values_are_rejected() {
        let mut config = make_config();
        config.allowed_origins = vec!["https://bad origin.example".to_string()];
        assert!(CorsMiddleware::try_new(&config).is_err());

        let mut config = make_config();
        config.allowed_methods = vec!["GET\nPOST".to_string()];
        assert!(CorsMiddleware::try_new(&config).is_err());

        let mut config = make_config();
        config.allowed_headers = vec!["bad header".to_string()];
        assert!(CorsMiddleware::try_new(&config).is_err());
    }

    #[tokio::test]
    async fn response_uses_the_request_origin_for_multiple_allowed_origins() {
        let mut config = make_config();
        config.allowed_origins = vec![
            "https://example.com".to_string(),
            "https://app.example.com".to_string(),
        ];
        let mw = CorsMiddleware::try_new(&config).unwrap();
        let (mut parts, _) = Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();
        let request_headers = http::HeaderMap::from_iter([(
            ORIGIN,
            HeaderValue::from_static("https://app.example.com"),
        )]);

        mw.handle_response_with_request(&request_headers, &mut parts)
            .await
            .unwrap();
        assert_eq!(
            parts.headers.get(ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example.com"
        );
        assert_eq!(parts.headers.get(VARY).unwrap(), "Origin");
    }

    #[tokio::test]
    async fn response_omits_cors_header_for_disallowed_origin() {
        let mw = CorsMiddleware::try_new(&make_config()).unwrap();
        let (mut parts, _) = Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();
        let request_headers = http::HeaderMap::from_iter([(
            ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        )]);
        mw.handle_response_with_request(&request_headers, &mut parts)
            .await
            .unwrap();
        assert!(!parts.headers.contains_key(ACCESS_CONTROL_ALLOW_ORIGIN));
    }
}
