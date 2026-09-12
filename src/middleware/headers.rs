//! Headers middleware — add/modify request and response headers

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;
use std::collections::HashMap;

/// Headers modification middleware
#[derive(Debug)]
pub struct HeadersMiddleware {
    request_headers: Vec<(http::header::HeaderName, http::HeaderValue)>,
    response_headers: Vec<(http::header::HeaderName, http::HeaderValue)>,
    configuration_error: Option<String>,
}

impl HeadersMiddleware {
    /// Create a new headers middleware from configuration.
    ///
    /// This compatibility constructor retains the historical infallible API.
    /// Invalid entries are retained as a deferred configuration error and are
    /// returned by the first request/response operation instead of being
    /// silently discarded.
    pub fn new(config: &MiddlewareConfig) -> Self {
        match Self::try_new(config) {
            Ok(middleware) => middleware,
            Err(error) => Self {
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                configuration_error: Some(error.to_string()),
            },
        }
    }

    /// Create a new headers middleware and reject malformed header names or
    /// values during configuration validation.
    pub fn try_new(config: &MiddlewareConfig) -> Result<Self> {
        Ok(Self {
            request_headers: parse_headers(&config.request_headers, "request_headers")?,
            response_headers: parse_headers(&config.response_headers, "response_headers")?,
            configuration_error: None,
        })
    }

    fn ensure_valid(&self) -> Result<()> {
        if let Some(error) = &self.configuration_error {
            return Err(GatewayError::Config(format!(
                "headers middleware configuration is invalid: {error}"
            )));
        }
        Ok(())
    }
}

fn parse_headers(
    headers: &HashMap<String, String>,
    section: &str,
) -> Result<Vec<(http::header::HeaderName, http::HeaderValue)>> {
    // Sort keys so configuration errors are deterministic even though ACL
    // maps are represented by a HashMap.
    let mut entries = headers.iter().collect::<Vec<_>>();
    entries.sort_unstable_by_key(|(left, _)| *left);

    entries
        .into_iter()
        .map(|(key, value)| {
            let name = key.parse::<http::header::HeaderName>().map_err(|error| {
                GatewayError::Config(format!(
                    "headers middleware {section} entry '{key}' has an invalid name: {error}"
                ))
            })?;
            let value = value.parse::<http::HeaderValue>().map_err(|error| {
                GatewayError::Config(format!(
                    "headers middleware {section} entry '{key}' has an invalid value: {error}"
                ))
            })?;
            Ok((name, value))
        })
        .collect()
}

#[async_trait]
impl Middleware for HeadersMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        self.ensure_valid()?;
        for (name, value) in &self.request_headers {
            req.headers.insert(name.clone(), value.clone());
        }
        Ok(None)
    }

    async fn handle_response(&self, resp: &mut http::response::Parts) -> Result<()> {
        self.ensure_valid()?;
        for (name, value) in &self.response_headers {
            resp.headers.insert(name.clone(), value.clone());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "headers"
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

    fn make_config(
        req_headers: HashMap<String, String>,
        resp_headers: HashMap<String, String>,
    ) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "headers".to_string(),
            request_headers: req_headers,
            response_headers: resp_headers,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_add_request_headers() {
        let mut req_h = HashMap::new();
        req_h.insert("X-Forwarded-Proto".to_string(), "https".to_string());
        let config = make_config(req_h, HashMap::new());
        let mw = HeadersMiddleware::new(&config);

        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none());
        assert_eq!(parts.headers.get("X-Forwarded-Proto").unwrap(), "https");
    }

    #[tokio::test]
    async fn test_add_response_headers() {
        let mut resp_h = HashMap::new();
        resp_h.insert("X-Frame-Options".to_string(), "DENY".to_string());
        let config = make_config(HashMap::new(), resp_h);
        let mw = HeadersMiddleware::new(&config);

        let (mut parts, _) = Response::builder().body(()).unwrap().into_parts();
        mw.handle_response(&mut parts).await.unwrap();
        assert_eq!(parts.headers.get("X-Frame-Options").unwrap(), "DENY");
    }

    #[tokio::test]
    async fn test_empty_headers_passthrough() {
        let config = make_config(HashMap::new(), HashMap::new());
        let mw = HeadersMiddleware::new(&config);

        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_headers_name() {
        let config = make_config(HashMap::new(), HashMap::new());
        let mw = HeadersMiddleware::new(&config);
        assert_eq!(mw.name(), "headers");
    }

    #[test]
    fn invalid_header_configuration_is_rejected() {
        let config = make_config(
            HashMap::from([("bad header".to_string(), "value".to_string())]),
            HashMap::new(),
        );
        let error = HeadersMiddleware::try_new(&config).unwrap_err().to_string();
        assert!(error.contains("request_headers"));
        assert!(error.contains("invalid name"));
    }

    #[tokio::test]
    async fn compatibility_constructor_does_not_silently_drop_invalid_headers() {
        let config = make_config(
            HashMap::from([("X-Test".to_string(), "bad\nvalue".to_string())]),
            HashMap::new(),
        );
        let mw = HeadersMiddleware::new(&config);
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();
        let error = mw
            .handle_request(&mut parts, &make_ctx())
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("configuration is invalid"));
    }
}
