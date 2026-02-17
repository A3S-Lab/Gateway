//! Headers middleware — add/modify request and response headers

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::Result;
use async_trait::async_trait;
use http::Response;
use std::collections::HashMap;

/// Headers modification middleware
pub struct HeadersMiddleware {
    request_headers: HashMap<String, String>,
    response_headers: HashMap<String, String>,
}

impl HeadersMiddleware {
    /// Create a new headers middleware from configuration
    pub fn new(config: &MiddlewareConfig) -> Self {
        Self {
            request_headers: config.request_headers.clone(),
            response_headers: config.response_headers.clone(),
        }
    }
}

#[async_trait]
impl Middleware for HeadersMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        for (key, value) in &self.request_headers {
            if let (Ok(name), Ok(val)) = (
                key.parse::<http::header::HeaderName>(),
                value.parse::<http::header::HeaderValue>(),
            ) {
                req.headers.insert(name, val);
            }
        }
        Ok(None)
    }

    async fn handle_response(&self, resp: &mut http::response::Parts) -> Result<()> {
        for (key, value) in &self.response_headers {
            if let (Ok(name), Ok(val)) = (
                key.parse::<http::header::HeaderName>(),
                value.parse::<http::header::HeaderValue>(),
            ) {
                resp.headers.insert(name, val);
            }
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
}
