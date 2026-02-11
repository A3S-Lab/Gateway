//! Authentication middleware — API key and Basic Auth

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use http::Response;

/// Authentication middleware
pub struct AuthMiddleware {
    kind: AuthKind,
}

enum AuthKind {
    ApiKey {
        header: String,
        keys: Vec<String>,
    },
    BasicAuth {
        username: String,
        password: String,
    },
}

impl AuthMiddleware {
    /// Create an API key authentication middleware
    pub fn api_key(config: &MiddlewareConfig) -> Result<Self> {
        let header = config.header.clone().unwrap_or_else(|| "X-API-Key".to_string());
        if config.keys.is_empty() {
            return Err(GatewayError::Config(
                "api-key middleware requires at least one key".to_string(),
            ));
        }
        Ok(Self {
            kind: AuthKind::ApiKey {
                header,
                keys: config.keys.clone(),
            },
        })
    }

    /// Create a Basic Auth middleware
    pub fn basic_auth(config: &MiddlewareConfig) -> Result<Self> {
        let username = config.username.clone().ok_or_else(|| {
            GatewayError::Config("basic-auth middleware requires 'username'".to_string())
        })?;
        let password = config.password.clone().ok_or_else(|| {
            GatewayError::Config("basic-auth middleware requires 'password'".to_string())
        })?;
        Ok(Self {
            kind: AuthKind::BasicAuth { username, password },
        })
    }

    fn unauthorized_response(message: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(401)
            .header("Content-Type", "application/json")
            .body(format!(r#"{{"error":"{}"}}"#, message).into_bytes())
            .unwrap()
    }
}

#[async_trait]
impl Middleware for AuthMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        match &self.kind {
            AuthKind::ApiKey { header, keys } => {
                let provided = req.headers.get(header.as_str()).and_then(|v| v.to_str().ok());
                match provided {
                    Some(key) if keys.iter().any(|k| k == key) => Ok(None),
                    _ => Ok(Some(Self::unauthorized_response("Invalid or missing API key"))),
                }
            }
            AuthKind::BasicAuth { username, password } => {
                let auth_header = req
                    .headers
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok());

                match auth_header {
                    Some(value) if value.starts_with("Basic ") => {
                        let encoded = &value[6..];
                        let decoded = base64_decode(encoded);
                        let expected = format!("{}:{}", username, password);
                        if decoded == expected {
                            Ok(None)
                        } else {
                            Ok(Some(Self::unauthorized_response("Invalid credentials")))
                        }
                    }
                    _ => Ok(Some(Self::unauthorized_response("Missing Authorization header"))),
                }
            }
        }
    }

    fn name(&self) -> &str {
        "auth"
    }
}

/// Simple base64 decode (ASCII subset only, no padding validation)
fn base64_decode(input: &str) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn decode_char(c: u8) -> Option<u8> {
        TABLE.iter().position(|&b| b == c).map(|p| p as u8)
    }

    let bytes: Vec<u8> = input.bytes().filter(|&b| b != b'=').collect();
    let mut output = Vec::new();

    for chunk in bytes.chunks(4) {
        let vals: Vec<u8> = chunk.iter().filter_map(|&b| decode_char(b)).collect();
        if vals.len() >= 2 {
            output.push((vals[0] << 2) | (vals[1] >> 4));
        }
        if vals.len() >= 3 {
            output.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if vals.len() >= 4 {
            output.push((vals[2] << 6) | vals[3]);
        }
    }

    String::from_utf8_lossy(&output).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Request;
    use std::collections::HashMap;

    fn make_ctx() -> RequestContext {
        RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        }
    }

    fn make_config(mw_type: &str) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: mw_type.to_string(),
            header: None,
            keys: vec![],
            value: None,
            username: None,
            password: None,
            rate: None,
            burst: None,
            allowed_origins: vec![],
            allowed_methods: vec![],
            allowed_headers: vec![],
            max_age: None,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            prefixes: vec![],
            max_retries: None,
            retry_interval_ms: None,
            allowed_ips: vec![],
        }
    }

    #[test]
    fn test_api_key_requires_keys() {
        let config = make_config("api-key");
        let result = AuthMiddleware::api_key(&config);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_api_key_valid() {
        let mut config = make_config("api-key");
        config.header = Some("X-API-Key".to_string());
        config.keys = vec!["secret123".to_string()];

        let mw = AuthMiddleware::api_key(&config).unwrap();
        let (mut parts, _) = Request::builder()
            .header("X-API-Key", "secret123")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none()); // pass through
    }

    #[tokio::test]
    async fn test_api_key_invalid() {
        let mut config = make_config("api-key");
        config.header = Some("X-API-Key".to_string());
        config.keys = vec!["secret123".to_string()];

        let mw = AuthMiddleware::api_key(&config).unwrap();
        let (mut parts, _) = Request::builder()
            .header("X-API-Key", "wrong-key")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn test_api_key_missing() {
        let mut config = make_config("api-key");
        config.keys = vec!["secret123".to_string()];

        let mw = AuthMiddleware::api_key(&config).unwrap();
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[test]
    fn test_basic_auth_requires_username() {
        let mut config = make_config("basic-auth");
        config.password = Some("pass".to_string());
        assert!(AuthMiddleware::basic_auth(&config).is_err());
    }

    #[test]
    fn test_basic_auth_requires_password() {
        let mut config = make_config("basic-auth");
        config.username = Some("user".to_string());
        assert!(AuthMiddleware::basic_auth(&config).is_err());
    }

    #[tokio::test]
    async fn test_basic_auth_valid() {
        let mut config = make_config("basic-auth");
        config.username = Some("admin".to_string());
        config.password = Some("secret".to_string());

        let mw = AuthMiddleware::basic_auth(&config).unwrap();
        // "admin:secret" in base64 = "YWRtaW46c2VjcmV0"
        let (mut parts, _) = Request::builder()
            .header("Authorization", "Basic YWRtaW46c2VjcmV0")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_basic_auth_invalid() {
        let mut config = make_config("basic-auth");
        config.username = Some("admin".to_string());
        config.password = Some("secret".to_string());

        let mw = AuthMiddleware::basic_auth(&config).unwrap();
        // "wrong:creds" in base64 = "d3Jvbmc6Y3JlZHM="
        let (mut parts, _) = Request::builder()
            .header("Authorization", "Basic d3Jvbmc6Y3JlZHM=")
            .body(())
            .unwrap()
            .into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn test_basic_auth_missing_header() {
        let mut config = make_config("basic-auth");
        config.username = Some("admin".to_string());
        config.password = Some("secret".to_string());

        let mw = AuthMiddleware::basic_auth(&config).unwrap();
        let (mut parts, _) = Request::builder().body(()).unwrap().into_parts();

        let result = mw.handle_request(&mut parts, &make_ctx()).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("YWRtaW46c2VjcmV0"), "admin:secret");
        assert_eq!(base64_decode("dGVzdA=="), "test");
        assert_eq!(base64_decode(""), "");
    }

    #[test]
    fn test_auth_middleware_name() {
        let mut config = make_config("api-key");
        config.keys = vec!["key".to_string()];
        let mw = AuthMiddleware::api_key(&config).unwrap();
        assert_eq!(mw.name(), "auth");
    }
}
