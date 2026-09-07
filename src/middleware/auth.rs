//! Authentication middleware — API key and Basic Auth

use super::{Middleware, RequestContext};
use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http::Response;

/// Authentication middleware
pub struct AuthMiddleware {
    kind: AuthKind,
}

enum AuthKind {
    ApiKey { header: String, keys: Vec<String> },
    BasicAuth { username: String, password: String },
}

impl AuthMiddleware {
    /// Create an API key authentication middleware
    pub fn api_key(config: &MiddlewareConfig) -> Result<Self> {
        let header = config
            .header
            .clone()
            .unwrap_or_else(|| "X-API-Key".to_string());
        http::header::HeaderName::from_bytes(header.as_bytes()).map_err(|error| {
            GatewayError::Config(format!("api-key middleware header is invalid: {error}"))
        })?;
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
            .body(crate::error::json_error_body(message))
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
                let provided = req
                    .headers
                    .get(header.as_str())
                    .and_then(|v| v.to_str().ok());
                match provided {
                    Some(key)
                        if keys.iter().any(|expected| {
                            constant_time_eq(key.as_bytes(), expected.as_bytes())
                        }) =>
                    {
                        Ok(None)
                    }
                    _ => Ok(Some(Self::unauthorized_response(
                        "Invalid or missing API key",
                    ))),
                }
            }
            AuthKind::BasicAuth { username, password } => {
                let auth_header = req
                    .headers
                    .get("Authorization")
                    .and_then(|v| v.to_str().ok());

                match auth_header.and_then(parse_basic_credentials) {
                    Some(decoded) => {
                        let expected = format!("{}:{}", username, password);
                        if constant_time_eq(&decoded, expected.as_bytes()) {
                            Ok(None)
                        } else {
                            Ok(Some(Self::unauthorized_response("Invalid credentials")))
                        }
                    }
                    None => Ok(Some(Self::unauthorized_response(
                        "Missing Authorization header",
                    ))),
                }
            }
        }
    }

    fn name(&self) -> &str {
        "auth"
    }
}

fn parse_basic_credentials(value: &str) -> Option<Vec<u8>> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() {
        return None;
    }
    STANDARD.decode(encoded).ok()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let max_len = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..max_len {
        difference |= u8::from(
            left.get(index).copied().unwrap_or_default()
                != right.get(index).copied().unwrap_or_default(),
        ) as usize;
    }
    difference == 0
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

    fn make_config(mw_type: &str) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: mw_type.to_string(),
            ..Default::default()
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
    fn test_basic_credentials_use_strict_base64() {
        assert_eq!(
            parse_basic_credentials("Basic YWRtaW46c2VjcmV0").unwrap(),
            b"admin:secret"
        );
        assert!(parse_basic_credentials("Basic !!!").is_none());
        assert!(parse_basic_credentials("Bearer YWRtaW46c2VjcmV0").is_none());
    }

    #[test]
    fn test_api_key_header_must_be_valid() {
        let mut config = make_config("api-key");
        config.keys = vec!["key".to_string()];
        config.header = Some("not a header".to_string());
        assert!(AuthMiddleware::api_key(&config).is_err());
    }

    #[test]
    fn test_auth_middleware_name() {
        let mut config = make_config("api-key");
        config.keys = vec!["key".to_string()];
        let mw = AuthMiddleware::api_key(&config).unwrap();
        assert_eq!(mw.name(), "auth");
    }
}
