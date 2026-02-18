//! JWT authentication middleware — validates JSON Web Tokens
//!
//! Extracts and validates JWT tokens from the Authorization header,
//! supporting HS256/HS384/HS512 HMAC algorithms.

use crate::config::MiddlewareConfig;
use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use http::Response;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// Standard JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (user ID)
    #[serde(default)]
    pub sub: String,
    /// Expiration time (UTC timestamp)
    #[serde(default)]
    pub exp: u64,
    /// Issued at (UTC timestamp)
    #[serde(default)]
    pub iat: u64,
    /// Issuer
    #[serde(default)]
    pub iss: String,
    /// Audience
    #[serde(default)]
    pub aud: String,
}

/// JWT authentication middleware
pub struct JwtAuthMiddleware {
    /// Decoding key (from HMAC secret)
    decoding_key: DecodingKey,
    /// Validation configuration
    validation: Validation,
    /// Header name to extract the token from
    header_name: String,
    /// Token prefix to strip (e.g., "Bearer ")
    token_prefix: String,
}

impl JwtAuthMiddleware {
    /// Create from middleware config
    pub fn new(config: &MiddlewareConfig) -> Result<Self> {
        let secret = config.value.as_deref().ok_or_else(|| {
            GatewayError::Config("JWT middleware requires 'value' field as HMAC secret".to_string())
        })?;

        if secret.is_empty() {
            return Err(GatewayError::Config(
                "JWT secret cannot be empty".to_string(),
            ));
        }

        let header_name = config
            .header
            .clone()
            .unwrap_or_else(|| "Authorization".to_string());

        let decoding_key = DecodingKey::from_secret(secret.as_bytes());

        let mut validation = Validation::new(Algorithm::HS256);
        // Don't validate aud/iss by default
        validation.validate_aud = false;
        // Require exp claim
        validation.required_spec_claims = ["exp"].iter().map(|s| s.to_string()).collect();

        Ok(Self {
            decoding_key,
            validation,
            header_name,
            token_prefix: "Bearer ".to_string(),
        })
    }

    /// Create directly from a secret string (for programmatic use)
    #[allow(dead_code)]
    pub fn from_secret(secret: &str) -> Result<Self> {
        if secret.is_empty() {
            return Err(GatewayError::Config(
                "JWT secret cannot be empty".to_string(),
            ));
        }

        let decoding_key = DecodingKey::from_secret(secret.as_bytes());
        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_aud = false;
        validation.required_spec_claims = ["exp"].iter().map(|s| s.to_string()).collect();

        Ok(Self {
            decoding_key,
            validation,
            header_name: "Authorization".to_string(),
            token_prefix: "Bearer ".to_string(),
        })
    }

    /// Validate a JWT token string and return the claims
    pub fn validate_token(&self, token: &str) -> std::result::Result<Claims, String> {
        decode::<Claims>(token, &self.decoding_key, &self.validation)
            .map(|data| data.claims)
            .map_err(|e| format!("JWT validation failed: {}", e))
    }

    /// Extract the token from a header value (strips "Bearer " prefix)
    pub fn extract_token<'a>(&self, header_value: &'a str) -> Option<&'a str> {
        if header_value.starts_with(&self.token_prefix) {
            Some(&header_value[self.token_prefix.len()..])
        } else {
            // Try raw token (no prefix)
            Some(header_value)
        }
    }
}

#[async_trait]
impl Middleware for JwtAuthMiddleware {
    async fn handle_request(
        &self,
        req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        let header_value = match req.headers.get(&self.header_name) {
            Some(v) => match v.to_str() {
                Ok(s) => s.to_string(),
                Err(_) => {
                    return Ok(Some(
                        Response::builder()
                            .status(401)
                            .body(r#"{"error":"Invalid authorization header"}"#.as_bytes().to_vec())
                            .unwrap(),
                    ));
                }
            },
            None => {
                return Ok(Some(
                    Response::builder()
                        .status(401)
                        .body(r#"{"error":"Missing authorization header"}"#.as_bytes().to_vec())
                        .unwrap(),
                ));
            }
        };

        let token = match self.extract_token(&header_value) {
            Some(t) if !t.is_empty() => t.to_string(),
            _ => {
                return Ok(Some(
                    Response::builder()
                        .status(401)
                        .body(r#"{"error":"Missing token"}"#.as_bytes().to_vec())
                        .unwrap(),
                ));
            }
        };

        match self.validate_token(&token) {
            Ok(claims) => {
                // Inject claims as headers for downstream services
                if !claims.sub.is_empty() {
                    if let Ok(v) = claims.sub.parse() {
                        req.headers.insert("x-jwt-subject", v);
                    }
                }
                Ok(None) // Continue pipeline
            }
            Err(e) => {
                tracing::debug!(error = %e, "JWT validation failed");
                Ok(Some(
                    Response::builder()
                        .status(401)
                        .body(format!(r#"{{"error":"{}"}}"#, e).as_bytes().to_vec())
                        .unwrap(),
                ))
            }
        }
    }

    fn name(&self) -> &str {
        "jwt-auth"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};

    const TEST_SECRET: &str = "test-secret-key-for-unit-tests";

    fn make_token(claims: &Claims) -> String {
        encode(
            &Header::default(),
            claims,
            &EncodingKey::from_secret(TEST_SECRET.as_bytes()),
        )
        .unwrap()
    }

    fn valid_claims() -> Claims {
        Claims {
            sub: "user-123".to_string(),
            exp: (chrono::Utc::now().timestamp() + 3600) as u64,
            iat: chrono::Utc::now().timestamp() as u64,
            iss: "test".to_string(),
            aud: "".to_string(),
        }
    }

    fn expired_claims() -> Claims {
        Claims {
            sub: "user-123".to_string(),
            exp: 1000, // Long expired
            iat: 999,
            iss: "test".to_string(),
            aud: "".to_string(),
        }
    }

    fn jwt_config(secret: &str) -> MiddlewareConfig {
        MiddlewareConfig {
            middleware_type: "jwt".to_string(),
            value: Some(secret.to_string()),
            ..Default::default()
        }
    }

    // --- Construction tests ---

    #[test]
    fn test_jwt_name() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        assert_eq!(mw.name(), "jwt-auth");
    }

    #[test]
    fn test_from_config() {
        let mw = JwtAuthMiddleware::new(&jwt_config(TEST_SECRET));
        assert!(mw.is_ok());
    }

    #[test]
    fn test_from_config_missing_secret() {
        let mut config = jwt_config(TEST_SECRET);
        config.value = None;
        let result = JwtAuthMiddleware::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_config_empty_secret() {
        let result = JwtAuthMiddleware::new(&jwt_config(""));
        assert!(result.is_err());
    }

    #[test]
    fn test_from_secret_empty() {
        let result = JwtAuthMiddleware::from_secret("");
        assert!(result.is_err());
    }

    #[test]
    fn test_from_config_custom_header() {
        let mut config = jwt_config(TEST_SECRET);
        config.header = Some("X-Auth-Token".to_string());
        let mw = JwtAuthMiddleware::new(&config).unwrap();
        assert_eq!(mw.header_name, "X-Auth-Token");
    }

    // --- Token validation tests ---

    #[test]
    fn test_validate_valid_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let token = make_token(&valid_claims());
        let result = mw.validate_token(&token);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().sub, "user-123");
    }

    #[test]
    fn test_validate_expired_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let token = make_token(&expired_claims());
        let result = mw.validate_token(&token);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.contains("expired") || err.contains("Expired") || err.contains("ExpiredSignature"),
            "Unexpected error message: {}",
            err
        );
    }

    #[test]
    fn test_validate_wrong_secret() {
        let mw = JwtAuthMiddleware::from_secret("wrong-secret").unwrap();
        let token = make_token(&valid_claims());
        let result = mw.validate_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_malformed_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let result = mw.validate_token("not.a.valid.jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_empty_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let result = mw.validate_token("");
        assert!(result.is_err());
    }

    // --- Token extraction tests ---

    #[test]
    fn test_extract_bearer_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        assert_eq!(mw.extract_token("Bearer abc123"), Some("abc123"));
    }

    #[test]
    fn test_extract_raw_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        assert_eq!(mw.extract_token("abc123"), Some("abc123"));
    }

    // --- Middleware request handling tests ---

    #[tokio::test]
    async fn test_request_with_valid_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let token = make_token(&valid_claims());
        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "api".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none()); // Should pass through
        assert_eq!(parts.headers.get("x-jwt-subject").unwrap(), "user-123");
    }

    #[tokio::test]
    async fn test_request_with_expired_token() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let token = make_token(&expired_claims());
        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "api".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn test_request_missing_header() {
        let mw = JwtAuthMiddleware::from_secret(TEST_SECRET).unwrap();
        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "api".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    #[tokio::test]
    async fn test_request_wrong_secret() {
        let mw = JwtAuthMiddleware::from_secret("different-secret").unwrap();
        let token = make_token(&valid_claims());
        let (mut parts, _) = http::Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {}", token))
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "api".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().status(), 401);
    }

    // --- Claims serialization ---

    #[test]
    fn test_claims_serialization() {
        let claims = valid_claims();
        let json = serde_json::to_string(&claims).unwrap();
        let parsed: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.sub, "user-123");
    }
}
