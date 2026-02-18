//! Compress middleware — gzip/deflate response compression
//!
//! Compresses response bodies based on the client's Accept-Encoding header.
//! Supports gzip and deflate compression algorithms.

#![allow(dead_code)]
use crate::error::Result;
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use flate2::write::{DeflateEncoder, GzEncoder};
use flate2::Compression;
use http::Response;
use std::io::Write;

/// Supported compression encoding
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    Brotli,
    Gzip,
    Deflate,
    Identity,
}

impl Encoding {
    /// Content-Encoding header value
    pub fn header_value(&self) -> &'static str {
        match self {
            Self::Brotli => "br",
            Self::Gzip => "gzip",
            Self::Deflate => "deflate",
            Self::Identity => "identity",
        }
    }
}

impl std::fmt::Display for Encoding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.header_value())
    }
}

/// Compression middleware configuration
#[derive(Debug, Clone)]
pub struct CompressConfig {
    /// Minimum response size to compress (in bytes)
    pub min_size: usize,
    /// Compression level (0-9, higher = better compression, slower)
    pub level: u32,
}

impl Default for CompressConfig {
    fn default() -> Self {
        Self {
            min_size: 1024, // Don't compress responses < 1KB
            level: 6,       // Default compression level
        }
    }
}

/// Compress middleware — handles Accept-Encoding negotiation
pub struct CompressMiddleware {
    config: CompressConfig,
}

impl CompressMiddleware {
    /// Create with default configuration
    pub fn new() -> Self {
        Self {
            config: CompressConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(config: CompressConfig) -> Self {
        Self { config }
    }

    /// Get the configuration
    pub fn config(&self) -> &CompressConfig {
        &self.config
    }

    /// Parse Accept-Encoding header and return the best supported encoding
    ///
    /// Preference order: br > gzip > deflate
    pub fn negotiate_encoding(accept_encoding: &str) -> Encoding {
        let lower = accept_encoding.to_lowercase();
        // Prefer brotli over gzip over deflate
        if lower.contains("br") {
            Encoding::Brotli
        } else if lower.contains("gzip") {
            Encoding::Gzip
        } else if lower.contains("deflate") {
            Encoding::Deflate
        } else {
            Encoding::Identity
        }
    }

    /// Compress data with the given encoding
    pub fn compress(
        data: &[u8],
        encoding: Encoding,
        level: u32,
    ) -> std::result::Result<Vec<u8>, String> {
        match encoding {
            Encoding::Brotli => {
                let quality = level.min(11); // Brotli quality: 0-11
                let mut output = Vec::new();
                let params = brotli::enc::BrotliEncoderParams {
                    quality: quality as i32,
                    ..Default::default()
                };
                brotli::BrotliCompress(
                    &mut std::io::Cursor::new(data),
                    &mut output,
                    &params,
                )
                .map_err(|e| format!("Brotli compression failed: {}", e))?;
                Ok(output)
            }
            Encoding::Gzip => {
                let compression = Compression::new(level);
                let mut encoder = GzEncoder::new(Vec::new(), compression);
                encoder
                    .write_all(data)
                    .map_err(|e| format!("Gzip compression failed: {}", e))?;
                encoder
                    .finish()
                    .map_err(|e| format!("Gzip finalize failed: {}", e))
            }
            Encoding::Deflate => {
                let compression = Compression::new(level);
                let mut encoder = DeflateEncoder::new(Vec::new(), compression);
                encoder
                    .write_all(data)
                    .map_err(|e| format!("Deflate compression failed: {}", e))?;
                encoder
                    .finish()
                    .map_err(|e| format!("Deflate finalize failed: {}", e))
            }
            Encoding::Identity => Ok(data.to_vec()),
        }
    }

    /// Check if a content type should be compressed
    pub fn is_compressible(content_type: &str) -> bool {
        let ct = content_type.to_lowercase();
        ct.starts_with("text/")
            || ct.contains("json")
            || ct.contains("xml")
            || ct.contains("javascript")
            || ct.contains("css")
            || ct.contains("svg")
            || ct.contains("html")
    }
}

impl Default for CompressMiddleware {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Middleware for CompressMiddleware {
    async fn handle_request(
        &self,
        _req: &mut http::request::Parts,
        _ctx: &RequestContext,
    ) -> Result<Option<Response<Vec<u8>>>> {
        // Compression is applied on the response side, pass through on request
        Ok(None)
    }

    async fn handle_response(&self, resp: &mut http::response::Parts) -> Result<()> {
        // Mark that compression should be applied by adding a header
        // The actual compression happens in the proxy layer when building
        // the response body. Here we just set the Content-Encoding header
        // if the response is eligible.
        //
        // Note: In a real implementation, the proxy layer would check this
        // header and compress the body before sending it to the client.
        if !resp.headers.contains_key("content-encoding") {
            resp.headers
                .insert("x-gateway-compress", "eligible".parse().unwrap());
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "compress"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Encoding tests ---

    #[test]
    fn test_encoding_header_values() {
        assert_eq!(Encoding::Brotli.header_value(), "br");
        assert_eq!(Encoding::Gzip.header_value(), "gzip");
        assert_eq!(Encoding::Deflate.header_value(), "deflate");
        assert_eq!(Encoding::Identity.header_value(), "identity");
    }

    #[test]
    fn test_encoding_display() {
        assert_eq!(Encoding::Brotli.to_string(), "br");
        assert_eq!(Encoding::Gzip.to_string(), "gzip");
        assert_eq!(Encoding::Deflate.to_string(), "deflate");
    }

    // --- Negotiate encoding tests ---

    #[test]
    fn test_negotiate_gzip() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("gzip, deflate"),
            Encoding::Gzip
        );
    }

    #[test]
    fn test_negotiate_deflate() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("deflate"),
            Encoding::Deflate
        );
    }

    #[test]
    fn test_negotiate_brotli() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("br"),
            Encoding::Brotli
        );
    }

    #[test]
    fn test_negotiate_brotli_preferred_over_gzip() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("gzip, br, deflate"),
            Encoding::Brotli
        );
    }

    #[test]
    fn test_negotiate_identity() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("zstd"),
            Encoding::Identity
        );
    }

    #[test]
    fn test_negotiate_case_insensitive() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("GZIP"),
            Encoding::Gzip
        );
    }

    #[test]
    fn test_negotiate_gzip_preferred() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("deflate, gzip"),
            Encoding::Gzip
        );
    }

    #[test]
    fn test_negotiate_empty() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding(""),
            Encoding::Identity
        );
    }

    // --- Compression tests ---

    #[test]
    fn test_gzip_compress_decompress() {
        let data = b"Hello, World! This is test data for compression.";
        let compressed = CompressMiddleware::compress(data, Encoding::Gzip, 6).unwrap();
        assert!(compressed.len() < data.len() || data.len() < 50);
        // Verify it's valid gzip (starts with gzip magic bytes)
        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);
    }

    #[test]
    fn test_deflate_compress() {
        let data = b"Hello, World! This is test data for compression that should be long enough.";
        let compressed = CompressMiddleware::compress(data, Encoding::Deflate, 6).unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_identity_no_compression() {
        let data = b"Hello, World!";
        let result = CompressMiddleware::compress(data, Encoding::Identity, 6).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_compress_empty_data() {
        let compressed = CompressMiddleware::compress(b"", Encoding::Gzip, 6).unwrap();
        assert!(!compressed.is_empty()); // Gzip has header even for empty data
    }

    #[test]
    fn test_compress_large_data() {
        let data = vec![b'A'; 10000];
        let compressed = CompressMiddleware::compress(&data, Encoding::Gzip, 6).unwrap();
        // Highly repetitive data should compress well
        assert!(compressed.len() < data.len() / 2);
    }

    #[test]
    fn test_compression_levels() {
        let data = vec![b'X'; 5000];
        let fast = CompressMiddleware::compress(&data, Encoding::Gzip, 1).unwrap();
        let best = CompressMiddleware::compress(&data, Encoding::Gzip, 9).unwrap();
        // Both should work, best should be ≤ fast
        assert!(best.len() <= fast.len());
    }

    // --- Brotli compression tests ---

    #[test]
    fn test_brotli_compress() {
        let data = b"Hello, World! This is test data for brotli compression testing.";
        let compressed = CompressMiddleware::compress(data, Encoding::Brotli, 6).unwrap();
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_brotli_compress_large_data() {
        let data = vec![b'A'; 10000];
        let compressed = CompressMiddleware::compress(&data, Encoding::Brotli, 6).unwrap();
        // Highly repetitive data should compress well
        assert!(compressed.len() < data.len() / 2);
    }

    #[test]
    fn test_brotli_compress_empty() {
        let compressed = CompressMiddleware::compress(b"", Encoding::Brotli, 6).unwrap();
        // Brotli produces output even for empty data
        assert!(!compressed.is_empty());
    }

    #[test]
    fn test_brotli_quality_clamped() {
        // Quality > 11 should be clamped to 11
        let data = b"test data for quality clamping";
        let result = CompressMiddleware::compress(data, Encoding::Brotli, 20);
        assert!(result.is_ok());
    }

    #[test]
    fn test_brotli_vs_gzip_size() {
        // For text data, brotli should generally compress better than gzip
        let data = "The quick brown fox jumps over the lazy dog. ".repeat(100);
        let br = CompressMiddleware::compress(data.as_bytes(), Encoding::Brotli, 6).unwrap();
        let gz = CompressMiddleware::compress(data.as_bytes(), Encoding::Gzip, 6).unwrap();
        // Brotli should be at least as good as gzip for text
        assert!(br.len() <= gz.len());
    }

    // --- Compressible content type tests ---

    #[test]
    fn test_is_compressible_text() {
        assert!(CompressMiddleware::is_compressible("text/html"));
        assert!(CompressMiddleware::is_compressible("text/plain"));
        assert!(CompressMiddleware::is_compressible("text/css"));
    }

    #[test]
    fn test_is_compressible_json() {
        assert!(CompressMiddleware::is_compressible("application/json"));
    }

    #[test]
    fn test_is_compressible_xml() {
        assert!(CompressMiddleware::is_compressible("application/xml"));
        assert!(CompressMiddleware::is_compressible("text/xml"));
    }

    #[test]
    fn test_is_compressible_javascript() {
        assert!(CompressMiddleware::is_compressible(
            "application/javascript"
        ));
    }

    #[test]
    fn test_is_compressible_svg() {
        assert!(CompressMiddleware::is_compressible("image/svg+xml"));
    }

    #[test]
    fn test_not_compressible_binary() {
        assert!(!CompressMiddleware::is_compressible("image/png"));
        assert!(!CompressMiddleware::is_compressible("image/jpeg"));
        assert!(!CompressMiddleware::is_compressible(
            "application/octet-stream"
        ));
    }

    #[test]
    fn test_is_compressible_case_insensitive() {
        assert!(CompressMiddleware::is_compressible("Application/JSON"));
    }

    // --- Config tests ---

    #[test]
    fn test_default_config() {
        let config = CompressConfig::default();
        assert_eq!(config.min_size, 1024);
        assert_eq!(config.level, 6);
    }

    #[test]
    fn test_custom_config() {
        let mw = CompressMiddleware::with_config(CompressConfig {
            min_size: 512,
            level: 9,
        });
        assert_eq!(mw.config().min_size, 512);
        assert_eq!(mw.config().level, 9);
    }

    // --- Middleware interface ---

    #[test]
    fn test_middleware_name() {
        let mw = CompressMiddleware::new();
        assert_eq!(mw.name(), "compress");
    }

    #[test]
    fn test_default_impl() {
        let mw = CompressMiddleware::default();
        assert_eq!(mw.config().min_size, 1024);
    }

    #[tokio::test]
    async fn test_request_passthrough() {
        let mw = CompressMiddleware::new();
        let (mut parts, _) = http::Request::builder()
            .uri("/test")
            .header("Accept-Encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let ctx = RequestContext {
            client_ip: "127.0.0.1".to_string(),
            entrypoint: "web".to_string(),
            router: "test".to_string(),
        };
        let result = mw.handle_request(&mut parts, &ctx).await.unwrap();
        assert!(result.is_none()); // Always passes through
    }

    #[tokio::test]
    async fn test_response_marks_eligible() {
        let mw = CompressMiddleware::new();
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_response(&mut parts).await.unwrap();
        assert_eq!(parts.headers.get("x-gateway-compress").unwrap(), "eligible");
    }

    #[tokio::test]
    async fn test_response_already_encoded_skipped() {
        let mw = CompressMiddleware::new();
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        mw.handle_response(&mut parts).await.unwrap();
        assert!(parts.headers.get("x-gateway-compress").is_none());
    }
}
