//! Compress middleware — Brotli, gzip, and deflate response compression
//!
//! Compresses response bodies based on the client's Accept-Encoding header.
//! Supports Brotli, gzip, and deflate compression algorithms.

use crate::error::{GatewayError, Result};
use crate::middleware::{Middleware, RequestContext};
use async_trait::async_trait;
use bytes::Bytes;
use flate2::write::{GzEncoder, ZlibEncoder};
use flate2::Compression;
use http::{HeaderMap, HeaderValue, Response, StatusCode};
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
    /// Compression level (clamped to the selected encoding's supported range)
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
        let mut brotli = None;
        let mut gzip = None;
        let mut deflate = None;
        let mut identity = None;
        let mut wildcard = None;

        for item in accept_encoding.split(',') {
            let mut segments = item.split(';');
            let token = segments.next().unwrap_or_default().trim();
            let quality = parse_quality(segments);
            let slot = if token.eq_ignore_ascii_case("br") {
                Some(&mut brotli)
            } else if token.eq_ignore_ascii_case("gzip") {
                Some(&mut gzip)
            } else if token.eq_ignore_ascii_case("deflate") {
                Some(&mut deflate)
            } else if token.eq_ignore_ascii_case("identity") {
                Some(&mut identity)
            } else if token == "*" {
                Some(&mut wildcard)
            } else {
                None
            };
            if let Some(slot) = slot {
                retain_highest_quality(slot, quality);
            }
        }

        let wildcard = wildcard.unwrap_or(0.0);
        let mut selected = Encoding::Identity;
        let mut selected_quality = identity.unwrap_or(0.0);
        for (encoding, quality) in [
            (Encoding::Brotli, brotli.unwrap_or(wildcard)),
            (Encoding::Gzip, gzip.unwrap_or(wildcard)),
            (Encoding::Deflate, deflate.unwrap_or(wildcard)),
        ] {
            if quality > selected_quality
                || quality > 0.0 && quality == selected_quality && selected == Encoding::Identity
            {
                selected = encoding;
                selected_quality = quality;
            }
        }
        selected
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
                brotli::BrotliCompress(&mut std::io::Cursor::new(data), &mut output, &params)
                    .map_err(|e| format!("Brotli compression failed: {}", e))?;
                Ok(output)
            }
            Encoding::Gzip => {
                let compression = Compression::new(level.min(9));
                let mut encoder = GzEncoder::new(Vec::new(), compression);
                encoder
                    .write_all(data)
                    .map_err(|e| format!("Gzip compression failed: {}", e))?;
                encoder
                    .finish()
                    .map_err(|e| format!("Gzip finalize failed: {}", e))
            }
            Encoding::Deflate => {
                let compression = Compression::new(level.min(9));
                let mut encoder = ZlibEncoder::new(Vec::new(), compression);
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
        let media_type = content_type
            .split_once(';')
            .map_or(content_type, |(media_type, _)| media_type)
            .trim()
            .to_ascii_lowercase();
        media_type.starts_with("text/")
            || media_type == "application/json"
            || matches!(
                media_type.as_str(),
                "application/ndjson" | "application/x-ndjson"
            )
            || media_type.ends_with("+json")
            || media_type == "application/xml"
            || media_type.ends_with("+xml")
            || matches!(
                media_type.as_str(),
                "application/javascript" | "application/x-javascript" | "image/svg+xml"
            )
    }

    fn eligible_response(
        &self,
        request_headers: &HeaderMap,
        response: &http::response::Parts,
        body: &Bytes,
    ) -> bool {
        if body.len() < self.config.min_size
            || body.is_empty()
            || response.status.is_informational()
            || matches!(
                response.status,
                StatusCode::NO_CONTENT
                    | StatusCode::RESET_CONTENT
                    | StatusCode::NOT_MODIFIED
                    | StatusCode::PARTIAL_CONTENT
            )
            || request_headers.contains_key(http::header::RANGE)
            || response.headers.contains_key(http::header::CONTENT_RANGE)
            || response
                .headers
                .contains_key(http::header::CONTENT_ENCODING)
            || cache_control_forbids_transform(&response.headers)
        {
            return false;
        }

        response
            .headers
            .get(http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(Self::is_compressible)
    }

    fn request_encoding(request_headers: &HeaderMap) -> Encoding {
        let values = request_headers
            .get_all(http::header::ACCEPT_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>()
            .join(",");
        Self::negotiate_encoding(&values)
    }
}

fn parse_quality<'a>(parameters: impl Iterator<Item = &'a str>) -> f32 {
    for parameter in parameters {
        let Some((name, value)) = parameter.trim().split_once('=') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("q") {
            return value
                .trim()
                .parse::<f32>()
                .ok()
                .filter(|quality| (0.0..=1.0).contains(quality))
                .unwrap_or(0.0);
        }
    }
    1.0
}

fn retain_highest_quality(slot: &mut Option<f32>, quality: f32) {
    if slot.is_none_or(|current| quality > current) {
        *slot = Some(quality);
    }
}

fn cache_control_forbids_transform(headers: &HeaderMap) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|directive| directive.trim().eq_ignore_ascii_case("no-transform"))
}

fn ensure_accept_encoding_vary(headers: &mut HeaderMap) {
    let already_varies = headers
        .get_all(http::header::VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| {
            let token = token.trim();
            token == "*" || token.eq_ignore_ascii_case("accept-encoding")
        });
    if !already_varies {
        headers.append(
            http::header::VARY,
            HeaderValue::from_static("Accept-Encoding"),
        );
    }
}

fn weaken_strong_etag(headers: &mut HeaderMap) {
    let weak = headers
        .get(http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.starts_with("W/"))
        .and_then(|value| HeaderValue::from_str(&format!("W/{value}")).ok());
    if let Some(weak) = weak {
        headers.insert(http::header::ETAG, weak);
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

    async fn transform_buffered_response(
        &self,
        request_headers: &HeaderMap,
        response: &mut http::response::Parts,
        body: &mut Bytes,
    ) -> Result<()> {
        if !self.eligible_response(request_headers, response, body) {
            return Ok(());
        }

        ensure_accept_encoding_vary(&mut response.headers);
        let encoding = Self::request_encoding(request_headers);
        if encoding == Encoding::Identity {
            return Ok(());
        }

        let source = body.clone();
        let level = self.config.level;
        let compressed =
            tokio::task::spawn_blocking(move || Self::compress(source.as_ref(), encoding, level))
                .await
                .map_err(|error| {
                    GatewayError::Other(format!("Response compression task failed: {error}"))
                })?
                .map_err(|error| {
                    GatewayError::Other(format!("Response compression failed: {error}"))
                })?;
        let content_length =
            HeaderValue::from_str(&compressed.len().to_string()).map_err(|error| {
                GatewayError::Other(format!("Invalid compressed response length: {error}"))
            })?;

        response.headers.insert(
            http::header::CONTENT_ENCODING,
            HeaderValue::from_static(encoding.header_value()),
        );
        response
            .headers
            .insert(http::header::CONTENT_LENGTH, content_length);
        response.headers.remove(http::header::ACCEPT_RANGES);
        for name in ["content-md5", "digest", "content-digest", "repr-digest"] {
            response.headers.remove(name);
        }
        weaken_strong_etag(&mut response.headers);
        *body = Bytes::from(compressed);
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
    fn test_negotiate_honors_quality_before_server_preference() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("br;q=0.2, gzip;q=0.8, deflate;q=0.4"),
            Encoding::Gzip
        );
        assert_eq!(
            CompressMiddleware::negotiate_encoding("identity;q=0.9, gzip;q=0.5"),
            Encoding::Identity
        );
        assert_eq!(
            CompressMiddleware::negotiate_encoding("identity;q=0.5, gzip;q=0.5"),
            Encoding::Gzip
        );
    }

    #[test]
    fn test_negotiate_rejects_zero_quality_and_substring_matches() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("br;q=0, gzip;q=0, deflate;q=0"),
            Encoding::Identity
        );
        assert_eq!(
            CompressMiddleware::negotiate_encoding("zebra, x-gzip"),
            Encoding::Identity
        );
    }

    #[test]
    fn test_negotiate_wildcard_respects_explicit_exclusion() {
        assert_eq!(
            CompressMiddleware::negotiate_encoding("gzip;q=0, *;q=0.5"),
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
    fn test_deflate_uses_the_http_zlib_coding() {
        use std::io::Read as _;

        let data = b"Hello, World! This is test data for compression that should be long enough.";
        let compressed = CompressMiddleware::compress(data, Encoding::Deflate, 6).unwrap();
        let mut decoder = flate2::read::ZlibDecoder::new(compressed.as_slice());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, data);
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

    #[test]
    fn test_gzip_quality_is_clamped() {
        let data = vec![b'X'; 5000];
        let clamped = CompressMiddleware::compress(&data, Encoding::Gzip, 20).unwrap();
        let best = CompressMiddleware::compress(&data, Encoding::Gzip, 9).unwrap();
        assert_eq!(clamped, best);
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
        assert!(!CompressMiddleware::is_compressible(
            "application/not-json-like"
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
    async fn test_buffered_response_is_compressed_and_representation_headers_are_rebuilt() {
        use std::io::Read as _;

        let mw = CompressMiddleware::with_config(CompressConfig {
            min_size: 1,
            level: 6,
        });
        let mut request_headers = HeaderMap::new();
        request_headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CONTENT_LENGTH, "4096")
            .header(http::header::ETAG, "\"source\"")
            .header(http::header::ACCEPT_RANGES, "bytes")
            .header("content-md5", "obsolete")
            .body(())
            .unwrap()
            .into_parts();
        let original = Bytes::from(vec![b'a'; 4096]);
        let mut body = original.clone();

        mw.transform_buffered_response(&request_headers, &mut parts, &mut body)
            .await
            .unwrap();

        assert_eq!(parts.headers[http::header::CONTENT_ENCODING], "gzip");
        assert_eq!(
            parts.headers[http::header::CONTENT_LENGTH],
            body.len().to_string()
        );
        assert_eq!(parts.headers[http::header::VARY], "Accept-Encoding");
        assert_eq!(parts.headers[http::header::ETAG], "W/\"source\"");
        assert!(!parts.headers.contains_key(http::header::ACCEPT_RANGES));
        assert!(!parts.headers.contains_key("content-md5"));
        assert!(body.len() < original.len());

        let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
        let mut decoded = Vec::new();
        decoder.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[tokio::test]
    async fn test_response_already_encoded_skipped() {
        let mw = CompressMiddleware::with_config(CompressConfig {
            min_size: 1,
            level: 6,
        });
        let mut request_headers = HeaderMap::new();
        request_headers.insert(http::header::ACCEPT_ENCODING, "br".parse().unwrap());
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header("content-encoding", "gzip")
            .body(())
            .unwrap()
            .into_parts();
        let original = Bytes::from_static(b"already encoded");
        let mut body = original.clone();

        mw.transform_buffered_response(&request_headers, &mut parts, &mut body)
            .await
            .unwrap();

        assert_eq!(parts.headers[http::header::CONTENT_ENCODING], "gzip");
        assert!(!parts.headers.contains_key(http::header::VARY));
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn test_zero_quality_preserves_identity_and_sets_vary() {
        let mw = CompressMiddleware::with_config(CompressConfig {
            min_size: 1,
            level: 6,
        });
        let mut request_headers = HeaderMap::new();
        request_headers.insert(
            http::header::ACCEPT_ENCODING,
            "br;q=0, gzip;q=0, deflate;q=0".parse().unwrap(),
        );
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(())
            .unwrap()
            .into_parts();
        let original = Bytes::from_static(br#"{"result":"unchanged"}"#);
        let mut body = original.clone();

        mw.transform_buffered_response(&request_headers, &mut parts, &mut body)
            .await
            .unwrap();

        assert!(!parts.headers.contains_key(http::header::CONTENT_ENCODING));
        assert_eq!(parts.headers[http::header::VARY], "Accept-Encoding");
        assert_eq!(body, original);
    }

    #[tokio::test]
    async fn test_no_transform_response_is_not_compressed() {
        let mw = CompressMiddleware::with_config(CompressConfig {
            min_size: 1,
            level: 6,
        });
        let mut request_headers = HeaderMap::new();
        request_headers.insert(http::header::ACCEPT_ENCODING, "gzip".parse().unwrap());
        let (mut parts, _) = http::Response::builder()
            .status(200)
            .header(http::header::CONTENT_TYPE, "text/plain")
            .header(http::header::CACHE_CONTROL, "public, no-transform")
            .body(())
            .unwrap()
            .into_parts();
        let original = Bytes::from_static(b"must remain unchanged");
        let mut body = original.clone();

        mw.transform_buffered_response(&request_headers, &mut parts, &mut body)
            .await
            .unwrap();

        assert!(!parts.headers.contains_key(http::header::CONTENT_ENCODING));
        assert!(!parts.headers.contains_key(http::header::VARY));
        assert_eq!(body, original);
    }
}
