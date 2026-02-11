//! TCP router — SNI-based routing for TLS connections
//!
//! Routes raw TCP connections based on the TLS Server Name Indication (SNI)
//! extension. Supports `HostSNI()` matching rules and wildcard patterns.

use serde::{Deserialize, Serialize};

/// TCP routing rule — matches based on SNI hostname
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpRoute {
    /// Route name
    pub name: String,
    /// SNI rule expression (e.g., "HostSNI(`example.com`)")
    pub rule: String,
    /// Target service name
    pub service: String,
    /// Priority (lower = higher priority)
    #[serde(default)]
    pub priority: i32,
}

/// Compiled SNI matcher
#[derive(Debug, Clone)]
enum SniMatcher {
    /// Match any SNI (HostSNI(`*`))
    CatchAll,
    /// Match exact hostname
    Exact(String),
    /// Match wildcard (e.g., *.example.com)
    Wildcard(String),
}

impl SniMatcher {
    /// Parse an SNI rule expression
    fn parse(rule: &str) -> Result<Self, String> {
        let trimmed = rule.trim();

        // Extract HostSNI(`value`)
        if let Some(inner) = extract_hostsni(trimmed) {
            if inner == "*" {
                return Ok(Self::CatchAll);
            }
            if inner.starts_with("*.") {
                return Ok(Self::Wildcard(inner[1..].to_lowercase()));
            }
            return Ok(Self::Exact(inner.to_lowercase()));
        }

        Err(format!(
            "Invalid TCP rule '{}': expected HostSNI(`hostname`)",
            rule
        ))
    }

    /// Check if an SNI hostname matches this rule
    fn matches(&self, sni: Option<&str>) -> bool {
        match self {
            Self::CatchAll => true,
            Self::Exact(expected) => sni
                .map(|s| s.to_lowercase() == *expected)
                .unwrap_or(false),
            Self::Wildcard(suffix) => sni
                .map(|s| {
                    let lower = s.to_lowercase();
                    lower.ends_with(suffix.as_str()) && lower.len() > suffix.len()
                })
                .unwrap_or(false),
        }
    }
}

/// Extract the value from HostSNI(`value`)
fn extract_hostsni(rule: &str) -> Option<&str> {
    let rule = rule.trim();
    if let Some(rest) = rule.strip_prefix("HostSNI(") {
        if let Some(inner) = rest.strip_suffix(')') {
            let inner = inner.trim();
            // Strip backticks or quotes
            if inner.starts_with('`') && inner.ends_with('`') {
                return Some(&inner[1..inner.len() - 1]);
            }
            if inner.starts_with('"') && inner.ends_with('"') {
                return Some(&inner[1..inner.len() - 1]);
            }
            if inner.starts_with('\'') && inner.ends_with('\'') {
                return Some(&inner[1..inner.len() - 1]);
            }
            return Some(inner);
        }
    }
    None
}

/// Compiled TCP route with pre-parsed matcher
struct CompiledTcpRoute {
    name: String,
    matcher: SniMatcher,
    service: String,
    priority: i32,
}

/// TCP router table — matches incoming TCP connections by SNI
pub struct TcpRouterTable {
    routes: Vec<CompiledTcpRoute>,
}

/// Result of matching a TCP connection
#[derive(Debug, Clone)]
pub struct TcpResolvedRoute {
    /// Router name that matched
    pub router_name: String,
    /// Target service name
    pub service_name: String,
}

impl TcpRouterTable {
    /// Build a TCP router table from route configurations
    pub fn from_routes(routes: &[TcpRoute]) -> Result<Self, String> {
        let mut compiled: Vec<CompiledTcpRoute> = Vec::new();

        for route in routes {
            let matcher = SniMatcher::parse(&route.rule)?;
            compiled.push(CompiledTcpRoute {
                name: route.name.clone(),
                matcher,
                service: route.service.clone(),
                priority: route.priority,
            });
        }

        // Sort by priority (lower = higher priority)
        compiled.sort_by_key(|r| r.priority);

        Ok(Self { routes: compiled })
    }

    /// Match an incoming TCP connection by SNI hostname
    pub fn match_connection(&self, sni: Option<&str>) -> Option<TcpResolvedRoute> {
        for route in &self.routes {
            if route.matcher.matches(sni) {
                return Some(TcpResolvedRoute {
                    router_name: route.name.clone(),
                    service_name: route.service.clone(),
                });
            }
        }
        None
    }

    /// Number of compiled routes
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether the table is empty
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// Extract the SNI hostname from a TLS ClientHello message
///
/// Parses the first few bytes of a TLS handshake to extract the
/// Server Name Indication extension value.
pub fn extract_sni(buf: &[u8]) -> Option<String> {
    // Minimum TLS record: 5 bytes header + 1 byte content
    if buf.len() < 6 {
        return None;
    }

    // Check TLS record header
    // Content type: 0x16 = Handshake
    if buf[0] != 0x16 {
        return None;
    }

    // TLS version (major.minor) — we accept 3.x
    if buf[1] != 0x03 {
        return None;
    }

    // Record length
    let record_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    if buf.len() < 5 + record_len {
        return None;
    }

    let handshake = &buf[5..5 + record_len];

    // Handshake type: 0x01 = ClientHello
    if handshake.is_empty() || handshake[0] != 0x01 {
        return None;
    }

    // Handshake length (3 bytes)
    if handshake.len() < 4 {
        return None;
    }
    let hs_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + hs_len {
        return None;
    }

    let client_hello = &handshake[4..4 + hs_len];

    // Skip: version (2) + random (32) = 34 bytes
    if client_hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID length (1 byte) + session ID
    if pos >= client_hello.len() {
        return None;
    }
    let session_id_len = client_hello[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher suites length (2 bytes) + cipher suites
    if pos + 2 > client_hello.len() {
        return None;
    }
    let cipher_len = ((client_hello[pos] as usize) << 8) | (client_hello[pos + 1] as usize);
    pos += 2 + cipher_len;

    // Compression methods length (1 byte) + methods
    if pos >= client_hello.len() {
        return None;
    }
    let comp_len = client_hello[pos] as usize;
    pos += 1 + comp_len;

    // Extensions length (2 bytes)
    if pos + 2 > client_hello.len() {
        return None;
    }
    let ext_len = ((client_hello[pos] as usize) << 8) | (client_hello[pos + 1] as usize);
    pos += 2;

    let ext_end = pos + ext_len;
    if ext_end > client_hello.len() {
        return None;
    }

    // Parse extensions looking for SNI (type 0x0000)
    while pos + 4 <= ext_end {
        let ext_type = ((client_hello[pos] as u16) << 8) | (client_hello[pos + 1] as u16);
        let ext_data_len =
            ((client_hello[pos + 2] as usize) << 8) | (client_hello[pos + 3] as usize);
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(&client_hello[pos..pos + ext_data_len]);
        }

        pos += ext_data_len;
    }

    None
}

/// Parse the SNI extension data to extract the hostname
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 2 {
        return None;
    }

    // Server name list length
    let list_len = ((data[0] as usize) << 8) | (data[1] as usize);
    if data.len() < 2 + list_len {
        return None;
    }

    let mut pos = 2;
    while pos + 3 <= 2 + list_len {
        let name_type = data[pos];
        let name_len = ((data[pos + 1] as usize) << 8) | (data[pos + 2] as usize);
        pos += 3;

        if name_type == 0x00 {
            // Host name type
            if pos + name_len <= data.len() {
                return String::from_utf8(data[pos..pos + name_len].to_vec()).ok();
            }
        }

        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SniMatcher ---

    #[test]
    fn test_parse_catch_all() {
        let m = SniMatcher::parse("HostSNI(`*`)").unwrap();
        assert!(matches!(m, SniMatcher::CatchAll));
    }

    #[test]
    fn test_parse_exact() {
        let m = SniMatcher::parse("HostSNI(`example.com`)").unwrap();
        assert!(matches!(m, SniMatcher::Exact(ref s) if s == "example.com"));
    }

    #[test]
    fn test_parse_wildcard() {
        let m = SniMatcher::parse("HostSNI(`*.example.com`)").unwrap();
        assert!(matches!(m, SniMatcher::Wildcard(_)));
    }

    #[test]
    fn test_parse_with_quotes() {
        let m = SniMatcher::parse("HostSNI(\"example.com\")").unwrap();
        assert!(matches!(m, SniMatcher::Exact(ref s) if s == "example.com"));
    }

    #[test]
    fn test_parse_invalid() {
        assert!(SniMatcher::parse("InvalidRule").is_err());
        assert!(SniMatcher::parse("Host(`example.com`)").is_err());
    }

    // --- SniMatcher::matches ---

    #[test]
    fn test_catch_all_matches_everything() {
        let m = SniMatcher::CatchAll;
        assert!(m.matches(Some("example.com")));
        assert!(m.matches(Some("anything.test")));
        assert!(m.matches(None));
    }

    #[test]
    fn test_exact_match() {
        let m = SniMatcher::Exact("example.com".to_string());
        assert!(m.matches(Some("example.com")));
        assert!(m.matches(Some("EXAMPLE.COM")));
        assert!(!m.matches(Some("other.com")));
        assert!(!m.matches(None));
    }

    #[test]
    fn test_wildcard_match() {
        let m = SniMatcher::Wildcard(".example.com".to_string());
        assert!(m.matches(Some("sub.example.com")));
        assert!(m.matches(Some("deep.sub.example.com")));
        assert!(!m.matches(Some("example.com"))); // No subdomain
        assert!(!m.matches(Some("other.com")));
        assert!(!m.matches(None));
    }

    // --- extract_hostsni ---

    #[test]
    fn test_extract_hostsni_backticks() {
        assert_eq!(extract_hostsni("HostSNI(`example.com`)"), Some("example.com"));
    }

    #[test]
    fn test_extract_hostsni_quotes() {
        assert_eq!(extract_hostsni("HostSNI(\"test.com\")"), Some("test.com"));
    }

    #[test]
    fn test_extract_hostsni_star() {
        assert_eq!(extract_hostsni("HostSNI(`*`)"), Some("*"));
    }

    #[test]
    fn test_extract_hostsni_invalid() {
        assert_eq!(extract_hostsni("NotHostSNI(`test`)"), None);
        assert_eq!(extract_hostsni("HostSNI("), None);
    }

    // --- TcpRouterTable ---

    #[test]
    fn test_table_from_routes() {
        let routes = vec![
            TcpRoute {
                name: "grpc".to_string(),
                rule: "HostSNI(`*`)".to_string(),
                service: "grpc-backend".to_string(),
                priority: 10,
            },
            TcpRoute {
                name: "api".to_string(),
                rule: "HostSNI(`api.example.com`)".to_string(),
                service: "api-backend".to_string(),
                priority: 0,
            },
        ];
        let table = TcpRouterTable::from_routes(&routes).unwrap();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn test_table_match_exact() {
        let routes = vec![
            TcpRoute {
                name: "api".to_string(),
                rule: "HostSNI(`api.example.com`)".to_string(),
                service: "api-backend".to_string(),
                priority: 0,
            },
            TcpRoute {
                name: "catch-all".to_string(),
                rule: "HostSNI(`*`)".to_string(),
                service: "default-backend".to_string(),
                priority: 100,
            },
        ];
        let table = TcpRouterTable::from_routes(&routes).unwrap();

        let result = table.match_connection(Some("api.example.com"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().service_name, "api-backend");
    }

    #[test]
    fn test_table_match_catch_all() {
        let routes = vec![TcpRoute {
            name: "catch-all".to_string(),
            rule: "HostSNI(`*`)".to_string(),
            service: "default".to_string(),
            priority: 0,
        }];
        let table = TcpRouterTable::from_routes(&routes).unwrap();

        let result = table.match_connection(Some("anything.com"));
        assert!(result.is_some());
        assert_eq!(result.unwrap().service_name, "default");
    }

    #[test]
    fn test_table_match_wildcard() {
        let routes = vec![TcpRoute {
            name: "wildcard".to_string(),
            rule: "HostSNI(`*.example.com`)".to_string(),
            service: "wildcard-backend".to_string(),
            priority: 0,
        }];
        let table = TcpRouterTable::from_routes(&routes).unwrap();

        assert!(table.match_connection(Some("sub.example.com")).is_some());
        assert!(table.match_connection(Some("example.com")).is_none());
    }

    #[test]
    fn test_table_priority_order() {
        let routes = vec![
            TcpRoute {
                name: "catch-all".to_string(),
                rule: "HostSNI(`*`)".to_string(),
                service: "default".to_string(),
                priority: 100,
            },
            TcpRoute {
                name: "specific".to_string(),
                rule: "HostSNI(`api.example.com`)".to_string(),
                service: "api".to_string(),
                priority: 0,
            },
        ];
        let table = TcpRouterTable::from_routes(&routes).unwrap();

        // Specific route has higher priority (lower number)
        let result = table.match_connection(Some("api.example.com")).unwrap();
        assert_eq!(result.service_name, "api");
    }

    #[test]
    fn test_table_no_match() {
        let routes = vec![TcpRoute {
            name: "specific".to_string(),
            rule: "HostSNI(`api.example.com`)".to_string(),
            service: "api".to_string(),
            priority: 0,
        }];
        let table = TcpRouterTable::from_routes(&routes).unwrap();

        assert!(table.match_connection(Some("other.com")).is_none());
        assert!(table.match_connection(None).is_none());
    }

    #[test]
    fn test_table_empty() {
        let table = TcpRouterTable::from_routes(&[]).unwrap();
        assert!(table.is_empty());
        assert!(table.match_connection(Some("test.com")).is_none());
    }

    #[test]
    fn test_table_invalid_rule() {
        let routes = vec![TcpRoute {
            name: "bad".to_string(),
            rule: "InvalidRule".to_string(),
            service: "svc".to_string(),
            priority: 0,
        }];
        assert!(TcpRouterTable::from_routes(&routes).is_err());
    }

    // --- extract_sni ---

    #[test]
    fn test_extract_sni_too_short() {
        assert!(extract_sni(&[]).is_none());
        assert!(extract_sni(&[0x16, 0x03]).is_none());
    }

    #[test]
    fn test_extract_sni_not_tls() {
        assert!(extract_sni(&[0x00, 0x03, 0x01, 0x00, 0x05, 0x01]).is_none());
    }

    #[test]
    fn test_extract_sni_not_handshake() {
        // TLS record but not handshake type
        assert!(extract_sni(&[0x16, 0x03, 0x01, 0x00, 0x01, 0x00]).is_none());
    }

    #[test]
    fn test_extract_sni_valid_client_hello() {
        // Construct a minimal TLS ClientHello with SNI extension
        let sni_hostname = b"example.com";
        let sni_hostname_len = sni_hostname.len();

        // SNI extension data
        let mut sni_ext = Vec::new();
        // Server name list length
        let name_entry_len = 3 + sni_hostname_len; // type(1) + len(2) + name
        sni_ext.push(((name_entry_len >> 8) & 0xff) as u8);
        sni_ext.push((name_entry_len & 0xff) as u8);
        // Host name type (0x00)
        sni_ext.push(0x00);
        // Host name length
        sni_ext.push(((sni_hostname_len >> 8) & 0xff) as u8);
        sni_ext.push((sni_hostname_len & 0xff) as u8);
        sni_ext.extend_from_slice(sni_hostname);

        // Extensions block
        let mut extensions = Vec::new();
        // SNI extension type (0x0000)
        extensions.push(0x00);
        extensions.push(0x00);
        // Extension data length
        extensions.push(((sni_ext.len() >> 8) & 0xff) as u8);
        extensions.push((sni_ext.len() & 0xff) as u8);
        extensions.extend_from_slice(&sni_ext);

        // ClientHello body
        let mut client_hello = Vec::new();
        // Version (TLS 1.2)
        client_hello.push(0x03);
        client_hello.push(0x03);
        // Random (32 bytes)
        client_hello.extend_from_slice(&[0u8; 32]);
        // Session ID length (0)
        client_hello.push(0x00);
        // Cipher suites length (2) + one cipher suite
        client_hello.push(0x00);
        client_hello.push(0x02);
        client_hello.push(0x00);
        client_hello.push(0x2f); // TLS_RSA_WITH_AES_128_CBC_SHA
        // Compression methods length (1) + null
        client_hello.push(0x01);
        client_hello.push(0x00);
        // Extensions length
        client_hello.push(((extensions.len() >> 8) & 0xff) as u8);
        client_hello.push((extensions.len() & 0xff) as u8);
        client_hello.extend_from_slice(&extensions);

        // Handshake message
        let mut handshake = Vec::new();
        // Handshake type: ClientHello (0x01)
        handshake.push(0x01);
        // Length (3 bytes)
        let ch_len = client_hello.len();
        handshake.push(((ch_len >> 16) & 0xff) as u8);
        handshake.push(((ch_len >> 8) & 0xff) as u8);
        handshake.push((ch_len & 0xff) as u8);
        handshake.extend_from_slice(&client_hello);

        // TLS record
        let mut record = Vec::new();
        // Content type: Handshake (0x16)
        record.push(0x16);
        // Version (TLS 1.0 for record layer)
        record.push(0x03);
        record.push(0x01);
        // Record length
        let hs_len = handshake.len();
        record.push(((hs_len >> 8) & 0xff) as u8);
        record.push((hs_len & 0xff) as u8);
        record.extend_from_slice(&handshake);

        let result = extract_sni(&record);
        assert_eq!(result, Some("example.com".to_string()));
    }

    // --- TcpResolvedRoute ---

    #[test]
    fn test_resolved_route_clone() {
        let route = TcpResolvedRoute {
            router_name: "test".to_string(),
            service_name: "backend".to_string(),
        };
        let cloned = route.clone();
        assert_eq!(cloned.router_name, "test");
        assert_eq!(cloned.service_name, "backend");
    }
}
