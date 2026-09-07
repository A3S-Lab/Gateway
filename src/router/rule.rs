//! Rule engine — Traefik-style rule parsing and matching
//!
//! Parses expressions like:
//! ```text
//! Host(`api.example.com`) && PathPrefix(`/v1`)
//! ```

use http::HeaderMap;

const MAX_RULE_BYTES: usize = 16 * 1024;
const MAX_MATCHERS: usize = 64;
const MAX_ARGUMENT_BYTES: usize = 4 * 1024;

/// A single matcher condition
#[derive(Debug, Clone, PartialEq)]
pub enum Matcher {
    /// Match by hostname: `Host(`domain`)`
    Host(String),
    /// Match by exact path: `Path(`/exact`)`
    Path(String),
    /// Match by path prefix: `PathPrefix(`/prefix`)`
    PathPrefix(String),
    /// Match by HTTP method: `Method(`GET`)`
    Method(String),
    /// Match by header key-value: `Headers(`key`, `value`)`
    Headers(String, String),
}

impl Matcher {
    /// Check if this matcher matches the given request
    fn matches(&self, host: Option<&str>, path: &str, method: &str, headers: &HeaderMap) -> bool {
        match self {
            Matcher::Host(expected) => host
                .map(|h| strip_host_port(h).eq_ignore_ascii_case(strip_host_port(expected)))
                .unwrap_or(false),
            Matcher::Path(expected) => path == expected,
            Matcher::PathPrefix(prefix) => path.starts_with(prefix.as_str()),
            Matcher::Method(expected) => method.eq_ignore_ascii_case(expected),
            Matcher::Headers(key, value) => headers
                .get(key.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| v == value.as_str())
                .unwrap_or(false),
        }
    }
}

/// Strip an optional `:port` suffix from a request authority before host matching.
///
/// Mirrors standard HTTP / Traefik behavior: the `Host` header / `:authority`
/// may carry a port (e.g. `example.com:8443`) that must be ignored when matching
/// against an Ingress-derived bare hostname. IPv6 literals are kept intact: only
/// a colon that appears after the closing `]` is treated as the port separator.
pub(crate) fn strip_host_port(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:443`. `close` is the `]` index within
        // `rest` (the authority minus the leading `[`), so in `authority` the `]`
        // sits at `close + 1`; slice through `close + 2` to KEEP the closing `]`.
        match rest.find(']') {
            Some(close) => {
                let suffix = &rest[close + 1..];
                if suffix.is_empty()
                    || (suffix.starts_with(':') && suffix[1..].parse::<u16>().is_ok())
                {
                    &authority[..close + 2] // keep `[..]`, drop a numeric `:port`
                } else {
                    authority
                }
            }
            None => authority, // malformed; leave as-is
        }
    } else {
        // Reg-name or IPv4: split off the trailing `:port` if present.
        match authority.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') && port.parse::<u16>().is_ok() => host,
            None => authority,
            Some(_) => authority,
        }
    }
}

/// A compiled rule — a list of matchers combined with AND
#[derive(Debug, Clone)]
pub struct Rule {
    /// All matchers must match (AND logic)
    matchers: Vec<Matcher>,
}

impl Rule {
    /// Parse a rule expression string
    ///
    /// # Examples
    ///
    /// ```rust,ignore
    /// use a3s_gateway::router::Rule;
    ///
    /// let rule = Rule::parse("Host(`example.com`) && PathPrefix(`/api`)").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.trim().is_empty() {
            return Err("Rule must contain at least one matcher".to_string());
        }
        if input.len() > MAX_RULE_BYTES {
            return Err(format!("Rule exceeds the {} byte limit", MAX_RULE_BYTES));
        }
        let parts = Self::split_matchers(input)?;
        if parts.len() > MAX_MATCHERS {
            return Err(format!(
                "Rule contains more than the {} matcher limit",
                MAX_MATCHERS
            ));
        }
        let mut matchers = Vec::new();

        for part in parts {
            if part.is_empty() {
                return Err("Rule contains an empty matcher".to_string());
            }
            let matcher = Self::parse_matcher(part)?;
            matchers.push(matcher);
        }

        if matchers.is_empty() {
            return Err("Rule must contain at least one matcher".to_string());
        }

        Ok(Self { matchers })
    }

    /// Split `&&` conjunctions while preserving the same sequence inside a
    /// backtick-delimited argument. A plain string split would turn a valid
    /// header value or path containing `&&` into unrelated matchers.
    fn split_matchers(input: &str) -> Result<Vec<&str>, String> {
        let bytes = input.as_bytes();
        let mut parts = Vec::new();
        let mut start = 0;
        let mut in_backticks = false;
        let mut index = 0;

        while index < bytes.len() {
            match bytes[index] {
                b'`' => in_backticks = !in_backticks,
                b'&' if !in_backticks && bytes.get(index + 1) == Some(&b'&') => {
                    parts.push(input[start..index].trim());
                    index += 1;
                    start = index + 1;
                }
                _ => {}
            }
            index += 1;
        }

        parts.push(input[start..].trim());
        Ok(parts)
    }

    /// Parse a single matcher expression
    fn parse_matcher(input: &str) -> Result<Matcher, String> {
        let input = input.trim();

        // Extract function name and arguments: Name(`arg1`, `arg2`)
        let paren_start = input
            .find('(')
            .ok_or_else(|| format!("Invalid matcher syntax, expected '(': {}", input))?;
        let paren_end = input
            .rfind(')')
            .ok_or_else(|| format!("Invalid matcher syntax, expected ')': {}", input))?;

        if paren_end <= paren_start {
            return Err(format!("Invalid matcher syntax: {}", input));
        }
        if !input[paren_end + 1..].trim().is_empty() {
            return Err(format!(
                "Invalid matcher syntax, unexpected content after ')': {}",
                input
            ));
        }

        let name = input[..paren_start].trim();
        if name.is_empty() || name.chars().any(char::is_whitespace) {
            return Err(format!("Invalid matcher name: {}", name));
        }
        let args_str = &input[paren_start + 1..paren_end];

        // Parse backtick-delimited arguments
        let args = Self::parse_args(args_str)?;

        match name {
            "Host" => {
                if args.len() != 1 {
                    return Err(format!("Host() expects 1 argument, got {}", args.len()));
                }
                validate_host_argument(&args[0])?;
                Ok(Matcher::Host(args[0].clone()))
            }
            "Path" => {
                if args.len() != 1 {
                    return Err(format!("Path() expects 1 argument, got {}", args.len()));
                }
                validate_path_argument(&args[0])?;
                Ok(Matcher::Path(args[0].clone()))
            }
            "PathPrefix" => {
                if args.len() != 1 {
                    return Err(format!(
                        "PathPrefix() expects 1 argument, got {}",
                        args.len()
                    ));
                }
                validate_path_argument(&args[0])?;
                Ok(Matcher::PathPrefix(args[0].clone()))
            }
            "Method" => {
                if args.len() != 1 {
                    return Err(format!("Method() expects 1 argument, got {}", args.len()));
                }
                validate_method_argument(&args[0])?;
                Ok(Matcher::Method(args[0].clone()))
            }
            "Headers" => {
                if args.len() != 2 {
                    return Err(format!("Headers() expects 2 arguments, got {}", args.len()));
                }
                validate_header_argument(&args[0], &args[1])?;
                Ok(Matcher::Headers(args[0].clone(), args[1].clone()))
            }
            _ => Err(format!("Unknown matcher: {}", name)),
        }
    }

    /// Parse backtick-delimited arguments: `arg1`, `arg2`
    fn parse_args(input: &str) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        let mut chars = input.chars().peekable();

        skip_argument_whitespace(&mut chars);
        if chars.peek().is_none() {
            return Ok(args);
        }

        loop {
            match chars.next() {
                Some('`') => {}
                Some(c) => return Err(format!("Expected backtick, got '{}'", c)),
                None => return Err("Expected backtick argument".to_string()),
            }

            let mut arg = String::new();
            loop {
                match chars.next() {
                    Some('`') => break,
                    Some(c) => {
                        if arg.len() >= MAX_ARGUMENT_BYTES {
                            return Err(format!(
                                "Matcher argument exceeds the {} byte limit",
                                MAX_ARGUMENT_BYTES
                            ));
                        }
                        arg.push(c);
                    }
                    None => return Err("Unterminated backtick argument".to_string()),
                }
            }
            args.push(arg);

            skip_argument_whitespace(&mut chars);
            if chars.peek().is_none() {
                break;
            }
            if chars.next() != Some(',') {
                return Err("Expected ',' between matcher arguments".to_string());
            }
            skip_argument_whitespace(&mut chars);
            if chars.peek().is_none() {
                return Err("Matcher argument cannot end with a comma".to_string());
            }
        }

        Ok(args)
    }

    /// Check if this rule matches the given request
    pub fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HeaderMap,
    ) -> bool {
        self.matchers
            .iter()
            .all(|m| m.matches(host, path, method, headers))
    }

    /// Return the exact host matcher used to index this rule, when present.
    pub(crate) fn host_hint(&self) -> Option<&str> {
        self.matchers.iter().find_map(|matcher| match matcher {
            Matcher::Host(host) => Some(host.as_str()),
            _ => None,
        })
    }

    /// Number of matchers in this rule
    #[allow(dead_code)]
    pub fn matcher_count(&self) -> usize {
        self.matchers.len()
    }
}

fn skip_argument_whitespace(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while chars
        .peek()
        .is_some_and(|character| character.is_whitespace())
    {
        chars.next();
    }
}

fn validate_host_argument(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value.contains('/')
    {
        return Err("Host matcher argument must be a non-empty hostname".to_string());
    }
    // Parse the authority so malformed ports and unbracketed IPv6 literals do
    // not silently become a different host after normalization. Wildcards
    // remain intentionally unsupported by the exact Host matcher.
    let authority = value
        .parse::<http::uri::Authority>()
        .map_err(|_| "Host matcher argument must be a valid host authority".to_string())?;
    let explicit_port = if let Some(rest) = value.strip_prefix('[') {
        rest.find(']')
            .is_some_and(|close| rest[close + 1..].starts_with(':'))
    } else {
        value
            .rsplit_once(':')
            .is_some_and(|(host, _)| !host.contains(':'))
    };
    if authority.host().is_empty() || (explicit_port && authority.port_u16().is_none()) {
        return Err(
            "Host matcher argument must use a numeric port when one is present".to_string(),
        );
    }
    Ok(())
}

fn validate_path_argument(value: &str) -> Result<(), String> {
    if !value.starts_with('/')
        || value.starts_with("//")
        || value.chars().any(char::is_control)
        || value.contains('#')
    {
        return Err("Path matcher argument must be an origin-form path".to_string());
    }
    Ok(())
}

fn validate_method_argument(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_alphabetic() && !b"!#$%&'*+-.^_`|~".contains(&byte))
    {
        return Err("Method matcher argument must be an HTTP method token".to_string());
    }
    Ok(())
}

fn validate_header_argument(name: &str, value: &str) -> Result<(), String> {
    http::header::HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| "Headers matcher name must be a valid HTTP header name".to_string())?;
    if value.chars().any(char::is_control) {
        return Err("Headers matcher value must not contain control characters".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host() {
        let rule = Rule::parse("Host(`example.com`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_path() {
        let rule = Rule::parse("Path(`/health`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_path_prefix() {
        let rule = Rule::parse("PathPrefix(`/api`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_method() {
        let rule = Rule::parse("Method(`POST`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_headers() {
        let rule = Rule::parse("Headers(`X-Custom`, `value`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_combined_rule() {
        let rule = Rule::parse("Host(`api.example.com`) && PathPrefix(`/v1`)").unwrap();
        assert_eq!(rule.matcher_count(), 2);
    }

    #[test]
    fn test_parse_triple_rule() {
        let rule = Rule::parse("Host(`api.com`) && PathPrefix(`/v1`) && Method(`GET`)").unwrap();
        assert_eq!(rule.matcher_count(), 3);
    }

    #[test]
    fn test_parse_invalid_matcher() {
        let result = Rule::parse("Unknown(`test`)");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Unknown matcher"));
    }

    #[test]
    fn test_parse_missing_backtick() {
        let result = Rule::parse("Host(example.com)");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_wrong_arg_count_host() {
        let result = Rule::parse("Host(`a`, `b`)");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expects 1 argument"));
    }

    #[test]
    fn test_parse_wrong_arg_count_headers() {
        let result = Rule::parse("Headers(`key`)");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expects 2 arguments"));
    }

    #[test]
    fn test_match_host() {
        let rule = Rule::parse("Host(`example.com`)").unwrap();
        let headers = http::HeaderMap::new();
        assert!(rule.matches(Some("example.com"), "/", "GET", &headers));
        assert!(rule.matches(Some("EXAMPLE.COM"), "/", "GET", &headers)); // case insensitive
        assert!(!rule.matches(Some("other.com"), "/", "GET", &headers));
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_host_strips_port() {
        // A Host header carrying a port (e.g. behind a non-:80 external entry) must
        // still match a port-less Ingress host rule — standard HTTP/Traefik behavior.
        let rule = Rule::parse("Host(`deep-research.10.12.111.133.nip.io`)").unwrap();
        let headers = http::HeaderMap::new();
        assert!(rule.matches(
            Some("deep-research.10.12.111.133.nip.io:49164"),
            "/",
            "GET",
            &headers
        ));
        assert!(rule.matches(
            Some("deep-research.10.12.111.133.nip.io"),
            "/",
            "GET",
            &headers
        ));
        assert!(!rule.matches(Some("other.nip.io:49164"), "/", "GET", &headers));

        // IPv6 literals keep their brackets; only a trailing `:port` is stripped.
        let v6 = Rule::parse("Host(`[::1]`)").unwrap();
        assert!(v6.matches(Some("[::1]:443"), "/", "GET", &headers));
        assert!(v6.matches(Some("[::1]"), "/", "GET", &headers));

        let port_rule = Rule::parse("Host(`example.com:8443`)").unwrap();
        assert!(port_rule.matches(Some("example.com:443"), "/", "GET", &headers));
    }

    #[test]
    fn test_match_path() {
        let rule = Rule::parse("Path(`/health`)").unwrap();
        let headers = http::HeaderMap::new();
        assert!(rule.matches(None, "/health", "GET", &headers));
        assert!(!rule.matches(None, "/health/check", "GET", &headers));
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_path_prefix() {
        let rule = Rule::parse("PathPrefix(`/api`)").unwrap();
        let headers = http::HeaderMap::new();
        assert!(rule.matches(None, "/api", "GET", &headers));
        assert!(rule.matches(None, "/api/users", "GET", &headers));
        assert!(rule.matches(None, "/api/users/123", "GET", &headers));
        assert!(!rule.matches(None, "/other", "GET", &headers));
    }

    #[test]
    fn test_match_method() {
        let rule = Rule::parse("Method(`POST`)").unwrap();
        let headers = http::HeaderMap::new();
        assert!(rule.matches(None, "/", "POST", &headers));
        assert!(rule.matches(None, "/", "post", &headers)); // case insensitive
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_headers() {
        let rule = Rule::parse("Headers(`X-Custom`, `value`)").unwrap();
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "x-custom".parse::<http::header::HeaderName>().unwrap(),
            "value".parse::<http::HeaderValue>().unwrap(),
        );
        assert!(rule.matches(None, "/", "GET", &headers));

        headers.insert(
            "x-custom".parse::<http::header::HeaderName>().unwrap(),
            "other".parse::<http::HeaderValue>().unwrap(),
        );
        assert!(!rule.matches(None, "/", "GET", &headers));

        let empty = http::HeaderMap::new();
        assert!(!rule.matches(None, "/", "GET", &empty));
    }

    #[test]
    fn test_match_combined_and() {
        let rule = Rule::parse("Host(`api.com`) && PathPrefix(`/v1`)").unwrap();
        let headers = http::HeaderMap::new();

        // Both match
        assert!(rule.matches(Some("api.com"), "/v1/users", "GET", &headers));

        // Only host matches
        assert!(!rule.matches(Some("api.com"), "/v2/users", "GET", &headers));

        // Only path matches
        assert!(!rule.matches(Some("other.com"), "/v1/users", "GET", &headers));

        // Neither matches
        assert!(!rule.matches(Some("other.com"), "/v2/users", "GET", &headers));
    }

    #[test]
    fn test_match_triple_and() {
        let rule = Rule::parse("Host(`api.com`) && PathPrefix(`/v1`) && Method(`GET`)").unwrap();
        let headers = http::HeaderMap::new();

        assert!(rule.matches(Some("api.com"), "/v1/users", "GET", &headers));
        assert!(!rule.matches(Some("api.com"), "/v1/users", "POST", &headers));
    }

    #[test]
    fn test_parse_empty_rule() {
        // Empty string after split produces one empty part which fails to parse
        let result = Rule::parse("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_closing_paren() {
        // Missing closing paren causes syntax error before backtick processing
        let result = Rule::parse("Host(`unterminated");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expected ')'"));
    }

    #[test]
    fn test_parse_args_whitespace_and_commas() {
        // Rule::parse handles the full expression, but we can test the parse_args path
        // through parsing with extra whitespace
        let rule = Rule::parse("Host(`example.com`)").unwrap();
        assert_eq!(rule.matcher_count(), 1);
    }

    #[test]
    fn test_parse_args_trailing_content_after_backtick() {
        // Extra content after closing backtick before comma
        let result = Rule::parse("Host(`test`extra`)");
        assert!(result.is_err());
    }

    #[test]
    fn parser_rejects_trailing_matcher_content_and_empty_conjunctions() {
        assert!(Rule::parse("Host(`example.com`) trailing").is_err());
        assert!(Rule::parse("Host(`example.com`) &&").is_err());
        assert!(Rule::parse("&& Host(`example.com`)").is_err());
        assert!(Rule::parse("Host(`example.com`) && && Path(`/api`)").is_err());
    }

    #[test]
    fn parser_keeps_conjunctions_inside_backtick_arguments() {
        let rule = Rule::parse("Headers(`x-query`, `a&&b`) && Path(`/api`)").unwrap();
        assert_eq!(rule.matcher_count(), 2);
    }

    #[test]
    fn parser_requires_argument_commas_and_valid_path_headers() {
        assert!(Rule::parse("Headers(`x-a` `one`)").is_err());
        assert!(Rule::parse("Path(`relative`)").is_err());
        assert!(Rule::parse("PathPrefix(`//authority`)").is_err());
        assert!(Rule::parse("Headers(`not a header`, `value`)").is_err());
    }

    #[test]
    fn parser_rejects_malformed_host_ports_and_ipv6_authorities() {
        assert!(Rule::parse("Host(`example.com:garbage`)").is_err());
        assert!(Rule::parse("Host(`example.com:99999`)").is_err());
        assert!(Rule::parse("Host(`2001:db8::1`)").is_err());
        assert!(Rule::parse("Host(`[2001:db8::1]:8443`)").is_ok());

        let rule = Rule::parse("Host(`example.com`)").unwrap();
        let headers = HeaderMap::new();
        assert!(!rule.matches(Some("example.com:garbage"), "/", "GET", &headers));
    }
}
