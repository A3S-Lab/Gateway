//! Rule engine — Traefik-style rule parsing and matching
//!
//! Parses expressions like:
//! ```text
//! Host(`api.example.com`) && PathPrefix(`/v1`)
//! ```

use std::collections::HashMap;

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
    fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> bool {
        match self {
            Matcher::Host(expected) => host
                .map(|h| h.eq_ignore_ascii_case(expected))
                .unwrap_or(false),
            Matcher::Path(expected) => path == expected,
            Matcher::PathPrefix(prefix) => path.starts_with(prefix.as_str()),
            Matcher::Method(expected) => method.eq_ignore_ascii_case(expected),
            Matcher::Headers(key, value) => headers.get(key).map(|v| v == value).unwrap_or(false),
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
    /// ```
    /// use a3s_gateway::router::Rule;
    ///
    /// let rule = Rule::parse("Host(`example.com`) && PathPrefix(`/api`)").unwrap();
    /// ```
    pub fn parse(input: &str) -> Result<Self, String> {
        let parts: Vec<&str> = input.split("&&").map(|s| s.trim()).collect();
        let mut matchers = Vec::new();

        for part in parts {
            let matcher = Self::parse_matcher(part)?;
            matchers.push(matcher);
        }

        if matchers.is_empty() {
            return Err("Rule must contain at least one matcher".to_string());
        }

        Ok(Self { matchers })
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

        let name = &input[..paren_start];
        let args_str = &input[paren_start + 1..paren_end];

        // Parse backtick-delimited arguments
        let args = Self::parse_args(args_str)?;

        match name {
            "Host" => {
                if args.len() != 1 {
                    return Err(format!("Host() expects 1 argument, got {}", args.len()));
                }
                Ok(Matcher::Host(args[0].clone()))
            }
            "Path" => {
                if args.len() != 1 {
                    return Err(format!("Path() expects 1 argument, got {}", args.len()));
                }
                Ok(Matcher::Path(args[0].clone()))
            }
            "PathPrefix" => {
                if args.len() != 1 {
                    return Err(format!(
                        "PathPrefix() expects 1 argument, got {}",
                        args.len()
                    ));
                }
                Ok(Matcher::PathPrefix(args[0].clone()))
            }
            "Method" => {
                if args.len() != 1 {
                    return Err(format!("Method() expects 1 argument, got {}", args.len()));
                }
                Ok(Matcher::Method(args[0].clone()))
            }
            "Headers" => {
                if args.len() != 2 {
                    return Err(format!("Headers() expects 2 arguments, got {}", args.len()));
                }
                Ok(Matcher::Headers(args[0].clone(), args[1].clone()))
            }
            _ => Err(format!("Unknown matcher: {}", name)),
        }
    }

    /// Parse backtick-delimited arguments: `arg1`, `arg2`
    fn parse_args(input: &str) -> Result<Vec<String>, String> {
        let mut args = Vec::new();
        let mut chars = input.chars().peekable();

        loop {
            // Skip whitespace and commas
            while chars
                .peek()
                .map(|c| *c == ' ' || *c == ',')
                .unwrap_or(false)
            {
                chars.next();
            }

            if chars.peek().is_none() {
                break;
            }

            // Expect backtick
            match chars.next() {
                Some('`') => {}
                Some(c) => return Err(format!("Expected backtick, got '{}'", c)),
                None => break,
            }

            // Read until closing backtick
            let mut arg = String::new();
            loop {
                match chars.next() {
                    Some('`') => break,
                    Some(c) => arg.push(c),
                    None => return Err("Unterminated backtick argument".to_string()),
                }
            }

            args.push(arg);
        }

        Ok(args)
    }

    /// Check if this rule matches the given request
    pub fn matches(
        &self,
        host: Option<&str>,
        path: &str,
        method: &str,
        headers: &HashMap<String, String>,
    ) -> bool {
        self.matchers
            .iter()
            .all(|m| m.matches(host, path, method, headers))
    }

    /// Number of matchers in this rule
    pub fn matcher_count(&self) -> usize {
        self.matchers.len()
    }
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
        let headers = HashMap::new();
        assert!(rule.matches(Some("example.com"), "/", "GET", &headers));
        assert!(rule.matches(Some("EXAMPLE.COM"), "/", "GET", &headers)); // case insensitive
        assert!(!rule.matches(Some("other.com"), "/", "GET", &headers));
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_path() {
        let rule = Rule::parse("Path(`/health`)").unwrap();
        let headers = HashMap::new();
        assert!(rule.matches(None, "/health", "GET", &headers));
        assert!(!rule.matches(None, "/health/check", "GET", &headers));
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_path_prefix() {
        let rule = Rule::parse("PathPrefix(`/api`)").unwrap();
        let headers = HashMap::new();
        assert!(rule.matches(None, "/api", "GET", &headers));
        assert!(rule.matches(None, "/api/users", "GET", &headers));
        assert!(rule.matches(None, "/api/users/123", "GET", &headers));
        assert!(!rule.matches(None, "/other", "GET", &headers));
    }

    #[test]
    fn test_match_method() {
        let rule = Rule::parse("Method(`POST`)").unwrap();
        let headers = HashMap::new();
        assert!(rule.matches(None, "/", "POST", &headers));
        assert!(rule.matches(None, "/", "post", &headers)); // case insensitive
        assert!(!rule.matches(None, "/", "GET", &headers));
    }

    #[test]
    fn test_match_headers() {
        let rule = Rule::parse("Headers(`X-Custom`, `value`)").unwrap();
        let mut headers = HashMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        assert!(rule.matches(None, "/", "GET", &headers));

        headers.insert("X-Custom".to_string(), "other".to_string());
        assert!(!rule.matches(None, "/", "GET", &headers));

        let empty = HashMap::new();
        assert!(!rule.matches(None, "/", "GET", &empty));
    }

    #[test]
    fn test_match_combined_and() {
        let rule = Rule::parse("Host(`api.com`) && PathPrefix(`/v1`)").unwrap();
        let headers = HashMap::new();

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
        let headers = HashMap::new();

        assert!(rule.matches(Some("api.com"), "/v1/users", "GET", &headers));
        assert!(!rule.matches(Some("api.com"), "/v1/users", "POST", &headers));
    }

    #[test]
    fn test_parse_empty_rule() {
        // Empty string after split produces one empty part which fails to parse
        let result = Rule::parse("");
        assert!(result.is_err());
    }
}
