//! Request and manifest path normalization for static object targets.
//!
//! Paths are normalized once. Absolute paths, `..`, backslashes, NULs,
//! empty segments, and ambiguous percent-encoding fail closed before any
//! object authority contact.

use super::StaticObjectError;

/// Normalize a relative UTF-8 object path for manifest lookup.
///
/// Accepted form after normalization: slash-separated segments with no
/// leading slash (for example `index.html`, `assets/app.js`).
pub fn normalize_object_path(raw: &str) -> Result<String, StaticObjectError> {
    if raw.is_empty() {
        return Err(StaticObjectError::InvalidPath(
            "static object path must be non-empty".into(),
        ));
    }
    if raw.as_bytes().contains(&0) {
        return Err(StaticObjectError::InvalidPath(
            "static object path must not contain NUL".into(),
        ));
    }
    if raw.contains('\\') {
        return Err(StaticObjectError::InvalidPath(
            "static object path must not contain backslashes".into(),
        ));
    }
    if raw.starts_with('/') || raw.contains("://") || raw.contains(':') {
        return Err(StaticObjectError::InvalidPath(
            "static object path must be a relative UTF-8 path without scheme or drive prefix"
                .into(),
        ));
    }

    let decoded = decode_path_percent(raw)?;
    if decoded.as_bytes().contains(&0) || decoded.contains('\\') || decoded.starts_with('/') {
        return Err(StaticObjectError::InvalidPath(
            "static object path percent-decoding produced an illegal path".into(),
        ));
    }

    let mut segments = Vec::new();
    for segment in decoded.split('/') {
        if segment.is_empty() {
            return Err(StaticObjectError::InvalidPath(
                "static object path must not contain empty segments".into(),
            ));
        }
        if segment == "." {
            continue;
        }
        if segment == ".." {
            return Err(StaticObjectError::InvalidPath(
                "static object path must not contain '..'".into(),
            ));
        }
        if segment.contains('%') {
            return Err(StaticObjectError::InvalidPath(
                "static object path must not leave unresolved percent sequences".into(),
            ));
        }
        segments.push(segment);
    }
    if segments.is_empty() {
        return Err(StaticObjectError::InvalidPath(
            "static object path must retain at least one segment".into(),
        ));
    }
    Ok(segments.join("/"))
}

/// Strip an optional leading `/` from a request path, then normalize.
///
/// A bare `/` (or empty) becomes `Ok("")` so callers can map it to the
/// sealed entry document without inventing a path.
pub fn normalize_request_path(raw: &str) -> Result<String, StaticObjectError> {
    let trimmed = raw.trim_start_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    normalize_object_path(trimmed)
}

fn decode_path_percent(raw: &str) -> Result<String, StaticObjectError> {
    if !raw.contains('%') {
        return Ok(raw.to_owned());
    }
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(StaticObjectError::InvalidPath(
                        "static object path has truncated percent-encoding".into(),
                    ));
                }
                let hi = from_hex(bytes[index + 1]).ok_or_else(|| {
                    StaticObjectError::InvalidPath(
                        "static object path has non-hex percent-encoding".into(),
                    )
                })?;
                let lo = from_hex(bytes[index + 2]).ok_or_else(|| {
                    StaticObjectError::InvalidPath(
                        "static object path has non-hex percent-encoding".into(),
                    )
                })?;
                let value = (hi << 4) | lo;
                // Reject encoded separators and controls that would change
                // path structure after a naive decode.
                if value == 0
                    || value == b'/'
                    || value == b'\\'
                    || value == b'%'
                    || value.is_ascii_control()
                {
                    return Err(StaticObjectError::InvalidPath(
                        "static object path percent-encoding is ambiguous".into(),
                    ));
                }
                out.push(value);
                index += 3;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| {
        StaticObjectError::InvalidPath("static object path must decode to UTF-8".into())
    })
}

fn from_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_relative_paths() {
        assert_eq!(normalize_object_path("index.html").unwrap(), "index.html");
        assert_eq!(
            normalize_object_path("assets/app.js").unwrap(),
            "assets/app.js"
        );
    }

    #[test]
    fn rejects_traversal_and_absolute_forms() {
        for raw in [
            "",
            "/",
            "/index.html",
            "../secret",
            "a/../b",
            "a\\b",
            "C:/windows",
            "https://evil.example/x",
            "a//b",
            "a/\0/b",
            "%2e%2e/secret",
            "a%2fb",
            "a%00b",
            "%zz",
            "a%",
        ] {
            assert!(
                normalize_object_path(raw).is_err(),
                "expected rejection for {raw:?}"
            );
        }
    }

    #[test]
    fn request_path_strips_leading_slash() {
        assert_eq!(
            normalize_request_path("/assets/app.js").unwrap(),
            "assets/app.js"
        );
        assert_eq!(normalize_request_path("/").unwrap(), "");
    }
}
