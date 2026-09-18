//! Bounded single-byte-range parsing for WEB0.4.
//!
//! Only one contiguous `bytes=` range is admitted. Multipart ranges are
//! ignored so the server returns the full representation instead of inventing
//! multipart/byteranges framing.

/// Inclusive byte range within an object representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeParse {
    /// Apply this single contiguous range.
    Satisfiable(ByteRange),
    /// Range unit present but unsatisfiable for this size.
    Unsatisfiable,
    /// Header absent, empty, or multipart/unsupported — serve full body.
    Ignore,
}

/// Parse a single `Range` header value against a known representation size.
pub fn parse_single_byte_range(header: Option<&str>, size: u64) -> RangeParse {
    let Some(raw) = header.map(str::trim).filter(|value| !value.is_empty()) else {
        return RangeParse::Ignore;
    };
    let Some(spec) = raw.strip_prefix("bytes=") else {
        return RangeParse::Ignore;
    };
    if spec.contains(',') {
        // Multipart ranges are out of scope for WEB0.4.
        return RangeParse::Ignore;
    }
    if size == 0 {
        return RangeParse::Unsatisfiable;
    }

    if let Some(suffix) = spec.strip_prefix('-') {
        let Ok(suffix_len) = suffix.parse::<u64>() else {
            return RangeParse::Ignore;
        };
        if suffix_len == 0 {
            return RangeParse::Ignore;
        }
        let start = size.saturating_sub(suffix_len);
        return RangeParse::Satisfiable(ByteRange {
            start,
            end: size - 1,
        });
    }

    let mut parts = spec.splitn(2, '-');
    let Some(start_raw) = parts.next() else {
        return RangeParse::Ignore;
    };
    let Some(end_raw) = parts.next() else {
        return RangeParse::Ignore;
    };
    let Ok(start) = start_raw.parse::<u64>() else {
        return RangeParse::Ignore;
    };
    if end_raw.is_empty() {
        if start >= size {
            return RangeParse::Unsatisfiable;
        }
        return RangeParse::Satisfiable(ByteRange {
            start,
            end: size - 1,
        });
    }
    let Ok(end) = end_raw.parse::<u64>() else {
        return RangeParse::Ignore;
    };
    if end < start {
        return RangeParse::Ignore;
    }
    if start >= size {
        return RangeParse::Unsatisfiable;
    }
    RangeParse::Satisfiable(ByteRange {
        start,
        end: end.min(size - 1),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_closed_open_and_suffix_ranges() {
        assert_eq!(
            parse_single_byte_range(Some("bytes=0-3"), 10),
            RangeParse::Satisfiable(ByteRange { start: 0, end: 3 })
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=8-"), 10),
            RangeParse::Satisfiable(ByteRange { start: 8, end: 9 })
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=-4"), 10),
            RangeParse::Satisfiable(ByteRange { start: 6, end: 9 })
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=100-200"), 10),
            RangeParse::Unsatisfiable
        );
        assert_eq!(
            parse_single_byte_range(Some("bytes=0-1,2-3"), 10),
            RangeParse::Ignore
        );
    }
}
