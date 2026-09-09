//! Provisional Gateway token estimator for local grant reservation.
//!
//! This is not OpenAI `cl100k_base` and is not a Cloud-certified billing
//! tokenizer. It is a deterministic, fail-closed reservation helper that can be
//! reconciled from upstream `usage` when present. The revision string is the
//! shared ACL contract [`crate::config::INFERENCE_TOKENIZER_REVISION`].

/// Stable revision identity for this provisional estimator.
pub(crate) use crate::config::INFERENCE_TOKENIZER_REVISION as TOKENIZER_REVISION;

/// Estimate tokens for one UTF-8 text span.
///
/// Rules (v1):
/// - Unicode whitespace separates segments and is not counted.
/// - Each CJK Unified Ideograph / Hangul syllable / kana character counts as
///   one token.
/// - Remaining non-whitespace runs are charged `ceil(utf8_bytes / 4)`, with a
///   minimum of one token per non-empty run.
pub(crate) fn estimate_text_tokens(text: &str) -> u64 {
    let mut total = 0_u64;
    let mut latin_bytes = 0_u64;
    let mut in_latin_run = false;

    let flush_latin = |total: &mut u64, latin_bytes: &mut u64, in_latin_run: &mut bool| {
        if *in_latin_run {
            *total = total.saturating_add((*latin_bytes).div_ceil(4).max(1));
            *latin_bytes = 0;
            *in_latin_run = false;
        }
    };

    for ch in text.chars() {
        if ch.is_whitespace() {
            flush_latin(&mut total, &mut latin_bytes, &mut in_latin_run);
            continue;
        }
        if is_cjk_unit(ch) {
            flush_latin(&mut total, &mut latin_bytes, &mut in_latin_run);
            total = total.saturating_add(1);
            continue;
        }
        in_latin_run = true;
        latin_bytes = latin_bytes.saturating_add(ch.len_utf8() as u64);
    }
    flush_latin(&mut total, &mut latin_bytes, &mut in_latin_run);
    total
}

fn is_cjk_unit(ch: char) -> bool {
    matches!(
        ch,
        '\u{3400}'..='\u{4DBF}'   // CJK Extension A
        | '\u{4E00}'..='\u{9FFF}' // CJK Unified
        | '\u{F900}'..='\u{FAFF}' // CJK Compatibility
        | '\u{3040}'..='\u{30FF}' // Hiragana + Katakana
        | '\u{31F0}'..='\u{31FF}' // Katakana Phonetic Extensions
        | '\u{AC00}'..='\u{D7AF}' // Hangul Syllables
        | '\u{1100}'..='\u{11FF}' // Hangul Jamo
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revision_is_stable() {
        assert_eq!(TOKENIZER_REVISION, "a3s.gateway.tokenizer.v1");
    }

    #[test]
    fn empty_and_whitespace_are_zero() {
        assert_eq!(estimate_text_tokens(""), 0);
        assert_eq!(estimate_text_tokens(" \n\t"), 0);
    }

    #[test]
    fn latin_runs_use_byte_quarters() {
        assert_eq!(estimate_text_tokens("abcd"), 1);
        assert_eq!(estimate_text_tokens("abcdefgh"), 2);
        assert_eq!(estimate_text_tokens("hi"), 1);
        assert_eq!(estimate_text_tokens("hello world"), 4); // ceil(5/4)+ceil(5/4)
    }

    #[test]
    fn cjk_characters_are_one_token_each() {
        assert_eq!(estimate_text_tokens("你好"), 2);
        assert_eq!(estimate_text_tokens("こんにちは"), 5);
        assert_eq!(estimate_text_tokens("한글"), 2);
    }

    #[test]
    fn mixed_scripts_compose() {
        // "hi" => 1, "你好" => 2
        assert_eq!(estimate_text_tokens("hi 你好"), 3);
    }

    #[test]
    fn emoji_and_non_cjk_multibyte_use_byte_quarters() {
        // First principles: non-CJK multibyte runs share the latin/other rule.
        // Do not special-case emoji (that would overfit billing quirks).
        assert_eq!(estimate_text_tokens("😀"), 1); // 4 UTF-8 bytes
        assert_eq!(estimate_text_tokens("a😀b"), 2); // one run: 1+4+1 = 6 bytes → 2
    }

    #[test]
    fn adjacent_cjk_and_latin_do_not_merge_counts() {
        assert_eq!(estimate_text_tokens("中文abc"), 2 + 1); // 2 CJK + ceil(3/4)
        assert_eq!(estimate_text_tokens("abc中文"), 1 + 2);
    }
}
