// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! MCP tool-name encoding (NPS-CR-0010 §5.1) — *canonical on output, forgiving
//! on input*.
//!
//! **Encoding only: there is deliberately no decode.** The transform is lossy
//! (`.` and `_` both become `_`, and a node name may itself contain `__`), so
//! resolution MUST re-encode each candidate and compare, never split the
//! incoming string.

/// `Sanitize(node) + "__" + EncodeActionSegment(action)`.
pub fn encode(node: &str, action: &str) -> String {
    format!("{}__{}", sanitize(node), encode_action_segment(action))
}

/// `Sanitize(a)` with `.` folded to `_`.
pub fn encode_action_segment(action: &str) -> String {
    sanitize(action).replace('.', "_")
}

/// Trim; replace every char that is not a letter, digit, `_`, `-` or `.` with
/// `_`; then trim leading/trailing `_`. An empty result becomes `"node"`.
pub fn sanitize(s: &str) -> String {
    let mapped: String = s
        .trim()
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = mapped.trim_matches('_');
    if trimmed.is_empty() {
        "node".to_string()
    } else {
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_the_reference_example() {
        assert_eq!(
            encode("bridge-inbound-test", "orders.lookup"),
            "bridge-inbound-test__orders_lookup"
        );
    }

    #[test]
    fn sanitize_replaces_then_trims_underscores() {
        assert_eq!(sanitize("  a b/c  "), "a_b_c");
        assert_eq!(sanitize("__x__"), "x");
        assert_eq!(sanitize("///"), "node");
        assert_eq!(sanitize(""), "node");
        assert_eq!(sanitize("keep.dots-and_underscores"), "keep.dots-and_underscores");
    }

    #[test]
    fn action_segment_folds_dots() {
        assert_eq!(encode_action_segment("a.b.c"), "a_b_c");
        assert_eq!(encode_action_segment("a_b"), "a_b");
    }

    #[test]
    fn encoding_is_lossy_which_is_why_there_is_no_decode() {
        // Two distinct (node, action) pairs collide on one encoded name.
        assert_eq!(encode("n", "a.b"), encode("n", "a_b"));
    }
}
