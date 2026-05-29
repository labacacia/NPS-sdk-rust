// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! CGN (Cognon) estimation helpers — token-budget.md §2.2 byte-size fallback.

const BYTES_PER_CGN: usize = 4;

/// CGN = ceil(UTF-8 bytes / 4). Returns 0 for empty input.
pub fn estimate_cgn(s: &str) -> usize {
    let n = s.len(); // str.len() is byte count in Rust
    if n == 0 { 0 } else { (n + BYTES_PER_CGN - 1) / BYTES_PER_CGN }
}

/// CGN estimate for a raw byte slice.
pub fn estimate_cgn_bytes(b: &[u8]) -> usize {
    let n = b.len();
    if n == 0 { 0 } else { (n + BYTES_PER_CGN - 1) / BYTES_PER_CGN }
}

/// Serialize v as compact JSON and return CGN estimate.
/// Requires serde_json. Returns 0 on serialization error.
pub fn estimate_cgn_json<T: serde::Serialize>(v: &T) -> usize {
    match serde_json::to_vec(v) {
        Ok(b) => estimate_cgn_bytes(&b),
        Err(_) => 0,
    }
}

/// Sum CGN estimates for a slice of serializable items.
pub fn estimate_cgn_rows<T: serde::Serialize>(rows: &[T]) -> usize {
    rows.iter().map(estimate_cgn_json).sum()
}

/// Wire-level CGN budget descriptor (NWP §5, NWM token_budget block).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenBudgetMeta {
    pub cgn_limit: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supported_tokenizers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_budget_hint: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl TokenBudgetMeta {
    pub fn new(cgn_limit: u32) -> Self {
        Self {
            cgn_limit,
            tokenizer: None,
            supported_tokenizers: None,
            token_budget_hint: Some(true),
            profile: Some("cgn.v1".into()),
        }
    }

    pub fn effective_profile(&self) -> &str {
        self.profile.as_deref().unwrap_or("cgn.v1")
    }
}

/// Error returned when a response would exceed the declared CGN budget.
#[derive(Debug)]
pub struct BudgetExceededError {
    pub requested: usize,
    pub limit: usize,
}

impl std::fmt::Display for BudgetExceededError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CGN budget exceeded: {} > {}", self.requested, self.limit)
    }
}

impl std::error::Error for BudgetExceededError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_string_is_zero() {
        assert_eq!(estimate_cgn(""), 0);
    }

    #[test]
    fn four_bytes_is_one() {
        assert_eq!(estimate_cgn("test"), 1); // 4 bytes
    }

    #[test]
    fn five_bytes_is_two() {
        assert_eq!(estimate_cgn("hello"), 2); // 5 bytes -> ceil(5/4)=2
    }

    #[test]
    fn eight_bytes_is_two() {
        assert_eq!(estimate_cgn("abcdefgh"), 2); // exactly 8/4=2
    }

    #[test]
    fn chinese_six_bytes_is_two() {
        assert_eq!(estimate_cgn("你好"), 2); // 6 UTF-8 bytes -> ceil(6/4)=2
    }

    #[test]
    fn empty_bytes_is_zero() {
        assert_eq!(estimate_cgn_bytes(&[]), 0);
    }

    #[test]
    fn json_positive() {
        let mut m = HashMap::new();
        m.insert("key", "val");
        assert!(estimate_cgn_json(&m) > 0);
    }

    #[test]
    fn rows_sums() {
        let rows = vec!["a", "bb", "ccc"];
        let total = estimate_cgn_rows(&rows);
        assert!(total >= 1);
    }

    #[test]
    fn token_budget_meta_defaults() {
        let m = TokenBudgetMeta::new(500);
        assert_eq!(m.effective_profile(), "cgn.v1");
        assert_eq!(m.token_budget_hint, Some(true));
    }

    #[test]
    fn budget_exceeded_error_fields() {
        let e = BudgetExceededError { requested: 200, limit: 100 };
        assert_eq!(e.requested, 200);
        assert_eq!(e.limit, 100);
        assert!(e.to_string().contains("200 > 100"));
    }
}
