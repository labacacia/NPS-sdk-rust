// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! RFC-0005 reputation policy types (NPS-RFC-0005 §4.1–4.3).

/// A single ban_on / reject_on / throttle_on rule.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReputationRule {
    #[serde(default = "default_incident")]
    pub incident: String,
    #[serde(default = "default_severity")]
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub within_days: Option<u32>,
    #[serde(default = "default_count")]
    pub count: u32,
}

fn default_incident() -> String {
    "*".into()
}
fn default_severity() -> String {
    ">=minor".into()
}
fn default_count() -> u32 {
    1
}

/// Node-side reputation enforcement policy (NPS-RFC-0005 §4.1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReputationPolicy {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub log_sources: Vec<String>,
    #[serde(default = "default_anonymous")]
    pub min_assurance_level: String,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl_seconds: u32,
    #[serde(default = "default_ban_ttl")]
    pub ban_ttl_seconds: u32,
    #[serde(default = "default_allow")]
    pub on_log_unavailable: String,
    #[serde(default)]
    pub throttle_on: Vec<ReputationRule>,
    #[serde(default)]
    pub reject_on: Vec<ReputationRule>,
    #[serde(default)]
    pub ban_on: Vec<ReputationRule>,
}

fn default_true() -> bool {
    true
}
fn default_anonymous() -> String {
    "anonymous".into()
}
fn default_cache_ttl() -> u32 {
    300
}
fn default_ban_ttl() -> u32 {
    3600
}
fn default_allow() -> String {
    "allow".into()
}

/// Admission outcome from a reputation policy evaluation (NPS-RFC-0005 §4.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepOutcome {
    Accept,
    Throttle,
    Reject,
    Ban,
}

/// Result from a reputation policy evaluation.
#[derive(Debug, Clone)]
pub struct ReputationDecision {
    pub outcome: RepOutcome,
    pub matched_rule: Option<ReputationRule>,
    pub error_code: Option<String>,
}

impl ReputationDecision {
    pub fn accept() -> Self {
        Self {
            outcome: RepOutcome::Accept,
            matched_rule: None,
            error_code: None,
        }
    }
    pub fn is_accepted(&self) -> bool {
        self.outcome == RepOutcome::Accept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy() {
        let p: ReputationPolicy = serde_json::from_str("{}").unwrap();
        assert!(p.enabled);
        assert_eq!(p.min_assurance_level, "anonymous");
        assert_eq!(p.cache_ttl_seconds, 300);
        assert_eq!(p.ban_ttl_seconds, 3600);
        assert_eq!(p.on_log_unavailable, "allow");
    }

    #[test]
    fn reputation_decision_accept() {
        let d = ReputationDecision::accept();
        assert!(d.is_accepted());
        assert_eq!(d.outcome, RepOutcome::Accept);
    }

    #[test]
    fn rep_outcome_variants() {
        assert_ne!(RepOutcome::Accept, RepOutcome::Reject);
        assert_ne!(RepOutcome::Throttle, RepOutcome::Ban);
    }
}
