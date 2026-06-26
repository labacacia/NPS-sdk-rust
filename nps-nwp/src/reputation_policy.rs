// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Reference reputation policy evaluator (NPS-RFC-0005 §4.1.4).
//!
//! The reputation *types* ship as client-side parity in [`crate::reputation`]
//! (`ReputationPolicy` / `ReputationRule` / `ReputationDecision` / `RepOutcome`);
//! this module adds the net-new [`DefaultReputationPolicyEvaluator`] that drives
//! the Anchor Node server admission gate: min_assurance → ban cache → log query
//! (cached) → ban_on → reject_on → throttle_on → accept. State is in-process.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use nps_nip::reputation::{IncidentType, ReputationLogClient, ReputationLogEntry, Severity};
use nps_nip::AssuranceLevel;
use serde_json::Value;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error_codes;
use crate::reputation::{RepOutcome, ReputationDecision, ReputationPolicy, ReputationRule};

/// In-process reference evaluator producing the canonical [`ReputationDecision`].
#[derive(Default)]
pub struct DefaultReputationPolicyEvaluator {
    query_cache: Mutex<HashMap<String, (Vec<ReputationLogEntry>, i64)>>,
    ban_cache: Mutex<HashMap<String, i64>>,
}

impl DefaultReputationPolicyEvaluator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Testing / warm-start helper: prime the per-NID query cache.
    pub fn prime_cache(&self, nid: &str, entries: Vec<ReputationLogEntry>, ttl_seconds: i64) {
        let expiry = now_unix() + ttl_seconds;
        self.query_cache
            .lock()
            .unwrap()
            .insert(nid.to_string(), (entries, expiry));
    }

    pub async fn evaluate(
        &self,
        requester_nid: &str,
        assurance: &AssuranceLevel,
        policy: &ReputationPolicy,
    ) -> ReputationDecision {
        if !policy.enabled {
            return ReputationDecision::accept();
        }
        let now = now_unix();

        // Step 1: min_assurance_level.
        let min =
            AssuranceLevel::from_wire(&policy.min_assurance_level).unwrap_or(nps_nip::ANONYMOUS);
        if !assurance.meets_or_exceeds(&min) {
            return reject(error_codes::AUTH_ASSURANCE_TOO_LOW);
        }

        // Step 2: ban cache.
        if let Some(&exp) = self.ban_cache.lock().unwrap().get(requester_nid) {
            if exp > now {
                return decision(RepOutcome::Ban, None, error_codes::REPUTATION_BANNED);
            }
        }

        // Step 3: log query.
        let (available, entries) = self.fetch_entries(requester_nid, policy, now).await;
        if !available && policy.on_log_unavailable.eq_ignore_ascii_case("deny") {
            return reject(error_codes::NODE_UNAVAILABLE);
        }

        // Step 4: ban_on
        if let Some(rule) = first_matching_rule(&policy.ban_on, &entries, now) {
            let exp = now + policy.ban_ttl_seconds as i64;
            self.ban_cache
                .lock()
                .unwrap()
                .insert(requester_nid.to_string(), exp);
            return decision(RepOutcome::Ban, Some(rule), error_codes::REPUTATION_BANNED);
        }

        // Step 5: reject_on
        if let Some(rule) = first_matching_rule(&policy.reject_on, &entries, now) {
            return decision(
                RepOutcome::Reject,
                Some(rule),
                error_codes::REPUTATION_REJECTED,
            );
        }

        // Step 6: throttle_on
        if let Some(rule) = first_matching_rule(&policy.throttle_on, &entries, now) {
            return decision(
                RepOutcome::Throttle,
                Some(rule),
                error_codes::REPUTATION_THROTTLED,
            );
        }

        // Step 7: accept
        ReputationDecision::accept()
    }

    async fn fetch_entries(
        &self,
        nid: &str,
        policy: &ReputationPolicy,
        now: i64,
    ) -> (bool, Vec<ReputationLogEntry>) {
        if policy.cache_ttl_seconds > 0 {
            if let Some((entries, expiry)) = self.query_cache.lock().unwrap().get(nid) {
                if *expiry > now {
                    return (true, entries.clone());
                }
            }
        }
        for source in &policy.log_sources {
            let client = ReputationLogClient::new(source.clone());
            match client.query(Some(nid), None).await {
                Ok(results) => {
                    if policy.cache_ttl_seconds > 0 {
                        let expiry = now + policy.cache_ttl_seconds as i64;
                        self.query_cache
                            .lock()
                            .unwrap()
                            .insert(nid.to_string(), (results.clone(), expiry));
                    }
                    return (true, results);
                }
                Err(_) => continue,
            }
        }
        if let Some((entries, _)) = self.query_cache.lock().unwrap().get(nid) {
            return (false, entries.clone());
        }
        (false, Vec::new())
    }
}

fn decision(
    outcome: RepOutcome,
    matched_rule: Option<ReputationRule>,
    code: &str,
) -> ReputationDecision {
    ReputationDecision {
        outcome,
        matched_rule,
        error_code: Some(code.to_string()),
    }
}

fn reject(code: &str) -> ReputationDecision {
    decision(RepOutcome::Reject, None, code)
}

fn first_matching_rule(
    rules: &[ReputationRule],
    entries: &[ReputationLogEntry],
    now: i64,
) -> Option<ReputationRule> {
    for rule in rules {
        let needed = if rule.count == 0 { 1 } else { rule.count };
        let mut matched = 0u32;
        for entry in entries {
            if !rule_matches(rule, entry, now) {
                continue;
            }
            matched += 1;
            if matched >= needed {
                return Some(rule.clone());
            }
        }
    }
    None
}

fn rule_matches(rule: &ReputationRule, entry: &ReputationLogEntry, now_unix: i64) -> bool {
    if rule.incident != "*" && !incident_wire(entry).eq_ignore_ascii_case(&rule.incident) {
        return false;
    }
    let s = rule.severity.trim();
    let (at_least, level_str) = match s.strip_prefix(">=") {
        Some(rest) => (true, rest.trim()),
        None => (false, s),
    };
    let threshold = match severity_from_wire(level_str) {
        Some(t) => t,
        None => return false,
    };
    if at_least {
        if entry.severity < threshold {
            return false;
        }
    } else if entry.severity != threshold {
        return false;
    }
    if let Some(days) = rule.within_days {
        let ts = match OffsetDateTime::parse(&entry.timestamp, &Rfc3339) {
            Ok(t) => t.unix_timestamp(),
            Err(_) => return false,
        };
        if now_unix - ts > (days as i64) * 86_400 {
            return false;
        }
    }
    true
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn severity_from_wire(s: &str) -> Option<Severity> {
    serde_json::from_value::<Severity>(Value::String(s.to_ascii_lowercase())).ok()
}

fn incident_wire(entry: &ReputationLogEntry) -> String {
    if matches!(entry.incident, IncidentType::Other) {
        if let Some(raw) = &entry.incident_raw {
            return raw.clone();
        }
    }
    serde_json::to_value(&entry.incident)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}
