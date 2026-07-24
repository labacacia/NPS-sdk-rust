// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Configuration for the NIP CA service (NPS-3 §8). Mirror of the .NET
//! `NipCaOptions`, minus the ASP.NET-hosting-only fields (connection strings,
//! ACME toggles, OCSP timing) that don't apply to the framework-agnostic
//! library surface.

use std::collections::HashSet;

use time::Duration;

/// Enrollment tier governing which RA gate an inbound registration must pass
/// (NPS-CR-0005 §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentTier {
    /// Tier 1 — operator-configured glob allowlist. Default.
    Allowlist = 1,
    /// Tier 2 — single-use bootstrap token (`nps-bootstrap-` prefix).
    BootstrapToken = 2,
    /// Tier 3 — pending queue with operator approve/reject.
    PendingQueue = 3,
}

impl Default for EnrollmentTier {
    fn default() -> Self {
        EnrollmentTier::Allowlist
    }
}

/// Configuration for [`crate::ca::NipCaService`].
#[derive(Debug, Clone)]
pub struct NipCaOptions {
    /// CA NID, e.g. `urn:nps:org:ca.example.com`. Used as `issued_by`.
    pub ca_nid: String,
    /// Human-readable CA name for the discovery document.
    pub display_name: Option<String>,

    /// Agent certificate validity in days. Default 30.
    pub agent_cert_validity_days: i64,
    /// Node certificate validity in days. Default 90.
    pub node_cert_validity_days: i64,
    /// Renewal window in days before expiry. Default 7.
    pub renewal_window_days: i64,
    /// Orchestrator group NID validity in days. Default 365.
    pub group_cert_validity_days: i64,

    /// Default session validity when the request omits it. Default 1 hour.
    pub session_default_validity: Duration,
    /// Maximum permitted session validity. Default 24 hours.
    pub session_max_validity: Duration,
    /// Minimum permitted session validity. Default 60 seconds.
    pub session_min_validity: Duration,
    /// Allowed clock-skew for the group-JWS `iat`. Default ±5 minutes.
    pub session_jws_clock_skew: Duration,

    /// Base URL of this CA (discovery document only).
    pub base_url: String,
    /// Route prefix for CA endpoints. Default `""`.
    pub route_prefix: String,
    /// Algorithms advertised in the discovery document. Default `["ed25519"]`.
    pub algorithms: Vec<String>,

    /// Operator bearer token for privileged endpoints. `None` skips auth.
    pub operator_api_key: Option<String>,
    /// When set, only these capabilities may be requested at registration.
    pub allowed_capabilities: Option<HashSet<String>>,

    // ── Enrollment / RA (NPS-CR-0005) ────────────────────────────────────────
    /// Active enrollment tier. Default [`EnrollmentTier::Allowlist`].
    pub enrollment_tier: EnrollmentTier,
    /// Glob patterns for Tier 1. Default `["*"]` (open CA).
    pub enrollment_allowlist_patterns: Vec<String>,
    /// Max TTL for bootstrap tokens. Default 24 hours.
    pub bootstrap_token_max_ttl: Duration,
    /// Max records in `Pending` status. Default 1000.
    pub pending_queue_max_size: usize,
    /// Age after which non-pending records are swept. Default 7 days.
    pub pending_queue_max_age: Duration,
}

impl NipCaOptions {
    /// Construct options with the .NET defaults for the given CA NID + base URL.
    pub fn new(ca_nid: impl Into<String>, base_url: impl Into<String>) -> Self {
        Self {
            ca_nid: ca_nid.into(),
            display_name: None,
            agent_cert_validity_days: 30,
            node_cert_validity_days: 90,
            renewal_window_days: 7,
            group_cert_validity_days: 365,
            session_default_validity: Duration::hours(1),
            session_max_validity: Duration::hours(24),
            session_min_validity: Duration::minutes(1),
            session_jws_clock_skew: Duration::minutes(5),
            base_url: base_url.into(),
            route_prefix: String::new(),
            algorithms: vec!["ed25519".into()],
            operator_api_key: None,
            allowed_capabilities: None,
            enrollment_tier: EnrollmentTier::Allowlist,
            enrollment_allowlist_patterns: vec!["*".into()],
            bootstrap_token_max_ttl: Duration::hours(24),
            pending_queue_max_size: 1000,
            pending_queue_max_age: Duration::days(7),
        }
    }
}
