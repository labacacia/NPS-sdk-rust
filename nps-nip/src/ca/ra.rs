// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Registration Authority (RA) enrollment tiers (NPS-CR-0005 §3):
//! [`AllowlistPolicy`] (T1), [`BootstrapTokenPolicy`] (T2, with
//! [`BootstrapTokenStore`]), and [`PendingQueuePolicy`] (T3, with
//! [`PendingStore`]). [`create_enrollment_policy`] builds the policy selected
//! by [`NipCaOptions::enrollment_tier`].

use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use time::{Duration, OffsetDateTime};

use crate::error_codes;

use super::error::{EnrollmentOutcome, NipCaError, NipRaPending};
use super::options::{EnrollmentTier, NipCaOptions};

/// Registration context passed to an [`EnrollmentPolicy`].
pub struct EnrollmentRequest<'a> {
    pub entity_type: &'a str,
    pub identifier: &'a str,
    pub pub_key: &'a str,
    pub capabilities: &'a [String],
    pub scope_json: &'a str,
    pub metadata_json: Option<&'a str>,
    /// Bootstrap token from the `X-NPS-Enrollment-Token` header (Tier 2).
    pub enrollment_token: Option<&'a str>,
}

/// Gate that must pass before a NIP CA issues an IdentFrame (NPS-CR-0005 §3).
pub trait EnrollmentPolicy: Send + Sync {
    /// Return [`EnrollmentOutcome::Admit`] to proceed, `Deny` to reject, or
    /// `Pending` to enqueue (Tier 3).
    fn check(&self, req: &EnrollmentRequest<'_>) -> EnrollmentOutcome;
}

// ── Tier 1: Allowlist ─────────────────────────────────────────────────────────

/// Enrollment Tier 1: admits identifiers matching at least one glob pattern.
pub struct AllowlistPolicy {
    patterns: Vec<String>,
}

impl AllowlistPolicy {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }
}

impl EnrollmentPolicy for AllowlistPolicy {
    fn check(&self, req: &EnrollmentRequest<'_>) -> EnrollmentOutcome {
        for p in &self.patterns {
            if glob_match(p, req.identifier) {
                return EnrollmentOutcome::Admit;
            }
        }
        EnrollmentOutcome::Deny(NipCaError::new(
            format!(
                "Identifier '{}' does not match any enrollment allowlist pattern.",
                req.identifier
            ),
            error_codes::RA_NID_NOT_ALLOWED,
        ))
    }
}

/// Glob match supporting `*` (any run) and `?` (single char); `*` alone matches
/// everything. Mirrors the .NET `GlobToRegex` semantics.
fn glob_match(pattern: &str, input: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Anchored full-string match.
    fn m(p: &[u8], s: &[u8]) -> bool {
        match p.first() {
            None => s.is_empty(),
            Some(b'*') => {
                // Match zero or more chars.
                m(&p[1..], s) || (!s.is_empty() && m(p, &s[1..]))
            }
            Some(b'?') => !s.is_empty() && m(&p[1..], &s[1..]),
            Some(&c) => !s.is_empty() && s[0] == c && m(&p[1..], &s[1..]),
        }
    }
    m(pattern.as_bytes(), input.as_bytes())
}

// ── Tier 2: Bootstrap token ───────────────────────────────────────────────────

/// Public metadata for a bootstrap token (raw value excluded).
#[derive(Debug, Clone)]
pub struct BootstrapTokenInfo {
    pub id: String,
    pub label: Option<String>,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub consumed: bool,
    pub revoked: bool,
}

/// Store for single-use enrollment bootstrap tokens (NPS-CR-0005 §3.3). Tokens
/// are persisted as SHA-256 hashes; the raw value is returned only at creation.
pub trait BootstrapTokenStore: Send + Sync {
    /// Create a token, store its hash, return the raw `nps-bootstrap-…` value.
    fn create(&self, label: Option<String>, expires_at: OffsetDateTime) -> String;
    /// Validate and atomically consume `token`. `false` if not found / expired /
    /// already consumed.
    fn validate_and_consume(&self, token: &str) -> bool;
    /// List all tokens (consumed or live) for operator inspection.
    fn list(&self) -> Vec<BootstrapTokenInfo>;
    /// Administratively revoke a token by id before consumption.
    fn revoke(&self, token_id: &str) -> bool;
}

struct TokenEntry {
    id: String,
    hash: Vec<u8>,
    label: Option<String>,
    created_at: OffsetDateTime,
    expires_at: OffsetDateTime,
    consumed: bool,
    revoked: bool,
}

/// In-memory [`BootstrapTokenStore`].
#[derive(Default)]
pub struct InMemoryBootstrapTokenStore {
    tokens: Mutex<Vec<TokenEntry>>,
}

impl InMemoryBootstrapTokenStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn random_id() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

impl BootstrapTokenStore for InMemoryBootstrapTokenStore {
    fn create(&self, label: Option<String>, expires_at: OffsetDateTime) -> String {
        let mut rand_bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut rand_bytes);
        let raw = format!("nps-bootstrap-{}", hex::encode(rand_bytes));
        let entry = TokenEntry {
            id: random_id(),
            hash: sha256(raw.as_bytes()),
            label,
            created_at: OffsetDateTime::now_utc(),
            expires_at,
            consumed: false,
            revoked: false,
        };
        self.tokens.lock().unwrap().push(entry);
        raw
    }

    fn validate_and_consume(&self, token: &str) -> bool {
        let hash = sha256(token.as_bytes());
        let now = OffsetDateTime::now_utc();
        let mut g = self.tokens.lock().unwrap();
        for e in g.iter_mut() {
            if e.consumed || e.revoked {
                continue;
            }
            if now > e.expires_at {
                continue;
            }
            if e.hash == hash {
                e.consumed = true;
                return true;
            }
        }
        false
    }

    fn list(&self) -> Vec<BootstrapTokenInfo> {
        self.tokens
            .lock()
            .unwrap()
            .iter()
            .map(|e| BootstrapTokenInfo {
                id: e.id.clone(),
                label: e.label.clone(),
                created_at: e.created_at,
                expires_at: e.expires_at,
                consumed: e.consumed,
                revoked: e.revoked,
            })
            .collect()
    }

    fn revoke(&self, token_id: &str) -> bool {
        let mut g = self.tokens.lock().unwrap();
        for e in g.iter_mut() {
            if e.id != token_id {
                continue;
            }
            if e.consumed || e.revoked {
                return false;
            }
            e.revoked = true;
            return true;
        }
        false
    }
}

/// Enrollment Tier 2: requires a valid single-use bootstrap token.
pub struct BootstrapTokenPolicy<'s> {
    store: &'s dyn BootstrapTokenStore,
}

impl<'s> BootstrapTokenPolicy<'s> {
    pub fn new(store: &'s dyn BootstrapTokenStore) -> Self {
        Self { store }
    }
}

impl EnrollmentPolicy for BootstrapTokenPolicy<'_> {
    fn check(&self, req: &EnrollmentRequest<'_>) -> EnrollmentOutcome {
        let token = req.enrollment_token.unwrap_or("");
        if token.is_empty() || !token.starts_with("nps-bootstrap-") {
            return EnrollmentOutcome::Deny(NipCaError::new(
                "A bootstrap token (prefix 'nps-bootstrap-') is required for enrollment.",
                error_codes::RA_TOKEN_INVALID,
            ));
        }
        if self.store.validate_and_consume(token) {
            EnrollmentOutcome::Admit
        } else {
            EnrollmentOutcome::Deny(NipCaError::new(
                "Bootstrap token is invalid, expired, or already consumed.",
                error_codes::RA_TOKEN_EXPIRED,
            ))
        }
    }
}

// ── Tier 3: Pending queue ─────────────────────────────────────────────────────

/// Lifecycle state of a pending registration record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingStatus {
    Pending,
    Approved,
    Rejected,
}

impl PendingStatus {
    pub fn as_wire(&self) -> &'static str {
        match self {
            PendingStatus::Pending => "pending",
            PendingStatus::Approved => "approved",
            PendingStatus::Rejected => "rejected",
        }
    }
}

/// A registration request waiting for operator approval.
#[derive(Debug, Clone)]
pub struct PendingRegistration {
    pub id: String,
    pub entity_type: String,
    pub identifier: String,
    pub pub_key: String,
    pub capabilities: Vec<String>,
    pub scope_json: String,
    pub metadata_json: Option<String>,
    pub requested_at: OffsetDateTime,
    pub status: PendingStatus,
    pub reject_reason: Option<String>,
}

/// Store for pending registration requests (NPS-CR-0005 §3.4).
pub trait PendingStore: Send + Sync {
    /// Enqueue a new pending registration; returns its id.
    fn enqueue(&self, request: PendingRegistration) -> String;
    /// List all records (any status).
    fn list(&self) -> Vec<PendingRegistration>;
    /// Get one record by id.
    fn get(&self, id: &str) -> Option<PendingRegistration>;
    /// Transition `Pending` → `Approved`. `false` if not found / not pending.
    fn approve(&self, id: &str) -> bool;
    /// Transition `Pending` → `Rejected`. `false` if not found / not pending.
    fn reject(&self, id: &str, reason: &str) -> bool;
    /// Count of records currently in `Pending` status.
    fn pending_count(&self) -> usize;
}

/// In-memory [`PendingStore`].
#[derive(Default)]
pub struct InMemoryPendingStore {
    records: Mutex<Vec<PendingRegistration>>,
}

impl InMemoryPendingStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PendingStore for InMemoryPendingStore {
    fn enqueue(&self, request: PendingRegistration) -> String {
        let id = request.id.clone();
        self.records.lock().unwrap().push(request);
        id
    }

    fn list(&self) -> Vec<PendingRegistration> {
        self.records.lock().unwrap().clone()
    }

    fn get(&self, id: &str) -> Option<PendingRegistration> {
        self.records
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned()
    }

    fn approve(&self, id: &str) -> bool {
        let mut g = self.records.lock().unwrap();
        if let Some(r) = g.iter_mut().find(|r| r.id == id) {
            if r.status == PendingStatus::Pending {
                r.status = PendingStatus::Approved;
                return true;
            }
        }
        false
    }

    fn reject(&self, id: &str, reason: &str) -> bool {
        let mut g = self.records.lock().unwrap();
        if let Some(r) = g.iter_mut().find(|r| r.id == id) {
            if r.status == PendingStatus::Pending {
                r.status = PendingStatus::Rejected;
                r.reject_reason = Some(reason.to_string());
                return true;
            }
        }
        false
    }

    fn pending_count(&self) -> usize {
        self.records
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.status == PendingStatus::Pending)
            .count()
    }
}

/// Enrollment Tier 3: every request is queued; the caller receives `202`.
pub struct PendingQueuePolicy<'s> {
    store: &'s dyn PendingStore,
    max_size: usize,
}

impl<'s> PendingQueuePolicy<'s> {
    pub fn new(store: &'s dyn PendingStore, max_size: usize) -> Self {
        Self { store, max_size }
    }
}

impl EnrollmentPolicy for PendingQueuePolicy<'_> {
    fn check(&self, req: &EnrollmentRequest<'_>) -> EnrollmentOutcome {
        if self.store.pending_count() >= self.max_size {
            return EnrollmentOutcome::Deny(NipCaError::new(
                format!(
                    "Pending enrollment queue is full (max {}). Retry later.",
                    self.max_size
                ),
                error_codes::RA_TOKEN_INVALID,
            ));
        }
        let id = new_uuid_hex();
        let record = PendingRegistration {
            id: id.clone(),
            entity_type: req.entity_type.to_string(),
            identifier: req.identifier.to_string(),
            pub_key: req.pub_key.to_string(),
            capabilities: req.capabilities.to_vec(),
            scope_json: req.scope_json.to_string(),
            metadata_json: req.metadata_json.map(str::to_string),
            requested_at: OffsetDateTime::now_utc(),
            status: PendingStatus::Pending,
            reject_reason: None,
        };
        self.store.enqueue(record);
        EnrollmentOutcome::Pending(NipRaPending::new(id))
    }
}

/// 32-hex-char id (128 random bits), matching the .NET `Guid.NewGuid("N")` shape.
pub fn new_uuid_hex() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    hex::encode(b)
}

/// Base64url helper re-export for token comparison sites that need it.
pub(crate) fn _b64url(data: &[u8]) -> String {
    B64URL.encode(data)
}

/// Factory: build the policy selected by `opts.enrollment_tier`.
///
/// Returns `Err` when the selected tier needs a store that was not supplied.
pub fn create_enrollment_policy<'a>(
    opts: &NipCaOptions,
    bootstrap_token_store: Option<&'a dyn BootstrapTokenStore>,
    pending_store: Option<&'a dyn PendingStore>,
) -> Result<Box<dyn EnrollmentPolicy + 'a>, String> {
    match opts.enrollment_tier {
        EnrollmentTier::Allowlist => Ok(Box::new(AllowlistPolicy::new(
            opts.enrollment_allowlist_patterns.clone(),
        ))),
        EnrollmentTier::BootstrapToken => match bootstrap_token_store {
            Some(s) => Ok(Box::new(BootstrapTokenPolicy::new(s))),
            None => Err(
                "EnrollmentTier::BootstrapToken requires a BootstrapTokenStore.".to_string(),
            ),
        },
        EnrollmentTier::PendingQueue => match pending_store {
            Some(s) => Ok(Box::new(PendingQueuePolicy::new(
                s,
                opts.pending_queue_max_size,
            ))),
            None => {
                Err("EnrollmentTier::PendingQueue requires a PendingStore.".to_string())
            }
        },
    }
}

/// Clamp a requested TTL to `opts.bootstrap_token_max_ttl`.
pub fn clamp_bootstrap_ttl(opts: &NipCaOptions, requested: Option<Duration>) -> Duration {
    let ttl = requested
        .filter(|d| d.is_positive())
        .unwrap_or(opts.bootstrap_token_max_ttl);
    if ttl > opts.bootstrap_token_max_ttl {
        opts.bootstrap_token_max_ttl
    } else {
        ttl
    }
}
