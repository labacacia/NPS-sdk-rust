// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NipIdentVerifier — Node-side IdentFrame verifier implementing the full
//! NPS-3 §7 six-step flow, plus the dual-trust (v1 Ed25519 + v2 X.509)
//! layering of NPS-RFC-0002 §8.1.
//!
//! Behavioural parity with the .NET reference
//! (`NPS.NIP.Verification.NipIdentVerifier`). The six steps (ALL must pass):
//!
//! 1. **Expiry** — `expires_at > now` (context `as_of` or wall clock).
//! 2. **Trusted issuer** — `issued_by ∈ options.trusted_issuers`.
//! 3. **Signature** — Ed25519 sig over the canonical frame verifies against the
//!    issuer CA pubkey, PLUS X.509 chain validation when `cert_format = v2-x509`
//!    and `trusted_x509_roots` is set. A v1-only verifier (no X.509 roots)
//!    ignores `cert_chain` entirely.
//! 4. **Revocation** — local CRL → `revocation_check` callback →
//!    `revocation_store` → OCSP `GET {ocsp_url}/{nid}`. Pass-through when
//!    nothing is configured. OCSP transport failure honours `ocsp_fail_open`.
//! 5. **Capabilities** — frame capability set ⊇ `context.required_capabilities`.
//! 6. **Scope** — `context.target_node_path` matched by `scope.nodes` patterns.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::assurance_level::{AssuranceLevel, ANONYMOUS};
use crate::cert_format::V2_X509;
use crate::error_codes;
use crate::frames::IdentFrame;
use crate::phase3;
use crate::revocation_policy::{
    NipRevocationMode, NipRevocationOutcome, NipRevocationPolicy, NipRevocationSource,
};
use crate::x509;

// ── NipVerifyContext (NPS-3 §7 steps 1, 5, 6) ────────────────────────────────

/// Per-request context passed to [`NipIdentVerifier`]. All fields are optional;
/// omit one to skip the corresponding check.
#[derive(Debug, Default, Clone)]
pub struct NipVerifyContext {
    /// Capabilities the Node requires the Agent to hold (Step 5).
    /// Empty skips the capability check.
    pub required_capabilities: Vec<String>,
    /// The full NWP node path the Agent is trying to access (Step 6).
    /// `None` skips the scope check.
    pub target_node_path: Option<String>,
    /// Clock override for testing (replaces wall-clock in the expiry check).
    pub as_of: Option<OffsetDateTime>,
}

// ── Revocation records + store trait (Step 4) ────────────────────────────────

/// A CA store record consulted as a live revocation source. Mirrors the
/// relevant fields of the .NET `NipCertRecord`.
#[derive(Debug, Clone, Default)]
pub struct NipCertRecord {
    pub serial: String,
    /// Populated when the certificate has been revoked.
    pub revoked_at: Option<String>,
    pub revoke_reason: Option<String>,
}

/// Live revocation source used as Step 4's third check. The verifier rejects
/// records whose `revoked_at` is populated.
pub trait NipCaStore: Send + Sync {
    /// Look up a certificate record by serial number.
    fn get_by_serial<'a>(
        &'a self,
        serial: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<NipCertRecord>> + Send + 'a>>;
}

/// Live revocation callback (mirror of the .NET `NipRevocationCheck` delegate).
/// Return `Some(failing_result)` to reject the identity, or `None`/OK to
/// continue to the next configured revocation source.
pub type NipRevocationCheck = Arc<
    dyn Fn(&IdentFrame) -> Pin<Box<dyn Future<Output = Option<NipIdentVerifyResult>> + Send>>
        + Send
        + Sync,
>;

// ── OCSP JSON wire shape ─────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OcspResponse {
    #[serde(default)]
    pub valid: bool,
    #[serde(default)]
    pub error_code: Option<String>,
}

// ── Options ──────────────────────────────────────────────────────────────────

#[derive(Clone, Default)]
pub struct NipVerifierOptions {
    /// Trusted CA issuers keyed by issuer NID. Value is the CA public key in
    /// `ed25519:{hex}` form. Used by Step 2 (trusted issuer) and Step 3
    /// (signature). Alias of the .NET `TrustedIssuers`.
    pub trusted_ca_public_keys: HashMap<String, String>,
    /// X.509 trust anchors as raw DER. Empty makes Step 3b skip even for v2
    /// frames (v1-only stance). Alias of the .NET `TrustedX509Roots`.
    pub trusted_x509_roots_der: Vec<Vec<u8>>,
    /// Local CRL: revoked serials checked before any network call (Step 4).
    pub local_revoked_serials: Vec<String>,
    /// Marks an empty local CRL as a configured, current revocation source.
    pub local_crl_configured: bool,
    /// Optional live revocation callback (Step 4).
    pub revocation_check: Option<NipRevocationCheck>,
    /// Optional CA store used as a live revocation source (Step 4).
    pub revocation_store: Option<Arc<dyn NipCaStore>>,
    /// Optional OCSP endpoint base URL. `GET {ocsp_url}/{nid}` (Step 4).
    pub ocsp_url: Option<String>,
    /// When true, OCSP transport failures pass through. Secure default is
    /// fail-closed (`NIP-OCSP-UNAVAILABLE`).
    pub ocsp_fail_open: bool,
    /// Required mode rejects when no revocation source is configured.
    pub revocation_mode: NipRevocationMode,
    /// Minimum required assurance level (NPS-RFC-0003). Enforced as part of
    /// Step 3 when set.
    pub min_assurance_level: Option<AssuranceLevel>,
    /// NIP v0.12 §7.5 hardens v2-x509 verification with CA-attested
    /// node_roles/capabilities and OCSP-staple freshness checks. Defaults false
    /// so existing v2 deployments remain advisory until explicitly enabled.
    pub phase3_enforcement: bool,
}

impl std::fmt::Debug for NipVerifierOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NipVerifierOptions")
            .field("trusted_ca_public_keys", &self.trusted_ca_public_keys)
            .field(
                "trusted_x509_roots_der.len",
                &self.trusted_x509_roots_der.len(),
            )
            .field("local_revoked_serials", &self.local_revoked_serials)
            .field("local_crl_configured", &self.local_crl_configured)
            .field("revocation_check", &self.revocation_check.is_some())
            .field("revocation_store", &self.revocation_store.is_some())
            .field("ocsp_url", &self.ocsp_url)
            .field("ocsp_fail_open", &self.ocsp_fail_open)
            .field("revocation_mode", &self.revocation_mode)
            .field("min_assurance_level", &self.min_assurance_level)
            .field("phase3_enforcement", &self.phase3_enforcement)
            .finish()
    }
}

// ── Result ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NipIdentVerifyResult {
    pub valid: bool,
    /// The NPS-3 §7 step (1–6) that failed, or 0 on success.
    pub step_failed: u8,
    pub error_code: Option<&'static str>,
    pub message: Option<String>,
}

pub(crate) fn ok() -> NipIdentVerifyResult {
    NipIdentVerifyResult {
        valid: true,
        step_failed: 0,
        error_code: None,
        message: None,
    }
}

pub(crate) fn fail(step: u8, code: &'static str, msg: impl Into<String>) -> NipIdentVerifyResult {
    NipIdentVerifyResult {
        valid: false,
        step_failed: step,
        error_code: Some(code),
        message: Some(msg.into()),
    }
}

// ── Verifier ─────────────────────────────────────────────────────────────────

pub struct NipIdentVerifier {
    pub options: NipVerifierOptions,
    http: reqwest::Client,
}

impl NipIdentVerifier {
    pub fn new(options: NipVerifierOptions) -> Self {
        Self {
            options,
            http: reqwest::Client::new(),
        }
    }

    pub fn with_client(options: NipVerifierOptions, http: reqwest::Client) -> Self {
        Self { options, http }
    }

    /// Full NPS-3 §7 six-step verification.
    ///
    /// `issuer_nid` is the CA that is expected to have signed the frame; when
    /// the frame carries an `issued_by`, it MUST equal `issuer_nid` (Step 2).
    pub async fn verify(
        &self,
        frame: &IdentFrame,
        issuer_nid: &str,
        context: &NipVerifyContext,
    ) -> NipIdentVerifyResult {
        let now = context.as_of.unwrap_or_else(OffsetDateTime::now_utc);

        // ── Step 1: Expiry ───────────────────────────────────────────────
        if let Some(expires_at) = frame.expires_at.as_deref() {
            match parse_ts(expires_at) {
                Some(exp) if exp > now => {}
                _ => {
                    return fail(
                        1,
                        error_codes::CERT_EXPIRED,
                        format!("Certificate expired at {expires_at}."),
                    );
                }
            }
        }

        // ── Step 2: Trusted issuer ───────────────────────────────────────
        // The declared issuer (when present) must match the expected issuer.
        if let Some(declared) = frame.issued_by.as_deref() {
            if declared != issuer_nid {
                return fail(
                    2,
                    error_codes::CERT_UNTRUSTED_ISSUER,
                    format!("Issuer '{declared}' does not match expected issuer '{issuer_nid}'."),
                );
            }
        }
        let Some(ca_pub_key_str) = self.options.trusted_ca_public_keys.get(issuer_nid) else {
            return fail(
                2,
                error_codes::CERT_UNTRUSTED_ISSUER,
                format!("Issuer '{issuer_nid}' is not in the trusted issuers list."),
            );
        };

        // ── Step 3: Signature (Ed25519 v1) ───────────────────────────────
        if let r @ NipIdentVerifyResult { valid: false, .. } =
            verify_signature(frame, ca_pub_key_str)
        {
            return r;
        }

        // ── Step 3 (cont.): minimum assurance level (NPS-RFC-0003) ───────
        if let Some(min) = &self.options.min_assurance_level {
            let got = frame.assurance_level.unwrap_or(ANONYMOUS);
            if !got.meets_or_exceeds(min) {
                return fail(
                    3,
                    error_codes::ASSURANCE_MISMATCH,
                    format!(
                        "assurance_level ({}) below required minimum ({})",
                        got.wire, min.wire
                    ),
                );
            }
        }

        // ── Step 3b: X.509 chain (v2-x509 only, when trust anchors set) ──
        let has_v2_trust = !self.options.trusted_x509_roots_der.is_empty();
        let is_v2_frame = frame.cert_format.as_deref() == Some(V2_X509);
        if has_v2_trust && is_v2_frame {
            let chain = frame.cert_chain.as_deref().unwrap_or(&[]);
            let r = x509::verify(x509::VerifyOptions {
                cert_chain_b64u_der: chain,
                asserted_nid: &frame.nid,
                asserted_assurance_level: frame.assurance_level,
                trusted_root_certs_der: &self.options.trusted_x509_roots_der,
            });
            if !r.valid {
                return fail(
                    3,
                    r.error_code.unwrap_or(error_codes::CERT_FORMAT_INVALID),
                    r.message
                        .unwrap_or_else(|| "X.509 chain validation failed".into()),
                );
            }
            if self.options.phase3_enforcement {
                let Some(leaf_b64u) = chain.first() else {
                    return fail(3, error_codes::CERT_FORMAT_INVALID, "cert_chain is empty.");
                };
                let leaf_der = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(leaf_b64u)
                {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return fail(
                            3,
                            error_codes::CERT_FORMAT_INVALID,
                            "cert_chain[0] is not valid base64url DER.",
                        )
                    }
                };
                let phase3_result = phase3::enforce(frame, &leaf_der, Some(now));
                if !phase3_result.valid {
                    return phase3_result;
                }
            }
        }

        // ── Step 4: Revocation ───────────────────────────────────────────
        let revocation = self.check_revocation(frame).await;
        if !revocation.valid {
            return revocation;
        }

        // ── Step 5: Capabilities ─────────────────────────────────────────
        if !context.required_capabilities.is_empty() {
            let missing: Vec<&String> = context
                .required_capabilities
                .iter()
                .filter(|c| !frame.capabilities.contains(c))
                .collect();
            if !missing.is_empty() {
                let list = missing
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return fail(
                    5,
                    error_codes::CERT_CAPABILITY_MISSING,
                    format!("Certificate is missing required capabilities: {list}."),
                );
            }
        }

        // ── Step 6: Scope ────────────────────────────────────────────────
        if let Some(target) = context.target_node_path.as_deref() {
            return check_scope(frame, target);
        }

        ok()
    }

    async fn check_revocation(&self, frame: &IdentFrame) -> NipIdentVerifyResult {
        let serial = frame.serial.as_deref().unwrap_or("");
        let mut policy =
            NipRevocationPolicy::new(self.options.revocation_mode, self.options.ocsp_fail_open);

        // Local CRL first (fast, no network).
        if self.options.local_crl_configured || !self.options.local_revoked_serials.is_empty() {
            let revoked = !serial.is_empty()
                && self
                    .options
                    .local_revoked_serials
                    .iter()
                    .any(|s| s == serial);
            if let Some(result) = policy.observe(
                NipRevocationSource::LocalCrl,
                if revoked {
                    NipRevocationOutcome::Revoked
                } else {
                    NipRevocationOutcome::Good
                },
            ) {
                return result;
            }
        }

        // Live revocation callback.
        if let Some(cb) = &self.options.revocation_check {
            if let Some(r) = cb(frame).await {
                if !r.valid {
                    return r;
                }
            }
            let _ = policy.observe(NipRevocationSource::Callback, NipRevocationOutcome::Good);
        }

        // CA store lookup.
        if let Some(store) = &self.options.revocation_store {
            let record = store.get_by_serial(serial).await;
            let revoked = record
                .as_ref()
                .is_some_and(|item| item.revoked_at.is_some());
            if let Some(result) = policy.observe(
                NipRevocationSource::CaStore,
                if revoked {
                    NipRevocationOutcome::Revoked
                } else {
                    NipRevocationOutcome::Good
                },
            ) {
                return result;
            }
        }

        // OCSP call to the CA server (optional).
        if let Some(ocsp_url) = self.options.ocsp_url.as_deref() {
            let ocsp = self.ocsp_check(ocsp_url, &frame.nid).await;
            let outcome = if ocsp.valid {
                NipRevocationOutcome::Good
            } else if ocsp.error_code == Some(error_codes::CERT_REVOKED) {
                NipRevocationOutcome::Revoked
            } else {
                NipRevocationOutcome::Unavailable
            };
            if let Some(result) = policy.observe(NipRevocationSource::Ocsp, outcome) {
                return result;
            }
        }

        policy.complete()
    }

    async fn ocsp_check(&self, ocsp_url: &str, nid: &str) -> NipIdentVerifyResult {
        let url = format!("{}/{}", ocsp_url.trim_end_matches('/'), escape(nid));
        let resp = match self.http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => return self.ocsp_transport_failure(nid, &e.to_string()),
        };

        if !resp.status().is_success() {
            return fail(
                4,
                error_codes::OCSP_UNAVAILABLE,
                format!("OCSP endpoint returned {}.", resp.status().as_u16()),
            );
        }

        let body = match resp.json::<OcspResponse>().await {
            Ok(b) => b,
            Err(e) => return self.ocsp_transport_failure(nid, &e.to_string()),
        };

        if !body.valid {
            let code: &'static str = match body.error_code.as_deref() {
                Some(error_codes::CERT_REVOKED) | None => error_codes::CERT_REVOKED,
                Some(error_codes::CERT_EXPIRED) => error_codes::CERT_EXPIRED,
                Some(error_codes::OCSP_UNAVAILABLE) => error_codes::OCSP_UNAVAILABLE,
                Some(_) => error_codes::CERT_REVOKED,
            };
            return fail(4, code, format!("OCSP check failed for NID {nid}."));
        }

        ok()
    }

    fn ocsp_transport_failure(&self, nid: &str, err: &str) -> NipIdentVerifyResult {
        fail(
            4,
            error_codes::OCSP_UNAVAILABLE,
            format!("OCSP call failed for NID {nid}: {err}"),
        )
    }
}

// ── Signature verification helper (Step 3) ───────────────────────────────────

fn verify_signature(frame: &IdentFrame, ca_pub_key_str: &str) -> NipIdentVerifyResult {
    let Some(sig_str) = frame.signature.as_ref() else {
        return fail(3, error_codes::CERT_SIGNATURE_INVALID, "missing signature");
    };
    if !sig_str.starts_with("ed25519:") {
        return fail(
            3,
            error_codes::CERT_SIGNATURE_INVALID,
            "malformed signature prefix",
        );
    }
    let pub_key_bytes = match parse_pub_key_string(ca_pub_key_str) {
        Ok(b) => b,
        Err(e) => return fail(3, error_codes::CERT_SIGNATURE_INVALID, e),
    };
    let verifying_key = match VerifyingKey::from_bytes(&pub_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return fail(
                3,
                error_codes::CERT_SIGNATURE_INVALID,
                format!("invalid Ed25519 pubkey: {e}"),
            )
        }
    };
    let sig_bytes =
        match base64::engine::general_purpose::STANDARD.decode(&sig_str["ed25519:".len()..]) {
            Ok(b) => b,
            Err(e) => {
                return fail(
                    3,
                    error_codes::CERT_SIGNATURE_INVALID,
                    format!("base64 decode: {e}"),
                )
            }
        };
    let signature = match Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(e) => {
            return fail(
                3,
                error_codes::CERT_SIGNATURE_INVALID,
                format!("signature parse: {e}"),
            )
        }
    };
    let canonical = canonical_json(&frame.unsigned_dict());
    if verifying_key
        .verify(canonical.as_bytes(), &signature)
        .is_err()
    {
        return fail(
            3,
            error_codes::CERT_SIGNATURE_INVALID,
            "Certificate signature verification failed.",
        );
    }
    ok()
}

// ── Scope check (Step 6) ─────────────────────────────────────────────────────

fn check_scope(frame: &IdentFrame, target_path: &str) -> NipIdentVerifyResult {
    let nodes = frame
        .scope
        .as_ref()
        .and_then(|s| s.get("nodes"))
        .and_then(|n| n.as_array());
    let Some(nodes) = nodes else {
        return fail(
            6,
            error_codes::CERT_SCOPE_VIOLATION,
            "IdentFrame scope is missing 'nodes' field.",
        );
    };
    for pattern in nodes {
        if let Some(p) = pattern.as_str() {
            if nwp_path_matches(p, target_path) {
                return ok();
            }
        }
    }
    fail(
        6,
        error_codes::CERT_SCOPE_VIOLATION,
        format!("Target path '{target_path}' is not covered by the certificate scope."),
    )
}

/// Matches a NWP path against a scope pattern.
///
/// - A bare `*` matches any path.
/// - A trailing `/*` matches the prefix and any path under it (at a `/`
///   boundary).
/// - All other patterns are exact, case-insensitive matches.
pub fn nwp_path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let lower_path = path.to_ascii_lowercase();
        let lower_prefix = prefix.to_ascii_lowercase();
        return lower_path.starts_with(&lower_prefix)
            && (path.len() == prefix.len() || path.as_bytes().get(prefix.len()) == Some(&b'/'));
    }
    pattern.eq_ignore_ascii_case(path)
}

// ── Shared helpers ───────────────────────────────────────────────────────────

fn parse_ts(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

fn parse_pub_key_string(s: &str) -> Result<[u8; 32], String> {
    let prefix = "ed25519:";
    if !s.starts_with(prefix) {
        return Err(format!("unsupported public key format: {s}"));
    }
    let raw = hex::decode(&s[prefix.len()..]).map_err(|e| format!("hex decode: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("public key wrong size: {}", raw.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn escape(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Canonical JSON matching NipIdentity.sign — top-level keys sorted.
pub fn canonical_json(d: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut keys: Vec<&String> = d.keys().collect();
    keys.sort();
    let mut ordered = serde_json::Map::with_capacity(d.len());
    for k in keys {
        ordered.insert(k.clone(), d[k].clone());
    }
    serde_json::to_string(&ordered).unwrap_or_default()
}
