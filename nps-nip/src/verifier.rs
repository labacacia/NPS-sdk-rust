// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NipIdentVerifier — Phase 1 dual-trust IdentFrame verifier per
//! NPS-RFC-0002 §8.1.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::HashMap;

use crate::assurance_level::{AssuranceLevel, ANONYMOUS};
use crate::cert_format::V2_X509;
use crate::error_codes;
use crate::frames::IdentFrame;
use crate::x509;

#[derive(Debug, Default, Clone)]
pub struct NipVerifierOptions {
    /// Map of issuer NID → CA public key string ("ed25519:<hex>").
    pub trusted_ca_public_keys: HashMap<String, String>,
    /// X.509 trust anchors as raw DER. Empty makes Step 3b skip even for v2 frames.
    pub trusted_x509_roots_der: Vec<Vec<u8>>,
    /// Minimum required assurance level (NPS-RFC-0003).
    pub min_assurance_level: Option<AssuranceLevel>,
}

#[derive(Debug, Clone)]
pub struct NipIdentVerifyResult {
    pub valid:       bool,
    /// 0 = none, 1 = sig, 2 = assurance, 3 = X.509.
    pub step_failed: u8,
    pub error_code:  Option<&'static str>,
    pub message:     Option<String>,
}

fn ok() -> NipIdentVerifyResult {
    NipIdentVerifyResult { valid: true, step_failed: 0, error_code: None, message: None }
}

fn fail(step: u8, code: &'static str, msg: impl Into<String>) -> NipIdentVerifyResult {
    NipIdentVerifyResult {
        valid: false, step_failed: step, error_code: Some(code), message: Some(msg.into()),
    }
}

pub struct NipIdentVerifier {
    pub options: NipVerifierOptions,
}

impl NipIdentVerifier {
    pub fn new(options: NipVerifierOptions) -> Self { Self { options } }

    pub fn verify(&self, frame: &IdentFrame, issuer_nid: &str) -> NipIdentVerifyResult {
        // ── Step 1: v1 Ed25519 signature check ───────────────────────────
        let Some(ca_pub_key_str) = self.options.trusted_ca_public_keys.get(issuer_nid) else {
            return fail(1, error_codes::CERT_UNTRUSTED_ISSUER,
                format!("no trusted CA public key for issuer: {issuer_nid}"));
        };
        let Some(sig_str) = frame.signature.as_ref() else {
            return fail(1, error_codes::CERT_SIGNATURE_INVALID, "missing signature");
        };
        if !sig_str.starts_with("ed25519:") {
            return fail(1, error_codes::CERT_SIGNATURE_INVALID, "malformed signature prefix");
        }
        let pub_key_bytes = match parse_pub_key_string(ca_pub_key_str) {
            Ok(b) => b,
            Err(e) => return fail(1, error_codes::CERT_SIGNATURE_INVALID, e),
        };
        let verifying_key = match VerifyingKey::from_bytes(&pub_key_bytes) {
            Ok(k) => k,
            Err(e) => return fail(1, error_codes::CERT_SIGNATURE_INVALID,
                format!("invalid Ed25519 pubkey: {e}")),
        };
        let sig_bytes = match base64::engine::general_purpose::STANDARD
            .decode(&sig_str["ed25519:".len()..])
        {
            Ok(b) => b,
            Err(e) => return fail(1, error_codes::CERT_SIGNATURE_INVALID,
                format!("base64 decode: {e}")),
        };
        let signature = match Signature::from_slice(&sig_bytes) {
            Ok(s) => s,
            Err(e) => return fail(1, error_codes::CERT_SIGNATURE_INVALID,
                format!("signature parse: {e}")),
        };
        let canonical = canonical_json(&frame.unsigned_dict());
        if verifying_key.verify(canonical.as_bytes(), &signature).is_err() {
            return fail(1, error_codes::CERT_SIGNATURE_INVALID,
                "v1 Ed25519 signature did not verify against issuer CA key");
        }

        // ── Step 2: minimum assurance level ───────────────────────────────
        if let Some(min) = &self.options.min_assurance_level {
            let got = frame.assurance_level.unwrap_or(ANONYMOUS);
            if !got.meets_or_exceeds(min) {
                return fail(2, error_codes::ASSURANCE_MISMATCH,
                    format!("assurance_level ({}) below required minimum ({})",
                        got.wire, min.wire));
            }
        }

        // ── Step 3b: X.509 chain check ───────────────────────────────────
        let has_v2_trust = !self.options.trusted_x509_roots_der.is_empty();
        let is_v2_frame = frame.cert_format.as_deref() == Some(V2_X509);
        if has_v2_trust && is_v2_frame {
            let chain = frame.cert_chain.as_deref().unwrap_or(&[]);
            let r = x509::verify(x509::VerifyOptions {
                cert_chain_b64u_der:      chain,
                asserted_nid:             &frame.nid,
                asserted_assurance_level: frame.assurance_level,
                trusted_root_certs_der:   &self.options.trusted_x509_roots_der,
            });
            if !r.valid {
                return fail(3,
                    r.error_code.unwrap_or(error_codes::CERT_FORMAT_INVALID),
                    r.message.unwrap_or_else(|| "X.509 chain validation failed".into()));
            }
        }

        ok()
    }
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
