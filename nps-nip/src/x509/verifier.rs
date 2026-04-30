// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Verifies NPS X.509 NID certificate chains per NPS-RFC-0002 §4.6.

use base64::Engine;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use x509_parser::oid_registry::Oid;
use x509_parser::prelude::*;

use crate::assurance_level::AssuranceLevel;
use crate::error_codes;

use super::oids::{
    oid_equals, EKU_AGENT_IDENTITY_OID, EKU_NODE_IDENTITY_OID,
    EXTENSION_EXTENDED_KEY_USAGE_OID, NID_ASSURANCE_LEVEL_OID,
};

#[derive(Debug, Clone)]
pub struct VerifyResult {
    pub valid:       bool,
    pub error_code:  Option<&'static str>,
    pub message:     Option<String>,
    /// Raw DER of the leaf cert on success.
    pub leaf_der:    Option<Vec<u8>>,
}

fn ok(leaf_der: Vec<u8>) -> VerifyResult {
    VerifyResult { valid: true, error_code: None, message: None, leaf_der: Some(leaf_der) }
}

fn fail(code: &'static str, msg: impl Into<String>) -> VerifyResult {
    VerifyResult {
        valid: false, error_code: Some(code), message: Some(msg.into()), leaf_der: None,
    }
}

pub struct VerifyOptions<'a> {
    pub cert_chain_b64u_der:        &'a [String],
    pub asserted_nid:               &'a str,
    pub asserted_assurance_level:   Option<AssuranceLevel>,
    pub trusted_root_certs_der:     &'a [Vec<u8>],
}

/// Verify an NPS X.509 NID certificate chain.
///
/// Stages:
///   1. Decode chain (base64url DER → x509-parser Certificate).
///   2. Leaf EKU check — critical, contains agent-identity OR node-identity OID.
///   3. Subject CN / SAN URI match against asserted NID.
///   4. Assurance-level extension match against asserted level (if both present).
///   5. Chain signature verification — leaf → intermediates → trusted root.
pub fn verify(opts: VerifyOptions<'_>) -> VerifyResult {
    if opts.cert_chain_b64u_der.is_empty() {
        return fail(error_codes::CERT_FORMAT_INVALID, "cert_chain is empty");
    }
    let mut chain_der: Vec<Vec<u8>> = Vec::with_capacity(opts.cert_chain_b64u_der.len());
    for (i, s) in opts.cert_chain_b64u_der.iter().enumerate() {
        match base64_url_decode(s) {
            Ok(b) => chain_der.push(b),
            Err(e) => return fail(error_codes::CERT_FORMAT_INVALID,
                format!("chain[{i}] base64url decode: {e}")),
        }
    }
    // Parse all certs.
    let mut chain: Vec<X509Certificate> = Vec::with_capacity(chain_der.len());
    for (i, der) in chain_der.iter().enumerate() {
        match X509Certificate::from_der(der) {
            Ok((_, c)) => chain.push(c),
            Err(e) => return fail(error_codes::CERT_FORMAT_INVALID,
                format!("chain[{i}] DER parse: {e}")),
        }
    }
    let leaf = &chain[0];

    // Stage 2: EKU.
    if let Some(r) = check_leaf_eku(leaf) {
        return r;
    }
    // Stage 3: subject NID.
    if let Some(r) = check_subject_nid(leaf, opts.asserted_nid) {
        return r;
    }
    // Stage 4: assurance level.
    if let Some(r) = check_assurance_level(leaf, opts.asserted_assurance_level.as_ref()) {
        return r;
    }
    // Stage 5: chain signature.
    if let Some(r) = check_chain_signature(&chain, opts.trusted_root_certs_der) {
        return r;
    }
    ok(chain_der.into_iter().next().unwrap())
}

fn check_leaf_eku(leaf: &X509Certificate) -> Option<VerifyResult> {
    for ext in leaf.extensions() {
        if oid_equals(&ext.oid, EXTENSION_EXTENDED_KEY_USAGE_OID) {
            if !ext.critical {
                return Some(fail(error_codes::CERT_EKU_MISSING,
                    "ExtendedKeyUsage extension is not marked critical"));
            }
            // Walk the ParsedExtension::ExtendedKeyUsage variant if present;
            // otherwise, decode the raw value as SEQUENCE OF OID.
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                for oid in &eku.other {
                    if oid_equals(oid, EKU_AGENT_IDENTITY_OID) ||
                       oid_equals(oid, EKU_NODE_IDENTITY_OID) {
                        return None;
                    }
                }
            } else {
                // Manually parse SEQUENCE OF OID from the raw value.
                if raw_seq_contains_oid(ext.value, EKU_AGENT_IDENTITY_OID) ||
                   raw_seq_contains_oid(ext.value, EKU_NODE_IDENTITY_OID) {
                    return None;
                }
            }
            return Some(fail(error_codes::CERT_EKU_MISSING,
                "ExtendedKeyUsage does not contain agent-identity or node-identity OID"));
        }
    }
    Some(fail(error_codes::CERT_EKU_MISSING, "leaf has no ExtendedKeyUsage extension"))
}

fn check_subject_nid(leaf: &X509Certificate, asserted_nid: &str) -> Option<VerifyResult> {
    // Subject CN.
    let mut cn_match = false;
    for cn in leaf.subject().iter_common_name() {
        if let Ok(s) = cn.as_str() {
            if s == asserted_nid {
                cn_match = true;
                break;
            }
        }
    }
    if !cn_match {
        return Some(fail(error_codes::CERT_SUBJECT_NID_MISMATCH,
            format!("leaf subject CN does not match asserted NID ({asserted_nid})")));
    }
    // SAN URI.
    if let Ok(Some(san_ext)) = leaf.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let GeneralName::URI(u) = name {
                if *u == asserted_nid {
                    return None;
                }
            }
        }
    }
    Some(fail(error_codes::CERT_SUBJECT_NID_MISMATCH, "no SAN URI matches asserted NID"))
}

fn check_assurance_level(
    leaf: &X509Certificate, asserted: Option<&AssuranceLevel>,
) -> Option<VerifyResult> {
    let Some(asserted) = asserted else { return None; };
    for ext in leaf.extensions() {
        if oid_equals(&ext.oid, NID_ASSURANCE_LEVEL_OID) {
            // ASN.1 ENUMERATED: tag=0x0A, len=0x01, content=<rank>.
            if ext.value.len() != 3 || ext.value[0] != 0x0A || ext.value[1] != 0x01 {
                return Some(fail(error_codes::CERT_FORMAT_INVALID,
                    format!("malformed assurance-level extension: {}", hex::encode(ext.value))));
            }
            let rank = ext.value[2];
            let cert_level = match AssuranceLevel::from_rank(rank) {
                Ok(l) => l,
                Err(_) => return Some(fail(error_codes::ASSURANCE_UNKNOWN,
                    format!("assurance-level extension contains unknown value: {rank}"))),
            };
            if cert_level != *asserted {
                return Some(fail(error_codes::ASSURANCE_MISMATCH,
                    format!("cert assurance-level ({}) does not match asserted ({})",
                        cert_level.wire, asserted.wire)));
            }
            return None;
        }
    }
    // Optional in v0.1 — pass silently.
    None
}

fn check_chain_signature(
    chain: &[X509Certificate], trusted_roots_der: &[Vec<u8>],
) -> Option<VerifyResult> {
    if trusted_roots_der.is_empty() {
        return Some(fail(error_codes::CERT_FORMAT_INVALID,
            "no trusted X.509 roots configured"));
    }
    // Walk leaf → intermediates: each MUST be signed by its successor.
    for i in 0..chain.len() - 1 {
        if let Err(e) = verify_signed_by(&chain[i], &chain[i + 1]) {
            return Some(fail(error_codes::CERT_FORMAT_INVALID,
                format!("chain link {i} signature did not verify: {e}")));
        }
    }
    let last = &chain[chain.len() - 1];
    let last_der = last.as_ref();
    for root_der in trusted_roots_der {
        if last_der == root_der.as_slice() {
            return None;
        }
        if let Ok((_, root)) = X509Certificate::from_der(root_der) {
            if verify_signed_by(last, &root).is_ok() {
                return None;
            }
        }
    }
    Some(fail(error_codes::CERT_FORMAT_INVALID,
        "chain does not anchor to any trusted root"))
}

fn verify_signed_by(child: &X509Certificate, issuer: &X509Certificate) -> Result<(), String> {
    // Issuer's SPKI must be Ed25519 (RFC 8410 OID 1.3.101.112).
    let pub_key_bytes = issuer.public_key().subject_public_key.data.as_ref();
    if pub_key_bytes.len() != 32 {
        return Err(format!("issuer pubkey is not 32 bytes ({} bytes)", pub_key_bytes.len()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(pub_key_bytes);
    let verifying_key = VerifyingKey::from_bytes(&pk)
        .map_err(|e| format!("issuer Ed25519 pubkey parse: {e}"))?;

    let signature_bytes = child.signature_value.data.as_ref();
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|e| format!("child signature parse: {e}"))?;

    verifying_key.verify(child.tbs_certificate.as_ref(), &signature)
        .map_err(|e| format!("Ed25519 verify failed: {e}"))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn base64_url_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|e| format!("{e}"))
}

/// Walk a DER `SEQUENCE OF OBJECT IDENTIFIER` value and check whether it
/// contains the given OID. Used as a fallback when ParsedExtension cannot
/// surface our custom EKU OID.
fn raw_seq_contains_oid(value: &[u8], expected: &[u64]) -> bool {
    if value.len() < 2 || value[0] != 0x30 {
        return false;
    }
    // Skip outer SEQUENCE tag + length.
    let (start, content_len) = match read_der_length(&value[1..]) {
        Some((len, hdr)) => (1 + hdr, len),
        None => return false,
    };
    let end = start + content_len;
    if end > value.len() { return false; }
    let mut pos = start;
    while pos + 2 <= end {
        if value[pos] != 0x06 { return false; }
        let (oid_start, oid_len) = match read_der_length(&value[pos + 1..]) {
            Some((len, hdr)) => (pos + 1 + hdr, len),
            None => return false,
        };
        if oid_start + oid_len > value.len() { return false; }
        let oid_bytes = &value[oid_start..oid_start + oid_len];
        let expected_bytes = super::oids::encode_oid_content(expected);
        if oid_bytes == expected_bytes.as_slice() {
            return true;
        }
        pos = oid_start + oid_len;
    }
    false
}

/// Read a DER length-of-content prefix from the start of `b`.
/// Returns (content_length, header_length).
fn read_der_length(b: &[u8]) -> Option<(usize, usize)> {
    if b.is_empty() { return None; }
    let first = b[0];
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n { return None; }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | b[1 + i] as usize;
    }
    Some((len, 1 + n))
}

// Re-export used types so the tests file can `use x509::Verifier as _` more easily.
pub use x509_parser::extensions::GeneralName;
