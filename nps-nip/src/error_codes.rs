// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NIP error code wire constants — mirror of `spec/error-codes.md` NIP section.

// ── Cert verification (v1 + v2) ──────────────────────────────────────────────
pub const CERT_EXPIRED:            &str = "NIP-CERT-EXPIRED";
pub const CERT_REVOKED:            &str = "NIP-CERT-REVOKED";
pub const CERT_SIGNATURE_INVALID:  &str = "NIP-CERT-SIGNATURE-INVALID";
pub const CERT_UNTRUSTED_ISSUER:   &str = "NIP-CERT-UNTRUSTED-ISSUER";
pub const CERT_CAPABILITY_MISSING: &str = "NIP-CERT-CAPABILITY-MISSING";
pub const CERT_SCOPE_VIOLATION:    &str = "NIP-CERT-SCOPE-VIOLATION";

// ── CA service ───────────────────────────────────────────────────────────────
pub const CA_NID_NOT_FOUND:           &str = "NIP-CA-NID-NOT-FOUND";
pub const CA_NID_ALREADY_EXISTS:      &str = "NIP-CA-NID-ALREADY-EXISTS";
pub const CA_SERIAL_DUPLICATE:        &str = "NIP-CA-SERIAL-DUPLICATE";
pub const CA_RENEWAL_TOO_EARLY:       &str = "NIP-CA-RENEWAL-TOO-EARLY";
pub const CA_SCOPE_EXPANSION_DENIED:  &str = "NIP-CA-SCOPE-EXPANSION-DENIED";

pub const OCSP_UNAVAILABLE:    &str = "NIP-OCSP-UNAVAILABLE";
pub const TRUST_FRAME_INVALID: &str = "NIP-TRUST-FRAME-INVALID";

// ── RFC-0003 (assurance level) ───────────────────────────────────────────────
pub const ASSURANCE_MISMATCH: &str = "NIP-ASSURANCE-MISMATCH";
pub const ASSURANCE_UNKNOWN:  &str = "NIP-ASSURANCE-UNKNOWN";

// ── RFC-0004 (reputation log) ────────────────────────────────────────────────
pub const REPUTATION_ENTRY_INVALID:    &str = "NIP-REPUTATION-ENTRY-INVALID";
pub const REPUTATION_LOG_UNREACHABLE:  &str = "NIP-REPUTATION-LOG-UNREACHABLE";

// ── RFC-0002 (X.509 + ACME) ──────────────────────────────────────────────────
pub const CERT_FORMAT_INVALID:       &str = "NIP-CERT-FORMAT-INVALID";
pub const CERT_EKU_MISSING:          &str = "NIP-CERT-EKU-MISSING";
pub const CERT_SUBJECT_NID_MISMATCH: &str = "NIP-CERT-SUBJECT-NID-MISMATCH";
pub const ACME_CHALLENGE_FAILED:     &str = "NIP-ACME-CHALLENGE-FAILED";
