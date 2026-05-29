// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NDP error code wire constants — mirror of `spec/error-codes.md` NDP section.

// ── Resolve ───────────────────────────────────────────────────────────────────
pub const RESOLVE_NOT_FOUND: &str = "NDP-RESOLVE-NOT-FOUND";
pub const RESOLVE_AMBIGUOUS: &str = "NDP-RESOLVE-AMBIGUOUS";
pub const RESOLVE_TIMEOUT:   &str = "NDP-RESOLVE-TIMEOUT";

// ── Announce ──────────────────────────────────────────────────────────────────
pub const ANNOUNCE_SIGNATURE_INVALID: &str = "NDP-ANNOUNCE-SIGNATURE-INVALID";
pub const ANNOUNCE_NID_MISMATCH:      &str = "NDP-ANNOUNCE-NID-MISMATCH";
pub const ANNOUNCE_ROLE_REMOVED:      &str = "NDP-ANNOUNCE-ROLE-REMOVED";
pub const ANNOUNCE_ROLE_UNKNOWN:      &str = "NDP-ANNOUNCE-ROLE-UNKNOWN";
pub const ANNOUNCE_CONFLICT:          &str = "NDP-ANNOUNCE-CONFLICT";

// ── Graph ─────────────────────────────────────────────────────────────────────
pub const GRAPH_SEQ_ROLLBACK: &str = "NDP-GRAPH-SEQ-ROLLBACK";
pub const GRAPH_SEQ_GAP:      &str = "NDP-GRAPH-SEQ-GAP";
pub const GRAPH_INVALID:      &str = "NDP-GRAPH-INVALID";
pub const GRAPH_TOO_LARGE:    &str = "NDP-GRAPH-TOO-LARGE";

// ── Issuer / CA ───────────────────────────────────────────────────────────────
pub const ISSUER_NOT_ALLOWED: &str = "NDP-ISSUER-NOT-ALLOWED";
pub const CA_ATTEST_REQUIRED: &str = "NDP-CA-ATTEST-REQUIRED";

// ── Federation ────────────────────────────────────────────────────────────────
pub const FEDERATION_LOOP: &str = "NDP-FEDERATION-LOOP";

// ── Registry ──────────────────────────────────────────────────────────────────
pub const REGISTRY_UNAVAILABLE: &str = "NDP-REGISTRY-UNAVAILABLE";

// ── Mapping to NPS status ──────────────────────────────────────────────────────

/// Map a NDP error code to the corresponding NPS status code.
pub fn to_nps_status(code: &str) -> &'static str {
    match code {
        RESOLVE_NOT_FOUND          => "NPS-CLIENT-NOT-FOUND",
        RESOLVE_AMBIGUOUS          => "NPS-CLIENT-CONFLICT",
        RESOLVE_TIMEOUT            => "NPS-SERVER-TIMEOUT",

        ANNOUNCE_SIGNATURE_INVALID => "NPS-AUTH-UNAUTHENTICATED",
        ANNOUNCE_NID_MISMATCH      => "NPS-CLIENT-BAD-FRAME",
        ANNOUNCE_ROLE_REMOVED      => "NPS-CLIENT-BAD-FRAME",
        ANNOUNCE_ROLE_UNKNOWN      => "NPS-CLIENT-BAD-FRAME",
        ANNOUNCE_CONFLICT          => "NPS-CLIENT-CONFLICT",

        GRAPH_SEQ_ROLLBACK         => "NPS-CLIENT-BAD-FRAME",
        GRAPH_SEQ_GAP              => "NPS-STREAM-SEQ-GAP",
        GRAPH_INVALID              => "NPS-CLIENT-BAD-FRAME",
        GRAPH_TOO_LARGE            => "NPS-LIMIT-PAYLOAD",

        ISSUER_NOT_ALLOWED         => "NPS-AUTH-FORBIDDEN",
        CA_ATTEST_REQUIRED         => "NPS-AUTH-UNAUTHENTICATED",

        FEDERATION_LOOP            => "NPS-CLIENT-CONFLICT",

        REGISTRY_UNAVAILABLE       => "NPS-SERVER-UNAVAILABLE",

        _                          => "NPS-SERVER-INTERNAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_errors() {
        assert_eq!(to_nps_status(RESOLVE_NOT_FOUND), "NPS-CLIENT-NOT-FOUND");
        assert_eq!(to_nps_status(RESOLVE_AMBIGUOUS), "NPS-CLIENT-CONFLICT");
        assert_eq!(to_nps_status(RESOLVE_TIMEOUT),   "NPS-SERVER-TIMEOUT");
    }

    #[test]
    fn announce_errors() {
        assert_eq!(to_nps_status(ANNOUNCE_SIGNATURE_INVALID), "NPS-AUTH-UNAUTHENTICATED");
        assert_eq!(to_nps_status(ANNOUNCE_NID_MISMATCH),      "NPS-CLIENT-BAD-FRAME");
        assert_eq!(to_nps_status(ANNOUNCE_ROLE_REMOVED),      "NPS-CLIENT-BAD-FRAME");
        assert_eq!(to_nps_status(ANNOUNCE_ROLE_UNKNOWN),      "NPS-CLIENT-BAD-FRAME");
        assert_eq!(to_nps_status(ANNOUNCE_CONFLICT),          "NPS-CLIENT-CONFLICT");
    }

    #[test]
    fn graph_errors() {
        assert_eq!(to_nps_status(GRAPH_SEQ_ROLLBACK), "NPS-CLIENT-BAD-FRAME");
        assert_eq!(to_nps_status(GRAPH_SEQ_GAP),      "NPS-STREAM-SEQ-GAP");
        assert_eq!(to_nps_status(GRAPH_INVALID),      "NPS-CLIENT-BAD-FRAME");
        assert_eq!(to_nps_status(GRAPH_TOO_LARGE),    "NPS-LIMIT-PAYLOAD");
    }

    #[test]
    fn issuer_and_federation() {
        assert_eq!(to_nps_status(ISSUER_NOT_ALLOWED), "NPS-AUTH-FORBIDDEN");
        assert_eq!(to_nps_status(CA_ATTEST_REQUIRED), "NPS-AUTH-UNAUTHENTICATED");
        assert_eq!(to_nps_status(FEDERATION_LOOP),    "NPS-CLIENT-CONFLICT");
    }

    #[test]
    fn registry_unavailable() {
        assert_eq!(to_nps_status(REGISTRY_UNAVAILABLE), "NPS-SERVER-UNAVAILABLE");
    }

    #[test]
    fn unknown_falls_back_to_internal() {
        assert_eq!(to_nps_status("NDP-BOGUS"), "NPS-SERVER-INTERNAL");
    }

    #[test]
    fn constants_have_correct_prefix() {
        let codes = [
            RESOLVE_NOT_FOUND, RESOLVE_AMBIGUOUS, RESOLVE_TIMEOUT,
            ANNOUNCE_SIGNATURE_INVALID, ANNOUNCE_NID_MISMATCH,
            ANNOUNCE_ROLE_REMOVED, ANNOUNCE_ROLE_UNKNOWN, ANNOUNCE_CONFLICT,
            GRAPH_SEQ_ROLLBACK, GRAPH_SEQ_GAP, GRAPH_INVALID, GRAPH_TOO_LARGE,
            ISSUER_NOT_ALLOWED, CA_ATTEST_REQUIRED,
            FEDERATION_LOOP, REGISTRY_UNAVAILABLE,
        ];
        for c in &codes {
            assert!(c.starts_with("NDP-"), "Expected NDP- prefix, got: {c}");
        }
    }
}
