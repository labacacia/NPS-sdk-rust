// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS native status-code constants and HTTP mapping.
//!
//! Mirrors the full table in `spec/status-codes.md` (version 0.5, 2026-07-05).

// ── Success ───────────────────────────────────────────────────────────────────
pub const NPS_OK: &str = "NPS-OK";
pub const NPS_OK_ACCEPTED: &str = "NPS-OK-ACCEPTED";
pub const NPS_OK_NO_CONTENT: &str = "NPS-OK-NO-CONTENT";

// ── Client Errors ─────────────────────────────────────────────────────────────
pub const NPS_CLIENT_BAD_FRAME: &str = "NPS-CLIENT-BAD-FRAME";
pub const NPS_CLIENT_BAD_PARAM: &str = "NPS-CLIENT-BAD-PARAM";
pub const NPS_CLIENT_NOT_FOUND: &str = "NPS-CLIENT-NOT-FOUND";
pub const NPS_CLIENT_CONFLICT: &str = "NPS-CLIENT-CONFLICT";
pub const NPS_CLIENT_GONE: &str = "NPS-CLIENT-GONE";
pub const NPS_CLIENT_UNPROCESSABLE: &str = "NPS-CLIENT-UNPROCESSABLE";

// ── Authentication & Authorization ───────────────────────────────────────────
pub const NPS_AUTH_UNAUTHENTICATED: &str = "NPS-AUTH-UNAUTHENTICATED";
pub const NPS_AUTH_FORBIDDEN: &str = "NPS-AUTH-FORBIDDEN";

// ── Resource Limits ───────────────────────────────────────────────────────────
pub const NPS_LIMIT_RATE: &str = "NPS-LIMIT-RATE";
pub const NPS_LIMIT_BUDGET: &str = "NPS-LIMIT-BUDGET";
pub const NPS_LIMIT_PAYLOAD: &str = "NPS-LIMIT-PAYLOAD";
pub const NPS_LIMIT_RESOURCE: &str = "NPS-LIMIT-RESOURCE";

// ── Server Errors ─────────────────────────────────────────────────────────────
pub const NPS_SERVER_INTERNAL: &str = "NPS-SERVER-INTERNAL";
pub const NPS_SERVER_UNSUPPORTED: &str = "NPS-SERVER-UNSUPPORTED";
pub const NPS_SERVER_UNAVAILABLE: &str = "NPS-SERVER-UNAVAILABLE";
pub const NPS_SERVER_TIMEOUT: &str = "NPS-SERVER-TIMEOUT";
pub const NPS_SERVER_ENCODING_UNSUPPORTED: &str = "NPS-SERVER-ENCODING-UNSUPPORTED";
pub const NPS_DOWNSTREAM_UNAVAILABLE: &str = "NPS-DOWNSTREAM-UNAVAILABLE";

// ── Stream ────────────────────────────────────────────────────────────────────
pub const NPS_STREAM_SEQ_GAP: &str = "NPS-STREAM-SEQ-GAP";
pub const NPS_STREAM_NOT_FOUND: &str = "NPS-STREAM-NOT-FOUND";
pub const NPS_STREAM_LIMIT: &str = "NPS-STREAM-LIMIT";

// ── Protocol-Level ────────────────────────────────────────────────────────────
pub const NPS_PROTO_VERSION_INCOMPATIBLE: &str = "NPS-PROTO-VERSION-INCOMPATIBLE";
pub const NPS_PROTO_PREAMBLE_INVALID: &str = "NPS-PROTO-PREAMBLE-INVALID";

// ── Extra status codes referenced by NWP error table ─────────────────────────
/// NWP reputation throttle — closely related to NPS-LIMIT-RATE.
pub const NPS_CLIENT_RATE_LIMITED: &str = "NPS-CLIENT-RATE-LIMITED";
/// NWP CGN budget overrun — related to NPS-LIMIT-BUDGET.
pub const NPS_CLIENT_REQUEST_TOO_LARGE: &str = "NPS-CLIENT-REQUEST-TOO-LARGE";
/// NWP subscribe limit.
pub const NPS_LIMIT_EXCEEDED: &str = "NPS-LIMIT-EXCEEDED";

// ── HTTP mapping ──────────────────────────────────────────────────────────────

/// Map an NPS status code to the primary HTTP status code.
///
/// Returns `None` for codes that have no meaningful HTTP analogue or are
/// intentionally not emitted over the wire (e.g. `NPS-PROTO-PREAMBLE-INVALID`).
pub fn to_http_status(code: &str) -> Option<u16> {
    match code {
        NPS_OK => Some(200),
        NPS_OK_ACCEPTED => Some(202),
        NPS_OK_NO_CONTENT => Some(204),

        NPS_CLIENT_BAD_FRAME => Some(400),
        NPS_CLIENT_BAD_PARAM => Some(400),
        NPS_CLIENT_NOT_FOUND => Some(404),
        NPS_CLIENT_CONFLICT => Some(409),
        NPS_CLIENT_GONE => Some(410),
        NPS_CLIENT_UNPROCESSABLE => Some(422),
        NPS_CLIENT_RATE_LIMITED => Some(429),
        NPS_CLIENT_REQUEST_TOO_LARGE => Some(413),

        NPS_AUTH_UNAUTHENTICATED => Some(401),
        NPS_AUTH_FORBIDDEN => Some(403),

        NPS_LIMIT_RATE => Some(429),
        NPS_LIMIT_BUDGET => Some(429),
        NPS_LIMIT_PAYLOAD => Some(413),
        NPS_LIMIT_RESOURCE => Some(429),
        NPS_LIMIT_EXCEEDED => Some(429),

        NPS_SERVER_INTERNAL => Some(500),
        NPS_SERVER_UNSUPPORTED => Some(501),
        NPS_SERVER_UNAVAILABLE => Some(503),
        NPS_SERVER_TIMEOUT => Some(504),
        NPS_SERVER_ENCODING_UNSUPPORTED => Some(415),
        NPS_DOWNSTREAM_UNAVAILABLE => Some(502),

        NPS_STREAM_SEQ_GAP => Some(422),
        NPS_STREAM_NOT_FOUND => Some(404),
        NPS_STREAM_LIMIT => Some(429),

        NPS_PROTO_VERSION_INCOMPATIBLE => Some(426),
        // NPS_PROTO_PREAMBLE_INVALID is intentionally not emitted as an ErrorFrame;
        // returning 400 for SDK-internal telemetry classification only.
        NPS_PROTO_PREAMBLE_INVALID => Some(400),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_codes_map_to_2xx() {
        assert_eq!(to_http_status(NPS_OK), Some(200));
        assert_eq!(to_http_status(NPS_OK_ACCEPTED), Some(202));
        assert_eq!(to_http_status(NPS_OK_NO_CONTENT), Some(204));
    }

    #[test]
    fn client_errors_map_to_4xx() {
        assert_eq!(to_http_status(NPS_CLIENT_BAD_FRAME), Some(400));
        assert_eq!(to_http_status(NPS_CLIENT_NOT_FOUND), Some(404));
        assert_eq!(to_http_status(NPS_CLIENT_CONFLICT), Some(409));
        assert_eq!(to_http_status(NPS_CLIENT_UNPROCESSABLE), Some(422));
    }

    #[test]
    fn auth_codes() {
        assert_eq!(to_http_status(NPS_AUTH_UNAUTHENTICATED), Some(401));
        assert_eq!(to_http_status(NPS_AUTH_FORBIDDEN), Some(403));
    }

    #[test]
    fn server_errors_map_to_5xx() {
        assert_eq!(to_http_status(NPS_SERVER_INTERNAL), Some(500));
        assert_eq!(to_http_status(NPS_SERVER_UNSUPPORTED), Some(501));
        assert_eq!(to_http_status(NPS_SERVER_UNAVAILABLE), Some(503));
        assert_eq!(to_http_status(NPS_SERVER_TIMEOUT), Some(504));
    }

    #[test]
    fn limit_codes() {
        assert_eq!(to_http_status(NPS_LIMIT_RATE), Some(429));
        assert_eq!(to_http_status(NPS_LIMIT_BUDGET), Some(429));
        assert_eq!(to_http_status(NPS_LIMIT_PAYLOAD), Some(413));
        assert_eq!(to_http_status(NPS_LIMIT_RESOURCE), Some(429));
    }

    #[test]
    fn stream_codes() {
        assert_eq!(to_http_status(NPS_STREAM_SEQ_GAP), Some(422));
        assert_eq!(to_http_status(NPS_STREAM_NOT_FOUND), Some(404));
        assert_eq!(to_http_status(NPS_STREAM_LIMIT), Some(429));
    }

    #[test]
    fn proto_codes() {
        assert_eq!(to_http_status(NPS_PROTO_VERSION_INCOMPATIBLE), Some(426));
        assert_eq!(to_http_status(NPS_PROTO_PREAMBLE_INVALID), Some(400));
    }

    #[test]
    fn downstream_unavailable() {
        assert_eq!(to_http_status(NPS_DOWNSTREAM_UNAVAILABLE), Some(502));
    }

    #[test]
    fn unknown_code_returns_none() {
        assert_eq!(to_http_status("NPS-BOGUS-CODE"), None);
    }

    #[test]
    fn all_26_core_codes_have_http_mapping() {
        let core_codes = [
            NPS_OK,
            NPS_OK_ACCEPTED,
            NPS_OK_NO_CONTENT,
            NPS_CLIENT_BAD_FRAME,
            NPS_CLIENT_BAD_PARAM,
            NPS_CLIENT_NOT_FOUND,
            NPS_CLIENT_CONFLICT,
            NPS_CLIENT_GONE,
            NPS_CLIENT_UNPROCESSABLE,
            NPS_AUTH_UNAUTHENTICATED,
            NPS_AUTH_FORBIDDEN,
            NPS_LIMIT_RATE,
            NPS_LIMIT_BUDGET,
            NPS_LIMIT_PAYLOAD,
            NPS_LIMIT_RESOURCE,
            NPS_SERVER_INTERNAL,
            NPS_SERVER_UNSUPPORTED,
            NPS_SERVER_UNAVAILABLE,
            NPS_SERVER_TIMEOUT,
            NPS_SERVER_ENCODING_UNSUPPORTED,
            NPS_DOWNSTREAM_UNAVAILABLE,
            NPS_STREAM_SEQ_GAP,
            NPS_STREAM_NOT_FOUND,
            NPS_STREAM_LIMIT,
            NPS_PROTO_VERSION_INCOMPATIBLE,
            NPS_PROTO_PREAMBLE_INVALID,
        ];
        for code in &core_codes {
            assert!(
                to_http_status(code).is_some(),
                "Missing HTTP mapping for {code}"
            );
        }
    }
}
