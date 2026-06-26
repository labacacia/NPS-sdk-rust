// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP error code wire constants — mirror of `spec/error-codes.md` NWP section.

// ── Auth / NID ────────────────────────────────────────────────────────────────
pub const AUTH_NID_SCOPE_VIOLATION: &str = "NWP-AUTH-NID-SCOPE-VIOLATION";
pub const AUTH_NID_EXPIRED: &str = "NWP-AUTH-NID-EXPIRED";
pub const AUTH_NID_REVOKED: &str = "NWP-AUTH-NID-REVOKED";
pub const AUTH_NID_UNTRUSTED_ISSUER: &str = "NWP-AUTH-NID-UNTRUSTED-ISSUER";
pub const AUTH_NID_CAPABILITY_MISSING: &str = "NWP-AUTH-NID-CAPABILITY-MISSING";
pub const AUTH_ASSURANCE_TOO_LOW: &str = "NWP-AUTH-ASSURANCE-TOO-LOW";
/// Deprecated — alias for NWP-REPUTATION-REJECTED / NWP-REPUTATION-BANNED.
pub const AUTH_REPUTATION_BLOCKED: &str = "NWP-AUTH-REPUTATION-BLOCKED";

// ── Reputation ────────────────────────────────────────────────────────────────
pub const REPUTATION_THROTTLED: &str = "NWP-REPUTATION-THROTTLED";
pub const REPUTATION_REJECTED: &str = "NWP-REPUTATION-REJECTED";
pub const REPUTATION_BANNED: &str = "NWP-REPUTATION-BANNED";

// ── Query ─────────────────────────────────────────────────────────────────────
pub const QUERY_FILTER_INVALID: &str = "NWP-QUERY-FILTER-INVALID";
pub const QUERY_FIELD_UNKNOWN: &str = "NWP-QUERY-FIELD-UNKNOWN";
pub const QUERY_CURSOR_INVALID: &str = "NWP-QUERY-CURSOR-INVALID";
pub const QUERY_REGEX_UNSAFE: &str = "NWP-QUERY-REGEX-UNSAFE";
pub const QUERY_VECTOR_UNSUPPORTED: &str = "NWP-QUERY-VECTOR-UNSUPPORTED";
pub const QUERY_AGGREGATE_UNSUPPORTED: &str = "NWP-QUERY-AGGREGATE-UNSUPPORTED";
pub const QUERY_AGGREGATE_INVALID: &str = "NWP-QUERY-AGGREGATE-INVALID";
pub const QUERY_STREAM_UNSUPPORTED: &str = "NWP-QUERY-STREAM-UNSUPPORTED";

// ── Action ────────────────────────────────────────────────────────────────────
pub const ACTION_NOT_FOUND: &str = "NWP-ACTION-NOT-FOUND";
pub const ACTION_PARAMS_INVALID: &str = "NWP-ACTION-PARAMS-INVALID";
pub const ACTION_IDEMPOTENCY_CONFLICT: &str = "NWP-ACTION-IDEMPOTENCY-CONFLICT";

// ── Task ──────────────────────────────────────────────────────────────────────
pub const TASK_NOT_FOUND: &str = "NWP-TASK-NOT-FOUND";
pub const TASK_ALREADY_CANCELLED: &str = "NWP-TASK-ALREADY-CANCELLED";
pub const TASK_ALREADY_COMPLETED: &str = "NWP-TASK-ALREADY-COMPLETED";
pub const TASK_ALREADY_FAILED: &str = "NWP-TASK-ALREADY-FAILED";

// ── Subscribe ─────────────────────────────────────────────────────────────────
pub const SUBSCRIBE_STREAM_NOT_FOUND: &str = "NWP-SUBSCRIBE-STREAM-NOT-FOUND";
pub const SUBSCRIBE_LIMIT_EXCEEDED: &str = "NWP-SUBSCRIBE-LIMIT-EXCEEDED";
pub const SUBSCRIBE_FILTER_UNSUPPORTED: &str = "NWP-SUBSCRIBE-FILTER-UNSUPPORTED";
pub const SUBSCRIBE_INTERRUPTED: &str = "NWP-SUBSCRIBE-INTERRUPTED";
pub const SUBSCRIBE_SEQ_TOO_OLD: &str = "NWP-SUBSCRIBE-SEQ-TOO-OLD";

// ── Budget / depth ────────────────────────────────────────────────────────────
pub const BUDGET_EXCEEDED: &str = "NWP-BUDGET-EXCEEDED";
pub const CGN_LIMIT_EXCEEDED: &str = "NWP-CGN-LIMIT-EXCEEDED";
pub const DEPTH_EXCEEDED: &str = "NWP-DEPTH-EXCEEDED";
pub const GRAPH_CYCLE: &str = "NWP-GRAPH-CYCLE";

// ── Node availability ─────────────────────────────────────────────────────────
pub const NODE_UNAVAILABLE: &str = "NWP-NODE-UNAVAILABLE";

// ── Manifest ──────────────────────────────────────────────────────────────────
pub const MANIFEST_VERSION_UNSUPPORTED: &str = "NWP-MANIFEST-VERSION-UNSUPPORTED";
pub const MANIFEST_NODE_TYPE_REMOVED: &str = "NWP-MANIFEST-NODE-TYPE-REMOVED";
pub const MANIFEST_NODE_TYPE_UNKNOWN: &str = "NWP-MANIFEST-NODE-TYPE-UNKNOWN";

// ── Rate / reserved ───────────────────────────────────────────────────────────
pub const RATE_LIMIT_EXCEEDED: &str = "NWP-RATE-LIMIT-EXCEEDED";
pub const RESERVED_TYPE_UNSUPPORTED: &str = "NWP-RESERVED-TYPE-UNSUPPORTED";

// ── Topology (NPS-CR-0002) ────────────────────────────────────────────────────
pub const TOPOLOGY_UNAUTHORIZED: &str = "NWP-TOPOLOGY-UNAUTHORIZED";
pub const TOPOLOGY_UNSUPPORTED_SCOPE: &str = "NWP-TOPOLOGY-UNSUPPORTED-SCOPE";
pub const TOPOLOGY_DEPTH_UNSUPPORTED: &str = "NWP-TOPOLOGY-DEPTH-UNSUPPORTED";
pub const TOPOLOGY_FILTER_UNSUPPORTED: &str = "NWP-TOPOLOGY-FILTER-UNSUPPORTED";

// ── Mapping to NPS status ──────────────────────────────────────────────────────

/// Map a NWP error code to the corresponding NPS status code.
pub fn to_nps_status(code: &str) -> &'static str {
    match code {
        AUTH_NID_SCOPE_VIOLATION => "NPS-AUTH-FORBIDDEN",
        AUTH_NID_EXPIRED => "NPS-AUTH-UNAUTHENTICATED",
        AUTH_NID_REVOKED => "NPS-AUTH-UNAUTHENTICATED",
        AUTH_NID_UNTRUSTED_ISSUER => "NPS-AUTH-UNAUTHENTICATED",
        AUTH_NID_CAPABILITY_MISSING => "NPS-AUTH-FORBIDDEN",
        AUTH_ASSURANCE_TOO_LOW => "NPS-AUTH-FORBIDDEN",
        AUTH_REPUTATION_BLOCKED => "NPS-AUTH-FORBIDDEN",

        REPUTATION_THROTTLED => "NPS-CLIENT-RATE-LIMITED",
        REPUTATION_REJECTED => "NPS-AUTH-FORBIDDEN",
        REPUTATION_BANNED => "NPS-AUTH-FORBIDDEN",

        QUERY_FILTER_INVALID => "NPS-CLIENT-BAD-PARAM",
        QUERY_FIELD_UNKNOWN => "NPS-CLIENT-BAD-PARAM",
        QUERY_CURSOR_INVALID => "NPS-CLIENT-BAD-PARAM",
        QUERY_REGEX_UNSAFE => "NPS-CLIENT-BAD-PARAM",
        QUERY_VECTOR_UNSUPPORTED => "NPS-SERVER-UNSUPPORTED",
        QUERY_AGGREGATE_UNSUPPORTED => "NPS-SERVER-UNSUPPORTED",
        QUERY_AGGREGATE_INVALID => "NPS-CLIENT-BAD-PARAM",
        QUERY_STREAM_UNSUPPORTED => "NPS-SERVER-UNSUPPORTED",

        ACTION_NOT_FOUND => "NPS-CLIENT-NOT-FOUND",
        ACTION_PARAMS_INVALID => "NPS-CLIENT-UNPROCESSABLE",
        ACTION_IDEMPOTENCY_CONFLICT => "NPS-CLIENT-CONFLICT",

        TASK_NOT_FOUND => "NPS-CLIENT-NOT-FOUND",
        TASK_ALREADY_CANCELLED => "NPS-CLIENT-CONFLICT",
        TASK_ALREADY_COMPLETED => "NPS-CLIENT-CONFLICT",
        TASK_ALREADY_FAILED => "NPS-CLIENT-CONFLICT",

        SUBSCRIBE_STREAM_NOT_FOUND => "NPS-CLIENT-NOT-FOUND",
        SUBSCRIBE_LIMIT_EXCEEDED => "NPS-LIMIT-EXCEEDED",
        SUBSCRIBE_FILTER_UNSUPPORTED => "NPS-SERVER-UNSUPPORTED",
        SUBSCRIBE_INTERRUPTED => "NPS-SERVER-UNAVAILABLE",
        SUBSCRIBE_SEQ_TOO_OLD => "NPS-CLIENT-CONFLICT",

        BUDGET_EXCEEDED => "NPS-LIMIT-BUDGET",
        CGN_LIMIT_EXCEEDED => "NPS-CLIENT-REQUEST-TOO-LARGE",
        DEPTH_EXCEEDED => "NPS-CLIENT-BAD-PARAM",
        GRAPH_CYCLE => "NPS-CLIENT-UNPROCESSABLE",

        NODE_UNAVAILABLE => "NPS-SERVER-UNAVAILABLE",

        MANIFEST_VERSION_UNSUPPORTED => "NPS-CLIENT-BAD-PARAM",
        MANIFEST_NODE_TYPE_REMOVED => "NPS-CLIENT-BAD-FRAME",
        MANIFEST_NODE_TYPE_UNKNOWN => "NPS-CLIENT-BAD-FRAME",

        RATE_LIMIT_EXCEEDED => "NPS-LIMIT-RATE",
        RESERVED_TYPE_UNSUPPORTED => "NPS-SERVER-UNSUPPORTED",

        TOPOLOGY_UNAUTHORIZED => "NPS-AUTH-FORBIDDEN",
        TOPOLOGY_UNSUPPORTED_SCOPE => "NPS-CLIENT-BAD-PARAM",
        TOPOLOGY_DEPTH_UNSUPPORTED => "NPS-CLIENT-BAD-PARAM",
        TOPOLOGY_FILTER_UNSUPPORTED => "NPS-CLIENT-BAD-PARAM",

        _ => "NPS-SERVER-INTERNAL",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_nid_errors() {
        assert_eq!(
            to_nps_status(AUTH_NID_SCOPE_VIOLATION),
            "NPS-AUTH-FORBIDDEN"
        );
        assert_eq!(to_nps_status(AUTH_NID_EXPIRED), "NPS-AUTH-UNAUTHENTICATED");
        assert_eq!(to_nps_status(AUTH_NID_REVOKED), "NPS-AUTH-UNAUTHENTICATED");
        assert_eq!(
            to_nps_status(AUTH_NID_UNTRUSTED_ISSUER),
            "NPS-AUTH-UNAUTHENTICATED"
        );
        assert_eq!(
            to_nps_status(AUTH_NID_CAPABILITY_MISSING),
            "NPS-AUTH-FORBIDDEN"
        );
        assert_eq!(to_nps_status(AUTH_ASSURANCE_TOO_LOW), "NPS-AUTH-FORBIDDEN");
    }

    #[test]
    fn reputation_errors() {
        assert_eq!(
            to_nps_status(REPUTATION_THROTTLED),
            "NPS-CLIENT-RATE-LIMITED"
        );
        assert_eq!(to_nps_status(REPUTATION_REJECTED), "NPS-AUTH-FORBIDDEN");
        assert_eq!(to_nps_status(REPUTATION_BANNED), "NPS-AUTH-FORBIDDEN");
    }

    #[test]
    fn query_errors() {
        assert_eq!(to_nps_status(QUERY_FILTER_INVALID), "NPS-CLIENT-BAD-PARAM");
        assert_eq!(
            to_nps_status(QUERY_VECTOR_UNSUPPORTED),
            "NPS-SERVER-UNSUPPORTED"
        );
        assert_eq!(
            to_nps_status(QUERY_AGGREGATE_UNSUPPORTED),
            "NPS-SERVER-UNSUPPORTED"
        );
        assert_eq!(
            to_nps_status(QUERY_AGGREGATE_INVALID),
            "NPS-CLIENT-BAD-PARAM"
        );
        assert_eq!(
            to_nps_status(QUERY_STREAM_UNSUPPORTED),
            "NPS-SERVER-UNSUPPORTED"
        );
    }

    #[test]
    fn action_and_task_errors() {
        assert_eq!(to_nps_status(ACTION_NOT_FOUND), "NPS-CLIENT-NOT-FOUND");
        assert_eq!(
            to_nps_status(ACTION_PARAMS_INVALID),
            "NPS-CLIENT-UNPROCESSABLE"
        );
        assert_eq!(
            to_nps_status(ACTION_IDEMPOTENCY_CONFLICT),
            "NPS-CLIENT-CONFLICT"
        );
        assert_eq!(to_nps_status(TASK_NOT_FOUND), "NPS-CLIENT-NOT-FOUND");
        assert_eq!(to_nps_status(TASK_ALREADY_CANCELLED), "NPS-CLIENT-CONFLICT");
    }

    #[test]
    fn subscribe_errors() {
        assert_eq!(
            to_nps_status(SUBSCRIBE_STREAM_NOT_FOUND),
            "NPS-CLIENT-NOT-FOUND"
        );
        assert_eq!(
            to_nps_status(SUBSCRIBE_LIMIT_EXCEEDED),
            "NPS-LIMIT-EXCEEDED"
        );
        assert_eq!(
            to_nps_status(SUBSCRIBE_FILTER_UNSUPPORTED),
            "NPS-SERVER-UNSUPPORTED"
        );
        assert_eq!(
            to_nps_status(SUBSCRIBE_INTERRUPTED),
            "NPS-SERVER-UNAVAILABLE"
        );
        assert_eq!(to_nps_status(SUBSCRIBE_SEQ_TOO_OLD), "NPS-CLIENT-CONFLICT");
    }

    #[test]
    fn budget_and_limit_errors() {
        assert_eq!(to_nps_status(BUDGET_EXCEEDED), "NPS-LIMIT-BUDGET");
        assert_eq!(
            to_nps_status(CGN_LIMIT_EXCEEDED),
            "NPS-CLIENT-REQUEST-TOO-LARGE"
        );
        assert_eq!(to_nps_status(DEPTH_EXCEEDED), "NPS-CLIENT-BAD-PARAM");
        assert_eq!(to_nps_status(RATE_LIMIT_EXCEEDED), "NPS-LIMIT-RATE");
    }

    #[test]
    fn manifest_and_topology_errors() {
        assert_eq!(
            to_nps_status(MANIFEST_VERSION_UNSUPPORTED),
            "NPS-CLIENT-BAD-PARAM"
        );
        assert_eq!(
            to_nps_status(MANIFEST_NODE_TYPE_REMOVED),
            "NPS-CLIENT-BAD-FRAME"
        );
        assert_eq!(
            to_nps_status(MANIFEST_NODE_TYPE_UNKNOWN),
            "NPS-CLIENT-BAD-FRAME"
        );
        assert_eq!(to_nps_status(TOPOLOGY_UNAUTHORIZED), "NPS-AUTH-FORBIDDEN");
        assert_eq!(
            to_nps_status(TOPOLOGY_UNSUPPORTED_SCOPE),
            "NPS-CLIENT-BAD-PARAM"
        );
    }

    #[test]
    fn unknown_falls_back_to_internal() {
        assert_eq!(to_nps_status("NWP-BOGUS"), "NPS-SERVER-INTERNAL");
    }

    #[test]
    fn constants_have_correct_prefix() {
        let codes = [
            AUTH_NID_SCOPE_VIOLATION,
            AUTH_NID_EXPIRED,
            AUTH_NID_REVOKED,
            AUTH_NID_UNTRUSTED_ISSUER,
            AUTH_NID_CAPABILITY_MISSING,
            AUTH_ASSURANCE_TOO_LOW,
            AUTH_REPUTATION_BLOCKED,
            REPUTATION_THROTTLED,
            REPUTATION_REJECTED,
            REPUTATION_BANNED,
            QUERY_FILTER_INVALID,
            QUERY_FIELD_UNKNOWN,
            QUERY_CURSOR_INVALID,
            QUERY_REGEX_UNSAFE,
            QUERY_VECTOR_UNSUPPORTED,
            QUERY_AGGREGATE_UNSUPPORTED,
            QUERY_AGGREGATE_INVALID,
            QUERY_STREAM_UNSUPPORTED,
            ACTION_NOT_FOUND,
            ACTION_PARAMS_INVALID,
            ACTION_IDEMPOTENCY_CONFLICT,
            TASK_NOT_FOUND,
            TASK_ALREADY_CANCELLED,
            TASK_ALREADY_COMPLETED,
            TASK_ALREADY_FAILED,
            SUBSCRIBE_STREAM_NOT_FOUND,
            SUBSCRIBE_LIMIT_EXCEEDED,
            SUBSCRIBE_FILTER_UNSUPPORTED,
            SUBSCRIBE_INTERRUPTED,
            SUBSCRIBE_SEQ_TOO_OLD,
            BUDGET_EXCEEDED,
            CGN_LIMIT_EXCEEDED,
            DEPTH_EXCEEDED,
            GRAPH_CYCLE,
            NODE_UNAVAILABLE,
            MANIFEST_VERSION_UNSUPPORTED,
            MANIFEST_NODE_TYPE_REMOVED,
            MANIFEST_NODE_TYPE_UNKNOWN,
            RATE_LIMIT_EXCEEDED,
            RESERVED_TYPE_UNSUPPORTED,
            TOPOLOGY_UNAUTHORIZED,
            TOPOLOGY_UNSUPPORTED_SCOPE,
            TOPOLOGY_DEPTH_UNSUPPORTED,
            TOPOLOGY_FILTER_UNSUPPORTED,
        ];
        for c in &codes {
            assert!(c.starts_with("NWP-"), "Expected NWP- prefix, got: {c}");
        }
    }
}
