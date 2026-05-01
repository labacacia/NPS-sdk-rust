// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP error code wire constants — mirror of `spec/error-codes.md` NWP section.

// ── Auth ─────────────────────────────────────────────────────────────────────
pub const AUTH_NID_SCOPE_VIOLATION:    &str = "NWP-AUTH-NID-SCOPE-VIOLATION";
pub const AUTH_NID_EXPIRED:            &str = "NWP-AUTH-NID-EXPIRED";
pub const AUTH_NID_REVOKED:            &str = "NWP-AUTH-NID-REVOKED";
pub const AUTH_NID_UNTRUSTED_ISSUER:   &str = "NWP-AUTH-NID-UNTRUSTED-ISSUER";
pub const AUTH_NID_CAPABILITY_MISSING: &str = "NWP-AUTH-NID-CAPABILITY-MISSING";
pub const AUTH_ASSURANCE_TOO_LOW:      &str = "NWP-AUTH-ASSURANCE-TOO-LOW";
pub const AUTH_REPUTATION_BLOCKED:     &str = "NWP-AUTH-REPUTATION-BLOCKED";

// ── Query ─────────────────────────────────────────────────────────────────────
pub const QUERY_FILTER_INVALID:        &str = "NWP-QUERY-FILTER-INVALID";
pub const QUERY_FIELD_UNKNOWN:         &str = "NWP-QUERY-FIELD-UNKNOWN";
pub const QUERY_CURSOR_INVALID:        &str = "NWP-QUERY-CURSOR-INVALID";
pub const QUERY_REGEX_UNSAFE:          &str = "NWP-QUERY-REGEX-UNSAFE";
pub const QUERY_VECTOR_UNSUPPORTED:    &str = "NWP-QUERY-VECTOR-UNSUPPORTED";
pub const QUERY_AGGREGATE_UNSUPPORTED: &str = "NWP-QUERY-AGGREGATE-UNSUPPORTED";
pub const QUERY_AGGREGATE_INVALID:     &str = "NWP-QUERY-AGGREGATE-INVALID";
pub const QUERY_STREAM_UNSUPPORTED:    &str = "NWP-QUERY-STREAM-UNSUPPORTED";

// ── Action ────────────────────────────────────────────────────────────────────
pub const ACTION_NOT_FOUND:            &str = "NWP-ACTION-NOT-FOUND";
pub const ACTION_PARAMS_INVALID:       &str = "NWP-ACTION-PARAMS-INVALID";
pub const ACTION_IDEMPOTENCY_CONFLICT: &str = "NWP-ACTION-IDEMPOTENCY-CONFLICT";

// ── Task ──────────────────────────────────────────────────────────────────────
pub const TASK_NOT_FOUND:         &str = "NWP-TASK-NOT-FOUND";
pub const TASK_ALREADY_CANCELLED: &str = "NWP-TASK-ALREADY-CANCELLED";
pub const TASK_ALREADY_COMPLETED: &str = "NWP-TASK-ALREADY-COMPLETED";
pub const TASK_ALREADY_FAILED:    &str = "NWP-TASK-ALREADY-FAILED";

// ── Subscribe ─────────────────────────────────────────────────────────────────
pub const SUBSCRIBE_STREAM_NOT_FOUND:   &str = "NWP-SUBSCRIBE-STREAM-NOT-FOUND";
pub const SUBSCRIBE_LIMIT_EXCEEDED:     &str = "NWP-SUBSCRIBE-LIMIT-EXCEEDED";
pub const SUBSCRIBE_FILTER_UNSUPPORTED: &str = "NWP-SUBSCRIBE-FILTER-UNSUPPORTED";
pub const SUBSCRIBE_INTERRUPTED:        &str = "NWP-SUBSCRIBE-INTERRUPTED";
pub const SUBSCRIBE_SEQ_TOO_OLD:        &str = "NWP-SUBSCRIBE-SEQ-TOO-OLD";

// ── Infrastructure ────────────────────────────────────────────────────────────
pub const BUDGET_EXCEEDED:     &str = "NWP-BUDGET-EXCEEDED";
pub const DEPTH_EXCEEDED:      &str = "NWP-DEPTH-EXCEEDED";
pub const GRAPH_CYCLE:         &str = "NWP-GRAPH-CYCLE";
pub const NODE_UNAVAILABLE:    &str = "NWP-NODE-UNAVAILABLE";
pub const RATE_LIMIT_EXCEEDED: &str = "NWP-RATE-LIMIT-EXCEEDED";

// ── Manifest ──────────────────────────────────────────────────────────────────
pub const MANIFEST_VERSION_UNSUPPORTED: &str = "NWP-MANIFEST-VERSION-UNSUPPORTED";
pub const MANIFEST_NODE_TYPE_REMOVED:   &str = "NWP-MANIFEST-NODE-TYPE-REMOVED";
pub const MANIFEST_NODE_TYPE_UNKNOWN:   &str = "NWP-MANIFEST-NODE-TYPE-UNKNOWN";

// ── Topology (alpha.4+) ───────────────────────────────────────────────────────
pub const TOPOLOGY_UNAUTHORIZED:       &str = "NWP-TOPOLOGY-UNAUTHORIZED";
pub const TOPOLOGY_UNSUPPORTED_SCOPE:  &str = "NWP-TOPOLOGY-UNSUPPORTED-SCOPE";
pub const TOPOLOGY_DEPTH_UNSUPPORTED:  &str = "NWP-TOPOLOGY-DEPTH-UNSUPPORTED";
pub const TOPOLOGY_FILTER_UNSUPPORTED: &str = "NWP-TOPOLOGY-FILTER-UNSUPPORTED";

// ── Reserved type (alpha.5+) ─────────────────────────────────────────────────
pub const RESERVED_TYPE_UNSUPPORTED: &str = "NWP-RESERVED-TYPE-UNSUPPORTED";
