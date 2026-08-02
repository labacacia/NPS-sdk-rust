// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP §16.3 error mapping — **one implementation serving both directions and
//! all three protocols**. No inbound or outbound path may hand-roll its own.

// ── JSON-RPC codes ───────────────────────────────────────────────────────────

/// Parse error.
pub const JSONRPC_PARSE_ERROR: i32 = -32700;
/// Invalid Request.
pub const JSONRPC_INVALID_REQUEST: i32 = -32600;
/// Method not found.
pub const JSONRPC_METHOD_NOT_FOUND: i32 = -32601;
/// Invalid params.
pub const JSONRPC_INVALID_PARAMS: i32 = -32602;
/// Internal error.
pub const JSONRPC_INTERNAL_ERROR: i32 = -32603;
/// Upstream error — used by the hosting layer for a dispatch timeout.
pub const JSONRPC_UPSTREAM_ERROR: i32 = -32000;
pub const JSONRPC_UNAUTHENTICATED: i32 = -32001;
pub const JSONRPC_FORBIDDEN: i32 = -32003;
pub const JSONRPC_CONFLICT: i32 = -32004;
pub const JSONRPC_LIMIT: i32 = -32005;

/// `-32002` is **reserved and MUST NOT be emitted** — it was the pre-CR-0010
/// "resource not found" code and is retired.
pub const JSONRPC_RESERVED_NEVER_EMIT: i32 = -32002;

// ── gRPC status codes ────────────────────────────────────────────────────────

/// The canonical gRPC status codes, by numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum GrpcStatusCode {
    Ok = 0,
    InvalidArgument = 3,
    DeadlineExceeded = 4,
    NotFound = 5,
    AlreadyExists = 6,
    PermissionDenied = 7,
    ResourceExhausted = 8,
    FailedPrecondition = 9,
    Aborted = 10,
    Unimplemented = 12,
    Internal = 13,
    Unavailable = 14,
    DataLoss = 15,
    Unauthenticated = 16,
    Unknown = 2,
}

// ── NPS status → foreign protocol ────────────────────────────────────────────

/// NPS status → JSON-RPC code (MCP and A2A).
///
/// `NPS-CLIENT-NOT-FOUND` is the only param-sensitive row: an unknown **tool**
/// in `tools/call` is `-32601`, an unknown **URI** in `resources/read` is
/// `-32602`.
pub fn to_json_rpc(nps_status: &str, resource_read: bool) -> i32 {
    match nps_status {
        "NPS-CLIENT-BAD-FRAME" => JSONRPC_INVALID_REQUEST,
        "NPS-CLIENT-BAD-PARAM" | "NPS-CLIENT-UNPROCESSABLE" => JSONRPC_INVALID_PARAMS,
        "NPS-CLIENT-NOT-FOUND" => {
            if resource_read {
                JSONRPC_INVALID_PARAMS
            } else {
                JSONRPC_METHOD_NOT_FOUND
            }
        }
        "NPS-CLIENT-GONE" => JSONRPC_INVALID_PARAMS,
        "NPS-CLIENT-CONFLICT" => JSONRPC_CONFLICT,
        // MUST be a JSON-RPC error, never a successful result carrying an
        // error payload; and MUST NOT be collapsed onto one another.
        "NPS-AUTH-UNAUTHENTICATED" => JSONRPC_UNAUTHENTICATED,
        "NPS-AUTH-FORBIDDEN" => JSONRPC_FORBIDDEN,
        "NPS-LIMIT-RATE" | "NPS-LIMIT-BUDGET" | "NPS-LIMIT-PAYLOAD" => JSONRPC_LIMIT,
        // Includes NWP-BRIDGE-DIRECTION-UNSUPPORTED.
        "NPS-SERVER-UNSUPPORTED" => JSONRPC_METHOD_NOT_FOUND,
        "NPS-SERVER-INTERNAL"
        | "NPS-SERVER-UNAVAILABLE"
        | "NPS-SERVER-TIMEOUT"
        | "NPS-DOWNSTREAM-UNAVAILABLE" => JSONRPC_INTERNAL_ERROR,
        _ => JSONRPC_INTERNAL_ERROR,
    }
}

/// NPS status → gRPC status code.
pub fn to_grpc_status(nps_status: &str) -> GrpcStatusCode {
    match nps_status {
        "NPS-CLIENT-BAD-FRAME" | "NPS-CLIENT-BAD-PARAM" | "NPS-CLIENT-UNPROCESSABLE" => {
            GrpcStatusCode::InvalidArgument
        }
        "NPS-CLIENT-NOT-FOUND" | "NPS-CLIENT-GONE" => GrpcStatusCode::NotFound,
        "NPS-CLIENT-CONFLICT" => GrpcStatusCode::Aborted,
        "NPS-AUTH-UNAUTHENTICATED" => GrpcStatusCode::Unauthenticated,
        // 401 and 403 are NOT collapsed — the old ingress did, §16.3 forbids it.
        "NPS-AUTH-FORBIDDEN" => GrpcStatusCode::PermissionDenied,
        "NPS-LIMIT-RATE" | "NPS-LIMIT-BUDGET" | "NPS-LIMIT-PAYLOAD" => {
            GrpcStatusCode::ResourceExhausted
        }
        "NPS-SERVER-UNSUPPORTED" => GrpcStatusCode::Unimplemented,
        "NPS-SERVER-INTERNAL" => GrpcStatusCode::Internal,
        // Nor is every 5xx collapsed onto UNAVAILABLE.
        "NPS-SERVER-UNAVAILABLE" | "NPS-DOWNSTREAM-UNAVAILABLE" => GrpcStatusCode::Unavailable,
        "NPS-SERVER-TIMEOUT" => GrpcStatusCode::DeadlineExceeded,
        _ => GrpcStatusCode::Internal,
    }
}

/// Infrastructure-class failures — **the tool did not run**.
///
/// These MUST surface as a protocol error, not as a successful result with
/// `isError: true`: returning a 403 as "a tool that returned unhappy text" lets
/// an MCP client mistake an authorization failure for a domain answer, and A2A
/// peers retry failed tasks. Genuine tool-domain failures (`NPS-CLIENT-*`) stay
/// as `isError: true` content, which is what MCP's flag is for.
pub fn must_be_protocol_error(nps_status: &str) -> bool {
    matches!(
        nps_status,
        "NPS-AUTH-UNAUTHENTICATED"
            | "NPS-AUTH-FORBIDDEN"
            | "NPS-LIMIT-RATE"
            | "NPS-LIMIT-BUDGET"
            | "NPS-LIMIT-PAYLOAD"
            | "NPS-SERVER-UNSUPPORTED"
            | "NPS-SERVER-INTERNAL"
            | "NPS-SERVER-UNAVAILABLE"
            | "NPS-SERVER-TIMEOUT"
            | "NPS-DOWNSTREAM-UNAVAILABLE"
    )
}

// ── Reverse direction: foreign protocol → NPS status ─────────────────────────
//
// The inverse is not injective, so always choose the MOST SPECIFIC status —
// never a blanket `NPS-SERVER-INTERNAL`.

/// HTTP status → NPS status.
pub fn from_http_status(status: u16) -> &'static str {
    match status {
        400 => "NPS-CLIENT-BAD-PARAM",
        401 => "NPS-AUTH-UNAUTHENTICATED",
        403 => "NPS-AUTH-FORBIDDEN",
        404 => "NPS-CLIENT-NOT-FOUND",
        408 => "NPS-SERVER-TIMEOUT",
        409 => "NPS-CLIENT-CONFLICT",
        410 => "NPS-CLIENT-GONE",
        413 => "NPS-LIMIT-PAYLOAD",
        415 => "NPS-SERVER-ENCODING-UNSUPPORTED",
        422 => "NPS-CLIENT-UNPROCESSABLE",
        429 => "NPS-LIMIT-RATE",
        501 => "NPS-SERVER-UNSUPPORTED",
        502 | 504 => "NPS-DOWNSTREAM-UNAVAILABLE",
        503 => "NPS-SERVER-UNAVAILABLE",
        s if s >= 500 => "NPS-SERVER-INTERNAL",
        s if s >= 400 => "NPS-CLIENT-BAD-PARAM",
        _ => "NPS-OK",
    }
}

/// JSON-RPC code → NPS status.
pub fn from_json_rpc(code: i32) -> &'static str {
    match code {
        JSONRPC_PARSE_ERROR | JSONRPC_INVALID_REQUEST => "NPS-CLIENT-BAD-FRAME",
        JSONRPC_METHOD_NOT_FOUND => "NPS-CLIENT-NOT-FOUND",
        JSONRPC_INVALID_PARAMS => "NPS-CLIENT-BAD-PARAM",
        JSONRPC_INTERNAL_ERROR => "NPS-SERVER-INTERNAL",
        JSONRPC_UNAUTHENTICATED => "NPS-AUTH-UNAUTHENTICATED",
        JSONRPC_FORBIDDEN => "NPS-AUTH-FORBIDDEN",
        JSONRPC_CONFLICT => "NPS-CLIENT-CONFLICT",
        JSONRPC_LIMIT => "NPS-LIMIT-RATE",
        JSONRPC_UPSTREAM_ERROR => "NPS-DOWNSTREAM-UNAVAILABLE",
        _ => "NPS-SERVER-INTERNAL",
    }
}

/// gRPC status → NPS status.
pub fn from_grpc_status(code: GrpcStatusCode) -> &'static str {
    match code {
        GrpcStatusCode::Ok => "NPS-OK",
        GrpcStatusCode::InvalidArgument => "NPS-CLIENT-BAD-PARAM",
        GrpcStatusCode::FailedPrecondition => "NPS-CLIENT-UNPROCESSABLE",
        GrpcStatusCode::NotFound => "NPS-CLIENT-NOT-FOUND",
        GrpcStatusCode::AlreadyExists | GrpcStatusCode::Aborted => "NPS-CLIENT-CONFLICT",
        GrpcStatusCode::Unauthenticated => "NPS-AUTH-UNAUTHENTICATED",
        GrpcStatusCode::PermissionDenied => "NPS-AUTH-FORBIDDEN",
        GrpcStatusCode::ResourceExhausted => "NPS-LIMIT-RATE",
        GrpcStatusCode::Unimplemented => "NPS-SERVER-UNSUPPORTED",
        GrpcStatusCode::Unavailable => "NPS-SERVER-UNAVAILABLE",
        GrpcStatusCode::DeadlineExceeded => "NPS-SERVER-TIMEOUT",
        GrpcStatusCode::Internal | GrpcStatusCode::Unknown | GrpcStatusCode::DataLoss => {
            "NPS-SERVER-INTERNAL"
        }
    }
}
