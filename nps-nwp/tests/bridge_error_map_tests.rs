// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP §16.3 error mapping — ports `tests/NPS.Tests/Nwp/BridgeErrorMapTests.cs`.

use nps_nwp::bridge_inbound::error_map::*;

// ── NPS status → JSON-RPC ────────────────────────────────────────────────────

#[test]
fn to_json_rpc_matches_the_normative_table() {
    assert_eq!(to_json_rpc("NPS-CLIENT-BAD-FRAME", false), -32600);
    assert_eq!(to_json_rpc("NPS-CLIENT-BAD-PARAM", false), -32602);
    assert_eq!(to_json_rpc("NPS-CLIENT-UNPROCESSABLE", false), -32602);
    assert_eq!(to_json_rpc("NPS-CLIENT-GONE", false), -32602);
    assert_eq!(to_json_rpc("NPS-CLIENT-CONFLICT", false), -32004);
    assert_eq!(to_json_rpc("NPS-AUTH-UNAUTHENTICATED", false), -32001);
    assert_eq!(to_json_rpc("NPS-AUTH-FORBIDDEN", false), -32003);
    assert_eq!(to_json_rpc("NPS-LIMIT-RATE", false), -32005);
    assert_eq!(to_json_rpc("NPS-LIMIT-BUDGET", false), -32005);
    assert_eq!(to_json_rpc("NPS-LIMIT-PAYLOAD", false), -32005);
    assert_eq!(to_json_rpc("NPS-SERVER-UNSUPPORTED", false), -32601);
    assert_eq!(to_json_rpc("NPS-SERVER-INTERNAL", false), -32603);
    assert_eq!(to_json_rpc("NPS-SERVER-UNAVAILABLE", false), -32603);
    assert_eq!(to_json_rpc("NPS-SERVER-TIMEOUT", false), -32603);
    assert_eq!(to_json_rpc("NPS-DOWNSTREAM-UNAVAILABLE", false), -32603);
}

#[test]
fn not_found_is_the_only_param_sensitive_row() {
    // Unknown tool in tools/call ⇒ -32601; unknown URI in resources/read ⇒ -32602.
    assert_eq!(to_json_rpc("NPS-CLIENT-NOT-FOUND", false), -32601);
    assert_eq!(to_json_rpc("NPS-CLIENT-NOT-FOUND", true), -32602);
    // Every other row is insensitive to the flag.
    for s in [
        "NPS-CLIENT-BAD-FRAME",
        "NPS-CLIENT-CONFLICT",
        "NPS-AUTH-FORBIDDEN",
        "NPS-SERVER-UNSUPPORTED",
        "NPS-SERVER-INTERNAL",
    ] {
        assert_eq!(to_json_rpc(s, false), to_json_rpc(s, true), "{s}");
    }
}

#[test]
fn auth_classes_are_not_collapsed() {
    assert_ne!(
        to_json_rpc("NPS-AUTH-UNAUTHENTICATED", false),
        to_json_rpc("NPS-AUTH-FORBIDDEN", false)
    );
}

#[test]
fn unknown_status_falls_back_to_internal_error() {
    assert_eq!(to_json_rpc("NPS-SOMETHING-NEW", false), -32603);
}

#[test]
fn the_retired_code_is_never_produced() {
    // -32002 is reserved and MUST NOT be emitted.
    for s in [
        "NPS-CLIENT-BAD-FRAME",
        "NPS-CLIENT-BAD-PARAM",
        "NPS-CLIENT-NOT-FOUND",
        "NPS-CLIENT-GONE",
        "NPS-CLIENT-CONFLICT",
        "NPS-AUTH-UNAUTHENTICATED",
        "NPS-AUTH-FORBIDDEN",
        "NPS-LIMIT-RATE",
        "NPS-SERVER-UNSUPPORTED",
        "NPS-SERVER-INTERNAL",
        "NPS-WHATEVER",
    ] {
        for rr in [false, true] {
            assert_ne!(to_json_rpc(s, rr), JSONRPC_RESERVED_NEVER_EMIT, "{s}");
        }
    }
}

// ── NPS status → gRPC ────────────────────────────────────────────────────────

#[test]
fn to_grpc_status_matches_the_normative_table() {
    use GrpcStatusCode::*;
    assert_eq!(to_grpc_status("NPS-CLIENT-BAD-FRAME"), InvalidArgument);
    assert_eq!(to_grpc_status("NPS-CLIENT-BAD-PARAM"), InvalidArgument);
    assert_eq!(to_grpc_status("NPS-CLIENT-UNPROCESSABLE"), InvalidArgument);
    assert_eq!(to_grpc_status("NPS-CLIENT-NOT-FOUND"), NotFound);
    assert_eq!(to_grpc_status("NPS-CLIENT-GONE"), NotFound);
    assert_eq!(to_grpc_status("NPS-CLIENT-CONFLICT"), Aborted);
    assert_eq!(to_grpc_status("NPS-AUTH-UNAUTHENTICATED"), Unauthenticated);
    assert_eq!(to_grpc_status("NPS-AUTH-FORBIDDEN"), PermissionDenied);
    assert_eq!(to_grpc_status("NPS-LIMIT-RATE"), ResourceExhausted);
    assert_eq!(to_grpc_status("NPS-SERVER-UNSUPPORTED"), Unimplemented);
    assert_eq!(to_grpc_status("NPS-SERVER-INTERNAL"), Internal);
    assert_eq!(to_grpc_status("NPS-SERVER-UNAVAILABLE"), Unavailable);
    assert_eq!(to_grpc_status("NPS-DOWNSTREAM-UNAVAILABLE"), Unavailable);
    assert_eq!(to_grpc_status("NPS-SERVER-TIMEOUT"), DeadlineExceeded);
    assert_eq!(to_grpc_status("NPS-BOGUS"), Internal);
}

#[test]
fn grpc_does_not_collapse_401_403_or_every_5xx() {
    // The old ingress collapsed 401 and 403 both onto PERMISSION_DENIED …
    assert_ne!(
        to_grpc_status("NPS-AUTH-UNAUTHENTICATED"),
        to_grpc_status("NPS-AUTH-FORBIDDEN")
    );
    // … and every 5xx onto UNAVAILABLE. §16.3 forbids both.
    assert_ne!(
        to_grpc_status("NPS-SERVER-INTERNAL"),
        to_grpc_status("NPS-SERVER-UNAVAILABLE")
    );
    assert_ne!(
        to_grpc_status("NPS-SERVER-TIMEOUT"),
        to_grpc_status("NPS-SERVER-UNAVAILABLE")
    );
}

// ── the protocol-error / isError split ───────────────────────────────────────

#[test]
fn must_be_protocol_error_covers_exactly_the_infrastructure_classes() {
    for s in [
        "NPS-AUTH-UNAUTHENTICATED",
        "NPS-AUTH-FORBIDDEN",
        "NPS-LIMIT-RATE",
        "NPS-LIMIT-BUDGET",
        "NPS-LIMIT-PAYLOAD",
        "NPS-SERVER-UNSUPPORTED",
        "NPS-SERVER-INTERNAL",
        "NPS-SERVER-UNAVAILABLE",
        "NPS-SERVER-TIMEOUT",
        "NPS-DOWNSTREAM-UNAVAILABLE",
    ] {
        assert!(must_be_protocol_error(s), "{s} must be a protocol error");
    }
    // The tool-domain classes stay isError:true content.
    for s in [
        "NPS-CLIENT-BAD-FRAME",
        "NPS-CLIENT-BAD-PARAM",
        "NPS-CLIENT-NOT-FOUND",
        "NPS-CLIENT-GONE",
        "NPS-CLIENT-CONFLICT",
        "NPS-CLIENT-UNPROCESSABLE",
        "NPS-OK",
    ] {
        assert!(!must_be_protocol_error(s), "{s} must NOT be a protocol error");
    }
}

// ── reverse direction ────────────────────────────────────────────────────────

#[test]
fn from_http_status_matches_the_normative_table() {
    assert_eq!(from_http_status(400), "NPS-CLIENT-BAD-PARAM");
    assert_eq!(from_http_status(401), "NPS-AUTH-UNAUTHENTICATED");
    assert_eq!(from_http_status(403), "NPS-AUTH-FORBIDDEN");
    assert_eq!(from_http_status(404), "NPS-CLIENT-NOT-FOUND");
    assert_eq!(from_http_status(408), "NPS-SERVER-TIMEOUT");
    assert_eq!(from_http_status(409), "NPS-CLIENT-CONFLICT");
    assert_eq!(from_http_status(410), "NPS-CLIENT-GONE");
    assert_eq!(from_http_status(413), "NPS-LIMIT-PAYLOAD");
    assert_eq!(from_http_status(415), "NPS-SERVER-ENCODING-UNSUPPORTED");
    assert_eq!(from_http_status(422), "NPS-CLIENT-UNPROCESSABLE");
    assert_eq!(from_http_status(429), "NPS-LIMIT-RATE");
    assert_eq!(from_http_status(501), "NPS-SERVER-UNSUPPORTED");
    assert_eq!(from_http_status(502), "NPS-DOWNSTREAM-UNAVAILABLE");
    assert_eq!(from_http_status(504), "NPS-DOWNSTREAM-UNAVAILABLE");
    assert_eq!(from_http_status(503), "NPS-SERVER-UNAVAILABLE");
    assert_eq!(from_http_status(500), "NPS-SERVER-INTERNAL");
    assert_eq!(from_http_status(418), "NPS-CLIENT-BAD-PARAM");
    assert_eq!(from_http_status(200), "NPS-OK");
}

#[test]
fn from_http_status_never_blanket_internals_a_client_error() {
    for s in [400u16, 401, 403, 404, 409, 410, 413, 422, 429] {
        assert!(
            !from_http_status(s).starts_with("NPS-SERVER"),
            "{s} must not degrade to a server class"
        );
    }
}

#[test]
fn from_json_rpc_matches_the_normative_table() {
    assert_eq!(from_json_rpc(-32700), "NPS-CLIENT-BAD-FRAME");
    assert_eq!(from_json_rpc(-32600), "NPS-CLIENT-BAD-FRAME");
    assert_eq!(from_json_rpc(-32601), "NPS-CLIENT-NOT-FOUND");
    assert_eq!(from_json_rpc(-32602), "NPS-CLIENT-BAD-PARAM");
    assert_eq!(from_json_rpc(-32603), "NPS-SERVER-INTERNAL");
    assert_eq!(from_json_rpc(-32001), "NPS-AUTH-UNAUTHENTICATED");
    assert_eq!(from_json_rpc(-32003), "NPS-AUTH-FORBIDDEN");
    assert_eq!(from_json_rpc(-32004), "NPS-CLIENT-CONFLICT");
    assert_eq!(from_json_rpc(-32005), "NPS-LIMIT-RATE");
    assert_eq!(from_json_rpc(-32000), "NPS-DOWNSTREAM-UNAVAILABLE");
    assert_eq!(from_json_rpc(-1), "NPS-SERVER-INTERNAL");
}

#[test]
fn from_grpc_status_matches_the_normative_table() {
    use GrpcStatusCode::*;
    assert_eq!(from_grpc_status(Ok), "NPS-OK");
    assert_eq!(from_grpc_status(InvalidArgument), "NPS-CLIENT-BAD-PARAM");
    assert_eq!(
        from_grpc_status(FailedPrecondition),
        "NPS-CLIENT-UNPROCESSABLE"
    );
    assert_eq!(from_grpc_status(NotFound), "NPS-CLIENT-NOT-FOUND");
    assert_eq!(from_grpc_status(AlreadyExists), "NPS-CLIENT-CONFLICT");
    assert_eq!(from_grpc_status(Aborted), "NPS-CLIENT-CONFLICT");
    assert_eq!(from_grpc_status(Unauthenticated), "NPS-AUTH-UNAUTHENTICATED");
    assert_eq!(from_grpc_status(PermissionDenied), "NPS-AUTH-FORBIDDEN");
    assert_eq!(from_grpc_status(ResourceExhausted), "NPS-LIMIT-RATE");
    assert_eq!(from_grpc_status(Unimplemented), "NPS-SERVER-UNSUPPORTED");
    assert_eq!(from_grpc_status(Unavailable), "NPS-SERVER-UNAVAILABLE");
    assert_eq!(from_grpc_status(DeadlineExceeded), "NPS-SERVER-TIMEOUT");
    assert_eq!(from_grpc_status(Internal), "NPS-SERVER-INTERNAL");
    assert_eq!(from_grpc_status(Unknown), "NPS-SERVER-INTERNAL");
    assert_eq!(from_grpc_status(DataLoss), "NPS-SERVER-INTERNAL");
}

#[test]
fn json_rpc_round_trip_is_stable_for_the_distinct_classes() {
    for s in [
        "NPS-CLIENT-BAD-FRAME",
        "NPS-CLIENT-BAD-PARAM",
        "NPS-CLIENT-CONFLICT",
        "NPS-AUTH-UNAUTHENTICATED",
        "NPS-AUTH-FORBIDDEN",
        "NPS-SERVER-INTERNAL",
    ] {
        assert_eq!(from_json_rpc(to_json_rpc(s, false)), s, "{s}");
    }
}
