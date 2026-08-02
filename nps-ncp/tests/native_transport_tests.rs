// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the NCP native-mode TCP transport.
//!
//! These drive the REAL [`NcpServer`] with the REAL [`NcpNativeClient`] over a
//! loopback TCP socket (`127.0.0.1:0`), exercising the full 3-step handshake,
//! encoding negotiation, server rejection, EXT header handling, and a live
//! session frame exchange.

use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use nps_ncp::encoding_policy::NcpEncodingPolicy;
use nps_ncp::transport::read_frame_header;
use nps_ncp::transport::ConnectError;
use nps_ncp::{
    patch_format, CapsFrame, ErrorFrame, HelloFrame, NcpNativeClient, NcpServer,
    HANDSHAKE_UNEXPECTED_FRAME,
};
use serde_json::json;
use std::io::Cursor;

fn client_hello(encodings: &[&str]) -> HelloFrame {
    HelloFrame::new(
        "0.11",
        encodings.iter().map(|s| s.to_string()).collect(),
        vec!["ncp".to_string()],
    )
}

fn server_caps() -> CapsFrame {
    let mut caps = CapsFrame::new("native:test", vec![json!({ "id": 1 })]);
    caps.node_id = Some("urn:nps:agent:test:node".to_string());
    caps.caps = vec!["ncp".to_string(), "nwp".to_string()];
    caps
}

#[tokio::test]
async fn handshake_happy_path_json() {
    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let conn = server.accept_connection().await.unwrap();
        // The client sent a Hello — verify it round-tripped.
        assert_eq!(conn.client_hello().nps_version, "0.11");
        assert!(conn
            .client_hello()
            .supported_encodings
            .contains(&"json".to_string()));
        conn.accept(server_caps()).await.unwrap()
    });

    let hello = client_hello(&["json"]);
    let session = NcpNativeClient::connect(addr, &hello).await.unwrap();

    let server_session = srv.await.unwrap();

    assert_eq!(session.negotiated_tier(), EncodingTier::Json);
    assert_eq!(
        session.server_caps().node_id.as_deref(),
        Some("urn:nps:agent:test:node")
    );
    assert_eq!(
        session.server_caps().negotiated_encoding.as_deref(),
        Some("json")
    );
    assert_eq!(server_session.negotiated_tier(), EncodingTier::Json);
}

#[tokio::test]
async fn encoding_negotiation_prefers_msgpack() {
    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let conn = server.accept_connection().await.unwrap();
        conn.accept(server_caps()).await.unwrap()
    });

    // Client offers msgpack first — server should pick it as the stable default.
    let hello = client_hello(&["msgpack", "json"]);
    let session = NcpNativeClient::connect(addr, &hello).await.unwrap();
    let _ = srv.await.unwrap();

    assert_eq!(session.negotiated_tier(), EncodingTier::MsgPack);
    assert_eq!(
        session.server_caps().enabled_encodings,
        Some(vec!["msgpack".to_string()])
    );
}

#[tokio::test]
async fn encoding_negotiation_enables_binary_vector_extension() {
    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let conn = server.accept_connection().await.unwrap();
        conn.accept(server_caps()).await.unwrap()
    });

    let hello = client_hello(&["msgpack", "binary_vector.v1"]);
    let session = NcpNativeClient::connect(addr, &hello).await.unwrap();
    let _ = srv.await.unwrap();

    assert_eq!(session.negotiated_tier(), EncodingTier::MsgPack);
    assert!(session.encoding_policy().binary_vector_enabled);
    assert_eq!(
        session.server_caps().enabled_encodings,
        Some(vec!["msgpack".to_string(), "binary_vector.v1".to_string()])
    );
}

#[tokio::test]
async fn server_rejection_surfaces_error_code() {
    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        let conn = server.accept_connection().await.unwrap();
        conn.reject(&ErrorFrame {
            error_code: "NCP-VERSION-INCOMPATIBLE".to_string(),
            message: "server refuses this client".to_string(),
            detail: None,
        })
        .await
        .unwrap();
    });

    let hello = client_hello(&["json"]);
    let result = NcpNativeClient::connect_detailed(addr, &hello).await;
    srv.await.unwrap();

    match result {
        Err(ConnectError::Handshake(h)) => {
            assert_eq!(h.error_code, "NCP-VERSION-INCOMPATIBLE");
            assert_eq!(h.message, "server refuses this client");
        }
        Err(other) => panic!("expected handshake rejection, got transport error {other}"),
        Ok(_) => panic!("expected handshake rejection, got a live session"),
    }
}

#[tokio::test]
async fn live_session_frame_exchange() {
    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    // Server: accept, then echo one Query -> Caps frame.
    let srv = tokio::spawn(async move {
        let conn = server.accept_connection().await.unwrap();
        let mut session = conn.accept(server_caps()).await.unwrap();

        let (ft, dict) = session.recv_frame().await.unwrap().unwrap();
        assert_eq!(ft, FrameType::Query);
        let intent = dict.get("intent").and_then(|v| v.as_str()).unwrap();

        let mut reply = CapsFrame::new("native:reply", vec![json!({ "echo": intent })]);
        reply.node_id = Some("srv".to_string());
        session
            .send_frame(FrameType::Caps, &reply.to_dict(), EncodingTier::Json)
            .await
            .unwrap();
    });

    let hello = client_hello(&["json"]);
    let mut session = NcpNativeClient::connect(addr, &hello).await.unwrap();

    let mut query = serde_json::Map::new();
    query.insert("intent".into(), json!("ping"));
    session
        .send_frame(FrameType::Query, &query, EncodingTier::Json)
        .await
        .unwrap();

    let (ft, dict) = session.recv_frame().await.unwrap().unwrap();
    assert_eq!(ft, FrameType::Caps);
    let caps = CapsFrame::from_dict(&dict).unwrap();
    assert_eq!(caps.data[0]["echo"], json!("ping"));

    srv.await.unwrap();
}

#[tokio::test]
async fn ext_header_round_trip() {
    // Build an extended (EXT) frame header, then parse it back through the same
    // 2-byte-peek reader the transport uses on the wire.
    let big_payload_len: u64 = 0x1_2345; // > 0xFFFF forces the extended header
    let header = FrameHeader::new(FrameType::Caps, EncodingTier::Json, true, big_payload_len);
    assert!(header.is_extended);
    let raw = header.to_bytes();
    assert_eq!(raw.len(), 8);
    assert!(raw[1] & 0x80 != 0, "EXT flag (bit 7) must be set");

    let mut cursor = Cursor::new(raw.clone());
    let (parsed, echoed_raw) = read_frame_header(&mut cursor).await.unwrap();
    assert!(parsed.is_extended);
    assert_eq!(parsed.payload_length, big_payload_len);
    assert_eq!(parsed.frame_type, FrameType::Caps);
    assert_eq!(echoed_raw, raw);

    // A default (non-EXT) header reads back as 4 bytes.
    let small = FrameHeader::new(FrameType::Hello, EncodingTier::Json, true, 42);
    let small_raw = small.to_bytes();
    assert_eq!(small_raw.len(), 4);
    let mut cursor2 = Cursor::new(small_raw);
    let (parsed2, raw2) = read_frame_header(&mut cursor2).await.unwrap();
    assert!(!parsed2.is_extended);
    assert_eq!(parsed2.payload_length, 42);
    assert_eq!(raw2.len(), 4);
}

#[tokio::test]
async fn unknown_first_frame_is_rejected_by_server() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move { server.accept_connection().await });

    // Send a valid preamble but a non-Hello (Caps) first frame.
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(nps_ncp::preamble::BYTES).await.unwrap();
    let bogus = FrameHeader::new(FrameType::Caps, EncodingTier::Json, true, 2);
    let mut wire = bogus.to_bytes();
    wire.extend_from_slice(b"{}");
    stream.write_all(&wire).await.unwrap();
    stream.flush().await.unwrap();

    let result = srv.await.unwrap();
    assert!(
        result.is_err(),
        "server must reject a non-Hello first frame"
    );
}

#[tokio::test]
async fn invalid_preamble_is_rejected_by_server() {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let server = NcpServer::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();

    let srv = tokio::spawn(async move { server.accept_connection().await });

    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(b"GET / HTTP").await.unwrap(); // 8 bytes, wrong content
    stream.flush().await.unwrap();

    let result = srv.await.unwrap();
    assert!(result.is_err(), "server must reject an invalid preamble");
}

#[test]
fn encoding_policy_allow_and_deny() {
    let json_only = NcpEncodingPolicy::new(EncodingTier::Json);
    assert!(json_only.allows(EncodingTier::Json, FrameType::Caps));
    assert!(!json_only.allows(EncodingTier::MsgPack, FrameType::Caps));
    assert_eq!(json_only.enabled_encodings(), vec!["json"]);

    let with_bv = NcpEncodingPolicy::with_binary_vector(EncodingTier::MsgPack, true);
    assert!(with_bv.allows(EncodingTier::MsgPack, FrameType::Caps));
    assert!(with_bv.allows(EncodingTier::BinaryVector, FrameType::Query));
    assert!(!with_bv.allows(EncodingTier::BinaryVector, FrameType::Caps));

    // ensure_allows returns Err for a denied header.
    let denied = FrameHeader::new(FrameType::Caps, EncodingTier::MsgPack, true, 0);
    assert!(json_only.ensure_allows(&denied).is_err());
    let allowed = FrameHeader::new(FrameType::Caps, EncodingTier::Json, true, 0);
    assert!(json_only.ensure_allows(&allowed).is_ok());
}

#[test]
fn patch_format_constants_and_helpers() {
    assert_eq!(patch_format::JSON_PATCH, "json_patch");
    assert_eq!(patch_format::BINARY_BITSET, "binary_bitset");
    assert!(patch_format::is_known("json_patch"));
    assert!(patch_format::is_known("binary_bitset"));
    assert!(!patch_format::is_known("nope"));
    // binary_bitset requires MsgPack availability.
    assert!(patch_format::allows_with_msgpack("json_patch", false));
    assert!(!patch_format::allows_with_msgpack("binary_bitset", false));
    assert!(patch_format::allows_with_msgpack("binary_bitset", true));
}

#[test]
fn handshake_unexpected_frame_code_matches_dotnet() {
    // Cross-SDK interop: this exact string is thrown by the .NET reference.
    assert_eq!(HANDSHAKE_UNEXPECTED_FRAME, "NCP-HANDSHAKE-UNEXPECTED-FRAME");
}
