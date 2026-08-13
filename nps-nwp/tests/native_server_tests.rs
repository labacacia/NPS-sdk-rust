// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::codec::NpsFrameCodec;
use nps_core::frames::{EncodingTier, FrameType};
use nps_core::registry::FrameRegistry;
use nps_ncp::error_codes;
use nps_ncp::CapsFrame;
use nps_nwp::{ActionFrame, NwpNativeNodeServer, QueryFrame};
use serde_json::json;

#[test]
fn dispatch_wire_returns_caps_for_query() {
    let codec = NpsFrameCodec::new(FrameRegistry::create_full());
    let server = NwpNativeNodeServer::new()
        .with_query_handler(|_| Ok(CapsFrame::new("native:test", vec![json!({ "id": 42 })])));
    let mut query = QueryFrame::new("sha256:a");
    query.request_id = Some("req-query-1".into());
    let wire = codec
        .encode(
            FrameType::Query,
            &query.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();

    let out = server.dispatch_wire(&wire).unwrap();
    let (ft, dict) = codec.decode(&out).unwrap();
    let caps = CapsFrame::from_dict(&dict).unwrap();

    assert_eq!(ft, FrameType::Caps);
    assert_eq!(caps.count, Some(1));
    assert_eq!(caps.data[0]["id"], 42);
    assert_eq!(caps.request_id.as_deref(), Some("req-query-1"));
}

#[test]
fn dispatch_wire_accepts_action_id_shape() {
    let codec = NpsFrameCodec::new(FrameRegistry::create_full());
    let server = NwpNativeNodeServer::new()
        .with_action_handler(|frame| Ok(json!({ "action": frame.action })));
    let mut action = ActionFrame {
        action: "ping".into(),
        params: None,
        anchor_ref: None,
        async_: false,
        idempotency_key: None,
        timeout_ms: None,
        request_id: Some("req-action-1".into()),
    }
    .to_dict();
    action.remove("action");

    let wire = codec
        .encode(FrameType::Action, &action, EncodingTier::MsgPack, true)
        .unwrap();
    let out = server.dispatch_wire(&wire).unwrap();
    let (_, dict) = codec.decode(&out).unwrap();
    let caps = CapsFrame::from_dict(&dict).unwrap();

    assert_eq!(caps.data[0]["action"], "ping");
    assert_eq!(caps.request_id.as_deref(), Some("req-action-1"));
}

#[test]
fn dispatch_wire_rejects_unnegotiated_binary_vector() {
    let codec = NpsFrameCodec::new(FrameRegistry::create_full());
    let server = NwpNativeNodeServer::new()
        .with_query_handler(|_| Ok(CapsFrame::new("native:test", vec![json!({ "id": 42 })])));
    let wire = codec
        .encode(
            FrameType::Query,
            &vector_query_dict(),
            EncodingTier::BinaryVector,
            true,
        )
        .unwrap();

    let out = server.dispatch_wire(&wire).unwrap();
    let (ft, dict) = codec.decode(&out).unwrap();

    assert_eq!(ft, FrameType::Error);
    assert_eq!(dict["error"], error_codes::ENCODING_UNSUPPORTED);
}

#[test]
fn dispatch_wire_allows_negotiated_binary_vector_query() {
    let codec = NpsFrameCodec::new(FrameRegistry::create_full());
    let server = NwpNativeNodeServer::new()
        .with_enabled_encodings(["msgpack", "binary_vector.v1"])
        .with_query_handler(|_| Ok(CapsFrame::new("native:test", vec![json!({ "id": 42 })])));
    let wire = codec
        .encode(
            FrameType::Query,
            &vector_query_dict(),
            EncodingTier::BinaryVector,
            true,
        )
        .unwrap();

    let out = server.dispatch_wire(&wire).unwrap();
    let (ft, dict) = codec.decode(&out).unwrap();
    let caps = CapsFrame::from_dict(&dict).unwrap();

    assert_eq!(ft, FrameType::Caps);
    assert_eq!(caps.count, Some(1));
}

fn vector_query_dict() -> FrameDict {
    let mut out = serde_json::Map::new();
    out.insert("anchor_ref".into(), json!("sha256:a"));
    out.insert("limit".into(), json!(1));
    out.insert(
        "vector_search".into(),
        json!({
            "field": "embedding",
            "vector": [0.25, -1.5, 3.0],
            "top_k": 1
        }),
    );
    out
}
