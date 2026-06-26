// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::NpsFrameCodec;
use nps_core::frames::{EncodingTier, FrameType};
use nps_core::registry::FrameRegistry;
use nps_ncp::CapsFrame;
use nps_nwp::{ActionFrame, NwpNativeNodeServer, QueryFrame};
use serde_json::json;

#[test]
fn dispatch_wire_returns_caps_for_query() {
    let codec = NpsFrameCodec::new(FrameRegistry::create_full());
    let server = NwpNativeNodeServer::new()
        .with_query_handler(|_| Ok(CapsFrame::new("native:test", vec![json!({ "id": 42 })])));
    let query = QueryFrame::new("sha256:a");
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
}
