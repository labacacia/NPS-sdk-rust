// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::NpsFrameCodec;
use nps_core::frames::{EncodingTier, FrameType};
use nps_core::registry::FrameRegistry;
use nps_ncp::HelloFrame;

// ── HelloFrame ────────────────────────────────────────────────────────────────

#[test]
fn hello_frame_type_is_0x06() {
    assert_eq!(HelloFrame::frame_type().as_u8(), 0x06);
    assert_eq!(HelloFrame::frame_type(), FrameType::Hello);
}

#[test]
fn hello_frame_default_registry_registers_hello() {
    let reg = FrameRegistry::create_default();
    assert!(reg.is_registered(FrameType::Hello));
}

#[test]
fn hello_frame_full_roundtrip_json() {
    let mut frame = HelloFrame::new(
        "0.2",
        vec!["tier-1".into(), "tier-2".into()],
        vec!["ncp".into(), "nwp".into(), "nip".into()],
    );
    frame.min_version            = Some("0.1".into());
    frame.agent_id               = Some("urn:nps:agent:example.com:hello-1".into());
    frame.ext_support            = true;
    frame.max_concurrent_streams = 64;
    frame.e2e_enc_algorithms     = Some(vec!["aes-256-gcm".into()]);

    let reg   = FrameRegistry::create_full();
    let codec = NpsFrameCodec::new(reg);
    let dict  = frame.to_dict();

    // Handshake: always JSON (encoding not yet negotiated).
    let wire  = codec.encode(FrameType::Hello, &dict, EncodingTier::Json, true).unwrap();
    let (_, out_d) = codec.decode(&wire).unwrap();
    let out        = HelloFrame::from_dict(&out_d).unwrap();

    assert_eq!(out.nps_version,            "0.2");
    assert_eq!(out.supported_encodings,    vec!["tier-1", "tier-2"]);
    assert_eq!(out.supported_protocols,    vec!["ncp", "nwp", "nip"]);
    assert_eq!(out.min_version.as_deref(), Some("0.1"));
    assert_eq!(out.agent_id.as_deref(),    Some("urn:nps:agent:example.com:hello-1"));
    assert!(out.ext_support);
    assert_eq!(out.max_concurrent_streams, 64);
    assert_eq!(out.e2e_enc_algorithms,     Some(vec!["aes-256-gcm".into()]));
}

#[test]
fn hello_frame_minimal_roundtrip_msgpack() {
    let frame = HelloFrame::new("0.2", vec!["tier-1".into()], vec!["ncp".into()]);

    let reg   = FrameRegistry::create_default();
    let codec = NpsFrameCodec::new(reg);
    let wire  = codec.encode(FrameType::Hello, &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, out_d) = codec.decode(&wire).unwrap();
    let out        = HelloFrame::from_dict(&out_d).unwrap();

    assert_eq!(out.nps_version,            "0.2");
    assert!(out.min_version.is_none());
    assert!(out.agent_id.is_none());
    assert!(out.e2e_enc_algorithms.is_none());
    assert!(!out.ext_support);
    assert_eq!(out.max_frame_payload,      HelloFrame::DEFAULT_MAX_FRAME_PAYLOAD);
    assert_eq!(out.max_concurrent_streams, HelloFrame::DEFAULT_MAX_CONCURRENT_STREAMS);
}
