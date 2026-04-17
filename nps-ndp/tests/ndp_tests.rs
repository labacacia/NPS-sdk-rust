// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::NpsFrameCodec;
use nps_core::frames::EncodingTier;
use nps_core::registry::FrameRegistry;
use nps_ndp::{AnnounceFrame, ResolveFrame, GraphFrame};
use nps_ndp::{InMemoryNdpRegistry, NdpAnnounceValidator};
use nps_nip::identity::NipIdentity;
use serde_json::{json, Map};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};

const NID: &str  = "urn:nps:node:example.com:data";
const TS:  &str  = "2026-01-01T00:00:00Z";

fn full_codec() -> NpsFrameCodec {
    NpsFrameCodec::new(FrameRegistry::create_full())
}

fn make_addr() -> Map<String, serde_json::Value> {
    let mut m = Map::new();
    m.insert("host".into(),     json!("example.com"));
    m.insert("port".into(),     json!(17433));
    m.insert("protocol".into(), json!("nwp"));
    m
}

fn make_announce(id: &NipIdentity, ttl: u64) -> AnnounceFrame {
    let addrs = vec![make_addr()];
    let caps  = vec!["nwp/query".to_string(), "nwp/stream".to_string()];
    let tmp   = AnnounceFrame {
        nid: NID.into(), addresses: addrs.clone(), caps: caps.clone(),
        ttl, timestamp: TS.into(), signature: "placeholder".into(), node_type: None,
    };
    let sig = id.sign(&tmp.unsigned_dict());
    AnnounceFrame {
        nid: NID.into(), addresses: addrs, caps, ttl,
        timestamp: TS.into(), signature: sig, node_type: None,
    }
}

// ── AnnounceFrame ─────────────────────────────────────────────────────────────

#[test]
fn announce_frame_roundtrip() {
    let id    = NipIdentity::generate();
    let frame = make_announce(&id, 300);
    let back  = AnnounceFrame::from_dict(&frame.to_dict()).unwrap();
    assert_eq!(back.nid, NID);
    assert_eq!(back.ttl, 300);
    assert!(back.unsigned_dict().get("signature").is_none());
}

#[test]
fn announce_frame_codec_roundtrip() {
    let codec = full_codec();
    let id    = NipIdentity::generate();
    let frame = make_announce(&id, 300);
    let wire  = codec.encode(AnnounceFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back  = AnnounceFrame::from_dict(&dict).unwrap();
    assert_eq!(back.nid, NID);
}

// ── ResolveFrame ──────────────────────────────────────────────────────────────

#[test]
fn resolve_frame_roundtrip() {
    let mut resolved = Map::new();
    resolved.insert("host".into(), json!("example.com"));
    resolved.insert("port".into(), json!(17433));
    resolved.insert("ttl".into(),  json!(300));
    let frame = ResolveFrame {
        target:        "nwp://example.com/data".into(),
        requester_nid: Some("urn:nps:node:a:1".into()),
        resolved:      Some(resolved),
    };
    let back = ResolveFrame::from_dict(&frame.to_dict()).unwrap();
    assert_eq!(back.target, "nwp://example.com/data");
    assert!(back.resolved.is_some());
}

#[test]
fn resolve_frame_optional_fields_null() {
    let frame = ResolveFrame {
        target: "nwp://example.com/data".into(),
        requester_nid: None,
        resolved: None,
    };
    let back = ResolveFrame::from_dict(&frame.to_dict()).unwrap();
    assert!(back.requester_nid.is_none());
    assert!(back.resolved.is_none());
}

// ── GraphFrame ────────────────────────────────────────────────────────────────

#[test]
fn graph_frame_roundtrip() {
    let codec = full_codec();
    let frame = GraphFrame {
        seq: 1, initial_sync: true,
        nodes: vec![json!({"nid": NID})],
        patch: None,
    };
    let wire = codec.encode(GraphFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = GraphFrame::from_dict(&dict).unwrap();
    assert_eq!(back.seq, 1);
    assert!(back.initial_sync);
    assert!(back.patch.is_none());
}

// ── InMemoryNdpRegistry ───────────────────────────────────────────────────────

#[test]
fn announce_and_get_by_nid() {
    let mut reg = InMemoryNdpRegistry::new();
    let id      = NipIdentity::generate();
    let frame   = make_announce(&id, 300);
    reg.announce(frame);
    assert!(reg.get_by_nid(NID).is_some());
}

#[test]
fn get_by_nid_returns_none_for_unknown() {
    let reg = InMemoryNdpRegistry::new();
    assert!(reg.get_by_nid("urn:nps:node:x:y").is_none());
}

#[test]
fn ttl_zero_deregisters() {
    let mut reg = InMemoryNdpRegistry::new();
    let id      = NipIdentity::generate();
    reg.announce(make_announce(&id, 300));
    reg.announce(make_announce(&id, 0));
    assert!(reg.get_by_nid(NID).is_none());
}

#[test]
fn ttl_expiry() {
    let base    = Instant::now();
    let elapsed = Arc::new(Mutex::new(0u64));
    let elapsed2 = elapsed.clone();
    let mut reg  = InMemoryNdpRegistry::new();
    reg.clock = Box::new(move || base + Duration::from_secs(*elapsed2.lock().unwrap()));

    let id = NipIdentity::generate();
    reg.announce(make_announce(&id, 10));
    assert!(reg.get_by_nid(NID).is_some());

    *elapsed.lock().unwrap() = 11;
    assert!(reg.get_by_nid(NID).is_none());
}

#[test]
fn resolve_returns_matching_entry() {
    let mut reg = InMemoryNdpRegistry::new();
    let id      = NipIdentity::generate();
    reg.announce(make_announce(&id, 300));
    let r = reg.resolve("nwp://example.com/data/sub").unwrap();
    assert_eq!(r.host, "example.com");
    assert_eq!(r.port, 17433);
}

#[test]
fn resolve_returns_none_for_non_match() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(make_announce(&NipIdentity::generate(), 300));
    assert!(reg.resolve("nwp://other.com/data").is_none());
}

#[test]
fn get_all_returns_active_entries() {
    let base    = Instant::now();
    let elapsed = Arc::new(Mutex::new(0u64));
    let elapsed2 = elapsed.clone();
    let mut reg  = InMemoryNdpRegistry::new();
    reg.clock = Box::new(move || base + Duration::from_secs(*elapsed2.lock().unwrap()));

    let id1 = NipIdentity::generate();
    let id2 = NipIdentity::generate();
    let nid1 = "urn:nps:node:a.com:x";
    let nid2 = "urn:nps:node:b.com:y";
    let addrs = vec![make_addr()];
    let caps  = vec!["nwp/query".to_string()];

    let tmp1 = AnnounceFrame { nid: nid1.into(), addresses: addrs.clone(), caps: caps.clone(), ttl: 100, timestamp: TS.into(), signature: "ph".into(), node_type: None };
    let tmp2 = AnnounceFrame { nid: nid2.into(), addresses: addrs.clone(), caps: caps.clone(), ttl: 1,   timestamp: TS.into(), signature: "ph".into(), node_type: None };
    let sig1 = id1.sign(&tmp1.unsigned_dict());
    let sig2 = id2.sign(&tmp2.unsigned_dict());

    reg.announce(AnnounceFrame { nid: nid1.into(), addresses: addrs.clone(), caps: caps.clone(), ttl: 100, timestamp: TS.into(), signature: sig1, node_type: None });
    reg.announce(AnnounceFrame { nid: nid2.into(), addresses: addrs.clone(), caps: caps.clone(), ttl: 1,   timestamp: TS.into(), signature: sig2, node_type: None });

    *elapsed.lock().unwrap() = 2;
    let all = reg.get_all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].nid, nid1);
}

// ── nwp_target_matches_nid ────────────────────────────────────────────────────

#[test]
fn exact_match()        { assert!( InMemoryNdpRegistry::nwp_target_matches_nid(NID, "nwp://example.com/data")); }
#[test]
fn sub_path_match()     { assert!( InMemoryNdpRegistry::nwp_target_matches_nid(NID, "nwp://example.com/data/sub")); }
#[test]
fn different_authority(){ assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(NID, "nwp://other.com/data")); }
#[test]
fn sibling_path()       { assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(NID, "nwp://example.com/dataset")); }
#[test]
fn invalid_nid()        { assert!(!InMemoryNdpRegistry::nwp_target_matches_nid("invalid", "nwp://example.com/data")); }
#[test]
fn non_nwp_target()     { assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(NID, "http://example.com/data")); }
#[test]
fn no_slash_in_target() { assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(NID, "nwp://example.com")); }

// ── NdpAnnounceValidator ──────────────────────────────────────────────────────

#[test]
fn validator_fails_when_no_key_registered() {
    let v = NdpAnnounceValidator::new();
    let r = v.validate(&make_announce(&NipIdentity::generate(), 300));
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some("NDP-ANNOUNCE-NID-MISMATCH"));
}

#[test]
fn validates_correctly_signed_frame() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    let frame = make_announce(&id, 300);
    assert!(v.validate(&frame).is_valid);
}

#[test]
fn rejects_wrong_signature_prefix() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    let frame = AnnounceFrame {
        nid: NID.into(), addresses: vec![make_addr()], caps: vec![], ttl: 300,
        timestamp: TS.into(), signature: "rsa:invalid".into(), node_type: None,
    };
    let r = v.validate(&frame);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some("NDP-ANNOUNCE-SIG-INVALID"));
}

#[test]
fn remove_public_key_deregisters() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    v.remove_public_key(NID);
    assert!(!v.known_public_keys().contains_key(NID));
}

#[test]
fn announce_result_ok() {
    use nps_ndp::NdpAnnounceResult;
    let r = NdpAnnounceResult::ok();
    assert!(r.is_valid);
    assert!(r.error_code.is_none());
}

#[test]
fn announce_result_fail() {
    use nps_ndp::NdpAnnounceResult;
    let r = NdpAnnounceResult::fail("CODE", "msg");
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some("CODE"));
    assert_eq!(r.message.as_deref(), Some("msg"));
}
