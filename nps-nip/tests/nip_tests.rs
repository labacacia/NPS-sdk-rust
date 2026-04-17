// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::{NpsFrameCodec, FrameDict};
use nps_core::frames::EncodingTier;
use nps_core::registry::FrameRegistry;
use nps_nip::{IdentFrame, TrustFrame, RevokeFrame};
use nps_nip::identity::NipIdentity;
use serde_json::json;

fn full_codec() -> NpsFrameCodec {
    NpsFrameCodec::new(FrameRegistry::create_full())
}

fn sample_payload() -> FrameDict {
    let mut m = serde_json::Map::new();
    m.insert("nid".into(), json!("urn:nps:node:a:1"));
    m.insert("action".into(), json!("test"));
    m
}

// ── NipIdentity ───────────────────────────────────────────────────────────────

#[test]
fn generate_creates_distinct_keys() {
    let a = NipIdentity::generate();
    let b = NipIdentity::generate();
    assert_ne!(a.pub_key_string(), b.pub_key_string());
}

#[test]
fn pub_key_string_format() {
    let id = NipIdentity::generate();
    assert!(id.pub_key_string().starts_with("ed25519:"));
    assert_eq!(id.pub_key_string().len(), "ed25519:".len() + 64); // 32 bytes hex = 64 chars
}

#[test]
fn sign_verify_roundtrip() {
    let id      = NipIdentity::generate();
    let payload = sample_payload();
    let sig     = id.sign(&payload);
    assert!(sig.starts_with("ed25519:"));
    assert!(id.verify(&payload, &sig));
}

#[test]
fn verify_returns_false_for_tampered_payload() {
    let id  = NipIdentity::generate();
    let sig = id.sign(&sample_payload());
    let mut bad = serde_json::Map::new();
    bad.insert("nid".into(), json!("urn:nps:node:a:1"));
    bad.insert("action".into(), json!("tampered"));
    assert!(!id.verify(&bad, &sig));
}

#[test]
fn verify_returns_false_for_wrong_prefix() {
    let id = NipIdentity::generate();
    assert!(!id.verify(&sample_payload(), "rsa:abc123"));
}

#[test]
fn verify_returns_false_for_corrupted_base64() {
    let id = NipIdentity::generate();
    assert!(!id.verify(&sample_payload(), "ed25519:!!!garbage!!!"));
}

#[test]
fn sign_is_canonical_key_order_independent() {
    let id = NipIdentity::generate();
    let mut p1 = serde_json::Map::new();
    p1.insert("b".into(), json!(2));
    p1.insert("a".into(), json!(1));
    let mut p2 = serde_json::Map::new();
    p2.insert("a".into(), json!(1));
    p2.insert("b".into(), json!(2));
    assert_eq!(id.sign(&p1), id.sign(&p2));
}

#[test]
fn save_and_load_roundtrip() {
    let dir  = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let id   = NipIdentity::generate();
    id.save(&path, "test-pass").unwrap();
    let loaded = NipIdentity::load(&path, "test-pass").unwrap();
    assert_eq!(id.pub_key_string(), loaded.pub_key_string());
    let payload = sample_payload();
    assert!(loaded.verify(&payload, &id.sign(&payload)));
}

#[test]
fn load_wrong_passphrase_returns_err() {
    let dir  = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let id   = NipIdentity::generate();
    id.save(&path, "correct-pass").unwrap();
    assert!(NipIdentity::load(&path, "wrong-pass").is_err());
}

#[test]
fn verify_with_pub_key_str_correct() {
    let id      = NipIdentity::generate();
    let payload = sample_payload();
    let sig     = id.sign(&payload);
    assert!(NipIdentity::verify_with_pub_key_str(&payload, &id.pub_key_string(), &sig));
}

#[test]
fn verify_with_pub_key_str_bad_prefix() {
    let id      = NipIdentity::generate();
    let payload = sample_payload();
    let sig     = id.sign(&payload);
    assert!(!NipIdentity::verify_with_pub_key_str(&payload, "rsa:badhex", &sig));
}

// ── IdentFrame ────────────────────────────────────────────────────────────────

#[test]
fn ident_frame_roundtrip() {
    let codec  = full_codec();
    let mut meta = serde_json::Map::new();
    meta.insert("issuer".into(), json!("urn:nps:ca:root"));
    let frame  = IdentFrame {
        nid:       "urn:nps:node:a:1".into(),
        pub_key:   "ed25519:aabbcc".into(),
        meta:      Some(meta),
        signature: Some("ed25519:sig".into()),
    };
    let wire = codec.encode(IdentFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = IdentFrame::from_dict(&dict).unwrap();
    assert_eq!(back.nid, "urn:nps:node:a:1");
    assert!(back.unsigned_dict().get("signature").is_none());
}

#[test]
fn ident_frame_optional_fields_null() {
    let codec = full_codec();
    let frame = IdentFrame {
        nid:       "urn:nps:node:x:1".into(),
        pub_key:   "ed25519:aabb".into(),
        meta:      None,
        signature: None,
    };
    let wire = codec.encode(IdentFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = IdentFrame::from_dict(&dict).unwrap();
    assert!(back.meta.is_none());
    assert!(back.signature.is_none());
}

// ── TrustFrame ────────────────────────────────────────────────────────────────

#[test]
fn trust_frame_roundtrip() {
    let codec = full_codec();
    let frame = TrustFrame {
        issuer_nid:  "urn:nps:node:a:1".into(),
        subject_nid: "urn:nps:node:b:1".into(),
        scopes:      vec!["nwp/query".into()],
        expires_at:  Some("2027-01-01T00:00:00Z".into()),
        signature:   Some("ed25519:sig".into()),
    };
    let wire = codec.encode(TrustFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = TrustFrame::from_dict(&dict).unwrap();
    assert_eq!(back.subject_nid, "urn:nps:node:b:1");
    assert_eq!(back.scopes, vec!["nwp/query"]);
}

// ── RevokeFrame ───────────────────────────────────────────────────────────────

#[test]
fn revoke_frame_roundtrip() {
    let codec = full_codec();
    let frame = RevokeFrame {
        nid:        "urn:nps:node:a:1".into(),
        reason:     Some("compromised".into()),
        revoked_at: Some("2026-06-01T00:00:00Z".into()),
    };
    let wire = codec.encode(RevokeFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = RevokeFrame::from_dict(&dict).unwrap();
    assert_eq!(back.reason.as_deref(), Some("compromised"));
    assert_eq!(back.revoked_at.as_deref(), Some("2026-06-01T00:00:00Z"));
}

#[test]
fn revoke_frame_optional_fields_null() {
    let codec = full_codec();
    let frame = RevokeFrame { nid: "urn:nps:node:x:1".into(), reason: None, revoked_at: None };
    let wire = codec.encode(RevokeFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = RevokeFrame::from_dict(&dict).unwrap();
    assert!(back.reason.is_none());
    assert!(back.revoked_at.is_none());
}
