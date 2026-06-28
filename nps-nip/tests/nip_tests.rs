// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::{FrameDict, NpsFrameCodec};
use nps_core::frames::EncodingTier;
use nps_core::registry::FrameRegistry;
use nps_nip::identity::NipIdentity;
use nps_nip::{IdentFrame, RevokeFrame, TrustFrame};
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
    let id = NipIdentity::generate();
    let payload = sample_payload();
    let sig = id.sign(&payload);
    assert!(sig.starts_with("ed25519:"));
    assert!(id.verify(&payload, &sig));
}

#[test]
fn verify_returns_false_for_tampered_payload() {
    let id = NipIdentity::generate();
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
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let id = NipIdentity::generate();
    id.save(&path, "test-pass").unwrap();
    let loaded = NipIdentity::load(&path, "test-pass").unwrap();
    assert_eq!(id.pub_key_string(), loaded.pub_key_string());
    let payload = sample_payload();
    assert!(loaded.verify(&payload, &id.sign(&payload)));
}

#[test]
fn load_wrong_passphrase_returns_err() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("key.json");
    let id = NipIdentity::generate();
    id.save(&path, "correct-pass").unwrap();
    assert!(NipIdentity::load(&path, "wrong-pass").is_err());
}

#[test]
fn verify_with_pub_key_str_correct() {
    let id = NipIdentity::generate();
    let payload = sample_payload();
    let sig = id.sign(&payload);
    assert!(NipIdentity::verify_with_pub_key_str(
        &payload,
        &id.pub_key_string(),
        &sig
    ));
}

#[test]
fn verify_with_pub_key_str_bad_prefix() {
    let id = NipIdentity::generate();
    let payload = sample_payload();
    let sig = id.sign(&payload);
    assert!(!NipIdentity::verify_with_pub_key_str(
        &payload,
        "rsa:badhex",
        &sig
    ));
}

// ── IdentFrame ────────────────────────────────────────────────────────────────

#[test]
fn ident_frame_roundtrip() {
    let codec = full_codec();
    let mut meta = serde_json::Map::new();
    meta.insert("issuer".into(), json!("urn:nps:org:root"));
    let frame = IdentFrame {
        nid: "urn:nps:node:a:1".into(),
        pub_key: "ed25519:aabbcc".into(),
        meta: Some(meta),
        signature: Some("ed25519:sig".into()),
        assurance_level: None,
        cert_format: None,
        cert_chain: None,
        ocsp_staple: None,
        reputation_policy: None,
        node_roles: None,
    };
    let wire = codec
        .encode(
            IdentFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = IdentFrame::from_dict(&dict).unwrap();
    assert_eq!(back.nid, "urn:nps:node:a:1");
    assert!(back.unsigned_dict().get("signature").is_none());
}

#[test]
fn ident_frame_optional_fields_null() {
    let codec = full_codec();
    let frame = IdentFrame {
        nid: "urn:nps:node:x:1".into(),
        pub_key: "ed25519:aabb".into(),
        meta: None,
        signature: None,
        assurance_level: None,
        cert_format: None,
        cert_chain: None,
        ocsp_staple: None,
        reputation_policy: None,
        node_roles: None,
    };
    let wire = codec
        .encode(
            IdentFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::Json,
            true,
        )
        .unwrap();
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
        grantor_nid: "urn:nps:org:org-a.com".into(),
        grantee_ca: "urn:nps:org:org-b.com".into(),
        trust_scope: vec!["nwp:query".into()],
        nodes: vec!["nwp://api.org-a.com/public/**".into()],
        issued_at: "2026-05-11T00:00:00Z".into(),
        expires_at: "2027-01-01T00:00:00Z".into(),
        serial: "00000000000A3F9C".into(),
        signer_nid: "urn:nps:org:org-a.com".into(),
        signature: "ed25519:sig".into(),
    };
    assert!(!frame.unsigned_dict().contains_key("signature"));
    let wire = codec
        .encode(
            TrustFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = TrustFrame::from_dict(&dict).unwrap();
    assert_eq!(back.grantee_ca, "urn:nps:org:org-b.com");
    assert_eq!(back.trust_scope, vec!["nwp:query"]);
    assert_eq!(back.nodes, vec!["nwp://api.org-a.com/public/**"]);
    assert_eq!(back.serial, "00000000000A3F9C");
    assert_eq!(back.signer_nid, "urn:nps:org:org-a.com");
}

// ── RevokeFrame ───────────────────────────────────────────────────────────────

#[test]
fn revoke_frame_roundtrip() {
    let codec = full_codec();
    let frame = RevokeFrame {
        target_nid: "urn:nps:agent:ca.example.com:session-1".into(),
        serial: Some("0x0A3F9C".into()),
        reason: "parent_revoked".into(),
        revoked_at: "2026-06-01T00:00:00Z".into(),
        parent_nid: Some("urn:nps:agent:ca.example.com:group-1".into()),
        signer_nid: "urn:nps:org:ca.example.com".into(),
        signature: "ed25519:sig".into(),
    };
    assert!(!frame.unsigned_dict().contains_key("signature"));
    let wire = codec
        .encode(
            RevokeFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = RevokeFrame::from_dict(&dict).unwrap();
    assert_eq!(back.reason, "parent_revoked");
    assert_eq!(back.revoked_at, "2026-06-01T00:00:00Z");
    assert_eq!(back.serial.as_deref(), Some("0x0A3F9C"));
    assert_eq!(
        back.parent_nid.as_deref(),
        Some("urn:nps:agent:ca.example.com:group-1")
    );
}

#[test]
fn revoke_frame_whole_nid_revocation_omits_serial() {
    let codec = full_codec();
    let frame = RevokeFrame {
        target_nid: "urn:nps:agent:ca.example.com:old".into(),
        serial: None,
        reason: "affiliation_changed".into(),
        revoked_at: "2026-06-01T00:00:00Z".into(),
        parent_nid: None,
        signer_nid: "urn:nps:org:ca.example.com".into(),
        signature: "ed25519:sig".into(),
    };
    let wire = codec
        .encode(
            RevokeFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::Json,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = RevokeFrame::from_dict(&dict).unwrap();
    assert!(back.serial.is_none());
    assert_eq!(back.reason, "affiliation_changed");
}

#[test]
fn revoke_frame_rejects_invalid_parent_nid_shape() {
    let missing_parent = json!({
        "frame": "0x22",
        "target_nid": "urn:nps:agent:ca.example.com:session-1",
        "reason": "parent_revoked",
        "revoked_at": "2026-06-01T00:00:00Z",
        "signer_nid": "urn:nps:org:ca.example.com",
        "signature": "ed25519:sig"
    })
    .as_object()
    .unwrap()
    .clone();
    let err = RevokeFrame::from_dict(&missing_parent).unwrap_err();
    assert!(format!("{err:?}").contains("NIP-REVOKE-FRAME-INVALID"));

    let stray_parent = json!({
        "frame": "0x22",
        "target_nid": "urn:nps:agent:ca.example.com:old",
        "reason": "key_compromise",
        "revoked_at": "2026-06-01T00:00:00Z",
        "parent_nid": "urn:nps:agent:ca.example.com:group-1",
        "signer_nid": "urn:nps:org:ca.example.com",
        "signature": "ed25519:sig"
    })
    .as_object()
    .unwrap()
    .clone();
    let err = RevokeFrame::from_dict(&stray_parent).unwrap_err();
    assert!(format!("{err:?}").contains("NIP-REVOKE-FRAME-INVALID"));
}
