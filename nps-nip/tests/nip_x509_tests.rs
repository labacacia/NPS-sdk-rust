// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Rust parallel of .NET / Java / Python / TypeScript / Go NipX509Tests
//! per NPS-RFC-0002 §4. Covers the 5 verification scenarios documented in
//! the .NET reference.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use nps_nip::{
    AssuranceLevel, IdentFrame, NipIdentVerifier, NipVerifierOptions, ANONYMOUS, ATTESTED,
};
use nps_nip::cert_format::V2_X509;
use nps_nip::error_codes;
use nps_nip::x509::{self, IssueLeafOptions, IssueRootOptions, LeafRole};

#[test]
fn register_x509_round_trip_verifier_accepts() {
    let ca_nid    = "urn:nps:ca:test";
    let agent_nid = "urn:nps:agent:happy:1";

    let ca_sk    = SigningKey::generate(&mut OsRng);
    let agent_sk = SigningKey::generate(&mut OsRng);

    let root = mk_root(&ca_sk, ca_nid, &[1]);
    let leaf = mk_leaf(agent_nid, &agent_sk, &ca_sk, &root, ca_nid,
        LeafRole::Agent, ATTESTED, &[2]);

    let frame = build_v2_frame(agent_nid, agent_sk.verifying_key().as_bytes(), &ca_sk,
        Some(ATTESTED), leaf.der(), root.der());

    let verifier = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(ca_nid, &pub_key_str(&ca_sk))]),
        trusted_x509_roots_der: vec![root.der().to_vec()],
        ..Default::default()
    });
    let r = verifier.verify(&frame, ca_nid);
    assert!(r.valid, "expected valid; got step={} code={:?} msg={:?}",
        r.step_failed, r.error_code, r.message);
}

#[test]
fn register_x509_leaf_eku_stripped_rejects_eku_missing() {
    let ca_nid    = "urn:nps:ca:test";
    let agent_nid = "urn:nps:agent:eku-stripped:1";

    let ca_sk    = SigningKey::generate(&mut OsRng);
    let agent_sk = SigningKey::generate(&mut OsRng);

    let root = mk_root(&ca_sk, ca_nid, &[1]);
    let tampered_der = build_leaf_without_eku(agent_nid, agent_sk.verifying_key().as_bytes(),
        &ca_sk, &root, ca_nid, &[99]);

    let frame = build_v2_frame_with_der(agent_nid, agent_sk.verifying_key().as_bytes(), &ca_sk,
        None, &tampered_der, root.der());

    let verifier = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(ca_nid, &pub_key_str(&ca_sk))]),
        trusted_x509_roots_der: vec![root.der().to_vec()],
        ..Default::default()
    });
    let r = verifier.verify(&frame, ca_nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_EKU_MISSING),
        "got code={:?} msg={:?}", r.error_code, r.message);
    assert_eq!(r.step_failed, 3);
}

#[test]
fn register_x509_leaf_for_different_nid_rejects_subject_mismatch() {
    let ca_nid     = "urn:nps:ca:test";
    let victim_nid = "urn:nps:agent:victim:1";
    let forged_nid = "urn:nps:agent:attacker:9";

    let ca_sk    = SigningKey::generate(&mut OsRng);
    let agent_sk = SigningKey::generate(&mut OsRng);

    let root = mk_root(&ca_sk, ca_nid, &[1]);
    // Issue a leaf whose CN/SAN are the *forged* NID, but splice it into a frame
    // claiming the *victim* NID. The IdentFrame v1 sig still asserts victim.
    let forged_leaf = mk_leaf(forged_nid, &agent_sk, &ca_sk, &root, ca_nid,
        LeafRole::Agent, ANONYMOUS, &[77]);

    let frame = build_v2_frame(victim_nid, agent_sk.verifying_key().as_bytes(), &ca_sk,
        None, forged_leaf.der(), root.der());

    let verifier = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(ca_nid, &pub_key_str(&ca_sk))]),
        trusted_x509_roots_der: vec![root.der().to_vec()],
        ..Default::default()
    });
    let r = verifier.verify(&frame, ca_nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_SUBJECT_NID_MISMATCH),
        "got code={:?} msg={:?}", r.error_code, r.message);
    assert_eq!(r.step_failed, 3);
}

#[test]
fn v1_only_verifier_accepts_v2_frame_by_ignoring_chain() {
    let ca_nid    = "urn:nps:ca:test";
    let agent_nid = "urn:nps:agent:v1-compat:1";

    let ca_sk    = SigningKey::generate(&mut OsRng);
    let agent_sk = SigningKey::generate(&mut OsRng);

    let root = mk_root(&ca_sk, ca_nid, &[1]);
    let leaf = mk_leaf(agent_nid, &agent_sk, &ca_sk, &root, ca_nid,
        LeafRole::Agent, ANONYMOUS, &[2]);

    let frame = build_v2_frame(agent_nid, agent_sk.verifying_key().as_bytes(), &ca_sk,
        None, leaf.der(), root.der());

    // Verifier WITHOUT trustedX509Roots — Step 3b skipped entirely.
    let verifier = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(ca_nid, &pub_key_str(&ca_sk))]),
        ..Default::default()
    });
    let r = verifier.verify(&frame, ca_nid);
    assert!(r.valid, "v1-only verifier MUST accept v2 frames; got code={:?} msg={:?}",
        r.error_code, r.message);
}

#[test]
fn v2_verifier_rejects_v2_frame_when_trusted_roots_missing() {
    let ca_nid    = "urn:nps:ca:test";
    let agent_nid = "urn:nps:agent:wrong-trust:1";

    let ca_sk    = SigningKey::generate(&mut OsRng);
    let agent_sk = SigningKey::generate(&mut OsRng);

    let root = mk_root(&ca_sk, ca_nid, &[1]);
    let leaf = mk_leaf(agent_nid, &agent_sk, &ca_sk, &root, ca_nid,
        LeafRole::Agent, ANONYMOUS, &[2]);

    let frame = build_v2_frame(agent_nid, agent_sk.verifying_key().as_bytes(), &ca_sk,
        None, leaf.der(), root.der());

    // Different unrelated CA root — chain won't anchor.
    let other_ca_sk = SigningKey::generate(&mut OsRng);
    let other_root  = mk_root(&other_ca_sk, "urn:nps:ca:other", &[1]);

    let verifier = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(ca_nid, &pub_key_str(&ca_sk))]),
        trusted_x509_roots_der: vec![other_root.der().to_vec()],
        ..Default::default()
    });
    let r = verifier.verify(&frame, ca_nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_FORMAT_INVALID),
        "got code={:?} msg={:?}", r.error_code, r.message);
    assert_eq!(r.step_failed, 3);
}

// ── Test helpers ────────────────────────────────────────────────────────────

fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries.iter().map(|(k, v)| ((*k).to_string(), (*v).to_string())).collect()
}

fn pub_key_str(sk: &SigningKey) -> String {
    format!("ed25519:{}", hex::encode(sk.verifying_key().as_bytes()))
}

fn mk_root(ca_sk: &SigningKey, ca_nid: &str, serial: &[u8]) -> rcgen::Certificate {
    let now = SystemTime::now();
    x509::issue_root(IssueRootOptions {
        ca_nid, ca_signing_key: ca_sk,
        not_before:    now - Duration::from_secs(60),
        not_after:     now + Duration::from_secs(365 * 24 * 3600),
        serial_number: serial,
    }).expect("issue_root")
}

fn mk_leaf(
    nid: &str, agent_sk: &SigningKey, ca_sk: &SigningKey, ca_root: &rcgen::Certificate,
    ca_nid: &str, role: LeafRole, level: AssuranceLevel, serial: &[u8],
) -> rcgen::Certificate {
    let now = SystemTime::now();
    x509::issue_leaf(IssueLeafOptions {
        subject_nid:     nid,
        subject_pub_raw: agent_sk.verifying_key().as_bytes(),
        ca_signing_key:  ca_sk,
        ca_root_cert:    ca_root,
        role,
        assurance_level: level,
        not_before:      now - Duration::from_secs(60),
        not_after:       now + Duration::from_secs(30 * 24 * 3600),
        serial_number:   serial,
    }).expect("issue_leaf")
}

/// Build an IdentFrame including the v1 Ed25519 CA signature covering
/// unsigned_dict(), and attach the X.509 chain (leaf + root).
fn build_v2_frame(
    nid: &str, subject_pub: &[u8; 32], ca_sk: &SigningKey,
    level: Option<AssuranceLevel>, leaf_der: &[u8], root_der: &[u8],
) -> IdentFrame {
    build_v2_frame_with_der(nid, subject_pub, ca_sk, level, leaf_der, root_der)
}

fn build_v2_frame_with_der(
    nid: &str, subject_pub: &[u8; 32], ca_sk: &SigningKey,
    level: Option<AssuranceLevel>, leaf_der: &[u8], root_der: &[u8],
) -> IdentFrame {
    let pub_key_str = format!("ed25519:{}", hex::encode(subject_pub));
    let mut meta = serde_json::Map::new();
    meta.insert("issued_by".into(), json!("test-ca"));

    let mut frame = IdentFrame::new(nid.to_string(), pub_key_str);
    frame.meta = Some(meta);
    frame.assurance_level = level;

    // Sign with CA private key over canonical(unsigned_dict()).
    let canonical = nps_nip::verifier::canonical_json(&frame.unsigned_dict());
    let sig = ca_sk.sign(canonical.as_bytes());
    frame.signature = Some(format!("ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())));

    frame.cert_format = Some(V2_X509.to_string());
    frame.cert_chain = Some(vec![
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf_der),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(root_der),
    ]);
    frame
}

/// Build a leaf cert WITHOUT the EKU extension — exercises the verifier's
/// EKU presence check. Returns raw DER directly (rcgen has no easy API for
/// "build cert minus this extension", so we use rcgen with a custom set
/// of extensions excluding EKU).
fn build_leaf_without_eku(
    nid: &str, subject_pub: &[u8; 32], ca_sk: &SigningKey,
    ca_root: &rcgen::Certificate, ca_nid: &str, serial: &[u8],
) -> Vec<u8> {
    use rcgen::{
        BasicConstraints as BC, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo,
    };

    // Repurpose builder helpers via the public API.
    let ca_keypair_pkcs8 = {
        let mut pkcs8 = Vec::with_capacity(48);
        pkcs8.extend_from_slice(&[
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
            0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
        ]);
        pkcs8.extend_from_slice(ca_sk.as_bytes());
        pkcs8
    };
    let ca_keypair = KeyPair::try_from(ca_keypair_pkcs8.as_slice()).expect("ca keypair");
    let _ = BC::Unconstrained;
    let _ = IsCa::NoCa;

    let subject_spki_der = {
        let mut spki = Vec::with_capacity(44);
        spki.extend_from_slice(&[
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
            0x70, 0x03, 0x21, 0x00,
        ]);
        spki.extend_from_slice(subject_pub);
        spki
    };
    let subject_spki = SubjectPublicKeyInfo::from_der(&subject_spki_der).expect("subject spki");

    let mut params = CertificateParams::new(vec![nid.to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, nid.to_string());
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::URI(nid.try_into().unwrap())];
    params.serial_number = Some(SerialNumber::from_slice(serial));
    let now = SystemTime::now();
    params.not_before = sys_to_offset(now - Duration::from_secs(60));
    params.not_after  = sys_to_offset(now + Duration::from_secs(30 * 24 * 3600));
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    // ★ Deliberately NO EKU extension and NO assurance-level extension.

    let _ = ca_nid; // Issuer DN comes from the issuer cert.
    let cert = params.signed_by(&subject_spki, ca_root, &ca_keypair).expect("signed_by");
    cert.der().to_vec()
}

fn sys_to_offset(t: SystemTime) -> time::OffsetDateTime {
    let d = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    time::OffsetDateTime::from_unix_timestamp(d.as_secs() as i64)
        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}
