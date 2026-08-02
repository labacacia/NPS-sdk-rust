// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NIP v0.12 §7.5 Phase-3 enforcement.
//!
//! Ports `tests/NPS.Tests/Nip/NipPhase3EnforcerTests.cs` (brief B Part 1 §6),
//! including the "ports SHOULD additionally add" cases.
//!
//! Fixed clock `NOW = 2026-07-05T12:00:00Z`.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use time::macros::datetime;
use time::OffsetDateTime;

use nps_nip::cert_format::V2_X509;
use nps_nip::error_codes;
use nps_nip::phase3;
use nps_nip::x509::oids::{
    encode_oid_content, ID_NPS_CAPABILITIES_OID, ID_NPS_NODE_ROLES_OID, NID_ASSURANCE_LEVEL_OID,
};
use nps_nip::x509::{self, IssueLeafOptions, IssueRootOptions, LeafRole};
use nps_nip::{IdentFrame, NipIdentVerifier, NipVerifierOptions, NipVerifyContext, ANONYMOUS};

const NOW: OffsetDateTime = datetime!(2026-07-05 12:00:00 UTC);
const NID: &str = "urn:nps:agent:ca.example.com:p3-001";

// ── fixtures ─────────────────────────────────────────────────────────────────

fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// Baseline IdentFrame from the brief.
fn base_frame() -> IdentFrame {
    let mut f = IdentFrame::new(NID.to_string(), "ed25519:AAAA".to_string());
    f.capabilities = strings(&["nwp:query"]);
    f.signature = Some("ed25519:test".into());
    f
}

/// A leaf cert optionally carrying the two `id-nps-*` attestation extensions.
/// `None` OMITS the extension; `Some(&[])` emits it present-but-empty.
fn leaf_der(roles: Option<&[String]>, caps: Option<&[String]>) -> Vec<u8> {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let subject_sk = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now();
    let root = x509::issue_root(IssueRootOptions {
        ca_nid: "urn:nps:org:example.com",
        ca_signing_key: &ca_sk,
        not_before: now - Duration::from_secs(60),
        not_after: now + Duration::from_secs(365 * 24 * 3600),
        serial_number: &[1],
    })
    .expect("issue_root");

    x509::issue_leaf(IssueLeafOptions {
        subject_nid: NID,
        subject_pub_raw: subject_sk.verifying_key().as_bytes(),
        ca_signing_key: &ca_sk,
        ca_root_cert: &root,
        role: LeafRole::Agent,
        assurance_level: ANONYMOUS,
        // NOW-1d .. NOW+30d, as in the .NET fixture.
        not_before: now - Duration::from_secs(24 * 3600),
        not_after: now + Duration::from_secs(30 * 24 * 3600),
        serial_number: &[2],
        attested_node_roles: roles,
        attested_capabilities: caps,
    })
    .expect("issue_leaf")
    .der()
    .to_vec()
}

// ── minimal RFC 6960 staple builder ──────────────────────────────────────────

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    if content.len() < 0x80 {
        v.push(content.len() as u8);
    } else if content.len() < 0x100 {
        v.extend([0x81, content.len() as u8]);
    } else {
        v.extend([0x82, (content.len() >> 8) as u8, (content.len() & 0xFF) as u8]);
    }
    v.extend_from_slice(content);
    v
}

fn gen_time(t: OffsetDateTime) -> Vec<u8> {
    let s = format!(
        "{:04}{:02}{:02}{:02}{:02}{:02}Z",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    );
    tlv(0x18, s.as_bytes())
}

/// Base64url (unpadded) minimal OCSPResponse with the given `nextUpdate`.
fn staple(next_update: OffsetDateTime) -> String {
    let mut single = Vec::new();
    single.extend(tlv(0x30, &[])); // certID
    single.extend(tlv(0x80, &[])); // certStatus [0] good
    single.extend(gen_time(NOW)); // thisUpdate
    single.extend(tlv(0xA0, &gen_time(next_update))); // nextUpdate [0] EXPLICIT
    let responses = tlv(0x30, &tlv(0x30, &single));

    let mut rd = Vec::new();
    rd.extend(tlv(0xA1, &[])); // responderID [1]
    rd.extend(gen_time(NOW)); // producedAt
    rd.extend(responses);
    let basic = tlv(0x30, &tlv(0x30, &rd));

    let mut rb = Vec::new();
    rb.extend(tlv(
        0x06,
        &encode_oid_content(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
    ));
    rb.extend(tlv(0x04, &basic));

    let mut outer = Vec::new();
    outer.extend(tlv(0x0A, &[0x00]));
    outer.extend(tlv(0xA0, &tlv(0x30, &rb)));
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(tlv(0x30, &outer))
}

fn fresh_staple() -> String {
    staple(NOW + time::Duration::hours(6))
}

// ── the 8 .NET scenarios ─────────────────────────────────────────────────────

#[test]
fn subset_claims_with_fresh_staple_pass() {
    let der = leaf_der(
        Some(&strings(&["memory", "anchor"])),
        Some(&strings(&["nwp:query", "nwp:action"])),
    );
    let mut f = base_frame();
    f.node_roles = Some(strings(&["memory"]));
    f.capabilities = strings(&["nwp:query"]);
    f.ocsp_staple = Some(fresh_staple());

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(r.valid, "expected valid, got {:?} {:?}", r.error_code, r.message);
}

#[test]
fn unattested_role_fails_with_node_roles_mismatch() {
    let der = leaf_der(Some(&strings(&["memory"])), None);
    let mut f = base_frame();
    f.node_roles = Some(strings(&["memory", "orchestrator"]));
    f.ocsp_staple = Some(fresh_staple());

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_NODE_ROLES_MISMATCH));
    assert_eq!(r.step_failed, 3);
    assert!(r.message.unwrap().contains("orchestrator"));
}

#[test]
fn unattested_capability_fails_with_capabilities_exceeded() {
    let der = leaf_der(None, Some(&strings(&["nwp:query"])));
    let mut f = base_frame();
    f.capabilities = strings(&["nwp:query", "nop:orchestrate"]);
    f.ocsp_staple = Some(fresh_staple());

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_CAPABILITIES_EXCEEDED));
    assert_eq!(
        error_codes::to_nps_status(error_codes::CERT_CAPABILITIES_EXCEEDED),
        "NPS-AUTH-FORBIDDEN"
    );
    assert!(r.message.unwrap().contains("nop:orchestrate"));
}

#[test]
fn no_extensions_means_attribute_checks_do_not_apply() {
    let der = leaf_der(None, None);
    let mut f = base_frame();
    f.node_roles = Some(strings(&["anything", "at", "all"]));
    f.capabilities = strings(&["whatever:i:like"]);
    f.ocsp_staple = Some(fresh_staple());

    assert!(phase3::enforce(&f, &der, Some(NOW)).valid);
}

#[test]
fn missing_staple_fails() {
    let der = leaf_der(None, None);
    let mut f = base_frame();
    f.ocsp_staple = None;

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::OCSP_STAPLE_EXPIRED));
    assert!(r.message.unwrap().contains("none was supplied"));
}

#[test]
fn expired_staple_fails() {
    let der = leaf_der(None, None);
    let mut f = base_frame();
    f.ocsp_staple = Some(staple(NOW - time::Duration::minutes(1)));

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::OCSP_STAPLE_EXPIRED));
    assert!(r.message.unwrap().contains("elapsed"));
}

#[test]
fn malformed_staple_fails_closed() {
    let der = leaf_der(None, None);
    let mut f = base_frame();
    f.ocsp_staple = Some("bm90LWFuLW9jc3A".into());

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::OCSP_STAPLE_EXPIRED));
}

#[test]
fn utf8_sequence_extension_parses() {
    let der = leaf_der(Some(&strings(&["memory", "anchor"])), None);
    assert_eq!(
        phase3::read_utf8_sequence_extension(&der, ID_NPS_NODE_ROLES_OID),
        Some(strings(&["memory", "anchor"]))
    );
    // Absent extension is None — NOT an empty list.
    assert_eq!(
        phase3::read_utf8_sequence_extension(&der, ID_NPS_CAPABILITIES_OID),
        None
    );
}

// ── "ports SHOULD additionally add" ──────────────────────────────────────────

#[test]
fn malformed_attribute_extension_reads_as_empty_so_any_claim_fails() {
    // Present but not a SEQUENCE OF UTF8String: the strictest reading is `[]`,
    // under which any claim exceeds the attestation. The assurance-level
    // extension (an ENUMERATED) stands in for a malformed attribute value.
    let der = leaf_der(None, None);
    let malformed = phase3::read_utf8_sequence_extension(&der, NID_ASSURANCE_LEVEL_OID);
    assert_eq!(malformed, Some(vec![]), "malformed ⇒ [], never None");
}

#[test]
fn present_but_empty_attestation_rejects_any_claim() {
    let der = leaf_der(Some(&[]), Some(&[]));
    assert_eq!(
        phase3::read_utf8_sequence_extension(&der, ID_NPS_NODE_ROLES_OID),
        Some(vec![])
    );

    let mut f = base_frame();
    f.node_roles = Some(strings(&["memory"]));
    f.ocsp_staple = Some(fresh_staple());
    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_NODE_ROLES_MISMATCH));
}

#[test]
fn next_update_exactly_now_fails() {
    // `<=`, not `<`.
    let der = leaf_der(None, None);
    let mut f = base_frame();
    f.ocsp_staple = Some(staple(NOW));

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::OCSP_STAPLE_EXPIRED));
    assert!(r.message.unwrap().contains("elapsed"));
}

#[test]
fn evaluation_order_is_roles_then_capabilities_then_staple() {
    // Everything wrong at once ⇒ the FIRST row reported is node_roles.
    let der = leaf_der(Some(&strings(&["memory"])), Some(&strings(&["nwp:query"])));
    let mut f = base_frame();
    f.node_roles = Some(strings(&["orchestrator"]));
    f.capabilities = strings(&["nop:orchestrate"]);
    f.ocsp_staple = None;

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert_eq!(r.error_code, Some(error_codes::CERT_NODE_ROLES_MISMATCH));

    // With roles satisfied, capabilities is next — still ahead of the staple.
    f.node_roles = Some(strings(&["memory"]));
    let r = phase3::enforce(&f, &der, Some(NOW));
    assert_eq!(r.error_code, Some(error_codes::CERT_CAPABILITIES_EXCEEDED));

    // With both satisfied, the staple is reached.
    f.capabilities = strings(&["nwp:query"]);
    let r = phase3::enforce(&f, &der, Some(NOW));
    assert_eq!(r.error_code, Some(error_codes::OCSP_STAPLE_EXPIRED));
}

#[test]
fn null_node_roles_is_an_empty_set_and_always_a_subset() {
    let der = leaf_der(Some(&strings(&["memory"])), None);
    let mut f = base_frame();
    f.node_roles = None;
    f.ocsp_staple = Some(fresh_staple());
    assert!(phase3::enforce(&f, &der, Some(NOW)).valid);
}

#[test]
fn comparison_is_ordinal_not_case_insensitive() {
    let der = leaf_der(Some(&strings(&["memory"])), None);
    let mut f = base_frame();
    f.node_roles = Some(strings(&["Memory"]));
    f.ocsp_staple = Some(fresh_staple());

    let r = phase3::enforce(&f, &der, Some(NOW));
    assert!(!r.valid, "ordinal comparison: 'Memory' != 'memory'");
    assert_eq!(r.error_code, Some(error_codes::CERT_NODE_ROLES_MISMATCH));
}

// ── verifier integration (step 3c + scope gate) ──────────────────────────────

fn map(entries: &[(&str, &str)]) -> HashMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

/// Build a full v2-x509 frame whose chain verifies against `root`.
fn v2_frame(
    ca_sk: &SigningKey,
    subject_sk: &SigningKey,
    leaf: &[u8],
    root: &[u8],
    caps: Option<Vec<String>>,
    staple: Option<String>,
) -> IdentFrame {
    let mut f = IdentFrame::new(
        NID.to_string(),
        format!("ed25519:{}", hex::encode(subject_sk.verifying_key().as_bytes())),
    );
    f.capabilities = caps.unwrap_or_default();
    f.ocsp_staple = staple;
    let canonical = nps_nip::verifier::canonical_json(&f.unsigned_dict());
    let sig = ca_sk.sign(canonical.as_bytes());
    f.signature = Some(format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    ));
    f.cert_format = Some(V2_X509.to_string());
    f.cert_chain = Some(vec![
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(leaf),
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(root),
    ]);
    f
}

struct Chain {
    ca_sk: SigningKey,
    subject_sk: SigningKey,
    leaf: Vec<u8>,
    root: Vec<u8>,
}

fn chain(caps: Option<&[String]>) -> Chain {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let subject_sk = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now();
    let root = x509::issue_root(IssueRootOptions {
        ca_nid: "urn:nps:org:example.com",
        ca_signing_key: &ca_sk,
        not_before: now - Duration::from_secs(60),
        not_after: now + Duration::from_secs(365 * 24 * 3600),
        serial_number: &[1],
    })
    .expect("issue_root");
    let leaf = x509::issue_leaf(IssueLeafOptions {
        subject_nid: NID,
        subject_pub_raw: subject_sk.verifying_key().as_bytes(),
        ca_signing_key: &ca_sk,
        ca_root_cert: &root,
        role: LeafRole::Agent,
        assurance_level: ANONYMOUS,
        not_before: now - Duration::from_secs(24 * 3600),
        not_after: now + Duration::from_secs(30 * 24 * 3600),
        serial_number: &[2],
        attested_node_roles: None,
        attested_capabilities: caps,
    })
    .expect("issue_leaf");
    Chain {
        ca_sk,
        subject_sk,
        leaf: leaf.der().to_vec(),
        root: root.der().to_vec(),
    }
}

#[test]
fn phase3_enforcement_defaults_to_false() {
    assert!(!NipVerifierOptions::default().phase3_enforcement);
}

#[tokio::test]
async fn flag_off_means_a_failing_frame_still_verifies_advisory_only() {
    let c = chain(Some(&strings(&["nwp:query"])));
    // Over-claims and carries no staple — would fail every Phase-3 row.
    let f = v2_frame(
        &c.ca_sk,
        &c.subject_sk,
        &c.leaf,
        &c.root,
        Some(strings(&["nwp:query", "nop:orchestrate"])),
        None,
    );
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(
            "urn:nps:org:example.com",
            &format!("ed25519:{}", hex::encode(c.ca_sk.verifying_key().as_bytes())),
        )]),
        trusted_x509_roots_der: vec![c.root.clone()],
        phase3_enforcement: false,
        ..Default::default()
    });
    let r = v
        .verify(&f, "urn:nps:org:example.com", &NipVerifyContext::default())
        .await;
    assert!(r.valid, "phase-3 is advisory when the flag is off: {r:?}");
}

#[tokio::test]
async fn flag_on_makes_the_same_frame_a_hard_failure() {
    let c = chain(Some(&strings(&["nwp:query"])));
    let f = v2_frame(
        &c.ca_sk,
        &c.subject_sk,
        &c.leaf,
        &c.root,
        Some(strings(&["nwp:query", "nop:orchestrate"])),
        Some(fresh_staple()),
    );
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(
            "urn:nps:org:example.com",
            &format!("ed25519:{}", hex::encode(c.ca_sk.verifying_key().as_bytes())),
        )]),
        trusted_x509_roots_der: vec![c.root.clone()],
        phase3_enforcement: true,
        ..Default::default()
    });
    let r = v
        .verify(&f, "urn:nps:org:example.com", &NipVerifyContext::default())
        .await;
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_CAPABILITIES_EXCEEDED));
    assert_eq!(r.step_failed, 3);
}

#[tokio::test]
async fn non_v2_frame_with_the_flag_on_never_reaches_the_enforcer() {
    let c = chain(Some(&strings(&["nwp:query"])));
    let mut f = v2_frame(
        &c.ca_sk,
        &c.subject_sk,
        &c.leaf,
        &c.root,
        Some(strings(&["nwp:query", "nop:orchestrate"])),
        None,
    );
    // v1 / self-declared: cert_format is not "v2-x509".
    f.cert_format = None;
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(
            "urn:nps:org:example.com",
            &format!("ed25519:{}", hex::encode(c.ca_sk.verifying_key().as_bytes())),
        )]),
        trusted_x509_roots_der: vec![c.root.clone()],
        phase3_enforcement: true,
        ..Default::default()
    });
    assert!(
        v.verify(&f, "urn:nps:org:example.com", &NipVerifyContext::default())
            .await
            .valid
    );
}

#[tokio::test]
async fn v1_only_verifier_ignores_cert_chain_even_with_the_flag_on() {
    let c = chain(Some(&strings(&["nwp:query"])));
    let f = v2_frame(
        &c.ca_sk,
        &c.subject_sk,
        &c.leaf,
        &c.root,
        Some(strings(&["nwp:query", "nop:orchestrate"])),
        None,
    );
    // No X.509 trust anchors ⇒ not a v2-aware verifier.
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: map(&[(
            "urn:nps:org:example.com",
            &format!("ed25519:{}", hex::encode(c.ca_sk.verifying_key().as_bytes())),
        )]),
        trusted_x509_roots_der: vec![],
        phase3_enforcement: true,
        ..Default::default()
    });
    assert!(
        v.verify(&f, "urn:nps:org:example.com", &NipVerifyContext::default())
            .await
            .valid
    );
}

#[test]
fn capabilities_is_wire_only_and_not_in_the_signed_body() {
    // Adding `capabilities` to IdentFrame must not change what an existing v1
    // signature covers in this SDK (it mirrors the node_roles treatment).
    let mut f = IdentFrame::new(NID.to_string(), "ed25519:AAAA".to_string());
    let before = nps_nip::verifier::canonical_json(&f.unsigned_dict());
    f.capabilities = strings(&["nwp:query"]);
    let after = nps_nip::verifier::canonical_json(&f.unsigned_dict());
    assert_eq!(before, after);
    assert!(!after.contains("capabilities"));

    // It IS on the wire.
    let d = f.to_dict();
    assert_eq!(d.get("capabilities"), Some(&serde_json::json!(["nwp:query"])));
    let back = IdentFrame::from_dict(&d).unwrap();
    assert_eq!(back.capabilities, strings(&["nwp:query"]));
}
