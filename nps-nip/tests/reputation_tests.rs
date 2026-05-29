// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// NPS-RFC-0004 — Reputation module tests.

use nps_nip::reputation::{
    sign_entry, verify_entry, IncidentType, InclusionProof, ObservationWindow, ReputationLogClient,
    ReputationLogEntry, Severity, SignedTreeHead,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Helpers shared across Part 4 and Part 5
// ---------------------------------------------------------------------------

fn make_unsigned(subject_nid: &str) -> ReputationLogEntry {
    ReputationLogEntry {
        v: 1,
        log_id: "urn:nps:org:log.test".into(),
        seq: 1,
        timestamp: "2026-01-01T00:00:00Z".into(),
        subject_nid: subject_nid.into(),
        incident: IncidentType::CertRevoked,
        incident_raw: None,
        severity: Severity::Info,
        window: None,
        observation: None,
        evidence_ref: None,
        evidence_sha256: None,
        issuer_nid: "urn:nps:org:issuer.test".into(),
        signature: String::new(),
    }
}

/// Compute the Merkle leaf hash: SHA-256(0x00 || leaf_canonical_json).
///
/// The canonical JSON is a sorted BTreeMap of all entry fields including
/// `signature` (but NOT `incident_raw`), matching the wire snake_case keys.
fn leaf_hash(entry: &ReputationLogEntry) -> Vec<u8> {
    let mut m: BTreeMap<String, serde_json::Value> = BTreeMap::new();

    m.insert("v".into(), serde_json::Value::Number(entry.v.into()));
    m.insert(
        "log_id".into(),
        serde_json::Value::String(entry.log_id.clone()),
    );
    m.insert("seq".into(), serde_json::Value::Number(entry.seq.into()));
    m.insert(
        "timestamp".into(),
        serde_json::Value::String(entry.timestamp.clone()),
    );
    m.insert(
        "subject_nid".into(),
        serde_json::Value::String(entry.subject_nid.clone()),
    );
    m.insert(
        "incident".into(),
        serde_json::to_value(&entry.incident).unwrap(),
    );
    m.insert(
        "severity".into(),
        serde_json::to_value(&entry.severity).unwrap(),
    );
    if let Some(w) = &entry.window {
        m.insert("window".into(), serde_json::to_value(w).unwrap());
    }
    if let Some(obs) = &entry.observation {
        m.insert("observation".into(), obs.clone());
    }
    if let Some(r) = &entry.evidence_ref {
        m.insert("evidence_ref".into(), serde_json::Value::String(r.clone()));
    }
    if let Some(s) = &entry.evidence_sha256 {
        m.insert(
            "evidence_sha256".into(),
            serde_json::Value::String(s.clone()),
        );
    }
    m.insert(
        "issuer_nid".into(),
        serde_json::Value::String(entry.issuer_nid.clone()),
    );
    m.insert(
        "signature".into(),
        serde_json::Value::String(entry.signature.clone()),
    );

    let canonical = serde_json::to_string(&m).unwrap();
    let mut h = Sha256::new();
    h.update(&[0x00u8]);
    h.update(canonical.as_bytes());
    h.finalize().to_vec()
}

/// Compute an internal Merkle node hash: SHA-256(0x01 || left || right).
fn node_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut buf = vec![0x01u8];
    buf.extend_from_slice(left);
    buf.extend_from_slice(right);
    Sha256::digest(&buf).to_vec()
}

fn b64url(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

/// Build a signed ReputationLogEntry with the given subject_nid and a fresh key.
fn make_signed(signing_key: &ed25519_dalek::SigningKey, subject_nid: &str) -> ReputationLogEntry {
    sign_entry(signing_key, make_unsigned(subject_nid))
}

// ---------------------------------------------------------------------------
// Part 1 — IncidentType serde
// ---------------------------------------------------------------------------

#[test]
fn incident_type_wire_roundtrip_cert_revoked() {
    let v = IncidentType::CertRevoked;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"cert-revoked\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::CertRevoked);
}

#[test]
fn incident_type_wire_roundtrip_rate_limit_violation() {
    let v = IncidentType::RateLimitViolation;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"rate-limit-violation\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::RateLimitViolation);
}

#[test]
fn incident_type_wire_roundtrip_tos_violation() {
    let v = IncidentType::TosViolation;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"tos-violation\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::TosViolation);
}

#[test]
fn incident_type_wire_roundtrip_scraping_pattern() {
    let v = IncidentType::ScrapingPattern;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"scraping-pattern\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::ScrapingPattern);
}

#[test]
fn incident_type_wire_roundtrip_payment_default() {
    let v = IncidentType::PaymentDefault;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"payment-default\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::PaymentDefault);
}

#[test]
fn incident_type_wire_roundtrip_contract_dispute() {
    let v = IncidentType::ContractDispute;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"contract-dispute\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::ContractDispute);
}

#[test]
fn incident_type_wire_roundtrip_impersonation_claim() {
    let v = IncidentType::ImpersonationClaim;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"impersonation-claim\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::ImpersonationClaim);
}

#[test]
fn incident_type_wire_roundtrip_positive_attestation() {
    let v = IncidentType::PositiveAttestation;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"positive-attestation\"");
    let back: IncidentType = serde_json::from_str(&json).unwrap();
    assert_eq!(back, IncidentType::PositiveAttestation);
}

#[test]
fn incident_type_unknown_wire_deserializes_as_other() {
    let back: IncidentType = serde_json::from_str("\"completely-unknown-incident\"").unwrap();
    assert_eq!(back, IncidentType::Other);
}

#[test]
fn incident_type_other_serializes_as_other() {
    let v = IncidentType::Other;
    let json = serde_json::to_string(&v).unwrap();
    assert_eq!(json, "\"other\"");
}

// ---------------------------------------------------------------------------
// Part 2 — Severity serde
// ---------------------------------------------------------------------------

#[test]
fn severity_serde_info() {
    let json = serde_json::to_string(&Severity::Info).unwrap();
    assert_eq!(json, "\"info\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Info);
}

#[test]
fn severity_serde_minor() {
    let json = serde_json::to_string(&Severity::Minor).unwrap();
    assert_eq!(json, "\"minor\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Minor);
}

#[test]
fn severity_serde_moderate() {
    let json = serde_json::to_string(&Severity::Moderate).unwrap();
    assert_eq!(json, "\"moderate\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Moderate);
}

#[test]
fn severity_serde_major() {
    let json = serde_json::to_string(&Severity::Major).unwrap();
    assert_eq!(json, "\"major\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Major);
}

#[test]
fn severity_serde_critical() {
    let json = serde_json::to_string(&Severity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
    let back: Severity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, Severity::Critical);
}

#[test]
fn severity_ordering() {
    assert!(Severity::Info < Severity::Minor);
    assert!(Severity::Minor < Severity::Moderate);
    assert!(Severity::Moderate < Severity::Major);
    assert!(Severity::Major < Severity::Critical);
    // Transitive
    assert!(Severity::Info < Severity::Critical);
}

#[test]
fn severity_unknown_wire_is_error() {
    let result: Result<Severity, _> = serde_json::from_str("\"unknown-level\"");
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Part 3 — ReputationLogEntry JSON round-trip
// ---------------------------------------------------------------------------

#[test]
fn entry_serializes_to_snake_case_keys() {
    let entry = ReputationLogEntry {
        v: 1,
        log_id: "urn:nps:org:log.test".into(),
        seq: 42,
        timestamp: "2026-01-01T00:00:00Z".into(),
        subject_nid: "urn:nps:node:subject:1".into(),
        incident: IncidentType::TosViolation,
        incident_raw: None,
        severity: Severity::Moderate,
        window: None,
        observation: None,
        evidence_ref: None,
        evidence_sha256: None,
        issuer_nid: "urn:nps:org:issuer.test".into(),
        signature: "ed25519:abc".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    // Snake-case field names must be present
    assert!(json.contains("\"log_id\""));
    assert!(json.contains("\"subject_nid\""));
    assert!(json.contains("\"issuer_nid\""));
    assert!(json.contains("\"tos-violation\""));
    // incident_raw is skipped
    assert!(!json.contains("incident_raw"));
}

#[test]
fn entry_optional_fields_omitted_when_none() {
    let entry = ReputationLogEntry {
        v: 1,
        log_id: "urn:nps:org:log.test".into(),
        seq: 1,
        timestamp: "2026-01-01T00:00:00Z".into(),
        subject_nid: "urn:nps:node:subject:1".into(),
        incident: IncidentType::CertRevoked,
        incident_raw: None,
        severity: Severity::Info,
        window: None,
        observation: None,
        evidence_ref: None,
        evidence_sha256: None,
        issuer_nid: "urn:nps:org:issuer.test".into(),
        signature: String::new(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(!json.contains("\"window\""));
    assert!(!json.contains("\"observation\""));
    assert!(!json.contains("\"evidence_ref\""));
    assert!(!json.contains("\"evidence_sha256\""));
}

#[test]
fn entry_full_roundtrip_preserves_all_fields() {
    let entry = ReputationLogEntry {
        v: 1,
        log_id: "urn:nps:org:log.test".into(),
        seq: 99,
        timestamp: "2026-06-15T12:00:00Z".into(),
        subject_nid: "urn:nps:node:alpha:1".into(),
        incident: IncidentType::PaymentDefault,
        incident_raw: None,
        severity: Severity::Major,
        window: Some(ObservationWindow {
            start: "2026-01-01T00:00:00Z".into(),
            end: "2026-06-01T00:00:00Z".into(),
        }),
        observation: Some(serde_json::json!({"count": 3})),
        evidence_ref: Some("https://example.com/evidence/123".into()),
        evidence_sha256: Some("abc123def456".into()),
        issuer_nid: "urn:nps:org:issuer.test".into(),
        signature: "ed25519:dummysig".into(),
    };

    let json = serde_json::to_string(&entry).unwrap();
    let back: ReputationLogEntry = serde_json::from_str(&json).unwrap();

    assert_eq!(back.v, entry.v);
    assert_eq!(back.log_id, entry.log_id);
    assert_eq!(back.seq, entry.seq);
    assert_eq!(back.timestamp, entry.timestamp);
    assert_eq!(back.subject_nid, entry.subject_nid);
    assert_eq!(back.incident, entry.incident);
    assert_eq!(back.severity, entry.severity);
    assert_eq!(back.issuer_nid, entry.issuer_nid);
    assert_eq!(back.signature, entry.signature);
    assert_eq!(back.evidence_ref, entry.evidence_ref);
    assert_eq!(back.evidence_sha256, entry.evidence_sha256);

    let w = back.window.unwrap();
    assert_eq!(w.start, "2026-01-01T00:00:00Z");
    assert_eq!(w.end, "2026-06-01T00:00:00Z");

    let obs = back.observation.unwrap();
    assert_eq!(obs["count"], 3);
}

// ---------------------------------------------------------------------------
// Part 4 — sign_entry / verify_entry
// ---------------------------------------------------------------------------

#[test]
fn sign_and_verify_roundtrip() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let entry = sign_entry(&signing_key, make_unsigned("urn:nps:node:subject:1"));

    assert!(!entry.signature.is_empty());
    assert!(verify_entry(&signing_key.verifying_key(), &entry));
}

#[test]
fn verify_rejects_tampered_subject_nid() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let mut entry = sign_entry(&signing_key, make_unsigned("urn:nps:node:honest:1"));

    // Tamper after signing
    entry.subject_nid = "urn:nps:node:attacker:1".into();

    assert!(!verify_entry(&signing_key.verifying_key(), &entry));
}

#[test]
fn verify_rejects_wrong_key() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let key_a = SigningKey::generate(&mut OsRng);
    let key_b = SigningKey::generate(&mut OsRng);

    let entry = sign_entry(&key_a, make_unsigned("urn:nps:node:subject:1"));

    // Verify with a different key — must fail
    assert!(!verify_entry(&key_b.verifying_key(), &entry));
}

#[test]
fn sign_is_deterministic() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let signing_key = SigningKey::generate(&mut OsRng);
    let entry_a = sign_entry(&signing_key, make_unsigned("urn:nps:node:subject:1"));
    let entry_b = sign_entry(&signing_key, make_unsigned("urn:nps:node:subject:1"));

    // ed25519 is deterministic — identical inputs must produce identical signatures
    assert_eq!(entry_a.signature, entry_b.signature);
}

// ---------------------------------------------------------------------------
// Part 5 — verify_inclusion (Merkle)
// ---------------------------------------------------------------------------

/// Build an InclusionProof and SignedTreeHead for a single-entry tree.
///
/// For a 1-leaf tree: root == leaf_hash, audit_path is empty.
fn proof_for_single(entry: &ReputationLogEntry) -> (InclusionProof, SignedTreeHead) {
    let lh = leaf_hash(entry);
    let root = b64url(&lh);
    let proof = InclusionProof {
        seq: entry.seq,
        leaf_index: 0,
        tree_size: 1,
        leaf_hash: root.clone(),
        audit_path: vec![],
    };
    let sth = SignedTreeHead {
        log_id: entry.log_id.clone(),
        tree_size: 1,
        timestamp: entry.timestamp.clone(),
        sha256_root_hash: root,
        signature: String::new(),
    };
    (proof, sth)
}

/// Build proofs/STH for a 2-leaf tree: entries[0] and entries[1].
///
/// Tree layout (RFC 9162):
///   root = node_hash(leaf0, leaf1)
///   leaf_index 0: audit_path = [leaf1]
///   leaf_index 1: audit_path = [leaf0]
fn proofs_for_two(entries: &[ReputationLogEntry; 2]) -> (Vec<InclusionProof>, SignedTreeHead) {
    let lh: Vec<Vec<u8>> = entries.iter().map(leaf_hash).collect();
    let root = node_hash(&lh[0], &lh[1]);
    let root_b64 = b64url(&root);

    let proofs = vec![
        InclusionProof {
            seq: entries[0].seq,
            leaf_index: 0,
            tree_size: 2,
            leaf_hash: b64url(&lh[0]),
            audit_path: vec![b64url(&lh[1])],
        },
        InclusionProof {
            seq: entries[1].seq,
            leaf_index: 1,
            tree_size: 2,
            leaf_hash: b64url(&lh[1]),
            audit_path: vec![b64url(&lh[0])],
        },
    ];
    let sth = SignedTreeHead {
        log_id: entries[0].log_id.clone(),
        tree_size: 2,
        timestamp: entries[0].timestamp.clone(),
        sha256_root_hash: root_b64,
        signature: String::new(),
    };
    (proofs, sth)
}

/// Build proofs/STH for a 4-leaf tree.
///
/// Tree layout:
///   level 0 (leaves):  L0  L1  L2  L3
///   level 1 (nodes):   N01 = node(L0,L1)   N23 = node(L2,L3)
///   root:              node(N01, N23)
///
/// Audit paths (RFC 9162 §2.1.3.2, leaf_index bit-walk):
///   idx 0 (bits 0,0): path = [L1, N23]
///   idx 1 (bits 1,0): path = [L0, N23]
///   idx 2 (bits 0,1): path = [L3, N01]
///   idx 3 (bits 1,1): path = [L2, N01]
fn proofs_for_four(entries: &[ReputationLogEntry; 4]) -> (Vec<InclusionProof>, SignedTreeHead) {
    let lh: Vec<Vec<u8>> = entries.iter().map(leaf_hash).collect();
    let n01 = node_hash(&lh[0], &lh[1]);
    let n23 = node_hash(&lh[2], &lh[3]);
    let root = node_hash(&n01, &n23);
    let root_b64 = b64url(&root);

    let proofs = vec![
        InclusionProof {
            seq: entries[0].seq,
            leaf_index: 0,
            tree_size: 4,
            leaf_hash: b64url(&lh[0]),
            audit_path: vec![b64url(&lh[1]), b64url(&n23)],
        },
        InclusionProof {
            seq: entries[1].seq,
            leaf_index: 1,
            tree_size: 4,
            leaf_hash: b64url(&lh[1]),
            audit_path: vec![b64url(&lh[0]), b64url(&n23)],
        },
        InclusionProof {
            seq: entries[2].seq,
            leaf_index: 2,
            tree_size: 4,
            leaf_hash: b64url(&lh[2]),
            audit_path: vec![b64url(&lh[3]), b64url(&n01)],
        },
        InclusionProof {
            seq: entries[3].seq,
            leaf_index: 3,
            tree_size: 4,
            leaf_hash: b64url(&lh[3]),
            audit_path: vec![b64url(&lh[2]), b64url(&n01)],
        },
    ];
    let sth = SignedTreeHead {
        log_id: entries[0].log_id.clone(),
        tree_size: 4,
        timestamp: entries[0].timestamp.clone(),
        sha256_root_hash: root_b64,
        signature: String::new(),
    };
    (proofs, sth)
}

#[test]
fn verify_inclusion_single_leaf() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let entry = make_signed(&sk, "urn:nps:node:subject:1");
    let (proof, sth) = proof_for_single(&entry);
    assert!(ReputationLogClient::verify_inclusion(&proof, &sth, &entry));
}

#[test]
fn verify_inclusion_two_leaf_tree() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let mut e0 = make_signed(&sk, "urn:nps:node:subject:0");
    e0.seq = 0;
    let mut e1 = make_signed(&sk, "urn:nps:node:subject:1");
    e1.seq = 1;
    let entries = [e0, e1];
    let (proofs, sth) = proofs_for_two(&entries);

    assert!(ReputationLogClient::verify_inclusion(
        &proofs[0],
        &sth,
        &entries[0]
    ));
    assert!(ReputationLogClient::verify_inclusion(
        &proofs[1],
        &sth,
        &entries[1]
    ));
}

#[test]
fn verify_inclusion_four_leaf_tree() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let make_entry = |seq: u64, nid: &str| {
        let mut e = make_signed(&sk, nid);
        e.seq = seq;
        e
    };

    let entries = [
        make_entry(0, "urn:nps:node:subject:0"),
        make_entry(1, "urn:nps:node:subject:1"),
        make_entry(2, "urn:nps:node:subject:2"),
        make_entry(3, "urn:nps:node:subject:3"),
    ];
    let (proofs, sth) = proofs_for_four(&entries);

    for i in 0..4 {
        assert!(
            ReputationLogClient::verify_inclusion(&proofs[i], &sth, &entries[i]),
            "leaf {i} failed verification"
        );
    }
}

#[test]
fn verify_inclusion_false_on_tampered_entry() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let entry = make_signed(&sk, "urn:nps:node:honest:1");
    let (proof, sth) = proof_for_single(&entry);

    // Tamper with the entry after building the proof
    let mut tampered = entry.clone();
    tampered.subject_nid = "urn:nps:node:attacker:1".into();

    assert!(!ReputationLogClient::verify_inclusion(
        &proof, &sth, &tampered
    ));
}

#[test]
fn verify_inclusion_false_on_wrong_root() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let entry = make_signed(&sk, "urn:nps:node:subject:1");
    let (proof, mut sth) = proof_for_single(&entry);

    // Corrupt the root hash in the STH
    sth.sha256_root_hash = b64url(&[0xffu8; 32]);

    assert!(!ReputationLogClient::verify_inclusion(&proof, &sth, &entry));
}

#[test]
fn verify_inclusion_false_on_wrong_leaf_hash() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let entry = make_signed(&sk, "urn:nps:node:subject:1");
    let (mut proof, sth) = proof_for_single(&entry);

    // Corrupt the leaf_hash in the proof
    proof.leaf_hash = b64url(&[0xaau8; 32]);

    assert!(!ReputationLogClient::verify_inclusion(&proof, &sth, &entry));
}

#[test]
fn verify_inclusion_false_on_corrupted_audit_path() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let sk = SigningKey::generate(&mut OsRng);
    let mut e0 = make_signed(&sk, "urn:nps:node:subject:0");
    e0.seq = 0;
    let mut e1 = make_signed(&sk, "urn:nps:node:subject:1");
    e1.seq = 1;
    let entries = [e0, e1];
    let (mut proofs, sth) = proofs_for_two(&entries);

    // Corrupt the sibling hash in the audit path for leaf 0
    proofs[0].audit_path[0] = b64url(&[0xbbu8; 32]);

    assert!(!ReputationLogClient::verify_inclusion(
        &proofs[0],
        &sth,
        &entries[0]
    ));
}
