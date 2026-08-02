// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Rust parallel of the .NET NipIdentVerifier / TrustFrameValidator tests.
//! Exercises the NPS-3 §7 six-step IdentFrame flow (per-step pass/fail),
//! OCSP fail-open vs fail-closed, scope matching, and TrustFrame validation.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde_json::json;
use tiny_http::{Header, Response, Server};

use nps_nip::error_codes;
use nps_nip::{
    nwp_path_matches, validate_trust_frame, IdentFrame, NipCaStore, NipCertRecord,
    NipIdentVerifier, NipIdentVerifyResult, NipRevocationCheck, NipRevocationMode,
    NipVerifierOptions, NipVerifyContext, TrustFrame, TrustFrameValidationContext,
};

// ── Helpers ──────────────────────────────────────────────────────────────────

const CA_NID: &str = "urn:nps:org:ca.example.com";

fn pub_key_str(sk: &SigningKey) -> String {
    format!("ed25519:{}", hex::encode(sk.verifying_key().as_bytes()))
}

fn trusted(sk: &SigningKey) -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(CA_NID.to_string(), pub_key_str(sk));
    m
}

/// Build a fully populated, CA-signed v1 IdentFrame.
fn signed_frame(ca_sk: &SigningKey, expires_at: &str, serial: &str) -> IdentFrame {
    let agent_sk = SigningKey::generate(&mut OsRng);
    let mut frame = IdentFrame::new(
        "urn:nps:agent:ca.example.com:abc".into(),
        pub_key_str(&agent_sk),
    );
    frame.capabilities = vec!["nwp:query".into(), "nwp:stream".into()];
    frame.scope = Some(json!({ "nodes": ["nwp://api.myapp.com/*"] }));
    frame.issued_by = Some(CA_NID.into());
    frame.issued_at = Some("2026-01-01T00:00:00Z".into());
    frame.expires_at = Some(expires_at.into());
    frame.serial = Some(serial.into());

    let canonical = nps_nip::verifier::canonical_json(&frame.unsigned_dict());
    let sig = ca_sk.sign(canonical.as_bytes());
    frame.signature = Some(format!(
        "ed25519:{}",
        base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
    ));
    frame
}

fn far_future() -> String {
    "2099-01-01T00:00:00Z".into()
}

fn opts(ca_sk: &SigningKey) -> NipVerifierOptions {
    NipVerifierOptions {
        trusted_ca_public_keys: trusted(ca_sk),
        ..Default::default()
    }
}

// ── Step 1: Expiry ───────────────────────────────────────────────────────────

#[tokio::test]
async fn step1_expired_cert_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, "2000-01-01T00:00:00Z", "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 1);
    assert_eq!(r.error_code, Some(error_codes::CERT_EXPIRED));
}

#[tokio::test]
async fn step1_as_of_override_makes_valid_cert_expired() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, "2030-01-01T00:00:00Z", "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let ctx = NipVerifyContext {
        as_of: Some(
            time::OffsetDateTime::parse(
                "2031-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339,
            )
            .unwrap(),
        ),
        ..Default::default()
    };
    let r = v.verify(&frame, CA_NID, &ctx).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 1);
}

// ── Step 2: Trusted issuer ───────────────────────────────────────────────────

#[tokio::test]
async fn step2_untrusted_issuer_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    // Verifier trusts nobody.
    let v = NipIdentVerifier::new(NipVerifierOptions::default());
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 2);
    assert_eq!(r.error_code, Some(error_codes::CERT_UNTRUSTED_ISSUER));
}

#[tokio::test]
async fn step2_issued_by_mismatch_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let mut frame = signed_frame(&ca_sk, &far_future(), "0x1");
    frame.issued_by = Some("urn:nps:org:other".into());
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 2);
    assert_eq!(r.error_code, Some(error_codes::CERT_UNTRUSTED_ISSUER));
}

// ── Step 3: Signature ────────────────────────────────────────────────────────

#[tokio::test]
async fn step3_bad_signature_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let mut frame = signed_frame(&ca_sk, &far_future(), "0x1");
    // Tamper a signed field (pub_key is covered by unsigned_dict) after signing.
    frame.pub_key = "ed25519:00".into();
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 3);
    assert_eq!(r.error_code, Some(error_codes::CERT_SIGNATURE_INVALID));
}

// ── Full happy path ──────────────────────────────────────────────────────────

#[tokio::test]
async fn all_steps_pass() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let ctx = NipVerifyContext {
        required_capabilities: vec!["nwp:query".into()],
        target_node_path: Some("nwp://api.myapp.com/products".into()),
        as_of: None,
    };
    let r = v.verify(&frame, CA_NID, &ctx).await;
    assert!(
        r.valid,
        "expected valid; step={} code={:?} msg={:?}",
        r.step_failed, r.error_code, r.message
    );
}

// ── Step 4: Revocation ───────────────────────────────────────────────────────

#[tokio::test]
async fn step4_local_crl_revokes() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x0A3F9C");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        local_revoked_serials: vec!["0x0A3F9C".into()],
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));
}

#[tokio::test]
async fn step4_revocation_callback_rejects() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let cb: NipRevocationCheck = Arc::new(|_frame: &IdentFrame| {
        Box::pin(async {
            Some(NipIdentVerifyResult {
                valid: false,
                step_failed: 4,
                error_code: Some(error_codes::CERT_REVOKED),
                message: Some("callback says revoked".into()),
            })
        }) as Pin<Box<dyn Future<Output = Option<NipIdentVerifyResult>> + Send>>
    });
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        revocation_check: Some(cb),
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));
}

struct RevokedStore;
impl NipCaStore for RevokedStore {
    fn get_by_serial<'a>(
        &'a self,
        serial: &'a str,
    ) -> Pin<Box<dyn Future<Output = Option<NipCertRecord>> + Send + 'a>> {
        let serial = serial.to_string();
        Box::pin(async move {
            Some(NipCertRecord {
                serial,
                revoked_at: Some("2026-06-01T00:00:00Z".into()),
                revoke_reason: Some("key_compromise".into()),
            })
        })
    }
}

#[tokio::test]
async fn step4_store_revokes() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        revocation_store: Some(Arc::new(RevokedStore)),
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));
}

#[tokio::test]
async fn step4_ocsp_valid_passes() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let guard = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let body = r#"{"valid":true}"#;
        let resp = Response::from_string(body)
            .with_header(Header::from_str("Content-Type: application/json").unwrap());
        req.respond(resp).unwrap();
    });

    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        ocsp_url: Some(base),
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(r.valid, "code={:?} msg={:?}", r.error_code, r.message);
    guard.join().unwrap();
}

#[tokio::test]
async fn step4_ocsp_invalid_revokes() {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let base = format!("http://127.0.0.1:{port}");
    let guard = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        let body = r#"{"valid":false,"error_code":"NIP-CERT-REVOKED"}"#;
        let resp = Response::from_string(body)
            .with_header(Header::from_str("Content-Type: application/json").unwrap());
        req.respond(resp).unwrap();
    });

    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        ocsp_url: Some(base),
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));
    guard.join().unwrap();
}

#[tokio::test]
async fn step4_ocsp_transport_failure_fail_closed() {
    // Point at a port nothing is listening on.
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        ocsp_url: Some("http://127.0.0.1:1".into()),
        ocsp_fail_open: false,
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::OCSP_UNAVAILABLE));
}

#[tokio::test]
async fn step4_ocsp_transport_failure_fail_open() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        ocsp_url: Some("http://127.0.0.1:1".into()),
        ocsp_fail_open: true,
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(r.valid, "fail-open should pass; code={:?}", r.error_code);
}

#[tokio::test]
async fn step4_unconfigured_passes_through() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(r.valid);
}

#[tokio::test]
async fn step4_required_without_source_fails_closed() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        revocation_mode: NipRevocationMode::Required,
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 4);
    assert_eq!(r.error_code, Some(error_codes::OCSP_UNAVAILABLE));
}

#[tokio::test]
async fn step4_required_accepts_configured_empty_local_crl() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(NipVerifierOptions {
        trusted_ca_public_keys: trusted(&ca_sk),
        local_crl_configured: true,
        revocation_mode: NipRevocationMode::Required,
        ..Default::default()
    });
    let r = v.verify(&frame, CA_NID, &NipVerifyContext::default()).await;
    assert!(r.valid, "code={:?} msg={:?}", r.error_code, r.message);
}

// ── Step 5: Capabilities ─────────────────────────────────────────────────────

#[tokio::test]
async fn step5_missing_capability_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let ctx = NipVerifyContext {
        required_capabilities: vec!["nwp:admin".into()],
        ..Default::default()
    };
    let r = v.verify(&frame, CA_NID, &ctx).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 5);
    assert_eq!(r.error_code, Some(error_codes::CERT_CAPABILITY_MISSING));
}

// ── Step 6: Scope ────────────────────────────────────────────────────────────

#[tokio::test]
async fn step6_scope_violation_rejected() {
    let ca_sk = SigningKey::generate(&mut OsRng);
    let frame = signed_frame(&ca_sk, &far_future(), "0x1");
    let v = NipIdentVerifier::new(opts(&ca_sk));
    let ctx = NipVerifyContext {
        target_node_path: Some("nwp://other.host/x".into()),
        ..Default::default()
    };
    let r = v.verify(&frame, CA_NID, &ctx).await;
    assert!(!r.valid);
    assert_eq!(r.step_failed, 6);
    assert_eq!(r.error_code, Some(error_codes::CERT_SCOPE_VIOLATION));
}

#[test]
fn nwp_path_matching_rules() {
    // Bare wildcard.
    assert!(nwp_path_matches("*", "nwp://anything/at/all"));
    // Trailing /* prefix at boundary.
    assert!(nwp_path_matches(
        "nwp://api.myapp.com/*",
        "nwp://api.myapp.com/products"
    ));
    assert!(nwp_path_matches(
        "nwp://api.myapp.com/*",
        "nwp://api.myapp.com"
    ));
    // Not a boundary match.
    assert!(!nwp_path_matches(
        "nwp://api.myapp.com/*",
        "nwp://api.myapp.com.evil/x"
    ));
    // Exact, case-insensitive.
    assert!(nwp_path_matches("nwp://Host/A", "nwp://host/a"));
    assert!(!nwp_path_matches("nwp://host/a", "nwp://host/b"));
}

// ── TrustFrameValidator ──────────────────────────────────────────────────────

fn sample_trust_frame() -> TrustFrame {
    TrustFrame {
        grantor_nid: "urn:nps:org:root".into(),
        grantee_ca: "urn:nps:org:sub-ca".into(),
        trust_scope: vec!["nwp:query".into()],
        nodes: vec!["nwp://api.myapp.com/*".into()],
        issued_at: "2026-01-01T00:00:00Z".into(),
        expires_at: "2099-01-01T00:00:00Z".into(),
        serial: "0x1".into(),
        signer_nid: "urn:nps:org:root".into(),
        signature: "ed25519:sig".into(),
    }
}

fn trust_ctx() -> TrustFrameValidationContext {
    TrustFrameValidationContext {
        trusted_grantors: vec!["urn:nps:org:root".into()],
        expected_grantee_ca: "urn:nps:org:sub-ca".into(),
        required_capabilities: vec!["nwp:query".into()],
        target_node_path: Some("nwp://api.myapp.com/products".into()),
        as_of: None,
    }
}

#[test]
fn trust_frame_valid() {
    let r = validate_trust_frame(&sample_trust_frame(), &trust_ctx());
    assert!(r.valid, "code={:?} msg={:?}", r.error_code, r.message);
}

#[test]
fn trust_frame_missing_field_invalid() {
    let mut f = sample_trust_frame();
    f.trust_scope.clear();
    let r = validate_trust_frame(&f, &trust_ctx());
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::TRUST_FRAME_INVALID));
}

#[test]
fn trust_frame_expired() {
    let mut f = sample_trust_frame();
    f.expires_at = "2000-01-01T00:00:00Z".into();
    let r = validate_trust_frame(&f, &trust_ctx());
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::TRUST_FRAME_EXPIRED));
}

#[test]
fn trust_frame_untrusted_grantor() {
    let mut ctx = trust_ctx();
    ctx.trusted_grantors = vec!["urn:nps:org:someone-else".into()];
    let r = validate_trust_frame(&sample_trust_frame(), &ctx);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_UNTRUSTED_ISSUER));
}

#[test]
fn trust_frame_grantee_mismatch() {
    let mut ctx = trust_ctx();
    ctx.expected_grantee_ca = "urn:nps:org:wrong".into();
    let r = validate_trust_frame(&sample_trust_frame(), &ctx);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::TRUST_FRAME_INVALID));
}

#[test]
fn trust_frame_scope_exceeds_grantor() {
    let mut ctx = trust_ctx();
    ctx.required_capabilities = vec!["nwp:admin".into()];
    let r = validate_trust_frame(&sample_trust_frame(), &ctx);
    assert!(!r.valid);
    assert_eq!(r.step_failed, 5);
    assert_eq!(
        r.error_code,
        Some(error_codes::TRUST_FRAME_SCOPE_EXCEEDS_GRANTOR)
    );
}

#[test]
fn trust_frame_node_scope_violation() {
    let mut ctx = trust_ctx();
    ctx.target_node_path = Some("nwp://other.host/x".into());
    let r = validate_trust_frame(&sample_trust_frame(), &ctx);
    assert!(!r.valid);
    assert_eq!(r.step_failed, 6);
    assert_eq!(r.error_code, Some(error_codes::CERT_SCOPE_VIOLATION));
}
