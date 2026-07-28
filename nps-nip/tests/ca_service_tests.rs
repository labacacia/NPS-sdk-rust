// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// NIP CA service library + RA tier tests (parity with .NET NPS.NIP.Ca).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use time::{Duration, OffsetDateTime};

use nps_nip::ca::{
    build_flattened_jws, ca_verify, create_enrollment_policy, decode_public_key,
    BootstrapTokenStore, CaRequest, EnrollmentOutcome, EnrollmentRequest, EnrollmentTier,
    InMemoryBootstrapTokenStore, InMemoryNipCaStore, InMemoryPendingStore, IssueSessionParams,
    NipCaCertStore, NipCaOptions, NipCaRouter, NipCaService, PendingStore, RegisterWithRaError,
};
use nps_nip::error_codes;

const CA_NID: &str = "urn:nps:org:ca.example.com";
const BASE_URL: &str = "https://ca.example.com";

fn ca_key() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}

fn pub_key(seed: u8) -> (SigningKey, String) {
    let sk = SigningKey::from_bytes(&[seed; 32]);
    let vk = sk.verifying_key();
    (sk, format!("ed25519:{}", B64URL.encode(vk.as_bytes())))
}

fn service() -> NipCaService<InMemoryNipCaStore> {
    NipCaService::new(
        NipCaOptions::new(CA_NID, BASE_URL),
        InMemoryNipCaStore::new(),
        ca_key(),
    )
}

fn caps(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

// ── register → verify + signature ─────────────────────────────────────────────

#[test]
fn register_then_verify_and_signature_valid() {
    let ca = service();
    let (_, pk) = pub_key(1);
    let frame = ca
        .register("agent", "alice", &pk, &caps(&["nwp:query"]), "{}", None)
        .expect("register");

    assert_eq!(frame.nid, "urn:nps:agent:ca.example.com:alice");
    assert_eq!(frame.issued_by.as_deref(), Some(CA_NID));
    assert!(frame.serial.is_some());

    // Verify the CA signature over the canonical signed payload.
    let sig = frame.signature.clone().unwrap();
    let mut payload = serde_json::Map::new();
    payload.insert("capabilities".into(), json!(frame.capabilities));
    payload.insert("expires_at".into(), json!(frame.expires_at));
    payload.insert("frame".into(), json!("0x20"));
    payload.insert("issued_at".into(), json!(frame.issued_at));
    payload.insert("issued_by".into(), json!(frame.issued_by));
    payload.insert("nid".into(), json!(frame.nid));
    payload.insert("pub_key".into(), json!(frame.pub_key));
    payload.insert("scope".into(), frame.scope.clone().unwrap());
    payload.insert("serial".into(), json!(frame.serial));
    let ca_vk = decode_public_key(&ca.get_ca_public_key()).unwrap();
    assert!(ca_verify(&ca_vk, &Value::Object(payload), &sig));

    let r = ca.verify(&frame.nid);
    assert!(r.valid, "expected valid, got {:?}", r.error_code);
}

#[test]
fn duplicate_nid_rejected() {
    let ca = service();
    let (_, pk) = pub_key(1);
    ca.register("agent", "bob", &pk, &caps(&[]), "{}", None)
        .unwrap();
    let err = ca
        .register("agent", "bob", &pk, &caps(&[]), "{}", None)
        .unwrap_err();
    assert_eq!(err.code, error_codes::CA_NID_ALREADY_EXISTS);
}

#[test]
fn verify_missing_nid_not_found() {
    let ca = service();
    let r = ca.verify("urn:nps:agent:ca.example.com:ghost");
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CA_NID_NOT_FOUND));
}

// ── renewal window ────────────────────────────────────────────────────────────

#[test]
fn renew_too_early_then_allowed() {
    // Agent validity 30d, renewal window 7d. Fresh cert can't renew.
    let ca = service();
    let (_, pk) = pub_key(2);
    ca.register("agent", "carol", &pk, &caps(&[]), "{}", None)
        .unwrap();
    let nid = "urn:nps:agent:ca.example.com:carol";
    let err = ca.renew(nid).unwrap_err();
    assert_eq!(err.code, error_codes::CA_RENEWAL_TOO_EARLY);

    // With a 1-day validity + 7-day window, we're already inside the window.
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.agent_cert_validity_days = 1;
    let ca2 = NipCaService::new(opts, InMemoryNipCaStore::new(), ca_key());
    ca2.register("agent", "dave", &pk, &caps(&[]), "{}", None)
        .unwrap();
    let frame = ca2
        .renew("urn:nps:agent:ca.example.com:dave")
        .expect("renew");
    assert!(frame.serial.is_some());
}

// ── revoke + cascade ──────────────────────────────────────────────────────────

#[test]
fn revoke_agent_then_verify_revoked() {
    let ca = service();
    let (_, pk) = pub_key(3);
    ca.register("agent", "eve", &pk, &caps(&[]), "{}", None)
        .unwrap();
    let nid = "urn:nps:agent:ca.example.com:eve";
    let rf = ca.revoke(nid, "key_compromise").expect("revoke");
    assert_eq!(rf.target_nid, nid);
    assert_eq!(rf.reason, "key_compromise");
    assert!(!rf.signature.is_empty());

    let r = ca.verify(nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));

    // CRL now contains the entry.
    assert_eq!(ca.get_crl().len(), 1);
}

#[test]
fn revoke_group_cascades_to_sessions() {
    let ca = service();
    let (_, gpk) = pub_key(4);
    let group = ca
        .register_group(
            Some("group-orch"),
            &gpk,
            &caps(&["nwp:query", "nwp:stream"]),
            "{}",
            Some("user-1"),
            None,
            None,
        )
        .expect("register group");
    let group_nid = group.nid.clone();

    let (_, spk) = pub_key(5);
    let session = ca
        .issue_session(&group_nid, &spk, IssueSessionParams::default())
        .expect("issue session");
    let session_nid = session.nid.clone();

    // Session verifies before revocation.
    assert!(ca.verify(&session_nid).valid);

    // Revoke the group → cascades to the session (its own revoked_at is set
    // with reason parent_revoked, so verify reports CERT-REVOKED first).
    ca.revoke(&group_nid, "cessation_of_operation")
        .expect("revoke group");
    let r = ca.verify(&session_nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_REVOKED));

    // The cascaded child record carries the parent_revoked reason.
    let child = ca.get_cert(&session_nid).unwrap();
    assert_eq!(child.revoke_reason.as_deref(), Some("parent_revoked"));

    // Both group and session appear in the CRL.
    assert_eq!(ca.get_crl().len(), 2);
}

#[test]
fn verify_session_chain_rejects_revoked_parent_without_cascade() {
    // Defense-in-depth: even if a child record was not cascade-revoked, the
    // §7 step 3a chain check rejects a session whose parent is revoked.
    let ca = service();
    let (_, gpk) = pub_key(40);
    let group = ca
        .register_group(
            Some("group-chain"),
            &gpk,
            &caps(&["a"]),
            "{}",
            None,
            None,
            None,
        )
        .unwrap();
    let group_nid = group.nid.clone();
    let (_, spk) = pub_key(41);
    let session = ca
        .issue_session(&group_nid, &spk, IssueSessionParams::default())
        .unwrap();

    // Revoke only the parent record directly in the store (no cascade).
    assert!(ca
        .store()
        .revoke(&group_nid, "key_compromise", OffsetDateTime::now_utc()));

    let r = ca.verify(&session.nid);
    assert!(!r.valid);
    assert_eq!(r.error_code, Some(error_codes::CERT_PARENT_REVOKED));
}

// ── group register + issue-session (clamp + subset) ───────────────────────────

#[test]
fn issue_session_clamps_and_enforces_subset() {
    let ca = service();
    let (_, gpk) = pub_key(6);
    let group = ca
        .register_group(
            None,
            &gpk,
            &caps(&["a", "b"]),
            r#"{"nodes":["x"]}"#,
            None,
            None,
            None,
        )
        .expect("group");
    assert!(group.nid.contains(":agent:"));
    assert!(group.nid.contains(":group-"));
    let group_nid = group.nid.clone();

    let (_, spk) = pub_key(7);

    // Validity below the 60s minimum is rejected.
    let too_short = ca.issue_session(
        &group_nid,
        &spk,
        IssueSessionParams {
            validity: Some(Duration::seconds(10)),
            ..Default::default()
        },
    );
    assert_eq!(
        too_short.unwrap_err().code,
        error_codes::CA_SESSION_VALIDITY_INVALID
    );

    // Validity above 24h is rejected.
    let too_long = ca.issue_session(
        &group_nid,
        &spk,
        IssueSessionParams {
            validity: Some(Duration::hours(48)),
            ..Default::default()
        },
    );
    assert_eq!(
        too_long.unwrap_err().code,
        error_codes::CA_SESSION_VALIDITY_INVALID
    );

    // Capability expansion beyond the group is denied.
    let expanded = ca.issue_session(
        &group_nid,
        &spk,
        IssueSessionParams {
            capabilities: Some(caps(&["a", "c"])),
            ..Default::default()
        },
    );
    assert_eq!(
        expanded.unwrap_err().code,
        error_codes::CA_SCOPE_EXPANSION_DENIED
    );

    // A valid subset session inherits scope + subset caps.
    let ok = ca
        .issue_session(
            &group_nid,
            &spk,
            IssueSessionParams {
                capabilities: Some(caps(&["a"])),
                ..Default::default()
            },
        )
        .expect("subset session");
    assert_eq!(ok.capabilities, caps(&["a"]));
    assert_eq!(ok.scope, Some(json!({"nodes":["x"]})));
}

#[test]
fn issue_session_under_non_group_rejected() {
    let ca = service();
    let (_, pk) = pub_key(8);
    ca.register("agent", "plain", &pk, &caps(&[]), "{}", None)
        .unwrap();
    let (_, spk) = pub_key(9);
    let err = ca
        .issue_session(
            "urn:nps:agent:ca.example.com:plain",
            &spk,
            IssueSessionParams::default(),
        )
        .unwrap_err();
    assert_eq!(err.code, error_codes::CA_PARENT_NOT_GROUP);
}

// ── RA tiers ──────────────────────────────────────────────────────────────────

#[test]
fn ra_allowlist_admits_and_denies() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::Allowlist;
    opts.enrollment_allowlist_patterns = vec!["svc-*".into()];
    let policy = create_enrollment_policy(&opts, None, None).unwrap();

    let admit = EnrollmentRequest {
        identifier: "svc-a",
        ..base_req()
    };
    assert!(matches!(policy.check(&admit), EnrollmentOutcome::Admit));

    let denied = EnrollmentRequest {
        identifier: "other",
        ..base_req()
    };
    match policy.check(&denied) {
        EnrollmentOutcome::Deny(e) => assert_eq!(e.code, error_codes::RA_NID_NOT_ALLOWED),
        other => panic!("expected deny, got {other:?}"),
    }
}

fn base_req<'a>() -> EnrollmentRequest<'a> {
    EnrollmentRequest {
        entity_type: "agent",
        identifier: "svc-a",
        pub_key: "ed25519:x",
        capabilities: &[],
        scope_json: "{}",
        metadata_json: None,
        enrollment_token: None,
    }
}

#[test]
fn ra_bootstrap_token_tier() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::BootstrapToken;
    let store = InMemoryBootstrapTokenStore::new();
    let token = store.create(
        Some("ci".into()),
        OffsetDateTime::now_utc() + Duration::hours(1),
    );

    let policy = create_enrollment_policy(&opts, Some(&store), None).unwrap();

    // Missing token → invalid.
    let missing = EnrollmentRequest {
        enrollment_token: None,
        ..base_req()
    };
    match policy.check(&missing) {
        EnrollmentOutcome::Deny(e) => assert_eq!(e.code, error_codes::RA_TOKEN_INVALID),
        o => panic!("expected deny, got {o:?}"),
    }

    // Valid token → admit (single use).
    let good = EnrollmentRequest {
        enrollment_token: Some(&token),
        ..base_req()
    };
    assert!(matches!(policy.check(&good), EnrollmentOutcome::Admit));

    // Second use of the same token → expired/consumed.
    let reuse = EnrollmentRequest {
        enrollment_token: Some(&token),
        ..base_req()
    };
    match policy.check(&reuse) {
        EnrollmentOutcome::Deny(e) => assert_eq!(e.code, error_codes::RA_TOKEN_EXPIRED),
        o => panic!("expected deny, got {o:?}"),
    }
}

#[test]
fn ra_pending_queue_tier() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::PendingQueue;
    let store = InMemoryPendingStore::new();
    let policy = create_enrollment_policy(&opts, None, Some(&store)).unwrap();

    match policy.check(&base_req()) {
        EnrollmentOutcome::Pending(p) => assert!(!p.pending_id.is_empty()),
        o => panic!("expected pending, got {o:?}"),
    }
    assert_eq!(store.pending_count(), 1);
}

#[test]
fn register_with_ra_pending_surfaces_error() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::PendingQueue;
    let store = InMemoryPendingStore::new();
    let policy = create_enrollment_policy(&opts, None, Some(&store)).unwrap();
    let ca = NipCaService::new(opts, InMemoryNipCaStore::new(), ca_key());
    let (_, pk) = pub_key(10);

    let res = ca.register_with_ra(
        "agent",
        "queued-1",
        &pk,
        &caps(&[]),
        "{}",
        None,
        None,
        policy.as_ref(),
    );
    match res {
        Err(RegisterWithRaError::Pending(p)) => assert!(!p.pending_id.is_empty()),
        o => panic!("expected pending, got {o:?}"),
    }
}

// ── group-JWS verify ──────────────────────────────────────────────────────────

#[test]
fn group_jws_roundtrip_verify() {
    let (gsk, _gpk) = pub_key(11);
    let gvk = gsk.verifying_key();
    let payload = r#"{"session_pub_key":"ed25519:zzz","iat":1700000000}"#;
    let jws = build_flattened_jws(&gsk, "urn:nps:agent:ca.example.com:group-x", payload);

    let ok = nps_nip::ca::verify_group_jws(&jws, &gvk).expect("verify");
    assert_eq!(ok.kid, "urn:nps:agent:ca.example.com:group-x");
    assert_eq!(ok.payload_json, payload);

    // Tampered signature → invalid.
    let (wrong, _) = pub_key(12);
    let err = nps_nip::ca::verify_group_jws(&jws, &wrong.verifying_key()).unwrap_err();
    assert_eq!(err, error_codes::CA_JWS_INVALID);
}

// ── router endpoints (handler-direct) ─────────────────────────────────────────

#[test]
fn router_register_and_verify_and_crl() {
    let ca = service();
    let opts = NipCaOptions::new(CA_NID, BASE_URL);
    let policy = create_enrollment_policy(&opts, None, None).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, None);

    let (_, pk) = pub_key(20);
    let body =
        json!({ "identifier": "router-agent", "pub_key": pk, "capabilities": ["nwp:query"] });
    let resp = router.handle(&CaRequest::new("POST", "/v1/agents/register").with_json(&body));
    assert_eq!(resp.status, 201, "body={:?}", resp.json_value());
    let nid = resp.json_value().unwrap()["nid"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(nid, "urn:nps:agent:ca.example.com:router-agent");

    // Verify via OCSP endpoint.
    let vpath = format!("/v1/agents/{nid}/verify");
    let vresp = router.handle(&CaRequest::new("GET", &vpath));
    assert_eq!(vresp.status, 200);
    assert_eq!(vresp.json_value().unwrap()["valid"], json!(true));

    // Duplicate → 409.
    let dup = router.handle(&CaRequest::new("POST", "/v1/agents/register").with_json(&body));
    assert_eq!(dup.status, 409);
    assert_eq!(
        dup.json_value().unwrap()["error_code"],
        json!(error_codes::CA_NID_ALREADY_EXISTS)
    );

    // Revoke → then CRL has an entry + is signed.
    let rev = router.handle(
        &CaRequest::new("POST", format!("/v1/agents/{nid}/revoke"))
            .with_json(&json!({ "reason": "superseded" })),
    );
    assert_eq!(rev.status, 200);

    let crl = router.handle(&CaRequest::new("GET", "/v1/crl"));
    assert_eq!(crl.status, 200);
    let crl_body = crl.json_value().unwrap();
    assert!(crl_body["signature"].is_string());
    assert_eq!(crl_body["entries"].as_array().unwrap().len(), 1);
}

#[test]
fn router_discovery_and_ca_cert() {
    let ca = service();
    let opts = NipCaOptions::new(CA_NID, BASE_URL);
    let policy = create_enrollment_policy(&opts, None, None).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, None);

    let disc = router.handle(&CaRequest::new("GET", "/.well-known/nps-ca"));
    assert_eq!(disc.status, 200);
    let d = disc.json_value().unwrap();
    assert_eq!(d["issuer"], json!(CA_NID));
    assert!(d["public_key"].as_str().unwrap().starts_with("ed25519:"));
    assert!(d["capabilities"]
        .as_array()
        .unwrap()
        .contains(&json!("ra-tier-1")));

    let cert = router.handle(&CaRequest::new("GET", "/v1/ca/cert"));
    assert_eq!(cert.status, 200);
    assert_eq!(cert.json_value().unwrap()["algorithm"], json!("ed25519"));
}

#[test]
fn router_operator_auth_gate() {
    let ca = {
        let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
        opts.operator_api_key = Some("secret-key".into());
        NipCaService::new(opts, InMemoryNipCaStore::new(), ca_key())
    };
    let opts = ca.options().clone();
    let policy = create_enrollment_policy(&opts, None, None).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, None);

    let (_, pk) = pub_key(21);
    let body = json!({ "identifier": "auth-agent", "pub_key": pk });

    // No token → 401.
    let unauth = router.handle(&CaRequest::new("POST", "/v1/agents/register").with_json(&body));
    assert_eq!(unauth.status, 401);

    // Correct token → 201.
    let ok = router.handle(
        &CaRequest::new("POST", "/v1/agents/register")
            .with_json(&body)
            .with_header("Authorization", "Bearer secret-key"),
    );
    assert_eq!(ok.status, 201);
}

#[test]
fn router_group_register_and_session_issue_via_jws() {
    let ca = service();
    let opts = NipCaOptions::new(CA_NID, BASE_URL);
    let policy = create_enrollment_policy(&opts, None, None).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, None);

    let (gsk, gpk) = pub_key(22);
    let greq = json!({ "identifier": "group-r", "pub_key": gpk, "capabilities": ["a", "b"] });
    let gresp = router
        .handle(&CaRequest::new("POST", "/v1/orchestrators/groups/register").with_json(&greq));
    assert_eq!(gresp.status, 201, "body={:?}", gresp.json_value());
    let group_nid = gresp.json_value().unwrap()["nid"]
        .as_str()
        .unwrap()
        .to_string();

    // Issue a session via group-JWS (jose+json content type).
    let (_, spk) = pub_key(23);
    let iat = OffsetDateTime::now_utc().unix_timestamp();
    let payload = json!({ "session_pub_key": spk, "iat": iat, "capabilities": ["a"] }).to_string();
    let jws = build_flattened_jws(&gsk, &group_nid, &payload);
    let jws_body = json!({
        "protected": jws.protected,
        "payload": jws.payload,
        "signature": jws.signature,
    });

    let issue = router.handle(
        &CaRequest::new(
            "POST",
            format!("/v1/orchestrators/groups/{group_nid}/sessions/issue"),
        )
        .with_json(&jws_body)
        .with_header("Content-Type", "application/jose+json"),
    );
    assert_eq!(issue.status, 201, "body={:?}", issue.json_value());
    let sframe = issue.json_value().unwrap();
    assert!(sframe["nid"].as_str().unwrap().contains(":session-"));
    assert_eq!(sframe["capabilities"], json!(["a"]));

    // List sessions endpoint.
    let list = router.handle(&CaRequest::new(
        "GET",
        format!("/v1/orchestrators/groups/{group_nid}/sessions"),
    ));
    assert_eq!(list.status, 200);
    assert_eq!(list.json_value().unwrap()["count"], json!(1));
}

#[test]
fn router_session_issue_bad_jws_signature() {
    let ca = service();
    let opts = NipCaOptions::new(CA_NID, BASE_URL);
    let policy = create_enrollment_policy(&opts, None, None).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, None);

    let (_gsk, gpk) = pub_key(24);
    let greq = json!({ "identifier": "group-bad", "pub_key": gpk });
    let gresp = router
        .handle(&CaRequest::new("POST", "/v1/orchestrators/groups/register").with_json(&greq));
    let group_nid = gresp.json_value().unwrap()["nid"]
        .as_str()
        .unwrap()
        .to_string();

    // Sign with the WRONG key.
    let (wrong_sk, _) = pub_key(99);
    let (_, spk) = pub_key(25);
    let iat = OffsetDateTime::now_utc().unix_timestamp();
    let payload = json!({ "session_pub_key": spk, "iat": iat }).to_string();
    let jws = build_flattened_jws(&wrong_sk, &group_nid, &payload);
    let jws_body =
        json!({ "protected": jws.protected, "payload": jws.payload, "signature": jws.signature });

    let issue = router.handle(
        &CaRequest::new(
            "POST",
            format!("/v1/orchestrators/groups/{group_nid}/sessions/issue"),
        )
        .with_json(&jws_body)
        .with_header("Content-Type", "application/jose+json"),
    );
    assert_eq!(issue.status, 401);
    assert_eq!(
        issue.json_value().unwrap()["error_code"],
        json!(error_codes::CA_JWS_INVALID)
    );
}

#[test]
fn router_pending_queue_flow() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::PendingQueue;
    let store = InMemoryPendingStore::new();
    let ca = NipCaService::new(opts.clone(), InMemoryNipCaStore::new(), ca_key());
    let policy = create_enrollment_policy(&opts, None, Some(&store)).unwrap();
    let router = NipCaRouter::new(&ca, policy, None, Some(&store));

    // Register → 202 queued.
    let (_, pk) = pub_key(26);
    let body = json!({ "identifier": "pending-agent", "pub_key": pk });
    let resp = router.handle(&CaRequest::new("POST", "/v1/agents/register").with_json(&body));
    assert_eq!(resp.status, 202);
    let id = resp.json_value().unwrap()["pending_id"]
        .as_str()
        .unwrap()
        .to_string();

    // List pending.
    let list = router.handle(&CaRequest::new("GET", "/v1/enrollment/pending"));
    assert_eq!(list.status, 200);
    assert_eq!(list.json_value().unwrap()["count"], json!(1));

    // Approve → 201 issues the cert.
    let approve = router.handle(&CaRequest::new(
        "POST",
        format!("/v1/enrollment/pending/{id}/approve"),
    ));
    assert_eq!(approve.status, 201, "body={:?}", approve.json_value());
    assert_eq!(
        approve.json_value().unwrap()["nid"],
        json!("urn:nps:agent:ca.example.com:pending-agent")
    );

    // Re-approve → 409 (already approved).
    let again = router.handle(&CaRequest::new(
        "POST",
        format!("/v1/enrollment/pending/{id}/approve"),
    ));
    assert_eq!(again.status, 409);
}

#[test]
fn router_bootstrap_token_endpoint() {
    let mut opts = NipCaOptions::new(CA_NID, BASE_URL);
    opts.enrollment_tier = EnrollmentTier::BootstrapToken;
    let bstore = InMemoryBootstrapTokenStore::new();
    let ca = NipCaService::new(opts.clone(), InMemoryNipCaStore::new(), ca_key());
    let policy = create_enrollment_policy(&opts, Some(&bstore), None).unwrap();
    let router = NipCaRouter::new(&ca, policy, Some(&bstore), None);

    // Create a token.
    let tok = router.handle(
        &CaRequest::new("POST", "/v1/enrollment/tokens").with_json(&json!({ "ttl_seconds": 3600 })),
    );
    assert_eq!(tok.status, 201);
    let raw = tok.json_value().unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(raw.starts_with("nps-bootstrap-"));

    // Register with the token → 201.
    let (_, pk) = pub_key(27);
    let body = json!({ "identifier": "boot-agent", "pub_key": pk });
    let ok = router.handle(
        &CaRequest::new("POST", "/v1/agents/register")
            .with_json(&body)
            .with_header("X-NPS-Enrollment-Token", raw),
    );
    assert_eq!(ok.status, 201, "body={:?}", ok.json_value());

    // Register without a token → 401 RA-TOKEN-INVALID.
    let (_, pk2) = pub_key(28);
    let body2 = json!({ "identifier": "boot-agent-2", "pub_key": pk2 });
    let missing = router.handle(&CaRequest::new("POST", "/v1/agents/register").with_json(&body2));
    assert_eq!(missing.status, 401);
    assert_eq!(
        missing.json_value().unwrap()["error_code"],
        json!(error_codes::RA_TOKEN_INVALID)
    );
}

#[test]
fn register_x509_carries_cert_chain() {
    let ca = service();
    let (_, pk) = pub_key(30);
    let frame = ca
        .register_x509(
            "agent",
            "x509-agent",
            &pk,
            &caps(&["nwp:query"]),
            "{}",
            None,
            None,
        )
        .expect("register x509");
    assert_eq!(
        frame.cert_format.as_deref(),
        Some(nps_nip::cert_format::V2_X509)
    );
    let chain = frame.cert_chain.as_ref().unwrap();
    assert_eq!(chain.len(), 2);
    assert!(ca.verify(&frame.nid).valid);
}
