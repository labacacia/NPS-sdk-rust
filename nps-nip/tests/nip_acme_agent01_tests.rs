// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Rust parallel of .NET / Java / Python / TypeScript / Go AcmeAgent01Tests
//! per NPS-RFC-0002 §4.4. End-to-end agent-01 round-trip plus
//! tampered-signature negative path.

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::time::{Duration, SystemTime};

use nps_nip::acme::{
    jws, AcmeClient, AcmeServer, AcmeServerOptions,
};
use nps_nip::acme::messages::{
    Authorization, ChallengeRespondPayload, Directory, NewAccountPayload,
    NewOrderPayload, Order, ProblemDetail, Identifier,
};
use nps_nip::acme::wire;
use nps_nip::error_codes;
use nps_nip::x509::{self, IssueRootOptions};

struct Fixture {
    #[allow(dead_code)] ca_nid: String,
    agent_nid:   String,
    ca_root_der: Vec<u8>,
    agent_sk:    SigningKey,
    server:      AcmeServer,
}

fn create_fixture() -> Fixture {
    let ca_nid    = "urn:nps:ca:acme-test".to_string();
    let agent_nid = "urn:nps:agent:acme-test:1".to_string();

    let ca_sk = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now();
    // rcgen::Certificate is not Clone, so we issue the root once and capture
    // its DER for the verifier before transferring ownership to the server.
    let ca_root = x509::issue_root(IssueRootOptions {
        ca_nid: &ca_nid, ca_signing_key: &ca_sk,
        not_before: now - Duration::from_secs(60),
        not_after:  now + Duration::from_secs(365 * 24 * 3600),
        serial_number: &[1],
    }).expect("issue ca root");
    let ca_root_der = ca_root.der().to_vec();

    let agent_sk = SigningKey::generate(&mut OsRng);

    let server = AcmeServer::start(AcmeServerOptions {
        ca_nid:         ca_nid.clone(),
        ca_signing_key: ca_sk,
        ca_root_cert:   ca_root,
        cert_validity:  Duration::from_secs(30 * 24 * 3600),
    }).expect("server start");

    Fixture { ca_nid, agent_nid, ca_root_der, agent_sk, server }
}

#[tokio::test]
async fn issue_agent_cert_round_trip_returns_valid_pem_chain() {
    let fx = create_fixture();
    let mut client = AcmeClient::new(fx.server.directory_url(), fx.agent_sk);
    let pem = client.issue_agent_cert(&fx.agent_nid).await
        .expect("issue_agent_cert");
    assert!(pem.contains("BEGIN CERTIFICATE"), "PEM missing certificate marker");

    // Parse PEM into base64url(DER) chain and verify against the trusted root.
    let chain_b64u = parse_pem_chain_b64u(&pem);
    assert!(!chain_b64u.is_empty(), "PEM chain empty");
    let r = x509::verify(x509::VerifyOptions {
        cert_chain_b64u_der:      &chain_b64u,
        asserted_nid:             &fx.agent_nid,
        asserted_assurance_level: Some(nps_nip::ANONYMOUS),
        trusted_root_certs_der:   &[fx.ca_root_der.clone()],
    });
    assert!(r.valid, "leaf must verify; got code={:?} msg={:?}",
        r.error_code, r.message);
}

#[tokio::test]
async fn respond_agent01_tampered_signature_server_returns_challenge_failed() {
    let fx = create_fixture();
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build().unwrap();

    // Step 1: directory + nonce.
    let dir: Directory = http.get(fx.server.directory_url()).send().await
        .unwrap().json().await.unwrap();
    let nonce_resp = http.head(&dir.new_nonce).send().await.unwrap();
    let mut nonce = nonce_resp.headers().get("Replay-Nonce")
        .and_then(|v| v.to_str().ok()).unwrap().to_string();

    // newAccount.
    let agent_pub = fx.agent_sk.verifying_key();
    let jwk = jws::jwk_from_public_key(agent_pub.as_bytes());
    let acct_env = jws::sign(
        &jws::ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce: nonce.clone(),
            url: dir.new_account.clone(), jwk: Some(jwk), kid: None },
        Some(&NewAccountPayload { terms_of_service_agreed: Some(true), ..Default::default() }),
        &fx.agent_sk,
    ).unwrap();
    let acct_resp = http.post(&dir.new_account)
        .header("Content-Type", wire::CONTENT_TYPE_JOSE_JSON)
        .body(serde_json::to_vec(&acct_env).unwrap())
        .send().await.unwrap();
    assert_eq!(acct_resp.status().as_u16(), 201);
    let account_url = acct_resp.headers().get("Location")
        .and_then(|v| v.to_str().ok()).unwrap().to_string();
    nonce = acct_resp.headers().get("Replay-Nonce")
        .and_then(|v| v.to_str().ok()).unwrap().to_string();

    // newOrder.
    let order_env = jws::sign(
        &jws::ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce: nonce.clone(),
            url: dir.new_order.clone(), jwk: None, kid: Some(account_url.clone()) },
        Some(&NewOrderPayload {
            identifiers: vec![Identifier {
                type_: wire::IDENTIFIER_TYPE_NID.into(),
                value: fx.agent_nid.clone(),
            }],
            not_before: None, not_after: None,
        }),
        &fx.agent_sk,
    ).unwrap();
    let order_resp = http.post(&dir.new_order)
        .header("Content-Type", wire::CONTENT_TYPE_JOSE_JSON)
        .body(serde_json::to_vec(&order_env).unwrap())
        .send().await.unwrap();
    assert_eq!(order_resp.status().as_u16(), 201);
    nonce = order_resp.headers().get("Replay-Nonce")
        .and_then(|v| v.to_str().ok()).unwrap().to_string();
    let order: Order = order_resp.json().await.unwrap();

    // POST-as-GET on authz to discover the challenge URL + token.
    let authz_env = jws::sign::<NewAccountPayload>(
        &jws::ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce: nonce.clone(),
            url: order.authorizations[0].clone(), jwk: None, kid: Some(account_url.clone()) },
        None, &fx.agent_sk,
    ).unwrap();
    let authz_resp = http.post(&order.authorizations[0])
        .header("Content-Type", wire::CONTENT_TYPE_JOSE_JSON)
        .body(serde_json::to_vec(&authz_env).unwrap())
        .send().await.unwrap();
    nonce = authz_resp.headers().get("Replay-Nonce")
        .and_then(|v| v.to_str().ok()).unwrap().to_string();
    let authz: Authorization = authz_resp.json().await.unwrap();
    let ch = authz.challenges.iter()
        .find(|c| c.type_ == wire::CHALLENGE_AGENT_01).expect("agent-01 challenge");

    // ★ Tampered: sign challenge token with a *different* keypair, but submit
    //   the JWS envelope under the registered account's key. Server verifies
    //   the JWS sig (passes with account key) and then verifies the agent
    //   signature against the same account key (fails).
    let forger_sk = SigningKey::generate(&mut OsRng);
    let forged_sig = forger_sk.sign(ch.token.as_bytes());

    let ch_env = jws::sign(
        &jws::ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce: nonce.clone(),
            url: ch.url.clone(), jwk: None, kid: Some(account_url.clone()) },
        Some(&ChallengeRespondPayload {
            agent_signature: jws::b64u_encode(&forged_sig.to_bytes()),
        }),
        &fx.agent_sk,
    ).unwrap();
    let ch_resp = http.post(&ch.url)
        .header("Content-Type", wire::CONTENT_TYPE_JOSE_JSON)
        .body(serde_json::to_vec(&ch_env).unwrap())
        .send().await.unwrap();
    assert_eq!(ch_resp.status().as_u16(), 400);
    let problem: ProblemDetail = ch_resp.json().await.unwrap();
    assert_eq!(problem.type_, error_codes::ACME_CHALLENGE_FAILED,
        "got problem type {:?}, detail {:?}", problem.type_, problem.detail);
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn parse_pem_chain_b64u(pem: &str) -> Vec<String> {
    let mut out = Vec::new();
    let marker_begin = "-----BEGIN CERTIFICATE-----";
    let marker_end   = "-----END CERTIFICATE-----";
    let mut pos = 0;
    while let Some(start) = pem[pos..].find(marker_begin).map(|i| pos + i) {
        let body_start = start + marker_begin.len();
        let Some(end) = pem[body_start..].find(marker_end).map(|i| body_start + i) else { break; };
        let body: String = pem[body_start..end].chars()
            .filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&body) {
            out.push(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&der));
        }
        pos = end + marker_end.len();
    }
    out
}
