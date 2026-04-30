// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! In-process ACME server implementing the `agent-01` challenge for tests.

use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, Verifier as _, VerifyingKey};
use rand::RngCore;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use tiny_http::{Header, Method, Request, Response, Server};
use x509_parser::prelude::*;

use crate::error_codes;
use crate::x509::{issue_leaf, IssueLeafOptions, LeafRole};

use super::jws::{self, Jwk, ProtectedHeader, Envelope};
use super::messages::*;
use super::wire;

pub struct AcmeServerOptions {
    pub ca_nid:         String,
    pub ca_signing_key: SigningKey,
    pub ca_root_cert:   rcgen::Certificate,
    pub cert_validity:  Duration,
}

#[derive(Clone)]
struct OrderState {
    identifier:      Identifier,
    status:          String,
    authz_id:        String,
    finalize_url:    String,
    account_url:     String,
    certificate_url: Option<String>,
}

#[derive(Clone)]
struct AuthzState {
    identifier:    Identifier,
    status:        String,
    challenge_ids: Vec<String>,
    #[allow(dead_code)] account_url: String,
}

#[derive(Clone)]
struct ChallengeState {
    id:          String,
    type_:       String,
    status:      String,
    token:       String,
    authz_id:    String,
    account_url: String,
}

struct State {
    nonces:       std::collections::HashSet<String>,
    account_jwks: HashMap<String, Jwk>,         // accountUrl → jwk
    orders:       HashMap<String, OrderState>,
    authzs:       HashMap<String, AuthzState>,
    challenges:   HashMap<String, ChallengeState>,
    certs:        HashMap<String, String>,
}

pub struct AcmeServer {
    base_url:       String,
    handle:         Option<JoinHandle<()>>,
    server:         Option<Arc<Server>>,
}

impl AcmeServer {
    pub fn start(opts: AcmeServerOptions) -> Result<Self, String> {
        let server = Server::http("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
        let port = server.server_addr()
            .to_ip().map(|s| s.port())
            .ok_or("server_addr returned no IP")?;
        let base_url = format!("http://127.0.0.1:{port}");
        let server = Arc::new(server);

        let state = Arc::new(Mutex::new(State {
            nonces:       Default::default(),
            account_jwks: Default::default(),
            orders:       Default::default(),
            authzs:       Default::default(),
            challenges:   Default::default(),
            certs:        Default::default(),
        }));
        let opts = Arc::new(opts);

        let server_clone = server.clone();
        let base_url_clone = base_url.clone();
        let handle = thread::spawn(move || {
            for req in server_clone.incoming_requests() {
                let state = state.clone();
                let opts = opts.clone();
                let base_url = base_url_clone.clone();
                // Handle each request synchronously (in this background thread).
                handle_request(req, state, opts, &base_url);
            }
        });

        Ok(Self {
            base_url,
            handle:  Some(handle),
            server:  Some(server),
        })
    }

    pub fn directory_url(&self) -> String { format!("{}/directory", self.base_url) }
    pub fn base_url(&self) -> &str { &self.base_url }
}

impl Drop for AcmeServer {
    fn drop(&mut self) {
        if let Some(s) = self.server.take() { s.unblock(); }
        if let Some(h) = self.handle.take() { let _ = h.join(); }
    }
}

// ── Request handling ────────────────────────────────────────────────────────

fn handle_request(mut req: Request, state: Arc<Mutex<State>>,
                   opts: Arc<AcmeServerOptions>, base_url: &str) {
    let path = req.url().to_string();
    let method = req.method().clone();

    let result: Result<(u16, String, Vec<(String, String)>), (u16, String)> = (|| {
        if method == Method::Get && path == "/directory" {
            return Ok(json_response(200, &Directory {
                new_nonce:   format!("{base_url}/new-nonce"),
                new_account: format!("{base_url}/new-account"),
                new_order:   format!("{base_url}/new-order"),
                revoke_cert: None,
                key_change:  None,
                meta:        None,
            }, vec![]));
        }
        if path == "/new-nonce" {
            let nonce = mint_nonce(&state);
            let status = if method == Method::Head { 200 } else { 204 };
            return Ok((status, String::new(), vec![
                ("Replay-Nonce".into(),  nonce),
                ("Cache-Control".into(), "no-store".into()),
            ]));
        }
        if method == Method::Post && path == "/new-account" {
            return handle_new_account(&mut req, &state, base_url);
        }
        if method == Method::Post && path == "/new-order" {
            return handle_new_order(&mut req, &state, base_url);
        }
        if method == Method::Post && path.starts_with("/authz/") {
            return handle_authz(&mut req, &state, base_url, &path);
        }
        if method == Method::Post && path.starts_with("/chall/") {
            return handle_challenge(&mut req, &state, base_url, &path);
        }
        if method == Method::Post && path.starts_with("/finalize/") {
            return handle_finalize(&mut req, &state, &opts, base_url, &path);
        }
        if method == Method::Post && path.starts_with("/cert/") {
            return handle_cert(&mut req, &state, base_url, &path);
        }
        if method == Method::Post && path.starts_with("/order/") {
            return handle_order(&mut req, &state, base_url, &path);
        }
        Err((404, problem_body("urn:ietf:params:acme:error:malformed", "no such resource", 404)))
    })();

    let (status, body, extra_headers) = match result {
        Ok(v) => v,
        Err((status, body)) => (status, body, vec![
            ("Content-Type".into(), wire::CONTENT_TYPE_PROBLEM.into()),
        ]),
    };

    let mut resp = Response::from_string(body).with_status_code(status);
    for (k, v) in extra_headers {
        if let Ok(h) = Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            resp = resp.with_header(h);
        }
    }
    let _ = req.respond(resp);
}

fn handle_new_account(
    req: &mut Request, state: &Arc<Mutex<State>>, base_url: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env: Envelope = read_envelope(req)?;
    let header = parse_header(&env)?;
    let Some(ref jwk) = header.jwk else {
        return Err(problem(400, "urn:ietf:params:acme:error:malformed",
            "newAccount must include a 'jwk' member"));
    };
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    let pub_key = jws::public_key_from_jwk(jwk).map_err(|e| problem(400,
        "urn:ietf:params:acme:error:malformed", &format!("jwk parse: {e}")))?;
    if jws::verify(&env, &pub_key).is_err() {
        return Err(problem(400, "urn:ietf:params:acme:error:malformed",
            "JWS signature verify failed"));
    }
    let account_id = short_id();
    let account_url = format!("{base_url}/account/{account_id}");
    state.lock().unwrap().account_jwks.insert(account_url.clone(), jwk.clone());

    let new_nonce = mint_nonce(state);
    Ok(json_response(201, &serde_json::json!({"status": wire::STATUS_VALID}), vec![
        ("Location".into(),     account_url),
        ("Replay-Nonce".into(), new_nonce),
    ]))
}

fn handle_new_order(
    req: &mut Request, state: &Arc<Mutex<State>>, base_url: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env: Envelope = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    if !verify_account(state, &env, &header) {
        return Err(problem(401, "urn:ietf:params:acme:error:accountDoesNotExist",
            &format!("unknown kid: {}", header.kid.as_deref().unwrap_or("<missing>"))));
    }
    let payload: NewOrderPayload = match jws::decode_payload(&env)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed", &e))?
    {
        Some(p) => p,
        None => return Err(problem(400, "urn:ietf:params:acme:error:malformed",
            "missing payload")),
    };
    if payload.identifiers.is_empty() {
        return Err(problem(400, "urn:ietf:params:acme:error:malformed", "missing identifiers"));
    }
    let ident = payload.identifiers.into_iter().next().unwrap();

    let order_id = short_id();
    let authz_id = short_id();
    let chall_id = short_id();
    let token    = jws::b64u_encode(&random_bytes(32));
    let order_url    = format!("{base_url}/order/{order_id}");
    let authz_url    = format!("{base_url}/authz/{authz_id}");
    let chall_url    = format!("{base_url}/chall/{chall_id}");
    let finalize_url = format!("{base_url}/finalize/{order_id}");
    let account_url  = header.kid.unwrap_or_default();
    {
        let mut s = state.lock().unwrap();
        s.challenges.insert(chall_id.clone(), ChallengeState {
            id: chall_id.clone(), type_: wire::CHALLENGE_AGENT_01.into(),
            status: wire::STATUS_PENDING.into(), token, authz_id: authz_id.clone(),
            account_url: account_url.clone(),
        });
        s.authzs.insert(authz_id.clone(), AuthzState {
            identifier: ident.clone(), status: wire::STATUS_PENDING.into(),
            challenge_ids: vec![chall_id.clone()], account_url: account_url.clone(),
        });
        s.orders.insert(order_id.clone(), OrderState {
            identifier: ident.clone(), status: wire::STATUS_PENDING.into(),
            authz_id: authz_id.clone(), finalize_url: finalize_url.clone(),
            account_url: account_url.clone(), certificate_url: None,
        });
    }
    let _ = chall_url; // Unused — challenges materialize via the authz GET.
    let new_nonce = mint_nonce(state);
    Ok(json_response(201, &Order {
        status: wire::STATUS_PENDING.into(), expires: None,
        identifiers: vec![ident],
        authorizations: vec![authz_url], finalize: finalize_url,
        certificate: None, error: None,
    }, vec![
        ("Location".into(),     order_url),
        ("Replay-Nonce".into(), new_nonce),
    ]))
}

fn handle_authz(
    req: &mut Request, state: &Arc<Mutex<State>>, base_url: &str, path: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    if !verify_account(state, &env, &header) {
        return Err(problem(401, "urn:ietf:params:acme:error:unauthorized", "bad sig"));
    }
    let id = path.trim_start_matches("/authz/").to_string();
    let (az, challenges) = {
        let s = state.lock().unwrap();
        let Some(az) = s.authzs.get(&id).cloned() else {
            return Err(problem(404, "urn:ietf:params:acme:error:malformed", "no authz"));
        };
        let challenges: Vec<Challenge> = az.challenge_ids.iter()
            .filter_map(|cid| s.challenges.get(cid).cloned())
            .map(|cs| Challenge {
                type_: cs.type_, url: format!("{base_url}/chall/{}", cs.id),
                status: cs.status, token: cs.token, validated: None, error: None,
            })
            .collect();
        (az, challenges)
    };
    let new_nonce = mint_nonce(state);
    Ok(json_response(200, &Authorization {
        status: az.status, expires: None, identifier: az.identifier, challenges,
    }, vec![("Replay-Nonce".into(), new_nonce)]))
}

fn handle_challenge(
    req: &mut Request, state: &Arc<Mutex<State>>, base_url: &str, path: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    let kid = header.kid.clone().unwrap_or_default();
    let Some(account_jwk) = state.lock().unwrap().account_jwks.get(&kid).cloned() else {
        return Err(problem(401, "urn:ietf:params:acme:error:accountDoesNotExist",
            "unknown kid"));
    };
    let account_pub = jws::public_key_from_jwk(&account_jwk)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed", &e))?;
    if jws::verify(&env, &account_pub).is_err() {
        return Err(problem(400, "urn:ietf:params:acme:error:malformed", "JWS sig fail"));
    }
    let id = path.trim_start_matches("/chall/").to_string();
    let mut ch = match state.lock().unwrap().challenges.get(&id).cloned() {
        Some(c) => c,
        None => return Err(problem(404, "urn:ietf:params:acme:error:malformed", "no chall")),
    };
    let payload: Option<ChallengeRespondPayload> = jws::decode_payload(&env)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed", &e))?;
    let agent_sig_b64 = match payload.and_then(|p| Some(p.agent_signature)) {
        Some(s) if !s.is_empty() => s,
        _ => {
            mark_challenge_invalid(state, &ch.id);
            return Err(problem(400, error_codes::ACME_CHALLENGE_FAILED,
                "missing agent_signature in challenge response"));
        }
    };
    let agent_sig = jws::b64u_decode(&agent_sig_b64).map_err(|e| {
        mark_challenge_invalid(state, &ch.id);
        problem(400, error_codes::ACME_CHALLENGE_FAILED,
            &format!("agent-01 verification error: {e}"))
    })?;
    let agent_sig = Signature::from_slice(&agent_sig).map_err(|e| {
        mark_challenge_invalid(state, &ch.id);
        problem(400, error_codes::ACME_CHALLENGE_FAILED,
            &format!("agent-01 verification error: {e}"))
    })?;
    if account_pub.verify(ch.token.as_bytes(), &agent_sig).is_err() {
        mark_challenge_invalid(state, &ch.id);
        return Err(problem(400, error_codes::ACME_CHALLENGE_FAILED,
            "agent-01 signature did not verify"));
    }
    // Challenge OK — flip statuses.
    {
        let mut s = state.lock().unwrap();
        if let Some(c) = s.challenges.get_mut(&ch.id) {
            c.status = wire::STATUS_VALID.into();
            ch.status = wire::STATUS_VALID.into();
        }
        if let Some(az) = s.authzs.get_mut(&ch.authz_id) {
            az.status = wire::STATUS_VALID.into();
        }
        for o in s.orders.values_mut() {
            if o.authz_id == ch.authz_id {
                o.status = wire::STATUS_READY.into();
            }
        }
    }
    let new_nonce = mint_nonce(state);
    Ok(json_response(200, &Challenge {
        type_: ch.type_, url: format!("{base_url}/chall/{}", ch.id),
        status: ch.status, token: ch.token, validated: None, error: None,
    }, vec![("Replay-Nonce".into(), new_nonce)]))
}

fn handle_finalize(
    req: &mut Request, state: &Arc<Mutex<State>>, opts: &Arc<AcmeServerOptions>,
    base_url: &str, path: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    if !verify_account(state, &env, &header) {
        return Err(problem(401, "urn:ietf:params:acme:error:unauthorized", "bad sig"));
    }
    let order_id = path.trim_start_matches("/finalize/").to_string();
    let mut os = match state.lock().unwrap().orders.get(&order_id).cloned() {
        Some(o) => o,
        None => return Err(problem(404, "urn:ietf:params:acme:error:malformed", "no order")),
    };
    if os.status != wire::STATUS_READY {
        return Err(problem(403, "urn:ietf:params:acme:error:orderNotReady",
            &format!("order is in state '{}', not 'ready'", os.status)));
    }
    let fp: Option<FinalizePayload> = jws::decode_payload(&env)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed", &e))?;
    let csr_b64 = fp.map(|f| f.csr).filter(|s| !s.is_empty())
        .ok_or_else(|| problem(400, "urn:ietf:params:acme:error:malformed", "missing csr"))?;
    let csr_der = jws::b64u_decode(&csr_b64)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:badCSR",
            &format!("CSR base64url: {e}")))?;
    // Parse CSR with x509-parser.
    let (_rem, csr) = X509CertificationRequest::from_der(&csr_der)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:badCSR",
            &format!("CSR parse: {e}")))?;
    let subject_cn: Option<&str> = csr.certification_request_info.subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok());
    if subject_cn != Some(os.identifier.value.as_str()) {
        return Err(problem(400, error_codes::CERT_SUBJECT_NID_MISMATCH,
            &format!("CSR subject CN '{}' does not match order identifier '{}'",
                subject_cn.unwrap_or(""), os.identifier.value)));
    }
    let pub_key_bytes = csr.certification_request_info.subject_pki
        .subject_public_key.data.as_ref();
    if pub_key_bytes.len() != 32 {
        return Err(problem(400, "urn:ietf:params:acme:error:badCSR",
            "CSR public key is not 32 bytes (Ed25519)"));
    }
    let mut subject_pub = [0u8; 32];
    subject_pub.copy_from_slice(pub_key_bytes);
    let _ = VerifyingKey::from_bytes(&subject_pub).map_err(|e| problem(400,
        "urn:ietf:params:acme:error:badCSR", &format!("CSR pubkey: {e}")))?;
    let now = SystemTime::now();
    let leaf = issue_leaf(IssueLeafOptions {
        subject_nid:     &os.identifier.value,
        subject_pub_raw: &subject_pub,
        ca_signing_key:  &opts.ca_signing_key,
        ca_root_cert:    &opts.ca_root_cert,
        role:            LeafRole::Agent,
        assurance_level: crate::assurance_level::ANONYMOUS,
        not_before:      now - Duration::from_secs(60),
        not_after:       now + opts.cert_validity,
        serial_number:   &random_bytes(20),
    }).map_err(|e| problem(400, "urn:ietf:params:acme:error:badCSR",
        &format!("issue leaf: {e}")))?;

    let mut pem = String::new();
    pem.push_str(&leaf.pem());
    pem.push_str(&opts.ca_root_cert.pem());

    let cert_id  = short_id();
    let cert_url = format!("{base_url}/cert/{cert_id}");
    {
        let mut s = state.lock().unwrap();
        s.certs.insert(cert_id.clone(), pem);
        if let Some(o) = s.orders.get_mut(&order_id) {
            o.status = wire::STATUS_VALID.into();
            o.certificate_url = Some(cert_url.clone());
        }
    }
    os.status = wire::STATUS_VALID.into();
    os.certificate_url = Some(cert_url);
    let authz_url = format!("{base_url}/authz/{}", os.authz_id);
    let new_nonce = mint_nonce(state);
    Ok(json_response(200, &Order {
        status: os.status, expires: None,
        identifiers: vec![os.identifier],
        authorizations: vec![authz_url], finalize: os.finalize_url,
        certificate: os.certificate_url, error: None,
    }, vec![("Replay-Nonce".into(), new_nonce)]))
}

fn handle_cert(
    req: &mut Request, state: &Arc<Mutex<State>>, _base_url: &str, path: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    if !verify_account(state, &env, &header) {
        return Err(problem(401, "urn:ietf:params:acme:error:unauthorized", "bad sig"));
    }
    let cert_id = path.trim_start_matches("/cert/").to_string();
    let pem = state.lock().unwrap().certs.get(&cert_id).cloned()
        .ok_or_else(|| problem(404, "urn:ietf:params:acme:error:malformed", "no cert"))?;
    let new_nonce = mint_nonce(state);
    Ok((200, pem, vec![
        ("Content-Type".into(), wire::CONTENT_TYPE_PEM_CERT.into()),
        ("Replay-Nonce".into(), new_nonce),
    ]))
}

fn handle_order(
    req: &mut Request, state: &Arc<Mutex<State>>, base_url: &str, path: &str,
) -> Result<(u16, String, Vec<(String, String)>), (u16, String)> {
    let env = read_envelope(req)?;
    let header = parse_header(&env)?;
    if !consume_nonce(state, &header.nonce) {
        return Err(problem(400, "urn:ietf:params:acme:error:badNonce", "invalid nonce"));
    }
    if !verify_account(state, &env, &header) {
        return Err(problem(401, "urn:ietf:params:acme:error:unauthorized", "bad sig"));
    }
    let order_id = path.trim_start_matches("/order/").to_string();
    let os = state.lock().unwrap().orders.get(&order_id).cloned()
        .ok_or_else(|| problem(404, "urn:ietf:params:acme:error:malformed", "no order"))?;
    let authz_url = format!("{base_url}/authz/{}", os.authz_id);
    let new_nonce = mint_nonce(state);
    Ok(json_response(200, &Order {
        status: os.status, expires: None,
        identifiers: vec![os.identifier],
        authorizations: vec![authz_url], finalize: os.finalize_url,
        certificate: os.certificate_url, error: None,
    }, vec![("Replay-Nonce".into(), new_nonce)]))
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn read_envelope(req: &mut Request) -> Result<Envelope, (u16, String)> {
    let mut body = String::new();
    req.as_reader().read_to_string(&mut body)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed",
            &format!("body read: {e}")))?;
    serde_json::from_str(&body).map_err(|e| problem(400,
        "urn:ietf:params:acme:error:malformed", &format!("body parse: {e}")))
}

fn parse_header(env: &Envelope) -> Result<ProtectedHeader, (u16, String)> {
    let bytes = jws::b64u_decode(&env.protected)
        .map_err(|e| problem(400, "urn:ietf:params:acme:error:malformed",
            &format!("malformed protected header: {e}")))?;
    serde_json::from_slice(&bytes).map_err(|e| problem(400,
        "urn:ietf:params:acme:error:malformed",
        &format!("protected header parse: {e}")))
}

fn verify_account(state: &Arc<Mutex<State>>, env: &Envelope, header: &ProtectedHeader) -> bool {
    let Some(kid) = header.kid.as_ref() else { return false; };
    let Some(jwk) = state.lock().unwrap().account_jwks.get(kid).cloned() else { return false; };
    let Ok(pk) = jws::public_key_from_jwk(&jwk) else { return false; };
    jws::verify(env, &pk).is_ok()
}

fn mint_nonce(state: &Arc<Mutex<State>>) -> String {
    let nonce = jws::b64u_encode(&random_bytes(16));
    state.lock().unwrap().nonces.insert(nonce.clone());
    nonce
}

fn consume_nonce(state: &Arc<Mutex<State>>, nonce: &str) -> bool {
    state.lock().unwrap().nonces.remove(nonce)
}

fn mark_challenge_invalid(state: &Arc<Mutex<State>>, id: &str) {
    if let Some(c) = state.lock().unwrap().challenges.get_mut(id) {
        c.status = wire::STATUS_INVALID.into();
    }
}

fn json_response<T: serde::Serialize>(
    status: u16, body: &T, extra_headers: Vec<(String, String)>,
) -> (u16, String, Vec<(String, String)>) {
    let mut headers = vec![("Content-Type".into(), "application/json".into())];
    headers.extend(extra_headers);
    (status, serde_json::to_string(body).unwrap_or_default(), headers)
}

fn problem(status: u16, type_: &str, detail: &str) -> (u16, String) {
    (status, problem_body(type_, detail, status))
}

fn problem_body(type_: &str, detail: &str, status: u16) -> String {
    serde_json::to_string(&ProblemDetail {
        type_: type_.into(),
        detail: Some(detail.into()),
        status: Some(status),
    }).unwrap_or_default()
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn short_id() -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random_bytes(8))
}
