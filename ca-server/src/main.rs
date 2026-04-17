// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
mod ca;
mod db;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use db::{CaDb, InsertRec, iso_now};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{env, net::SocketAddr, sync::Arc, time::{SystemTime, UNIX_EPOCH}};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct AppState {
    ca:             Arc<ca::Ca>,
    db:             Arc<CaDb>,
    ca_nid:         String,
    base_url:       String,
    display_name:   String,
    agent_days:     i64,
    node_days:      i64,
    renewal_days:   i64,
}

// ── Models ─────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct RegisterReq {
    nid:          Option<String>,
    pub_key:      String,
    capabilities: Option<Vec<String>>,
    scope:        Option<Map<String, Value>>,
    metadata:     Option<Map<String, Value>>,
}

#[derive(Deserialize)]
struct RevokeReq {
    reason: Option<String>,
}

// ── Handlers ───────────────────────────────────────────────────────────────────

async fn register_agent(State(s): State<AppState>, Json(req): Json<RegisterReq>)
    -> impl IntoResponse { register(s, req, "agent").await }

async fn register_node(State(s): State<AppState>, Json(req): Json<RegisterReq>)
    -> impl IntoResponse { register(s, req, "node").await }

async fn register(s: AppState, req: RegisterReq, entity_type: &str) -> impl IntoResponse {
    let domain = ca_domain(&s.ca_nid);
    let nid = req.nid.unwrap_or_else(|| ca::generate_nid(&domain, entity_type));
    if s.db.get_active(&nid).unwrap_or(None).is_some() {
        return (StatusCode::CONFLICT, Json(json!({
            "error_code": "NIP-CA-NID-ALREADY-EXISTS",
            "message": format!("{nid} already has an active certificate")
        }))).into_response();
    }
    let caps = req.capabilities.unwrap_or_default();
    let scope = req.scope.unwrap_or_default();
    let days = if entity_type == "agent" { s.agent_days } else { s.node_days };
    let serial = s.db.next_serial().unwrap();
    let cert = ca::issue_cert(&s.ca.signing_key, &s.ca_nid, &nid, &req.pub_key,
        caps.clone(), scope.clone(), days, &serial, req.metadata.clone());

    let issued_at  = cert["issued_at"].as_str().unwrap_or("").to_string();
    let expires_at = cert["expires_at"].as_str().unwrap_or("").to_string();
    s.db.insert(&InsertRec {
        nid: nid.clone(), entity_type: entity_type.to_string(), serial: serial.clone(),
        pub_key: req.pub_key.clone(), capabilities: caps, scope,
        issued_by: s.ca_nid.clone(), issued_at: issued_at.clone(),
        expires_at: expires_at.clone(), metadata: req.metadata,
    }).ok();

    (StatusCode::CREATED, Json(json!({
        "nid": nid, "serial": serial,
        "issued_at": issued_at, "expires_at": expires_at,
        "ident_frame": cert
    }))).into_response()
}

async fn renew(State(s): State<AppState>, Path(nid): Path<String>) -> impl IntoResponse {
    let rec = match s.db.get_active(&nid).unwrap_or(None) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error_code":"NIP-CA-NID-NOT-FOUND","message":format!("{nid} not found")}))).into_response(),
    };
    let exp_secs = iso_to_epoch(&rec.expires_at);
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days_left = (exp_secs.saturating_sub(now_secs)) / 86400;
    if days_left as i64 > s.renewal_days {
        return (StatusCode::BAD_REQUEST, Json(json!({
            "error_code": "NIP-CA-RENEWAL-TOO-EARLY",
            "message": format!("Renewal window opens in {} days", days_left as i64 - s.renewal_days)
        }))).into_response();
    }
    let days = if rec.entity_type == "agent" { s.agent_days } else { s.node_days };
    let serial = s.db.next_serial().unwrap();
    let cert = ca::issue_cert(&s.ca.signing_key, &s.ca_nid, &nid, &rec.pub_key,
        rec.capabilities.clone(), rec.scope.clone(), days, &serial, rec.metadata.clone());
    let issued_at  = cert["issued_at"].as_str().unwrap_or("").to_string();
    let expires_at = cert["expires_at"].as_str().unwrap_or("").to_string();
    s.db.insert(&InsertRec {
        nid: nid.clone(), entity_type: rec.entity_type.clone(), serial: serial.clone(),
        pub_key: rec.pub_key.clone(), capabilities: rec.capabilities,
        scope: rec.scope, issued_by: s.ca_nid.clone(),
        issued_at: issued_at.clone(), expires_at: expires_at.clone(), metadata: rec.metadata,
    }).ok();
    Json(json!({"nid": nid, "serial": serial, "issued_at": issued_at, "expires_at": expires_at, "ident_frame": cert})).into_response()
}

async fn revoke_handler(State(s): State<AppState>, Path(nid): Path<String>,
    body: Option<Json<RevokeReq>>) -> impl IntoResponse {
    let reason = body.and_then(|b| b.reason.clone())
        .unwrap_or_else(|| "cessation_of_operation".to_string());
    if !s.db.revoke(&nid, &reason).unwrap_or(false) {
        return (StatusCode::NOT_FOUND, Json(json!({"error_code":"NIP-CA-NID-NOT-FOUND","message":format!("{nid} not found")}))).into_response();
    }
    Json(json!({"nid": nid, "revoked_at": iso_now(), "reason": reason})).into_response()
}

async fn verify_handler(State(s): State<AppState>, Path(nid): Path<String>) -> impl IntoResponse {
    let rec = match s.db.get_active(&nid).unwrap_or(None) {
        Some(r) => r,
        None => return (StatusCode::NOT_FOUND, Json(json!({"error_code":"NIP-CA-NID-NOT-FOUND","message":format!("{nid} not found")}))).into_response(),
    };
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let valid = iso_to_epoch(&rec.expires_at) > now_secs;
    let mut resp = json!({
        "valid": valid, "nid": nid, "entity_type": rec.entity_type,
        "pub_key": rec.pub_key, "capabilities": rec.capabilities,
        "issued_by": rec.issued_by, "issued_at": rec.issued_at,
        "expires_at": rec.expires_at, "serial": rec.serial,
    });
    if !valid { resp["error_code"] = json!("NIP-CERT-EXPIRED"); }
    Json(resp).into_response()
}

async fn ca_cert(State(s): State<AppState>) -> Json<Value> {
    Json(json!({"nid": s.ca_nid, "display_name": s.display_name,
                "pub_key": s.ca.pub_key_str, "algorithm": "ed25519"}))
}

async fn crl(State(s): State<AppState>) -> impl IntoResponse {
    Json(json!({"revoked": s.db.crl().unwrap_or_default()}))
}

async fn well_known(State(s): State<AppState>) -> Json<Value> {
    let base = s.base_url.trim_end_matches('/');
    Json(json!({
        "nps_ca": "0.1", "issuer": s.ca_nid, "display_name": s.display_name,
        "public_key": s.ca.pub_key_str, "algorithms": ["ed25519"],
        "endpoints": {
            "register": format!("{base}/v1/agents/register"),
            "verify":   format!("{base}/v1/agents/{{nid}}/verify"),
            "ocsp":     format!("{base}/v1/agents/{{nid}}/verify"),
            "crl":      format!("{base}/v1/crl"),
        },
        "capabilities": ["agent","node"],
        "max_cert_validity_days": std::cmp::max(s.agent_days, s.node_days),
    }))
}

async fn health() -> Json<Value> { Json(json!({"status":"ok"})) }

// ── Main ───────────────────────────────────────────────────────────────────────

fn env_str(k: &str, default: &str) -> String { env::var(k).unwrap_or_else(|_| default.to_string()) }
fn env_i64(k: &str, default: i64) -> i64 { env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default) }

fn ca_domain(ca_nid: &str) -> String {
    let parts: Vec<&str> = ca_nid.split(':').collect();
    if parts.len() >= 5 { parts[parts.len()-2].to_string() } else { "ca.local".to_string() }
}

fn iso_to_epoch(s: &str) -> u64 {
    // Parse "2026-05-17T12:00:00Z" to unix seconds (simple, no external crate)
    let s = s.trim_end_matches('Z');
    let parts: Vec<u64> = s.split(['T','-',':']).filter_map(|p| p.parse().ok()).collect();
    if parts.len() < 6 { return 0; }
    let (y, mo, d, h, mi, sec) = (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
    days_since_epoch(y, mo, d) * 86400 + h * 3600 + mi * 60 + sec
}

fn days_since_epoch(y: u64, mo: u64, d: u64) -> u64 {
    let (y, mo) = if mo <= 2 { (y-1, mo+9) } else { (y, mo-3) };
    let era = y / 400;
    let yoe = y - era*400;
    let doy = (153*mo+2)/5 + d - 1;
    let doe = yoe*365 + yoe/4 - yoe/100 + doy;
    era*146_097 + doe - 719_468
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let ca_nid      = env::var("NIP_CA_NID").expect("NIP_CA_NID is required");
    let passphrase  = env::var("NIP_CA_PASSPHRASE").expect("NIP_CA_PASSPHRASE is required");
    let base_url    = env::var("NIP_CA_BASE_URL").expect("NIP_CA_BASE_URL is required");
    let key_file    = env_str("NIP_CA_KEY_FILE", "/data/ca.key.enc");
    let db_path     = env_str("NIP_CA_DB_PATH",  "/data/ca.db");
    let display_name = env_str("NIP_CA_DISPLAY_NAME", "NPS CA");
    let agent_days  = env_i64("NIP_CA_AGENT_VALIDITY_DAYS", 30);
    let node_days   = env_i64("NIP_CA_NODE_VALIDITY_DAYS",  90);
    let renewal_days = env_i64("NIP_CA_RENEWAL_WINDOW_DAYS", 7);
    let port: u16   = env_str("PORT", "17440").parse().unwrap_or(17440);

    let signing_key = if std::path::Path::new(&key_file).exists() {
        ca::load_key(&key_file, &passphrase).expect("failed to load key")
    } else {
        let sk = ca::generate_key();
        ca::save_key(&sk, &key_file, &passphrase).expect("failed to save key");
        sk
    };
    let pub_key_str = ca::pub_key_string(&signing_key.verifying_key());

    let state = AppState {
        ca: Arc::new(ca::Ca { signing_key, pub_key_str }),
        db: Arc::new(CaDb::open(&db_path).expect("failed to open db")),
        ca_nid, base_url, display_name, agent_days, node_days, renewal_days,
    };

    let app = Router::new()
        .route("/v1/agents/register",     post(register_agent))
        .route("/v1/nodes/register",      post(register_node))
        .route("/v1/agents/:nid/renew",   post(renew))
        .route("/v1/agents/:nid/revoke",  post(revoke_handler))
        .route("/v1/agents/:nid/verify",  get(verify_handler))
        .route("/v1/ca/cert",             get(ca_cert))
        .route("/v1/crl",                 get(crl))
        .route("/.well-known/nps-ca",     get(well_known))
        .route("/health",                 get(health))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("NIP CA Server listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
