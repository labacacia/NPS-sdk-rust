// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Framework-agnostic HTTP router for the NIP CA service (NPS-3 §8), in the
//! style of `nps-nwp`'s `anchor_server`: a [`CaRequest`] in, a [`CaResponse`]
//! out, no transport dependency. Mirrors the endpoint surface, wire field
//! names, and HTTP status codes of the .NET `NipCaRouter`.

use std::collections::HashMap;

use serde_json::{json, Map, Value};
use time::{Duration, OffsetDateTime};

use crate::error_codes;
use crate::frames::IdentFrame;

use super::error::NipCaError;
use super::group_jws::{self, FlattenedJws};
use super::ra::{BootstrapTokenStore, EnrollmentPolicy, PendingStatus, PendingStore};
use super::service::{
    self, IssueSessionParams, NipCaService, NipVerifyResult, RegisterWithRaError,
};
use super::signer;
use super::store::{NipCaStore, ROLE_GROUP};

const VALID_REVOCATION_REASONS: &[&str] = &[
    "key_compromise",
    "ca_compromise",
    "affiliation_changed",
    "superseded",
    "cessation_of_operation",
    "parent_revoked",
];

/// A CA HTTP request (framework-agnostic).
#[derive(Debug, Clone)]
pub struct CaRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl CaRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self {
            method: method.into().to_uppercase(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_lowercase(), value.into());
        self
    }

    pub fn with_json(mut self, value: &Value) -> Self {
        self.body = serde_json::to_vec(value).unwrap_or_default();
        self.headers
            .insert("content-type".into(), "application/json".into());
        self
    }

    pub fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_lowercase()).map(String::as_str)
    }

    fn json_value(&self) -> Option<Value> {
        if self.body.is_empty() {
            None
        } else {
            serde_json::from_slice(&self.body).ok()
        }
    }
}

/// A CA HTTP response.
#[derive(Debug, Clone)]
pub struct CaResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl CaResponse {
    fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(&value).unwrap_or_default(),
        }
    }

    pub fn json_value(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Router wrapping a [`NipCaService`] with optional RA stores.
pub struct NipCaRouter<'a, S: NipCaStore> {
    ca: &'a NipCaService<S>,
    policy: Box<dyn EnrollmentPolicy + 'a>,
    bootstrap_store: Option<&'a dyn BootstrapTokenStore>,
    pending_store: Option<&'a dyn PendingStore>,
}

impl<'a, S: NipCaStore> NipCaRouter<'a, S> {
    /// Build a router. `policy` is typically produced by
    /// [`super::ra::create_enrollment_policy`].
    pub fn new(
        ca: &'a NipCaService<S>,
        policy: Box<dyn EnrollmentPolicy + 'a>,
        bootstrap_store: Option<&'a dyn BootstrapTokenStore>,
        pending_store: Option<&'a dyn PendingStore>,
    ) -> Self {
        Self {
            ca,
            policy,
            bootstrap_store,
            pending_store,
        }
    }

    fn pfx(&self) -> String {
        self.ca
            .options()
            .route_prefix
            .trim_end_matches('/')
            .to_string()
    }

    /// Dispatch a request to the matching handler.
    pub fn handle(&self, req: &CaRequest) -> CaResponse {
        let pfx = self.pfx();
        let path = req.path.as_str();
        let m = req.method.as_str();

        // Strip prefix for matching (keep a leading '/').
        let rel = path.strip_prefix(&pfx).unwrap_or(path);

        // Discovery.
        if m == "GET" && path == "/.well-known/nps-ca" {
            return self.discovery();
        }
        if m == "GET" && rel == "/v1/ca/cert" {
            return CaResponse::json(
                200,
                json!({ "public_key": self.ca.get_ca_public_key(), "algorithm": "ed25519" }),
            );
        }
        if m == "GET" && rel == "/v1/crl" {
            return self.crl();
        }
        if m == "GET" && rel == "/v1/certificates" {
            return self.certificates(req);
        }

        // Register (agent / node).
        if m == "POST" && rel == "/v1/agents/register" {
            return self.register(req, "agent", &[]);
        }
        if m == "POST" && rel == "/v1/nodes/register" {
            return self.register(
                req,
                "node",
                &["nwp:query".to_string(), "nwp:stream".to_string()],
            );
        }

        // Register X.509.
        if m == "POST" && rel == "/v1/agents/register-x509" {
            return self.register_x509(req, "agent", &[]);
        }
        if m == "POST" && rel == "/v1/nodes/register-x509" {
            return self.register_x509(
                req,
                "node",
                &["nwp:query".to_string(), "nwp:stream".to_string()],
            );
        }

        // Group register.
        if m == "POST" && rel == "/v1/orchestrators/groups/register" {
            return self.register_group(req);
        }

        // Enrollment.
        if m == "POST" && rel == "/v1/enrollment/tokens" {
            return self.create_token(req);
        }
        if m == "GET" && rel == "/v1/enrollment/pending" {
            return self.list_pending(req);
        }

        // Path-parameterised routes.
        if let Some(nid) = seg_between(rel, "/v1/agents/", "/renew")
            .or_else(|| seg_between(rel, "/v1/nodes/", "/renew"))
        {
            if m == "POST" {
                return self.renew(req, &nid);
            }
        }
        if let Some(nid) = seg_between(rel, "/v1/agents/", "/revoke")
            .or_else(|| seg_between(rel, "/v1/nodes/", "/revoke"))
        {
            if m == "POST" {
                return self.revoke(req, &nid);
            }
        }
        if let Some(nid) = seg_between(rel, "/v1/agents/", "/verify")
            .or_else(|| seg_between(rel, "/v1/nodes/", "/verify"))
        {
            if m == "GET" {
                return self.verify(&nid);
            }
        }
        if let Some(gnid) = seg_between(rel, "/v1/orchestrators/groups/", "/sessions/issue") {
            if m == "POST" {
                return self.issue_session(req, &gnid);
            }
        }
        if let Some(gnid) = seg_between(rel, "/v1/orchestrators/groups/", "/sessions") {
            if m == "GET" {
                return self.list_group_sessions(&gnid);
            }
        }
        if let Some(gnid) = seg_between(rel, "/v1/orchestrators/groups/", "/revoke") {
            if m == "POST" {
                return self.revoke(req, &gnid);
            }
        }
        if let Some(id) = seg_between(rel, "/v1/enrollment/pending/", "/approve") {
            if m == "POST" {
                return self.approve_pending(&id);
            }
        }
        if let Some(id) = seg_between(rel, "/v1/enrollment/pending/", "/reject") {
            if m == "POST" {
                return self.reject_pending(req, &id);
            }
        }

        CaResponse::json(
            404,
            json!({ "error_code": "NIP-CA-NOT-FOUND", "message": "No route matches." }),
        )
    }

    // ── Handlers ──────────────────────────────────────────────────────────────

    fn discovery(&self) -> CaResponse {
        let opts = self.ca.options();
        let pfx = self.pfx();
        let body = json!({
            "nps_ca": "0.1",
            "issuer": opts.ca_nid,
            "display_name": opts.display_name,
            "public_key": self.ca.get_ca_public_key(),
            "algorithms": opts.algorithms,
            "endpoints": {
                "register": format!("{}{}/v1/agents/register", opts.base_url, pfx),
                "verify": format!("{}{}/v1/agents/{{nid}}/verify", opts.base_url, pfx),
                "ocsp": format!("{}{}/v1/agents/{{nid}}/verify", opts.base_url, pfx),
                "node_ocsp": format!("{}{}/v1/nodes/{{nid}}/verify", opts.base_url, pfx),
                "crl": format!("{}{}/v1/crl", opts.base_url, pfx),
            },
            "capabilities": [
                "agent", "node", "orchestrator-group",
                format!("ra-tier-{}", opts.enrollment_tier as i32),
            ],
            "max_cert_validity_days": opts.agent_cert_validity_days,
        });
        CaResponse::json(200, body)
    }

    fn crl(&self) -> CaResponse {
        let opts = self.ca.options();
        let mut revoked = self.ca.get_crl();
        revoked.sort_by(|left, right| {
            left.revoked_at
                .cmp(&right.revoked_at)
                .then_with(|| left.serial.cmp(&right.serial))
                .then_with(|| left.nid.cmp(&right.nid))
        });
        let entries: Vec<Value> = revoked
            .iter()
            .map(|r| {
                json!({
                    "nid": r.nid,
                    "serial": r.serial,
                    "revoked_at": r.revoked_at.map(service::fmt_ts),
                    "reason": r.revoke_reason,
                })
            })
            .collect();
        let mut body = Map::new();
        body.insert("issued_by".into(), json!(opts.ca_nid));
        body.insert(
            "issued_at".into(),
            json!(service::fmt_ts(OffsetDateTime::now_utc())),
        );
        body.insert("entries".into(), json!(entries));
        let signature = self.ca.sign_artifact(&Value::Object(body.clone()));
        let mut out = body;
        out.insert("signature".into(), json!(signature));
        CaResponse::json(200, Value::Object(out))
    }

    fn certificates(&self, req: &CaRequest) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let mut records = self.ca.list_certificates();
        records.sort_by(|left, right| {
            left.issued_at
                .cmp(&right.issued_at)
                .then_with(|| left.serial.cmp(&right.serial))
        });
        let entries: Vec<Value> = records
            .iter()
            .map(|record| {
                json!({
                    "nid": record.nid,
                    "entity_type": record.entity_type,
                    "serial": record.serial,
                    "pub_key": record.pub_key,
                    "capabilities": record.capabilities,
                    "scope": serde_json::from_str::<Value>(&record.scope_json)
                        .unwrap_or(Value::Null),
                    "issued_by": record.issued_by,
                    "issued_at": service::fmt_ts(record.issued_at),
                    "expires_at": service::fmt_ts(record.expires_at),
                    "revoked_at": record.revoked_at.map(service::fmt_ts),
                    "revoke_reason": record.revoke_reason,
                    "nid_role": record.nid_role,
                    "parent_nid": record.parent_nid,
                })
            })
            .collect();
        CaResponse::json(200, json!({ "entries": entries }))
    }

    fn register(
        &self,
        req: &CaRequest,
        entity_type: &str,
        node_default_caps: &[String],
    ) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let body = match req.json_value() {
            Some(v) => v,
            None => return bad_request("Invalid JSON body."),
        };
        let (identifier, pub_key) = match validate_register(&body) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        let capabilities =
            string_list(&body, "capabilities").unwrap_or_else(|| node_default_caps.to_vec());
        let scope_json = scope_json(&body);
        let metadata_json = opt_string_field(&body, "metadata_json");
        let token = req.header("x-nps-enrollment-token").map(str::to_string);

        match self.ca.register_with_ra(
            entity_type,
            &identifier,
            &pub_key,
            &capabilities,
            &scope_json,
            metadata_json.as_deref(),
            token.as_deref(),
            self.policy.as_ref(),
        ) {
            Ok(frame) => CaResponse::json(201, frame_to_json(&frame)),
            Err(RegisterWithRaError::Pending(p)) => CaResponse::json(
                202,
                json!({ "pending_id": p.pending_id, "status": "queued" }),
            ),
            Err(RegisterWithRaError::Ca(e)) => error_result(&e),
        }
    }

    fn register_x509(
        &self,
        req: &CaRequest,
        entity_type: &str,
        node_default_caps: &[String],
    ) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let body = match req.json_value() {
            Some(v) => v,
            None => return bad_request("Invalid JSON body."),
        };
        let (identifier, pub_key) = match validate_register(&body) {
            Ok(t) => t,
            Err(e) => return bad_request(&e),
        };
        let capabilities =
            string_list(&body, "capabilities").unwrap_or_else(|| node_default_caps.to_vec());
        let scope_json = scope_json(&body);
        let metadata_json = opt_string_field(&body, "metadata_json");
        let assurance = parse_assurance(opt_string_field(&body, "assurance_level").as_deref());

        match self.ca.register_x509(
            entity_type,
            &identifier,
            &pub_key,
            &capabilities,
            &scope_json,
            Some(assurance),
            metadata_json.as_deref(),
        ) {
            Ok(frame) => CaResponse::json(201, frame_to_json(&frame)),
            Err(e) => error_result(&e),
        }
    }

    fn register_group(&self, req: &CaRequest) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let body = match req.json_value() {
            Some(v) => v,
            None => return bad_request("Invalid JSON body."),
        };
        let identifier = opt_string_field(&body, "identifier");
        if let Some(id) = &identifier {
            if !valid_identifier(id) {
                return bad_request(
                    "identifier contains invalid characters. Allowed: a-z A-Z 0-9 . _ : @ / -",
                );
            }
        }
        let pub_key = opt_string_field(&body, "pub_key").unwrap_or_default();
        if !valid_pub_key(&pub_key) {
            return bad_request("pub_key must be 'ed25519:<base64url>'.");
        }
        let capabilities = string_list(&body, "capabilities").unwrap_or_default();
        let scope_json = scope_json(&body);

        match self.ca.register_group(
            identifier.as_deref(),
            &pub_key,
            &capabilities,
            &scope_json,
            opt_string_field(&body, "owner_user_id").as_deref(),
            opt_string_field(&body, "owner_key_id").as_deref(),
            opt_string_field(&body, "metadata_json").as_deref(),
        ) {
            Ok(frame) => CaResponse::json(201, frame_to_json(&frame)),
            Err(e) => error_result(&e),
        }
    }

    fn renew(&self, req: &CaRequest, nid: &str) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        match self.ca.renew(&unescape(nid)) {
            Ok(frame) => CaResponse::json(200, frame_to_json(&frame)),
            Err(e) => error_result(&e),
        }
    }

    fn revoke(&self, req: &CaRequest, nid: &str) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let reason = req
            .json_value()
            .as_ref()
            .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| "cessation_of_operation".to_string());
        if !VALID_REVOCATION_REASONS.contains(&reason.as_str()) {
            return bad_request(&format!(
                "Invalid revocation reason '{reason}'. Allowed: {}.",
                VALID_REVOCATION_REASONS.join(", ")
            ));
        }
        match self.ca.revoke(&unescape(nid), &reason) {
            Ok(frame) => CaResponse::json(200, revoke_frame_to_json(&frame)),
            Err(e) => error_result(&e),
        }
    }

    fn verify(&self, nid: &str) -> CaResponse {
        ocsp_result(self.ca.verify(&unescape(nid)))
    }

    fn issue_session(&self, req: &CaRequest, group_nid: &str) -> CaResponse {
        let group_nid = unescape(group_nid);
        let ctype = req.header("content-type").unwrap_or("");
        let is_jws = ctype.to_ascii_lowercase().contains("jose+json");

        let (session_pub_key, purpose, validity_seconds, capabilities, scope_json, metadata_json);

        if is_jws {
            let jws: FlattenedJws = match req
                .json_value()
                .and_then(|v| serde_json::from_value(v).ok())
            {
                Some(j) => j,
                None => return bad_request("Invalid JWS body."),
            };
            let group_rec = match self.ca.get_cert(&group_nid) {
                Some(r) => r,
                None => {
                    return error_result(&NipCaError::new(
                        format!("Group {group_nid} not found."),
                        error_codes::CA_PARENT_NOT_FOUND,
                    ))
                }
            };
            if group_rec.nid_role.as_deref() != Some(ROLE_GROUP) {
                return error_result(&NipCaError::new(
                    format!("NID {group_nid} is not a group."),
                    error_codes::CA_PARENT_NOT_GROUP,
                ));
            }
            if group_rec.revoked_at.is_some() {
                return error_result(&NipCaError::new(
                    format!("Group {group_nid} revoked."),
                    error_codes::CA_GROUP_REVOKED,
                ));
            }
            let vk = match signer::decode_public_key(&group_rec.pub_key) {
                Some(k) => k,
                None => {
                    return CaResponse::json(
                        401,
                        json!({
                            "error_code": error_codes::CA_JWS_INVALID,
                            "message": "Group public key could not be decoded.",
                        }),
                    )
                }
            };
            let verified = match group_jws::try_verify(&jws, &vk) {
                Ok(v) => v,
                Err(code) => {
                    return CaResponse::json(
                        401,
                        json!({ "error_code": code, "message": "Group-JWS verification failed." }),
                    )
                }
            };
            if verified.kid != group_nid {
                return CaResponse::json(
                    401,
                    json!({
                        "error_code": error_codes::CA_JWS_INVALID,
                        "message": format!("JWS kid '{}' does not match URL group_nid '{}'.", verified.kid, group_nid),
                    }),
                );
            }
            let payload: Value = match serde_json::from_str(&verified.payload_json) {
                Ok(v) => v,
                Err(_) => {
                    return CaResponse::json(
                        401,
                        json!({
                            "error_code": error_codes::CA_JWS_INVALID,
                            "message": "JWS payload is not valid JSON.",
                        }),
                    )
                }
            };
            let iat = payload.get("iat").and_then(Value::as_i64).unwrap_or(0);
            let skew = self.ca.options().session_jws_clock_skew.whole_seconds();
            let now = OffsetDateTime::now_utc().unix_timestamp();
            if iat == 0 || (now - iat).abs() > skew {
                return CaResponse::json(
                    401,
                    json!({
                        "error_code": error_codes::CA_JWS_EXPIRED,
                        "message": format!("JWS iat outside ±{skew}s window."),
                    }),
                );
            }
            session_pub_key = payload
                .get("session_pub_key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            purpose = payload
                .get("purpose")
                .and_then(Value::as_str)
                .map(str::to_string);
            validity_seconds = payload.get("validity_seconds").and_then(Value::as_i64);
            capabilities = string_list(&payload, "capabilities");
            scope_json = payload
                .get("scope_json")
                .and_then(Value::as_str)
                .map(str::to_string);
            metadata_json = payload
                .get("metadata_json")
                .and_then(Value::as_str)
                .map(str::to_string);
        } else {
            if !self.authorized(req) {
                return unauthorized();
            }
            let body = match req.json_value() {
                Some(v) => v,
                None => return bad_request("Invalid JSON body."),
            };
            session_pub_key = opt_string_field(&body, "session_pub_key").unwrap_or_default();
            purpose = opt_string_field(&body, "purpose");
            validity_seconds = body.get("validity_seconds").and_then(Value::as_i64);
            capabilities = string_list(&body, "capabilities");
            scope_json = opt_string_field(&body, "scope_json");
            metadata_json = opt_string_field(&body, "metadata_json");
        }

        if !valid_pub_key(&session_pub_key) {
            return bad_request("session_pub_key must be 'ed25519:<base64url>'.");
        }

        let validity = validity_seconds.filter(|s| *s > 0).map(Duration::seconds);

        match self.ca.issue_session(
            &group_nid,
            &session_pub_key,
            IssueSessionParams {
                validity,
                purpose,
                capabilities,
                scope_json,
                metadata_json,
            },
        ) {
            Ok(frame) => CaResponse::json(201, frame_to_json(&frame)),
            Err(e) => error_result(&e),
        }
    }

    fn list_group_sessions(&self, group_nid: &str) -> CaResponse {
        let group_nid = unescape(group_nid);
        let sessions = self.ca.list_sessions(&group_nid);
        let items: Vec<Value> = sessions
            .iter()
            .map(|s| {
                json!({
                    "nid": s.nid,
                    "serial": s.serial,
                    "issued_at": service::fmt_ts(s.issued_at),
                    "expires_at": service::fmt_ts(s.expires_at),
                    "revoked_at": s.revoked_at.map(service::fmt_ts),
                    "revoke_reason": s.revoke_reason,
                })
            })
            .collect();
        CaResponse::json(
            200,
            json!({ "group_nid": group_nid, "count": sessions.len(), "sessions": items }),
        )
    }

    fn create_token(&self, req: &CaRequest) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let store = match self.bootstrap_store {
            Some(s) => s,
            None => {
                return CaResponse::json(
                    400,
                    json!({
                        "error_code": "NIP-CA-BAD-REQUEST",
                        "message": "Bootstrap token enrollment is not enabled on this CA.",
                    }),
                )
            }
        };
        let body = req.json_value();
        let ttl_seconds = body
            .as_ref()
            .and_then(|v| v.get("ttl_seconds").and_then(Value::as_i64));
        let requested = ttl_seconds.filter(|s| *s > 0).map(Duration::seconds);
        let ttl = super::ra::clamp_bootstrap_ttl(self.ca.options(), requested);
        let label = body
            .as_ref()
            .and_then(|v| v.get("label").and_then(Value::as_str).map(str::to_string));
        let expires_at = OffsetDateTime::now_utc() + ttl;
        let raw = store.create(label.clone(), expires_at);
        CaResponse::json(
            201,
            json!({ "token": raw, "expires_at": service::fmt_ts(expires_at), "label": label }),
        )
    }

    fn list_pending(&self, req: &CaRequest) -> CaResponse {
        if !self.authorized(req) {
            return unauthorized();
        }
        let store = match self.pending_store {
            Some(s) => s,
            None => return pending_disabled(),
        };
        let records = store.list();
        let items: Vec<Value> = records
            .iter()
            .map(|r| {
                json!({
                    "id": r.id,
                    "entity_type": r.entity_type,
                    "identifier": r.identifier,
                    "pub_key": r.pub_key,
                    "capabilities": r.capabilities,
                    "scope_json": r.scope_json,
                    "requested_at": service::fmt_ts(r.requested_at),
                    "status": r.status.as_wire(),
                    "reject_reason": r.reject_reason,
                })
            })
            .collect();
        CaResponse::json(200, json!({ "count": records.len(), "items": items }))
    }

    fn approve_pending(&self, id: &str) -> CaResponse {
        let store = match self.pending_store {
            Some(s) => s,
            None => return pending_disabled(),
        };
        let record = match store.get(id) {
            Some(r) => r,
            None => {
                return CaResponse::json(
                    404,
                    json!({
                        "error_code": error_codes::CA_NID_NOT_FOUND,
                        "message": format!("Pending registration '{id}' not found."),
                    }),
                )
            }
        };
        if record.status != PendingStatus::Pending {
            return CaResponse::json(
                409,
                json!({
                    "error_code": "NIP-CA-BAD-REQUEST",
                    "message": format!("Record '{id}' is already {}.", record.status.as_wire()),
                }),
            );
        }
        match self.ca.register(
            &record.entity_type,
            &record.identifier,
            &record.pub_key,
            &record.capabilities,
            &record.scope_json,
            record.metadata_json.as_deref(),
        ) {
            Ok(frame) => {
                store.approve(id);
                CaResponse::json(201, frame_to_json(&frame))
            }
            Err(e) => error_result(&e),
        }
    }

    fn reject_pending(&self, req: &CaRequest, id: &str) -> CaResponse {
        let store = match self.pending_store {
            Some(s) => s,
            None => return pending_disabled(),
        };
        let reason = req
            .json_value()
            .as_ref()
            .and_then(|v| v.get("reason").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| "rejected_by_operator".to_string());

        if store.reject(id, &reason) {
            return CaResponse::json(
                200,
                json!({ "id": id, "status": "rejected", "reason": reason }),
            );
        }
        match store.get(id) {
            None => CaResponse::json(
                404,
                json!({
                    "error_code": "NIP-CA-BAD-REQUEST",
                    "message": format!("Pending registration '{id}' not found."),
                }),
            ),
            Some(r) => CaResponse::json(
                409,
                json!({
                    "error_code": "NIP-CA-BAD-REQUEST",
                    "message": format!("Record '{id}' is already {}.", r.status.as_wire()),
                }),
            ),
        }
    }

    // ── Auth ──────────────────────────────────────────────────────────────────

    fn authorized(&self, req: &CaRequest) -> bool {
        let key = match &self.ca.options().operator_api_key {
            Some(k) => k,
            None => return true,
        };
        let header = req.header("authorization").unwrap_or("");
        let provided = match header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        {
            Some(p) => p.trim(),
            None => return false,
        };
        constant_time_eq(provided.as_bytes(), key.as_bytes())
    }
}

// ── Free helpers ────────────────────────────────────────────────────────────

/// Extract the segment between `prefix` and `suffix` in `rel`, when `rel` is
/// exactly `{prefix}{seg}{suffix}` and `seg` is non-empty.
fn seg_between(rel: &str, prefix: &str, suffix: &str) -> Option<String> {
    let rest = rel.strip_prefix(prefix)?;
    let seg = rest.strip_suffix(suffix)?;
    if seg.is_empty() {
        None
    } else {
        Some(seg.to_string())
    }
}

fn unescape(s: &str) -> String {
    // Minimal percent-decoding for NIDs (`urn:nps:...` may contain `%3A`, etc.).
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_string())
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 256
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '@' | '/' | '-'))
}

fn valid_pub_key(pk: &str) -> bool {
    pk.starts_with("ed25519:") && pk.len() > 8
}

fn validate_register(body: &Value) -> Result<(String, String), String> {
    let identifier = opt_string_field(body, "identifier").unwrap_or_default();
    let pub_key = opt_string_field(body, "pub_key").unwrap_or_default();
    if identifier.is_empty() || pub_key.is_empty() {
        return Err("identifier and pub_key are required.".into());
    }
    if !valid_identifier(&identifier) {
        return Err(
            "identifier contains invalid characters. Allowed: a-z A-Z 0-9 . _ : @ / -".into(),
        );
    }
    if !valid_pub_key(&pub_key) {
        return Err("pub_key must be 'ed25519:<base64url>'.".into());
    }
    Ok((identifier, pub_key))
}

fn opt_string_field(body: &Value, key: &str) -> Option<String> {
    body.get(key).and_then(Value::as_str).map(str::to_string)
}

fn string_list(body: &Value, key: &str) -> Option<Vec<String>> {
    body.get(key).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

fn scope_json(body: &Value) -> String {
    match body.get("scope_json") {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => "{}".to_string(),
    }
}

fn parse_assurance(raw: Option<&str>) -> crate::assurance_level::AssuranceLevel {
    match raw.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("attested") => crate::assurance_level::ATTESTED,
        Some("verified") => crate::assurance_level::VERIFIED,
        _ => crate::assurance_level::ANONYMOUS,
    }
}

fn frame_to_json(frame: &IdentFrame) -> Value {
    Value::Object(frame.to_dict())
}

fn revoke_frame_to_json(frame: &crate::frames::RevokeFrame) -> Value {
    Value::Object(frame.to_dict())
}

fn ocsp_result(r: NipVerifyResult) -> CaResponse {
    if r.valid {
        let rec = r.record.unwrap();
        return CaResponse::json(
            200,
            json!({
                "valid": true,
                "nid": rec.nid,
                "expires_at": service::fmt_ts(rec.expires_at),
                "serial": rec.serial,
            }),
        );
    }
    let code = r.error_code.unwrap_or(error_codes::CA_NID_NOT_FOUND);
    let status = if code == error_codes::CA_NID_NOT_FOUND {
        404
    } else {
        200
    };
    CaResponse::json(
        status,
        json!({ "valid": false, "error_code": code, "message": r.message }),
    )
}

fn error_result(e: &NipCaError) -> CaResponse {
    let status = match e.code {
        error_codes::CA_NID_NOT_FOUND => 404,
        error_codes::CA_PARENT_NOT_FOUND => 404,
        error_codes::CA_NID_ALREADY_EXISTS => 409,
        error_codes::CA_SERIAL_DUPLICATE => 409,
        error_codes::CA_RENEWAL_TOO_EARLY => 400,
        error_codes::CA_SESSION_VALIDITY_INVALID => 400,
        error_codes::CA_PARENT_NOT_GROUP => 400,
        error_codes::CA_SCOPE_EXPANSION_DENIED => 403,
        error_codes::CERT_CAPABILITY_MISSING => 403,
        error_codes::CA_GROUP_REVOKED => 403,
        error_codes::CA_JWS_INVALID => 401,
        error_codes::CA_JWS_EXPIRED => 401,
        error_codes::CERT_EXPIRED => 401,
        error_codes::CERT_REVOKED => 401,
        error_codes::CERT_PARENT_REVOKED => 401,
        error_codes::RA_TOKEN_INVALID => 401,
        error_codes::RA_TOKEN_EXPIRED => 401,
        error_codes::RA_NID_NOT_ALLOWED => 403,
        error_codes::RA_PENDING_REJECTED => 403,
        _ => 400,
    };
    CaResponse::json(
        status,
        json!({ "error_code": e.code, "message": e.message }),
    )
}

fn bad_request(msg: &str) -> CaResponse {
    CaResponse::json(
        400,
        json!({ "error_code": "NIP-CA-BAD-REQUEST", "message": msg }),
    )
}

fn unauthorized() -> CaResponse {
    CaResponse::json(
        401,
        json!({ "error_code": "NIP-CA-UNAUTHORIZED", "message": "Valid operator Bearer token required." }),
    )
}

fn pending_disabled() -> CaResponse {
    CaResponse::json(
        400,
        json!({
            "error_code": "NIP-CA-BAD-REQUEST",
            "message": "Pending-queue enrollment is not enabled on this CA.",
        }),
    )
}
