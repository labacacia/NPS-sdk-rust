// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Anchor Node server — framework-agnostic request handler (zero new deps).
//!
//! Server-side counterpart of [`crate::anchor_client::AnchorNodeClient`], porting
//! the .NET `AnchorNodeMiddleware` wire contract (NPS-AaaS §2, NPS-2 §12) and
//! mirroring the Python/TS/Go/Java reference ports.
//!
//! [`AnchorNodeApp::handle`] takes an [`AnchorRequest`] and returns an
//! [`AnchorResponse`] — adapt it to any HTTP server (hyper, axum, tiny_http, …).
//! The business execution behind `/invoke` is delegated to an injected
//! [`InvokeHandler`] (NOP orchestration is host-supplied).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nps_nip::AssuranceLevel;
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::anchor_client::{MemberInfo, TopologyEvent, TopologyFilter, TopologySnapshot};
use crate::reputation::{RepOutcome, ReputationPolicy};
use crate::reputation_policy::DefaultReputationPolicyEvaluator;
use crate::{error_codes, http_headers};

const SNAPSHOT_ANCHOR_REF: &str = "nps:system:topology:snapshot";

// ── Request / response ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnchorRequest {
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl AnchorRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        AnchorRequest {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_ascii_lowercase(), value.into());
        self
    }

    pub fn with_json(mut self, value: &Value) -> Self {
        self.body = serde_json::to_vec(value).unwrap_or_default();
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(&name.to_ascii_lowercase()).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct AnchorResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl AnchorResponse {
    pub fn json_value(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// NDJSON lines (for `/subscribe`).
    pub fn ndjson_lines(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.body)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

// ── Options / handler / topology ──────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct AnchorActionSpec {
    pub description: Option<String>,
    pub params_anchor: Option<String>,
    pub result_anchor: Option<String>,
    pub estimated_cgn: Option<u32>,
    pub timeout_ms_default: Option<u32>,
    pub timeout_ms_max: Option<u32>,
    pub required_capability: Option<String>,
    pub async_: bool,
}

pub struct AnchorNodeOptions {
    pub node_id: String,
    pub path_prefix: String,
    pub actions: HashMap<String, AnchorActionSpec>,
    pub display_name: Option<String>,
    pub require_auth: bool,
    pub required_capabilities: Option<Vec<String>>,
    pub require_topology_capability: bool,
    pub default_timeout_ms: u32,
    pub max_timeout_ms: u32,
    pub default_token_budget: u32,
    pub cgn_limit: u32,
    pub assurance_hint_url: Option<String>,
    pub reputation_policy: Option<ReputationPolicy>,
    pub trust_anchors: Option<Vec<String>>,
    pub rate_limits: Option<Value>,
    pub auto_inject_trace_context: bool,
}

impl AnchorNodeOptions {
    pub fn new(node_id: impl Into<String>, path_prefix: impl Into<String>) -> Self {
        AnchorNodeOptions {
            node_id: node_id.into(),
            path_prefix: path_prefix.into(),
            actions: HashMap::new(),
            display_name: None,
            require_auth: true,
            required_capabilities: None,
            require_topology_capability: false,
            default_timeout_ms: 30_000,
            max_timeout_ms: 300_000,
            default_token_budget: 0,
            cgn_limit: 0,
            assurance_hint_url: None,
            reputation_policy: None,
            trust_anchors: None,
            rate_limits: None,
            auto_inject_trace_context: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InvokeContext {
    pub agent_nid: Option<String>,
    pub effective_timeout_ms: u32,
    pub budget_cgn: u32,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnchorActionError {
    pub http_status: u16,
    pub nps_status: String,
    pub error_code: String,
    pub message: String,
    pub details: Option<Value>,
}

/// Executes an action and returns the result payload, or an error envelope.
pub type InvokeHandler =
    Box<dyn Fn(&str, Option<&Value>, &InvokeContext) -> Result<Value, AnchorActionError> + Send + Sync>;

/// Outcome of a rate-limit admission check.
#[derive(Debug, Clone)]
pub struct RateDecision {
    pub allowed: bool,
    pub retry_after_seconds: Option<u32>,
    pub reason: Option<String>,
}

impl RateDecision {
    pub fn allow() -> Self {
        RateDecision { allowed: true, retry_after_seconds: None, reason: None }
    }
}

/// Per-consumer rate-limit hook for `/invoke` admission (mirrors the Python/Java/TS ports'
/// `RateLimiter`). The default [`AllowAllRateLimiter`] is a no-op; inject a real limiter with
/// [`AnchorNodeApp::with_rate_limiter`].
pub trait RateLimiter: Send + Sync {
    fn try_acquire(&self, consumer_key: &str, cost_hint: u32) -> RateDecision;
    fn release(&self, consumer_key: &str);
}

/// Default permissive limiter — admits every request.
pub struct AllowAllRateLimiter;

impl RateLimiter for AllowAllRateLimiter {
    fn try_acquire(&self, _consumer_key: &str, _cost_hint: u32) -> RateDecision {
        RateDecision::allow()
    }
    fn release(&self, _consumer_key: &str) {}
}

#[derive(Debug, Clone)]
pub struct AnchorSnapshotRequest {
    pub scope: String,
    pub include: Vec<String>,
    pub depth: u8,
    pub target_nid: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnchorStreamRequest {
    pub scope: String,
    pub filter: Option<TopologyFilter>,
    pub since_version: Option<u64>,
}

pub trait AnchorTopologyService: Send + Sync {
    fn anchor_nid(&self) -> &str;
    fn get_snapshot(&self, req: &AnchorSnapshotRequest) -> TopologySnapshot;
    fn subscribe(&self, req: &AnchorStreamRequest) -> Vec<TopologyEvent>;
}

pub struct InMemoryAnchorTopologyService {
    pub nid: String,
    pub members: Vec<MemberInfo>,
    pub version: u64,
    pub events: Vec<TopologyEvent>,
}

impl AnchorTopologyService for InMemoryAnchorTopologyService {
    fn anchor_nid(&self) -> &str {
        &self.nid
    }

    fn get_snapshot(&self, req: &AnchorSnapshotRequest) -> TopologySnapshot {
        let members = if req.include.iter().any(|i| i == "members") {
            self.members.clone()
        } else {
            Vec::new()
        };
        TopologySnapshot {
            version: self.version,
            anchor_nid: self.nid.clone(),
            cluster_size: self.members.len() as u32,
            members,
            truncated: None,
        }
    }

    fn subscribe(&self, _req: &AnchorStreamRequest) -> Vec<TopologyEvent> {
        self.events.clone()
    }
}

struct TopologyProtocolError {
    nwp_error_code: &'static str,
    nps_status: &'static str,
    message: String,
}

// ── The app ──────────────────────────────────────────────────────────────────

pub struct AnchorNodeApp {
    opt: AnchorNodeOptions,
    prefix: String,
    handler: Option<InvokeHandler>,
    topology: Option<Box<dyn AnchorTopologyService>>,
    evaluator: Option<DefaultReputationPolicyEvaluator>,
    limiter: Box<dyn RateLimiter>,
    nwm_json: Vec<u8>,
    actions_json: Vec<u8>,
}

impl AnchorNodeApp {
    pub fn new(
        opt: AnchorNodeOptions,
        handler: Option<InvokeHandler>,
        topology: Option<Box<dyn AnchorTopologyService>>,
        evaluator: Option<DefaultReputationPolicyEvaluator>,
    ) -> Self {
        let prefix = opt.path_prefix.trim_end_matches('/').to_string();
        let nwm_json = serde_json::to_vec(&build_manifest(&opt, &prefix)).unwrap_or_default();
        let actions_json =
            serde_json::to_vec(&json!({ "actions": actions_map(&opt) })).unwrap_or_default();
        AnchorNodeApp {
            opt,
            prefix,
            handler,
            topology,
            evaluator,
            limiter: Box::new(AllowAllRateLimiter),
            nwm_json,
            actions_json,
        }
    }

    /// Installs a per-consumer rate limiter for `/invoke` admission (defaults to
    /// [`AllowAllRateLimiter`]). Mirrors the `RateLimiter` hook in the Python/Java/TS ports.
    pub fn with_rate_limiter(mut self, limiter: Box<dyn RateLimiter>) -> Self {
        self.limiter = limiter;
        self
    }

    pub async fn handle(&self, req: AnchorRequest) -> AnchorResponse {
        if !req.path.starts_with(&self.prefix) {
            return error_resp(404, "NPS-CLIENT-NOT-FOUND", error_codes::ACTION_NOT_FOUND,
                "no NWP node at this path.", None, &[]);
        }
        let sub = &req.path[self.prefix.len()..];

        // Resolve the route BEFORE the auth gate: an unknown sub-path is a 404 regardless of auth,
        // so a missing X-NWP-Agent on a non-existent route does not leak a 401 (auth state) for a
        // path that has no resource. Known routes still fall through to the auth check below.
        let known_route = matches!(
            sub,
            "/.nwm" | "/.nwm/" | "/.schema" | "/.schema/" | "/actions" | "/actions/"
                | "/invoke" | "/invoke/" | "/query" | "/query/" | "/subscribe" | "/subscribe/"
        );
        if !known_route {
            return error_resp(404, "NPS-CLIENT-NOT-FOUND", error_codes::ACTION_NOT_FOUND,
                "unknown anchor sub-path.", None, &[]);
        }

        if self.opt.require_auth && req.header(http_headers::AGENT).is_none() {
            return error_resp(401, "NPS-AUTH-UNAUTHENTICATED", error_codes::AUTH_NID_SCOPE_VIOLATION,
                "X-NWP-Agent header is required.", None, &[]);
        }

        match sub {
            "/.nwm" | "/.nwm/" => AnchorResponse {
                status: 200,
                headers: vec![
                    ("content-type".into(), http_headers::MIME_MANIFEST.into()),
                    (http_headers::NODE_TYPE.to_ascii_lowercase(), "anchor".into()),
                ],
                body: self.nwm_json.clone(),
            },
            "/.schema" | "/.schema/" | "/actions" | "/actions/" => AnchorResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.actions_json.clone(),
            },
            "/invoke" | "/invoke/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_invoke(&req).await
            }
            "/query" | "/query/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_query(&req)
            }
            "/subscribe" | "/subscribe/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_subscribe(&req)
            }
            _ => error_resp(404, "NPS-CLIENT-NOT-FOUND", error_codes::ACTION_NOT_FOUND,
                "unknown anchor sub-path.", None, &[]),
        }
    }

    fn handle_query(&self, req: &AnchorRequest) -> AnchorResponse {
        if let Some(resp) = self.check_topology_capability(req) {
            return resp;
        }
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return error_resp(400, "NPS-CLIENT-BAD-REQUEST", error_codes::QUERY_FILTER_INVALID,
                &e.to_string(), None, &[]),
        };
        if body.get("type").and_then(Value::as_str) != Some("topology.snapshot") {
            let t = body.get("type").and_then(Value::as_str);
            let msg = match t {
                None => "Anchor /query requires a reserved type per NPS-2 §12.".to_string(),
                Some(t) => format!("Reserved query type '{t}' is not implemented by this Anchor Node."),
            };
            return error_resp(501, "NPS-SERVER-UNSUPPORTED", error_codes::RESERVED_TYPE_UNSUPPORTED, &msg, None, &[]);
        }
        let topology = match &self.topology {
            Some(t) => t,
            None => return error_resp(501, "NPS-SERVER-UNSUPPORTED", error_codes::NODE_UNAVAILABLE,
                "topology.snapshot is not available — no topology service registered.", None, &[]),
        };
        let request = match parse_snapshot_request(&body) {
            Ok(r) => r,
            Err(e) => return topology_error_resp(&e),
        };
        let snap = topology.get_snapshot(&request);
        let caps = json!({ "anchor_ref": SNAPSHOT_ANCHOR_REF, "count": 1, "data": [snap] });
        AnchorResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), http_headers::MIME_CAPSULE.into()),
                (http_headers::NODE_TYPE.to_ascii_lowercase(), "anchor".into()),
                (http_headers::SCHEMA.to_ascii_lowercase(), SNAPSHOT_ANCHOR_REF.into()),
            ],
            body: serde_json::to_vec(&caps).unwrap_or_default(),
        }
    }

    fn handle_subscribe(&self, req: &AnchorRequest) -> AnchorResponse {
        if let Some(resp) = self.check_topology_capability(req) {
            return resp;
        }
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return error_resp(400, "NPS-CLIENT-BAD-REQUEST", error_codes::QUERY_FILTER_INVALID,
                &e.to_string(), None, &[]),
        };
        if body.get("type").and_then(Value::as_str) != Some("topology.stream") {
            let t = body.get("type").and_then(Value::as_str);
            let msg = match t {
                None => "Anchor /subscribe requires a reserved type per NPS-2 §12.".to_string(),
                Some(t) => format!("Reserved subscribe type '{t}' is not implemented by this Anchor Node."),
            };
            return error_resp(501, "NPS-SERVER-UNSUPPORTED", error_codes::RESERVED_TYPE_UNSUPPORTED, &msg, None, &[]);
        }
        let topology = match &self.topology {
            Some(t) => t,
            None => return error_resp(501, "NPS-SERVER-UNSUPPORTED", error_codes::NODE_UNAVAILABLE,
                "topology.stream is not available — no topology service registered.", None, &[]),
        };
        let (request, stream_id) = match parse_stream_request(&body) {
            Ok(r) => r,
            Err(e) => return topology_error_resp(&e),
        };

        let mut out = String::new();
        let ack = json!({
            "kind": "ack", "stream_id": stream_id, "status": "subscribed",
            "last_seq": 0, "resumed": request.since_version.is_some()
        });
        out.push_str(&serde_json::to_string(&ack).unwrap_or_default());
        out.push('\n');
        for ev in topology.subscribe(&request) {
            let envelope = event_to_envelope(&stream_id, &ev);
            out.push_str(&serde_json::to_string(&envelope).unwrap_or_default());
            out.push('\n');
            if matches!(ev, TopologyEvent::ResyncRequired { .. }) {
                break;
            }
        }
        AnchorResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), http_headers::MIME_CAPSULE.into()),
                (http_headers::NODE_TYPE.to_ascii_lowercase(), "anchor".into()),
            ],
            body: out.into_bytes(),
        }
    }

    async fn handle_invoke(&self, req: &AnchorRequest) -> AnchorResponse {
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => return error_resp(400, "NPS-CLIENT-BAD-REQUEST", error_codes::ACTION_PARAMS_INVALID,
                &e.to_string(), None, &[]),
        };
        let action_id = match body.get("action_id").and_then(Value::as_str) {
            Some(a) if !a.is_empty() => a.to_string(),
            _ => return error_resp(400, "NPS-CLIENT-BAD-REQUEST", error_codes::ACTION_PARAMS_INVALID,
                "invalid ActionFrame: missing action_id.", None, &[]),
        };
        let spec = match self.opt.actions.get(&action_id) {
            Some(s) => s.clone(),
            None => return error_resp(404, "NPS-CLIENT-NOT-FOUND", error_codes::ACTION_NOT_FOUND,
                &format!("Unknown action_id '{action_id}'."), None, &[]),
        };
        let is_async = body.get("async").and_then(Value::as_bool).unwrap_or(false);
        if is_async && !spec.async_ {
            return error_resp(400, "NPS-CLIENT-BAD-REQUEST", error_codes::ACTION_PARAMS_INVALID,
                &format!("action '{action_id}' does not support async execution."), None, &[]);
        }

        let agent_nid = req.header(http_headers::AGENT).map(String::from);
        let timeout_ms = body.get("timeout_ms").and_then(Value::as_u64).unwrap_or(0) as u32;
        let effective_timeout = clamp_timeout(timeout_ms, &spec, &self.opt);
        let budget_cgn = read_effective_budget(req, &self.opt);
        let cgn_cost_hint = spec.estimated_cgn.unwrap_or(0);

        // Reputation policy gate.
        let assurance = extract_ident_assurance(req);
        if let (Some(policy), Some(evaluator)) = (&self.opt.reputation_policy, &self.evaluator) {
            if policy.enabled {
                let consumer = agent_nid.clone().unwrap_or_else(|| "anonymous".to_string());
                let decision = evaluator.evaluate(&consumer, &assurance, policy).await;
                if let Some(resp) = self.apply_reputation(&decision, policy, &assurance) {
                    return resp;
                }
            }
        }

        if budget_cgn > 0 && cgn_cost_hint > 0 && cgn_cost_hint > budget_cgn {
            return error_resp(400, "NPS-CLIENT-REQUEST-TOO-LARGE", error_codes::CGN_LIMIT_EXCEEDED,
                &format!("estimated CGN {cgn_cost_hint} exceeds effective budget {budget_cgn}."),
                Some(json!({ "effective_budget": budget_cgn, "estimated_cgn": cgn_cost_hint })), &[]);
        }

        let handler = match &self.handler {
            Some(h) => h,
            None => return error_resp(501, "NPS-SERVER-UNSUPPORTED", error_codes::NODE_UNAVAILABLE,
                "no invoke handler registered on this Anchor Node.", None, &[]),
        };

        // Rate-limit admission (NPS-AaaS; mirrors the Python/Java/TS ports). The default
        // AllowAllRateLimiter is a no-op; a real limiter is injected via with_rate_limiter().
        let consumer_key = agent_nid.clone().unwrap_or_else(|| "anonymous".to_string());
        let rate = self.limiter.try_acquire(&consumer_key, cgn_cost_hint);
        if !rate.allowed {
            let extra = match rate.retry_after_seconds {
                Some(s) => vec![("retry-after".to_string(), s.to_string())],
                None => Vec::new(),
            };
            return error_resp(429, "NPS-CLIENT-RATE-LIMITED", error_codes::RATE_LIMIT_EXCEEDED,
                rate.reason.as_deref().unwrap_or("rate limit exceeded."), None, &extra);
        }

        let ctx = InvokeContext {
            agent_nid: agent_nid.clone(),
            effective_timeout_ms: effective_timeout,
            budget_cgn,
            trace_id: if self.opt.auto_inject_trace_context { Some(gen_hex(16)) } else { None },
            span_id: if self.opt.auto_inject_trace_context { Some(gen_hex(8)) } else { None },
        };
        let params = body.get("params");

        // NOTE: the invoke handler is a synchronous closure, so the runtime cannot preempt it on
        // `ctx.effective_timeout_ms` (unlike the Python async port's `asyncio.wait_for`). A
        // long-running handler MUST honour `effective_timeout_ms` cooperatively; the host adapter
        // (hyper/axum/…) is responsible for any hard wall-clock deadline on the connection.
        if is_async {
            let task_id = gen_hex(16);
            let _ = handler(&action_id, params, &ctx); // reference impl runs inline, result discarded
            self.limiter.release(&consumer_key);
            return AnchorResponse {
                status: 202,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    (http_headers::NODE_TYPE.to_ascii_lowercase(), "anchor".into()),
                ],
                body: serde_json::to_vec(&json!({
                    "task_id": task_id, "status": "pending", "poll_url": format!("{}/invoke", self.prefix)
                })).unwrap_or_default(),
            };
        }

        let response = match handler(&action_id, params, &ctx) {
            Ok(result) => {
                let (count, data) = if result.is_null() {
                    (0, vec![])
                } else {
                    (1, vec![result])
                };
                let caps = json!({
                    "anchor_ref": spec.result_anchor.clone().unwrap_or_default(),
                    "count": count, "data": data
                });
                let mut headers = vec![
                    ("content-type".to_string(), http_headers::MIME_CAPSULE.to_string()),
                    (http_headers::NODE_TYPE.to_ascii_lowercase(), "anchor".to_string()),
                ];
                if let Some(ra) = &spec.result_anchor {
                    headers.push((http_headers::SCHEMA.to_ascii_lowercase(), ra.clone()));
                }
                if let Some(c) = spec.estimated_cgn {
                    if c > 0 {
                        headers.push((http_headers::TOKENS.to_ascii_lowercase(), c.to_string()));
                    }
                }
                AnchorResponse { status: 200, headers, body: serde_json::to_vec(&caps).unwrap_or_default() }
            }
            Err(e) => error_resp(e.http_status, &e.nps_status, &e.error_code, &e.message, e.details, &[]),
        };
        self.limiter.release(&consumer_key);
        response
    }

    fn apply_reputation(
        &self,
        d: &crate::reputation::ReputationDecision,
        policy: &ReputationPolicy,
        assurance: &AssuranceLevel,
    ) -> Option<AnchorResponse> {
        // The reference ReputationDecision carries the matched rule rather than separate
        // incident/severity fields; derive them from matched_rule.
        let incident = d.matched_rule.as_ref().map(|r| r.incident.clone());
        let severity = d.matched_rule.as_ref().map(|r| r.severity.clone());
        match d.outcome {
            RepOutcome::Accept => None,
            RepOutcome::Ban => {
                let (msg, details) = if incident.is_some() {
                    (format!("Request rejected: {} ({}) — NID temporarily banned.",
                        opt_str(&incident), opt_str(&severity)),
                     Some(json!({ "matched_incident": incident, "matched_severity": severity })))
                } else {
                    ("Request rejected: NID temporarily banned.".to_string(), None)
                };
                Some(error_resp(403, "NPS-AUTH-FORBIDDEN", error_codes::REPUTATION_BANNED, &msg, details, &[]))
            }
            RepOutcome::Reject => {
                if d.error_code.as_deref() == Some(error_codes::AUTH_ASSURANCE_TOO_LOW) {
                    Some(error_resp(403, "NPS-AUTH-FORBIDDEN", error_codes::AUTH_ASSURANCE_TOO_LOW,
                        &format!("Assurance level too low: requires '{}', caller declared '{}'.",
                            policy.min_assurance_level, assurance.wire),
                        Some(json!({ "matched_incident": Value::Null, "hint": self.opt.assurance_hint_url })), &[]))
                } else {
                    let (msg, details) = if incident.is_some() {
                        (format!("Request rejected: {} ({}).", opt_str(&incident), opt_str(&severity)),
                         Some(json!({ "matched_incident": incident, "matched_severity": severity })))
                    } else {
                        ("Request rejected by reputation policy.".to_string(), None)
                    };
                    Some(error_resp(403, "NPS-AUTH-FORBIDDEN", error_codes::REPUTATION_REJECTED, &msg, details, &[]))
                }
            }
            RepOutcome::Throttle => {
                let (msg, details) = if incident.is_some() {
                    (format!("Request rate-limited: {} ({}).", opt_str(&incident), opt_str(&severity)),
                     Some(json!({ "matched_incident": incident, "matched_severity": severity })))
                } else {
                    ("Request rate-limited by reputation policy.".to_string(), None)
                };
                Some(error_resp(429, "NPS-CLIENT-RATE-LIMITED", error_codes::REPUTATION_THROTTLED, &msg, details,
                    &[("retry-after".to_string(), "60".to_string())]))
            }
        }
    }

    fn check_topology_capability(&self, req: &AnchorRequest) -> Option<AnchorResponse> {
        if !self.opt.require_topology_capability {
            return None;
        }
        let raw = req.header(http_headers::CAPABILITIES).unwrap_or("");
        if raw.split(',').any(|c| c.trim().eq_ignore_ascii_case("topology:read")) {
            return None;
        }
        Some(error_resp(403, "NPS-AUTH-FORBIDDEN", error_codes::TOPOLOGY_UNAUTHORIZED,
            "Caller must declare 'topology:read' in X-NWP-Capabilities to access topology endpoints.", None, &[]))
    }
}

// ── Free helpers ──────────────────────────────────────────────────────────────

fn opt_str(o: &Option<String>) -> &str {
    o.as_deref().unwrap_or("")
}

fn empty(status: u16) -> AnchorResponse {
    AnchorResponse { status, headers: vec![], body: vec![] }
}

fn error_resp(
    status: u16,
    nps_status: &str,
    error_code: &str,
    message: &str,
    details: Option<Value>,
    extra: &[(String, String)],
) -> AnchorResponse {
    let mut env = Map::new();
    env.insert("status".into(), Value::String(nps_status.into()));
    env.insert("error".into(), Value::String(error_code.into()));
    env.insert("message".into(), Value::String(message.into()));
    if let Some(d) = details {
        env.insert("details".into(), d);
    }
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend(extra.iter().cloned());
    AnchorResponse { status, headers, body: serde_json::to_vec(&Value::Object(env)).unwrap_or_default() }
}

fn topology_error_resp(e: &TopologyProtocolError) -> AnchorResponse {
    let status = if e.nps_status == "NPS-AUTH-FORBIDDEN" { 403 } else { 400 };
    error_resp(status, e.nps_status, e.nwp_error_code, &e.message, None, &[])
}

fn clamp_timeout(requested: u32, spec: &AnchorActionSpec, opt: &AnchorNodeOptions) -> u32 {
    let spec_max = spec.timeout_ms_max.unwrap_or(opt.max_timeout_ms);
    let hard_max = spec_max.min(opt.max_timeout_ms);
    if requested == 0 {
        return spec.timeout_ms_default.unwrap_or(opt.default_timeout_ms);
    }
    requested.min(hard_max)
}

fn read_effective_budget(req: &AnchorRequest, opt: &AnchorNodeOptions) -> u32 {
    let agent_budget = req
        .header(http_headers::BUDGET)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(opt.default_token_budget);
    let cgn_limit = opt.cgn_limit;
    if cgn_limit == 0 {
        return agent_budget;
    }
    if agent_budget == 0 {
        return cgn_limit;
    }
    cgn_limit.min(agent_budget)
}

fn extract_ident_assurance(req: &AnchorRequest) -> AssuranceLevel {
    let raw = match req.header(http_headers::IDENT) {
        Some(r) if !r.is_empty() => r,
        _ => return nps_nip::ANONYMOUS,
    };
    if let Ok(doc) = serde_json::from_str::<Value>(raw) {
        if let Some(lvl) = doc.get("assurance_level").and_then(Value::as_str) {
            if let Ok(a) = AssuranceLevel::from_wire(lvl) {
                return a;
            }
        }
    }
    nps_nip::ANONYMOUS
}

fn event_to_envelope(stream_id: &str, ev: &TopologyEvent) -> Value {
    let (event_type, seq, payload): (&str, Option<u64>, Value) = match ev {
        TopologyEvent::MemberJoined { version, member } => (
            "member_joined",
            Some(*version),
            serde_json::to_value(member).unwrap_or(Value::Null),
        ),
        TopologyEvent::MemberLeft { version, nid } => {
            ("member_left", Some(*version), json!({ "nid": nid }))
        }
        TopologyEvent::MemberUpdated { version, nid, changes } => (
            "member_updated",
            Some(*version),
            json!({ "nid": nid, "changes": changes }),
        ),
        TopologyEvent::AnchorState { version, field, details } => (
            "anchor_state",
            Some(*version),
            json!({ "field": field, "details": details }),
        ),
        TopologyEvent::ResyncRequired { reason } => {
            ("resync_required", None, json!({ "reason": reason }))
        }
    };
    let raw_len = serde_json::to_vec(&payload).map(|v| v.len()).unwrap_or(0);
    let cgn_est = (raw_len / 4).max(1);
    let mut env = Map::new();
    env.insert("stream_id".into(), Value::String(stream_id.into()));
    env.insert("event_type".into(), Value::String(event_type.into()));
    env.insert("timestamp".into(), Value::String(now_rfc3339()));
    env.insert("payload".into(), payload);
    env.insert("cgn_est".into(), Value::from(cgn_est));
    if let Some(s) = seq {
        env.insert("seq".into(), Value::from(s));
    }
    Value::Object(env)
}

fn parse_snapshot_request(body: &Value) -> Result<AnchorSnapshotRequest, TopologyProtocolError> {
    let topo = body.get("topology").and_then(Value::as_object).ok_or(TopologyProtocolError {
        nwp_error_code: error_codes::TOPOLOGY_UNSUPPORTED_SCOPE,
        nps_status: "NPS-CLIENT-BAD-PARAM",
        message: "topology.snapshot requires a 'topology' object per NPS-2 §12.1.".into(),
    })?;
    let scope = parse_scope(topo)?;
    let include = parse_include(topo);
    let depth = parse_depth(topo);
    let target_nid = topo.get("target_nid").and_then(Value::as_str).map(String::from);
    if scope == "member" && target_nid.as_deref().unwrap_or("").is_empty() {
        return Err(TopologyProtocolError {
            nwp_error_code: error_codes::TOPOLOGY_UNSUPPORTED_SCOPE,
            nps_status: "NPS-CLIENT-BAD-PARAM",
            message: "topology.target_nid is required when topology.scope = \"member\".".into(),
        });
    }
    Ok(AnchorSnapshotRequest { scope, include, depth, target_nid })
}

fn parse_stream_request(body: &Value) -> Result<(AnchorStreamRequest, String), TopologyProtocolError> {
    let topo = body.get("topology").and_then(Value::as_object).ok_or(TopologyProtocolError {
        nwp_error_code: error_codes::TOPOLOGY_UNSUPPORTED_SCOPE,
        nps_status: "NPS-CLIENT-BAD-PARAM",
        message: "topology.stream requires a 'topology' object per NPS-2 §12.2.".into(),
    })?;
    let scope = parse_scope(topo)?;
    let mut filter = None;
    if let Some(f) = topo.get("filter").and_then(Value::as_object) {
        validate_filter_keys(f)?;
        filter = serde_json::from_value(Value::Object(f.clone())).ok();
    }
    let since = topo
        .get("since_version")
        .and_then(Value::as_u64)
        .or_else(|| body.get("resume_from_seq").and_then(Value::as_u64));
    let stream_id = body
        .get("stream_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| gen_hex(16));
    Ok((AnchorStreamRequest { scope, filter, since_version: since }, stream_id))
}

fn parse_scope(topo: &Map<String, Value>) -> Result<String, TopologyProtocolError> {
    match topo.get("scope").and_then(Value::as_str) {
        None | Some("") => Ok("cluster".into()),
        Some("cluster") => Ok("cluster".into()),
        Some("member") => Ok("member".into()),
        Some(other) => Err(TopologyProtocolError {
            nwp_error_code: error_codes::TOPOLOGY_UNSUPPORTED_SCOPE,
            nps_status: "NPS-CLIENT-BAD-PARAM",
            message: format!("unknown topology.scope '{other}'."),
        }),
    }
}

fn parse_include(topo: &Map<String, Value>) -> Vec<String> {
    let known = ["members", "capabilities", "tags", "metrics"];
    let mut out: Vec<String> = Vec::new();
    if let Some(arr) = topo.get("include").and_then(Value::as_array) {
        for v in arr {
            if let Some(s) = v.as_str() {
                if known.contains(&s) {
                    out.push(s.to_string());
                }
            }
        }
    }
    if out.is_empty() {
        out.push("members".into());
    }
    out
}

fn parse_depth(topo: &Map<String, Value>) -> u8 {
    topo.get("depth").and_then(Value::as_u64).filter(|d| *d > 0).map(|d| d as u8).unwrap_or(1)
}

fn validate_filter_keys(f: &Map<String, Value>) -> Result<(), TopologyProtocolError> {
    for key in f.keys() {
        match key.as_str() {
            "tags_any" | "tags_all" | "node_roles" => {}
            "node_kind" => {
                return Err(TopologyProtocolError {
                    nwp_error_code: error_codes::TOPOLOGY_FILTER_UNSUPPORTED,
                    nps_status: "NPS-CLIENT-BAD-PARAM",
                    message: "topology.filter.node_kind expired after alpha.5; use node_roles.".into(),
                })
            }
            other => {
                return Err(TopologyProtocolError {
                    nwp_error_code: error_codes::TOPOLOGY_FILTER_UNSUPPORTED,
                    nps_status: "NPS-CLIENT-BAD-PARAM",
                    message: format!("topology.filter key '{other}' is not recognized."),
                })
            }
        }
    }
    Ok(())
}

fn actions_map(opt: &AnchorNodeOptions) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for (id, spec) in &opt.actions {
        let mut entry = Map::new();
        entry.insert("action_id".into(), Value::String(id.clone()));
        entry.insert("async".into(), Value::from(spec.async_));
        if let Some(d) = &spec.description {
            entry.insert("description".into(), Value::String(d.clone()));
        }
        if let Some(p) = &spec.params_anchor {
            entry.insert("params_anchor".into(), Value::String(p.clone()));
        }
        if let Some(r) = &spec.result_anchor {
            entry.insert("result_anchor".into(), Value::String(r.clone()));
        }
        if let Some(c) = spec.estimated_cgn {
            entry.insert("cgn_est".into(), Value::from(c));
        }
        if let Some(t) = spec.timeout_ms_default {
            entry.insert("timeout_ms_default".into(), Value::from(t));
        }
        if let Some(t) = spec.timeout_ms_max {
            entry.insert("timeout_ms_max".into(), Value::from(t));
        }
        if let Some(rc) = &spec.required_capability {
            entry.insert("required_capability".into(), Value::String(rc.clone()));
        }
        out.insert(id.clone(), Value::Object(entry));
    }
    out
}

fn build_manifest(opt: &AnchorNodeOptions, prefix: &str) -> Value {
    let mut m = Map::new();
    m.insert("nwp".into(), Value::String("0.4".into()));
    m.insert("node_id".into(), Value::String(opt.node_id.clone()));
    m.insert("node_type".into(), Value::String("anchor".into()));
    if let Some(dn) = &opt.display_name {
        m.insert("display_name".into(), Value::String(dn.clone()));
    }
    m.insert("wire_formats".into(), json!(["ncp-capsule", "json"]));
    m.insert("preferred_format".into(), Value::String("json".into()));
    m.insert("capabilities".into(), json!({
        "query": false, "stream": false, "subscribe": false,
        "vector_search": false, "token_budget_hint": true, "ext_frame": false
    }));
    let mut auth = Map::new();
    auth.insert("required".into(), Value::from(opt.require_auth));
    auth.insert("identity_type".into(), Value::String(if opt.require_auth { "nip-cert" } else { "none" }.into()));
    if let Some(rc) = &opt.required_capabilities {
        auth.insert("required_capabilities".into(), json!(rc));
    }
    m.insert("auth".into(), Value::Object(auth));
    m.insert("endpoints".into(), json!({ "invoke": format!("{prefix}/invoke"), "schema": format!("{prefix}/.schema") }));
    if opt.cgn_limit > 0 {
        m.insert("token_budget".into(), json!({ "cgn_limit": opt.cgn_limit, "profile": "cgn.v1" }));
    }
    if let Some(rl) = &opt.rate_limits {
        m.insert("rate_limits".into(), rl.clone());
    }
    if let Some(rp) = &opt.reputation_policy {
        if rp.enabled {
            m.insert("reputation_policy".into(), serde_json::to_value(rp).unwrap_or(Value::Null));
        }
    }
    if let Some(ta) = &opt.trust_anchors {
        if !ta.is_empty() {
            m.insert("trust_anchors".into(), json!(ta));
        }
    }
    let actions: Vec<Value> = actions_map(opt).into_values().collect();
    m.insert("actions".into(), Value::Array(actions));
    Value::Object(m)
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn gen_hex(n_bytes: usize) -> String {
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
    let mut s = format!("{t:016x}{c:016x}");
    s.truncate(n_bytes * 2);
    s
}

fn now_rfc3339() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    OffsetDateTime::from_unix_timestamp(secs)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_default()
}
