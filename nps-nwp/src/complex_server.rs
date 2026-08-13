// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Complex Node server — framework-agnostic request handler (zero new deps).
//!
//! Faithful port of the .NET `ComplexNodeMiddleware` (NPS-2 §2.1, §11). Exposes a
//! single Complex Node at a configurable path prefix. Sub-paths: `/.nwm`,
//! `/.schema`, `/actions`, `/query`, `/invoke`.
//!
//! On `/query` it asks the [`ComplexNodeProvider`] for local rows, then — if the
//! request carries `X-NWP-Depth > 0` and at least one child ref is declared —
//! fetches each child's `/query` and attaches the embedded capsule bodies under a
//! top-level `graph` array. Child fetching is delegated to an injectable
//! [`ChildFetcher`] so the handler stays transport-agnostic and testable.
//!
//! Security (NPS-2 §13.2): child URLs are SSRF/allowlist validated, cycle
//! detection uses the `X-NWP-Trace` header, and depth is clamped to
//! [`ABSOLUTE_MAX_DEPTH`] (5).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::action_server::{
    is_private_host, parse_absolute_url, ActionCancellation, ActionContext, ActionError,
    ActionExecutionResult, ActionSpec, ParsedActionFrame, SYSTEM_TASK_CANCEL, SYSTEM_TASK_STATUS,
};
use crate::memory_server::{
    MemoryNodeError, MemoryNodeQueryResult, MemoryNodeSchema, ParsedQueryFrame,
};
use crate::node_http::{empty, error_resp, NodeRequest, NodeResponse};
use crate::{error_codes, http_headers};

const NODE_TYPE_COMPLEX: &str = "complex";

/// Header carrying the visited-nodes trace for cycle detection.
pub const TRACE_HEADER: &str = "X-NWP-Trace";

/// Absolute ceiling on traversal depth per NPS-2 §11.
pub const ABSOLUTE_MAX_DEPTH: u32 = 5;

// ── Graph ref ──────────────────────────────────────────────────────────────────

/// Child node reference declared in [`ComplexNodeOptions::graph`] (NPS-2 §11).
#[derive(Debug, Clone)]
pub struct ComplexGraphRef {
    pub rel: String,
    pub node_url: String,
}

impl ComplexGraphRef {
    pub fn new(rel: impl Into<String>, node_url: impl Into<String>) -> Self {
        ComplexGraphRef {
            rel: rel.into(),
            node_url: node_url.into(),
        }
    }
}

// ── Options ────────────────────────────────────────────────────────────────────

/// Configuration for a single Complex Node (NPS-2 §2.1, §11). Port of .NET `ComplexNodeOptions`.
pub struct ComplexNodeOptions {
    pub node_id: String,
    pub display_name: Option<String>,
    pub path_prefix: String,
    pub schema: Option<MemoryNodeSchema>,
    pub actions: BTreeMap<String, ActionSpec>,
    pub graph: Vec<ComplexGraphRef>,
    pub graph_max_depth: u32,
    pub allowed_child_url_prefixes: Vec<String>,
    pub reject_private_child_urls: bool,
    pub allow_http_child_urls: bool,
    pub require_auth: bool,
    pub default_limit: u32,
    pub max_limit: u32,
    pub default_timeout_ms: u32,
    pub max_timeout_ms: u32,
}

impl ComplexNodeOptions {
    pub fn new(node_id: impl Into<String>, path_prefix: impl Into<String>) -> Self {
        ComplexNodeOptions {
            node_id: node_id.into(),
            display_name: None,
            path_prefix: path_prefix.into(),
            schema: None,
            actions: BTreeMap::new(),
            graph: Vec::new(),
            graph_max_depth: 2,
            allowed_child_url_prefixes: Vec::new(),
            reject_private_child_urls: true,
            allow_http_child_urls: false,
            require_auth: false,
            default_limit: 20,
            max_limit: 1000,
            default_timeout_ms: 5_000,
            max_timeout_ms: 300_000,
        }
    }
}

// ── Provider ───────────────────────────────────────────────────────────────────

/// Local behaviour of a Complex Node. Port of .NET `IComplexNodeProvider`.
pub trait ComplexNodeProvider: Send + Sync {
    fn query(
        &self,
        frame: &ParsedQueryFrame,
        options: &ComplexNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError>;

    fn execute(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError>;
}

/// Convenience provider for pure-aggregator Complex Nodes with no local data/actions.
/// Port of .NET `NullComplexNodeProvider`.
pub struct NullComplexNodeProvider;

impl ComplexNodeProvider for NullComplexNodeProvider {
    fn query(
        &self,
        _frame: &ParsedQueryFrame,
        _options: &ComplexNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError> {
        Ok(MemoryNodeQueryResult::default())
    }

    fn execute(
        &self,
        _frame: &ParsedActionFrame,
        _context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        Err(ActionError::internal(
            "NullComplexNodeProvider does not handle actions.",
        ))
    }
}

// ── Child fetcher ──────────────────────────────────────────────────────────────

/// The result of fetching one child node during graph expansion.
#[derive(Debug, Clone)]
pub enum ChildOutcome {
    /// Child returned a capsule (its full JSON body).
    Ok(Value),
    /// Child fetch failed — carries a `{code, message}` error.
    Err { code: String, message: String },
}

/// Fetches a child node's `/query`. Injected so the Complex Node handler stays
/// transport-agnostic; a host provides a real HTTP fetcher, tests provide a stub.
pub trait ChildFetcher: Send + Sync {
    /// Fetch `{node_url}/query` with the given serialized QueryFrame body and the
    /// propagated depth/trace/agent/budget headers.
    fn fetch(
        &self,
        node_url: &str,
        body: &[u8],
        child_depth: u32,
        trace: &[String],
        agent: Option<&str>,
        budget: Option<&str>,
    ) -> ChildOutcome;
}

// ── Child URL validator ────────────────────────────────────────────────────────

/// Validates a child-node URL before dereferencing (NPS-2 §13.2). Returns `None`
/// on success. Port of .NET `ComplexChildUrlValidator`.
pub fn validate_child_url(
    child_url: &str,
    allowed_prefixes: &[String],
    reject_private: bool,
    allow_http: bool,
) -> Option<String> {
    if child_url.trim().is_empty() {
        return Some("child node URL must not be empty.".into());
    }
    let parsed = match parse_absolute_url(child_url) {
        Some(p) => p,
        None => {
            return Some(format!(
                "child node URL '{child_url}' is not a valid absolute URI."
            ))
        }
    };
    let is_https = parsed.scheme.eq_ignore_ascii_case("https");
    let is_http = parsed.scheme.eq_ignore_ascii_case("http");
    if !(is_https || allow_http && is_http) {
        return Some(format!(
            "child node URL MUST use the https:// scheme (got '{}://').",
            parsed.scheme
        ));
    }
    if !allowed_prefixes.is_empty() {
        let matched = allowed_prefixes.iter().any(|p| {
            child_url
                .to_ascii_lowercase()
                .starts_with(&p.to_ascii_lowercase())
        });
        if !matched {
            return Some(format!(
                "child node URL '{child_url}' is not in the allowed prefix list."
            ));
        }
    }
    if reject_private && is_private_host(&parsed.host) {
        return Some(format!(
            "child node host '{}' resolves to a private or loopback address (SSRF guard).",
            parsed.host
        ));
    }
    None
}

// ── The app ────────────────────────────────────────────────────────────────────

pub struct ComplexNodeApp {
    opt: ComplexNodeOptions,
    prefix: String,
    provider: Arc<dyn ComplexNodeProvider>,
    fetcher: Option<Arc<dyn ChildFetcher>>,
    nwm_json: Vec<u8>,
    schema_json: Vec<u8>,
    actions_json: Vec<u8>,
    anchor_id: String,
}

impl ComplexNodeApp {
    /// Build a Complex Node app. Panics if a reserved action id is registered or if
    /// `graph_max_depth` exceeds [`ABSOLUTE_MAX_DEPTH`] (matches .NET ctor guards).
    pub fn new(
        opt: ComplexNodeOptions,
        provider: Arc<dyn ComplexNodeProvider>,
        fetcher: Option<Arc<dyn ChildFetcher>>,
    ) -> Self {
        if opt.actions.contains_key(SYSTEM_TASK_STATUS)
            || opt.actions.contains_key(SYSTEM_TASK_CANCEL)
        {
            panic!(
                "Reserved action ids '{SYSTEM_TASK_STATUS}' / '{SYSTEM_TASK_CANCEL}' MUST NOT be \
                 registered on a Complex Node."
            );
        }
        if opt.graph_max_depth > ABSOLUTE_MAX_DEPTH {
            panic!(
                "graph_max_depth {} exceeds NPS-2 §11 absolute cap {ABSOLUTE_MAX_DEPTH}.",
                opt.graph_max_depth
            );
        }
        let prefix = opt.path_prefix.trim_end_matches('/').to_string();

        let (schema_json, anchor_id) = match &opt.schema {
            Some(s) => {
                let sj = serde_json::to_vec(&build_frame_schema(s)).unwrap_or_default();
                let anchor = format!("sha256:{}", hex::encode(Sha256::digest(&sj)));
                (sj, anchor)
            }
            None => (b"{}".to_vec(), String::new()),
        };

        let nwm_json =
            serde_json::to_vec(&build_manifest(&opt, &prefix, &anchor_id)).unwrap_or_default();
        let actions_json =
            serde_json::to_vec(&json!({ "actions": actions_map(&opt) })).unwrap_or_default();

        ComplexNodeApp {
            opt,
            prefix,
            provider,
            fetcher,
            nwm_json,
            schema_json,
            actions_json,
            anchor_id,
        }
    }

    pub async fn handle(&self, req: NodeRequest) -> NodeResponse {
        if !req.path.starts_with(&self.prefix) {
            return empty(404);
        }
        let sub = &req.path[self.prefix.len()..];

        if self.opt.require_auth && req.header(http_headers::AGENT).is_none() {
            return error_resp(
                401,
                "NPS-CLIENT-UNAUTHORIZED",
                error_codes::AUTH_NID_SCOPE_VIOLATION,
                "X-NWP-Agent header is required.",
                None,
                &[],
            );
        }

        match sub {
            "/.nwm" | "/.nwm/" => NodeResponse {
                status: 200,
                headers: vec![
                    ("content-type".into(), http_headers::MIME_MANIFEST.into()),
                    (
                        http_headers::NODE_TYPE.to_ascii_lowercase(),
                        NODE_TYPE_COMPLEX.into(),
                    ),
                ],
                body: self.nwm_json.clone(),
            },
            "/.schema" | "/.schema/" => {
                let mut headers =
                    vec![("content-type".to_string(), "application/json".to_string())];
                if !self.anchor_id.is_empty() {
                    headers.push((
                        http_headers::SCHEMA.to_ascii_lowercase(),
                        self.anchor_id.clone(),
                    ));
                }
                NodeResponse {
                    status: 200,
                    headers,
                    body: self.schema_json.clone(),
                }
            }
            "/actions" | "/actions/" => NodeResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.actions_json.clone(),
            },
            "/query" | "/query/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_query(&req)
            }
            "/invoke" | "/invoke/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_invoke(&req)
            }
            _ => empty(404),
        }
    }

    fn handle_query(&self, req: &NodeRequest) -> NodeResponse {
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::QUERY_FILTER_INVALID,
                    &e.to_string(),
                    None,
                    &[],
                )
            }
        };
        let frame = match ParsedQueryFrame::from_json(&body, self.opt.default_limit) {
            Ok(f) => f,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::QUERY_FILTER_INVALID,
                    &e,
                    None,
                    &[],
                )
            }
        };

        // Depth parsing (header absent => 0 = local only).
        let requested_depth = match self.parse_depth(req) {
            Ok(d) => d,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::DEPTH_EXCEEDED,
                    &e,
                    None,
                    &[],
                )
            }
        };

        // Cycle detection.
        let trace = parse_trace(req);
        if trace.iter().any(|t| t == &self.opt.node_id) {
            return error_resp(
                422,
                "NPS-CLIENT-UNPROCESSABLE",
                error_codes::GRAPH_CYCLE,
                &format!("graph cycle detected at '{}'.", self.opt.node_id),
                None,
                &[],
            );
        }

        let local = match self.provider.query(&frame, &self.opt) {
            Ok(r) => r,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    &e.nwp_error_code,
                    &e.message,
                    None,
                    &[],
                )
            }
        };

        let local_data: Vec<Value> = local
            .rows
            .iter()
            .map(|r| Value::Object(r.clone()))
            .collect();

        // Graph expansion.
        let mut graph_element: Option<Value> = None;
        if requested_depth > 0 && !self.opt.graph.is_empty() {
            let mut next_trace = trace.clone();
            next_trace.push(self.opt.node_id.clone());
            let child_depth = requested_depth - 1;

            let agent = req.header(http_headers::AGENT).map(String::from);
            let budget = req.header(http_headers::BUDGET).map(String::from);
            let child_body = serde_json::to_vec(&body).unwrap_or_default();

            let mut arr: Vec<Value> = Vec::with_capacity(self.opt.graph.len());
            for gref in &self.opt.graph {
                arr.push(self.fetch_child(
                    gref,
                    &child_body,
                    child_depth,
                    &next_trace,
                    agent.as_deref(),
                    budget.as_deref(),
                ));
            }
            graph_element = Some(Value::Array(arr));
        }

        let mut caps = Map::new();
        if !self.anchor_id.is_empty() {
            caps.insert("anchor_ref".into(), Value::String(self.anchor_id.clone()));
        } else {
            caps.insert("anchor_ref".into(), Value::Null);
        }
        caps.insert("count".into(), json!(local_data.len()));
        caps.insert("data".into(), Value::Array(local_data));
        if let Some(nc) = &local.next_cursor {
            caps.insert("next_cursor".into(), Value::String(nc.clone()));
        }
        if let Some(g) = graph_element {
            caps.insert("graph".into(), g);
        }

        let mut headers = vec![
            (
                "content-type".to_string(),
                http_headers::MIME_CAPSULE.to_string(),
            ),
            (
                http_headers::NODE_TYPE.to_ascii_lowercase(),
                NODE_TYPE_COMPLEX.into(),
            ),
        ];
        if !self.anchor_id.is_empty() {
            headers.push((
                http_headers::SCHEMA.to_ascii_lowercase(),
                self.anchor_id.clone(),
            ));
        }

        NodeResponse {
            status: 200,
            headers,
            body: serde_json::to_vec(&Value::Object(caps)).unwrap_or_default(),
        }
    }

    fn fetch_child(
        &self,
        gref: &ComplexGraphRef,
        body: &[u8],
        child_depth: u32,
        next_trace: &[String],
        agent: Option<&str>,
        budget: Option<&str>,
    ) -> Value {
        if let Some(err) = validate_child_url(
            &gref.node_url,
            &self.opt.allowed_child_url_prefixes,
            self.opt.reject_private_child_urls,
            self.opt.allow_http_child_urls,
        ) {
            return child_result(
                &gref.rel,
                &gref.node_url,
                None,
                Some((error_codes::AUTH_NID_SCOPE_VIOLATION, &err)),
            );
        }

        let fetcher = match &self.fetcher {
            Some(f) => f,
            None => {
                return child_result(
                    &gref.rel,
                    &gref.node_url,
                    None,
                    Some((
                        error_codes::NODE_UNAVAILABLE,
                        "no child fetcher configured on this Complex Node.",
                    )),
                )
            }
        };

        match fetcher.fetch(&gref.node_url, body, child_depth, next_trace, agent, budget) {
            ChildOutcome::Ok(capsule) => {
                child_result(&gref.rel, &gref.node_url, Some(capsule), None)
            }
            ChildOutcome::Err { code, message } => {
                child_result(&gref.rel, &gref.node_url, None, Some((&code, &message)))
            }
        }
    }

    fn handle_invoke(&self, req: &NodeRequest) -> NodeResponse {
        let body: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    &e.to_string(),
                    None,
                    &[],
                )
            }
        };
        let frame = match ParsedActionFrame::from_json(&body) {
            Ok(f) => f,
            Err(e) => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    &e,
                    None,
                    &[],
                )
            }
        };

        let spec = match self.opt.actions.get(&frame.action_id) {
            Some(s) => s.clone(),
            None => {
                return error_resp(
                    404,
                    "NPS-CLIENT-NOT-FOUND",
                    error_codes::ACTION_NOT_FOUND,
                    &format!("Unknown action_id '{}'.", frame.action_id),
                    None,
                    &[],
                )
            }
        };

        // Complex Node does not own async task machinery.
        if frame.async_ {
            return error_resp(
                400,
                "NPS-CLIENT-BAD-REQUEST",
                error_codes::ACTION_PARAMS_INVALID,
                "Complex Node does not support async actions; invoke a downstream Action Node instead.",
                None,
                &[],
            );
        }

        if let Some(p) = &frame.priority {
            if !matches!(p.as_str(), "low" | "normal" | "high") {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    &format!("priority '{p}' is invalid (allowed: low/normal/high)."),
                    None,
                    &[],
                );
            }
        }

        let timeout_ms = clamp_timeout(frame.timeout_ms, &spec, &self.opt);
        let agent_nid = req.header(http_headers::AGENT).map(String::from);

        let ctx = ActionContext {
            agent_nid,
            request_id: frame.request_id.clone(),
            task_id: None,
            spec: spec.clone(),
            timeout_ms,
            priority: frame.priority.clone().unwrap_or_else(|| "normal".into()),
            cancellation: ActionCancellation::new(),
        };

        let result = match self.provider.execute(&frame, &ctx) {
            Ok(r) => r,
            Err(e) => {
                return error_resp(
                    e.http_status,
                    &e.nps_status,
                    &e.error_code,
                    &e.message,
                    None,
                    &[],
                )
            }
        };

        let anchor = result
            .anchor_ref
            .clone()
            .or_else(|| spec.result_anchor.clone())
            .unwrap_or_default();
        let (count, data) = match &result.result {
            Some(v) => (1u32, vec![v.clone()]),
            None => (0u32, vec![]),
        };
        let mut caps = Map::new();
        caps.insert("anchor_ref".into(), Value::String(anchor.clone()));
        caps.insert("count".into(), json!(count));
        caps.insert("data".into(), Value::Array(data));
        if result.token_est > 0 {
            caps.insert("token_est".into(), json!(result.token_est));
        }

        let mut headers = vec![
            (
                "content-type".to_string(),
                http_headers::MIME_CAPSULE.to_string(),
            ),
            (
                http_headers::NODE_TYPE.to_ascii_lowercase(),
                NODE_TYPE_COMPLEX.into(),
            ),
        ];
        if !anchor.is_empty() {
            headers.push((http_headers::SCHEMA.to_ascii_lowercase(), anchor));
        }
        if result.token_est > 0 {
            headers.push((
                http_headers::TOKENS.to_ascii_lowercase(),
                result.token_est.to_string(),
            ));
        }
        if let Some(rid) = &frame.request_id {
            headers.push((http_headers::REQUEST_ID.to_ascii_lowercase(), rid.clone()));
        }

        NodeResponse {
            status: 200,
            headers,
            body: serde_json::to_vec(&Value::Object(caps)).unwrap_or_default(),
        }
    }

    fn parse_depth(&self, req: &NodeRequest) -> Result<u32, String> {
        let raw = match req.header(http_headers::DEPTH) {
            Some(r) => r,
            None => return Ok(0),
        };
        let depth: u32 = raw
            .parse()
            .map_err(|_| format!("X-NWP-Depth '{raw}' is not a non-negative integer."))?;
        if depth > self.opt.graph_max_depth {
            return Err(format!(
                "X-NWP-Depth {depth} exceeds node max_depth {}.",
                self.opt.graph_max_depth
            ));
        }
        if depth > ABSOLUTE_MAX_DEPTH {
            return Err(format!(
                "X-NWP-Depth {depth} exceeds NPS-2 §11 absolute cap {ABSOLUTE_MAX_DEPTH}."
            ));
        }
        Ok(depth)
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

fn child_result(rel: &str, node: &str, data: Option<Value>, error: Option<(&str, &str)>) -> Value {
    let mut m = Map::new();
    m.insert("rel".into(), Value::String(rel.into()));
    m.insert("node".into(), Value::String(node.into()));
    if let Some(d) = data {
        m.insert("data".into(), d);
    }
    if let Some((code, message)) = error {
        m.insert("error".into(), json!({ "code": code, "message": message }));
    }
    Value::Object(m)
}

fn parse_trace(req: &NodeRequest) -> Vec<String> {
    req.header(TRACE_HEADER)
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

fn clamp_timeout(requested: u32, spec: &ActionSpec, opt: &ComplexNodeOptions) -> u32 {
    let spec_max = spec.timeout_ms_max.unwrap_or(opt.max_timeout_ms);
    let hard_max = spec_max.min(opt.max_timeout_ms);
    if requested == 0 {
        return spec.timeout_ms_default.unwrap_or(opt.default_timeout_ms);
    }
    requested.min(hard_max)
}

fn actions_map(opt: &ComplexNodeOptions) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    for (id, spec) in &opt.actions {
        let mut entry = Map::new();
        entry.insert("async".into(), Value::Bool(spec.async_));
        if let Some(d) = &spec.description {
            entry.insert("description".into(), Value::String(d.clone()));
        }
        if let Some(p) = &spec.params_anchor {
            entry.insert("params_anchor".into(), Value::String(p.clone()));
        }
        if let Some(r) = &spec.result_anchor {
            entry.insert("result_anchor".into(), Value::String(r.clone()));
        }
        if let Some(t) = spec.timeout_ms_default {
            entry.insert("timeout_ms_default".into(), json!(t));
        }
        if let Some(t) = spec.timeout_ms_max {
            entry.insert("timeout_ms_max".into(), json!(t));
        }
        if let Some(rc) = &spec.required_capability {
            entry.insert("required_capability".into(), Value::String(rc.clone()));
        }
        out.insert(id.clone(), Value::Object(entry));
    }
    out
}

fn build_frame_schema(schema: &MemoryNodeSchema) -> Value {
    let fields: Vec<Value> = schema
        .fields
        .iter()
        .map(|f| json!({ "name": f.name, "type": f.type_, "nullable": f.nullable }))
        .collect();
    json!({ "fields": fields })
}

fn build_manifest(opt: &ComplexNodeOptions, prefix: &str, anchor_id: &str) -> Value {
    let mut m = Map::new();
    m.insert("nwp".into(), Value::String("0.4".into()));
    m.insert("node_id".into(), Value::String(opt.node_id.clone()));
    m.insert("node_type".into(), Value::String(NODE_TYPE_COMPLEX.into()));
    if let Some(dn) = &opt.display_name {
        m.insert("display_name".into(), Value::String(dn.clone()));
    }
    m.insert("wire_formats".into(), json!(["ncp-capsule", "json"]));
    m.insert("preferred_format".into(), Value::String("json".into()));
    if !anchor_id.is_empty() {
        m.insert("schema_anchors".into(), json!({ "default": anchor_id }));
    }
    let query_cap = opt.schema.is_some() || !opt.graph.is_empty();
    m.insert(
        "capabilities".into(),
        json!({ "query": query_cap, "stream": false, "token_budget_hint": true }),
    );
    m.insert(
        "auth".into(),
        json!({
            "required": opt.require_auth,
            "identity_type": if opt.require_auth { "nip-cert" } else { "none" }
        }),
    );
    let mut endpoints = Map::new();
    endpoints.insert("query".into(), Value::String(format!("{prefix}/query")));
    if !opt.actions.is_empty() {
        endpoints.insert("invoke".into(), Value::String(format!("{prefix}/invoke")));
    }
    endpoints.insert("schema".into(), Value::String(format!("{prefix}/.schema")));
    m.insert("endpoints".into(), Value::Object(endpoints));
    if !opt.graph.is_empty() {
        let refs: Vec<Value> = opt
            .graph
            .iter()
            .map(|r| json!({ "rel": r.rel, "node_url": r.node_url }))
            .collect();
        m.insert(
            "graph".into(),
            json!({ "refs": refs, "max_depth": opt.graph_max_depth }),
        );
    }
    Value::Object(m)
}
