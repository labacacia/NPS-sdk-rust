// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Memory Node server — framework-agnostic request handler (zero new deps).
//!
//! Faithful port of the .NET `MemoryNodeMiddleware` (NPS-2 §2.1, §4, §5). Exposes
//! a single Memory Node at a configurable path prefix. Sub-paths: `/.nwm`,
//! `/.schema`, `/query`, `/stream`.
//!
//! SQL providers + the NWP-filter→SQL translator are intentionally OUT OF SCOPE;
//! the [`MemoryNodeProvider`] trait stays clean and the bundled
//! [`InMemoryMemoryNodeProvider`] does in-memory filtering for tests.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::node_http::{empty, error_resp, NodeRequest, NodeResponse};
use crate::{error_codes, http_headers};

const NODE_TYPE_MEMORY: &str = "memory";

// ── Schema ─────────────────────────────────────────────────────────────────────

/// One field in a Memory Node schema (NPS-2 §4.1). Port of .NET `MemoryNodeField`.
#[derive(Debug, Clone)]
pub struct MemoryNodeField {
    pub name: String,
    pub type_: String,
    pub description: Option<String>,
    pub nullable: bool,
    pub column_name: Option<String>,
}

impl MemoryNodeField {
    pub fn new(name: impl Into<String>, type_: impl Into<String>) -> Self {
        MemoryNodeField {
            name: name.into(),
            type_: type_.into(),
            description: None,
            nullable: true,
            column_name: None,
        }
    }

    /// Resolved database column name — falls back to [`Self::name`] when
    /// [`Self::column_name`] is unset. Mirrors .NET `ResolvedColumnName`.
    pub fn resolved_column_name(&self) -> &str {
        self.column_name.as_deref().unwrap_or(&self.name)
    }
}

/// Schema definition for a Memory Node. Port of .NET `MemoryNodeSchema`.
#[derive(Debug, Clone)]
pub struct MemoryNodeSchema {
    pub table_name: String,
    pub primary_key: String,
    pub fields: Vec<MemoryNodeField>,
}

impl MemoryNodeSchema {
    pub fn get_field(&self, name: &str) -> Option<&MemoryNodeField> {
        self.fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
    }

    pub fn has_field(&self, name: &str) -> bool {
        self.get_field(name).is_some()
    }
}

// ── Options ────────────────────────────────────────────────────────────────────

/// Configuration for a single Memory Node (NPS-2 §2.1). Port of .NET `MemoryNodeOptions`.
pub struct MemoryNodeOptions {
    pub node_id: String,
    pub display_name: Option<String>,
    pub schema: MemoryNodeSchema,
    pub default_limit: u32,
    pub max_limit: u32,
    pub require_auth: bool,
    pub default_token_budget: u32,
    pub path_prefix: String,
}

impl MemoryNodeOptions {
    pub fn new(
        node_id: impl Into<String>,
        path_prefix: impl Into<String>,
        schema: MemoryNodeSchema,
    ) -> Self {
        MemoryNodeOptions {
            node_id: node_id.into(),
            display_name: None,
            schema,
            default_limit: 20,
            max_limit: 1000,
            require_auth: false,
            default_token_budget: 0,
            path_prefix: path_prefix.into(),
        }
    }
}

// ── Provider ───────────────────────────────────────────────────────────────────

/// A single result row: field-name → JSON value.
pub type MemoryNodeRow = Map<String, Value>;

/// Result of a Memory Node query (NPS-2 §5). Port of .NET `MemoryNodeQueryResult`.
#[derive(Debug, Clone, Default)]
pub struct MemoryNodeQueryResult {
    pub rows: Vec<MemoryNodeRow>,
    pub next_cursor: Option<String>,
}

/// Parsed `QueryFrame` fields the Memory Node consumes.
#[derive(Debug, Clone, Default)]
pub struct ParsedQueryFrame {
    pub anchor_ref: Option<String>,
    pub filter: Option<Value>,
    pub fields: Option<Vec<String>>,
    pub limit: u32,
    pub cursor: Option<String>,
    pub order: Option<Value>,
}

impl ParsedQueryFrame {
    pub(crate) fn from_json(body: &Value, default_limit: u32) -> Result<Self, String> {
        let obj = body
            .as_object()
            .ok_or_else(|| "QueryFrame must be a JSON object.".to_string())?;
        let limit = obj
            .get("limit")
            .and_then(Value::as_u64)
            .map(|l| l as u32)
            .unwrap_or(default_limit);
        Ok(ParsedQueryFrame {
            anchor_ref: obj
                .get("anchor_ref")
                .and_then(Value::as_str)
                .map(String::from),
            filter: obj.get("filter").cloned().filter(|v| !v.is_null()),
            fields: obj.get("fields").and_then(Value::as_array).map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            }),
            limit,
            cursor: obj.get("cursor").and_then(Value::as_str).map(String::from),
            order: obj.get("order").cloned().filter(|v| !v.is_null()),
        })
    }
}

/// Error a provider may raise, carrying the NWP error code (e.g. filter validation).
#[derive(Debug, Clone)]
pub struct MemoryNodeError {
    pub nwp_error_code: String,
    pub message: String,
}

impl MemoryNodeError {
    /// General constructor with an explicit NWP error code.
    pub fn new(nwp_error_code: impl Into<String>, message: impl Into<String>) -> Self {
        MemoryNodeError {
            nwp_error_code: nwp_error_code.into(),
            message: message.into(),
        }
    }

    pub fn filter_invalid(message: impl Into<String>) -> Self {
        MemoryNodeError {
            nwp_error_code: error_codes::QUERY_FILTER_INVALID.into(),
            message: message.into(),
        }
    }

    pub fn field_unknown(message: impl Into<String>) -> Self {
        MemoryNodeError {
            nwp_error_code: error_codes::QUERY_FIELD_UNKNOWN.into(),
            message: message.into(),
        }
    }
}

/// Abstraction over the data backing a Memory Node (NPS-2 §2.1). Port of .NET
/// `IMemoryNodeProvider` (SQL engines are host-supplied; SQL translation deferred).
pub trait MemoryNodeProvider: Send + Sync {
    fn query(
        &self,
        frame: &ParsedQueryFrame,
        schema: &MemoryNodeSchema,
        options: &MemoryNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError>;
}

// ── In-memory provider (test/dev) ───────────────────────────────────────────────

/// In-memory provider that applies a small subset of the NWP filter DSL in memory
/// (`$eq`,`$ne`,`$lt`,`$lte`,`$gt`,`$gte`,`$in`,`$contains`, plus `$and`/`$or`).
/// SQL translation is deferred; this is enough for tests and demos.
pub struct InMemoryMemoryNodeProvider {
    rows: Vec<MemoryNodeRow>,
}

impl InMemoryMemoryNodeProvider {
    pub fn new(rows: Vec<MemoryNodeRow>) -> Self {
        InMemoryMemoryNodeProvider { rows }
    }
}

impl MemoryNodeProvider for InMemoryMemoryNodeProvider {
    fn query(
        &self,
        frame: &ParsedQueryFrame,
        schema: &MemoryNodeSchema,
        _options: &MemoryNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError> {
        // Validate requested fields against the schema.
        if let Some(fields) = &frame.fields {
            for f in fields {
                if !schema.has_field(f) {
                    return Err(MemoryNodeError::field_unknown(format!(
                        "unknown field '{f}'."
                    )));
                }
            }
        }

        let mut out: Vec<MemoryNodeRow> = Vec::new();
        for row in &self.rows {
            let keep = match &frame.filter {
                Some(f) => match_filter(row, f)?,
                None => true,
            };
            if keep {
                let projected = project(row, frame.fields.as_deref());
                out.push(projected);
            }
            if out.len() as u32 >= frame.limit {
                break;
            }
        }
        Ok(MemoryNodeQueryResult {
            rows: out,
            next_cursor: None,
        })
    }
}

fn project(row: &MemoryNodeRow, fields: Option<&[String]>) -> MemoryNodeRow {
    match fields {
        None => row.clone(),
        Some(fs) => {
            let mut m = Map::new();
            for f in fs {
                if let Some(v) = row.get(f) {
                    m.insert(f.clone(), v.clone());
                }
            }
            m
        }
    }
}

/// Evaluate a row against a subset of the NWP filter DSL.
fn match_filter(row: &MemoryNodeRow, filter: &Value) -> Result<bool, MemoryNodeError> {
    let obj = filter
        .as_object()
        .ok_or_else(|| MemoryNodeError::filter_invalid("filter must be an object."))?;
    for (key, cond) in obj {
        match key.as_str() {
            "$and" => {
                let arr = cond
                    .as_array()
                    .ok_or_else(|| MemoryNodeError::filter_invalid("$and requires an array."))?;
                for sub in arr {
                    if !match_filter(row, sub)? {
                        return Ok(false);
                    }
                }
            }
            "$or" => {
                let arr = cond
                    .as_array()
                    .ok_or_else(|| MemoryNodeError::filter_invalid("$or requires an array."))?;
                let mut any = false;
                for sub in arr {
                    if match_filter(row, sub)? {
                        any = true;
                        break;
                    }
                }
                if !any {
                    return Ok(false);
                }
            }
            field => {
                let actual = row.get(field).unwrap_or(&Value::Null);
                if !match_field_cond(actual, cond)? {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn match_field_cond(actual: &Value, cond: &Value) -> Result<bool, MemoryNodeError> {
    // Bare value → equality.
    let obj = match cond.as_object() {
        Some(o) => o,
        None => return Ok(actual == cond),
    };
    for (op, expected) in obj {
        let ok = match op.as_str() {
            "$eq" => actual == expected,
            "$ne" => actual != expected,
            "$lt" => cmp_num(actual, expected)
                .map(|o| o.is_lt())
                .unwrap_or(false),
            "$lte" => cmp_num(actual, expected)
                .map(|o| o.is_le())
                .unwrap_or(false),
            "$gt" => cmp_num(actual, expected)
                .map(|o| o.is_gt())
                .unwrap_or(false),
            "$gte" => cmp_num(actual, expected)
                .map(|o| o.is_ge())
                .unwrap_or(false),
            "$in" => expected
                .as_array()
                .map(|a| a.iter().any(|v| v == actual))
                .unwrap_or(false),
            "$nin" => expected
                .as_array()
                .map(|a| !a.iter().any(|v| v == actual))
                .unwrap_or(false),
            "$contains" => match (actual.as_str(), expected.as_str()) {
                (Some(h), Some(n)) => h.contains(n),
                _ => false,
            },
            other => {
                return Err(MemoryNodeError::filter_invalid(format!(
                    "unsupported filter operator '{other}'."
                )))
            }
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

fn cmp_num(a: &Value, b: &Value) -> Option<std::cmp::Ordering> {
    a.as_f64()
        .zip(b.as_f64())
        .and_then(|(x, y)| x.partial_cmp(&y))
}

// ── The app ────────────────────────────────────────────────────────────────────

pub struct MemoryNodeApp {
    opt: MemoryNodeOptions,
    prefix: String,
    provider: std::sync::Arc<dyn MemoryNodeProvider>,
    nwm_json: Vec<u8>,
    schema_json: Vec<u8>,
    anchor_id: String,
}

impl MemoryNodeApp {
    pub fn new(opt: MemoryNodeOptions, provider: std::sync::Arc<dyn MemoryNodeProvider>) -> Self {
        let prefix = opt.path_prefix.trim_end_matches('/').to_string();
        let schema_json = serde_json::to_vec(&build_frame_schema(&opt.schema)).unwrap_or_default();
        let anchor_id = format!("sha256:{}", hex::encode(Sha256::digest(&schema_json)));
        let nwm_json =
            serde_json::to_vec(&build_manifest(&opt, &prefix, &anchor_id)).unwrap_or_default();
        MemoryNodeApp {
            opt,
            prefix,
            provider,
            nwm_json,
            schema_json,
            anchor_id,
        }
    }

    pub fn anchor_id(&self) -> &str {
        &self.anchor_id
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
                        NODE_TYPE_MEMORY.into(),
                    ),
                ],
                body: self.nwm_json.clone(),
            },
            "/.schema" | "/.schema/" => NodeResponse {
                status: 200,
                headers: vec![
                    ("content-type".into(), "application/json".into()),
                    (
                        http_headers::SCHEMA.to_ascii_lowercase(),
                        self.anchor_id.clone(),
                    ),
                ],
                body: self.schema_json.clone(),
            },
            "/query" | "/query/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_query(&req)
            }
            "/stream" | "/stream/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_stream(&req)
            }
            _ => empty(404),
        }
    }

    fn parse_frame(&self, req: &NodeRequest) -> Result<ParsedQueryFrame, NodeResponse> {
        let body: Value = serde_json::from_slice(&req.body).map_err(|e| {
            error_resp(
                400,
                "NPS-CLIENT-BAD-REQUEST",
                error_codes::QUERY_FILTER_INVALID,
                &e.to_string(),
                None,
                &[],
            )
        })?;
        ParsedQueryFrame::from_json(&body, self.opt.default_limit).map_err(|e| {
            error_resp(
                400,
                "NPS-CLIENT-BAD-REQUEST",
                error_codes::QUERY_FILTER_INVALID,
                &e,
                None,
                &[],
            )
        })
    }

    fn handle_query(&self, req: &NodeRequest) -> NodeResponse {
        let mut frame = match self.parse_frame(req) {
            Ok(f) => f,
            Err(resp) => return resp,
        };
        // Clamp limit.
        if frame.limit > self.opt.max_limit {
            frame.limit = self.opt.max_limit;
        }

        let result = match self.provider.query(&frame, &self.opt.schema, &self.opt) {
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

        let mut rows = result.rows;
        let mut token_est = measure_rows(&rows);

        let budget = effective_budget(parse_budget(req), self.opt.default_token_budget);
        if budget > 0 && token_est > budget {
            let (trimmed, tok) = trim_to_budget(&rows, budget);
            rows = trimmed;
            token_est = tok;
        }

        let data: Vec<Value> = rows.iter().map(|r| Value::Object(r.clone())).collect();
        let mut caps = Map::new();
        caps.insert("anchor_ref".into(), Value::String(self.anchor_id.clone()));
        caps.insert("count".into(), json!(data.len()));
        caps.insert("data".into(), Value::Array(data));
        if let Some(nc) = &result.next_cursor {
            caps.insert("next_cursor".into(), Value::String(nc.clone()));
        }
        caps.insert("token_est".into(), json!(token_est));

        NodeResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), http_headers::MIME_CAPSULE.into()),
                (
                    http_headers::SCHEMA.to_ascii_lowercase(),
                    self.anchor_id.clone(),
                ),
                (
                    http_headers::TOKENS.to_ascii_lowercase(),
                    token_est.to_string(),
                ),
                (
                    http_headers::NODE_TYPE.to_ascii_lowercase(),
                    NODE_TYPE_MEMORY.into(),
                ),
            ],
            body: serde_json::to_vec(&Value::Object(caps)).unwrap_or_default(),
        }
    }

    fn handle_stream(&self, req: &NodeRequest) -> NodeResponse {
        let frame = match self.parse_frame(req) {
            Ok(f) => f,
            Err(resp) => return resp,
        };
        let result = match self.provider.query(&frame, &self.opt.schema, &self.opt) {
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
        let stream_id = gen_hex(16);
        let data: Vec<Value> = result
            .rows
            .iter()
            .map(|r| Value::Object(r.clone()))
            .collect();

        let mut out = String::new();
        let chunk = json!({
            "stream_id": stream_id, "seq": 0, "is_last": false,
            "anchor_ref": self.anchor_id, "data": data
        });
        out.push_str(&serde_json::to_string(&chunk).unwrap_or_default());
        out.push('\n');
        let last = json!({
            "stream_id": stream_id, "seq": 1, "is_last": true, "data": []
        });
        out.push_str(&serde_json::to_string(&last).unwrap_or_default());
        out.push('\n');

        NodeResponse {
            status: 200,
            headers: vec![
                ("content-type".into(), http_headers::MIME_CAPSULE.into()),
                (
                    http_headers::SCHEMA.to_ascii_lowercase(),
                    self.anchor_id.clone(),
                ),
                (
                    http_headers::NODE_TYPE.to_ascii_lowercase(),
                    NODE_TYPE_MEMORY.into(),
                ),
            ],
            body: out.into_bytes(),
        }
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

fn parse_budget(req: &NodeRequest) -> u32 {
    req.header(http_headers::BUDGET)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0)
}

fn effective_budget(agent_budget: u32, cgn_limit: u32) -> u32 {
    if cgn_limit == 0 {
        return agent_budget;
    }
    if agent_budget == 0 {
        return cgn_limit;
    }
    cgn_limit.min(agent_budget)
}

fn measure_rows(rows: &[MemoryNodeRow]) -> u32 {
    let arr: Vec<Value> = rows.iter().map(|r| Value::Object(r.clone())).collect();
    let bytes = serde_json::to_vec(&Value::Array(arr))
        .map(|v| v.len())
        .unwrap_or(0);
    bytes.div_ceil(4) as u32
}

fn measure_row(row: &MemoryNodeRow) -> u32 {
    let bytes = serde_json::to_vec(&Value::Object(row.clone()))
        .map(|v| v.len())
        .unwrap_or(0);
    bytes.div_ceil(4) as u32
}

fn trim_to_budget(rows: &[MemoryNodeRow], budget: u32) -> (Vec<MemoryNodeRow>, u32) {
    let mut out = Vec::new();
    let mut acc = 0u32;
    for row in rows {
        let tok = measure_row(row);
        if acc + tok > budget {
            break;
        }
        out.push(row.clone());
        acc += tok;
    }
    (out, acc)
}

fn build_frame_schema(schema: &MemoryNodeSchema) -> Value {
    let fields: Vec<Value> = schema
        .fields
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "type": f.type_,
                "nullable": f.nullable
            })
        })
        .collect();
    json!({ "fields": fields })
}

fn build_manifest(opt: &MemoryNodeOptions, prefix: &str, anchor_id: &str) -> Value {
    let mut m = Map::new();
    m.insert("nwp".into(), Value::String("0.4".into()));
    m.insert("node_id".into(), Value::String(opt.node_id.clone()));
    m.insert("node_type".into(), Value::String(NODE_TYPE_MEMORY.into()));
    if let Some(dn) = &opt.display_name {
        m.insert("display_name".into(), Value::String(dn.clone()));
    }
    m.insert("wire_formats".into(), json!(["ncp-capsule", "json"]));
    m.insert("preferred_format".into(), Value::String("json".into()));
    m.insert("schema_anchors".into(), json!({ "default": anchor_id }));
    m.insert(
        "capabilities".into(),
        json!({ "query": true, "stream": true, "token_budget_hint": true }),
    );
    m.insert(
        "auth".into(),
        json!({
            "required": opt.require_auth,
            "identity_type": if opt.require_auth { "nip-cert" } else { "none" }
        }),
    );
    m.insert(
        "endpoints".into(),
        json!({
            "query": format!("{prefix}/query"),
            "stream": format!("{prefix}/stream"),
            "schema": format!("{prefix}/.schema")
        }),
    );
    Value::Object(m)
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn gen_hex(n_bytes: usize) -> String {
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut s = format!("{t:016x}{c:016x}");
    s.truncate(n_bytes * 2);
    s
}
