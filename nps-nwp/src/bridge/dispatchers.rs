// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Built-in outbound Bridge dispatchers. All speak JSON / JSON-RPC over HTTP via
//! `reqwest` — there is no native gRPC/protobuf transport.

use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{json, Map, Value};

use nps_ncp::CapsFrame;

use super::dispatcher::{BridgeDispatcher, DispatchFuture};
use super::endpoint::parse_http_endpoint;
use super::error::{bridge_error_codes, BridgeDispatchError};
use super::target::{target_get_json, target_get_string};
use super::types::{bridge_protocols, BridgeTarget};
use crate::frames::ActionFrame;

fn estimate_token_cost(len: usize) -> u64 {
    if len == 0 {
        0
    } else {
        std::cmp::max(1, len / 4) as u64
    }
}

fn caps_from_record(anchor_ref: &str, record: Value, token_est: u64) -> CapsFrame {
    let mut caps = CapsFrame::new(anchor_ref, vec![record]);
    caps.token_est = Some(token_est);
    caps
}

/// Collect `bridge_target.headers` (string→string map) as header pairs.
fn header_pairs(target: &BridgeTarget) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Some(Value::Object(headers)) = target_get_json(target, "headers") {
        for (name, value) in headers {
            if let Value::String(v) = value {
                if !v.is_empty() {
                    out.push((name, v));
                }
            }
        }
    }
    out
}

fn apply_headers(mut builder: reqwest::RequestBuilder, target: &BridgeTarget) -> reqwest::RequestBuilder {
    for (name, value) in header_pairs(target) {
        builder = builder.header(name, value);
    }
    builder
}

fn response_headers_map(resp: &reqwest::Response) -> Value {
    let mut map = Map::new();
    for (name, value) in resp.headers().iter() {
        let entry = map
            .entry(name.as_str().to_string())
            .or_insert_with(|| Value::String(String::new()));
        let text = value.to_str().unwrap_or_default();
        if let Value::String(existing) = entry {
            if existing.is_empty() {
                *existing = text.to_string();
            } else {
                existing.push(',');
                existing.push_str(text);
            }
        }
    }
    Value::Object(map)
}

// ── HTTP dispatcher ───────────────────────────────────────────────────────────

/// Built-in Bridge dispatcher for HTTP and HTTPS endpoints.
pub struct HttpBridgeDispatcher {
    client: reqwest::Client,
}

impl HttpBridgeDispatcher {
    /// Anchor reference used for HTTP bridge response records.
    pub const RESPONSE_ANCHOR_REF: &'static str = "nps://bridge/http-response/v1";

    /// Create an HTTP bridge dispatcher over an existing client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn dispatch_impl(
        &self,
        frame: &ActionFrame,
        target: &BridgeTarget,
    ) -> Result<CapsFrame, BridgeDispatchError> {
        let uri = parse_http_endpoint(target)?;
        let method_str = target_get_string(target, "method", Some("POST"))
            .unwrap_or_else(|| "POST".to_string());
        let method_norm = if method_str.trim().is_empty() {
            "POST".to_string()
        } else {
            method_str.trim().to_ascii_uppercase()
        };
        let method = reqwest::Method::from_bytes(method_norm.as_bytes())
            .unwrap_or(reqwest::Method::POST);

        let mut builder = self.client.request(method.clone(), &uri.url);
        builder = apply_headers(builder, target);

        // Body: only for non-GET/HEAD.
        if method != reqwest::Method::GET && method != reqwest::Method::HEAD {
            if let Some((body, media)) = resolve_http_body(frame, target) {
                builder = builder.header(reqwest::header::CONTENT_TYPE, media);
                builder = builder.body(body);
            }
        }

        let resp = builder
            .send()
            .await
            .map_err(|e| BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("HTTP bridge request failed. ({e})"),
            ))?;

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let headers = response_headers_map(&resp);
        let reason = status.canonical_reason().map(str::to_string);

        let body_text = resp
            .text()
            .await
            .map_err(|e| BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("HTTP bridge response read failed. ({e})"),
            ))?;

        let mut record = Map::new();
        record.insert("status_code".into(), json!(status.as_u16()));
        record.insert("reason_phrase".into(), json!(reason));
        record.insert("success".into(), json!(status.is_success()));
        record.insert("content_type".into(), json!(content_type));
        record.insert("headers".into(), headers);
        write_json_or_text_body(&mut record, "body", "body_text", &body_text, content_type.as_deref());

        Ok(caps_from_record(
            Self::RESPONSE_ANCHOR_REF,
            Value::Object(record),
            estimate_token_cost(body_text.len()),
        ))
    }
}

fn resolve_http_body(frame: &ActionFrame, target: &BridgeTarget) -> Option<(String, String)> {
    let body = if let Some(Value::Object(params)) = frame.params.as_ref() {
        params.get("body").cloned()
    } else {
        None
    }
    .or_else(|| target_get_json(target, "body"))?;

    let media = target_get_string(target, "content_type", Some("application/json"))
        .unwrap_or_else(|| "application/json".to_string());
    Some((raw_json_text(&body), media))
}

/// Emit JSON body verbatim (compact) matching .NET `JsonElement.GetRawText()`.
fn raw_json_text(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// Write either a parsed JSON body under `json_key` (when content-type is JSON and
/// the text parses) or the raw text under `text_key`.
fn write_json_or_text_body(
    record: &mut Map<String, Value>,
    json_key: &str,
    text_key: &str,
    body_text: &str,
    content_type: Option<&str>,
) {
    let is_json = content_type
        .map(|c| c.to_ascii_lowercase().contains("json"))
        .unwrap_or(false);
    if is_json && !body_text.trim().is_empty() {
        if let Ok(parsed) = serde_json::from_str::<Value>(body_text) {
            record.insert(json_key.to_string(), parsed);
            return;
        }
    }
    record.insert(text_key.to_string(), json!(body_text));
}

impl BridgeDispatcher for HttpBridgeDispatcher {
    fn protocol(&self) -> &str {
        bridge_protocols::HTTP
    }

    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a> {
        Box::pin(self.dispatch_impl(frame, target))
    }
}

// ── gRPC-JSON dispatcher ──────────────────────────────────────────────────────

/// Built-in Bridge dispatcher for unary gRPC calls using the JSON gRPC codec
/// (`application/grpc+json`) over HTTP POST. The endpoint path identifies the
/// service and method, e.g. `https://host/Package.Service/Method`.
pub struct GrpcBridgeDispatcher {
    client: reqwest::Client,
}

impl GrpcBridgeDispatcher {
    /// Anchor reference used for gRPC bridge response records.
    pub const RESPONSE_ANCHOR_REF: &'static str = "nps://bridge/grpc-json-response/v1";

    /// Create a gRPC bridge dispatcher over an existing client.
    pub fn new(client: reqwest::Client) -> Self {
        Self { client }
    }

    async fn dispatch_impl(
        &self,
        frame: &ActionFrame,
        target: &BridgeTarget,
    ) -> Result<CapsFrame, BridgeDispatchError> {
        let uri = parse_http_endpoint(target)?;
        let message = build_grpc_message(frame, target);

        let mut builder = self
            .client
            .post(&uri.url)
            .header(reqwest::header::CONTENT_TYPE, "application/grpc+json")
            .header("te", "trailers")
            .body(message);
        builder = apply_headers(builder, target);

        let resp = builder
            .send()
            .await
            .map_err(|e| BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("gRPC bridge request failed. ({e})"),
            ))?;

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let grpc_status = read_header(&resp, "grpc-status");
        let grpc_message = read_header(&resp, "grpc-message");
        let headers = response_headers_map(&resp);

        let bytes = resp
            .bytes()
            .await
            .map_err(|e| BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("gRPC bridge response read failed. ({e})"),
            ))?;

        let grpc_ok = matches!(grpc_status.as_deref(), Some("0") | None);
        let messages: Vec<Value> = read_grpc_messages(&bytes)
            .into_iter()
            .map(|m| match serde_json::from_slice::<Value>(&m) {
                Ok(v) => v,
                Err(_) => Value::String(base64_standard(&m)),
            })
            .collect();

        let mut record = Map::new();
        record.insert("status_code".into(), json!(status.as_u16()));
        record.insert("success".into(), json!(status.is_success() && grpc_ok));
        record.insert("content_type".into(), json!(content_type));
        record.insert("grpc_status".into(), json!(grpc_status));
        record.insert("grpc_message".into(), json!(grpc_message));
        record.insert("headers".into(), headers);
        // reqwest folds trailers into headers; expose an empty trailers object for shape parity.
        record.insert("trailers".into(), Value::Object(Map::new()));
        record.insert("messages".into(), Value::Array(messages));

        Ok(caps_from_record(
            Self::RESPONSE_ANCHOR_REF,
            Value::Object(record),
            estimate_token_cost(bytes.len()),
        ))
    }
}

fn build_grpc_message(frame: &ActionFrame, target: &BridgeTarget) -> Vec<u8> {
    let payload = target_get_json(target, "grpc_message")
        .or_else(|| target_get_json(target, "message"))
        .or_else(|| target_get_json(target, "body"))
        .or_else(|| {
            if let Some(Value::Object(params)) = frame.params.as_ref() {
                params.get("grpc_message").cloned()
            } else {
                None
            }
        })
        .or_else(|| frame.params.clone())
        .unwrap_or_else(|| json!({}));

    let json = raw_json_text(&payload).into_bytes();
    let mut wire = Vec::with_capacity(json.len() + 5);
    wire.push(0u8); // uncompressed
    wire.extend_from_slice(&(json.len() as u32).to_be_bytes());
    wire.extend_from_slice(&json);
    wire
}

fn read_grpc_messages(body: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while body.len().saturating_sub(offset) >= 5 {
        let compressed = body[offset] != 0;
        let length = u32::from_be_bytes([
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
            body[offset + 4],
        ]) as usize;
        offset += 5;
        if compressed || body.len().saturating_sub(offset) < length {
            break;
        }
        out.push(body[offset..offset + length].to_vec());
        offset += length;
    }
    out
}

fn read_header(resp: &reqwest::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Minimal standard base64 encoder (no external dep) for opaque gRPC messages.
fn base64_standard(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(n & 63) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

impl BridgeDispatcher for GrpcBridgeDispatcher {
    fn protocol(&self) -> &str {
        bridge_protocols::GRPC
    }

    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a> {
        Box::pin(self.dispatch_impl(frame, target))
    }
}

// ── JSON-RPC base dispatcher ──────────────────────────────────────────────────

static RPC_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Base dispatcher for JSON-RPC 2.0 protocols transported over HTTP POST.
pub struct JsonRpcBridgeDispatcher {
    client: reqwest::Client,
    protocol: &'static str,
    default_method: &'static str,
    response_anchor_ref: &'static str,
}

impl JsonRpcBridgeDispatcher {
    /// Create a JSON-RPC bridge dispatcher.
    pub fn new(
        client: reqwest::Client,
        protocol: &'static str,
        default_method: &'static str,
        response_anchor_ref: &'static str,
    ) -> Self {
        Self {
            client,
            protocol,
            default_method,
            response_anchor_ref,
        }
    }

    async fn dispatch_impl(
        &self,
        frame: &ActionFrame,
        target: &BridgeTarget,
    ) -> Result<CapsFrame, BridgeDispatchError> {
        let uri = parse_http_endpoint(target)?;
        let request_body = self.build_request_body(frame, target);

        let mut builder = self
            .client
            .post(&uri.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(request_body);
        builder = apply_headers(builder, target);

        let resp = builder.send().await.map_err(|e| {
            BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("{} JSON-RPC bridge request failed. ({e})", self.protocol),
            )
        })?;

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let headers = response_headers_map(&resp);

        let body_text = resp.text().await.map_err(|e| {
            BridgeDispatchError::new(
                bridge_error_codes::UPSTREAM_FAILED,
                format!("{} JSON-RPC bridge response read failed. ({e})", self.protocol),
            )
        })?;

        let mut record = Map::new();
        record.insert("status_code".into(), json!(status.as_u16()));
        record.insert("success".into(), json!(status.is_success()));
        record.insert("content_type".into(), json!(content_type));
        record.insert("headers".into(), headers);
        write_jsonrpc_body(&mut record, &body_text, content_type.as_deref());

        Ok(caps_from_record(
            self.response_anchor_ref,
            Value::Object(record),
            estimate_token_cost(body_text.len()),
        ))
    }

    fn build_request_body(&self, frame: &ActionFrame, target: &BridgeTarget) -> String {
        let mut obj = Map::new();
        obj.insert("jsonrpc".into(), json!("2.0"));
        obj.insert("id".into(), self.request_id(frame, target));
        obj.insert("method".into(), json!(self.rpc_method(frame, target)));
        obj.insert("params".into(), self.rpc_params(frame, target));
        serde_json::to_string(&Value::Object(obj)).unwrap_or_default()
    }

    fn rpc_method(&self, frame: &ActionFrame, target: &BridgeTarget) -> String {
        if let Some(m) = target_get_string(target, "rpc_method", None)
            .or_else(|| target_get_string(target, "method", None))
        {
            if !m.trim().is_empty() {
                return m;
            }
        }
        if let Some(Value::Object(params)) = frame.params.as_ref() {
            if let Some(Value::String(m)) = params.get("rpc_method") {
                if !m.trim().is_empty() {
                    return m.clone();
                }
            }
        }
        self.default_method.to_string()
    }

    fn request_id(&self, frame: &ActionFrame, target: &BridgeTarget) -> Value {
        if let Some(id) = target_get_json(target, "id") {
            return id;
        }
        if let Some(Value::Object(params)) = frame.params.as_ref() {
            if let Some(id) = params.get("id") {
                return id.clone();
            }
        }
        let n = RPC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        Value::String(format!("{nanos:x}{n:x}"))
    }

    fn rpc_params(&self, frame: &ActionFrame, target: &BridgeTarget) -> Value {
        if let Some(p) = target_get_json(target, "rpc_params")
            .or_else(|| target_get_json(target, "params"))
        {
            return p;
        }

        let Some(Value::Object(params)) = frame.params.as_ref() else {
            return json!({});
        };

        for name in ["rpc_params", "params", "body"] {
            if let Some(selected) = params.get(name) {
                return selected.clone();
            }
        }

        let mut out = Map::new();
        for (name, value) in params {
            if matches!(name.as_str(), "bridge_target" | "rpc_method" | "method" | "id") {
                continue;
            }
            out.insert(name.clone(), value.clone());
        }
        Value::Object(out)
    }
}

fn write_jsonrpc_body(record: &mut Map<String, Value>, body_text: &str, content_type: Option<&str>) {
    let is_json = content_type
        .map(|c| c.to_ascii_lowercase().contains("json"))
        .unwrap_or(false);
    if is_json && !body_text.trim().is_empty() {
        if let Ok(parsed) = serde_json::from_str::<Value>(body_text) {
            record.insert("jsonrpc_response".into(), parsed.clone());
            if let Value::Object(obj) = &parsed {
                if let Some(result) = obj.get("result") {
                    record.insert("result".into(), result.clone());
                }
                if let Some(error) = obj.get("error") {
                    record.insert("error".into(), error.clone());
                }
            }
            return;
        }
    }
    record.insert("body_text".into(), json!(body_text));
}

impl BridgeDispatcher for JsonRpcBridgeDispatcher {
    fn protocol(&self) -> &str {
        self.protocol
    }

    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a> {
        Box::pin(self.dispatch_impl(frame, target))
    }
}

// ── MCP dispatcher ────────────────────────────────────────────────────────────

/// Built-in Bridge dispatcher for MCP JSON-RPC servers over HTTP POST.
pub struct McpBridgeDispatcher {
    inner: JsonRpcBridgeDispatcher,
}

impl McpBridgeDispatcher {
    /// Anchor reference used for MCP bridge response records.
    pub const RESPONSE_ANCHOR_REF: &'static str = "nps://bridge/mcp-jsonrpc-response/v1";

    /// Create an MCP bridge dispatcher over an existing client.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            inner: JsonRpcBridgeDispatcher::new(
                client,
                bridge_protocols::MCP,
                "tools/call",
                Self::RESPONSE_ANCHOR_REF,
            ),
        }
    }
}

impl BridgeDispatcher for McpBridgeDispatcher {
    fn protocol(&self) -> &str {
        bridge_protocols::MCP
    }

    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a> {
        self.inner.dispatch(frame, target)
    }
}

// ── A2A dispatcher ────────────────────────────────────────────────────────────

/// Built-in Bridge dispatcher for A2A JSON-RPC endpoints over HTTP POST.
pub struct A2aBridgeDispatcher {
    inner: JsonRpcBridgeDispatcher,
}

impl A2aBridgeDispatcher {
    /// Anchor reference used for A2A bridge response records.
    pub const RESPONSE_ANCHOR_REF: &'static str = "nps://bridge/a2a-jsonrpc-response/v1";

    /// Create an A2A bridge dispatcher over an existing client.
    pub fn new(client: reqwest::Client) -> Self {
        Self {
            inner: JsonRpcBridgeDispatcher::new(
                client,
                bridge_protocols::A2A,
                "tasks/send",
                Self::RESPONSE_ANCHOR_REF,
            ),
        }
    }
}

impl BridgeDispatcher for A2aBridgeDispatcher {
    fn protocol(&self) -> &str {
        bridge_protocols::A2A
    }

    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a> {
        self.inner.dispatch(frame, target)
    }
}
