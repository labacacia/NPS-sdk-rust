// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! The inbound Bridge backend abstraction (NPS-CR-0010 §1).
//!
//! The consolidation is a **backend abstraction, not a deletion**: two
//! deployment shapes behind one trait, and the protocol servers are written
//! against the trait alone, unaware of the shape.
//!
//! ```text
//! NwpBackend ──┬── InProcessNwpBackend  (delegate dispatch — the SDK's shape)
//!              └── HttpNwpBackend       (HTTP to a remote node — the ingress shape)
//!                     ▲
//!        one McpInboundServer / A2aInboundServer / GrpcInboundService
//!        serving the full method set over either backend
//! ```

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use crate::error_codes;
use crate::frames::{ActionFrame, QueryFrame};

/// Boxed future returned by [`NwpBackend`] methods. `async fn` in traits is not
/// dyn-compatible, and the Bridge stores its backends as trait objects.
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

// ── Node role / descriptors ──────────────────────────────────────────────────

/// NWM `node_type`, mapped onto the projection capabilities the Bridge needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NwpNodeRole {
    /// Unreachable or unrecognised upstream — projected onto nothing.
    #[default]
    Unknown,
    Memory,
    Action,
    Complex,
    Anchor,
    Bridge,
}

impl NwpNodeRole {
    /// Lower-cases and maps the five known names; anything else is `Unknown`.
    pub fn parse(node_type: &str) -> Self {
        match node_type.trim().to_ascii_lowercase().as_str() {
            "memory" => NwpNodeRole::Memory,
            "action" => NwpNodeRole::Action,
            "complex" => NwpNodeRole::Complex,
            "anchor" => NwpNodeRole::Anchor,
            "bridge" => NwpNodeRole::Bridge,
            _ => NwpNodeRole::Unknown,
        }
    }

    /// Wire spelling, or `""` for `Unknown`.
    pub fn wire(&self) -> &'static str {
        match self {
            NwpNodeRole::Unknown => "",
            NwpNodeRole::Memory => "memory",
            NwpNodeRole::Action => "action",
            NwpNodeRole::Complex => "complex",
            NwpNodeRole::Anchor => "anchor",
            NwpNodeRole::Bridge => "bridge",
        }
    }
}

/// Identity of one NWP node fronted by the Bridge.
#[derive(Debug, Clone)]
pub struct NwpNodeDescriptor {
    /// Unique per Bridge — it namespaces resource URIs and MCP tool names.
    pub name: String,
    pub role: NwpNodeRole,
    pub display_name: Option<String>,
    pub description: Option<String>,
}

impl NwpNodeDescriptor {
    pub fn new(name: impl Into<String>, role: NwpNodeRole) -> Self {
        NwpNodeDescriptor {
            name: name.into(),
            role,
            display_name: None,
            description: None,
        }
    }

    /// Memory and Complex nodes answer queries — they become MCP resources.
    pub fn is_queryable(&self) -> bool {
        matches!(self.role, NwpNodeRole::Memory | NwpNodeRole::Complex)
    }

    /// Action and Complex nodes run actions — they become MCP tools / A2A skills.
    pub fn is_invokable(&self) -> bool {
        matches!(self.role, NwpNodeRole::Action | NwpNodeRole::Complex)
    }
}

/// One action exposed by a fronted node.
#[derive(Debug, Clone)]
pub struct NwpActionDescriptor {
    pub action_id: String,
    pub description: Option<String>,
    /// Absent ⇒ the Bridge advertises the open object schema.
    pub input_schema: Option<Value>,
    pub is_async: bool,
    pub tags: Option<Vec<String>>,
}

impl NwpActionDescriptor {
    pub fn new(action_id: impl Into<String>) -> Self {
        NwpActionDescriptor {
            action_id: action_id.into(),
            description: None,
            input_schema: None,
            is_async: false,
            tags: None,
        }
    }

    /// The schema advertised for this action: its own, or the open object
    /// schema when it declares none.
    pub fn effective_input_schema(&self) -> Value {
        self.input_schema.clone().unwrap_or_else(open_object_schema)
    }
}

/// `{"type":"object","additionalProperties":true}`.
pub fn open_object_schema() -> Value {
    json!({ "type": "object", "additionalProperties": true })
}

// ── Result ───────────────────────────────────────────────────────────────────

/// Outcome of a backend call.
///
/// **This type is why the §16.3 mapping works**: it carries the NPS status
/// forward instead of an opaque body, so the protocol servers can pick the
/// right foreign-protocol code rather than collapsing everything onto "error".
#[derive(Debug, Clone, PartialEq)]
pub struct NwpResult {
    pub ok: bool,
    pub payload: Option<Value>,
    pub nps_status: Option<String>,
    pub nwp_error: Option<String>,
    pub message: Option<String>,
}

impl NwpResult {
    pub fn success(payload: Value) -> Self {
        NwpResult {
            ok: true,
            payload: Some(payload),
            nps_status: None,
            nwp_error: None,
            message: None,
        }
    }

    pub fn failure(
        nps_status: impl Into<String>,
        nwp_error: Option<&str>,
        message: Option<&str>,
    ) -> Self {
        NwpResult {
            ok: false,
            payload: None,
            nps_status: Some(nps_status.into()),
            nwp_error: nwp_error.map(str::to_string),
            message: message.map(str::to_string),
        }
    }

    /// `NPS-SERVER-INTERNAL` / `NWP-BRIDGE-SERVER-DISPATCH-FAILED`.
    pub fn dispatch_failed(message: &str) -> Self {
        Self::failure(
            "NPS-SERVER-INTERNAL",
            Some(error_codes::BRIDGE_SERVER_DISPATCH_FAILED),
            Some(message),
        )
    }

    /// Failure body projected for a foreign protocol: `{status, error, message}`.
    pub fn failure_payload(&self) -> Value {
        json!({
            "status":  self.nps_status,
            "error":   self.nwp_error,
            "message": self.message,
        })
    }

    /// Best available human-readable detail, in the .NET precedence order.
    pub fn detail(&self) -> String {
        self.message
            .clone()
            .or_else(|| self.nwp_error.clone())
            .or_else(|| self.nps_status.clone())
            .unwrap_or_default()
    }
}

// ── The trait ────────────────────────────────────────────────────────────────

/// One NWP node fronted by the Bridge, whether local or remote.
pub trait NwpBackend: Send + Sync {
    fn descriptor(&self) -> BackendFuture<'_, NwpNodeDescriptor>;
    /// The raw `/.nwm` manifest.
    fn manifest(&self) -> BackendFuture<'_, NwpResult>;
    fn actions(&self) -> BackendFuture<'_, Vec<NwpActionDescriptor>>;
    fn query(&self, query: Value) -> BackendFuture<'_, NwpResult>;
    fn invoke<'a>(
        &'a self,
        action_id: &'a str,
        arguments: Option<Value>,
        is_async: bool,
    ) -> BackendFuture<'a, NwpResult>;
}

// ── In-process backend ───────────────────────────────────────────────────────

/// Error a local dispatcher returns. An `nps_status` of `None` means "the
/// dispatcher blew up" and maps onto `NWP-BRIDGE-SERVER-DISPATCH-FAILED` — the
/// Rust stand-in for the reference's catch-all exception arm.
#[derive(Debug, Clone)]
pub struct BridgeDispatchError {
    pub nps_status: Option<String>,
    pub nwp_error: Option<String>,
    pub message: Option<String>,
}

impl BridgeDispatchError {
    /// An ErrorFrame coming back from the fronted node.
    pub fn error_frame(
        nps_status: impl Into<String>,
        nwp_error: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        BridgeDispatchError {
            nps_status: Some(nps_status.into()),
            nwp_error: Some(nwp_error.into()),
            message: Some(message.into()),
        }
    }

    /// An unexpected dispatcher failure.
    pub fn failed(message: impl Into<String>) -> Self {
        BridgeDispatchError {
            nps_status: None,
            nwp_error: None,
            message: Some(message.into()),
        }
    }

    fn into_result(self) -> NwpResult {
        match self.nps_status {
            Some(status) => NwpResult {
                ok: false,
                payload: None,
                nps_status: Some(status),
                nwp_error: self.nwp_error,
                message: self.message,
            },
            None => NwpResult::dispatch_failed(&self.message.unwrap_or_default()),
        }
    }
}

pub type ActionDispatcher =
    Arc<dyn Fn(&ActionFrame) -> Result<Value, BridgeDispatchError> + Send + Sync>;
pub type QueryDispatcher =
    Arc<dyn Fn(&QueryFrame) -> Result<Value, BridgeDispatchError> + Send + Sync>;

/// Fronts a node running inside this process, reached through injected
/// dispatch delegates. This is the SDK's deployment shape.
pub struct InProcessNwpBackend {
    descriptor: NwpNodeDescriptor,
    actions: Vec<NwpActionDescriptor>,
    invoke_dispatcher: Option<ActionDispatcher>,
    query_dispatcher: Option<QueryDispatcher>,
}

impl InProcessNwpBackend {
    pub fn new(descriptor: NwpNodeDescriptor) -> Self {
        InProcessNwpBackend {
            descriptor,
            actions: Vec::new(),
            invoke_dispatcher: None,
            query_dispatcher: None,
        }
    }

    pub fn with_actions(mut self, actions: Vec<NwpActionDescriptor>) -> Self {
        self.actions = actions;
        self
    }

    pub fn with_invoke_dispatcher(mut self, d: ActionDispatcher) -> Self {
        self.invoke_dispatcher = Some(d);
        self
    }

    pub fn with_query_dispatcher(mut self, d: QueryDispatcher) -> Self {
        self.query_dispatcher = Some(d);
        self
    }
}

impl NwpBackend for InProcessNwpBackend {
    fn descriptor(&self) -> BackendFuture<'_, NwpNodeDescriptor> {
        let d = self.descriptor.clone();
        Box::pin(async move { d })
    }

    fn manifest(&self) -> BackendFuture<'_, NwpResult> {
        let d = self.descriptor.clone();
        Box::pin(async move {
            NwpResult::success(json!({
                "node_type":    d.role.wire(),
                "display_name": d.display_name,
                "description":  d.description,
            }))
        })
    }

    fn actions(&self) -> BackendFuture<'_, Vec<NwpActionDescriptor>> {
        // A non-invokable node exposes no tools, whatever it declared.
        let a = if self.descriptor.is_invokable() {
            self.actions.clone()
        } else {
            Vec::new()
        };
        Box::pin(async move { a })
    }

    fn query(&self, query: Value) -> BackendFuture<'_, NwpResult> {
        Box::pin(async move {
            if !self.descriptor.is_queryable() {
                return NwpResult::failure(
                    "NPS-SERVER-UNSUPPORTED",
                    Some(error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND),
                    Some(&format!(
                        "Node '{}' is not queryable (role: {}).",
                        self.descriptor.name,
                        self.descriptor.role.wire()
                    )),
                );
            }
            let Some(d) = &self.query_dispatcher else {
                return NwpResult::failure(
                    "NPS-SERVER-INTERNAL",
                    Some(error_codes::BRIDGE_SERVER_DISPATCHER_MISSING),
                    Some(&format!(
                        "Node '{}' has no query dispatcher configured.",
                        self.descriptor.name
                    )),
                );
            };
            let mut frame = QueryFrame::new("");
            frame.filter = Some(query);
            match d(&frame) {
                Ok(v) => NwpResult::success(v),
                Err(e) => e.into_result(),
            }
        })
    }

    fn invoke<'a>(
        &'a self,
        action_id: &'a str,
        arguments: Option<Value>,
        is_async: bool,
    ) -> BackendFuture<'a, NwpResult> {
        Box::pin(async move {
            let Some(d) = &self.invoke_dispatcher else {
                // Deliberately loud: a deployment that declared actions but
                // forgot the dispatcher fails here with a registered code
                // rather than looking like "this node exposes nothing".
                return NwpResult::failure(
                    "NPS-SERVER-INTERNAL",
                    Some(error_codes::BRIDGE_SERVER_DISPATCHER_MISSING),
                    Some(&format!(
                        "Node '{}' has no action dispatcher configured.",
                        self.descriptor.name
                    )),
                );
            };
            let frame = ActionFrame {
                action: action_id.to_string(),
                params: arguments,
                anchor_ref: None,
                async_: is_async,
                idempotency_key: None,
                timeout_ms: None,
                request_id: None,
            };
            match d(&frame) {
                Ok(v) => NwpResult::success(v),
                Err(e) => e.into_result(),
            }
        })
    }
}

// ── HTTP backend ─────────────────────────────────────────────────────────────

/// A remote NWP node the Bridge fronts over HTTP.
#[derive(Debug, Clone)]
pub struct NwpUpstream {
    pub name: String,
    pub base_url: String,
    pub agent_nid: Option<String>,
    pub auth_header: Option<String>,
    pub read_limit: u32,
}

impl NwpUpstream {
    pub fn new(name: impl Into<String>, base_url: impl Into<String>) -> Self {
        NwpUpstream {
            name: name.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            agent_nid: None,
            auth_header: None,
            read_limit: 100,
        }
    }
}

/// Fronts a node reached over HTTP (`GET /.nwm`, `GET /actions`, `POST /query`,
/// `POST /invoke`) — the shape the retired `compat/*-ingress` projects had.
pub struct HttpNwpBackend {
    upstream: NwpUpstream,
    http: reqwest::Client,
    /// Cached after the first fetch. An unreachable `/.nwm` caches
    /// `role = Unknown`: a dead upstream must not take down the Bridge, it is
    /// simply projected onto nothing.
    descriptor: Mutex<Option<NwpNodeDescriptor>>,
}

impl HttpNwpBackend {
    pub fn new(upstream: NwpUpstream, http: reqwest::Client) -> Self {
        HttpNwpBackend {
            upstream,
            http,
            descriptor: Mutex::new(None),
        }
    }

    fn decorate(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut rb = rb;
        if let Some(nid) = &self.upstream.agent_nid {
            rb = rb.header(crate::http_headers::AGENT, nid);
        }
        if let Some(auth) = &self.upstream.auth_header {
            rb = rb.header("Authorization", auth);
        }
        rb
    }

    /// The §16.3 inverse direction: translate a transport failure into the most
    /// specific NPS status, never a blanket `NPS-SERVER-INTERNAL`.
    fn transport_failure(e: &reqwest::Error) -> NwpResult {
        let status = if e.is_timeout() {
            "NPS-SERVER-TIMEOUT"
        } else {
            "NPS-DOWNSTREAM-UNAVAILABLE"
        };
        NwpResult::failure(
            status,
            Some(error_codes::BRIDGE_UPSTREAM_FAILED),
            Some(&e.to_string()),
        )
    }

    async fn read_json(resp: reqwest::Response) -> NwpResult {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let parsed: Option<Value> = serde_json::from_str(&body).ok();
        if (200..300).contains(&status) {
            return match parsed {
                Some(v) => NwpResult::success(v),
                None => NwpResult::failure(
                    "NPS-DOWNSTREAM-UNAVAILABLE",
                    Some(error_codes::BRIDGE_UPSTREAM_FAILED),
                    Some("upstream returned a non-JSON 2xx body."),
                ),
            };
        }
        let nwp_error = parsed
            .as_ref()
            .and_then(|v| v.get("error"))
            .and_then(Value::as_str)
            .map(str::to_string);
        NwpResult::failure(
            super::error_map::from_http_status(status),
            nwp_error.as_deref(),
            Some(&body),
        )
    }
}

impl NwpBackend for HttpNwpBackend {
    fn descriptor(&self) -> BackendFuture<'_, NwpNodeDescriptor> {
        Box::pin(async move {
            if let Some(d) = self.descriptor.lock().unwrap().clone() {
                return d;
            }
            let url = format!("{}/.nwm", self.upstream.base_url);
            let role = match self.decorate(self.http.get(&url)).send().await {
                Ok(r) => {
                    let v: Value = r.json().await.unwrap_or(Value::Null);
                    v.get("node_type")
                        .and_then(Value::as_str)
                        .map(NwpNodeRole::parse)
                        .unwrap_or(NwpNodeRole::Unknown)
                }
                Err(_) => NwpNodeRole::Unknown,
            };
            let d = NwpNodeDescriptor::new(self.upstream.name.clone(), role);
            *self.descriptor.lock().unwrap() = Some(d.clone());
            d
        })
    }

    fn manifest(&self) -> BackendFuture<'_, NwpResult> {
        Box::pin(async move {
            let url = format!("{}/.nwm", self.upstream.base_url);
            match self.decorate(self.http.get(&url)).send().await {
                Ok(r) => Self::read_json(r).await,
                Err(e) => Self::transport_failure(&e),
            }
        })
    }

    fn actions(&self) -> BackendFuture<'_, Vec<NwpActionDescriptor>> {
        Box::pin(async move {
            if !self.descriptor().await.is_invokable() {
                return Vec::new();
            }
            let url = format!("{}/actions", self.upstream.base_url);
            let Ok(r) = self.decorate(self.http.get(&url)).send().await else {
                return Vec::new();
            };
            let v: Value = r.json().await.unwrap_or(Value::Null);
            // { "actions": { "<action_id>": { "description", "params_schema" } } }
            let Some(map) = v.get("actions").and_then(Value::as_object) else {
                return Vec::new();
            };
            map.iter()
                .map(|(id, spec)| NwpActionDescriptor {
                    action_id: id.clone(),
                    description: spec
                        .get("description")
                        .and_then(Value::as_str)
                        .map(str::to_string),
                    input_schema: spec.get("params_schema").cloned(),
                    is_async: spec.get("async").and_then(Value::as_bool).unwrap_or(false),
                    tags: None,
                })
                .collect()
        })
    }

    fn query(&self, query: Value) -> BackendFuture<'_, NwpResult> {
        Box::pin(async move {
            let d = self.descriptor().await;
            if !d.is_queryable() {
                return NwpResult::failure(
                    "NPS-SERVER-UNSUPPORTED",
                    Some(error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND),
                    Some(&format!(
                        "Node '{}' is not queryable (role: {}).",
                        d.name,
                        d.role.wire()
                    )),
                );
            }
            let url = format!("{}/query", self.upstream.base_url);
            match self
                .decorate(self.http.post(&url))
                .header("Content-Type", crate::http_headers::MIME_FRAME)
                .json(&query)
                .send()
                .await
            {
                Ok(r) => Self::read_json(r).await,
                Err(e) => Self::transport_failure(&e),
            }
        })
    }

    fn invoke<'a>(
        &'a self,
        action_id: &'a str,
        arguments: Option<Value>,
        is_async: bool,
    ) -> BackendFuture<'a, NwpResult> {
        Box::pin(async move {
            let url = format!("{}/invoke", self.upstream.base_url);
            let body = json!({
                "action_id": action_id,
                "params":    arguments,
                "async":     is_async,
            });
            match self
                .decorate(self.http.post(&url))
                .header("Content-Type", crate::http_headers::MIME_FRAME)
                .json(&body)
                .send()
                .await
            {
                Ok(r) => Self::read_json(r).await,
                Err(e) => Self::transport_failure(&e),
            }
        })
    }
}
