// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Action Node server — framework-agnostic request handler (zero new deps).
//!
//! Faithful port of the .NET `ActionNodeMiddleware` (NPS-2 §3.2, §7). Exposes a
//! single Action Node at a configurable path prefix. Sub-paths: `/.nwm`,
//! `/.schema`, `/actions`, `/invoke`. The reserved actions `system.task.status`
//! and `system.task.cancel` are handled by the server itself and MUST NOT appear
//! in [`ActionNodeOptions::actions`].
//!
//! [`ActionNodeApp::handle`] takes a [`NodeRequest`] and returns a
//! [`NodeResponse`] — adapt it to any HTTP server. Business execution behind
//! `/invoke` is delegated to an [`ActionNodeProvider`].

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::node_http::{empty, error_resp, NodeRequest, NodeResponse};
use crate::{error_codes, http_headers};

/// Reserved action id for polling async task state (NPS-2 §7.3).
pub const SYSTEM_TASK_STATUS: &str = "system.task.status";
/// Reserved action id for cancelling a running async task (NPS-2 §7.3).
pub const SYSTEM_TASK_CANCEL: &str = "system.task.cancel";

const NODE_TYPE_ACTION: &str = "action";

// ── ActionSpec ─────────────────────────────────────────────────────────────────

/// NWM action registry entry (NPS-2 §4.6). Port of .NET `ActionSpec`.
#[derive(Debug, Clone, Default)]
pub struct ActionSpec {
    pub description: Option<String>,
    pub params_anchor: Option<String>,
    pub result_anchor: Option<String>,
    pub async_: bool,
    pub idempotent: Option<bool>,
    pub timeout_ms_default: Option<u32>,
    pub timeout_ms_max: Option<u32>,
    pub required_capability: Option<String>,
}

impl ActionSpec {
    pub fn new(async_: bool) -> Self {
        ActionSpec {
            async_,
            ..Default::default()
        }
    }
}

// ── Options ────────────────────────────────────────────────────────────────────

/// Configuration for a single Action Node (NPS-2 §2.1, §7). Port of .NET `ActionNodeOptions`.
pub struct ActionNodeOptions {
    pub node_id: String,
    pub display_name: Option<String>,
    pub actions: BTreeMap<String, ActionSpec>,
    /// Optional NWM profile descriptors keyed by profile name.
    pub profiles: BTreeMap<String, Value>,
    pub path_prefix: String,
    pub require_auth: bool,
    pub default_timeout_ms: u32,
    pub max_timeout_ms: u32,
    /// Idempotency cache TTL. Default 24 h (NPS-2 §7.1).
    pub idempotency_ttl: Duration,
    /// Retention for terminal-state tasks. Default 1 h.
    pub task_retention: Duration,
    /// Reject callback_url that resolves to a private/loopback address. Default true.
    pub reject_private_callback_urls: bool,
    pub default_token_budget: u32,
}

impl ActionNodeOptions {
    pub fn new(node_id: impl Into<String>, path_prefix: impl Into<String>) -> Self {
        ActionNodeOptions {
            node_id: node_id.into(),
            display_name: None,
            actions: BTreeMap::new(),
            profiles: BTreeMap::new(),
            path_prefix: path_prefix.into(),
            require_auth: false,
            default_timeout_ms: 5_000,
            max_timeout_ms: 300_000,
            idempotency_ttl: Duration::from_secs(24 * 3600),
            task_retention: Duration::from_secs(3600),
            reject_private_callback_urls: true,
            default_token_budget: 0,
        }
    }
}

// ── Provider ───────────────────────────────────────────────────────────────────

/// Result of a single action execution. Port of .NET `ActionExecutionResult`.
#[derive(Clone, Default)]
pub struct ActionExecutionResult {
    /// Action output (single CapsFrame data element). `None` = no payload.
    pub result: Option<Value>,
    /// Streaming output. The Action Server emits NDJSON under a fresh stream id.
    pub stream: Option<Arc<dyn ActionStream>>,
    /// Optional anchor_id overriding [`ActionSpec::result_anchor`].
    pub anchor_ref: Option<String>,
    /// Approximate token count of the serialised result. 0 when unknown.
    pub token_est: u32,
}

impl std::fmt::Debug for ActionExecutionResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionExecutionResult")
            .field("result", &self.result)
            .field("stream", &self.stream.as_ref().map(|_| "ActionStream"))
            .field("anchor_ref", &self.anchor_ref)
            .field("token_est", &self.token_est)
            .finish()
    }
}

/// Canonical NWP streaming response shape used by Action Nodes.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActionStreamFrame {
    #[serde(default)]
    pub stream_id: String,
    pub seq: u64,
    pub is_last: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_ref: Option<String>,
    #[serde(default)]
    pub data: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Producer-side stream callback. Implementations must emit contiguous frames
/// beginning at sequence zero and exactly one terminal frame.
pub trait ActionStream: Send + Sync {
    fn write(
        &self,
        cancellation: &ActionCancellation,
        emit: &mut dyn FnMut(ActionStreamFrame) -> Result<(), ActionError>,
    ) -> Result<(), ActionError>;
}

impl<F> ActionStream for F
where
    F: Fn(
            &ActionCancellation,
            &mut dyn FnMut(ActionStreamFrame) -> Result<(), ActionError>,
        ) -> Result<(), ActionError>
        + Send
        + Sync,
{
    fn write(
        &self,
        cancellation: &ActionCancellation,
        emit: &mut dyn FnMut(ActionStreamFrame) -> Result<(), ActionError>,
    ) -> Result<(), ActionError> {
        self(cancellation, emit)
    }
}

/// Execution context passed to [`ActionNodeProvider::execute`]. Port of .NET `ActionContext`.
#[derive(Debug, Clone)]
pub struct ActionContext {
    pub agent_nid: Option<String>,
    pub request_id: Option<String>,
    pub task_id: Option<String>,
    pub spec: ActionSpec,
    pub timeout_ms: u32,
    pub priority: String,
    /// Exact serialized ActionFrame payload length at the decoder boundary.
    pub wire_input_bytes: u64,
    pub cancellation: ActionCancellation,
}

type CancellationListener = Box<dyn FnOnce() + Send + 'static>;

#[derive(Default)]
struct CancellationState {
    cancelled: AtomicBool,
    listeners: Mutex<Vec<CancellationListener>>,
}

/// Cooperative cancellation shared by task hosting and provider coordinators.
#[derive(Clone, Default)]
pub struct ActionCancellation {
    state: Arc<CancellationState>,
}

impl std::fmt::Debug for ActionCancellation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ActionCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl ActionCancellation {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.state.cancelled.load(Ordering::Acquire)
    }

    pub fn on_cancel(&self, listener: impl FnOnce() + Send + 'static) {
        if self.is_cancelled() {
            listener();
            return;
        }
        let mut listeners = self.state.listeners.lock().expect("cancellation listeners");
        if self.is_cancelled() {
            drop(listeners);
            listener();
        } else {
            listeners.push(Box::new(listener));
        }
    }

    pub fn cancel(&self) {
        if self.state.cancelled.swap(true, Ordering::AcqRel) {
            return;
        }
        let listeners = {
            let mut listeners = self.state.listeners.lock().expect("cancellation listeners");
            std::mem::take(&mut *listeners)
        };
        for listener in listeners {
            listener();
        }
    }
}

/// Error envelope a provider may return to shape the HTTP error response.
#[derive(Debug, Clone)]
pub struct ActionError {
    pub http_status: u16,
    pub nps_status: String,
    pub error_code: String,
    pub message: String,
}

impl ActionError {
    /// A generic execution failure → 500 / NWP-NODE-UNAVAILABLE (matches .NET catch-all).
    pub fn internal(message: impl Into<String>) -> Self {
        ActionError {
            http_status: 500,
            nps_status: "NPS-SERVER-INTERNAL".into(),
            error_code: error_codes::NODE_UNAVAILABLE.into(),
            message: message.into(),
        }
    }
}

/// Implement this to expose a set of actions on an Action Node. Port of .NET `IActionNodeProvider`.
pub trait ActionNodeProvider: Send + Sync {
    /// Admission check executed before idempotency-cache replay.
    fn authorize(
        &self,
        _frame: &ParsedActionFrame,
        _context: &ActionContext,
    ) -> Result<(), ActionError> {
        Ok(())
    }

    fn execute(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError>;
}

/// Parsed `ActionFrame` (NPS-2 §6). Field names mirror the .NET wire contract.
#[derive(Debug, Clone)]
pub struct ParsedActionFrame {
    pub action_id: String,
    pub params: Option<Value>,
    pub idempotency_key: Option<String>,
    pub timeout_ms: u32,
    pub async_: bool,
    pub callback_url: Option<String>,
    pub priority: Option<String>,
    pub request_id: Option<String>,
}

impl ParsedActionFrame {
    pub(crate) fn from_json(body: &Value) -> Result<Self, String> {
        let obj = body
            .as_object()
            .ok_or_else(|| "ActionFrame must be a JSON object.".to_string())?;
        let action_id = obj
            .get("action_id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "invalid ActionFrame: missing action_id.".to_string())?
            .to_string();
        Ok(ParsedActionFrame {
            action_id,
            params: obj.get("params").cloned().filter(|v| !v.is_null()),
            idempotency_key: obj
                .get("idempotency_key")
                .and_then(Value::as_str)
                .map(String::from),
            timeout_ms: obj.get("timeout_ms").and_then(Value::as_u64).unwrap_or(0) as u32,
            async_: obj.get("async").and_then(Value::as_bool).unwrap_or(false),
            callback_url: obj
                .get("callback_url")
                .and_then(Value::as_str)
                .map(String::from),
            priority: obj
                .get("priority")
                .and_then(Value::as_str)
                .map(String::from),
            request_id: obj
                .get("request_id")
                .and_then(Value::as_str)
                .map(String::from),
        })
    }
}

// ── Task store ─────────────────────────────────────────────────────────────────

/// Record of a single async action task. State machine (NPS-2 §7.2):
/// `pending → running → completed / failed / cancelled`.
#[derive(Debug, Clone)]
pub struct ActionTaskRecord {
    pub task_id: String,
    pub action_id: String,
    pub status: String,
    pub progress: Option<f64>,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub request_id: Option<String>,
    pub agent_nid: Option<String>,
    pub result: Option<Value>,
    pub error: Option<Value>,
}

fn is_terminal(status: &str) -> bool {
    matches!(status, "completed" | "failed" | "cancelled")
}

/// Storage for async task state. Port of .NET `IActionTaskStore`.
pub trait ActionTaskStore: Send + Sync {
    fn create(
        &self,
        task_id: &str,
        action_id: &str,
        request_id: Option<&str>,
        agent_nid: Option<&str>,
    ) -> ActionTaskRecord;
    fn get(&self, task_id: &str) -> Option<ActionTaskRecord>;
    fn try_transition(&self, task_id: &str, expected: &str, new: &str) -> bool;
    fn complete(&self, task_id: &str, result: Option<Value>) -> bool;
    fn fail(&self, task_id: &str, error: Value) -> bool;
    fn cancel(&self, task_id: &str) -> bool;
    fn update_progress(&self, task_id: &str, progress: f64) -> bool;
}

/// In-process task store. Port of .NET `InMemoryActionTaskStore`.
#[derive(Default)]
pub struct InMemoryActionTaskStore {
    tasks: Mutex<BTreeMap<String, ActionTaskRecord>>,
}

impl InMemoryActionTaskStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ActionTaskStore for InMemoryActionTaskStore {
    fn create(
        &self,
        task_id: &str,
        action_id: &str,
        request_id: Option<&str>,
        agent_nid: Option<&str>,
    ) -> ActionTaskRecord {
        let now = now_utc();
        let rec = ActionTaskRecord {
            task_id: task_id.to_string(),
            action_id: action_id.to_string(),
            status: "pending".into(),
            progress: None,
            created_at: now,
            updated_at: now,
            request_id: request_id.map(String::from),
            agent_nid: agent_nid.map(String::from),
            result: None,
            error: None,
        };
        self.tasks
            .lock()
            .unwrap()
            .insert(task_id.to_string(), rec.clone());
        rec
    }

    fn get(&self, task_id: &str) -> Option<ActionTaskRecord> {
        self.tasks.lock().unwrap().get(task_id).cloned()
    }

    fn try_transition(&self, task_id: &str, expected: &str, new: &str) -> bool {
        let mut g = self.tasks.lock().unwrap();
        if let Some(rec) = g.get_mut(task_id) {
            if rec.status == expected {
                rec.status = new.into();
                rec.updated_at = now_utc();
                return true;
            }
        }
        false
    }

    fn complete(&self, task_id: &str, result: Option<Value>) -> bool {
        let mut g = self.tasks.lock().unwrap();
        if let Some(rec) = g.get_mut(task_id) {
            if is_terminal(&rec.status) {
                return false;
            }
            rec.status = "completed".into();
            rec.result = result;
            rec.progress = Some(1.0);
            rec.updated_at = now_utc();
            return true;
        }
        false
    }

    fn fail(&self, task_id: &str, error: Value) -> bool {
        let mut g = self.tasks.lock().unwrap();
        if let Some(rec) = g.get_mut(task_id) {
            if is_terminal(&rec.status) {
                return false;
            }
            rec.status = "failed".into();
            rec.error = Some(error);
            rec.updated_at = now_utc();
            return true;
        }
        false
    }

    fn cancel(&self, task_id: &str) -> bool {
        let mut g = self.tasks.lock().unwrap();
        if let Some(rec) = g.get_mut(task_id) {
            if is_terminal(&rec.status) {
                return false;
            }
            rec.status = "cancelled".into();
            rec.updated_at = now_utc();
            return true;
        }
        false
    }

    fn update_progress(&self, task_id: &str, progress: f64) -> bool {
        let mut g = self.tasks.lock().unwrap();
        if let Some(rec) = g.get_mut(task_id) {
            rec.progress = Some(progress.clamp(0.0, 1.0));
            rec.updated_at = now_utc();
            return true;
        }
        false
    }
}

// ── Idempotency cache ──────────────────────────────────────────────────────────

/// A cached idempotent response (NPS-2 §7.1). Port of .NET `IdempotentEntry`.
#[derive(Debug, Clone)]
pub struct IdempotentEntry {
    pub action_id: String,
    pub params_hash: String,
    pub result: Option<Value>,
    pub stream_frames: Option<Vec<ActionStreamFrame>>,
    pub anchor_ref: Option<String>,
    pub task_id: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// Cache of idempotent action results. Port of .NET `IIdempotencyCache`.
pub trait IdempotencyCache: Send + Sync {
    fn get(&self, action_id: &str, idempotency_key: &str) -> Option<IdempotentEntry>;
    /// Store an entry. If one with the same key exists and its `params_hash` differs,
    /// returns `false` (caller raises NWP-ACTION-IDEMPOTENCY-CONFLICT). Same hash re-stores.
    fn try_store(&self, action_id: &str, idempotency_key: &str, entry: IdempotentEntry) -> bool;
}

/// In-process idempotency cache. Port of .NET `InMemoryIdempotencyCache`.
#[derive(Default)]
pub struct InMemoryIdempotencyCache {
    entries: Mutex<BTreeMap<String, IdempotentEntry>>,
}

impl InMemoryIdempotencyCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(action_id: &str, idempotency_key: &str) -> String {
        format!("{action_id}\u{1f}{idempotency_key}")
    }
}

impl IdempotencyCache for InMemoryIdempotencyCache {
    fn get(&self, action_id: &str, idempotency_key: &str) -> Option<IdempotentEntry> {
        let key = Self::key(action_id, idempotency_key);
        let mut g = self.entries.lock().unwrap();
        if let Some(entry) = g.get(&key) {
            if entry.expires_at <= now_utc() {
                g.remove(&key);
                return None;
            }
            return Some(entry.clone());
        }
        None
    }

    fn try_store(&self, action_id: &str, idempotency_key: &str, entry: IdempotentEntry) -> bool {
        let key = Self::key(action_id, idempotency_key);
        let now = now_utc();
        let mut g = self.entries.lock().unwrap();
        if let Some(existing) = g.get(&key) {
            if existing.expires_at > now {
                return existing.params_hash == entry.params_hash;
            }
        }
        g.insert(key, entry);
        true
    }
}

// ── Callback SSRF validator ────────────────────────────────────────────────────

/// Validates `ActionFrame.callback_url` per NPS-2 §7.1. Returns `None` on success,
/// otherwise a human-readable error. Port of .NET `ActionCallbackValidator`.
pub fn validate_callback_url(callback_url: &str, reject_private: bool) -> Option<String> {
    if callback_url.trim().is_empty() {
        return Some("callback_url must not be empty.".into());
    }
    let parsed = match parse_absolute_url(callback_url) {
        Some(p) => p,
        None => {
            return Some(format!(
                "callback_url '{callback_url}' is not a valid absolute URI."
            ))
        }
    };
    if !parsed.scheme.eq_ignore_ascii_case("https") {
        return Some(format!(
            "callback_url MUST use the https:// scheme (got '{}://').",
            parsed.scheme
        ));
    }
    if reject_private && is_private_host(&parsed.host) {
        return Some(format!(
            "callback_url host '{}' resolves to a private or loopback address (SSRF guard).",
            parsed.host
        ));
    }
    None
}

pub(crate) struct ParsedUrl {
    pub scheme: String,
    pub host: String,
}

/// Minimal absolute-URL parser (scheme://host[:port]/...). No external deps.
pub(crate) fn parse_absolute_url(url: &str) -> Option<ParsedUrl> {
    let idx = url.find("://")?;
    let scheme = &url[..idx];
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
    {
        return None;
    }
    let rest = &url[idx + 3..];
    if rest.is_empty() {
        return None;
    }
    // authority ends at first '/', '?' or '#'
    let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..auth_end];
    if authority.is_empty() {
        return None;
    }
    // strip userinfo
    let hostport = authority.rsplit('@').next().unwrap_or(authority);
    // handle IPv6 literal [::1]
    let host = if let Some(close) = hostport.find(']') {
        // [addr] form
        hostport[..=close].to_string()
    } else {
        // strip :port
        hostport.split(':').next().unwrap_or(hostport).to_string()
    };
    if host.is_empty() {
        return None;
    }
    Some(ParsedUrl {
        scheme: scheme.to_string(),
        host,
    })
}

/// Detects loopback / link-local / RFC1918 hosts. Port of .NET `IsPrivateHost`.
pub(crate) fn is_private_host(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    // IPv4?
    if let Some(octets) = parse_ipv4(stripped) {
        let [a, b, _, _] = octets;
        return a == 127
            || a == 10
            || a == 0
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 169 && b == 254);
    }
    // IPv6 loopback / link-local / unique-local
    if stripped.contains(':') {
        let lower = stripped.to_ascii_lowercase();
        if lower == "::1" {
            return true;
        }
        if lower.starts_with("fe80") || lower.starts_with("fc") || lower.starts_with("fd") {
            return true;
        }
        // ::ffff:127.0.0.1 mapped
        if let Some(pos) = lower.rfind(':') {
            if let Some(octets) = parse_ipv4(&lower[pos + 1..]) {
                return is_private_host(&format!(
                    "{}.{}.{}.{}",
                    octets[0], octets[1], octets[2], octets[3]
                ));
            }
        }
        return false;
    }
    false
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().ok()?;
    }
    Some(out)
}

// ── The app ────────────────────────────────────────────────────────────────────

pub struct ActionNodeApp {
    opt: ActionNodeOptions,
    prefix: String,
    provider: Arc<dyn ActionNodeProvider>,
    task_store: Arc<dyn ActionTaskStore>,
    idempotency: Arc<dyn IdempotencyCache>,
    task_cancellations: Arc<Mutex<BTreeMap<String, ActionCancellation>>>,
    nwm_json: Vec<u8>,
    actions_json: Vec<u8>,
}

impl ActionNodeApp {
    /// Build an Action Node app. Panics if a reserved action id is registered
    /// (matches .NET `ActionNodeMiddleware` ctor guard).
    pub fn new(
        opt: ActionNodeOptions,
        provider: Arc<dyn ActionNodeProvider>,
        task_store: Arc<dyn ActionTaskStore>,
        idempotency: Arc<dyn IdempotencyCache>,
    ) -> Self {
        if opt.actions.contains_key(SYSTEM_TASK_STATUS)
            || opt.actions.contains_key(SYSTEM_TASK_CANCEL)
        {
            panic!(
                "Reserved action ids '{SYSTEM_TASK_STATUS}' / '{SYSTEM_TASK_CANCEL}' are provided by \
                 the server and MUST NOT be registered in ActionNodeOptions.actions."
            );
        }
        let prefix = opt.path_prefix.trim_end_matches('/').to_string();
        let nwm_json = serde_json::to_vec(&build_manifest(&opt, &prefix)).unwrap_or_default();
        let actions_json =
            serde_json::to_vec(&json!({ "actions": actions_map(&opt) })).unwrap_or_default();
        ActionNodeApp {
            opt,
            prefix,
            provider,
            task_store,
            idempotency,
            task_cancellations: Arc::new(Mutex::new(BTreeMap::new())),
            nwm_json,
            actions_json,
        }
    }

    /// Convenience constructor with in-memory task store + idempotency cache.
    pub fn with_in_memory(opt: ActionNodeOptions, provider: Arc<dyn ActionNodeProvider>) -> Self {
        Self::new(
            opt,
            provider,
            Arc::new(InMemoryActionTaskStore::new()),
            Arc::new(InMemoryIdempotencyCache::new()),
        )
    }

    pub fn task_store(&self) -> &Arc<dyn ActionTaskStore> {
        &self.task_store
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
                        NODE_TYPE_ACTION.into(),
                    ),
                ],
                body: self.nwm_json.clone(),
            },
            "/.schema" | "/.schema/" | "/actions" | "/actions/" => NodeResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/json".into())],
                body: self.actions_json.clone(),
            },
            "/invoke" | "/invoke/" => {
                if req.method != "POST" {
                    return empty(405);
                }
                self.handle_invoke(&req)
            }
            _ => empty(404),
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

        let agent_nid = req.header(http_headers::AGENT).map(String::from);

        // Reserved actions handled by the server itself.
        if frame.action_id == SYSTEM_TASK_STATUS {
            return self.handle_task_status(&frame, agent_nid.as_deref());
        }
        if frame.action_id == SYSTEM_TASK_CANCEL {
            return self.handle_task_cancel(&frame, agent_nid.as_deref());
        }

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

        // Priority validation.
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

        // Async-capable check.
        if frame.async_ && !spec.async_ {
            return error_resp(
                400,
                "NPS-CLIENT-BAD-REQUEST",
                error_codes::ACTION_PARAMS_INVALID,
                &format!(
                    "action '{}' does not support async execution.",
                    frame.action_id
                ),
                None,
                &[],
            );
        }

        let effective_timeout = clamp_timeout(frame.timeout_ms, &spec, &self.opt);

        // Callback URL SSRF guard.
        if let Some(cb) = &frame.callback_url {
            if let Some(err) = validate_callback_url(cb, self.opt.reject_private_callback_urls) {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    &err,
                    None,
                    &[],
                );
            }
        }

        let priority = frame.priority.clone().unwrap_or_else(|| "normal".into());
        let admission_context = ActionContext {
            agent_nid: agent_nid.clone(),
            request_id: frame.request_id.clone(),
            task_id: None,
            spec: spec.clone(),
            timeout_ms: effective_timeout,
            priority: priority.clone(),
            wire_input_bytes: req.body.len() as u64,
            cancellation: ActionCancellation::new(),
        };
        if let Err(error) = self.provider.authorize(&frame, &admission_context) {
            return error_resp(
                error.http_status,
                &error.nps_status,
                &error.error_code,
                &error.message,
                None,
                &[],
            );
        }

        // Idempotency check (sync + async). §7.1. Cache entries are caller-scoped
        // so a key chosen by one authenticated principal cannot replay to another.
        let params_hash = hash_params(&frame.params);
        let cache_scope = idempotency_cache_scope(&frame.action_id, agent_nid.as_deref());
        if let Some(key) = &frame.idempotency_key {
            if let Some(cached) = self.idempotency.get(&cache_scope, key) {
                if cached.params_hash != params_hash {
                    return error_resp(
                        409,
                        "NPS-CLIENT-CONFLICT",
                        error_codes::ACTION_IDEMPOTENCY_CONFLICT,
                        "idempotency_key reuse with different params.",
                        None,
                        &[],
                    );
                }
                if let Some(task_id) = &cached.task_id {
                    let status = self
                        .task_store
                        .get(task_id)
                        .map(|r| r.status)
                        .unwrap_or_else(|| "pending".into());
                    return self.write_async_response(task_id, &status, &frame.request_id, None);
                }
                if let Some(frames) = cached.stream_frames {
                    return self
                        .write_stream(
                            &ReplayActionStream(frames),
                            &admission_context.cancellation,
                            &frame.request_id,
                        )
                        .0;
                }
                return self.write_caps(
                    &cached.result,
                    cached.anchor_ref.as_deref(),
                    &frame.request_id,
                    0,
                );
            }
        }

        if frame.async_ {
            let task_id = gen_hex(16);
            self.task_store.create(
                &task_id,
                &frame.action_id,
                frame.request_id.as_deref(),
                agent_nid.as_deref(),
            );

            if let Some(key) = &frame.idempotency_key {
                self.idempotency.try_store(
                    &cache_scope,
                    key,
                    IdempotentEntry {
                        action_id: frame.action_id.clone(),
                        params_hash: params_hash.clone(),
                        result: None,
                        stream_frames: None,
                        anchor_ref: None,
                        task_id: Some(task_id.clone()),
                        expires_at: now_utc() + self.opt.idempotency_ttl,
                    },
                );
            }

            let ctx = ActionContext {
                task_id: Some(task_id.clone()),
                ..admission_context.clone()
            };
            self.task_cancellations
                .lock()
                .expect("task cancellations")
                .insert(task_id.clone(), ctx.cancellation.clone());
            self.spawn_async_task(task_id.clone(), frame.clone(), ctx, effective_timeout);

            return self.write_async_response(
                &task_id,
                "pending",
                &frame.request_id,
                spec.timeout_ms_default,
            );
        }

        // Synchronous path. Provider work runs off-thread so the deadline remains enforceable
        // even when a synchronous provider blocks or suppresses cooperative cancellation.
        let ctx = admission_context;
        let provider = self.provider.clone();
        let worker_frame = frame.clone();
        let worker_context = ctx.clone();
        let (send, receive) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let _ = send.send(provider.execute(&worker_frame, &worker_context));
        });
        let result = match receive.recv_timeout(Duration::from_millis(u64::from(effective_timeout)))
        {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => {
                return error_resp(
                    error.http_status,
                    &error.nps_status,
                    &error.error_code,
                    &error.message,
                    None,
                    &[],
                )
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                ctx.cancellation.cancel();
                return error_resp(
                    504,
                    "NPS-SERVER-TIMEOUT",
                    error_codes::NODE_UNAVAILABLE,
                    "action execution timed out.",
                    None,
                    &[],
                );
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                ctx.cancellation.cancel();
                return error_resp(
                    500,
                    "NPS-SERVER-INTERNAL",
                    error_codes::NODE_UNAVAILABLE,
                    "action execution worker disconnected.",
                    None,
                    &[],
                );
            }
        };

        if let Some(stream) = result.stream.as_ref() {
            let (response, completed) =
                self.write_stream(stream.as_ref(), &ctx.cancellation, &frame.request_id);
            if let (Some(key), Some(frames)) = (&frame.idempotency_key, completed) {
                let anchor = result
                    .anchor_ref
                    .clone()
                    .or_else(|| spec.result_anchor.clone());
                self.idempotency.try_store(
                    &cache_scope,
                    key,
                    IdempotentEntry {
                        action_id: frame.action_id.clone(),
                        params_hash,
                        result: None,
                        stream_frames: Some(frames),
                        anchor_ref: anchor,
                        task_id: None,
                        expires_at: now_utc() + self.opt.idempotency_ttl,
                    },
                );
            }
            return response;
        }

        if let Some(key) = &frame.idempotency_key {
            let anchor = result
                .anchor_ref
                .clone()
                .or_else(|| spec.result_anchor.clone());
            self.idempotency.try_store(
                &cache_scope,
                key,
                IdempotentEntry {
                    action_id: frame.action_id.clone(),
                    params_hash,
                    result: result.result.clone(),
                    stream_frames: None,
                    anchor_ref: anchor,
                    task_id: None,
                    expires_at: now_utc() + self.opt.idempotency_ttl,
                },
            );
        }

        let anchor = result
            .anchor_ref
            .clone()
            .or_else(|| spec.result_anchor.clone());
        self.write_caps(
            &result.result,
            anchor.as_deref(),
            &frame.request_id,
            result.token_est,
        )
    }

    fn spawn_async_task(
        &self,
        task_id: String,
        frame: ParsedActionFrame,
        context: ActionContext,
        timeout_ms: u32,
    ) {
        let provider = self.provider.clone();
        let task_store = self.task_store.clone();
        let cancellations = self.task_cancellations.clone();
        std::thread::spawn(move || {
            if !task_store.try_transition(&task_id, "pending", "running") {
                cancellations
                    .lock()
                    .expect("task cancellations")
                    .remove(&task_id);
                return;
            }
            let worker_provider = provider.clone();
            let worker_frame = frame.clone();
            let worker_context = context.clone();
            let (send, receive) = mpsc::sync_channel(1);
            std::thread::spawn(move || {
                let _ = send.send(worker_provider.execute(&worker_frame, &worker_context));
            });

            let deadline = Instant::now() + Duration::from_millis(u64::from(timeout_ms));
            loop {
                if context.cancellation.is_cancelled() {
                    break;
                }
                let now = Instant::now();
                if now >= deadline {
                    context.cancellation.cancel();
                    task_store.fail(
                        &task_id,
                        json!({ "code": error_codes::NODE_UNAVAILABLE, "message": "task timed out" }),
                    );
                    break;
                }
                let wait = (deadline - now).min(Duration::from_millis(10));
                match receive.recv_timeout(wait) {
                    Ok(Ok(result)) => {
                        if !context.cancellation.is_cancelled() {
                            task_store.complete(&task_id, result.result);
                        }
                        break;
                    }
                    Ok(Err(error)) => {
                        if !context.cancellation.is_cancelled() {
                            task_store.fail(
                                &task_id,
                                json!({ "code": error.error_code, "message": error.message }),
                            );
                        }
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        task_store.fail(
                            &task_id,
                            json!({ "code": error_codes::NODE_UNAVAILABLE, "message": "task worker disconnected" }),
                        );
                        break;
                    }
                }
            }
            cancellations
                .lock()
                .expect("task cancellations")
                .remove(&task_id);
        });
    }

    fn handle_task_status(
        &self,
        frame: &ParsedActionFrame,
        agent_nid: Option<&str>,
    ) -> NodeResponse {
        let task_id = match read_string_param(&frame.params, "task_id") {
            Some(t) if !t.is_empty() => t,
            _ => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    "params.task_id is required.",
                    None,
                    &[],
                )
            }
        };
        let rec = match self.task_store.get(&task_id) {
            Some(r) => r,
            None => {
                return error_resp(
                    404,
                    "NPS-CLIENT-NOT-FOUND",
                    error_codes::TASK_NOT_FOUND,
                    &format!("Unknown task_id '{task_id}'."),
                    None,
                    &[],
                )
            }
        };
        if rec.agent_nid.as_deref() != agent_nid {
            return error_resp(
                403,
                "NPS-AUTH-FORBIDDEN",
                error_codes::AUTH_NID_SCOPE_VIOLATION,
                "the caller does not own this task.",
                None,
                &[],
            );
        }
        let mut status = Map::new();
        status.insert("task_id".into(), Value::String(rec.task_id.clone()));
        status.insert("status".into(), Value::String(rec.status.clone()));
        if let Some(p) = rec.progress {
            status.insert("progress".into(), json!(p));
        }
        status.insert(
            "created_at".into(),
            Value::String(fmt_rfc3339(&rec.created_at)),
        );
        status.insert(
            "updated_at".into(),
            Value::String(fmt_rfc3339(&rec.updated_at)),
        );
        if let Some(rid) = &rec.request_id {
            status.insert("request_id".into(), Value::String(rid.clone()));
        }
        if let Some(r) = &rec.result {
            status.insert("result".into(), r.clone());
        }
        if let Some(e) = &rec.error {
            status.insert("error".into(), e.clone());
        }
        self.write_caps(&Some(Value::Object(status)), None, &frame.request_id, 0)
    }

    fn handle_task_cancel(
        &self,
        frame: &ParsedActionFrame,
        agent_nid: Option<&str>,
    ) -> NodeResponse {
        let task_id = match read_string_param(&frame.params, "task_id") {
            Some(t) if !t.is_empty() => t,
            _ => {
                return error_resp(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    error_codes::ACTION_PARAMS_INVALID,
                    "params.task_id is required.",
                    None,
                    &[],
                )
            }
        };
        let rec = match self.task_store.get(&task_id) {
            Some(r) => r,
            None => {
                return error_resp(
                    404,
                    "NPS-CLIENT-NOT-FOUND",
                    error_codes::TASK_NOT_FOUND,
                    &format!("Unknown task_id '{task_id}'."),
                    None,
                    &[],
                )
            }
        };
        if rec.agent_nid.as_deref() != agent_nid {
            return error_resp(
                403,
                "NPS-AUTH-FORBIDDEN",
                error_codes::AUTH_NID_SCOPE_VIOLATION,
                "the caller does not own this task.",
                None,
                &[],
            );
        }
        if is_terminal(&rec.status) {
            return error_resp(
                409,
                "NPS-CLIENT-CONFLICT",
                error_codes::TASK_ALREADY_CANCELLED,
                &format!(
                    "Task '{task_id}' is already in a terminal state ('{}').",
                    rec.status
                ),
                None,
                &[],
            );
        }
        self.task_store.cancel(&task_id);
        if let Some(cancellation) = self
            .task_cancellations
            .lock()
            .expect("task cancellations")
            .get(&task_id)
            .cloned()
        {
            cancellation.cancel();
        }
        let payload = json!({ "task_id": task_id, "status": "cancelled" });
        self.write_caps(&Some(payload), None, &frame.request_id, 0)
    }

    fn write_async_response(
        &self,
        task_id: &str,
        status: &str,
        request_id: &Option<String>,
        estimated_ms: Option<u32>,
    ) -> NodeResponse {
        let mut body = Map::new();
        body.insert("task_id".into(), Value::String(task_id.into()));
        body.insert("status".into(), Value::String(status.into()));
        body.insert(
            "poll_url".into(),
            Value::String(format!("{}/invoke", self.prefix)),
        );
        if let Some(ms) = estimated_ms {
            body.insert("estimated_ms".into(), json!(ms));
        }
        if let Some(rid) = request_id {
            body.insert("request_id".into(), Value::String(rid.clone()));
        }
        NodeResponse {
            status: 202,
            headers: vec![
                ("content-type".into(), "application/json".into()),
                (
                    http_headers::NODE_TYPE.to_ascii_lowercase(),
                    NODE_TYPE_ACTION.into(),
                ),
            ],
            body: serde_json::to_vec(&Value::Object(body)).unwrap_or_default(),
        }
    }

    fn write_caps(
        &self,
        payload: &Option<Value>,
        anchor_ref: Option<&str>,
        request_id: &Option<String>,
        token_est: u32,
    ) -> NodeResponse {
        let (count, data) = match payload {
            Some(v) => (1u32, vec![v.clone()]),
            None => (0u32, vec![]),
        };
        let mut caps = Map::new();
        caps.insert(
            "anchor_ref".into(),
            Value::String(anchor_ref.unwrap_or("").to_string()),
        );
        caps.insert("count".into(), json!(count));
        caps.insert("data".into(), Value::Array(data));
        if token_est > 0 {
            caps.insert("token_est".into(), json!(token_est));
        }

        let mut headers = vec![
            ("content-type".into(), http_headers::MIME_CAPSULE.into()),
            (
                http_headers::NODE_TYPE.to_ascii_lowercase(),
                NODE_TYPE_ACTION.into(),
            ),
        ];
        if let Some(a) = anchor_ref {
            headers.push((http_headers::SCHEMA.to_ascii_lowercase(), a.to_string()));
        }
        if token_est > 0 {
            headers.push((
                http_headers::TOKENS.to_ascii_lowercase(),
                token_est.to_string(),
            ));
        }
        if let Some(rid) = request_id {
            headers.push((http_headers::REQUEST_ID.to_ascii_lowercase(), rid.clone()));
        }
        NodeResponse {
            status: 200,
            headers,
            body: serde_json::to_vec(&Value::Object(caps)).unwrap_or_default(),
        }
    }

    fn write_stream(
        &self,
        stream: &dyn ActionStream,
        cancellation: &ActionCancellation,
        request_id: &Option<String>,
    ) -> (NodeResponse, Option<Vec<ActionStreamFrame>>) {
        let stream_id = gen_hex(16);
        let mut emitted = Vec::new();
        let mut body = Vec::new();
        let mut next_seq = 0u64;
        let mut terminal = false;
        let mut emit = |mut supplied: ActionStreamFrame| -> Result<(), ActionError> {
            if cancellation.is_cancelled() {
                return Err(ActionError::internal("action stream was cancelled"));
            }
            if terminal {
                return Err(ActionError::internal(
                    "action stream emitted frames after its terminal frame",
                ));
            }
            if supplied.seq != next_seq {
                return Err(ActionError::internal(
                    "action stream sequence is not contiguous from zero",
                ));
            }
            if supplied.error_code.is_some() && !supplied.is_last {
                return Err(ActionError::internal(
                    "action stream error_code is terminal-only",
                ));
            }
            supplied.stream_id = stream_id.clone();
            let encoded = serde_json::to_vec(&supplied).map_err(|error| {
                ActionError::internal(format!("serialize stream frame: {error}"))
            })?;
            body.extend_from_slice(&encoded);
            body.push(b'\n');
            next_seq += 1;
            terminal = supplied.is_last;
            emitted.push(supplied);
            Ok(())
        };

        let mut failure = stream.write(cancellation, &mut emit).err();
        drop(emit);
        if failure.is_none() && !terminal {
            failure = Some(ActionError::internal(
                "action stream ended without a terminal frame",
            ));
        }
        if let Some(error) = &failure {
            if !terminal && !cancellation.is_cancelled() {
                let terminal_frame = ActionStreamFrame {
                    stream_id: stream_id.clone(),
                    seq: next_seq,
                    is_last: true,
                    error_code: Some(error.error_code.clone()),
                    ..Default::default()
                };
                if let Ok(encoded) = serde_json::to_vec(&terminal_frame) {
                    body.extend_from_slice(&encoded);
                    body.push(b'\n');
                    emitted.push(terminal_frame);
                }
            }
        }

        let completed = if failure.is_none()
            && !emitted.is_empty()
            && emitted
                .last()
                .is_some_and(|frame| frame.error_code.is_none())
        {
            Some(emitted)
        } else {
            None
        };
        let mut headers = vec![
            ("content-type".into(), "application/x-ndjson".into()),
            (
                http_headers::NODE_TYPE.to_ascii_lowercase(),
                NODE_TYPE_ACTION.into(),
            ),
        ];
        if let Some(request_id) = request_id {
            headers.push((
                http_headers::REQUEST_ID.to_ascii_lowercase(),
                request_id.clone(),
            ));
        }
        (
            NodeResponse {
                status: 200,
                headers,
                body,
            },
            completed,
        )
    }
}

struct ReplayActionStream(Vec<ActionStreamFrame>);

impl ActionStream for ReplayActionStream {
    fn write(
        &self,
        _cancellation: &ActionCancellation,
        emit: &mut dyn FnMut(ActionStreamFrame) -> Result<(), ActionError>,
    ) -> Result<(), ActionError> {
        for frame in &self.0 {
            emit(frame.clone())?;
        }
        Ok(())
    }
}

// ── Free helpers ───────────────────────────────────────────────────────────────

fn clamp_timeout(requested: u32, spec: &ActionSpec, opt: &ActionNodeOptions) -> u32 {
    let spec_max = spec.timeout_ms_max.unwrap_or(opt.max_timeout_ms);
    let hard_max = spec_max.min(opt.max_timeout_ms);
    if requested == 0 {
        return spec.timeout_ms_default.unwrap_or(opt.default_timeout_ms);
    }
    requested.min(hard_max)
}

fn hash_params(params: &Option<Value>) -> String {
    // Canonicalise like .NET (System.Text.Json serialize of the element, or "null").
    let json = match params {
        None => "null".to_string(),
        Some(v) => serde_json::to_string(v).unwrap_or_else(|_| "null".into()),
    };
    fnv1a_hex(json.as_bytes())
}

fn idempotency_cache_scope(action_id: &str, agent_nid: Option<&str>) -> String {
    format!("{action_id}\u{1f}{}", agent_nid.unwrap_or(""))
}

/// Deterministic content hash for params comparison. The exact algorithm is a
/// local detail (never crosses the wire); only equality vs a prior request matters.
fn fnv1a_hex(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016X}")
}

fn read_string_param(params: &Option<Value>, name: &str) -> Option<String> {
    params
        .as_ref()
        .and_then(|v| v.as_object())
        .and_then(|o| o.get(name))
        .and_then(Value::as_str)
        .map(String::from)
}

fn actions_map(opt: &ActionNodeOptions) -> BTreeMap<String, Value> {
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
        if let Some(i) = spec.idempotent {
            entry.insert("idempotent".into(), Value::Bool(i));
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

fn build_manifest(opt: &ActionNodeOptions, prefix: &str) -> Value {
    let mut m = Map::new();
    m.insert("nwp".into(), Value::String("0.4".into()));
    m.insert("node_id".into(), Value::String(opt.node_id.clone()));
    m.insert("node_type".into(), Value::String(NODE_TYPE_ACTION.into()));
    if let Some(dn) = &opt.display_name {
        m.insert("display_name".into(), Value::String(dn.clone()));
    }
    m.insert("wire_formats".into(), json!(["ncp-capsule", "json"]));
    m.insert("preferred_format".into(), Value::String("json".into()));
    let supports_stream = opt
        .profiles
        .get("llm")
        .and_then(Value::as_object)
        .and_then(|profile| profile.get("supports_stream"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    m.insert(
        "capabilities".into(),
        json!({ "query": false, "stream": supports_stream, "token_budget_hint": true }),
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
        json!({ "invoke": format!("{prefix}/invoke"), "schema": format!("{prefix}/.schema") }),
    );
    m.insert("actions".into(), json!(actions_map(opt)));
    if !opt.profiles.is_empty() {
        m.insert("profiles".into(), json!(opt.profiles));
    }
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

fn now_utc() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn fmt_rfc3339(t: &OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}
