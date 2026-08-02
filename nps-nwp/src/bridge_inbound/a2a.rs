// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound A2A Bridge server (JSON-RPC 2.0) — NWP §16.1.2, NPS-CR-0010.
//!
//! Serves the AgentCard at `/.well-known/agent.json` and exactly one JSON-RPC
//! method, `tasks/send`.

use std::sync::Arc;

use serde_json::{json, Map, Value};

use crate::error_codes;

use super::backend::{NwpBackend, NwpResult};
use super::error_map::{self, JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND};
use super::jsonrpc::{BridgeJsonRpcRequest, BridgeJsonRpcResponse};
use super::options::BridgeInboundOptions;
use super::tool_name;

pub const PROVIDER_ORGANIZATION: &str = "LabAcacia / INNO LOTUS PTY LTD";
pub const PROVIDER_URL: &str = "https://github.com/labacacia/nps";

/// Metadata keys consulted, in order, when resolving which skill a task names.
const SKILL_KEYS: &[&str] = &["action_id", "actionId", "skill_id", "skillId", "skill"];

pub struct A2aInboundServer {
    options: BridgeInboundOptions,
}

struct ResolvedSkill {
    backend: Arc<dyn NwpBackend>,
    action_id: String,
}

impl A2aInboundServer {
    pub fn new(options: BridgeInboundOptions) -> Self {
        A2aInboundServer { options }
    }

    pub fn options(&self) -> &BridgeInboundOptions {
        &self.options
    }

    // ── AgentCard ────────────────────────────────────────────────────────────

    /// Served at `/.well-known/agent.json`.
    pub async fn build_agent_card(&self, endpoint_url: &str) -> Value {
        let mut skills = Vec::new();
        for b in &self.options.backends {
            let d = b.descriptor().await;
            if !d.is_invokable() {
                continue;
            }
            for a in b.actions().await {
                skills.push(json!({
                    // Qualified, like tools/list.
                    "id":          tool_name::encode(&d.name, &a.action_id),
                    "name":        a.description.clone().unwrap_or_else(|| a.action_id.clone()),
                    "description": a.description,
                    "tags":        a.tags,
                    "inputModes":  ["text", "data"],
                    "outputModes": ["data"],
                }));
            }
        }
        json!({
            "name":        self.options.server_name,
            "description": format!("NPS Bridge Node '{}' — inbound A2A surface.", self.options.server_name),
            "url":         endpoint_url,
            "provider":    { "organization": PROVIDER_ORGANIZATION, "url": PROVIDER_URL },
            "version":     self.options.server_version,
            "capabilities": {
                "streaming":             false,
                "pushNotifications":     false,
                "stateTransitionHistory": false,
            },
            // Part of the protocol surface, not merely host config.
            "authentication": if self.options.require_auth {
                json!({ "schemes": ["apikey"], "credentials": "X-NWP-Agent" })
            } else {
                Value::Null
            },
            "skills": skills,
        })
    }

    // ── dispatch ─────────────────────────────────────────────────────────────

    pub async fn dispatch(&self, req: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        let id = req.id.clone();

        if !self.options.serves_inbound("a2a") {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                "This Bridge Node does not declare \"a2a\" in bridge_inbound_protocols.",
                Some(json!({
                    "error": error_codes::BRIDGE_DIRECTION_UNSUPPORTED,
                    "hint":  self.options.direction_hint(),
                })),
            );
        }

        // Only one method is served.
        if req.method != "tasks/send" {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                format!(
                    "A2A method '{}' is not supported by this Bridge Node.",
                    req.method
                ),
                Some(json!({ "error": error_codes::BRIDGE_DIRECTION_UNSUPPORTED })),
            );
        }

        let Some(params) = req.params.as_ref().and_then(Value::as_object) else {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                "A2A tasks/send requires a params object.",
                None,
            );
        };
        let task_id = params
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if task_id.is_empty() {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                "A2A tasks/send params.id is required.",
                None,
            );
        }
        let session_id = params.get("sessionId").cloned().unwrap_or(Value::Null);
        let message = params.get("message").cloned().unwrap_or(Value::Null);

        let resolved = match self.resolve_skill(params).await {
            Some(r) => r,
            None => {
                return BridgeJsonRpcResponse::err(
                    id,
                    JSONRPC_INVALID_PARAMS,
                    "A2A task metadata must identify an exposed NPS action when more than one is available.",
                    Some(json!({ "error": error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND })),
                );
            }
        };

        let arguments = Self::extract_arguments(params);
        let result = resolved
            .backend
            .invoke(&resolved.action_id, arguments, false)
            .await;

        // §16.3: infrastructure-class failures become JSON-RPC errors instead of
        // tasks. Reporting one as a task — even a failed one — hands the peer a
        // task object where it should have received a transport error, and A2A
        // peers retry failed tasks.
        if !result.ok {
            let status = result.nps_status.clone().unwrap_or_default();
            if error_map::must_be_protocol_error(&status) {
                return BridgeJsonRpcResponse::err(
                    id,
                    error_map::to_json_rpc(&status, false),
                    result.detail(),
                    Some(json!({ "status": status, "error": result.nwp_error })),
                );
            }
        }

        BridgeJsonRpcResponse::ok(
            id,
            Self::to_task(&task_id, &session_id, &message, &result),
        )
    }

    // ── skill resolution ─────────────────────────────────────────────────────

    /// Look for a skill identifier in `task.metadata`, then
    /// `task.message.metadata`, then per-part `part.metadata` and `part.data`.
    fn find_skill_hint(params: &Map<String, Value>) -> Option<String> {
        let mut sources: Vec<&Value> = Vec::new();
        if let Some(m) = params.get("metadata") {
            sources.push(m);
        }
        if let Some(msg) = params.get("message") {
            if let Some(m) = msg.get("metadata") {
                sources.push(m);
            }
            if let Some(parts) = msg.get("parts").and_then(Value::as_array) {
                for p in parts {
                    if let Some(m) = p.get("metadata") {
                        sources.push(m);
                    }
                    if let Some(d) = p.get("data") {
                        sources.push(d);
                    }
                }
            }
        }
        for src in sources {
            for k in SKILL_KEYS {
                if let Some(s) = src.get(*k).and_then(Value::as_str) {
                    if !s.trim().is_empty() {
                        return Some(s.trim().to_string());
                    }
                }
            }
        }
        None
    }

    async fn resolve_skill(&self, params: &Map<String, Value>) -> Option<ResolvedSkill> {
        let hint = Self::find_skill_hint(params);
        let mut all: Vec<ResolvedSkill> = Vec::new();

        for b in &self.options.backends {
            let d = b.descriptor().await;
            if !d.is_invokable() {
                continue;
            }
            for a in b.actions().await {
                if let Some(h) = &hint {
                    // Match the qualified name OR the raw action_id.
                    if tool_name::encode(&d.name, &a.action_id).eq_ignore_ascii_case(h)
                        || a.action_id.eq_ignore_ascii_case(h)
                    {
                        return Some(ResolvedSkill {
                            backend: b.clone(),
                            action_id: a.action_id,
                        });
                    }
                } else {
                    all.push(ResolvedSkill {
                        backend: b.clone(),
                        action_id: a.action_id,
                    });
                }
            }
        }
        // With no skill named, accept only if exactly one exists in total.
        if hint.is_none() && all.len() == 1 {
            return all.into_iter().next();
        }
        None
    }

    // ── argument extraction ──────────────────────────────────────────────────

    fn params_or_arguments(v: &Value) -> Option<Value> {
        v.get("params")
            .or_else(|| v.get("arguments"))
            .filter(|x| !x.is_null())
            .cloned()
    }

    /// In order: `task.metadata.params|arguments` →
    /// `task.message.metadata.params|arguments` → per part `part.data.params|arguments`
    /// → a `type:"data"` part's whole `data` → a `type:"text"` part becomes
    /// `{ text: <the text> }` → else `None`.
    fn extract_arguments(params: &Map<String, Value>) -> Option<Value> {
        if let Some(m) = params.get("metadata") {
            if let Some(v) = Self::params_or_arguments(m) {
                return Some(v);
            }
        }
        let msg = params.get("message")?;
        if let Some(m) = msg.get("metadata") {
            if let Some(v) = Self::params_or_arguments(m) {
                return Some(v);
            }
        }
        let parts = msg.get("parts").and_then(Value::as_array)?;
        for p in parts {
            if let Some(d) = p.get("data") {
                if let Some(v) = Self::params_or_arguments(d) {
                    return Some(v);
                }
            }
        }
        for p in parts {
            if p.get("type").and_then(Value::as_str) == Some("data") {
                if let Some(d) = p.get("data") {
                    if !d.is_null() {
                        return Some(d.clone());
                    }
                }
            }
        }
        for p in parts {
            if p.get("type").and_then(Value::as_str) == Some("text") {
                if let Some(t) = p.get("text").and_then(Value::as_str) {
                    return Some(json!({ "text": t }));
                }
            }
        }
        None
    }

    // ── task projection ──────────────────────────────────────────────────────

    fn now_iso() -> String {
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_default()
    }

    fn to_task(task_id: &str, session_id: &Value, message: &Value, result: &NwpResult) -> Value {
        let ok = result.ok;
        let payload = if ok {
            result.payload.clone().unwrap_or(Value::Null)
        } else {
            result.failure_payload()
        };
        json!({
            "id":        task_id,
            "sessionId": session_id,
            "status": {
                "state":     if ok { "completed" } else { "failed" },
                "timestamp": Self::now_iso(),
                "message":   if ok {
                    Value::Null
                } else {
                    json!({
                        "role":  "agent",
                        "parts": [ { "type": "text", "text": result.detail() } ],
                    })
                },
            },
            "artifacts": [ {
                "name":  if ok { "nps-result" } else { "nps-error" },
                "parts": [ { "type": "data", "data": payload } ],
                "index": 0,
            } ],
            "history": [ message ],
        })
    }
}
