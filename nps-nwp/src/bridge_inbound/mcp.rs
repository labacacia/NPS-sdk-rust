// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound MCP Bridge server (JSON-RPC 2.0) — NWP §16.1.2, NPS-CR-0010.

use std::io::{BufRead, Write};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::error_codes;

use super::backend::{NwpBackend, NwpNodeDescriptor, NwpResult};
use super::error_map::{self, JSONRPC_INVALID_PARAMS, JSONRPC_METHOD_NOT_FOUND};
use super::jsonrpc::{BridgeJsonRpcRequest, BridgeJsonRpcResponse};
use super::options::BridgeInboundOptions;
use super::tool_name;

/// The normative required method set (NWP §16.1.2 MUST-3), exported as data.
///
/// An inbound MCP Bridge that omits `resources/*` is **not conformant**.
/// Serving `resources/*` over an *empty set* IS conformant — the requirement is
/// on the methods, not on a Memory Node existing behind them.
pub const REQUIRED_METHODS: &[&str] = &[
    "initialize",
    "ping",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/read",
];

pub struct McpInboundServer {
    options: BridgeInboundOptions,
}

/// A resolved tool: which backend serves it and under what action id.
struct ResolvedTool {
    backend: Arc<dyn NwpBackend>,
    action_id: String,
}

impl McpInboundServer {
    pub fn new(options: BridgeInboundOptions) -> Self {
        McpInboundServer { options }
    }

    pub fn options(&self) -> &BridgeInboundOptions {
        &self.options
    }

    pub async fn dispatch(&self, req: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        let id = req.id.clone();

        // Direction gate FIRST (NWP §16.1.2 MUST-5).
        if !self.options.serves_inbound("mcp") {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                "This Bridge Node does not declare \"mcp\" in bridge_inbound_protocols.",
                Some(json!({
                    "error": error_codes::BRIDGE_DIRECTION_UNSUPPORTED,
                    "hint":  self.options.direction_hint(),
                })),
            );
        }

        match req.method.as_str() {
            "initialize" => BridgeJsonRpcResponse::ok(
                id,
                json!({
                    "serverInfo": {
                        "name":    self.options.server_name,
                        "version": self.options.server_version,
                    },
                    // BOTH capabilities are always advertised, even with no
                    // Memory Node behind the Bridge.
                    "capabilities": { "tools": {}, "resources": {} },
                }),
            ),
            "ping" => BridgeJsonRpcResponse::ok(id, json!({})),
            "tools/list" => {
                BridgeJsonRpcResponse::ok(id, json!({ "tools": self.list_tools().await }))
            }
            "tools/call" => self.tools_call(id, req.params.as_ref()).await,
            "resources/list" => {
                BridgeJsonRpcResponse::ok(id, json!({ "resources": self.list_resources().await }))
            }
            "resources/read" => self.resources_read(id, req.params.as_ref()).await,
            other => BridgeJsonRpcResponse::err(
                id,
                JSONRPC_METHOD_NOT_FOUND,
                format!("MCP method '{other}' is not supported by this Bridge Node."),
                Some(json!({ "error": error_codes::BRIDGE_DIRECTION_UNSUPPORTED })),
            ),
        }
    }

    // ── tools ────────────────────────────────────────────────────────────────

    async fn list_tools(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for b in &self.options.backends {
            let d = b.descriptor().await;
            if !d.is_invokable() {
                continue;
            }
            for a in b.actions().await {
                out.push(json!({
                    // Always QUALIFIED on output: MCP tool names are a flat
                    // namespace and a Bridge may front several nodes.
                    "name":        tool_name::encode(&d.name, &a.action_id),
                    "description": a.description,
                    "inputSchema": a.effective_input_schema(),
                }));
            }
        }
        out
    }

    /// Resolve a tool name — *canonical on output, forgiving on input*.
    ///
    /// 1. A qualified match (`node__action`, ignore-case) wins immediately.
    /// 2. Otherwise a bare `action_id` or encoded action segment is collected as
    ///    an unqualified candidate.
    /// 3. After the full scan the single candidate is returned iff exactly one
    ///    exists. Two nodes exposing the same action id must be disambiguated by
    ///    the caller, not guessed at here.
    ///
    /// Returns `Err(candidates)` when ambiguous, listing every qualified name so
    /// the rejection is deterministic and actionable.
    async fn resolve_tool(&self, tool: &str) -> Result<Option<ResolvedTool>, Vec<String>> {
        let mut unqualified: Vec<(Arc<dyn NwpBackend>, String, String)> = Vec::new();
        for b in &self.options.backends {
            let d = b.descriptor().await;
            if !d.is_invokable() {
                continue;
            }
            for a in b.actions().await {
                let qualified = tool_name::encode(&d.name, &a.action_id);
                if qualified.eq_ignore_ascii_case(tool) {
                    return Ok(Some(ResolvedTool {
                        backend: b.clone(),
                        action_id: a.action_id,
                    }));
                }
                if a.action_id.eq_ignore_ascii_case(tool)
                    || tool_name::encode_action_segment(&a.action_id).eq_ignore_ascii_case(tool)
                {
                    unqualified.push((b.clone(), a.action_id.clone(), qualified));
                }
            }
        }
        match unqualified.len() {
            0 => Ok(None),
            1 => {
                let (backend, action_id, _) = unqualified.into_iter().next().unwrap();
                Ok(Some(ResolvedTool { backend, action_id }))
            }
            _ => Err(unqualified.into_iter().map(|(_, _, q)| q).collect()),
        }
    }

    async fn tools_call(&self, id: Value, params: Option<&Value>) -> BridgeJsonRpcResponse {
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if name.is_empty() {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                "MCP tools/call requires params.name.",
                None,
            );
        }
        let arguments = params.and_then(|p| p.get("arguments")).cloned();

        let resolved = match self.resolve_tool(&name).await {
            Ok(Some(r)) => r,
            Ok(None) => {
                // Unknown tool ⇒ -32601 Method not found. -32002 is RETIRED and
                // MUST NOT be emitted.
                return BridgeJsonRpcResponse::err(
                    id,
                    JSONRPC_METHOD_NOT_FOUND,
                    format!("MCP tool '{name}' is not exposed by this Bridge Node."),
                    Some(json!({
                        "error": error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND,
                        "tool":  name,
                    })),
                );
            }
            Err(candidates) => {
                return BridgeJsonRpcResponse::err(
                    id,
                    JSONRPC_METHOD_NOT_FOUND,
                    format!(
                        "MCP tool '{name}' is ambiguous across this Bridge Node's fronted nodes; \
                         use one of the qualified names: {}.",
                        candidates.join(", ")
                    ),
                    Some(json!({
                        "error":      error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND,
                        "tool":       name,
                        // TC-N2-BridgeIn-04 wants the rejection to name BOTH
                        // qualified candidates; the .NET impl names only the
                        // requested tool.
                        "candidates": candidates,
                    })),
                );
            }
        };

        let result = resolved
            .backend
            .invoke(&resolved.action_id, arguments, false)
            .await;
        Self::project_tool_result(id, result)
    }

    /// The §16.3 split. Infrastructure failures become JSON-RPC errors;
    /// tool-domain failures stay `isError: true` content.
    fn project_tool_result(id: Value, result: NwpResult) -> BridgeJsonRpcResponse {
        if result.ok {
            let text = result
                .payload
                .as_ref()
                .map(|p| serde_json::to_string(p).unwrap_or_default())
                .unwrap_or_default();
            return BridgeJsonRpcResponse::ok(
                id,
                json!({
                    "isError": false,
                    "content": [ { "type": "text", "text": text } ],
                }),
            );
        }
        let status = result.nps_status.clone().unwrap_or_default();
        if error_map::must_be_protocol_error(&status) {
            return BridgeJsonRpcResponse::err(
                id,
                error_map::to_json_rpc(&status, false),
                result.detail(),
                Some(json!({ "status": status, "error": result.nwp_error })),
            );
        }
        BridgeJsonRpcResponse::ok(
            id,
            json!({
                "isError": true,
                "content": [ {
                    "type": "text",
                    "text": serde_json::to_string(&result.failure_payload()).unwrap_or_default(),
                } ],
            }),
        )
    }

    // ── resources ────────────────────────────────────────────────────────────

    async fn list_resources(&self) -> Vec<Value> {
        let mut out = Vec::new();
        for b in &self.options.backends {
            let d = b.descriptor().await;
            if !d.is_queryable() {
                continue;
            }
            out.push(json!({
                "uri":         format!("nwp://{}/", d.name),
                "name":        d.display_name.clone().unwrap_or_else(|| d.name.clone()),
                "description": d.description.clone().unwrap_or_else(|| format!(
                    "NWP {} Node '{}' — read to query.", d.role.wire(), d.name)),
                "mimeType":    "application/json",
            }));
        }
        out
    }

    /// Host portion of `nwp://<node>/`, or `None` when the URI is not an
    /// absolute `nwp` URI.
    fn parse_resource_host(uri: &str) -> Option<&str> {
        let rest = uri.strip_prefix("nwp://")?;
        let host = rest.split('/').next().unwrap_or("");
        if host.is_empty() {
            None
        } else {
            Some(host)
        }
    }

    async fn find_queryable(&self, host: &str) -> Option<(Arc<dyn NwpBackend>, NwpNodeDescriptor)> {
        for b in &self.options.backends {
            let d = b.descriptor().await;
            if d.is_queryable() && d.name.eq_ignore_ascii_case(host) {
                return Some((b.clone(), d));
            }
        }
        None
    }

    async fn resources_read(&self, id: Value, params: Option<&Value>) -> BridgeJsonRpcResponse {
        let uri = params
            .and_then(|p| p.get("uri"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_string();
        if uri.is_empty() {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                "MCP resources/read requires params.uri.",
                None,
            );
        }
        let Some(host) = Self::parse_resource_host(&uri) else {
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                format!("Resource URI '{uri}' must be of the form nwp://<node>/."),
                None,
            );
        };
        let Some((backend, _)) = self.find_queryable(host).await else {
            // Unknown host is -32602 (Invalid params), NOT -32601 — this is the
            // param-sensitive row of the §16.3 table.
            return BridgeJsonRpcResponse::err(
                id,
                JSONRPC_INVALID_PARAMS,
                format!("Resource URI '{uri}' does not name a queryable node fronted by this Bridge Node."),
                Some(json!({
                    "error": error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND,
                    "uri":   uri,
                })),
            );
        };

        let result = backend
            .query(json!({ "limit": self.options.resource_read_limit }))
            .await;
        if result.ok {
            let text = result
                .payload
                .as_ref()
                .map(|p| serde_json::to_string(p).unwrap_or_default())
                .unwrap_or_default();
            return BridgeJsonRpcResponse::ok(
                id,
                json!({
                    "contents": [ {
                        "uri":      uri,
                        "mimeType": "application/json",
                        "text":     text,
                    } ],
                }),
            );
        }
        let status = result.nps_status.clone().unwrap_or_default();
        BridgeJsonRpcResponse::err(
            id,
            error_map::to_json_rpc(&status, true),
            result.detail(),
            Some(json!({ "status": status, "error": result.nwp_error, "uri": uri })),
        )
    }

    // ── stdio transport ──────────────────────────────────────────────────────

    /// Line-delimited JSON-RPC in, one line of JSON-RPC out per request.
    ///
    /// stdio is part of the inbound profile, not an extra. Blank lines are
    /// skipped; end of input ends the loop; a request that fails to deserialize
    /// yields `-32700` with `id: null`; each response is flushed.
    pub async fn run_stdio<R: BufRead, W: Write>(
        &self,
        input: R,
        output: &mut W,
    ) -> std::io::Result<()> {
        for line in input.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let resp = match serde_json::from_str::<BridgeJsonRpcRequest>(&line) {
                Ok(req) => self.dispatch(&req).await,
                Err(e) => BridgeJsonRpcResponse::err(
                    Value::Null,
                    error_map::JSONRPC_PARSE_ERROR,
                    e.to_string(),
                    None,
                ),
            };
            writeln!(
                output,
                "{}",
                serde_json::to_string(&resp).unwrap_or_default()
            )?;
            output.flush()?;
        }
        Ok(())
    }
}
