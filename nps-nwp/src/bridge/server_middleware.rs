// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Framework-agnostic middleware exposing inbound MCP/A2A Bridge server adapters.
//!
//! The [`BridgeServerMiddleware::handle`] entry point mirrors the shape used by
//! [`crate::anchor_server`]: a decoded [`NodeRequest`] in, a [`NodeResponse`] out,
//! so hosts can adapt it to hyper/axum/tiny_http.

use serde::Serialize;

use super::jsonrpc::{
    bridge_jsonrpc_error_codes as codes, BridgeJsonRpcRequest, BridgeJsonRpcResponse,
};
use super::server_a2a::A2aServerBridge;
use super::server_mcp::McpServerBridge;
use super::server_options::BridgeServerOptions;
use crate::http_headers;
use crate::node_http::{NodeRequest, NodeResponse};

/// Result of handling a Bridge server request: the raw HTTP response plus the
/// decoded JSON-RPC response (when one was produced) for direct testing.
#[derive(Debug, Clone)]
pub struct BridgeServerResult {
    pub response: NodeResponse,
}

/// Framework-agnostic middleware exposing inbound MCP/A2A Bridge server adapters.
#[derive(Clone)]
pub struct BridgeServerMiddleware {
    mcp: McpServerBridge,
    a2a: A2aServerBridge,
    options: BridgeServerOptions,
}

impl BridgeServerMiddleware {
    /// Create Bridge server middleware over shared options.
    pub fn new(options: BridgeServerOptions) -> Self {
        Self {
            mcp: McpServerBridge::new(options.clone()),
            a2a: A2aServerBridge::new(options.clone()),
            options,
        }
    }

    /// Access the underlying MCP server bridge.
    pub fn mcp(&self) -> &McpServerBridge {
        &self.mcp
    }

    /// Access the underlying A2A server bridge.
    pub fn a2a(&self) -> &A2aServerBridge {
        &self.a2a
    }

    /// Handle one inbound request. Returns `None` when the request path does not
    /// belong to this middleware (host should fall through to the next handler).
    pub async fn handle(&self, req: &NodeRequest) -> Option<NodeResponse> {
        let path = req.path.as_str();
        let prefix = self.options.path_prefix.trim_end_matches('/');

        if !path.to_ascii_lowercase().starts_with(&prefix.to_ascii_lowercase()) {
            return None;
        }

        let sub = &path[prefix.len()..];

        let mcp_sse = append(&self.options.mcp_path, "/sse");
        if matches(sub, &self.options.mcp_path) || matches(sub, &mcp_sse) {
            let use_sse = is_sse_request(req) || matches(sub, &mcp_sse);
            return Some(self.handle_mcp(req, use_sse).await);
        }

        if matches(sub, &self.options.a2a_path) {
            return Some(self.handle_a2a(req).await);
        }

        if matches(sub, &self.options.a2a_agent_card_path) {
            return Some(self.handle_agent_card(req));
        }

        None
    }

    async fn handle_mcp(&self, req: &NodeRequest, use_sse: bool) -> NodeResponse {
        if req.method.eq_ignore_ascii_case("GET") && use_sse {
            let endpoint = join(&self.options.path_prefix, &self.options.mcp_path);
            return NodeResponse {
                status: 200,
                headers: vec![(
                    "content-type".to_string(),
                    "text/event-stream".to_string(),
                )],
                body: format!("event: endpoint\ndata: {endpoint}\n\n").into_bytes(),
            };
        }

        if !req.method.eq_ignore_ascii_case("POST") {
            return empty(405);
        }

        if let Some(deny) = self.authorize(req) {
            return write_jsonrpc_error(401, codes::INVALID_REQUEST, &deny);
        }

        let (status, response) = self.read_and_dispatch(req, Dispatch::Mcp).await;
        if use_sse {
            write_sse(status, &response)
        } else {
            write_json(status, &response)
        }
    }

    async fn handle_a2a(&self, req: &NodeRequest) -> NodeResponse {
        if !req.method.eq_ignore_ascii_case("POST") {
            return empty(405);
        }

        if let Some(deny) = self.authorize(req) {
            return write_jsonrpc_error(401, codes::INVALID_REQUEST, &deny);
        }

        let (status, response) = self.read_and_dispatch(req, Dispatch::A2a).await;
        write_json(status, &response)
    }

    fn handle_agent_card(&self, req: &NodeRequest) -> NodeResponse {
        if !req.method.eq_ignore_ascii_case("GET") {
            return empty(405);
        }
        // Host adapter cannot reconstruct scheme/host reliably; expose the
        // configured relative A2A endpoint. Hosts may override before sending.
        let endpoint = join(&self.options.path_prefix, &self.options.a2a_path);
        let card = self.a2a.build_agent_card(&endpoint);
        write_json(200, &card)
    }

    async fn read_and_dispatch(
        &self,
        req: &NodeRequest,
        which: Dispatch,
    ) -> (u16, BridgeJsonRpcResponse) {
        let max = self.options.max_request_body_bytes;
        if max > 0 && req.body.len() as u64 > max {
            return (
                413,
                BridgeJsonRpcResponse::error_with_id(
                    None,
                    codes::INVALID_REQUEST,
                    format!("Bridge server request body exceeds the configured {max} byte limit."),
                    None,
                ),
            );
        }

        let request: BridgeJsonRpcRequest = match serde_json::from_slice(&req.body) {
            Ok(r) => r,
            Err(e) => {
                return (
                    400,
                    BridgeJsonRpcResponse::error_with_id(
                        None,
                        codes::PARSE_ERROR,
                        e.to_string(),
                        None,
                    ),
                );
            }
        };

        let response = match which {
            Dispatch::Mcp => self.mcp.dispatch(&request).await,
            Dispatch::A2a => self.a2a.dispatch(&request).await,
        };
        (200, response)
    }

    /// Returns `Some(message)` when the caller is denied, `None` when allowed.
    fn authorize(&self, req: &NodeRequest) -> Option<String> {
        if !self.options.require_auth {
            return None;
        }

        let agent = req.header(http_headers::AGENT).map(str::trim).unwrap_or("");
        if agent.is_empty() || !is_valid_agent_nid(agent) {
            return Some("A valid X-NWP-Agent NID is required.".to_string());
        }
        None
    }
}

enum Dispatch {
    Mcp,
    A2a,
}

fn is_valid_agent_nid(nid: &str) -> bool {
    const PREFIX: &str = "urn:nps:agent:";
    if !nid.starts_with(PREFIX) || nid.len() > 512 {
        return false;
    }
    let rest = &nid[PREFIX.len()..];
    let Some(sep) = rest.find(':') else {
        return false;
    };
    if sep == 0 || sep == rest.len() - 1 {
        return false;
    }
    let domain = &rest[..sep];
    let identifier = &rest[sep + 1..];
    domain.chars().all(is_domain_char) && identifier.chars().all(is_identifier_char)
}

fn is_domain_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || ch == '.' || ch == '-'
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '~' | ':' | '@' | '/')
}

fn write_json<T: Serialize>(status: u16, body: &T) -> NodeResponse {
    NodeResponse {
        status,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

fn write_jsonrpc_error(status: u16, code: i32, message: &str) -> NodeResponse {
    write_json(
        status,
        &BridgeJsonRpcResponse::error_with_id(None, code, message, None),
    )
}

fn write_sse(status: u16, response: &BridgeJsonRpcResponse) -> NodeResponse {
    let payload = serde_json::to_string(response).unwrap_or_default();
    NodeResponse {
        status,
        headers: vec![(
            "content-type".to_string(),
            "text/event-stream".to_string(),
        )],
        body: format!("event: message\ndata: {payload}\n\n").into_bytes(),
    }
}

fn empty(status: u16) -> NodeResponse {
    NodeResponse {
        status,
        headers: vec![],
        body: vec![],
    }
}

fn matches(actual: &str, expected: &str) -> bool {
    let normalized = if expected.starts_with('/') {
        expected.to_string()
    } else {
        format!("/{expected}")
    };
    actual.eq_ignore_ascii_case(&normalized)
        || actual.eq_ignore_ascii_case(&format!("{normalized}/"))
}

fn append(path: &str, suffix: &str) -> String {
    format!("{}{}", path.trim_end_matches('/'), suffix)
}

fn join(prefix: &str, path: &str) -> String {
    let left = prefix.trim_end_matches('/');
    let right = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    if left.is_empty() {
        right
    } else {
        format!("{left}{right}")
    }
}

fn is_sse_request(req: &NodeRequest) -> bool {
    req.header("accept")
        .map(|v| v.to_ascii_lowercase().contains("text/event-stream"))
        .unwrap_or(false)
}

impl BridgeServerResult {
    /// The wrapped HTTP response.
    pub fn into_response(self) -> NodeResponse {
        self.response
    }
}
