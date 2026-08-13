// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Hosting layer for the inbound Bridge — framework-agnostic, adopting the
//! [`AnchorRequest`] / [`AnchorResponse`] + `async fn handle()` shape of
//! [`crate::anchor_server`] so there is no HTTP framework dependency.
//!
//! Carries the NPS-CR-0010 §7 security defaults: fail-closed auth, a bounded
//! body, a dispatch timeout, method gating, and sanitized errors.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::anchor_server::{AnchorRequest, AnchorResponse};
use crate::http_headers;

use super::a2a::A2aInboundServer;
use super::error_map::{
    JSONRPC_INTERNAL_ERROR, JSONRPC_INVALID_PARAMS, JSONRPC_INVALID_REQUEST, JSONRPC_UPSTREAM_ERROR,
};
use super::jsonrpc::{BridgeJsonRpcRequest, BridgeJsonRpcResponse};
use super::mcp::McpInboundServer;
use super::options::BridgeInboundOptions;

/// `(agent_nid, request) -> bool`. Takes the full request on purpose, so a
/// deployment can bind the NID to a NIP client certificate off the connection.
pub type BridgeVerifier = Arc<dyn Fn(&str, &AnchorRequest) -> bool + Send + Sync>;

pub struct BridgeServerOptions {
    pub path_prefix: String,
    pub mcp_path: String,
    pub a2a_path: String,
    pub a2a_agent_card_path: String,
    /// `true` by default — fail closed.
    pub require_auth: bool,
    /// **If auth is required and no verifier is configured, every request is
    /// denied.**
    pub verifier: Option<BridgeVerifier>,
    /// 1 MiB by default; `0` disables.
    pub max_request_body_bytes: usize,
    /// 30 s by default; `0` disables.
    ///
    /// NOTE: an [`InProcessNwpBackend`][super::backend::InProcessNwpBackend]
    /// dispatcher is a *synchronous* closure, so the runtime cannot preempt it
    /// on this deadline — the same caveat the Anchor server carries. A
    /// long-running local dispatcher MUST honour the deadline cooperatively, or
    /// be written as a genuinely async [`NwpBackend`][super::backend::NwpBackend].
    pub dispatch_timeout_ms: u64,
}

impl Default for BridgeServerOptions {
    fn default() -> Self {
        BridgeServerOptions {
            path_prefix: String::new(),
            mcp_path: "/mcp".to_string(),
            a2a_path: "/a2a".to_string(),
            a2a_agent_card_path: "/.well-known/agent.json".to_string(),
            require_auth: true,
            verifier: None,
            max_request_body_bytes: 1024 * 1024,
            dispatch_timeout_ms: 30_000,
        }
    }
}

/// Syntactic validation of an `X-NWP-Agent` value: prefix `urn:nps:agent:`,
/// total length ≤ 512, then `{domain}:{identifier}` with both segments
/// non-empty.
pub fn is_valid_agent_nid(nid: &str) -> bool {
    const PREFIX: &str = "urn:nps:agent:";
    if nid.len() > 512 || !nid.starts_with(PREFIX) {
        return false;
    }
    let rest = &nid[PREFIX.len()..];
    let Some(sep) = rest.find(':') else {
        return false;
    };
    let (domain, identifier) = (&rest[..sep], &rest[sep + 1..]);
    if domain.is_empty() || identifier.is_empty() {
        return false;
    }
    domain
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && identifier.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | ':' | '@' | '/' | '-')
        })
}

pub struct BridgeInboundApp {
    mcp: McpInboundServer,
    a2a: A2aInboundServer,
    host: BridgeServerOptions,
    prefix: String,
}

impl BridgeInboundApp {
    /// Both protocol servers share the inbound options, which are cloned by
    /// reference through the backend `Arc`s.
    pub fn new(inbound: BridgeInboundOptions, host: BridgeServerOptions) -> Self {
        let mirror = BridgeInboundOptions {
            backends: inbound.backends.clone(),
            inbound_protocols: inbound.inbound_protocols.clone(),
            outbound_protocols: inbound.outbound_protocols.clone(),
            server_name: inbound.server_name.clone(),
            server_version: inbound.server_version.clone(),
            resource_read_limit: inbound.resource_read_limit,
            require_auth: inbound.require_auth,
        };
        let prefix = host.path_prefix.trim_end_matches('/').to_string();
        BridgeInboundApp {
            mcp: McpInboundServer::new(inbound),
            a2a: A2aInboundServer::new(mirror),
            host,
            prefix,
        }
    }

    pub fn mcp(&self) -> &McpInboundServer {
        &self.mcp
    }
    pub fn a2a(&self) -> &A2aInboundServer {
        &self.a2a
    }

    pub async fn handle(&self, req: AnchorRequest) -> AnchorResponse {
        if !req.path.starts_with(&self.prefix) {
            return empty(404);
        }
        let sub = &req.path[self.prefix.len()..];

        // AgentCard: GET only.
        if sub == self.host.a2a_agent_card_path {
            if req.method != "GET" {
                return empty(405);
            }
            if let Some(denied) = self.auth_gate(&req) {
                return denied;
            }
            let card = self.a2a.build_agent_card(&self.prefix).await;
            return json_response(200, &card);
        }

        let is_mcp = sub == self.host.mcp_path || sub == format!("{}/sse", self.host.mcp_path);
        let is_a2a = sub == self.host.a2a_path;
        if !is_mcp && !is_a2a {
            return empty(404);
        }
        if req.method != "POST" {
            return empty(405);
        }
        if let Some(denied) = self.auth_gate(&req) {
            return denied;
        }
        // Bounded body: a declared Content-Length pre-check AND the actual byte
        // count, so a lying or absent Content-Length cannot bypass the cap.
        if let Some(denied) = self.body_limit(&req) {
            return denied;
        }

        let parsed: Result<BridgeJsonRpcRequest, _> = serde_json::from_slice(&req.body);
        let rpc = match parsed {
            Ok(r) => r,
            Err(e) => {
                return json_response(
                    200,
                    &to_value(BridgeJsonRpcResponse::err(
                        Value::Null,
                        JSONRPC_INVALID_PARAMS,
                        e.to_string(),
                        None,
                    )),
                )
            }
        };

        let fut = async {
            if is_mcp {
                self.mcp.dispatch(&rpc).await
            } else {
                self.a2a.dispatch(&rpc).await
            }
        };

        let resp = if self.host.dispatch_timeout_ms > 0 {
            match tokio::time::timeout(
                std::time::Duration::from_millis(self.host.dispatch_timeout_ms),
                fut,
            )
            .await
            {
                Ok(r) => r,
                Err(_) => {
                    // HTTP 504 + -32000 UpstreamError.
                    return json_response(
                        504,
                        &to_value(BridgeJsonRpcResponse::err(
                            rpc.id.clone(),
                            JSONRPC_UPSTREAM_ERROR,
                            "Bridge dispatch timed out.",
                            None,
                        )),
                    );
                }
            }
        } else {
            fut.await
        };

        json_response(200, &to_value(resp))
    }

    /// Auth gate — HTTP 401 + a JSON-RPC error body (`-32600`, `id: null`).
    fn auth_gate(&self, req: &AnchorRequest) -> Option<AnchorResponse> {
        if !self.host.require_auth {
            return None;
        }
        let nid = req.header(http_headers::AGENT).unwrap_or("").trim();
        if nid.is_empty() || !is_valid_agent_nid(nid) {
            return Some(unauthorized());
        }
        // Fail closed: auth required with no verifier configured denies
        // everything.
        match &self.host.verifier {
            Some(v) if v(nid, req) => None,
            _ => Some(unauthorized()),
        }
    }

    fn body_limit(&self, req: &AnchorRequest) -> Option<AnchorResponse> {
        let cap = self.host.max_request_body_bytes;
        if cap == 0 {
            return None;
        }
        let declared = req
            .header("content-length")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
        if declared > cap || req.body.len() > cap {
            return Some(json_response(
                413,
                &to_value(BridgeJsonRpcResponse::err(
                    Value::Null,
                    JSONRPC_INVALID_REQUEST,
                    "Request body exceeds the configured limit.",
                    None,
                )),
            ));
        }
        None
    }
}

/// The catch-all arm: no exception detail ever leaks to the foreign client.
pub fn sanitized_server_error() -> AnchorResponse {
    json_response(
        500,
        &to_value(BridgeJsonRpcResponse::err(
            Value::Null,
            JSONRPC_INTERNAL_ERROR,
            "Bridge server request failed.",
            None,
        )),
    )
}

fn unauthorized() -> AnchorResponse {
    json_response(
        401,
        &to_value(BridgeJsonRpcResponse::err(
            Value::Null,
            JSONRPC_INVALID_REQUEST,
            "A valid X-NWP-Agent NID is required.",
            None,
        )),
    )
}

fn to_value(r: BridgeJsonRpcResponse) -> Value {
    serde_json::to_value(r).unwrap_or(json!({}))
}

fn json_response(status: u16, body: &Value) -> AnchorResponse {
    AnchorResponse {
        status,
        headers: vec![("content-type".into(), "application/json".into())],
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

fn empty(status: u16) -> AnchorResponse {
    AnchorResponse {
        status,
        headers: vec![],
        body: vec![],
    }
}
