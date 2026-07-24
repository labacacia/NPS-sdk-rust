// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Framework-agnostic middleware exposing an outbound Bridge Node at
//! `/.nwm`, `/actions`, and `/invoke`.

use serde_json::{json, Value};

use nps_core::codec::FrameDict;

use super::error::{bridge_error_codes, BridgeDispatchError};
use super::node::BridgeNode;
use super::types::NODE_TYPE_BRIDGE;
use crate::frames::ActionFrame;
use crate::http_headers;
use crate::node_http::{NodeRequest, NodeResponse};

/// Options for the outbound Bridge Node middleware.
#[derive(Debug, Clone)]
pub struct BridgeNodeOptions {
    /// Bridge Node identifier surfaced in `/.nwm`.
    pub node_id: String,
    /// Path prefix for the Bridge Node endpoints. Empty string means root.
    pub path_prefix: String,
    /// Action id accepted by `/invoke`.
    pub action_id: String,
    /// Require the `X-NWP-Agent` header before dispatching.
    pub require_auth: bool,
}

impl Default for BridgeNodeOptions {
    fn default() -> Self {
        Self {
            node_id: "nps-bridge".to_string(),
            path_prefix: String::new(),
            action_id: "bridge.dispatch".to_string(),
            require_auth: false,
        }
    }
}

/// Framework-agnostic Bridge Node middleware.
#[derive(Clone)]
pub struct BridgeNodeMiddleware {
    bridge: BridgeNode,
    options: BridgeNodeOptions,
}

impl BridgeNodeMiddleware {
    /// Create Bridge Node middleware.
    pub fn new(bridge: BridgeNode, options: BridgeNodeOptions) -> Self {
        Self { bridge, options }
    }

    /// Handle one request. Returns `None` when the path is outside this node's
    /// prefix/routes (host falls through).
    pub async fn handle(&self, req: &NodeRequest) -> Option<NodeResponse> {
        let path = req.path.as_str();
        let prefix = self.options.path_prefix.trim_end_matches('/');
        if !path.starts_with(prefix) {
            return None;
        }

        let sub = &path[prefix.len()..];
        match sub {
            "/.nwm" | "/.nwm/" => Some(write_json(
                200,
                self.build_manifest(),
                http_headers::MIME_MANIFEST,
            )),
            "/actions" | "/actions/" => {
                Some(write_json(200, self.build_actions(), "application/json"))
            }
            "/invoke" | "/invoke/" => {
                if !req.method.eq_ignore_ascii_case("POST") {
                    return Some(empty(405));
                }
                Some(self.handle_invoke(req).await)
            }
            _ => None,
        }
    }

    async fn handle_invoke(&self, req: &NodeRequest) -> NodeResponse {
        if self.options.require_auth && req.header(http_headers::AGENT).is_none() {
            return write_error(
                401,
                "NPS-CLIENT-UNAUTHORIZED",
                "NWP-BRIDGE-AUTH-REQUIRED",
                "X-NWP-Agent header is required.",
            );
        }

        let value: Value = match serde_json::from_slice(&req.body) {
            Ok(v) => v,
            Err(e) => {
                return write_error(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    bridge_error_codes::TARGET_INVALID,
                    &e.to_string(),
                )
            }
        };

        let Value::Object(map) = value else {
            return write_error(
                400,
                "NPS-CLIENT-BAD-REQUEST",
                bridge_error_codes::TARGET_INVALID,
                "ActionFrame body is required.",
            );
        };
        let dict: FrameDict = map;

        let frame = match ActionFrame::from_dict(&dict) {
            Ok(f) => f,
            Err(e) => {
                return write_error(
                    400,
                    "NPS-CLIENT-BAD-REQUEST",
                    bridge_error_codes::TARGET_INVALID,
                    &e.to_string(),
                )
            }
        };

        if frame.action != self.options.action_id {
            return write_error(
                404,
                "NPS-CLIENT-NOT-FOUND",
                "NWP-BRIDGE-ACTION-NOT-FOUND",
                &format!("Unknown bridge action '{}'.", frame.action),
            );
        }

        match self.bridge.dispatch(&frame).await {
            Ok(caps) => write_json(200, Value::Object(caps.to_dict()), "application/json"),
            Err(err) => map_dispatch_error(&err),
        }
    }

    fn build_manifest(&self) -> Value {
        json!({
            "node_type": NODE_TYPE_BRIDGE,
            "node_id": self.options.node_id,
            "bridge_protocols": self.bridge.registry().protocols(),
            "actions": [self.options.action_id],
        })
    }

    fn build_actions(&self) -> Value {
        json!([{
            "action_id": self.options.action_id,
            "description": "Dispatch an NWP ActionFrame to an external Bridge target.",
            "bridge_protocols": self.bridge.registry().protocols(),
        }])
    }
}

fn map_dispatch_error(err: &BridgeDispatchError) -> NodeResponse {
    let (status, nps_status) = if err.error_code == bridge_error_codes::UPSTREAM_FAILED {
        (502, "NPS-SERVER-UPSTREAM-FAILED")
    } else {
        (400, "NPS-CLIENT-BAD-REQUEST")
    };
    write_error(status, nps_status, &err.error_code, &err.message)
}

fn write_json(status: u16, body: Value, content_type: &str) -> NodeResponse {
    NodeResponse {
        status,
        headers: vec![("content-type".to_string(), content_type.to_string())],
        body: serde_json::to_vec(&body).unwrap_or_default(),
    }
}

fn write_error(status: u16, nps_status: &str, error: &str, message: &str) -> NodeResponse {
    let body = json!({
        "status": nps_status,
        "error": error,
        "message": message,
    });
    write_json(status, body, "application/json")
}

fn empty(status: u16) -> NodeResponse {
    NodeResponse {
        status,
        headers: vec![],
        body: vec![],
    }
}
