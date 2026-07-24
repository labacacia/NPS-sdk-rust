// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 envelopes used by MCP and A2A Bridge servers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJsonRpcRequest {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    /// Request id. `None` indicates a notification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJsonRpcResponse {
    #[serde(default = "default_jsonrpc")]
    pub jsonrpc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<BridgeJsonRpcError>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

fn default_jsonrpc() -> String {
    "2.0".to_string()
}

/// Standard JSON-RPC error codes plus Bridge server application codes.
pub mod bridge_jsonrpc_error_codes {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
    pub const UPSTREAM_ERROR: i32 = -32000;
    pub const TOOL_NOT_FOUND: i32 = -32002;
}

impl BridgeJsonRpcResponse {
    /// Build a JSON-RPC success response echoing the request id.
    pub fn success(request: &BridgeJsonRpcRequest, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id: request.id.clone(),
            result: Some(result),
            error: None,
        }
    }

    /// Build a JSON-RPC error response echoing the request id.
    pub fn error(request: &BridgeJsonRpcRequest, code: i32, message: impl Into<String>) -> Self {
        Self::error_with_id(request.id.clone(), code, message, None)
    }

    /// Build a JSON-RPC error response with `data` echoing the request id.
    pub fn error_data(
        request: &BridgeJsonRpcRequest,
        code: i32,
        message: impl Into<String>,
        data: Value,
    ) -> Self {
        Self::error_with_id(request.id.clone(), code, message, Some(data))
    }

    /// Build a JSON-RPC error response with an explicit id.
    pub fn error_with_id(
        id: Option<Value>,
        code: i32,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(BridgeJsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}
