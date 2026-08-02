// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! JSON-RPC 2.0 envelope types shared by the MCP and A2A inbound servers.

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeJsonRpcRequest {
    #[serde(default = "two_zero")]
    pub jsonrpc: String,
    #[serde(default)]
    pub id: Value,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

fn two_zero() -> String {
    "2.0".to_string()
}

impl BridgeJsonRpcRequest {
    pub fn new(id: Value, method: impl Into<String>, params: Option<Value>) -> Self {
        BridgeJsonRpcRequest {
            jsonrpc: two_zero(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeJsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BridgeJsonRpcResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<BridgeJsonRpcError>,
}

impl BridgeJsonRpcResponse {
    pub fn ok(id: Value, result: Value) -> Self {
        BridgeJsonRpcResponse {
            jsonrpc: two_zero(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(id: Value, code: i32, message: impl Into<String>, data: Option<Value>) -> Self {
        BridgeJsonRpcResponse {
            jsonrpc: two_zero(),
            id,
            result: None,
            error: Some(BridgeJsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }

    pub fn is_error(&self) -> bool {
        self.error.is_some()
    }

    pub fn error_code(&self) -> Option<i32> {
        self.error.as_ref().map(|e| e.code)
    }
}
