// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound MCP adapter that exposes local NPS actions as MCP tools.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::error::bridge_error_codes;
use super::frame_json::BridgeFrame;
use super::jsonrpc::{
    bridge_jsonrpc_error_codes as codes, BridgeJsonRpcRequest, BridgeJsonRpcResponse,
};
use super::server_options::{BridgeServerAction, BridgeServerActionInvoker, BridgeServerOptions};
use crate::frames::ActionFrame;

/// MCP protocol version implemented by the Bridge server adapter.
pub const MCP_SERVER_VERSION: &str = "2024-11-05";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpInitializeResult {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    #[serde(rename = "serverInfo")]
    pub server_info: McpServerInfo,
    pub capabilities: McpServerCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerCapabilities {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<McpToolCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCapabilities {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolListResult {
    pub tools: Vec<McpTool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCallParams {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCallResult {
    pub content: Vec<McpContent>,
    #[serde(rename = "isError")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpContent {
    #[serde(rename = "type")]
    pub content_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// Inbound MCP adapter that exposes local NPS actions as MCP tools.
#[derive(Clone)]
pub struct McpServerBridge {
    options: BridgeServerOptions,
    invoker: BridgeServerActionInvoker,
}

impl McpServerBridge {
    /// Create an MCP server bridge.
    pub fn new(options: BridgeServerOptions) -> Self {
        let invoker = BridgeServerActionInvoker::new(&options);
        Self { options, invoker }
    }

    /// Dispatch one MCP JSON-RPC request.
    pub async fn dispatch(&self, request: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        match request.method.as_str() {
            "initialize" => BridgeJsonRpcResponse::success(
                request,
                serde_json::to_value(self.initialize()).unwrap_or(Value::Null),
            ),
            "tools/list" => BridgeJsonRpcResponse::success(
                request,
                serde_json::to_value(self.list_tools()).unwrap_or(Value::Null),
            ),
            "tools/call" => self.call_tool(request).await,
            "ping" => BridgeJsonRpcResponse::success(request, json!({})),
            other => BridgeJsonRpcResponse::error(
                request,
                codes::METHOD_NOT_FOUND,
                format!("MCP method '{other}' is not supported by NWP Bridge server."),
            ),
        }
    }

    fn initialize(&self) -> McpInitializeResult {
        McpInitializeResult {
            protocol_version: MCP_SERVER_VERSION.to_string(),
            server_info: McpServerInfo {
                name: self.options.server_name.clone(),
                version: self.options.server_version.clone(),
            },
            capabilities: McpServerCapabilities {
                tools: Some(McpToolCapabilities { list_changed: false }),
            },
        }
    }

    fn list_tools(&self) -> McpToolListResult {
        McpToolListResult {
            tools: self
                .options
                .actions
                .iter()
                .map(|action| McpTool {
                    name: action.effective_tool_name(),
                    description: action.description.clone(),
                    input_schema: action
                        .input_schema
                        .clone()
                        .unwrap_or_else(default_input_schema),
                })
                .collect(),
        }
    }

    async fn call_tool(&self, request: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        let Some(params) = request.params.as_ref() else {
            return BridgeJsonRpcResponse::error(
                request,
                codes::INVALID_PARAMS,
                "MCP tools/call requires params.",
            );
        };

        let call: McpToolCallParams = match serde_json::from_value(params.clone()) {
            Ok(c) => c,
            Err(e) => {
                return BridgeJsonRpcResponse::error(request, codes::INVALID_PARAMS, e.to_string())
            }
        };

        if call.name.trim().is_empty() {
            return BridgeJsonRpcResponse::error(
                request,
                codes::INVALID_PARAMS,
                "MCP tools/call params.name is required.",
            );
        }

        let Some(action) = self.resolve_action(&call.name) else {
            return BridgeJsonRpcResponse::error_data(
                request,
                codes::TOOL_NOT_FOUND,
                format!("MCP tool '{}' is not exposed by NWP Bridge server.", call.name),
                json!({
                    "error": bridge_error_codes::SERVER_TOOL_NOT_FOUND,
                    "tool": call.name,
                }),
            );
        };

        let frame = ActionFrame {
            action: action.action_id.clone(),
            params: call.arguments.clone(),
            anchor_ref: None,
            async_: action.async_,
        };

        let result = self.invoker.invoke(frame).await;
        BridgeJsonRpcResponse::success(
            request,
            serde_json::to_value(to_tool_result(&result)).unwrap_or(Value::Null),
        )
    }

    fn resolve_action(&self, tool_name: &str) -> Option<&BridgeServerAction> {
        self.options.actions.iter().find(|action| {
            action.effective_tool_name().eq_ignore_ascii_case(tool_name)
                || action.action_id.eq_ignore_ascii_case(tool_name)
        })
    }
}

fn to_tool_result(frame: &BridgeFrame) -> McpToolCallResult {
    McpToolCallResult {
        is_error: frame.is_error(),
        content: vec![McpContent {
            content_type: "text".to_string(),
            text: Some(frame.to_json_string()),
        }],
    }
}

fn default_input_schema() -> Value {
    json!({ "type": "object", "additionalProperties": true })
}
