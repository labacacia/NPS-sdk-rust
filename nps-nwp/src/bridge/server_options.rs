// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Options and types for inbound MCP/A2A Bridge server hosting.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde_json::Value;

use super::error::bridge_error_codes;
use super::frame_json::BridgeFrame;
use crate::frames::ActionFrame;

/// Result of a local NPS action dispatch fed to inbound Bridge server adapters.
pub type DispatcherResult = BridgeFrame;

/// Local NPS action dispatcher used by inbound Bridge server adapters.
///
/// Given a decoded [`ActionFrame`], returns the resulting frame (success caps or
/// error envelope).
pub type LocalActionDispatcher = Arc<
    dyn Fn(ActionFrame) -> Pin<Box<dyn Future<Output = DispatcherResult> + Send>> + Send + Sync,
>;

/// Action exposed by inbound MCP/A2A Bridge server adapters.
#[derive(Debug, Clone)]
pub struct BridgeServerAction {
    /// NPS action identifier dispatched to the local node.
    pub action_id: String,
    /// Protocol-safe MCP tool name. Defaults to a sanitized `action_id`.
    pub tool_name: Option<String>,
    /// Human-readable display name for A2A AgentCard entries.
    pub display_name: Option<String>,
    /// Short action/tool description.
    pub description: Option<String>,
    /// JSON Schema describing input arguments.
    pub input_schema: Option<Value>,
    /// Whether generated [`ActionFrame`] values should request async execution.
    pub async_: bool,
    /// Optional A2A skill tags.
    pub tags: Option<Vec<String>>,
}

impl BridgeServerAction {
    /// Create an exposed action from its id.
    pub fn new(action_id: impl Into<String>) -> Self {
        Self {
            action_id: action_id.into(),
            tool_name: None,
            display_name: None,
            description: None,
            input_schema: None,
            async_: false,
            tags: None,
        }
    }

    /// Effective MCP tool name for this action.
    pub fn effective_tool_name(&self) -> String {
        match &self.tool_name {
            Some(t) if !t.trim().is_empty() => t.clone(),
            _ => Self::to_tool_name(&self.action_id),
        }
    }

    /// Effective display name for A2A AgentCard skills.
    pub fn effective_display_name(&self) -> String {
        match &self.display_name {
            Some(d) if !d.trim().is_empty() => d.clone(),
            _ => self.action_id.clone(),
        }
    }

    /// Return a protocol-safe MCP tool name for an NPS action id.
    pub fn to_tool_name(action_id: &str) -> String {
        if action_id.trim().is_empty() {
            return "action".to_string();
        }
        let mapped: String = action_id
            .trim()
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                    ch
                } else {
                    '_'
                }
            })
            .collect();
        let name = mapped.trim_matches('_');
        if name.is_empty() {
            "action".to_string()
        } else {
            name.to_string()
        }
    }
}

/// Options for inbound MCP/A2A Bridge server hosting.
#[derive(Clone)]
pub struct BridgeServerOptions {
    /// Bridge server identifier surfaced in protocol metadata.
    pub node_id: String,
    /// Path prefix for inbound Bridge server endpoints. Empty string means root.
    pub path_prefix: String,
    /// MCP HTTP endpoint under `path_prefix`.
    pub mcp_path: String,
    /// A2A JSON-RPC endpoint under `path_prefix`.
    pub a2a_path: String,
    /// A2A AgentCard endpoint under `path_prefix`.
    pub a2a_agent_card_path: String,
    /// Require a valid `X-NWP-Agent` NID header before dispatching requests.
    pub require_auth: bool,
    /// Server name returned by MCP initialize and A2A AgentCard.
    pub server_name: String,
    /// Server version returned by MCP initialize and A2A AgentCard.
    pub server_version: String,
    /// Server description returned by A2A AgentCard.
    pub description: Option<String>,
    /// Actions exposed as MCP tools and A2A skills.
    pub actions: Vec<BridgeServerAction>,
    /// Maximum inbound JSON-RPC request body size in bytes. 0 disables the limit.
    pub max_request_body_bytes: u64,
    /// Local NPS action dispatcher used by inbound Bridge server adapters.
    pub dispatch: Option<LocalActionDispatcher>,
}

impl Default for BridgeServerOptions {
    fn default() -> Self {
        Self {
            node_id: "nps-bridge-server".to_string(),
            path_prefix: String::new(),
            mcp_path: "/mcp".to_string(),
            a2a_path: "/a2a".to_string(),
            a2a_agent_card_path: "/.well-known/agent.json".to_string(),
            require_auth: true,
            server_name: "nps-bridge-server".to_string(),
            server_version: "1.0.0-alpha.15".to_string(),
            description: Some("NPS Bridge server ingress.".to_string()),
            actions: Vec::new(),
            max_request_body_bytes: 1024 * 1024,
            dispatch: None,
        }
    }
}

impl BridgeServerOptions {
    /// Add an exposed local action and return these options for chaining.
    pub fn add_action(mut self, action: BridgeServerAction) -> Self {
        self.actions.push(action);
        self
    }

    /// Set the local action dispatcher.
    pub fn with_dispatch(mut self, dispatch: LocalActionDispatcher) -> Self {
        self.dispatch = Some(dispatch);
        self
    }
}

/// Invokes local NPS actions for inbound Bridge server adapters.
#[derive(Clone)]
pub struct BridgeServerActionInvoker {
    dispatch: Option<LocalActionDispatcher>,
}

impl BridgeServerActionInvoker {
    /// Build an invoker from the configured options.
    pub fn new(options: &BridgeServerOptions) -> Self {
        Self {
            dispatch: options.dispatch.clone(),
        }
    }

    /// Invoke a local NPS action and return its frame response.
    pub async fn invoke(&self, frame: ActionFrame) -> BridgeFrame {
        match &self.dispatch {
            Some(dispatch) => dispatch(frame).await,
            None => BridgeFrame::Error {
                status: "NPS-SERVER-NOT-IMPLEMENTED".to_string(),
                error: bridge_error_codes::SERVER_DISPATCHER_MISSING.to_string(),
                message:
                    "BridgeServerOptions.dispatch must be configured before handling inbound Bridge calls."
                        .to_string(),
            },
        }
    }
}
