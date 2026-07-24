// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound A2A adapter that exposes local NPS actions as A2A skills.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::error::bridge_error_codes;
use super::frame_json::BridgeFrame;
use super::jsonrpc::{
    bridge_jsonrpc_error_codes as codes, BridgeJsonRpcRequest, BridgeJsonRpcResponse,
};
use super::server_options::{BridgeServerAction, BridgeServerActionInvoker, BridgeServerOptions};
use crate::frames::ActionFrame;

/// A2A protocol version implemented by the Bridge server adapter.
pub const A2A_SERVER_VERSION: &str = "0.2";
pub const A2A_TASK_STATE_COMPLETED: &str = "completed";
pub const A2A_TASK_STATE_FAILED: &str = "failed";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAgentCard {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<A2aAgentProvider>,
    pub version: String,
    pub capabilities: A2aAgentCapabilities,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<A2aAgentAuthentication>,
    #[serde(rename = "defaultInputModes")]
    pub default_input_modes: Vec<String>,
    #[serde(rename = "defaultOutputModes")]
    pub default_output_modes: Vec<String>,
    pub skills: Vec<A2aAgentSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAgentProvider {
    pub organization: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAgentCapabilities {
    pub streaming: bool,
    #[serde(rename = "pushNotifications")]
    pub push_notifications: bool,
    #[serde(rename = "stateTransitionHistory")]
    pub state_transition_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAgentAuthentication {
    pub schemes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAgentSkill {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(rename = "inputModes", skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    #[serde(rename = "outputModes", skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aTask {
    pub id: String,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub status: A2aTaskStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<A2aArtifact>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<A2aMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aTaskStatus {
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aMessage {
    pub role: String,
    pub parts: Vec<A2aPart>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aPart {
    #[serde(rename = "type")]
    pub part_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aArtifact {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub parts: Vec<A2aPart>,
    pub index: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aSendTaskParams {
    pub id: String,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub message: A2aMessage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

/// Inbound A2A adapter that exposes local NPS actions as A2A skills.
#[derive(Clone)]
pub struct A2aServerBridge {
    options: BridgeServerOptions,
    invoker: BridgeServerActionInvoker,
}

impl A2aServerBridge {
    /// Create an A2A server bridge.
    pub fn new(options: BridgeServerOptions) -> Self {
        let invoker = BridgeServerActionInvoker::new(&options);
        Self { options, invoker }
    }

    /// Build the A2A AgentCard for the hosted Bridge server.
    pub fn build_agent_card(&self, endpoint_url: &str) -> A2aAgentCard {
        A2aAgentCard {
            name: self.options.server_name.clone(),
            description: self.options.description.clone(),
            url: endpoint_url.to_string(),
            provider: Some(A2aAgentProvider {
                organization: "LabAcacia / INNO LOTUS PTY LTD".to_string(),
                url: Some("https://github.com/labacacia/nps".to_string()),
            }),
            version: self.options.server_version.clone(),
            capabilities: A2aAgentCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: false,
            },
            authentication: if self.options.require_auth {
                Some(A2aAgentAuthentication {
                    schemes: vec!["apikey".to_string()],
                    credentials: Some("X-NWP-Agent".to_string()),
                })
            } else {
                None
            },
            default_input_modes: vec!["text".to_string(), "data".to_string()],
            default_output_modes: vec!["text".to_string(), "data".to_string()],
            skills: self
                .options
                .actions
                .iter()
                .map(|action| A2aAgentSkill {
                    id: action.action_id.clone(),
                    name: action.effective_display_name(),
                    description: action.description.clone(),
                    tags: action.tags.clone(),
                    input_modes: Some(vec!["text".to_string(), "data".to_string()]),
                    output_modes: Some(vec!["data".to_string()]),
                })
                .collect(),
        }
    }

    /// Dispatch one A2A JSON-RPC request.
    pub async fn dispatch(&self, request: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        match request.method.as_str() {
            "tasks/send" => self.send_task(request).await,
            other => BridgeJsonRpcResponse::error(
                request,
                codes::METHOD_NOT_FOUND,
                format!("A2A method '{other}' is not supported by NWP Bridge server."),
            ),
        }
    }

    async fn send_task(&self, request: &BridgeJsonRpcRequest) -> BridgeJsonRpcResponse {
        let Some(params) = request.params.as_ref() else {
            return BridgeJsonRpcResponse::error(
                request,
                codes::INVALID_PARAMS,
                "A2A tasks/send requires params.",
            );
        };

        let task: A2aSendTaskParams = match serde_json::from_value(params.clone()) {
            Ok(t) => t,
            Err(e) => {
                return BridgeJsonRpcResponse::error(request, codes::INVALID_PARAMS, e.to_string())
            }
        };

        if task.id.trim().is_empty() {
            return BridgeJsonRpcResponse::error(
                request,
                codes::INVALID_PARAMS,
                "A2A tasks/send params.id is required.",
            );
        }

        let Some(action) = self.resolve_action(&task) else {
            return BridgeJsonRpcResponse::error_data(
                request,
                codes::INVALID_PARAMS,
                "A2A task metadata must identify an exposed NPS action when multiple actions exist.",
                json!({ "error": bridge_error_codes::SERVER_TOOL_NOT_FOUND }),
            );
        };

        let frame = ActionFrame {
            action: action.action_id.clone(),
            params: extract_action_params(&task),
            anchor_ref: None,
            async_: action.async_,
        };

        let result = self.invoker.invoke(frame).await;
        BridgeJsonRpcResponse::success(
            request,
            serde_json::to_value(to_task(&task, &result)).unwrap_or(Value::Null),
        )
    }

    fn resolve_action(&self, task: &A2aSendTaskParams) -> Option<&BridgeServerAction> {
        let keys = ["action_id", "actionId", "skill_id", "skillId", "skill"];
        let mut requested = try_get_string(task.metadata.as_ref(), &keys)
            .or_else(|| try_get_string(task.message.metadata.as_ref(), &keys));

        if requested.as_deref().map(str::trim).unwrap_or("").is_empty() {
            for part in &task.message.parts {
                requested = try_get_string(part.metadata.as_ref(), &keys)
                    .or_else(|| try_get_string(part.data.as_ref(), &keys));
                if !requested.as_deref().map(str::trim).unwrap_or("").is_empty() {
                    break;
                }
            }
        }

        let requested = requested.unwrap_or_default();
        if requested.trim().is_empty() && self.options.actions.len() == 1 {
            return self.options.actions.first();
        }

        self.options.actions.iter().find(|action| {
            action.action_id.eq_ignore_ascii_case(&requested)
                || action.effective_tool_name().eq_ignore_ascii_case(&requested)
        })
    }
}

fn extract_action_params(task: &A2aSendTaskParams) -> Option<Value> {
    let keys = ["params", "arguments"];
    if let Some(v) = try_get_element(task.metadata.as_ref(), &keys)
        .or_else(|| try_get_element(task.message.metadata.as_ref(), &keys))
    {
        return Some(v);
    }

    for part in &task.message.parts {
        if let Some(nested) = try_get_element(part.data.as_ref(), &keys) {
            return Some(nested);
        }
        if part.part_type.eq_ignore_ascii_case("data") {
            if let Some(data) = &part.data {
                return Some(data.clone());
            }
        }
        if part.part_type.eq_ignore_ascii_case("text") {
            if let Some(text) = &part.text {
                if !text.trim().is_empty() {
                    return Some(json!({ "text": text }));
                }
            }
        }
    }

    None
}

fn to_task(request: &A2aSendTaskParams, frame: &BridgeFrame) -> A2aTask {
    let is_error = frame.is_error();
    let timestamp = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();
    let payload = frame.to_element();

    A2aTask {
        id: request.id.clone(),
        session_id: request.session_id.clone(),
        status: A2aTaskStatus {
            state: if is_error {
                A2A_TASK_STATE_FAILED.to_string()
            } else {
                A2A_TASK_STATE_COMPLETED.to_string()
            },
            timestamp: Some(timestamp),
            message: if is_error {
                Some(A2aMessage {
                    role: "agent".to_string(),
                    parts: vec![A2aPart {
                        part_type: "text".to_string(),
                        text: Some(frame.error_text()),
                        data: None,
                        metadata: None,
                    }],
                    metadata: None,
                })
            } else {
                None
            },
        },
        artifacts: Some(vec![A2aArtifact {
            name: Some(if is_error { "nps-error" } else { "nps-result" }.to_string()),
            description: None,
            parts: vec![A2aPart {
                part_type: "data".to_string(),
                text: None,
                data: Some(payload),
                metadata: None,
            }],
            index: 0,
            metadata: None,
        }]),
        history: Some(vec![request.message.clone()]),
        metadata: None,
    }
}

fn try_get_string(source: Option<&Value>, names: &[&str]) -> Option<String> {
    match try_get_element(source, names) {
        Some(Value::String(s)) => Some(s),
        _ => None,
    }
}

fn try_get_element(source: Option<&Value>, names: &[&str]) -> Option<Value> {
    let obj = source?.as_object()?;
    for name in names {
        if let Some(value) = obj.get(*name) {
            return Some(value.clone());
        }
    }
    None
}
