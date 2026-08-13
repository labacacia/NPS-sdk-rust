// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use crate::frames::ActionFrame;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const LLM_COMPLETE: &str = "llm.complete";
pub const LLM_CONTEXT_STATUS: &str = "llm.context.status";
pub const LLM_CONTEXT_RELEASE: &str = "llm.context.release";
pub const LLM_COMPLETE_RESPONSE_ANCHOR: &str = "nps:system:llm.complete:response";
pub const LLM_COMPLETE_STREAM_ANCHOR: &str = "nps:system:llm.complete:stream";
pub const LLM_CONTEXT_STATUS_RESPONSE_ANCHOR: &str = "nps:system:llm.context.status:response";
pub const LLM_CONTEXT_RELEASE_RESPONSE_ANCHOR: &str = "nps:system:llm.context.release:response";
pub const CAPABILITY_LLM_COMPLETE: &str = "llm:complete";
pub const CAPABILITY_LLM_CONTEXT: &str = "llm:context";
pub const CAPABILITY_LLM_STREAM: &str = "llm:stream";
pub const CAPABILITY_LLM_TOOL_CALL: &str = "llm:tool_call";

fn complete_kind() -> String {
    LLM_COMPLETE.to_owned()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmStopReason {
    EndTurn,
    ToolUse,
    ToolCalls,
    MaxTokens,
    Length,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmContextOperation {
    Create,
    Append,
    Fork,
    Reset,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LlmContextState {
    Busy,
    Active,
    Released,
    Expired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmToolCallDto {
    pub call_id: String,
    pub tool_name: String,
    pub arguments_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolParameterDto {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmToolDefinitionDto {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Vec<ToolParameterDto>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmMessageDto {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<LlmToolCallDto>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmContextRequestDto {
    pub operation: LlmContextOperation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmContextReceiptDto {
    pub context_id: String,
    pub version: u64,
    pub operation: LlmContextOperation,
    pub state: LlmContextState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmContextStatusRequestDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmContextReleaseRequestDto {
    pub context_id: String,
    pub base_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmContextStatusDto {
    pub state: LlmContextState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmUsageDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_hit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluated_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_input_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCompleteActionRequest {
    #[serde(default = "complete_kind")]
    pub kind: String,
    pub model: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stream: bool,
    pub messages: Vec<LlmMessageDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<LlmToolDefinitionDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<LlmContextRequestDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCompleteActionResponse {
    pub stop_reason: LlmStopReason,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<LlmToolCallDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<LlmUsageDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<LlmContextReceiptDto>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmCompleteStreamChunkDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_delta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<LlmToolCallDto>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_reason: Option<LlmStopReason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<LlmUsageDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<LlmContextReceiptDto>,
}

pub fn complete_action_frame(
    request: &LlmCompleteActionRequest,
    idempotency_key: Option<String>,
    timeout_ms: Option<u32>,
    request_id: Option<String>,
) -> serde_json::Result<ActionFrame> {
    Ok(ActionFrame {
        action: LLM_COMPLETE.to_owned(),
        params: Some(serde_json::to_value(request)?),
        anchor_ref: None,
        async_: false,
        idempotency_key,
        timeout_ms: timeout_ms.or(Some(5000)),
        request_id,
    })
}

pub fn status_action_frame(
    request: &LlmContextStatusRequestDto,
) -> serde_json::Result<ActionFrame> {
    Ok(ActionFrame {
        action: LLM_CONTEXT_STATUS.to_owned(),
        params: Some(serde_json::to_value(request)?),
        anchor_ref: None,
        async_: false,
        idempotency_key: None,
        timeout_ms: Some(5000),
        request_id: None,
    })
}

pub fn release_action_frame(
    request: &LlmContextReleaseRequestDto,
    idempotency_key: String,
) -> serde_json::Result<ActionFrame> {
    Ok(ActionFrame {
        action: LLM_CONTEXT_RELEASE.to_owned(),
        params: Some(serde_json::to_value(request)?),
        anchor_ref: None,
        async_: false,
        idempotency_key: Some(idempotency_key),
        timeout_ms: Some(5000),
        request_id: None,
    })
}

pub fn request_from_value(value: Value) -> serde_json::Result<LlmCompleteActionRequest> {
    serde_json::from_value(value)
}
