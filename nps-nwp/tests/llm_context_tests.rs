// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nwp::*;

#[test]
fn context_errors_use_the_shared_resource_limit_status() {
    assert_eq!(
        error_codes::to_nps_status(error_codes::LLM_CONTEXT_LIMIT_EXCEEDED),
        nps_core::status_codes::NPS_LIMIT_RESOURCE
    );
    assert_eq!(
        nps_core::status_codes::to_http_status(nps_core::status_codes::NPS_LIMIT_RESOURCE),
        Some(429)
    );
}

#[test]
fn stateful_completion_uses_canonical_wire_fields() {
    let request = LlmCompleteActionRequest {
        kind: LLM_COMPLETE.into(),
        model: "willow-small".into(),
        max_tokens: None,
        stream: false,
        messages: vec![LlmMessageDto {
            role: "user".into(),
            content: Some("Hello".into()),
            tool_call_id: None,
            tool_name: None,
            tool_calls: None,
        }],
        tools: None,
        context: Some(LlmContextRequestDto {
            operation: LlmContextOperation::Create,
            context_id: None,
            base_version: None,
            ttl_seconds: Some(600),
        }),
    };
    let wire = serde_json::to_value(&request).unwrap();
    assert_eq!(wire["kind"], "llm.complete");
    assert_eq!(wire["context"]["operation"], "create");
    assert_eq!(wire["context"]["ttl_seconds"], 600);
    let decoded = request_from_value(wire).unwrap();
    assert_eq!(
        decoded.context.unwrap().operation,
        LlmContextOperation::Create
    );
}

#[test]
fn lifecycle_helpers_use_canonical_action_ids() {
    let status = status_action_frame(&LlmContextStatusRequestDto {
        context_id: None,
        idempotency_key: Some("create-1".into()),
    })
    .unwrap();
    assert_eq!(status.action, LLM_CONTEXT_STATUS);

    let release = release_action_frame(
        &LlmContextReleaseRequestDto {
            context_id: "AQIDBAUGBwgJCgsMDQ4PEA".into(),
            base_version: 7,
        },
        "release-1".into(),
    )
    .unwrap();
    assert_eq!(release.action, LLM_CONTEXT_RELEASE);
    assert_eq!(release.idempotency_key.as_deref(), Some("release-1"));
    assert_eq!(release.params.unwrap()["base_version"], 7);
}
