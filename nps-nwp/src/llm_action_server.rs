// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Action Server coordinator for the NWP stateful LLM context contract.

use crate::action_server::{
    ActionContext, ActionError, ActionExecutionResult, ActionNodeOptions, ActionNodeProvider,
    ActionSpec, ActionStream, ActionStreamFrame, ParsedActionFrame,
};
use crate::context_store::{
    InMemoryLlmContextStore, LlmContextBinding, LlmContextMutationRequest,
    LlmContextMutationReservation, LlmContextOwner, LlmContextStoreError,
};
use crate::error_codes;
use crate::llm::{
    LlmCompleteActionRequest, LlmCompleteActionResponse, LlmCompleteStreamChunkDto,
    LlmContextOperation, LlmContextReleaseRequestDto, LlmContextStatusRequestDto, LlmMessageDto,
    LlmStopReason, CAPABILITY_LLM_COMPLETE, CAPABILITY_LLM_CONTEXT, CAPABILITY_LLM_STREAM,
    CAPABILITY_LLM_TOOL_CALL, LLM_COMPLETE, LLM_COMPLETE_RESPONSE_ANCHOR,
    LLM_COMPLETE_STREAM_ANCHOR, LLM_CONTEXT_RELEASE, LLM_CONTEXT_RELEASE_RESPONSE_ANCHOR,
    LLM_CONTEXT_STATUS, LLM_CONTEXT_STATUS_RESPONSE_ANCHOR,
};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmAuthorizationStage {
    Admission,
    Commit,
}

pub type LlmContextAuthorizer = Arc<
    dyn Fn(
            &LlmContextOwner,
            &str,
            LlmAuthorizationStage,
            &[String],
            &ActionContext,
        ) -> Result<(), ActionError>
        + Send
        + Sync,
>;

#[derive(Clone)]
pub struct StatefulLlmActionOptions {
    /// Deployment-authenticated tenant/workspace scope. Never read from payloads.
    pub security_scope: String,
    /// Provider/runtime compatibility revision included in the immutable binding.
    pub runtime_revision: String,
    pub provider_name: Option<String>,
    pub default_model: Option<String>,
    pub supports_tools: bool,
    pub supports_stream: bool,
    pub supports_json_mode: bool,
    pub reasoning_visibility: Option<String>,
    /// NIP check for every supplied capability. Called at admission and before commit;
    /// stateful requests fail closed when this is absent.
    pub authorizer: Option<LlmContextAuthorizer>,
}

impl StatefulLlmActionOptions {
    pub fn new(security_scope: impl Into<String>, runtime_revision: impl Into<String>) -> Self {
        Self {
            security_scope: security_scope.into(),
            runtime_revision: runtime_revision.into(),
            provider_name: None,
            default_model: None,
            supports_tools: false,
            supports_stream: false,
            supports_json_mode: false,
            reasoning_visibility: None,
            authorizer: None,
        }
    }
}

/// Wraps an ordinary LLM provider with the official context lifecycle state machine.
pub struct StatefulLlmActionProvider {
    inner: Arc<dyn ActionNodeProvider>,
    store: Arc<InMemoryLlmContextStore>,
    options: StatefulLlmActionOptions,
}

impl StatefulLlmActionProvider {
    pub fn new(
        inner: Arc<dyn ActionNodeProvider>,
        store: Arc<InMemoryLlmContextStore>,
        options: StatefulLlmActionOptions,
    ) -> Self {
        Self {
            inner,
            store,
            options,
        }
    }

    pub fn store(&self) -> &Arc<InMemoryLlmContextStore> {
        &self.store
    }

    /// Registers the exact actions and process-persistence profile implemented by this wrapper.
    pub fn configure_node(&self, node: &mut ActionNodeOptions) {
        let complete = node
            .actions
            .entry(LLM_COMPLETE.to_owned())
            .or_insert_with(|| ActionSpec::new(true));
        complete.params_anchor = Some("nps:system:llm.complete:request".into());
        complete.result_anchor = Some(LLM_COMPLETE_RESPONSE_ANCHOR.into());
        complete.idempotent = Some(true);
        complete.required_capability = Some(CAPABILITY_LLM_COMPLETE.into());

        node.actions.insert(
            LLM_CONTEXT_STATUS.into(),
            ActionSpec {
                description: Some("Inspect an LLM context or retained create outcome".into()),
                params_anchor: Some("nps:system:llm.context.status:request".into()),
                result_anchor: Some(LLM_CONTEXT_STATUS_RESPONSE_ANCHOR.into()),
                required_capability: Some(CAPABILITY_LLM_CONTEXT.into()),
                ..Default::default()
            },
        );
        node.actions.insert(
            LLM_CONTEXT_RELEASE.into(),
            ActionSpec {
                description: Some("Release an LLM context".into()),
                params_anchor: Some("nps:system:llm.context.release:request".into()),
                result_anchor: Some(LLM_CONTEXT_RELEASE_RESPONSE_ANCHOR.into()),
                idempotent: Some(true),
                required_capability: Some(CAPABILITY_LLM_CONTEXT.into()),
                ..Default::default()
            },
        );

        let descriptor = self.store.descriptor();
        let operations: Vec<Value> = descriptor
            .operations
            .iter()
            .map(|operation| serde_json::to_value(operation).expect("context operation serializes"))
            .collect();
        let mut profile = json!({
            "profile_version": "0.2",
            "actions": [LLM_COMPLETE, LLM_CONTEXT_STATUS, LLM_CONTEXT_RELEASE],
            "supports_stream": self.options.supports_stream,
            "supports_tools": self.options.supports_tools,
            "supports_json_mode": self.options.supports_json_mode,
            "context": {
                "supported": true,
                "operations": operations,
                "persistence": descriptor.persistence,
                "max_contexts_per_principal": descriptor.max_contexts_per_principal,
                "max_ttl_seconds": descriptor.max_ttl_seconds,
                "tombstone_seconds": descriptor.tombstone_seconds
            }
        });
        if let Some(provider) = &self.options.provider_name {
            profile["provider"] = Value::String(provider.clone());
        }
        if let Some(model) = &self.options.default_model {
            profile["default_model"] = Value::String(model.clone());
        }
        if let Some(visibility) = &self.options.reasoning_visibility {
            profile["reasoning_visibility"] = Value::String(visibility.clone());
        }
        node.profiles.insert("llm".into(), profile);
    }

    fn owner(&self, context: &ActionContext) -> Result<LlmContextOwner, ActionError> {
        let nid = context
            .agent_nid
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| ActionError {
                http_status: 401,
                nps_status: nps_core::status_codes::NPS_AUTH_UNAUTHENTICATED.into(),
                error_code: error_codes::AUTH_NID_SCOPE_VIOLATION.into(),
                message: "stateful LLM context actions require an authenticated agent NID".into(),
            })?;
        Ok(LlmContextOwner {
            nid: nid.to_owned(),
            security_scope: self.options.security_scope.clone(),
        })
    }

    fn check_authorization(
        &self,
        owner: &LlmContextOwner,
        action: &str,
        stage: LlmAuthorizationStage,
        required_capabilities: &[String],
        context: &ActionContext,
    ) -> Result<(), ActionError> {
        let Some(authorizer) = &self.options.authorizer else {
            return Err(ActionError {
                http_status: 403,
                nps_status: nps_core::status_codes::NPS_AUTH_FORBIDDEN.into(),
                error_code: error_codes::LLM_CONTEXT_FORBIDDEN.into(),
                message: "stateful LLM context authorization is not configured".into(),
            });
        };
        authorizer(owner, action, stage, required_capabilities, context)
    }

    fn complete(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        let request: LlmCompleteActionRequest = decode_params(frame, LLM_COMPLETE)?;
        if request.kind != LLM_COMPLETE {
            return Err(params_error("params.kind must be 'llm.complete'"));
        }
        if request.model.trim().is_empty() {
            return Err(params_error("llm.complete requires a non-empty model"));
        }
        if !self.options.supports_tools
            && request
                .tools
                .as_ref()
                .is_some_and(|tools| !tools.is_empty())
        {
            return Err(params_error(
                "this node does not advertise LLM tool-definition support",
            ));
        }
        if request.stream && !self.options.supports_stream {
            return Err(params_error(
                "this node does not advertise LLM streaming support",
            ));
        }
        if request.stream && frame.async_ {
            return Err(params_error(
                "stream=true cannot be combined with async=true",
            ));
        }
        let Some(context_request) = request.context.clone() else {
            return self.inner.execute(frame, context);
        };
        if matches!(
            context_request.operation,
            LlmContextOperation::Append | LlmContextOperation::Fork | LlmContextOperation::Reset
        ) && (context_request.context_id.is_none() || context_request.base_version.is_none())
        {
            return Err(params_error(
                "append/fork/reset require context_id and base_version",
            ));
        }

        let owner = self.owner(context)?;
        let binding = self.resolve_binding(&owner, &request, &context_request)?;
        let mutation = LlmContextMutationRequest {
            operation: context_request.operation,
            owner: owner.clone(),
            context_id: context_request.context_id,
            base_version: context_request.base_version,
            binding,
            messages: request.messages.clone(),
            ttl_seconds: context_request.ttl_seconds,
            idempotency_key: frame.idempotency_key.clone().unwrap_or_default(),
            request_id: frame.request_id.clone().unwrap_or_default(),
        };
        let reservation = self.store.reserve(mutation).map_err(store_error)?;
        let guard = ReservationGuard::new(self.store.clone(), reservation);
        let cancelled_guard = guard.clone();
        context.cancellation.on_cancel(move || {
            cancelled_guard.abort(error_codes::NODE_UNAVAILABLE);
        });
        self.execute_reserved(frame, context, &owner, guard, request.stream)
    }

    fn execute_reserved(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
        owner: &LlmContextOwner,
        guard: ReservationGuard,
        streaming: bool,
    ) -> Result<ActionExecutionResult, ActionError> {
        let result = match self.inner.execute(frame, context) {
            Ok(result) => result,
            Err(error) => {
                guard.abort(&error.error_code);
                return Err(error);
            }
        };
        if context.cancellation.is_cancelled() {
            guard.abort(error_codes::NODE_UNAVAILABLE);
            return Err(ActionError::internal("stateful llm.complete was cancelled"));
        }
        if streaming {
            let Some(source) = result.stream.clone() else {
                guard.abort(error_codes::NODE_UNAVAILABLE);
                return Err(ActionError::internal(
                    "stateful streaming llm.complete returned no StreamFrame sequence",
                ));
            };
            return Ok(ActionExecutionResult {
                result: None,
                stream: Some(self.coordinate_stream(
                    source,
                    guard,
                    owner.clone(),
                    frame.clone(),
                    context.clone(),
                )),
                anchor_ref: result
                    .anchor_ref
                    .or_else(|| Some(LLM_COMPLETE_STREAM_ANCHOR.into())),
                token_est: result.token_est,
            });
        }
        if result.stream.is_some() {
            guard.abort(error_codes::NODE_UNAVAILABLE);
            return Err(ActionError::internal(
                "stateful unary llm.complete returned a StreamFrame sequence",
            ));
        }
        let payload = match result.result.clone() {
            Some(payload) => payload,
            None => {
                guard.abort(error_codes::NODE_UNAVAILABLE);
                return Err(ActionError::internal(
                    "stateful llm.complete returned no result payload",
                ));
            }
        };
        let mut response: LlmCompleteActionResponse = match serde_json::from_value(payload) {
            Ok(response) => response,
            Err(error) => {
                guard.abort(error_codes::NODE_UNAVAILABLE);
                return Err(ActionError::internal(format!(
                    "stateful llm.complete returned an invalid official response: {error}"
                )));
            }
        };
        if response.stop_reason == LlmStopReason::Error {
            guard.abort(error_codes::NODE_UNAVAILABLE);
            response.context = None;
            return Ok(ActionExecutionResult {
                result: Some(serde_json::to_value(response).map_err(|error| {
                    ActionError::internal(format!(
                        "serialize failed stateful completion response: {error}"
                    ))
                })?),
                stream: None,
                anchor_ref: result
                    .anchor_ref
                    .or_else(|| Some(LLM_COMPLETE_RESPONSE_ANCHOR.into())),
                token_est: result.token_est,
            });
        }
        if let Err(error) = self.check_authorization(
            owner,
            LLM_COMPLETE,
            LlmAuthorizationStage::Commit,
            &required_capabilities(frame),
            context,
        ) {
            guard.abort(&error.error_code);
            return Err(error);
        }
        if context.cancellation.is_cancelled() {
            guard.abort(error_codes::NODE_UNAVAILABLE);
            return Err(ActionError::internal("stateful llm.complete was cancelled"));
        }

        let assistant = LlmMessageDto {
            role: "assistant".into(),
            content: response.content.clone(),
            tool_call_id: None,
            tool_name: None,
            tool_calls: response.tool_calls.clone(),
        };
        let receipt = guard.commit(assistant)?;
        response.context = Some(receipt);
        Ok(ActionExecutionResult {
            result: Some(serde_json::to_value(response).map_err(|error| {
                ActionError::internal(format!("serialize stateful completion response: {error}"))
            })?),
            stream: None,
            anchor_ref: result
                .anchor_ref
                .or_else(|| Some(LLM_COMPLETE_RESPONSE_ANCHOR.into())),
            token_est: result.token_est,
        })
    }

    fn coordinate_stream(
        &self,
        source: Arc<dyn ActionStream>,
        guard: ReservationGuard,
        owner: LlmContextOwner,
        request_frame: ParsedActionFrame,
        action_context: ActionContext,
    ) -> Arc<dyn ActionStream> {
        let authorizer = self.options.authorizer.clone();
        Arc::new(
            move |cancellation: &crate::action_server::ActionCancellation,
                  emit: &mut dyn FnMut(ActionStreamFrame) -> Result<(), ActionError>| {
                let mut content = String::new();
                let mut tool_calls = Vec::new();
                let mut resolved = false;
                let mut terminal_seen = false;
                let outcome = (|| {
                    source.write(cancellation, &mut |mut frame: ActionStreamFrame| {
                        if cancellation.is_cancelled() {
                            return Err(ActionError::internal("action stream was cancelled"));
                        }
                        if terminal_seen {
                            return Err(ActionError::internal(
                                "LLM stream emitted frames after terminal",
                            ));
                        }
                        let mut chunks = frame
                            .data
                            .into_iter()
                            .map(|payload| {
                                serde_json::from_value::<LlmCompleteStreamChunkDto>(payload)
                                    .map_err(|error| {
                                        ActionError::internal(format!(
                                            "stateful llm.complete returned an invalid stream payload: {error}"
                                        ))
                                    })
                            })
                            .collect::<Result<Vec<_>, _>>()?;
                        if !frame.is_last
                            && chunks.iter().any(|chunk| {
                                chunk.stop_reason.is_some()
                                    || chunk.error.is_some()
                                    || chunk.usage.is_some()
                                    || chunk.context.is_some()
                            })
                        {
                            return Err(ActionError::internal(
                                "LLM stream stop_reason, error, usage, and context are terminal-only fields",
                            ));
                        }
                        for chunk in &mut chunks {
                            if let Some(delta) = &chunk.content_delta {
                                content.push_str(delta);
                            }
                            if let Some(calls) = &chunk.tool_calls {
                                tool_calls.extend(calls.clone());
                            }
                            chunk.context = None;
                        }
                        frame.data = chunks
                            .iter()
                            .map(serde_json::to_value)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|error| {
                                ActionError::internal(format!(
                                    "serialize stateful LLM stream chunk: {error}"
                                ))
                            })?;
                        if !frame.is_last {
                            return emit(frame);
                        }

                        terminal_seen = true;
                        let terminal_index = chunks
                            .iter()
                            .rposition(|chunk| chunk.stop_reason.is_some());
                        let failed = frame.error_code.is_some()
                            || chunks.iter().any(|chunk| {
                                chunk.error.is_some()
                                    || chunk.stop_reason == Some(LlmStopReason::Error)
                            });
                        if failed {
                            let code = frame
                                .error_code
                                .clone()
                                .unwrap_or_else(|| error_codes::NODE_UNAVAILABLE.into());
                            guard.abort(&code);
                            resolved = true;
                            frame.error_code = Some(code);
                            return emit(frame);
                        }
                        let terminal_index = terminal_index.ok_or_else(|| {
                            ActionError::internal(
                                "successful LLM stream terminal frame requires stop_reason",
                            )
                        })?;
                        let authorize = authorizer.as_ref().ok_or_else(|| ActionError {
                            http_status: 403,
                            nps_status: nps_core::status_codes::NPS_AUTH_FORBIDDEN.into(),
                            error_code: error_codes::LLM_CONTEXT_FORBIDDEN.into(),
                            message: "stateful LLM context authorization is not configured".into(),
                        })?;
                        authorize(
                            &owner,
                            &request_frame.action_id,
                            LlmAuthorizationStage::Commit,
                            &required_capabilities(&request_frame),
                            &action_context,
                        )?;
                        if cancellation.is_cancelled() {
                            return Err(ActionError::internal("action stream was cancelled"));
                        }
                        let receipt = guard.commit(LlmMessageDto {
                            role: "assistant".into(),
                            content: (!content.is_empty()).then(|| content.clone()),
                            tool_call_id: None,
                            tool_name: None,
                            tool_calls: (!tool_calls.is_empty()).then(|| tool_calls.clone()),
                        })?;
                        chunks[terminal_index].context = Some(receipt);
                        frame.data = chunks
                            .iter()
                            .map(serde_json::to_value)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|error| {
                                ActionError::internal(format!(
                                    "serialize terminal stateful LLM stream chunk: {error}"
                                ))
                            })?;
                        resolved = true;
                        emit(frame)
                    })?;
                    if !terminal_seen {
                        return Err(ActionError::internal(
                            "stateful llm.complete stream ended without a terminal frame",
                        ));
                    }
                    Ok(())
                })();
                if outcome.is_err() && !resolved {
                    guard.abort(error_codes::NODE_UNAVAILABLE);
                }
                outcome
            },
        )
    }

    fn resolve_binding(
        &self,
        owner: &LlmContextOwner,
        request: &LlmCompleteActionRequest,
        context: &crate::llm::LlmContextRequestDto,
    ) -> Result<LlmContextBinding, ActionError> {
        if matches!(
            context.operation,
            LlmContextOperation::Append | LlmContextOperation::Fork
        ) {
            let context_id = context
                .context_id
                .as_deref()
                .ok_or_else(|| params_error("append/fork require context_id and base_version"))?;
            let snapshot = self
                .store
                .snapshot(owner, context_id)
                .map_err(store_error)?;
            return Ok(LlmContextBinding {
                model: request.model.clone(),
                system_messages: snapshot.binding.system_messages,
                tools: request.tools.clone().unwrap_or(snapshot.binding.tools),
                runtime_revision: self.options.runtime_revision.clone(),
            });
        }
        Ok(LlmContextBinding {
            model: request.model.clone(),
            system_messages: request
                .messages
                .iter()
                .filter(|message| message.role.eq_ignore_ascii_case("system"))
                .cloned()
                .collect(),
            tools: request.tools.clone().unwrap_or_default(),
            runtime_revision: self.options.runtime_revision.clone(),
        })
    }

    fn status(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        let request: LlmContextStatusRequestDto = decode_params(frame, LLM_CONTEXT_STATUS)?;
        let owner = self.owner(context)?;
        let status = self
            .store
            .status(
                &owner,
                request.context_id.as_deref(),
                request.idempotency_key.as_deref(),
            )
            .map_err(store_error)?;
        Ok(ActionExecutionResult {
            result: Some(serde_json::to_value(status).map_err(|error| {
                ActionError::internal(format!("serialize context status: {error}"))
            })?),
            stream: None,
            anchor_ref: Some(LLM_CONTEXT_STATUS_RESPONSE_ANCHOR.into()),
            token_est: 0,
        })
    }

    fn release(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        let request: LlmContextReleaseRequestDto = decode_params(frame, LLM_CONTEXT_RELEASE)?;
        let owner = self.owner(context)?;
        let receipt = self
            .store
            .release(
                &owner,
                &request.context_id,
                request.base_version,
                frame.idempotency_key.as_deref().unwrap_or_default(),
            )
            .map_err(store_error)?;
        Ok(ActionExecutionResult {
            result: Some(serde_json::to_value(receipt).map_err(|error| {
                ActionError::internal(format!("serialize context release: {error}"))
            })?),
            stream: None,
            anchor_ref: Some(LLM_CONTEXT_RELEASE_RESPONSE_ANCHOR.into()),
            token_est: 0,
        })
    }
}

impl ActionNodeProvider for StatefulLlmActionProvider {
    fn authorize(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<(), ActionError> {
        self.inner.authorize(frame, context)?;
        let needs_context_auth = match frame.action_id.as_str() {
            LLM_CONTEXT_STATUS | LLM_CONTEXT_RELEASE => true,
            LLM_COMPLETE => frame
                .params
                .as_ref()
                .and_then(Value::as_object)
                .is_some_and(|params| params.get("context").is_some_and(|value| !value.is_null())),
            _ => false,
        };
        if !needs_context_auth {
            return Ok(());
        }
        let owner = self.owner(context)?;
        self.check_authorization(
            &owner,
            &frame.action_id,
            LlmAuthorizationStage::Admission,
            &required_capabilities(frame),
            context,
        )
    }

    fn execute(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        match frame.action_id.as_str() {
            LLM_COMPLETE => self.complete(frame, context),
            LLM_CONTEXT_STATUS => self.status(frame, context),
            LLM_CONTEXT_RELEASE => self.release(frame, context),
            _ => self.inner.execute(frame, context),
        }
    }
}

fn required_capabilities(frame: &ParsedActionFrame) -> Vec<String> {
    if matches!(
        frame.action_id.as_str(),
        LLM_CONTEXT_STATUS | LLM_CONTEXT_RELEASE
    ) {
        return vec![CAPABILITY_LLM_CONTEXT.into()];
    }
    let mut capabilities = vec![
        CAPABILITY_LLM_COMPLETE.into(),
        CAPABILITY_LLM_CONTEXT.into(),
    ];
    if let Some(params) = frame.params.as_ref().and_then(Value::as_object) {
        if params.get("stream").and_then(Value::as_bool) == Some(true) {
            capabilities.push(CAPABILITY_LLM_STREAM.into());
        }
        if params
            .get("tools")
            .and_then(Value::as_array)
            .is_some_and(|tools| !tools.is_empty())
        {
            capabilities.push(CAPABILITY_LLM_TOOL_CALL.into());
        }
    }
    capabilities
}

const RESERVATION_ACTIVE: u8 = 0;
const RESERVATION_COMMITTING: u8 = 1;
const RESERVATION_ABORTED: u8 = 2;
const RESERVATION_COMMITTED: u8 = 3;

#[derive(Clone)]
struct ReservationGuard {
    store: Arc<InMemoryLlmContextStore>,
    reservation: LlmContextMutationReservation,
    state: Arc<AtomicU8>,
}

impl ReservationGuard {
    fn new(
        store: Arc<InMemoryLlmContextStore>,
        reservation: LlmContextMutationReservation,
    ) -> Self {
        Self {
            store,
            reservation,
            state: Arc::new(AtomicU8::new(RESERVATION_ACTIVE)),
        }
    }

    fn abort(&self, error_code: &str) {
        if self
            .state
            .compare_exchange(
                RESERVATION_ACTIVE,
                RESERVATION_ABORTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            let _ = self.store.abort(&self.reservation, Some(error_code));
        }
    }

    fn commit(
        &self,
        assistant: LlmMessageDto,
    ) -> Result<crate::llm::LlmContextReceiptDto, ActionError> {
        self.state
            .compare_exchange(
                RESERVATION_ACTIVE,
                RESERVATION_COMMITTING,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map_err(|_| ActionError::internal("LLM context reservation is no longer active"))?;
        match self.store.commit(&self.reservation, assistant) {
            Ok(receipt) => {
                self.state.store(RESERVATION_COMMITTED, Ordering::Release);
                Ok(receipt)
            }
            Err(error) => {
                let _ = self.store.abort(&self.reservation, Some(&error.error_code));
                self.state.store(RESERVATION_ABORTED, Ordering::Release);
                Err(store_error(error))
            }
        }
    }
}

fn decode_params<T: serde::de::DeserializeOwned>(
    frame: &ParsedActionFrame,
    action: &str,
) -> Result<T, ActionError> {
    let value = frame
        .params
        .clone()
        .ok_or_else(|| params_error(&format!("{action} requires params")))?;
    serde_json::from_value(value)
        .map_err(|error| params_error(&format!("invalid {action} params: {error}")))
}

fn params_error(message: &str) -> ActionError {
    ActionError {
        http_status: 422,
        nps_status: nps_core::status_codes::NPS_CLIENT_UNPROCESSABLE.into(),
        error_code: error_codes::ACTION_PARAMS_INVALID.into(),
        message: message.into(),
    }
}

fn store_error(error: LlmContextStoreError) -> ActionError {
    let nps_status = error_codes::to_nps_status(&error.error_code);
    ActionError {
        http_status: nps_core::status_codes::to_http_status(nps_status).unwrap_or(500),
        nps_status: nps_status.into(),
        error_code: error.error_code,
        message: error.message,
    }
}
