// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Result types returned by the orchestrator (NPS-5 §5). Faithful port of the
//! .NET `NopTaskResult` and `SagaCompensationResult`.

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

use crate::error_codes;
use crate::models::TaskState;

/// Summary of the Saga compensation run (NPS-5 §3.5).
#[derive(Debug, Clone, Serialize)]
pub struct SagaCompensationResult {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub failed_node_ids: Vec<String>,
}

impl SagaCompensationResult {
    pub fn new(
        attempted: usize,
        succeeded: usize,
        failed: usize,
        failed_node_ids: Vec<String>,
    ) -> Self {
        SagaCompensationResult {
            attempted,
            succeeded,
            failed,
            failed_node_ids,
        }
    }
}

/// Final result returned by [`crate::orchestrator::NopOrchestrator::execute`] (NPS-5 §5).
#[derive(Debug, Clone, Serialize)]
pub struct NopTaskResult {
    pub task_id: String,
    #[serde(serialize_with = "serialize_state")]
    pub final_state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregated_result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    pub node_results: HashMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensation: Option<SagaCompensationResult>,
}

fn serialize_state<S: serde::Serializer>(state: &TaskState, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(state.as_str())
}

impl NopTaskResult {
    pub fn success(
        task_id: impl Into<String>,
        aggregated_result: Option<Value>,
        node_results: HashMap<String, Value>,
        compensation: Option<SagaCompensationResult>,
    ) -> Self {
        NopTaskResult {
            task_id: task_id.into(),
            final_state: TaskState::Completed,
            aggregated_result,
            error_code: None,
            error_message: None,
            node_results,
            compensation,
        }
    }

    pub fn failure(
        task_id: impl Into<String>,
        error_code: impl Into<String>,
        error_message: impl Into<String>,
        compensation: Option<SagaCompensationResult>,
    ) -> Self {
        NopTaskResult {
            task_id: task_id.into(),
            final_state: TaskState::Failed,
            aggregated_result: None,
            error_code: Some(error_code.into()),
            error_message: Some(error_message.into()),
            node_results: HashMap::new(),
            compensation,
        }
    }

    pub fn cancelled(task_id: impl Into<String>, reason: impl Into<String>) -> Self {
        NopTaskResult {
            task_id: task_id.into(),
            final_state: TaskState::Cancelled,
            aggregated_result: None,
            error_code: Some(error_codes::TASK_CANCELLED.to_string()),
            error_message: Some(reason.into()),
            node_results: HashMap::new(),
            compensation: None,
        }
    }
}
