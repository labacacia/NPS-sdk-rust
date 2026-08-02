// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── compensation_policy constants ────────────────────────────────────────────

pub mod compensation_policy {
    /// Run compensation for completed predecessors when the task fails;
    /// compensation failures are reported but do not stop remaining compensation.
    pub const BEST_EFFORT: &str = "best_effort";
    /// Run compensation for completed predecessors when the task fails;
    /// missing or failed compensation is terminal.
    pub const STRICT: &str = "strict";
    /// Legacy alias: no saga rollback. Not a NPS-5 wire value.
    pub const NONE: &str = "none";
    /// Legacy alias for [`BEST_EFFORT`].
    pub const ON_FAILURE: &str = "on_failure";
    /// Non-standard extension: run compensation after both success and failure.
    pub const ALWAYS: &str = "always";

    /// Returns true when the policy runs compensation after a task failure.
    pub fn runs_on_failure(policy: Option<&str>) -> bool {
        matches!(policy, Some(BEST_EFFORT | STRICT | ON_FAILURE | ALWAYS))
    }

    /// Returns true when the policy runs compensation after a successful task.
    pub fn runs_on_success(policy: Option<&str>) -> bool {
        policy == Some(ALWAYS)
    }

    /// Returns true when any missing or failed compensation step is terminal.
    pub fn is_strict(policy: Option<&str>) -> bool {
        policy == Some(STRICT)
    }
}

// ── aggregate_strategy constants ──────────────────────────────────────────────

pub mod aggregate_strategy {
    pub const MERGE: &str = "merge";
    pub const FIRST: &str = "first";
    pub const ALL: &str = "all";
    pub const FASTEST_K: &str = "fastest_k";
    pub const WEIGHTED_FIRST_K: &str = "weighted_first_k";
    pub const MERGE_ALL: &str = "merge_all";
}

// ── task_priority constants ────────────────────────────────────────────────────

pub mod task_priority {
    pub const LOW: &str = "low";
    pub const NORMAL: &str = "normal";
    pub const HIGH: &str = "high";
}

// ── backoff_strategy constants ─────────────────────────────────────────────────

pub mod backoff_strategy {
    pub const FIXED: &str = "fixed";
    pub const LINEAR: &str = "linear";
    pub const EXPONENTIAL: &str = "exponential";
}

// ── DagNode ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub id: String,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_nid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inputs: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensate_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compensate_params_mapping: Option<serde_json::Map<String, Value>>,
}

// ── BackoffStrategy ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffStrategy {
    Fixed,
    Linear,
    Exponential,
}

impl BackoffStrategy {
    /// Compute retry delay in milliseconds.
    pub fn compute_delay_ms(self, base_ms: u64, max_ms: u64, attempt: u32) -> u64 {
        let raw = match self {
            BackoffStrategy::Fixed => base_ms,
            BackoffStrategy::Linear => base_ms * (attempt as u64 + 1),
            BackoffStrategy::Exponential => base_ms * (1u64 << attempt),
        };
        raw.min(max_ms)
    }
}

// ── TaskState ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Preflight,
    Running,
    WaitingSync,
    Completed,
    Failed,
    Cancelled,
    Skipped,
    /// Saga rollback in progress — compensation actions are being dispatched.
    Compensating,
    /// Saga rollback complete — all compensation actions have been dispatched.
    Compensated,
}

impl TaskState {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(TaskState::Pending),
            "preflight" => Some(TaskState::Preflight),
            "running" => Some(TaskState::Running),
            "waiting_sync" => Some(TaskState::WaitingSync),
            "completed" => Some(TaskState::Completed),
            "failed" => Some(TaskState::Failed),
            "cancelled" => Some(TaskState::Cancelled),
            "skipped" => Some(TaskState::Skipped),
            "compensating" => Some(TaskState::Compensating),
            "compensated" => Some(TaskState::Compensated),
            _ => None,
        }
    }

    /// Snake-case wire representation.
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Pending => "pending",
            TaskState::Preflight => "preflight",
            TaskState::Running => "running",
            TaskState::WaitingSync => "waiting_sync",
            TaskState::Completed => "completed",
            TaskState::Failed => "failed",
            TaskState::Cancelled => "cancelled",
            TaskState::Skipped => "skipped",
            TaskState::Compensating => "compensating",
            TaskState::Compensated => "compensated",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskState::Completed
                | TaskState::Failed
                | TaskState::Cancelled
                | TaskState::Compensated
        )
    }
}

// ── NopTaskStatus ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NopTaskStatus {
    raw: serde_json::Map<String, Value>,
}

impl NopTaskStatus {
    pub fn from_dict(raw: serde_json::Map<String, Value>) -> Self {
        NopTaskStatus { raw }
    }

    pub fn task_id(&self) -> &str {
        self.raw
            .get("task_id")
            .and_then(Value::as_str)
            .unwrap_or("")
    }

    pub fn state(&self) -> Option<TaskState> {
        self.raw
            .get("state")
            .and_then(Value::as_str)
            .and_then(TaskState::from_str)
    }

    pub fn is_terminal(&self) -> bool {
        self.state().map(TaskState::is_terminal).unwrap_or(false)
    }

    pub fn error_code(&self) -> Option<&str> {
        self.raw.get("error_code").and_then(Value::as_str)
    }

    pub fn error_message(&self) -> Option<&str> {
        self.raw.get("error_message").and_then(Value::as_str)
    }

    pub fn node_results(&self) -> Option<&serde_json::Map<String, Value>> {
        self.raw.get("node_results").and_then(Value::as_object)
    }

    pub fn raw(&self) -> &serde_json::Map<String, Value> {
        &self.raw
    }
}

impl std::fmt::Display for NopTaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "NopTaskStatus(task_id={}, state={:?})",
            self.task_id(),
            self.state()
        )
    }
}
