// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;

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
            BackoffStrategy::Fixed       => base_ms,
            BackoffStrategy::Linear      => base_ms * (attempt as u64 + 1),
            BackoffStrategy::Exponential => base_ms * (1u64 << attempt),
        };
        raw.min(max_ms)
    }
}

// ── TaskState ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl TaskState {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending"   => Some(TaskState::Pending),
            "running"   => Some(TaskState::Running),
            "completed" => Some(TaskState::Completed),
            "failed"    => Some(TaskState::Failed),
            "cancelled" => Some(TaskState::Cancelled),
            _           => None,
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, TaskState::Completed | TaskState::Failed | TaskState::Cancelled)
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
        self.raw.get("task_id").and_then(Value::as_str).unwrap_or("")
    }

    pub fn state(&self) -> Option<TaskState> {
        self.raw.get("state").and_then(Value::as_str)
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
        write!(f, "NopTaskStatus(task_id={}, state={:?})", self.task_id(), self.state())
    }
}
