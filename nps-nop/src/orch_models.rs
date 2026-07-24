// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Typed models for the NOP orchestration engine (faithful port of the .NET
//! `NPS.NOP.Models` and `NPS.NOP.Frames` types used by `NopOrchestrator`).
//!
//! These are distinct from the lightweight client-facing frames in
//! [`crate::frames`], which are kept for the submit/poll `NopClient`.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::constants;
use crate::models::backoff_strategy;

// ── RetryPolicy ─────────────────────────────────────────────────────────────

/// Per-node retry policy (NPS-5 §3.1.4).
/// Delay formula: `min(initial_delay_ms * factor^attempt, max_delay_ms)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicy {
    /// Maximum retry attempts. Overrides `TaskFrame.max_retries` for this node.
    #[serde(default)]
    pub max_retries: u8,
    /// Backoff strategy: `"fixed"`, `"linear"`, or `"exponential"` (default).
    #[serde(default = "default_backoff")]
    pub backoff: String,
    /// Initial retry delay in milliseconds. Default 1000.
    #[serde(default = "default_initial_delay")]
    pub initial_delay_ms: u32,
    /// Maximum delay cap in milliseconds. Default 30000.
    #[serde(default = "default_max_delay")]
    pub max_delay_ms: u32,
    /// Error codes that trigger retry. `None` means retry on all failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_on: Option<Vec<String>>,
}

fn default_backoff() -> String {
    backoff_strategy::EXPONENTIAL.to_string()
}
fn default_initial_delay() -> u32 {
    1000
}
fn default_max_delay() -> u32 {
    30_000
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_retries: 0,
            backoff: default_backoff(),
            initial_delay_ms: default_initial_delay(),
            max_delay_ms: default_max_delay(),
            retry_on: None,
        }
    }
}

impl RetryPolicy {
    /// Computes the delay for a given attempt number (0-based).
    pub fn compute_delay_ms(&self, attempt: u32) -> u32 {
        let factor: f64 = match self.backoff.as_str() {
            backoff_strategy::FIXED => 1.0,
            backoff_strategy::LINEAR => (attempt + 1) as f64,
            _ => 2f64.powi(attempt as i32),
        };
        let delay = (self.initial_delay_ms as f64 * factor).min(self.max_delay_ms as f64);
        delay as u32
    }
}

// ── DagNode / DagEdge / TaskDag ─────────────────────────────────────────────

/// A single node (vertex) in a task DAG (NPS-5 §3.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagNode {
    /// Node unique identifier (unique within the DAG).
    pub id: String,
    /// Operation URL (`nwp://...`).
    pub action: String,
    /// Worker Agent NID that executes this node.
    pub agent: String,
    /// Upstream node IDs this node depends on. Empty/None for start nodes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_from: Option<Vec<String>>,
    /// Upstream output → local input parameter mapping using JSONPath (NPS-5 §3.1.3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_mapping: Option<HashMap<String, Value>>,
    /// Per-node timeout in milliseconds. Overrides `TaskFrame.timeout_ms`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u32>,
    /// Per-node retry strategy (NPS-5 §3.1.4).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_policy: Option<RetryPolicy>,
    /// CEL subset condition expression. When false, the node is skipped (NPS-5 §3.1.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// K-of-N: minimum number of `input_from` deps that must succeed before dispatch.
    /// 0 or omitted means all deps must succeed (NPS-5 §3.3.1).
    #[serde(default)]
    pub min_required: u32,
    /// Saga compensation action URL (`nwp://...`) called on rollback (NPS-5 §3.5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensate_action: Option<String>,
    /// Parameter mapping for the compensation call (same syntax as `input_mapping`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compensate_params_mapping: Option<HashMap<String, Value>>,
}

/// A directed edge in a task DAG (NPS-5 §3.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DagEdge {
    /// Source node ID.
    pub from: String,
    /// Target node ID.
    pub to: String,
}

/// DAG (Directed Acyclic Graph) definition for a TaskFrame (NPS-5 §3.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDag {
    /// DAG vertices — each represents a sub-task to execute.
    pub nodes: Vec<DagNode>,
    /// Directed edges defining execution order and data flow.
    #[serde(default)]
    pub edges: Vec<DagEdge>,
}

// ── TaskContext ─────────────────────────────────────────────────────────────

/// Transparent context carried across all sub-tasks (NPS-5 §3.1.2).
/// Supports OpenTelemetry W3C TraceContext for distributed tracing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// OpenTelemetry Trace ID (16 bytes hex, 32 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Current Span ID (8 bytes hex, 16 characters).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    /// OpenTelemetry Trace Flags (e.g. 0x01 = sampled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_flags: Option<u8>,
    /// OpenTelemetry Baggage key-value pairs, propagated to all sub-tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baggage: Option<HashMap<String, String>>,
    /// Application-defined context. NOP does not inspect this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom: Option<Value>,
}

// ── StreamError ─────────────────────────────────────────────────────────────

/// Error payload carried by an AlignStream final frame (NPS-5 §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamError {
    /// NOP error code (e.g. `NOP-TASK-TIMEOUT`).
    pub code: String,
    /// Human-readable error description.
    pub message: String,
    /// Whether the caller may retry this operation.
    #[serde(default)]
    pub retryable: bool,
}

// ── TaskFrame (typed, orchestrator input) ───────────────────────────────────

/// Task definition frame consumed by the orchestrator (NPS-5 §3.1).
/// Distinct from the wire-oriented [`crate::frames::TaskFrame`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskFrame {
    pub task_id: String,
    pub dag: TaskDag,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_max_retries")]
    pub max_retries: u8,
    #[serde(default = "default_priority")]
    pub priority: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_secret: Option<String>,
    #[serde(default)]
    pub preflight: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<TaskContext>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default)]
    pub delegate_depth: i64,
    #[serde(default = "default_compensation_policy")]
    pub compensation_policy: String,
}

fn default_timeout() -> u64 {
    constants::DEFAULT_TIMEOUT_MS
}
fn default_max_retries() -> u8 {
    2
}
fn default_priority() -> String {
    crate::models::task_priority::NORMAL.to_string()
}
fn default_compensation_policy() -> String {
    crate::models::compensation_policy::BEST_EFFORT.to_string()
}

impl TaskFrame {
    /// Builds a minimal task frame with defaults.
    pub fn new(task_id: impl Into<String>, dag: TaskDag) -> Self {
        TaskFrame {
            task_id: task_id.into(),
            dag,
            timeout_ms: default_timeout(),
            max_retries: default_max_retries(),
            priority: default_priority(),
            callback_url: None,
            callback_secret: None,
            preflight: false,
            context: None,
            request_id: None,
            delegate_depth: 0,
            compensation_policy: default_compensation_policy(),
        }
    }
}

// ── DelegateFrame (typed) ───────────────────────────────────────────────────

/// Sub-task delegation frame produced by the orchestrator per DAG node (NPS-5 §3.2).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegateFrame {
    pub parent_task_id: String,
    pub subtask_id: String,
    pub node_id: String,
    pub target_agent_nid: String,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    pub delegated_scope: Value,
    pub deadline_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<TaskContext>,
    #[serde(default)]
    pub delegate_depth: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_cluster_anchor: Option<String>,
}

// ── AlignStreamFrame (typed) ────────────────────────────────────────────────

/// Directed task stream frame carrying intermediate/final results (NPS-5 §3.4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlignStreamFrame {
    pub stream_id: String,
    pub task_id: String,
    pub subtask_id: String,
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_size: Option<u32>,
    pub is_final: bool,
    pub sender_nid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<StreamError>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nak_seq: Option<u64>,
}

impl AlignStreamFrame {
    /// Convenience constructor for a successful final frame.
    pub fn final_ok(
        task_id: impl Into<String>,
        subtask_id: impl Into<String>,
        sender_nid: impl Into<String>,
        seq: u64,
        data: Option<Value>,
    ) -> Self {
        AlignStreamFrame {
            stream_id: String::new(),
            task_id: task_id.into(),
            subtask_id: subtask_id.into(),
            seq,
            payload_ref: None,
            data,
            window_size: None,
            is_final: true,
            sender_nid: sender_nid.into(),
            error: None,
            ack_seq: None,
            nak_seq: None,
        }
    }

    /// Convenience constructor for a failed final frame.
    pub fn final_err(
        task_id: impl Into<String>,
        subtask_id: impl Into<String>,
        sender_nid: impl Into<String>,
        seq: u64,
        error: StreamError,
    ) -> Self {
        AlignStreamFrame {
            stream_id: String::new(),
            task_id: task_id.into(),
            subtask_id: subtask_id.into(),
            seq,
            payload_ref: None,
            data: None,
            window_size: None,
            is_final: true,
            sender_nid: sender_nid.into(),
            error: Some(error),
            ack_seq: None,
            nak_seq: None,
        }
    }
}
