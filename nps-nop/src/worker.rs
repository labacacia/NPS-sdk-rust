// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Worker-client abstraction for dispatching `DelegateFrame`s to Worker Agents
//! and receiving `AlignStreamFrame` results (NPS-5 §3.2, §3.4). Faithful port of
//! the .NET `INopWorkerClient`, modelling Delegate streaming as a boxed async
//! stream of frames plus a Preflight probe.

use futures::stream::BoxStream;

use crate::orch_models::{AlignStreamFrame, DelegateFrame};

/// Result returned by a Worker Agent in response to a preflight probe (NPS-5 §4.3).
#[derive(Debug, Clone)]
pub struct PreflightResult {
    /// NID of the responding Worker Agent.
    pub agent_nid: String,
    /// True when the agent can accept the delegated workload.
    pub available: bool,
    /// CGN budget the agent can commit. `None` when unavailable.
    pub available_cgn: Option<i64>,
    /// Estimated queue depth in milliseconds. `None` when unavailable.
    pub estimated_queue_ms: Option<i32>,
    /// Capability identifiers the agent supports.
    pub capabilities: Option<Vec<String>>,
    /// Human-readable reason when `available` is false.
    pub unavailable_reason: Option<String>,
}

impl PreflightResult {
    pub fn available(agent_nid: impl Into<String>) -> Self {
        PreflightResult {
            agent_nid: agent_nid.into(),
            available: true,
            available_cgn: None,
            estimated_queue_ms: None,
            capabilities: None,
            unavailable_reason: None,
        }
    }

    pub fn unavailable(agent_nid: impl Into<String>, reason: impl Into<String>) -> Self {
        PreflightResult {
            agent_nid: agent_nid.into(),
            available: false,
            available_cgn: None,
            estimated_queue_ms: None,
            capabilities: None,
            unavailable_reason: Some(reason.into()),
        }
    }
}

/// Abstraction for dispatching `DelegateFrame`s to Worker Agents and receiving
/// `AlignStreamFrame` results. Implement this to connect the orchestrator to
/// real agents (HTTP/NWP, in-process, or a mock in tests).
pub trait NopWorkerClient: Send + Sync {
    /// Dispatches a `DelegateFrame` and returns a stream of `AlignStreamFrame`
    /// messages. The final frame has `is_final == true`.
    fn delegate(&self, frame: DelegateFrame) -> BoxStream<'static, AlignStreamFrame>;

    /// Sends a lightweight preflight probe to confirm resource availability
    /// before committing to full execution (NPS-5 §4).
    fn preflight<'a>(
        &'a self,
        agent_nid: String,
        action: String,
        estimated_npt: i64,
        required_capabilities: Option<Vec<String>>,
    ) -> futures::future::BoxFuture<'a, PreflightResult>;
}
