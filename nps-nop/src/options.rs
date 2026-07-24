// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Configuration options for the orchestrator. Faithful port of the .NET
//! `NopOrchestratorOptions`.

use crate::models::aggregate_strategy;

/// Configuration options for [`crate::orchestrator::NopOrchestrator`].
#[derive(Debug, Clone)]
pub struct NopOrchestratorOptions {
    /// Maximum number of DAG nodes that may execute concurrently per task.
    pub max_concurrent_nodes: usize,
    /// When true, validate `AlignStreamFrame.sender_nid` against the node agent
    /// NID for every received frame.
    pub validate_sender_nid: bool,
    /// When true, POST the result to `callback_url` on completion.
    pub enable_callback: bool,
    /// HTTP client timeout for callback POST requests (milliseconds).
    pub callback_timeout_ms: u64,
    /// Base delay for exponential backoff between callback retry attempts.
    /// Set to 0 in tests to avoid real delays.
    pub callback_retry_base_delay_ms: u64,
    /// Default aggregate strategy applied to terminal nodes.
    pub default_aggregate_strategy: String,
}

impl Default for NopOrchestratorOptions {
    fn default() -> Self {
        let cpus = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        NopOrchestratorOptions {
            max_concurrent_nodes: cpus * 2,
            validate_sender_nid: true,
            enable_callback: true,
            callback_timeout_ms: 10_000,
            callback_retry_base_delay_ms: 1000,
            default_aggregate_strategy: aggregate_strategy::MERGE.to_string(),
        }
    }
}
