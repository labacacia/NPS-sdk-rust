// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS Neural Orchestration Protocol (NOP) — client frames plus the full
//! orchestration engine (DAG execution, K-of-N sync, retries, saga
//! compensation, callbacks). Ported to functional parity with the .NET
//! reference `NPS.NOP`.

pub mod aggregator;
pub mod callback;
pub mod client;
pub mod cluster_delegation;
pub mod condition;
pub mod constants;
pub mod error_codes;
pub mod frames;
pub mod input_mapper;
pub mod models;
pub mod options;
pub mod orch_models;
pub mod orchestrator;
pub mod portable_profile;
pub mod result;
pub mod store;
pub mod telemetry;
pub mod validation;
pub mod worker;

// ── Telemetry ─────────────────────────────────────────────────────────────────
pub use telemetry::NopTelemetry;

// ── Client (submit/poll) ──────────────────────────────────────────────────────
pub use client::NopClient;
pub use cluster_delegation::{ClusterAnchorInfo, ClusterDelegationResolver};

// ── Wire frames (client-facing) ───────────────────────────────────────────────
pub use frames::{AlignStreamFrame, DelegateFrame, SyncFrame, TaskFrame};

// ── Model constants / enums ───────────────────────────────────────────────────
pub use models::{aggregate_strategy, backoff_strategy, compensation_policy, task_priority};
pub use models::{BackoffStrategy, NopTaskStatus, TaskState};

// ── Orchestration engine ──────────────────────────────────────────────────────
pub use options::NopOrchestratorOptions;
pub use orch_models::{
    AlignStreamFrame as OrchAlignStreamFrame, DagEdge, DagNode as OrchDagNode,
    DelegateFrame as OrchDelegateFrame, RetryPolicy, StreamError, TaskContext, TaskDag,
    TaskFrame as OrchTaskFrame,
};
pub use orchestrator::NopOrchestrator;
pub use portable_profile::{compute_dedup_key, evaluate_orchestration, evaluate_runtime};
pub use result::{NopTaskResult, SagaCompensationResult};
pub use store::{
    InMemoryNopTaskStore, NopSubtaskRecord, NopTaskRecord, NopTaskStore, SubtaskUpdate,
};
pub use validation::{validate_callback_url, validate_dag, DagValidationResult};
pub use worker::{NopWorkerClient, PreflightResult};
