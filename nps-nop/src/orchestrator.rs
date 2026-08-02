// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Core NOP Orchestrator: accepts a [`TaskFrame`], runs its DAG by dispatching
//! [`DelegateFrame`]s to Worker Agents, handles retries, condition-based
//! skipping, K-of-N sync, saga compensation, and result aggregation
//! (NPS-5 §3, §5). Faithful port of the .NET `NopOrchestrator`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::stream::{FuturesUnordered, StreamExt};
use serde_json::{json, Value};

use crate::aggregator;
use crate::callback;
use crate::condition;
use crate::constants;
use crate::error_codes;
use crate::input_mapper;
use crate::models::{compensation_policy, TaskState};
use crate::options::NopOrchestratorOptions;
use crate::orch_models::{
    AlignStreamFrame, DagEdge, DagNode, DelegateFrame, TaskContext, TaskFrame,
};
use crate::result::{NopTaskResult, SagaCompensationResult};
use crate::store::{NopTaskRecord, NopTaskStore, SubtaskUpdate};
use crate::validation::{validate_callback_url, validate_dag};
use crate::worker::NopWorkerClient;

/// Outcome of a single node execution attempt or run.
#[derive(Debug, Clone)]
struct NodeOutcome {
    state: TaskState,
    result: Option<Value>,
    error_code: Option<String>,
    error_message: Option<String>,
}

impl NodeOutcome {
    fn new(state: TaskState, result: Option<Value>, error_code: Option<String>) -> Self {
        NodeOutcome {
            state,
            result,
            error_code,
            error_message: None,
        }
    }
    fn with_msg(
        state: TaskState,
        result: Option<Value>,
        error_code: Option<String>,
        msg: Option<String>,
    ) -> Self {
        NodeOutcome {
            state,
            result,
            error_code,
            error_message: msg,
        }
    }
}

/// Core NOP orchestrator.
pub struct NopOrchestrator<W: NopWorkerClient, S: NopTaskStore> {
    worker: Arc<W>,
    store: Arc<S>,
    opts: NopOrchestratorOptions,
    http: reqwest::Client,
}

impl<W: NopWorkerClient, S: NopTaskStore> NopOrchestrator<W, S> {
    pub fn new(worker: Arc<W>, store: Arc<S>, opts: Option<NopOrchestratorOptions>) -> Self {
        let opts = opts.unwrap_or_default();
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(opts.callback_timeout_ms))
            .build()
            .unwrap_or_default();
        NopOrchestrator {
            worker,
            store,
            opts,
            http,
        }
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Executes the full task lifecycle: validate → (preflight) → run DAG →
    /// aggregate → (callback). Blocks until the task reaches a terminal state.
    pub async fn execute(&self, task: TaskFrame) -> NopTaskResult {
        // 1a. Delegation chain depth.
        if task.delegate_depth >= constants::MAX_DELEGATE_CHAIN_DEPTH {
            return NopTaskResult::failure(
                &task.task_id,
                error_codes::DELEGATE_CHAIN_TOO_DEEP,
                format!(
                    "Delegation chain depth {} exceeds the maximum of {}.",
                    task.delegate_depth,
                    constants::MAX_DELEGATE_CHAIN_DEPTH
                ),
                None,
            );
        }

        // 1b. Callback URL.
        if let Some(url) = &task.callback_url {
            if !url.is_empty() {
                if let Some(err) = validate_callback_url(url) {
                    return NopTaskResult::failure(
                        &task.task_id,
                        error_codes::TASK_DAG_INVALID,
                        err,
                        None,
                    );
                }
            }
        }

        // 1c. Validate DAG.
        let validation = validate_dag(&task.dag);
        if !validation.is_valid {
            return NopTaskResult::failure(
                &task.task_id,
                validation.error_code.unwrap_or_default(),
                validation.error_message.unwrap_or_default(),
                None,
            );
        }
        let topo_order = validation.topological_order.unwrap();

        // 2. Reject duplicate tasks.
        if self.store.get(&task.task_id).await.is_some() {
            return NopTaskResult::failure(
                &task.task_id,
                error_codes::TASK_ALREADY_COMPLETED,
                format!("Task '{}' already exists.", task.task_id),
                None,
            );
        }

        // 3. Persist initial record.
        let record = NopTaskRecord {
            task_id: task.task_id.clone(),
            frame: task.clone(),
            state: TaskState::Pending,
            started_at_ms: now_ms(),
            completed_at_ms: None,
            subtasks: HashMap::new(),
        };
        let _ = self.store.save(record).await;

        // 4. Timeout = min(task.timeout_ms, MaxTimeoutMs).
        let timeout_ms = task.timeout_ms.min(constants::MAX_TIMEOUT_MS);

        let run = self.run_lifecycle(&task, &topo_order);
        match tokio::time::timeout(Duration::from_millis(timeout_ms), run).await {
            Ok(result) => result,
            Err(_) => {
                // Our own timeout fired.
                self.store
                    .update_state(&task.task_id, TaskState::Failed)
                    .await;
                NopTaskResult::failure(
                    &task.task_id,
                    error_codes::TASK_TIMEOUT,
                    format!("Task exceeded timeout of {timeout_ms}ms."),
                    None,
                )
            }
        }
    }

    /// Requests cancellation of a running task (records `Cancelled` state).
    /// In-flight subtasks are abandoned by the caller dropping the future.
    pub async fn cancel(&self, task_id: &str) {
        self.store.update_state(task_id, TaskState::Cancelled).await;
    }

    /// Returns the current status of a task, or `None` if not found.
    pub async fn get_status(&self, task_id: &str) -> Option<NopTaskRecord> {
        self.store.get(task_id).await
    }

    // ── Lifecycle (preflight → run DAG → finalise → callback) ────────────────

    async fn run_lifecycle(&self, task: &TaskFrame, topo_order: &[String]) -> NopTaskResult {
        // 5. Optional preflight.
        if task.preflight {
            self.store
                .update_state(&task.task_id, TaskState::Preflight)
                .await;
            if let Some(fail) = self.run_preflight(task).await {
                self.store
                    .update_state(&task.task_id, TaskState::Failed)
                    .await;
                return NopTaskResult::failure(
                    &task.task_id,
                    error_codes::RESOURCE_INSUFFICIENT,
                    fail,
                    None,
                );
            }
        }

        self.store
            .update_state(&task.task_id, TaskState::Running)
            .await;

        // 6. Execute DAG.
        let result = self.run_dag(task, topo_order).await;

        // 7. Finalise state.
        self.store
            .update_state(&task.task_id, result.final_state)
            .await;

        // 8. Fire callback (fire-and-forget style; awaited but non-fatal).
        if self.opts.enable_callback {
            if let Some(url) = &task.callback_url {
                if !url.is_empty() {
                    let payload = serde_json::to_string(&result).unwrap_or_else(|_| "{}".into());
                    callback::fire_callback(
                        &self.http,
                        url,
                        task.callback_secret.as_deref(),
                        &payload,
                        self.opts.callback_retry_base_delay_ms,
                    )
                    .await;
                }
            }
        }

        result
    }

    // ── DAG execution ───────────────────────────────────────────────────────

    async fn run_dag(&self, task: &TaskFrame, topo_order: &[String]) -> NopTaskResult {
        let all_nodes: HashMap<String, DagNode> = task
            .dag
            .nodes
            .iter()
            .map(|n| (n.id.clone(), n.clone()))
            .collect();

        let mut node_results: HashMap<String, Value> = HashMap::new();
        let mut node_states: HashMap<String, TaskState> = HashMap::new();

        // Identify end nodes (no outgoing edges).
        let has_outgoing: HashSet<&str> = task.dag.edges.iter().map(|e| e.from.as_str()).collect();
        let end_node_ids: Vec<String> = all_nodes
            .keys()
            .filter(|id| !has_outgoing.contains(id.as_str()))
            .cloned()
            .collect();

        // FuturesUnordered of (node_id, outcome).
        let mut in_flight: FuturesUnordered<_> = FuturesUnordered::new();
        let mut in_flight_ids: HashSet<String> = HashSet::new();

        while node_states.len() < all_nodes.len() {
            // Find ready nodes (deps done, not started).
            let mut ready: Vec<DagNode> = task
                .dag
                .nodes
                .iter()
                .filter(|n| !node_states.contains_key(&n.id) && !in_flight_ids.contains(&n.id))
                .filter(|n| are_deps_done(n, &node_states))
                .cloned()
                .collect();

            // K-of-N: fail nodes whose K can never be satisfied.
            let mut i = 0;
            while i < ready.len() {
                let n = &ready[i];
                let has_deps = n
                    .input_from
                    .as_ref()
                    .map(|d| !d.is_empty())
                    .unwrap_or(false);
                if !has_deps {
                    i += 1;
                    continue;
                }
                let deps = n.input_from.as_ref().unwrap();
                let total = deps.len();
                let k = if n.min_required > 0 {
                    n.min_required as usize
                } else {
                    total
                };
                let success = deps
                    .iter()
                    .filter(|d| {
                        matches!(
                            node_states.get(*d),
                            Some(TaskState::Completed) | Some(TaskState::Skipped)
                        )
                    })
                    .count();
                if success < k {
                    let node_id = n.id.clone();
                    node_states.insert(node_id.clone(), TaskState::Failed);
                    self.store
                        .update_subtask(
                            &task.task_id,
                            &node_id,
                            &new_uuid(),
                            TaskState::Failed,
                            SubtaskUpdate {
                                error_code: Some(error_codes::SYNC_DEPENDENCY_FAILED.to_string()),
                                error_message: Some(format!(
                                    "Only {success}/{k} required dependencies succeeded."
                                )),
                                attempt: 1,
                                ..Default::default()
                            },
                        )
                        .await;
                    ready.remove(i);
                } else {
                    i += 1;
                }
            }

            // Launch ready nodes up to max_concurrent_nodes.
            for node in ready {
                if in_flight_ids.len() >= self.opts.max_concurrent_nodes {
                    break;
                }
                let ctx_snapshot = node_results.clone();
                let node_id = node.id.clone();
                in_flight_ids.insert(node_id.clone());
                in_flight.push(async move {
                    let outcome = self
                        .execute_node_with_retry(task, &node, &ctx_snapshot)
                        .await;
                    (node_id, outcome)
                });
            }

            if in_flight.is_empty() {
                break; // stuck or finished
            }

            // Wait for the next completion.
            let (finished_node_id, outcome) = in_flight.next().await.unwrap();
            in_flight_ids.remove(&finished_node_id);

            node_states.insert(finished_node_id.clone(), outcome.state);
            if outcome.state == TaskState::Completed {
                if let Some(r) = &outcome.result {
                    node_results.insert(finished_node_id.clone(), r.clone());
                }
            }

            // On failure, check whether any end node is now unrecoverable.
            if outcome.state == TaskState::Failed {
                let must_abort = end_node_ids.iter().any(|e| {
                    can_reach_end_node(e, &finished_node_id, &task.dag.edges)
                        && !can_end_node_still_succeed(e, &all_nodes, &node_states)
                });

                if must_abort {
                    // Drain remaining in-flight nodes (they were already spawned).
                    while in_flight.next().await.is_some() {}
                    let compensation =
                        if compensation_policy::runs_on_failure(Some(&task.compensation_policy)) {
                            Some(
                                self.run_saga_compensation(
                                    task,
                                    &all_nodes,
                                    topo_order,
                                    &node_results,
                                    &node_states,
                                )
                                .await,
                            )
                        } else {
                            None
                        };
                    let error_code = compensation_failure_error_code(task, compensation.as_ref())
                        .unwrap_or_else(|| error_codes::SYNC_DEPENDENCY_FAILED.to_string());
                    return NopTaskResult::failure(
                        &task.task_id,
                        error_code,
                        format!(
                            "Node '{}' failed: {}",
                            finished_node_id,
                            outcome.error_code.clone().unwrap_or_default()
                        ),
                        compensation,
                    );
                }
            }
        }

        // All nodes done — check for end-node failures.
        let failed_nodes: Vec<String> = node_states
            .iter()
            .filter(|(_, &v)| v == TaskState::Failed)
            .map(|(k, _)| k.clone())
            .collect();
        let end_failed = end_node_ids
            .iter()
            .any(|e| node_states.get(e) == Some(&TaskState::Failed));

        if !failed_nodes.is_empty() && end_failed {
            let compensation =
                if compensation_policy::runs_on_failure(Some(&task.compensation_policy)) {
                    Some(
                        self.run_saga_compensation(
                            task,
                            &all_nodes,
                            topo_order,
                            &node_results,
                            &node_states,
                        )
                        .await,
                    )
                } else {
                    None
                };
            let error_code = compensation_failure_error_code(task, compensation.as_ref())
                .unwrap_or_else(|| error_codes::SYNC_DEPENDENCY_FAILED.to_string());
            let mut failed_sorted = failed_nodes.clone();
            failed_sorted.sort();
            return NopTaskResult::failure(
                &task.task_id,
                error_code,
                format!("End node(s) failed: {}", failed_sorted.join(", ")),
                compensation,
            );
        }

        // Aggregate end-node results.
        let aggregated = aggregator::aggregate_end_nodes(
            &end_node_ids,
            &node_results,
            &self.opts.default_aggregate_strategy,
        );

        let success_compensation =
            if compensation_policy::runs_on_success(Some(&task.compensation_policy)) {
                Some(
                    self.run_saga_compensation(
                        task,
                        &all_nodes,
                        topo_order,
                        &node_results,
                        &node_states,
                    )
                    .await,
                )
            } else {
                None
            };

        NopTaskResult::success(
            &task.task_id,
            Some(aggregated),
            node_results,
            success_compensation,
        )
    }

    // ── Node execution + retry ───────────────────────────────────────────────

    async fn execute_node_with_retry(
        &self,
        task: &TaskFrame,
        node: &DagNode,
        context: &HashMap<String, Value>,
    ) -> NodeOutcome {
        let subtask_id = new_uuid();
        let idempotency_key = new_uuid();
        let max_retries: u8 = node
            .retry_policy
            .as_ref()
            .map(|p| p.max_retries)
            .unwrap_or(task.max_retries);
        let max_retries = max_retries as u32;

        for attempt in 1..=(max_retries + 1) {
            // Evaluate condition once, before the first attempt.
            if attempt == 1 {
                if let Some(cond) = &node.condition {
                    if !cond.is_empty() {
                        match condition::evaluate(cond, context) {
                            Ok(false) => {
                                self.store
                                    .update_subtask(
                                        &task.task_id,
                                        &node.id,
                                        &subtask_id,
                                        TaskState::Skipped,
                                        SubtaskUpdate::default(),
                                    )
                                    .await;
                                return NodeOutcome::new(TaskState::Skipped, None, None);
                            }
                            Ok(true) => {}
                            Err(e) => {
                                self.store
                                    .update_subtask(
                                        &task.task_id,
                                        &node.id,
                                        &subtask_id,
                                        TaskState::Failed,
                                        SubtaskUpdate {
                                            error_code: Some(
                                                error_codes::CONDITION_EVAL_ERROR.to_string(),
                                            ),
                                            error_message: Some(e.message),
                                            attempt: attempt as i32,
                                            ..Default::default()
                                        },
                                    )
                                    .await;
                                return NodeOutcome::new(
                                    TaskState::Failed,
                                    None,
                                    Some(error_codes::CONDITION_EVAL_ERROR.to_string()),
                                );
                            }
                        }
                    }
                }
            }

            self.store
                .update_subtask(
                    &task.task_id,
                    &node.id,
                    &subtask_id,
                    TaskState::Running,
                    SubtaskUpdate {
                        attempt: attempt as i32,
                        ..Default::default()
                    },
                )
                .await;

            let outcome = self
                .execute_node_once(task, node, &subtask_id, &idempotency_key, context)
                .await;

            if outcome.state == TaskState::Completed {
                self.store
                    .update_subtask(
                        &task.task_id,
                        &node.id,
                        &subtask_id,
                        TaskState::Completed,
                        SubtaskUpdate {
                            result: outcome.result.clone(),
                            attempt: attempt as i32,
                            ..Default::default()
                        },
                    )
                    .await;
                return outcome;
            }

            // Failed — retryable?
            let retriable = should_retry(
                node.retry_policy.as_ref(),
                outcome.error_code.as_deref(),
                attempt,
                max_retries,
            );
            if !retriable {
                self.store
                    .update_subtask(
                        &task.task_id,
                        &node.id,
                        &subtask_id,
                        TaskState::Failed,
                        SubtaskUpdate {
                            error_code: outcome.error_code.clone(),
                            error_message: outcome.error_message.clone(),
                            attempt: attempt as i32,
                            ..Default::default()
                        },
                    )
                    .await;
                return outcome;
            }

            let delay_ms = node
                .retry_policy
                .as_ref()
                .map(|p| p.compute_delay_ms(attempt - 1) as u64)
                .unwrap_or(1000);
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }

        // Exhausted retries.
        self.store
            .update_subtask(
                &task.task_id,
                &node.id,
                &subtask_id,
                TaskState::Failed,
                SubtaskUpdate {
                    error_code: Some(error_codes::DELEGATE_TIMEOUT.to_string()),
                    error_message: Some(format!(
                        "Node '{}' exhausted {max_retries} retries.",
                        node.id
                    )),
                    attempt: 0,
                    ..Default::default()
                },
            )
            .await;
        NodeOutcome::new(
            TaskState::Failed,
            None,
            Some(error_codes::DELEGATE_TIMEOUT.to_string()),
        )
    }

    async fn execute_node_once(
        &self,
        task: &TaskFrame,
        node: &DagNode,
        subtask_id: &str,
        idempotency_key: &str,
        context: &HashMap<String, Value>,
    ) -> NodeOutcome {
        // Resolve input_mapping → params.
        let resolved_params = match input_mapper::build_params(node.input_mapping.as_ref(), context)
        {
            Ok(p) => Some(p),
            Err(e) => {
                return NodeOutcome::with_msg(
                    TaskState::Failed,
                    None,
                    Some(e.error_code),
                    Some(e.message),
                )
            }
        };

        let node_timeout_ms = node
            .timeout_ms
            .map(|t| t as u64)
            .unwrap_or(task.timeout_ms)
            .min(constants::MAX_TIMEOUT_MS);
        let deadline = now_ms() + node_timeout_ms as u128;

        // Propagate context (W3C tracecontext passthrough).
        let delegate_ctx = task.context.clone().or(Some(TaskContext::default()));

        let delegate_frame = DelegateFrame {
            parent_task_id: task.task_id.clone(),
            subtask_id: subtask_id.to_string(),
            node_id: node.id.clone(),
            target_agent_nid: node.agent.clone(),
            action: node.action.clone(),
            params: resolved_params,
            delegated_scope: json!({}),
            deadline_at: deadline.to_string(),
            idempotency_key: Some(idempotency_key.to_string()),
            priority: Some(task.priority.clone()),
            context: delegate_ctx,
            delegate_depth: task.delegate_depth + 1,
            target_cluster_anchor: None,
        };

        let stream_fut = async {
            let mut stream = self.worker.delegate(delegate_frame);
            let mut final_result: Option<Value> = None;
            let mut error_code: Option<String> = None;
            let mut error_msg: Option<String> = None;
            let mut last_seq: u64 = 0;
            let mut got_final = false;

            while let Some(frame) = stream.next().await {
                let frame: AlignStreamFrame = frame;

                // Sequence gap check.
                if frame.seq != last_seq && frame.seq != 0 && frame.seq != last_seq + 1 {
                    return NodeOutcome::new(
                        TaskState::Failed,
                        None,
                        Some(error_codes::STREAM_SEQ_GAP.to_string()),
                    );
                }
                last_seq = frame.seq;

                // Sender NID validation.
                if self.opts.validate_sender_nid && frame.sender_nid != node.agent {
                    return NodeOutcome::new(
                        TaskState::Failed,
                        None,
                        Some(error_codes::STREAM_NID_MISMATCH.to_string()),
                    );
                }

                if frame.is_final {
                    got_final = true;
                    if let Some(err) = &frame.error {
                        error_code = Some(err.code.clone());
                        error_msg = Some(err.message.clone());
                    } else {
                        final_result = frame.data.clone();
                    }
                    break;
                }
            }

            if !got_final {
                return NodeOutcome::with_msg(
                    TaskState::Failed,
                    None,
                    Some(error_codes::DELEGATE_TIMEOUT.to_string()),
                    Some("Stream ended without final frame.".to_string()),
                );
            }
            if let Some(code) = error_code {
                return NodeOutcome::with_msg(TaskState::Failed, None, Some(code), error_msg);
            }
            NodeOutcome::new(TaskState::Completed, final_result, None)
        };

        match tokio::time::timeout(Duration::from_millis(node_timeout_ms), stream_fut).await {
            Ok(outcome) => outcome,
            Err(_) => NodeOutcome::with_msg(
                TaskState::Failed,
                None,
                Some(error_codes::DELEGATE_TIMEOUT.to_string()),
                Some(format!(
                    "Node '{}' timed out after {node_timeout_ms}ms.",
                    node.id
                )),
            ),
        }
    }

    // ── Preflight ─────────────────────────────────────────────────────────────

    async fn run_preflight(&self, task: &TaskFrame) -> Option<String> {
        // Deduplicate by agent NID (one probe per unique agent).
        let mut seen: HashSet<String> = HashSet::new();
        let mut unique: Vec<(String, String)> = Vec::new();
        for n in &task.dag.nodes {
            if seen.insert(n.agent.clone()) {
                unique.push((n.agent.clone(), n.action.clone()));
            }
        }

        let mut probes = FuturesUnordered::new();
        for (agent, action) in unique {
            probes.push(self.worker.preflight(agent, action, 0, None));
        }

        while let Some(res) = probes.next().await {
            if !res.available {
                return Some(format!(
                    "Agent '{}' is unavailable: {}",
                    res.agent_nid,
                    res.unavailable_reason
                        .unwrap_or_else(|| "no reason given".to_string())
                ));
            }
        }
        None
    }

    // ── Saga compensation ─────────────────────────────────────────────────────

    async fn run_saga_compensation(
        &self,
        task: &TaskFrame,
        all_nodes: &HashMap<String, DagNode>,
        topo_order: &[String],
        node_results: &HashMap<String, Value>,
        node_states: &HashMap<String, TaskState>,
    ) -> SagaCompensationResult {
        // Completed nodes in reverse topo order.
        let mut completed: Vec<String> = topo_order
            .iter()
            .filter(|id| {
                node_states.get(*id) == Some(&TaskState::Completed) && all_nodes.contains_key(*id)
            })
            .cloned()
            .collect();
        completed.reverse();

        if compensation_policy::is_strict(Some(&task.compensation_policy)) {
            let missing: Vec<String> = completed
                .iter()
                .filter(|id| {
                    all_nodes[*id]
                        .compensate_action
                        .as_ref()
                        .map(|a| a.trim().is_empty())
                        .unwrap_or(true)
                })
                .cloned()
                .collect();
            if !missing.is_empty() {
                let n = missing.len();
                return SagaCompensationResult::new(0, 0, n, missing);
            }
        }

        let to_compensate: Vec<String> = completed
            .iter()
            .filter(|id| {
                all_nodes[*id]
                    .compensate_action
                    .as_ref()
                    .map(|a| !a.trim().is_empty())
                    .unwrap_or(false)
            })
            .cloned()
            .collect();

        if to_compensate.is_empty() {
            return SagaCompensationResult::new(0, 0, 0, Vec::new());
        }

        self.store
            .update_state(&task.task_id, TaskState::Compensating)
            .await;

        let mut succeeded = 0usize;
        let mut failed_ids: Vec<String> = Vec::new();

        for node_id in &to_compensate {
            let node = &all_nodes[node_id];
            let mut compensation_node = node.clone();
            compensation_node.action = node.compensate_action.clone().unwrap();
            compensation_node.input_mapping = node.compensate_params_mapping.clone();

            let outcome = self
                .execute_node_once(
                    task,
                    &compensation_node,
                    &new_uuid(),
                    &new_uuid(),
                    node_results,
                )
                .await;

            if outcome.state == TaskState::Completed {
                succeeded += 1;
            } else {
                failed_ids.push(node_id.clone());
            }
        }

        let failed = failed_ids.len();
        SagaCompensationResult::new(to_compensate.len(), succeeded, failed, failed_ids)
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────────

/// Returns true when a node's dependencies are terminal in a way that allows it
/// to proceed (K-of-N satisfied) or be marked failed (impossible to satisfy K).
fn are_deps_done(node: &DagNode, states: &HashMap<String, TaskState>) -> bool {
    let deps = match &node.input_from {
        Some(d) if !d.is_empty() => d,
        _ => return true,
    };
    let total = deps.len();
    let k = if node.min_required > 0 {
        node.min_required as usize
    } else {
        total
    };
    let success = deps
        .iter()
        .filter(|d| {
            matches!(
                states.get(*d),
                Some(TaskState::Completed) | Some(TaskState::Skipped)
            )
        })
        .count();
    let failed = deps
        .iter()
        .filter(|d| states.get(*d) == Some(&TaskState::Failed))
        .count();

    if success >= k {
        return true; // K already satisfied
    }
    if total - failed < k {
        return true; // impossible to satisfy K
    }
    false // still waiting
}

/// Returns true when the end node can still complete successfully after a
/// dependency failure, considering K-of-N (optimistic view).
fn can_end_node_still_succeed(
    end_node_id: &str,
    all_nodes: &HashMap<String, DagNode>,
    node_states: &HashMap<String, TaskState>,
) -> bool {
    let node = &all_nodes[end_node_id];
    let deps = match &node.input_from {
        Some(d) if !d.is_empty() => d,
        _ => return false, // no deps but reachable → can't recover
    };
    let total = deps.len();
    let k = if node.min_required > 0 {
        node.min_required as usize
    } else {
        total
    };
    let failed = deps
        .iter()
        .filter(|d| node_states.get(*d) == Some(&TaskState::Failed))
        .count();
    let optimistic = total - failed;
    optimistic >= k
}

/// BFS: can we reach `end_node_id` from `failed_node_id` following edges?
fn can_reach_end_node(end_node_id: &str, failed_node_id: &str, edges: &[DagEdge]) -> bool {
    let mut adj: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in edges {
        adj.entry(e.from.as_str()).or_default().push(e.to.as_str());
    }
    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::new();
    queue.push_back(failed_node_id);

    while let Some(cur) = queue.pop_front() {
        if cur == end_node_id {
            return true;
        }
        if !visited.insert(cur) {
            continue;
        }
        if let Some(neighbors) = adj.get(cur) {
            for n in neighbors {
                queue.push_back(n);
            }
        }
    }
    false
}

fn should_retry(
    policy: Option<&crate::orch_models::RetryPolicy>,
    error_code: Option<&str>,
    attempt: u32,
    max_retries: u32,
) -> bool {
    if attempt > max_retries {
        return false;
    }
    if let Some(p) = policy {
        if let Some(retry_on) = &p.retry_on {
            if !retry_on.is_empty() {
                return match error_code {
                    Some(code) => retry_on.iter().any(|c| c == code),
                    None => true,
                };
            }
        }
    }
    true
}

fn compensation_failure_error_code(
    task: &TaskFrame,
    compensation: Option<&SagaCompensationResult>,
) -> Option<String> {
    if !compensation_policy::is_strict(Some(&task.compensation_policy)) {
        return None;
    }
    let comp = compensation?;
    if comp.failed == 0 {
        return None;
    }
    Some(if comp.attempted == 0 {
        error_codes::COMPENSATION_NOT_SUPPORTED.to_string()
    } else {
        error_codes::COMPENSATION_FAILED.to_string()
    })
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// Minimal UUID-v4-shaped identifier (std-only, no external uuid crate).
fn new_uuid() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let a = (nanos as u64) ^ (c.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let b = (nanos >> 64) as u64 ^ c.rotate_left(17);
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (a >> 32) as u32,
        (a >> 16) as u16,
        (a & 0x0fff) as u16,
        ((b >> 48) as u16 & 0x3fff) | 0x8000,
        b & 0xffff_ffff_ffff
    )
}
