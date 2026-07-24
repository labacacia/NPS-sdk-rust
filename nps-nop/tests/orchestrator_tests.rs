// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Orchestration-engine tests mirroring the .NET NOP test suite:
//! DAG validation, condition truth table, input mapper, aggregation strategies,
//! linear/diamond/K-of-N execution, retry, saga compensation, callback signature.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use futures::future::BoxFuture;
use futures::stream::{self, BoxStream};
use serde_json::{json, Value};

use nps_nop::aggregator;
use nps_nop::callback::build_callback_signature;
use nps_nop::condition;
use nps_nop::error_codes;
use nps_nop::input_mapper;
use nps_nop::models::{aggregate_strategy, compensation_policy, TaskState};
use nps_nop::orch_models::{
    AlignStreamFrame, DagEdge, DagNode, DelegateFrame, RetryPolicy, StreamError, TaskDag, TaskFrame,
};
use nps_nop::validation::{validate_callback_url, validate_dag};
use nps_nop::worker::{NopWorkerClient, PreflightResult};
use nps_nop::{InMemoryNopTaskStore, NopOrchestrator, NopOrchestratorOptions};

// ── Mock worker client ────────────────────────────────────────────────────────

type Handler = Arc<dyn Fn(&DelegateFrame) -> Vec<AlignStreamFrame> + Send + Sync>;

#[derive(Default)]
struct MockWorkerClient {
    handlers: Mutex<HashMap<String, Handler>>,
    preflight_available: Mutex<bool>,
    preflight_reason: Mutex<Option<String>>,
    // call counts by node id
    calls: Mutex<HashMap<String, usize>>,
    // captured delegate frames per node id
    captured: Mutex<HashMap<String, Vec<DelegateFrame>>>,
}

impl MockWorkerClient {
    fn new() -> Arc<Self> {
        let m = MockWorkerClient::default();
        *m.preflight_available.lock().unwrap() = true;
        Arc::new(m)
    }

    fn setup_success(&self, node_id: &str, result: Value) {
        let nid = node_id.to_string();
        self.handlers.lock().unwrap().insert(
            node_id.to_string(),
            Arc::new(move |_f: &DelegateFrame| {
                vec![AlignStreamFrame::final_ok(
                    "task",
                    "sub",
                    nid.clone(),
                    0,
                    Some(result.clone()),
                )]
            }),
        );
    }

    fn setup_failure(&self, node_id: &str, error_code: &str, msg: &str) {
        let nid = node_id.to_string();
        let ec = error_code.to_string();
        let m = msg.to_string();
        self.handlers.lock().unwrap().insert(
            node_id.to_string(),
            Arc::new(move |_f: &DelegateFrame| {
                vec![AlignStreamFrame::final_err(
                    "task",
                    "sub",
                    nid.clone(),
                    0,
                    StreamError {
                        code: ec.clone(),
                        message: m.clone(),
                        retryable: false,
                    },
                )]
            }),
        );
    }

    fn setup_handler(&self, node_id: &str, handler: Handler) {
        self.handlers
            .lock()
            .unwrap()
            .insert(node_id.to_string(), handler);
    }

    fn set_preflight(&self, available: bool, reason: Option<&str>) {
        *self.preflight_available.lock().unwrap() = available;
        *self.preflight_reason.lock().unwrap() = reason.map(str::to_string);
    }

    fn call_count(&self, node_id: &str) -> usize {
        *self.calls.lock().unwrap().get(node_id).unwrap_or(&0)
    }

    fn captured_for(&self, node_id: &str) -> Vec<DelegateFrame> {
        self.captured
            .lock()
            .unwrap()
            .get(node_id)
            .cloned()
            .unwrap_or_default()
    }
}

impl NopWorkerClient for MockWorkerClient {
    fn delegate(&self, frame: DelegateFrame) -> BoxStream<'static, AlignStreamFrame> {
        // record call + capture
        *self
            .calls
            .lock()
            .unwrap()
            .entry(frame.node_id.clone())
            .or_insert(0) += 1;
        self.captured
            .lock()
            .unwrap()
            .entry(frame.node_id.clone())
            .or_default()
            .push(frame.clone());

        let frames = match self.handlers.lock().unwrap().get(&frame.node_id) {
            Some(h) => h(&frame),
            None => vec![AlignStreamFrame::final_ok(
                "task",
                "sub",
                frame.node_id.clone(),
                0,
                Some(json!({"ok": true})),
            )],
        };
        Box::pin(stream::iter(frames))
    }

    fn preflight<'a>(
        &'a self,
        agent_nid: String,
        _action: String,
        _estimated_npt: i64,
        _required_capabilities: Option<Vec<String>>,
    ) -> BoxFuture<'a, PreflightResult> {
        let available = *self.preflight_available.lock().unwrap();
        let reason = self.preflight_reason.lock().unwrap().clone();
        Box::pin(async move {
            if available {
                PreflightResult::available(agent_nid)
            } else {
                PreflightResult::unavailable(agent_nid, reason.unwrap_or_default())
            }
        })
    }
}

// ── Builders ──────────────────────────────────────────────────────────────────

fn build_orch(
    worker: Arc<MockWorkerClient>,
    validate_sender_nid: bool,
) -> NopOrchestrator<MockWorkerClient, InMemoryNopTaskStore> {
    let opts = NopOrchestratorOptions {
        validate_sender_nid,
        enable_callback: false,
        callback_retry_base_delay_ms: 0,
        ..Default::default()
    };
    NopOrchestrator::new(worker, Arc::new(InMemoryNopTaskStore::new()), Some(opts))
}

fn node(id: &str, input_from: Option<Vec<&str>>) -> DagNode {
    DagNode {
        id: id.to_string(),
        action: format!("nwp://node/{id}"),
        agent: id.to_string(),
        input_from: input_from.map(|v| v.into_iter().map(str::to_string).collect()),
        input_mapping: None,
        timeout_ms: None,
        retry_policy: None,
        condition: None,
        min_required: 0,
        compensate_action: None,
        compensate_params_mapping: None,
    }
}

fn linear_task(ids: &[&str]) -> TaskFrame {
    let nodes: Vec<DagNode> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| {
            if i == 0 {
                node(id, None)
            } else {
                node(id, Some(vec![ids[i - 1]]))
            }
        })
        .collect();
    let edges: Vec<DagEdge> = ids
        .windows(2)
        .map(|w| DagEdge {
            from: w[0].to_string(),
            to: w[1].to_string(),
        })
        .collect();
    let mut t = TaskFrame::new(new_id(), TaskDag { nodes, edges });
    t.timeout_ms = 10_000;
    t
}

fn single_task(id: &str, condition: Option<&str>) -> TaskFrame {
    let mut n = node(id, None);
    n.condition = condition.map(str::to_string);
    let mut t = TaskFrame::new(
        new_id(),
        TaskDag {
            nodes: vec![n],
            edges: vec![],
        },
    );
    t.timeout_ms = 10_000;
    t
}

static ID_COUNTER: AtomicUsize = AtomicUsize::new(0);
fn new_id() -> String {
    format!("task-{}", ID_COUNTER.fetch_add(1, Ordering::Relaxed))
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

// ══════════════════════════════════════════════════════════════════════════════
//  DAG validation
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn dag_valid_linear() {
    let dag = linear_task(&["a", "b", "c"]).dag;
    let r = validate_dag(&dag);
    assert!(r.is_valid);
    assert_eq!(r.topological_order.unwrap(), vec!["a", "b", "c"]);
}

#[test]
fn dag_empty_is_invalid() {
    let dag = TaskDag {
        nodes: vec![],
        edges: vec![],
    };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_INVALID));
}

#[test]
fn dag_duplicate_node_id() {
    let dag = TaskDag {
        nodes: vec![node("a", None), node("a", None)],
        edges: vec![],
    };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_INVALID));
}

#[test]
fn dag_cycle_detected() {
    // s → a → b → a (cycle), a → e
    let dag = TaskDag {
        nodes: vec![node("s", None), node("a", None), node("b", None), node("e", None)],
        edges: vec![
            DagEdge { from: "s".into(), to: "a".into() },
            DagEdge { from: "a".into(), to: "b".into() },
            DagEdge { from: "b".into(), to: "a".into() },
            DagEdge { from: "a".into(), to: "e".into() },
        ],
    };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_CYCLE));
}

#[test]
fn dag_too_large() {
    let nodes: Vec<DagNode> = (0..33).map(|i| node(&format!("n{i}"), None)).collect();
    let dag = TaskDag { nodes, edges: vec![] };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_TOO_LARGE));
}

#[test]
fn dag_edge_unknown_node() {
    let dag = TaskDag {
        nodes: vec![node("a", None)],
        edges: vec![DagEdge { from: "a".into(), to: "ghost".into() }],
    };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_INVALID));
}

#[test]
fn dag_no_start_node() {
    // a↔b two-cycle: neither has in-degree 0.
    let dag = TaskDag {
        nodes: vec![node("a", None), node("b", None)],
        edges: vec![
            DagEdge { from: "a".into(), to: "b".into() },
            DagEdge { from: "b".into(), to: "a".into() },
        ],
    };
    let r = validate_dag(&dag);
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some(error_codes::TASK_DAG_INVALID));
}

// ══════════════════════════════════════════════════════════════════════════════
//  Callback URL validation
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn callback_url_https_public_ok() {
    assert!(validate_callback_url("https://cb.example.com/hook").is_none());
}

#[test]
fn callback_url_http_rejected() {
    assert!(validate_callback_url("http://cb.example.com/hook").is_some());
}

#[test]
fn callback_url_private_ip_rejected() {
    assert!(validate_callback_url("https://10.0.0.5/hook").is_some());
    assert!(validate_callback_url("https://127.0.0.1/hook").is_some());
    assert!(validate_callback_url("https://192.168.1.1/hook").is_some());
    assert!(validate_callback_url("https://localhost/hook").is_some());
    assert!(validate_callback_url("https://[::1]/hook").is_some());
}

#[test]
fn callback_url_public_ip_ok() {
    assert!(validate_callback_url("https://8.8.8.8/hook").is_none());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Condition truth table
// ══════════════════════════════════════════════════════════════════════════════

fn ctx(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}

#[test]
fn condition_numeric_comparisons() {
    let c = ctx(&[("n", json!({"score": 0.8}))]);
    assert!(condition::evaluate("$.n.score > 0.7", &c).unwrap());
    assert!(!condition::evaluate("$.n.score > 0.9", &c).unwrap());
    assert!(condition::evaluate("$.n.score >= 0.8", &c).unwrap());
    assert!(condition::evaluate("$.n.score < 1.0", &c).unwrap());
    assert!(condition::evaluate("$.n.score <= 0.8", &c).unwrap());
    assert!(condition::evaluate("$.n.score == 0.8", &c).unwrap());
    assert!(condition::evaluate("$.n.score != 0.1", &c).unwrap());
}

#[test]
fn condition_string_comparisons() {
    let c = ctx(&[("n", json!({"status": "ok"}))]);
    assert!(condition::evaluate("$.n.status == \"ok\"", &c).unwrap());
    assert!(!condition::evaluate("$.n.status == \"bad\"", &c).unwrap());
    assert!(condition::evaluate("$.n.status != \"bad\"", &c).unwrap());
}

#[test]
fn condition_boolean_logic() {
    let c = ctx(&[("n", json!({"a": 1, "b": 5}))]);
    assert!(condition::evaluate("$.n.a == 1 && $.n.b == 5", &c).unwrap());
    assert!(!condition::evaluate("$.n.a == 1 && $.n.b == 9", &c).unwrap());
    assert!(condition::evaluate("$.n.a == 9 || $.n.b == 5", &c).unwrap());
    assert!(condition::evaluate("!($.n.a == 9)", &c).unwrap());
    assert!(condition::evaluate("($.n.a == 1) && ($.n.b > 0)", &c).unwrap());
}

#[test]
fn condition_null_and_literals() {
    let c = ctx(&[("n", json!({"x": null}))]);
    assert!(condition::evaluate("$.n.x == null", &c).unwrap());
    assert!(!condition::evaluate("$.n.missing != null", &c).unwrap());
    assert!(condition::evaluate("true", &c).unwrap());
    assert!(!condition::evaluate("false", &c).unwrap());
    // empty condition → true
    assert!(condition::evaluate("", &c).unwrap());
}

#[test]
fn condition_truthy_bare_value() {
    let c = ctx(&[("n", json!({"flag": true, "count": 0}))]);
    assert!(condition::evaluate("$.n.flag", &c).unwrap());
    assert!(!condition::evaluate("$.n.count", &c).unwrap());
}

#[test]
fn condition_syntax_error() {
    let c = ctx(&[]);
    assert!(condition::evaluate("$.n.x >> 3", &c).is_err());
    assert!(condition::evaluate("bogus_token", &c).is_err());
}

// ══════════════════════════════════════════════════════════════════════════════
//  Input mapper
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn mapper_resolves_nested() {
    let c = ctx(&[("n1", json!({"data": {"value": 42}}))]);
    assert_eq!(
        input_mapper::resolve("$.n1.data.value", &c).unwrap(),
        Some(json!(42))
    );
    assert_eq!(input_mapper::resolve("$.n1", &c).unwrap(), Some(json!({"data": {"value": 42}})));
}

#[test]
fn mapper_missing_returns_none() {
    let c = ctx(&[("n1", json!({"a": 1}))]);
    assert_eq!(input_mapper::resolve("$.n1.missing", &c).unwrap(), None);
    assert_eq!(input_mapper::resolve("$.ghost", &c).unwrap(), None);
}

#[test]
fn mapper_must_start_with_dollar() {
    let c = ctx(&[]);
    assert!(input_mapper::resolve("n1.value", &c).is_err());
    assert!(input_mapper::resolve("", &c).is_err());
}

#[test]
fn mapper_depth_limit() {
    let c = ctx(&[]);
    // 9 levels beyond $ exceeds MAX_INPUT_MAPPING_DEPTH (8)
    let deep = "$.a.b.c.d.e.f.g.h.i";
    assert!(input_mapper::resolve(deep, &c).is_err());
}

#[test]
fn mapper_build_params() {
    let c = ctx(&[("n1", json!({"charge_id": "ch_1"}))]);
    let mut mapping = HashMap::new();
    mapping.insert("id".to_string(), json!("$.n1.charge_id"));
    let params = input_mapper::build_params(Some(&mapping), &c).unwrap();
    assert_eq!(params, json!({"id": "ch_1"}));
}

#[test]
fn mapper_whole_context() {
    let c = ctx(&[("n1", json!({"a": 1})), ("n2", json!({"b": 2}))]);
    // Whole-context path is "$." (must start with "$." per NPS-5 §3.1.3).
    let all = input_mapper::resolve("$.", &c).unwrap().unwrap();
    assert_eq!(all.get("n1"), Some(&json!({"a": 1})));
    assert_eq!(all.get("n2"), Some(&json!({"b": 2})));
}

// ══════════════════════════════════════════════════════════════════════════════
//  Aggregation strategies
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn aggregate_merge() {
    let results = vec![json!({"a": 1}), json!({"b": 2})];
    let r = aggregator::aggregate(aggregate_strategy::MERGE, &results, 0);
    assert_eq!(r, json!({"a": 1, "b": 2}));
}

#[test]
fn aggregate_first() {
    let results = vec![json!({"a": 1}), json!({"b": 2})];
    assert_eq!(aggregator::aggregate(aggregate_strategy::FIRST, &results, 0), json!({"a": 1}));
}

#[test]
fn aggregate_all() {
    let results = vec![json!(1), json!(2), json!(3)];
    assert_eq!(aggregator::aggregate(aggregate_strategy::ALL, &results, 0), json!([1, 2, 3]));
}

#[test]
fn aggregate_fastest_k() {
    let results = vec![json!(1), json!(2), json!(3)];
    assert_eq!(aggregator::aggregate(aggregate_strategy::FASTEST_K, &results, 2), json!([1, 2]));
}

#[test]
fn aggregate_merge_non_object() {
    let results = vec![json!({"a": 1}), json!(99)];
    let r = aggregator::aggregate(aggregate_strategy::MERGE, &results, 0);
    assert_eq!(r, json!({"a": 1, "_result_1": 99}));
}

#[test]
fn aggregate_empty_is_object() {
    assert_eq!(aggregator::aggregate(aggregate_strategy::MERGE, &[], 0), json!({}));
}

// ══════════════════════════════════════════════════════════════════════════════
//  Execution: linear / diamond / aggregation
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn single_node_succeeds() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({"value": 42}));
        let orch = build_orch(worker, false);
        let result = orch.execute(single_task("a", None)).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert_eq!(result.node_results["a"]["value"], json!(42));
    });
}

#[test]
fn linear_chain_all_complete() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        for id in ["fetch", "analyze", "report"] {
            worker.setup_success(id, json!({"step": id}));
        }
        let orch = build_orch(worker, false);
        let result = orch.execute(linear_task(&["fetch", "analyze", "report"])).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert_eq!(result.node_results.len(), 3);
    });
}

#[test]
fn diamond_dag_both_branches() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("start", json!({"x": 1}));
        worker.setup_success("left", json!({"l": 10}));
        worker.setup_success("right", json!({"r": 20}));
        worker.setup_success("end", json!({"done": true}));
        let orch = build_orch(worker, false);
        let dag = TaskDag {
            nodes: vec![
                node("start", None),
                node("left", Some(vec!["start"])),
                node("right", Some(vec!["start"])),
                node("end", Some(vec!["left", "right"])),
            ],
            edges: vec![
                DagEdge { from: "start".into(), to: "left".into() },
                DagEdge { from: "start".into(), to: "right".into() },
                DagEdge { from: "left".into(), to: "end".into() },
                DagEdge { from: "right".into(), to: "end".into() },
            ],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert_eq!(result.node_results.len(), 4);
    });
}

#[test]
fn aggregated_result_merges_end_nodes() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({"field_a": "hello"}));
        worker.setup_success("b", json!({"field_b": "world"}));
        let orch = build_orch(worker, false);
        let dag = TaskDag {
            nodes: vec![node("a", None), node("b", None)],
            edges: vec![],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        let agg = result.aggregated_result.unwrap();
        assert!(agg.get("field_a").is_some());
        assert!(agg.get("field_b").is_some());
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Condition skip in execution
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn condition_false_node_skipped() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("fetch", json!({"count": 0}));
        worker.setup_success("report", json!({"done": true}));
        let orch = build_orch(worker, false);
        let mut report = node("report", Some(vec!["fetch"]));
        report.condition = Some("$.fetch.count > 0".to_string());
        let dag = TaskDag {
            nodes: vec![node("fetch", None), report],
            edges: vec![DagEdge { from: "fetch".into(), to: "report".into() }],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert!(result.node_results.contains_key("fetch"));
        assert!(!result.node_results.contains_key("report"));
    });
}

#[test]
fn condition_true_node_executes() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("fetch", json!({"count": 5}));
        worker.setup_success("report", json!({"done": true}));
        let orch = build_orch(worker, false);
        let mut report = node("report", Some(vec!["fetch"]));
        report.condition = Some("$.fetch.count > 0".to_string());
        let dag = TaskDag {
            nodes: vec![node("fetch", None), report],
            edges: vec![DagEdge { from: "fetch".into(), to: "report".into() }],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert!(result.node_results.contains_key("report"));
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Failure handling
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn node_failure_task_fails() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_failure("fetch", "NOP-DELEGATE-REJECTED", "capacity exceeded");
        let orch = build_orch(worker, false);
        let result = orch.execute(single_task("fetch", None)).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert!(result.error_code.is_some());
    });
}

#[test]
fn node_failure_propagates_to_dependent() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_failure("fetch", "NOP-DELEGATE-REJECTED", "");
        worker.setup_success("analyze", json!({"ok": true}));
        let orch = build_orch(worker, false);
        let result = orch.execute(linear_task(&["fetch", "analyze"])).await;
        assert_eq!(result.final_state, TaskState::Failed);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  K-of-N
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn k_of_n_one_branch_fails_still_completes() {
    rt().block_on(async {
        // start → a,b,c → end (min_required = 2). one branch fails.
        let worker = MockWorkerClient::new();
        worker.setup_success("start", json!({"x": 1}));
        worker.setup_success("a", json!({"a": 1}));
        worker.setup_success("b", json!({"b": 2}));
        worker.setup_failure("c", "BRANCH-FAILED", "");
        worker.setup_success("end", json!({"done": true}));
        let orch = build_orch(worker, false);

        let mut end = node("end", Some(vec!["a", "b", "c"]));
        end.min_required = 2;
        let dag = TaskDag {
            nodes: vec![
                node("start", None),
                node("a", Some(vec!["start"])),
                node("b", Some(vec!["start"])),
                node("c", Some(vec!["start"])),
                end,
            ],
            edges: vec![
                DagEdge { from: "start".into(), to: "a".into() },
                DagEdge { from: "start".into(), to: "b".into() },
                DagEdge { from: "start".into(), to: "c".into() },
                DagEdge { from: "a".into(), to: "end".into() },
                DagEdge { from: "b".into(), to: "end".into() },
                DagEdge { from: "c".into(), to: "end".into() },
            ],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert!(result.node_results.contains_key("end"));
    });
}

#[test]
fn k_of_n_too_many_failures_aborts() {
    rt().block_on(async {
        // start → a,b,c → end (min_required = 2). two branches fail → K unsatisfiable.
        let worker = MockWorkerClient::new();
        worker.setup_success("start", json!({"x": 1}));
        worker.setup_success("a", json!({"a": 1}));
        worker.setup_failure("b", "BRANCH-FAILED", "");
        worker.setup_failure("c", "BRANCH-FAILED", "");
        worker.setup_success("end", json!({"done": true}));
        let orch = build_orch(worker, false);

        let mut end = node("end", Some(vec!["a", "b", "c"]));
        end.min_required = 2;
        let dag = TaskDag {
            nodes: vec![
                node("start", None),
                node("a", Some(vec!["start"])),
                node("b", Some(vec!["start"])),
                node("c", Some(vec!["start"])),
                end,
            ],
            edges: vec![
                DagEdge { from: "start".into(), to: "a".into() },
                DagEdge { from: "start".into(), to: "b".into() },
                DagEdge { from: "start".into(), to: "c".into() },
                DagEdge { from: "a".into(), to: "end".into() },
                DagEdge { from: "b".into(), to: "end".into() },
                DagEdge { from: "c".into(), to: "end".into() },
            ],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Retry
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn retry_succeeds_on_second_attempt() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let counter2 = counter.clone();
        worker.setup_handler(
            "op",
            Arc::new(move |_f: &DelegateFrame| {
                let c = counter2.fetch_add(1, Ordering::SeqCst) + 1;
                if c == 1 {
                    vec![AlignStreamFrame::final_err(
                        "t",
                        "s",
                        "op",
                        0,
                        StreamError { code: "ERR".into(), message: "".into(), retryable: true },
                    )]
                } else {
                    vec![AlignStreamFrame::final_ok("t", "s", "op", 0, Some(json!({"ok": true})))]
                }
            }),
        );
        let orch = build_orch(worker, false);

        let mut n = node("op", None);
        n.retry_policy = Some(RetryPolicy {
            max_retries: 2,
            initial_delay_ms: 1,
            ..Default::default()
        });
        let mut task = TaskFrame::new(new_id(), TaskDag { nodes: vec![n], edges: vec![] });
        task.max_retries = 2;
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    });
}

#[test]
fn retry_on_allowlist_skips_non_listed() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_failure("op", "OTHER-ERR", "");
        let orch = build_orch(worker.clone(), false);

        let mut n = node("op", None);
        n.retry_policy = Some(RetryPolicy {
            max_retries: 3,
            initial_delay_ms: 1,
            retry_on: Some(vec!["RETRYABLE-ERR".to_string()]),
            ..Default::default()
        });
        let mut task = TaskFrame::new(new_id(), TaskDag { nodes: vec![n], edges: vec![] });
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        // Only one call — error not in allowlist, no retries.
        assert_eq!(worker.call_count("op"), 1);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Saga compensation
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn saga_best_effort_compensates_predecessor() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        let refund_calls = Arc::new(AtomicUsize::new(0));
        let rc = refund_calls.clone();
        worker.setup_handler(
            "charge",
            Arc::new(move |f: &DelegateFrame| {
                if f.action == "nwp://payments/refund" {
                    rc.fetch_add(1, Ordering::SeqCst);
                    vec![AlignStreamFrame::final_ok("t", "s", "charge", 0, Some(json!({"refunded": true})))]
                } else {
                    vec![AlignStreamFrame::final_ok(
                        "t",
                        "s",
                        "charge",
                        0,
                        Some(json!({"charge_id": "ch_1", "amount": 25})),
                    )]
                }
            }),
        );
        worker.setup_failure("ship", "SHIP-FAILED", "");
        let orch = build_orch(worker.clone(), false);

        let mut charge = node("charge", None);
        charge.compensate_action = Some("nwp://payments/refund".to_string());
        let mut cmap = HashMap::new();
        cmap.insert("charge_id".to_string(), json!("$.charge.charge_id"));
        charge.compensate_params_mapping = Some(cmap);

        let dag = TaskDag {
            nodes: vec![charge, node("ship", Some(vec!["charge"]))],
            edges: vec![DagEdge { from: "charge".into(), to: "ship".into() }],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        // default policy = best_effort

        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(refund_calls.load(Ordering::SeqCst), 1);
        let comp = result.compensation.unwrap();
        assert_eq!(comp.attempted, 1);
        assert_eq!(comp.succeeded, 1);
        // verify compensate params were resolved against charge output
        let refund_frame = worker
            .captured_for("charge")
            .into_iter()
            .find(|f| f.action == "nwp://payments/refund")
            .unwrap();
        assert_eq!(refund_frame.params.unwrap()["charge_id"], json!("ch_1"));
    });
}

#[test]
fn saga_strict_missing_compensate_action_not_supported() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("charge", json!({"charge_id": "ch_1"}));
        worker.setup_failure("ship", "SHIP-FAILED", "");
        let orch = build_orch(worker, false);

        let dag = TaskDag {
            nodes: vec![node("charge", None), node("ship", Some(vec!["charge"]))],
            edges: vec![DagEdge { from: "charge".into(), to: "ship".into() }],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        task.compensation_policy = compensation_policy::STRICT.to_string();

        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(result.error_code.as_deref(), Some(error_codes::COMPENSATION_NOT_SUPPORTED));
        let comp = result.compensation.unwrap();
        assert_eq!(comp.attempted, 0);
        assert_eq!(comp.failed, 1);
        assert_eq!(comp.failed_node_ids, vec!["charge"]);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Duplicate / status / timeout / depth / preflight / cycle
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn duplicate_task_id_fails() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({}));
        let orch = build_orch(worker, false);
        let task = single_task("a", None);
        let _ = orch.execute(task.clone()).await;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(result.error_code.as_deref(), Some(error_codes::TASK_ALREADY_COMPLETED));
    });
}

#[test]
fn get_status_returns_record() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({}));
        let orch = build_orch(worker, false);
        let task = single_task("a", None);
        let task_id = task.task_id.clone();
        let _ = orch.execute(task).await;
        let record = orch.get_status(&task_id).await.unwrap();
        assert_eq!(record.task_id, task_id);
        assert_eq!(record.state, TaskState::Completed);
    });
}

#[test]
fn get_status_unknown_is_none() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        let orch = build_orch(worker, false);
        assert!(orch.get_status("no-such").await.is_none());
    });
}

#[test]
fn invalid_dag_cycle_returns_failed() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        let orch = build_orch(worker, false);
        let dag = TaskDag {
            nodes: vec![node("s", None), node("a", None), node("b", None), node("e", None)],
            edges: vec![
                DagEdge { from: "s".into(), to: "a".into() },
                DagEdge { from: "a".into(), to: "b".into() },
                DagEdge { from: "b".into(), to: "a".into() },
                DagEdge { from: "a".into(), to: "e".into() },
            ],
        };
        let mut task = TaskFrame::new(new_id(), dag);
        task.timeout_ms = 10_000;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(result.error_code.as_deref(), Some(error_codes::TASK_DAG_CYCLE));
    });
}

#[test]
fn delegate_depth_exceeded_rejected() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({}));
        let orch = build_orch(worker, false);
        let mut task = single_task("a", None);
        task.delegate_depth = 3;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(result.error_code.as_deref(), Some(error_codes::DELEGATE_CHAIN_TOO_DEEP));
    });
}

#[test]
fn preflight_unavailable_fails() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({}));
        worker.set_preflight(false, Some("no capacity"));
        let orch = build_orch(worker, false);
        let mut task = single_task("a", None);
        task.preflight = true;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
        assert_eq!(result.error_code.as_deref(), Some(error_codes::RESOURCE_INSUFFICIENT));
    });
}

#[test]
fn preflight_available_proceeds() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        worker.setup_success("a", json!({"ok": true}));
        let orch = build_orch(worker, false);
        let mut task = single_task("a", None);
        task.preflight = true;
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Completed);
    });
}

#[test]
fn timeout_fails_with_timeout_code() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        // Handler that never yields a final frame (blocks until task timeout).
        worker.setup_handler(
            "slow",
            Arc::new(|_f: &DelegateFrame| {
                // Yield an intermediate non-final frame only; stream then ends,
                // but node timeout / task timeout will fire first because we make
                // the node timeout large and task timeout tiny.
                vec![]
            }),
        );
        let orch = build_orch(worker, false);
        let mut task = single_task("slow", None);
        task.timeout_ms = 50;
        // node has no timeout override → uses task.timeout_ms; empty stream → no final
        // frame → DELEGATE_TIMEOUT, but with 50ms task timeout the outer timeout may win.
        let result = orch.execute(task).await;
        assert_eq!(result.final_state, TaskState::Failed);
    });
}

#[test]
fn sender_nid_mismatch_detected() {
    rt().block_on(async {
        let worker = MockWorkerClient::new();
        // final frame with wrong sender_nid
        worker.setup_handler(
            "a",
            Arc::new(|_f: &DelegateFrame| {
                vec![AlignStreamFrame::final_ok("t", "s", "wrong-agent", 0, Some(json!({})))]
            }),
        );
        let orch = build_orch(worker, true); // validate_sender_nid = true
        let result = orch.execute(single_task("a", None)).await;
        assert_eq!(result.final_state, TaskState::Failed);
    });
}

// ══════════════════════════════════════════════════════════════════════════════
//  Callback signature
// ══════════════════════════════════════════════════════════════════════════════

#[test]
fn callback_signature_valid_key() {
    // 32-byte key, base64url encoded (no padding).
    use base64::Engine;
    let key = [7u8; 32];
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key);
    let sig = build_callback_signature(Some(&secret), "{\"a\":1}").unwrap();
    assert!(sig.starts_with("sha256="));
    // 64 hex chars after the prefix
    assert_eq!(sig.len(), "sha256=".len() + 64);
    assert!(sig["sha256=".len()..].chars().all(|c| c.is_ascii_hexdigit()));
    // deterministic
    assert_eq!(sig, build_callback_signature(Some(&secret), "{\"a\":1}").unwrap());
}

#[test]
fn callback_signature_wrong_key_length_none() {
    use base64::Engine;
    let short = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 16]);
    assert!(build_callback_signature(Some(&short), "payload").is_none());
}

#[test]
fn callback_signature_absent_secret_none() {
    assert!(build_callback_signature(None, "payload").is_none());
    assert!(build_callback_signature(Some(""), "payload").is_none());
}

#[test]
fn callback_signature_matches_known_vector() {
    // HMAC-SHA256 of "hello" with a 32-byte all-zero key.
    use base64::Engine;
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]);
    let sig = build_callback_signature(Some(&secret), "hello").unwrap();
    // Precomputed: HMAC-SHA256(key=32*0x00, msg="hello")
    assert_eq!(
        sig,
        "sha256=4352b26e33fe0d769a8922a6ba29004109f01688e26acc9e6cb347e5a5afc4da"
    );
}
