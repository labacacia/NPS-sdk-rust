// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::NpsFrameCodec;
use nps_core::frames::EncodingTier;
use nps_core::registry::FrameRegistry;
use nps_nop::{TaskFrame, DelegateFrame, SyncFrame, AlignStreamFrame};
use nps_nop::models::{BackoffStrategy, TaskState, NopTaskStatus};
use serde_json::{json, Map};

fn full_codec() -> NpsFrameCodec {
    NpsFrameCodec::new(FrameRegistry::create_full())
}

fn sample_dag() -> serde_json::Value {
    json!({
        "nodes": [{"id": "n1", "action": "search", "agent": "urn:nps:node:a:1"}],
        "edges": []
    })
}

// ── BackoffStrategy ───────────────────────────────────────────────────────────

#[test]
fn fixed_delay_ignores_attempt() {
    assert_eq!(BackoffStrategy::Fixed.compute_delay_ms(500, 30_000, 0), 500);
    assert_eq!(BackoffStrategy::Fixed.compute_delay_ms(500, 30_000, 5), 500);
}

#[test]
fn linear_scales_with_attempt() {
    assert_eq!(BackoffStrategy::Linear.compute_delay_ms(1000, 30_000, 0), 1000);
    assert_eq!(BackoffStrategy::Linear.compute_delay_ms(1000, 30_000, 2), 3000);
}

#[test]
fn exponential_doubles_each_attempt() {
    assert_eq!(BackoffStrategy::Exponential.compute_delay_ms(1000, 30_000, 0), 1000);
    assert_eq!(BackoffStrategy::Exponential.compute_delay_ms(1000, 30_000, 1), 2000);
    assert_eq!(BackoffStrategy::Exponential.compute_delay_ms(1000, 30_000, 3), 8000);
}

#[test]
fn delay_capped_at_max_ms() {
    assert_eq!(BackoffStrategy::Exponential.compute_delay_ms(1000, 5000, 10), 5000);
}

// ── TaskState ─────────────────────────────────────────────────────────────────

#[test]
fn task_state_from_str_known() {
    assert_eq!(TaskState::from_str("completed"), Some(TaskState::Completed));
    assert_eq!(TaskState::from_str("running"),   Some(TaskState::Running));
    assert_eq!(TaskState::from_str("failed"),    Some(TaskState::Failed));
}

#[test]
fn task_state_from_str_unknown() {
    assert_eq!(TaskState::from_str("unknown"), None);
}

#[test]
fn task_state_terminal_states() {
    assert!(TaskState::Completed.is_terminal());
    assert!(TaskState::Failed.is_terminal());
    assert!(TaskState::Cancelled.is_terminal());
    assert!(!TaskState::Pending.is_terminal());
    assert!(!TaskState::Running.is_terminal());
}

// ── NopTaskStatus ─────────────────────────────────────────────────────────────

fn make_status(task_id: &str, state: &str) -> NopTaskStatus {
    let mut m = Map::new();
    m.insert("task_id".into(), json!(task_id));
    m.insert("state".into(),   json!(state));
    NopTaskStatus::from_dict(m)
}

#[test]
fn nop_task_status_getters() {
    let s = make_status("t1", "running");
    assert_eq!(s.task_id(), "t1");
    assert_eq!(s.state(), Some(TaskState::Running));
    assert!(!s.is_terminal());
}

#[test]
fn nop_task_status_terminal_states() {
    assert!( make_status("x", "completed").is_terminal());
    assert!( make_status("x", "failed").is_terminal());
    assert!( make_status("x", "cancelled").is_terminal());
    assert!(!make_status("x", "pending").is_terminal());
}

#[test]
fn nop_task_status_error_fields() {
    let mut m = Map::new();
    m.insert("task_id".into(),      json!("t1"));
    m.insert("state".into(),        json!("failed"));
    m.insert("error_code".into(),   json!("NOP-TASK-FAILED"));
    m.insert("error_message".into(), json!("Agent timeout"));
    let s = NopTaskStatus::from_dict(m);
    assert_eq!(s.error_code(), Some("NOP-TASK-FAILED"));
    assert_eq!(s.error_message(), Some("Agent timeout"));
}

#[test]
fn nop_task_status_node_results() {
    let mut m = Map::new();
    m.insert("task_id".into(), json!("t1"));
    m.insert("state".into(),   json!("completed"));
    let mut nr = Map::new();
    nr.insert("n1".into(), json!({"out": 42}));
    m.insert("node_results".into(), serde_json::Value::Object(nr));
    let s = NopTaskStatus::from_dict(m);
    assert!(s.node_results().is_some());
    assert!(s.node_results().unwrap().contains_key("n1"));
}

#[test]
fn nop_task_status_to_string() {
    let s = make_status("t1", "running");
    let txt = s.to_string();
    assert!(txt.contains("t1"));
    assert!(txt.contains("Running"));
}

// ── TaskFrame ─────────────────────────────────────────────────────────────────

#[test]
fn task_frame_roundtrip() {
    let codec = full_codec();
    let frame = TaskFrame {
        task_id:      "t1".into(),
        dag:          sample_dag(),
        timeout_ms:   Some(5000),
        callback_url: Some("https://cb.example.com/hook".into()),
        context:      Some(json!({"traceId": "tr1"})),
        priority:     Some("high".into()),
        depth:        Some(1),
    };
    let wire = codec.encode(TaskFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = TaskFrame::from_dict(&dict).unwrap();
    assert_eq!(back.task_id, "t1");
    assert_eq!(back.timeout_ms, Some(5000));
    assert_eq!(back.callback_url.as_deref(), Some("https://cb.example.com/hook"));
    assert_eq!(back.priority.as_deref(), Some("high"));
    assert_eq!(back.depth, Some(1));
}

#[test]
fn task_frame_optional_fields_null() {
    let codec = full_codec();
    let frame = TaskFrame {
        task_id: "t2".into(), dag: sample_dag(),
        timeout_ms: None, callback_url: None, context: None, priority: None, depth: None,
    };
    let wire = codec.encode(TaskFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = TaskFrame::from_dict(&dict).unwrap();
    assert!(back.timeout_ms.is_none());
    assert!(back.callback_url.is_none());
}

// ── DelegateFrame ─────────────────────────────────────────────────────────────

#[test]
fn delegate_frame_roundtrip() {
    let codec = full_codec();
    let frame = DelegateFrame {
        task_id:         "t1".into(),
        subtask_id:      "sub1".into(),
        action:          "classify".into(),
        target_nid:      "urn:nps:node:a:1".into(),
        inputs:          Some(json!({"text": "hello"})),
        config:          Some(json!({"model": "gpt-4"})),
        idempotency_key: Some("idem-x".into()),
    };
    let wire = codec.encode(DelegateFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = DelegateFrame::from_dict(&dict).unwrap();
    assert_eq!(back.subtask_id, "sub1");
    assert_eq!(back.idempotency_key.as_deref(), Some("idem-x"));
}

#[test]
fn delegate_frame_optional_fields_null() {
    let codec = full_codec();
    let frame = DelegateFrame {
        task_id: "t1".into(), subtask_id: "s1".into(),
        action: "act".into(), target_nid: "urn:nps:node:a:1".into(),
        inputs: None, config: None, idempotency_key: None,
    };
    let wire = codec.encode(DelegateFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = DelegateFrame::from_dict(&dict).unwrap();
    assert!(back.inputs.is_none());
    assert!(back.idempotency_key.is_none());
}

// ── SyncFrame ─────────────────────────────────────────────────────────────────

#[test]
fn sync_frame_roundtrip() {
    let codec = full_codec();
    let frame = SyncFrame {
        task_id:      "t1".into(),
        sync_id:      "sync1".into(),
        subtask_ids:  vec!["a".into(), "b".into()],
        min_required: 1,
        aggregate:    "fastest_k".into(),
        timeout_ms:   Some(3000),
    };
    let wire = codec.encode(SyncFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = SyncFrame::from_dict(&dict).unwrap();
    assert_eq!(back.sync_id, "sync1");
    assert_eq!(back.min_required, 1);
    assert_eq!(back.aggregate, "fastest_k");
    assert_eq!(back.timeout_ms, Some(3000));
}

#[test]
fn sync_frame_defaults() {
    let codec = full_codec();
    let frame = SyncFrame {
        task_id: "t1".into(), sync_id: "s1".into(),
        subtask_ids: vec!["a".into()],
        min_required: 0, aggregate: "merge".into(), timeout_ms: None,
    };
    let wire = codec.encode(SyncFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = SyncFrame::from_dict(&dict).unwrap();
    assert_eq!(back.min_required, 0);
    assert_eq!(back.aggregate, "merge");
    assert!(back.timeout_ms.is_none());
}

// ── AlignStreamFrame ──────────────────────────────────────────────────────────

#[test]
fn align_stream_frame_with_error() {
    let codec = full_codec();
    let err   = json!({"error_code": "NOP-DELEGATE-FAILED", "message": "timeout"});
    let frame = AlignStreamFrame {
        sync_id:    "s1".into(),
        task_id:    "t1".into(),
        subtask_id: "sub1".into(),
        seq:        3,
        is_final:   true,
        source_nid: Some("urn:nps:node:a:1".into()),
        result:     Some(json!({"score": 0.9})),
        error:      Some(err),
        window_size: Some(10),
    };
    let wire = codec.encode(AlignStreamFrame::frame_type(), &frame.to_dict(), EncodingTier::MsgPack, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = AlignStreamFrame::from_dict(&dict).unwrap();
    assert_eq!(back.seq, 3);
    assert!(back.is_final);
    assert_eq!(back.error_code(), Some("NOP-DELEGATE-FAILED"));
    assert_eq!(back.error_message(), Some("timeout"));
    assert_eq!(back.window_size, Some(10));
}

#[test]
fn align_stream_frame_null_error() {
    let codec = full_codec();
    let frame = AlignStreamFrame {
        sync_id: "s1".into(), task_id: "t1".into(), subtask_id: "sub1".into(),
        seq: 0, is_final: false, source_nid: None, result: None, error: None, window_size: None,
    };
    let wire = codec.encode(AlignStreamFrame::frame_type(), &frame.to_dict(), EncodingTier::Json, true).unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = AlignStreamFrame::from_dict(&dict).unwrap();
    assert!(back.error.is_none());
    assert!(back.error_code().is_none());
}
