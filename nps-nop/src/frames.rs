// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde_json::{json, Value};

fn get_str<'a>(d: &'a FrameDict, k: &str) -> NpsResult<&'a str> {
    d.get(k).and_then(Value::as_str)
        .ok_or_else(|| NpsError::Frame(format!("missing field: {k}")))
}

fn opt_str<'a>(d: &'a FrameDict, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str)
}

fn opt_u64(d: &FrameDict, k: &str) -> Option<u64> {
    d.get(k).and_then(Value::as_u64)
}

fn opt_i64(d: &FrameDict, k: &str) -> Option<i64> {
    d.get(k).and_then(Value::as_i64)
}

// ── TaskFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TaskFrame {
    pub task_id:      String,
    pub dag:          Value,
    pub timeout_ms:   Option<u64>,
    pub callback_url: Option<String>,
    pub context:      Option<Value>,
    pub priority:     Option<String>,
    pub depth:        Option<i64>,
}

impl TaskFrame {
    pub fn frame_type() -> FrameType { FrameType::Task }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("task_id".into(), json!(self.task_id));
        m.insert("dag".into(),     self.dag.clone());
        if let Some(v) = self.timeout_ms  { m.insert("timeout_ms".into(),   json!(v)); }
        if let Some(v) = &self.callback_url { m.insert("callback_url".into(), json!(v)); }
        if let Some(v) = &self.context    { m.insert("context".into(),      v.clone()); }
        if let Some(v) = &self.priority   { m.insert("priority".into(),     json!(v)); }
        if let Some(v) = self.depth       { m.insert("depth".into(),        json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(TaskFrame {
            task_id:      get_str(d, "task_id")?.to_string(),
            dag:          d.get("dag").cloned().unwrap_or(Value::Null),
            timeout_ms:   opt_u64(d, "timeout_ms"),
            callback_url: opt_str(d, "callback_url").map(str::to_string),
            context:      d.get("context").cloned(),
            priority:     opt_str(d, "priority").map(str::to_string),
            depth:        opt_i64(d, "depth"),
        })
    }
}

// ── DelegateFrame ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DelegateFrame {
    pub task_id:          String,
    pub subtask_id:       String,
    pub action:           String,
    pub target_nid:       String,
    pub inputs:           Option<Value>,
    pub config:           Option<Value>,
    pub idempotency_key:  Option<String>,
}

impl DelegateFrame {
    pub fn frame_type() -> FrameType { FrameType::Delegate }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("task_id".into(),    json!(self.task_id));
        m.insert("subtask_id".into(), json!(self.subtask_id));
        m.insert("action".into(),     json!(self.action));
        m.insert("target_nid".into(), json!(self.target_nid));
        if let Some(v) = &self.inputs          { m.insert("inputs".into(),           v.clone()); }
        if let Some(v) = &self.config          { m.insert("config".into(),           v.clone()); }
        if let Some(v) = &self.idempotency_key { m.insert("idempotency_key".into(),  json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(DelegateFrame {
            task_id:         get_str(d, "task_id")?.to_string(),
            subtask_id:      get_str(d, "subtask_id")?.to_string(),
            action:          get_str(d, "action")?.to_string(),
            target_nid:      get_str(d, "target_nid")?.to_string(),
            inputs:          d.get("inputs").cloned(),
            config:          d.get("config").cloned(),
            idempotency_key: opt_str(d, "idempotency_key").map(str::to_string),
        })
    }
}

// ── SyncFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct SyncFrame {
    pub task_id:      String,
    pub sync_id:      String,
    pub subtask_ids:  Vec<String>,
    pub min_required: i64,
    pub aggregate:    String,
    pub timeout_ms:   Option<u64>,
}

impl SyncFrame {
    pub fn frame_type() -> FrameType { FrameType::Sync }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("task_id".into(),      json!(self.task_id));
        m.insert("sync_id".into(),      json!(self.sync_id));
        m.insert("subtask_ids".into(),  json!(self.subtask_ids));
        m.insert("min_required".into(), json!(self.min_required));
        m.insert("aggregate".into(),    json!(self.aggregate));
        if let Some(v) = self.timeout_ms { m.insert("timeout_ms".into(), json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let subtask_ids = d.get("subtask_ids").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(SyncFrame {
            task_id:      get_str(d, "task_id")?.to_string(),
            sync_id:      get_str(d, "sync_id")?.to_string(),
            subtask_ids,
            min_required: opt_i64(d, "min_required").unwrap_or(0),
            aggregate:    opt_str(d, "aggregate").unwrap_or("merge").to_string(),
            timeout_ms:   opt_u64(d, "timeout_ms"),
        })
    }
}

// ── AlignStreamFrame ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AlignStreamFrame {
    pub sync_id:    String,
    pub task_id:    String,
    pub subtask_id: String,
    pub seq:        u64,
    pub is_final:   bool,
    pub source_nid: Option<String>,
    pub result:     Option<Value>,
    pub error:      Option<Value>,
    pub window_size: Option<u64>,
}

impl AlignStreamFrame {
    pub fn frame_type() -> FrameType { FrameType::AlignStream }

    pub fn error_code(&self) -> Option<&str> {
        self.error.as_ref()
            .and_then(|e| e.get("error_code"))
            .and_then(Value::as_str)
    }

    pub fn error_message(&self) -> Option<&str> {
        self.error.as_ref()
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("sync_id".into(),    json!(self.sync_id));
        m.insert("task_id".into(),    json!(self.task_id));
        m.insert("subtask_id".into(), json!(self.subtask_id));
        m.insert("seq".into(),        json!(self.seq));
        m.insert("is_final".into(),   json!(self.is_final));
        if let Some(v) = &self.source_nid  { m.insert("source_nid".into(),  json!(v)); }
        if let Some(v) = &self.result      { m.insert("result".into(),       v.clone()); }
        if let Some(v) = &self.error       { m.insert("error".into(),        v.clone()); }
        if let Some(v) = self.window_size  { m.insert("window_size".into(),  json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(AlignStreamFrame {
            sync_id:    get_str(d, "sync_id")?.to_string(),
            task_id:    get_str(d, "task_id")?.to_string(),
            subtask_id: get_str(d, "subtask_id")?.to_string(),
            seq:        opt_u64(d, "seq").unwrap_or(0),
            is_final:   d.get("is_final").and_then(Value::as_bool).unwrap_or(false),
            source_nid: opt_str(d, "source_nid").map(str::to_string),
            result:     d.get("result").cloned(),
            error:      d.get("error").cloned(),
            window_size: opt_u64(d, "window_size"),
        })
    }
}
