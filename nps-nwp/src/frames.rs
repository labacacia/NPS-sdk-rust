// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

fn get_str<'a>(d: &'a FrameDict, k: &str) -> NpsResult<&'a str> {
    d.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| NpsError::Frame(format!("missing field: {k}")))
}

fn opt_str<'a>(d: &'a FrameDict, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str)
}

fn opt_u64(d: &FrameDict, k: &str) -> Option<u64> {
    d.get(k).and_then(Value::as_u64)
}

pub const TOPOLOGY_SNAPSHOT_KIND: &str = "topology.snapshot";
pub const TOPOLOGY_STREAM_KIND: &str = "topology.stream";

// ── NWP v0.14 ─────────────────────────────────────────────────────────────────
pub const X_NWM_VERSION: &str = "X-NWM-Version";

#[derive(Debug, Clone)]
pub struct TopologySnapshotRequest {
    pub kind: String,
    pub anchor_ref: Option<String>,
    pub include_bridges: bool,
    pub include_capabilities: bool,
    pub max_depth: Option<u64>,
    pub since: Option<String>,
}

impl Default for TopologySnapshotRequest {
    fn default() -> Self {
        Self {
            kind: TOPOLOGY_SNAPSHOT_KIND.to_string(),
            anchor_ref: None,
            include_bridges: false,
            include_capabilities: false,
            max_depth: None,
            since: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopologyStreamRequest {
    pub kind: String,
    pub anchor_ref: Option<String>,
    pub include_initial_snapshot: bool,
    pub event_types: Option<Vec<String>>,
    pub since: Option<String>,
}

impl Default for TopologyStreamRequest {
    fn default() -> Self {
        Self {
            kind: TOPOLOGY_STREAM_KIND.to_string(),
            anchor_ref: None,
            include_initial_snapshot: true,
            event_types: None,
            since: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TopologyMember {
    pub node_id: String,
    pub node_type: Option<String>,
    pub anchor_ref: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct BridgeNodeSpec {
    pub bridge_id: String,
    pub source_protocol: String,
    pub target_protocol: String,
    pub source_ref: Option<String>,
    pub target_ref: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub metadata: Option<Value>,
}

// ── QueryFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QueryFrame {
    pub anchor_ref: String,
    pub filter: Option<Value>,
    pub order: Option<Value>,
    pub fields: Option<Vec<String>>,
    pub vector_search: Option<Value>,
    pub cursor: Option<String>,
    pub token_budget: Option<u64>,
    pub tokenizer: Option<String>,
    pub request_id: Option<String>,
    pub auto_anchor: Option<bool>,
    pub stream: Option<bool>,
    pub aggregate: Option<Value>,
    pub limit: Option<u64>,
    pub offset: Option<u64>,
    pub depth: Option<u64>,
}

impl QueryFrame {
    pub fn new(anchor_ref: impl Into<String>) -> Self {
        QueryFrame {
            anchor_ref: anchor_ref.into(),
            filter: None,
            order: None,
            fields: None,
            vector_search: None,
            cursor: None,
            token_budget: None,
            tokenizer: None,
            request_id: None,
            auto_anchor: None,
            stream: None,
            aggregate: None,
            limit: None,
            offset: None,
            depth: None,
        }
    }

    pub fn frame_type() -> FrameType {
        FrameType::Query
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_ref".into(), json!(self.anchor_ref));
        if let Some(v) = &self.filter {
            m.insert("filter".into(), v.clone());
        }
        if let Some(v) = &self.order {
            m.insert("order".into(), v.clone());
        }
        if let Some(v) = &self.fields {
            m.insert("fields".into(), json!(v));
        }
        if let Some(v) = &self.vector_search {
            m.insert("vector_search".into(), v.clone());
        }
        if let Some(v) = &self.cursor {
            m.insert("cursor".into(), json!(v));
        }
        if let Some(v) = self.token_budget {
            m.insert("token_budget".into(), json!(v));
        }
        if let Some(v) = &self.tokenizer {
            m.insert("tokenizer".into(), json!(v));
        }
        if let Some(v) = &self.request_id {
            m.insert("request_id".into(), json!(v));
        }
        if let Some(v) = self.auto_anchor {
            m.insert("auto_anchor".into(), json!(v));
        }
        if let Some(v) = self.stream {
            m.insert("stream".into(), json!(v));
        }
        if let Some(v) = &self.aggregate {
            m.insert("aggregate".into(), v.clone());
        }
        if let Some(v) = self.limit {
            m.insert("limit".into(), json!(v));
        }
        if let Some(v) = self.offset {
            m.insert("offset".into(), json!(v));
        }
        if let Some(v) = self.depth {
            m.insert("depth".into(), json!(v));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(QueryFrame {
            anchor_ref: get_str(d, "anchor_ref")?.to_string(),
            filter: d.get("filter").cloned(),
            order: d.get("order").or_else(|| d.get("order_by")).cloned(),
            fields: string_vec(d.get("fields")),
            vector_search: d.get("vector_search").cloned(),
            cursor: opt_str(d, "cursor").map(str::to_string),
            token_budget: opt_u64(d, "token_budget"),
            tokenizer: opt_str(d, "tokenizer").map(str::to_string),
            request_id: opt_str(d, "request_id").map(str::to_string),
            auto_anchor: d.get("auto_anchor").and_then(Value::as_bool),
            stream: d.get("stream").and_then(Value::as_bool),
            aggregate: d.get("aggregate").cloned(),
            limit: opt_u64(d, "limit"),
            offset: opt_u64(d, "offset"),
            depth: opt_u64(d, "depth"),
        })
    }
}

fn string_vec(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}

// ── ActionFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ActionFrame {
    pub action: String,
    pub params: Option<Value>,
    pub anchor_ref: Option<String>,
    pub async_: bool,
    pub idempotency_key: Option<String>,
    pub timeout_ms: Option<u32>,
    pub request_id: Option<String>,
}

impl ActionFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Action
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("action_id".into(), json!(self.action));
        m.insert("action".into(), json!(self.action));
        m.insert("async".into(), json!(self.async_));
        if let Some(v) = &self.params {
            m.insert("params".into(), v.clone());
        }
        if let Some(v) = &self.anchor_ref {
            m.insert("anchor_ref".into(), json!(v));
        }
        if let Some(v) = &self.request_id {
            m.insert("request_id".into(), json!(v));
        }
        if let Some(v) = &self.idempotency_key {
            m.insert("idempotency_key".into(), json!(v));
        }
        if let Some(v) = self.timeout_ms {
            m.insert("timeout_ms".into(), json!(v));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ActionFrame {
            action: d
                .get("action_id")
                .or_else(|| d.get("action"))
                .and_then(Value::as_str)
                .ok_or_else(|| NpsError::Frame("missing field: action_id".into()))?
                .to_string(),
            params: d.get("params").cloned(),
            anchor_ref: opt_str(d, "anchor_ref").map(str::to_string),
            async_: d.get("async").and_then(Value::as_bool).unwrap_or(false),
            idempotency_key: opt_str(d, "idempotency_key").map(str::to_string),
            timeout_ms: opt_u64(d, "timeout_ms").map(|value| value as u32),
            request_id: opt_str(d, "request_id").map(str::to_string),
        })
    }
}

// ── AsyncActionResponse ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AsyncActionResponse {
    pub task_id: String,
    pub status_url: Option<String>,
    pub callback_url: Option<String>,
}

impl AsyncActionResponse {
    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(AsyncActionResponse {
            task_id: get_str(d, "task_id")?.to_string(),
            status_url: opt_str(d, "status_url").map(str::to_string),
            callback_url: opt_str(d, "callback_url").map(str::to_string),
        })
    }
}

// ── SubscribeFrame ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeFrame {
    pub subscription_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<serde_json::Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_events: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}
