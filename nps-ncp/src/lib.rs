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

// ── AnchorFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnchorFrame {
    pub anchor_id:   String,
    pub schema:      serde_json::Map<String, Value>,
    pub namespace:   Option<String>,
    pub description: Option<String>,
    pub node_type:   Option<String>,
    pub ttl:         u64,
}

impl AnchorFrame {
    pub fn frame_type() -> FrameType { FrameType::Anchor }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(),   json!(self.anchor_id));
        m.insert("schema".into(),      Value::Object(self.schema.clone()));
        m.insert("ttl".into(),         json!(self.ttl));
        if let Some(v) = &self.namespace   { m.insert("namespace".into(),   json!(v)); }
        if let Some(v) = &self.description { m.insert("description".into(), json!(v)); }
        if let Some(v) = &self.node_type   { m.insert("node_type".into(),   json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id = get_str(d, "anchor_id")?.to_string();
        let schema    = d.get("schema")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let ttl       = opt_u64(d, "ttl").unwrap_or(3600);
        Ok(AnchorFrame {
            anchor_id,
            schema,
            namespace:   opt_str(d, "namespace").map(str::to_string),
            description: opt_str(d, "description").map(str::to_string),
            node_type:   opt_str(d, "node_type").map(str::to_string),
            ttl,
        })
    }
}

// ── DiffFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiffFrame {
    pub anchor_id:     String,
    pub new_anchor_id: String,
    pub patch:         Vec<Value>,
}

impl DiffFrame {
    pub fn frame_type() -> FrameType { FrameType::Diff }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(),     json!(self.anchor_id));
        m.insert("new_anchor_id".into(), json!(self.new_anchor_id));
        m.insert("patch".into(),         Value::Array(self.patch.clone()));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id     = get_str(d, "anchor_id")?.to_string();
        let new_anchor_id = get_str(d, "new_anchor_id")?.to_string();
        let patch         = d.get("patch").and_then(Value::as_array).cloned().unwrap_or_default();
        Ok(DiffFrame { anchor_id, new_anchor_id, patch })
    }
}

// ── StreamFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub anchor_id: String,
    pub seq:       u64,
    pub payload:   Value,
    pub is_last:   bool,
}

impl StreamFrame {
    pub fn frame_type() -> FrameType { FrameType::Stream }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(), json!(self.anchor_id));
        m.insert("seq".into(),       json!(self.seq));
        m.insert("payload".into(),   self.payload.clone());
        m.insert("is_last".into(),   json!(self.is_last));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id = get_str(d, "anchor_id")?.to_string();
        let seq       = opt_u64(d, "seq").unwrap_or(0);
        let payload   = d.get("payload").cloned().unwrap_or(Value::Null);
        let is_last   = d.get("is_last").and_then(Value::as_bool).unwrap_or(false);
        Ok(StreamFrame { anchor_id, seq, payload, is_last })
    }
}

// ── CapsFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapsFrame {
    pub node_id:    String,
    pub caps:       Vec<String>,
    pub anchor_ref: Option<String>,
    pub payload:    Option<Value>,
}

impl CapsFrame {
    pub fn frame_type() -> FrameType { FrameType::Caps }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("node_id".into(), json!(self.node_id));
        m.insert("caps".into(),    json!(self.caps));
        if let Some(v) = &self.anchor_ref { m.insert("anchor_ref".into(), json!(v)); }
        if let Some(v) = &self.payload    { m.insert("payload".into(),    v.clone()); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let node_id = get_str(d, "node_id")?.to_string();
        let caps    = d.get("caps").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(CapsFrame {
            node_id,
            caps,
            anchor_ref: opt_str(d, "anchor_ref").map(str::to_string),
            payload:    d.get("payload").cloned(),
        })
    }
}

// ── ErrorFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ErrorFrame {
    pub error_code: String,
    pub message:    String,
    pub detail:     Option<Value>,
}

impl ErrorFrame {
    pub fn frame_type() -> FrameType { FrameType::Error }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("error_code".into(), json!(self.error_code));
        m.insert("message".into(),    json!(self.message));
        if let Some(v) = &self.detail { m.insert("detail".into(), v.clone()); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ErrorFrame {
            error_code: get_str(d, "error_code")?.to_string(),
            message:    get_str(d, "message")?.to_string(),
            detail:     d.get("detail").cloned(),
        })
    }
}
