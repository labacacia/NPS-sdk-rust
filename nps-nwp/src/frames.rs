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

// ── QueryFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct QueryFrame {
    pub anchor_ref:  String,
    pub filter:      Option<Value>,
    pub order:       Option<Value>,
    pub token_budget: Option<u64>,
    pub limit:       Option<u64>,
    pub offset:      Option<u64>,
}

impl QueryFrame {
    pub fn new(anchor_ref: impl Into<String>) -> Self {
        QueryFrame {
            anchor_ref: anchor_ref.into(),
            filter: None, order: None, token_budget: None, limit: None, offset: None,
        }
    }

    pub fn frame_type() -> FrameType { FrameType::Query }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_ref".into(), json!(self.anchor_ref));
        if let Some(v) = &self.filter       { m.insert("filter".into(),       v.clone()); }
        if let Some(v) = &self.order        { m.insert("order".into(),        v.clone()); }
        if let Some(v) = self.token_budget  { m.insert("token_budget".into(), json!(v)); }
        if let Some(v) = self.limit         { m.insert("limit".into(),        json!(v)); }
        if let Some(v) = self.offset        { m.insert("offset".into(),       json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(QueryFrame {
            anchor_ref:   get_str(d, "anchor_ref")?.to_string(),
            filter:       d.get("filter").cloned(),
            order:        d.get("order").cloned(),
            token_budget: opt_u64(d, "token_budget"),
            limit:        opt_u64(d, "limit"),
            offset:       opt_u64(d, "offset"),
        })
    }
}

// ── ActionFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ActionFrame {
    pub action:    String,
    pub params:    Option<Value>,
    pub anchor_ref: Option<String>,
    pub async_:    bool,
}

impl ActionFrame {
    pub fn frame_type() -> FrameType { FrameType::Action }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("action".into(), json!(self.action));
        m.insert("async".into(),  json!(self.async_));
        if let Some(v) = &self.params     { m.insert("params".into(),     v.clone()); }
        if let Some(v) = &self.anchor_ref { m.insert("anchor_ref".into(), json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ActionFrame {
            action:     get_str(d, "action")?.to_string(),
            params:     d.get("params").cloned(),
            anchor_ref: opt_str(d, "anchor_ref").map(str::to_string),
            async_:     d.get("async").and_then(Value::as_bool).unwrap_or(false),
        })
    }
}

// ── AsyncActionResponse ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AsyncActionResponse {
    pub task_id:     String,
    pub status_url:  Option<String>,
    pub callback_url: Option<String>,
}

impl AsyncActionResponse {
    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(AsyncActionResponse {
            task_id:      get_str(d, "task_id")?.to_string(),
            status_url:   opt_str(d, "status_url").map(str::to_string),
            callback_url: opt_str(d, "callback_url").map(str::to_string),
        })
    }
}
