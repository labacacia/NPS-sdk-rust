// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
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

// ── AnnounceFrame ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnnounceFrame {
    pub nid:       String,
    pub addresses: Vec<serde_json::Map<String, Value>>,
    pub caps:      Vec<String>,
    pub ttl:       u64,
    pub timestamp: String,
    pub signature: String,
    pub node_type: Option<String>,
}

impl AnnounceFrame {
    pub fn frame_type() -> FrameType { FrameType::Announce }

    /// Dict without signature — for signing / verifying
    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nid".into(),       json!(self.nid));
        m.insert("addresses".into(), json!(self.addresses));
        m.insert("caps".into(),      json!(self.caps));
        m.insert("ttl".into(),       json!(self.ttl));
        m.insert("timestamp".into(), json!(self.timestamp));
        m.insert("node_type".into(), Value::Null);
        // Sort for canonical representation
        let sorted: BTreeMap<String, Value> = m.into_iter().collect();
        sorted.into_iter().collect()
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        m.insert("signature".into(), json!(self.signature));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let addresses = d.get("addresses").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_object).cloned().collect())
            .unwrap_or_default();
        let caps = d.get("caps").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(AnnounceFrame {
            nid:       get_str(d, "nid")?.to_string(),
            addresses,
            caps,
            ttl:       opt_u64(d, "ttl").unwrap_or(300),
            timestamp: get_str(d, "timestamp")?.to_string(),
            signature: opt_str(d, "signature").unwrap_or("").to_string(),
            node_type: opt_str(d, "node_type").map(str::to_string),
        })
    }
}

// ── ResolveFrame ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResolveFrame {
    pub target:        String,
    pub requester_nid: Option<String>,
    pub resolved:      Option<serde_json::Map<String, Value>>,
}

impl ResolveFrame {
    pub fn frame_type() -> FrameType { FrameType::Resolve }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("target".into(), json!(self.target));
        if let Some(v) = &self.requester_nid { m.insert("requester_nid".into(), json!(v)); }
        if let Some(v) = &self.resolved      { m.insert("resolved".into(), Value::Object(v.clone())); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ResolveFrame {
            target:        get_str(d, "target")?.to_string(),
            requester_nid: opt_str(d, "requester_nid").map(str::to_string),
            resolved:      d.get("resolved").and_then(Value::as_object).cloned(),
        })
    }
}

// ── GraphFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GraphFrame {
    pub seq:          u64,
    pub initial_sync: bool,
    pub nodes:        Vec<Value>,
    pub patch:        Option<Vec<Value>>,
}

impl GraphFrame {
    pub fn frame_type() -> FrameType { FrameType::Graph }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("seq".into(),          json!(self.seq));
        m.insert("initial_sync".into(), json!(self.initial_sync));
        m.insert("nodes".into(),        json!(self.nodes));
        if let Some(p) = &self.patch { m.insert("patch".into(), json!(p)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(GraphFrame {
            seq:          opt_u64(d, "seq").unwrap_or(0),
            initial_sync: d.get("initial_sync").and_then(Value::as_bool).unwrap_or(false),
            nodes:        d.get("nodes").and_then(Value::as_array).cloned().unwrap_or_default(),
            patch:        d.get("patch").and_then(Value::as_array).cloned(),
        })
    }
}
