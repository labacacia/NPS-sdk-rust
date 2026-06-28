// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

use crate::error_codes::{GRAPH_INVALID, GRAPH_TOO_LARGE};

const MAX_GRAPH_NODES: usize = 256;
const MAX_GRAPH_EDGES: usize = 1024;

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

// ── AnnounceFrame ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnnounceFrame {
    pub nid: String,
    pub addresses: Vec<serde_json::Map<String, Value>>,
    pub caps: Vec<String>,
    pub ttl: u64,
    pub timestamp: String,
    pub signature: String,
    pub node_type: Option<String>,
    pub node_roles: Option<Vec<String>>,
    pub cluster_anchor: Option<String>,
    /// NDP v0.9 — opaque string reference resolving to a SpawnSpec.
    pub spawn_spec_ref: Option<String>,
    pub bridge_protocols: Option<Vec<String>>,
    pub activation_mode: Option<String>,
    pub activation_endpoint: Option<serde_json::Map<String, Value>>,
    /// NDP v0.9 — keepalive interval in ms; 0 means disabled.
    pub heartbeat_interval_ms: u64,
    /// NDP v0.9 liveness — wire-only, EXCLUDED from the signed canonical form
    /// (last_seen updates every heartbeat → must not require re-signing; §3.2.1).
    pub health: Option<String>, // "healthy" / "degraded" / "draining"
    pub last_seen: Option<String>, // ISO 8601 UTC liveness beat
}

impl AnnounceFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Announce
    }

    /// Dict without signature — for signing / verifying
    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nid".into(), json!(self.nid));
        m.insert("addresses".into(), json!(self.addresses));
        m.insert("capabilities".into(), json!(self.caps));
        m.insert("ttl".into(), json!(self.ttl));
        m.insert("timestamp".into(), json!(self.timestamp));
        m.insert(
            "heartbeat_interval_ms".into(),
            json!(self.heartbeat_interval_ms),
        );
        if let Some(v) = &self.node_type {
            m.insert("node_type".into(), json!(v));
        }
        if let Some(v) = &self.node_roles {
            m.insert("node_roles".into(), json!(v));
        }
        if let Some(v) = &self.cluster_anchor {
            m.insert("cluster_anchor".into(), json!(v));
        }
        if let Some(v) = &self.spawn_spec_ref {
            m.insert("spawn_spec_ref".into(), json!(v));
        }
        if let Some(v) = &self.bridge_protocols {
            m.insert("bridge_protocols".into(), json!(v));
        }
        if let Some(v) = &self.activation_mode {
            m.insert("activation_mode".into(), json!(v));
        }
        if let Some(v) = &self.activation_endpoint {
            m.insert("activation_endpoint".into(), Value::Object(v.clone()));
        }
        // Sort for canonical representation
        let sorted: BTreeMap<String, Value> = m.into_iter().collect();
        sorted.into_iter().collect()
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        m.insert("signature".into(), json!(self.signature));
        if let Some(v) = &self.node_roles {
            m.insert("node_roles".into(), json!(v));
        }
        if let Some(v) = &self.cluster_anchor {
            m.insert("cluster_anchor".into(), json!(v));
        }
        if let Some(v) = &self.spawn_spec_ref {
            m.insert("spawn_spec_ref".into(), json!(v));
        }
        if let Some(v) = &self.bridge_protocols {
            m.insert("bridge_protocols".into(), json!(v));
        }
        if let Some(v) = &self.activation_mode {
            m.insert("activation_mode".into(), json!(v));
        }
        if let Some(v) = &self.activation_endpoint {
            m.insert("activation_endpoint".into(), Value::Object(v.clone()));
        }
        m.insert(
            "heartbeat_interval_ms".into(),
            json!(self.heartbeat_interval_ms),
        );
        // Liveness fields live on the wire only (not in unsigned_dict → not signed).
        if let Some(v) = &self.health {
            m.insert("health".into(), json!(v));
        }
        if let Some(v) = &self.last_seen {
            m.insert("last_seen".into(), json!(v));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let addresses = d
            .get("addresses")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_object).cloned().collect())
            .unwrap_or_default();
        let caps_raw = d.get("capabilities").or_else(|| d.get("caps"));
        let caps = caps_raw
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let node_roles = d.get("node_roles").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        });
        let bridge_protocols = d
            .get("bridge_protocols")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            });
        Ok(AnnounceFrame {
            nid: get_str(d, "nid")?.to_string(),
            addresses,
            caps,
            ttl: opt_u64(d, "ttl").unwrap_or(300),
            timestamp: get_str(d, "timestamp")?.to_string(),
            signature: opt_str(d, "signature").unwrap_or("").to_string(),
            node_type: opt_str(d, "node_type").map(str::to_string),
            node_roles,
            cluster_anchor: opt_str(d, "cluster_anchor").map(str::to_string),
            spawn_spec_ref: opt_str(d, "spawn_spec_ref").map(str::to_string),
            bridge_protocols,
            activation_mode: opt_str(d, "activation_mode").map(str::to_string),
            activation_endpoint: d
                .get("activation_endpoint")
                .and_then(Value::as_object)
                .cloned(),
            heartbeat_interval_ms: opt_u64(d, "heartbeat_interval_ms").unwrap_or(60_000),
            health: opt_str(d, "health").map(str::to_string),
            last_seen: opt_str(d, "last_seen").map(str::to_string),
        })
    }
}

// ── ResolveFrame ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ResolveFrame {
    pub target: String,
    pub requester_nid: Option<String>,
    pub resolved: Option<serde_json::Map<String, Value>>,
}

impl ResolveFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Resolve
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("target".into(), json!(self.target));
        if let Some(v) = &self.requester_nid {
            m.insert("requester_nid".into(), json!(v));
        }
        if let Some(v) = &self.resolved {
            m.insert("resolved".into(), Value::Object(v.clone()));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ResolveFrame {
            target: get_str(d, "target")?.to_string(),
            requester_nid: opt_str(d, "requester_nid").map(str::to_string),
            resolved: d.get("resolved").and_then(Value::as_object).cloned(),
        })
    }
}

// ── GraphNode ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub nid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_roles: Option<Vec<String>>,
}

// ── GraphEdge ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub from_nid: String,
    pub to_nid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
}

// ── GraphFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GraphFrame {
    pub graph_id: String,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    pub ttl: u32,
    pub metadata: Option<serde_json::Map<String, Value>>,
}

impl GraphFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Graph
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("graph_id".into(), json!(self.graph_id));
        m.insert("nodes".into(), json!(self.nodes));
        m.insert("edges".into(), json!(self.edges));
        m.insert("ttl".into(), json!(self.ttl));
        if let Some(v) = &self.metadata {
            m.insert("metadata".into(), Value::Object(v.clone()));
        }
        m
    }

    pub fn validate(&self) -> NpsResult<()> {
        if self.nodes.len() > MAX_GRAPH_NODES {
            return Err(NpsError::Frame(format!(
                "{GRAPH_TOO_LARGE}: nodes length exceeds {MAX_GRAPH_NODES}"
            )));
        }
        if self.edges.len() > MAX_GRAPH_EDGES {
            return Err(NpsError::Frame(format!(
                "{GRAPH_TOO_LARGE}: edges length exceeds {MAX_GRAPH_EDGES}"
            )));
        }

        let mut node_ids = HashSet::with_capacity(self.nodes.len());
        for node in &self.nodes {
            if node.nid.is_empty() {
                return Err(NpsError::Frame(format!(
                    "{GRAPH_INVALID}: graph nodes require nid"
                )));
            }
            node_ids.insert(node.nid.as_str());
        }
        for edge in &self.edges {
            if edge.from_nid.is_empty() || edge.to_nid.is_empty() {
                return Err(NpsError::Frame(format!(
                    "{GRAPH_INVALID}: graph edges require from_nid and to_nid"
                )));
            }
            if edge.from_nid == edge.to_nid {
                return Err(NpsError::Frame(format!(
                    "{GRAPH_INVALID}: graph self-edges are forbidden"
                )));
            }
            if !node_ids.contains(edge.from_nid.as_str())
                || !node_ids.contains(edge.to_nid.as_str())
            {
                return Err(NpsError::Frame(format!(
                    "{GRAPH_INVALID}: graph edge endpoints must appear in nodes"
                )));
            }
        }
        Ok(())
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let nodes: Vec<GraphNode> = d
            .get("nodes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let edges: Vec<GraphEdge> = d
            .get("edges")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| serde_json::from_value(v.clone()).ok())
                    .collect()
            })
            .unwrap_or_default();
        let frame = GraphFrame {
            graph_id: opt_str(d, "graph_id").unwrap_or("").to_string(),
            nodes,
            edges,
            ttl: d.get("ttl").and_then(Value::as_u64).unwrap_or(300) as u32,
            metadata: d.get("metadata").and_then(Value::as_object).cloned(),
        };
        frame.validate()?;
        Ok(frame)
    }
}
