// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Typed HTTP client for an Anchor Node's reserved query types
//! (`topology.snapshot` and `topology.stream` — NPS-2 §12).
//!
//! # Quick start
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use nps_nwp::{AnchorNodeClient, SCOPE_CLUSTER};
//! use futures::StreamExt;
//!
//! let client = AnchorNodeClient::new("http://anchor.local:7400");
//!
//! // Pull the current snapshot
//! let snapshot = client.get_snapshot().await?;
//! println!("cluster_size={}", snapshot.cluster_size);
//!
//! // Stream live events
//! let mut stream = client.subscribe().await?;
//! while let Some(event) = stream.next().await {
//!     println!("{:?}", event?);
//! }
//! # Ok(())
//! # }
//! ```

use bytes::Bytes;
use futures::Stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::pin::Pin;

// ── Wire constants ────────────────────────────────────────────────────────────

pub const SCOPE_CLUSTER: &str = "cluster";
pub const SCOPE_MEMBER: &str = "member";

const TYPE_SNAPSHOT: &str = "topology.snapshot";
const TYPE_STREAM: &str = "topology.stream";

const EVENT_MEMBER_JOINED: &str = "member_joined";
const EVENT_MEMBER_LEFT: &str = "member_left";
const EVENT_MEMBER_UPDATED: &str = "member_updated";
const EVENT_ANCHOR_STATE: &str = "anchor_state";
const EVENT_RESYNC_REQUIRED: &str = "resync_required";

// ── Data types ────────────────────────────────────────────────────────────────

/// Per-member metadata returned in a [`TopologySnapshot`] or a
/// [`TopologyEvent::MemberJoined`] event (NPS-2 §12.1 member object schema).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemberInfo {
    pub nid: String,
    pub node_roles: Vec<String>,
    pub activation_mode: String,
    pub child_anchor: Option<bool>,
    pub member_count: Option<u32>,
    pub tags: Option<Vec<String>>,
    pub joined_at: Option<String>,
    pub last_seen: Option<String>,
    pub capabilities: Option<Value>,
    pub metrics: Option<Value>,
}

/// Materialized cluster topology returned by [`AnchorNodeClient::get_snapshot`]
/// (NPS-2 §12.1).
#[derive(Debug, Clone, Deserialize)]
pub struct TopologySnapshot {
    pub version: u64,
    pub anchor_nid: String,
    pub cluster_size: u32,
    pub members: Vec<MemberInfo>,
    pub truncated: Option<bool>,
}

/// Subscriber-side filter for [`AnchorNodeClient::subscribe_with`].
/// All populated clauses are AND-combined (NPS-2 §12.2).
#[derive(Debug, Clone, Serialize, Default)]
pub struct TopologyFilter {
    /// Member's tag set MUST overlap with this list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags_any: Option<Vec<String>>,
    /// Member's tag set MUST be a superset of this list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags_all: Option<Vec<String>>,
    /// Member's `node_roles` MUST contain at least one of these values.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_roles: Option<Vec<String>>,
}

/// Field-level diff per NPS-CR-0002 §10. Only populated fields changed.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct MemberChanges {
    pub node_roles: Option<Vec<String>>,
    pub activation_mode: Option<String>,
    pub tags: Option<Vec<String>>,
    pub member_count: Option<u32>,
    pub last_seen: Option<String>,
    pub capabilities: Option<Value>,
    pub metrics: Option<Value>,
}

/// Live event emitted on a `topology.stream` subscription (NPS-2 §12.2).
#[derive(Debug, Clone)]
pub enum TopologyEvent {
    /// A new member joined the cluster.
    MemberJoined { version: u64, member: MemberInfo },
    /// A member left (or was removed from) the cluster.
    MemberLeft { version: u64, nid: String },
    /// A member's fields changed; only modified fields are present.
    MemberUpdated {
        version: u64,
        nid: String,
        changes: MemberChanges,
    },
    /// Anchor internal state change (e.g. `version_rebased`).
    AnchorState {
        version: u64,
        field: String,
        details: Option<Value>,
    },
    /// The requested `since_version` is no longer replayable; caller MUST
    /// fetch a fresh snapshot before resubscribing.
    ResyncRequired { reason: String },
}

/// Errors returned by [`AnchorNodeClient`] operations.
#[derive(Debug, thiserror::Error)]
pub enum AnchorTopologyError {
    #[error("NWP error {nwp_error_code} ({nps_status}): {message}")]
    Protocol {
        nwp_error_code: String,
        nps_status: String,
        message: String,
    },
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },
    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Stream ended unexpectedly")]
    StreamEnded,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Typed HTTP client for an Anchor Node's `/query` and `/subscribe` endpoints.
///
/// Constructed via [`AnchorNodeClient::new`]; optionally customised with
/// [`with_path_prefix`][Self::with_path_prefix] and
/// [`with_client`][Self::with_client].
pub struct AnchorNodeClient {
    base_url: String,
    path_prefix: String,
    http: reqwest::Client,
}

impl AnchorNodeClient {
    /// Build a new client pointing at `base_url` (trailing slashes are stripped).
    pub fn new(base_url: impl Into<String>) -> Self {
        AnchorNodeClient {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            path_prefix: String::new(),
            http: reqwest::Client::new(),
        }
    }

    /// Override the path prefix for the Anchor middleware (e.g. `"/anchor"`).
    /// Leading slash is kept; trailing slash is stripped.
    pub fn with_path_prefix(mut self, prefix: impl Into<String>) -> Self {
        let p = prefix.into();
        self.path_prefix = p.trim_end_matches('/').to_string();
        self
    }

    /// Supply a pre-configured [`reqwest::Client`] (e.g. with auth headers or
    /// a custom TLS stack).
    pub fn with_client(mut self, client: reqwest::Client) -> Self {
        self.http = client;
        self
    }

    // ── topology.snapshot ────────────────────────────────────────────────────

    /// Fetch the current cluster topology with default parameters
    /// (`scope=cluster`, `depth=1`).
    pub async fn get_snapshot(&self) -> Result<TopologySnapshot, AnchorTopologyError> {
        self.get_snapshot_with(SCOPE_CLUSTER, &[], 1, None).await
    }

    /// Fetch the current cluster topology with explicit parameters (NPS-2 §12.1).
    ///
    /// * `scope`      — `"cluster"` or `"member"` (use [`SCOPE_CLUSTER`] /
    ///   [`SCOPE_MEMBER`]).
    /// * `include`    — slice of include tokens, e.g. `&["members", "capabilities"]`.
    ///   Empty slice uses the server default.
    /// * `depth`      — recursion depth into sub-clusters (`1` = direct members only).
    /// * `target_nid` — required when `scope == "member"`.
    pub async fn get_snapshot_with(
        &self,
        scope: &str,
        include: &[&str],
        depth: u8,
        target_nid: Option<&str>,
    ) -> Result<TopologySnapshot, AnchorTopologyError> {
        let mut topology = serde_json::json!({ "scope": scope });
        if !include.is_empty() {
            topology["include"] = Value::Array(
                include
                    .iter()
                    .map(|s| Value::String(s.to_string()))
                    .collect(),
            );
        }
        if depth != 1 {
            topology["depth"] = Value::Number(depth.into());
        }
        if let Some(nid) = target_nid {
            topology["target_nid"] = Value::String(nid.to_string());
        }

        let body = serde_json::json!({
            "type":     TYPE_SNAPSHOT,
            "topology": topology,
        });

        let url = format!("{}{}/query", self.base_url, self.path_prefix);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(parse_error_body(status.as_u16(), &body_text));
        }

        // Response shape: { "data": [ <snapshot> ] }
        let mut caps: serde_json::Value = resp.json().await?;
        let snapshot_value = caps["data"]
            .as_array_mut()
            .and_then(|arr| {
                if arr.is_empty() {
                    None
                } else {
                    Some(arr.swap_remove(0))
                }
            })
            .ok_or_else(|| AnchorTopologyError::Http {
                status: 200,
                body: "topology.snapshot: data array missing or empty".to_string(),
            })?;

        let snapshot: TopologySnapshot = serde_json::from_value(snapshot_value)?;
        Ok(snapshot)
    }

    // ── topology.stream ──────────────────────────────────────────────────────

    /// Subscribe to live topology changes with default parameters
    /// (`scope=cluster`, no filter, from "now").
    pub async fn subscribe(
        &self,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<TopologyEvent, AnchorTopologyError>> + Send>>,
        AnchorTopologyError,
    > {
        self.subscribe_with(SCOPE_CLUSTER, None, None).await
    }

    /// Subscribe to live topology changes (NPS-2 §12.2).
    ///
    /// * `scope`         — `"cluster"` or `"member"`.
    /// * `filter`        — optional member filter; `None` means no filter.
    /// * `since_version` — resume from a previous version; `None` means "from now".
    ///
    /// Returns a [`Stream`] of [`TopologyEvent`] items. The first NDJSON line
    /// (subscription ack) is consumed internally and not yielded. When a
    /// [`TopologyEvent::ResyncRequired`] event is received, it is yielded and
    /// the stream terminates — the caller MUST fetch a fresh snapshot before
    /// resubscribing.
    pub async fn subscribe_with(
        &self,
        scope: &str,
        filter: Option<&TopologyFilter>,
        since_version: Option<u64>,
    ) -> Result<
        Pin<Box<dyn Stream<Item = Result<TopologyEvent, AnchorTopologyError>> + Send>>,
        AnchorTopologyError,
    > {
        let stream_id = format!(
            "anc-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let mut topology = serde_json::json!({ "scope": scope });
        if let Some(f) = filter {
            topology["filter"] = serde_json::to_value(f)?;
        }
        if let Some(sv) = since_version {
            topology["since_version"] = Value::Number(sv.into());
        }

        let body = serde_json::json!({
            "type":      TYPE_STREAM,
            "action":    "subscribe",
            "stream_id": stream_id,
            "topology":  topology,
        });

        let url = format!("{}{}/subscribe", self.base_url, self.path_prefix);
        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/x-ndjson")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(parse_error_body(status.as_u16(), &body_text));
        }

        // We have the response headers; now stream the body.
        let byte_stream = resp.bytes_stream();
        let out = parse_event_stream(byte_stream);
        Ok(Box::pin(out))
    }
}

// ── Stream parser ─────────────────────────────────────────────────────────────

/// Drives a `bytes_stream()` response, buffers lines, skips the ack, then
/// yields deserialized [`TopologyEvent`]s.
fn parse_event_stream(
    byte_stream: impl Stream<Item = Result<Bytes, reqwest::Error>> + Send + 'static,
) -> impl Stream<Item = Result<TopologyEvent, AnchorTopologyError>> + Send {
    async_stream::stream! {
        use futures::StreamExt;

        let mut byte_stream = Box::pin(byte_stream);
        let mut buf = String::new();
        let mut ack_skipped = false;

        loop {
            match byte_stream.next().await {
                None => {
                    // Flush any remaining buffered data
                    if !buf.is_empty() {
                        let line = buf.trim_end_matches('\r').to_string();
                        buf.clear();
                        if !line.is_empty() {
                            if !ack_skipped {
                                ack_skipped = true;
                                continue;
                            }
                            match parse_event_line(&line) {
                                Ok(Some(ev)) => {
                                    let is_resync = matches!(ev, TopologyEvent::ResyncRequired { .. });
                                    yield Ok(ev);
                                    if is_resync { return; }
                                }
                                Ok(None) => {}
                                Err(e) => { yield Err(e); return; }
                            }
                        }
                    }
                    return;
                }
                Some(Err(e)) => {
                    yield Err(AnchorTopologyError::Reqwest(e));
                    return;
                }
                Some(Ok(chunk)) => {
                    let text = match std::str::from_utf8(&chunk) {
                        Ok(s) => s.to_string(),
                        Err(_) => {
                            yield Err(AnchorTopologyError::Http {
                                status: 0,
                                body: "stream contained invalid UTF-8".to_string(),
                            });
                            return;
                        }
                    };
                    buf.push_str(&text);

                    // Process all complete lines in the buffer
                    while let Some(nl_pos) = buf.find('\n') {
                        let line = buf[..nl_pos].trim_end_matches('\r').to_string();
                        buf.drain(..=nl_pos);

                        if line.is_empty() {
                            continue;
                        }

                        if !ack_skipped {
                            ack_skipped = true;
                            continue;
                        }

                        match parse_event_line(&line) {
                            Ok(Some(ev)) => {
                                let is_resync = matches!(ev, TopologyEvent::ResyncRequired { .. });
                                yield Ok(ev);
                                if is_resync { return; }
                            }
                            Ok(None) => {}
                            Err(e) => { yield Err(e); return; }
                        }
                    }
                }
            }
        }
    }
}

/// Parse one NDJSON line into a [`TopologyEvent`], returning:
/// - `Ok(Some(ev))` — a valid event
/// - `Ok(None)`     — unknown/irrelevant event type; caller skips
/// - `Err(e)`       — protocol error or JSON parse error; caller terminates
fn parse_event_line(line: &str) -> Result<Option<TopologyEvent>, AnchorTopologyError> {
    let root: serde_json::Value = serde_json::from_str(line)?;

    // Error envelope: has "error" + "status" but no "event_type"
    if root.get("event_type").is_none() {
        if let (Some(err), Some(st)) = (root.get("error"), root.get("status")) {
            if let (Some(e_str), Some(s_str)) = (err.as_str(), st.as_str()) {
                let msg = root
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("")
                    .to_string();
                return Err(AnchorTopologyError::Protocol {
                    nwp_error_code: e_str.to_string(),
                    nps_status: s_str.to_string(),
                    message: msg,
                });
            }
        }
        // Unrecognised non-event line — skip silently
        return Ok(None);
    }

    let event_type = match root["event_type"].as_str() {
        Some(s) => s,
        None => return Ok(None),
    };

    let seq: u64 = root.get("seq").and_then(|v| v.as_u64()).unwrap_or(0);
    let payload = root.get("payload").cloned().unwrap_or(Value::Null);

    let ev = match event_type {
        EVENT_MEMBER_JOINED => {
            let member: MemberInfo = serde_json::from_value(payload)?;
            TopologyEvent::MemberJoined {
                version: seq,
                member,
            }
        }
        EVENT_MEMBER_LEFT => {
            let nid = payload
                .get("nid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            TopologyEvent::MemberLeft { version: seq, nid }
        }
        EVENT_MEMBER_UPDATED => {
            let nid = payload
                .get("nid")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let changes_val = payload
                .get("changes")
                .cloned()
                .unwrap_or(Value::Object(Default::default()));
            let changes: MemberChanges = serde_json::from_value(changes_val)?;
            TopologyEvent::MemberUpdated {
                version: seq,
                nid,
                changes,
            }
        }
        EVENT_ANCHOR_STATE => {
            let field = payload
                .get("field")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let details = payload.get("details").cloned();
            TopologyEvent::AnchorState {
                version: seq,
                field,
                details,
            }
        }
        EVENT_RESYNC_REQUIRED => {
            let reason = payload
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            TopologyEvent::ResyncRequired { reason }
        }
        _ => return Ok(None),
    };

    Ok(Some(ev))
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn parse_error_body(status: u16, body: &str) -> AnchorTopologyError {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
        if let (Some(err), Some(st)) = (v.get("error"), v.get("status")) {
            if let (Some(e_str), Some(s_str)) = (err.as_str(), st.as_str()) {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or(body)
                    .to_string();
                return AnchorTopologyError::Protocol {
                    nwp_error_code: e_str.to_string(),
                    nps_status: s_str.to_string(),
                    message: msg,
                };
            }
        }
    }
    AnchorTopologyError::Http {
        status,
        body: body.to_string(),
    }
}
