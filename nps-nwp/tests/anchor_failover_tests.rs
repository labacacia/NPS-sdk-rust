// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS-CR-0009 — `anchor_failover` / `anchor_quorum_lost` AnchorState sub-types
//! and `cluster_epoch` on TopologySnapshot.
//!
//! Ports `tests/NPS.Tests/Nwp/NwpAnchorFailoverTests.cs` (brief A §5.2) plus the
//! full-envelope JSON round-trip and the §5.6 "not covered anywhere" cases the
//! .NET tree has no implementation for.
//!
//! These assert on **wire key names inside `details`** — renaming a key fails
//! the suite, which is the point.

use nps_nwp::anchor_client::{AnchorState, TopologyEvent, TopologySnapshot};
use nps_nwp::anchor_server::{
    AnchorNodeApp, AnchorNodeOptions, AnchorRequest, InMemoryAnchorTopologyService,
};
use serde_json::{json, Value};

const NID: &str = "urn:nps:node:api.test:anchor-a";

fn parts(ev: &TopologyEvent) -> (u64, String, Value) {
    match ev {
        TopologyEvent::AnchorState {
            version,
            field,
            details,
        } => (*version, field.clone(), details.clone().unwrap()),
        other => panic!("expected AnchorState, got {other:?}"),
    }
}

// ── §5.2 ─────────────────────────────────────────────────────────────────────

#[test]
fn failover_event_carries_successor_epoch_reason() {
    let ev = AnchorState::failover_with(
        "urn:nps:node:x:anchor-b",
        3,
        AnchorState::REASON_ACTIVE_LOST,
        0,
    );
    let (_, field, d) = parts(&ev);
    assert_eq!(field, "anchor_failover");
    assert_eq!(d["successor_nid"], "urn:nps:node:x:anchor-b");
    assert_eq!(d["cluster_epoch"], json!(3u64));
    assert!(d["cluster_epoch"].is_u64(), "cluster_epoch must be uint64");
    assert_eq!(d["reason"], "active_lost");
}

#[test]
fn quorum_lost_event_carries_counts() {
    let ev = AnchorState::quorum_lost(3, 1);
    let (_, field, d) = parts(&ev);
    assert_eq!(field, "anchor_quorum_lost");
    assert_eq!(d["quorum_size"], json!(3u32));
    assert_eq!(d["available"], json!(1u32));
    assert!(d["quorum_size"].is_u64());
    assert!(d["available"].is_u64());
}

#[test]
fn failover_reason_defaults_to_planned() {
    let ev = AnchorState::failover("urn:nps:node:x:anchor-b", 2);
    let (version, field, d) = parts(&ev);
    assert_eq!(field, "anchor_failover");
    assert_eq!(d["reason"], "planned");
    assert_eq!(version, 0, "version defaults to 0");
}

#[test]
fn sub_type_tags_are_the_exact_wire_strings() {
    assert_eq!(AnchorState::FIELD_VERSION_REBASED, "version_rebased");
    assert_eq!(AnchorState::FIELD_ANCHOR_FAILOVER, "anchor_failover");
    assert_eq!(AnchorState::FIELD_ANCHOR_QUORUM_LOST, "anchor_quorum_lost");
    assert_eq!(AnchorState::REASON_PLANNED, "planned");
    assert_eq!(AnchorState::REASON_ACTIVE_LOST, "active_lost");
}

#[test]
fn details_carry_exactly_the_specified_keys() {
    let (_, _, f) = parts(&AnchorState::failover("urn:nps:node:x:b", 2));
    let mut keys: Vec<&str> = f.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["cluster_epoch", "reason", "successor_nid"]);

    let (_, _, q) = parts(&AnchorState::quorum_lost(3, 1));
    let mut keys: Vec<&str> = q.as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["available", "quorum_size"]);
}

// ── full-envelope round-trip through the Anchor server ───────────────────────

fn app_with_events(events: Vec<TopologyEvent>, cluster_epoch: Option<u64>) -> AnchorNodeApp {
    let topo = Box::new(InMemoryAnchorTopologyService {
        nid: NID.into(),
        members: vec![],
        version: 7,
        events,
        cluster_epoch,
    });
    let mut o = AnchorNodeOptions::new(NID, "/gw");
    o.require_auth = false;
    AnchorNodeApp::new(o, None, Some(topo), None)
}

#[tokio::test]
async fn anchor_state_events_round_trip_on_the_stream_envelope() {
    let app = app_with_events(
        vec![
            AnchorState::failover_with(
                "urn:nps:node:x:anchor-b",
                3,
                AnchorState::REASON_ACTIVE_LOST,
                9,
            ),
            AnchorState::quorum_lost_with(3, 1, 10),
        ],
        Some(3),
    );

    let body = json!({
        "type": "topology.stream", "action": "subscribe", "stream_id": "s-1",
        "topology": { "scope": "cluster" }
    });
    let resp = app
        .handle(AnchorRequest::new("POST", "/gw/subscribe").with_json(&body))
        .await;
    assert_eq!(resp.status, 200);

    let lines = resp.ndjson_lines();
    // [0] is the subscription ack.
    let failover = &lines[1];
    assert_eq!(failover["event_type"], "anchor_state");
    assert_eq!(failover["seq"], 9);
    assert_eq!(failover["payload"]["field"], "anchor_failover");
    assert_eq!(
        failover["payload"]["details"]["successor_nid"],
        "urn:nps:node:x:anchor-b"
    );
    assert_eq!(failover["payload"]["details"]["cluster_epoch"], 3);
    assert_eq!(failover["payload"]["details"]["reason"], "active_lost");

    let quorum = &lines[2];
    assert_eq!(quorum["event_type"], "anchor_state");
    assert_eq!(quorum["payload"]["field"], "anchor_quorum_lost");
    assert_eq!(quorum["payload"]["details"]["quorum_size"], 3);
    assert_eq!(quorum["payload"]["details"]["available"], 1);
}

#[tokio::test]
async fn snapshot_response_carries_cluster_epoch() {
    let app = app_with_events(vec![], Some(4));
    let body = json!({ "type": "topology.snapshot", "topology": { "scope": "cluster" } });
    let resp = app
        .handle(AnchorRequest::new("POST", "/gw/query").with_json(&body))
        .await;
    assert_eq!(resp.status, 200);

    let v = resp.json_value().unwrap();
    assert_eq!(v["data"][0]["cluster_epoch"], 4);

    let snap: TopologySnapshot = serde_json::from_value(v["data"][0].clone()).unwrap();
    assert_eq!(snap.cluster_epoch, Some(4));
    assert_eq!(snap.effective_cluster_epoch(), 4);
}

#[tokio::test]
async fn single_anchor_snapshot_omits_cluster_epoch_and_reads_as_one() {
    let app = app_with_events(vec![], None);
    let body = json!({ "type": "topology.snapshot", "topology": { "scope": "cluster" } });
    let resp = app
        .handle(AnchorRequest::new("POST", "/gw/query").with_json(&body))
        .await;

    let v = resp.json_value().unwrap();
    assert!(v["data"][0].get("cluster_epoch").is_none());

    let snap: TopologySnapshot = serde_json::from_value(v["data"][0].clone()).unwrap();
    assert_eq!(snap.cluster_epoch, None);
    assert_eq!(snap.effective_cluster_epoch(), 1);
}

#[test]
fn unknown_anchor_state_sub_types_stay_decodable() {
    // Subscribers already MUST ignore unknown anchor_state sub-types, so the
    // two new ones are safe for pre-CR-0009 subscribers: the decoder keeps the
    // tag and payload verbatim rather than rejecting them.
    let ev = TopologyEvent::AnchorState {
        version: 1,
        field: "some_future_subtype".into(),
        details: Some(json!({ "x": 1 })),
    };
    let (_, field, d) = parts(&ev);
    assert_eq!(field, "some_future_subtype");
    assert_eq!(d["x"], 1);
}
