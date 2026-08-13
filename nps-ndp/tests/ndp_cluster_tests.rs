// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS-CR-0009 — `cluster_epoch` wire field, highest-epoch cluster resolution,
//! the `NDP-CLUSTER-SPLIT` split-brain fault, and the signature canonical-form
//! regressions that keep pre-CR-0009 signed announcements verifying.
//!
//! Ports `tests/NPS.Tests/Ndp/NdpClusterResolutionTests.cs` (brief A §5.1) plus
//! the canonical-form template `NdpFrameTests.AnnounceFrame_CanonicalJson_*`
//! (brief A §5.5).

use nps_ndp::{AnnounceFrame, InMemoryNdpRegistry, NdpClusterResolution};
use serde_json::{json, Map, Value};
use std::time::{Duration, Instant};

const CLUSTER: &str = "urn:nps:cluster:api.test:main";
const TS: &str = "2026-07-05T00:00:00Z";

fn addr() -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("host".into(), json!("10.0.0.1"));
    m.insert("port".into(), json!(17433));
    m.insert("protocol".into(), json!("nwp"));
    m
}

/// A cluster member fixture matching the .NET test fixture exactly.
fn member(local: &str, cluster_epoch: Option<u64>) -> AnnounceFrame {
    AnnounceFrame {
        nid: format!("urn:nps:node:api.test:{local}"),
        addresses: vec![addr()],
        caps: vec!["topology.read".into()],
        ttl: 3600,
        timestamp: TS.into(),
        signature: "ed25519:placeholder".into(),
        node_type: Some("anchor".into()),
        node_roles: Some(vec!["anchor".into()]),
        cluster_anchor: Some(CLUSTER.into()),
        cluster_epoch,
        spawn_spec_ref: None,
        bridge_protocols: None,
        bridge_inbound_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
        graph_seq: None,
    }
}

/// Canonical JSON exactly as the signing path produces it (NIP canonicalisation
/// over `unsigned_dict()`); `serde_json::Map` is a `BTreeMap` here, so nesting
/// is sorted too.
fn canonical(frame: &AnnounceFrame) -> String {
    serde_json::to_string(&Value::Object(frame.unsigned_dict())).unwrap()
}

// ── §5.1 cluster resolution ──────────────────────────────────────────────────

#[test]
fn resolves_the_highest_epoch_active_anchor() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", Some(1)));
    reg.announce(member("anchor-b", Some(3)));

    let winner = reg.resolve_cluster(CLUSTER).expect("must not split");
    let winner = winner.expect("must resolve");
    assert_eq!(winner.nid, "urn:nps:node:api.test:anchor-b");
    assert_eq!(winner.cluster_epoch, Some(3));
    assert_eq!(winner.effective_cluster_epoch(), 3);
}

#[test]
fn absent_epoch_is_treated_as_one() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", None));

    let winner = reg.resolve_cluster(CLUSTER).expect("must not split");
    let winner = winner.expect("must resolve");
    assert_eq!(winner.nid, "urn:nps:node:api.test:anchor-a");
    // Coerced at comparison time only — storage keeps None.
    assert_eq!(winner.cluster_epoch, None);
    assert_eq!(winner.effective_cluster_epoch(), 1);
}

#[test]
fn split_brain_at_the_top_epoch_throws() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", Some(2)));
    reg.announce(member("anchor-b", Some(2)));

    let err = reg.resolve_cluster(CLUSTER).expect_err("must split");
    assert_eq!(err.error_code(), "NDP-CLUSTER-SPLIT");
    assert_eq!(err.nps_status(), "NPS-CLIENT-CONFLICT");
    assert_eq!(err.epoch, 2);
    assert_eq!(err.cluster_anchor, CLUSTER);
    assert_eq!(
        err.to_string(),
        format!(
            "NDP-CLUSTER-SPLIT: cluster '{CLUSTER}' has multiple live active Anchors at epoch 2."
        )
    );
}

#[test]
fn no_live_members_resolves_to_none() {
    let reg = InMemoryNdpRegistry::new();
    assert!(reg
        .resolve_cluster(CLUSTER)
        .expect("must not split")
        .is_none());
}

// ── §5.1 "ports SHOULD add" ──────────────────────────────────────────────────

#[test]
fn two_members_both_omitting_epoch_split() {
    // Both coerce to 1 and tie at the top — a real consequence of the rule,
    // deliberately not special-cased away.
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", None));
    reg.announce(member("anchor-b", None));

    let err = reg.resolve_cluster(CLUSTER).expect_err("must split");
    assert_eq!(err.error_code(), "NDP-CLUSTER-SPLIT");
    assert_eq!(err.epoch, 1);
}

#[test]
fn ttl_expired_member_is_excluded_from_the_election() {
    let mut reg = InMemoryNdpRegistry::new();
    let base = Instant::now();
    reg.clock = Box::new(move || base);

    let mut short = member("anchor-b", Some(9));
    short.ttl = 10;
    reg.announce(short);
    reg.announce(member("anchor-a", Some(1)));

    // Before expiry the high-epoch member wins.
    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:anchor-b"
    );

    // After anchor-b's TTL elapses it is purged and anchor-a wins uncontested.
    reg.clock = Box::new(move || base + Duration::from_secs(60));
    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:anchor-a"
    );
}

#[test]
fn ttl_zero_announce_evicts_and_changes_the_winner() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", Some(1)));
    reg.announce(member("anchor-b", Some(3)));
    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:anchor-b"
    );

    // Orderly shutdown of the leader: ttl == 0 evicts immediately.
    let mut bye = member("anchor-b", Some(3));
    bye.ttl = 0;
    reg.announce(bye);

    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:anchor-a"
    );
}

#[test]
fn members_of_another_cluster_do_not_participate() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", Some(1)));
    let mut other = member("anchor-z", Some(99));
    other.cluster_anchor = Some("urn:nps:cluster:api.test:other".into());
    reg.announce(other);

    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:anchor-a"
    );
}

#[test]
fn role_is_not_filtered_any_live_member_participates() {
    // The reference does not filter by node_roles — mirror that.
    let mut reg = InMemoryNdpRegistry::new();
    let mut memory_node = member("mem-1", Some(7));
    memory_node.node_type = Some("memory".into());
    memory_node.node_roles = Some(vec!["memory".into()]);
    reg.announce(memory_node);
    reg.announce(member("anchor-a", Some(1)));

    assert_eq!(
        reg.resolve_cluster(CLUSTER).unwrap().unwrap().nid,
        "urn:nps:node:api.test:mem-1"
    );
}

#[test]
fn empty_cluster_anchor_argument_resolves_to_none() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(member("anchor-a", Some(1)));
    assert!(reg.resolve_cluster("").unwrap().is_none());
}

// ── §5.5 signature canonical-form regressions ────────────────────────────────

#[test]
fn canonical_json_contains_cluster_epoch_when_set() {
    let f = member("anchor-b", Some(3));
    let c = canonical(&f);
    assert!(
        c.contains(r#""cluster_epoch":3"#),
        "cluster_epoch must be inside the signed body: {c}"
    );
}

#[test]
fn canonical_json_omits_cluster_epoch_when_absent_and_is_byte_identical_to_pre_cr0009() {
    let after = member("anchor-a", None);

    // The pre-CR-0009 canonical form of the same frame, reconstructed field by
    // field. If `cluster_epoch: None` leaked in as `null` or a normalised `1`,
    // these bytes would differ and every already-signed announcement would stop
    // verifying.
    let mut before = Map::new();
    before.insert("addresses".into(), json!(after.addresses));
    before.insert("capabilities".into(), json!(after.caps));
    before.insert("cluster_anchor".into(), json!(CLUSTER));
    before.insert("heartbeat_interval_ms".into(), json!(60_000));
    before.insert("nid".into(), json!(after.nid));
    before.insert("node_roles".into(), json!(["anchor"]));
    before.insert("node_type".into(), json!("anchor"));
    before.insert("timestamp".into(), json!(TS));
    before.insert("ttl".into(), json!(3600));
    let before = serde_json::to_string(&Value::Object(before)).unwrap();

    let c = canonical(&after);
    assert!(
        !c.contains("cluster_epoch"),
        "absent cluster_epoch must be omitted entirely: {c}"
    );
    assert_eq!(
        c, before,
        "canonical bytes must be byte-identical to the pre-CR-0009 form"
    );
}

#[test]
fn canonical_json_omits_bridge_inbound_protocols_when_absent() {
    let f = member("anchor-a", None);
    assert!(!canonical(&f).contains("bridge_inbound_protocols"));
}

#[test]
fn canonical_json_contains_bridge_inbound_protocols_when_set() {
    let mut f = member("anchor-a", None);
    f.bridge_inbound_protocols = Some(vec!["mcp".into(), "a2a".into()]);
    let c = canonical(&f);
    assert!(
        c.contains(r#""bridge_inbound_protocols":["mcp","a2a"]"#),
        "bridge_inbound_protocols must be inside the signed body: {c}"
    );
}

#[test]
fn canonical_json_excludes_wire_only_and_null_fields() {
    let mut f = member("anchor-b", Some(3));
    f.health = Some("healthy".into());
    f.last_seen = Some("2026-07-05T00:00:05Z".into());
    let c = canonical(&f);

    // Liveness fields are wire-only (NDP v0.9 §3.2.1) and the signature never
    // appears in the body it covers.
    assert!(!c.contains("health"));
    assert!(!c.contains("last_seen"));
    assert!(!c.contains("signature"));
    // Null-valued optionals are dropped, not emitted as null.
    assert!(!c.contains("spawn_spec_ref"));
    assert!(!c.contains("activation_mode"));
    assert!(!c.contains("null"));
}

#[test]
fn canonical_keys_are_sorted_ordinal_ascending() {
    let mut f = member("anchor-b", Some(3));
    f.bridge_inbound_protocols = Some(vec!["mcp".into()]);
    let c = canonical(&f);
    let dict = f.unsigned_dict();
    let keys: Vec<&str> = dict.keys().map(String::as_str).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(
        keys, sorted,
        "canonical form must sort keys ordinal-ascending"
    );
    assert!(c.starts_with(r#"{"addresses":"#));
}

// ── round-trip ───────────────────────────────────────────────────────────────

#[test]
fn cluster_epoch_round_trips_through_to_dict_and_from_dict() {
    let f = member("anchor-b", Some(42));
    let d = f.to_dict();
    assert_eq!(d.get("cluster_epoch").and_then(Value::as_u64), Some(42));

    let back = AnnounceFrame::from_dict(&d).unwrap();
    assert_eq!(back.cluster_epoch, Some(42));
}

#[test]
fn absent_cluster_epoch_round_trips_as_none_not_one() {
    let f = member("anchor-a", None);
    let d = f.to_dict();
    assert!(!d.contains_key("cluster_epoch"));

    let back = AnnounceFrame::from_dict(&d).unwrap();
    assert_eq!(back.cluster_epoch, None);
    assert_eq!(back.effective_cluster_epoch(), 1);
}

#[test]
fn bridge_inbound_protocols_round_trips() {
    let mut f = member("bridge-1", None);
    f.bridge_protocols = Some(vec!["http".into()]);
    f.bridge_inbound_protocols = Some(vec!["mcp".into(), "a2a".into()]);
    let d = f.to_dict();
    assert_eq!(
        d.get("bridge_inbound_protocols"),
        Some(&json!(["mcp", "a2a"]))
    );

    let back = AnnounceFrame::from_dict(&d).unwrap();
    assert_eq!(
        back.bridge_inbound_protocols.as_deref(),
        Some(&["mcp".to_string(), "a2a".to_string()][..])
    );
    // Receivers MUST treat an absent value as [], never as "unknown".
    let plain = AnnounceFrame::from_dict(&member("anchor-a", None).to_dict()).unwrap();
    assert_eq!(plain.bridge_inbound_protocols, None);
}
