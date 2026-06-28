// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::NpsFrameCodec;
use nps_core::frames::EncodingTier;
use nps_core::registry::FrameRegistry;
use nps_ndp::{AnnounceFrame, GraphFrame, ResolveFrame};
use nps_ndp::{InMemoryNdpRegistry, NdpAnnounceValidator};
use nps_nip::identity::NipIdentity;
use serde_json::{json, Map};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NID: &str = "urn:nps:node:example.com:data";
const TS: &str = "2026-01-01T00:00:00Z";

fn full_codec() -> NpsFrameCodec {
    NpsFrameCodec::new(FrameRegistry::create_full())
}

fn make_addr() -> Map<String, serde_json::Value> {
    let mut m = Map::new();
    m.insert("host".into(), json!("example.com"));
    m.insert("port".into(), json!(17433));
    m.insert("protocol".into(), json!("nwp"));
    m
}

fn make_announce(id: &NipIdentity, ttl: u64) -> AnnounceFrame {
    let addrs = vec![make_addr()];
    let caps = vec!["nwp/query".to_string(), "nwp/stream".to_string()];
    let tmp = AnnounceFrame {
        nid: NID.into(),
        addresses: addrs.clone(),
        caps: caps.clone(),
        ttl,
        timestamp: TS.into(),
        signature: "placeholder".into(),
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    };
    let sig = id.sign(&tmp.unsigned_dict());
    AnnounceFrame {
        nid: NID.into(),
        addresses: addrs,
        caps,
        ttl,
        timestamp: TS.into(),
        signature: sig,
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    }
}

#[test]
fn announce_liveness_wire_only() {
    // NDP v0.9 health/last_seen: on the wire, but NOT in the signed canonical form.
    let id = NipIdentity::generate();
    let base = make_announce(&id, 300);
    let f = AnnounceFrame {
        health: Some("draining".into()),
        last_seen: Some("2026-06-13T00:00:00Z".into()),
        ..base.clone()
    };
    let d = f.to_dict();
    assert_eq!(d.get("health").and_then(|v| v.as_str()), Some("draining"));
    assert_eq!(
        d.get("last_seen").and_then(|v| v.as_str()),
        Some("2026-06-13T00:00:00Z")
    );
    let u = f.unsigned_dict();
    assert!(!u.contains_key("health") && !u.contains_key("last_seen"));
    assert!(!u.contains_key("frame"));
    assert_eq!(
        u.get("heartbeat_interval_ms").and_then(|v| v.as_u64()),
        Some(60_000)
    );
    // Signs identically to the same frame without liveness fields.
    assert_eq!(u, base.unsigned_dict());
    let back = AnnounceFrame::from_dict(&d).unwrap();
    assert_eq!(back.health.as_deref(), Some("draining"));
    assert_eq!(back.last_seen.as_deref(), Some("2026-06-13T00:00:00Z"));
}

#[test]
fn announce_heartbeat_zero_canonicalizes_literally() {
    let id = NipIdentity::generate();
    let frame = AnnounceFrame {
        heartbeat_interval_ms: 0,
        ..make_announce(&id, 300)
    };
    assert_eq!(
        frame
            .unsigned_dict()
            .get("heartbeat_interval_ms")
            .and_then(|v| v.as_u64()),
        Some(0)
    );
}

#[test]
fn announce_from_dict_absent_heartbeat_defaults() {
    let mut absent = Map::new();
    absent.insert("nid".into(), json!(NID));
    absent.insert("addresses".into(), json!([]));
    absent.insert("capabilities".into(), json!([]));
    absent.insert("ttl".into(), json!(300));
    absent.insert("timestamp".into(), json!(TS));
    absent.insert("signature".into(), json!("ed25519:sig"));
    let frame = AnnounceFrame::from_dict(&absent).unwrap();
    assert_eq!(frame.heartbeat_interval_ms, 60_000);

    let mut explicit_zero = absent;
    explicit_zero.insert("heartbeat_interval_ms".into(), json!(0));
    let frame = AnnounceFrame::from_dict(&explicit_zero).unwrap();
    assert_eq!(frame.heartbeat_interval_ms, 0);
}

// ── AnnounceFrame ─────────────────────────────────────────────────────────────

#[test]
fn announce_activation_endpoint_is_address_object() {
    let id = NipIdentity::generate();
    let mut endpoint = Map::new();
    endpoint.insert("host".into(), json!("10.0.0.5"));
    endpoint.insert("port".into(), json!(17440));
    endpoint.insert("protocol".into(), json!("nwp"));
    let f = AnnounceFrame {
        activation_mode: Some("resident".into()),
        activation_endpoint: Some(endpoint.clone()),
        ..make_announce(&id, 300)
    };

    let d = f.to_dict();
    assert_eq!(
        d.get("activation_endpoint")
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str()),
        Some("10.0.0.5")
    );
    let back = AnnounceFrame::from_dict(&d).unwrap();
    assert_eq!(back.activation_endpoint, Some(endpoint));
    assert_eq!(
        f.unsigned_dict()
            .get("activation_endpoint")
            .and_then(|v| v.get("host"))
            .and_then(|v| v.as_str()),
        Some("10.0.0.5")
    );
}

#[test]
fn announce_frame_roundtrip() {
    let id = NipIdentity::generate();
    let frame = make_announce(&id, 300);
    let dict = frame.to_dict();
    assert!(dict.contains_key("capabilities"));
    assert!(!dict.contains_key("caps"));
    let back = AnnounceFrame::from_dict(&frame.to_dict()).unwrap();
    assert_eq!(back.nid, NID);
    assert_eq!(back.ttl, 300);
    assert!(back.unsigned_dict().get("signature").is_none());
    assert!(back.unsigned_dict().get("node_type").is_none());
}

#[test]
fn announce_frame_accepts_legacy_caps_alias() {
    let mut dict = Map::new();
    dict.insert("nid".into(), json!(NID));
    dict.insert("addresses".into(), json!([]));
    dict.insert("caps".into(), json!(["nwp:query"]));
    dict.insert("ttl".into(), json!(300));
    dict.insert("timestamp".into(), json!(TS));
    dict.insert("signature".into(), json!("ed25519:placeholder"));

    let back = AnnounceFrame::from_dict(&dict).unwrap();
    assert_eq!(back.caps, vec!["nwp:query"]);
}

#[test]
fn announce_frame_codec_roundtrip() {
    let codec = full_codec();
    let id = NipIdentity::generate();
    let frame = make_announce(&id, 300);
    let wire = codec
        .encode(
            AnnounceFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = AnnounceFrame::from_dict(&dict).unwrap();
    assert_eq!(back.nid, NID);
}

// ── ResolveFrame ──────────────────────────────────────────────────────────────

#[test]
fn resolve_frame_roundtrip() {
    let mut resolved = Map::new();
    resolved.insert("host".into(), json!("example.com"));
    resolved.insert("port".into(), json!(17433));
    resolved.insert("ttl".into(), json!(300));
    let frame = ResolveFrame {
        target: "nwp://example.com/data".into(),
        requester_nid: Some("urn:nps:node:a:1".into()),
        resolved: Some(resolved),
    };
    let back = ResolveFrame::from_dict(&frame.to_dict()).unwrap();
    assert_eq!(back.target, "nwp://example.com/data");
    assert!(back.resolved.is_some());
}

#[test]
fn resolve_frame_optional_fields_null() {
    let frame = ResolveFrame {
        target: "nwp://example.com/data".into(),
        requester_nid: None,
        resolved: None,
    };
    let back = ResolveFrame::from_dict(&frame.to_dict()).unwrap();
    assert!(back.requester_nid.is_none());
    assert!(back.resolved.is_none());
}

// ── GraphFrame ────────────────────────────────────────────────────────────────

#[test]
fn graph_frame_roundtrip() {
    use nps_ndp::GraphNode;
    let codec = full_codec();
    let frame = GraphFrame {
        graph_id: "g1".into(),
        nodes: vec![GraphNode {
            nid: NID.into(),
            cluster_anchor: None,
            node_roles: None,
        }],
        edges: vec![],
        ttl: 300,
        metadata: None,
    };
    let wire = codec
        .encode(
            GraphFrame::frame_type(),
            &frame.to_dict(),
            EncodingTier::MsgPack,
            true,
        )
        .unwrap();
    let (_, dict) = codec.decode(&wire).unwrap();
    let back = GraphFrame::from_dict(&dict).unwrap();
    assert_eq!(back.graph_id, "g1");
    assert_eq!(back.nodes.len(), 1);
    assert_eq!(back.nodes[0].nid, NID);
    assert!(back.edges.is_empty());
}

#[test]
fn graph_frame_rejects_too_large() {
    use nps_ndp::GraphNode;
    let nodes = (0..257)
        .map(|i| GraphNode {
            nid: format!("urn:nps:node:example.com:{i}"),
            cluster_anchor: None,
            node_roles: None,
        })
        .collect();
    let frame = GraphFrame {
        graph_id: "too-big".into(),
        nodes,
        edges: vec![],
        ttl: 60,
        metadata: None,
    };
    let err = frame.validate().unwrap_err();
    assert!(format!("{err:?}").contains("NDP-GRAPH-TOO-LARGE"));
}

#[test]
fn graph_frame_rejects_invalid_edges() {
    use nps_ndp::{GraphEdge, GraphNode};
    let nodes = vec![GraphNode {
        nid: "urn:nps:node:example.com:a".into(),
        cluster_anchor: None,
        node_roles: None,
    }];
    for edge in [
        GraphEdge {
            from_nid: nodes[0].nid.clone(),
            to_nid: nodes[0].nid.clone(),
            latency_ms: None,
            protocol: None,
        },
        GraphEdge {
            from_nid: nodes[0].nid.clone(),
            to_nid: "urn:nps:node:example.com:missing".into(),
            latency_ms: None,
            protocol: None,
        },
    ] {
        let frame = GraphFrame {
            graph_id: "bad-edge".into(),
            nodes: nodes.clone(),
            edges: vec![edge],
            ttl: 60,
            metadata: None,
        };
        let err = frame.validate().unwrap_err();
        assert!(format!("{err:?}").contains("NDP-GRAPH-INVALID"));
    }
}

#[test]
fn federation_forwarded_by_helpers() {
    let header = "urn:nps:agent:registry-a.example.com:r1, urn:nps:agent:registry-b.example.com:r2";
    assert_eq!(
        nps_ndp::parse_forwarded_by(Some(header)),
        vec![
            "urn:nps:agent:registry-a.example.com:r1".to_string(),
            "urn:nps:agent:registry-b.example.com:r2".to_string(),
        ]
    );

    let next =
        nps_ndp::append_forwarded_by("urn:nps:agent:registry-c.example.com:r3", Some(header))
            .unwrap()
            .unwrap();
    assert!(next.contains("registry-c"));

    let err = nps_ndp::append_forwarded_by("urn:nps:agent:registry-b.example.com:r2", Some(header))
        .unwrap_err();
    assert!(format!("{err:?}").contains("NDP-FEDERATION-LOOP"));

    let full_header = format!("{header}, urn:nps:agent:registry-c.example.com:r3");
    let dropped = nps_ndp::append_forwarded_by(
        "urn:nps:agent:registry-d.example.com:r4",
        Some(&full_header),
    )
    .unwrap();
    assert!(dropped.is_none());
}

// ── InMemoryNdpRegistry ───────────────────────────────────────────────────────

#[test]
fn announce_and_get_by_nid() {
    let mut reg = InMemoryNdpRegistry::new();
    let id = NipIdentity::generate();
    let frame = make_announce(&id, 300);
    reg.announce(frame);
    assert!(reg.get_by_nid(NID).is_some());
}

#[test]
fn get_by_nid_returns_none_for_unknown() {
    let reg = InMemoryNdpRegistry::new();
    assert!(reg.get_by_nid("urn:nps:node:x:y").is_none());
}

#[test]
fn ttl_zero_deregisters() {
    let mut reg = InMemoryNdpRegistry::new();
    let id = NipIdentity::generate();
    reg.announce(make_announce(&id, 300));
    reg.announce(make_announce(&id, 0));
    assert!(reg.get_by_nid(NID).is_none());
}

#[test]
fn ttl_expiry() {
    let base = Instant::now();
    let elapsed = Arc::new(Mutex::new(0u64));
    let elapsed2 = elapsed.clone();
    let mut reg = InMemoryNdpRegistry::new();
    reg.clock = Box::new(move || base + Duration::from_secs(*elapsed2.lock().unwrap()));

    let id = NipIdentity::generate();
    reg.announce(make_announce(&id, 10));
    assert!(reg.get_by_nid(NID).is_some());

    *elapsed.lock().unwrap() = 11;
    assert!(reg.get_by_nid(NID).is_none());
}

#[test]
fn resolve_returns_matching_entry() {
    let mut reg = InMemoryNdpRegistry::new();
    let id = NipIdentity::generate();
    reg.announce(make_announce(&id, 300));
    let r = reg.resolve("nwp://example.com/data/sub").unwrap();
    assert_eq!(r.host, "example.com");
    assert_eq!(r.port, 17433);
}

#[test]
fn resolve_returns_none_for_non_match() {
    let mut reg = InMemoryNdpRegistry::new();
    reg.announce(make_announce(&NipIdentity::generate(), 300));
    assert!(reg.resolve("nwp://other.com/data").is_none());
}

#[test]
fn get_all_returns_active_entries() {
    let base = Instant::now();
    let elapsed = Arc::new(Mutex::new(0u64));
    let elapsed2 = elapsed.clone();
    let mut reg = InMemoryNdpRegistry::new();
    reg.clock = Box::new(move || base + Duration::from_secs(*elapsed2.lock().unwrap()));

    let id1 = NipIdentity::generate();
    let id2 = NipIdentity::generate();
    let nid1 = "urn:nps:node:a.com:x";
    let nid2 = "urn:nps:node:b.com:y";
    let addrs = vec![make_addr()];
    let caps = vec!["nwp/query".to_string()];

    let tmp1 = AnnounceFrame {
        nid: nid1.into(),
        addresses: addrs.clone(),
        caps: caps.clone(),
        ttl: 100,
        timestamp: TS.into(),
        signature: "ph".into(),
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    };
    let tmp2 = AnnounceFrame {
        nid: nid2.into(),
        addresses: addrs.clone(),
        caps: caps.clone(),
        ttl: 1,
        timestamp: TS.into(),
        signature: "ph".into(),
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    };
    let sig1 = id1.sign(&tmp1.unsigned_dict());
    let sig2 = id2.sign(&tmp2.unsigned_dict());

    reg.announce(AnnounceFrame {
        nid: nid1.into(),
        addresses: addrs.clone(),
        caps: caps.clone(),
        ttl: 100,
        timestamp: TS.into(),
        signature: sig1,
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    });
    reg.announce(AnnounceFrame {
        nid: nid2.into(),
        addresses: addrs.clone(),
        caps: caps.clone(),
        ttl: 1,
        timestamp: TS.into(),
        signature: sig2,
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    });

    *elapsed.lock().unwrap() = 2;
    let all = reg.get_all();
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].nid, nid1);
}

// ── nwp_target_matches_nid ────────────────────────────────────────────────────

#[test]
fn exact_match() {
    assert!(InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "nwp://example.com/data"
    ));
}
#[test]
fn sub_path_match() {
    assert!(InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "nwp://example.com/data/sub"
    ));
}
#[test]
fn different_authority() {
    assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "nwp://other.com/data"
    ));
}
#[test]
fn sibling_path() {
    assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "nwp://example.com/dataset"
    ));
}
#[test]
fn invalid_nid() {
    assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(
        "invalid",
        "nwp://example.com/data"
    ));
}
#[test]
fn non_nwp_target() {
    assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "http://example.com/data"
    ));
}
#[test]
fn no_slash_in_target() {
    assert!(!InMemoryNdpRegistry::nwp_target_matches_nid(
        NID,
        "nwp://example.com"
    ));
}

// ── DNS TXT resolution ────────────────────────────────────────────────────────

mod dns_txt_tests {
    use super::*;
    use nps_ndp::dns_txt::{
        extract_host_from_target, parse_nps_txt_record, DnsTxtLookup, DNS_TXT_DEFAULT_TTL,
    };
    use nps_ndp::InMemoryNdpRegistry;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};

    // ── Mock lookup ───────────────────────────────────────────────────────────

    struct MockDnsTxtLookup {
        records: Vec<String>,
        called: AtomicBool,
    }

    impl MockDnsTxtLookup {
        fn new(records: Vec<String>) -> Self {
            Self {
                records,
                called: AtomicBool::new(false),
            }
        }

        fn was_called(&self) -> bool {
            self.called.load(Ordering::SeqCst)
        }
    }

    impl DnsTxtLookup for MockDnsTxtLookup {
        fn lookup_txt<'a>(
            &'a self,
            _hostname: &'a str,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>> {
            self.called.store(true, Ordering::SeqCst);
            let records = self.records.clone();
            Box::pin(async move { Ok(records) })
        }
    }

    // ── parse_nps_txt_record ──────────────────────────────────────────────────

    #[test]
    fn test_parse_valid_record() {
        let txt = "v=nps1 type=memory port=17434 nid=urn:nps:node:api.example.com:products fp=sha256:a3f9";
        let result = parse_nps_txt_record(txt, "api.example.com").unwrap();
        assert_eq!(result.host, "api.example.com");
        assert_eq!(result.port, 17434);
        assert_eq!(result.protocol, "https");
    }

    #[test]
    fn test_parse_missing_v() {
        let txt = "type=memory port=17434 nid=urn:nps:node:api.example.com:products";
        assert!(parse_nps_txt_record(txt, "api.example.com").is_none());
    }

    #[test]
    fn test_parse_wrong_v() {
        let txt = "v=nps2 nid=urn:nps:node:api.example.com:products";
        assert!(parse_nps_txt_record(txt, "api.example.com").is_none());
    }

    #[test]
    fn test_parse_missing_nid() {
        let txt = "v=nps1 type=memory port=17434";
        assert!(parse_nps_txt_record(txt, "api.example.com").is_none());
    }

    #[test]
    fn test_parse_default_port() {
        let txt = "v=nps1 nid=urn:nps:node:api.example.com:products";
        let result = parse_nps_txt_record(txt, "api.example.com").unwrap();
        assert_eq!(result.port, 17433);
    }

    // ── extract_host_from_target ──────────────────────────────────────────────

    #[test]
    fn test_extract_host_from_target() {
        assert_eq!(
            extract_host_from_target("nwp://api.example.com/products"),
            Some("api.example.com"),
        );
        // No path separator → None
        assert!(extract_host_from_target("nwp://api.example.com").is_none());
        // Wrong scheme → None
        assert!(extract_host_from_target("http://api.example.com/path").is_none());
    }

    // ── resolve_via_dns ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_resolve_via_dns_registry_hit() {
        // Pre-populate registry; DNS should NOT be called.
        let mut reg = InMemoryNdpRegistry::new();
        reg.announce(make_announce(&NipIdentity::generate(), 300));

        let mock = MockDnsTxtLookup::new(vec![]);
        let result = reg.resolve_via_dns("nwp://example.com/data", &mock).await;
        assert!(result.is_some());
        assert!(
            !mock.was_called(),
            "DNS must not be queried when registry has a hit"
        );
        assert_eq!(result.unwrap().host, "example.com");
    }

    #[tokio::test]
    async fn test_resolve_via_dns_dns_fallback() {
        // Empty registry → must fall back to DNS.
        let reg = InMemoryNdpRegistry::new();
        let txt = "v=nps1 nid=urn:nps:node:api.example.com:products port=17434".to_string();
        let mock = MockDnsTxtLookup::new(vec![txt]);

        let result = reg
            .resolve_via_dns("nwp://api.example.com/products", &mock)
            .await;
        assert!(result.is_some(), "should resolve via DNS TXT fallback");
        assert!(mock.was_called());
        let r = result.unwrap();
        assert_eq!(r.host, "api.example.com");
        assert_eq!(r.port, 17434);
        assert_eq!(r.protocol, "https");
    }

    #[tokio::test]
    async fn test_resolve_via_dns_invalid_txt() {
        // DNS returns a record with wrong version; should return None.
        let reg = InMemoryNdpRegistry::new();
        let txt = "v=nps2 nid=urn:nps:node:api.example.com:products".to_string();
        let mock = MockDnsTxtLookup::new(vec![txt]);

        let result = reg
            .resolve_via_dns("nwp://api.example.com/products", &mock)
            .await;
        assert!(result.is_none(), "invalid TXT record must not resolve");
        assert!(mock.was_called());
    }

    // ── constant sanity ───────────────────────────────────────────────────────

    #[test]
    fn test_dns_txt_default_ttl() {
        assert_eq!(DNS_TXT_DEFAULT_TTL, 300);
    }
}

// ── NdpAnnounceValidator ──────────────────────────────────────────────────────

#[test]
fn validator_fails_when_no_key_registered() {
    let v = NdpAnnounceValidator::new();
    let r = v.validate(&make_announce(&NipIdentity::generate(), 300));
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some("NDP-ANNOUNCE-NID-MISMATCH"));
}

#[test]
fn validates_correctly_signed_frame() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    let frame = make_announce(&id, 300);
    assert!(v.validate(&frame).is_valid);
}

#[test]
fn rejects_wrong_signature_prefix() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    let frame = AnnounceFrame {
        nid: NID.into(),
        addresses: vec![make_addr()],
        caps: vec![],
        ttl: 300,
        timestamp: TS.into(),
        signature: "rsa:invalid".into(),
        node_type: None,
        node_roles: None,
        cluster_anchor: None,
        spawn_spec_ref: None,
        bridge_protocols: None,
        activation_mode: None,
        activation_endpoint: None,
        heartbeat_interval_ms: 60_000,
        health: None,
        last_seen: None,
    };
    let r = v.validate(&frame);
    assert!(!r.is_valid);
    assert_eq!(
        r.error_code.as_deref(),
        Some("NDP-ANNOUNCE-SIGNATURE-INVALID")
    );
}

#[test]
fn remove_public_key_deregisters() {
    let id = NipIdentity::generate();
    let mut v = NdpAnnounceValidator::new();
    v.register_public_key(NID, id.pub_key_string());
    v.remove_public_key(NID);
    assert!(!v.known_public_keys().contains_key(NID));
}

#[test]
fn announce_result_ok() {
    use nps_ndp::NdpAnnounceResult;
    let r = NdpAnnounceResult::ok();
    assert!(r.is_valid);
    assert!(r.error_code.is_none());
}

#[test]
fn announce_result_fail() {
    use nps_ndp::NdpAnnounceResult;
    let r = NdpAnnounceResult::fail("CODE", "msg");
    assert!(!r.is_valid);
    assert_eq!(r.error_code.as_deref(), Some("CODE"));
    assert_eq!(r.message.as_deref(), Some("msg"));
}
