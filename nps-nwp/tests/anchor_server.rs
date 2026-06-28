// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nip::reputation::{IncidentType, ReputationLogEntry, Severity};
use nps_nwp::anchor_client::{MemberInfo, TopologyEvent, TopologySnapshot};
use nps_nwp::anchor_server::*;
use nps_nwp::reputation::{ReputationPolicy, ReputationRule};
use nps_nwp::reputation_policy::DefaultReputationPolicyEvaluator;
use serde_json::{json, Value};

fn rule(incident: &str, severity: &str) -> ReputationRule {
    ReputationRule {
        incident: incident.into(),
        severity: severity.into(),
        within_days: None,
        count: 1,
    }
}

fn rep_policy(log_sources: Vec<String>, ban_on: Vec<ReputationRule>) -> ReputationPolicy {
    ReputationPolicy {
        enabled: true,
        log_sources,
        min_assurance_level: "anonymous".into(),
        cache_ttl_seconds: 300,
        ban_ttl_seconds: 3600,
        on_log_unavailable: "allow".into(),
        throttle_on: vec![],
        reject_on: vec![],
        ban_on,
    }
}

const NID: &str = "urn:nps:node:anchor.example.com:svc";
const AGENT: &str = "urn:nps:agent:tester";

fn base_opts() -> AnchorNodeOptions {
    let mut o = AnchorNodeOptions::new(NID, "/gw");
    o.actions.insert(
        "orders.create".into(),
        AnchorActionSpec {
            result_anchor: Some("nps:orders:result".into()),
            estimated_cgn: Some(10),
            ..Default::default()
        },
    );
    o
}

fn members() -> Vec<MemberInfo> {
    vec![
        MemberInfo {
            nid: "urn:nps:node:w1".into(),
            node_roles: vec!["worker".into()],
            activation_mode: "resident".into(),
            child_anchor: None,
            member_count: None,
            tags: None,
            joined_at: None,
            last_seen: None,
            capabilities: None,
            metrics: None,
        },
        MemberInfo {
            nid: "urn:nps:node:w2".into(),
            node_roles: vec!["worker".into()],
            activation_mode: "ephemeral".into(),
            child_anchor: None,
            member_count: None,
            tags: Some(vec!["gpu".into()]),
            joined_at: None,
            last_seen: None,
            capabilities: None,
            metrics: None,
        },
    ]
}

fn ok_handler() -> InvokeHandler {
    Box::new(|action_id, _params, ctx| {
        Ok(json!({
            "order_id": "o-123",
            "action": action_id,
            "agent": ctx.agent_nid
        }))
    })
}

fn req(method: &str, path: &str) -> AnchorRequest {
    AnchorRequest::new(method, path).with_header("X-NWP-Agent", AGENT)
}

#[tokio::test]
async fn manifest_and_splice() {
    let mut o = base_opts();
    o.display_name = Some("Svc".into());
    o.cgn_limit = 500;
    o.trust_anchors = Some(vec!["urn:nps:org:root".into()]);
    let policy = rep_policy(vec!["https://log".into()], vec![rule("*", ">=critical")]);
    o.reputation_policy = Some(policy);
    let app = AnchorNodeApp::new(o, None, None, None);

    let resp = app.handle(req("GET", "/gw/.nwm")).await;
    assert_eq!(resp.status, 200);
    assert_eq!(
        resp.header("content-type"),
        Some("application/nwp-manifest+json")
    );
    assert_eq!(resp.header("x-nwp-node-type"), Some("anchor"));
    let m = resp.json_value().unwrap();
    assert_eq!(m["nwp"], "0.4");
    assert_eq!(m["node_type"], "anchor");
    assert_eq!(m["auth"]["identity_type"], "nip-cert");
    assert_eq!(m["token_budget"]["cgn_limit"], 500);
    assert_eq!(
        m["reputation_policy"]["log_sources"],
        json!(["https://log"])
    );
    assert_eq!(m["trust_anchors"], json!(["urn:nps:org:root"]));
}

#[tokio::test]
async fn auth_gate() {
    let app = AnchorNodeApp::new(base_opts(), None, None, None);
    let resp = app.handle(AnchorRequest::new("GET", "/gw/.nwm")).await;
    assert_eq!(resp.status, 401);
    assert_eq!(
        resp.json_value().unwrap()["error"],
        "NWP-AUTH-NID-SCOPE-VIOLATION"
    );
}

#[tokio::test]
async fn snapshot_wire_compat() {
    let topo = Box::new(InMemoryAnchorTopologyService {
        nid: NID.into(),
        members: members(),
        version: 7,
        events: vec![],
    });
    let mut o = base_opts();
    o.require_auth = false;
    let app = AnchorNodeApp::new(o, None, Some(topo), None);

    let body = json!({ "type": "topology.snapshot", "topology": { "scope": "cluster" } });
    let resp = app
        .handle(AnchorRequest::new("POST", "/gw/query").with_json(&body))
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type"), Some("application/nwp-capsule"));
    let v = resp.json_value().unwrap();
    // Deserialize data[0] into the client's TopologySnapshot to prove wire-compat.
    let snap: TopologySnapshot = serde_json::from_value(v["data"][0].clone()).unwrap();
    assert_eq!(snap.version, 7);
    assert_eq!(snap.anchor_nid, NID);
    assert_eq!(snap.cluster_size, 2);
    assert_eq!(snap.members.len(), 2);
}

#[tokio::test]
async fn stream_ndjson() {
    let events = vec![
        TopologyEvent::MemberJoined {
            version: 8,
            member: members()[0].clone(),
        },
        TopologyEvent::ResyncRequired {
            reason: "rebased".into(),
        },
    ];
    let topo = Box::new(InMemoryAnchorTopologyService {
        nid: NID.into(),
        members: members(),
        version: 1,
        events,
    });
    let mut o = base_opts();
    o.require_auth = false;
    let app = AnchorNodeApp::new(o, None, Some(topo), None);

    let body = json!({ "type": "topology.stream", "topology": { "scope": "cluster" } });
    let resp = app
        .handle(AnchorRequest::new("POST", "/gw/subscribe").with_json(&body))
        .await;
    assert_eq!(resp.status, 200);
    let lines = resp.ndjson_lines();
    assert_eq!(lines.len(), 3); // ack + 2 events
    assert_eq!(lines[0]["kind"], "ack");
    assert_eq!(lines[1]["event_type"], "member_joined");
    assert_eq!(lines[1]["payload"]["nid"], "urn:nps:node:w1");
    assert_eq!(lines[2]["event_type"], "resync_required");
}

#[tokio::test]
async fn topology_errors() {
    let topo = Box::new(InMemoryAnchorTopologyService {
        nid: NID.into(),
        members: members(),
        version: 1,
        events: vec![],
    });
    let app = AnchorNodeApp::new(base_opts(), None, Some(topo), None);

    let r1 = app
        .handle(req("POST", "/gw/query").with_json(&json!({"type":"topology.bogus","topology":{}})))
        .await;
    assert_eq!(r1.status, 501);
    assert_eq!(
        r1.json_value().unwrap()["error"],
        "NWP-RESERVED-TYPE-UNSUPPORTED"
    );

    let r2 = app
        .handle(
            req("POST", "/gw/query")
                .with_json(&json!({"type":"topology.snapshot","topology":{"scope":"member"}})),
        )
        .await;
    assert_eq!(r2.status, 400);
    assert_eq!(
        r2.json_value().unwrap()["error"],
        "NWP-TOPOLOGY-UNSUPPORTED-SCOPE"
    );

    let app2 = AnchorNodeApp::new(base_opts(), None, None, None);
    let r3 = app2
        .handle(
            req("POST", "/gw/query")
                .with_json(&json!({"type":"topology.snapshot","topology":{"scope":"cluster"}})),
        )
        .await;
    assert_eq!(r3.status, 501);
    assert_eq!(r3.json_value().unwrap()["error"], "NWP-NODE-UNAVAILABLE");
}

#[tokio::test]
async fn capability_gate() {
    let topo = Box::new(InMemoryAnchorTopologyService {
        nid: NID.into(),
        members: members(),
        version: 1,
        events: vec![],
    });
    let mut o = base_opts();
    o.require_topology_capability = true;
    let app = AnchorNodeApp::new(o, None, Some(topo), None);

    let denied = app
        .handle(
            req("POST", "/gw/query").with_json(&json!({"type":"topology.snapshot","topology":{}})),
        )
        .await;
    assert_eq!(denied.status, 403);
    assert_eq!(
        denied.json_value().unwrap()["error"],
        "NWP-TOPOLOGY-UNAUTHORIZED"
    );

    let ok = app
        .handle(
            req("POST", "/gw/query")
                .with_header("X-NWP-Capabilities", "topology:read")
                .with_json(&json!({"type":"topology.snapshot","topology":{}})),
        )
        .await;
    assert_eq!(ok.status, 200);
}

#[tokio::test]
async fn invoke_sync_caps() {
    let app = AnchorNodeApp::new(base_opts(), Some(ok_handler()), None, None);
    let resp = app
        .handle(
            req("POST", "/gw/invoke")
                .with_json(&json!({"action_id":"orders.create","params":{"x":1}})),
        )
        .await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.header("content-type"), Some("application/nwp-capsule"));
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["data"][0]["order_id"], "o-123");
    assert_eq!(v["data"][0]["agent"], AGENT);
}

#[tokio::test]
async fn invoke_errors() {
    let app = AnchorNodeApp::new(base_opts(), Some(ok_handler()), None, None);

    let unknown = app
        .handle(req("POST", "/gw/invoke").with_json(&json!({"action_id":"nope.verb"})))
        .await;
    assert_eq!(unknown.status, 404);
    assert_eq!(
        unknown.json_value().unwrap()["error"],
        "NWP-ACTION-NOT-FOUND"
    );

    let cgn = app
        .handle(
            req("POST", "/gw/invoke")
                .with_header("X-NWP-Budget", "5")
                .with_json(&json!({"action_id":"orders.create"})),
        )
        .await;
    assert_eq!(cgn.status, 400);
    assert_eq!(cgn.json_value().unwrap()["error"], "NWP-CGN-LIMIT-EXCEEDED");

    let no_handler = AnchorNodeApp::new(base_opts(), None, None, None);
    let nh = no_handler
        .handle(req("POST", "/gw/invoke").with_json(&json!({"action_id":"orders.create"})))
        .await;
    assert_eq!(nh.status, 501);
}

#[tokio::test]
async fn invoke_handler_error_envelope() {
    let handler: InvokeHandler = Box::new(|_a, _p, _c| {
        Err(AnchorActionError {
            http_status: 422,
            nps_status: "NPS-CLIENT-BAD-REQUEST".into(),
            error_code: "NWP-ACTION-PARAMS-INVALID".into(),
            message: "bad".into(),
            details: None,
        })
    });
    let app = AnchorNodeApp::new(base_opts(), Some(handler), None, None);
    let resp = app
        .handle(req("POST", "/gw/invoke").with_json(&json!({"action_id":"orders.create"})))
        .await;
    assert_eq!(resp.status, 422);
    assert_eq!(
        resp.json_value().unwrap()["error"],
        "NWP-ACTION-PARAMS-INVALID"
    );
}

#[tokio::test]
async fn reputation_ban_blocks_invoke() {
    let ev = DefaultReputationPolicyEvaluator::new();
    let entry = ReputationLogEntry {
        v: 1,
        log_id: "l".into(),
        seq: 1,
        timestamp: "2026-06-12T00:00:00Z".into(),
        subject_nid: AGENT.into(),
        incident: IncidentType::ImpersonationClaim,
        incident_raw: None,
        severity: Severity::Critical,
        window: None,
        observation: None,
        evidence_ref: None,
        evidence_sha256: None,
        issuer_nid: "i".into(),
        signature: String::new(),
    };
    ev.prime_cache(AGENT, vec![entry], 3600);
    let mut o = base_opts();
    o.reputation_policy = Some(rep_policy(vec![], vec![rule("*", ">=critical")]));
    let app = AnchorNodeApp::new(o, Some(ok_handler()), None, Some(ev));

    let resp = app
        .handle(req("POST", "/gw/invoke").with_json(&json!({"action_id":"orders.create"})))
        .await;
    assert_eq!(resp.status, 403);
    let _: Value = resp.json_value().unwrap();
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-REPUTATION-BANNED");
}

#[tokio::test]
async fn unknown_subpath_is_404_before_auth() {
    // An unknown sub-path must be 404 regardless of auth — a missing X-NWP-Agent on a route that
    // has no resource must NOT leak a 401 (D4). Note: no agent header is sent.
    let app = AnchorNodeApp::new(base_opts(), None, None, None);
    let resp = app.handle(AnchorRequest::new("GET", "/gw/nope")).await;
    assert_eq!(resp.status, 404);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-ACTION-NOT-FOUND");
}

struct DenyLimiter;
impl RateLimiter for DenyLimiter {
    fn try_acquire(&self, _c: &str, _h: u32) -> RateDecision {
        RateDecision {
            allowed: false,
            retry_after_seconds: Some(30),
            reason: Some("over quota".into()),
        }
    }
    fn release(&self, _c: &str) {}
}

#[tokio::test]
async fn rate_limiter_rejects_invoke() {
    let app = AnchorNodeApp::new(base_opts(), Some(ok_handler()), None, None)
        .with_rate_limiter(Box::new(DenyLimiter));
    let resp = app
        .handle(
            req("POST", "/gw/invoke")
                .with_json(&json!({ "action_id": "orders.create", "params": {} })),
        )
        .await;
    assert_eq!(resp.status, 429);
    assert_eq!(resp.header("retry-after"), Some("30"));
    assert_eq!(
        resp.json_value().unwrap()["error"],
        "NWP-RATE-LIMIT-EXCEEDED"
    );
}
