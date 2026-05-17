// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for [`AnchorNodeClient`].
//!
//! Each test spins up a `tiny_http::Server` bound to `127.0.0.1:0` in a
//! background thread, exercises one code-path of the client, then verifies
//! the outcome.  The server always writes a `Content-Length` header so that
//! `reqwest` does not attempt chunked-transfer decoding.

use futures::StreamExt;
use nps_nwp::{
    AnchorNodeClient, AnchorTopologyError, TopologyEvent,
    TopologyFilter, SCOPE_CLUSTER, SCOPE_MEMBER,
};
use std::str::FromStr;
use tiny_http::{Header, Response, Server};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Bind a server, return it together with the full base-URL string.
fn bind_server() -> (Server, String) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);
    (server, url)
}

/// Send a single JSON response from a background thread and return the guard.
fn serve_once_json(server: Server, body: String) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Ok(Some(req)) =
            server.recv_timeout(std::time::Duration::from_secs(5))
        {
            let len = body.len();
            let resp = Response::from_string(body)
                .with_header(
                    Header::from_str("Content-Type: application/json").unwrap(),
                )
                .with_header(
                    Header::from_str(&format!("Content-Length: {}", len)).unwrap(),
                );
            let _ = req.respond(resp);
        }
    })
}

/// Send a single plain-text response from a background thread.
fn serve_once_status(server: Server, status: u16, body: String) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Ok(Some(req)) =
            server.recv_timeout(std::time::Duration::from_secs(5))
        {
            let len = body.len();
            let resp = Response::from_string(body)
                .with_status_code(status as i32)
                .with_header(
                    Header::from_str("Content-Type: text/plain").unwrap(),
                )
                .with_header(
                    Header::from_str(&format!("Content-Length: {}", len)).unwrap(),
                );
            let _ = req.respond(resp);
        }
    })
}

/// Send a single NDJSON response (all lines pre-joined with '\n').
fn serve_once_ndjson(server: Server, body: String) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        if let Ok(Some(req)) =
            server.recv_timeout(std::time::Duration::from_secs(5))
        {
            let len = body.len();
            let resp = Response::from_string(body)
                .with_header(
                    Header::from_str("Content-Type: application/x-ndjson").unwrap(),
                )
                .with_header(
                    Header::from_str(&format!("Content-Length: {}", len)).unwrap(),
                );
            let _ = req.respond(resp);
        }
    })
}

/// Build the minimal JSON for a `TopologySnapshot` wrapped in `{"data":[...]}`.
fn snapshot_json(version: u64, anchor_nid: &str, cluster_size: u32) -> String {
    format!(
        r#"{{"data":[{{"version":{version},"anchor_nid":"{anchor_nid}","cluster_size":{cluster_size},"members":[],"truncated":null}}]}}"#
    )
}

/// Build snapshot JSON that includes one member.
fn snapshot_with_member_json() -> String {
    r#"{"data":[{"version":10,"anchor_nid":"anc-1","cluster_size":2,"members":[{"nid":"m-1","node_roles":["worker"],"activation_mode":"auto","child_anchor":false,"member_count":null,"tags":["env:prod"],"joined_at":"2026-01-01T00:00:00Z","last_seen":null,"capabilities":null,"metrics":null}],"truncated":false}]}"#.to_string()
}

// ── topology.snapshot tests ───────────────────────────────────────────────────

/// Test 1 — `get_snapshot` success: verify response fields.
#[tokio::test]
async fn test_get_snapshot_success() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, snapshot_json(42, "anc-x", 3));

    let client = AnchorNodeClient::new(&url);
    let snap = client.get_snapshot().await.expect("get_snapshot should succeed");

    assert_eq!(snap.version, 42);
    assert_eq!(snap.anchor_nid, "anc-x");
    assert_eq!(snap.cluster_size, 3);
    assert!(snap.members.is_empty());
}

/// Test 2 — `get_snapshot_with` member scope + target_nid succeeds.
#[tokio::test]
async fn test_get_snapshot_member_scope_with_target_nid() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, snapshot_with_member_json());

    let client = AnchorNodeClient::new(&url);
    let snap = client
        .get_snapshot_with(SCOPE_MEMBER, &[], 1, Some("m-1"))
        .await
        .expect("get_snapshot_with should succeed");

    assert_eq!(snap.cluster_size, 2);
    assert_eq!(snap.members.len(), 1);
    assert_eq!(snap.members[0].nid, "m-1");
}

/// Test 3 — non-2xx with NPS error JSON → `AnchorTopologyError::Protocol`.
#[tokio::test]
async fn test_get_snapshot_nps_error_json() {
    let (server, url) = bind_server();
    let body = r#"{"error":"NWP-0042","status":"topology.not_found","message":"anchor not ready"}"#
        .to_string();
    let _guard = serve_once_status(server, 404, body);

    let client = AnchorNodeClient::new(&url);
    let err = client.get_snapshot().await.expect_err("should fail");

    match err {
        AnchorTopologyError::Protocol {
            nwp_error_code,
            nps_status,
            message,
        } => {
            assert_eq!(nwp_error_code, "NWP-0042");
            assert_eq!(nps_status, "topology.not_found");
            assert_eq!(message, "anchor not ready");
        }
        other => panic!("expected Protocol error, got {:?}", other),
    }
}

/// Test 4 — non-2xx plain body → `AnchorTopologyError::Http`.
#[tokio::test]
async fn test_get_snapshot_http_error_plain_body() {
    let (server, url) = bind_server();
    let _guard = serve_once_status(server, 503, "Service Unavailable".to_string());

    let client = AnchorNodeClient::new(&url);
    let err = client.get_snapshot().await.expect_err("should fail");

    match err {
        AnchorTopologyError::Http { status, body } => {
            assert_eq!(status, 503);
            assert!(body.contains("Service Unavailable"));
        }
        other => panic!("expected Http error, got {:?}", other),
    }
}

/// Test 5 — 200 with empty `data` array → error.
#[tokio::test]
async fn test_get_snapshot_empty_data_array() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, r#"{"data":[]}"#.to_string());

    let client = AnchorNodeClient::new(&url);
    let err = client.get_snapshot().await.expect_err("should fail on empty data");

    match err {
        AnchorTopologyError::Http { status, .. } => assert_eq!(status, 200),
        other => panic!("expected Http error, got {:?}", other),
    }
}

// ── topology.stream tests ─────────────────────────────────────────────────────

/// Build a complete NDJSON stream string for the happy-path.
fn happy_path_ndjson() -> String {
    let lines = [
        // ack (consumed internally)
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"test-1","seq":0}"#,
        // member_joined
        r#"{"event_type":"member_joined","seq":1,"payload":{"nid":"m-1","node_roles":["worker"],"activation_mode":"auto","child_anchor":null,"member_count":null,"tags":null,"joined_at":null,"last_seen":null,"capabilities":null,"metrics":null}}"#,
        // member_left
        r#"{"event_type":"member_left","seq":2,"payload":{"nid":"m-2"}}"#,
        // member_updated
        r#"{"event_type":"member_updated","seq":3,"payload":{"nid":"m-3","changes":{"activation_mode":"manual"}}}"#,
        // anchor_state
        r#"{"event_type":"anchor_state","seq":4,"payload":{"field":"version_rebased","details":{"old":1,"new":10}}}"#,
    ];
    lines.join("\n") + "\n"
}

/// Test 6 — subscribe success: ack consumed + all event types collected.
#[tokio::test]
async fn test_subscribe_success_all_event_types() {
    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, happy_path_ndjson());

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.expect("subscribe should succeed");
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 4, "should have 4 events (ack skipped)");

    // event 0 — member_joined
    match &events[0] {
        Ok(TopologyEvent::MemberJoined { version, member }) => {
            assert_eq!(*version, 1);
            assert_eq!(member.nid, "m-1");
        }
        other => panic!("expected MemberJoined, got {:?}", other),
    }

    // event 1 — member_left
    match &events[1] {
        Ok(TopologyEvent::MemberLeft { version, nid }) => {
            assert_eq!(*version, 2);
            assert_eq!(nid, "m-2");
        }
        other => panic!("expected MemberLeft, got {:?}", other),
    }

    // event 2 — member_updated
    match &events[2] {
        Ok(TopologyEvent::MemberUpdated { version, nid, changes }) => {
            assert_eq!(*version, 3);
            assert_eq!(nid, "m-3");
            assert_eq!(
                changes.activation_mode.as_deref(),
                Some("manual")
            );
        }
        other => panic!("expected MemberUpdated, got {:?}", other),
    }

    // event 3 — anchor_state
    match &events[3] {
        Ok(TopologyEvent::AnchorState { version, field, details }) => {
            assert_eq!(*version, 4);
            assert_eq!(field, "version_rebased");
            assert!(details.is_some());
        }
        other => panic!("expected AnchorState, got {:?}", other),
    }
}

/// Test 7 — `resync_required` terminates the stream.
#[tokio::test]
async fn test_subscribe_resync_required_terminates_stream() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"member_joined","seq":1,"payload":{"nid":"m-1","node_roles":[],"activation_mode":"auto","child_anchor":null,"member_count":null,"tags":null,"joined_at":null,"last_seen":null,"capabilities":null,"metrics":null}}"#,
        r#"{"event_type":"resync_required","seq":2,"payload":{"reason":"version_gap"}}"#,
        // this line MUST NOT be yielded
        r#"{"event_type":"member_left","seq":3,"payload":{"nid":"m-x"}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    // member_joined + resync_required; the trailing member_left is cut off
    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Ok(TopologyEvent::MemberJoined { .. })));
    match &events[1] {
        Ok(TopologyEvent::ResyncRequired { reason }) => assert_eq!(reason, "version_gap"),
        other => panic!("expected ResyncRequired, got {:?}", other),
    }
}

/// Test 8 — mid-stream error envelope → `Err(Protocol)` yielded, stream ends.
#[tokio::test]
async fn test_subscribe_mid_stream_error_envelope() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"member_joined","seq":1,"payload":{"nid":"m-1","node_roles":[],"activation_mode":"auto","child_anchor":null,"member_count":null,"tags":null,"joined_at":null,"last_seen":null,"capabilities":null,"metrics":null}}"#,
        // error envelope (no event_type)
        r#"{"error":"NWP-0099","status":"stream.fault","message":"internal fault"}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 2);
    assert!(matches!(events[0], Ok(TopologyEvent::MemberJoined { .. })));
    match &events[1] {
        Err(AnchorTopologyError::Protocol {
            nwp_error_code,
            nps_status,
            message,
        }) => {
            assert_eq!(nwp_error_code, "NWP-0099");
            assert_eq!(nps_status, "stream.fault");
            assert_eq!(message, "internal fault");
        }
        other => panic!("expected Protocol error, got {:?}", other),
    }
}

/// Test 9 — subscribe non-2xx → `Err` returned from `subscribe()` itself.
#[tokio::test]
async fn test_subscribe_non_2xx_returns_error() {
    let (server, url) = bind_server();
    let body = r#"{"error":"NWP-0001","status":"auth.required","message":"missing token"}"#
        .to_string();
    let _guard = serve_once_status(server, 401, body);

    let client = AnchorNodeClient::new(&url);
    match client.subscribe().await {
        Err(AnchorTopologyError::Protocol { nwp_error_code, .. }) => {
            assert_eq!(nwp_error_code, "NWP-0001");
        }
        Err(other) => panic!("expected Protocol error, got {:?}", other),
        Ok(_) => panic!("subscribe should fail on 401"),
    }
}

/// Test 10 — subscribe_with filter is forwarded (server just responds successfully).
#[tokio::test]
async fn test_subscribe_with_filter() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let filter = TopologyFilter {
        tags_any: Some(vec!["env:prod".to_string()]),
        tags_all: None,
        node_roles: Some(vec!["worker".to_string()]),
    };

    let client = AnchorNodeClient::new(&url);
    let stream = client
        .subscribe_with(SCOPE_CLUSTER, Some(&filter), None)
        .await
        .expect("subscribe_with filter should succeed");

    // ack only — no events yielded
    let events: Vec<_> = stream.collect().await;
    assert!(events.is_empty());
}

/// Test 11 — subscribe_with since_version is forwarded.
#[tokio::test]
async fn test_subscribe_with_since_version() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client
        .subscribe_with(SCOPE_CLUSTER, None, Some(99))
        .await
        .expect("subscribe_with since_version should succeed");

    let events: Vec<_> = stream.collect().await;
    assert!(events.is_empty());
}

// ── URL normalisation / builder tests ────────────────────────────────────────

/// Test 12 — trailing slash in base_url is stripped.
#[tokio::test]
async fn test_url_normalisation_trailing_slash() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, snapshot_json(1, "anc-1", 1));

    // Pass URL with trailing slash
    let client = AnchorNodeClient::new(format!("{}/", url));
    let snap = client.get_snapshot().await.expect("should succeed");
    assert_eq!(snap.version, 1);
}

/// Test 13 — path_prefix is prepended to every request path.
#[tokio::test]
async fn test_path_prefix_prepended() {
    let (server, url) = bind_server();

    // The server checks that the path starts with "/anchor/query"
    let _guard = std::thread::spawn(move || {
        if let Ok(Some(req)) =
            server.recv_timeout(std::time::Duration::from_secs(5))
        {
            let path = req.url().to_string();
            assert!(
                path.starts_with("/anchor/query"),
                "expected path /anchor/query, got {}",
                path
            );
            let body = snapshot_json(5, "anc-pfx", 2);
            let len = body.len();
            let _ = req.respond(
                Response::from_string(body)
                    .with_header(Header::from_str("Content-Type: application/json").unwrap())
                    .with_header(
                        Header::from_str(&format!("Content-Length: {}", len)).unwrap(),
                    ),
            );
        }
    });

    let client = AnchorNodeClient::new(&url).with_path_prefix("/anchor");
    let snap = client.get_snapshot().await.expect("should succeed");
    assert_eq!(snap.anchor_nid, "anc-pfx");
}

// ── per-event-type field tests ────────────────────────────────────────────────

/// Test 14 — MemberJoined payload fields are fully populated.
#[tokio::test]
async fn test_member_joined_payload_fields() {
    let member_json = r#"{"nid":"node-42","node_roles":["anchor","worker"],"activation_mode":"manual","child_anchor":true,"member_count":5,"tags":["env:dev"],"joined_at":"2026-01-02T00:00:00Z","last_seen":"2026-01-03T00:00:00Z","capabilities":{"ping":true},"metrics":{"cpu":0.4}}"#;
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        &format!(
            r#"{{"event_type":"member_joined","seq":7,"payload":{}}}"#,
            member_json
        ),
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        Ok(TopologyEvent::MemberJoined { version, member }) => {
            assert_eq!(*version, 7);
            assert_eq!(member.nid, "node-42");
            assert_eq!(member.node_roles, vec!["anchor", "worker"]);
            assert_eq!(member.activation_mode, "manual");
            assert_eq!(member.child_anchor, Some(true));
            assert_eq!(member.member_count, Some(5));
            assert_eq!(
                member.tags.as_deref(),
                Some(&["env:dev".to_string()][..])
            );
            assert_eq!(member.joined_at.as_deref(), Some("2026-01-02T00:00:00Z"));
            assert!(member.capabilities.is_some());
            assert!(member.metrics.is_some());
        }
        other => panic!("expected MemberJoined, got {:?}", other),
    }
}

/// Test 15 — MemberLeft payload nid.
#[tokio::test]
async fn test_member_left_payload_nid() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"member_left","seq":11,"payload":{"nid":"gone-node"}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        Ok(TopologyEvent::MemberLeft { version, nid }) => {
            assert_eq!(*version, 11);
            assert_eq!(nid, "gone-node");
        }
        other => panic!("expected MemberLeft, got {:?}", other),
    }
}

/// Test 16 — MemberUpdated nid + changes.
#[tokio::test]
async fn test_member_updated_nid_and_changes() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"member_updated","seq":20,"payload":{"nid":"upd-node","changes":{"node_roles":["coordinator"],"tags":["tier:1"],"member_count":8}}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        Ok(TopologyEvent::MemberUpdated { version, nid, changes }) => {
            assert_eq!(*version, 20);
            assert_eq!(nid, "upd-node");
            assert_eq!(
                changes.node_roles.as_deref(),
                Some(&["coordinator".to_string()][..])
            );
            assert_eq!(
                changes.tags.as_deref(),
                Some(&["tier:1".to_string()][..])
            );
            assert_eq!(changes.member_count, Some(8));
        }
        other => panic!("expected MemberUpdated, got {:?}", other),
    }
}

/// Test 17 — AnchorState field + details.
#[tokio::test]
async fn test_anchor_state_field_and_details() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"anchor_state","seq":30,"payload":{"field":"leader_changed","details":{"new_leader":"anc-2"}}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        Ok(TopologyEvent::AnchorState { version, field, details }) => {
            assert_eq!(*version, 30);
            assert_eq!(field, "leader_changed");
            let d = details.as_ref().expect("details should be present");
            assert_eq!(d["new_leader"].as_str(), Some("anc-2"));
        }
        other => panic!("expected AnchorState, got {:?}", other),
    }
}

/// Test 18 — ResyncRequired reason.
#[tokio::test]
async fn test_resync_required_reason() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"resync_required","seq":0,"payload":{"reason":"snapshot_compacted"}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert_eq!(events.len(), 1);
    match &events[0] {
        Ok(TopologyEvent::ResyncRequired { reason }) => {
            assert_eq!(reason, "snapshot_compacted");
        }
        other => panic!("expected ResyncRequired, got {:?}", other),
    }
}

/// Test 19 — unknown event type is silently skipped; stream continues.
#[tokio::test]
async fn test_unknown_event_type_silently_skipped() {
    let lines = [
        r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#,
        r#"{"event_type":"unknown_future_event","seq":1,"payload":{}}"#,
        r#"{"event_type":"also_unknown","seq":2,"payload":{"x":1}}"#,
        r#"{"event_type":"member_left","seq":3,"payload":{"nid":"real-node"}}"#,
    ];
    let body = lines.join("\n") + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    // only the member_left should be yielded
    assert_eq!(events.len(), 1);
    assert!(matches!(events[0], Ok(TopologyEvent::MemberLeft { .. })));
}

/// Test 20 — `AnchorTopologyError::Protocol` attributes are accessible.
#[tokio::test]
async fn test_anchor_topology_error_protocol_attributes() {
    let (server, url) = bind_server();
    let body = r#"{"error":"NWP-ERR-9","status":"topology.forbidden","message":"access denied"}"#
        .to_string();
    let _guard = serve_once_status(server, 403, body);

    let client = AnchorNodeClient::new(&url);
    let err = client.get_snapshot().await.expect_err("should fail");

    // Verify Display and Debug work and expose expected content
    let display = format!("{}", err);
    assert!(display.contains("NWP-ERR-9"), "display: {}", display);
    assert!(display.contains("topology.forbidden"), "display: {}", display);
    assert!(display.contains("access denied"), "display: {}", display);

    let debug_str = format!("{:?}", err);
    assert!(debug_str.contains("Protocol"), "debug: {}", debug_str);

    // Destructure directly
    match err {
        AnchorTopologyError::Protocol {
            nwp_error_code,
            nps_status,
            message,
        } => {
            assert_eq!(nwp_error_code, "NWP-ERR-9");
            assert_eq!(nps_status, "topology.forbidden");
            assert_eq!(message, "access denied");
        }
        other => panic!("unexpected variant: {:?}", other),
    }
}

// ── bonus edge-case tests ─────────────────────────────────────────────────────

/// Test 21 — get_snapshot_with include slice is forwarded (server answers ok).
#[tokio::test]
async fn test_get_snapshot_with_include_slice() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, snapshot_json(7, "anc-inc", 1));

    let client = AnchorNodeClient::new(&url);
    let snap = client
        .get_snapshot_with(SCOPE_CLUSTER, &["members", "capabilities"], 2, None)
        .await
        .expect("should succeed");

    assert_eq!(snap.version, 7);
}

/// Test 22 — multiple members in snapshot deserialized correctly.
#[tokio::test]
async fn test_get_snapshot_multiple_members() {
    let body = r#"{"data":[{"version":3,"anchor_nid":"anc-m","cluster_size":3,"members":[
        {"nid":"a","node_roles":["worker"],"activation_mode":"auto","child_anchor":null,"member_count":null,"tags":null,"joined_at":null,"last_seen":null,"capabilities":null,"metrics":null},
        {"nid":"b","node_roles":["anchor"],"activation_mode":"manual","child_anchor":true,"member_count":2,"tags":["tier:1"],"joined_at":null,"last_seen":null,"capabilities":null,"metrics":null}
    ],"truncated":false}]}"#.to_string();

    let (server, url) = bind_server();
    let _guard = serve_once_json(server, body);

    let client = AnchorNodeClient::new(&url);
    let snap = client.get_snapshot().await.expect("should succeed");

    assert_eq!(snap.cluster_size, 3);
    assert_eq!(snap.members.len(), 2);
    assert_eq!(snap.members[0].nid, "a");
    assert_eq!(snap.members[1].nid, "b");
    assert_eq!(snap.members[1].child_anchor, Some(true));
    assert_eq!(snap.truncated, Some(false));
}

/// Test 23 — stream with only the ack line yields no events.
#[tokio::test]
async fn test_subscribe_only_ack_yields_no_events() {
    let body = r#"{"type":"topology.stream","action":"subscribed","stream_id":"s","seq":0}"#
        .to_string()
        + "\n";

    let (server, url) = bind_server();
    let _guard = serve_once_ndjson(server, body);

    let client = AnchorNodeClient::new(&url);
    let stream = client.subscribe().await.unwrap();
    let events: Vec<_> = stream.collect().await;

    assert!(events.is_empty());
}

/// Test 24 — `with_client` builder replaces the inner reqwest client.
#[tokio::test]
async fn test_with_client_builder() {
    let (server, url) = bind_server();
    let _guard = serve_once_json(server, snapshot_json(99, "anc-custom", 7));

    let custom_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap();

    let client = AnchorNodeClient::new(&url).with_client(custom_client);
    let snap = client.get_snapshot().await.expect("should succeed");
    assert_eq!(snap.version, 99);
    assert_eq!(snap.cluster_size, 7);
}

/// Test 25 — SCOPE_MEMBER constant has expected value.
#[tokio::test]
async fn test_scope_constants() {
    assert_eq!(SCOPE_CLUSTER, "cluster");
    assert_eq!(SCOPE_MEMBER, "member");
}
