// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the NWP Bridge subsystem.
//!
//! Outbound dispatchers are exercised against a `tiny_http` mock server bound to
//! `127.0.0.1:0` (with `reject_private: false` so the SSRF guard permits the
//! loopback test target). Inbound server bridges are exercised directly through
//! `dispatch()` / the middleware `handle()` function.

use std::str::FromStr;
use std::sync::Arc;

use serde_json::{json, Value};
use tiny_http::{Header, Response, Server};

use nps_nwp::{
    bridge_error_codes, bridge_jsonrpc_error_codes, bridge_target_from_json, parse_http_endpoint,
    A2aBridgeDispatcher, A2aServerBridge, BridgeDispatcher, BridgeDispatcherRegistry, BridgeFrame,
    BridgeJsonRpcRequest, BridgeNode, BridgeServerAction, BridgeServerMiddleware,
    BridgeServerOptions, BridgeTarget, GrpcBridgeDispatcher, HttpBridgeDispatcher,
    McpBridgeDispatcher, McpServerBridge,
};
use nps_nwp::{ActionFrame, NodeRequest};

// ── helpers ──────────────────────────────────────────────────────────────────

fn bind_server() -> (Server, String) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    (server, format!("http://127.0.0.1:{port}"))
}

/// Reply once with the given content-type/status/body. Returns the captured
/// request body via a channel for assertions.
fn serve_once(
    server: Server,
    content_type: &'static str,
    status: u16,
    body: Vec<u8>,
    extra_headers: Vec<(&'static str, &'static str)>,
) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        if let Ok(Some(mut req)) = server.recv_timeout(std::time::Duration::from_secs(5)) {
            let mut captured = Vec::new();
            let _ = std::io::Read::read_to_end(req.as_reader(), &mut captured);
            let _ = tx.send(captured);

            let len = body.len();
            let mut resp = Response::from_data(body)
                .with_status_code(status as i32)
                .with_header(Header::from_str(&format!("Content-Type: {content_type}")).unwrap())
                .with_header(Header::from_str(&format!("Content-Length: {len}")).unwrap());
            for (k, v) in extra_headers {
                resp = resp.with_header(Header::from_str(&format!("{k}: {v}")).unwrap());
            }
            let _ = req.respond(resp);
        }
    });
    rx
}

fn action_frame(params: Value) -> ActionFrame {
    ActionFrame {
        action: "bridge.dispatch".to_string(),
        params: Some(params),
        anchor_ref: None,
        async_: false,
    }
}

fn target(protocol: &str, endpoint: &str, mut extras: Value) -> BridgeTarget {
    // Ensure the loopback test host passes the SSRF guard.
    if extras.get("reject_private").is_none() {
        extras["reject_private"] = json!(false);
    }
    let mut obj = json!({ "protocol": protocol, "endpoint": endpoint });
    for (k, v) in extras.as_object().unwrap() {
        obj[k] = v.clone();
    }
    bridge_target_from_json(&obj).unwrap()
}

// ── target parsing ───────────────────────────────────────────────────────────

#[test]
fn target_parsing_reads_protocol_endpoint_and_extras() {
    let obj = json!({
        "protocol": "http",
        "endpoint": "https://api.example.com/v1",
        "method": "GET",
        "extras": { "content_type": "text/plain" }
    });
    let t = bridge_target_from_json(&obj).unwrap();
    assert_eq!(t.protocol, "http");
    assert_eq!(t.endpoint, "https://api.example.com/v1");
    let extras = t.extras.unwrap();
    assert_eq!(extras.get("method").unwrap(), "GET");
    // extras.* is flattened into the map.
    assert_eq!(extras.get("content_type").unwrap(), "text/plain");
}

#[test]
fn target_parsing_missing_protocol_is_target_invalid() {
    let obj = json!({ "endpoint": "https://x" });
    let err = bridge_target_from_json(&obj).unwrap_err();
    assert_eq!(err.error_code, bridge_error_codes::TARGET_INVALID);
}

#[test]
fn target_from_action_frame_reads_nested_bridge_target() {
    let frame = action_frame(json!({
        "bridge_target": { "protocol": "mcp", "endpoint": "https://m" }
    }));
    let t = nps_nwp::bridge_target_from_action_frame(&frame).unwrap();
    assert_eq!(t.protocol, "mcp");
    assert_eq!(t.endpoint, "https://m");
}

// ── endpoint / SSRF ──────────────────────────────────────────────────────────

#[test]
fn endpoint_rejects_private_host() {
    let t = bridge_target_from_json(&json!({
        "protocol": "http",
        "endpoint": "http://127.0.0.1:8080/x"
    }))
    .unwrap();
    let err = parse_http_endpoint(&t).unwrap_err();
    assert_eq!(err.error_code, bridge_error_codes::ENDPOINT_INVALID);
    assert!(err.message.contains("SSRF"));
}

#[test]
fn endpoint_rejects_non_http_scheme() {
    let t = bridge_target_from_json(&json!({
        "protocol": "http",
        "endpoint": "ftp://example.com/x"
    }))
    .unwrap();
    let err = parse_http_endpoint(&t).unwrap_err();
    assert_eq!(err.error_code, bridge_error_codes::ENDPOINT_INVALID);
}

#[test]
fn endpoint_allows_public_host() {
    let t = bridge_target_from_json(&json!({
        "protocol": "http",
        "endpoint": "https://api.example.com/v1"
    }))
    .unwrap();
    let parsed = parse_http_endpoint(&t).unwrap();
    assert_eq!(parsed.scheme, "https");
    assert_eq!(parsed.host, "api.example.com");
    assert_eq!(parsed.port, 443);
}

#[test]
fn endpoint_allowed_prefixes_enforced() {
    let t = bridge_target_from_json(&json!({
        "protocol": "http",
        "endpoint": "https://evil.example.com/x",
        "reject_private": false,
        "allowed_prefixes": ["https://api.example.com/"]
    }))
    .unwrap();
    let err = parse_http_endpoint(&t).unwrap_err();
    assert_eq!(err.error_code, bridge_error_codes::ENDPOINT_INVALID);
}

// ── protocol resolution ──────────────────────────────────────────────────────

#[tokio::test]
async fn protocol_unsupported_when_not_registered() {
    let registry = BridgeDispatcherRegistry::new();
    let node = BridgeNode::new(registry);
    let frame = action_frame(json!({ "protocol": "smtp", "endpoint": "https://x" }));
    let err = node.dispatch(&frame).await.unwrap_err();
    assert_eq!(err.error_code, bridge_error_codes::PROTOCOL_UNSUPPORTED);
}

#[test]
fn default_registry_has_all_builtins() {
    let registry = BridgeDispatcherRegistry::create_default(reqwest::Client::new());
    let protocols = registry.protocols();
    assert_eq!(protocols, vec!["a2a", "grpc", "http", "mcp"]);
}

// ── HTTP dispatcher ──────────────────────────────────────────────────────────

#[tokio::test]
async fn http_dispatcher_posts_body_and_maps_json_response() {
    let (server, url) = bind_server();
    let rx = serve_once(
        server,
        "application/json",
        201,
        br#"{"ok":true,"n":7}"#.to_vec(),
        vec![],
    );

    let dispatcher = HttpBridgeDispatcher::new(reqwest::Client::new());
    let frame = action_frame(json!({ "body": { "hello": "world" } }));
    let t = target("http", &url, json!({ "method": "POST" }));
    let caps = dispatcher.dispatch(&frame, &t).await.unwrap();

    assert_eq!(
        caps.anchor_ref.as_deref(),
        Some(HttpBridgeDispatcher::RESPONSE_ANCHOR_REF)
    );
    let record = &caps.data[0];
    assert_eq!(record["status_code"], 201);
    assert_eq!(record["success"], true);
    assert_eq!(record["body"]["ok"], true);
    assert_eq!(record["body"]["n"], 7);

    let sent = rx.recv().unwrap();
    let sent_json: Value = serde_json::from_slice(&sent).unwrap();
    assert_eq!(sent_json["hello"], "world");
}

#[tokio::test]
async fn http_dispatcher_non_json_falls_back_to_body_text() {
    let (server, url) = bind_server();
    let _rx = serve_once(server, "text/plain", 200, b"plain text".to_vec(), vec![]);

    let dispatcher = HttpBridgeDispatcher::new(reqwest::Client::new());
    let frame = action_frame(json!({}));
    let t = target("http", &url, json!({ "method": "GET" }));
    let caps = dispatcher.dispatch(&frame, &t).await.unwrap();
    assert_eq!(caps.data[0]["body_text"], "plain text");
}

// ── gRPC-JSON dispatcher ─────────────────────────────────────────────────────

#[tokio::test]
async fn grpc_dispatcher_frames_and_unframes_json_messages() {
    // Build a length-prefixed gRPC-JSON reply: [0][len:be32][json].
    let payload = br#"{"reply":"pong"}"#.to_vec();
    let mut wire = vec![0u8];
    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    wire.extend_from_slice(&payload);

    let (server, url) = bind_server();
    let rx = serve_once(
        server,
        "application/grpc+json",
        200,
        wire,
        vec![("grpc-status", "0")],
    );

    let dispatcher = GrpcBridgeDispatcher::new(reqwest::Client::new());
    let frame = action_frame(json!({ "grpc_message": { "ping": 1 } }));
    let t = target("grpc", &format!("{url}/pkg.Svc/Method"), json!({}));
    let caps = dispatcher.dispatch(&frame, &t).await.unwrap();

    let record = &caps.data[0];
    assert_eq!(record["grpc_status"], "0");
    assert_eq!(record["success"], true);
    assert_eq!(record["messages"][0]["reply"], "pong");

    // Verify request framing: leading 0 byte, big-endian length, then JSON.
    let sent = rx.recv().unwrap();
    assert_eq!(sent[0], 0);
    let len = u32::from_be_bytes([sent[1], sent[2], sent[3], sent[4]]) as usize;
    let body: Value = serde_json::from_slice(&sent[5..5 + len]).unwrap();
    assert_eq!(body["ping"], 1);
}

// ── JSON-RPC (MCP/A2A) dispatchers ───────────────────────────────────────────

#[tokio::test]
async fn mcp_dispatcher_builds_jsonrpc_and_extracts_result() {
    let (server, url) = bind_server();
    let rx = serve_once(
        server,
        "application/json",
        200,
        br#"{"jsonrpc":"2.0","id":"1","result":{"content":[]}}"#.to_vec(),
        vec![],
    );

    let dispatcher = McpBridgeDispatcher::new(reqwest::Client::new());
    let frame = action_frame(json!({ "rpc_params": { "name": "echo" }, "id": "1" }));
    let t = target("mcp", &url, json!({}));
    let caps = dispatcher.dispatch(&frame, &t).await.unwrap();

    assert_eq!(
        caps.anchor_ref.as_deref(),
        Some(McpBridgeDispatcher::RESPONSE_ANCHOR_REF)
    );
    assert!(caps.data[0].get("result").is_some());

    let sent: Value = serde_json::from_slice(&rx.recv().unwrap()).unwrap();
    assert_eq!(sent["jsonrpc"], "2.0");
    assert_eq!(sent["method"], "tools/call"); // MCP default method
    assert_eq!(sent["params"]["name"], "echo");
    assert_eq!(sent["id"], "1");
}

#[tokio::test]
async fn a2a_dispatcher_defaults_to_tasks_send() {
    let (server, url) = bind_server();
    let rx = serve_once(
        server,
        "application/json",
        200,
        br#"{"jsonrpc":"2.0","id":"x","result":{}}"#.to_vec(),
        vec![],
    );

    let dispatcher = A2aBridgeDispatcher::new(reqwest::Client::new());
    let frame = action_frame(json!({ "id": "x" }));
    let t = target("a2a", &url, json!({}));
    let _ = dispatcher.dispatch(&frame, &t).await.unwrap();

    let sent: Value = serde_json::from_slice(&rx.recv().unwrap()).unwrap();
    assert_eq!(sent["method"], "tasks/send");
}

// ── inbound MCP server bridge ────────────────────────────────────────────────

fn echo_options() -> BridgeServerOptions {
    let dispatch: nps_nwp::LocalActionDispatcher = Arc::new(|frame: ActionFrame| {
        Box::pin(async move {
            let mut caps = nps_ncp::CapsFrame::new(
                "nps://echo/v1",
                vec![json!({ "action": frame.action, "params": frame.params })],
            );
            caps.token_est = Some(1);
            BridgeFrame::Caps(caps)
        })
    });
    BridgeServerOptions {
        require_auth: false,
        ..BridgeServerOptions::default()
    }
    .add_action(BridgeServerAction {
        description: Some("Echo tool".to_string()),
        ..BridgeServerAction::new("echo.act")
    })
    .with_dispatch(dispatch)
}

#[tokio::test]
async fn mcp_server_tools_call_invokes_local_action() {
    let bridge = McpServerBridge::new(echo_options());
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": "echo_act", "arguments": { "k": "v" } })),
    };
    let resp = bridge.dispatch(&request).await;
    assert!(resp.error.is_none(), "expected success, got {resp:?}");
    let result = resp.result.unwrap();
    assert_eq!(result["isError"], false);
    // Content text is the serialized CapsFrame.
    let text = result["content"][0]["text"].as_str().unwrap();
    let caps: Value = serde_json::from_str(text).unwrap();
    assert_eq!(caps["anchor_ref"], "nps://echo/v1");
    assert_eq!(caps["data"][0]["params"]["k"], "v");
}

#[tokio::test]
async fn mcp_server_tools_list_reports_exposed_tool() {
    let bridge = McpServerBridge::new(echo_options());
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/list".to_string(),
        params: None,
    };
    let resp = bridge.dispatch(&request).await;
    let tools = resp.result.unwrap()["tools"].clone();
    assert_eq!(tools[0]["name"], "echo_act"); // sanitized tool name
    assert_eq!(tools[0]["description"], "Echo tool");
}

#[tokio::test]
async fn mcp_server_tool_not_found() {
    let bridge = McpServerBridge::new(echo_options());
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": "does_not_exist" })),
    };
    let resp = bridge.dispatch(&request).await;
    let err = resp.error.unwrap();
    assert_eq!(err.code, bridge_jsonrpc_error_codes::TOOL_NOT_FOUND);
    assert_eq!(
        err.data.unwrap()["error"],
        bridge_error_codes::SERVER_TOOL_NOT_FOUND
    );
}

#[tokio::test]
async fn mcp_server_dispatcher_missing_surfaces_error_frame() {
    // No dispatch configured → invoker returns SERVER-DISPATCHER-MISSING frame.
    let options = BridgeServerOptions {
        require_auth: false,
        ..BridgeServerOptions::default()
    }
    .add_action(BridgeServerAction::new("echo.act"));
    let bridge = McpServerBridge::new(options);
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tools/call".to_string(),
        params: Some(json!({ "name": "echo_act" })),
    };
    let resp = bridge.dispatch(&request).await;
    let result = resp.result.unwrap();
    assert_eq!(result["isError"], true);
    let text = result["content"][0]["text"].as_str().unwrap();
    let frame: Value = serde_json::from_str(text).unwrap();
    assert_eq!(
        frame["error"],
        bridge_error_codes::SERVER_DISPATCHER_MISSING
    );
}

// ── inbound A2A server bridge ────────────────────────────────────────────────

#[tokio::test]
async fn a2a_server_tasks_send_invokes_single_action() {
    let bridge = A2aServerBridge::new(echo_options());
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!("t1")),
        method: "tasks/send".to_string(),
        params: Some(json!({
            "id": "t1",
            "message": {
                "role": "user",
                "parts": [ { "type": "data", "data": { "n": 42 } } ]
            }
        })),
    };
    let resp = bridge.dispatch(&request).await;
    assert!(resp.error.is_none(), "got {resp:?}");
    let task = resp.result.unwrap();
    assert_eq!(task["status"]["state"], "completed");
    let artifact_data = &task["artifacts"][0]["parts"][0]["data"];
    assert_eq!(artifact_data["data"][0]["params"]["n"], 42);
}

#[tokio::test]
async fn a2a_server_unknown_method() {
    let bridge = A2aServerBridge::new(echo_options());
    let request = BridgeJsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(json!(1)),
        method: "tasks/cancel".to_string(),
        params: None,
    };
    let resp = bridge.dispatch(&request).await;
    assert_eq!(
        resp.error.unwrap().code,
        bridge_jsonrpc_error_codes::METHOD_NOT_FOUND
    );
}

#[tokio::test]
async fn a2a_agent_card_lists_skills() {
    let bridge = A2aServerBridge::new(echo_options());
    let card = bridge.build_agent_card("https://host/a2a");
    assert_eq!(card.url, "https://host/a2a");
    assert_eq!(card.skills[0].id, "echo.act");
    assert!(card.authentication.is_none()); // require_auth = false
}

// ── server middleware (handle) ───────────────────────────────────────────────

#[tokio::test]
async fn middleware_routes_mcp_post() {
    let mw = BridgeServerMiddleware::new(echo_options());
    let body = serde_json::to_vec(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "ping"
    }))
    .unwrap();
    let req = NodeRequest {
        method: "POST".to_string(),
        path: "/mcp".to_string(),
        headers: Default::default(),
        body,
    };
    let resp = mw.handle(&req).await.expect("mcp route");
    assert_eq!(resp.status, 200);
    let value = resp.json_value().unwrap();
    assert!(value["result"].is_object());
}

#[tokio::test]
async fn middleware_requires_auth_when_enabled() {
    let mut options = echo_options();
    options.require_auth = true;
    let mw = BridgeServerMiddleware::new(options);
    let req = NodeRequest {
        method: "POST".to_string(),
        path: "/mcp".to_string(),
        headers: Default::default(),
        body: b"{}".to_vec(),
    };
    let resp = mw.handle(&req).await.expect("mcp route");
    assert_eq!(resp.status, 401);
}

#[tokio::test]
async fn middleware_accepts_valid_agent_nid() {
    let mut options = echo_options();
    options.require_auth = true;
    let mw = BridgeServerMiddleware::new(options);
    let req = NodeRequest::new("POST", "/mcp")
        .with_header("x-nwp-agent", "urn:nps:agent:example.com:alice")
        .with_json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }));
    let resp = mw.handle(&req).await.expect("mcp route");
    assert_eq!(resp.status, 200);
}

#[tokio::test]
async fn middleware_returns_none_for_foreign_path() {
    let mw = BridgeServerMiddleware::new(echo_options());
    let req = NodeRequest::new("GET", "/other");
    assert!(mw.handle(&req).await.is_none());
}

#[tokio::test]
async fn middleware_agent_card_route() {
    let mw = BridgeServerMiddleware::new(echo_options());
    let req = NodeRequest::new("GET", "/.well-known/agent.json");
    let resp = mw.handle(&req).await.expect("agent card route");
    assert_eq!(resp.status, 200);
    let card = resp.json_value().unwrap();
    assert_eq!(card["skills"][0]["id"], "echo.act");
}

#[tokio::test]
async fn middleware_body_too_large() {
    let mut options = echo_options();
    options.require_auth = false;
    options.max_request_body_bytes = 4;
    let mw = BridgeServerMiddleware::new(options);
    let req = NodeRequest::new("POST", "/a2a")
        .with_json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "tasks/send" }));
    let resp = mw.handle(&req).await.expect("a2a route");
    assert_eq!(resp.status, 413);
}
