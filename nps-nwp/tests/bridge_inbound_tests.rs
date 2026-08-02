// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS-CR-0010 inbound Bridge servers.
//!
//! Covers the six `TC-N2-BridgeIn-*` conformance cases
//! (`spec/services/conformance/NPS-Node-L2.md` §3.3) and the .NET
//! `BridgeNodeTests` inbound suite (brief B Part 2 §8).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use nps_nwp::anchor_server::{AnchorRequest, AnchorResponse};
use nps_nwp::bridge_inbound::{
    A2aInboundServer, BridgeDispatchError, BridgeInboundApp, BridgeInboundOptions,
    BridgeJsonRpcRequest, BridgeJsonRpcResponse, BridgeServerOptions, GrpcInboundService,
    GrpcStatusCode, InProcessNwpBackend, McpInboundServer, NwpActionDescriptor, NwpBackend,
    NwpNodeDescriptor, NwpNodeRole, UpstreamContext, REQUIRED_METHODS,
};

const NODE: &str = "bridge-inbound-test";

// ── fixtures ─────────────────────────────────────────────────────────────────

/// An Action node exposing `orders.lookup`, echoing its arguments back.
fn action_backend(name: &str, actions: &[&str]) -> Arc<dyn NwpBackend> {
    let descs = actions
        .iter()
        .map(|a| NwpActionDescriptor::new(*a))
        .collect();
    Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(name, NwpNodeRole::Action))
            .with_actions(descs)
            .with_invoke_dispatcher(Arc::new(|f| {
                Ok(json!({
                    "anchor_ref": "nps:test:order",
                    "action":     f.action,
                    "params":     f.params,
                }))
            })),
    )
}

/// A Complex node — both queryable and invokable.
fn complex_backend(name: &str) -> Arc<dyn NwpBackend> {
    Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(name, NwpNodeRole::Complex))
            .with_actions(vec![NwpActionDescriptor::new("orders.lookup")])
            .with_invoke_dispatcher(Arc::new(|_| Ok(json!({ "ok": true }))))
            .with_query_dispatcher(Arc::new(|q| {
                Ok(json!({ "count": 1, "data": [ { "filter": q.filter } ] }))
            })),
    )
}

/// A backend whose dispatcher returns a given NPS fault.
fn failing_backend(status: &'static str, code: &'static str) -> Arc<dyn NwpBackend> {
    Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(NODE, NwpNodeRole::Action))
            .with_actions(vec![NwpActionDescriptor::new("orders.lookup")])
            .with_invoke_dispatcher(Arc::new(move |_| {
                Err(BridgeDispatchError::error_frame(status, code, "denied"))
            })),
    )
}

fn mcp(backends: Vec<Arc<dyn NwpBackend>>, protocols: &[&str]) -> McpInboundServer {
    let mut o = BridgeInboundOptions::new()
        .with_inbound_protocols(protocols.iter().map(|s| s.to_string()).collect());
    o.backends = backends;
    McpInboundServer::new(o)
}

fn a2a(backends: Vec<Arc<dyn NwpBackend>>, protocols: &[&str]) -> A2aInboundServer {
    let mut o = BridgeInboundOptions::new()
        .with_inbound_protocols(protocols.iter().map(|s| s.to_string()).collect());
    o.backends = backends;
    A2aInboundServer::new(o)
}

fn req(method: &str, params: Value) -> BridgeJsonRpcRequest {
    BridgeJsonRpcRequest::new(json!(1), method, Some(params))
}

fn result_of(r: &BridgeJsonRpcResponse) -> &Value {
    r.result.as_ref().unwrap_or_else(|| {
        panic!("expected a result, got error {:?}", r.error);
    })
}

// ── TC-N2-BridgeIn-01: MCP serves the full required method set ───────────────

#[tokio::test]
async fn bridge_in_01_mcp_serves_the_full_required_method_set() {
    let s = mcp(
        vec![
            complex_backend("mem-node"),
            action_backend(NODE, &["orders.lookup"]),
        ],
        &["mcp"],
    );

    assert_eq!(
        REQUIRED_METHODS,
        [
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "resources/list",
            "resources/read"
        ]
    );

    for m in REQUIRED_METHODS {
        let params = match *m {
            "tools/call" => json!({ "name": "bridge-inbound-test__orders_lookup" }),
            "resources/read" => json!({ "uri": "nwp://mem-node/" }),
            _ => json!({}),
        };
        let r = s.dispatch(&req(m, params)).await;
        assert!(!r.is_error(), "{m} must return a successful result: {r:?}");
    }

    // tools/list surfaces qualified node__action names.
    let r = s.dispatch(&req("tools/list", json!({}))).await;
    let names: Vec<&str> = result_of(&r)["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"bridge-inbound-test__orders_lookup"), "{names:?}");
    assert!(names.contains(&"mem-node__orders_lookup"), "{names:?}");
}

#[tokio::test]
async fn mcp_initialize_always_advertises_tools_and_resources() {
    // Even with NO Memory Node behind it.
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s.dispatch(&req("initialize", json!({}))).await;
    let caps = &result_of(&r)["capabilities"];
    assert!(caps.get("tools").is_some());
    assert!(caps.get("resources").is_some());
    assert_eq!(result_of(&r)["serverInfo"]["name"], "nps-bridge-server");
}

#[tokio::test]
async fn mcp_serves_resources_methods_even_with_no_memory_node() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);

    // An empty set is conformant — "method not found" is NOT.
    let r = s.dispatch(&req("resources/list", json!({}))).await;
    assert!(!r.is_error());
    assert_eq!(result_of(&r)["resources"], json!([]));
}

#[tokio::test]
async fn mcp_serves_resources_over_a_queryable_node() {
    let s = mcp(vec![complex_backend(NODE)], &["mcp"]);

    let r = s.dispatch(&req("resources/list", json!({}))).await;
    let res = &result_of(&r)["resources"][0];
    assert_eq!(res["uri"], "nwp://bridge-inbound-test/");
    assert_eq!(res["mimeType"], "application/json");
    assert!(res["description"].as_str().unwrap().contains("complex"));

    let r = s
        .dispatch(&req("resources/read", json!({ "uri": "nwp://bridge-inbound-test/" })))
        .await;
    let c = &result_of(&r)["contents"][0];
    assert_eq!(c["uri"], "nwp://bridge-inbound-test/");
    assert_eq!(c["mimeType"], "application/json");
    // The payload's raw JSON, carrying the ResourceReadLimit-bearing query.
    assert!(c["text"].as_str().unwrap().contains("\"limit\":100"));
}

#[tokio::test]
async fn mcp_resources_read_rejects_a_bad_or_unknown_uri() {
    let s = mcp(vec![complex_backend(NODE)], &["mcp"]);

    // Missing uri.
    let r = s.dispatch(&req("resources/read", json!({}))).await;
    assert_eq!(r.error_code(), Some(-32602));

    // Not an absolute nwp:// URI.
    let r = s
        .dispatch(&req("resources/read", json!({ "uri": "https://x/" })))
        .await;
    assert_eq!(r.error_code(), Some(-32602));
    assert!(r.error.unwrap().message.contains("nwp://<node>/"));

    // Unknown host ⇒ -32602 (NOT -32601), with the registered code in data.
    let r = s
        .dispatch(&req("resources/read", json!({ "uri": "nwp://nope/" })))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32602);
    assert_eq!(
        e.data.unwrap()["error"],
        "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND"
    );
}

#[tokio::test]
async fn mcp_lists_tools_and_dispatches_a_tool_call() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s
        .dispatch(&req(
            "tools/call",
            json!({
                "name":      "bridge-inbound-test__orders_lookup",
                "arguments": { "order_id": "A-1" },
            }),
        ))
        .await;
    let res = result_of(&r);
    assert_eq!(res["isError"], false);
    let text = res["content"][0]["text"].as_str().unwrap();
    // The action id reaching the node is the ORIGINAL, dotted one.
    assert!(text.contains("orders.lookup"), "{text}");
    assert!(text.contains("A-1"), "{text}");
}

#[tokio::test]
async fn mcp_still_resolves_unqualified_tool_names() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    // The bare, encoded segment resolves back to action id `orders.lookup`.
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders_lookup" })))
        .await;
    assert_eq!(result_of(&r)["isError"], false);

    // As does the raw dotted id.
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders.lookup" })))
        .await;
    assert_eq!(result_of(&r)["isError"], false);
}

#[tokio::test]
async fn mcp_tools_call_requires_a_name() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    for p in [json!({}), json!({ "name": "   " })] {
        let r = s.dispatch(&req("tools/call", p)).await;
        let e = r.error.unwrap();
        assert_eq!(e.code, -32602);
        assert_eq!(e.message, "MCP tools/call requires params.name.");
    }
}

#[tokio::test]
async fn mcp_unknown_tool_is_method_not_found_never_the_retired_code() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "nope" })))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    assert_ne!(e.code, -32002, "-32002 is retired");
    assert!(e.message.contains("is not exposed by this Bridge Node"));
    assert_eq!(
        e.data.unwrap()["error"],
        "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND"
    );
}

#[tokio::test]
async fn mcp_unknown_method_is_method_not_found() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s.dispatch(&req("prompts/list", json!({}))).await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    assert_eq!(
        e.data.unwrap()["error"],
        "NWP-BRIDGE-DIRECTION-UNSUPPORTED"
    );
}

// ── TC-N2-BridgeIn-04: bare id resolves, ambiguity is rejected ───────────────

#[tokio::test]
async fn bridge_in_04_bare_id_resolves_and_ambiguity_is_rejected() {
    // Two nodes: exactly one defines `orders_lookup`, both define `status`.
    let s = mcp(
        vec![
            action_backend("node-a", &["orders_lookup", "status"]),
            action_backend("node-b", &["status"]),
        ],
        &["mcp"],
    );

    // Bare, unambiguous ⇒ resolves and succeeds.
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders_lookup" })))
        .await;
    assert_eq!(result_of(&r)["isError"], false);

    // Bare, ambiguous ⇒ a deterministic error NAMING BOTH qualified candidates.
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "status" })))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    let data = e.data.unwrap();
    let candidates: Vec<&str> = data["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert!(candidates.contains(&"node-a__status"), "{candidates:?}");
    assert!(candidates.contains(&"node-b__status"), "{candidates:?}");
    assert!(e.message.contains("node-a__status"));
    assert!(e.message.contains("node-b__status"));

    // Qualifying disambiguates.
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "node-b__status" })))
        .await;
    assert_eq!(result_of(&r)["isError"], false);
}

// ── TC-N2-BridgeIn-05: error mapping matches §16.3 ───────────────────────────

#[tokio::test]
async fn bridge_in_05_auth_failure_is_a_protocol_error_not_an_is_error_result() {
    let s = mcp(
        vec![failing_backend("NPS-AUTH-FORBIDDEN", "NWP-AUTH-NID-SCOPE-VIOLATION")],
        &["mcp"],
    );
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders.lookup" })))
        .await;
    assert_eq!(r.error_code(), Some(-32003));
    assert!(r.result.is_none(), "result MUST be absent for an auth failure");
}

#[tokio::test]
async fn bridge_in_05_unknown_action_and_timeout_map_to_distinct_codes() {
    // Unknown action ⇒ -32601.
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "ghost" })))
        .await;
    assert_eq!(r.error_code(), Some(-32601));

    // Upstream timeout ⇒ -32603.
    let s = mcp(
        vec![failing_backend("NPS-SERVER-TIMEOUT", "NWP-BRIDGE-UPSTREAM-FAILED")],
        &["mcp"],
    );
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders.lookup" })))
        .await;
    assert_eq!(r.error_code(), Some(-32603));
}

#[tokio::test]
async fn domain_failures_stay_is_error_content() {
    let s = mcp(
        vec![failing_backend("NPS-CLIENT-NOT-FOUND", "NWP-ACTION-NOT-FOUND")],
        &["mcp"],
    );
    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders.lookup" })))
        .await;
    let res = result_of(&r);
    assert_eq!(res["isError"], true);
    let text = res["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("NPS-CLIENT-NOT-FOUND"), "{text}");
}

#[tokio::test]
async fn missing_dispatcher_fails_loudly_with_a_registered_code() {
    // Declares an action but forgets the dispatcher — the backend still exists,
    // so the tool appears and the call fails loudly.
    let backend: Arc<dyn NwpBackend> = Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(NODE, NwpNodeRole::Action))
            .with_actions(vec![NwpActionDescriptor::new("orders.lookup")]),
    );
    let s = mcp(vec![backend], &["mcp"]);

    let r = s.dispatch(&req("tools/list", json!({}))).await;
    assert_eq!(result_of(&r)["tools"].as_array().unwrap().len(), 1);

    let r = s
        .dispatch(&req("tools/call", json!({ "name": "orders.lookup" })))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32603);
    let data = serde_json::to_string(&e.data).unwrap();
    assert!(data.contains("NWP-BRIDGE-SERVER-DISPATCHER-MISSING"), "{data}");
    assert!(
        !data.contains("NPS-SERVER-NOT-IMPLEMENTED"),
        "the invented status must not be reintroduced"
    );
}

// ── TC-N2-BridgeIn-06: undeclared direction is refused ───────────────────────

#[tokio::test]
async fn bridge_in_06_undeclared_protocol_is_refused_with_both_arrays_in_hint() {
    let mut o = BridgeInboundOptions::new()
        .with_inbound_protocols(vec!["mcp".into()])
        .with_outbound_protocols(vec!["http".into()]);
    o.backends = vec![action_backend(NODE, &["orders.lookup"])];
    let s = A2aInboundServer::new(o);

    // A well-formed A2A tasks/send against an MCP-only Bridge.
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({ "id": "t-1", "message": { "role": "user", "parts": [] } }),
        ))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    let data = e.data.unwrap();
    assert_eq!(data["error"], "NWP-BRIDGE-DIRECTION-UNSUPPORTED");
    assert_eq!(data["hint"]["bridge_inbound_protocols"], json!(["mcp"]));
    assert_eq!(data["hint"]["bridge_protocols"], json!(["http"]));
}

#[tokio::test]
async fn mcp_is_refused_when_undeclared() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    let r = s.dispatch(&req("initialize", json!({}))).await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    assert!(e.message.contains("\"mcp\""));
    assert_eq!(e.data.unwrap()["error"], "NWP-BRIDGE-DIRECTION-UNSUPPORTED");
}

// ── TC-N2-BridgeIn-03: A2A round-trip ────────────────────────────────────────

#[tokio::test]
async fn bridge_in_03_agent_card_lists_qualified_skills() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    let card = s.build_agent_card("https://bridge.test/a2a").await;

    assert_eq!(card["url"], "https://bridge.test/a2a");
    assert_eq!(card["provider"]["organization"], "LabAcacia / INNO LOTUS PTY LTD");
    assert_eq!(card["capabilities"]["streaming"], false);
    assert_eq!(card["capabilities"]["pushNotifications"], false);
    assert_eq!(card["capabilities"]["stateTransitionHistory"], false);
    // RequireAuth defaults to true, so the scheme is advertised.
    assert_eq!(card["authentication"]["schemes"], json!(["apikey"]));
    assert_eq!(card["authentication"]["credentials"], "X-NWP-Agent");

    let skill = &card["skills"][0];
    assert_eq!(skill["id"], "bridge-inbound-test__orders_lookup");
    assert_eq!(skill["inputModes"], json!(["text", "data"]));
    assert_eq!(skill["outputModes"], json!(["data"]));
}

#[tokio::test]
async fn bridge_in_03_tasks_send_completes_and_returns_an_artifact() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({
                "id":        "t-1",
                "sessionId": "s-1",
                "metadata":  { "action_id": "bridge-inbound-test__orders_lookup" },
                "message": {
                    "role":  "user",
                    "parts": [ { "type": "data", "data": { "order_id": "A-1" } } ],
                },
            }),
        ))
        .await;

    let task = result_of(&r);
    assert_eq!(task["id"], "t-1");
    assert_eq!(task["sessionId"], "s-1");
    assert_eq!(task["status"]["state"], "completed");
    assert!(task["status"]["message"].is_null());
    let artifact = &task["artifacts"][0];
    assert_eq!(artifact["name"], "nps-result");
    assert_eq!(artifact["index"], 0);
    assert_eq!(artifact["parts"][0]["type"], "data");
    assert_eq!(artifact["parts"][0]["data"]["anchor_ref"], "nps:test:order");
    assert_eq!(artifact["parts"][0]["data"]["params"]["order_id"], "A-1");
    assert_eq!(task["history"][0]["role"], "user");
}

#[tokio::test]
async fn a2a_only_serves_tasks_send() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    let r = s.dispatch(&req("tasks/get", json!({}))).await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32601);
    assert!(e.message.contains("A2A method 'tasks/get'"));
    assert_eq!(e.data.unwrap()["error"], "NWP-BRIDGE-DIRECTION-UNSUPPORTED");
}

#[tokio::test]
async fn a2a_requires_a_task_id() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    for p in [json!({}), json!({ "id": "  " })] {
        let r = s.dispatch(&req("tasks/send", p)).await;
        let e = r.error.unwrap();
        assert_eq!(e.code, -32602);
        assert!(e.message.contains("params.id is required"));
    }
    // A non-object params is also -32602.
    let r = s
        .dispatch(&BridgeJsonRpcRequest::new(
            json!(1),
            "tasks/send",
            Some(json!("nope")),
        ))
        .await;
    assert_eq!(r.error_code(), Some(-32602));
}

#[tokio::test]
async fn a2a_resolves_the_sole_action_with_no_skill_named() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({ "id": "t-1", "message": { "role": "user", "parts": [] } }),
        ))
        .await;
    assert_eq!(result_of(&r)["status"]["state"], "completed");
}

#[tokio::test]
async fn a2a_rejects_an_unnamed_skill_when_several_are_exposed() {
    let s = a2a(vec![action_backend(NODE, &["a", "b"])], &["a2a"]);
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({ "id": "t-1", "message": { "role": "user", "parts": [] } }),
        ))
        .await;
    let e = r.error.unwrap();
    assert_eq!(e.code, -32602);
    assert!(e.message.contains("must identify an exposed NPS action"));
    assert_eq!(e.data.unwrap()["error"], "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND");
}

#[tokio::test]
async fn a2a_accepts_every_skill_metadata_key_and_the_raw_action_id() {
    for key in ["action_id", "actionId", "skill_id", "skillId", "skill"] {
        let s = a2a(vec![action_backend(NODE, &["a", "orders.lookup"])], &["a2a"]);
        let r = s
            .dispatch(&req(
                "tasks/send",
                json!({
                    "id":       "t-1",
                    "metadata": { key: "orders.lookup" },
                    "message":  { "role": "user", "parts": [] },
                }),
            ))
            .await;
        assert_eq!(
            result_of(&r)["status"]["state"],
            "completed",
            "metadata key {key}"
        );
    }
}

#[tokio::test]
async fn a2a_extracts_arguments_in_the_documented_order() {
    let s = a2a(vec![action_backend(NODE, &["orders.lookup"])], &["a2a"]);

    // task.metadata.params wins.
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({
                "id":       "t-1",
                "metadata": { "params": { "from": "task-metadata" } },
                "message":  { "role": "user", "parts": [
                    { "type": "data", "data": { "from": "part-data" } }
                ] },
            }),
        ))
        .await;
    assert_eq!(
        result_of(&r)["artifacts"][0]["parts"][0]["data"]["params"]["from"],
        "task-metadata"
    );

    // A bare data part becomes the whole argument object.
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({
                "id":      "t-2",
                "message": { "role": "user", "parts": [
                    { "type": "data", "data": { "from": "part-data" } }
                ] },
            }),
        ))
        .await;
    assert_eq!(
        result_of(&r)["artifacts"][0]["parts"][0]["data"]["params"]["from"],
        "part-data"
    );

    // A text part becomes { text: ... }.
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({
                "id":      "t-3",
                "message": { "role": "user", "parts": [
                    { "type": "text", "text": "hello" }
                ] },
            }),
        ))
        .await;
    assert_eq!(
        result_of(&r)["artifacts"][0]["parts"][0]["data"]["params"]["text"],
        "hello"
    );
}

#[tokio::test]
async fn a2a_domain_failure_is_a_failed_task_but_infra_failure_is_a_protocol_error() {
    // NPS-CLIENT-* ⇒ a failed task carrying the code verbatim.
    let s = a2a(
        vec![failing_backend("NPS-CLIENT-NOT-FOUND", "NWP-ACTION-NOT-FOUND")],
        &["a2a"],
    );
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({ "id": "t-1", "message": { "role": "user", "parts": [] } }),
        ))
        .await;
    let task = result_of(&r);
    assert_eq!(task["status"]["state"], "failed");
    assert_eq!(task["status"]["message"]["role"], "agent");
    assert_eq!(task["artifacts"][0]["name"], "nps-error");
    assert_eq!(
        task["artifacts"][0]["parts"][0]["data"]["status"],
        "NPS-CLIENT-NOT-FOUND"
    );

    // Infrastructure class ⇒ a JSON-RPC error, NOT a task object.
    let s = a2a(
        vec![failing_backend("NPS-AUTH-FORBIDDEN", "NWP-AUTH-NID-SCOPE-VIOLATION")],
        &["a2a"],
    );
    let r = s
        .dispatch(&req(
            "tasks/send",
            json!({ "id": "t-1", "message": { "role": "user", "parts": [] } }),
        ))
        .await;
    assert_eq!(r.error_code(), Some(-32003));
    assert!(r.result.is_none());
}

// ── stdio transport ──────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_stdio_handles_line_delimited_json_rpc() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        "\n",
        "\n", // blank lines are skipped
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        "\n",
        "not json\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
        "\n",
    );
    let mut out: Vec<u8> = Vec::new();
    s.run_stdio(std::io::Cursor::new(input), &mut out)
        .await
        .unwrap();

    let lines: Vec<Value> = String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 4);
    assert_eq!(lines[0]["id"], 1);
    assert!(lines[0]["result"]["capabilities"].is_object());
    assert_eq!(lines[1]["id"], 2);
    assert_eq!(lines[1]["result"], json!({}));
    // A parse failure yields -32700 with id: null.
    assert_eq!(lines[2]["error"]["code"], -32700);
    assert!(lines[2]["id"].is_null());
    assert_eq!(lines[3]["id"], 3);
}

// ── gRPC service logic ───────────────────────────────────────────────────────

fn grpc(backends: Vec<Arc<dyn NwpBackend>>, protocols: &[&str]) -> GrpcInboundService {
    let mut o = BridgeInboundOptions::new()
        .with_inbound_protocols(protocols.iter().map(|s| s.to_string()).collect());
    o.backends = backends;
    GrpcInboundService::new(o)
}

#[tokio::test]
async fn bridge_in_02_grpc_unary_invoke_round_trip() {
    let s = grpc(vec![action_backend(NODE, &["orders.lookup"])], &["grpc"]);
    let ctx = UpstreamContext::default(); // no upstream, exactly one backend

    let r = s
        .invoke(&ctx, "orders.lookup", br#"{"order_id":"A-1"}"#)
        .await
        .expect("invoke");
    assert_eq!(r.http_status, 200);
    assert_eq!(r.task_id, "");
    let body: Value = serde_json::from_slice(&r.body_json).unwrap();
    // The response payload equals the Action Node's NWP result body — the
    // client supplied no NID, frame, or NPS addressing knowledge.
    assert_eq!(body["params"]["order_id"], "A-1");
    assert_eq!(body["action"], "orders.lookup");
}

#[tokio::test]
async fn grpc_manifest_query_and_list_actions() {
    let s = grpc(vec![complex_backend(NODE)], &["grpc"]);
    let ctx = UpstreamContext::for_upstream(NODE);

    let m = s.get_manifest(&ctx).await.unwrap();
    assert_eq!(m.node_type, "complex");
    let nwm: Value = serde_json::from_slice(&m.nwm_json).unwrap();
    assert_eq!(nwm["node_type"], "complex");

    // An empty query body means `{}`.
    let q = s.query(&ctx, b"").await.unwrap();
    assert_eq!(q.http_status, 200);
    let body: Value = serde_json::from_slice(&q.body_json).unwrap();
    assert_eq!(body["data"][0]["filter"], json!({}));

    let a = s.list_actions(&ctx).await.unwrap();
    let actions: Value = serde_json::from_slice(&a.actions_json).unwrap();
    assert!(actions["actions"].get("orders.lookup").is_some());
}

#[tokio::test]
async fn grpc_refuses_when_grpc_is_undeclared() {
    // gRPC is deliberately NOT in the default inbound set.
    let s = grpc(vec![action_backend(NODE, &["orders.lookup"])], &["mcp", "a2a"]);
    let e = s
        .invoke(&UpstreamContext::default(), "orders.lookup", b"{}")
        .await
        .unwrap_err();
    assert_eq!(e.code, GrpcStatusCode::Unimplemented);
    assert!(e.message.contains("NWP-BRIDGE-DIRECTION-UNSUPPORTED"));
    assert!(e.message.contains("NPS-SERVER-UNSUPPORTED"));
}

#[tokio::test]
async fn grpc_requires_an_action_id_and_resolves_backends_by_name() {
    let s = grpc(
        vec![action_backend("a", &["x"]), action_backend("b", &["y"])],
        &["grpc"],
    );

    let e = s
        .invoke(&UpstreamContext::for_upstream("a"), "  ", b"{}")
        .await
        .unwrap_err();
    assert_eq!(e.code, GrpcStatusCode::InvalidArgument);
    assert_eq!(e.message, "action_id is required");

    // Case-insensitive name match.
    assert!(s
        .invoke(&UpstreamContext::for_upstream("B"), "y", b"{}")
        .await
        .is_ok());

    // No match ⇒ NOT_FOUND with the recoverable detail string.
    let e = s
        .invoke(&UpstreamContext::for_upstream("ghost"), "y", b"{}")
        .await
        .unwrap_err();
    assert_eq!(e.code, GrpcStatusCode::NotFound);
    assert!(e.message.contains("NPS-CLIENT-NOT-FOUND"));
    assert!(e.message.contains("NWP-BRIDGE-SERVER-TOOL-NOT-FOUND"));

    // With >1 backend an empty upstream cannot be resolved implicitly.
    let e = s
        .invoke(&UpstreamContext::default(), "y", b"{}")
        .await
        .unwrap_err();
    assert_eq!(e.code, GrpcStatusCode::NotFound);
}

#[tokio::test]
async fn grpc_surfaces_the_exact_nps_fault_in_the_detail_string() {
    let s = grpc(
        vec![failing_backend("NPS-AUTH-FORBIDDEN", "NWP-AUTH-NID-SCOPE-VIOLATION")],
        &["grpc"],
    );
    let e = s
        .invoke(&UpstreamContext::default(), "orders.lookup", b"{}")
        .await
        .unwrap_err();
    // PERMISSION_DENIED, not the coarse INTERNAL, and the detail carries the
    // precise NPS status + NWP code + message.
    assert_eq!(e.code, GrpcStatusCode::PermissionDenied);
    assert_eq!(
        e.message,
        "NPS-AUTH-FORBIDDEN NWP-AUTH-NID-SCOPE-VIOLATION: denied"
    );
}

#[tokio::test]
async fn grpc_invoke_lifts_the_task_id_from_the_payload() {
    let backend: Arc<dyn NwpBackend> = Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(NODE, NwpNodeRole::Action))
            .with_actions(vec![NwpActionDescriptor::new("go")])
            .with_invoke_dispatcher(Arc::new(|_| Ok(json!({ "task_id": "T-9" })))),
    );
    let s = grpc(vec![backend], &["grpc"]);
    let r = s
        .invoke(&UpstreamContext::default(), "go", b"{}")
        .await
        .unwrap();
    assert_eq!(r.task_id, "T-9");
}

// ── backend abstraction ──────────────────────────────────────────────────────

#[tokio::test]
async fn node_role_projection_rules() {
    use NwpNodeRole::*;
    assert_eq!(NwpNodeRole::parse("MEMORY"), Memory);
    assert_eq!(NwpNodeRole::parse(" complex "), Complex);
    assert_eq!(NwpNodeRole::parse("nonsense"), Unknown);

    let q = |r| NwpNodeDescriptor::new("n", r).is_queryable();
    let i = |r| NwpNodeDescriptor::new("n", r).is_invokable();
    assert!(q(Memory) && q(Complex) && !q(Action) && !q(Anchor) && !q(Unknown));
    assert!(i(Action) && i(Complex) && !i(Memory) && !i(Anchor) && !i(Unknown));
}

#[tokio::test]
async fn non_invokable_backend_exposes_no_actions_and_non_queryable_refuses_queries() {
    let memory: Arc<dyn NwpBackend> = Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new("mem", NwpNodeRole::Memory))
            .with_actions(vec![NwpActionDescriptor::new("nope")])
            .with_query_dispatcher(Arc::new(|_| Ok(json!({ "count": 0, "data": [] })))),
    );
    assert!(memory.actions().await.is_empty());

    let action = action_backend("act", &["x"]);
    let r = action.query(json!({})).await;
    assert!(!r.ok);
    assert_eq!(r.nps_status.as_deref(), Some("NPS-SERVER-UNSUPPORTED"));
    assert_eq!(
        r.nwp_error.as_deref(),
        Some("NWP-BRIDGE-SERVER-TOOL-NOT-FOUND")
    );
}

#[tokio::test]
async fn absent_input_schema_advertises_the_open_object_schema() {
    let s = mcp(vec![action_backend(NODE, &["orders.lookup"])], &["mcp"]);
    let r = s.dispatch(&req("tools/list", json!({}))).await;
    assert_eq!(
        result_of(&r)["tools"][0]["inputSchema"],
        json!({ "type": "object", "additionalProperties": true })
    );
}

#[tokio::test]
async fn a_dispatcher_that_blows_up_maps_to_dispatch_failed() {
    let backend: Arc<dyn NwpBackend> = Arc::new(
        InProcessNwpBackend::new(NwpNodeDescriptor::new(NODE, NwpNodeRole::Action))
            .with_actions(vec![NwpActionDescriptor::new("boom")])
            .with_invoke_dispatcher(Arc::new(|_| Err(BridgeDispatchError::failed("kaboom")))),
    );
    let r = backend.invoke("boom", None, false).await;
    assert!(!r.ok);
    assert_eq!(r.nps_status.as_deref(), Some("NPS-SERVER-INTERNAL"));
    assert_eq!(
        r.nwp_error.as_deref(),
        Some("NWP-BRIDGE-SERVER-DISPATCH-FAILED")
    );
    assert_eq!(r.message.as_deref(), Some("kaboom"));
}

// ── hosting layer (security defaults) ────────────────────────────────────────

fn app(host: BridgeServerOptions) -> BridgeInboundApp {
    let mut o = BridgeInboundOptions::new().with_inbound_protocols(vec!["mcp".into(), "a2a".into()]);
    o.backends = vec![action_backend(NODE, &["orders.lookup"])];
    BridgeInboundApp::new(o, host)
}

fn post(path: &str, body: &Value) -> AnchorRequest {
    AnchorRequest::new("POST", path)
        .with_header(nps_nwp::http_headers::AGENT, "urn:nps:agent:test.example:a1")
        .with_json(body)
}

fn body_json(r: &AnchorResponse) -> Value {
    r.json_value().unwrap_or(Value::Null)
}

#[tokio::test]
async fn auth_is_required_by_default_and_fails_closed_without_a_verifier() {
    let a = app(BridgeServerOptions::default());
    let r = a
        .handle(post("/mcp", &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })))
        .await;
    // A valid NID but no verifier configured ⇒ still denied.
    assert_eq!(r.status, 401);
    assert_eq!(body_json(&r)["error"]["code"], -32600);
    assert!(body_json(&r)["id"].is_null());
}

#[tokio::test]
async fn missing_or_malformed_agent_nid_is_401() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        ..Default::default()
    });

    // Missing header.
    let r = a
        .handle(
            AnchorRequest::new("POST", "/mcp")
                .with_json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })),
        )
        .await;
    assert_eq!(r.status, 401);

    for bad in [
        "not-a-nid",
        "urn:nps:agent:",
        "urn:nps:agent:example.com",
        "urn:nps:agent::id",
        "urn:nps:agent:exa mple:id",
    ] {
        let r = a
            .handle(
                AnchorRequest::new("POST", "/mcp")
                    .with_header(nps_nwp::http_headers::AGENT, bad)
                    .with_json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })),
            )
            .await;
        assert_eq!(r.status, 401, "NID {bad} must be rejected");
    }
}

#[tokio::test]
async fn a_rejecting_verifier_is_401_and_an_accepting_one_dispatches() {
    let calls = Arc::new(AtomicUsize::new(0));
    let c = calls.clone();
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(move |_, _| {
            c.fetch_add(1, Ordering::SeqCst);
            false
        })),
        ..Default::default()
    });
    let r = a
        .handle(post("/mcp", &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })))
        .await;
    assert_eq!(r.status, 401);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|nid, _| nid == "urn:nps:agent:test.example:a1")),
        ..Default::default()
    });
    let r = a
        .handle(post("/mcp", &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(body_json(&r)["result"], json!({}));
}

#[tokio::test]
async fn body_over_the_limit_is_413_with_invalid_request() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        max_request_body_bytes: 32,
        ..Default::default()
    });
    let big = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": { "pad": "x".repeat(200) } });
    let r = a.handle(post("/mcp", &big)).await;
    assert_eq!(r.status, 413);
    assert_eq!(body_json(&r)["error"]["code"], -32600);
}

#[tokio::test]
async fn a_lying_content_length_cannot_bypass_the_cap() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        max_request_body_bytes: 32,
        ..Default::default()
    });
    let big = json!({ "jsonrpc": "2.0", "id": 1, "method": "ping", "params": { "pad": "x".repeat(200) } });
    // Content-Length claims a tiny body; the real bytes still trip the cap.
    let r = a
        .handle(post("/mcp", &big).with_header("content-length", "4"))
        .await;
    assert_eq!(r.status, 413);

    // And a declared-but-oversized length is rejected too.
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        max_request_body_bytes: 4096,
        ..Default::default()
    });
    let r = a
        .handle(
            post("/mcp", &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" }))
                .with_header("content-length", "999999"),
        )
        .await;
    assert_eq!(r.status, 413);
}

#[tokio::test]
async fn method_gating_and_agent_card_exposure() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        ..Default::default()
    });

    // Non-POST on /mcp and /a2a ⇒ 405.
    for p in ["/mcp", "/a2a"] {
        let r = a
            .handle(
                AnchorRequest::new("GET", p)
                    .with_header(nps_nwp::http_headers::AGENT, "urn:nps:agent:test.example:a1"),
            )
            .await;
        assert_eq!(r.status, 405, "{p}");
    }
    // Non-GET on the AgentCard path ⇒ 405.
    let r = a
        .handle(
            AnchorRequest::new("POST", "/.well-known/agent.json")
                .with_header(nps_nwp::http_headers::AGENT, "urn:nps:agent:test.example:a1"),
        )
        .await;
    assert_eq!(r.status, 405);

    // GET ⇒ the AgentCard.
    let r = a
        .handle(
            AnchorRequest::new("GET", "/.well-known/agent.json")
                .with_header(nps_nwp::http_headers::AGENT, "urn:nps:agent:test.example:a1"),
        )
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(
        body_json(&r)["skills"][0]["id"],
        "bridge-inbound-test__orders_lookup"
    );

    // Unknown path ⇒ 404.
    let r = a.handle(AnchorRequest::new("POST", "/nope")).await;
    assert_eq!(r.status, 404);
}

#[tokio::test]
async fn the_sse_path_is_served_by_the_mcp_server() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        ..Default::default()
    });
    let r = a
        .handle(post("/mcp/sse", &json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(body_json(&r)["result"], json!({}));
}

#[tokio::test]
async fn a2a_path_dispatches_to_the_a2a_server() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        ..Default::default()
    });
    let r = a
        .handle(post(
            "/a2a",
            &json!({
                "jsonrpc": "2.0", "id": 1, "method": "tasks/send",
                "params": { "id": "t-1", "message": { "role": "user", "parts": [] } },
            }),
        ))
        .await;
    assert_eq!(r.status, 200);
    assert_eq!(body_json(&r)["result"]["status"]["state"], "completed");
}

/// A backend whose `invoke` genuinely awaits, so the dispatch timeout can
/// preempt it. (An `InProcessNwpBackend` dispatcher is a synchronous closure
/// and therefore never yields — see the note on `BridgeServerOptions`.)
struct SlowBackend;

impl NwpBackend for SlowBackend {
    fn descriptor(&self) -> nps_nwp::bridge_inbound::backend::BackendFuture<'_, NwpNodeDescriptor> {
        Box::pin(async { NwpNodeDescriptor::new(NODE, NwpNodeRole::Action) })
    }
    fn manifest(&self) -> nps_nwp::bridge_inbound::backend::BackendFuture<'_, nps_nwp::bridge_inbound::NwpResult> {
        Box::pin(async { nps_nwp::bridge_inbound::NwpResult::success(json!({})) })
    }
    fn actions(&self) -> nps_nwp::bridge_inbound::backend::BackendFuture<'_, Vec<NwpActionDescriptor>> {
        Box::pin(async { vec![NwpActionDescriptor::new("slow")] })
    }
    fn query(&self, _q: Value) -> nps_nwp::bridge_inbound::backend::BackendFuture<'_, nps_nwp::bridge_inbound::NwpResult> {
        Box::pin(async { nps_nwp::bridge_inbound::NwpResult::success(json!({})) })
    }
    fn invoke<'a>(
        &'a self,
        _action_id: &'a str,
        _arguments: Option<Value>,
        _is_async: bool,
    ) -> nps_nwp::bridge_inbound::backend::BackendFuture<'a, nps_nwp::bridge_inbound::NwpResult> {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            nps_nwp::bridge_inbound::NwpResult::success(json!({}))
        })
    }
}

#[tokio::test]
async fn a_dispatch_timeout_is_504_with_upstream_error() {
    let mut o = BridgeInboundOptions::new();
    o.backends = vec![Arc::new(SlowBackend)];
    let a = BridgeInboundApp::new(
        o,
        BridgeServerOptions {
            verifier: Some(Arc::new(|_, _| true)),
            dispatch_timeout_ms: 5,
            ..Default::default()
        },
    );
    let r = a
        .handle(post(
            "/mcp",
            &json!({
                "jsonrpc": "2.0", "id": 7, "method": "tools/call",
                "params": { "name": "slow" },
            }),
        ))
        .await;
    assert_eq!(r.status, 504);
    assert_eq!(body_json(&r)["error"]["code"], -32000);
}

#[tokio::test]
async fn malformed_json_body_is_a_json_rpc_invalid_params_error() {
    let a = app(BridgeServerOptions {
        verifier: Some(Arc::new(|_, _| true)),
        ..Default::default()
    });
    let mut req = AnchorRequest::new("POST", "/mcp")
        .with_header(nps_nwp::http_headers::AGENT, "urn:nps:agent:test.example:a1");
    req.body = b"{not json".to_vec();
    let r = a.handle(req).await;
    assert_eq!(r.status, 200);
    assert_eq!(body_json(&r)["error"]["code"], -32602);
}

#[tokio::test]
async fn auth_can_be_disabled_for_a_trusted_deployment() {
    let a = app(BridgeServerOptions {
        require_auth: false,
        ..Default::default()
    });
    let r = a
        .handle(
            AnchorRequest::new("POST", "/mcp")
                .with_json(&json!({ "jsonrpc": "2.0", "id": 1, "method": "ping" })),
        )
        .await;
    assert_eq!(r.status, 200);
}
