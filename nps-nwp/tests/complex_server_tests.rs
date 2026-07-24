// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Complex Node server — handler-direct tests, mirroring .NET `ComplexNodeMiddleware`
//! (NPS-2 §11, §13.2). Covers graph expansion, depth clamp, cycle detection, and
//! child-URL SSRF validation. Child fetching is stubbed via a test `ChildFetcher`.

use std::sync::Arc;

use nps_nwp::action_server::{ActionContext, ActionError, ActionExecutionResult, ParsedActionFrame};
use nps_nwp::complex_server::*;
use nps_nwp::memory_server::{
    MemoryNodeError, MemoryNodeQueryResult, MemoryNodeRow, ParsedQueryFrame,
};
use nps_nwp::node_http::NodeRequest;
use serde_json::{json, Map};

const NID: &str = "complex.example.com";
const PREFIX: &str = "/cx";

/// Provider returning one local row plus a trivial action.
struct LocalProvider;

impl ComplexNodeProvider for LocalProvider {
    fn query(
        &self,
        _frame: &ParsedQueryFrame,
        _opt: &ComplexNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError> {
        let mut row: MemoryNodeRow = Map::new();
        row.insert("id".into(), json!("local-1"));
        Ok(MemoryNodeQueryResult {
            rows: vec![row],
            next_cursor: None,
        })
    }

    fn execute(
        &self,
        frame: &ParsedActionFrame,
        _ctx: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        Ok(ActionExecutionResult {
            result: Some(json!({ "did": frame.action_id })),
            anchor_ref: None,
            token_est: 0,
        })
    }
}

/// Stub fetcher that records the depth/trace it was called with and echoes a capsule.
struct StubFetcher;

impl ChildFetcher for StubFetcher {
    fn fetch(
        &self,
        node_url: &str,
        _body: &[u8],
        child_depth: u32,
        trace: &[String],
        _agent: Option<&str>,
        _budget: Option<&str>,
    ) -> ChildOutcome {
        ChildOutcome::Ok(json!({
            "node_url": node_url,
            "child_depth": child_depth,
            "trace": trace,
            "data": [ { "id": "child-1" } ]
        }))
    }
}

fn opts_with_child() -> ComplexNodeOptions {
    let mut o = ComplexNodeOptions::new(NID, PREFIX);
    o.graph
        .push(ComplexGraphRef::new("orders", "https://child.example.com/node"));
    o.graph_max_depth = 3;
    o
}

fn app(opt: ComplexNodeOptions, fetcher: Option<Arc<dyn ChildFetcher>>) -> ComplexNodeApp {
    ComplexNodeApp::new(opt, Arc::new(LocalProvider), fetcher)
}

fn query_req(depth: Option<u32>, trace: Option<&str>) -> NodeRequest {
    let mut r = NodeRequest::new("POST", format!("{PREFIX}/query")).with_json(&json!({}));
    if let Some(d) = depth {
        r = r.with_header("X-NWP-Depth", d.to_string());
    }
    if let Some(t) = trace {
        r = r.with_header("X-NWP-Trace", t);
    }
    r
}

#[tokio::test]
async fn query_local_only_without_depth() {
    let app = app(opts_with_child(), Some(Arc::new(StubFetcher)));
    let resp = app.handle(query_req(None, None)).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["data"][0]["id"], "local-1");
    assert!(v.get("graph").is_none(), "no graph expansion without depth");
    assert_eq!(resp.header("X-NWP-Node-Type").unwrap(), "complex");
}

#[tokio::test]
async fn query_with_depth_expands_graph() {
    let app = app(opts_with_child(), Some(Arc::new(StubFetcher)));
    let resp = app.handle(query_req(Some(2), None)).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    let graph = v["graph"].as_array().unwrap();
    assert_eq!(graph.len(), 1);
    let child = &graph[0];
    assert_eq!(child["rel"], "orders");
    assert_eq!(child["node"], "https://child.example.com/node");
    // child_depth = requested_depth - 1
    assert_eq!(child["data"]["child_depth"], 1);
    // The trace propagated to the child includes this node.
    assert_eq!(child["data"]["trace"][0], NID);
}

#[tokio::test]
async fn depth_over_node_max_is_400() {
    let app = app(opts_with_child(), Some(Arc::new(StubFetcher)));
    let resp = app.handle(query_req(Some(4), None)).await; // node max_depth = 3
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-DEPTH-EXCEEDED");
}

#[tokio::test]
async fn non_integer_depth_is_400() {
    let app = app(opts_with_child(), Some(Arc::new(StubFetcher)));
    let req = NodeRequest::new("POST", format!("{PREFIX}/query"))
        .with_header("X-NWP-Depth", "abc")
        .with_json(&json!({}));
    let resp = app.handle(req).await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-DEPTH-EXCEEDED");
}

#[tokio::test]
async fn cycle_detected_via_trace_header_is_422() {
    let app = app(opts_with_child(), Some(Arc::new(StubFetcher)));
    // Trace already contains this node's id → cycle.
    let resp = app.handle(query_req(Some(1), Some(NID))).await;
    assert_eq!(resp.status, 422);
    let v = resp.json_value().unwrap();
    assert_eq!(v["status"], "NPS-CLIENT-UNPROCESSABLE");
    assert_eq!(v["error"], "NWP-GRAPH-CYCLE");
}

#[tokio::test]
async fn private_child_url_yields_child_error() {
    let mut o = ComplexNodeOptions::new(NID, PREFIX);
    o.graph
        .push(ComplexGraphRef::new("bad", "https://127.0.0.1/node"));
    o.graph_max_depth = 2;
    let app = app(o, Some(Arc::new(StubFetcher)));
    let resp = app.handle(query_req(Some(1), None)).await;
    // The parent query still succeeds; the child entry carries an error.
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    let child = &v["graph"][0];
    assert!(child.get("data").is_none());
    assert!(child["error"]["message"]
        .as_str()
        .unwrap()
        .contains("SSRF"));
}

#[tokio::test]
async fn no_fetcher_yields_child_error() {
    let app = app(opts_with_child(), None);
    let resp = app.handle(query_req(Some(1), None)).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["graph"][0]["error"]["code"], "NWP-NODE-UNAVAILABLE");
}

#[tokio::test]
async fn invoke_delegates_to_provider() {
    let mut o = ComplexNodeOptions::new(NID, PREFIX);
    o.actions.insert(
        "cx.act".into(),
        nps_nwp::action_server::ActionSpec::new(false),
    );
    let app = app(o, None);
    let req = NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_json(&json!({ "action_id": "cx.act" }));
    let resp = app.handle(req).await;
    assert_eq!(resp.status, 200);
    assert_eq!(resp.json_value().unwrap()["data"][0]["did"], "cx.act");
}

#[tokio::test]
async fn invoke_async_rejected() {
    let mut o = ComplexNodeOptions::new(NID, PREFIX);
    o.actions.insert(
        "cx.act".into(),
        nps_nwp::action_server::ActionSpec::new(true),
    );
    let app = app(o, None);
    let req = NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_json(&json!({ "action_id": "cx.act", "async": true }));
    let resp = app.handle(req).await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-ACTION-PARAMS-INVALID");
}

#[tokio::test]
async fn graph_max_depth_over_absolute_cap_panics() {
    let result = std::panic::catch_unwind(|| {
        let mut o = ComplexNodeOptions::new(NID, PREFIX);
        o.graph_max_depth = ABSOLUTE_MAX_DEPTH + 1;
        ComplexNodeApp::new(o, Arc::new(LocalProvider), None)
    });
    assert!(result.is_err());
}

#[test]
fn validate_child_url_unit() {
    let allow: Vec<String> = vec![];
    assert!(validate_child_url("https://ok.example.com/n", &allow, true, false).is_none());
    assert!(validate_child_url("http://ok.example.com/n", &allow, true, false).is_some());
    assert!(validate_child_url("https://10.0.0.1/n", &allow, true, false).is_some());
    // Allowlist enforced.
    let allow2 = vec!["https://trusted.example.com".to_string()];
    assert!(validate_child_url("https://other.example.com/n", &allow2, true, false).is_some());
    assert!(validate_child_url("https://trusted.example.com/n", &allow2, true, false).is_none());
    // http permitted when allow_http = true.
    assert!(validate_child_url("http://ok.example.com/n", &allow, true, true).is_none());
}
