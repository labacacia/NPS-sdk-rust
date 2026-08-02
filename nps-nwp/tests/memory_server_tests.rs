// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Memory Node server — handler-direct tests, mirroring .NET `MemoryNodeMiddleware`
//! (NPS-2 §4, §5). SQL providers/translation are out of scope; exercises the bundled
//! in-memory provider's filtering.

use std::sync::Arc;

use nps_nwp::memory_server::*;
use nps_nwp::node_http::NodeRequest;
use serde_json::{json, Map, Value};

const NID: &str = "urn:nps:node:mem.example.com:svc";
const PREFIX: &str = "/mem";

fn schema() -> MemoryNodeSchema {
    MemoryNodeSchema {
        table_name: "orders".into(),
        primary_key: "id".into(),
        fields: vec![
            MemoryNodeField::new("id", "string"),
            MemoryNodeField::new("status", "string"),
            MemoryNodeField::new("amount", "number"),
        ],
    }
}

fn row(id: &str, status: &str, amount: i64) -> MemoryNodeRow {
    let mut m = Map::new();
    m.insert("id".into(), json!(id));
    m.insert("status".into(), json!(status));
    m.insert("amount".into(), json!(amount));
    m
}

fn app() -> MemoryNodeApp {
    let rows = vec![
        row("1", "open", 10),
        row("2", "closed", 20),
        row("3", "open", 30),
    ];
    let opt = MemoryNodeOptions::new(NID, PREFIX, schema());
    MemoryNodeApp::new(opt, Arc::new(InMemoryMemoryNodeProvider::new(rows)))
}

fn query(body: Value) -> NodeRequest {
    NodeRequest::new("POST", format!("{PREFIX}/query")).with_json(&body)
}

#[tokio::test]
async fn nwm_advertises_query_and_stream() {
    let resp = app()
        .handle(NodeRequest::new("GET", format!("{PREFIX}/.nwm")))
        .await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["node_type"], "memory");
    assert_eq!(v["capabilities"]["query"], true);
    assert_eq!(v["capabilities"]["stream"], true);
}

#[tokio::test]
async fn schema_route_returns_anchor_header() {
    let app = app();
    let resp = app
        .handle(NodeRequest::new("GET", format!("{PREFIX}/.schema")))
        .await;
    assert_eq!(resp.status, 200);
    let anchor = resp.header("X-NWP-Schema").unwrap();
    assert!(anchor.starts_with("sha256:"));
    assert_eq!(anchor, app.anchor_id());
}

#[tokio::test]
async fn query_no_filter_returns_all() {
    let resp = app().handle(query(json!({}))).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 3);
    assert_eq!(resp.header("X-NWP-Node-Type").unwrap(), "memory");
    assert!(resp.header("X-NWP-Tokens").is_some());
}

#[tokio::test]
async fn query_eq_filter() {
    let resp = app()
        .handle(query(json!({ "filter": { "status": "open" } })))
        .await;
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 2);
    for r in v["data"].as_array().unwrap() {
        assert_eq!(r["status"], "open");
    }
}

#[tokio::test]
async fn query_gt_operator() {
    let resp = app()
        .handle(query(json!({ "filter": { "amount": { "$gt": 15 } } })))
        .await;
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 2);
}

#[tokio::test]
async fn query_and_or_combination() {
    let resp = app()
        .handle(query(json!({
            "filter": { "$and": [ { "status": "open" }, { "amount": { "$gte": 30 } } ] }
        })))
        .await;
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["data"][0]["id"], "3");
}

#[tokio::test]
async fn query_projection_selects_fields() {
    let resp = app()
        .handle(query(json!({ "fields": ["id"], "filter": { "id": "1" } })))
        .await;
    let v = resp.json_value().unwrap();
    let row = &v["data"][0];
    assert_eq!(row["id"], "1");
    assert!(row.get("status").is_none());
}

#[tokio::test]
async fn query_unknown_field_is_400() {
    let resp = app().handle(query(json!({ "fields": ["nope"] }))).await;
    assert_eq!(resp.status, 400);
    let v = resp.json_value().unwrap();
    assert_eq!(v["error"], "NWP-QUERY-FIELD-UNKNOWN");
}

#[tokio::test]
async fn query_unsupported_operator_is_400() {
    let resp = app()
        .handle(query(json!({ "filter": { "amount": { "$mod": 2 } } })))
        .await;
    assert_eq!(resp.status, 400);
    assert_eq!(
        resp.json_value().unwrap()["error"],
        "NWP-QUERY-FILTER-INVALID"
    );
}

#[tokio::test]
async fn query_limit_clamped_to_max() {
    let mut opt = MemoryNodeOptions::new(NID, PREFIX, schema());
    opt.max_limit = 1;
    let app = MemoryNodeApp::new(
        opt,
        Arc::new(InMemoryMemoryNodeProvider::new(vec![
            row("1", "open", 10),
            row("2", "open", 20),
        ])),
    );
    let resp = app.handle(query(json!({ "limit": 999 }))).await;
    assert_eq!(resp.json_value().unwrap()["count"], 1);
}

#[tokio::test]
async fn stream_emits_ndjson_chunks() {
    let resp = app()
        .handle(NodeRequest::new("POST", format!("{PREFIX}/stream")).with_json(&json!({})))
        .await;
    assert_eq!(resp.status, 200);
    let lines = resp.ndjson_lines();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["seq"], 0);
    assert_eq!(lines[0]["is_last"], false);
    assert_eq!(lines[1]["is_last"], true);
}

#[tokio::test]
async fn get_on_query_is_405() {
    let resp = app()
        .handle(NodeRequest::new("GET", format!("{PREFIX}/query")))
        .await;
    assert_eq!(resp.status, 405);
}

#[tokio::test]
async fn missing_agent_when_auth_required_is_401() {
    let mut opt = MemoryNodeOptions::new(NID, PREFIX, schema());
    opt.require_auth = true;
    let app = MemoryNodeApp::new(opt, Arc::new(InMemoryMemoryNodeProvider::new(vec![])));
    let resp = app.handle(query(json!({}))).await;
    assert_eq!(resp.status, 401);
    assert_eq!(
        resp.json_value().unwrap()["status"],
        "NPS-CLIENT-UNAUTHORIZED"
    );
}
