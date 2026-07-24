// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Action Node server — handler-direct request→response tests, mirroring the .NET
//! `ActionNodeMiddleware` wire contract (NPS-2 §3.2, §7).

use std::sync::Arc;

use nps_nwp::action_server::*;
use nps_nwp::node_http::{NodeRequest, NodeResponse};
use serde_json::{json, Value};

const NID: &str = "urn:nps:node:action.example.com:svc";
const AGENT: &str = "urn:nps:agent:tester";
const PREFIX: &str = "/act";

/// Echoing provider: returns `{ echoed: params }` and records the last frame it saw.
struct EchoProvider;

impl ActionNodeProvider for EchoProvider {
    fn execute(
        &self,
        frame: &ParsedActionFrame,
        _ctx: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        if frame.action_id == "orders.fail" {
            return Err(ActionError::internal("boom"));
        }
        Ok(ActionExecutionResult {
            result: Some(json!({ "echoed": frame.params.clone().unwrap_or(Value::Null) })),
            anchor_ref: None,
            token_est: 0,
        })
    }
}

fn base_opts() -> ActionNodeOptions {
    let mut o = ActionNodeOptions::new(NID, PREFIX);
    o.actions.insert(
        "orders.create".into(),
        ActionSpec {
            result_anchor: Some("nps:orders:result".into()),
            timeout_ms_default: Some(1000),
            timeout_ms_max: Some(5000),
            ..Default::default()
        },
    );
    o.actions.insert(
        "orders.async".into(),
        ActionSpec {
            async_: true,
            result_anchor: Some("nps:orders:result".into()),
            ..Default::default()
        },
    );
    o.actions.insert("orders.fail".into(), ActionSpec::new(false));
    o
}

fn app() -> ActionNodeApp {
    ActionNodeApp::with_in_memory(base_opts(), Arc::new(EchoProvider))
}

fn invoke(body: Value) -> NodeRequest {
    NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_header("X-NWP-Agent", AGENT)
        .with_json(&body)
}

async fn run(app: &ActionNodeApp, req: NodeRequest) -> NodeResponse {
    app.handle(req).await
}

// ── Manifest / schema routes ────────────────────────────────────────────────────

#[tokio::test]
async fn nwm_route_returns_manifest() {
    let resp = run(&app(), NodeRequest::new("GET", format!("{PREFIX}/.nwm"))).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["node_type"], "action");
    assert_eq!(v["nwp"], "0.4");
    assert_eq!(resp.header("X-NWP-Node-Type").unwrap(), "action");
}

#[tokio::test]
async fn actions_route_lists_registry() {
    let resp = run(&app(), NodeRequest::new("GET", format!("{PREFIX}/actions"))).await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert!(v["actions"]["orders.create"].is_object());
}

#[tokio::test]
async fn unknown_path_is_404() {
    let resp = run(&app(), NodeRequest::new("GET", format!("{PREFIX}/nope"))).await;
    assert_eq!(resp.status, 404);
}

// ── Sync invoke ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sync_invoke_returns_capsule() {
    let resp = run(
        &app(),
        invoke(json!({ "action_id": "orders.create", "params": { "sku": "A1" } })),
    )
    .await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    assert_eq!(v["count"], 1);
    assert_eq!(v["anchor_ref"], "nps:orders:result");
    assert_eq!(v["data"][0]["echoed"]["sku"], "A1");
    assert_eq!(resp.header("X-NWP-Node-Type").unwrap(), "action");
    assert_eq!(resp.header("X-NWP-Schema").unwrap(), "nps:orders:result");
}

#[tokio::test]
async fn unknown_action_is_404() {
    let resp = run(&app(), invoke(json!({ "action_id": "does.not.exist" }))).await;
    assert_eq!(resp.status, 404);
    let v = resp.json_value().unwrap();
    assert_eq!(v["status"], "NPS-CLIENT-NOT-FOUND");
    assert_eq!(v["error"], "NWP-ACTION-NOT-FOUND");
}

#[tokio::test]
async fn missing_action_id_is_400() {
    let resp = run(&app(), invoke(json!({ "params": {} }))).await;
    assert_eq!(resp.status, 400);
    let v = resp.json_value().unwrap();
    assert_eq!(v["error"], "NWP-ACTION-PARAMS-INVALID");
}

#[tokio::test]
async fn provider_error_maps_to_status() {
    let resp = run(&app(), invoke(json!({ "action_id": "orders.fail" }))).await;
    assert_eq!(resp.status, 500);
    let v = resp.json_value().unwrap();
    assert_eq!(v["status"], "NPS-SERVER-INTERNAL");
    assert_eq!(v["error"], "NWP-NODE-UNAVAILABLE");
}

#[tokio::test]
async fn get_on_invoke_is_405() {
    let req = NodeRequest::new("GET", format!("{PREFIX}/invoke")).with_header("X-NWP-Agent", AGENT);
    let resp = run(&app(), req).await;
    assert_eq!(resp.status, 405);
}

#[tokio::test]
async fn invalid_priority_is_400() {
    let resp = run(
        &app(),
        invoke(json!({ "action_id": "orders.create", "priority": "urgent" })),
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-ACTION-PARAMS-INVALID");
}

// ── Async invoke + reserved task actions ─────────────────────────────────────────

#[tokio::test]
async fn async_invoke_returns_202_task_handle() {
    let resp = run(
        &app(),
        invoke(json!({ "action_id": "orders.async", "async": true, "params": { "x": 1 } })),
    )
    .await;
    assert_eq!(resp.status, 202);
    let v = resp.json_value().unwrap();
    assert!(v["task_id"].as_str().unwrap().len() > 0);
    assert_eq!(v["poll_url"], format!("{PREFIX}/invoke"));
    assert_eq!(resp.header("X-NWP-Node-Type").unwrap(), "action");
}

#[tokio::test]
async fn async_on_sync_only_action_is_400() {
    let resp = run(
        &app(),
        invoke(json!({ "action_id": "orders.create", "async": true })),
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-ACTION-PARAMS-INVALID");
}

#[tokio::test]
async fn task_status_returns_terminal_state() {
    let app = app();
    // Kick off the async task (reference impl runs it inline → completed).
    let started = run(
        &app,
        invoke(json!({ "action_id": "orders.async", "async": true })),
    )
    .await;
    let task_id = started.json_value().unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = run(
        &app,
        invoke(json!({
            "action_id": "system.task.status",
            "params": { "task_id": task_id }
        })),
    )
    .await;
    assert_eq!(resp.status, 200);
    let v = resp.json_value().unwrap();
    let status = &v["data"][0];
    assert_eq!(status["task_id"], task_id);
    assert_eq!(status["status"], "completed");
}

#[tokio::test]
async fn task_status_unknown_task_is_404() {
    let resp = run(
        &app(),
        invoke(json!({ "action_id": "system.task.status", "params": { "task_id": "nope" } })),
    )
    .await;
    assert_eq!(resp.status, 404);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-TASK-NOT-FOUND");
}

#[tokio::test]
async fn task_cancel_on_terminal_is_409() {
    let app = app();
    let started = run(
        &app,
        invoke(json!({ "action_id": "orders.async", "async": true })),
    )
    .await;
    let task_id = started.json_value().unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_string();

    // Task already completed (inline execution) → cancel must be 409 conflict.
    let resp = run(
        &app,
        invoke(json!({ "action_id": "system.task.cancel", "params": { "task_id": task_id } })),
    )
    .await;
    assert_eq!(resp.status, 409);
    let v = resp.json_value().unwrap();
    assert_eq!(v["status"], "NPS-CLIENT-CONFLICT");
    assert_eq!(v["error"], "NWP-TASK-ALREADY-CANCELLED");
}

#[tokio::test]
async fn reserved_action_registration_panics() {
    let result = std::panic::catch_unwind(|| {
        let mut o = ActionNodeOptions::new(NID, PREFIX);
        o.actions
            .insert(SYSTEM_TASK_STATUS.into(), ActionSpec::new(false));
        ActionNodeApp::with_in_memory(o, Arc::new(EchoProvider))
    });
    assert!(result.is_err());
}

// ── Idempotency ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn idempotent_replay_returns_cached_result() {
    let app = app();
    let body = json!({
        "action_id": "orders.create", "params": { "sku": "A1" }, "idempotency_key": "k1"
    });
    let first = run(&app, invoke(body.clone())).await;
    assert_eq!(first.status, 200);
    let second = run(&app, invoke(body)).await;
    assert_eq!(second.status, 200);
    assert_eq!(first.json_value(), second.json_value());
}

#[tokio::test]
async fn idempotency_conflict_on_param_change_is_409() {
    let app = app();
    run(
        &app,
        invoke(json!({
            "action_id": "orders.create", "params": { "sku": "A1" }, "idempotency_key": "k2"
        })),
    )
    .await;
    let resp = run(
        &app,
        invoke(json!({
            "action_id": "orders.create", "params": { "sku": "DIFFERENT" }, "idempotency_key": "k2"
        })),
    )
    .await;
    assert_eq!(resp.status, 409);
    let v = resp.json_value().unwrap();
    assert_eq!(v["status"], "NPS-CLIENT-CONFLICT");
    assert_eq!(v["error"], "NWP-ACTION-IDEMPOTENCY-CONFLICT");
}

#[tokio::test]
async fn idempotent_async_rehit_returns_same_task() {
    let app = app();
    let body = json!({
        "action_id": "orders.async", "async": true, "params": { "x": 1 }, "idempotency_key": "a1"
    });
    let first = run(&app, invoke(body.clone())).await;
    let first_task = first.json_value().unwrap()["task_id"].as_str().unwrap().to_string();
    let second = run(&app, invoke(body)).await;
    assert_eq!(second.status, 202);
    let second_task = second.json_value().unwrap()["task_id"].as_str().unwrap().to_string();
    assert_eq!(first_task, second_task);
}

// ── Timeout clamp ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn timeout_is_clamped_to_spec_max() {
    // Provider that echoes the effective timeout so we can assert the clamp.
    struct TimeoutProbe;
    impl ActionNodeProvider for TimeoutProbe {
        fn execute(
            &self,
            _frame: &ParsedActionFrame,
            ctx: &ActionContext,
        ) -> Result<ActionExecutionResult, ActionError> {
            Ok(ActionExecutionResult {
                result: Some(json!({ "timeout_ms": ctx.timeout_ms })),
                anchor_ref: None,
                token_est: 0,
            })
        }
    }
    let app = ActionNodeApp::with_in_memory(base_opts(), Arc::new(TimeoutProbe));
    // Request 999999 → clamped to spec.timeout_ms_max = 5000.
    let resp = run(
        &app,
        invoke(json!({ "action_id": "orders.create", "timeout_ms": 999_999 })),
    )
    .await;
    assert_eq!(resp.json_value().unwrap()["data"][0]["timeout_ms"], 5000);

    // Omitted → spec.timeout_ms_default = 1000.
    let resp = run(&app, invoke(json!({ "action_id": "orders.create" }))).await;
    assert_eq!(resp.json_value().unwrap()["data"][0]["timeout_ms"], 1000);
}

// ── Callback SSRF guard ─────────────────────────────────────────────────────────

#[tokio::test]
async fn callback_private_host_rejected() {
    let resp = run(
        &app(),
        invoke(json!({
            "action_id": "orders.create",
            "callback_url": "https://127.0.0.1/hook"
        })),
    )
    .await;
    assert_eq!(resp.status, 400);
    assert_eq!(resp.json_value().unwrap()["error"], "NWP-ACTION-PARAMS-INVALID");
}

#[tokio::test]
async fn callback_http_scheme_rejected() {
    let resp = run(
        &app(),
        invoke(json!({
            "action_id": "orders.create",
            "callback_url": "http://public.example.com/hook"
        })),
    )
    .await;
    assert_eq!(resp.status, 400);
}

#[tokio::test]
async fn callback_public_https_accepted() {
    let resp = run(
        &app(),
        invoke(json!({
            "action_id": "orders.create",
            "callback_url": "https://hooks.example.com/hook"
        })),
    )
    .await;
    assert_eq!(resp.status, 200);
}

#[test]
fn validate_callback_url_unit() {
    assert!(validate_callback_url("https://ok.example.com/x", true).is_none());
    assert!(validate_callback_url("http://ok.example.com/x", true).is_some());
    assert!(validate_callback_url("https://localhost/x", true).is_some());
    assert!(validate_callback_url("https://10.0.0.5/x", true).is_some());
    assert!(validate_callback_url("https://[::1]/x", true).is_some());
    // With SSRF guard off, a private host is allowed (still must be https).
    assert!(validate_callback_url("https://10.0.0.5/x", false).is_none());
}

// ── Auth gate ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn missing_agent_when_auth_required_is_401() {
    let mut o = base_opts();
    o.require_auth = true;
    let app = ActionNodeApp::with_in_memory(o, Arc::new(EchoProvider));
    let req = NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_json(&json!({ "action_id": "orders.create" }));
    let resp = app.handle(req).await;
    assert_eq!(resp.status, 401);
    assert_eq!(resp.json_value().unwrap()["status"], "NPS-CLIENT-UNAUTHORIZED");
}
