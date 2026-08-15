// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nwp::action_server::{
    ActionContext, ActionError, ActionExecutionResult, ActionNodeApp, ActionNodeOptions,
    ActionNodeProvider, ParsedActionFrame,
};
use nps_nwp::node_http::{NodeRequest, NodeResponse};
use nps_nwp::*;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const NODE: &str = "urn:nps:node:llm.example:willow";
const PREFIX: &str = "/llm";
const ALICE: &str = "urn:nps:agent:labacacia:alice";
const BOB: &str = "urn:nps:agent:labacacia:bob";

#[derive(Clone, Copy)]
enum ProviderMode {
    Success,
    Failure,
    ModelError,
    StreamSuccess,
    StreamAbnormal,
    BlockIgnoringCancellation,
}

struct TestLlmProvider {
    calls: AtomicUsize,
    mode: Mutex<ProviderMode>,
    started: AtomicBool,
    release: AtomicBool,
}

impl TestLlmProvider {
    fn new(mode: ProviderMode) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            mode: Mutex::new(mode),
            started: AtomicBool::new(false),
            release: AtomicBool::new(false),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ActionNodeProvider for TestLlmProvider {
    fn execute(
        &self,
        frame: &ParsedActionFrame,
        context: &ActionContext,
    ) -> Result<ActionExecutionResult, ActionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(frame.action_id, LLM_COMPLETE);
        let mode = *self.mode.lock().expect("provider mode");
        match mode {
            ProviderMode::Failure => Err(ActionError::internal("provider failed")),
            ProviderMode::ModelError => Ok(ActionExecutionResult {
                result: Some(json!({
                    "stop_reason": "error",
                    "error": "model unavailable",
                    "context": {
                        "context_id": "AQIDBAUGBwgJCgsMDQ4PEA",
                        "version": 99,
                        "operation": "create",
                        "state": "active"
                    }
                })),
                stream: None,
                anchor_ref: None,
                token_est: 0,
            }),
            ProviderMode::BlockIgnoringCancellation => {
                self.started.store(true, Ordering::Release);
                while !self.release.load(Ordering::Acquire) {
                    std::thread::sleep(Duration::from_millis(2));
                }
                Ok(ActionExecutionResult {
                    result: Some(json!({
                        "stop_reason": "end_turn",
                        "content": "too late"
                    })),
                    stream: None,
                    anchor_ref: None,
                    token_est: 0,
                })
            }
            ProviderMode::StreamSuccess | ProviderMode::StreamAbnormal => {
                let abnormal = matches!(mode, ProviderMode::StreamAbnormal);
                let stream =
                    Arc::new(
                        move |_cancellation: &ActionCancellation,
                              emit: &mut dyn FnMut(
                            ActionStreamFrame,
                        )
                            -> Result<(), ActionError>| {
                            emit(ActionStreamFrame {
                                seq: 0,
                                data: vec![json!({ "content_delta": "Fir" })],
                                ..Default::default()
                            })?;
                            if abnormal {
                                return Ok(());
                            }
                            emit(ActionStreamFrame {
                                seq: 1,
                                is_last: true,
                                anchor_ref: Some(LLM_COMPLETE_STREAM_ANCHOR.into()),
                                data: vec![json!({
                                    "content_delta": "st",
                                    "stop_reason": "end_turn",
                                    "usage": { "output_tokens": 1 }
                                })],
                                ..Default::default()
                            })
                        },
                    );
                Ok(ActionExecutionResult {
                    result: None,
                    stream: Some(stream),
                    anchor_ref: Some(LLM_COMPLETE_STREAM_ANCHOR.into()),
                    token_est: 1,
                })
            }
            ProviderMode::Success => Ok(ActionExecutionResult {
                result: Some(json!({
                    "stop_reason": "end_turn",
                    "content": "First",
                    "usage": {
                        "input_tokens": 2,
                        "output_tokens": 1,
                        "wire_input_bytes": context.wire_input_bytes
                    }
                })),
                stream: None,
                anchor_ref: None,
                token_est: 1,
            }),
        }
    }
}

struct TestApp {
    app: ActionNodeApp,
    store: Arc<InMemoryLlmContextStore>,
    provider: Arc<TestLlmProvider>,
}

fn test_app(
    mode: ProviderMode,
    configure_store: impl FnOnce(&mut LlmContextStoreOptions),
    configure_llm: impl FnOnce(&mut StatefulLlmActionOptions),
) -> TestApp {
    let mut store_options = LlmContextStoreOptions::default();
    configure_store(&mut store_options);
    let store = Arc::new(InMemoryLlmContextStore::new(store_options));
    let provider = Arc::new(TestLlmProvider::new(mode));
    let mut llm_options = StatefulLlmActionOptions::new("workspace-a", "runtime-1");
    llm_options.provider_name = Some("willow".into());
    llm_options.default_model = Some("willow-small".into());
    llm_options.authorizer = Some(Arc::new(|_, _, _, _, _| Ok(())));
    configure_llm(&mut llm_options);
    let coordinator = Arc::new(StatefulLlmActionProvider::new(
        provider.clone(),
        store.clone(),
        llm_options,
    ));
    let mut node_options = ActionNodeOptions::new(NODE, PREFIX);
    coordinator.configure_node(&mut node_options);
    TestApp {
        app: ActionNodeApp::with_in_memory(node_options, coordinator),
        store,
        provider,
    }
}

fn create_params() -> Value {
    json!({
        "kind": "llm.complete",
        "model": "willow-small",
        "stream": false,
        "messages": [
            { "role": "system", "content": "Be concise." },
            { "role": "user", "content": "One" }
        ],
        "context": { "operation": "create", "ttl_seconds": 600 }
    })
}

fn invoke(agent: Option<&str>, action: &str, params: Value, key: Option<&str>) -> NodeRequest {
    let mut frame = json!({ "action_id": action, "params": params });
    if let Some(key) = key {
        frame["idempotency_key"] = Value::String(key.into());
    }
    let mut request = NodeRequest::new("POST", format!("{PREFIX}/invoke")).with_json(&frame);
    if let Some(agent) = agent {
        request = request.with_header("X-NWP-Agent", agent);
    }
    request
}

async fn run(app: &ActionNodeApp, request: NodeRequest) -> NodeResponse {
    app.handle(request).await
}

fn data(response: &NodeResponse) -> Value {
    response.json_value().unwrap()["data"][0].clone()
}

#[tokio::test]
async fn nwm_advertises_exact_actions_and_process_limits() {
    let test = test_app(
        ProviderMode::Success,
        |options| {
            options.max_contexts_per_principal = 7;
            options.max_ttl_seconds = 900;
            options.tombstone_seconds = 120;
            options.supported_operations = Some(HashSet::from([
                LlmContextOperation::Create,
                LlmContextOperation::Append,
                LlmContextOperation::Reset,
                LlmContextOperation::Release,
            ]));
        },
        |options| options.supports_stream = true,
    );
    let response = run(&test.app, NodeRequest::new("GET", format!("{PREFIX}/.nwm"))).await;
    assert_eq!(response.status, 200);
    let manifest = response.json_value().unwrap();
    assert_eq!(
        manifest["actions"][LLM_CONTEXT_STATUS]["required_capability"],
        CAPABILITY_LLM_CONTEXT
    );
    assert_eq!(
        manifest["actions"][LLM_CONTEXT_RELEASE]["required_capability"],
        CAPABILITY_LLM_CONTEXT
    );
    let profile = &manifest["profiles"]["llm"];
    assert_eq!(profile["profile_version"], "0.2");
    assert_eq!(profile["provider"], "willow");
    assert_eq!(profile["supports_stream"], true);
    assert_eq!(manifest["capabilities"]["stream"], true);
    assert_eq!(profile["context"]["persistence"], "process");
    assert_eq!(profile["context"]["max_contexts_per_principal"], 7);
    assert_eq!(profile["context"]["max_ttl_seconds"], 900);
    assert_eq!(profile["context"]["tombstone_seconds"], 120);
    assert_eq!(
        profile["context"]["operations"],
        json!(["create", "append", "reset", "release"])
    );
}

#[tokio::test]
async fn stateful_stream_commits_at_terminal_and_replays_under_a_fresh_id() {
    let test = test_app(
        ProviderMode::StreamSuccess,
        |_| {},
        |options| options.supports_stream = true,
    );
    let mut params = create_params();
    params["stream"] = json!(true);
    let first = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            params.clone(),
            Some("stream-success"),
        ),
    )
    .await;
    assert_eq!(first.status, 200);
    assert_eq!(first.header("content-type"), Some("application/x-ndjson"));
    let first_frames = first.ndjson_lines();
    assert_eq!(first_frames.len(), 2);
    assert_eq!(first_frames[0]["seq"], 0);
    assert_eq!(first_frames[1]["seq"], 1);
    assert_eq!(first_frames[1]["is_last"], true);
    assert_eq!(first_frames[0]["stream_id"], first_frames[1]["stream_id"]);
    assert!(first_frames[0]["data"][0].get("context").is_none());
    let receipt = first_frames[1]["data"][0]["context"].clone();
    assert_eq!(receipt["version"], 1);

    let replay = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, params, Some("stream-success")),
    )
    .await;
    let replay_frames = replay.ndjson_lines();
    assert_eq!(replay_frames.len(), 2);
    assert_ne!(first_frames[0]["stream_id"], replay_frames[0]["stream_id"]);
    assert_eq!(replay_frames[1]["data"][0]["context"], receipt);
    assert_eq!(test.provider.calls(), 1);

    let context_id = receipt["context_id"].as_str().unwrap();
    let status = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_CONTEXT_STATUS,
            json!({ "context_id": context_id }),
            None,
        ),
    )
    .await;
    assert_eq!(data(&status)["state"], "active");
    assert_eq!(data(&status)["version"], 1);
}

#[tokio::test]
async fn stateful_stream_without_terminal_aborts_and_is_not_cached() {
    let test = test_app(
        ProviderMode::StreamAbnormal,
        |_| {},
        |options| options.supports_stream = true,
    );
    let mut params = create_params();
    params["stream"] = json!(true);
    let response = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, params, Some("stream-abnormal")),
    )
    .await;
    let frames = response.ndjson_lines();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[1]["is_last"], true);
    assert_eq!(frames[1]["error_code"], error_codes::NODE_UNAVAILABLE);
    let status = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_CONTEXT_STATUS,
            json!({ "idempotency_key": "stream-abnormal" }),
            None,
        ),
    )
    .await;
    assert_eq!(data(&status)["state"], "failed");
}

#[tokio::test]
async fn synchronous_create_commits_and_status_recovers_it() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let response = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("create-1")),
    )
    .await;
    assert_eq!(response.status, 200);
    assert_eq!(
        response.header("X-NWP-Schema"),
        Some(LLM_COMPLETE_RESPONSE_ANCHOR)
    );
    let completion = data(&response);
    let receipt = &completion["context"];
    assert_eq!(receipt["version"], 1);
    assert_eq!(receipt["operation"], "create");
    assert_eq!(receipt["state"], "active");
    assert!(completion["usage"]["wire_input_bytes"].as_u64().unwrap() > 0);

    let context_id = receipt["context_id"].as_str().unwrap();
    let status = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_CONTEXT_STATUS,
            json!({ "context_id": context_id }),
            None,
        ),
    )
    .await;
    assert_eq!(status.status, 200);
    assert_eq!(
        status.header("X-NWP-Schema"),
        Some(LLM_CONTEXT_STATUS_RESPONSE_ANCHOR)
    );
    assert_eq!(data(&status)["state"], "active");
    assert_eq!(data(&status)["version"], 1);
    assert_eq!(test.provider.calls(), 1);
}

#[tokio::test]
async fn reconnect_concurrent_append_and_process_restart_follow_contract() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let provider = test.provider.clone();
    let app = Arc::new(test.app);

    // Treat the create response as lost and recover it by idempotency key.
    assert_eq!(
        run(
            app.as_ref(),
            invoke(
                Some(ALICE),
                LLM_COMPLETE,
                create_params(),
                Some("lost-create")
            ),
        )
        .await
        .status,
        200
    );
    let recovered = data(
        &run(
            app.as_ref(),
            invoke(
                Some(ALICE),
                LLM_CONTEXT_STATUS,
                json!({ "idempotency_key": "lost-create" }),
                None,
            ),
        )
        .await,
    );
    assert_eq!(recovered["state"], "active");
    assert_eq!(recovered["version"], 1);
    let context_id = recovered["context_id"].as_str().unwrap().to_owned();
    let append = json!({
        "kind": "llm.complete",
        "model": "willow-small",
        "messages": [{ "role": "user", "content": "Two" }],
        "context": {
            "operation": "append",
            "context_id": context_id,
            "base_version": 1
        }
    });
    *provider.mode.lock().unwrap() = ProviderMode::BlockIgnoringCancellation;
    provider.started.store(false, Ordering::Release);
    provider.release.store(false, Ordering::Release);
    let winner_app = app.clone();
    let winner_request = invoke(
        Some(ALICE),
        LLM_COMPLETE,
        append.clone(),
        Some("append-winner"),
    );
    let winner = std::thread::spawn(move || {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run(winner_app.as_ref(), winner_request))
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    while !provider.started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "winner did not enter provider");
        std::thread::sleep(Duration::from_millis(2));
    }
    let loser = run(
        app.as_ref(),
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            append.clone(),
            Some("append-loser"),
        ),
    )
    .await;
    assert_eq!(loser.status, 409);
    assert_eq!(
        loser.json_value().unwrap()["error"],
        error_codes::LLM_CONTEXT_VERSION_CONFLICT
    );
    provider.release.store(true, Ordering::Release);
    let winner = winner.join().unwrap();
    assert_eq!(data(&winner)["context"]["version"], 2);
    assert_eq!(provider.calls(), 2);

    let restarted = test_app(ProviderMode::Success, |_| {}, |_| {});
    let mut after_restart = append;
    after_restart["context"]["base_version"] = json!(2);
    let missing = run(
        &restarted.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            after_restart,
            Some("append-after-restart"),
        ),
    )
    .await;
    assert_eq!(missing.status, 404);
    assert_eq!(
        missing.json_value().unwrap()["error"],
        error_codes::LLM_CONTEXT_NOT_FOUND
    );
    assert_eq!(restarted.provider.calls(), 0);
}

#[tokio::test]
async fn append_commits_delta_and_release_creates_tombstone() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let created = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("create-1")),
    )
    .await;
    let context_id = data(&created)["context"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let append = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            json!({
                "kind": "llm.complete",
                "model": "willow-small",
                "messages": [{ "role": "user", "content": "Two" }],
                "context": {
                    "operation": "append",
                    "context_id": context_id,
                    "base_version": 1
                }
            }),
            Some("append-1"),
        ),
    )
    .await;
    assert_eq!(data(&append)["context"]["version"], 2);
    let snapshot = test.store.snapshot(&owner(ALICE), &context_id).unwrap();
    assert_eq!(snapshot.transcript.len(), 5);

    let released = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_CONTEXT_RELEASE,
            json!({ "context_id": context_id, "base_version": 2 }),
            Some("release-1"),
        ),
    )
    .await;
    assert_eq!(released.status, 200);
    assert_eq!(
        released.header("X-NWP-Schema"),
        Some(LLM_CONTEXT_RELEASE_RESPONSE_ANCHOR)
    );
    assert_eq!(data(&released)["state"], "released");
    assert_eq!(data(&released)["version"], 3);
}

#[tokio::test]
async fn provider_and_model_errors_abort_without_allocating_context() {
    for (mode, key, expected_status) in [
        (ProviderMode::Failure, "provider-failure", 500),
        (ProviderMode::ModelError, "model-error", 200),
    ] {
        let test = test_app(mode, |_| {}, |_| {});
        let response = run(
            &test.app,
            invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some(key)),
        )
        .await;
        assert_eq!(response.status, expected_status);
        if mode_matches_model_error(mode) {
            assert!(data(&response).get("context").is_none());
        }
        let status = run(
            &test.app,
            invoke(
                Some(ALICE),
                LLM_CONTEXT_STATUS,
                json!({ "idempotency_key": key }),
                None,
            ),
        )
        .await;
        assert_eq!(data(&status)["state"], "failed");
        assert!(data(&status).get("context_id").is_none());
    }
}

#[tokio::test]
async fn commit_reauthorization_failure_aborts_and_surfaces_auth_error() {
    let test = test_app(
        ProviderMode::Success,
        |_| {},
        |options| {
            options.authorizer = Some(Arc::new(|_, _, stage, _, _| {
                if stage == LlmAuthorizationStage::Commit {
                    Err(ActionError {
                        http_status: 401,
                        nps_status: nps_core::status_codes::NPS_AUTH_UNAUTHENTICATED.into(),
                        error_code: error_codes::AUTH_NID_REVOKED.into(),
                        message: "revoked before commit".into(),
                    })
                } else {
                    Ok(())
                }
            }));
        },
    );
    let response = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("revoked")),
    )
    .await;
    assert_eq!(response.status, 401);
    assert_eq!(
        response.json_value().unwrap()["error"],
        error_codes::AUTH_NID_REVOKED
    );
    let status = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_CONTEXT_STATUS,
            json!({ "idempotency_key": "revoked" }),
            None,
        ),
    )
    .await;
    assert_eq!(data(&status)["state"], "failed");
    assert_eq!(data(&status)["error_code"], error_codes::AUTH_NID_REVOKED);
}

#[tokio::test]
async fn async_completion_puts_receipt_only_in_terminal_task_result() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let request = NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_header("X-NWP-Agent", ALICE)
        .with_json(&json!({
            "action_id": LLM_COMPLETE,
            "params": create_params(),
            "idempotency_key": "async-create",
            "async": true
        }));
    let accepted = run(&test.app, request).await;
    assert_eq!(accepted.status, 202);
    assert!(accepted.json_value().unwrap().get("context").is_none());
    let task_id = accepted.json_value().unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(1);
    let task = loop {
        let polled = run(
            &test.app,
            invoke(
                Some(ALICE),
                SYSTEM_TASK_STATUS,
                json!({ "task_id": task_id }),
                None,
            ),
        )
        .await;
        let task = data(&polled);
        if task["status"] == "completed" {
            break task;
        }
        assert!(Instant::now() < deadline, "async completion did not finish");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(task["status"], "completed");
    assert_eq!(task["result"]["context"]["version"], 1);
}

#[tokio::test]
async fn cancellation_aborts_before_provider_that_ignores_signal_returns() {
    let test = test_app(ProviderMode::BlockIgnoringCancellation, |_| {}, |_| {});
    let request = NodeRequest::new("POST", format!("{PREFIX}/invoke"))
        .with_header("X-NWP-Agent", ALICE)
        .with_json(&json!({
            "action_id": LLM_COMPLETE,
            "params": create_params(),
            "idempotency_key": "cancel-create",
            "async": true
        }));
    let accepted = run(&test.app, request).await;
    assert_eq!(accepted.status, 202);
    let task_id = accepted.json_value().unwrap()["task_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let deadline = Instant::now() + Duration::from_secs(1);
    while !test.provider.started.load(Ordering::Acquire) {
        assert!(Instant::now() < deadline, "provider did not start");
        std::thread::sleep(Duration::from_millis(2));
    }

    let bob = run(
        &test.app,
        invoke(
            Some(BOB),
            SYSTEM_TASK_STATUS,
            json!({ "task_id": task_id }),
            None,
        ),
    )
    .await;
    assert_eq!(bob.status, 403);
    let cancelled = run(
        &test.app,
        invoke(
            Some(ALICE),
            SYSTEM_TASK_CANCEL,
            json!({ "task_id": task_id }),
            None,
        ),
    )
    .await;
    assert_eq!(cancelled.status, 200);

    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        let status = run(
            &test.app,
            invoke(
                Some(ALICE),
                LLM_CONTEXT_STATUS,
                json!({ "idempotency_key": "cancel-create" }),
                None,
            ),
        )
        .await;
        let outcome = data(&status);
        if outcome["state"] == "failed" {
            assert!(outcome["context_id"].is_null());
            break;
        }
        assert!(Instant::now() < deadline, "reservation did not abort");
        std::thread::sleep(Duration::from_millis(5));
    }
    test.provider.release.store(true, Ordering::Release);
}

#[tokio::test]
async fn response_idempotency_is_owner_scoped_and_does_not_recommit() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let alice_first = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            create_params(),
            Some("shared-key"),
        ),
    )
    .await;
    let alice_replay = run(
        &test.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            create_params(),
            Some("shared-key"),
        ),
    )
    .await;
    let bob_first = run(
        &test.app,
        invoke(Some(BOB), LLM_COMPLETE, create_params(), Some("shared-key")),
    )
    .await;
    let alice_id = data(&alice_first)["context"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let replay_id = data(&alice_replay)["context"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let bob_id = data(&bob_first)["context"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(alice_id, replay_id);
    assert_ne!(alice_id, bob_id);
    assert_eq!(test.provider.calls(), 2);
    assert_eq!(
        test.store
            .snapshot(&owner(ALICE), &alice_id)
            .unwrap()
            .version,
        1
    );
}

#[tokio::test]
async fn cached_replay_rechecks_authorization_before_returning_result() {
    let admitted = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let check = Arc::clone(&admitted);
    let test = test_app(
        ProviderMode::Success,
        |_| {},
        move |options| {
            options.authorizer = Some(Arc::new(move |_, _, stage, _, _| {
                if stage == LlmAuthorizationStage::Admission && !check.load(Ordering::SeqCst) {
                    Err(ActionError {
                        http_status: 401,
                        nps_status: nps_core::status_codes::NPS_AUTH_UNAUTHENTICATED.into(),
                        error_code: error_codes::AUTH_NID_REVOKED.into(),
                        message: "caller was revoked".into(),
                    })
                } else {
                    Ok(())
                }
            }));
        },
    );
    let first = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("cached")),
    )
    .await;
    assert_eq!(first.status, 200);
    admitted.store(false, Ordering::SeqCst);
    let replay = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("cached")),
    )
    .await;
    assert_eq!(replay.status, 401);
    assert_eq!(
        replay.json_value().unwrap()["error"],
        error_codes::AUTH_NID_REVOKED
    );
    assert_eq!(test.provider.calls(), 1);
}

#[tokio::test]
async fn authorization_receives_exact_capabilities_and_fails_closed_when_missing() {
    let checks = Arc::new(Mutex::new(Vec::<Vec<String>>::new()));
    let capture = Arc::clone(&checks);
    let test = test_app(
        ProviderMode::Success,
        |_| {},
        move |options| {
            options.authorizer = Some(Arc::new(move |_, _, _, required, _| {
                capture.lock().unwrap().push(required.to_vec());
                Ok(())
            }));
        },
    );
    assert_eq!(
        run(
            &test.app,
            invoke(
                Some(ALICE),
                LLM_COMPLETE,
                create_params(),
                Some("capabilities")
            ),
        )
        .await
        .status,
        200
    );
    assert_eq!(
        run(
            &test.app,
            invoke(
                Some(ALICE),
                LLM_CONTEXT_STATUS,
                json!({"idempotency_key": "capabilities"}),
                None,
            ),
        )
        .await
        .status,
        200
    );
    let mut extended = create_params();
    extended["stream"] = json!(true);
    extended["tools"] = json!([{"name": "lookup"}]);
    assert_eq!(
        run(
            &test.app,
            invoke(
                Some(ALICE),
                LLM_COMPLETE,
                extended,
                Some("extended-capabilities"),
            ),
        )
        .await
        .status,
        422
    );
    assert_eq!(
        *checks.lock().unwrap(),
        vec![
            vec![String::from("llm:complete"), String::from("llm:context")],
            vec![String::from("llm:complete"), String::from("llm:context")],
            vec![String::from("llm:context")],
            vec![
                String::from("llm:complete"),
                String::from("llm:context"),
                String::from("llm:stream"),
                String::from("llm:tool_call"),
            ],
        ]
    );

    let denied = test_app(
        ProviderMode::Success,
        |_| {},
        |options| options.authorizer = None,
    );
    let response = run(
        &denied.app,
        invoke(
            Some(ALICE),
            LLM_COMPLETE,
            create_params(),
            Some("no-authorizer"),
        ),
    )
    .await;
    assert_eq!(response.status, 403);
    assert_eq!(
        response.json_value().unwrap()["error"],
        error_codes::LLM_CONTEXT_FORBIDDEN
    );
    assert_eq!(denied.provider.calls(), 0);
}

#[tokio::test]
async fn malformed_stateful_requests_fail_before_provider_dispatch() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    for (params, key) in [
        (create_params(), None),
        (
            json!({
                "kind": "wrong.kind",
                "model": "willow-small",
                "messages": [{ "role": "user", "content": "One" }],
                "context": { "operation": "create" }
            }),
            Some("wrong-kind"),
        ),
        (
            json!({
                "kind": "llm.complete",
                "model": "willow-small",
                "messages": [{ "role": "user", "content": "One" }],
                "tools": [{ "name": "lookup" }],
                "context": { "operation": "create" }
            }),
            Some("tools-not-advertised"),
        ),
        (
            json!({
                "kind": "llm.complete",
                "model": "willow-small",
                "stream": true,
                "messages": [{ "role": "user", "content": "One" }],
                "context": { "operation": "create" }
            }),
            Some("stream-not-advertised"),
        ),
        (
            json!({
                "kind": "llm.complete",
                "model": "willow-small",
                "messages": [{ "role": "user", "content": "One" }],
                "context": { "operation": "reset" }
            }),
            Some("reset-without-version"),
        ),
    ] {
        let response = run(&test.app, invoke(Some(ALICE), LLM_COMPLETE, params, key)).await;
        assert_eq!(response.status, 422);
        assert_eq!(
            response.json_value().unwrap()["error"],
            error_codes::ACTION_PARAMS_INVALID
        );
    }
    assert_eq!(test.provider.calls(), 0);
}

#[tokio::test]
async fn lifecycle_actions_require_authentication_and_owner() {
    let test = test_app(ProviderMode::Success, |_| {}, |_| {});
    let unauthenticated = run(
        &test.app,
        invoke(
            None,
            LLM_CONTEXT_STATUS,
            json!({ "context_id": "AQIDBAUGBwgJCgsMDQ4PEA" }),
            None,
        ),
    )
    .await;
    assert_eq!(unauthenticated.status, 401);

    let created = run(
        &test.app,
        invoke(Some(ALICE), LLM_COMPLETE, create_params(), Some("create-1")),
    )
    .await;
    let context_id = data(&created)["context"]["context_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let forbidden = run(
        &test.app,
        invoke(
            Some(BOB),
            LLM_CONTEXT_STATUS,
            json!({ "context_id": context_id }),
            None,
        ),
    )
    .await;
    assert_eq!(forbidden.status, 403);
    assert_eq!(
        forbidden.json_value().unwrap()["error"],
        error_codes::LLM_CONTEXT_FORBIDDEN
    );
}

fn owner(nid: &str) -> LlmContextOwner {
    LlmContextOwner {
        nid: nid.into(),
        security_scope: "workspace-a".into(),
    }
}

fn mode_matches_model_error(mode: ProviderMode) -> bool {
    matches!(mode, ProviderMode::ModelError)
}
