// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nwp::*;
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

const ID_1: &str = "AQIDBAUGBwgJCgsMDQ4PEA";
const ID_2: &str = "ERITFBUWFxgZGhscHR4fIA";
const ID_3: &str = "ISIjJCUmJygpKissLS4vMA";

fn repo_file(relative: &str) -> PathBuf {
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = current.join(relative);
        if candidate.is_file() {
            return candidate;
        }
        assert!(
            current.pop(),
            "unable to locate repository file: {relative}"
        );
    }
}

fn shared_fixture() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(repo_file(
            "spec/conformance/nwp/llm_context_vectors.json",
        ))
        .expect("shared fixture file"),
    )
    .expect("shared fixture JSON")
}

fn alice() -> LlmContextOwner {
    LlmContextOwner {
        nid: "urn:nps:agent:labacacia:alice".into(),
        security_scope: "workspace-a".into(),
    }
}

fn bob() -> LlmContextOwner {
    LlmContextOwner {
        nid: "urn:nps:agent:labacacia:bob".into(),
        security_scope: "workspace-a".into(),
    }
}

struct Harness {
    now: Arc<Mutex<OffsetDateTime>>,
    store: InMemoryLlmContextStore,
}

impl Harness {
    fn new(configure: impl FnOnce(&mut LlmContextStoreOptions)) -> Self {
        let now = Arc::new(Mutex::new(
            OffsetDateTime::UNIX_EPOCH + Duration::seconds(2_000_000_000),
        ));
        let ids = Arc::new(Mutex::new(VecDeque::from([
            ID_1.to_owned(),
            ID_2.to_owned(),
            ID_3.to_owned(),
            "MTIzNDU2Nzg5Ojs8PT4_QA".to_owned(),
        ])));
        let mut options = LlmContextStoreOptions::default();
        let clock = Arc::clone(&now);
        options.clock = Arc::new(move || *clock.lock().expect("test clock"));
        options.context_id_factory = Arc::new(move || {
            ids.lock()
                .map_err(|_| test_error("test ID queue poisoned"))?
                .pop_front()
                .ok_or_else(|| test_error("test ID queue exhausted"))
        });
        configure(&mut options);
        Self {
            now,
            store: InMemoryLlmContextStore::new(options),
        }
    }

    fn advance(&self, seconds: i64) {
        let mut now = self.now.lock().expect("test clock");
        *now += Duration::seconds(seconds);
    }

    fn current_time(&self) -> OffsetDateTime {
        *self.now.lock().expect("test clock")
    }

    fn request(
        &self,
        operation: LlmContextOperation,
        key: &str,
        context_id: Option<&str>,
        base_version: Option<u64>,
    ) -> LlmContextMutationRequest {
        let messages = if operation == LlmContextOperation::Create {
            vec![system("Be concise."), user("One")]
        } else {
            vec![user("Continue")]
        };
        LlmContextMutationRequest {
            operation,
            owner: alice(),
            context_id: context_id.map(str::to_owned),
            base_version,
            binding: binding("willow-small", "runtime-1"),
            messages,
            ttl_seconds: None,
            idempotency_key: key.into(),
            request_id: format!("req-{key}"),
        }
    }

    fn create(&self, key: &str, ttl_seconds: Option<u32>) -> LlmContextReceiptDto {
        let mut request = self.request(LlmContextOperation::Create, key, None, None);
        request.ttl_seconds = ttl_seconds;
        let reservation = self.store.reserve(request).expect("reserve create");
        self.store
            .commit(&reservation, assistant("First"))
            .expect("commit create")
    }
}

#[test]
fn shared_fixture_has_exactly_the_implemented_vectors() {
    let fixture = shared_fixture();
    let actual: HashSet<_> = fixture["vectors"]
        .as_array()
        .expect("vectors")
        .iter()
        .map(|vector| vector["id"].as_str().expect("vector id"))
        .collect();
    let expected: HashSet<_> = (1..=19)
        .map(|number| format!("nwp.llm-context.{number:03}"))
        .collect();
    assert_eq!(actual.len(), 19);
    assert_eq!(actual, expected.iter().map(String::as_str).collect());
}

#[test]
fn vector_001_stateless_compatibility() {
    assert_vector("nwp.llm-context.001");
    let request = LlmCompleteActionRequest {
        kind: LLM_COMPLETE.into(),
        model: "willow-small".into(),
        max_tokens: None,
        stream: false,
        messages: vec![user("Hello")],
        tools: None,
        context: None,
    };
    assert!(request.context.is_none());
}

#[test]
fn vector_002_create_commits_at_terminal_success() {
    assert_vector("nwp.llm-context.002");
    let h = Harness::new(|_| {});
    let reservation = h
        .store
        .reserve(h.request(LlmContextOperation::Create, "create-1", None, None))
        .unwrap();
    let busy = h.store.status(&alice(), None, Some("create-1")).unwrap();
    assert_eq!(busy.state, LlmContextState::Busy);
    assert!(busy.context_id.is_none() && busy.version.is_none());
    h.advance(5);
    let receipt = h.store.commit(&reservation, assistant("First")).unwrap();
    assert_eq!((receipt.context_id.as_str(), receipt.version), (ID_1, 1));
    let expected_expiry = (h.current_time() + Duration::hours(1))
        .format(&Rfc3339)
        .unwrap();
    assert_eq!(
        receipt.expires_at.as_deref(),
        Some(expected_expiry.as_str())
    );
}

#[test]
fn vector_003_append_commits_one_version() {
    assert_vector("nwp.llm-context.003");
    let h = Harness::new(|_| {});
    let created = h.create("create-1", None);
    let mut request = h.request(
        LlmContextOperation::Append,
        "append-1",
        Some(&created.context_id),
        Some(1),
    );
    request.messages = vec![user("Two")];
    let reservation = h.store.reserve(request).unwrap();
    let receipt = h.store.commit(&reservation, assistant("Second")).unwrap();
    let snapshot = h.store.snapshot(&alice(), ID_1).unwrap();
    assert_eq!(receipt.version, 2);
    assert_eq!(snapshot.transcript.len(), 5);
    assert_eq!(snapshot.transcript[3].content.as_deref(), Some("Two"));
}

#[test]
fn vector_004_compare_and_swap_rejects_losers() {
    assert_vector("nwp.llm-context.004");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let winner = h
        .store
        .reserve(h.request(LlmContextOperation::Append, "winner", Some(ID_1), Some(1)))
        .unwrap();
    let error = h
        .store
        .reserve(h.request(LlmContextOperation::Append, "loser", Some(ID_1), Some(1)))
        .unwrap_err();
    assert_error(&error, error_codes::LLM_CONTEXT_VERSION_CONFLICT);
    assert_eq!(error.current_version, Some(1));
    h.store.abort(&winner, None).unwrap();
    let stale = h
        .store
        .reserve(h.request(LlmContextOperation::Append, "stale", Some(ID_1), Some(0)))
        .unwrap_err();
    assert_error(&stale, error_codes::LLM_CONTEXT_VERSION_CONFLICT);
}

#[test]
fn vector_005_fork_snapshots_admission_version() {
    assert_vector("nwp.llm-context.005");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let mut fork_request = h.request(LlmContextOperation::Fork, "fork-1", Some(ID_1), Some(1));
    fork_request.messages.clear();
    let fork = h.store.reserve(fork_request).unwrap();
    let parent_append = h
        .store
        .reserve(h.request(
            LlmContextOperation::Append,
            "parent-append",
            Some(ID_1),
            Some(1),
        ))
        .unwrap();
    h.store
        .commit(&parent_append, assistant("Parent moved"))
        .unwrap();
    let child = h.store.commit(&fork, assistant("Branch")).unwrap();
    assert_eq!(child.parent_context_id.as_deref(), Some(ID_1));
    assert_eq!(child.parent_version, Some(1));
    assert_eq!(h.store.snapshot(&alice(), ID_1).unwrap().version, 2);
    assert_eq!(
        h.store.snapshot(&alice(), ID_2).unwrap().transcript.len(),
        4
    );
}

#[test]
fn vector_006_reset_replaces_binding_and_transcript() {
    assert_vector("nwp.llm-context.006");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let mut request = h.request(LlmContextOperation::Reset, "reset-1", Some(ID_1), Some(1));
    request.binding = binding("willow-medium", "runtime-2");
    request.messages = vec![system("Use JSON."), user("Restart")];
    let reservation = h.store.reserve(request).unwrap();
    h.store.commit(&reservation, assistant("{}")).unwrap();
    let snapshot = h.store.snapshot(&alice(), ID_1).unwrap();
    assert_eq!(snapshot.version, 2);
    assert_eq!(snapshot.binding.model, "willow-medium");
    assert_eq!(snapshot.transcript.len(), 3);
}

#[test]
fn vector_007_binding_mismatch_fails_closed() {
    assert_vector("nwp.llm-context.007");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let mut request = h.request(
        LlmContextOperation::Append,
        "bad-binding",
        Some(ID_1),
        Some(1),
    );
    request.binding = binding("willow-large", "runtime-1");
    let error = h.store.reserve(request).unwrap_err();
    assert_error(&error, error_codes::LLM_CONTEXT_BINDING_MISMATCH);
}

#[test]
fn vector_008_context_id_is_not_authorization() {
    assert_vector("nwp.llm-context.008");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let error = h.store.status(&bob(), Some(ID_1), None).unwrap_err();
    assert_error(&error, error_codes::LLM_CONTEXT_FORBIDDEN);
}

#[test]
fn vector_009_abort_preserves_version_and_ttl() {
    assert_vector("nwp.llm-context.009");
    let h = Harness::new(|options| options.default_ttl_seconds = 10);
    h.create("create-1", Some(10));
    let reservation = h
        .store
        .reserve(h.request(LlmContextOperation::Append, "abort-1", Some(ID_1), Some(1)))
        .unwrap();
    h.advance(11);
    h.store
        .abort(&reservation, Some("NPS-SERVER-TIMEOUT"))
        .unwrap();
    let status = h.store.status(&alice(), Some(ID_1), None).unwrap();
    let failed = h.store.status(&alice(), None, Some("abort-1")).unwrap();
    assert_eq!(status.state, LlmContextState::Expired);
    assert_eq!(status.version, Some(1));
    assert_eq!(failed.error_code.as_deref(), Some("NPS-SERVER-TIMEOUT"));
}

#[test]
fn vector_010_lost_create_is_recovered_by_idempotency() {
    assert_vector("nwp.llm-context.010");
    let h = Harness::new(|options| {
        options.default_ttl_seconds = 10;
        options.tombstone_seconds = 5;
    });
    h.create("lost-create", None);
    let active = h.store.status(&alice(), None, Some("lost-create")).unwrap();
    h.advance(16);
    h.store.sweep_expired().unwrap();
    let retained = h.store.status(&alice(), None, Some("lost-create")).unwrap();
    assert_eq!(retained.context_id, active.context_id);
    assert_eq!(retained.version, Some(1));
}

#[test]
fn vector_011_release_and_expiry_keep_tombstones() {
    assert_vector("nwp.llm-context.011");
    let h = Harness::new(|options| {
        options.default_ttl_seconds = 10;
        options.tombstone_seconds = 5;
    });
    h.create("create-1", Some(10));
    let released = h.store.release(&alice(), ID_1, 1, "release-1").unwrap();
    assert_eq!(
        (released.state, released.version),
        (LlmContextState::Released, 2)
    );
    let replay = h.store.release(&alice(), ID_1, 1, "release-1").unwrap();
    assert_eq!(replay.version, 2);
    let conflict = h.store.release(&alice(), ID_2, 1, "release-1").unwrap_err();
    assert_error(&conflict, error_codes::ACTION_IDEMPOTENCY_CONFLICT);
    let after_release = h
        .store
        .reserve(h.request(
            LlmContextOperation::Append,
            "after-release",
            Some(ID_1),
            Some(2),
        ))
        .unwrap_err();
    assert_error(&after_release, error_codes::LLM_CONTEXT_NOT_FOUND);
    h.create("create-expiring", Some(10));
    h.advance(11);
    h.store.sweep_expired().unwrap();
    let expired = h.store.snapshot(&alice(), ID_2).unwrap_err();
    assert_error(&expired, error_codes::LLM_CONTEXT_EXPIRED);
    assert_eq!(expired.current_version, Some(1));
    h.advance(6);
    h.store.sweep_expired().unwrap();
    assert_error(
        &h.store.status(&alice(), Some(ID_2), None).unwrap_err(),
        error_codes::LLM_CONTEXT_NOT_FOUND,
    );
}

#[test]
fn vector_012_usage_preserves_distinct_accounting() {
    assert_vector("nwp.llm-context.012");
    let usage = LlmUsageDto {
        input_tokens: Some(1200),
        output_tokens: Some(80),
        cache_hit: Some(true),
        reused_tokens: Some(1000),
        evaluated_tokens: Some(200),
        wire_input_bytes: Some(384),
    };
    assert_eq!(
        usage.reused_tokens.unwrap() + usage.evaluated_tokens.unwrap(),
        usage.input_tokens.unwrap()
    );
    assert_eq!(usage.cache_hit, Some(true));
    assert!(usage.wire_input_bytes.unwrap() < 4096);
}

#[test]
fn vector_013_manifest_operations_match_implementation() {
    assert_vector("nwp.llm-context.013");
    let h = Harness::new(|options| {
        options.supported_operations = Some(HashSet::from([
            LlmContextOperation::Create,
            LlmContextOperation::Append,
            LlmContextOperation::Reset,
            LlmContextOperation::Release,
        ]));
    });
    h.create("create-1", None);
    let mut request = h.request(
        LlmContextOperation::Fork,
        "fork-disabled",
        Some(ID_1),
        Some(1),
    );
    request.messages.clear();
    assert_error(
        &h.store.reserve(request).unwrap_err(),
        error_codes::LLM_CONTEXT_OPERATION_UNSUPPORTED,
    );
}

#[test]
fn vector_014_process_restart_does_not_recreate_state() {
    assert_vector("nwp.llm-context.014");
    let first = Harness::new(|_| {});
    first.create("create-1", None);
    let restarted = Harness::new(|_| {});
    let error = restarted
        .store
        .reserve(restarted.request(
            LlmContextOperation::Append,
            "after-restart",
            Some(ID_1),
            Some(1),
        ))
        .unwrap_err();
    assert_error(&error, error_codes::LLM_CONTEXT_NOT_FOUND);
}

#[test]
fn vector_015_completion_idempotency_does_not_recommit() {
    assert_vector("nwp.llm-context.015");
    let h = Harness::new(|_| {});
    h.create("stream-replay", None);
    let error = h
        .store
        .reserve(h.request(LlmContextOperation::Create, "stream-replay", None, None))
        .unwrap_err();
    assert_error(&error, error_codes::ACTION_IDEMPOTENCY_CONFLICT);
    assert_eq!(h.store.snapshot(&alice(), ID_1).unwrap().version, 1);
}

#[test]
fn vector_016_revocation_before_commit_aborts() {
    assert_vector("nwp.llm-context.016");
    let h = Harness::new(|_| {});
    h.create("create-1", None);
    let reservation = h
        .store
        .reserve(h.request(LlmContextOperation::Append, "revoked", Some(ID_1), Some(1)))
        .unwrap();
    h.store
        .abort(&reservation, Some(error_codes::AUTH_NID_REVOKED))
        .unwrap();
    let outcome = h.store.status(&alice(), None, Some("revoked")).unwrap();
    assert_eq!(
        outcome.error_code.as_deref(),
        Some(error_codes::AUTH_NID_REVOKED)
    );
    assert_eq!(h.store.snapshot(&alice(), ID_1).unwrap().version, 1);
}

#[test]
fn vector_017_context_limit_includes_live_and_pending() {
    assert_vector("nwp.llm-context.017");
    let h = Harness::new(|options| options.max_contexts_per_principal = 1);
    h.create("create-1", None);
    assert_error(
        &h.store
            .reserve(h.request(LlmContextOperation::Create, "over-limit", None, None))
            .unwrap_err(),
        error_codes::LLM_CONTEXT_LIMIT_EXCEEDED,
    );
}

#[test]
fn vector_018_unsupported_operation_has_dedicated_error() {
    assert_vector("nwp.llm-context.018");
    let h = Harness::new(|options| {
        options.supported_operations = Some(HashSet::from([
            LlmContextOperation::Create,
            LlmContextOperation::Append,
            LlmContextOperation::Reset,
            LlmContextOperation::Release,
        ]));
    });
    h.create("create-1", None);
    let mut request = h.request(
        LlmContextOperation::Fork,
        "fork-disabled",
        Some(ID_1),
        Some(1),
    );
    request.messages.clear();
    let error = h.store.reserve(request).unwrap_err();
    assert_error(&error, error_codes::LLM_CONTEXT_OPERATION_UNSUPPORTED);
    assert_eq!(
        error_codes::to_nps_status(&error.error_code),
        "NPS-SERVER-UNSUPPORTED"
    );
}

#[test]
fn vector_019_stateful_request_requires_idempotency() {
    assert_vector("nwp.llm-context.019");
    let h = Harness::new(|_| {});
    let error = h
        .store
        .reserve(h.request(LlmContextOperation::Create, "", None, None))
        .unwrap_err();
    assert_error(&error, error_codes::ACTION_PARAMS_INVALID);
}

#[test]
fn reservations_and_snapshots_are_defensive_copies() {
    let h = Harness::new(|_| {});
    let mut request = h.request(LlmContextOperation::Create, "immutable", None, None);
    request.messages[1].content = Some("Original".into());
    let mut caller_copy = request.clone();
    let reservation = h.store.reserve(request).unwrap();
    caller_copy.messages[1].content = Some("Tampered".into());
    caller_copy.binding.model = "tampered-model".into();
    h.store.commit(&reservation, assistant("Stable")).unwrap();
    let mut snapshot = h.store.snapshot(&alice(), ID_1).unwrap();
    assert_eq!(snapshot.binding.model, "willow-small");
    assert_eq!(snapshot.transcript[1].content.as_deref(), Some("Original"));
    snapshot.transcript[1].content = Some("Mutated snapshot".into());
    assert_eq!(
        h.store.snapshot(&alice(), ID_1).unwrap().transcript[1]
            .content
            .as_deref(),
        Some("Original")
    );
}

fn assert_vector(id: &str) {
    let fixture = shared_fixture();
    let vector = fixture["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["id"] == id)
        .unwrap_or_else(|| panic!("shared vector {id} is missing"));
    assert_fixture_contract(vector);
}

fn assert_fixture_contract(vector: &Value) {
    let id = text(vector, "id");
    let input = &vector["input"];
    let expected = &vector["expected"];
    assert!(input.as_object().is_some_and(|value| !value.is_empty()));
    assert!(expected.as_object().is_some_and(|value| !value.is_empty()));
    match &id[id.len() - 3..] {
        "001" => {
            assert!(input["params"].get("context").is_none());
            assert_eq!(text(expected, "mode"), "stateless");
            assert!(boolean(expected, "dispatched") && !boolean(expected, "context_mutated"));
        }
        "002" => {
            assert_eq!(text(expected, "owner_nid"), text(input, "owner_nid"));
            assert_eq!(number(expected, "version"), 1);
            assert!(boolean(expected, "committed"));
        }
        "003" => {
            assert_eq!(
                number(expected, "version"),
                number(&input["pre_state"], "version") + 1
            );
            assert_eq!(
                number(expected, "accepted_delta_message_count"),
                array_len(&input["params"], "messages")
            );
            assert_eq!(
                number(expected, "post_message_count"),
                array_len(&input["pre_state"], "messages")
                    + array_len(&input["params"], "messages")
                    + 1
            );
        }
        "004" => {
            assert_eq!(
                number(expected, "post_version"),
                number(&input["pre_state"], "version")
            );
            assert_eq!(
                number(&expected["hint"], "current_version"),
                number(&input["pre_state"], "version")
            );
            assert_eq!(
                text(expected, "error"),
                error_codes::LLM_CONTEXT_VERSION_CONFLICT
            );
        }
        "005" => {
            assert_eq!(
                number(expected, "parent_version"),
                number(&input["request"], "base_version")
            );
            assert_eq!(
                number(expected, "post_parent_version"),
                number(input, "parent_version_at_child_commit")
            );
            assert_eq!(number(expected, "version"), 1);
        }
        "006" => {
            assert_eq!(
                number(expected, "version"),
                number(&input["pre_state"], "version") + 1
            );
            assert_eq!(
                text(expected, "resolved_model"),
                text(&input["request"], "model")
            );
        }
        "007" => {
            assert_eq!(
                number(expected, "post_version"),
                number(&input["pre_state"], "version")
            );
            assert_eq!(
                text(expected, "error"),
                error_codes::LLM_CONTEXT_BINDING_MISMATCH
            );
            assert!(
                !boolean(expected, "provider_dispatched")
                    && !boolean(expected, "stateless_fallback")
            );
        }
        "008" => {
            assert_ne!(text(input, "owner_nid"), text(input, "caller_nid"));
            assert!(!strings(input, "caller_capabilities").contains(&CAPABILITY_LLM_CONTEXT));
            assert_eq!(text(expected, "error"), error_codes::LLM_CONTEXT_FORBIDDEN);
        }
        "009" => {
            assert_eq!(
                number(expected, "post_version"),
                number(&input["pre_state"], "version")
            );
            assert!(!boolean(expected, "committed") && boolean(expected, "reservation_released"));
        }
        "010" => {
            let sequence = input["status_sequence"].as_array().unwrap();
            let terminal = sequence.last().unwrap();
            assert!(!boolean(&expected["running_status"], "context_id_present"));
            assert_eq!(
                text(&expected["completed_status"], "context_id"),
                text(terminal, "context_id")
            );
            assert_eq!(
                number(&expected["completed_status"], "version"),
                number(terminal, "version")
            );
        }
        "011" => {
            assert_eq!(
                number(&expected["release_receipt"], "version"),
                number(&input["pre_state"], "version") + 1
            );
            assert_eq!(
                number(&expected["expiry_tombstone"], "version"),
                number(&input["expiry_branch"], "active_version")
            );
        }
        "012" => {
            let usage = &input["usage"];
            assert_eq!(
                number(usage, "input_tokens"),
                number(usage, "reused_tokens") + number(usage, "evaluated_tokens")
            );
            assert!(
                number(usage, "wire_input_bytes") < number(input, "stateless_wire_input_bytes")
            );
            assert!(
                boolean(expected, "usage_equation_valid")
                    && boolean(expected, "wire_input_smaller_than_stateless")
            );
        }
        "013" => {
            let context = &input["manifest"]["context"];
            assert_eq!(context["operations"], input["implemented_operations"]);
            assert_eq!(
                text(context, "persistence"),
                text(input, "implemented_persistence")
            );
            assert!(boolean(expected, "manifest_valid"));
            assert_eq!(
                text(expected, "requires_capability"),
                CAPABILITY_LLM_CONTEXT
            );
        }
        "014" => {
            assert_eq!(text(input, "persistence"), "process");
            assert_eq!(text(input, "event"), "process_restart");
            assert_eq!(text(expected, "error"), error_codes::LLM_CONTEXT_NOT_FOUND);
            assert!(
                !boolean(expected, "replacement_created")
                    && !boolean(expected, "stateless_fallback")
            );
        }
        "015" => {
            let original = &input["original"];
            assert_eq!(
                strings(original, "chunks").concat(),
                text(expected, "ordered_content")
            );
            assert_ne!(text(original, "stream_id"), text(input, "replay_stream_id"));
            assert_eq!(
                number(expected, "provider_invocations")
                    + number(expected, "additional_context_commits"),
                0
            );
        }
        "016" => {
            assert_eq!(text(input, "authorization_at_admission"), "valid");
            assert_eq!(text(input, "authorization_at_commit"), "revoked");
            assert_eq!(
                number(expected, "post_version"),
                number(&input["pre_state"], "version")
            );
            assert_eq!(text(expected, "error"), error_codes::AUTH_NID_REVOKED);
        }
        "017" => {
            assert_eq!(
                number(input, "live_contexts"),
                number(input, "max_contexts_per_principal")
            );
            assert_eq!(
                text(expected, "error"),
                error_codes::LLM_CONTEXT_LIMIT_EXCEEDED
            );
            assert!(!boolean(expected, "context_allocated"));
        }
        "018" => {
            assert!(!strings(input, "advertised_operations")
                .contains(&text(&input["request"], "operation")));
            assert_eq!(
                text(expected, "error"),
                error_codes::LLM_CONTEXT_OPERATION_UNSUPPORTED
            );
        }
        "019" => {
            assert!(!boolean(input, "idempotency_key_present"));
            assert_eq!(text(expected, "error"), error_codes::ACTION_PARAMS_INVALID);
            assert!(
                !boolean(expected, "context_allocated")
                    && !boolean(expected, "provider_dispatched")
            );
        }
        _ => panic!("unimplemented fixture contract: {id}"),
    }
}

fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value[field].as_str().unwrap()
}

fn number(value: &Value, field: &str) -> u64 {
    value[field].as_u64().unwrap()
}

fn boolean(value: &Value, field: &str) -> bool {
    value[field].as_bool().unwrap()
}

fn array_len(value: &Value, field: &str) -> u64 {
    value[field].as_array().unwrap().len() as u64
}

fn strings<'a>(value: &'a Value, field: &str) -> Vec<&'a str> {
    value[field]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item.as_str().unwrap())
        .collect()
}

fn assert_error(error: &LlmContextStoreError, expected: &str) {
    assert_eq!(error.error_code, expected);
}

fn binding(model: &str, runtime_revision: &str) -> LlmContextBinding {
    LlmContextBinding {
        model: model.into(),
        system_messages: vec![system(if model == "willow-small" {
            "Be concise."
        } else {
            "Use JSON."
        })],
        tools: Vec::new(),
        runtime_revision: runtime_revision.into(),
    }
}

fn message(role: &str, content: &str) -> LlmMessageDto {
    LlmMessageDto {
        role: role.into(),
        content: Some(content.into()),
        tool_call_id: None,
        tool_name: None,
        tool_calls: None,
    }
}

fn system(content: &str) -> LlmMessageDto {
    message("system", content)
}

fn user(content: &str) -> LlmMessageDto {
    message("user", content)
}

fn assistant(content: &str) -> LlmMessageDto {
    message("assistant", content)
}

fn test_error(message: &str) -> LlmContextStoreError {
    LlmContextStoreError {
        error_code: "NPS-SERVER-INTERNAL".into(),
        message: message.into(),
        current_version: None,
    }
}
