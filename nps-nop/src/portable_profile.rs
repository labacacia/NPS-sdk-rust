// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent NOP 0.9 orchestration and runtime profile.

use crate::error_codes::{
    CALLBACK_HMAC_INVALID, CALLBACK_HMAC_MISSING, CALLBACK_INVALID, COMPENSATION_FAILED,
    COMPENSATION_NOT_SUPPORTED, CONDITION_EVAL_ERROR, DELEGATE_REJECTED, DELEGATE_SCOPE_VIOLATION,
    DELEGATE_TIMEOUT, INPUT_MAPPING_ERROR, RESOURCE_INSUFFICIENT, RUNTIME_IDLE_TIMEOUT,
    RUNTIME_MAX_RUNTIME, SPAWN_SPEC_INVALID, TASK_CANCELLED, TASK_DAG_CYCLE, TASK_DAG_INVALID,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

const CLUSTER_SPLIT: &str = "NDP-CLUSTER-SPLIT";

/// Run one shared deterministic orchestration transcript.
pub fn evaluate_orchestration(task: &Value) -> Value {
    let Some(task_object) = task.as_object() else {
        return empty_failure(TASK_DAG_INVALID);
    };
    let Some(raw_nodes) = task_object.get("nodes").and_then(Value::as_array) else {
        return empty_failure(TASK_DAG_INVALID);
    };
    let mut nodes = BTreeMap::new();
    for node in raw_nodes {
        let Some(id) = node.get("id").and_then(Value::as_str) else {
            return empty_failure(TASK_DAG_INVALID);
        };
        if nodes.insert(id.to_string(), node.clone()).is_some() {
            return empty_failure(TASK_DAG_INVALID);
        }
    }
    let Some(topo) = stable_topology(&nodes) else {
        return empty_failure(TASK_DAG_CYCLE);
    };

    let mut events = Vec::new();
    if bool_value(task, "preflight", false) {
        events.push("task:preflight".to_string());
        if topo
            .iter()
            .any(|id| !bool_value(&nodes[id], "preflight_available", true))
        {
            events.push("task:failed".to_string());
            return build_result(
                events,
                "failed",
                Some(RESOURCE_INSUFFICIENT),
                Value::Null,
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                vec![],
            );
        }
    }

    events.push("task:running".to_string());
    let mut results = BTreeMap::<String, Value>::new();
    let mut states = BTreeMap::<String, String>::new();
    let mut attempts = BTreeMap::<String, usize>::new();
    let mut mapped = BTreeMap::<String, Value>::new();
    let task_retries = usize_value(task, "max_retries", 0);

    for id in &topo {
        let node = &nodes[id];
        if string_value(task, "cancel_before").is_some_and(|value| value == id) {
            events.push("task:cancelled".to_string());
            return build_result(
                events,
                "cancelled",
                Some(TASK_CANCELLED),
                Value::Null,
                states,
                attempts,
                mapped,
                vec![],
            );
        }

        if let Some(condition) = string_value(node, "condition") {
            match evaluate_condition(condition, &results) {
                Some(false) => {
                    states.insert(id.clone(), "skipped".to_string());
                    attempts.insert(id.clone(), 0);
                    events.push(format!("{id}:skipped"));
                    continue;
                }
                Some(true) => {}
                None => {
                    states.insert(id.clone(), "failed".to_string());
                    attempts.insert(id.clone(), 0);
                    events.push(format!("{id}:failed"));
                    events.push("task:failed".to_string());
                    return build_result(
                        events,
                        "failed",
                        Some(CONDITION_EVAL_ERROR),
                        Value::Null,
                        states,
                        attempts,
                        mapped,
                        vec![],
                    );
                }
            }
        }

        if let Some(mapping) = node.get("input_mapping").and_then(Value::as_object) {
            let Some(parameters) = resolve_mapping(mapping, &results) else {
                states.insert(id.clone(), "failed".to_string());
                attempts.insert(id.clone(), 0);
                events.push(format!("{id}:failed"));
                events.push("task:failed".to_string());
                return build_result(
                    events,
                    "failed",
                    Some(INPUT_MAPPING_ERROR),
                    Value::Null,
                    states,
                    attempts,
                    mapped,
                    vec![],
                );
            };
            mapped.insert(id.clone(), Value::Object(parameters));
        }

        let max_retries = usize_value(node, "max_retries", task_retries);
        let scripted = node
            .get("attempts")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut final_error = None;
        let mut completed = false;
        let mut count = 0;
        for (index, outcome) in scripted.iter().take(max_retries + 1).enumerate() {
            count += 1;
            events.push(format!("{id}:attempt:{count}"));
            let kind = outcome
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if kind == "success" {
                results.insert(
                    id.clone(),
                    outcome.get("result").cloned().unwrap_or_else(|| json!({})),
                );
                states.insert(id.clone(), "completed".to_string());
                events.push(format!("{id}:completed"));
                completed = true;
                break;
            }
            let error = if kind == "timeout" {
                DELEGATE_TIMEOUT
            } else {
                outcome
                    .get("error_code")
                    .and_then(Value::as_str)
                    .unwrap_or(DELEGATE_REJECTED)
            };
            final_error = Some(error);
            let retryable = kind == "timeout" || bool_value(outcome, "retryable", false);
            let selected = node
                .get("retry_on")
                .and_then(Value::as_array)
                .is_none_or(|values| values.iter().any(|value| value.as_str() == Some(error)));
            if retryable && selected && count <= max_retries && index + 1 < scripted.len() {
                events.push(format!("{id}:retrying"));
                continue;
            }
            states.insert(id.clone(), "failed".to_string());
            events.push(format!("{id}:failed"));
            break;
        }
        attempts.insert(id.clone(), count);
        if completed {
            continue;
        }

        let compensation = compensate(task, id, &topo, &nodes, &mut states, &mut events);
        events.push("task:failed".to_string());
        return build_result(
            events,
            "failed",
            compensation
                .error
                .or(final_error)
                .or(Some(DELEGATE_REJECTED)),
            Value::Null,
            states,
            attempts,
            mapped,
            compensation.order,
        );
    }

    let aggregate = aggregate_results(task, &topo, &nodes, &states, &results);
    events.push("task:completed".to_string());
    build_result(
        events,
        "completed",
        None,
        aggregate,
        states,
        attempts,
        mapped,
        vec![],
    )
}

/// Evaluate one shared runtime/security vector category.
pub fn evaluate_runtime(category: &str, input: &Value) -> Value {
    match category {
        "callback" => evaluate_callback(input),
        "hmac" => evaluate_hmac(input),
        "lease" => evaluate_lease(input),
        "delegation" => evaluate_delegation(input),
        "spawn_spec" => evaluate_spawn_spec(input),
        "lifecycle" => evaluate_lifecycle(input),
        "dedup_key" => json!({
            "value": compute_dedup_key(
                input.get("task_id").and_then(Value::as_str).unwrap_or_default(),
                input.get("dag_hash").and_then(Value::as_str).unwrap_or_default(),
            )
        }),
        _ => panic!("unknown NOP profile category: {category}"),
    }
}

/// SHA-256(task_id + NUL + dag_hash), lowercase hex.
pub fn compute_dedup_key(task_id: &str, dag_hash: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(task_id.as_bytes());
    digest.update([0]);
    digest.update(dag_hash.as_bytes());
    hex::encode(digest.finalize())
}

fn stable_topology(nodes: &BTreeMap<String, Value>) -> Option<Vec<String>> {
    let mut indegree: BTreeMap<String, usize> = nodes.keys().map(|id| (id.clone(), 0)).collect();
    let mut outgoing: BTreeMap<String, Vec<String>> =
        nodes.keys().map(|id| (id.clone(), Vec::new())).collect();
    for (id, node) in nodes {
        for dependency in dependencies(node) {
            if !nodes.contains_key(dependency) {
                return None;
            }
            *indegree.get_mut(id)? += 1;
            outgoing.get_mut(dependency)?.push(id.clone());
        }
    }
    let mut ready: BTreeSet<String> = indegree
        .iter()
        .filter(|(_, value)| **value == 0)
        .map(|(id, _)| id.clone())
        .collect();
    let mut order = Vec::new();
    while let Some(id) = ready.pop_first() {
        order.push(id.clone());
        let mut next_values = outgoing.get(&id)?.clone();
        next_values.sort();
        for next in next_values {
            let value = indegree.get_mut(&next)?;
            *value -= 1;
            if *value == 0 {
                ready.insert(next);
            }
        }
    }
    (order.len() == nodes.len()).then_some(order)
}

fn dependencies(node: &Value) -> Vec<&str> {
    node.get("depends_on")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn evaluate_condition(expression: &str, results: &BTreeMap<String, Value>) -> Option<bool> {
    let operators = ["==", "!=", ">=", "<=", ">", "<"];
    let (operator, offset) = operators
        .iter()
        .filter_map(|operator| expression.find(operator).map(|offset| (*operator, offset)))
        .min_by_key(|(_, offset)| *offset)?;
    let path = expression[..offset].trim();
    let literal = expression[offset + operator.len()..].trim();
    let result_object = Value::Object(
        results
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    let left = resolve_path(&result_object, path)?;
    let right: Value = serde_json::from_str(literal).ok()?;
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => Some(match operator {
            "==" => left == right,
            "!=" => left != right,
            ">" => left > right,
            ">=" => left >= right,
            "<" => left < right,
            "<=" => left <= right,
            _ => return None,
        }),
        _ => Some(match operator {
            "==" => left == &right,
            "!=" => left != &right,
            _ => return None,
        }),
    }
}

fn resolve_mapping(
    mapping: &Map<String, Value>,
    results: &BTreeMap<String, Value>,
) -> Option<Map<String, Value>> {
    let root = Value::Object(
        results
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    );
    mapping
        .iter()
        .map(|(name, path)| {
            resolve_path(&root, path.as_str()?)
                .cloned()
                .map(|value| (name.clone(), value))
        })
        .collect()
}

fn resolve_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let path = path.strip_prefix("$.")?;
    path.split('.')
        .try_fold(root, |current, segment| current.get(segment))
}

struct Compensation {
    order: Vec<String>,
    error: Option<&'static str>,
}

fn compensate(
    task: &Value,
    failed_id: &str,
    topo: &[String],
    nodes: &BTreeMap<String, Value>,
    states: &mut BTreeMap<String, String>,
    events: &mut Vec<String>,
) -> Compensation {
    let policy = string_value(task, "compensation_policy");
    if !matches!(policy, Some("best_effort" | "strict")) {
        return Compensation {
            order: vec![],
            error: None,
        };
    }
    let mut ancestors = HashSet::new();
    let mut pending = VecDeque::from([failed_id.to_string()]);
    while let Some(id) = pending.pop_front() {
        for dependency in dependencies(&nodes[&id]) {
            if ancestors.insert(dependency.to_string()) {
                pending.push_back(dependency.to_string());
            }
        }
    }
    let candidates: Vec<String> = topo
        .iter()
        .rev()
        .filter(|id| {
            ancestors.contains(*id) && states.get(*id).is_some_and(|state| state == "completed")
        })
        .cloned()
        .collect();
    if policy == Some("strict")
        && candidates
            .iter()
            .any(|id| nodes[id].get("compensate_action").is_none())
    {
        return Compensation {
            order: vec![],
            error: Some(COMPENSATION_NOT_SUPPORTED),
        };
    }
    let mut order = Vec::new();
    for id in candidates {
        let node = &nodes[&id];
        if node.get("compensate_action").is_none() {
            continue;
        }
        order.push(id.clone());
        events.push(format!("{id}:compensating"));
        if string_value(node, "compensation_outcome") == Some("failure") {
            states.insert(id.clone(), "compensation_failed".to_string());
            events.push(format!("{id}:compensation_failed"));
            if policy == Some("strict") {
                return Compensation {
                    order,
                    error: Some(COMPENSATION_FAILED),
                };
            }
        } else {
            states.insert(id.clone(), "compensated".to_string());
            events.push(format!("{id}:compensated"));
        }
    }
    Compensation { order, error: None }
}

fn aggregate_results(
    task: &Value,
    topo: &[String],
    nodes: &BTreeMap<String, Value>,
    states: &BTreeMap<String, String>,
    results: &BTreeMap<String, Value>,
) -> Value {
    let has_outgoing: HashSet<String> = nodes
        .values()
        .flat_map(dependencies)
        .map(str::to_string)
        .collect();
    let values: Vec<Value> = topo
        .iter()
        .filter(|id| {
            !has_outgoing.contains(*id)
                && states.get(*id).is_some_and(|state| state == "completed")
                && results.contains_key(*id)
        })
        .map(|id| results[id].clone())
        .collect();
    if values.is_empty() {
        return Value::Null;
    }
    if string_value(task, "aggregate") == Some("all") {
        return Value::Array(values);
    }
    let mut output = Map::new();
    for value in values {
        let Some(object) = value.as_object() else {
            continue;
        };
        for (key, value) in object {
            if string_value(task, "aggregate") == Some("merge_all") {
                if let (Some(existing), Some(incoming)) = (
                    output.get_mut(key).and_then(Value::as_array_mut),
                    value.as_array(),
                ) {
                    existing.extend(incoming.iter().cloned());
                    continue;
                }
            }
            output.insert(key.clone(), value.clone());
        }
    }
    Value::Object(output)
}

fn evaluate_callback(input: &Value) -> Value {
    let mut allowed = callback_allowed(
        string_value(input, "url").unwrap_or_default(),
        input.get("resolved_ips").and_then(Value::as_array),
    );
    if allowed {
        if let Some(redirect) = string_value(input, "redirect_url") {
            allowed = callback_allowed(
                redirect,
                input.get("redirect_resolved_ips").and_then(Value::as_array),
            );
        }
    }
    json!({
        "allowed": allowed,
        "error": if allowed { Value::Null } else { json!(CALLBACK_INVALID) }
    })
}

fn callback_allowed(value: &str, addresses: Option<&Vec<Value>>) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.host_str().is_none()
    {
        return false;
    }
    let Some(addresses) = addresses.filter(|values| !values.is_empty()) else {
        return false;
    };
    addresses.iter().all(|value| {
        value
            .as_str()
            .and_then(|text| text.parse::<IpAddr>().ok())
            .is_some_and(is_public_ip)
    })
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => {
            !value.is_private()
                && !value.is_loopback()
                && !value.is_link_local()
                && !value.is_multicast()
                && !value.is_unspecified()
                && !value.is_broadcast()
        }
        IpAddr::V6(value) => {
            !value.is_loopback()
                && !value.is_unicast_link_local()
                && !value.is_unique_local()
                && !value.is_multicast()
                && !value.is_unspecified()
        }
    }
}

fn evaluate_hmac(input: &Value) -> Value {
    let Some(signature) = string_value(input, "signature") else {
        return json!({"valid": false, "error": CALLBACK_HMAC_MISSING});
    };
    let valid = URL_SAFE_NO_PAD
        .decode(
            string_value(input, "secret_base64url")
                .unwrap_or_default()
                .as_bytes(),
        )
        .ok()
        .filter(|key| key.len() == 32)
        .and_then(|key| {
            let mut mac = Hmac::<Sha256>::new_from_slice(&key).ok()?;
            mac.update(
                string_value(input, "raw_body")
                    .unwrap_or_default()
                    .as_bytes(),
            );
            let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
            Some(
                expected.len() == signature.len()
                    && expected
                        .as_bytes()
                        .iter()
                        .zip(signature.as_bytes())
                        .fold(0_u8, |accumulator, (left, right)| {
                            accumulator | (left ^ right)
                        })
                        == 0,
            )
        })
        .unwrap_or(false);
    json!({
        "valid": valid,
        "error": if valid { Value::Null } else { json!(CALLBACK_HMAC_INVALID) }
    })
}

#[derive(Clone)]
struct Lease {
    runner_nid: String,
    expires_at: i64,
}

fn evaluate_lease(input: &Value) -> Value {
    let mut leases = HashMap::<String, Lease>::new();
    let mut terminal = HashSet::new();
    let mut outcomes = Vec::new();
    let events = input
        .get("events")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for event in events {
        let at = event.get("at").and_then(Value::as_i64).unwrap_or_default();
        match string_value(&event, "op").unwrap_or_default() {
            "claim" => {
                let task_id = string_value(&event, "task_id")
                    .unwrap_or_default()
                    .to_string();
                let runner = string_value(&event, "runner_nid").unwrap_or_default();
                let seconds = i64_value(&event, "lease_seconds", 10).clamp(10, 600);
                if let Some(lease) = leases.get(&task_id).filter(|lease| lease.expires_at > at) {
                    if lease.runner_nid == runner {
                        leases.insert(
                            task_id,
                            Lease {
                                runner_nid: runner.to_string(),
                                expires_at: at + seconds,
                            },
                        );
                        outcomes.push("granted");
                    } else {
                        outcomes.push("conflict");
                    }
                } else {
                    let reclaimed = leases.contains_key(&task_id);
                    leases.insert(
                        task_id,
                        Lease {
                            runner_nid: runner.to_string(),
                            expires_at: at + seconds,
                        },
                    );
                    outcomes.push(if reclaimed { "reclaimed" } else { "granted" });
                }
            }
            "renew" => {
                let task_id = string_value(&event, "task_id")
                    .unwrap_or_default()
                    .to_string();
                let runner = string_value(&event, "runner_nid").unwrap_or_default();
                let seconds = i64_value(&event, "lease_seconds", 10).clamp(10, 600);
                if leases
                    .get(&task_id)
                    .is_some_and(|lease| lease.expires_at > at && lease.runner_nid == runner)
                {
                    leases.insert(
                        task_id,
                        Lease {
                            runner_nid: runner.to_string(),
                            expires_at: at + seconds,
                        },
                    );
                    outcomes.push("granted");
                } else {
                    outcomes.push("conflict");
                }
            }
            "mark_terminal" => {
                terminal.insert(terminal_key(&event));
                outcomes.push("recorded");
            }
            "is_terminal" => outcomes.push(if terminal.contains(&terminal_key(&event)) {
                "terminal"
            } else {
                "pending"
            }),
            _ => {}
        }
    }
    json!({"outcomes": outcomes})
}

fn terminal_key(event: &Value) -> String {
    format!(
        "{}\0{}",
        string_value(event, "dedup_key").unwrap_or_default(),
        string_value(event, "node_id").unwrap_or_default()
    )
}

fn evaluate_delegation(input: &Value) -> Value {
    let parent = input.get("parent_scope").unwrap_or(&Value::Null);
    let delegated = input.get("delegated_scope").unwrap_or(&Value::Null);
    if !scope_subset(parent, delegated) {
        return json!({"targets": [], "error": DELEGATE_SCOPE_VIOLATION});
    }
    let mut targets = Vec::new();
    let attempts = input
        .get("attempts")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for attempt in attempts {
        let live: Vec<&Value> = attempt
            .get("candidates")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter(|candidate| bool_value(candidate, "live", false))
                    .collect()
            })
            .unwrap_or_default();
        let Some(highest) = live
            .iter()
            .filter_map(|candidate| candidate.get("cluster_epoch")?.as_u64())
            .max()
        else {
            return json!({"targets": targets, "error": DELEGATE_REJECTED});
        };
        let leaders: Vec<&&Value> = live
            .iter()
            .filter(|candidate| {
                candidate.get("cluster_epoch").and_then(Value::as_u64) == Some(highest)
            })
            .collect();
        if leaders.len() != 1 {
            return json!({"targets": targets, "error": CLUSTER_SPLIT});
        }
        targets.push(
            leaders[0]
                .get("nid")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
        );
    }
    json!({"targets": targets, "error": Value::Null})
}

fn scope_subset(parent: &Value, delegated: &Value) -> bool {
    string_set(delegated, "nodes").is_subset(&string_set(parent, "nodes"))
        && string_set(delegated, "actions").is_subset(&string_set(parent, "actions"))
        && delegated
            .get("max_token_budget")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX)
            <= parent
                .get("max_token_budget")
                .and_then(Value::as_u64)
                .unwrap_or_default()
}

fn string_set(value: &Value, key: &str) -> HashSet<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn evaluate_spawn_spec(input: &Value) -> Value {
    let spec = input.get("spawn_spec").unwrap_or(&Value::Null);
    let mut valid = string_value(spec, "image").is_some_and(|value| !value.trim().is_empty());
    if valid {
        if let (Some(idle), Some(maximum)) = (
            spec.get("idle_timeout_seconds").and_then(Value::as_u64),
            spec.get("max_runtime_seconds").and_then(Value::as_u64),
        ) {
            valid = idle <= maximum;
        }
    }
    json!({
        "error": if valid { Value::Null } else { json!(SPAWN_SPEC_INVALID) }
    })
}

fn evaluate_lifecycle(input: &Value) -> Value {
    if i64_value(input, "elapsed_seconds", 0) >= i64_value(input, "max_runtime_seconds", 0) {
        json!({"state": "failed", "error": RUNTIME_MAX_RUNTIME})
    } else if i64_value(input, "idle_seconds", 0) >= i64_value(input, "idle_timeout_seconds", 0) {
        json!({"state": "failed", "error": RUNTIME_IDLE_TIMEOUT})
    } else if string_value(input, "worker_terminal") == Some("done") {
        json!({"state": "completed", "error": Value::Null})
    } else {
        json!({"state": "failed", "error": DELEGATE_REJECTED})
    }
}

#[allow(clippy::too_many_arguments)]
fn build_result(
    events: Vec<String>,
    state: &str,
    error: Option<&str>,
    aggregate: Value,
    states: BTreeMap<String, String>,
    attempts: BTreeMap<String, usize>,
    mapped: BTreeMap<String, Value>,
    compensation: Vec<String>,
) -> Value {
    json!({
        "events": events,
        "terminal_state": state,
        "error_code": error,
        "aggregate": aggregate,
        "node_states": states,
        "attempt_counts": attempts,
        "mapped_params": mapped,
        "compensation_order": compensation,
    })
}

fn empty_failure(error: &str) -> Value {
    build_result(
        vec!["task:failed".to_string()],
        "failed",
        Some(error),
        Value::Null,
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        vec![],
    )
}

fn bool_value(value: &Value, key: &str, fallback: bool) -> bool {
    value.get(key).and_then(Value::as_bool).unwrap_or(fallback)
}

fn usize_value(value: &Value, key: &str, fallback: usize) -> usize {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|number| usize::try_from(number).ok())
        .unwrap_or(fallback)
}

fn i64_value(value: &Value, key: &str, fallback: i64) -> i64 {
    value.get(key).and_then(Value::as_i64).unwrap_or(fallback)
}

fn string_value<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
