// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Aggregates results from multiple completed subtasks using the strategy
//! defined in `SyncFrame.aggregate` or the orchestrator default (NPS-5 §3.3.2).
//! Faithful port of the .NET `NopResultAggregator`.

use serde_json::{Map, Value};
use std::collections::HashMap;

use crate::models::aggregate_strategy;

/// Aggregates `results` using `strategy`.
///
/// `min_required` is only used by [`aggregate_strategy::FASTEST_K`].
pub fn aggregate(strategy: &str, results: &[Value], min_required: usize) -> Value {
    if results.is_empty() {
        return Value::Object(Map::new());
    }

    match strategy {
        aggregate_strategy::FIRST => results[0].clone(),
        aggregate_strategy::ALL => build_array(results),
        aggregate_strategy::FASTEST_K => {
            let take = if min_required > 0 {
                min_required
            } else {
                results.len()
            };
            let take = take.min(results.len());
            build_array(&results[..take])
        }
        // "merge", "merge_all", and default
        _ => merge(results),
    }
}

/// Merges all JSON object results into one (last-write-wins on key conflicts).
/// Non-object results are added under `_result_{i}` keys.
pub fn merge(results: &[Value]) -> Value {
    let mut merged = Map::new();
    for (i, result) in results.iter().enumerate() {
        match result {
            Value::Object(obj) => {
                for (k, v) in obj {
                    merged.insert(k.clone(), v.clone());
                }
            }
            other => {
                merged.insert(format!("_result_{i}"), other.clone());
            }
        }
    }
    Value::Object(merged)
}

/// Returns all results as a JSON array.
pub fn build_array(results: &[Value]) -> Value {
    Value::Array(results.to_vec())
}

/// Filters `all_results` to only end nodes, then aggregates.
pub fn aggregate_end_nodes(
    end_node_ids: &[String],
    all_results: &HashMap<String, Value>,
    strategy: &str,
) -> Value {
    let end_results: Vec<Value> = end_node_ids
        .iter()
        .filter_map(|id| all_results.get(id).cloned())
        .collect();
    aggregate(strategy, &end_results, 0)
}
