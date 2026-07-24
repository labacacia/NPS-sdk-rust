// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Resolves NOP JSONPath expressions of the form `$.node_id.field.subfield`
//! against a map of upstream node results (NPS-5 §3.1.3). Faithful port of
//! the .NET `NopInputMapper`.

use serde_json::{Map, Value};
use std::collections::HashMap;

use crate::constants;
use crate::error_codes;

/// Error raised when an input mapping path cannot be resolved.
#[derive(Debug, Clone)]
pub struct MappingError {
    pub message: String,
    pub error_code: String,
}

impl MappingError {
    fn new(message: impl Into<String>) -> Self {
        MappingError {
            message: message.into(),
            error_code: error_codes::INPUT_MAPPING_ERROR.to_string(),
        }
    }
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Resolves a single JSONPath expression against the upstream node result context.
///
/// Returns `Ok(None)` when the path leads to a missing property.
/// Returns `Err` for malformed paths or depth violations.
pub fn resolve(path: &str, context: &HashMap<String, Value>) -> Result<Option<Value>, MappingError> {
    if path.trim().is_empty() {
        return Err(MappingError::new("Input mapping path must not be empty."));
    }

    if !path.starts_with("$.") {
        return Err(MappingError::new(format!(
            "Input mapping path must start with '$.' — got: {path}"
        )));
    }

    // Split: "$", "node_id", "field", "sub", ... (dropping empty segments)
    let parts: Vec<&str> = path.split('.').filter(|s| !s.is_empty()).collect();
    // parts[0] == "$"

    if parts.len() > constants::MAX_INPUT_MAPPING_DEPTH + 1 {
        return Err(MappingError::new(format!(
            "Input mapping path depth {} exceeds maximum {}: {path}",
            parts.len() - 1,
            constants::MAX_INPUT_MAPPING_DEPTH
        )));
    }

    if parts.len() == 1 {
        // Just "$" → the entire context as a JSON object.
        let map: Map<String, Value> = context
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        return Ok(Some(Value::Object(map)));
    }

    let node_id = parts[1];
    let node_result = match context.get(node_id) {
        Some(v) => v,
        None => return Ok(None),
    };

    if parts.len() == 2 {
        return Ok(Some(node_result.clone())); // "$.node_id" → full result
    }

    // Navigate deeper.
    let mut current = node_result;
    for part in &parts[2..] {
        match current {
            Value::Object(obj) => match obj.get(*part) {
                Some(v) => current = v,
                None => return Ok(None),
            },
            _ => return Ok(None),
        }
    }
    Ok(Some(current.clone()))
}

/// Builds a `params` object by resolving all `input_mapping` entries against the
/// upstream result context. `None` mapping produces an empty object.
pub fn build_params(
    input_mapping: Option<&HashMap<String, Value>>,
    context: &HashMap<String, Value>,
) -> Result<Value, MappingError> {
    let mapping = match input_mapping {
        Some(m) if !m.is_empty() => m,
        _ => return Ok(Value::Object(Map::new())),
    };

    let mut out = Map::new();
    for (param_name, path_element) in mapping {
        let resolved = match path_element {
            Value::String(s) => resolve(s, context)?.unwrap_or(Value::Null),
            Value::Array(arr) => {
                let mut list = Vec::with_capacity(arr.len());
                for p in arr {
                    let v = match p {
                        Value::String(s) => resolve(s, context)?.unwrap_or(Value::Null),
                        other => other.clone(),
                    };
                    list.push(v);
                }
                Value::Array(list)
            }
            other => other.clone(),
        };
        out.insert(param_name.clone(), resolved);
    }
    Ok(Value::Object(out))
}
