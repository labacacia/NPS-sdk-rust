// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Parser and accessors for the `bridge_target` action parameter.

use std::collections::HashMap;

use serde_json::Value;

use super::error::{bridge_error_codes, BridgeDispatchError};
use super::types::BridgeTarget;
use crate::frames::ActionFrame;

/// Parse `params.bridge_target` from an action frame.
pub fn bridge_target_from_action_frame(
    frame: &ActionFrame,
) -> Result<BridgeTarget, BridgeDispatchError> {
    let params = frame.params.as_ref().ok_or_else(|| {
        BridgeDispatchError::new(
            bridge_error_codes::TARGET_INVALID,
            "params.bridge_target is required.",
        )
    })?;

    let target_element = match params {
        Value::Object(map) => map.get("bridge_target").unwrap_or(params),
        _ => params,
    };

    bridge_target_from_json(target_element)
}

/// Parse a bridge target JSON object.
pub fn bridge_target_from_json(target: &Value) -> Result<BridgeTarget, BridgeDispatchError> {
    let obj = target.as_object().ok_or_else(|| {
        BridgeDispatchError::new(
            bridge_error_codes::TARGET_INVALID,
            "bridge_target must be an object.",
        )
    })?;

    let protocol = read_required_string(obj, "protocol")?;
    let endpoint = read_required_string(obj, "endpoint")?;

    let mut extras: HashMap<String, Value> = HashMap::new();
    for (name, value) in obj {
        if name == "protocol" || name == "endpoint" {
            continue;
        }
        if name == "extras" {
            if let Value::Object(nested) = value {
                for (k, v) in nested {
                    extras.insert(k.clone(), v.clone());
                }
                continue;
            }
        }
        extras.insert(name.clone(), value.clone());
    }

    Ok(BridgeTarget {
        protocol,
        endpoint,
        extras: if extras.is_empty() { None } else { Some(extras) },
    })
}

fn read_required_string(
    obj: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<String, BridgeDispatchError> {
    match obj.get(name).and_then(Value::as_str) {
        Some(s) if !s.trim().is_empty() => Ok(s.to_string()),
        _ => Err(BridgeDispatchError::new(
            bridge_error_codes::TARGET_INVALID,
            format!("bridge_target.{name} is required."),
        )),
    }
}

/// Read a string extra from a target (case-insensitive key match).
pub fn target_get_string<'a>(
    target: &BridgeTarget,
    name: &str,
    default_value: Option<&'a str>,
) -> Option<String> {
    match get_extra(target, name) {
        Some(value) => match value {
            Value::String(s) => Some(s.clone()),
            Value::Number(n) => Some(n.to_string()),
            Value::Bool(b) => Some(if *b { "True" } else { "False" }.to_string()),
            Value::Null => default_value.map(str::to_string),
            other => Some(other.to_string()),
        },
        None => default_value.map(str::to_string),
    }
}

/// Try to read a JSON extra from a target (case-insensitive key match).
pub fn target_get_json(target: &BridgeTarget, name: &str) -> Option<Value> {
    get_extra(target, name).cloned()
}

fn get_extra<'a>(target: &'a BridgeTarget, name: &str) -> Option<&'a Value> {
    let extras = target.extras.as_ref()?;
    // .NET uses OrdinalIgnoreCase; match case-insensitively.
    extras
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v)
}
