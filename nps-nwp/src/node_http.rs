// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Shared framework-agnostic request/response types for the NWP node servers
//! (Action, Complex, Memory). Mirrors the [`crate::anchor_server::AnchorRequest`]
//! shape so every node server can be adapted to hyper/axum/tiny_http by the host.

use std::collections::HashMap;

use serde_json::{Map, Value};

/// An inbound HTTP request, already stripped to a node-relative `path` (the
/// host adapter is responsible for prefix matching, as `AnchorNodeApp` does).
#[derive(Debug, Clone)]
pub struct NodeRequest {
    pub method: String,
    /// Full request path; each node server trims its own configured prefix.
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl NodeRequest {
    pub fn new(method: impl Into<String>, path: impl Into<String>) -> Self {
        NodeRequest {
            method: method.into(),
            path: path.into(),
            headers: HashMap::new(),
            body: Vec::new(),
        }
    }

    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.insert(name.to_ascii_lowercase(), value.into());
        self
    }

    pub fn with_json(mut self, value: &Value) -> Self {
        self.body = serde_json::to_vec(value).unwrap_or_default();
        self
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }
}

/// An outbound HTTP response.
#[derive(Debug, Clone)]
pub struct NodeResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl NodeResponse {
    pub fn json_value(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// NDJSON lines (for `/stream`).
    pub fn ndjson_lines(&self) -> Vec<Value> {
        String::from_utf8_lossy(&self.body)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

/// Empty response with just a status (used for 405 etc.).
pub(crate) fn empty(status: u16) -> NodeResponse {
    NodeResponse {
        status,
        headers: vec![],
        body: vec![],
    }
}

/// Build an `ErrorFrame` response — `{ status, error, message, details? }`, matching
/// the .NET `ErrorFrame` wire shape (NPS.Core.Frames.Ncp.ErrorFrame).
pub(crate) fn error_resp(
    status: u16,
    nps_status: &str,
    error_code: &str,
    message: &str,
    details: Option<Value>,
    extra: &[(String, String)],
) -> NodeResponse {
    let mut env = Map::new();
    env.insert("status".into(), Value::String(nps_status.into()));
    env.insert("error".into(), Value::String(error_code.into()));
    env.insert("message".into(), Value::String(message.into()));
    if let Some(d) = details {
        env.insert("details".into(), d);
    }
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    headers.extend(extra.iter().cloned());
    NodeResponse {
        status,
        headers,
        body: serde_json::to_vec(&Value::Object(env)).unwrap_or_default(),
    }
}
