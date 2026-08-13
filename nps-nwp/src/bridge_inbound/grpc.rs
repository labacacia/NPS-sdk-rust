// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound gRPC Bridge **service logic** — the four `NwpIngress` RPC handlers
//! over the backend abstraction, backend resolution, and the §16.3 status
//! mapping.
//!
//! **No transport binding.** This workspace depends on neither `tonic` nor
//! `prost`, and NPS-CR-0010 forbids pulling a heavy new dependency in for the
//! port, so this module implements the service semantics against plain Rust
//! request/response structs. A host that wants the wire protocol generates
//! stubs from the published `Protos/nwp_ingress.proto` (package
//! `labacacia.grpc_ingress.v1`, carried over unchanged — clients hold generated
//! stubs, so the `.proto` is public API) and forwards each RPC here.
//!
//! All payloads are JSON-encoded NWP frame bodies carried as bytes: NWP schemas
//! are runtime-declared through AnchorFrame, so a typed proto is impossible.

use std::sync::Arc;

use serde_json::{json, Value};

use crate::error_codes;

use super::backend::{NwpBackend, NwpResult};
use super::error_map::{self, GrpcStatusCode};
use super::options::BridgeInboundOptions;

// ── Wire structs (mirrors of nwp_ingress.proto) ──────────────────────────────

/// `UpstreamContext { upstream = 1; agent_nid = 2; idempotency_key = 3; traceparent = 4; }`
#[derive(Debug, Clone, Default)]
pub struct UpstreamContext {
    pub upstream: String,
    pub agent_nid: String,
    pub idempotency_key: String,
    pub traceparent: String,
}

impl UpstreamContext {
    pub fn for_upstream(name: impl Into<String>) -> Self {
        UpstreamContext {
            upstream: name.into(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManifestResponse {
    pub nwm_json: Vec<u8>,
    /// Empty when the role is `Unknown`.
    pub node_type: String,
}

#[derive(Debug, Clone)]
pub struct InvokeResponse {
    pub http_status: i32,
    pub body_json: Vec<u8>,
    /// Lifted from the payload's `task_id`, or `""`.
    pub task_id: String,
}

#[derive(Debug, Clone)]
pub struct QueryResponse {
    pub http_status: i32,
    pub body_json: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ActionsResponse {
    /// `{ "actions": { "<id>": { "description": ... } } }`
    pub actions_json: Vec<u8>,
}

/// A gRPC status carried out of a handler — the equivalent of `RpcException`.
///
/// The detail string is `"{npsStatus} {nwpError}: {message}"` so a caller can
/// recover the exact NPS fault, not only the coarse gRPC class.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}: {message}")]
pub struct GrpcStatusError {
    pub code: GrpcStatusCode,
    pub message: String,
}

impl GrpcStatusError {
    pub fn new(code: GrpcStatusCode, message: impl Into<String>) -> Self {
        GrpcStatusError {
            code,
            message: message.into(),
        }
    }

    fn from_result(r: &NwpResult) -> Self {
        let status = r.nps_status.clone().unwrap_or_default();
        GrpcStatusError {
            code: error_map::to_grpc_status(&status),
            message: format!(
                "{status} {}: {}",
                r.nwp_error.clone().unwrap_or_default(),
                r.message.clone().unwrap_or_default()
            ),
        }
    }
}

// ── The service ──────────────────────────────────────────────────────────────

pub struct GrpcInboundService {
    options: BridgeInboundOptions,
}

impl GrpcInboundService {
    pub fn new(options: BridgeInboundOptions) -> Self {
        GrpcInboundService { options }
    }

    pub fn options(&self) -> &BridgeInboundOptions {
        &self.options
    }

    fn direction_gate(&self) -> Result<(), GrpcStatusError> {
        if self.options.serves_inbound("grpc") {
            return Ok(());
        }
        Err(GrpcStatusError::new(
            GrpcStatusCode::Unimplemented,
            format!(
                "NPS-SERVER-UNSUPPORTED {}: this Bridge Node does not declare \"grpc\" in \
                 bridge_inbound_protocols.",
                error_codes::BRIDGE_DIRECTION_UNSUPPORTED
            ),
        ))
    }

    /// If `ctx.upstream` is empty **and exactly one** backend is configured, use
    /// it; otherwise match `descriptor.name` case-insensitively.
    async fn resolve_backend(
        &self,
        ctx: &UpstreamContext,
    ) -> Result<Arc<dyn NwpBackend>, GrpcStatusError> {
        if ctx.upstream.trim().is_empty() && self.options.backends.len() == 1 {
            return Ok(self.options.backends[0].clone());
        }
        for b in &self.options.backends {
            if b.descriptor()
                .await
                .name
                .eq_ignore_ascii_case(ctx.upstream.trim())
            {
                return Ok(b.clone());
            }
        }
        Err(GrpcStatusError::new(
            GrpcStatusCode::NotFound,
            format!(
                "NPS-CLIENT-NOT-FOUND {}: no NWP node named '{}' is fronted by this Bridge Node.",
                error_codes::BRIDGE_SERVER_TOOL_NOT_FOUND,
                ctx.upstream
            ),
        ))
    }

    pub async fn get_manifest(
        &self,
        ctx: &UpstreamContext,
    ) -> Result<ManifestResponse, GrpcStatusError> {
        self.direction_gate()?;
        let b = self.resolve_backend(ctx).await?;
        let d = b.descriptor().await;
        let r = b.manifest().await;
        if !r.ok {
            return Err(GrpcStatusError::from_result(&r));
        }
        Ok(ManifestResponse {
            nwm_json: serde_json::to_vec(&r.payload.unwrap_or(Value::Null)).unwrap_or_default(),
            node_type: d.role.wire().to_string(),
        })
    }

    pub async fn invoke(
        &self,
        ctx: &UpstreamContext,
        action_id: &str,
        params_json: &[u8],
    ) -> Result<InvokeResponse, GrpcStatusError> {
        self.direction_gate()?;
        if action_id.trim().is_empty() {
            return Err(GrpcStatusError::new(
                GrpcStatusCode::InvalidArgument,
                "action_id is required",
            ));
        }
        let b = self.resolve_backend(ctx).await?;
        let params: Option<Value> = if params_json.is_empty() {
            None
        } else {
            serde_json::from_slice(params_json).ok()
        };
        // The unary RPC is always synchronous.
        let r = b.invoke(action_id, params, false).await;
        if !r.ok {
            return Err(GrpcStatusError::from_result(&r));
        }
        let payload = r.payload.unwrap_or(Value::Null);
        let task_id = payload
            .get("task_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok(InvokeResponse {
            http_status: 200,
            body_json: serde_json::to_vec(&payload).unwrap_or_default(),
            task_id,
        })
    }

    pub async fn query(
        &self,
        ctx: &UpstreamContext,
        query_json: &[u8],
    ) -> Result<QueryResponse, GrpcStatusError> {
        self.direction_gate()?;
        let b = self.resolve_backend(ctx).await?;
        // An empty request body means `{}`.
        let query: Value = if query_json.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(query_json).unwrap_or_else(|_| json!({}))
        };
        let r = b.query(query).await;
        if !r.ok {
            return Err(GrpcStatusError::from_result(&r));
        }
        Ok(QueryResponse {
            http_status: 200,
            body_json: serde_json::to_vec(&r.payload.unwrap_or(Value::Null)).unwrap_or_default(),
        })
    }

    pub async fn list_actions(
        &self,
        ctx: &UpstreamContext,
    ) -> Result<ActionsResponse, GrpcStatusError> {
        self.direction_gate()?;
        let b = self.resolve_backend(ctx).await?;
        let mut map = serde_json::Map::new();
        for a in b.actions().await {
            map.insert(a.action_id.clone(), json!({ "description": a.description }));
        }
        Ok(ActionsResponse {
            actions_json: serde_json::to_vec(&json!({ "actions": map })).unwrap_or_default(),
        })
    }
}
