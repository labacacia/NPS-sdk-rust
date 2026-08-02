// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP v0.20 transport-independent Node and Bridge server decisions.

use nps_core::status_codes;
use serde::{Deserialize, Serialize};

use crate::{complex_server, error_codes, http_headers};

/// Serving transport for the portable Node profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NwpServerTransport {
    Http,
    Native,
}

/// Operative Node role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NwpPortableNodeRole {
    Memory,
    Action,
    Complex,
}

/// Input to portable Node admission.
#[derive(Debug, Clone, Deserialize)]
pub struct NwpPortableNodeRequest {
    pub transport: NwpServerTransport,
    pub node_role: NwpPortableNodeRole,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub accept: Option<String>,
    #[serde(default)]
    pub body_bytes: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: u64,
    #[serde(default)]
    pub frame_kind: Option<String>,
    #[serde(default = "default_true")]
    pub body_valid: bool,
    #[serde(default)]
    pub cancelled: bool,
    #[serde(default)]
    pub correlation_id: Option<String>,
}

/// Terminal portable Node decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NwpPortableNodeDecision {
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allow: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_frame: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub telemetry_outcome: &'static str,
    pub legacy_media_type_accepted: bool,
}

/// Evaluate admission without reading a stream or invoking a provider.
pub fn evaluate_portable_node(request: &NwpPortableNodeRequest) -> NwpPortableNodeDecision {
    if request.cancelled {
        return node_result(request, "abort", "cancelled");
    }
    match request.transport {
        NwpServerTransport::Native => evaluate_native_node(request),
        NwpServerTransport::Http => evaluate_http_node(request),
    }
}

fn evaluate_http_node(request: &NwpPortableNodeRequest) -> NwpPortableNodeDecision {
    let path = lower(request.path.as_deref());
    let method = request
        .method
        .as_deref()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if path == "/.nwm" {
        if method != "GET" {
            return method_not_allowed(request, "GET");
        }
        return NwpPortableNodeDecision {
            http_status: Some(200),
            content_type: Some(http_headers::MIME_MANIFEST),
            ..node_result(request, "serve_manifest", "success")
        };
    }
    if path != "/query" && path != "/invoke" {
        return node_reject(
            request,
            404,
            status_codes::NPS_CLIENT_NOT_FOUND,
            error_codes::HTTP_FRAME_BODY_MALFORMED,
        );
    }
    if method != "POST" {
        return method_not_allowed(request, "POST");
    }

    let media_type = base_media_type(request.content_type.as_deref());
    let legacy = media_type == http_headers::MIME_LEGACY_FRAME;
    if !legacy && media_type != http_headers::MIME_FRAME {
        return node_reject(
            request,
            400,
            status_codes::NPS_CLIENT_BAD_FRAME,
            error_codes::HTTP_CONTENT_TYPE_UNSUPPORTED,
        );
    }
    if !accepts(request.accept.as_deref(), http_headers::MIME_CAPSULE) {
        return node_reject(
            request,
            400,
            status_codes::NPS_CLIENT_BAD_PARAM,
            error_codes::HTTP_ACCEPT_UNSATISFIABLE,
        );
    }
    assert!(
        request.max_body_bytes > 0,
        "max_body_bytes must be positive"
    );
    if request.body_bytes > request.max_body_bytes {
        return node_reject(
            request,
            413,
            status_codes::NPS_LIMIT_PAYLOAD,
            error_codes::HTTP_BODY_TOO_LARGE,
        );
    }
    if !request.body_valid {
        return node_reject(
            request,
            400,
            status_codes::NPS_CLIENT_BAD_FRAME,
            error_codes::HTTP_FRAME_BODY_MALFORMED,
        );
    }

    let frame_kind = lower(request.frame_kind.as_deref());
    let query = path == "/query"
        && matches!(
            request.node_role,
            NwpPortableNodeRole::Memory | NwpPortableNodeRole::Complex
        )
        && frame_kind == "query";
    let action = path == "/invoke"
        && matches!(
            request.node_role,
            NwpPortableNodeRole::Action | NwpPortableNodeRole::Complex
        )
        && frame_kind == "action";
    if !query && !action {
        return node_reject(
            request,
            400,
            status_codes::NPS_CLIENT_BAD_FRAME,
            error_codes::HTTP_FRAME_BODY_MALFORMED,
        );
    }
    NwpPortableNodeDecision {
        http_status: Some(200),
        content_type: Some(http_headers::MIME_CAPSULE),
        legacy_media_type_accepted: legacy,
        ..node_result(
            request,
            if query {
                "dispatch_query"
            } else {
                "dispatch_action"
            },
            "success",
        )
    }
}

fn evaluate_native_node(request: &NwpPortableNodeRequest) -> NwpPortableNodeDecision {
    let frame_kind = lower(request.frame_kind.as_deref());
    let query = frame_kind == "query"
        && matches!(
            request.node_role,
            NwpPortableNodeRole::Memory | NwpPortableNodeRole::Complex
        );
    let action = frame_kind == "action"
        && matches!(
            request.node_role,
            NwpPortableNodeRole::Action | NwpPortableNodeRole::Complex
        );
    if request.body_valid && (query || action) {
        return NwpPortableNodeDecision {
            response_frame: Some("caps"),
            ..node_result(
                request,
                if query {
                    "dispatch_query"
                } else {
                    "dispatch_action"
                },
                "success",
            )
        };
    }
    NwpPortableNodeDecision {
        status: Some(status_codes::NPS_CLIENT_BAD_FRAME),
        error: Some("NWP-NATIVE-FRAME-UNSUPPORTED".into()),
        response_frame: Some("error"),
        ..node_result(request, "error_frame", "rejected")
    }
}

fn method_not_allowed(
    request: &NwpPortableNodeRequest,
    allowed_method: &'static str,
) -> NwpPortableNodeDecision {
    NwpPortableNodeDecision {
        http_status: Some(405),
        allow: Some(allowed_method),
        ..node_result(request, "reject", "rejected")
    }
}

fn node_reject(
    request: &NwpPortableNodeRequest,
    http_status: u16,
    status: &'static str,
    error: &'static str,
) -> NwpPortableNodeDecision {
    NwpPortableNodeDecision {
        http_status: Some(http_status),
        content_type: Some(http_headers::MIME_ERROR),
        status: Some(status),
        error: Some(error.into()),
        ..node_result(request, "reject", "rejected")
    }
}

fn node_result(
    request: &NwpPortableNodeRequest,
    decision: &'static str,
    telemetry_outcome: &'static str,
) -> NwpPortableNodeDecision {
    NwpPortableNodeDecision {
        decision,
        http_status: None,
        content_type: None,
        status: None,
        error: None,
        allow: None,
        response_frame: None,
        correlation_id: request.correlation_id.clone(),
        telemetry_outcome,
        legacy_media_type_accepted: false,
    }
}

/// Input to portable outbound Bridge preflight.
#[derive(Debug, Clone, Deserialize)]
pub struct BridgeLifecycleRequest {
    pub protocol: String,
    pub endpoint: String,
    pub registered_protocols: Vec<String>,
    #[serde(default = "default_true")]
    pub allow_http: bool,
    #[serde(default = "default_true")]
    pub reject_private: bool,
    #[serde(default)]
    pub allowed_prefixes: Vec<String>,
    pub timeout_ms: u64,
    #[serde(default)]
    pub elapsed_ms: u64,
    #[serde(default)]
    pub cancelled: bool,
    #[serde(default)]
    pub correlation_id: Option<String>,
    #[serde(default = "default_task_mode")]
    pub task_mode: String,
}

/// Terminal outbound Bridge lifecycle decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BridgeLifecycleDecision {
    pub decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_mode: Option<&'static str>,
    pub telemetry_outcome: &'static str,
}

/// Evaluate target, dispatcher, endpoint, cancellation, and deadline.
pub fn evaluate_bridge_lifecycle(request: &BridgeLifecycleRequest) -> BridgeLifecycleDecision {
    if request.cancelled {
        return bridge_result(request, "abort", "cancelled");
    }
    if request.protocol.trim().is_empty() || request.endpoint.trim().is_empty() {
        return BridgeLifecycleDecision {
            http_status: Some(422),
            status: Some(status_codes::NPS_CLIENT_UNPROCESSABLE),
            error: Some(error_codes::BRIDGE_TARGET_INVALID.into()),
            ..bridge_result(request, "reject", "rejected")
        };
    }
    if !request
        .registered_protocols
        .iter()
        .any(|value| value.eq_ignore_ascii_case(&request.protocol))
    {
        return BridgeLifecycleDecision {
            http_status: Some(501),
            status: Some(status_codes::NPS_SERVER_UNSUPPORTED),
            error: Some(error_codes::BRIDGE_PROTOCOL_UNSUPPORTED.into()),
            ..bridge_result(request, "reject", "rejected")
        };
    }

    if complex_server::validate_child_url(
        &request.endpoint,
        &request.allowed_prefixes,
        request.reject_private,
        request.allow_http,
    )
    .is_some()
    {
        return BridgeLifecycleDecision {
            http_status: Some(422),
            status: Some(status_codes::NPS_CLIENT_UNPROCESSABLE),
            error: Some(error_codes::BRIDGE_ENDPOINT_INVALID.into()),
            ..bridge_result(request, "reject", "rejected")
        };
    }

    assert!(request.timeout_ms > 0, "timeout_ms must be positive");
    if request.elapsed_ms >= request.timeout_ms {
        return BridgeLifecycleDecision {
            http_status: Some(504),
            status: Some(status_codes::NPS_SERVER_TIMEOUT),
            error: Some(error_codes::BRIDGE_UPSTREAM_FAILED.into()),
            ..bridge_result(request, "reject", "timeout")
        };
    }

    let task_mode = if request.task_mode.eq_ignore_ascii_case("async") {
        "async"
    } else {
        "sync"
    };
    BridgeLifecycleDecision {
        status: Some(if task_mode == "async" {
            status_codes::NPS_OK_ACCEPTED
        } else {
            status_codes::NPS_OK
        }),
        task_mode: Some(task_mode),
        ..bridge_result(request, "dispatch", "success")
    }
}

fn bridge_result(
    request: &BridgeLifecycleRequest,
    decision: &'static str,
    telemetry_outcome: &'static str,
) -> BridgeLifecycleDecision {
    BridgeLifecycleDecision {
        decision,
        http_status: None,
        status: None,
        error: None,
        correlation_id: request.correlation_id.clone(),
        task_mode: None,
        telemetry_outcome,
    }
}

fn base_media_type(value: Option<&str>) -> String {
    value
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

fn accepts(value: Option<&str>, response_type: &str) -> bool {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return true;
    };
    value.split(',').any(|item| {
        matches!(
            base_media_type(Some(item)).as_str(),
            "*/*" | "application/*"
        ) || base_media_type(Some(item)) == response_type
    })
}

fn lower(value: Option<&str>) -> String {
    value.unwrap_or_default().to_ascii_lowercase()
}

fn default_true() -> bool {
    true
}

fn default_max_body_bytes() -> u64 {
    1024 * 1024
}

fn default_task_mode() -> String {
    "sync".into()
}
