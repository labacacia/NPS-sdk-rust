// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Frame → JSON helpers for inbound Bridge server adapters.

use serde_json::{json, Value};

use nps_ncp::CapsFrame;

/// A frame payload produced by a local NPS action dispatch — either a success
/// `CapsFrame` or an error envelope in the `.NET ErrorFrame` wire shape
/// (`{ status, error, message }`).
#[derive(Debug, Clone)]
pub enum BridgeFrame {
    /// Successful action result.
    Caps(CapsFrame),
    /// Error envelope: NPS status, NWP error code, message.
    Error {
        status: String,
        error: String,
        message: String,
    },
}

impl BridgeFrame {
    /// Whether this frame carries an error.
    pub fn is_error(&self) -> bool {
        matches!(self, BridgeFrame::Error { .. })
    }

    /// Serialize this frame to a JSON element matching the .NET wire shape.
    pub fn to_element(&self) -> Value {
        match self {
            BridgeFrame::Caps(caps) => Value::Object(caps.to_dict()),
            BridgeFrame::Error {
                status,
                error,
                message,
            } => json!({
                "status": status,
                "error": error,
                "message": message,
            }),
        }
    }

    /// Serialize this frame to a compact JSON string.
    pub fn to_json_string(&self) -> String {
        serde_json::to_string(&self.to_element()).unwrap_or_else(|_| "{}".to_string())
    }

    /// Error text used for A2A failure messages.
    pub fn error_text(&self) -> String {
        match self {
            BridgeFrame::Error { message, error, .. } => {
                if message.is_empty() {
                    error.clone()
                } else {
                    message.clone()
                }
            }
            BridgeFrame::Caps(_) => "NPS action failed.".to_string(),
        }
    }
}
