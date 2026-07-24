// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Bridge dispatch error type and NWP error codes.

use std::fmt;

/// NWP-compatible error codes used by Bridge dispatchers and inbound servers.
pub mod bridge_error_codes {
    /// The invocation does not contain a valid `bridge_target`.
    pub const TARGET_INVALID: &str = "NWP-BRIDGE-TARGET-INVALID";
    /// The requested bridge protocol has no registered dispatcher.
    pub const PROTOCOL_UNSUPPORTED: &str = "NWP-BRIDGE-PROTOCOL-UNSUPPORTED";
    /// The target endpoint is invalid or disallowed.
    pub const ENDPOINT_INVALID: &str = "NWP-BRIDGE-ENDPOINT-INVALID";
    /// The external call failed or returned an unusable response.
    pub const UPSTREAM_FAILED: &str = "NWP-BRIDGE-UPSTREAM-FAILED";
    /// An inbound Bridge server request named a tool/action that is not exposed.
    pub const SERVER_TOOL_NOT_FOUND: &str = "NWP-BRIDGE-SERVER-TOOL-NOT-FOUND";
    /// An inbound Bridge server was not configured with a local action dispatcher.
    pub const SERVER_DISPATCHER_MISSING: &str = "NWP-BRIDGE-SERVER-DISPATCHER-MISSING";
    /// An inbound Bridge server local action dispatch failed unexpectedly.
    pub const SERVER_DISPATCH_FAILED: &str = "NWP-BRIDGE-SERVER-DISPATCH-FAILED";
}

/// Error raised when a Bridge Node cannot parse, route, or execute an invocation.
#[derive(Debug, Clone)]
pub struct BridgeDispatchError {
    /// NWP-compatible error code for the failed dispatch.
    pub error_code: String,
    /// Human-readable failure message.
    pub message: String,
}

impl BridgeDispatchError {
    /// Create a Bridge dispatch error.
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_code: error_code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for BridgeDispatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.error_code, self.message)
    }
}

impl std::error::Error for BridgeDispatchError {}
