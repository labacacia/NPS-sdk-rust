// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Bridge dispatcher trait and in-memory registry.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use nps_ncp::CapsFrame;

use super::error::{bridge_error_codes, BridgeDispatchError};
use super::types::BridgeTarget;
use crate::frames::ActionFrame;

/// Boxed future returned by [`BridgeDispatcher::dispatch`].
pub type DispatchFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CapsFrame, BridgeDispatchError>> + Send + 'a>>;

/// Translates one NWP action invocation into a concrete non-NPS protocol call.
pub trait BridgeDispatcher: Send + Sync {
    /// Bridge protocol identifier served by this dispatcher.
    fn protocol(&self) -> &str;

    /// Dispatch an action frame to the requested external target.
    fn dispatch<'a>(
        &'a self,
        frame: &'a ActionFrame,
        target: &'a BridgeTarget,
    ) -> DispatchFuture<'a>;
}

/// In-memory registry mapping bridge protocol identifiers to dispatchers.
#[derive(Clone, Default)]
pub struct BridgeDispatcherRegistry {
    dispatchers: HashMap<String, Arc<dyn BridgeDispatcher>>,
}

impl BridgeDispatcherRegistry {
    /// Create an empty dispatcher registry.
    pub fn new() -> Self {
        Self {
            dispatchers: HashMap::new(),
        }
    }

    /// Create a registry with all built-in dispatchers over a shared HTTP client:
    /// HTTP/HTTPS, gRPC-JSON, MCP JSON-RPC, and A2A JSON-RPC.
    pub fn create_default(client: reqwest::Client) -> Self {
        use super::dispatchers::{
            A2aBridgeDispatcher, GrpcBridgeDispatcher, HttpBridgeDispatcher, McpBridgeDispatcher,
        };
        Self::new()
            .register(Arc::new(HttpBridgeDispatcher::new(client.clone())))
            .register(Arc::new(GrpcBridgeDispatcher::new(client.clone())))
            .register(Arc::new(McpBridgeDispatcher::new(client.clone())))
            .register(Arc::new(A2aBridgeDispatcher::new(client)))
    }

    /// The currently registered protocol identifiers (sorted).
    pub fn protocols(&self) -> Vec<String> {
        let mut out: Vec<String> = self.dispatchers.keys().cloned().collect();
        out.sort_by_key(|a| a.to_ascii_lowercase());
        out
    }

    /// Register or replace the dispatcher for its protocol. Protocol lookup is
    /// case-insensitive (keys are lower-cased).
    pub fn register(mut self, dispatcher: Arc<dyn BridgeDispatcher>) -> Self {
        let protocol = dispatcher.protocol().to_string();
        debug_assert!(
            !protocol.trim().is_empty(),
            "Bridge dispatcher protocol must not be empty."
        );
        self.dispatchers
            .insert(protocol.to_ascii_lowercase(), dispatcher);
        self
    }

    /// Resolve a dispatcher for `protocol`.
    pub fn resolve(
        &self,
        protocol: &str,
    ) -> Result<Arc<dyn BridgeDispatcher>, BridgeDispatchError> {
        if protocol.trim().is_empty() {
            return Err(BridgeDispatchError::new(
                bridge_error_codes::TARGET_INVALID,
                "bridge_target.protocol is required.",
            ));
        }

        self.dispatchers
            .get(&protocol.to_ascii_lowercase())
            .cloned()
            .ok_or_else(|| {
                BridgeDispatchError::new(
                    bridge_error_codes::PROTOCOL_UNSUPPORTED,
                    format!("Bridge protocol '{protocol}' is not registered."),
                )
            })
    }
}
