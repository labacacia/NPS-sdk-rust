// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Stateless Bridge Node dispatcher facade.

use nps_ncp::CapsFrame;

use super::dispatcher::BridgeDispatcherRegistry;
use super::error::BridgeDispatchError;
use super::target::bridge_target_from_action_frame;
use crate::frames::ActionFrame;

/// Stateless Bridge Node dispatcher facade. Host transports feed decoded
/// [`ActionFrame`] values here and write the returned [`CapsFrame`].
#[derive(Clone)]
pub struct BridgeNode {
    dispatchers: BridgeDispatcherRegistry,
}

impl BridgeNode {
    /// Create a Bridge Node facade over a dispatcher registry.
    pub fn new(dispatchers: BridgeDispatcherRegistry) -> Self {
        Self { dispatchers }
    }

    /// The dispatcher registry backing this node.
    pub fn registry(&self) -> &BridgeDispatcherRegistry {
        &self.dispatchers
    }

    /// Parse `bridge_target`, resolve a protocol dispatcher, and invoke it.
    pub async fn dispatch(&self, frame: &ActionFrame) -> Result<CapsFrame, BridgeDispatchError> {
        let target = bridge_target_from_action_frame(frame)?;
        let dispatcher = self.dispatchers.resolve(&target.protocol)?;
        dispatcher.dispatch(frame, &target).await
    }
}
