// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent inbound Bridge options.
//!
//! **Layering rule**: [`BridgeInboundOptions`] (backends, declared protocols,
//! server identity) is a *separate type* from the hosting options
//! ([`crate::bridge_inbound::server::BridgeServerOptions`]: paths, verifier,
//! limits). The protocol servers are written against this base type only, so
//! they never touch a request context and can be driven from stdio or a unit
//! test with no web host.

use std::sync::Arc;

use super::backend::NwpBackend;

/// The declared inbound protocol set — the NDP `bridge_inbound_protocols` value.
///
/// **Default `["mcp","a2a"]`**: gRPC is NOT in the default set, so the gRPC
/// service refuses until `"grpc"` is added explicitly.
pub fn default_inbound_protocols() -> Vec<String> {
    vec!["mcp".to_string(), "a2a".to_string()]
}

pub struct BridgeInboundOptions {
    /// Nodes this Bridge fronts.
    pub backends: Vec<Arc<dyn NwpBackend>>,
    /// NDP `bridge_inbound_protocols`. Absent/empty means an outbound-only
    /// Bridge Node, which serves no inbound protocol at all.
    pub inbound_protocols: Vec<String>,
    /// Also advertised as `bridge_protocols` — the outbound set. Independent of
    /// `inbound_protocols` over the same value domain; carried here only so the
    /// direction-refusal `hint` can name both declared arrays.
    pub outbound_protocols: Vec<String>,
    pub server_name: String,
    pub server_version: String,
    /// Rows per `resources/read`.
    pub resource_read_limit: u32,
    /// Advertised on the A2A AgentCard, so it is part of the protocol surface,
    /// not merely host config.
    pub require_auth: bool,
}

impl Default for BridgeInboundOptions {
    fn default() -> Self {
        BridgeInboundOptions {
            backends: Vec::new(),
            inbound_protocols: default_inbound_protocols(),
            outbound_protocols: Vec::new(),
            server_name: "nps-bridge-server".to_string(),
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            resource_read_limit: 100,
            require_auth: true,
        }
    }
}

impl BridgeInboundOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_backend(mut self, b: Arc<dyn NwpBackend>) -> Self {
        self.backends.push(b);
        self
    }

    pub fn with_inbound_protocols(mut self, p: Vec<String>) -> Self {
        self.inbound_protocols = p;
        self
    }

    pub fn with_outbound_protocols(mut self, p: Vec<String>) -> Self {
        self.outbound_protocols = p;
        self
    }

    /// Case-insensitive membership test over the declared inbound set
    /// (NWP §16.1.2 MUST-5).
    pub fn serves_inbound(&self, protocol: &str) -> bool {
        self.inbound_protocols
            .iter()
            .any(|p| p.eq_ignore_ascii_case(protocol))
    }

    /// Both declared arrays, for the `hint` a direction refusal SHOULD carry.
    pub fn direction_hint(&self) -> serde_json::Value {
        serde_json::json!({
            "bridge_protocols":         self.outbound_protocols,
            "bridge_inbound_protocols": self.inbound_protocols,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grpc_is_not_in_the_default_inbound_set() {
        let o = BridgeInboundOptions::default();
        assert!(o.serves_inbound("mcp"));
        assert!(o.serves_inbound("a2a"));
        assert!(!o.serves_inbound("grpc"));
        assert!(!o.serves_inbound("http"));
    }

    #[test]
    fn membership_is_case_insensitive() {
        let o = BridgeInboundOptions::default().with_inbound_protocols(vec!["MCP".into()]);
        assert!(o.serves_inbound("mcp"));
        assert!(o.serves_inbound("McP"));
    }

    #[test]
    fn empty_set_serves_nothing() {
        let o = BridgeInboundOptions::default().with_inbound_protocols(vec![]);
        for p in ["mcp", "a2a", "grpc", "http"] {
            assert!(!o.serves_inbound(p));
        }
    }

    #[test]
    fn direction_hint_names_both_declared_arrays() {
        let o = BridgeInboundOptions::default()
            .with_inbound_protocols(vec!["mcp".into()])
            .with_outbound_protocols(vec!["http".into()]);
        let h = o.direction_hint();
        assert_eq!(h["bridge_inbound_protocols"], serde_json::json!(["mcp"]));
        assert_eq!(h["bridge_protocols"], serde_json::json!(["http"]));
    }
}
