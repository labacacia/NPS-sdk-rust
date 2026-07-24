// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP Bridge Node type definitions (NPS-2 §2A, NPS-CR-0001).

/// NWM node_type wire value for Bridge Node.
pub const NODE_TYPE_BRIDGE: &str = "bridge";

/// Standard bridge_protocols wire-string constants.
pub mod bridge_protocols {
    /// HTTP / HTTPS, REST + streaming.
    pub const HTTP: &str = "http";
    /// gRPC (transported as gRPC-JSON over HTTP here).
    pub const GRPC: &str = "grpc";
    /// Model Context Protocol.
    pub const MCP: &str = "mcp";
    /// Agent-to-Agent (Google A2A v0.2).
    pub const A2A: &str = "a2a";
    /// The full set of standard targets.
    pub const STANDARD: &[&str] = &[HTTP, GRPC, MCP, A2A];
    /// Protocols with built-in dispatchers in this package.
    pub const BUILT_IN: &[&str] = &[HTTP, GRPC, MCP, A2A];
}

/// Declares which external protocols a Bridge Node deployment can reach.
#[derive(Debug, Clone)]
pub struct BridgeNodeDescriptor {
    pub nid: String,
    pub supported_protocols: Vec<String>,
}

/// Inbound parameter object for a bridge invocation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeTarget {
    pub protocol: String,
    pub endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extras: Option<std::collections::HashMap<String, serde_json::Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants() {
        assert_eq!(NODE_TYPE_BRIDGE, "bridge");
        assert_eq!(bridge_protocols::HTTP, "http");
        assert_eq!(bridge_protocols::GRPC, "grpc");
        assert_eq!(bridge_protocols::MCP, "mcp");
        assert_eq!(bridge_protocols::A2A, "a2a");
        assert_eq!(bridge_protocols::STANDARD.len(), 4);
    }

    #[test]
    fn bridge_node_descriptor() {
        let d = BridgeNodeDescriptor {
            nid: "urn:nps:node:ex.com:b".into(),
            supported_protocols: vec!["http".into(), "grpc".into()],
        };
        assert_eq!(d.nid, "urn:nps:node:ex.com:b");
        assert_eq!(d.supported_protocols.len(), 2);
    }

    #[test]
    fn bridge_target_roundtrip() {
        let bt = BridgeTarget {
            protocol: "http".into(),
            endpoint: "https://api.example.com".into(),
            extras: None,
        };
        let json = serde_json::to_string(&bt).unwrap();
        let back: BridgeTarget = serde_json::from_str(&json).unwrap();
        assert_eq!(back.protocol, "http");
    }
}
