// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP Bridge Node type definitions (NPS-2 §2A, NPS-CR-0001).

/// NWM node_type wire value for Bridge Node.
pub const NODE_TYPE_BRIDGE: &str = "bridge";

/// Standard bridge_protocols wire-string constants.
pub mod bridge_protocols {
    pub const HTTP: &str = "http";
    pub const GRPC: &str = "grpc";
    pub const MCP: &str = "mcp";
    pub const A2A: &str = "a2a";
    pub const STANDARD: &[&str] = &[HTTP, GRPC, MCP, A2A];
}

/// Declares which external protocols a Bridge Node bridges, in each direction.
///
/// - `supported_protocols` → `Announce.bridge_protocols` (OUTBOUND: NPS → external)
/// - `inbound_protocols` → `Announce.bridge_inbound_protocols` (INBOUND: external → NPS)
///
/// An empty `inbound_protocols` means the node exposes no inbound surface — an
/// outbound-only Bridge Node, the only kind that existed through alpha.15. A Bridge Node
/// MUST have at least one of the two non-empty. (NPS-CR-0010)
#[derive(Debug, Clone)]
pub struct BridgeNodeDescriptor {
    pub nid: String,
    pub supported_protocols: Vec<String>,
    pub inbound_protocols: Vec<String>,
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
            inbound_protocols: vec![],
        };
        assert_eq!(d.nid, "urn:nps:node:ex.com:b");
        assert_eq!(d.supported_protocols.len(), 2);
        assert!(d.inbound_protocols.is_empty());
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
