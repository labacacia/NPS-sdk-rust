// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP Bridge Node subsystem (NPS-2 §2A, NPS-CR-0001).
//!
//! A Bridge Node is a stateless translator between NPS frames and non-NPS
//! protocols. This module carries both directions:
//!
//! * **Outbound (NPS → external):** [`BridgeNode`] parses `bridge_target`, resolves a
//!   protocol [`BridgeDispatcher`] from a [`BridgeDispatcherRegistry`], and invokes it.
//!   Built-in dispatchers cover HTTP/HTTPS ([`HttpBridgeDispatcher`]), gRPC-JSON over
//!   HTTP ([`GrpcBridgeDispatcher`]), MCP JSON-RPC ([`McpBridgeDispatcher`]), and A2A
//!   JSON-RPC ([`A2aBridgeDispatcher`]). Every dispatcher speaks JSON / JSON-RPC over
//!   HTTP via `reqwest` — there is no native gRPC/protobuf transport.
//! * **Inbound (external → NPS):** [`McpServerBridge`] and [`A2aServerBridge`] translate
//!   inbound MCP/A2A JSON-RPC into local NWP action dispatch, wired to a framework-agnostic
//!   [`BridgeServerMiddleware`] / [`BridgeNodeMiddleware`] `handle()` shape.

mod dispatcher;
mod dispatchers;
mod endpoint;
mod error;
mod frame_json;
mod jsonrpc;
mod node;
mod node_middleware;
mod server_a2a;
mod server_mcp;
mod server_middleware;
mod server_options;
mod target;
mod types;

pub use dispatcher::{BridgeDispatcher, BridgeDispatcherRegistry};
pub use dispatchers::{
    A2aBridgeDispatcher, GrpcBridgeDispatcher, HttpBridgeDispatcher, JsonRpcBridgeDispatcher,
    McpBridgeDispatcher,
};
pub use endpoint::parse_http_endpoint;
pub use error::{bridge_error_codes, BridgeDispatchError};
pub use frame_json::BridgeFrame;
pub use jsonrpc::{
    bridge_jsonrpc_error_codes, BridgeJsonRpcError, BridgeJsonRpcRequest, BridgeJsonRpcResponse,
};
pub use node::BridgeNode;
pub use node_middleware::{BridgeNodeMiddleware, BridgeNodeOptions};
pub use server_a2a::A2aServerBridge;
pub use server_a2a::{
    A2aAgentAuthentication, A2aAgentCapabilities, A2aAgentCard, A2aAgentProvider, A2aAgentSkill,
    A2aArtifact, A2aMessage, A2aPart, A2aSendTaskParams, A2aTask, A2aTaskStatus,
    A2A_SERVER_VERSION, A2A_TASK_STATE_COMPLETED, A2A_TASK_STATE_FAILED,
};
pub use server_mcp::McpServerBridge;
pub use server_mcp::{
    McpContent, McpInitializeResult, McpServerCapabilities, McpServerInfo, McpTool,
    McpToolCallParams, McpToolCallResult, McpToolCapabilities, McpToolListResult,
    MCP_SERVER_VERSION,
};
pub use server_middleware::{BridgeServerMiddleware, BridgeServerResult};
pub use server_options::{
    BridgeServerAction, BridgeServerActionInvoker, BridgeServerOptions, DispatcherResult,
    LocalActionDispatcher,
};
pub use target::{
    bridge_target_from_action_frame, bridge_target_from_json, target_get_json, target_get_string,
};
pub use types::{bridge_protocols, BridgeNodeDescriptor, BridgeTarget, NODE_TYPE_BRIDGE};
