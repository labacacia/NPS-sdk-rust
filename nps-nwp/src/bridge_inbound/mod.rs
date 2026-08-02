// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Inbound Bridge servers (NPS-CR-0010) — foreign client → NPS.
//!
//! The mirror image of [`crate::bridge`], which describes the OUTBOUND
//! direction (NPS → foreign protocol). A plain MCP / A2A / gRPC client with no
//! NPS knowledge reaches an NPS node through here:
//!
//! ```text
//! foreign client
//!   → transport        (/mcp, /mcp/sse, /a2a, /.well-known/agent.json; or gRPC; or stdio)
//!   → auth gate        (X-NWP-Agent NID syntax + verifier)
//!   → body limit       → JSON-RPC deserialize
//!   → direction gate   (options.serves_inbound(protocol))
//!   → protocol server  (mcp / a2a / grpc)
//!   → name resolution  (re-encode-and-compare; bare-id fallback)
//!   → NwpBackend::invoke / query      [dispatch timeout applies here]
//!        ├─ InProcess → ActionFrame / QueryFrame → local delegate
//!        └─ Http      → POST /invoke | /query → remote node
//!   → NwpResult (Ok | NpsStatus + NwpError + Message)
//!   → error_map (§16.3) → foreign-protocol success or error
//! ```
//!
//! A deployment running this as a plain hosting library, with no NID and no
//! Announce, is **not** a Bridge Node — it is the Bridge library. Only a
//! deployment issuing an Announce with `node_roles: ["bridge"]` is bound by the
//! §16 MUSTs.
//!
//! # Naming
//!
//! Like [`crate::bridge`], this module is **not** re-exported at the crate root:
//! consumers write `nps_nwp::bridge_inbound::McpInboundServer`. That keeps the
//! two halves of the Bridge feature symmetric, and keeps deliberately generic
//! names (`backend`, `options`, `server`, `jsonrpc`, `error_map`, `NwpResult`)
//! out of a crate root that already has `client`, `frames` and `error_codes`.
//! Everything public is re-exported from *this* module, so one `use` line is
//! enough. The `nps-sdk` facade re-exports whole crates
//! (`pub use nps_nwp as nwp;`), so `nps_sdk::nwp::bridge_inbound::…` resolves
//! with no facade change.

pub mod a2a;
pub mod backend;
pub mod error_map;
pub mod grpc;
pub mod jsonrpc;
pub mod mcp;
pub mod options;
pub mod server;
pub mod tool_name;

pub use a2a::A2aInboundServer;
pub use backend::{
    open_object_schema, ActionDispatcher, BridgeDispatchError, HttpNwpBackend, InProcessNwpBackend,
    NwpActionDescriptor, NwpBackend, NwpNodeDescriptor, NwpNodeRole, NwpResult, NwpUpstream,
    QueryDispatcher,
};
pub use error_map::GrpcStatusCode;
pub use grpc::{GrpcInboundService, GrpcStatusError, UpstreamContext};
pub use jsonrpc::{BridgeJsonRpcError, BridgeJsonRpcRequest, BridgeJsonRpcResponse};
pub use mcp::{McpInboundServer, REQUIRED_METHODS};
pub use options::BridgeInboundOptions;
pub use server::{BridgeInboundApp, BridgeServerOptions};
