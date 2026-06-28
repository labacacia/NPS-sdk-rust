// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod dns_txt;
pub mod error_codes;
pub mod federation;
pub mod frames;
pub mod registry;
pub mod validator;

pub use federation::{
    append_forwarded_by, parse_forwarded_by, FORWARDED_BY_HEADER, MAX_FEDERATION_HOPS,
};
pub use frames::{AnnounceFrame, GraphEdge, GraphFrame, GraphNode, ResolveFrame};
pub use registry::{InMemoryNdpRegistry, ResolveResult};
pub use validator::{NdpAnnounceResult, NdpAnnounceValidator};
