// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod dns_txt;
pub mod error_codes;
pub mod federation;
pub mod frames;
pub mod registry;
pub mod registry_profile;
pub mod validator;

pub use federation::{
    append_forwarded_by, parse_forwarded_by, FORWARDED_BY_HEADER, MAX_FEDERATION_HOPS,
};
pub use frames::{AnnounceFrame, GraphEdge, GraphFrame, GraphNode, ResolveFrame};
pub use registry::{
    InMemoryNdpRegistry, NdpClusterResolution, NdpClusterSplitError, ResolveResult,
};
pub use registry_profile::{
    canonical_announce_json, verify_announce_signature, NdpClusterSelection, NdpRegistryAdmission,
    NdpRegistryDecision, NdpRegistryProfile,
};
pub use validator::{NdpAnnounceResult, NdpAnnounceValidator};
