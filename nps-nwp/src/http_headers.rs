// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP HTTP header and MIME constants (port of .NET `NwpHttpHeaders`).
//! Header names are matched case-insensitively on the wire.

// Request headers
pub const AGENT: &str = "X-NWP-Agent";
pub const BUDGET: &str = "X-NWP-Budget";
pub const IDENT: &str = "X-NWP-Ident";
pub const CAPABILITIES: &str = "X-NWP-Capabilities";
pub const DEPTH: &str = "X-NWP-Depth";
pub const ENCODING: &str = "X-NWP-Encoding";
pub const TOKENIZER: &str = "X-NWP-Tokenizer";

// Response headers
pub const SCHEMA: &str = "X-NWP-Schema";
pub const TOKENS: &str = "X-NWP-Tokens";
pub const TOKENS_NATIVE: &str = "X-NWP-Tokens-Native";
pub const TOKENIZER_USED: &str = "X-NWP-Tokenizer-Used";
pub const CACHED: &str = "X-NWP-Cached";
pub const NODE_TYPE: &str = "X-NWP-Node-Type";
pub const REQUEST_ID: &str = "X-NWP-Request-Id";
pub const REPUTATION_STATUS: &str = "X-NWP-Reputation-Status";
pub const BAN_EXPIRES: &str = "X-NWP-Ban-Expires";

// MIME types
pub const MIME_FRAME: &str = "application/nwp-frame";
pub const MIME_LEGACY_FRAME: &str = "application/x-nps-frame";
pub const MIME_CAPSULE: &str = "application/nwp-capsule";
pub const MIME_ERROR: &str = "application/nwp-error+json";
pub const MIME_MANIFEST: &str = "application/nwp-manifest+json";
