// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! ACME wire constants (RFC 8555 + NPS-RFC-0002 §4.4).

pub const CONTENT_TYPE_JOSE_JSON: &str = "application/jose+json";
pub const CONTENT_TYPE_PROBLEM:   &str = "application/problem+json";
pub const CONTENT_TYPE_PEM_CERT:  &str = "application/pem-certificate-chain";

pub const CHALLENGE_AGENT_01:  &str = "agent-01";
pub const IDENTIFIER_TYPE_NID: &str = "nid";

// ACME status enumeration values (RFC 8555 §7.1.6).
pub const STATUS_PENDING:     &str = "pending";
pub const STATUS_READY:       &str = "ready";
pub const STATUS_PROCESSING:  &str = "processing";
pub const STATUS_VALID:       &str = "valid";
pub const STATUS_INVALID:     &str = "invalid";
pub const STATUS_EXPIRED:     &str = "expired";
pub const STATUS_DEACTIVATED: &str = "deactivated";
pub const STATUS_REVOKED:     &str = "revoked";
