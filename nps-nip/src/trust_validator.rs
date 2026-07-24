// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! TrustFrameValidator — basic open TrustFrame validator for self-hosted
//! deployments that pin trusted grantor anchors explicitly. Behavioural parity
//! with the .NET `NPS.NIP.Verification.TrustFrameValidator`.
//!
//! Checks frame shape, expiry, grantor/grantee membership, required capability
//! scope, and target node scope.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::error_codes;
use crate::frames::TrustFrame;
use crate::verifier::{fail, nwp_path_matches, ok, NipIdentVerifyResult};

/// Inputs for [`validate`].
#[derive(Debug, Default, Clone)]
pub struct TrustFrameValidationContext {
    /// Grantor CA NIDs that this node trusts as anchors.
    pub trusted_grantors: Vec<String>,
    /// The CA NID expected to be authorized by the TrustFrame.
    pub expected_grantee_ca: String,
    /// Capabilities required for the current request.
    pub required_capabilities: Vec<String>,
    /// Target NWP path required for the current request.
    pub target_node_path: Option<String>,
    /// Clock override for tests.
    pub as_of: Option<OffsetDateTime>,
}

/// Validate a [`TrustFrame`] against a [`TrustFrameValidationContext`].
pub fn validate(
    frame: &TrustFrame,
    context: &TrustFrameValidationContext,
) -> NipIdentVerifyResult {
    if frame.grantor_nid.trim().is_empty()
        || frame.grantee_ca.trim().is_empty()
        || frame.issued_at.trim().is_empty()
        || frame.expires_at.trim().is_empty()
        || frame.serial.trim().is_empty()
        || frame.signer_nid.trim().is_empty()
        || frame.signature.trim().is_empty()
        || frame.trust_scope.is_empty()
        || frame.nodes.is_empty()
    {
        return fail(
            3,
            error_codes::TRUST_FRAME_INVALID,
            "TrustFrame is missing grantor, grantee, issued_at, expires_at, serial, \
             signer_nid, signature, trust_scope, or nodes.",
        );
    }

    if OffsetDateTime::parse(&frame.issued_at, &Rfc3339).is_err() {
        return fail(
            3,
            error_codes::TRUST_FRAME_INVALID,
            format!("TrustFrame issued_at is not a valid timestamp: {}.", frame.issued_at),
        );
    }

    let expires_at = match OffsetDateTime::parse(&frame.expires_at, &Rfc3339) {
        Ok(t) => t,
        Err(_) => {
            return fail(
                3,
                error_codes::TRUST_FRAME_INVALID,
                format!(
                    "TrustFrame expires_at is not a valid timestamp: {}.",
                    frame.expires_at
                ),
            );
        }
    };

    let now = context.as_of.unwrap_or_else(OffsetDateTime::now_utc);
    if expires_at <= now {
        return fail(
            3,
            error_codes::TRUST_FRAME_EXPIRED,
            format!("TrustFrame expired at {}.", frame.expires_at),
        );
    }

    if !context.trusted_grantors.contains(&frame.grantor_nid) {
        return fail(
            3,
            error_codes::CERT_UNTRUSTED_ISSUER,
            format!(
                "TrustFrame grantor '{}' is not a trusted grantor.",
                frame.grantor_nid
            ),
        );
    }

    if frame.grantee_ca != context.expected_grantee_ca {
        return fail(
            3,
            error_codes::TRUST_FRAME_INVALID,
            format!(
                "TrustFrame grantee '{}' does not match expected CA '{}'.",
                frame.grantee_ca, context.expected_grantee_ca
            ),
        );
    }

    if !context.required_capabilities.is_empty() {
        let missing: Vec<&String> = context
            .required_capabilities
            .iter()
            .filter(|c| !frame.trust_scope.contains(c))
            .collect();
        if !missing.is_empty() {
            let list = missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return fail(
                5,
                error_codes::TRUST_FRAME_SCOPE_EXCEEDS_GRANTOR,
                format!("TrustFrame is missing required capabilities: {list}."),
            );
        }
    }

    if let Some(target) = context.target_node_path.as_deref() {
        let covered = frame
            .nodes
            .iter()
            .any(|pattern| nwp_path_matches(pattern, target));
        if !covered {
            return fail(
                6,
                error_codes::CERT_SCOPE_VIOLATION,
                format!(
                    "Target path '{target}' is not covered by the TrustFrame node scope."
                ),
            );
        }
    }

    ok()
}
