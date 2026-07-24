// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! CA service error type (mirror of the .NET `NipCaException`) plus the Tier-3
//! pending signal (`NipRaPending`).

/// A NIP CA operation failure carrying a wire error code (NPS-3 §9 /
/// NPS-CR-0005 §3). The `code` is one of the `crate::error_codes` constants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NipCaError {
    pub message: String,
    pub code: &'static str,
}

impl NipCaError {
    pub fn new(message: impl Into<String>, code: &'static str) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }
}

impl std::fmt::Display for NipCaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for NipCaError {}

/// Raised by a Tier-3 (pending queue) policy: the registration was queued and
/// the HTTP layer should return `202 Accepted` with the `pending_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NipRaPending {
    pub pending_id: String,
}

impl NipRaPending {
    pub fn new(pending_id: impl Into<String>) -> Self {
        Self {
            pending_id: pending_id.into(),
        }
    }
}

impl std::fmt::Display for NipRaPending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Registration queued with pending id: {}", self.pending_id)
    }
}

impl std::error::Error for NipRaPending {}

/// Result of an enrollment-policy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentOutcome {
    /// Admitted — proceed to issuance.
    Admit,
    /// Denied — surface `NipCaError`.
    Deny(NipCaError),
    /// Queued — surface `NipRaPending` (202).
    Pending(NipRaPending),
}
