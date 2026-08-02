// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NIP v0.13 deterministic live-revocation policy.

use crate::error_codes;
use crate::verifier::{fail, ok, NipIdentVerifyResult};

/// Whether Step 4 is optional for compatibility or required.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum NipRevocationMode {
    #[default]
    IfConfigured,
    Required,
}

/// Revocation sources in their normative consultation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NipRevocationSource {
    LocalCrl,
    Callback,
    CaStore,
    Ocsp,
}

/// Portable outcome reported by a configured source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NipRevocationOutcome {
    Good,
    Revoked,
    Unavailable,
}

/// Incremental Step-4 evaluator used by verifiers and conformance runners.
#[derive(Debug, Clone)]
pub struct NipRevocationPolicy {
    mode: NipRevocationMode,
    ocsp_fail_open: bool,
    consulted_sources: Vec<NipRevocationSource>,
}

impl NipRevocationPolicy {
    pub fn new(mode: NipRevocationMode, ocsp_fail_open: bool) -> Self {
        Self {
            mode,
            ocsp_fail_open,
            consulted_sources: Vec::new(),
        }
    }

    pub fn consulted_sources(&self) -> &[NipRevocationSource] {
        &self.consulted_sources
    }

    /// Record one configured source. `None` means evaluation may continue.
    pub fn observe(
        &mut self,
        source: NipRevocationSource,
        outcome: NipRevocationOutcome,
    ) -> Option<NipIdentVerifyResult> {
        self.consulted_sources.push(source);
        if source == NipRevocationSource::Ocsp
            && outcome == NipRevocationOutcome::Unavailable
            && self.ocsp_fail_open
        {
            return None;
        }
        match outcome {
            NipRevocationOutcome::Good => None,
            NipRevocationOutcome::Revoked => Some(fail(
                4,
                error_codes::CERT_REVOKED,
                format!("Revocation source {source:?} reports the certificate revoked."),
            )),
            NipRevocationOutcome::Unavailable => Some(fail(
                4,
                error_codes::OCSP_UNAVAILABLE,
                format!("Revocation source {source:?} is unavailable."),
            )),
        }
    }

    /// Complete evaluation after all configured sources have been consulted.
    pub fn complete(&self) -> NipIdentVerifyResult {
        if self.mode == NipRevocationMode::Required && self.consulted_sources.is_empty() {
            return fail(
                4,
                error_codes::OCSP_UNAVAILABLE,
                "Revocation mode is required, but no revocation source is configured.",
            );
        }
        ok()
    }
}
