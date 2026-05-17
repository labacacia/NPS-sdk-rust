// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod acme;
pub mod assurance_level;
pub mod cert_format;
pub mod error_codes;
pub mod frames;
pub mod identity;
pub mod reputation;
pub mod verifier;
pub mod x509;

pub use assurance_level::{AssuranceLevel, ANONYMOUS, ATTESTED, VERIFIED};
pub use frames::{IdentFrame, TrustFrame, RevokeFrame};
pub use identity::NipIdentity;
pub use reputation::{
    ReputationLogClient, ReputationLogEntry, ReputationLogError,
    SignedTreeHead, InclusionProof, IncidentType, Severity,
    ObservationWindow, sign_entry, verify_entry,
};
pub use verifier::{NipIdentVerifier, NipVerifierOptions, NipIdentVerifyResult};
