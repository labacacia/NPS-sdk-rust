// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod acme;
pub mod assurance_level;
pub mod ca_client;
pub mod cert_format;
pub mod error_codes;
pub mod frames;
pub mod identity;
pub mod reputation;
pub mod verifier;
pub mod x509;

pub use assurance_level::{AssuranceLevel, ANONYMOUS, ATTESTED, VERIFIED};
pub use ca_client::{
    NipCaClient, NipCaClientError, NipCaCrl, NipCaCrlEntry, NipCaDiscoveryDocument,
    NipCaIdentFrame, NipCaRegisterRequest, NipCaRegisterX509Request, NipCaRevokeFrame,
    NipCaVerifyResponse,
};
pub use frames::{IdentFrame, IdentReputationPolicyHint, RevokeFrame, TrustFrame};
pub use identity::NipIdentity;
pub use reputation::{
    sign_entry, verify_entry, IncidentType, InclusionProof, ObservationWindow, ReputationLogClient,
    ReputationLogEntry, Severity, SignedTreeHead,
};
pub use verifier::{NipIdentVerifier, NipIdentVerifyResult, NipVerifierOptions};
