// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod acme;
pub mod assurance_level;
pub mod ca;
pub mod ca_client;
pub mod cert_format;
pub mod error_codes;
pub mod frames;
pub mod identity;
pub mod phase3;
pub mod reputation;
pub mod revocation_policy;
pub mod trust_validator;
pub mod verifier;
pub mod x509;

pub use assurance_level::{AssuranceLevel, ANONYMOUS, ATTESTED, VERIFIED};
pub use ca::{
    create_enrollment_policy, AllowlistPolicy, BootstrapTokenPolicy, BootstrapTokenStore,
    CaRequest, CaResponse, CaSqlDialect, CaSqlError, CaSqlExecutor, CaSqlRow, CaSqlValue,
    EnrollmentOutcome, EnrollmentPolicy, EnrollmentRequest, EnrollmentTier, FlattenedJws,
    InMemoryBootstrapTokenStore, InMemoryCaSqlExecutor, InMemoryNipCaStore, InMemoryPendingStore,
    IssueSessionParams, NipCaCertRecord, NipCaCertStore, NipCaError, NipCaOptions, NipCaRouter,
    NipCaService, NipRaPending, NipVerifyResult, PendingQueuePolicy, PendingRegistration,
    PendingStatus, PendingStore, RegisterWithRaError, SqlNipCaStore,
};
pub use ca_client::{
    NipCaCertificateList, NipCaCertificateRecord, NipCaClient, NipCaClientError, NipCaCrl,
    NipCaCrlEntry, NipCaDiscoveryDocument, NipCaIdentFrame, NipCaRegisterRequest,
    NipCaRegisterX509Request, NipCaRevokeFrame, NipCaVerifyResponse,
};
pub use frames::{IdentFrame, IdentReputationPolicyHint, RevokeFrame, TrustFrame};
pub use identity::NipIdentity;
pub use phase3::{
    enforce as phase3_enforce, read_utf8_sequence_extension, try_get_ocsp_next_update,
};
pub use reputation::{
    sign_entry, verify_entry, IncidentType, InclusionProof, ObservationWindow, ReputationLogClient,
    ReputationLogEntry, Severity, SignedTreeHead,
};
pub use revocation_policy::{
    NipRevocationMode, NipRevocationOutcome, NipRevocationPolicy, NipRevocationSource,
};
pub use trust_validator::{validate as validate_trust_frame, TrustFrameValidationContext};
pub use verifier::{
    nwp_path_matches, NipCaStore, NipCertRecord, NipIdentVerifier, NipIdentVerifyResult,
    NipRevocationCheck, NipVerifierOptions, NipVerifyContext, OcspResponse,
};
