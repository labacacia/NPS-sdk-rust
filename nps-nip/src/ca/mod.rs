// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Reusable NIP Certificate Authority service library (NPS-3 §6–8) with
//! orchestrator groups + sessions (NPS-CR-0003) and the RA enrollment tiers
//! (NPS-CR-0005). Behavioural + wire parity with the .NET `NPS.NIP.Ca` surface.
//!
//! This is the framework-agnostic in-process library — distinct from the
//! standalone `ca-server` crate (Axum + SQLite). Compose:
//!
//! ```no_run
//! use nps_nip::ca::{NipCaOptions, NipCaService, InMemoryNipCaStore};
//! use ed25519_dalek::SigningKey;
//!
//! let opts = NipCaOptions::new("urn:nps:org:ca.example.com", "https://ca.example.com");
//! let store = InMemoryNipCaStore::new();
//! let key = SigningKey::from_bytes(&[1u8; 32]);
//! let ca = NipCaService::new(opts, store, key);
//! let _pub = ca.get_ca_public_key();
//! ```

pub mod error;
pub mod group_jws;
pub mod options;
pub mod ra;
pub mod router;
pub mod service;
pub mod signer;
pub mod sql_store;
pub mod store;

pub use error::{EnrollmentOutcome, NipCaError, NipRaPending};
pub use group_jws::{
    build_flattened_jws, try_verify as verify_group_jws, FlattenedJws, JwsVerified,
};
pub use options::{EnrollmentTier, NipCaOptions};
pub use ra::{
    clamp_bootstrap_ttl, create_enrollment_policy, new_uuid_hex, AllowlistPolicy,
    BootstrapTokenInfo, BootstrapTokenPolicy, BootstrapTokenStore, EnrollmentPolicy,
    EnrollmentRequest, InMemoryBootstrapTokenStore, InMemoryPendingStore, PendingQueuePolicy,
    PendingRegistration, PendingStatus, PendingStore,
};
pub use router::{CaRequest, CaResponse, NipCaRouter};
pub use service::{IssueSessionParams, NipCaService, NipVerifyResult, RegisterWithRaError};
pub use signer::{
    canonical_json as ca_canonical_json, decode_public_key, encode_public_key,
    encode_verifying_key, sign as ca_sign, verify as ca_verify,
};
pub use sql_store::{
    CaSqlDialect, CaSqlError, CaSqlExecutor, CaSqlRow, CaSqlValue, InMemoryCaSqlExecutor,
    SqlNipCaStore, SQLITE_SCHEMA,
};
pub use store::{
    InMemoryNipCaStore, NipCaStore as NipCaCertStore, NipCertRecord as NipCaCertRecord, StoreError,
    ROLE_GROUP, ROLE_SESSION,
};
