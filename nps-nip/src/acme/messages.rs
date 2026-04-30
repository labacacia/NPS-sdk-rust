// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! ACME wire-level DTOs (RFC 8555 + NPS-RFC-0002 §4.4).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DirectoryMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub website: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caa_identities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_account_required: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    #[serde(rename = "newNonce")]   pub new_nonce:   String,
    #[serde(rename = "newAccount")] pub new_account: String,
    #[serde(rename = "newOrder")]   pub new_order:   String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "revokeCert")]
    pub revoke_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "keyChange")]
    pub key_change:  Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<DirectoryMeta>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewAccountPayload {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "termsOfServiceAgreed")]
    pub terms_of_service_agreed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "onlyReturnExisting")]
    pub only_return_existing: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")] pub type_:  String,   // "nid" per NPS-RFC-0002 §4.4
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewOrderPayload {
    pub identifiers: Vec<Identifier>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notBefore")]
    pub not_before: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "notAfter")]
    pub not_after:  Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetail {
    #[serde(rename = "type")] pub type_: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Order {
    pub status:         String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires:        Option<String>,
    pub identifiers:    Vec<Identifier>,
    pub authorizations: Vec<String>,
    pub finalize:       String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate:    Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error:          Option<ProblemDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")] pub type_: String,   // "agent-01" per NPS-RFC-0002 §4.4
    pub url:    String,
    pub status: String,
    pub token:  String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validated: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ProblemDetail>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub status:     String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires:    Option<String>,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeRespondPayload {
    /// base64url(Ed25519(token)) per NPS-RFC-0002 §4.4.
    pub agent_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizePayload {
    /// base64url(CSR DER).
    pub csr: String,
}
