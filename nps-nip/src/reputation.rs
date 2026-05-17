// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// NPS-RFC-0004 — Reputation Log client, entry types, signing, and Merkle verification.

use std::collections::BTreeMap;

use base64::engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde::de::{self, Visitor};
use sha2::{Digest, Sha256};
use thiserror::Error;

// ---------------------------------------------------------------------------
// IncidentType
// ---------------------------------------------------------------------------

/// Incident classification.
///
/// Forward-compatible: unknown wire strings deserialize as `Other`.
/// For entries deserialized with an unknown incident type, `incident` is set
/// to `Other` and `incident_raw` is `None` (limitation: the raw string is not
/// preserved automatically during serde deserialization; callers that need the
/// raw value should inspect the original JSON before deserializing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IncidentType {
    Other,
    CertRevoked,
    RateLimitViolation,
    TosViolation,
    ScrapingPattern,
    PaymentDefault,
    ContractDispute,
    ImpersonationClaim,
    PositiveAttestation,
}

impl IncidentType {
    fn to_wire(&self) -> &'static str {
        match self {
            IncidentType::Other              => "other",
            IncidentType::CertRevoked        => "cert-revoked",
            IncidentType::RateLimitViolation => "rate-limit-violation",
            IncidentType::TosViolation       => "tos-violation",
            IncidentType::ScrapingPattern    => "scraping-pattern",
            IncidentType::PaymentDefault     => "payment-default",
            IncidentType::ContractDispute    => "contract-dispute",
            IncidentType::ImpersonationClaim => "impersonation-claim",
            IncidentType::PositiveAttestation => "positive-attestation",
        }
    }

    fn from_wire(s: &str) -> Self {
        match s {
            "cert-revoked"         => IncidentType::CertRevoked,
            "rate-limit-violation" => IncidentType::RateLimitViolation,
            "tos-violation"        => IncidentType::TosViolation,
            "scraping-pattern"     => IncidentType::ScrapingPattern,
            "payment-default"      => IncidentType::PaymentDefault,
            "contract-dispute"     => IncidentType::ContractDispute,
            "impersonation-claim"  => IncidentType::ImpersonationClaim,
            "positive-attestation" => IncidentType::PositiveAttestation,
            _                      => IncidentType::Other,
        }
    }
}

impl Serialize for IncidentType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.to_wire())
    }
}

impl<'de> Deserialize<'de> for IncidentType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IncidentVisitor;
        impl<'de> Visitor<'de> for IncidentVisitor {
            type Value = IncidentType;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "an incident type string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<IncidentType, E> {
                Ok(IncidentType::from_wire(v))
            }
        }
        deserializer.deserialize_str(IncidentVisitor)
    }
}

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

/// Ordered severity levels. Unknown wire strings are a deserialization error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info     = 0,
    Minor    = 1,
    Moderate = 2,
    Major    = 3,
    Critical = 4,
}

impl Serialize for Severity {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = match self {
            Severity::Info     => "info",
            Severity::Minor    => "minor",
            Severity::Moderate => "moderate",
            Severity::Major    => "major",
            Severity::Critical => "critical",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for Severity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct SeverityVisitor;
        impl<'de> Visitor<'de> for SeverityVisitor {
            type Value = Severity;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "a severity string: info/minor/moderate/major/critical")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Severity, E> {
                match v {
                    "info"     => Ok(Severity::Info),
                    "minor"    => Ok(Severity::Minor),
                    "moderate" => Ok(Severity::Moderate),
                    "major"    => Ok(Severity::Major),
                    "critical" => Ok(Severity::Critical),
                    other      => Err(E::unknown_variant(other, &["info","minor","moderate","major","critical"])),
                }
            }
        }
        deserializer.deserialize_str(SeverityVisitor)
    }
}

// ---------------------------------------------------------------------------
// Entry types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObservationWindow {
    pub start: String,
    pub end:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationLogEntry {
    pub v:           u32,
    pub log_id:      String,
    pub seq:         u64,
    pub timestamp:   String,
    pub subject_nid: String,
    pub incident:    IncidentType,
    /// In-memory only — not round-tripped through wire JSON.
    #[serde(skip)]
    pub incident_raw: Option<String>,
    pub severity:    Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window:      Option<ObservationWindow>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_ref:    Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub issuer_nid: String,
    pub signature:  String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedTreeHead {
    pub log_id:          String,
    pub tree_size:       u64,
    pub timestamp:       String,
    pub sha256_root_hash: String,
    pub signature:       String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub seq:        u64,
    pub leaf_index: u64,
    pub tree_size:  u64,
    pub leaf_hash:  String,
    pub audit_path: Vec<String>,
}

// ---------------------------------------------------------------------------
// Signing helpers
// ---------------------------------------------------------------------------

/// Build the canonical JSON map for signing (all entry fields except
/// `signature` and `incident_raw`, with sorted keys via BTreeMap).
fn signing_map(entry: &ReputationLogEntry) -> BTreeMap<String, serde_json::Value> {
    use serde_json::Value;

    let mut m: BTreeMap<String, Value> = BTreeMap::new();

    m.insert("v".into(),           Value::Number(entry.v.into()));
    m.insert("log_id".into(),      Value::String(entry.log_id.clone()));
    m.insert("seq".into(),         Value::Number(entry.seq.into()));
    m.insert("timestamp".into(),   Value::String(entry.timestamp.clone()));
    m.insert("subject_nid".into(), Value::String(entry.subject_nid.clone()));

    // incident: for Other+incident_raw use the raw string; otherwise use wire name
    let incident_wire: String = match &entry.incident {
        IncidentType::Other => entry.incident_raw
            .clone()
            .unwrap_or_else(|| "other".to_string()),
        other => other.to_wire().to_string(),
    };
    m.insert("incident".into(), Value::String(incident_wire));

    m.insert("severity".into(),    serde_json::to_value(&entry.severity).unwrap());
    m.insert("issuer_nid".into(),  Value::String(entry.issuer_nid.clone()));

    if let Some(w) = &entry.window {
        m.insert("window".into(), serde_json::to_value(w).unwrap());
    }
    if let Some(obs) = &entry.observation {
        m.insert("observation".into(), obs.clone());
    }
    if let Some(r) = &entry.evidence_ref {
        m.insert("evidence_ref".into(), Value::String(r.clone()));
    }
    if let Some(s) = &entry.evidence_sha256 {
        m.insert("evidence_sha256".into(), Value::String(s.clone()));
    }

    m
}

/// Build the canonical JSON used as the Merkle leaf (all fields including
/// `signature`, sorted keys via BTreeMap).
fn leaf_canonical_json(entry: &ReputationLogEntry) -> String {
    let mut m = signing_map(entry);
    m.insert("signature".into(), serde_json::Value::String(entry.signature.clone()));
    serde_json::to_string(&m).unwrap_or_default()
}

/// Sign `entry` with the issuer's private key. Returns the entry with
/// `signature` populated. The signing canonical form excludes `signature`
/// and `incident_raw`.
pub fn sign_entry(
    signing_key: &ed25519_dalek::SigningKey,
    mut entry: ReputationLogEntry,
) -> ReputationLogEntry {
    let map    = signing_map(&entry);
    let canon  = serde_json::to_string(&map).unwrap_or_default();
    let sig: Signature = signing_key.sign(canon.as_bytes());
    entry.signature = format!("ed25519:{}", B64.encode(sig.to_bytes()));
    entry
}

/// Verify the issuer-side signature on `entry`.
pub fn verify_entry(
    verifying_key: &ed25519_dalek::VerifyingKey,
    entry: &ReputationLogEntry,
) -> bool {
    let sig_b64 = match entry.signature.strip_prefix("ed25519:") {
        Some(s) => s,
        None    => return false,
    };
    let sig_bytes = match B64.decode(sig_b64) {
        Ok(b)  => b,
        Err(_) => return false,
    };
    let sig_arr: [u8; 64] = match sig_bytes.try_into() {
        Ok(b)  => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&sig_arr);
    let map   = signing_map(entry);
    let canon = serde_json::to_string(&map).unwrap_or_default();
    verifying_key.verify(canon.as_bytes(), &sig).is_ok()
}

// ---------------------------------------------------------------------------
// Merkle inclusion verification
// ---------------------------------------------------------------------------

fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    B64URL.decode(s)
}

impl ReputationLogClient {
    /// Verify that `entry` is included in the tree described by `sth`,
    /// given `proof`. Uses RFC 9162 §2.1.3.2 audit-path folding.
    pub fn verify_inclusion(
        proof: &InclusionProof,
        sth: &SignedTreeHead,
        entry: &ReputationLogEntry,
    ) -> bool {
        // 1. Compute leaf hash: 0x00 || leaf_canonical_json
        let leaf_json = leaf_canonical_json(entry);
        let mut hasher = Sha256::new();
        hasher.update(&[0x00u8]);
        hasher.update(leaf_json.as_bytes());
        let mut node_hash: [u8; 32] = hasher.finalize().into();

        // 2. Check supplied leaf_hash
        let expected_leaf = match base64url_decode(&proof.leaf_hash) {
            Ok(b)  => b,
            Err(_) => return false,
        };
        if node_hash.as_ref() != expected_leaf.as_slice() {
            return false;
        }

        // 3. Fold audit path (RFC 9162 §2.1.3.2)
        for (i, step) in proof.audit_path.iter().enumerate() {
            let sibling = match base64url_decode(step) {
                Ok(b)  => b,
                Err(_) => return false,
            };
            if sibling.len() != 32 {
                return false;
            }
            let mut buf = [0u8; 65];
            buf[0] = 0x01;
            if (proof.leaf_index >> i) & 1 == 0 {
                buf[1..33].copy_from_slice(&node_hash);
                buf[33..65].copy_from_slice(&sibling);
            } else {
                buf[1..33].copy_from_slice(&sibling);
                buf[33..65].copy_from_slice(&node_hash);
            }
            node_hash = Sha256::digest(&buf).into();
        }

        // 4. Compare to STH root hash
        let expected_root = match base64url_decode(&sth.sha256_root_hash) {
            Ok(b)  => b,
            Err(_) => return false,
        };
        node_hash.as_ref() == expected_root.as_slice()
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ReputationLogError {
    #[error("{message}")]
    Api {
        nip_error_code: String,
        nps_status:     String,
        message:        String,
    },
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

/// Error response shape returned by the NPS reputation log server.
#[derive(Debug, Deserialize)]
struct ApiErrorBody {
    error:   String,
    status:  String,
    message: String,
}

pub struct ReputationLogClient {
    base_url: String,
    client:   reqwest::Client,
}

impl ReputationLogClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        ReputationLogClient {
            base_url: base_url.into(),
            client:   reqwest::Client::new(),
        }
    }

    pub fn with_client(base_url: impl Into<String>, client: reqwest::Client) -> Self {
        ReputationLogClient {
            base_url: base_url.into(),
            client,
        }
    }

    /// Submit a signed entry to the log. Returns the server-stamped entry.
    pub async fn submit(
        &self,
        entry: &ReputationLogEntry,
    ) -> Result<ReputationLogEntry, ReputationLogError> {
        let url = format!("{}/v1/log/entries", self.base_url);
        let resp = self.client.post(&url).json(entry).send().await?;
        Self::parse_response(resp).await
    }

    /// Query entries from the log.
    ///
    /// - `nid`: filter by subject NID
    /// - `since_seq`: return only entries with `seq >= since_seq`
    pub async fn query(
        &self,
        nid: Option<&str>,
        since_seq: Option<u64>,
    ) -> Result<Vec<ReputationLogEntry>, ReputationLogError> {
        let mut url = format!("{}/v1/log/entries", self.base_url);
        let mut params: Vec<String> = Vec::new();
        if let Some(n) = nid {
            params.push(format!("nid={}", urlencoding_simple(n)));
        }
        if let Some(s) = since_seq {
            params.push(format!("since={}", s));
        }
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        let resp = self.client.get(&url).send().await?;
        Self::parse_response(resp).await
    }

    /// Retrieve the current Signed Tree Head.
    pub async fn get_sth(&self) -> Result<SignedTreeHead, ReputationLogError> {
        let url  = format!("{}/v1/log/sth", self.base_url);
        let resp = self.client.get(&url).send().await?;
        Self::parse_response(resp).await
    }

    /// Retrieve a Merkle inclusion proof for the given sequence number.
    pub async fn get_proof(&self, seq: u64) -> Result<InclusionProof, ReputationLogError> {
        let url  = format!("{}/v1/log/proof?seq={}", self.base_url, seq);
        let resp = self.client.get(&url).send().await?;
        Self::parse_response(resp).await
    }

    /// Retrieve the gossip Signed Tree Head.
    pub async fn get_gossip_sth(&self) -> Result<SignedTreeHead, ReputationLogError> {
        let url  = format!("{}/v1/log/gossip/sth", self.base_url);
        let resp = self.client.get(&url).send().await?;
        Self::parse_response(resp).await
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    async fn parse_response<T: for<'de> Deserialize<'de>>(
        resp: reqwest::Response,
    ) -> Result<T, ReputationLogError> {
        let status = resp.status();
        if status.is_success() {
            let body = resp.json::<T>().await?;
            Ok(body)
        } else {
            // Attempt to parse the NPS error body; fall back to a generic message.
            let text = resp.text().await.unwrap_or_default();
            if let Ok(err) = serde_json::from_str::<ApiErrorBody>(&text) {
                Err(ReputationLogError::Api {
                    nip_error_code: err.error,
                    nps_status:     err.status,
                    message:        err.message,
                })
            } else {
                Err(ReputationLogError::Api {
                    nip_error_code: String::new(),
                    nps_status:     status.as_str().to_string(),
                    message:        text,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal percent-encoding for NID query parameters (encode space and &)
// ---------------------------------------------------------------------------

fn urlencoding_simple(s: &str) -> String {
    s.chars().flat_map(|c| match c {
        ' '  => vec!['%', '2', '0'],
        '&'  => vec!['%', '2', '6'],
        '+'  => vec!['%', '2', 'B'],
        '%'  => vec!['%', '2', '5'],
        _    => vec![c],
    }).collect()
}
