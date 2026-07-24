// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Group-JWS verifier for NPS-CR-0003 §3.5 / §5.1.3 session-issue requests.
//!
//! The flattened JWS shape is
//! `{ "protected": b64url(header), "payload": b64url(payload),
//!    "signature": b64url(Ed25519 sig) }` where the protected header MUST be
//! `{ "alg": "EdDSA", "kid": "<group_nid>", "nps-purpose": "session-issue" }`
//! and the signature covers `ASCII(protected) "." ASCII(payload)` (RFC 7515 §3).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Deserialize;
use serde_json::json;

use crate::error_codes;

pub const EXPECTED_ALG: &str = "EdDSA";
pub const EXPECTED_PURPOSE: &str = "session-issue";

/// Flattened JWS object as it appears on the wire / in JSON.
#[derive(Debug, Clone, Deserialize)]
pub struct FlattenedJws {
    #[serde(default)]
    pub protected: Option<String>,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwsHeader {
    alg: Option<String>,
    kid: Option<String>,
    #[serde(rename = "nps-purpose")]
    nps_purpose: Option<String>,
}

/// Successful verification result: the decoded payload JSON text + asserted kid.
#[derive(Debug, Clone)]
pub struct JwsVerified {
    pub payload_json: String,
    pub kid: String,
}

/// Parse + verify a flattened JWS against `group_pub_key`. On success returns
/// [`JwsVerified`]; on failure returns the matching error code
/// ([`error_codes::CA_JWS_INVALID`]).
pub fn try_verify(jws: &FlattenedJws, group_pub_key: &VerifyingKey) -> Result<JwsVerified, &'static str> {
    let protected = jws.protected.as_deref().unwrap_or("");
    let payload = jws.payload.as_deref().unwrap_or("");
    let signature = jws.signature.as_deref().unwrap_or("");
    if protected.is_empty() || payload.is_empty() || signature.is_empty() {
        return Err(error_codes::CA_JWS_INVALID);
    }

    let header_bytes = B64URL
        .decode(protected.as_bytes())
        .map_err(|_| error_codes::CA_JWS_INVALID)?;
    let payload_bytes = B64URL
        .decode(payload.as_bytes())
        .map_err(|_| error_codes::CA_JWS_INVALID)?;
    let sig_bytes = B64URL
        .decode(signature.as_bytes())
        .map_err(|_| error_codes::CA_JWS_INVALID)?;

    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| error_codes::CA_JWS_INVALID)?;

    if header.alg.as_deref() != Some(EXPECTED_ALG)
        || header.nps_purpose.as_deref() != Some(EXPECTED_PURPOSE)
        || header.kid.as_deref().map(str::is_empty).unwrap_or(true)
    {
        return Err(error_codes::CA_JWS_INVALID);
    }

    let sig_arr: [u8; 64] = sig_bytes.try_into().map_err(|_| error_codes::CA_JWS_INVALID)?;
    let sig = Signature::from_bytes(&sig_arr);

    // RFC 7515 §3 signing input: ASCII(protected) "." ASCII(payload).
    let mut signing_input = Vec::with_capacity(protected.len() + 1 + payload.len());
    signing_input.extend_from_slice(protected.as_bytes());
    signing_input.push(b'.');
    signing_input.extend_from_slice(payload.as_bytes());

    if group_pub_key.verify(&signing_input, &sig).is_err() {
        return Err(error_codes::CA_JWS_INVALID);
    }

    let payload_json =
        String::from_utf8(payload_bytes).map_err(|_| error_codes::CA_JWS_INVALID)?;
    Ok(JwsVerified {
        payload_json,
        kid: header.kid.unwrap(),
    })
}

/// Build a signed flattened group-JWS over `payload_json` with the given group
/// signing key and `kid` (= group NID). The protected header is
/// `{ "alg": "EdDSA", "kid": kid, "nps-purpose": "session-issue" }`.
/// Provided so orchestrators (and tests) can mint session-issue authorisations.
pub fn build_flattened_jws(sk: &SigningKey, kid: &str, payload_json: &str) -> FlattenedJws {
    let header = json!({ "alg": EXPECTED_ALG, "kid": kid, "nps-purpose": EXPECTED_PURPOSE });
    let protected = B64URL.encode(serde_json::to_vec(&header).unwrap());
    let payload = B64URL.encode(payload_json.as_bytes());
    let signing_input = format!("{protected}.{payload}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    FlattenedJws {
        protected: Some(protected),
        payload: Some(payload),
        signature: Some(B64URL.encode(sig.to_bytes())),
    }
}
