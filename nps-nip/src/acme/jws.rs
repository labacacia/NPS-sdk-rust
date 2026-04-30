// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! JWS signing helpers for ACME with Ed25519 (`alg: "EdDSA"` per RFC 8037).
//!
//! Wire shape (RFC 8555 §6.2 + RFC 7515 flattened JWS JSON serialization):
//!
//! ```json
//! {
//!   "protected": "base64url(JSON({alg, nonce, url, [jwk|kid]}))",
//!   "payload":   "base64url(JSON(payload))",
//!   "signature": "base64url(Ed25519(protected || \".\" || payload))"
//! }
//! ```

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ALG_EDDSA:   &str = "EdDSA";   // RFC 8037 §3.1
pub const KTY_OKP:     &str = "OKP";     // RFC 8037 §2
pub const CRV_ED25519: &str = "Ed25519"; // RFC 8037 §2

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x:   String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectedHeader {
    pub alg:   String,
    pub nonce: String,
    pub url:   String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwk:   Option<Jwk>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid:   Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub protected: String,
    pub payload:   String,
    pub signature: String,
}

pub fn jwk_from_public_key(raw: &[u8; 32]) -> Jwk {
    Jwk { kty: KTY_OKP.into(), crv: CRV_ED25519.into(), x: b64u_encode(raw) }
}

pub fn public_key_from_jwk(jwk: &Jwk) -> Result<VerifyingKey, String> {
    if jwk.kty != KTY_OKP || jwk.crv != CRV_ED25519 {
        return Err(format!("JWK is not OKP/Ed25519: kty={} crv={}", jwk.kty, jwk.crv));
    }
    let raw = b64u_decode(&jwk.x).map_err(|e| format!("jwk x: {e}"))?;
    if raw.len() != 32 {
        return Err(format!("JWK x decodes to {} bytes, want 32", raw.len()));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    VerifyingKey::from_bytes(&arr).map_err(|e| format!("Ed25519 pubkey: {e}"))
}

/// RFC 7638 §3 thumbprint of an Ed25519 JWK (lex-sorted compact JSON, SHA-256, base64url).
pub fn thumbprint(jwk: &Jwk) -> String {
    let canonical = format!(r#"{{"crv":"{}","kty":"{}","x":"{}"}}"#, jwk.crv, jwk.kty, jwk.x);
    let mut hasher = Sha256::new();
    hasher.update(canonical.as_bytes());
    b64u_encode(&hasher.finalize())
}

/// Sign a flattened JWS envelope. payload may be `None` for POST-as-GET.
pub fn sign<P: Serialize>(
    header:  &ProtectedHeader,
    payload: Option<&P>,
    sk:      &SigningKey,
) -> Result<Envelope, String> {
    let header_bytes = serde_json::to_vec(header).map_err(|e| format!("marshal header: {e}"))?;
    let header_b64u = b64u_encode(&header_bytes);
    let payload_b64u = match payload {
        Some(p) => {
            let bytes = serde_json::to_vec(p).map_err(|e| format!("marshal payload: {e}"))?;
            b64u_encode(&bytes)
        }
        None => String::new(),
    };
    let signing_input = format!("{header_b64u}.{payload_b64u}");
    let sig: Signature = sk.sign(signing_input.as_bytes());
    Ok(Envelope {
        protected: header_b64u,
        payload:   payload_b64u,
        signature: b64u_encode(&sig.to_bytes()),
    })
}

/// Verify an envelope signature against pubkey. Returns the parsed protected
/// header on success, or an error string on failure.
pub fn verify(env: &Envelope, pk: &VerifyingKey) -> Result<ProtectedHeader, String> {
    let signing_input = format!("{}.{}", env.protected, env.payload);
    let sig_bytes = b64u_decode(&env.signature).map_err(|e| format!("sig b64u: {e}"))?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|e| format!("sig parse: {e}"))?;
    pk.verify(signing_input.as_bytes(), &sig)
        .map_err(|e| format!("JWS sig verify: {e}"))?;
    let header_bytes = b64u_decode(&env.protected).map_err(|e| format!("header b64u: {e}"))?;
    serde_json::from_slice(&header_bytes).map_err(|e| format!("header parse: {e}"))
}

pub fn decode_payload<T: for<'de> Deserialize<'de>>(env: &Envelope) -> Result<Option<T>, String> {
    if env.payload.is_empty() {
        return Ok(None);
    }
    let bytes = b64u_decode(&env.payload).map_err(|e| format!("payload b64u: {e}"))?;
    let v: T = serde_json::from_slice(&bytes).map_err(|e| format!("payload parse: {e}"))?;
    Ok(Some(v))
}

pub fn b64u_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub fn b64u_decode(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .map_err(|e| format!("{e}"))
}
