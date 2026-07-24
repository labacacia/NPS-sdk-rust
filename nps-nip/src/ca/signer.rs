// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! CA-side Ed25519 signer with RFC 8785-style canonical JSON (JCS), matching
//! the .NET `NPS.NIP.Crypto.NipSigner`. Public keys and signatures are encoded
//! `ed25519:{base64url}` (unpadded), and the signed canonical form:
//!
//! * sorts object keys recursively in byte-ordinal order,
//! * emits no whitespace,
//! * excludes the fields `signature`, `frame`, `metadata`, `cert_format`,
//!   `cert_chain`, `health`, `last_seen` (never covered by the v1 signature).

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;

/// Fields excluded from the canonical JSON over which the v1 signature covers.
const EXCLUDED: &[&str] = &[
    "signature",
    "frame",
    "metadata",
    "cert_format",
    "cert_chain",
    "health",
    "last_seen",
];

/// Encode a raw 32-byte Ed25519 public key as `ed25519:{base64url}`.
pub fn encode_public_key(pub_raw: &[u8; 32]) -> String {
    format!("ed25519:{}", B64URL.encode(pub_raw))
}

/// Encode a verifying key as `ed25519:{base64url}`.
pub fn encode_verifying_key(vk: &VerifyingKey) -> String {
    encode_public_key(vk.as_bytes())
}

/// Decode a `ed25519:{base64url}` public key. Returns `None` on any parse error.
pub fn decode_public_key(encoded: &str) -> Option<VerifyingKey> {
    let b64 = encoded.strip_prefix("ed25519:")?;
    let raw = B64URL.decode(b64.as_bytes()).ok()?;
    let arr: [u8; 32] = raw.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

/// Produce the canonical JSON string for `value` (recursive ordinal key sort,
/// no whitespace, excluded keys dropped).
pub fn canonical_json(value: &Value) -> String {
    let mut sb = String::new();
    write_canonical(value, &mut sb);
    sb
}

fn write_canonical(el: &Value, sb: &mut String) {
    match el {
        Value::Object(map) => {
            sb.push('{');
            let mut keys: Vec<&String> = map
                .keys()
                .filter(|k| !EXCLUDED.contains(&k.as_str()))
                .collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    sb.push(',');
                }
                // serde_json::to_string on a string produces a correctly
                // escaped JSON string literal.
                sb.push_str(&serde_json::to_string(k).unwrap());
                sb.push(':');
                write_canonical(&map[*k], sb);
            }
            sb.push('}');
        }
        Value::Array(items) => {
            sb.push('[');
            for (i, it) in items.iter().enumerate() {
                if i > 0 {
                    sb.push(',');
                }
                write_canonical(it, sb);
            }
            sb.push(']');
        }
        other => sb.push_str(&serde_json::to_string(other).unwrap()),
    }
}

/// Sign the canonical JSON of `payload`. Returns `ed25519:{base64url}`.
pub fn sign(sk: &SigningKey, payload: &Value) -> String {
    let canonical = canonical_json(payload);
    let sig: Signature = sk.sign(canonical.as_bytes());
    format!("ed25519:{}", B64URL.encode(sig.to_bytes()))
}

/// Verify a `ed25519:{base64url}` signature against the canonical JSON of
/// `payload` using `vk`.
pub fn verify(vk: &VerifyingKey, payload: &Value, signature: &str) -> bool {
    let sig_b64 = match signature.strip_prefix("ed25519:") {
        Some(s) => s,
        None => return false,
    };
    let bytes = match B64URL.decode(sig_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let arr: [u8; 64] = match bytes.try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = Signature::from_bytes(&arr);
    let canonical = canonical_json(payload);
    vk.verify(canonical.as_bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_sorts_and_excludes() {
        let v = json!({
            "nid": "n",
            "capabilities": ["b", "a"],
            "signature": "SIG",
            "frame": "0x20",
            "metadata": {"x": 1},
            "scope": {"z": 1, "a": 2},
        });
        // signature/frame/metadata excluded; keys ordinal-sorted; arrays kept
        // in order; nested objects sorted.
        assert_eq!(
            canonical_json(&v),
            r#"{"capabilities":["b","a"],"nid":"n","scope":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key();
        let payload = json!({"nid": "urn:nps:agent:x", "serial": "0x1"});
        let sig = sign(&sk, &payload);
        assert!(verify(&vk, &payload, &sig));
        let tampered = json!({"nid": "urn:nps:agent:y", "serial": "0x1"});
        assert!(!verify(&vk, &tampered, &sig));
    }

    #[test]
    fn pubkey_roundtrip_base64url() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let vk = sk.verifying_key();
        let enc = encode_verifying_key(&vk);
        assert!(enc.starts_with("ed25519:"));
        let dec = decode_public_key(&enc).unwrap();
        assert_eq!(dec.as_bytes(), vk.as_bytes());
    }
}
