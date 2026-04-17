// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// Ed25519 key management with AES-256-GCM encrypted persistence.

use std::collections::BTreeMap;
use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit, OsRng as AesOsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use rand::RngCore;
use sha2::Sha256;

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};

const PBKDF2_ITERS: u32 = 600_000;
const SALT_LEN:     usize = 16;
const NONCE_LEN:    usize = 12;

pub struct NipIdentity {
    signing_key: SigningKey,
}

impl NipIdentity {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        NipIdentity { signing_key }
    }

    pub fn pub_key_string(&self) -> String {
        format!("ed25519:{}", hex::encode(self.signing_key.verifying_key().as_bytes()))
    }

    /// Sign a map using canonical JSON (sorted keys).
    pub fn sign(&self, payload: &FrameDict) -> String {
        let canonical = canonical_json(payload);
        let sig: Signature = self.signing_key.sign(canonical.as_bytes());
        format!("ed25519:{}", B64.encode(sig.to_bytes()))
    }

    /// Verify a signature string against a map.
    pub fn verify(&self, payload: &FrameDict, signature: &str) -> bool {
        self.verify_with_key(self.signing_key.verifying_key(), payload, signature)
    }

    pub fn verify_with_key(&self, vk: VerifyingKey, payload: &FrameDict, signature: &str) -> bool {
        let sig_b64 = match signature.strip_prefix("ed25519:") {
            Some(s) => s,
            None    => return false,
        };
        let bytes = match B64.decode(sig_b64) {
            Ok(b)  => b,
            Err(_) => return false,
        };
        let sig_bytes: [u8; 64] = match bytes.try_into() {
            Ok(b)  => b,
            Err(_) => return false,
        };
        let sig = Signature::from_bytes(&sig_bytes);
        let canonical = canonical_json(payload);
        vk.verify(canonical.as_bytes(), &sig).is_ok()
    }

    /// Parse a `"ed25519:<hex>"` public key string and verify.
    pub fn verify_with_pub_key_str(payload: &FrameDict, pub_key: &str, signature: &str) -> bool {
        let hex_str = match pub_key.strip_prefix("ed25519:") {
            Some(s) => s,
            None    => return false,
        };
        let bytes = match hex::decode(hex_str) {
            Ok(b)  => b,
            Err(_) => return false,
        };
        let arr: [u8; 32] = match bytes.try_into() {
            Ok(b)  => b,
            Err(_) => return false,
        };
        let vk = match VerifyingKey::from_bytes(&arr) {
            Ok(v)  => v,
            Err(_) => return false,
        };
        let sig_b64 = match signature.strip_prefix("ed25519:") {
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
        let canonical = canonical_json(payload);
        vk.verify(canonical.as_bytes(), &sig).is_ok()
    }

    /// Save encrypted to file (AES-256-GCM + PBKDF2-SHA256).
    pub fn save(&self, path: &Path, passphrase: &str) -> NpsResult<()> {
        let mut salt  = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        rand::rngs::OsRng.fill_bytes(&mut nonce);

        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut key)
            .map_err(|e| NpsError::Identity(e.to_string()))?;

        let cipher   = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| NpsError::Identity(e.to_string()))?;
        let nonce_obj = Nonce::from_slice(&nonce);
        let plaintext = self.signing_key.to_bytes();
        let ciphertext = cipher.encrypt(nonce_obj, plaintext.as_ref())
            .map_err(|e| NpsError::Identity(e.to_string()))?;

        let envelope = serde_json::json!({
            "version":    1,
            "algorithm":  "ed25519",
            "pub_key":    self.pub_key_string(),
            "salt":       hex::encode(salt),
            "nonce":      hex::encode(nonce),
            "ciphertext": hex::encode(&ciphertext),
        });
        std::fs::write(path, envelope.to_string())
            .map_err(|e| NpsError::Io(e.to_string()))
    }

    /// Load from encrypted file.
    pub fn load(path: &Path, passphrase: &str) -> NpsResult<Self> {
        let data = std::fs::read_to_string(path)
            .map_err(|e| NpsError::Io(e.to_string()))?;
        let v: serde_json::Value = serde_json::from_str(&data)
            .map_err(|e| NpsError::Codec(e.to_string()))?;

        let salt_hex  = v["salt"].as_str().ok_or(NpsError::Identity("missing salt".into()))?;
        let nonce_hex = v["nonce"].as_str().ok_or(NpsError::Identity("missing nonce".into()))?;
        let ct_hex    = v["ciphertext"].as_str().ok_or(NpsError::Identity("missing ciphertext".into()))?;

        let salt  = hex::decode(salt_hex).map_err(|e| NpsError::Identity(e.to_string()))?;
        let nonce = hex::decode(nonce_hex).map_err(|e| NpsError::Identity(e.to_string()))?;
        let ct    = hex::decode(ct_hex).map_err(|e| NpsError::Identity(e.to_string()))?;

        let mut key = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut key)
            .map_err(|e| NpsError::Identity(e.to_string()))?;

        let cipher    = Aes256Gcm::new_from_slice(&key)
            .map_err(|e| NpsError::Identity(e.to_string()))?;
        let nonce_obj = Nonce::from_slice(&nonce);
        let plaintext = cipher.decrypt(nonce_obj, ct.as_ref())
            .map_err(|_| NpsError::Identity("decryption failed — wrong passphrase?".into()))?;

        let sk_bytes: [u8; 32] = plaintext.try_into()
            .map_err(|_| NpsError::Identity("invalid key length".into()))?;
        let signing_key = SigningKey::from_bytes(&sk_bytes);
        Ok(NipIdentity { signing_key })
    }
}

/// Canonical JSON: sort keys alphabetically, no whitespace.
fn canonical_json(dict: &FrameDict) -> String {
    let sorted: BTreeMap<_, _> = dict.iter().collect();
    serde_json::to_string(&serde_json::Value::Object(
        sorted.iter().map(|(k, v)| ((*k).clone(), (*v).clone())).collect()
    )).unwrap_or_default()
}
