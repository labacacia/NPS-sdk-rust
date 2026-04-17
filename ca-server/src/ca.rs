// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{SigningKey, VerifyingKey};
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde_json::{Map, Value};
use sha2::Sha256;
use std::{collections::BTreeMap, fs, path::Path, time::{Duration, SystemTime, UNIX_EPOCH}};

const PBKDF2_ITERS: u32 = 600_000;
const SALT_LEN:     usize = 16;
const NONCE_LEN:    usize = 12;
const KEY_LEN:      usize = 32;

pub struct Ca {
    pub signing_key:   SigningKey,
    pub pub_key_str:   String,
}

// ── Key Management ─────────────────────────────────────────────────────────

pub fn generate_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

pub fn pub_key_string(vk: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(vk.as_bytes()))
}

pub fn save_key(sk: &SigningKey, path: &str, passphrase: &str) -> Result<()> {
    let mut salt  = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut dk);

    let cipher = Aes256Gcm::new_from_slice(&dk)?;
    let n = Nonce::from_slice(&nonce);
    let ciphertext = cipher.encrypt(n, sk.as_bytes().as_ref())
        .map_err(|e| anyhow!("encrypt: {e}"))?;

    let vk = sk.verifying_key();
    let envelope = serde_json::json!({
        "version":    1,
        "algorithm":  "ed25519",
        "pub_key":    pub_key_string(&vk),
        "salt":       hex::encode(salt),
        "nonce":      hex::encode(nonce),
        "ciphertext": hex::encode(&ciphertext),
    });
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&envelope)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_key(path: &str, passphrase: &str) -> Result<SigningKey> {
    let data = fs::read_to_string(path)?;
    let env: serde_json::Value = serde_json::from_str(&data)?;
    let salt  = hex::decode(env["salt"].as_str().unwrap_or(""))?;
    let nonce = hex::decode(env["nonce"].as_str().unwrap_or(""))?;
    let ct    = hex::decode(env["ciphertext"].as_str().unwrap_or(""))?;

    let mut dk = [0u8; KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), &salt, PBKDF2_ITERS, &mut dk);

    let cipher = Aes256Gcm::new_from_slice(&dk)?;
    let n = Nonce::from_slice(&nonce);
    let seed = cipher.decrypt(n, ct.as_ref())
        .map_err(|_| anyhow!("Key decryption failed — wrong passphrase?"))?;
    let seed_arr: [u8; 32] = seed.try_into().map_err(|_| anyhow!("invalid seed length"))?;
    Ok(SigningKey::from_bytes(&seed_arr))
}

// ── Signing ────────────────────────────────────────────────────────────────

pub fn canonical_json(obj: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<_, _> = obj.iter().collect();
    serde_json::to_vec(&sorted).unwrap_or_default()
}

pub fn sign_dict(sk: &SigningKey, obj: &Map<String, Value>) -> String {
    use ed25519_dalek::Signer;
    let sig = sk.sign(&canonical_json(obj));
    format!("ed25519:{}", B64.encode(sig.to_bytes()))
}

// ── Certificate Issuance ───────────────────────────────────────────────────

fn iso_now_plus(days: i64) -> (String, String) {
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO).as_secs();
    let exp_secs = now_secs + (days as u64) * 86400;
    (fmt_iso(now_secs), fmt_iso(exp_secs))
}

fn fmt_iso(secs: u64) -> String {
    // Simple ISO 8601 formatter (UTC)
    let s = secs;
    let (y, mo, d, h, mi, sec) = epoch_to_parts(s);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, sec)
}

pub fn epoch_to_parts(secs: u64) -> (u64, u64, u64, u64, u64, u64) {
    let sec   = secs % 60;
    let mins  = secs / 60;
    let mi    = mins % 60;
    let hours = mins / 60;
    let h     = hours % 24;
    let days  = hours / 24;
    // Gregorian calendar calculation
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z.wrapping_sub(146_096) } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y   = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp  = (5 * doy + 2) / 153;
    let d   = doy - (153 * mp + 2) / 5 + 1;
    let mo  = if mp < 10 { mp + 3 } else { mp - 9 };
    let y   = if mo <= 2 { y + 1 } else { y };
    (y, mo, d, h, mi, sec)
}

pub fn issue_cert(
    sk: &SigningKey,
    ca_nid: &str,
    subject_nid: &str,
    subject_pub_key: &str,
    capabilities: Vec<String>,
    scope: Map<String, Value>,
    validity_days: i64,
    serial: &str,
    metadata: Option<Map<String, Value>>,
) -> Map<String, Value> {
    let (issued_at, expires_at) = iso_now_plus(validity_days);
    let mut unsigned = Map::new();
    unsigned.insert("capabilities".into(), Value::Array(capabilities.iter().map(|s| Value::String(s.clone())).collect()));
    unsigned.insert("expires_at".into(),   Value::String(expires_at.clone()));
    unsigned.insert("issued_at".into(),    Value::String(issued_at.clone()));
    unsigned.insert("issued_by".into(),    Value::String(ca_nid.to_string()));
    unsigned.insert("nid".into(),          Value::String(subject_nid.to_string()));
    unsigned.insert("pub_key".into(),      Value::String(subject_pub_key.to_string()));
    unsigned.insert("scope".into(),        Value::Object(scope));
    unsigned.insert("serial".into(),       Value::String(serial.to_string()));

    let signature = sign_dict(sk, &unsigned);
    let mut cert = unsigned;
    cert.insert("signature".into(), Value::String(signature));
    if let Some(meta) = metadata {
        cert.insert("metadata".into(), Value::Object(meta));
    }
    cert
}

pub fn generate_nid(domain: &str, entity_type: &str) -> String {
    let mut uid = [0u8; 8];
    OsRng.fill_bytes(&mut uid);
    format!("urn:nps:{}:{}:{}", entity_type, domain, hex::encode(uid))
}
