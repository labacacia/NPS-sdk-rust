// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Callback delivery: HMAC-SHA256 signing and exponential-backoff POST retry
//! (NPS-5 §8.4). Faithful port of the .NET `NopOrchestrator.FireCallbackAsync`.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::constants;

type HmacSha256 = Hmac<Sha256>;

/// Builds the `X-NPS-Signature` header value for `payload`, or `None` when the
/// secret is absent or not a valid base64url-encoded 32-byte key.
pub fn build_callback_signature(callback_secret: Option<&str>, payload: &str) -> Option<String> {
    let secret = callback_secret?;
    if secret.trim().is_empty() {
        return None;
    }

    let key = decode_base64url(secret.trim())?;
    if key.len() != 32 {
        return None;
    }

    let mut mac = HmacSha256::new_from_slice(&key).ok()?;
    mac.update(payload.as_bytes());
    let hash = mac.finalize().into_bytes();
    Some(format!("sha256={}", hex::encode(hash)))
}

/// Decodes a base64url string (accepting missing padding, `-`/`_` alphabet, and
/// standard `+`/`/`), matching the .NET `TryDecodeBase64Url` normalisation.
fn decode_base64url(value: &str) -> Option<Vec<u8>> {
    // Normalise URL-safe alphabet to standard, then pad.
    let normalized: String = value.trim().replace('-', "+").replace('_', "/");
    let pad = (4 - normalized.len() % 4) % 4;
    let padded = format!("{normalized}{}", "=".repeat(pad));
    base64::engine::general_purpose::STANDARD
        .decode(padded)
        .ok()
}

/// Posts `payload` to `callback_url` with exponential backoff (NPS-5 §8.4).
/// Failures are non-fatal.
pub async fn fire_callback(
    http: &reqwest::Client,
    callback_url: &str,
    callback_secret: Option<&str>,
    payload: &str,
    retry_base_delay_ms: u64,
) {
    let signature = build_callback_signature(callback_secret, payload);

    for attempt in 1..=constants::CALLBACK_MAX_RETRIES {
        let mut req = http
            .post(callback_url)
            .header("Content-Type", "application/json")
            .body(payload.to_string());
        if let Some(sig) = &signature {
            req = req.header("X-NPS-Signature", sig);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => return,
            _ => { /* non-success or transport error → retry */ }
        }

        if attempt < constants::CALLBACK_MAX_RETRIES && retry_base_delay_ms > 0 {
            let delay = retry_base_delay_ms * 2u64.pow(attempt - 1);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }
    }
    // Gave up — non-fatal.
}
