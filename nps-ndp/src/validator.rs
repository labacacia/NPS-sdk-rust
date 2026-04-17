// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use nps_nip::identity::NipIdentity;
use crate::frames::AnnounceFrame;

#[derive(Debug, Clone)]
pub struct NdpAnnounceResult {
    pub is_valid:   bool,
    pub error_code: Option<String>,
    pub message:    Option<String>,
}

impl NdpAnnounceResult {
    pub fn ok() -> Self {
        NdpAnnounceResult { is_valid: true, error_code: None, message: None }
    }

    pub fn fail(code: impl Into<String>, msg: impl Into<String>) -> Self {
        NdpAnnounceResult {
            is_valid:   false,
            error_code: Some(code.into()),
            message:    Some(msg.into()),
        }
    }
}

pub struct NdpAnnounceValidator {
    keys: HashMap<String, String>, // nid → "ed25519:<hex>"
}

impl NdpAnnounceValidator {
    pub fn new() -> Self {
        NdpAnnounceValidator { keys: HashMap::new() }
    }

    pub fn register_public_key(&mut self, nid: impl Into<String>, pub_key: impl Into<String>) {
        self.keys.insert(nid.into(), pub_key.into());
    }

    pub fn remove_public_key(&mut self, nid: &str) {
        self.keys.remove(nid);
    }

    pub fn known_public_keys(&self) -> &HashMap<String, String> {
        &self.keys
    }

    pub fn validate(&self, frame: &AnnounceFrame) -> NdpAnnounceResult {
        let pub_key = match self.keys.get(&frame.nid) {
            Some(k) => k,
            None    => return NdpAnnounceResult::fail(
                "NDP-ANNOUNCE-NID-MISMATCH",
                format!("no public key registered for NID {}", frame.nid),
            ),
        };

        if !frame.signature.starts_with("ed25519:") {
            return NdpAnnounceResult::fail(
                "NDP-ANNOUNCE-SIG-INVALID",
                "signature must have ed25519: prefix",
            );
        }

        let unsigned = frame.unsigned_dict();
        if NipIdentity::verify_with_pub_key_str(&unsigned, pub_key, &frame.signature) {
            NdpAnnounceResult::ok()
        } else {
            NdpAnnounceResult::fail("NDP-ANNOUNCE-SIG-INVALID", "signature verification failed")
        }
    }
}

impl Default for NdpAnnounceValidator {
    fn default() -> Self {
        Self::new()
    }
}
