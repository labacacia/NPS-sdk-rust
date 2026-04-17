// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde_json::{json, Value};

fn get_str<'a>(d: &'a FrameDict, k: &str) -> NpsResult<&'a str> {
    d.get(k).and_then(Value::as_str)
        .ok_or_else(|| NpsError::Frame(format!("missing field: {k}")))
}

fn opt_str<'a>(d: &'a FrameDict, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str)
}

// ── IdentFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdentFrame {
    pub nid:       String,
    pub pub_key:   String,
    pub meta:      Option<serde_json::Map<String, Value>>,
    pub signature: Option<String>,
}

impl IdentFrame {
    pub fn frame_type() -> FrameType { FrameType::Ident }

    /// Dict without signature — for signing
    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nid".into(),     json!(self.nid));
        m.insert("pub_key".into(), json!(self.pub_key));
        if let Some(v) = &self.meta { m.insert("meta".into(), Value::Object(v.clone())); }
        m
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        if let Some(s) = &self.signature { m.insert("signature".into(), json!(s)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(IdentFrame {
            nid:       get_str(d, "nid")?.to_string(),
            pub_key:   get_str(d, "pub_key")?.to_string(),
            meta:      d.get("meta").and_then(Value::as_object).cloned(),
            signature: opt_str(d, "signature").map(str::to_string),
        })
    }
}

// ── TrustFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustFrame {
    pub issuer_nid:  String,
    pub subject_nid: String,
    pub scopes:      Vec<String>,
    pub expires_at:  Option<String>,
    pub signature:   Option<String>,
}

impl TrustFrame {
    pub fn frame_type() -> FrameType { FrameType::Trust }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("issuer_nid".into(),  json!(self.issuer_nid));
        m.insert("subject_nid".into(), json!(self.subject_nid));
        m.insert("scopes".into(),      json!(self.scopes));
        if let Some(v) = &self.expires_at { m.insert("expires_at".into(), json!(v)); }
        if let Some(v) = &self.signature  { m.insert("signature".into(),  json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let scopes = d.get("scopes").and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        Ok(TrustFrame {
            issuer_nid:  get_str(d, "issuer_nid")?.to_string(),
            subject_nid: get_str(d, "subject_nid")?.to_string(),
            scopes,
            expires_at:  opt_str(d, "expires_at").map(str::to_string),
            signature:   opt_str(d, "signature").map(str::to_string),
        })
    }
}

// ── RevokeFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RevokeFrame {
    pub nid:        String,
    pub reason:     Option<String>,
    pub revoked_at: Option<String>,
}

impl RevokeFrame {
    pub fn frame_type() -> FrameType { FrameType::Revoke }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nid".into(), json!(self.nid));
        if let Some(v) = &self.reason     { m.insert("reason".into(),     json!(v)); }
        if let Some(v) = &self.revoked_at { m.insert("revoked_at".into(), json!(v)); }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(RevokeFrame {
            nid:        get_str(d, "nid")?.to_string(),
            reason:     opt_str(d, "reason").map(str::to_string),
            revoked_at: opt_str(d, "revoked_at").map(str::to_string),
        })
    }
}
