// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::error_codes::REVOKE_FRAME_INVALID;

const REASON_PARENT_REVOKED: &str = "parent_revoked";

fn get_str<'a>(d: &'a FrameDict, k: &str) -> NpsResult<&'a str> {
    d.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| NpsError::Frame(format!("missing field: {k}")))
}

fn opt_str<'a>(d: &'a FrameDict, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str)
}

// ── IdentReputationPolicyHint ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentReputationPolicyHint {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub log_sources: Vec<String>,
    #[serde(default)]
    pub consent: bool,
}

// ── IdentFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct IdentFrame {
    pub nid: String,
    pub pub_key: String,
    pub meta: Option<serde_json::Map<String, Value>>,
    pub signature: Option<String>,

    /// NPS-RFC-0003 — optional assurance level.
    pub assurance_level: Option<crate::assurance_level::AssuranceLevel>,
    /// NPS-RFC-0002 — optional v2 X.509 dual-trust extensions.
    /// `cert_format` wire form (`V1_PROPRIETARY` | `V2_X509`).
    pub cert_format: Option<String>,
    /// `cert_chain` is base64url(DER), `[leaf, intermediates..., root]`.
    pub cert_chain: Option<Vec<String>>,
    /// NPS-RFC-0004 — optional OCSP staple (base64-encoded DER).
    pub ocsp_staple: Option<String>,
    /// NPS-RFC-0004 — optional reputation policy hint embedded in metadata.
    pub reputation_policy: Option<IdentReputationPolicyHint>,
    /// NIP v0.10 — self-declared node-role tags (alpha.13).
    pub node_roles: Option<Vec<String>>,
}

impl IdentFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Ident
    }

    pub fn new(nid: String, pub_key: String) -> Self {
        Self {
            nid,
            pub_key,
            meta: None,
            signature: None,
            assurance_level: None,
            cert_format: None,
            cert_chain: None,
            ocsp_staple: None,
            reputation_policy: None,
            node_roles: None,
        }
    }

    /// Dict the v1 Ed25519 signature covers. Deliberately excludes
    /// cert_format / cert_chain so the v1 sig stays covering exactly the
    /// same payload as before NPS-RFC-0002.
    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nid".into(), json!(self.nid));
        m.insert("pub_key".into(), json!(self.pub_key));
        if let Some(v) = &self.meta {
            m.insert("metadata".into(), Value::Object(v.clone()));
        }
        if let Some(l) = &self.assurance_level {
            m.insert("assurance_level".into(), json!(l.wire));
        }
        m
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        if let Some(s) = &self.signature {
            m.insert("signature".into(), json!(s));
        }
        if let Some(s) = &self.cert_format {
            m.insert("cert_format".into(), json!(s));
        }
        if let Some(c) = &self.cert_chain {
            m.insert("cert_chain".into(), json!(c));
        }
        if let Some(s) = &self.ocsp_staple {
            m.insert("ocsp_staple".into(), json!(s));
        }
        if let Some(r) = &self.reputation_policy {
            if let Ok(v) = serde_json::to_value(r) {
                m.insert("reputation_policy".into(), v);
            }
        }
        if let Some(roles) = &self.node_roles {
            m.insert("node_roles".into(), json!(roles));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let assurance_level = d
            .get("assurance_level")
            .and_then(Value::as_str)
            .and_then(|s| crate::assurance_level::AssuranceLevel::from_wire(s).ok());
        let cert_chain = d.get("cert_chain").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
        let reputation_policy = d
            .get("reputation_policy")
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let node_roles = d.get("node_roles").and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
        Ok(IdentFrame {
            nid: get_str(d, "nid")?.to_string(),
            pub_key: get_str(d, "pub_key")?.to_string(),
            meta: d.get("metadata").and_then(Value::as_object).cloned(),
            signature: opt_str(d, "signature").map(str::to_string),
            assurance_level,
            cert_format: opt_str(d, "cert_format").map(str::to_string),
            cert_chain,
            ocsp_staple: opt_str(d, "ocsp_staple").map(str::to_string),
            reputation_policy,
            node_roles,
        })
    }
}

// ── TrustFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustFrame {
    pub grantor_nid: String,
    pub grantee_ca: String,
    pub trust_scope: Vec<String>,
    pub nodes: Vec<String>,
    pub issued_at: String,
    pub expires_at: String,
    pub serial: String,
    pub signer_nid: String,
    pub signature: String,
}

impl TrustFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Trust
    }

    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("frame".into(), json!("0x21"));
        m.insert("grantor_nid".into(), json!(self.grantor_nid));
        m.insert("grantee_ca".into(), json!(self.grantee_ca));
        m.insert("trust_scope".into(), json!(self.trust_scope));
        m.insert("nodes".into(), json!(self.nodes));
        m.insert("issued_at".into(), json!(self.issued_at));
        m.insert("expires_at".into(), json!(self.expires_at));
        m.insert("serial".into(), json!(self.serial));
        m.insert("signer_nid".into(), json!(self.signer_nid));
        m
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        m.insert("signature".into(), json!(self.signature));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let grantor_nid = opt_str(d, "grantor_nid")
            .or_else(|| opt_str(d, "issuer_nid"))
            .ok_or_else(|| NpsError::Frame("missing field: grantor_nid".into()))?
            .to_string();
        let grantee_ca = opt_str(d, "grantee_ca")
            .or_else(|| opt_str(d, "subject_nid"))
            .ok_or_else(|| NpsError::Frame("missing field: grantee_ca".into()))?
            .to_string();
        let trust_scope = string_list(d, "trust_scope")
            .or_else(|| string_list(d, "scopes"))
            .unwrap_or_default();
        Ok(TrustFrame {
            grantor_nid,
            grantee_ca,
            trust_scope,
            nodes: string_list(d, "nodes").unwrap_or_default(),
            issued_at: opt_str(d, "issued_at").unwrap_or("").to_string(),
            expires_at: get_str(d, "expires_at")?.to_string(),
            serial: opt_str(d, "serial").unwrap_or("").to_string(),
            signer_nid: opt_str(d, "signer_nid")
                .or_else(|| opt_str(d, "grantor_nid"))
                .or_else(|| opt_str(d, "issuer_nid"))
                .unwrap_or("")
                .to_string(),
            signature: get_str(d, "signature")?.to_string(),
        })
    }
}

// ── RevokeFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RevokeFrame {
    pub target_nid: String,
    pub serial: Option<String>,
    pub reason: String,
    pub revoked_at: String,
    pub parent_nid: Option<String>,
    pub signer_nid: String,
    pub signature: String,
}

impl RevokeFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Revoke
    }

    pub fn unsigned_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("frame".into(), json!("0x22"));
        m.insert("target_nid".into(), json!(self.target_nid));
        m.insert("reason".into(), json!(self.reason));
        m.insert("revoked_at".into(), json!(self.revoked_at));
        m.insert("signer_nid".into(), json!(self.signer_nid));
        if let Some(v) = &self.serial {
            m.insert("serial".into(), json!(v));
        }
        if let Some(v) = &self.parent_nid {
            m.insert("parent_nid".into(), json!(v));
        }
        m
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = self.unsigned_dict();
        m.insert("signature".into(), json!(self.signature));
        m
    }

    pub fn validate(&self) -> NpsResult<()> {
        if self.reason == REASON_PARENT_REVOKED {
            if self.parent_nid.as_deref().unwrap_or("").is_empty() {
                return Err(NpsError::Frame(format!(
                    "{REVOKE_FRAME_INVALID}: parent_nid is required when reason=parent_revoked"
                )));
            }
        } else if self.parent_nid.is_some() {
            return Err(NpsError::Frame(format!(
                "{REVOKE_FRAME_INVALID}: parent_nid must be omitted unless reason=parent_revoked"
            )));
        }
        Ok(())
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let frame = RevokeFrame {
            target_nid: opt_str(d, "target_nid")
                .or_else(|| opt_str(d, "nid"))
                .ok_or_else(|| NpsError::Frame("missing field: target_nid".into()))?
                .to_string(),
            serial: opt_str(d, "serial").map(str::to_string),
            reason: get_str(d, "reason")?.to_string(),
            revoked_at: get_str(d, "revoked_at")?.to_string(),
            parent_nid: opt_str(d, "parent_nid").map(str::to_string),
            signer_nid: opt_str(d, "signer_nid").unwrap_or("").to_string(),
            signature: opt_str(d, "signature").unwrap_or("").to_string(),
        };
        frame.validate()?;
        Ok(frame)
    }
}

fn string_list(d: &FrameDict, k: &str) -> Option<Vec<String>> {
    d.get(k).and_then(Value::as_array).map(|a| {
        a.iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    })
}
