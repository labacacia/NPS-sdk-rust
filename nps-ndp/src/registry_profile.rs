// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Transport-independent NDP 0.12 registry conformance profile.

use crate::error_codes::{
    ANNOUNCE_CONFLICT, ANNOUNCE_PROFILE_VIOLATION, ANNOUNCE_SIGNATURE_INVALID, ANNOUNCE_STALE,
    CLUSTER_SPLIT, GRAPH_SEQ_ROLLBACK,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Portable Announce admission outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NdpRegistryDecision {
    Accepted,
    Duplicate,
    Refreshed,
    Removed,
    Rejected,
}

impl NdpRegistryDecision {
    /// Lowercase wire name used by the shared transcript corpus.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Duplicate => "duplicate",
            Self::Refreshed => "refreshed",
            Self::Removed => "removed",
            Self::Rejected => "rejected",
        }
    }
}

/// Result of one portable Announce admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpRegistryAdmission {
    pub decision: NdpRegistryDecision,
    pub error_code: Option<&'static str>,
}

/// Result of deterministic cluster-Anchor resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpClusterSelection {
    pub nid: Option<String>,
    pub epoch: Option<u64>,
    pub error_code: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct Entry {
    frame: Value,
    signed_digest: String,
    expires_at: i64,
}

/// Return the canonical NDP 0.12 Announce signed body.
pub fn canonical_announce_json(frame: &Value) -> Result<String, &'static str> {
    let object = frame.as_object().ok_or("AnnounceFrame must be an object")?;
    let mut root = object.clone();
    for field in ["frame", "signature", "health", "last_seen"] {
        root.remove(field);
    }
    root.retain(|_, value| !value.is_null());
    root.entry("heartbeat_interval_ms")
        .or_insert_with(|| Value::from(60_000));
    let mut output = String::new();
    write_canonical(&Value::Object(root), &mut output);
    Ok(output)
}

/// Verify an `ed25519:<base64url>` signature over an Announce signed body.
pub fn verify_announce_signature(
    frame: &Value,
    encoded_public_key: &str,
    encoded_signature: &str,
) -> bool {
    let Some(key) = nps_nip::ca::decode_public_key(encoded_public_key) else {
        return false;
    };
    let Some(signature_body) = encoded_signature.strip_prefix("ed25519:") else {
        return false;
    };
    let Ok(signature_bytes) = B64URL.decode(signature_body.as_bytes()) else {
        return false;
    };
    let Ok(signature_array) = <[u8; 64]>::try_from(signature_bytes) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_array);
    let Ok(canonical) = canonical_announce_json(frame) else {
        return false;
    };
    key.verify(canonical.as_bytes(), &signature).is_ok()
}

/// NDP 0.12 in-memory registry state machine.
pub struct NdpRegistryProfile {
    security_profile: String,
    entries: HashMap<String, Entry>,
    sequences: HashMap<String, u64>,
}

impl NdpRegistryProfile {
    pub fn new(security_profile: impl Into<String>) -> Self {
        Self {
            security_profile: security_profile.into(),
            entries: HashMap::new(),
            sequences: HashMap::new(),
        }
    }

    pub fn apply_announce(
        &mut self,
        frame: &Value,
        signature_valid: bool,
        received_at: i64,
    ) -> NdpRegistryAdmission {
        if !signature_valid {
            return reject(ANNOUNCE_SIGNATURE_INVALID);
        }
        let Some(object) = frame.as_object() else {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        };
        let Some(nid) = string_value(object, "nid") else {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        };
        let Some(timestamp) = time_value(object, "timestamp") else {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        };
        let sequence = match object.get("graph_seq") {
            Some(value) => match value.as_u64() {
                Some(value) => value,
                None => return reject(ANNOUNCE_PROFILE_VIOLATION),
            },
            None if self.security_profile == "local-dev" => 0,
            None => return reject(ANNOUNCE_PROFILE_VIOLATION),
        };
        let Some(ttl) = number_value(object, "ttl").filter(|value| *value <= u32::MAX.into())
        else {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        };
        if !bridge_shape_is_valid(object) {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        }
        if self.security_profile != "local-dev" && (received_at - timestamp).abs() > 300 {
            return reject(ANNOUNCE_SIGNATURE_INVALID);
        }

        let Ok(canonical) = canonical_announce_json(frame) else {
            return reject(ANNOUNCE_PROFILE_VIOLATION);
        };
        let digest = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        if let Some(highest) = self.sequences.get(nid).copied() {
            if sequence < highest {
                return reject(GRAPH_SEQ_ROLLBACK);
            }
            if sequence == highest {
                let Some(current) = self.entries.get(nid) else {
                    return accepted(NdpRegistryDecision::Duplicate);
                };
                if current.signed_digest != digest {
                    return reject(ANNOUNCE_CONFLICT);
                }
                if same_liveness(&current.frame, frame) {
                    return accepted(NdpRegistryDecision::Duplicate);
                }
                let Some(expires_at) = freshness_deadline(object) else {
                    return reject(ANNOUNCE_STALE);
                };
                if expires_at <= received_at {
                    return reject(ANNOUNCE_STALE);
                }
                self.entries.insert(
                    nid.to_string(),
                    Entry {
                        frame: frame.clone(),
                        signed_digest: digest,
                        expires_at,
                    },
                );
                return accepted(NdpRegistryDecision::Refreshed);
            }
        }

        if ttl == 0 {
            self.sequences.insert(nid.to_string(), sequence);
            self.entries.remove(nid);
            return accepted(NdpRegistryDecision::Removed);
        }
        let Some(expires_at) = freshness_deadline(object) else {
            return reject(ANNOUNCE_STALE);
        };
        if expires_at <= received_at {
            return reject(ANNOUNCE_STALE);
        }
        self.sequences.insert(nid.to_string(), sequence);
        self.entries.insert(
            nid.to_string(),
            Entry {
                frame: frame.clone(),
                signed_digest: digest,
                expires_at,
            },
        );
        accepted(NdpRegistryDecision::Accepted)
    }

    pub fn live_nids(&self, now: i64) -> Vec<String> {
        let mut result: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .map(|(nid, _)| nid.clone())
            .collect();
        result.sort();
        result
    }

    pub fn highest_sequences(&self) -> BTreeMap<String, u64> {
        self.sequences
            .iter()
            .map(|(nid, sequence)| (nid.clone(), *sequence))
            .collect()
    }

    pub fn has_stale_entry(&self, now: i64) -> bool {
        self.entries.values().any(|entry| entry.expires_at <= now)
    }

    pub fn resolve_cluster(&self, cluster_anchor: &str, now: i64) -> NdpClusterSelection {
        let members: Vec<(&String, u64)> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .filter_map(|(nid, entry)| {
                let frame = entry.frame.as_object()?;
                if string_value(frame, "cluster_anchor") != Some(cluster_anchor)
                    || !strings(frame, "node_roles").contains(&"anchor")
                {
                    return None;
                }
                Some((nid, number_value(frame, "cluster_epoch").unwrap_or(1)))
            })
            .collect();
        let Some(top) = members.iter().map(|(_, epoch)| *epoch).max() else {
            return NdpClusterSelection {
                nid: None,
                epoch: None,
                error_code: None,
            };
        };
        let mut leaders: Vec<String> = members
            .iter()
            .filter(|(_, epoch)| *epoch == top)
            .map(|(nid, _)| (*nid).clone())
            .collect();
        leaders.sort();
        if leaders.len() == 1 {
            NdpClusterSelection {
                nid: leaders.into_iter().next(),
                epoch: Some(top),
                error_code: None,
            }
        } else {
            NdpClusterSelection {
                nid: None,
                epoch: None,
                error_code: Some(CLUSTER_SPLIT),
            }
        }
    }

    pub fn discover_bridges(&self, direction: &str, protocol: &str, now: i64) -> Vec<String> {
        let field = match direction {
            "inbound" => "bridge_inbound_protocols",
            "outbound" => "bridge_protocols",
            _ => return Vec::new(),
        };
        let mut result: Vec<String> = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.expires_at > now)
            .filter_map(|(nid, entry)| {
                let frame = entry.frame.as_object()?;
                if string_value(frame, "health") == Some("draining")
                    || !is_bridge(frame)
                    || !strings(frame, field).contains(&protocol)
                {
                    return None;
                }
                Some(nid.clone())
            })
            .collect();
        result.sort();
        result
    }
}

impl Default for NdpRegistryProfile {
    fn default() -> Self {
        Self::new("local-dev")
    }
}

fn accepted(decision: NdpRegistryDecision) -> NdpRegistryAdmission {
    NdpRegistryAdmission {
        decision,
        error_code: None,
    }
}

fn reject(error_code: &'static str) -> NdpRegistryAdmission {
    NdpRegistryAdmission {
        decision: NdpRegistryDecision::Rejected,
        error_code: Some(error_code),
    }
}

fn bridge_shape_is_valid(frame: &Map<String, Value>) -> bool {
    let Some((outbound_present, outbound)) = protocol_list(frame, "bridge_protocols") else {
        return false;
    };
    let Some((inbound_present, inbound)) = protocol_list(frame, "bridge_inbound_protocols") else {
        return false;
    };
    if is_bridge(frame) {
        !outbound.is_empty() || !inbound.is_empty()
    } else {
        !outbound_present && !inbound_present
    }
}

fn protocol_list<'a>(frame: &'a Map<String, Value>, field: &str) -> Option<(bool, Vec<&'a str>)> {
    let Some(value) = frame.get(field) else {
        return Some((false, Vec::new()));
    };
    let items = value.as_array()?;
    let mut values = Vec::with_capacity(items.len());
    for item in items {
        let value = item.as_str().filter(|value| !value.trim().is_empty())?;
        values.push(value);
    }
    Some((true, values))
}

fn is_bridge(frame: &Map<String, Value>) -> bool {
    strings(frame, "node_roles").contains(&"bridge")
        || string_value(frame, "node_type") == Some("bridge")
}

fn strings<'a>(frame: &'a Map<String, Value>, field: &str) -> Vec<&'a str> {
    frame
        .get(field)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn string_value<'a>(frame: &'a Map<String, Value>, field: &str) -> Option<&'a str> {
    frame.get(field).and_then(Value::as_str)
}

fn number_value(frame: &Map<String, Value>, field: &str) -> Option<u64> {
    frame.get(field).and_then(Value::as_u64)
}

fn time_value(frame: &Map<String, Value>, field: &str) -> Option<i64> {
    let value = string_value(frame, field)?;
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(|time| time.unix_timestamp())
}

fn freshness_deadline(frame: &Map<String, Value>) -> Option<i64> {
    let source = time_value(frame, "last_seen").or_else(|| time_value(frame, "timestamp"))?;
    let ttl = i64::try_from(number_value(frame, "ttl").unwrap_or(0)).ok()?;
    source.checked_add(ttl)
}

fn same_liveness(left: &Value, right: &Value) -> bool {
    left.get("health") == right.get("health") && left.get("last_seen") == right.get("last_seen")
}

fn write_canonical(value: &Value, output: &mut String) {
    match value {
        Value::Object(object) => {
            output.push('{');
            let mut fields: Vec<(&String, &Value)> = object
                .iter()
                .filter(|(_, value)| !value.is_null())
                .collect();
            fields.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in fields.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).expect("key serializes"));
                output.push(':');
                write_canonical(value, output);
            }
            output.push('}');
        }
        Value::Array(items) => {
            output.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    output.push(',');
                }
                write_canonical(item, output);
            }
            output.push(']');
        }
        scalar => output.push_str(&serde_json::to_string(scalar).expect("scalar serializes")),
    }
}
