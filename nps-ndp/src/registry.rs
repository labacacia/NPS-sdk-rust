// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use crate::dns_txt::{extract_host_from_target, parse_nps_txt_record, DnsTxtLookup};
use crate::error_codes::CLUSTER_SPLIT;
use crate::frames::AnnounceFrame;
use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ── Cluster resolution (NPS-CR-0009 §3.1) ────────────────────────────────────

/// Split-brain fault: a `cluster_anchor` cluster has more than one LIVE member
/// tied at the top `cluster_epoch`. The Registry refuses to resolve arbitrarily.
///
/// Carries the contested cluster NID and the contested epoch, and reports the
/// wire error code `NDP-CLUSTER-SPLIT` (NPS status `NPS-CLIENT-CONFLICT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NdpClusterSplitError {
    pub cluster_anchor: String,
    pub epoch: u64,
}

impl NdpClusterSplitError {
    pub fn new(cluster_anchor: impl Into<String>, epoch: u64) -> Self {
        NdpClusterSplitError {
            cluster_anchor: cluster_anchor.into(),
            epoch,
        }
    }

    /// Always `NDP-CLUSTER-SPLIT`.
    pub fn error_code(&self) -> &'static str {
        CLUSTER_SPLIT
    }

    /// Always `NPS-CLIENT-CONFLICT` (HTTP 409).
    pub fn nps_status(&self) -> &'static str {
        crate::error_codes::to_nps_status(CLUSTER_SPLIT)
    }
}

impl fmt::Display for NdpClusterSplitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{CLUSTER_SPLIT}: cluster '{}' has multiple live active Anchors at epoch {}.",
            self.cluster_anchor, self.epoch
        )
    }
}

impl std::error::Error for NdpClusterSplitError {}

/// Highest-epoch cluster resolution (NPS-CR-0009 §3.1 / NDP §9).
///
/// Implemented once as a trait default so **every** registry implementation
/// inherits the identical rule (the .NET reference expresses this as a default
/// interface method on `INdpRegistry`). An implementor only supplies
/// [`live_frames`][NdpClusterResolution::live_frames] — the liveness/TTL filter
/// — and gets `resolve_cluster` for free.
pub trait NdpClusterResolution {
    /// All LIVE (non-expired) announcements known to this registry.
    fn live_frames(&self) -> Vec<&AnnounceFrame>;

    /// Resolve the currently active Anchor of `cluster_anchor`.
    ///
    /// * `Ok(None)`   — no live member advertises this cluster (NOT an error).
    /// * `Ok(Some(f))` — the single member at the top epoch.
    /// * `Err(..)`     — two or more live members tie at the top epoch.
    ///
    /// Absent `cluster_epoch` coerces to 1 **at comparison time**, so two live
    /// members that both omit the field DO collide and split — that is the
    /// specified behaviour, not an edge case to special-case away. Role is not
    /// filtered: any live entry whose `cluster_anchor` matches participates.
    fn resolve_cluster(
        &self,
        cluster_anchor: &str,
    ) -> Result<Option<&AnnounceFrame>, NdpClusterSplitError> {
        if cluster_anchor.is_empty() {
            return Ok(None);
        }
        let members: Vec<&AnnounceFrame> = self
            .live_frames()
            .into_iter()
            // Ordinal (byte-exact) equality — no case folding, no normalisation.
            .filter(|f| f.cluster_anchor.as_deref() == Some(cluster_anchor))
            .collect();
        if members.is_empty() {
            return Ok(None);
        }
        let top = members
            .iter()
            .map(|f| f.effective_cluster_epoch())
            .max()
            .unwrap_or(AnnounceFrame::DEFAULT_CLUSTER_EPOCH);
        let leaders: Vec<&AnnounceFrame> = members
            .into_iter()
            .filter(|f| f.effective_cluster_epoch() == top)
            .collect();
        if leaders.len() > 1 {
            return Err(NdpClusterSplitError::new(cluster_anchor, top));
        }
        // Reached only when exactly one leader exists — no tiebreak.
        Ok(leaders.into_iter().next())
    }
}

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub host: String,
    pub port: u64,
    pub protocol: String,
}

struct Entry {
    frame: AnnounceFrame,
    expires: Instant,
}

pub struct InMemoryNdpRegistry {
    store: HashMap<String, Entry>,
    /// Injectable clock for testing
    pub clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl InMemoryNdpRegistry {
    pub fn new() -> Self {
        InMemoryNdpRegistry {
            store: HashMap::new(),
            clock: Box::new(Instant::now),
        }
    }

    pub fn announce(&mut self, frame: AnnounceFrame) {
        if frame.ttl == 0 {
            self.store.remove(&frame.nid);
            return;
        }
        let expires = (self.clock)() + Duration::from_secs(frame.ttl);
        self.store
            .insert(frame.nid.clone(), Entry { frame, expires });
    }

    pub fn get_by_nid(&self, nid: &str) -> Option<&AnnounceFrame> {
        let now = (self.clock)();
        self.store
            .get(nid)
            .filter(|e| e.expires > now)
            .map(|e| &e.frame)
    }

    pub fn resolve(&self, target: &str) -> Option<ResolveResult> {
        let now = (self.clock)();
        self.store
            .values()
            .filter(|e| e.expires > now)
            .find(|e| Self::nwp_target_matches_nid(&e.frame.nid, target))
            .and_then(|e| {
                e.frame.addresses.first().map(|addr| ResolveResult {
                    host: addr
                        .get("host")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    port: addr.get("port").and_then(|v| v.as_u64()).unwrap_or(17433),
                    protocol: addr
                        .get("protocol")
                        .and_then(|v| v.as_str())
                        .unwrap_or("nwp")
                        .to_string(),
                })
            })
    }

    pub fn get_all(&self) -> Vec<&AnnounceFrame> {
        let now = (self.clock)();
        self.store
            .values()
            .filter(|e| e.expires > now)
            .map(|e| &e.frame)
            .collect()
    }

    /// Resolve a target first from the in-memory registry, then via DNS TXT fallback.
    ///
    /// Lookup order:
    /// 1. Call [`Self::resolve`] — return immediately if a live in-memory entry matches.
    /// 2. Extract the hostname from `target` (expects `nwp://hostname/path` form).
    /// 3. Look up `_nps-node.{hostname}` TXT records via the provided `lookup` implementation.
    /// 4. Parse each record with [`parse_nps_txt_record`]; return the first valid result.
    ///
    /// Returns `None` if both the registry and DNS lookup yield no valid result.
    pub async fn resolve_via_dns<L: DnsTxtLookup>(
        &self,
        target: &str,
        lookup: &L,
    ) -> Option<ResolveResult> {
        // 1. Try in-memory registry first.
        if let Some(result) = self.resolve(target) {
            return Some(result);
        }

        // 2. Extract hostname from the NWP target URL.
        let host = extract_host_from_target(target)?;

        // 3. Query `_nps-node.{host}` for TXT records.
        let dns_name = format!("_nps-node.{host}");
        let records = lookup.lookup_txt(&dns_name).await.ok()?;

        // 4. Parse records; return the first valid one.
        for record in &records {
            if let Some(result) = parse_nps_txt_record(record, host) {
                return Some(result);
            }
        }

        None
    }

    /// Match a `nwp://authority/path` URL against a `urn:nps:node:{host}:{path}` NID.
    pub fn nwp_target_matches_nid(nid: &str, target: &str) -> bool {
        // Parse NID: urn:nps:node:{host}:{path_segment}
        let parts: Vec<&str> = nid.split(':').collect();
        if parts.len() < 5 || parts[0] != "urn" || parts[1] != "nps" || parts[2] != "node" {
            return false;
        }
        let nid_host = parts[3];
        let nid_path = parts[4..].join("/"); // e.g. "data"

        // Parse target URL: nwp://authority/path...
        let rest = match target.strip_prefix("nwp://") {
            Some(r) => r,
            None => return false,
        };
        let slash = match rest.find('/') {
            Some(i) => i,
            None => return false,
        };
        let authority = &rest[..slash];
        let path = &rest[slash + 1..]; // without leading /

        if authority != nid_host {
            return false;
        }

        // Path must be equal or a sub-path (must not match siblings like "dataset" vs "data")
        path == nid_path || path.starts_with(&format!("{nid_path}/"))
    }
}

impl Default for InMemoryNdpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// The in-memory registry inherits the highest-epoch rule unchanged; liveness
/// comes from `get_all()`, which drops entries past `registration_time + ttl`
/// (and `announce` with `ttl == 0` evicts immediately — an orderly shutdown
/// removes that Anchor from the election).
impl NdpClusterResolution for InMemoryNdpRegistry {
    fn live_frames(&self) -> Vec<&AnnounceFrame> {
        self.get_all()
    }
}
