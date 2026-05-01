// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::{Duration, Instant};
use crate::dns_txt::{DnsTxtLookup, extract_host_from_target, parse_nps_txt_record};
use crate::frames::AnnounceFrame;

#[derive(Debug, Clone)]
pub struct ResolveResult {
    pub host:     String,
    pub port:     u64,
    pub protocol: String,
}

struct Entry {
    frame:   AnnounceFrame,
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
        self.store.insert(frame.nid.clone(), Entry { frame, expires });
    }

    pub fn get_by_nid(&self, nid: &str) -> Option<&AnnounceFrame> {
        let now = (self.clock)();
        self.store.get(nid)
            .filter(|e| e.expires > now)
            .map(|e| &e.frame)
    }

    pub fn resolve(&self, target: &str) -> Option<ResolveResult> {
        let now = (self.clock)();
        self.store.values()
            .filter(|e| e.expires > now)
            .find(|e| Self::nwp_target_matches_nid(&e.frame.nid, target))
            .and_then(|e| {
                e.frame.addresses.first().map(|addr| ResolveResult {
                    host:     addr.get("host").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    port:     addr.get("port").and_then(|v| v.as_u64()).unwrap_or(17433),
                    protocol: addr.get("protocol").and_then(|v| v.as_str()).unwrap_or("nwp").to_string(),
                })
            })
    }

    pub fn get_all(&self) -> Vec<&AnnounceFrame> {
        let now = (self.clock)();
        self.store.values()
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
        let nid_path = parts[4..].join("/");  // e.g. "data"

        // Parse target URL: nwp://authority/path...
        let rest = match target.strip_prefix("nwp://") {
            Some(r) => r,
            None    => return false,
        };
        let slash = match rest.find('/') {
            Some(i) => i,
            None    => return false,
        };
        let authority = &rest[..slash];
        let path      = &rest[slash + 1..]; // without leading /

        if authority != nid_host { return false; }

        // Path must be equal or a sub-path (must not match siblings like "dataset" vs "data")
        path == nid_path || path.starts_with(&format!("{nid_path}/"))
    }
}

impl Default for InMemoryNdpRegistry {
    fn default() -> Self {
        Self::new()
    }
}
