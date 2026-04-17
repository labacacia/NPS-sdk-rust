// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::time::{Duration, Instant};
use sha2::{Digest, Sha256};
use serde_json::Value;
use crate::error::{NpsError, NpsResult};

#[derive(Debug, Clone)]
struct Entry {
    schema:    serde_json::Map<String, Value>,
    anchor_id: String,
    expires:   Instant,
}

pub struct AnchorFrameCache {
    store:  HashMap<String, Entry>,
    /// Injectable clock for testing — returns fake "now"
    pub clock: Box<dyn Fn() -> Instant + Send + Sync>,
}

impl AnchorFrameCache {
    pub fn new() -> Self {
        AnchorFrameCache {
            store: HashMap::new(),
            clock: Box::new(Instant::now),
        }
    }

    /// Compute anchor_id as hex-encoded SHA-256 of the canonical (sorted-field) JSON.
    pub fn compute_anchor_id(schema: &serde_json::Map<String, Value>) -> String {
        let mut sorted: Vec<(&String, &Value)> = schema.iter().collect();
        sorted.sort_by_key(|(k, _)| k.as_str());
        let canonical = serde_json::to_string(&serde_json::Value::Object(
            sorted.iter().map(|(k, v)| ((*k).clone(), (*v).clone())).collect()
        )).unwrap_or_default();
        let digest = Sha256::digest(canonical.as_bytes());
        format!("sha256:{}", hex::encode(digest))
    }

    /// Store schema with TTL. Returns `AnchorPoison` if the anchor_id is already cached
    /// with a *different* schema.
    pub fn set(&mut self, schema: serde_json::Map<String, Value>, ttl_secs: u64) -> NpsResult<String> {
        let anchor_id = Self::compute_anchor_id(&schema);
        let now       = (self.clock)();
        let expires   = now + Duration::from_secs(ttl_secs);

        if let Some(existing) = self.store.get(&anchor_id) {
            if existing.schema != schema && existing.expires > now {
                return Err(NpsError::AnchorPoison(format!(
                    "anchor {anchor_id} already cached with different schema"
                )));
            }
        }
        self.store.insert(anchor_id.clone(), Entry { schema, anchor_id: anchor_id.clone(), expires });
        Ok(anchor_id)
    }

    pub fn get(&self, anchor_id: &str) -> Option<&serde_json::Map<String, Value>> {
        let now = (self.clock)();
        self.store.get(anchor_id)
            .filter(|e| e.expires > now)
            .map(|e| &e.schema)
    }

    pub fn get_required(&self, anchor_id: &str) -> NpsResult<&serde_json::Map<String, Value>> {
        self.get(anchor_id)
            .ok_or_else(|| NpsError::AnchorNotFound(anchor_id.to_string()))
    }

    pub fn invalidate(&mut self, anchor_id: &str) {
        self.store.remove(anchor_id);
    }

    pub fn evict_expired(&mut self) {
        let now = (self.clock)();
        self.store.retain(|_, e| e.expires > now);
    }

    pub fn len(&self) -> usize {
        let now = (self.clock)();
        self.store.values().filter(|e| e.expires > now).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for AnchorFrameCache {
    fn default() -> Self {
        Self::new()
    }
}
