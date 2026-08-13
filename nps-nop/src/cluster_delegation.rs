// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Delegation re-resolution across an Anchor failover (NPS-CR-0009 §3.4).
//!
//! Port of `impl/dotnet/src/NPS.NOP/Orchestration/ClusterDelegationResolver.cs`.
//! Rust has no NOP orchestrator, so this is a standalone module the composition
//! root wires in.
//!
//! The cluster lookup is **injected**, so NOP carries no NDP dependency: the
//! composition root adapts `AnnounceFrame → ClusterAnchorInfo(frame.nid,
//! frame.cluster_epoch ?? 1)`.
//!
//! Concurrency: the cache lives behind interior mutability
//! ([`std::sync::Mutex`]), so `&self` is enough for readers and writers alike
//! and the compare-then-set in [`ClusterDelegationResolver::on_anchor_failover`]
//! is atomic.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::frames::DelegateFrame;

/// The Anchor currently owning a cluster, and the epoch it owns it under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterAnchorInfo {
    pub active_nid: String,
    pub cluster_epoch: u64,
}

impl ClusterAnchorInfo {
    pub fn new(active_nid: impl Into<String>, cluster_epoch: u64) -> Self {
        ClusterAnchorInfo {
            active_nid: active_nid.into(),
            cluster_epoch,
        }
    }
}

/// Resolves a delegation's target Anchor, keeping a per-cluster cache that only
/// ever moves forward.
pub struct ClusterDelegationResolver<F>
where
    F: Fn(&str) -> Option<ClusterAnchorInfo>,
{
    resolve_cluster: F,
    /// Ordinal (byte-exact) cluster keys.
    active: Mutex<HashMap<String, ClusterAnchorInfo>>,
}

impl<F> ClusterDelegationResolver<F>
where
    F: Fn(&str) -> Option<ClusterAnchorInfo>,
{
    pub fn new(resolve_cluster: F) -> Self {
        ClusterDelegationResolver {
            resolve_cluster,
            active: Mutex::new(HashMap::new()),
        }
    }

    /// Which NID a delegation should be dispatched to.
    ///
    /// With no `target_cluster_anchor` the frame's `target_agent_nid` is used
    /// verbatim and **no cluster lookup happens at all**.
    ///
    /// `None` means "cannot resolve" — the **caller** decides retry vs fail;
    /// this never raises for that.
    pub fn resolve_delegate_target(&self, frame: &DelegateFrame) -> Option<String> {
        match frame.target_cluster_anchor.as_deref() {
            None => Some(frame.target_nid.clone()),
            Some("") => Some(frame.target_nid.clone()),
            Some(cluster) => self.resolve_active(cluster).map(|i| i.active_nid),
        }
    }

    /// The cached owner of `cluster_anchor`, falling back to a fresh lookup.
    ///
    /// A cache hit performs **no** lookup. A negative result is **not** cached,
    /// so a cluster that comes up later is picked up on the next call.
    pub fn resolve_active(&self, cluster_anchor: &str) -> Option<ClusterAnchorInfo> {
        if cluster_anchor.is_empty() {
            return None;
        }
        if let Some(hit) = self.active.lock().unwrap().get(cluster_anchor) {
            return Some(hit.clone());
        }
        let fresh = (self.resolve_cluster)(cluster_anchor)?;
        self.active
            .lock()
            .unwrap()
            .insert(cluster_anchor.to_string(), fresh.clone());
        Some(fresh)
    }

    /// Record an observed `anchor_failover`, redirecting subsequent delegations.
    ///
    /// **Monotonic per cluster**: `cluster_epoch <= cached` is STALE and is
    /// ignored, returning `false`. *Equal is stale*, not idempotent-accept — an
    /// equal epoch from a different NID is exactly the split-brain case the
    /// registry refuses to resolve, and accepting it here would silently pick a
    /// side. A first observation is accepted unconditionally.
    pub fn on_anchor_failover(
        &self,
        cluster_anchor: &str,
        successor_nid: &str,
        cluster_epoch: u64,
    ) -> bool {
        if cluster_anchor.is_empty() || successor_nid.is_empty() {
            return false;
        }
        // The lock makes compare-then-set atomic, which is what the reference's
        // CAS retry loop achieves.
        let mut map = self.active.lock().unwrap();
        match map.get(cluster_anchor) {
            Some(cur) if cluster_epoch <= cur.cluster_epoch => false,
            _ => {
                map.insert(
                    cluster_anchor.to_string(),
                    ClusterAnchorInfo::new(successor_nid, cluster_epoch),
                );
                true
            }
        }
    }

    /// Drop the cached owner of a cluster.
    ///
    /// This is the documented recovery path after a dispatch was rejected with
    /// `NWP-ANCHOR-NOT-LEADER`: invalidate, take a fresh lookup, retry. The
    /// cache has no TTL — it is invalidated only by a strictly-newer
    /// `anchor_failover` or by this call.
    pub fn invalidate(&self, cluster_anchor: &str) {
        self.active.lock().unwrap().remove(cluster_anchor);
    }

    /// Currently cached clusters — diagnostics only.
    pub fn cached_len(&self) -> usize {
        self.active.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const CLUSTER: &str = "urn:nps:cluster:x:main";
    const AGENT: &str = "urn:nps:agent:x:w1";
    const ANCHOR_A: &str = "urn:nps:node:x:anchor-a";
    const ANCHOR_B: &str = "urn:nps:node:x:anchor-b";

    fn frame(cluster: Option<&str>) -> DelegateFrame {
        DelegateFrame {
            task_id: "t1".into(),
            subtask_id: "s1".into(),
            action: "do".into(),
            target_nid: AGENT.into(),
            inputs: None,
            config: Some(serde_json::json!({})),
            idempotency_key: None,
            target_cluster_anchor: cluster.map(str::to_string),
        }
    }

    #[test]
    fn without_cluster_target_uses_agent_nid() {
        // The lookup panics if called — it must not be.
        let r = ClusterDelegationResolver::new(|_: &str| -> Option<ClusterAnchorInfo> {
            panic!("NDP lookup must not be invoked")
        });
        assert_eq!(
            r.resolve_delegate_target(&frame(None)).as_deref(),
            Some(AGENT)
        );
        assert_eq!(
            r.resolve_delegate_target(&frame(Some(""))).as_deref(),
            Some(AGENT)
        );
    }

    #[test]
    fn cluster_target_resolves_to_active_anchor_and_caches() {
        let calls = AtomicUsize::new(0);
        let r = ClusterDelegationResolver::new(|_: &str| {
            calls.fetch_add(1, Ordering::SeqCst);
            Some(ClusterAnchorInfo::new(ANCHOR_A, 1))
        });

        let f = frame(Some(CLUSTER));
        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_A));
        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_A));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "cache hit must not look up"
        );
    }

    #[test]
    fn failover_event_redirects_subsequent_delegations_to_the_successor() {
        let r = ClusterDelegationResolver::new(|_: &str| Some(ClusterAnchorInfo::new(ANCHOR_A, 1)));
        let f = frame(Some(CLUSTER));
        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_A));

        assert!(r.on_anchor_failover(CLUSTER, ANCHOR_B, 2));
        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_B));
    }

    #[test]
    fn stale_failover_event_is_ignored() {
        let r = ClusterDelegationResolver::new(|_: &str| Some(ClusterAnchorInfo::new(ANCHOR_A, 1)));
        assert!(r.on_anchor_failover(CLUSTER, ANCHOR_B, 3));

        // EQUAL is stale, not idempotent-accept.
        assert!(!r.on_anchor_failover(CLUSTER, "urn:nps:node:x:anchor-c", 3));
        // Lower is stale.
        assert!(!r.on_anchor_failover(CLUSTER, "urn:nps:node:x:anchor-c", 2));

        assert_eq!(
            r.resolve_active(CLUSTER),
            Some(ClusterAnchorInfo::new(ANCHOR_B, 3))
        );
    }

    #[test]
    fn invalidate_forces_a_fresh_lookup() {
        let calls = AtomicUsize::new(0);
        let r = ClusterDelegationResolver::new(|_: &str| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            Some(if n == 0 {
                ClusterAnchorInfo::new(ANCHOR_A, 1)
            } else {
                ClusterAnchorInfo::new(ANCHOR_B, 2)
            })
        });
        let f = frame(Some(CLUSTER));

        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_A));
        r.invalidate(CLUSTER);
        assert_eq!(r.resolve_delegate_target(&f).as_deref(), Some(ANCHOR_B));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn first_observation_is_accepted_unconditionally() {
        let r = ClusterDelegationResolver::new(|_: &str| None);
        assert!(r.on_anchor_failover(CLUSTER, ANCHOR_B, 1));
        assert_eq!(
            r.resolve_active(CLUSTER),
            Some(ClusterAnchorInfo::new(ANCHOR_B, 1))
        );
    }

    #[test]
    fn negative_results_are_not_cached() {
        let calls = AtomicUsize::new(0);
        let r = ClusterDelegationResolver::new(|_: &str| {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                None
            } else {
                Some(ClusterAnchorInfo::new(ANCHOR_A, 1))
            }
        });

        assert_eq!(r.resolve_active(CLUSTER), None);
        assert_eq!(r.cached_len(), 0, "a negative result must not be cached");
        assert_eq!(
            r.resolve_active(CLUSTER),
            Some(ClusterAnchorInfo::new(ANCHOR_A, 1))
        );
    }

    #[test]
    fn unresolvable_cluster_target_returns_none_rather_than_raising() {
        let r = ClusterDelegationResolver::new(|_: &str| None);
        assert_eq!(r.resolve_delegate_target(&frame(Some(CLUSTER))), None);
    }

    #[test]
    fn blank_arguments_are_rejected_by_on_anchor_failover() {
        let r = ClusterDelegationResolver::new(|_: &str| None);
        assert!(!r.on_anchor_failover("", ANCHOR_B, 2));
        assert!(!r.on_anchor_failover(CLUSTER, "", 2));
    }

    #[test]
    fn cluster_keys_are_ordinal() {
        let r = ClusterDelegationResolver::new(|_: &str| None);
        assert!(r.on_anchor_failover(CLUSTER, ANCHOR_A, 5));
        // A case-different key is a DIFFERENT cluster.
        assert!(r.on_anchor_failover(&CLUSTER.to_uppercase(), ANCHOR_B, 1));
        assert_eq!(r.cached_len(), 2);
    }

    #[test]
    fn the_cache_is_safe_for_concurrent_readers_and_writers() {
        use std::sync::Arc;
        let r = Arc::new(ClusterDelegationResolver::new(|_: &str| {
            Some(ClusterAnchorInfo::new(ANCHOR_A, 1))
        }));
        let mut handles = Vec::new();
        for i in 0..8u64 {
            let r = r.clone();
            handles.push(std::thread::spawn(move || {
                for e in 1..=20u64 {
                    r.on_anchor_failover(CLUSTER, ANCHOR_B, i * 20 + e);
                    let _ = r.resolve_active(CLUSTER);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Whatever the interleaving, the cached epoch is the maximum observed:
        // monotonicity holds under concurrency.
        assert_eq!(r.resolve_active(CLUSTER).unwrap().cluster_epoch, 160);
    }
}
