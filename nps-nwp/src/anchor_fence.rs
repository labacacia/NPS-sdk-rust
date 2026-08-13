// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Anchor ownership state machine — the `cluster_epoch` fence and the topology
//! leader check (NPS-CR-0009 §3.2, NWP §12.2).
//!
//! **This has no .NET counterpart.** The .NET reference declares the two error
//! constants but implements no leader check, no standby state and no epoch
//! comparison; this module is built from the CR text.
//!
//! Intra-cluster consensus (Raft/Paxos/a lease store) is explicitly out of
//! scope and implementation-defined — only the observable wire contract below
//! is normative. The host drives the state machine from whatever consensus it
//! runs by calling [`AnchorOwnership::on_take_ownership`] and
//! [`AnchorOwnership::on_quorum_lost`].
//!
//! ```
//! use nps_nwp::anchor_fence::{AnchorOwnership, AnchorRole};
//!
//! let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
//! assert_eq!(own.role(), AnchorRole::Active);
//!
//! // A read from a peer still on the old epoch is fine.
//! assert!(own.on_inbound_frame(Some(1), None, false).is_ok());
//!
//! // A frame from a NEWER leader fences this Anchor.
//! let err = own
//!     .on_inbound_frame(Some(2), Some("urn:nps:node:api.test:anchor-b"), false)
//!     .unwrap_err();
//! assert_eq!(err.nwp_error_code, "NWP-ANCHOR-EPOCH-FENCED");
//! assert_eq!(own.role(), AnchorRole::Standby);
//! ```

use crate::anchor_client::{AnchorState, TopologyEvent, TopologySnapshot};
use crate::error_codes;

/// Error carried out of the fence / leader check, rendered by the transport as
/// an ErrorFrame. `NPS-CLIENT-CONFLICT` maps to HTTP 409.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{nwp_error_code} ({nps_status}): {message}")]
pub struct TopologyProtocolError {
    pub nwp_error_code: &'static str,
    pub nps_status: &'static str,
    pub message: String,
}

impl TopologyProtocolError {
    pub fn new(nwp_error_code: &'static str, message: impl Into<String>) -> Self {
        TopologyProtocolError {
            nwp_error_code,
            nps_status: error_codes::to_nps_status(nwp_error_code),
            message: message.into(),
        }
    }

    /// HTTP status for this fault (`NPS-CLIENT-CONFLICT` ⇒ 409).
    pub fn http_status(&self) -> u16 {
        match self.nps_status {
            "NPS-CLIENT-CONFLICT" => 409,
            "NPS-AUTH-FORBIDDEN" => 403,
            _ => 400,
        }
    }
}

/// Ownership role of this Anchor within its cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorRole {
    /// Owns the cluster at `own_epoch` and accepts topology writes.
    Active,
    /// Superseded (or never elected). MAY serve stale reads; rejects writes.
    Standby,
    // NOTE: read-only-degraded is modelled as Active + `degraded`, not as a
    // third role — it is the active owner that lost quorum, and it must still
    // report itself as the owner while refusing writes.
}

/// The Anchor's own view of cluster ownership.
///
/// Not internally synchronised: mutating methods take `&mut self`. A shared
/// deployment wraps it in whatever lock its host already uses.
#[derive(Debug, Clone)]
pub struct AnchorOwnership {
    anchor_nid: String,
    own_epoch: u64,
    role: AnchorRole,
    degraded: bool,
    highest_observed_epoch: u64,
    pending_events: Vec<TopologyEvent>,
    streams_open: bool,
}

impl AnchorOwnership {
    /// A freshly started single-Anchor cluster: `own_epoch = 1`, ACTIVE, not
    /// degraded. A single-Anchor cluster stays at epoch 1 forever and never
    /// emits `anchor_failover` / `anchor_quorum_lost`.
    pub fn new(anchor_nid: impl Into<String>) -> Self {
        AnchorOwnership {
            anchor_nid: anchor_nid.into(),
            own_epoch: 1,
            role: AnchorRole::Active,
            degraded: false,
            highest_observed_epoch: 1,
            pending_events: Vec::new(),
            streams_open: true,
        }
    }

    /// Start as a standby (an Anchor that has not been elected).
    pub fn new_standby(anchor_nid: impl Into<String>, own_epoch: u64) -> Self {
        let mut s = Self::new(anchor_nid);
        s.own_epoch = own_epoch;
        s.highest_observed_epoch = own_epoch;
        s.role = AnchorRole::Standby;
        s
    }

    pub fn anchor_nid(&self) -> &str {
        &self.anchor_nid
    }
    pub fn own_epoch(&self) -> u64 {
        self.own_epoch
    }
    pub fn role(&self) -> AnchorRole {
        self.role
    }
    /// True once quorum was lost: the owner is read-only-degraded.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }
    /// False once a fence closed the topology streams.
    pub fn streams_open(&self) -> bool {
        self.streams_open
    }

    /// Events produced since the last [`take_pending_events`][Self::take_pending_events].
    pub fn pending_events(&self) -> &[TopologyEvent] {
        &self.pending_events
    }

    /// Drain the events the host must publish on its `topology.stream`
    /// subscriptions.
    pub fn take_pending_events(&mut self) -> Vec<TopologyEvent> {
        std::mem::take(&mut self.pending_events)
    }

    /// Gate applied to every inbound frame (NPS-CR-0009 §3.2).
    ///
    /// * `inbound_epoch` — the frame's `cluster_epoch`; `None` ⇒ 1.
    /// * `sender_anchor_nid` — used as the `successor_nid` of the terminal
    ///   `anchor_failover` emitted when this Anchor is fenced.
    /// * `is_topology_write` — reads are always allowed (a standby MAY serve
    ///   stale reads stamped with its last-known epoch).
    ///
    /// (a) EPOCH FENCE first, for ANY inbound frame, read or write: a STRICTLY
    /// greater inbound epoch means this Anchor is a superseded leader, so it
    /// self-fences to STANDBY, emits a terminal `anchor_failover`, closes its
    /// topology streams and rejects with `NWP-ANCHOR-EPOCH-FENCED`. An epoch
    /// `<=` its own is deliberately NOT an error — note the asymmetry with NDP
    /// resolution, where an *equal* top epoch across two live members IS the
    /// fault.
    ///
    /// (b) LEADER CHECK, writes only: a standby, or the active owner while
    /// degraded, rejects with `NWP-ANCHOR-NOT-LEADER`.
    pub fn on_inbound_frame(
        &mut self,
        inbound_epoch: Option<u64>,
        sender_anchor_nid: Option<&str>,
        is_topology_write: bool,
    ) -> Result<(), TopologyProtocolError> {
        let inbound = inbound_epoch.unwrap_or(1);
        if inbound > self.highest_observed_epoch {
            self.highest_observed_epoch = inbound;
        }

        // (a) Epoch fence.
        if inbound > self.own_epoch {
            self.role = AnchorRole::Standby;
            self.pending_events.push(AnchorState::failover_with(
                sender_anchor_nid.unwrap_or_default(),
                inbound,
                AnchorState::REASON_ACTIVE_LOST,
                0,
            ));
            self.streams_open = false;
            return Err(TopologyProtocolError::new(
                error_codes::ANCHOR_EPOCH_FENCED,
                format!(
                    "inbound cluster_epoch {inbound} supersedes this Anchor's epoch {}; \
                     this Anchor is fenced.",
                    self.own_epoch
                ),
            ));
        }

        // (b) Leader check — writes only.
        if is_topology_write && (self.role != AnchorRole::Active || self.degraded) {
            let why = if self.role != AnchorRole::Active {
                "this Anchor is a standby"
            } else {
                "this Anchor is read-only-degraded (quorum lost)"
            };
            return Err(TopologyProtocolError::new(
                error_codes::ANCHOR_NOT_LEADER,
                format!("topology writes are only accepted by the active cluster owner: {why}."),
            ));
        }

        // (c) Reads always proceed.
        Ok(())
    }

    /// Stamp `cluster_epoch` on a snapshot / stream response (NWP §12.2 — every
    /// one of them MUST carry the current epoch). A standby stamps its
    /// last-known epoch.
    pub fn stamp_response(&self, snapshot: &mut TopologySnapshot) {
        snapshot.cluster_epoch = Some(self.own_epoch);
    }

    /// Quorum lost: go read-only-degraded and emit `anchor_quorum_lost`.
    /// The host MUST additionally set its NDP self-announcement
    /// `health = "degraded"`.
    pub fn on_quorum_lost(&mut self, quorum_size: u32, available: u32) -> TopologyEvent {
        self.degraded = true;
        let ev = AnchorState::quorum_lost(quorum_size, available);
        self.pending_events.push(ev.clone());
        ev
    }

    /// Quorum regained — clears the degraded flag. (Not on the wire; the host
    /// stops advertising `health = "degraded"`.)
    pub fn on_quorum_restored(&mut self) {
        self.degraded = false;
    }

    /// Take ownership at `new_epoch`.
    ///
    /// `new_epoch` MUST be strictly greater than every epoch ever observed —
    /// that is what makes the value a fencing token. Returns the
    /// `anchor_failover` event to publish; the caller MUST also **re-sign and
    /// re-publish** its AnnounceFrame with `cluster_epoch = new_epoch`, because
    /// that field is inside the signed canonical form (NPS-CR-0009 §1.1).
    pub fn on_take_ownership(
        &mut self,
        new_epoch: u64,
        reason: &str,
    ) -> Result<TopologyEvent, TopologyProtocolError> {
        if new_epoch <= self.highest_observed_epoch {
            return Err(TopologyProtocolError::new(
                error_codes::ANCHOR_EPOCH_FENCED,
                format!(
                    "cluster_epoch must strictly increase: {new_epoch} does not exceed the \
                     highest observed epoch {}.",
                    self.highest_observed_epoch
                ),
            ));
        }
        self.own_epoch = new_epoch;
        self.highest_observed_epoch = new_epoch;
        self.role = AnchorRole::Active;
        self.degraded = false;
        self.streams_open = true;
        let ev = AnchorState::failover_with(self.anchor_nid.clone(), new_epoch, reason, 0);
        self.pending_events.push(ev.clone());
        Ok(ev)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn details(ev: &TopologyEvent) -> (String, Value) {
        match ev {
            TopologyEvent::AnchorState { field, details, .. } => {
                (field.clone(), details.clone().unwrap())
            }
            other => panic!("expected AnchorState, got {other:?}"),
        }
    }

    fn snapshot() -> TopologySnapshot {
        TopologySnapshot {
            version: 7,
            anchor_nid: "urn:nps:node:api.test:anchor-a".into(),
            cluster_size: 0,
            members: vec![],
            truncated: None,
            cluster_epoch: None,
        }
    }

    #[test]
    fn standby_rejects_topology_writes_with_not_leader() {
        let mut own = AnchorOwnership::new_standby("urn:nps:node:api.test:anchor-b", 3);
        let err = own.on_inbound_frame(Some(3), None, true).unwrap_err();
        assert_eq!(err.nwp_error_code, "NWP-ANCHOR-NOT-LEADER");
        assert_eq!(err.nps_status, "NPS-CLIENT-CONFLICT");
        assert_eq!(err.http_status(), 409);
    }

    #[test]
    fn reads_succeed_on_a_standby() {
        let mut own = AnchorOwnership::new_standby("urn:nps:node:api.test:anchor-b", 3);
        assert!(own.on_inbound_frame(Some(3), None, false).is_ok());
    }

    #[test]
    fn degraded_active_owner_rejects_writes_but_serves_reads() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        own.on_quorum_lost(3, 1);
        assert!(own.is_degraded());
        assert_eq!(own.role(), AnchorRole::Active);

        let err = own.on_inbound_frame(Some(1), None, true).unwrap_err();
        assert_eq!(err.nwp_error_code, "NWP-ANCHOR-NOT-LEADER");
        assert!(own.on_inbound_frame(Some(1), None, false).is_ok());
    }

    #[test]
    fn higher_inbound_epoch_fences_the_superseded_leader() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        let err = own
            .on_inbound_frame(Some(2), Some("urn:nps:node:api.test:anchor-b"), false)
            .unwrap_err();

        assert_eq!(err.nwp_error_code, "NWP-ANCHOR-EPOCH-FENCED");
        assert_eq!(err.nps_status, "NPS-CLIENT-CONFLICT");
        assert_eq!(own.role(), AnchorRole::Standby);
        assert!(!own.streams_open(), "topology streams must be closed");

        // A terminal anchor_failover naming the new owner is emitted.
        let events = own.take_pending_events();
        assert_eq!(events.len(), 1);
        let (field, d) = details(&events[0]);
        assert_eq!(field, "anchor_failover");
        assert_eq!(d["successor_nid"], "urn:nps:node:api.test:anchor-b");
        assert_eq!(d["cluster_epoch"], 2);
        assert_eq!(d["reason"], "active_lost");
    }

    #[test]
    fn equal_or_lower_inbound_epoch_is_not_fenced() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        own.on_take_ownership(5, AnchorState::REASON_PLANNED)
            .unwrap();
        own.take_pending_events();

        assert!(own.on_inbound_frame(Some(5), None, true).is_ok());
        assert!(own.on_inbound_frame(Some(4), None, true).is_ok());
        assert!(own.on_inbound_frame(None, None, true).is_ok());
        assert_eq!(own.role(), AnchorRole::Active);
        assert!(own.take_pending_events().is_empty());
    }

    #[test]
    fn absent_inbound_epoch_coerces_to_one() {
        let mut own = AnchorOwnership::new_standby("urn:nps:node:api.test:anchor-b", 1);
        // 1 !> 1, so no fence; the write is refused for the leader reason only.
        let err = own.on_inbound_frame(None, None, true).unwrap_err();
        assert_eq!(err.nwp_error_code, "NWP-ANCHOR-NOT-LEADER");
    }

    #[test]
    fn every_snapshot_response_carries_cluster_epoch() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        own.on_take_ownership(4, AnchorState::REASON_PLANNED)
            .unwrap();
        let mut snap = snapshot();
        own.stamp_response(&mut snap);
        assert_eq!(snap.cluster_epoch, Some(4));

        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["cluster_epoch"], 4);
    }

    #[test]
    fn snapshot_omits_cluster_epoch_when_unset() {
        let json = serde_json::to_value(snapshot()).unwrap();
        assert!(json.get("cluster_epoch").is_none());
        assert_eq!(snapshot().effective_cluster_epoch(), 1);
    }

    #[test]
    fn take_ownership_requires_a_strictly_greater_epoch() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        own.on_take_ownership(3, AnchorState::REASON_PLANNED)
            .unwrap();

        assert!(own
            .on_take_ownership(3, AnchorState::REASON_PLANNED)
            .is_err());
        assert!(own
            .on_take_ownership(2, AnchorState::REASON_PLANNED)
            .is_err());
        assert!(own
            .on_take_ownership(4, AnchorState::REASON_PLANNED)
            .is_ok());
    }

    #[test]
    fn take_ownership_after_observing_a_higher_epoch_must_exceed_it() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        let _ = own.on_inbound_frame(Some(9), Some("urn:nps:node:api.test:anchor-b"), false);
        own.take_pending_events();

        // Epoch 9 was observed, so re-taking ownership at 9 is not allowed.
        assert!(own
            .on_take_ownership(9, AnchorState::REASON_PLANNED)
            .is_err());
        let ev = own
            .on_take_ownership(10, AnchorState::REASON_ACTIVE_LOST)
            .unwrap();
        let (_, d) = details(&ev);
        assert_eq!(d["successor_nid"], "urn:nps:node:api.test:anchor-a");
        assert_eq!(d["cluster_epoch"], 10);
        assert_eq!(d["reason"], "active_lost");
        assert_eq!(own.role(), AnchorRole::Active);
        assert!(!own.is_degraded());
    }

    #[test]
    fn quorum_lost_event_and_recovery() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:anchor-a");
        let ev = own.on_quorum_lost(3, 1);
        let (field, d) = details(&ev);
        assert_eq!(field, "anchor_quorum_lost");
        assert_eq!(d["quorum_size"], 3);
        assert_eq!(d["available"], 1);

        own.on_quorum_restored();
        assert!(!own.is_degraded());
        assert!(own.on_inbound_frame(Some(1), None, true).is_ok());
    }

    #[test]
    fn single_anchor_cluster_never_emits_ha_events() {
        let mut own = AnchorOwnership::new("urn:nps:node:api.test:solo");
        for _ in 0..5 {
            assert!(own.on_inbound_frame(None, None, true).is_ok());
        }
        assert_eq!(own.own_epoch(), 1);
        assert!(own.pending_events().is_empty());
    }
}
