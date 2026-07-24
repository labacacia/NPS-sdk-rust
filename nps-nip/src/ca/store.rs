// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! CA certificate store: persisted record type, the [`NipCaStore`] trait, and
//! an [`InMemoryNipCaStore`]. Mirrors the .NET `NipCertRecord` /
//! `INipCaStore` / `InMemoryNipCaStore`.

use std::sync::Mutex;

use time::OffsetDateTime;

/// Lineage role for group / session NIDs (NPS-CR-0003 §5.1.3).
pub const ROLE_GROUP: &str = "group";
pub const ROLE_SESSION: &str = "session";

/// Persisted record of a NIP certificate (NPS-3 §5.1).
#[derive(Debug, Clone)]
pub struct NipCertRecord {
    pub nid: String,
    /// `"agent"` | `"node"` | `"operator"`.
    pub entity_type: String,
    pub serial: String,
    pub pub_key: String,
    pub capabilities: Vec<String>,
    /// Scope as a JSON blob.
    pub scope_json: String,
    pub issued_by: String,
    pub issued_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoke_reason: Option<String>,
    pub metadata_json: Option<String>,

    /// Lineage role: `"group"`, `"session"`, or `None` for ordinary agents.
    pub nid_role: Option<String>,
    /// Immediate parent NID (session → group). `None` otherwise.
    pub parent_nid: Option<String>,
    /// Full signed lineage object as canonical JSON.
    pub lineage_json: Option<String>,
}

impl NipCertRecord {
    /// Convenience: is this record currently revoked?
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }
}

/// Error raised by store operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    NidExists(String),
    SerialExists(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NidExists(n) => write!(f, "NID already exists: {n}"),
            StoreError::SerialExists(s) => write!(f, "Serial already exists: {s}"),
        }
    }
}

impl std::error::Error for StoreError {}

/// Persistence abstraction for NIP CA certificate storage (NPS-3 §8).
/// Synchronous — the in-process CA library holds an in-memory or embedded store.
pub trait NipCaStore: Send + Sync {
    /// Save a newly issued record. Errors if the NID or serial already exists.
    fn save(&self, record: NipCertRecord) -> Result<(), StoreError>;

    /// Return the (latest) record for `nid`, or `None`.
    fn get_by_nid(&self, nid: &str) -> Option<NipCertRecord>;

    /// Return the record for `serial`, or `None`.
    fn get_by_serial(&self, serial: &str) -> Option<NipCertRecord>;

    /// Mark the latest live record for `nid` as revoked. Returns `false` if not
    /// found (or already revoked).
    fn revoke(&self, nid: &str, reason: &str, revoked_at: OffsetDateTime) -> bool;

    /// Generate and reserve the next unique hex serial, e.g. `0xA3F9C`.
    fn next_serial(&self) -> String;

    /// Return all records.
    fn list(&self) -> Vec<NipCertRecord>;

    /// Return all revoked records (for CRL generation).
    fn get_revoked(&self) -> Vec<NipCertRecord>;

    /// Return every record whose `parent_nid == parent_nid`.
    fn get_by_parent_nid(&self, parent_nid: &str) -> Vec<NipCertRecord>;
}

/// In-memory [`NipCaStore`] for tests, demos, and single-process stacks.
#[derive(Default)]
pub struct InMemoryNipCaStore {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    records: Vec<NipCertRecord>,
    serial: u64,
}

impl InMemoryNipCaStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl NipCaStore for InMemoryNipCaStore {
    fn save(&self, record: NipCertRecord) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        // Serials are globally unique. NIDs may recur across the audit trail
        // (renew issues a fresh serial under the same NID) — `get_by_nid`
        // returns the latest, so we do not reject a repeated NID here. Callers
        // that need first-issue uniqueness (register) pre-check via get_by_nid.
        if g.records.iter().any(|r| r.serial == record.serial) {
            return Err(StoreError::SerialExists(record.serial));
        }
        g.records.push(record);
        Ok(())
    }

    fn get_by_nid(&self, nid: &str) -> Option<NipCertRecord> {
        let g = self.inner.lock().unwrap();
        g.records.iter().rev().find(|r| r.nid == nid).cloned()
    }

    fn get_by_serial(&self, serial: &str) -> Option<NipCertRecord> {
        let g = self.inner.lock().unwrap();
        g.records.iter().find(|r| r.serial == serial).cloned()
    }

    fn revoke(&self, nid: &str, reason: &str, revoked_at: OffsetDateTime) -> bool {
        let mut g = self.inner.lock().unwrap();
        // FindLast live record for this nid.
        let idx = g
            .records
            .iter()
            .rposition(|r| r.nid == nid && r.revoked_at.is_none());
        match idx {
            Some(i) => {
                g.records[i].revoked_at = Some(revoked_at);
                g.records[i].revoke_reason = Some(reason.to_string());
                true
            }
            None => false,
        }
    }

    fn next_serial(&self) -> String {
        let mut g = self.inner.lock().unwrap();
        g.serial += 1;
        format!("0x{:X}", g.serial)
    }

    fn list(&self) -> Vec<NipCertRecord> {
        self.inner.lock().unwrap().records.clone()
    }

    fn get_revoked(&self) -> Vec<NipCertRecord> {
        let g = self.inner.lock().unwrap();
        g.records
            .iter()
            .filter(|r| r.revoked_at.is_some())
            .cloned()
            .collect()
    }

    fn get_by_parent_nid(&self, parent_nid: &str) -> Vec<NipCertRecord> {
        let g = self.inner.lock().unwrap();
        g.records
            .iter()
            .filter(|r| r.parent_nid.as_deref() == Some(parent_nid))
            .cloned()
            .collect()
    }
}
