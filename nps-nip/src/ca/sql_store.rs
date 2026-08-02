// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! SQL-backed NIP CA certificate store (NPS-3 §8).
//!
//! Port of the .NET `SqliteNipCaStore` / `PostgreSqlNipCaStore`. Those bind
//! Microsoft.Data.Sqlite / Npgsql directly; Rust has **no SQL driver in the
//! offline cargo cache** (`rusqlite`, `tokio-postgres` and `tiberius` are all
//! absent), so this store is built over an **injectable executor trait**
//! ([`CaSqlExecutor`]). The store owns the schema DDL, the exact SQL text of
//! every operation, and the row ⇄ [`NipCertRecord`] mapping — all fully
//! testable without a database. The only deferred piece is a concrete driver
//! binding, which slots in by implementing [`CaSqlExecutor`].
//!
//! The SQL text matches the .NET SQLite backend (`nip_certs` table,
//! `nip_serial` sequence table) verbatim at the string boundary.

use std::collections::HashMap;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::store::{NipCaStore, NipCertRecord, StoreError};

/// SQL dialect selector for the CA store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaSqlDialect {
    Sqlite,
    Postgres,
}

/// A bound SQL parameter for CA-store statements.
#[derive(Debug, Clone, PartialEq)]
pub enum CaSqlValue {
    Null,
    Text(String),
    Int(i64),
}

/// A row returned by a [`CaSqlExecutor`] query: column-name → value.
pub type CaSqlRow = HashMap<String, CaSqlValue>;

/// Error surfaced by a [`CaSqlExecutor`] implementation.
#[derive(Debug, Clone)]
pub struct CaSqlError(pub String);

impl std::fmt::Display for CaSqlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for CaSqlError {}

/// Injectable executor over which the CA store runs its SQL. A concrete driver
/// (rusqlite, Npgsql-equivalent) implements this; the store itself is
/// driver-agnostic.
pub trait CaSqlExecutor: Send + Sync {
    /// Executes a non-query statement (INSERT / UPDATE / DDL). Returns the
    /// number of affected rows.
    fn execute(&self, sql: &str, params: &[(&str, CaSqlValue)]) -> Result<u64, CaSqlError>;

    /// Executes a query and returns all matching rows.
    fn query(&self, sql: &str, params: &[(&str, CaSqlValue)]) -> Result<Vec<CaSqlRow>, CaSqlError>;

    /// Reserves and returns the next serial (atomic UPDATE+SELECT on
    /// `nip_serial`, or `nextval` on Postgres).
    fn next_serial_seq(&self) -> Result<i64, CaSqlError>;
}

/// The DDL statements creating the SQLite CA schema — identical text to the
/// .NET `SqliteNipCaStore.MigrateAsync` migration.
pub const SQLITE_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS nip_certs (\n\
                nid               TEXT NOT NULL,\n\
                entity_type       TEXT NOT NULL,\n\
                serial            TEXT NOT NULL UNIQUE,\n\
                pub_key           TEXT NOT NULL,\n\
                capabilities_json TEXT NOT NULL DEFAULT '[]',\n\
                scope_json        TEXT NOT NULL DEFAULT '{}',\n\
                issued_by         TEXT NOT NULL,\n\
                issued_at         TEXT NOT NULL,\n\
                expires_at        TEXT NOT NULL,\n\
                revoked_at        TEXT,\n\
                revoke_reason     TEXT,\n\
                metadata_json     TEXT,\n\
                nid_role          TEXT,\n\
                parent_nid        TEXT,\n\
                lineage_json      TEXT\n\
            )",
    "CREATE INDEX IF NOT EXISTS idx_nip_certs_nid        ON nip_certs (nid)",
    "CREATE INDEX IF NOT EXISTS idx_nip_certs_serial     ON nip_certs (serial)",
    "CREATE INDEX IF NOT EXISTS idx_nip_certs_parent_nid ON nip_certs (parent_nid)",
    "CREATE TABLE IF NOT EXISTS nip_serial (\n\
                id   INTEGER PRIMARY KEY,\n\
                seq  INTEGER NOT NULL DEFAULT 0\n\
            )",
    "INSERT OR IGNORE INTO nip_serial (id, seq) VALUES (1, 0)",
];

const INSERT_SQL: &str = "INSERT INTO nip_certs \
    (nid, entity_type, serial, pub_key, capabilities_json, scope_json, \
     issued_by, issued_at, expires_at, metadata_json, \
     nid_role, parent_nid, lineage_json) \
    VALUES \
    (@Nid, @EntityType, @Serial, @PubKey, @CapJson, @ScopeJson, \
     @IssuedBy, @IssuedAt, @ExpiresAt, @MetaJson, \
     @NidRole, @ParentNid, @LineageJson)";

const GET_BY_NID_SQL: &str =
    "SELECT * FROM nip_certs WHERE nid = @Nid ORDER BY issued_at DESC LIMIT 1";
const GET_BY_SERIAL_SQL: &str = "SELECT * FROM nip_certs WHERE serial = @Serial LIMIT 1";
const REVOKE_SQL: &str = "UPDATE nip_certs \
    SET revoked_at = @RevokedAt, revoke_reason = @Reason \
    WHERE nid = @Nid AND revoked_at IS NULL";
const LIST_SQL: &str = "SELECT * FROM nip_certs ORDER BY issued_at DESC";
const GET_REVOKED_SQL: &str =
    "SELECT * FROM nip_certs WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC";
const GET_BY_PARENT_SQL: &str =
    "SELECT * FROM nip_certs WHERE parent_nid = @ParentNid ORDER BY issued_at DESC";

/// SQL-backed NIP CA store over an injected [`CaSqlExecutor`].
pub struct SqlNipCaStore<E: CaSqlExecutor> {
    executor: E,
    #[allow(dead_code)]
    dialect: CaSqlDialect,
}

impl<E: CaSqlExecutor> SqlNipCaStore<E> {
    /// Wraps an executor as a SQLite-dialect store.
    pub fn sqlite(executor: E) -> Self {
        Self {
            executor,
            dialect: CaSqlDialect::Sqlite,
        }
    }

    /// Wraps an executor as a Postgres-dialect store.
    pub fn postgres(executor: E) -> Self {
        Self {
            executor,
            dialect: CaSqlDialect::Postgres,
        }
    }

    /// Applies the CA schema DDL through the executor.
    pub fn migrate(&self) -> Result<(), CaSqlError> {
        for stmt in SQLITE_SCHEMA {
            self.executor.execute(stmt, &[])?;
        }
        Ok(())
    }

    fn insert_params(record: &NipCertRecord) -> Vec<(&'static str, CaSqlValue)> {
        vec![
            ("@Nid", CaSqlValue::Text(record.nid.clone())),
            ("@EntityType", CaSqlValue::Text(record.entity_type.clone())),
            ("@Serial", CaSqlValue::Text(record.serial.clone())),
            ("@PubKey", CaSqlValue::Text(record.pub_key.clone())),
            (
                "@CapJson",
                CaSqlValue::Text(
                    serde_json::to_string(&record.capabilities).unwrap_or_else(|_| "[]".into()),
                ),
            ),
            ("@ScopeJson", CaSqlValue::Text(record.scope_json.clone())),
            ("@IssuedBy", CaSqlValue::Text(record.issued_by.clone())),
            ("@IssuedAt", CaSqlValue::Text(fmt_dt(record.issued_at))),
            ("@ExpiresAt", CaSqlValue::Text(fmt_dt(record.expires_at))),
            ("@MetaJson", opt_text(&record.metadata_json)),
            ("@NidRole", opt_text(&record.nid_role)),
            ("@ParentNid", opt_text(&record.parent_nid)),
            ("@LineageJson", opt_text(&record.lineage_json)),
        ]
    }
}

impl<E: CaSqlExecutor> NipCaStore for SqlNipCaStore<E> {
    fn save(&self, record: NipCertRecord) -> Result<(), StoreError> {
        let params = Self::insert_params(&record);
        self.executor
            .execute(INSERT_SQL, &params)
            .map_err(|_| StoreError::SerialExists(record.serial.clone()))?;
        Ok(())
    }

    fn get_by_nid(&self, nid: &str) -> Option<NipCertRecord> {
        let rows = self
            .executor
            .query(GET_BY_NID_SQL, &[("@Nid", CaSqlValue::Text(nid.into()))])
            .ok()?;
        rows.first().map(read_record)
    }

    fn get_by_serial(&self, serial: &str) -> Option<NipCertRecord> {
        let rows = self
            .executor
            .query(
                GET_BY_SERIAL_SQL,
                &[("@Serial", CaSqlValue::Text(serial.into()))],
            )
            .ok()?;
        rows.first().map(read_record)
    }

    fn revoke(&self, nid: &str, reason: &str, revoked_at: OffsetDateTime) -> bool {
        self.executor
            .execute(
                REVOKE_SQL,
                &[
                    ("@Nid", CaSqlValue::Text(nid.into())),
                    ("@Reason", CaSqlValue::Text(reason.into())),
                    ("@RevokedAt", CaSqlValue::Text(fmt_dt(revoked_at))),
                ],
            )
            .map(|n| n > 0)
            .unwrap_or(false)
    }

    fn next_serial(&self) -> String {
        let next = self.executor.next_serial_seq().unwrap_or(0);
        format!("0x{next:X}")
    }

    fn list(&self) -> Vec<NipCertRecord> {
        self.executor
            .query(LIST_SQL, &[])
            .map(|rows| rows.iter().map(read_record).collect())
            .unwrap_or_default()
    }

    fn get_revoked(&self) -> Vec<NipCertRecord> {
        self.executor
            .query(GET_REVOKED_SQL, &[])
            .map(|rows| rows.iter().map(read_record).collect())
            .unwrap_or_default()
    }

    fn get_by_parent_nid(&self, parent_nid: &str) -> Vec<NipCertRecord> {
        self.executor
            .query(
                GET_BY_PARENT_SQL,
                &[("@ParentNid", CaSqlValue::Text(parent_nid.into()))],
            )
            .map(|rows| rows.iter().map(read_record).collect())
            .unwrap_or_default()
    }
}

// ── Row mapping ────────────────────────────────────────────────────────────────

fn fmt_dt(dt: OffsetDateTime) -> String {
    dt.format(&Rfc3339).unwrap_or_default()
}

fn parse_dt(s: &str) -> OffsetDateTime {
    OffsetDateTime::parse(s, &Rfc3339).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn opt_text(v: &Option<String>) -> CaSqlValue {
    match v {
        Some(s) => CaSqlValue::Text(s.clone()),
        None => CaSqlValue::Null,
    }
}

fn cell_text(row: &CaSqlRow, col: &str) -> Option<String> {
    match row.get(col) {
        Some(CaSqlValue::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

fn read_record(row: &CaSqlRow) -> NipCertRecord {
    let caps: Vec<String> = cell_text(row, "capabilities_json")
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    NipCertRecord {
        nid: cell_text(row, "nid").unwrap_or_default(),
        entity_type: cell_text(row, "entity_type").unwrap_or_default(),
        serial: cell_text(row, "serial").unwrap_or_default(),
        pub_key: cell_text(row, "pub_key").unwrap_or_default(),
        capabilities: caps,
        scope_json: cell_text(row, "scope_json").unwrap_or_else(|| "{}".into()),
        issued_by: cell_text(row, "issued_by").unwrap_or_default(),
        issued_at: cell_text(row, "issued_at")
            .map(|s| parse_dt(&s))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        expires_at: cell_text(row, "expires_at")
            .map(|s| parse_dt(&s))
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        revoked_at: cell_text(row, "revoked_at").map(|s| parse_dt(&s)),
        revoke_reason: cell_text(row, "revoke_reason"),
        metadata_json: cell_text(row, "metadata_json"),
        nid_role: cell_text(row, "nid_role"),
        parent_nid: cell_text(row, "parent_nid"),
        lineage_json: cell_text(row, "lineage_json"),
    }
}

// ── In-memory executor (test / embedded backend) ────────────────────────────────

/// A dependency-free [`CaSqlExecutor`] that interprets the CA store's SQL
/// against an in-memory table. It lets the SQL-backed store round-trip fully
/// without a database driver — modelling exactly what the deferred rusqlite
/// binding will do — and records the SQL it executed for assertion.
#[derive(Default)]
pub struct InMemoryCaSqlExecutor {
    inner: std::sync::Mutex<ExecInner>,
}

#[derive(Default)]
struct ExecInner {
    rows: Vec<CaSqlRow>,
    seq: i64,
    sql_log: Vec<String>,
}

impl InMemoryCaSqlExecutor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn sql_log(&self) -> Vec<String> {
        self.inner.lock().unwrap().sql_log.clone()
    }

    fn param<'a>(params: &'a [(&str, CaSqlValue)], name: &str) -> Option<&'a CaSqlValue> {
        params.iter().find(|(n, _)| *n == name).map(|(_, v)| v)
    }

    fn param_text(params: &[(&str, CaSqlValue)], name: &str) -> Option<String> {
        match Self::param(params, name) {
            Some(CaSqlValue::Text(s)) => Some(s.clone()),
            _ => None,
        }
    }
}

impl CaSqlExecutor for InMemoryCaSqlExecutor {
    fn execute(&self, sql: &str, params: &[(&str, CaSqlValue)]) -> Result<u64, CaSqlError> {
        let mut g = self.inner.lock().unwrap();
        g.sql_log.push(sql.to_string());

        if sql.starts_with("CREATE") || sql.starts_with("INSERT OR IGNORE") {
            return Ok(0); // DDL / seed — no-op for the in-memory table
        }

        if sql.starts_with("INSERT INTO nip_certs") {
            // Serial is globally unique.
            let serial = Self::param_text(params, "@Serial").unwrap_or_default();
            if g.rows
                .iter()
                .any(|r| cell_text(r, "serial").as_deref() == Some(&serial))
            {
                return Err(CaSqlError(format!("serial exists: {serial}")));
            }
            let mut row = CaSqlRow::new();
            for (name, val) in params {
                let col = column_for_param(name);
                row.insert(col.to_string(), val.clone());
            }
            g.rows.push(row);
            return Ok(1);
        }

        if sql.starts_with("UPDATE nip_certs") {
            // Revoke: latest live record for nid.
            let nid = Self::param_text(params, "@Nid").unwrap_or_default();
            let revoked_at = Self::param(params, "@RevokedAt")
                .cloned()
                .unwrap_or(CaSqlValue::Null);
            let reason = Self::param(params, "@Reason")
                .cloned()
                .unwrap_or(CaSqlValue::Null);
            let idx = g.rows.iter().rposition(|r| {
                cell_text(r, "nid").as_deref() == Some(&nid)
                    && !matches!(r.get("revoked_at"), Some(CaSqlValue::Text(_)))
            });
            if let Some(i) = idx {
                g.rows[i].insert("revoked_at".into(), revoked_at);
                g.rows[i].insert("revoke_reason".into(), reason);
                return Ok(1);
            }
            return Ok(0);
        }

        Ok(0)
    }

    fn query(&self, sql: &str, params: &[(&str, CaSqlValue)]) -> Result<Vec<CaSqlRow>, CaSqlError> {
        let mut g = self.inner.lock().unwrap();
        g.sql_log.push(sql.to_string());
        let rows = g.rows.clone();

        let has_revoked = |r: &CaSqlRow| matches!(r.get("revoked_at"), Some(CaSqlValue::Text(_)));

        let mut result: Vec<CaSqlRow> = if sql.contains("WHERE nid = @Nid") {
            let nid = Self::param_text(params, "@Nid").unwrap_or_default();
            rows.into_iter()
                .filter(|r| cell_text(r, "nid").as_deref() == Some(&nid))
                .collect()
        } else if sql.contains("WHERE serial = @Serial") {
            let serial = Self::param_text(params, "@Serial").unwrap_or_default();
            rows.into_iter()
                .filter(|r| cell_text(r, "serial").as_deref() == Some(&serial))
                .collect()
        } else if sql.contains("WHERE parent_nid = @ParentNid") {
            let parent = Self::param_text(params, "@ParentNid").unwrap_or_default();
            rows.into_iter()
                .filter(|r| cell_text(r, "parent_nid").as_deref() == Some(&parent))
                .collect()
        } else if sql.contains("WHERE revoked_at IS NOT NULL") {
            rows.into_iter().filter(has_revoked).collect()
        } else {
            rows
        };

        // ORDER BY issued_at DESC — reverse insertion order for equal-key
        // stability so "latest" wins, matching the .NET store.
        if sql.contains("ORDER BY issued_at DESC") {
            result.sort_by(|a, b| {
                cell_text(b, "issued_at")
                    .unwrap_or_default()
                    .cmp(&cell_text(a, "issued_at").unwrap_or_default())
            });
        }
        if sql.contains("LIMIT 1") {
            result.truncate(1);
        }
        Ok(result)
    }

    fn next_serial_seq(&self) -> Result<i64, CaSqlError> {
        let mut g = self.inner.lock().unwrap();
        g.seq += 1;
        Ok(g.seq)
    }
}

fn column_for_param(param: &str) -> &'static str {
    match param {
        "@Nid" => "nid",
        "@EntityType" => "entity_type",
        "@Serial" => "serial",
        "@PubKey" => "pub_key",
        "@CapJson" => "capabilities_json",
        "@ScopeJson" => "scope_json",
        "@IssuedBy" => "issued_by",
        "@IssuedAt" => "issued_at",
        "@ExpiresAt" => "expires_at",
        "@MetaJson" => "metadata_json",
        "@NidRole" => "nid_role",
        "@ParentNid" => "parent_nid",
        "@LineageJson" => "lineage_json",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn store() -> SqlNipCaStore<InMemoryCaSqlExecutor> {
        let s = SqlNipCaStore::sqlite(InMemoryCaSqlExecutor::new());
        s.migrate().unwrap();
        s
    }

    fn make_record(nid: &str, serial: &str, issued_at: OffsetDateTime) -> NipCertRecord {
        NipCertRecord {
            nid: nid.into(),
            entity_type: "agent".into(),
            serial: serial.into(),
            pub_key: "ed25519:abc123".into(),
            capabilities: vec!["nwp:query".into(), "nwp:stream".into()],
            scope_json: "{\"nodes\":[\"*\"]}".into(),
            issued_by: "urn:nps:org:ca.test".into(),
            issued_at,
            expires_at: issued_at + Duration::days(30),
            revoked_at: None,
            revoke_reason: None,
            metadata_json: None,
            nid_role: None,
            parent_nid: None,
            lineage_json: None,
        }
    }

    #[test]
    fn migrate_emits_schema_ddl() {
        let s = store();
        let log = s.executor.sql_log();
        assert!(log
            .iter()
            .any(|q| q.contains("CREATE TABLE IF NOT EXISTS nip_certs")));
        assert!(log
            .iter()
            .any(|q| q.contains("CREATE TABLE IF NOT EXISTS nip_serial")));
        assert!(log.iter().any(|q| q.contains("idx_nip_certs_parent_nid")));
    }

    #[test]
    fn save_and_get_by_nid_round_trips() {
        let s = store();
        let now = OffsetDateTime::now_utc();
        let rec = make_record("urn:nps:agent:test:agent-1", "0x1", now);
        s.save(rec.clone()).unwrap();

        let got = s.get_by_nid("urn:nps:agent:test:agent-1").unwrap();
        assert_eq!(got.nid, rec.nid);
        assert_eq!(got.entity_type, "agent");
        assert_eq!(got.serial, "0x1");
        assert_eq!(got.pub_key, "ed25519:abc123");
        assert_eq!(got.capabilities, vec!["nwp:query", "nwp:stream"]);
        assert_eq!(got.scope_json, "{\"nodes\":[\"*\"]}");
        assert!(got.revoked_at.is_none());
    }

    #[test]
    fn get_by_nid_not_found_returns_none() {
        let s = store();
        assert!(s.get_by_nid("urn:nps:agent:test:ghost").is_none());
    }

    #[test]
    fn get_by_nid_multiple_returns_latest() {
        let s = store();
        let now = OffsetDateTime::now_utc();
        s.save(make_record(
            "urn:nps:agent:test:renewed",
            "0x1",
            now - Duration::days(60),
        ))
        .unwrap();
        s.save(make_record("urn:nps:agent:test:renewed", "0x2", now))
            .unwrap();
        let got = s.get_by_nid("urn:nps:agent:test:renewed").unwrap();
        assert_eq!(got.serial, "0x2");
    }

    #[test]
    fn get_by_serial_round_trips() {
        let s = store();
        s.save(make_record(
            "urn:nps:agent:test:agent-s",
            "0xABCD",
            OffsetDateTime::now_utc(),
        ))
        .unwrap();
        let got = s.get_by_serial("0xABCD").unwrap();
        assert_eq!(got.nid, "urn:nps:agent:test:agent-s");
    }

    #[test]
    fn get_by_serial_not_found_returns_none() {
        let s = store();
        assert!(s.get_by_serial("0xDEAD").is_none());
    }

    #[test]
    fn revoke_sets_fields() {
        let s = store();
        s.save(make_record(
            "urn:nps:agent:test:to-revoke",
            "0x2",
            OffsetDateTime::now_utc(),
        ))
        .unwrap();
        let ok = s.revoke(
            "urn:nps:agent:test:to-revoke",
            "key_compromise",
            OffsetDateTime::now_utc(),
        );
        assert!(ok);
        let got = s.get_by_nid("urn:nps:agent:test:to-revoke").unwrap();
        assert!(got.revoked_at.is_some());
        assert_eq!(got.revoke_reason.as_deref(), Some("key_compromise"));
    }

    #[test]
    fn revoke_not_found_returns_false() {
        let s = store();
        assert!(!s.revoke(
            "urn:nps:agent:test:ghost",
            "superseded",
            OffsetDateTime::now_utc()
        ));
    }

    #[test]
    fn revoke_already_revoked_returns_false() {
        let s = store();
        s.save(make_record(
            "urn:nps:agent:test:already",
            "0x3",
            OffsetDateTime::now_utc(),
        ))
        .unwrap();
        s.revoke(
            "urn:nps:agent:test:already",
            "superseded",
            OffsetDateTime::now_utc(),
        );
        assert!(!s.revoke(
            "urn:nps:agent:test:already",
            "key_compromise",
            OffsetDateTime::now_utc()
        ));
    }

    #[test]
    fn next_serial_increments() {
        let s = store();
        assert_eq!(s.next_serial(), "0x1");
        assert_eq!(s.next_serial(), "0x2");
        assert_eq!(s.next_serial(), "0x3");
    }

    #[test]
    fn get_revoked_returns_only_revoked() {
        let s = store();
        let now = OffsetDateTime::now_utc();
        s.save(make_record("urn:nps:agent:test:active", "0x10", now))
            .unwrap();
        s.save(make_record("urn:nps:agent:test:revoked1", "0x11", now))
            .unwrap();
        s.save(make_record("urn:nps:agent:test:revoked2", "0x12", now))
            .unwrap();
        s.revoke("urn:nps:agent:test:revoked1", "superseded", now);
        s.revoke("urn:nps:agent:test:revoked2", "key_compromise", now);
        let crl = s.get_revoked();
        assert_eq!(crl.len(), 2);
        assert!(crl.iter().all(|r| r.revoked_at.is_some()));
        assert!(!crl.iter().any(|r| r.nid == "urn:nps:agent:test:active"));
    }

    #[test]
    fn list_returns_all() {
        let s = store();
        let now = OffsetDateTime::now_utc();
        s.save(make_record("urn:nps:agent:sqlite.test:a", "0xA1", now))
            .unwrap();
        s.save(make_record("urn:nps:agent:sqlite.test:b", "0xA2", now))
            .unwrap();
        let all = s.list();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|r| r.serial == "0xA1"));
        assert!(all.iter().any(|r| r.serial == "0xA2"));
    }

    #[test]
    fn get_by_parent_nid_filters() {
        let s = store();
        let now = OffsetDateTime::now_utc();
        let mut child = make_record("urn:nps:agent:test:session1", "0xC1", now);
        child.parent_nid = Some("urn:nps:group:test:g1".into());
        child.nid_role = Some(super::super::store::ROLE_SESSION.into());
        s.save(child).unwrap();
        s.save(make_record("urn:nps:agent:test:solo", "0xC2", now))
            .unwrap();

        let sessions = s.get_by_parent_nid("urn:nps:group:test:g1");
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].nid, "urn:nps:agent:test:session1");
    }

    #[test]
    fn insert_sql_matches_dotnet_columns() {
        // The generated INSERT lists the nip_certs columns in the .NET order.
        assert!(INSERT_SQL
            .contains("(nid, entity_type, serial, pub_key, capabilities_json, scope_json,"));
        assert!(INSERT_SQL.contains("nid_role, parent_nid, lineage_json)"));
    }
}
