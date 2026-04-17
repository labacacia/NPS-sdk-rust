// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::{path::Path, sync::Mutex, time::{SystemTime, UNIX_EPOCH}};

const SCHEMA: &str = include_str!("../db/001_init.sql");

#[derive(Debug, Serialize, Deserialize)]
pub struct CertRecord {
    pub id:            i64,
    pub nid:           String,
    pub entity_type:   String,
    pub serial:        String,
    pub pub_key:       String,
    pub capabilities:  Vec<String>,
    pub scope:         Map<String, Value>,
    pub issued_by:     String,
    pub issued_at:     String,
    pub expires_at:    String,
    pub revoked_at:    Option<String>,
    pub revoke_reason: Option<String>,
    pub metadata:      Option<Map<String, Value>>,
}

pub struct CaDb(Mutex<Connection>);

impl CaDb {
    pub fn open(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        // Execute schema statement by statement
        for stmt in SCHEMA.split(';') {
            let s = stmt.trim();
            if !s.is_empty() {
                conn.execute_batch(&format!("{};", s))?;
            }
        }
        Ok(Self(Mutex::new(conn)))
    }

    pub fn next_serial(&self) -> Result<String> {
        let conn = self.0.lock().unwrap();
        let n: i64 = conn.query_row(
            "SELECT COALESCE(MAX(CAST(REPLACE(serial,'0x','') AS INTEGER)),0)+1 FROM nip_certificates",
            [],
            |row| row.get(0),
        )?;
        Ok(format!("0x{:06X}", n))
    }

    pub fn insert(&self, rec: &InsertRec) -> Result<i64> {
        let conn = self.0.lock().unwrap();
        conn.execute(
            "INSERT INTO nip_certificates (nid,entity_type,serial,pub_key,capabilities,scope_json,\
             issued_by,issued_at,expires_at,metadata_json) VALUES (?,?,?,?,?,?,?,?,?,?)",
            params![
                rec.nid, rec.entity_type, rec.serial, rec.pub_key,
                serde_json::to_string(&rec.capabilities)?,
                serde_json::to_string(&rec.scope)?,
                rec.issued_by, rec.issued_at, rec.expires_at,
                rec.metadata.as_ref().map(|m| serde_json::to_string(m).unwrap()),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn get_active(&self, nid: &str) -> Result<Option<CertRecord>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM nip_certificates WHERE nid=? AND revoked_at IS NULL \
             ORDER BY issued_at DESC LIMIT 1",
        )?;
        let mut rows = stmt.query(params![nid])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row_to_record(row)?))
        } else {
            Ok(None)
        }
    }

    pub fn revoke(&self, nid: &str, reason: &str) -> Result<bool> {
        let now = iso_now();
        let conn = self.0.lock().unwrap();
        let n = conn.execute(
            "UPDATE nip_certificates SET revoked_at=?,revoke_reason=? WHERE nid=? AND revoked_at IS NULL",
            params![now, reason, nid],
        )?;
        Ok(n > 0)
    }

    pub fn crl(&self) -> Result<Vec<serde_json::Value>> {
        let conn = self.0.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT serial,nid,revoked_at,revoke_reason FROM nip_certificates \
             WHERE revoked_at IS NOT NULL ORDER BY revoked_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(serde_json::json!({
                "serial":        row.get::<_,String>(0)?,
                "nid":           row.get::<_,String>(1)?,
                "revoked_at":    row.get::<_,String>(2)?,
                "revoke_reason": row.get::<_,Option<String>>(3)?,
            }))
        })?;
        Ok(rows.filter_map(|r| r.ok()).collect())
    }
}

pub struct InsertRec {
    pub nid:          String,
    pub entity_type:  String,
    pub serial:       String,
    pub pub_key:      String,
    pub capabilities: Vec<String>,
    pub scope:        Map<String, Value>,
    pub issued_by:    String,
    pub issued_at:    String,
    pub expires_at:   String,
    pub metadata:     Option<Map<String, Value>>,
}

fn row_to_record(row: &rusqlite::Row) -> rusqlite::Result<CertRecord> {
    let caps_json: String = row.get("capabilities")?;
    let scope_json: String = row.get("scope_json")?;
    let meta_json: Option<String> = row.get("metadata_json")?;
    Ok(CertRecord {
        id:            row.get("id")?,
        nid:           row.get("nid")?,
        entity_type:   row.get("entity_type")?,
        serial:        row.get("serial")?,
        pub_key:       row.get("pub_key")?,
        capabilities:  serde_json::from_str(&caps_json).unwrap_or_default(),
        scope:         serde_json::from_str(&scope_json).unwrap_or_default(),
        issued_by:     row.get("issued_by")?,
        issued_at:     row.get("issued_at")?,
        expires_at:    row.get("expires_at")?,
        revoked_at:    row.get("revoked_at")?,
        revoke_reason: row.get("revoke_reason")?,
        metadata:      meta_json.as_deref().and_then(|s| serde_json::from_str(s).ok()),
    })
}

pub fn iso_now() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    let (y, mo, d, h, mi, s) = crate::ca::epoch_to_parts(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, mi, s)
}
