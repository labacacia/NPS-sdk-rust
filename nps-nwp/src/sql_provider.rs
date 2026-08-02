// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! SQL-backed Memory Node provider (NPS-2 §2.1).
//!
//! Port of the .NET `PostgreSqlMemoryNodeProvider` / `SqlServerMemoryNodeProvider`.
//! The .NET versions bind Dapper + Npgsql / Microsoft.Data.SqlClient directly.
//! Rust has no database driver in the offline cargo cache (`rusqlite`, `tokio-postgres`
//! and `tiberius` are all absent), so the provider is built over an **injectable
//! executor trait** ([`SqlExecutor`]). This keeps the query-generation and
//! pagination logic fully portable and testable without a live database; a
//! concrete driver binding (rusqlite / Npgsql-equivalent) is the only deferred
//! piece and slots in by implementing [`SqlExecutor`].

use serde_json::{Map, Value};

use crate::frames::QueryFrame;
use crate::memory_server::{
    MemoryNodeError, MemoryNodeOptions, MemoryNodeQueryResult, MemoryNodeRow, MemoryNodeSchema,
};
use crate::query::{decode_cursor, encode_cursor, DatabaseDialect, SqlParams, SqlQueryBuilder};

/// Error surfaced by a [`SqlExecutor`] implementation.
#[derive(Debug, Clone)]
pub struct SqlExecutorError(pub String);

impl std::fmt::Display for SqlExecutorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SqlExecutorError {}

/// Injectable database executor. A concrete driver (rusqlite, Npgsql-equivalent,
/// SQL Server) implements this; the provider itself is driver-agnostic.
///
/// Executors receive the generated SQL and its parameters and return rows as
/// field-name → JSON value maps.
pub trait SqlExecutor: Send + Sync {
    /// Runs a `SELECT` and returns the result rows.
    fn query(&self, sql: &str, params: &SqlParams) -> Result<Vec<MemoryNodeRow>, SqlExecutorError>;

    /// Runs a `SELECT COUNT(*)` and returns the scalar count.
    fn count(&self, sql: &str, params: &SqlParams) -> Result<i64, SqlExecutorError>;
}

/// Memory Node provider backed by a relational database via [`SqlExecutor`].
/// Combines the dialect-aware [`SqlQueryBuilder`] with an injected executor.
pub struct SqlMemoryNodeProvider<E: SqlExecutor> {
    executor: E,
    dialect: DatabaseDialect,
}

impl<E: SqlExecutor> SqlMemoryNodeProvider<E> {
    /// Creates a PostgreSQL-dialect provider.
    pub fn postgres(executor: E) -> Self {
        Self {
            executor,
            dialect: DatabaseDialect::PostgreSql,
        }
    }

    /// Creates a SQL Server-dialect provider.
    pub fn sql_server(executor: E) -> Self {
        Self {
            executor,
            dialect: DatabaseDialect::SqlServer,
        }
    }

    pub fn dialect(&self) -> DatabaseDialect {
        self.dialect
    }

    /// Executes a query and returns a paginated result. Mirrors the .NET
    /// `QueryAsync` (identical cursor arithmetic and next-cursor logic).
    pub fn query(
        &self,
        frame: &QueryFrame,
        schema: &MemoryNodeSchema,
        options: &MemoryNodeOptions,
    ) -> Result<MemoryNodeQueryResult, MemoryNodeError> {
        let builder = SqlQueryBuilder::new(schema, self.dialect);
        let (sql, params) = builder
            .build(frame, options)
            .map_err(|e| MemoryNodeError::new(e.error_code, e.message))?;

        let rows = self
            .executor
            .query(&sql, &params)
            .map_err(|e| MemoryNodeError::new(crate::error_codes::NODE_UNAVAILABLE, e.0))?;

        let frame_limit = frame.limit.unwrap_or(0);
        let limit = (if frame_limit == 0 {
            options.default_limit as u64
        } else {
            frame_limit
        })
        .min(options.max_limit as u64) as i64;

        let next_cursor = if rows.len() as i64 == limit {
            encode_cursor(decode_cursor(frame.cursor.as_deref()) + limit)
        } else {
            None
        };

        Ok(MemoryNodeQueryResult { rows, next_cursor })
    }

    /// Streams all matching rows as pages. Mirrors the .NET `StreamAsync`
    /// cursor-advance loop; each returned page is one StreamFrame data chunk.
    pub fn stream(
        &self,
        frame: &QueryFrame,
        schema: &MemoryNodeSchema,
        options: &MemoryNodeOptions,
    ) -> Result<Vec<Vec<MemoryNodeRow>>, MemoryNodeError> {
        let builder = SqlQueryBuilder::new(schema, self.dialect);
        let frame_limit = frame.limit.unwrap_or(0);
        let page_limit = (if frame_limit == 0 {
            options.default_limit as u64
        } else {
            frame_limit
        })
        .min(options.max_limit as u64);

        let mut cursor = frame.cursor.clone();
        let mut pages = Vec::new();
        loop {
            let mut page_frame = frame.clone();
            page_frame.limit = Some(page_limit);
            page_frame.cursor = cursor.clone();

            let (sql, params) = builder
                .build(&page_frame, options)
                .map_err(|e| MemoryNodeError::new(e.error_code, e.message))?;
            let rows = self
                .executor
                .query(&sql, &params)
                .map_err(|e| MemoryNodeError::new(crate::error_codes::NODE_UNAVAILABLE, e.0))?;

            if rows.is_empty() {
                break;
            }

            let has_more = rows.len() as u64 == page_limit;
            cursor = encode_cursor(decode_cursor(cursor.as_deref()) + rows.len() as i64);
            pages.push(rows);

            if !has_more {
                break;
            }
        }
        Ok(pages)
    }

    /// Returns the total row count matching the frame's filter. Mirrors .NET
    /// `CountAsync`.
    pub fn count(
        &self,
        frame: &QueryFrame,
        schema: &MemoryNodeSchema,
    ) -> Result<i64, MemoryNodeError> {
        let builder = SqlQueryBuilder::new(schema, self.dialect);
        let (sql, params) = builder
            .build_count(frame)
            .map_err(|e| MemoryNodeError::new(e.error_code, e.message))?;
        self.executor
            .count(&sql, &params)
            .map_err(|e| MemoryNodeError::new(crate::error_codes::NODE_UNAVAILABLE, e.0))
    }
}

/// Test/in-memory executor: records the SQL it was handed and returns a fixed
/// row set. Lets provider logic (cursor advance, next-cursor emission) be
/// verified without a live database, exactly as the deferred driver would.
pub struct RecordingExecutor {
    pages: std::sync::Mutex<std::collections::VecDeque<Vec<MemoryNodeRow>>>,
    last_sql: std::sync::Mutex<Vec<String>>,
    count_value: i64,
}

impl RecordingExecutor {
    pub fn new(pages: Vec<Vec<MemoryNodeRow>>, count_value: i64) -> Self {
        Self {
            pages: std::sync::Mutex::new(pages.into_iter().collect()),
            last_sql: std::sync::Mutex::new(Vec::new()),
            count_value,
        }
    }

    pub fn sql_log(&self) -> Vec<String> {
        self.last_sql.lock().unwrap().clone()
    }
}

impl SqlExecutor for RecordingExecutor {
    fn query(
        &self,
        sql: &str,
        _params: &SqlParams,
    ) -> Result<Vec<MemoryNodeRow>, SqlExecutorError> {
        self.last_sql.lock().unwrap().push(sql.to_string());
        Ok(self.pages.lock().unwrap().pop_front().unwrap_or_default())
    }

    fn count(&self, sql: &str, _params: &SqlParams) -> Result<i64, SqlExecutorError> {
        self.last_sql.lock().unwrap().push(sql.to_string());
        Ok(self.count_value)
    }
}

/// Convenience: builds a row map from `(key, value)` pairs.
pub fn row(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> MemoryNodeRow {
    let mut m = Map::new();
    for (k, v) in pairs {
        m.insert(k.to_string(), v);
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_server::MemoryNodeField;
    use serde_json::json;

    fn schema() -> MemoryNodeSchema {
        MemoryNodeSchema {
            table_name: "products".into(),
            primary_key: "id".into(),
            fields: vec![
                MemoryNodeField::new("id", "number"),
                MemoryNodeField::new("name", "string"),
            ],
        }
    }

    fn options() -> MemoryNodeOptions {
        let mut o = MemoryNodeOptions::new("urn:nps:node:test:products", "/products", schema());
        o.default_limit = 2;
        o.max_limit = 100;
        o
    }

    fn make_rows(n: usize) -> Vec<MemoryNodeRow> {
        (0..n)
            .map(|i| row([("id", json!(i as i64)), ("name", json!(format!("n{i}")))]))
            .collect()
    }

    #[test]
    fn query_generates_sql_and_maps_rows() {
        let exec = RecordingExecutor::new(vec![make_rows(2)], 0);
        let provider = SqlMemoryNodeProvider::postgres(exec);
        let mut f = QueryFrame::new("urn:nps:node:test:products");
        f.limit = Some(2);
        let res = provider.query(&f, &schema(), &options()).unwrap();
        assert_eq!(res.rows.len(), 2);
        // full page → next cursor present
        assert!(res.next_cursor.is_some());
        let log = provider.executor.sql_log();
        assert!(log[0].contains("SELECT"));
        assert!(log[0].contains("FROM \"products\""));
        assert!(log[0].contains("LIMIT @_limit OFFSET @_offset"));
    }

    #[test]
    fn query_partial_page_no_next_cursor() {
        let exec = RecordingExecutor::new(vec![make_rows(1)], 0);
        let provider = SqlMemoryNodeProvider::postgres(exec);
        let mut f = QueryFrame::new("urn:nps:node:test:products");
        f.limit = Some(2);
        let res = provider.query(&f, &schema(), &options()).unwrap();
        assert_eq!(res.rows.len(), 1);
        assert!(res.next_cursor.is_none());
    }

    #[test]
    fn stream_advances_until_partial_page() {
        // two full pages (2 rows) then a partial page (1 row) then stop
        let exec = RecordingExecutor::new(vec![make_rows(2), make_rows(2), make_rows(1)], 0);
        let provider = SqlMemoryNodeProvider::postgres(exec);
        let mut f = QueryFrame::new("urn:nps:node:test:products");
        f.limit = Some(2);
        let pages = provider.stream(&f, &schema(), &options()).unwrap();
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[2].len(), 1);
    }

    #[test]
    fn count_uses_count_query() {
        let exec = RecordingExecutor::new(vec![], 42);
        let provider = SqlMemoryNodeProvider::sql_server(exec);
        let f = QueryFrame::new("urn:nps:node:test:products");
        let n = provider.count(&f, &schema()).unwrap();
        assert_eq!(n, 42);
        assert!(provider.executor.sql_log()[0].starts_with("SELECT COUNT(*) FROM [products]"));
    }
}
