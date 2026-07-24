// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NWP filter → parameterized SQL translation (NPS-2 §5.2).
//!
//! Pure logic port of the .NET `NwpFilterTranslator` and `SqlQueryBuilder`.
//! Translates the NWP filter DSL (`$eq`/`$ne`/`$lt`/`$lte`/`$gt`/`$gte`/`$in`/
//! `$nin`/`$contains`/`$between`/`$and`/`$or`) plus ordering, projection, limit
//! and cursor pagination into a parameterized SQL string and an ordered
//! parameter list. No database driver is involved — the output feeds any
//! executor (see [`crate::sql_provider`]).

use serde_json::Value;

use crate::error_codes::{QUERY_FIELD_UNKNOWN, QUERY_FILTER_INVALID};
use crate::frames::QueryFrame;
use crate::memory_server::{MemoryNodeOptions, MemoryNodeSchema};

/// Supported SQL dialects for quoting and pagination syntax.
/// Port of .NET `DatabaseDialect`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseDialect {
    SqlServer,
    PostgreSql,
}

/// A single parameter value bound into a translated query.
/// Mirrors the value shapes Dapper receives from the .NET translator.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    /// `$in` / `$nin` list — expands to a single Dapper `@p` list parameter
    /// on the .NET side; kept as a list here so executors can expand it.
    List(Vec<SqlValue>),
}

/// A named SQL parameter (`@name` → value).
#[derive(Debug, Clone, PartialEq)]
pub struct SqlParam {
    pub name: String,
    pub value: SqlValue,
}

/// Ordered collection of parameters, addressable by name.
/// Analogue of Dapper's `DynamicParameters`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SqlParams {
    params: Vec<SqlParam>,
}

impl SqlParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, name: impl Into<String>, value: SqlValue) {
        self.params.push(SqlParam {
            name: name.into(),
            value,
        });
    }

    pub fn get(&self, name: &str) -> Option<&SqlValue> {
        self.params.iter().find(|p| p.name == name).map(|p| &p.value)
    }

    pub fn iter(&self) -> impl Iterator<Item = &SqlParam> {
        self.params.iter()
    }

    pub fn len(&self) -> usize {
        self.params.len()
    }

    pub fn is_empty(&self) -> bool {
        self.params.is_empty()
    }
}

/// Error raised when a NWP filter cannot be translated to SQL.
/// Port of .NET `NwpFilterException`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NwpFilterError {
    pub message: String,
    pub error_code: &'static str,
}

impl NwpFilterError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            error_code: QUERY_FILTER_INVALID,
        }
    }

    fn with_code(message: impl Into<String>, error_code: &'static str) -> Self {
        Self {
            message: message.into(),
            error_code,
        }
    }
}

impl std::fmt::Display for NwpFilterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for NwpFilterError {}

pub type FilterResult<T> = Result<T, NwpFilterError>;

// ── Filter translator ──────────────────────────────────────────────────────────

/// Translates a NWP filter predicate to a parameterized SQL `WHERE` fragment.
/// Validates all field names against the schema to prevent SQL injection.
/// Port of .NET `NwpFilterTranslator`.
pub struct NwpFilterTranslator<'a> {
    schema: &'a MemoryNodeSchema,
    dialect: DatabaseDialect,
    param_index: usize,
}

impl<'a> NwpFilterTranslator<'a> {
    pub fn new(schema: &'a MemoryNodeSchema, dialect: DatabaseDialect) -> Self {
        Self {
            schema,
            dialect,
            param_index: 0,
        }
    }

    /// Translates `filter` into a `WHERE` clause fragment and populates `params`.
    /// Returns an empty string when `filter` is `None` or JSON `null`.
    pub fn translate(&mut self, filter: Option<&Value>, params: &mut SqlParams) -> FilterResult<String> {
        self.param_index = 0;
        match filter {
            None => Ok(String::new()),
            Some(Value::Null) => Ok(String::new()),
            Some(v) => self.build_object(v, params),
        }
    }

    fn build_object(&mut self, obj: &Value, p: &mut SqlParams) -> FilterResult<String> {
        let map = obj.as_object().ok_or_else(|| {
            NwpFilterError::new("Filter condition must be an object.")
        })?;

        let mut clauses = Vec::new();
        for (name, value) in map {
            if let Some(stripped) = name.strip_prefix('$') {
                let _ = stripped;
                clauses.push(self.build_logical(name, value, p)?);
            } else {
                let field = self.validate_field(name)?;
                clauses.push(self.build_field_condition(&field, value, p)?);
            }
        }
        // Empty logical children produce empty strings; drop them so the join
        // and the single-clause fast path match .NET behaviour.
        clauses.retain(|c| !c.is_empty());

        Ok(match clauses.len() {
            0 => String::new(),
            1 => clauses.into_iter().next().unwrap(),
            _ => format!("({})", clauses.join(" AND ")),
        })
    }

    fn build_logical(&mut self, op: &str, value: &Value, p: &mut SqlParams) -> FilterResult<String> {
        let arr = value.as_array().ok_or_else(|| {
            NwpFilterError::new(format!("Logical operator '{op}' requires an array value."))
        })?;

        let separator = match op {
            "$and" => " AND ",
            "$or" => " OR ",
            _ => {
                return Err(NwpFilterError::new(format!(
                    "Unknown logical operator '{op}'."
                )))
            }
        };

        let mut parts = Vec::new();
        for el in arr {
            let s = self.build_object(el, p)?;
            if !s.is_empty() {
                parts.push(s);
            }
        }

        Ok(match parts.len() {
            0 => String::new(),
            1 => parts.into_iter().next().unwrap(),
            _ => format!("({})", parts.join(separator)),
        })
    }

    fn build_field_condition(
        &mut self,
        field: &FieldRef,
        condition: &Value,
        p: &mut SqlParams,
    ) -> FilterResult<String> {
        let obj = condition.as_object().ok_or_else(|| {
            NwpFilterError::new(format!(
                "Field '{}' condition must be an object (e.g. {{\"$eq\": value}}).",
                field.name
            ))
        })?;

        let col = self.quote_column(&field.column);
        let mut parts = Vec::new();

        for (op, value) in obj {
            let part = match op.as_str() {
                "$in" => self.build_in(&col, value, p, false)?,
                "$nin" => self.build_in(&col, value, p, true)?,
                "$between" => self.build_between(&col, value, p)?,
                other => self.build_simple(&col, other, &field.name, value, p)?,
            };
            parts.push(part);
        }

        Ok(if parts.len() == 1 {
            parts.into_iter().next().unwrap()
        } else {
            format!("({})", parts.join(" AND "))
        })
    }

    fn build_simple(
        &mut self,
        col: &str,
        op: &str,
        field_name: &str,
        value: &Value,
        p: &mut SqlParams,
    ) -> FilterResult<String> {
        let param_name = format!("p{}", self.param_index);
        self.param_index += 1;

        let (sql_op, wrapped) = match op {
            "$eq" => ("=", false),
            "$ne" => ("<>", false),
            "$lt" => ("<", false),
            "$lte" => ("<=", false),
            "$gt" => (">", false),
            "$gte" => (">=", false),
            "$contains" => ("LIKE", true),
            _ => {
                return Err(NwpFilterError::new(format!(
                    "Unknown filter operator '{op}' on field '{field_name}'."
                )))
            }
        };

        let bound = if wrapped {
            // $contains → %value%
            match extract_value(value) {
                SqlValue::Text(s) => SqlValue::Text(format!("%{s}%")),
                other => SqlValue::Text(format!("%{}%", sql_value_to_string(&other))),
            }
        } else {
            extract_value(value)
        };
        p.add(param_name.clone(), bound);
        Ok(format!("{col} {sql_op} @{param_name}"))
    }

    fn build_in(&mut self, col: &str, arr: &Value, p: &mut SqlParams, negate: bool) -> FilterResult<String> {
        let items = arr.as_array().ok_or_else(|| {
            NwpFilterError::new("$in/$nin requires an array value.")
        })?;

        let values: Vec<SqlValue> = items.iter().map(extract_value).collect();
        if values.is_empty() {
            // empty IN → always false; empty NIN → always true
            return Ok(if negate { "1=1".into() } else { "1=0".into() });
        }

        let param_name = format!("p{}", self.param_index);
        self.param_index += 1;
        p.add(param_name.clone(), SqlValue::List(values));
        Ok(if negate {
            format!("{col} NOT IN @{param_name}")
        } else {
            format!("{col} IN @{param_name}")
        })
    }

    fn build_between(&mut self, col: &str, arr: &Value, p: &mut SqlParams) -> FilterResult<String> {
        let items = arr.as_array().filter(|a| a.len() == 2).ok_or_else(|| {
            NwpFilterError::new("$between requires an array of exactly two values [low, high].")
        })?;

        let p_low = format!("p{}", self.param_index);
        self.param_index += 1;
        let p_high = format!("p{}", self.param_index);
        self.param_index += 1;
        p.add(p_low.clone(), extract_value(&items[0]));
        p.add(p_high.clone(), extract_value(&items[1]));
        Ok(format!("{col} BETWEEN @{p_low} AND @{p_high}"))
    }

    fn validate_field(&self, name: &str) -> FilterResult<FieldRef> {
        self.schema
            .get_field(name)
            .map(FieldRef::from)
            .ok_or_else(|| {
                NwpFilterError::with_code(format!("Unknown field '{name}'."), QUERY_FIELD_UNKNOWN)
            })
    }

    fn quote_column(&self, col: &str) -> String {
        match self.dialect {
            DatabaseDialect::SqlServer => format!("[{col}]"),
            DatabaseDialect::PostgreSql => format!("\"{col}\""),
        }
    }
}

/// Owned snapshot of a resolved schema field (name + column).
struct FieldRef {
    name: String,
    column: String,
}

impl From<&crate::memory_server::MemoryNodeField> for FieldRef {
    fn from(f: &crate::memory_server::MemoryNodeField) -> Self {
        FieldRef {
            name: f.name.clone(),
            column: f.resolved_column_name().to_string(),
        }
    }
}

fn extract_value(el: &Value) -> SqlValue {
    match el {
        Value::String(s) => SqlValue::Text(s.clone()),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                SqlValue::Int(i)
            } else {
                SqlValue::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        Value::Bool(b) => SqlValue::Bool(*b),
        Value::Null => SqlValue::Null,
        other => SqlValue::Text(other.to_string()),
    }
}

fn sql_value_to_string(v: &SqlValue) -> String {
    match v {
        SqlValue::Null => "".into(),
        SqlValue::Bool(b) => b.to_string(),
        SqlValue::Int(i) => i.to_string(),
        SqlValue::Float(f) => f.to_string(),
        SqlValue::Text(s) => s.clone(),
        SqlValue::List(_) => "".into(),
    }
}

// ── SQL query builder ──────────────────────────────────────────────────────────

/// Builds a complete parameterized `SELECT` from a [`QueryFrame`], handling
/// field projection, filter, ordering, and cursor-based pagination.
/// Port of .NET `SqlQueryBuilder`.
pub struct SqlQueryBuilder<'a> {
    schema: &'a MemoryNodeSchema,
    dialect: DatabaseDialect,
}

impl<'a> SqlQueryBuilder<'a> {
    pub fn new(schema: &'a MemoryNodeSchema, dialect: DatabaseDialect) -> Self {
        Self { schema, dialect }
    }

    /// Builds the full `SELECT` query and its parameters.
    pub fn build(
        &self,
        frame: &QueryFrame,
        options: &MemoryNodeOptions,
    ) -> FilterResult<(String, SqlParams)> {
        let mut p = SqlParams::new();
        let mut sql = String::new();

        let frame_limit = frame.limit.unwrap_or(0);
        let default_limit = options.default_limit as u64;
        let max_limit = options.max_limit as u64;
        let limit = (if frame_limit == 0 { default_limit } else { frame_limit }).min(max_limit);
        let offset = decode_cursor(frame.cursor.as_deref());

        // SELECT
        sql.push_str("SELECT ");
        sql.push_str(&self.build_select_list(frame.fields.as_deref())?);

        // FROM
        sql.push_str(" FROM ");
        sql.push_str(&self.quote_table(&self.schema.table_name));

        // WHERE
        let mut translator = NwpFilterTranslator::new(self.schema, self.dialect);
        let where_clause = translator.translate(frame.filter.as_ref(), &mut p)?;
        if !where_clause.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clause);
        }

        // ORDER BY (required for stable pagination)
        sql.push_str(" ORDER BY ");
        match order_clauses(frame.order.as_ref()) {
            Some(clauses) if !clauses.is_empty() => {
                sql.push_str(&self.build_order_by(&clauses)?);
            }
            _ => {
                sql.push_str(&self.quote_column(&self.schema.primary_key));
            }
        }

        // PAGINATION — dialect-specific syntax
        match self.dialect {
            DatabaseDialect::SqlServer => {
                sql.push_str(" OFFSET @_offset ROWS FETCH NEXT @_limit ROWS ONLY");
            }
            DatabaseDialect::PostgreSql => {
                sql.push_str(" LIMIT @_limit OFFSET @_offset");
            }
        }

        p.add("_limit", SqlValue::Int(limit as i64));
        p.add("_offset", SqlValue::Int(offset as i64));

        Ok((sql, p))
    }

    /// Builds a `COUNT(*)` query for the same filter.
    pub fn build_count(&self, frame: &QueryFrame) -> FilterResult<(String, SqlParams)> {
        let mut p = SqlParams::new();
        let mut sql = String::new();

        sql.push_str("SELECT COUNT(*) FROM ");
        sql.push_str(&self.quote_table(&self.schema.table_name));

        let mut translator = NwpFilterTranslator::new(self.schema, self.dialect);
        let where_clause = translator.translate(frame.filter.as_ref(), &mut p)?;
        if !where_clause.is_empty() {
            sql.push_str(" WHERE ");
            sql.push_str(&where_clause);
        }

        Ok((sql, p))
    }

    fn build_select_list(&self, fields: Option<&[String]>) -> FilterResult<String> {
        match fields {
            None => Ok(self.all_columns()),
            Some(f) if f.is_empty() => Ok(self.all_columns()),
            Some(f) => {
                for name in f {
                    if !self.schema.has_field(name) {
                        return Err(NwpFilterError::with_code(
                            format!("Unknown field '{name}'."),
                            QUERY_FIELD_UNKNOWN,
                        ));
                    }
                }
                let cols: Vec<String> = f
                    .iter()
                    .map(|name| {
                        let field = self.schema.get_field(name).unwrap();
                        let col = self.quote_column(field.resolved_column_name());
                        // Alias back to the NWP name if the column name differs.
                        if field.column_name.is_some() {
                            format!("{col} AS {}", self.quote_column(&field.name))
                        } else {
                            col
                        }
                    })
                    .collect();
                Ok(cols.join(", "))
            }
        }
    }

    fn all_columns(&self) -> String {
        self.schema
            .fields
            .iter()
            .map(|f| self.quote_column(f.resolved_column_name()))
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn build_order_by(&self, order: &[OrderClause]) -> FilterResult<String> {
        let mut parts = Vec::new();
        for o in order {
            let field = self.schema.get_field(&o.field).ok_or_else(|| {
                NwpFilterError::with_code(
                    format!("Unknown order field '{}'.", o.field),
                    QUERY_FIELD_UNKNOWN,
                )
            })?;
            let dir = if o.dir.eq_ignore_ascii_case("DESC") {
                "DESC"
            } else {
                "ASC"
            };
            parts.push(format!(
                "{} {dir}",
                self.quote_column(field.resolved_column_name())
            ));
        }
        Ok(parts.join(", "))
    }

    fn quote_column(&self, col: &str) -> String {
        match self.dialect {
            DatabaseDialect::SqlServer => format!("[{col}]"),
            DatabaseDialect::PostgreSql => format!("\"{col}\""),
        }
    }

    fn quote_table(&self, table: &str) -> String {
        self.quote_column(table)
    }
}

/// One ORDER BY clause parsed from a `QueryFrame.order` element.
#[derive(Debug, Clone)]
pub struct OrderClause {
    pub field: String,
    pub dir: String,
}

/// Parses `QueryFrame.order` (JSON) into a list of [`OrderClause`].
///
/// Accepts the two wire shapes the .NET reference produces:
/// - array of `{ "field": "...", "dir": "ASC|DESC" }` objects, and
/// - array of `["field", "ASC|DESC"]` / single-key `{ "field": "dir" }` maps.
fn order_clauses(order: Option<&Value>) -> Option<Vec<OrderClause>> {
    let arr = order?.as_array()?;
    let mut out = Vec::new();
    for el in arr {
        if let Some(obj) = el.as_object() {
            if let (Some(field), dir) = (
                obj.get("field").and_then(Value::as_str),
                obj.get("dir").and_then(Value::as_str),
            ) {
                out.push(OrderClause {
                    field: field.to_string(),
                    dir: dir.unwrap_or("ASC").to_string(),
                });
                continue;
            }
            // single-key map: { "price": "DESC" }
            if let Some((field, dir)) = obj.iter().next() {
                out.push(OrderClause {
                    field: field.clone(),
                    dir: dir.as_str().unwrap_or("ASC").to_string(),
                });
            }
        } else if let Some(pair) = el.as_array() {
            if let Some(field) = pair.first().and_then(Value::as_str) {
                let dir = pair.get(1).and_then(Value::as_str).unwrap_or("ASC");
                out.push(OrderClause {
                    field: field.to_string(),
                    dir: dir.to_string(),
                });
            }
        } else if let Some(field) = el.as_str() {
            out.push(OrderClause {
                field: field.to_string(),
                dir: "ASC".to_string(),
            });
        }
    }
    Some(out)
}

// ── Cursor codec ───────────────────────────────────────────────────────────────

/// Encodes a row offset as an opaque Base64-URL cursor.
/// Returns `None` for `offset <= 0`. Port of .NET `SqlQueryBuilder.EncodeCursor`.
pub fn encode_cursor(next_offset: i64) -> Option<String> {
    if next_offset <= 0 {
        return None;
    }
    let json = format!("{{\"o\":{next_offset}}}");
    Some(base64url_encode(json.as_bytes()))
}

/// Decodes a Base64-URL cursor back to a row offset. Returns 0 for null/invalid.
/// Port of .NET `SqlQueryBuilder.DecodeCursor`.
pub fn decode_cursor(cursor: Option<&str>) -> i64 {
    let cursor = match cursor {
        Some(c) if !c.is_empty() => c,
        _ => return 0,
    };
    let bytes = match base64url_decode(cursor) {
        Some(b) => b,
        None => return 0,
    };
    let json = match std::str::from_utf8(&bytes) {
        Ok(s) => s,
        Err(_) => return 0,
    };
    match serde_json::from_str::<Value>(json) {
        Ok(v) => v.get("o").and_then(Value::as_i64).unwrap_or(0),
        Err(_) => 0,
    }
}

// Minimal Base64-URL (no padding) codec — matches the .NET cursor format:
// standard base64, `+`→`-`, `/`→`_`, trailing `=` stripped.
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64url_encode(input: &[u8]) -> String {
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63] as char);
        }
    }
    // URL-safe alphabet, padding already omitted.
    out.replace('+', "-").replace('/', "_")
}

fn base64url_decode(input: &str) -> Option<Vec<u8>> {
    let normalized = input.replace('-', "+").replace('_', "/");
    let bytes = normalized.as_bytes();
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &c in bytes {
        if c == b'=' {
            break;
        }
        let val = B64.iter().position(|&x| x == c)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
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
                MemoryNodeField::new("price", "number"),
                MemoryNodeField::new("active", "boolean"),
                MemoryNodeField::new("category", "string"),
            ],
        }
    }

    fn sku_schema() -> MemoryNodeSchema {
        let mut sku = MemoryNodeField::new("sku", "string");
        sku.column_name = Some("product_sku".into());
        MemoryNodeSchema {
            table_name: "products".into(),
            primary_key: "id".into(),
            fields: vec![
                MemoryNodeField::new("id", "number"),
                MemoryNodeField::new("name", "string"),
                MemoryNodeField::new("price", "number"),
                sku,
            ],
        }
    }

    fn options(schema: MemoryNodeSchema) -> MemoryNodeOptions {
        let mut o = MemoryNodeOptions::new("urn:nps:node:test:products", "/products", schema);
        o.default_limit = 20;
        o.max_limit = 100;
        o
    }

    fn pg(s: &MemoryNodeSchema) -> NwpFilterTranslator<'_> {
        NwpFilterTranslator::new(s, DatabaseDialect::PostgreSql)
    }
    fn mssql(s: &MemoryNodeSchema) -> NwpFilterTranslator<'_> {
        NwpFilterTranslator::new(s, DatabaseDialect::SqlServer)
    }

    // ── Null / empty ──────────────────────────────────────────────────────────

    #[test]
    fn null_filter_returns_empty() {
        let s = schema();
        let mut p = SqlParams::new();
        assert_eq!(pg(&s).translate(None, &mut p).unwrap(), "");
    }

    #[test]
    fn json_null_filter_returns_empty() {
        let s = schema();
        let mut p = SqlParams::new();
        assert_eq!(pg(&s).translate(Some(&json!(null)), &mut p).unwrap(), "");
    }

    // ── $eq / $ne ─────────────────────────────────────────────────────────────

    #[test]
    fn eq_postgresql_quotes_correctly() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"name":{"$eq":"widget"}})), &mut p)
            .unwrap();
        assert_eq!(sql, "\"name\" = @p0");
        assert_eq!(p.get("p0"), Some(&SqlValue::Text("widget".into())));
    }

    #[test]
    fn eq_sqlserver_uses_brackets() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = mssql(&s)
            .translate(Some(&json!({"name":{"$eq":"widget"}})), &mut p)
            .unwrap();
        assert_eq!(sql, "[name] = @p0");
    }

    #[test]
    fn ne_produces_not_equals() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"price":{"$ne":0}})), &mut p)
            .unwrap();
        assert!(sql.contains("<>"));
        assert_eq!(p.get("p0"), Some(&SqlValue::Int(0)));
    }

    #[test]
    fn comparison_ops_produce_correct_sql() {
        for (op, expected) in [("$lt", "<"), ("$lte", "<="), ("$gt", ">"), ("$gte", ">=")] {
            let s = schema();
            let mut p = SqlParams::new();
            let sql = pg(&s)
                .translate(Some(&json!({"price":{op:10}})), &mut p)
                .unwrap();
            assert!(sql.contains(expected), "op {op} => {sql}");
        }
    }

    #[test]
    fn contains_wraps_with_percent() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"name":{"$contains":"wid"}})), &mut p)
            .unwrap();
        assert!(sql.contains("LIKE"));
        assert_eq!(p.get("p0"), Some(&SqlValue::Text("%wid%".into())));
    }

    // ── $in / $nin ────────────────────────────────────────────────────────────

    #[test]
    fn in_produces_in_clause() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"category":{"$in":["A","B"]}})), &mut p)
            .unwrap();
        assert!(sql.contains("IN @p0"));
        match p.get("p0") {
            Some(SqlValue::List(v)) => assert_eq!(v.len(), 2),
            other => panic!("expected list, got {other:?}"),
        }
    }

    #[test]
    fn in_empty_array_returns_false() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"category":{"$in":[]}})), &mut p)
            .unwrap();
        assert_eq!(sql, "1=0");
    }

    #[test]
    fn nin_empty_array_returns_true() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"category":{"$nin":[]}})), &mut p)
            .unwrap();
        assert_eq!(sql, "1=1");
    }

    #[test]
    fn nin_produces_not_in_clause() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"category":{"$nin":["X"]}})), &mut p)
            .unwrap();
        assert!(sql.contains("NOT IN @p0"));
    }

    // ── $between ──────────────────────────────────────────────────────────────

    #[test]
    fn between_produces_between_clause() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(Some(&json!({"price":{"$between":[10,99]}})), &mut p)
            .unwrap();
        assert!(sql.contains("BETWEEN @p0 AND @p1"));
        assert_eq!(p.get("p0"), Some(&SqlValue::Int(10)));
        assert_eq!(p.get("p1"), Some(&SqlValue::Int(99)));
    }

    #[test]
    fn between_wrong_length_errors() {
        let s = schema();
        let mut p = SqlParams::new();
        assert!(pg(&s)
            .translate(Some(&json!({"price":{"$between":[10]}})), &mut p)
            .is_err());
    }

    // ── $and / $or ────────────────────────────────────────────────────────────

    #[test]
    fn and_joins_with_and() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(
                Some(&json!({"$and":[{"name":{"$eq":"x"}},{"active":{"$eq":true}}]})),
                &mut p,
            )
            .unwrap();
        assert!(sql.contains(" AND "));
    }

    #[test]
    fn or_joins_with_or() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(
                Some(&json!({"$or":[{"price":{"$lt":5}},{"price":{"$gt":100}}]})),
                &mut p,
            )
            .unwrap();
        assert!(sql.contains(" OR "));
    }

    #[test]
    fn multi_field_object_implicit_and() {
        let s = schema();
        let mut p = SqlParams::new();
        let sql = pg(&s)
            .translate(
                Some(&json!({"name":{"$eq":"x"},"active":{"$eq":true}})),
                &mut p,
            )
            .unwrap();
        assert!(sql.contains("AND"));
    }

    // ── Errors ────────────────────────────────────────────────────────────────

    #[test]
    fn unknown_field_errors_field_unknown() {
        let s = schema();
        let mut p = SqlParams::new();
        let err = pg(&s)
            .translate(Some(&json!({"ghost":{"$eq":1}})), &mut p)
            .unwrap_err();
        assert_eq!(err.error_code, QUERY_FIELD_UNKNOWN);
    }

    #[test]
    fn unknown_operator_errors() {
        let s = schema();
        let mut p = SqlParams::new();
        assert!(pg(&s)
            .translate(Some(&json!({"name":{"$regex":".*"}})), &mut p)
            .is_err());
    }

    #[test]
    fn unknown_logical_op_errors() {
        let s = schema();
        let mut p = SqlParams::new();
        assert!(pg(&s)
            .translate(Some(&json!({"$not":[{"name":{"$eq":"x"}}]})), &mut p)
            .is_err());
    }

    #[test]
    fn logical_op_non_array_errors() {
        let s = schema();
        let mut p = SqlParams::new();
        assert!(pg(&s)
            .translate(Some(&json!({"$and":{"name":{"$eq":"x"}}})), &mut p)
            .is_err());
    }

    // ── SqlQueryBuilder ──────────────────────────────────────────────────────

    fn frame() -> QueryFrame {
        QueryFrame::new("urn:nps:node:test:products")
    }

    #[test]
    fn build_no_fields_selects_all_schema_columns() {
        let s = sku_schema();
        let o = options(s.clone());
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&frame(), &o).unwrap();
        assert!(sql.contains("\"id\""));
        assert!(sql.contains("\"name\""));
        assert!(sql.contains("\"price\""));
        assert!(sql.contains("\"product_sku\""));
    }

    #[test]
    fn build_column_alias_applies_alias() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.fields = Some(vec!["sku".into()]);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&f, &o).unwrap();
        assert!(sql.contains("\"product_sku\" AS \"sku\""));
    }

    #[test]
    fn build_unknown_field_errors() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.fields = Some(vec!["ghost".into()]);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        assert!(b.build(&f, &o).is_err());
    }

    #[test]
    fn build_pg_quotes_table_name() {
        let s = sku_schema();
        let o = options(s.clone());
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&frame(), &o).unwrap();
        assert!(sql.contains("FROM \"products\""));
    }

    #[test]
    fn build_sqlserver_brackets_table_name() {
        let s = sku_schema();
        let o = options(s.clone());
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::SqlServer);
        let (sql, _) = b.build(&frame(), &o).unwrap();
        assert!(sql.contains("FROM [products]"));
    }

    #[test]
    fn build_with_filter_appends_where() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.filter = Some(json!({"name":{"$eq":"widget"}}));
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, p) = b.build(&f, &o).unwrap();
        assert!(sql.contains("WHERE"));
        assert_eq!(p.get("p0"), Some(&SqlValue::Text("widget".into())));
    }

    #[test]
    fn build_no_filter_no_where() {
        let s = sku_schema();
        let o = options(s.clone());
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&frame(), &o).unwrap();
        assert!(!sql.contains("WHERE"));
    }

    #[test]
    fn build_no_order_defaults_to_primary_key() {
        let s = sku_schema();
        let o = options(s.clone());
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&frame(), &o).unwrap();
        assert!(sql.contains("ORDER BY \"id\""));
    }

    #[test]
    fn build_explicit_order_applies_it() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.order = Some(json!([{"field":"price","dir":"DESC"}]));
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build(&f, &o).unwrap();
        assert!(sql.contains("ORDER BY \"price\" DESC"));
    }

    #[test]
    fn build_unknown_order_field_errors() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.order = Some(json!([{"field":"ghost","dir":"ASC"}]));
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        assert!(b.build(&f, &o).is_err());
    }

    #[test]
    fn build_pg_uses_limit_offset() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.limit = Some(10);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, p) = b.build(&f, &o).unwrap();
        assert!(sql.contains("LIMIT @_limit OFFSET @_offset"));
        assert_eq!(p.get("_limit"), Some(&SqlValue::Int(10)));
        assert_eq!(p.get("_offset"), Some(&SqlValue::Int(0)));
    }

    #[test]
    fn build_sqlserver_uses_offset_fetch() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.limit = Some(5);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::SqlServer);
        let (sql, p) = b.build(&f, &o).unwrap();
        assert!(sql.contains("OFFSET @_offset ROWS FETCH NEXT @_limit ROWS ONLY"));
        assert_eq!(p.get("_limit"), Some(&SqlValue::Int(5)));
    }

    #[test]
    fn build_limit_clamped_to_max_limit() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.limit = Some(999);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (_, p) = b.build(&f, &o).unwrap();
        assert_eq!(p.get("_limit"), Some(&SqlValue::Int(100)));
    }

    #[test]
    fn build_zero_limit_uses_default() {
        let s = sku_schema();
        let o = options(s.clone());
        let mut f = frame();
        f.limit = Some(0);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (_, p) = b.build(&f, &o).unwrap();
        assert_eq!(p.get("_limit"), Some(&SqlValue::Int(20)));
    }

    #[test]
    fn build_with_cursor_decodes_offset() {
        let s = sku_schema();
        let o = options(s.clone());
        let cursor = encode_cursor(40).unwrap();
        let mut f = frame();
        f.limit = Some(10);
        f.cursor = Some(cursor);
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (_, p) = b.build(&f, &o).unwrap();
        assert_eq!(p.get("_offset"), Some(&SqlValue::Int(40)));
    }

    // ── Cursor codec ─────────────────────────────────────────────────────────

    #[test]
    fn encode_cursor_zero_or_negative_returns_none() {
        assert!(encode_cursor(0).is_none());
        assert!(encode_cursor(-1).is_none());
    }

    #[test]
    fn cursor_roundtrip() {
        for offset in [1i64, 20, 1000, i64::MAX / 2] {
            let cursor = encode_cursor(offset).unwrap();
            assert_eq!(decode_cursor(Some(&cursor)), offset);
        }
    }

    #[test]
    fn decode_cursor_null_or_empty_returns_zero() {
        assert_eq!(decode_cursor(None), 0);
        assert_eq!(decode_cursor(Some("")), 0);
    }

    #[test]
    fn decode_cursor_garbage_returns_zero() {
        assert_eq!(decode_cursor(Some("not-a-cursor!@#$")), 0);
    }

    // ── build_count ──────────────────────────────────────────────────────────

    #[test]
    fn build_count_no_filter_no_where() {
        let s = sku_schema();
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build_count(&frame()).unwrap();
        assert!(sql.starts_with("SELECT COUNT(*) FROM"));
        assert!(!sql.contains("WHERE"));
    }

    #[test]
    fn build_count_with_filter_appends_where() {
        let s = sku_schema();
        let mut f = frame();
        f.filter = Some(json!({"price":{"$gt":0}}));
        let b = SqlQueryBuilder::new(&s, DatabaseDialect::PostgreSql);
        let (sql, _) = b.build_count(&f).unwrap();
        assert!(sql.contains("WHERE"));
    }
}
