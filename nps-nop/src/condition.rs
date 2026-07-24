// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Evaluates CEL-subset condition expressions used in DAG node `condition`
//! fields (NPS-5 §3.1.5). Faithful port of the .NET `NopConditionEvaluator`.
//!
//! Supported syntax:
//!   - Comparison: `$.node.field > 0.7`, `$.node.status == "ok"`, `$.n.x != null`
//!   - Boolean logic: `&&`, `||`, `!`
//!   - Grouping: `( expr )`
//!   - Literals: numbers, quoted strings, `true`, `false`, `null`
//!   - JSONPath access: `$.node_id.field.sub`

use serde_json::Value;
use std::collections::HashMap;

use crate::input_mapper;

/// Raised when a condition expression cannot be parsed or evaluated.
#[derive(Debug, Clone)]
pub struct ConditionError {
    pub message: String,
}

impl ConditionError {
    fn new(message: impl Into<String>, expression: &str) -> Self {
        ConditionError {
            message: format!("{}  Expression: «{}»", message.into(), expression),
        }
    }
}

impl std::fmt::Display for ConditionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Evaluates `condition` in the context of completed node results.
/// Returns `true` if the node should execute; `false` if it should be skipped.
pub fn evaluate(condition: &str, context: &HashMap<String, Value>) -> Result<bool, ConditionError> {
    if condition.trim().is_empty() {
        return Ok(true);
    }
    let trimmed = condition.trim();
    let tokens = tokenize(trimmed)?;
    let mut parser = Parser {
        tokens,
        pos: 0,
        context,
    };
    parser.parse_or_expr()
}

// ── Tokenizer ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TokenKind {
    DollarPath,
    Number,
    Str,
    True,
    False,
    Null,
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
    Neq,
    And,
    Or,
    Not,
    LParen,
    RParen,
    Eof,
}

#[derive(Debug, Clone)]
struct Token {
    kind: TokenKind,
    raw: String,
}

fn tokenize(input: &str) -> Result<Vec<Token>, ConditionError> {
    let chars: Vec<char> = input.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let n = chars.len();

    let push = |tokens: &mut Vec<Token>, kind: TokenKind, raw: &str| {
        tokens.push(Token {
            kind,
            raw: raw.to_string(),
        });
    };

    while i < n {
        let c = chars[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }

        // Dollar path
        if c == '$' && i + 1 < n && chars[i + 1] == '.' {
            let start = i;
            while i < n
                && (chars[i].is_alphanumeric()
                    || chars[i] == '_'
                    || chars[i] == '.'
                    || chars[i] == '$')
            {
                i += 1;
            }
            let raw: String = chars[start..i].iter().collect();
            push(&mut tokens, TokenKind::DollarPath, &raw);
            continue;
        }

        // String literal
        if c == '"' {
            let start = i;
            i += 1;
            while i < n && chars[i] != '"' {
                i += 1;
            }
            i += 1; // closing quote
            // content between quotes
            let content: String = chars[(start + 1)..(i - 1)].iter().collect();
            push(&mut tokens, TokenKind::Str, &content);
            continue;
        }

        // Number
        if c.is_ascii_digit() || (c == '-' && i + 1 < n && chars[i + 1].is_ascii_digit()) {
            let start = i;
            if chars[i] == '-' {
                i += 1;
            }
            while i < n && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            let raw: String = chars[start..i].iter().collect();
            push(&mut tokens, TokenKind::Number, &raw);
            continue;
        }

        // Two-char operators
        if c == '>' && i + 1 < n && chars[i + 1] == '=' {
            push(&mut tokens, TokenKind::Gte, ">=");
            i += 2;
            continue;
        }
        if c == '<' && i + 1 < n && chars[i + 1] == '=' {
            push(&mut tokens, TokenKind::Lte, "<=");
            i += 2;
            continue;
        }
        if c == '=' && i + 1 < n && chars[i + 1] == '=' {
            push(&mut tokens, TokenKind::Eq, "==");
            i += 2;
            continue;
        }
        if c == '!' && i + 1 < n && chars[i + 1] == '=' {
            push(&mut tokens, TokenKind::Neq, "!=");
            i += 2;
            continue;
        }
        if c == '&' && i + 1 < n && chars[i + 1] == '&' {
            push(&mut tokens, TokenKind::And, "&&");
            i += 2;
            continue;
        }
        if c == '|' && i + 1 < n && chars[i + 1] == '|' {
            push(&mut tokens, TokenKind::Or, "||");
            i += 2;
            continue;
        }

        // One-char operators
        match c {
            '>' => {
                push(&mut tokens, TokenKind::Gt, ">");
                i += 1;
                continue;
            }
            '<' => {
                push(&mut tokens, TokenKind::Lt, "<");
                i += 1;
                continue;
            }
            '!' => {
                push(&mut tokens, TokenKind::Not, "!");
                i += 1;
                continue;
            }
            '(' => {
                push(&mut tokens, TokenKind::LParen, "(");
                i += 1;
                continue;
            }
            ')' => {
                push(&mut tokens, TokenKind::RParen, ")");
                i += 1;
                continue;
            }
            _ => {}
        }

        // Keywords: true, false, null
        if c.is_alphabetic() {
            let start = i;
            while i < n && chars[i].is_alphanumeric() {
                i += 1;
            }
            let kw: String = chars[start..i].iter().collect();
            match kw.as_str() {
                "true" => push(&mut tokens, TokenKind::True, "true"),
                "false" => push(&mut tokens, TokenKind::False, "false"),
                "null" => push(&mut tokens, TokenKind::Null, "null"),
                _ => return Err(ConditionError::new(format!("Unknown token '{kw}'."), input)),
            }
            continue;
        }

        return Err(ConditionError::new(
            format!("Unexpected character '{c}' at position {i}."),
            input,
        ));
    }

    tokens.push(Token {
        kind: TokenKind::Eof,
        raw: String::new(),
    });
    Ok(tokens)
}

// ── Value model ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Val {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
}

fn vals_equal(a: &Val, b: &Val) -> bool {
    match (a, b) {
        (Val::Num(x), Val::Num(y)) => x == y,
        (Val::Str(x), Val::Str(y)) => x == y,
        (Val::Bool(x), Val::Bool(y)) => x == y,
        (Val::Null, Val::Null) => true,
        _ => false,
    }
}

// ── Recursive-descent parser ────────────────────────────────────────────────

struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    context: &'a HashMap<String, Value>,
}

impl<'a> Parser<'a> {
    fn current(&self) -> &Token {
        &self.tokens[self.pos]
    }
    fn consume(&mut self) -> Token {
        let t = self.tokens[self.pos].clone();
        self.pos += 1;
        t
    }

    // or_expr := and_expr ('||' and_expr)*
    fn parse_or_expr(&mut self) -> Result<bool, ConditionError> {
        let mut left = self.parse_and_expr()?;
        while self.current().kind == TokenKind::Or {
            self.consume();
            let right = self.parse_and_expr()?;
            left = left || right;
        }
        Ok(left)
    }

    // and_expr := not_expr ('&&' not_expr)*
    fn parse_and_expr(&mut self) -> Result<bool, ConditionError> {
        let mut left = self.parse_not_expr()?;
        while self.current().kind == TokenKind::And {
            self.consume();
            let right = self.parse_not_expr()?;
            left = left && right;
        }
        Ok(left)
    }

    // not_expr := '!' not_expr | comparison
    fn parse_not_expr(&mut self) -> Result<bool, ConditionError> {
        if self.current().kind == TokenKind::Not {
            self.consume();
            return Ok(!self.parse_not_expr()?);
        }
        self.parse_comparison()
    }

    // comparison := value (op value)? | '(' or_expr ')' | true | false
    fn parse_comparison(&mut self) -> Result<bool, ConditionError> {
        if self.current().kind == TokenKind::LParen {
            self.consume(); // '('
            let inner = self.parse_or_expr()?;
            if self.current().kind != TokenKind::RParen {
                return Err(ConditionError::new("Expected ')'.", ""));
            }
            self.consume();
            return Ok(inner);
        }

        if self.current().kind == TokenKind::True {
            self.consume();
            return Ok(true);
        }
        if self.current().kind == TokenKind::False {
            self.consume();
            return Ok(false);
        }

        let lhs = self.parse_value()?;

        let op_kind = self.current().kind;
        if !is_comparison_op(op_kind) {
            return Ok(as_truthy(&lhs));
        }

        self.consume(); // operator
        let rhs = self.parse_value()?;
        Ok(compare(&lhs, op_kind, &rhs))
    }

    // value := dollar_path | number | string | null | true | false
    fn parse_value(&mut self) -> Result<Val, ConditionError> {
        let tok = self.consume();
        match tok.kind {
            TokenKind::DollarPath => self.resolve_path(&tok.raw),
            TokenKind::Number => tok
                .raw
                .parse::<f64>()
                .map(Val::Num)
                .map_err(|_| ConditionError::new(format!("Invalid number '{}'.", tok.raw), "")),
            TokenKind::Str => Ok(Val::Str(tok.raw)),
            TokenKind::True => Ok(Val::Bool(true)),
            TokenKind::False => Ok(Val::Bool(false)),
            TokenKind::Null => Ok(Val::Null),
            _ => Err(ConditionError::new(
                format!("Expected a value, got '{}'.", tok.raw),
                "",
            )),
        }
    }

    fn resolve_path(&self, path: &str) -> Result<Val, ConditionError> {
        let element = input_mapper::resolve(path, self.context)
            .map_err(|e| ConditionError::new(e.message, path))?;
        Ok(match element {
            None => Val::Null,
            Some(Value::Null) => Val::Null,
            Some(Value::Number(n)) => Val::Num(n.as_f64().unwrap_or(0.0)),
            Some(Value::String(s)) => Val::Str(s),
            Some(Value::Bool(b)) => Val::Bool(b),
            // object/array → raw text (matches .NET GetRawText fallback)
            Some(other) => Val::Str(other.to_string()),
        })
    }
}

fn is_comparison_op(k: TokenKind) -> bool {
    matches!(
        k,
        TokenKind::Gt
            | TokenKind::Gte
            | TokenKind::Lt
            | TokenKind::Lte
            | TokenKind::Eq
            | TokenKind::Neq
    )
}

fn as_truthy(v: &Val) -> bool {
    match v {
        Val::Bool(b) => *b,
        Val::Num(d) => *d != 0.0,
        Val::Str(s) => !s.is_empty(),
        Val::Null => false,
    }
}

fn compare(lhs: &Val, op: TokenKind, rhs: &Val) -> bool {
    if op == TokenKind::Eq {
        return vals_equal(lhs, rhs);
    }
    if op == TokenKind::Neq {
        return !vals_equal(lhs, rhs);
    }
    if matches!(lhs, Val::Null) || matches!(rhs, Val::Null) {
        return false;
    }

    // Numeric comparisons
    if let (Val::Num(ld), Val::Num(rd)) = (lhs, rhs) {
        return match op {
            TokenKind::Gt => ld > rd,
            TokenKind::Gte => ld >= rd,
            TokenKind::Lt => ld < rd,
            TokenKind::Lte => ld <= rd,
            _ => false,
        };
    }

    // String comparisons (ordinal)
    if let (Val::Str(ls), Val::Str(rs)) = (lhs, rhs) {
        let cmp = ls.cmp(rs);
        return match op {
            TokenKind::Gt => cmp == std::cmp::Ordering::Greater,
            TokenKind::Gte => cmp != std::cmp::Ordering::Less,
            TokenKind::Lt => cmp == std::cmp::Ordering::Less,
            TokenKind::Lte => cmp != std::cmp::Ordering::Greater,
            _ => false,
        };
    }

    false
}
