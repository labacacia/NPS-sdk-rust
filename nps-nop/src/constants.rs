// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Protocol-level limits defined by NPS-5 §8.2 (mirror of .NET `NopConstants`).

/// Maximum number of nodes in a single DAG.
pub const MAX_DAG_NODES: usize = 32;

/// Maximum delegation chain depth (Orchestrator → Worker → Sub-Worker).
pub const MAX_DELEGATE_CHAIN_DEPTH: i64 = 3;

/// Maximum length of a CEL condition expression in characters.
pub const MAX_CONDITION_LENGTH: usize = 512;

/// Maximum JSONPath nesting depth in input_mapping values.
pub const MAX_INPUT_MAPPING_DEPTH: usize = 8;

/// Default task timeout in milliseconds.
pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Maximum task timeout in milliseconds (1 hour).
pub const MAX_TIMEOUT_MS: u64 = 3_600_000;

/// Default AnchorFrame TTL in seconds.
pub const DEFAULT_ANCHOR_TTL: u64 = 3600;

/// Maximum number of callback POST attempts with exponential backoff (NPS-5 §8.4).
pub const CALLBACK_MAX_RETRIES: u32 = 3;
