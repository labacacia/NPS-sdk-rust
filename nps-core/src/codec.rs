// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use crate::error::{NpsError, NpsResult};
use crate::frames::{EncodingTier, FrameHeader, FrameType};
use crate::registry::FrameRegistry;

pub type FrameDict = serde_json::Map<String, Value>;

// ── Encode helpers ─────────────────────────────────────────────────────────────

pub fn encode_json(dict: &FrameDict) -> NpsResult<Vec<u8>> {
    serde_json::to_vec(dict).map_err(|e| NpsError::Codec(e.to_string()))
}

pub fn encode_msgpack(dict: &FrameDict) -> NpsResult<Vec<u8>> {
    let v = serde_json::Value::Object(dict.clone());
    rmp_serde::to_vec_named(&v).map_err(|e| NpsError::Codec(e.to_string()))
}

pub fn decode_json(payload: &[u8]) -> NpsResult<FrameDict> {
    let v: Value = serde_json::from_slice(payload)
        .map_err(|e| NpsError::Codec(e.to_string()))?;
    match v {
        Value::Object(m) => Ok(m),
        _                => Err(NpsError::Codec("expected JSON object".into())),
    }
}

pub fn decode_msgpack(payload: &[u8]) -> NpsResult<FrameDict> {
    let v: Value = rmp_serde::from_slice(payload)
        .map_err(|e| NpsError::Codec(e.to_string()))?;
    match v {
        Value::Object(m) => Ok(m),
        _                => Err(NpsError::Codec("expected MsgPack map".into())),
    }
}

// ── NpsFrameCodec ──────────────────────────────────────────────────────────────

pub const DEFAULT_MAX_PAYLOAD: u64 = 10 * 1024 * 1024; // 10 MiB

pub struct NpsFrameCodec {
    registry:    FrameRegistry,
    max_payload: u64,
}

impl NpsFrameCodec {
    pub fn new(registry: FrameRegistry) -> Self {
        NpsFrameCodec { registry, max_payload: DEFAULT_MAX_PAYLOAD }
    }

    pub fn with_max_payload(mut self, max_payload: u64) -> Self {
        self.max_payload = max_payload;
        self
    }

    pub fn encode(&self, frame_type: FrameType, dict: &FrameDict, tier: EncodingTier, is_final: bool) -> NpsResult<Vec<u8>> {
        let payload = match tier {
            EncodingTier::Json    => encode_json(dict)?,
            EncodingTier::MsgPack => encode_msgpack(dict)?,
        };
        if payload.len() as u64 > self.max_payload {
            return Err(NpsError::Codec(format!(
                "payload {} exceeds max {}", payload.len(), self.max_payload
            )));
        }
        let header     = FrameHeader::new(frame_type, tier, is_final, payload.len() as u64);
        let mut wire   = header.to_bytes();
        wire.extend_from_slice(&payload);
        Ok(wire)
    }

    pub fn decode(&self, wire: &[u8]) -> NpsResult<(FrameType, FrameDict)> {
        let header  = FrameHeader::parse(wire)?;
        let hdr_len = header.header_size();
        let plen    = header.payload_length as usize;
        if wire.len() < hdr_len + plen {
            return Err(NpsError::Codec("wire too short for declared payload".into()));
        }
        let payload = &wire[hdr_len..hdr_len + plen];
        let dict = match header.encoding_tier() {
            EncodingTier::Json    => decode_json(payload)?,
            EncodingTier::MsgPack => decode_msgpack(payload)?,
        };
        // validate that the frame type is registered
        if !self.registry.is_registered(header.frame_type) {
            return Err(NpsError::Frame(format!(
                "unregistered frame type 0x{:02X}", header.frame_type.as_u8()
            )));
        }
        Ok((header.frame_type, dict))
    }

    pub fn peek_header(wire: &[u8]) -> NpsResult<FrameHeader> {
        FrameHeader::parse(wire)
    }
}
