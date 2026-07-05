// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use crate::error::{NpsError, NpsResult};
use crate::frames::{EncodingTier, FrameHeader, FrameType};
use crate::registry::FrameRegistry;
use serde_json::{Number, Value};

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
    let v: Value = serde_json::from_slice(payload).map_err(|e| NpsError::Codec(e.to_string()))?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(NpsError::Codec("expected JSON object".into())),
    }
}

pub fn decode_msgpack(payload: &[u8]) -> NpsResult<FrameDict> {
    let v: Value = rmp_serde::from_slice(payload).map_err(|e| NpsError::Codec(e.to_string()))?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(NpsError::Codec("expected MsgPack map".into())),
    }
}

// ── Tier-3 BinaryVector helpers ───────────────────────────────────────────────

const BINARY_VECTOR_MAGIC: &[u8; 4] = b"NPBV";
const BINARY_VECTOR_VERSION: u8 = 1;
const BINARY_VECTOR_PREFIX: usize = 16;
const BINARY_VECTOR_MARKER: &str = "$nps_binary_vector";

pub fn encode_binary_vector(dict: &FrameDict) -> NpsResult<Vec<u8>> {
    let mut metadata = dict.clone();
    let mut vectors: Vec<Vec<f32>> = Vec::new();
    extract_vector_search_vector(&mut metadata, &mut vectors);
    if vectors.len() > u16::MAX as usize {
        return Err(NpsError::Codec(
            "binary vector supports at most 65535 vectors per frame".into(),
        ));
    }

    let metadata_value = Value::Object(metadata);
    let metadata_bytes =
        rmp_serde::to_vec_named(&metadata_value).map_err(|e| NpsError::Codec(e.to_string()))?;

    let segment_bytes: usize = vectors.iter().map(|vector| 4 + vector.len() * 4).sum();
    let mut payload = vec![0u8; BINARY_VECTOR_PREFIX + metadata_bytes.len() + segment_bytes];
    payload[0..4].copy_from_slice(BINARY_VECTOR_MAGIC);
    payload[4] = BINARY_VECTOR_VERSION;
    payload[5] = 0;
    payload[6..8].copy_from_slice(&(vectors.len() as u16).to_be_bytes());
    payload[8..12].copy_from_slice(&(metadata_bytes.len() as u32).to_be_bytes());
    payload[12..16].copy_from_slice(&0u32.to_be_bytes());
    payload[BINARY_VECTOR_PREFIX..BINARY_VECTOR_PREFIX + metadata_bytes.len()]
        .copy_from_slice(&metadata_bytes);

    let mut offset = BINARY_VECTOR_PREFIX + metadata_bytes.len();
    for vector in vectors {
        payload[offset..offset + 4].copy_from_slice(&(vector.len() as u32).to_be_bytes());
        offset += 4;
        for value in vector {
            payload[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            offset += 4;
        }
    }

    Ok(payload)
}

pub fn decode_binary_vector(payload: &[u8]) -> NpsResult<FrameDict> {
    if payload.len() < BINARY_VECTOR_PREFIX {
        return Err(NpsError::Codec(format!(
            "binary vector payload too short: {} bytes",
            payload.len()
        )));
    }
    if &payload[0..4] != BINARY_VECTOR_MAGIC {
        return Err(NpsError::Codec(
            "binary vector payload magic mismatch".into(),
        ));
    }
    if payload[4] != BINARY_VECTOR_VERSION {
        return Err(NpsError::Codec(format!(
            "unsupported binary vector version: {}",
            payload[4]
        )));
    }
    if payload[5] != 0 || u32::from_be_bytes(payload[12..16].try_into().unwrap()) != 0 {
        return Err(NpsError::Codec(
            "binary vector reserved fields must be zero".into(),
        ));
    }

    let vector_count = u16::from_be_bytes(payload[6..8].try_into().unwrap()) as usize;
    let metadata_len = u32::from_be_bytes(payload[8..12].try_into().unwrap()) as usize;
    if metadata_len > payload.len() - BINARY_VECTOR_PREFIX {
        return Err(NpsError::Codec(
            "binary vector metadata length exceeds payload length".into(),
        ));
    }

    let mut offset = BINARY_VECTOR_PREFIX;
    let metadata: Value = rmp_serde::from_slice(&payload[offset..offset + metadata_len])
        .map_err(|e| NpsError::Codec(e.to_string()))?;
    offset += metadata_len;
    let mut metadata = match metadata {
        Value::Object(map) => map,
        _ => {
            return Err(NpsError::Codec(
                "binary vector metadata root must be a map".into(),
            ))
        }
    };

    let mut vectors: Vec<Vec<f32>> = Vec::with_capacity(vector_count);
    for _ in 0..vector_count {
        if payload.len() - offset < 4 {
            return Err(NpsError::Codec(
                "binary vector segment missing dimension".into(),
            ));
        }
        let dim = u32::from_be_bytes(payload[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        let byte_len = dim * 4;
        if payload.len() - offset < byte_len {
            return Err(NpsError::Codec("binary vector segment is truncated".into()));
        }

        let mut vector = Vec::with_capacity(dim);
        for _ in 0..dim {
            vector.push(f32::from_le_bytes(
                payload[offset..offset + 4].try_into().unwrap(),
            ));
            offset += 4;
        }
        vectors.push(vector);
    }

    if offset != payload.len() {
        return Err(NpsError::Codec(
            "binary vector payload has trailing bytes".into(),
        ));
    }

    restore_vector_search_vector(&mut metadata, &vectors)?;
    Ok(metadata)
}

fn extract_vector_search_vector(metadata: &mut FrameDict, vectors: &mut Vec<Vec<f32>>) {
    let Some(Value::Object(vector_search)) = metadata.get_mut("vector_search") else {
        return;
    };
    let Some(Value::Array(values)) = vector_search.get("vector") else {
        return;
    };

    let mut vector = Vec::with_capacity(values.len());
    for value in values {
        let Some(number) = value.as_f64() else {
            return;
        };
        if !number.is_finite() {
            return;
        }
        vector.push(number as f32);
    }

    let index = vectors.len();
    vectors.push(vector.clone());
    let mut marker = FrameDict::new();
    marker.insert(
        BINARY_VECTOR_MARKER.into(),
        Value::Number(Number::from(index as u64)),
    );
    marker.insert("dtype".into(), Value::String("float32".into()));
    marker.insert(
        "dim".into(),
        Value::Number(Number::from(vector.len() as u64)),
    );
    vector_search.insert("vector".into(), Value::Object(marker));
}

fn restore_vector_search_vector(metadata: &mut FrameDict, vectors: &[Vec<f32>]) -> NpsResult<()> {
    let Some(Value::Object(vector_search)) = metadata.get_mut("vector_search") else {
        return Ok(());
    };
    let Some(marker_value) = vector_search.get("vector") else {
        return Ok(());
    };
    let Value::Object(marker) = marker_value else {
        return Err(NpsError::Codec(
            "binary vector marker must be an object".into(),
        ));
    };

    let index = marker
        .get(BINARY_VECTOR_MARKER)
        .and_then(Value::as_u64)
        .ok_or_else(|| NpsError::Codec("binary vector marker missing vector index".into()))?
        as usize;
    if index >= vectors.len() {
        return Err(NpsError::Codec(format!(
            "binary vector marker references vector {index}, but only {} vectors are present",
            vectors.len()
        )));
    }
    if marker.get("dtype").and_then(Value::as_str) != Some("float32") {
        return Err(NpsError::Codec(
            "binary vector v1 only supports dtype=float32".into(),
        ));
    }
    let dim = marker.get("dim").and_then(Value::as_u64).ok_or_else(|| {
        NpsError::Codec("binary vector marker dimension does not match vector segment".into())
    })? as usize;
    if dim != vectors[index].len() {
        return Err(NpsError::Codec(
            "binary vector marker dimension does not match vector segment".into(),
        ));
    }

    let vector = vectors[index]
        .iter()
        .map(|value| {
            Number::from_f64(*value as f64)
                .map(Value::Number)
                .ok_or_else(|| {
                    NpsError::Codec("binary vector values must be finite float32".into())
                })
        })
        .collect::<NpsResult<Vec<_>>>()?;
    vector_search.insert("vector".into(), Value::Array(vector));
    Ok(())
}

// ── NpsFrameCodec ──────────────────────────────────────────────────────────────

pub const DEFAULT_MAX_PAYLOAD: u64 = 10 * 1024 * 1024; // 10 MiB

pub struct NpsFrameCodec {
    registry: FrameRegistry,
    max_payload: u64,
}

impl NpsFrameCodec {
    pub fn new(registry: FrameRegistry) -> Self {
        NpsFrameCodec {
            registry,
            max_payload: DEFAULT_MAX_PAYLOAD,
        }
    }

    pub fn with_max_payload(mut self, max_payload: u64) -> Self {
        self.max_payload = max_payload;
        self
    }

    pub fn encode(
        &self,
        frame_type: FrameType,
        dict: &FrameDict,
        tier: EncodingTier,
        is_final: bool,
    ) -> NpsResult<Vec<u8>> {
        let payload = match tier {
            EncodingTier::Json => encode_json(dict)?,
            EncodingTier::MsgPack => encode_msgpack(dict)?,
            EncodingTier::BinaryVector => encode_binary_vector(dict)?,
            EncodingTier::Reserved => {
                return Err(NpsError::Codec("reserved encoding tier 0x03".into()));
            }
        };
        if payload.len() as u64 > self.max_payload {
            return Err(NpsError::Codec(format!(
                "payload {} exceeds max {}",
                payload.len(),
                self.max_payload
            )));
        }
        let header = FrameHeader::new(frame_type, tier, is_final, payload.len() as u64);
        let mut wire = header.to_bytes();
        wire.extend_from_slice(&payload);
        Ok(wire)
    }

    pub fn decode(&self, wire: &[u8]) -> NpsResult<(FrameType, FrameDict)> {
        let header = FrameHeader::parse(wire)?;
        let hdr_len = header.header_size();
        let plen = header.payload_length as usize;
        if wire.len() < hdr_len + plen {
            return Err(NpsError::Codec(
                "wire too short for declared payload".into(),
            ));
        }
        let payload = &wire[hdr_len..hdr_len + plen];
        let dict = match header.encoding_tier() {
            EncodingTier::Json => decode_json(payload)?,
            EncodingTier::MsgPack => decode_msgpack(payload)?,
            EncodingTier::BinaryVector => decode_binary_vector(payload)?,
            EncodingTier::Reserved => {
                return Err(NpsError::Codec("reserved encoding tier 0x03".into()));
            }
        };
        // validate that the frame type is registered
        if !self.registry.is_registered(header.frame_type) {
            return Err(NpsError::Frame(format!(
                "unregistered frame type 0x{:02X}",
                header.frame_type.as_u8()
            )));
        }
        Ok((header.frame_type, dict))
    }

    pub fn peek_header(wire: &[u8]) -> NpsResult<FrameHeader> {
        FrameHeader::parse(wire)
    }
}
