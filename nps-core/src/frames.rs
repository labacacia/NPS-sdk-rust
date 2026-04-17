// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use crate::error::{NpsError, NpsResult};

// ── FrameType ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameType {
    Anchor        = 0x01,
    Diff          = 0x02,
    Stream        = 0x03,
    Caps          = 0x04,
    Query         = 0x10,
    Action        = 0x11,
    Ident         = 0x20,
    Trust         = 0x21,
    Revoke        = 0x22,
    Announce      = 0x30,
    Resolve       = 0x31,
    Graph         = 0x32,
    Task          = 0x40,
    Delegate      = 0x41,
    Sync          = 0x42,
    AlignStream   = 0x43,
    Error         = 0xFE,
}

impl FrameType {
    pub fn from_u8(v: u8) -> NpsResult<Self> {
        match v {
            0x01 => Ok(FrameType::Anchor),
            0x02 => Ok(FrameType::Diff),
            0x03 => Ok(FrameType::Stream),
            0x04 => Ok(FrameType::Caps),
            0x10 => Ok(FrameType::Query),
            0x11 => Ok(FrameType::Action),
            0x20 => Ok(FrameType::Ident),
            0x21 => Ok(FrameType::Trust),
            0x22 => Ok(FrameType::Revoke),
            0x30 => Ok(FrameType::Announce),
            0x31 => Ok(FrameType::Resolve),
            0x32 => Ok(FrameType::Graph),
            0x40 => Ok(FrameType::Task),
            0x41 => Ok(FrameType::Delegate),
            0x42 => Ok(FrameType::Sync),
            0x43 => Ok(FrameType::AlignStream),
            0xFE => Ok(FrameType::Error),
            _    => Err(NpsError::Frame(format!("unknown frame type: 0x{v:02X}"))),
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

// ── EncodingTier ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingTier {
    Json    = 0,
    MsgPack = 1,
}

// ── FrameHeader ───────────────────────────────────────────────────────────────

/// Wire-format frame header.
///
/// Default (EXT=0): 4 bytes — `[frame_type, flags, len_hi, len_lo]`
/// Extended (EXT=1): 8 bytes — `[frame_type, flags, 0, 0, len_b3, len_b2, len_b1, len_b0]`
///
/// Flags byte:
///   bit 7 (0x80) — TIER: 0 = JSON, 1 = MsgPack
///   bit 6 (0x40) — FINAL: 1 = last frame in stream
///   bit 0 (0x01) — EXT: 1 = 8-byte extended header
#[derive(Debug, Clone)]
pub struct FrameHeader {
    pub frame_type:     FrameType,
    pub flags:          u8,
    pub payload_length: u64,
    pub is_extended:    bool,
}

impl FrameHeader {
    pub fn new(frame_type: FrameType, tier: EncodingTier, is_final: bool, payload_length: u64) -> Self {
        let is_extended = payload_length > 0xFFFF;
        let mut flags: u8 = 0;
        if tier == EncodingTier::MsgPack { flags |= 0x80; }
        if is_final                      { flags |= 0x40; }
        if is_extended                   { flags |= 0x01; }
        FrameHeader { frame_type, flags, payload_length, is_extended }
    }

    pub fn encoding_tier(&self) -> EncodingTier {
        if self.flags & 0x80 != 0 { EncodingTier::MsgPack } else { EncodingTier::Json }
    }

    pub fn is_final(&self) -> bool {
        self.flags & 0x40 != 0
    }

    pub fn header_size(&self) -> usize {
        if self.is_extended { 8 } else { 4 }
    }

    pub fn parse(wire: &[u8]) -> NpsResult<Self> {
        if wire.len() < 4 {
            return Err(NpsError::Frame("buffer too small for header".into()));
        }
        let frame_type = FrameType::from_u8(wire[0])?;
        let flags      = wire[1];
        let is_ext     = flags & 0x01 != 0;

        if is_ext {
            if wire.len() < 8 {
                return Err(NpsError::Frame("buffer too small for extended header".into()));
            }
            let payload_length = u32::from_be_bytes([wire[4], wire[5], wire[6], wire[7]]) as u64;
            Ok(FrameHeader { frame_type, flags, payload_length, is_extended: true })
        } else {
            let payload_length = u16::from_be_bytes([wire[2], wire[3]]) as u64;
            Ok(FrameHeader { frame_type, flags, payload_length, is_extended: false })
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        if self.is_extended {
            let len = self.payload_length as u32;
            let b   = len.to_be_bytes();
            vec![self.frame_type.as_u8(), self.flags, 0, 0, b[0], b[1], b[2], b[3]]
        } else {
            let len = self.payload_length as u16;
            let b   = len.to_be_bytes();
            vec![self.frame_type.as_u8(), self.flags, b[0], b[1]]
        }
    }
}
