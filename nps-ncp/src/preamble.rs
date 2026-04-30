// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NCP native-mode connection preamble — the 8-byte ASCII constant
//! `b"NPS/1.0\n"` that every native-mode client MUST emit immediately
//! after the transport handshake and before its first HelloFrame.
//! Defined by NPS-RFC-0001 and NPS-1 NCP §2.6.1.
//!
//! HTTP-mode connections do not use the preamble.

use nps_core::error::{NpsError, NpsResult};

pub const LITERAL: &str = "NPS/1.0\n";
pub const BYTES:   &[u8] = b"NPS/1.0\n";
pub const LENGTH:  usize = 8;

/// Validation timeout in seconds (NPS-RFC-0001 §4.1).
pub const READ_TIMEOUT_SECS: u64 = 10;
/// Maximum delay before closing on mismatch, in milliseconds.
pub const CLOSE_DEADLINE_MS: u64 = 500;

pub const ERROR_CODE:  &str = "NCP-PREAMBLE-INVALID";
pub const STATUS_CODE: &str = "NPS-PROTO-PREAMBLE-INVALID";

/// Returns `true` iff `buf` starts with the 8-byte NPS/1.0 preamble.
/// Safe to call with shorter buffers.
pub fn matches(buf: &[u8]) -> bool {
    buf.len() >= LENGTH && &buf[..LENGTH] == BYTES
}

/// Validates a presumed-preamble buffer.
/// Returns `Ok(())` on success or `Err(NpsError::Frame(...))` on failure.
pub fn validate(buf: &[u8]) -> NpsResult<()> {
    if buf.len() < LENGTH {
        return Err(NpsError::Frame(format!(
            "short read ({}/{} bytes); peer is not speaking NCP",
            buf.len(), LENGTH
        )));
    }
    if !matches(buf) {
        if buf.len() >= 4 && &buf[..4] == b"NPS/" {
            return Err(NpsError::Frame(
                "future-major-version NPS preamble; close with NPS-PREAMBLE-UNSUPPORTED-VERSION diagnostic".into(),
            ));
        }
        return Err(NpsError::Frame("preamble mismatch; peer is not speaking NPS/1.x".into()));
    }
    Ok(())
}

/// Writes the preamble bytes to `writer`.
pub fn write(writer: &mut impl std::io::Write) -> std::io::Result<()> {
    writer.write_all(BYTES)
}
