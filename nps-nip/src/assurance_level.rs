// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Agent identity assurance level per NPS-RFC-0003 §5.1.1.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssuranceLevel {
    pub wire: &'static str,
    pub rank: u8,
}

pub const ANONYMOUS: AssuranceLevel = AssuranceLevel { wire: "anonymous", rank: 0 };
pub const ATTESTED:  AssuranceLevel = AssuranceLevel { wire: "attested",  rank: 1 };
pub const VERIFIED:  AssuranceLevel = AssuranceLevel { wire: "verified",  rank: 2 };

impl AssuranceLevel {
    pub fn meets_or_exceeds(&self, required: &AssuranceLevel) -> bool {
        self.rank >= required.rank
    }

    /// Parse a wire string.  `""` → [`ANONYMOUS`] (backward compat per
    /// NPS-RFC-0003 §5.1.1).  Any other unrecognised non-empty value returns
    /// `Err` — callers MUST surface this as `NIP-ASSURANCE-UNKNOWN`.
    pub fn from_wire(wire: &str) -> Result<Self, String> {
        if wire.is_empty() { return Ok(ANONYMOUS); }
        for l in [ANONYMOUS, ATTESTED, VERIFIED] {
            if l.wire == wire { return Ok(l); }
        }
        Err(format!("unknown assurance_level: {wire:?}"))
    }

    pub fn from_rank(rank: u8) -> Result<Self, String> {
        for l in [ANONYMOUS, ATTESTED, VERIFIED] {
            if l.rank == rank { return Ok(l); }
        }
        Err(format!("unknown assurance_level rank: {rank}"))
    }
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire)
    }
}
