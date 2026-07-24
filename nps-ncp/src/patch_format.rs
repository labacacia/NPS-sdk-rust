// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! `DiffFrame.patch_format` value constants (NPS-1 §4.2).
//!
//! Port of the .NET `NcpPatchFormat` static class.

/// Default format. `patch` is an RFC 6902 JSON Patch array.
/// Compatible with all encoding tiers.
pub const JSON_PATCH: &str = "json_patch";

/// Compact binary format. `binary_patch` contains a changed-fields bitset
/// followed by MsgPack-encoded new values.
/// MUST only be used in Tier-2 (MsgPack) frames.
pub const BINARY_BITSET: &str = "binary_bitset";

/// Returns `true` if `format` is a recognised patch-format token.
pub fn is_known(format: &str) -> bool {
    matches!(format, JSON_PATCH | BINARY_BITSET)
}

/// Returns `true` if `format` may be used with the given MsgPack availability.
/// `binary_bitset` requires Tier-2 (MsgPack); `json_patch` is universal.
pub fn allows_with_msgpack(format: &str, msgpack_available: bool) -> bool {
    match format {
        JSON_PATCH => true,
        BINARY_BITSET => msgpack_available,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_are_stable() {
        assert_eq!(JSON_PATCH, "json_patch");
        assert_eq!(BINARY_BITSET, "binary_bitset");
    }

    #[test]
    fn known_detection() {
        assert!(is_known(JSON_PATCH));
        assert!(is_known(BINARY_BITSET));
        assert!(!is_known("bogus"));
    }

    #[test]
    fn binary_bitset_requires_msgpack() {
        assert!(allows_with_msgpack(JSON_PATCH, false));
        assert!(allows_with_msgpack(JSON_PATCH, true));
        assert!(!allows_with_msgpack(BINARY_BITSET, false));
        assert!(allows_with_msgpack(BINARY_BITSET, true));
        assert!(!allows_with_msgpack("bogus", true));
    }
}
