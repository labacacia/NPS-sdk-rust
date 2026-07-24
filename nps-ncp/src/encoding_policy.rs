// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Encoding policy negotiated for an established NCP native-mode session.
//!
//! Port of the .NET `NcpEncodingPolicy` record. The default tier is stable for
//! ordinary frames; Tier-3 BinaryVector is an optional extension for frame
//! classes that explicitly bind to it (currently `QueryFrame`).

use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::{EncodingTier, FrameHeader, FrameType};

/// Wire token for Tier-3 BinaryVector.
pub const BINARY_VECTOR_TOKEN: &str = "binary_vector.v1";

/// Negotiated encoding policy for a live NCP session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcpEncodingPolicy {
    /// Stable default encoding tier used for ordinary session frames.
    pub default_tier: EncodingTier,
    /// Whether Tier-3 BinaryVector is enabled as an optional extension.
    pub binary_vector_enabled: bool,
}

impl NcpEncodingPolicy {
    /// Creates a policy with the given default tier and no BinaryVector extension.
    pub fn new(default_tier: EncodingTier) -> Self {
        Self {
            default_tier,
            binary_vector_enabled: false,
        }
    }

    /// Creates a policy with an explicit BinaryVector extension flag.
    pub fn with_binary_vector(default_tier: EncodingTier, binary_vector_enabled: bool) -> Self {
        Self {
            default_tier,
            binary_vector_enabled,
        }
    }

    /// The full list of enabled encoding tokens, matching .NET
    /// `NcpEncodingPolicy.EnabledEncodings`.
    pub fn enabled_encodings(&self) -> Vec<String> {
        if self.binary_vector_enabled {
            vec![
                Self::encoding_token(self.default_tier).to_string(),
                BINARY_VECTOR_TOKEN.to_string(),
            ]
        } else {
            vec![Self::encoding_token(self.default_tier).to_string()]
        }
    }

    /// Returns `true` if `tier` is allowed for `frame_type` under this policy.
    pub fn allows(&self, tier: EncodingTier, frame_type: FrameType) -> bool {
        tier == self.default_tier
            || (tier == EncodingTier::BinaryVector
                && self.binary_vector_enabled
                && Self::is_binary_vector_frame(frame_type))
    }

    /// Validates that a frame header conforms to this policy, returning
    /// `Err(NpsError::Codec(..))` otherwise (mirrors .NET
    /// `NpsEncodingUnsupportedException`).
    pub fn ensure_allows(&self, header: &FrameHeader) -> NpsResult<()> {
        if self.allows(header.encoding_tier(), header.frame_type) {
            return Ok(());
        }
        Err(NpsError::Codec(format!(
            "Frame type 0x{:02X} used {}, but the negotiated session policy allows {}.",
            header.frame_type.as_u8(),
            Self::encoding_token(header.encoding_tier()),
            self.enabled_encodings().join(", ")
        )))
    }

    /// Builds a policy from a default tier and the enabled-encodings list
    /// advertised by the peer's CapsFrame (mirrors .NET
    /// `NcpEncodingPolicy.FromEnabledEncodings`).
    pub fn from_enabled_encodings(
        default_tier: EncodingTier,
        enabled_encodings: Option<&[String]>,
    ) -> Self {
        let binary_vector_enabled = enabled_encodings
            .map(|e| e.iter().any(|enc| enc == BINARY_VECTOR_TOKEN))
            .unwrap_or(false);
        Self {
            default_tier,
            binary_vector_enabled,
        }
    }

    /// Maps an encoding tier to its wire token (mirrors .NET
    /// `NcpEncodingPolicy.EncodingToken`).
    pub fn encoding_token(tier: EncodingTier) -> String {
        match tier {
            EncodingTier::Json => "json".to_string(),
            EncodingTier::MsgPack => "msgpack".to_string(),
            EncodingTier::BinaryVector => BINARY_VECTOR_TOKEN.to_string(),
            EncodingTier::Reserved => format!("unknown:{}", EncodingTier::Reserved as u8),
        }
    }

    fn is_binary_vector_frame(frame_type: FrameType) -> bool {
        frame_type == FrameType::Query
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_default_only() {
        let p = NcpEncodingPolicy::new(EncodingTier::Json);
        assert_eq!(p.enabled_encodings(), vec!["json"]);
        assert!(p.allows(EncodingTier::Json, FrameType::Caps));
        assert!(!p.allows(EncodingTier::MsgPack, FrameType::Caps));
        assert!(!p.allows(EncodingTier::BinaryVector, FrameType::Query));
    }

    #[test]
    fn binary_vector_only_for_query() {
        let p = NcpEncodingPolicy::with_binary_vector(EncodingTier::MsgPack, true);
        assert_eq!(p.enabled_encodings(), vec!["msgpack", "binary_vector.v1"]);
        // Allowed: default tier for any frame.
        assert!(p.allows(EncodingTier::MsgPack, FrameType::Caps));
        // Allowed: binary vector only for Query frames.
        assert!(p.allows(EncodingTier::BinaryVector, FrameType::Query));
        // Denied: binary vector for non-Query frames.
        assert!(!p.allows(EncodingTier::BinaryVector, FrameType::Caps));
        // Denied: a tier that is neither the default nor binary vector.
        assert!(!p.allows(EncodingTier::Json, FrameType::Caps));
    }

    #[test]
    fn from_enabled_encodings_detects_extension() {
        let list = vec!["msgpack".to_string(), "binary_vector.v1".to_string()];
        let p = NcpEncodingPolicy::from_enabled_encodings(EncodingTier::MsgPack, Some(&list));
        assert!(p.binary_vector_enabled);

        let list2 = vec!["json".to_string()];
        let p2 = NcpEncodingPolicy::from_enabled_encodings(EncodingTier::Json, Some(&list2));
        assert!(!p2.binary_vector_enabled);

        let p3 = NcpEncodingPolicy::from_enabled_encodings(EncodingTier::Json, None);
        assert!(!p3.binary_vector_enabled);
    }

    #[test]
    fn ensure_allows_errors_on_denied() {
        let p = NcpEncodingPolicy::new(EncodingTier::Json);
        let header = FrameHeader::new(FrameType::Caps, EncodingTier::MsgPack, true, 0);
        assert!(p.ensure_allows(&header).is_err());

        let ok = FrameHeader::new(FrameType::Caps, EncodingTier::Json, true, 0);
        assert!(p.ensure_allows(&ok).is_ok());
    }

    #[test]
    fn encoding_tokens() {
        assert_eq!(NcpEncodingPolicy::encoding_token(EncodingTier::Json), "json");
        assert_eq!(
            NcpEncodingPolicy::encoding_token(EncodingTier::MsgPack),
            "msgpack"
        );
        assert_eq!(
            NcpEncodingPolicy::encoding_token(EncodingTier::BinaryVector),
            "binary_vector.v1"
        );
    }
}
