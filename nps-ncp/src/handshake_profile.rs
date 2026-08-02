// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NCP v0.11 portable native-server admission and negotiation policy.

use std::collections::HashSet;
use std::time::Duration;

use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use nps_core::status_codes;

use crate::{error_codes, preamble, HelloFrame};

/// Server capabilities used for deterministic native NCP negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcpHandshakeProfile {
    pub min_version: String,
    pub nps_version: String,
    pub supported_encodings: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub max_frame_payload: u64,
    pub ext_support: bool,
    pub max_concurrent_streams: u64,
}

impl Default for NcpHandshakeProfile {
    fn default() -> Self {
        Self {
            min_version: "0.1".into(),
            nps_version: "0.11".into(),
            supported_encodings: vec!["msgpack".into(), "json".into(), "binary_vector.v1".into()],
            supported_protocols: vec![
                "ncp".into(),
                "nwp".into(),
                "nip".into(),
                "ndp".into(),
                "nop".into(),
            ],
            max_frame_payload: 0xFFFF,
            ext_support: false,
            max_concurrent_streams: 32,
        }
    }
}

/// Observable outcome of one native-mode handshake stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NcpHandshakeAction {
    Continue,
    Accept,
    SilentClose,
    ErrorClose,
}

/// Portable handshake decision shared by admission checks and negotiation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NcpHandshakeDecision {
    pub action: NcpHandshakeAction,
    pub status: Option<&'static str>,
    pub error: Option<&'static str>,
    pub diagnostic_error: Option<&'static str>,
    pub session_version: Option<String>,
    pub negotiated_encoding: Option<String>,
    pub enabled_encodings: Option<Vec<String>>,
    pub supported_protocols: Option<Vec<String>>,
    pub max_frame_payload: Option<u64>,
    pub ext_support: Option<bool>,
    pub max_concurrent_streams: Option<u64>,
}

impl NcpHandshakeDecision {
    fn with_action(action: NcpHandshakeAction) -> Self {
        Self {
            action,
            status: None,
            error: None,
            diagnostic_error: None,
            session_version: None,
            negotiated_encoding: None,
            enabled_encodings: None,
            supported_protocols: None,
            max_frame_payload: None,
            ext_support: None,
            max_concurrent_streams: None,
        }
    }

    fn version_error() -> Self {
        Self {
            status: Some(status_codes::NPS_PROTO_VERSION_INCOMPATIBLE),
            error: Some(error_codes::VERSION_INCOMPATIBLE),
            ..Self::with_action(NcpHandshakeAction::ErrorClose)
        }
    }
}

/// Evaluate the preamble stage without performing I/O.
pub fn evaluate_preamble(
    received: &[u8],
    elapsed: Duration,
    timeout: Duration,
) -> NcpHandshakeDecision {
    if !timeout.is_zero() && elapsed >= timeout {
        return NcpHandshakeDecision::with_action(NcpHandshakeAction::SilentClose);
    }
    if received.len() < preamble::LENGTH {
        return NcpHandshakeDecision::with_action(NcpHandshakeAction::Continue);
    }
    if &received[..preamble::LENGTH] != preamble::BYTES {
        return NcpHandshakeDecision {
            diagnostic_error: Some(error_codes::PREAMBLE_INVALID),
            ..NcpHandshakeDecision::with_action(NcpHandshakeAction::SilentClose)
        };
    }
    NcpHandshakeDecision::with_action(NcpHandshakeAction::Continue)
}

/// Evaluate a Hello header before allocating its payload.
pub fn evaluate_hello_header(
    header: &FrameHeader,
    elapsed: Duration,
    timeout: Duration,
    max_hello_payload: u64,
) -> NcpHandshakeDecision {
    if !timeout.is_zero() && elapsed >= timeout {
        return NcpHandshakeDecision::with_action(NcpHandshakeAction::SilentClose);
    }
    if header.frame_type != FrameType::Hello
        || header.encoding_tier() != EncodingTier::Json
        || header.flags & 0x08 != 0
        || header.is_extended
        || header.payload_length > max_hello_payload
    {
        return NcpHandshakeDecision::with_action(NcpHandshakeAction::SilentClose);
    }
    NcpHandshakeDecision::with_action(NcpHandshakeAction::Continue)
}

/// Negotiate a decoded Hello against the server profile.
pub fn negotiate_handshake(
    server: &NcpHandshakeProfile,
    client: &HelloFrame,
) -> NcpHandshakeDecision {
    let Some(server_min) = parse_version(&server.min_version) else {
        return NcpHandshakeDecision::version_error();
    };
    let Some(server_max) = parse_version(&server.nps_version) else {
        return NcpHandshakeDecision::version_error();
    };
    let client_min_token = client.min_version.as_deref().unwrap_or(&client.nps_version);
    let Some(client_min) = parse_version(client_min_token) else {
        return NcpHandshakeDecision::version_error();
    };
    let Some(client_max) = parse_version(&client.nps_version) else {
        return NcpHandshakeDecision::version_error();
    };
    if server_min > server_max || client_min > client_max {
        return NcpHandshakeDecision::version_error();
    }
    let overlap_min = server_min.max(client_min);
    let overlap_max = server_max.min(client_max);
    if overlap_min > overlap_max {
        return NcpHandshakeDecision::version_error();
    }

    let server_encodings: HashSet<&str> = server
        .supported_encodings
        .iter()
        .map(String::as_str)
        .collect();
    let stable = client
        .supported_encodings
        .iter()
        .find(|token| {
            matches!(token.as_str(), "msgpack" | "json")
                && server_encodings.contains(token.as_str())
        })
        .cloned();
    let Some(stable) = stable else {
        return NcpHandshakeDecision {
            status: Some(status_codes::NPS_SERVER_ENCODING_UNSUPPORTED),
            error: Some(error_codes::ENCODING_UNSUPPORTED),
            ..NcpHandshakeDecision::with_action(NcpHandshakeAction::ErrorClose)
        };
    };

    let server_protocols: HashSet<&str> = server
        .supported_protocols
        .iter()
        .map(String::as_str)
        .collect();
    let mut seen = HashSet::new();
    let protocols: Vec<String> = client
        .supported_protocols
        .iter()
        .filter(|token| server_protocols.contains(token.as_str()))
        .filter(|token| seen.insert(token.as_str()))
        .cloned()
        .collect();
    if !protocols.iter().any(|token| token == "ncp")
        || client.max_frame_payload == 0
        || server.max_frame_payload == 0
        || client.max_concurrent_streams == 0
        || server.max_concurrent_streams == 0
    {
        return NcpHandshakeDecision::version_error();
    }

    let mut enabled = vec![stable.clone()];
    if server_encodings.contains("binary_vector.v1")
        && client
            .supported_encodings
            .iter()
            .any(|token| token == "binary_vector.v1")
    {
        enabled.push("binary_vector.v1".into());
    }

    NcpHandshakeDecision {
        action: NcpHandshakeAction::Accept,
        status: None,
        error: None,
        diagnostic_error: None,
        session_version: Some(format!("{}.{}", overlap_max.0, overlap_max.1)),
        negotiated_encoding: Some(stable),
        enabled_encodings: Some(enabled),
        supported_protocols: Some(protocols),
        max_frame_payload: Some(server.max_frame_payload.min(client.max_frame_payload)),
        ext_support: Some(server.ext_support && client.ext_support),
        max_concurrent_streams: Some(
            server
                .max_concurrent_streams
                .min(client.max_concurrent_streams),
        ),
    }
}

fn parse_version(value: &str) -> Option<(u64, u64)> {
    let mut parts = value.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor))
}
