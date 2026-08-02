// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

pub mod encoding_policy;
pub mod error_codes;
pub mod failover;
pub mod handshake_profile;
pub mod patch_format;
pub mod preamble;
pub mod transport;

pub use encoding_policy::NcpEncodingPolicy;
pub use handshake_profile::{
    evaluate_hello_header, evaluate_preamble, negotiate_handshake, NcpHandshakeAction,
    NcpHandshakeDecision, NcpHandshakeProfile,
};
pub use transport::{
    read_frame_header, ConnectError, NcpHandshakeError, NcpNativeClient, NcpServer,
    NcpServerConnection, NcpServerOptions, NcpSession, HANDSHAKE_UNEXPECTED_FRAME,
};

use nps_core::codec::FrameDict;
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::FrameType;
use serde_json::{json, Value};

fn get_str<'a>(d: &'a FrameDict, k: &str) -> NpsResult<&'a str> {
    d.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| NpsError::Frame(format!("missing field: {k}")))
}

fn opt_str<'a>(d: &'a FrameDict, k: &str) -> Option<&'a str> {
    d.get(k).and_then(Value::as_str)
}

fn opt_u64(d: &FrameDict, k: &str) -> Option<u64> {
    d.get(k).and_then(Value::as_u64)
}

// ── AnchorFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AnchorFrame {
    pub anchor_id: String,
    pub schema: serde_json::Map<String, Value>,
    pub namespace: Option<String>,
    pub description: Option<String>,
    pub node_type: Option<String>,
    pub ttl: u64,
}

impl AnchorFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Anchor
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(), json!(self.anchor_id));
        m.insert("schema".into(), Value::Object(self.schema.clone()));
        m.insert("ttl".into(), json!(self.ttl));
        if let Some(v) = &self.namespace {
            m.insert("namespace".into(), json!(v));
        }
        if let Some(v) = &self.description {
            m.insert("description".into(), json!(v));
        }
        if let Some(v) = &self.node_type {
            m.insert("node_type".into(), json!(v));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id = get_str(d, "anchor_id")?.to_string();
        let schema = d
            .get("schema")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let ttl = opt_u64(d, "ttl").unwrap_or(3600);
        Ok(AnchorFrame {
            anchor_id,
            schema,
            namespace: opt_str(d, "namespace").map(str::to_string),
            description: opt_str(d, "description").map(str::to_string),
            node_type: opt_str(d, "node_type").map(str::to_string),
            ttl,
        })
    }
}

// ── DiffFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DiffFrame {
    pub anchor_id: String,
    pub new_anchor_id: String,
    pub patch: Vec<Value>,
}

impl DiffFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Diff
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(), json!(self.anchor_id));
        m.insert("new_anchor_id".into(), json!(self.new_anchor_id));
        m.insert("patch".into(), Value::Array(self.patch.clone()));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id = get_str(d, "anchor_id")?.to_string();
        let new_anchor_id = get_str(d, "new_anchor_id")?.to_string();
        let patch = d
            .get("patch")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(DiffFrame {
            anchor_id,
            new_anchor_id,
            patch,
        })
    }
}

// ── StreamFrame ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StreamFrame {
    pub anchor_id: String,
    pub seq: u64,
    pub payload: Value,
    pub is_last: bool,
}

impl StreamFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Stream
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("anchor_id".into(), json!(self.anchor_id));
        m.insert("seq".into(), json!(self.seq));
        m.insert("payload".into(), self.payload.clone());
        m.insert("is_last".into(), json!(self.is_last));
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let anchor_id = get_str(d, "anchor_id")?.to_string();
        let seq = opt_u64(d, "seq").unwrap_or(0);
        let payload = d.get("payload").cloned().unwrap_or(Value::Null);
        let is_last = d.get("is_last").and_then(Value::as_bool).unwrap_or(false);
        Ok(StreamFrame {
            anchor_id,
            seq,
            payload,
            is_last,
        })
    }
}

// ── CapsFrame ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CapsFrame {
    pub node_id: Option<String>,
    pub caps: Vec<String>,
    pub anchor_ref: Option<String>,
    pub count: Option<u64>,
    pub data: Vec<Value>,
    pub next_cursor: Option<String>,
    pub token_est: Option<u64>,
    pub cached: Option<bool>,
    pub tokenizer_used: Option<String>,
    pub payload: Option<Value>,
    /// Handshake — stable default encoding selected for ordinary session frames.
    /// Mirrors .NET `NcpHandshakeCapsFrame.NegotiatedEncoding`.
    pub negotiated_encoding: Option<String>,
    /// Handshake — all encodings enabled by the negotiated policy, including
    /// optional extensions. Mirrors .NET `NcpHandshakeCapsFrame.EnabledEncodings`.
    pub enabled_encodings: Option<Vec<String>>,
    /// Protocol version selected from the client/server version overlap.
    pub session_version: Option<String>,
    /// Protocol tokens enabled for the session, in client preference order.
    pub supported_protocols: Option<Vec<String>>,
    /// Negotiated ordinary frame payload ceiling.
    pub max_frame_payload: Option<u64>,
    /// Whether both peers support extended frame headers.
    pub ext_support: Option<bool>,
    /// Negotiated concurrent stream ceiling.
    pub max_concurrent_streams: Option<u64>,
}

impl CapsFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Caps
    }

    pub fn new(anchor_ref: impl Into<String>, data: Vec<Value>) -> Self {
        CapsFrame {
            node_id: None,
            caps: Vec::new(),
            anchor_ref: Some(anchor_ref.into()),
            count: Some(data.len() as u64),
            data,
            next_cursor: None,
            token_est: None,
            cached: None,
            tokenizer_used: None,
            payload: None,
            negotiated_encoding: None,
            enabled_encodings: None,
            session_version: None,
            supported_protocols: None,
            max_frame_payload: None,
            ext_support: None,
            max_concurrent_streams: None,
        }
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        if let Some(v) = &self.node_id {
            m.insert("node_id".into(), json!(v));
        }
        if !self.caps.is_empty() {
            m.insert("caps".into(), json!(self.caps));
        }
        if let Some(v) = &self.anchor_ref {
            m.insert("anchor_ref".into(), json!(v));
        }
        if self.count.is_some() || !self.data.is_empty() {
            m.insert(
                "count".into(),
                json!(self.count.unwrap_or(self.data.len() as u64)),
            );
            m.insert("data".into(), Value::Array(self.data.clone()));
        }
        if let Some(v) = &self.next_cursor {
            m.insert("next_cursor".into(), json!(v));
        }
        if let Some(v) = self.token_est {
            m.insert("token_est".into(), json!(v));
        }
        if let Some(v) = self.cached {
            m.insert("cached".into(), json!(v));
        }
        if let Some(v) = &self.tokenizer_used {
            m.insert("tokenizer_used".into(), json!(v));
        }
        if let Some(v) = &self.payload {
            m.insert("payload".into(), v.clone());
        }
        if let Some(v) = &self.negotiated_encoding {
            m.insert("negotiated_encoding".into(), json!(v));
        }
        if let Some(v) = &self.enabled_encodings {
            m.insert("enabled_encodings".into(), json!(v));
        }
        if let Some(v) = &self.session_version {
            m.insert("session_version".into(), json!(v));
        }
        if let Some(v) = &self.supported_protocols {
            m.insert("supported_protocols".into(), json!(v));
        }
        if let Some(v) = self.max_frame_payload {
            m.insert("max_frame_payload".into(), json!(v));
        }
        if let Some(v) = self.ext_support {
            m.insert("ext_support".into(), json!(v));
        }
        if let Some(v) = self.max_concurrent_streams {
            m.insert("max_concurrent_streams".into(), json!(v));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let node_id = opt_str(d, "node_id").map(str::to_string);
        let caps = d
            .get("caps")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(CapsFrame {
            node_id,
            caps,
            anchor_ref: opt_str(d, "anchor_ref").map(str::to_string),
            count: opt_u64(d, "count"),
            data: d
                .get("data")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            next_cursor: opt_str(d, "next_cursor").map(str::to_string),
            token_est: opt_u64(d, "token_est"),
            cached: d.get("cached").and_then(Value::as_bool),
            tokenizer_used: opt_str(d, "tokenizer_used").map(str::to_string),
            payload: d.get("payload").cloned(),
            negotiated_encoding: opt_str(d, "negotiated_encoding").map(str::to_string),
            enabled_encodings: d
                .get("enabled_encodings")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                }),
            session_version: opt_str(d, "session_version").map(str::to_string),
            supported_protocols: d
                .get("supported_protocols")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_string)
                        .collect()
                }),
            max_frame_payload: opt_u64(d, "max_frame_payload"),
            ext_support: d.get("ext_support").and_then(Value::as_bool),
            max_concurrent_streams: opt_u64(d, "max_concurrent_streams"),
        })
    }
}

// ── HelloFrame ────────────────────────────────────────────────────────────────

/// Native-mode client handshake frame (NPS-1 §4.6).
///
/// The Agent MUST send this as the very first frame after opening a TCP/QUIC
/// connection; the Node replies with a CapsFrame. Not used in HTTP mode.
///
/// Preferred encoding is Tier-1 JSON because the encoding has not yet been
/// negotiated at handshake time.
#[derive(Debug, Clone)]
pub struct HelloFrame {
    pub nps_version: String,
    pub supported_encodings: Vec<String>,
    pub supported_protocols: Vec<String>,
    pub min_version: Option<String>,
    pub agent_id: Option<String>,
    pub max_frame_payload: u64,
    pub ext_support: bool,
    pub max_concurrent_streams: u64,
    pub e2e_enc_algorithms: Option<Vec<String>>,
    /// NCP v0.8 — keepalive interval in ms; 0 means disabled.
    pub ping_interval_ms: u64,
}

impl HelloFrame {
    pub const DEFAULT_MAX_FRAME_PAYLOAD: u64 = 0xFFFF;
    pub const DEFAULT_MAX_CONCURRENT_STREAMS: u64 = 32;

    pub fn frame_type() -> FrameType {
        FrameType::Hello
    }

    pub fn new(
        nps_version: impl Into<String>,
        supported_encodings: Vec<String>,
        supported_protocols: Vec<String>,
    ) -> Self {
        HelloFrame {
            nps_version: nps_version.into(),
            supported_encodings,
            supported_protocols,
            min_version: None,
            agent_id: None,
            max_frame_payload: Self::DEFAULT_MAX_FRAME_PAYLOAD,
            ext_support: false,
            max_concurrent_streams: Self::DEFAULT_MAX_CONCURRENT_STREAMS,
            e2e_enc_algorithms: None,
            ping_interval_ms: 0,
        }
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("nps_version".into(), json!(self.nps_version));
        m.insert(
            "supported_encodings".into(),
            json!(self.supported_encodings),
        );
        m.insert(
            "supported_protocols".into(),
            json!(self.supported_protocols),
        );
        m.insert("max_frame_payload".into(), json!(self.max_frame_payload));
        m.insert("ext_support".into(), json!(self.ext_support));
        m.insert(
            "max_concurrent_streams".into(),
            json!(self.max_concurrent_streams),
        );
        if let Some(v) = &self.min_version {
            m.insert("min_version".into(), json!(v));
        }
        if let Some(v) = &self.agent_id {
            m.insert("agent_id".into(), json!(v));
        }
        if let Some(v) = &self.e2e_enc_algorithms {
            m.insert("e2e_enc_algorithms".into(), json!(v));
        }
        if self.ping_interval_ms > 0 {
            m.insert("ping_interval_ms".into(), json!(self.ping_interval_ms));
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        let nps_version = get_str(d, "nps_version")?.to_string();
        let supported_encodings = d
            .get("supported_encodings")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let supported_protocols = d
            .get("supported_protocols")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let e2e_enc_algorithms = d
            .get("e2e_enc_algorithms")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            });
        Ok(HelloFrame {
            nps_version,
            supported_encodings,
            supported_protocols,
            min_version: opt_str(d, "min_version").map(str::to_string),
            agent_id: opt_str(d, "agent_id").map(str::to_string),
            max_frame_payload: opt_u64(d, "max_frame_payload")
                .unwrap_or(Self::DEFAULT_MAX_FRAME_PAYLOAD),
            ext_support: d
                .get("ext_support")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            max_concurrent_streams: opt_u64(d, "max_concurrent_streams")
                .unwrap_or(Self::DEFAULT_MAX_CONCURRENT_STREAMS),
            e2e_enc_algorithms,
            ping_interval_ms: opt_u64(d, "ping_interval_ms").unwrap_or(0),
        })
    }
}

// ── NopFrame (0x07) ───────────────────────────────────────────────────────────

/// NCP v0.8 keepalive/heartbeat frame. No payload — either peer MAY send after handshake.
#[derive(Debug, Clone, Default)]
pub struct NopFrame;

impl NopFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Nop
    }

    pub fn to_dict(&self) -> FrameDict {
        serde_json::Map::new()
    }

    pub fn from_dict(_d: &FrameDict) -> NpsResult<Self> {
        Ok(NopFrame)
    }
}

// ── ErrorFrame ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ErrorFrame {
    pub error_code: String,
    pub message: String,
    pub detail: Option<Value>,
}

impl ErrorFrame {
    pub fn frame_type() -> FrameType {
        FrameType::Error
    }

    pub fn to_dict(&self) -> FrameDict {
        let mut m = serde_json::Map::new();
        m.insert("error_code".into(), json!(self.error_code));
        m.insert("message".into(), json!(self.message));
        if let Some(v) = &self.detail {
            m.insert("detail".into(), v.clone());
        }
        m
    }

    pub fn from_dict(d: &FrameDict) -> NpsResult<Self> {
        Ok(ErrorFrame {
            error_code: get_str(d, "error_code")?.to_string(),
            message: get_str(d, "message")?.to_string(),
            detail: d.get("detail").cloned(),
        })
    }
}
