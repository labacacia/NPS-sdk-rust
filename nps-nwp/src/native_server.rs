// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use crate::frames::{ActionFrame, QueryFrame};
use nps_core::codec::{FrameDict, NpsFrameCodec};
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use nps_core::registry::FrameRegistry;
use nps_core::status_codes;
use nps_ncp::error_codes;
use nps_ncp::CapsFrame;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub type NativeQueryHandler = Arc<dyn Fn(QueryFrame) -> NpsResult<CapsFrame> + Send + Sync>;
pub type NativeActionHandler = Arc<dyn Fn(ActionFrame) -> NpsResult<Value> + Send + Sync>;

/// Native-mode NWP serving loop over an already established NCP stream.
///
/// TLS, preamble, and Hello negotiation stay owned by the caller or by a future
/// NCP session layer. This server only reads complete NPS frames, dispatches
/// QueryFrame/ActionFrame, and writes response frames.
pub struct NwpNativeNodeServer {
    codec: NpsFrameCodec,
    tier: EncodingTier,
    enabled_encodings: Vec<String>,
    anchor_ref: String,
    query_handler: Option<NativeQueryHandler>,
    action_handler: Option<NativeActionHandler>,
}

impl NwpNativeNodeServer {
    pub fn new() -> Self {
        Self {
            codec: NpsFrameCodec::new(FrameRegistry::create_full()),
            tier: EncodingTier::MsgPack,
            enabled_encodings: vec!["msgpack".to_string()],
            anchor_ref: "native:nwp".to_string(),
            query_handler: None,
            action_handler: None,
        }
    }

    pub fn with_tier(mut self, tier: EncodingTier) -> Self {
        self.tier = tier;
        self.enabled_encodings = vec![encoding_token(tier).to_string()];
        self
    }

    pub fn with_enabled_encodings<I, S>(mut self, enabled_encodings: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.enabled_encodings = enabled_encodings.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_anchor_ref(mut self, anchor_ref: impl Into<String>) -> Self {
        self.anchor_ref = anchor_ref.into();
        self
    }

    pub fn with_query_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(QueryFrame) -> NpsResult<CapsFrame> + Send + Sync + 'static,
    {
        self.query_handler = Some(Arc::new(handler));
        self
    }

    pub fn with_action_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(ActionFrame) -> NpsResult<Value> + Send + Sync + 'static,
    {
        self.action_handler = Some(Arc::new(handler));
        self
    }

    pub fn dispatch_wire(&self, wire: &[u8]) -> NpsResult<Vec<u8>> {
        let header = FrameHeader::parse(wire)?;
        if !encoding_allowed(&header, self.tier, &self.enabled_encodings) {
            return self.codec.encode(
                FrameType::Error,
                &error_dict(
                    status_codes::NPS_SERVER_ENCODING_UNSUPPORTED,
                    error_codes::ENCODING_UNSUPPORTED,
                    format!(
                        "Frame type 0x{:02X} used {}, but the negotiated policy allows {}.",
                        header.frame_type.as_u8(),
                        encoding_token(header.encoding_tier()),
                        self.enabled_encodings.join(", ")
                    ),
                ),
                self.tier,
                true,
            );
        }
        let (frame_type, dict) = self.codec.decode(wire)?;
        let (response_type, response_dict) = self.dispatch(frame_type, dict);
        self.codec
            .encode(response_type, &response_dict, self.tier, true)
    }

    pub async fn serve_stream<S>(&self, stream: &mut S) -> NpsResult<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        while let Some(wire) = read_wire_frame(stream).await? {
            let response = self.dispatch_wire(&wire)?;
            stream
                .write_all(&response)
                .await
                .map_err(|e| NpsError::Io(e.to_string()))?;
            stream
                .flush()
                .await
                .map_err(|e| NpsError::Io(e.to_string()))?;
        }
        Ok(())
    }

    fn dispatch(&self, frame_type: FrameType, dict: FrameDict) -> (FrameType, FrameDict) {
        let result = match frame_type {
            FrameType::Query => self.dispatch_query(dict),
            FrameType::Action => self.dispatch_action(dict),
            _ => Err(NpsError::Frame(format!(
                "Native NWP server does not handle frame type 0x{:02X}.",
                frame_type.as_u8()
            ))),
        };
        match result {
            Ok((ft, dict)) => (ft, dict),
            Err(err) => (
                FrameType::Error,
                error_dict(
                    "NPS-SERVER-INTERNAL",
                    "NWP-NATIVE-DISPATCH-FAILED",
                    err.to_string(),
                ),
            ),
        }
    }

    fn dispatch_query(&self, dict: FrameDict) -> NpsResult<(FrameType, FrameDict)> {
        let Some(handler) = &self.query_handler else {
            return Err(NpsError::Frame(
                "No native NWP query handler configured.".into(),
            ));
        };
        let frame = QueryFrame::from_dict(&dict)?;
        Ok((FrameType::Caps, handler(frame)?.to_dict()))
    }

    fn dispatch_action(&self, dict: FrameDict) -> NpsResult<(FrameType, FrameDict)> {
        let Some(handler) = &self.action_handler else {
            return Err(NpsError::Frame(
                "No native NWP action handler configured.".into(),
            ));
        };
        let value = handler(ActionFrame::from_dict(&dict)?)?;
        let mut caps = CapsFrame::new(
            self.anchor_ref.clone(),
            if value.is_null() {
                Vec::new()
            } else {
                vec![value]
            },
        );
        caps.tokenizer_used = Some("native-estimate".to_string());
        Ok((FrameType::Caps, caps.to_dict()))
    }
}

impl Default for NwpNativeNodeServer {
    fn default() -> Self {
        Self::new()
    }
}

async fn read_wire_frame<R>(reader: &mut R) -> NpsResult<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(NpsError::Io(e.to_string())),
    }
    let is_extended = header[1] & 0x01 != 0;
    let mut raw = header.to_vec();
    if is_extended {
        let mut rest = [0u8; 4];
        reader
            .read_exact(&mut rest)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        raw.extend_from_slice(&rest);
    }
    let parsed = FrameHeader::parse(&raw)?;
    let mut payload = vec![0u8; parsed.payload_length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| NpsError::Io(e.to_string()))?;
    raw.extend_from_slice(&payload);
    Ok(Some(raw))
}

fn error_dict(status: &str, error: &str, message: String) -> FrameDict {
    let mut out = serde_json::Map::new();
    out.insert("status".into(), json!(status));
    out.insert("error".into(), json!(error));
    out.insert("error_code".into(), json!(error));
    out.insert("message".into(), json!(message));
    out
}

fn encoding_allowed(header: &FrameHeader, default_tier: EncodingTier, enabled: &[String]) -> bool {
    header.encoding_tier() == default_tier
        || (header.encoding_tier() == EncodingTier::BinaryVector
            && header.frame_type == FrameType::Query
            && enabled.iter().any(|enc| enc == "binary_vector.v1"))
}

fn encoding_token(tier: EncodingTier) -> &'static str {
    match tier {
        EncodingTier::Json => "json",
        EncodingTier::MsgPack => "msgpack",
        EncodingTier::BinaryVector => "binary_vector.v1",
        EncodingTier::Reserved => "reserved",
    }
}
