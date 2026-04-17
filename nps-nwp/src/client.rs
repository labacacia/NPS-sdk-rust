// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_core::codec::{FrameDict, NpsFrameCodec};
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use nps_core::registry::FrameRegistry;
use nps_ncp::{AnchorFrame, CapsFrame, StreamFrame};
use crate::frames::{ActionFrame, AsyncActionResponse, QueryFrame};

const CONTENT_TYPE: &str = "application/x-nps-frame";

pub struct NwpClient {
    base_url: String,
    codec:    NpsFrameCodec,
    tier:     EncodingTier,
    http:     reqwest::Client,
}

impl NwpClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let codec    = NpsFrameCodec::new(FrameRegistry::create_full());
        NwpClient {
            base_url,
            codec,
            tier: EncodingTier::MsgPack,
            http: reqwest::Client::new(),
        }
    }

    pub fn with_tier(mut self, tier: EncodingTier) -> Self {
        self.tier = tier;
        self
    }

    // ── sendAnchor ────────────────────────────────────────────────────────────

    pub async fn send_anchor(&self, frame: &AnchorFrame) -> NpsResult<()> {
        let wire = self.codec.encode(AnchorFrame::frame_type(), &frame.to_dict(), self.tier, true)?;
        let res  = self.post(&format!("{}/anchor", self.base_url), wire).await?;
        self.check_ok(res.status(), "/anchor")
    }

    // ── query ─────────────────────────────────────────────────────────────────

    pub async fn query(&self, frame: &QueryFrame) -> NpsResult<CapsFrame> {
        let wire = self.codec.encode(QueryFrame::frame_type(), &frame.to_dict(), self.tier, true)?;
        let res  = self.post(&format!("{}/query", self.base_url), wire).await?;
        self.check_ok(res.status(), "/query")?;
        let body = res.bytes().await.map_err(|e| NpsError::Io(e.to_string()))?;
        let (ft, dict) = self.codec.decode(&body)?;
        if ft != FrameType::Caps {
            return Err(NpsError::Frame(format!("expected Caps, got {ft:?}")));
        }
        CapsFrame::from_dict(&dict)
    }

    // ── stream ────────────────────────────────────────────────────────────────

    pub async fn stream(&self, frame: &QueryFrame) -> NpsResult<Vec<StreamFrame>> {
        let wire = self.codec.encode(QueryFrame::frame_type(), &frame.to_dict(), self.tier, true)?;
        let res  = self.post(&format!("{}/stream", self.base_url), wire).await?;
        self.check_ok(res.status(), "/stream")?;
        let body: Vec<u8> = res.bytes().await
            .map_err(|e| NpsError::Io(e.to_string()))?.to_vec();

        let mut frames = Vec::new();
        let mut offset = 0usize;
        while offset < body.len() {
            let hdr   = FrameHeader::parse(&body[offset..])?;
            let total = hdr.header_size() + hdr.payload_length as usize;
            let (ft, dict) = self.codec.decode(&body[offset..offset + total])?;
            if ft != FrameType::Stream {
                return Err(NpsError::Frame(format!("expected Stream, got {ft:?}")));
            }
            let sf = StreamFrame::from_dict(&dict)?;
            let is_last = sf.is_last;
            frames.push(sf);
            if is_last { break; }
            offset += total;
        }
        Ok(frames)
    }

    // ── invoke ────────────────────────────────────────────────────────────────

    pub async fn invoke(&self, frame: &ActionFrame) -> NpsResult<InvokeResult> {
        let wire = self.codec.encode(ActionFrame::frame_type(), &frame.to_dict(), self.tier, true)?;
        let res  = self.post(&format!("{}/invoke", self.base_url), wire).await?;
        self.check_ok(res.status(), "/invoke")?;
        let ct   = res.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body: Vec<u8> = res.bytes().await
            .map_err(|e| NpsError::Io(e.to_string()))?.to_vec();

        if frame.async_ {
            let dict: FrameDict = serde_json::from_slice(&body)
                .map_err(|e| NpsError::Codec(e.to_string()))?;
            return Ok(InvokeResult::Async(AsyncActionResponse::from_dict(&dict)?));
        }
        if ct.contains(CONTENT_TYPE) {
            let (_, dict) = self.codec.decode(&body)?;
            return Ok(InvokeResult::Frame(dict));
        }
        let dict: FrameDict = serde_json::from_slice(&body)
            .map_err(|e| NpsError::Codec(e.to_string()))?;
        Ok(InvokeResult::Json(dict))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn post(&self, url: &str, body: Vec<u8>) -> NpsResult<reqwest::Response> {
        self.http.post(url)
            .header("Content-Type", CONTENT_TYPE)
            .header("Accept",       CONTENT_TYPE)
            .body(body)
            .send()
            .await
            .map_err(|e| NpsError::Io(e.to_string()))
    }

    fn check_ok(&self, status: reqwest::StatusCode, path: &str) -> NpsResult<()> {
        if status.is_success() { Ok(()) }
        else { Err(NpsError::Io(format!("NWP {path} failed: HTTP {}", status.as_u16()))) }
    }
}

#[derive(Debug)]
pub enum InvokeResult {
    Frame(FrameDict),
    Async(AsyncActionResponse),
    Json(FrameDict),
}
