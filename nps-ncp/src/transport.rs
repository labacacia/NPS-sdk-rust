// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NCP native-mode TCP transport (client, server, live session).
//!
//! Faithful port of the .NET reference `NcpNativeClient`, `NcpServer`,
//! `NcpServerConnection`, `NcpSession`, and `NcpServerOptions`. The 3-step
//! handshake follows NPS-1 §4.6:
//!
//! 1. preamble (`NPS/1.0\n`)
//! 2. `HelloFrame` (always Tier-1 JSON — encoding not yet negotiated)
//! 3. `NcpHandshakeCapsFrame` (or `ErrorFrame` on rejection)
//!
//! Uses `tokio` non-blocking sockets: the workspace is already async (reqwest,
//! ca-server uses `tokio::net`), and `tokio` with the `net` feature is present
//! in the offline cargo cache.

use crate::encoding_policy::NcpEncodingPolicy;
use crate::preamble;
use crate::{CapsFrame, ErrorFrame, HelloFrame};
use nps_core::codec::{decode_binary_vector, decode_json, decode_msgpack, encode_json, FrameDict};
use nps_core::error::{NpsError, NpsResult};
use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Handshake error mirroring .NET `NcpHandshakeException`: carries the wire
/// error code and human-readable message the server (or client) surfaced.
#[derive(Debug, Clone)]
pub struct NcpHandshakeError {
    pub error_code: String,
    pub message: String,
}

impl NcpHandshakeError {
    pub fn new(error_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error_code: error_code.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for NcpHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NCP handshake error [{}]: {}", self.error_code, self.message)
    }
}

impl std::error::Error for NcpHandshakeError {}

impl From<NcpHandshakeError> for NpsError {
    fn from(e: NcpHandshakeError) -> Self {
        NpsError::Frame(format!("[{}] {}", e.error_code, e.message))
    }
}

/// Unexpected-frame handshake error code, matching the .NET reference exactly
/// for cross-SDK interop.
pub const HANDSHAKE_UNEXPECTED_FRAME: &str = "NCP-HANDSHAKE-UNEXPECTED-FRAME";

// ── Header reading (EXT-aware) ──────────────────────────────────────────────

/// Reads a frame header from `reader`, peeking the EXT flag (bit 7, `0x80`) to
/// decide whether to read a 4-byte or 8-byte header. Returns the parsed header
/// and the raw header bytes. Mirrors .NET `NcpNativeClient.ReadFrameHeaderAsync`.
pub async fn read_frame_header<R>(reader: &mut R) -> NpsResult<(FrameHeader, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    // Always read 2 bytes first to detect the EXT flag.
    let mut peek = [0u8; 2];
    reader
        .read_exact(&mut peek)
        .await
        .map_err(|e| NpsError::Io(e.to_string()))?;

    let ext = peek[1] & 0x80 != 0;
    let remaining = if ext { 8 - 2 } else { 4 - 2 };

    let mut rest = vec![0u8; remaining];
    reader
        .read_exact(&mut rest)
        .await
        .map_err(|e| NpsError::Io(e.to_string()))?;

    let mut raw = Vec::with_capacity(peek.len() + rest.len());
    raw.extend_from_slice(&peek);
    raw.extend_from_slice(&rest);

    let header = FrameHeader::parse(&raw)?;
    Ok((header, raw))
}

/// Reads exactly `len` payload bytes.
async fn read_payload<R>(reader: &mut R, len: usize) -> NpsResult<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| NpsError::Io(e.to_string()))?;
    Ok(payload)
}

/// Decodes a handshake payload using the tier signalled in the header.
/// Mirrors .NET `NcpNativeClient.DecodeHandshakeFrame`.
fn decode_handshake_payload(header: &FrameHeader, payload: &[u8]) -> NpsResult<FrameDict> {
    match header.encoding_tier() {
        EncodingTier::Json => decode_json(payload),
        EncodingTier::MsgPack => decode_msgpack(payload),
        EncodingTier::BinaryVector => decode_binary_vector(payload),
        EncodingTier::Reserved => Err(NpsError::Codec(
            "Unsupported handshake encoding tier: reserved (0x03).".into(),
        )),
    }
}

/// Encodes a frame dict to wire bytes for the given tier (header + payload),
/// matching the layout produced by `NpsFrameCodec::encode`.
fn encode_frame(frame_type: FrameType, dict: &FrameDict, tier: EncodingTier) -> NpsResult<Vec<u8>> {
    use nps_core::codec::{encode_binary_vector, encode_msgpack};
    let payload = match tier {
        EncodingTier::Json => encode_json(dict)?,
        EncodingTier::MsgPack => encode_msgpack(dict)?,
        EncodingTier::BinaryVector => encode_binary_vector(dict)?,
        EncodingTier::Reserved => {
            return Err(NpsError::Codec("reserved encoding tier 0x03".into()))
        }
    };
    let header = FrameHeader::new(frame_type, tier, true, payload.len() as u64);
    let mut wire = header.to_bytes();
    wire.extend_from_slice(&payload);
    Ok(wire)
}

// ── NcpSession ──────────────────────────────────────────────────────────────

/// A live NCP native-mode session established after a successful handshake.
/// Wraps the underlying TCP stream and exposes the negotiated parameters.
/// Upper-layer protocols (NWP, NIP, …) drive frames through [`send_frame`]/[`recv_frame`]
/// or take ownership of the raw stream via [`into_stream`].
///
/// [`send_frame`]: NcpSession::send_frame
/// [`recv_frame`]: NcpSession::recv_frame
/// [`into_stream`]: NcpSession::into_stream
pub struct NcpSession {
    stream: TcpStream,
    server_caps: CapsFrame,
    policy: NcpEncodingPolicy,
}

impl NcpSession {
    fn new(stream: TcpStream, server_caps: CapsFrame, policy: NcpEncodingPolicy) -> Self {
        Self {
            stream,
            server_caps,
            policy,
        }
    }

    /// Capabilities the peer advertised during the handshake.
    pub fn server_caps(&self) -> &CapsFrame {
        &self.server_caps
    }

    /// Encoding policy negotiated during the handshake.
    pub fn encoding_policy(&self) -> &NcpEncodingPolicy {
        &self.policy
    }

    /// Stable default encoding tier negotiated during the handshake.
    pub fn negotiated_tier(&self) -> EncodingTier {
        self.policy.default_tier
    }

    /// Mutable access to the underlying stream for upper-layer serving loops.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Consumes the session and returns the raw authenticated stream.
    pub fn into_stream(self) -> TcpStream {
        self.stream
    }

    /// Encodes `dict` with the given tier, enforces the negotiated policy, and
    /// writes the resulting frame to the stream.
    pub async fn send_frame(
        &mut self,
        frame_type: FrameType,
        dict: &FrameDict,
        tier: EncodingTier,
    ) -> NpsResult<()> {
        let wire = encode_frame(frame_type, dict, tier)?;
        let header = FrameHeader::parse(&wire)?;
        self.policy.ensure_allows(&header)?;
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        Ok(())
    }

    /// Reads the next frame from the stream, enforces the negotiated policy, and
    /// decodes it with the tier signalled in the header. Returns `Ok(None)` on a
    /// clean EOF before any header bytes arrive.
    pub async fn recv_frame(&mut self) -> NpsResult<Option<(FrameType, FrameDict)>> {
        let mut first = [0u8; 1];
        match self.stream.read_exact(&mut first).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(NpsError::Io(e.to_string())),
        }

        // Read the second header byte and continue with the shared reader.
        let mut second = [0u8; 1];
        self.stream
            .read_exact(&mut second)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        let ext = second[0] & 0x80 != 0;
        let remaining = if ext { 8 - 2 } else { 4 - 2 };
        let mut rest = vec![0u8; remaining];
        self.stream
            .read_exact(&mut rest)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        let mut raw = vec![first[0], second[0]];
        raw.extend_from_slice(&rest);
        let header = FrameHeader::parse(&raw)?;
        self.policy.ensure_allows(&header)?;

        let payload = read_payload(&mut self.stream, header.payload_length as usize).await?;
        let dict = decode_handshake_payload(&header, &payload)?;
        Ok(Some((header.frame_type, dict)))
    }

    /// Closes the session, shutting down the write half of the socket.
    pub async fn close(mut self) -> NpsResult<()> {
        self.stream
            .shutdown()
            .await
            .map_err(|e| NpsError::Io(e.to_string()))
    }
}

// ── NcpNativeClient ─────────────────────────────────────────────────────────

/// NCP native-mode TCP client. Performs the 3-step handshake and returns a
/// live [`NcpSession`]. Port of .NET `NcpNativeClient`.
pub struct NcpNativeClient;

impl NcpNativeClient {
    /// Opens a TCP connection to `addr`, performs the NCP native-mode handshake,
    /// and returns a live session.
    ///
    /// Returns `Err(NpsError::Frame("[code] message"))` if the server rejects the
    /// handshake or sends an unexpected frame. Use [`connect_detailed`] to get the
    /// structured [`NcpHandshakeError`].
    ///
    /// [`connect_detailed`]: NcpNativeClient::connect_detailed
    pub async fn connect<A: ToSocketAddrs>(addr: A, hello: &HelloFrame) -> NpsResult<NcpSession> {
        Self::connect_detailed(addr, hello)
            .await
            .map_err(|e| match e {
                ConnectError::Handshake(h) => h.into(),
                ConnectError::Nps(n) => n,
            })
    }

    /// Like [`connect`], but surfaces server rejections as a structured
    /// [`NcpHandshakeError`].
    ///
    /// [`connect`]: NcpNativeClient::connect
    pub async fn connect_detailed<A: ToSocketAddrs>(
        addr: A,
        hello: &HelloFrame,
    ) -> Result<NcpSession, ConnectError> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| ConnectError::Nps(NpsError::Io(e.to_string())))?;

        // 1 — preamble (encoding not yet negotiated).
        stream
            .write_all(preamble::BYTES)
            .await
            .map_err(|e| ConnectError::Nps(NpsError::Io(e.to_string())))?;

        // 2 — HelloFrame (always Tier-1 JSON per spec).
        let hello_wire = encode_frame(FrameType::Hello, &hello.to_dict(), EncodingTier::Json)
            .map_err(ConnectError::Nps)?;
        stream
            .write_all(&hello_wire)
            .await
            .map_err(|e| ConnectError::Nps(NpsError::Io(e.to_string())))?;
        stream
            .flush()
            .await
            .map_err(|e| ConnectError::Nps(NpsError::Io(e.to_string())))?;

        // 3 — read server response header (handles EXT flag).
        let (header, _) = read_frame_header(&mut stream)
            .await
            .map_err(ConnectError::Nps)?;

        // 4 — read payload.
        let payload = read_payload(&mut stream, header.payload_length as usize)
            .await
            .map_err(ConnectError::Nps)?;

        // 5 — ErrorFrame → handshake error.
        if header.frame_type == FrameType::Error {
            let dict = decode_handshake_payload(&header, &payload).map_err(ConnectError::Nps)?;
            let err = ErrorFrame::from_dict(&dict).map_err(ConnectError::Nps)?;
            return Err(ConnectError::Handshake(NcpHandshakeError::new(
                err.error_code,
                err.message,
            )));
        }

        if header.frame_type != FrameType::Caps {
            return Err(ConnectError::Handshake(NcpHandshakeError::new(
                HANDSHAKE_UNEXPECTED_FRAME,
                format!(
                    "Expected CapsFrame (0x{:02X}), got 0x{:02X}.",
                    FrameType::Caps.as_u8(),
                    header.frame_type.as_u8()
                ),
            )));
        }

        // 6 — decode CapsFrame with the negotiated tier the server signalled.
        let negotiated_tier = header.encoding_tier();
        let dict = decode_handshake_payload(&header, &payload).map_err(ConnectError::Nps)?;
        let caps = CapsFrame::from_dict(&dict).map_err(ConnectError::Nps)?;
        let policy = NcpEncodingPolicy::from_enabled_encodings(
            negotiated_tier,
            caps.enabled_encodings.as_deref(),
        );

        Ok(NcpSession::new(stream, caps, policy))
    }
}

/// Error variants for [`NcpNativeClient::connect_detailed`].
#[derive(Debug)]
pub enum ConnectError {
    /// Server rejected the handshake or sent an unexpected frame.
    Handshake(NcpHandshakeError),
    /// Transport / codec failure.
    Nps(NpsError),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Handshake(h) => write!(f, "{h}"),
            ConnectError::Nps(n) => write!(f, "{n}"),
        }
    }
}

impl std::error::Error for ConnectError {}

// ── NcpServerOptions ────────────────────────────────────────────────────────

/// Server-side native NCP transport options. Port of .NET `NcpServerOptions`.
#[derive(Debug, Clone)]
pub struct NcpServerOptions {
    /// Maximum payload accepted for the initial `HelloFrame`. Defaults to the
    /// normal non-extended frame payload ceiling (65535 bytes) rather than the
    /// 4 GiB extended-frame limit — matching .NET `FrameHeader.DefaultMaxPayload`.
    pub max_hello_payload: u64,
}

impl Default for NcpServerOptions {
    fn default() -> Self {
        Self {
            max_hello_payload: 0xFFFF,
        }
    }
}

// ── NcpServerConnection ─────────────────────────────────────────────────────

/// Server-side representation of an inbound NCP connection that has passed the
/// preamble check and sent its `HelloFrame`. Call [`accept`] to complete the
/// handshake, or [`reject`] to send an error and close. Port of .NET
/// `NcpServerConnection`.
///
/// [`accept`]: NcpServerConnection::accept
/// [`reject`]: NcpServerConnection::reject
pub struct NcpServerConnection {
    stream: TcpStream,
    client_hello: HelloFrame,
}

impl NcpServerConnection {
    /// The `HelloFrame` sent by the connecting client.
    pub fn client_hello(&self) -> &HelloFrame {
        &self.client_hello
    }

    /// Sends `server_caps` to the client and returns a live [`NcpSession`].
    /// The encoding policy is negotiated from the client's `supported_encodings`.
    /// The outgoing CapsFrame's `negotiated_encoding` / `enabled_encodings` fields
    /// are set from the negotiated policy, matching .NET `AcceptAsync`.
    pub async fn accept(mut self, mut server_caps: CapsFrame) -> NpsResult<NcpSession> {
        let policy = Self::negotiate_encoding_policy(&self.client_hello)?;
        server_caps.negotiated_encoding = Some(NcpEncodingPolicy::encoding_token(policy.default_tier));
        server_caps.enabled_encodings = Some(policy.enabled_encodings());

        let wire = encode_frame(FrameType::Caps, &server_caps.to_dict(), policy.default_tier)?;
        self.stream
            .write_all(&wire)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        self.stream
            .flush()
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;

        Ok(NcpSession::new(self.stream, server_caps, policy))
    }

    /// Sends an `ErrorFrame` (always Tier-1 JSON) to reject the client and closes
    /// the connection. Port of .NET `RejectAsync`.
    pub async fn reject(mut self, error: &ErrorFrame) -> NpsResult<()> {
        let wire = encode_frame(FrameType::Error, &error.to_dict(), EncodingTier::Json)?;
        // Best-effort write, then always close (mirrors the finally block in .NET).
        let write_res = async {
            self.stream
                .write_all(&wire)
                .await
                .map_err(|e| NpsError::Io(e.to_string()))?;
            self.stream
                .flush()
                .await
                .map_err(|e| NpsError::Io(e.to_string()))
        }
        .await;
        let _ = self.stream.shutdown().await;
        write_res
    }

    /// Selects a stable default encoding from the client's `supported_encodings`.
    /// Optional encodings such as BinaryVector are recorded as extensions, not
    /// defaults. Mirrors .NET `NegotiateEncodingPolicy`.
    fn negotiate_encoding_policy(hello: &HelloFrame) -> NpsResult<NcpEncodingPolicy> {
        let binary_vector_enabled = hello
            .supported_encodings
            .iter()
            .any(|e| e == "binary_vector.v1");

        for enc in &hello.supported_encodings {
            match enc.as_str() {
                "msgpack" => {
                    return Ok(NcpEncodingPolicy::with_binary_vector(
                        EncodingTier::MsgPack,
                        binary_vector_enabled,
                    ))
                }
                "json" => {
                    return Ok(NcpEncodingPolicy::with_binary_vector(
                        EncodingTier::Json,
                        binary_vector_enabled,
                    ))
                }
                _ => {}
            }
        }

        Err(NpsError::Codec(
            "Client did not offer a supported stable default encoding (expected msgpack or json)."
                .into(),
        ))
    }
}

// ── NcpServer ───────────────────────────────────────────────────────────────

/// NCP native-mode TCP server. Listens on a configured endpoint, validates the
/// connection preamble, reads the client's `HelloFrame`, and returns an
/// [`NcpServerConnection`] for the application to accept or reject. Port of
/// .NET `NcpServer`.
pub struct NcpServer {
    listener: TcpListener,
    options: NcpServerOptions,
}

impl NcpServer {
    /// Binds a listener on `addr`. Pass `127.0.0.1:0` to let the OS choose a port.
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> NpsResult<Self> {
        Self::bind_with_options(addr, NcpServerOptions::default()).await
    }

    /// Binds a listener with explicit options.
    pub async fn bind_with_options<A: ToSocketAddrs>(
        addr: A,
        options: NcpServerOptions,
    ) -> NpsResult<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        Ok(Self { listener, options })
    }

    /// The local address the listener is bound to (useful with ephemeral port 0).
    pub fn local_addr(&self) -> NpsResult<std::net::SocketAddr> {
        self.listener
            .local_addr()
            .map_err(|e| NpsError::Io(e.to_string()))
    }

    /// Accepts the next inbound connection, validates the NPS preamble, reads the
    /// client's `HelloFrame`, and returns an [`NcpServerConnection`].
    pub async fn accept_connection(&self) -> NpsResult<NcpServerConnection> {
        let (mut stream, _peer) = self
            .listener
            .accept()
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;

        // 1 — read & validate preamble.
        let mut preamble_buf = [0u8; preamble::LENGTH];
        stream
            .read_exact(&mut preamble_buf)
            .await
            .map_err(|e| NpsError::Io(e.to_string()))?;
        preamble::validate(&preamble_buf)?;

        // 2 — read frame header.
        let (header, _) = read_frame_header(&mut stream).await?;

        if header.frame_type != FrameType::Hello {
            return Err(NpsError::Frame(format!(
                "Expected HelloFrame (0x{:02X}) as first frame after preamble, got 0x{:02X}.",
                FrameType::Hello.as_u8(),
                header.frame_type.as_u8()
            )));
        }

        if header.payload_length > self.options.max_hello_payload {
            return Err(NpsError::Frame(format!(
                "HelloFrame payload length {} exceeds configured maximum {} bytes.",
                header.payload_length, self.options.max_hello_payload
            )));
        }

        // 3 — read payload and deserialise HelloFrame (always JSON).
        let payload = read_payload(&mut stream, header.payload_length as usize).await?;
        let dict = decode_handshake_payload(&header, &payload)?;
        let hello = HelloFrame::from_dict(&dict)?;

        Ok(NcpServerConnection {
            stream,
            client_hello: hello,
        })
    }
}
