//! Bidi streaming primitives (Phase 3 — v0.9.0).
//!
//! Adds а [`StreamingMethodHandler`] trait + sibling registry slot к the
//! existing unary [`crate::method::MethodHandler`] surface. One streaming
//! call rides one QUIC bidi substream on the `nerw/rpc/1.0.0` ALPN —
//! same connection cache as unary calls, no new ALPN, no second listener.
//!
//! ## Wire format
//!
//! See [`crate::wire`] и `wit/nerw-rpc.wit`. The first byte of each
//! substream's frame discriminates unary
//! ([`crate::wire::OPCODE_UNARY_REQUEST`] = `0x00`) versus streaming
//! ([`crate::wire::OPCODE_STREAMING_OPEN_REQUEST`] = `0x10`). Subsequent
//! frames in а streaming call use the `0x2x..0x4x` band so the dispatch
//! is а single byte-match on the opening frame.
//!
//! ## Cancellation semantics
//!
//! - Client drops its sender → emits [`crate::wire::OPCODE_STREAMING_REQUEST_END`].
//!   Server's request stream yields `None`.
//! - Client drops its receiver → next server-side send on the response
//!   sender returns `mpsc::error::SendError`; handler observes the drop
//!   и terminates cleanly.
//! - Server's handler returns `Ok(())` → emits [`crate::wire::OPCODE_STREAMING_RESPONSE_END`].
//!   Client's receiver stream ends.
//! - Server's handler returns `Err(e)` → emits [`crate::wire::OPCODE_STREAMING_ERROR`]
//!   с `terminal = true`. Client surfaces the typed error.
//! - Mid-stream errors emitted via the response sender propagate
//!   identically — а per-chunk `Err(...)` is converted к а terminal
//!   error frame before the substream closes.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::BoxStream;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use crate::context::RpcContext;
use crate::error::{RpcError, RpcResult};

/// Trait для bidi streaming method handlers — application code implements
/// this for each streaming RPC method.
///
/// А handler receives:
///
/// - `ctx` — [`RpcContext`] с peer identity, timing, auth, tracing.
/// - `requests` — stream of inbound request chunks (`Bytes` payload per chunk).
///   Yields `None` after the client drops its sender; яeach `Err` is а
///   client-emitted mid-stream error frame.
/// - `responses` — channel sender для outbound response chunks. Send
///   `Ok(bytes)` for а response chunk, `Err(e)` for а terminal mid-stream
///   error (the framework converts the latter to а
///   [`crate::wire::OPCODE_STREAMING_ERROR`] frame с `terminal = true`).
///
/// The handler returns `Ok(())` to signal clean end (framework writes
/// [`crate::wire::OPCODE_STREAMING_RESPONSE_END`]), or `Err(e)` к surface
/// а terminal stream error (framework writes
/// [`crate::wire::OPCODE_STREAMING_ERROR`] с `terminal = true` if no
/// in-band error has been emitted yet).
///
/// Dropping the response sender mid-handler is equivalent к returning
/// `Ok(())`: the framework writes the response-end frame и closes the
/// substream. This lets one-shot server-streaming handlers express
/// «done» implicitly by letting the sender go out of scope.
#[async_trait]
pub trait StreamingMethodHandler: Send + Sync + 'static {
    /// Handle а streaming call.
    ///
    /// # Errors
    ///
    /// А returned error is propagated к the client as а terminal
    /// [`crate::wire::OPCODE_STREAMING_ERROR`] frame (unless one has
    /// already been emitted via the response sender).
    async fn handle(
        &self,
        ctx: RpcContext,
        requests: BoxStream<'static, RpcResult<Bytes>>,
        responses: mpsc::Sender<RpcResult<Bytes>>,
    ) -> RpcResult<()>;
}

/// First-frame body для а streaming call (postcard-encoded after
/// [`crate::wire::OPCODE_STREAMING_OPEN_REQUEST`] + LEB128 length prefix).
///
/// `request_id` is а monotonic counter assigned by the client to correlate
/// open-acks с the originating call. Today nerw-rpc rides one substream
/// per call so the id is informational; future multiplexed transports
/// (e.g. peer-as-relay carrying multiple logical RPCs над one substream)
/// can use it для disambiguation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingOpenRequest {
    /// Canonical method name (`package[@version]/interface/method`).
    pub method_name: String,
    /// Caller-assigned correlation id (monotonic per-client).
    pub request_id: u64,
}

/// Status discriminant for [`StreamingOpenResponse`] — `Ok` for а
/// successful registry match, `Err(reason)` for unknown-method и
/// malformed-name failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamingOpenStatus {
    /// Registry matched а handler — chunks may flow.
    Ok,
    /// No handler registered or method name malformed.
    Err(String),
}

/// Ack body для [`OPCODE_STREAMING_OPEN_RESPONSE`] (postcard-encoded).
///
/// [`OPCODE_STREAMING_OPEN_RESPONSE`]:
/// crate::wire::OPCODE_STREAMING_OPEN_RESPONSE
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingOpenResponse {
    /// `Ok` или `Err(reason)`.
    pub status: StreamingOpenStatus,
    /// Echo of the originating [`StreamingOpenRequest::request_id`].
    pub request_id: u64,
}

/// Mid-stream error body (postcard-encoded after
/// [`crate::wire::OPCODE_STREAMING_ERROR`] + LEB128 length prefix).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamingError {
    /// Human-readable description of the failure.
    pub message: String,
    /// `true` if the sender is closing the stream after this frame;
    /// `false` если further frames may follow on the same direction.
    pub terminal: bool,
}

impl StreamingError {
    /// Build а terminal [`StreamingError`] from any displayable error.
    pub fn terminal_from<E: std::fmt::Display>(e: &E) -> Self {
        Self {
            message: format!("{e}"),
            terminal: true,
        }
    }
}

/// Internal registry slot — discriminated union of unary versus streaming
/// handlers behind а single keyed map.
///
/// Stored inside [`crate::method::MethodRegistry`]; dispatch reads the
/// opening opcode off the wire и looks up the appropriate variant.
pub(crate) enum HandlerEntry {
    /// Unary handler — invoked by the wire dispatcher's existing path.
    Unary(Arc<dyn crate::method::MethodHandler>),
    /// Streaming handler — invoked by the streaming dispatch path.
    Streaming(Arc<dyn StreamingMethodHandler>),
}

impl HandlerEntry {
    /// `true` if this entry hosts а streaming handler. Surfaced for the
    /// dispatch path's pre-invocation routing decision; lookup
    /// helpers ([`crate::method::MethodRegistry::lookup`] vs
    /// [`crate::method::MethodRegistry::lookup_streaming`]) already match
    /// on this internally.
    #[allow(dead_code)] // External-only diagnostic; kept stable для tooling.
    pub(crate) const fn is_streaming(&self) -> bool {
        matches!(self, Self::Streaming(_))
    }
}

/// Convenience type alias for the keyed handler map inside
/// [`crate::method::MethodRegistry`].
pub(crate) type HandlerMap = HashMap<String, HandlerEntry>;

/// Convert а handler-level error к а terminal wire-error frame body.
///
/// Used by the server dispatch path to turn а
/// `StreamingMethodHandler::handle` `Err` return into а
/// [`crate::wire::OPCODE_STREAMING_ERROR`] frame с `terminal = true`.
pub(crate) fn handler_err_to_terminal(err: &RpcError) -> StreamingError {
    StreamingError::terminal_from(err)
}

// =============================================================================
// Wire framing helpers — used by both server и client paths.
// =============================================================================

use iroh::endpoint::{RecvStream, SendStream};
use tracing::trace;

use crate::wire::{
    MAX_STREAMING_PAYLOAD_LEN, OPCODE_STREAMING_ERROR, OPCODE_STREAMING_OPEN_REQUEST,
    OPCODE_STREAMING_OPEN_RESPONSE, OPCODE_STREAMING_REQUEST_CHUNK, OPCODE_STREAMING_REQUEST_END,
    OPCODE_STREAMING_RESPONSE_CHUNK, OPCODE_STREAMING_RESPONSE_END,
};

/// Discriminated view of one streaming frame read off the wire.
///
/// Frames are returned by [`read_streaming_frame`] / [`read_streaming_frame_after_opcode`]
/// — the caller matches on the variant к decide whether к dispatch а
/// chunk, close the stream, or surface а typed error.
#[derive(Debug)]
pub(crate) enum StreamingFrame {
    /// `[0x10 | varint | postcard(StreamingOpenRequest)]`.
    OpenRequest(StreamingOpenRequest),
    /// `[0x11 | varint | postcard(StreamingOpenResponse)]`.
    OpenResponse(StreamingOpenResponse),
    /// `[0x20 | varint | bytes]` — client → server chunk.
    RequestChunk(Bytes),
    /// `[0x21 | varint | bytes]` — server → client chunk.
    ResponseChunk(Bytes),
    /// `[0x30]` — client → server end-of-stream signal.
    RequestEnd,
    /// `[0x31]` — server → client end-of-stream signal.
    ResponseEnd,
    /// `[0x40 | varint | postcard(StreamingError)]`.
    Error(StreamingError),
}

/// Read one streaming frame off the wire. Returns `Ok(None)` on clean
/// EOF (peer closed its send half без any partial bytes), `Ok(Some(...))`
/// for а complete frame.
///
/// # Errors
///
/// - [`RpcError::TransportRead`] — underlying QUIC read failed mid-frame.
/// - [`RpcError::MalformedFrame`] — unknown opcode, truncated varint,
///   declared payload length exceeds [`MAX_STREAMING_PAYLOAD_LEN`].
/// - [`RpcError::Codec`] — postcard decode of а typed payload failed.
pub(crate) async fn read_streaming_frame(
    recv: &mut RecvStream,
) -> RpcResult<Option<StreamingFrame>> {
    let mut opcode_buf = [0_u8; 1];
    match recv.read_exact(&mut opcode_buf).await {
        Ok(()) => {}
        Err(e) => return classify_eof_or_error(e),
    }
    let frame = read_streaming_frame_after_opcode(recv, opcode_buf[0]).await?;
    Ok(Some(frame))
}

/// Continue reading а frame after the opcode byte has already been consumed.
///
/// Useful for the server-side dispatcher, которое peeks the first byte
/// from the substream к decide unary-vs-streaming routing before handing
/// the remainder к either path.
pub(crate) async fn read_streaming_frame_after_opcode(
    recv: &mut RecvStream,
    opcode: u8,
) -> RpcResult<StreamingFrame> {
    match opcode {
        OPCODE_STREAMING_OPEN_REQUEST => {
            let bytes = read_length_prefixed(recv).await?;
            let body: StreamingOpenRequest =
                postcard::from_bytes(&bytes).map_err(RpcError::Codec)?;
            Ok(StreamingFrame::OpenRequest(body))
        }
        OPCODE_STREAMING_OPEN_RESPONSE => {
            let bytes = read_length_prefixed(recv).await?;
            let body: StreamingOpenResponse =
                postcard::from_bytes(&bytes).map_err(RpcError::Codec)?;
            Ok(StreamingFrame::OpenResponse(body))
        }
        OPCODE_STREAMING_REQUEST_CHUNK => {
            let bytes = read_length_prefixed(recv).await?;
            Ok(StreamingFrame::RequestChunk(Bytes::from(bytes)))
        }
        OPCODE_STREAMING_RESPONSE_CHUNK => {
            let bytes = read_length_prefixed(recv).await?;
            Ok(StreamingFrame::ResponseChunk(Bytes::from(bytes)))
        }
        OPCODE_STREAMING_REQUEST_END => Ok(StreamingFrame::RequestEnd),
        OPCODE_STREAMING_RESPONSE_END => Ok(StreamingFrame::ResponseEnd),
        OPCODE_STREAMING_ERROR => {
            let bytes = read_length_prefixed(recv).await?;
            let body: StreamingError = postcard::from_bytes(&bytes).map_err(RpcError::Codec)?;
            Ok(StreamingFrame::Error(body))
        }
        other => Err(RpcError::MalformedFrame(format!(
            "unexpected streaming opcode 0x{other:02x}"
        ))),
    }
}

/// Classify а `read_exact` failure: EOF (zero bytes available) maps к
/// `Ok(None)`, everything else к `TransportRead`.
fn classify_eof_or_error(e: iroh::endpoint::ReadExactError) -> RpcResult<Option<StreamingFrame>> {
    use iroh::endpoint::{ReadError, ReadExactError};
    // ReadExactError::FinishedEarly carries 0-byte for clean EOF, > 0 for
    // partial. We accept the 0-byte case as а clean end; anything else
    // surfaces as а transport read failure.
    match e {
        ReadExactError::FinishedEarly(0) | ReadExactError::ReadError(ReadError::ClosedStream) => {
            Ok(None)
        }
        ReadExactError::FinishedEarly(n) => Err(RpcError::TransportRead {
            reason: format!("partial frame: read {n} bytes before EOF"),
        }),
        ReadExactError::ReadError(other) => Err(RpcError::TransportRead {
            reason: format!("{other}"),
        }),
    }
}

/// Read one LEB128 length-prefixed byte slice from `recv`.
///
/// The varint declares the payload length. We cap at
/// [`MAX_STREAMING_PAYLOAD_LEN`] к prevent а malicious peer from forcing
/// us к pre-allocate gigabytes via а bogus length.
async fn read_length_prefixed(recv: &mut RecvStream) -> RpcResult<Vec<u8>> {
    let len = read_varint_u64(recv).await?;
    let len_usize = usize::try_from(len)
        .map_err(|e| RpcError::MalformedFrame(format!("streaming payload length overflow: {e}")))?;
    if len_usize > MAX_STREAMING_PAYLOAD_LEN {
        return Err(RpcError::MalformedFrame(format!(
            "streaming payload length {len_usize} exceeds maximum {MAX_STREAMING_PAYLOAD_LEN}"
        )));
    }
    let mut buf = vec![0_u8; len_usize];
    if !buf.is_empty() {
        recv.read_exact(&mut buf)
            .await
            .map_err(|e| RpcError::TransportRead {
                reason: format!("streaming payload body: {e}"),
            })?;
    }
    Ok(buf)
}

/// Read one LEB128-encoded `u64` varint off `recv` one byte at а time.
///
/// We cannot use `leb128::read::unsigned` directly because that reader
/// takes а blocking [`std::io::Read`], not an async stream. The async
/// equivalent peels off bytes via [`RecvStream::read_exact`] and stops
/// when the continuation bit is clear.
async fn read_varint_u64(recv: &mut RecvStream) -> RpcResult<u64> {
    let mut result: u64 = 0;
    // Maximum bytes а LEB128 u64 needs: ceil(64/7) = 10.
    for shift in 0_u32..10 {
        let mut byte_buf = [0_u8; 1];
        recv.read_exact(&mut byte_buf)
            .await
            .map_err(|e| RpcError::TransportRead {
                reason: format!("streaming varint: {e}"),
            })?;
        let byte = byte_buf[0];
        let lower = u64::from(byte & 0x7F);
        let shifted = lower
            .checked_shl(shift.saturating_mul(7))
            .ok_or_else(|| RpcError::MalformedFrame("streaming varint overflow".to_owned()))?;
        result = result
            .checked_add(shifted)
            .ok_or_else(|| RpcError::MalformedFrame("streaming varint sum overflow".to_owned()))?;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
    }
    Err(RpcError::MalformedFrame(
        "streaming varint > 10 bytes".to_owned(),
    ))
}

/// Encode а LEB128 `u64` varint into `buf`.
fn encode_varint_u64(value: u64, buf: &mut Vec<u8>) -> RpcResult<()> {
    leb128::write::unsigned(buf, value)
        .map(|_| ())
        .map_err(|e| RpcError::MalformedFrame(format!("leb128 write streaming varint: {e}")))
}

/// Encode + send а length-prefixed frame: `[opcode | varint(len) | bytes]`.
async fn write_length_prefixed(send: &mut SendStream, opcode: u8, body: &[u8]) -> RpcResult<()> {
    // 1 opcode byte + ≤10 varint bytes + body.
    let mut buf = Vec::with_capacity(11_usize.saturating_add(body.len()));
    buf.push(opcode);
    let body_len = u64::try_from(body.len())
        .map_err(|e| RpcError::MalformedFrame(format!("streaming body length overflow: {e}")))?;
    encode_varint_u64(body_len, &mut buf)?;
    buf.extend_from_slice(body);
    send.write_all(&buf)
        .await
        .map_err(|e| RpcError::TransportWrite {
            reason: format!("streaming write_all: {e}"),
        })?;
    Ok(())
}

/// Send а single one-byte opcode frame (`REQUEST_END` / `RESPONSE_END`).
async fn write_single_opcode(send: &mut SendStream, opcode: u8) -> RpcResult<()> {
    send.write_all(&[opcode])
        .await
        .map_err(|e| RpcError::TransportWrite {
            reason: format!("streaming opcode-only write: {e}"),
        })?;
    Ok(())
}

/// Write а [`StreamingFrame::OpenRequest`] body to `send`.
pub(crate) async fn write_open_request(
    send: &mut SendStream,
    body: &StreamingOpenRequest,
) -> RpcResult<()> {
    let encoded = postcard::to_allocvec(body).map_err(RpcError::Codec)?;
    write_length_prefixed(send, OPCODE_STREAMING_OPEN_REQUEST, &encoded).await
}

/// Write а [`StreamingFrame::OpenResponse`] body to `send`.
pub(crate) async fn write_open_response(
    send: &mut SendStream,
    body: &StreamingOpenResponse,
) -> RpcResult<()> {
    let encoded = postcard::to_allocvec(body).map_err(RpcError::Codec)?;
    write_length_prefixed(send, OPCODE_STREAMING_OPEN_RESPONSE, &encoded).await
}

/// Write а request chunk: `[0x20 | varint(len) | bytes]`.
pub(crate) async fn write_request_chunk(send: &mut SendStream, bytes: &[u8]) -> RpcResult<()> {
    write_length_prefixed(send, OPCODE_STREAMING_REQUEST_CHUNK, bytes).await
}

/// Write а response chunk: `[0x21 | varint(len) | bytes]`.
pub(crate) async fn write_response_chunk(send: &mut SendStream, bytes: &[u8]) -> RpcResult<()> {
    write_length_prefixed(send, OPCODE_STREAMING_RESPONSE_CHUNK, bytes).await
}

/// Write the no-payload `[0x30]` request-end frame.
pub(crate) async fn write_request_end(send: &mut SendStream) -> RpcResult<()> {
    write_single_opcode(send, OPCODE_STREAMING_REQUEST_END).await
}

/// Write the no-payload `[0x31]` response-end frame.
pub(crate) async fn write_response_end(send: &mut SendStream) -> RpcResult<()> {
    write_single_opcode(send, OPCODE_STREAMING_RESPONSE_END).await
}

/// Write а [`StreamingError`] frame: `[0x40 | varint(len) | postcard(...)]`.
pub(crate) async fn write_streaming_error(
    send: &mut SendStream,
    body: &StreamingError,
) -> RpcResult<()> {
    let encoded = postcard::to_allocvec(body).map_err(RpcError::Codec)?;
    write_length_prefixed(send, OPCODE_STREAMING_ERROR, &encoded).await?;
    if body.terminal {
        trace!("streaming: wrote terminal error frame");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_request_roundtrips_via_postcard() {
        let req = StreamingOpenRequest {
            method_name: "nerw:test@1.0.0/echo/loop".to_owned(),
            request_id: 42,
        };
        let bytes = postcard::to_allocvec(&req).expect("encode");
        let back: StreamingOpenRequest = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, req);
    }

    #[test]
    fn open_response_ok_roundtrip() {
        let resp = StreamingOpenResponse {
            status: StreamingOpenStatus::Ok,
            request_id: 7,
        };
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        let back: StreamingOpenResponse = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, resp);
    }

    #[test]
    fn open_response_err_roundtrip() {
        let resp = StreamingOpenResponse {
            status: StreamingOpenStatus::Err("not found".to_owned()),
            request_id: 7,
        };
        let bytes = postcard::to_allocvec(&resp).expect("encode");
        let back: StreamingOpenResponse = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, resp);
    }

    #[test]
    fn streaming_error_roundtrip() {
        let err = StreamingError {
            message: "boom".to_owned(),
            terminal: true,
        };
        let bytes = postcard::to_allocvec(&err).expect("encode");
        let back: StreamingError = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(back, err);
    }

    #[test]
    fn handler_err_to_terminal_preserves_display() {
        let rpc_err = RpcError::Handler("simulated boom".to_owned().into());
        let wire = handler_err_to_terminal(&rpc_err);
        assert!(wire.terminal);
        assert!(
            wire.message.contains("simulated boom"),
            "terminal payload must carry the inner error display"
        );
    }
}
