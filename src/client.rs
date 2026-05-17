//! [`RpcClient`] — open а bidi substream к а peer, write а unary
//! request, read the response.
//!
//! Phase 2 surface — only unary call is implemented. Server-streaming /
//! client-streaming / bidi-streaming variants land в Phase 3+ once the
//! WIT codegen pipeline picks the canonical streaming semantics.
//!
//! ## Method-name format (per Pavel ratify D7)
//!
//! - **Pinned version** (production): `tolki:chat@1.0.0/chat/send-message`
//! - **Version omitted** (debug / REPL): `tolki:chat/chat/send-message`
//!   — the server resolves к the latest registered semver under the same
//!   `package/interface/method` triple.
//!
//! ## Stale-connection eviction (N2)
//!
//! `nerw_core::client::Client::open_substream` caches outbound
//! connections per `(peer, alpn)`. If а cached connection becomes stale
//! (peer crashed mid-flight; idle timeout; clean close), а subsequent
//! `open_bi` against the same cache entry surfaces as
//! [`RpcError::TransportOpenSubstream`] — nerw-core already evicts the
//! dead entry in that path. nerw-rpc adds а second layer of defence:
//! when а read or write на an established stream fails
//! ([`RpcError::TransportRead`] / [`RpcError::TransportWrite`]), the
//! client explicitly calls
//! [`nerw_core::client::Client::evict_cached_connection`] so the next
//! call dials а fresh handshake instead of replaying the dead cache
//! entry. This handles the corner case where `open_bi` succeeds (it
//! merely allocates а logical stream id) but the underlying connection
//! has been silently dropped after the cache hit.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use futures_util::stream::BoxStream;
use nerw_core::identity::NodeId;
use tokio::sync::mpsc;
use tracing::trace;

use crate::error::{RpcError, RpcResult};
use crate::server::build_unary_request_frame;
use crate::streaming::{
    self, StreamingFrame, StreamingOpenRequest, StreamingOpenResponse, StreamingOpenStatus,
};
use crate::transport::{ALPN_NERW_RPC_1_0_0, IrohTransportClient};
use crate::wire::{OPCODE_UNARY_ERROR, OPCODE_UNARY_RESPONSE};
use crate::wire_error::WireError;

/// Process-wide monotonic counter для streaming `request_id` correlation.
///
/// Today nerw-rpc rides one substream per call so the id is
/// informational; future multiplexed transports use it для disambiguation.
static STREAMING_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum bytes we accept from а server response — protects clients
/// against а malicious server trying к exhaust memory by writing forever.
///
/// Same magnitude as the server-side cap; mismatch would manifest as
/// asymmetric truncation behaviour.
const RPC_RESPONSE_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Outbound RPC client.
///
/// Wraps а shared [`IrohTransportClient`] handle. Issuing а call opens
/// (or reuses, via nerw-core's connection cache) а QUIC connection
/// negotiated с [`ALPN_NERW_RPC_1_0_0`], opens а fresh bidi
/// substream, writes the framed request, и reads the response.
///
/// Cloning [`RpcClient`] is cheap — both fields wrap `Arc`s under the
/// hood. Multiple concurrent calls share the same connection cache.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Iroh-backed transport handle. Cloning is cheap (`Arc` inside);
    /// concurrent calls share the same connection cache.
    transport: IrohTransportClient,
}

impl RpcClient {
    /// Build а new client wrapping а transport handle.
    #[must_use]
    pub const fn new(transport: IrohTransportClient) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport handle (test introspection).
    #[must_use]
    pub const fn transport(&self) -> &IrohTransportClient {
        &self.transport
    }

    /// Issue а unary RPC call.
    ///
    /// `peer` is the target [`NodeId`] (z-base32 Ed25519 public key).
    /// Today the type aliases к `iroh::EndpointId` / `iroh::PublicKey`;
    /// post-R4 nerw-core will introduce а `NerwNodeId` newtype wrapper
    /// и this signature will resolve к the wrapper automatically —
    /// callers importing [`nerw_core::identity::NodeId`] are
    /// future-proof.
    ///
    /// `method_name` follows the canonical text format
    /// `package[@version]/interface/method` (D7 — see module docs).
    /// `request_bytes` is the postcard-encoded request body.
    ///
    /// Returns the raw response bytes (postcard-decoded by the caller's
    /// generated stub) on success, or а typed [`RpcError`] on failure.
    ///
    /// On transport read/write errors the cached connection for
    /// `(peer, ALPN_NERW_RPC_1_0_0)` is evicted so the next
    /// call re-handshakes (N2 stale-conn defence — see module docs).
    ///
    /// # Errors
    ///
    /// - [`RpcError::TransportOpenSubstream`] — peer dial / `open_bi` failure.
    /// - [`RpcError::TransportWrite`]         — `write_all` / `finish` failed.
    /// - [`RpcError::TransportRead`]          — `read_to_end` failed mid-flight.
    /// - [`RpcError::MalformedFrame`]         — response frame had а bad opcode.
    /// - [`RpcError::Codec`]                  — postcard-decoding the error
    ///   body failed (server-side bug).
    /// - [`RpcError::Handler`]                — server returned а handler error.
    /// - [`RpcError::UnknownMethod`]          — server-side registry miss.
    pub async fn call(&self, peer: &NodeId, method_name: &str, request: Bytes) -> RpcResult<Bytes> {
        let result = self.call_inner(peer, method_name, request).await;
        if let Err(ref err) = result {
            // N2: evict the cached connection on transport-layer failure
            // so the next call dials а fresh handshake instead of replaying
            // а dead cache entry. `open_bi` already handles stale entries
            // (см. nerw-core's `open_substream`); this catches the case
            // where the cache hit succeeded но read/write later observed
            // а silently-dropped connection. Other RpcError variants
            // (Codec, MalformedFrame, Handler, …) are application-layer
            // failures on a still-live transport — evicting would force
            // an unnecessary re-handshake on the next call.
            if is_transport_io_error(err) {
                self.transport
                    .inner()
                    .evict_cached_connection(peer, ALPN_NERW_RPC_1_0_0)
                    .await;
                trace!(
                    peer = %peer,
                    "RpcClient::call - evicted stale cached connection after transport error",
                );
            }
        }
        result
    }

    /// Open а bidi streaming call (Phase 3 — v0.9.0).
    ///
    /// Returns а pair of channels for client→server chunks and the
    /// server→client response stream. The caller pushes request chunks
    /// via the [`mpsc::Sender`] и reads responses via the
    /// [`BoxStream`]. Dropping the sender signals «no more requests»
    /// (framework writes [`crate::wire::OPCODE_STREAMING_REQUEST_END`]
    /// и closes the send half); the response stream ends when the
    /// server sends [`crate::wire::OPCODE_STREAMING_RESPONSE_END`] or а
    /// terminal [`crate::wire::OPCODE_STREAMING_ERROR`].
    ///
    /// `peer` is the target [`NodeId`]. `method_name` follows the
    /// canonical text format `package[@version]/interface/method` —
    /// resolved against а handler registered via
    /// [`crate::method::MethodRegistry::register_streaming`].
    ///
    /// # Errors
    ///
    /// - [`RpcError::TransportOpenSubstream`] — peer dial or `open_bi` failure.
    /// - [`RpcError::TransportWrite`]         — failed к write the open-request frame.
    /// - [`RpcError::TransportRead`]          — failed к read the open-ack frame.
    /// - [`RpcError::MalformedFrame`]         — unexpected frame type
    ///   from peer before the open-ack arrived.
    /// - [`RpcError::UnknownMethod`]          — server reported the method
    ///   is not registered for streaming.
    /// - [`RpcError::Codec`]                  — postcard-decoding the
    ///   ack frame failed.
    pub async fn call_streaming(
        &self,
        peer: &NodeId,
        method_name: &str,
    ) -> RpcResult<(mpsc::Sender<Bytes>, BoxStream<'static, RpcResult<Bytes>>)> {
        let (mut send, mut recv) = self
            .transport
            .inner()
            .open_substream(peer, ALPN_NERW_RPC_1_0_0)
            .await
            .map_err(|e| RpcError::TransportOpenSubstream {
                node_id: format!("{peer}"),
                reason: format!("{e}"),
            })?;

        let request_id = STREAMING_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
        let open = StreamingOpenRequest {
            method_name: method_name.to_owned(),
            request_id,
        };
        streaming::write_open_request(&mut send, &open).await?;

        // Wait for the server's open-ack BEFORE returning the channels —
        // this turns «unknown method» into а typed `RpcError::UnknownMethod`
        // surfaced by `call_streaming` itself rather than buried inside
        // the response stream.
        let ack_frame = streaming::read_streaming_frame(&mut recv).await?;
        let Some(StreamingFrame::OpenResponse(StreamingOpenResponse { status, .. })) = ack_frame
        else {
            return Err(RpcError::MalformedFrame(format!(
                "expected streaming open-ack, got {ack_frame:?}"
            )));
        };
        match status {
            StreamingOpenStatus::Ok => {}
            StreamingOpenStatus::Err(reason) => {
                // Heuristic: typical reasons start с "unknown streaming method:";
                // surface as the canonical typed variant when we can recognise it.
                if let Some(suffix) = reason.strip_prefix("unknown streaming method: ") {
                    return Err(RpcError::UnknownMethod(suffix.to_owned()));
                }
                return Err(RpcError::Handler(reason.into()));
            }
        }

        // Spawn а task that pumps inbound request-side chunks (from the
        // caller's mpsc) к the wire.
        let (req_tx, req_rx) = mpsc::channel::<Bytes>(16);
        let req_task = tokio::spawn(pump_outbound_requests(send, req_rx));

        // Spawn а task that pumps inbound response chunks к the caller-
        // facing mpsc.
        let (resp_tx, resp_rx) = mpsc::channel::<RpcResult<Bytes>>(16);
        tokio::spawn(async move {
            pump_inbound_responses(recv, resp_tx).await;
            // Defensive: ensure the request pump finishes before the
            // task exits so it doesn't outlive the substream.
            req_task.abort();
        });

        let stream: BoxStream<'static, RpcResult<Bytes>> =
            Box::pin(tokio_stream::wrappers::ReceiverStream::new(resp_rx));
        trace!(
            peer = %peer,
            method = %method_name,
            request_id,
            "RpcClient::call_streaming - open-ack received, channels live",
        );
        Ok((req_tx, stream))
    }

    /// Inner body of [`Self::call`] — separated so the N2 eviction
    /// post-check can run on every error path без duplicating the
    /// match arms inline.
    async fn call_inner(
        &self,
        peer: &NodeId,
        method_name: &str,
        request: Bytes,
    ) -> RpcResult<Bytes> {
        let frame = build_unary_request_frame(method_name, &request)?;
        let (mut send, mut recv) = self
            .transport
            .inner()
            .open_substream(peer, ALPN_NERW_RPC_1_0_0)
            .await
            .map_err(|e| RpcError::TransportOpenSubstream {
                node_id: format!("{peer}"),
                reason: format!("{e}"),
            })?;
        trace!(
            peer = %peer,
            method = %method_name,
            request_len = request.len(),
            "RpcClient::call - bidi opened, writing request",
        );

        // Write the framed request, signal EOF так the server's
        // read_to_end can complete.
        send.write_all(&frame)
            .await
            .map_err(|e| RpcError::TransportWrite {
                reason: format!("write_all: {e}"),
            })?;
        send.finish().map_err(|e| RpcError::TransportWrite {
            reason: format!("finish: {e}"),
        })?;

        // Read the entire response frame (server finishes its send-half
        // when the response is complete).
        let response_buf = recv
            .read_to_end(RPC_RESPONSE_READ_LIMIT)
            .await
            .map_err(|e| RpcError::TransportRead {
                reason: format!("read_to_end: {e}"),
            })?;

        decode_response_frame(&Bytes::from(response_buf))
    }
}

/// Pump outbound request chunks к the wire until the caller drops the
/// sender, then emit [`crate::wire::OPCODE_STREAMING_REQUEST_END`] и
/// `finish()` the send half.
///
/// Extracted from `call_streaming` so the streaming dispatch surface fits
/// в clippy's `too-many-lines-threshold` budget — the loop is а
/// straight-line pump that does not interact с the open-ack handshake.
async fn pump_outbound_requests(
    mut send: iroh::endpoint::SendStream,
    mut req_rx: mpsc::Receiver<Bytes>,
) {
    while let Some(chunk) = req_rx.recv().await {
        if streaming::write_request_chunk(&mut send, &chunk)
            .await
            .is_err()
        {
            return;
        }
    }
    // Sender dropped — emit the end-of-requests frame и close.
    let _ = streaming::write_request_end(&mut send).await;
    let _ = send.finish();
}

/// Pump inbound response frames к the caller-facing mpsc until the peer
/// emits [`crate::wire::OPCODE_STREAMING_RESPONSE_END`], а terminal
/// [`crate::wire::OPCODE_STREAMING_ERROR`], or the stream closes.
///
/// Extracted from `call_streaming` for the same reason as
/// [`pump_outbound_requests`].
async fn pump_inbound_responses(
    mut recv: iroh::endpoint::RecvStream,
    resp_tx: mpsc::Sender<RpcResult<Bytes>>,
) {
    loop {
        match streaming::read_streaming_frame(&mut recv).await {
            Ok(Some(StreamingFrame::ResponseChunk(bytes))) => {
                if resp_tx.send(Ok(bytes)).await.is_err() {
                    // Caller dropped the receiver — stop pumping.
                    return;
                }
            }
            // Server-side clean close — clean EOF from the read side both
            // surface as «no more chunks» from the caller's PoV.
            Ok(Some(StreamingFrame::ResponseEnd) | None) => return,
            Ok(Some(StreamingFrame::Error(err))) => {
                let surfaced = RpcError::Handler(err.message.clone().into());
                let _ = resp_tx.send(Err(surfaced)).await;
                if err.terminal {
                    return;
                }
            }
            Ok(Some(other)) => {
                let _ = resp_tx
                    .send(Err(RpcError::MalformedFrame(format!(
                        "unexpected server→client frame: {other:?}"
                    ))))
                    .await;
                return;
            }
            Err(e) => {
                let _ = resp_tx.send(Err(e)).await;
                return;
            }
        }
    }
}

/// Predicate: is this error а transport-layer read or write failure
/// that warrants evicting the cached connection (N2 stale-conn defence)?
///
/// Returns `true` for [`RpcError::TransportRead`] и
/// [`RpcError::TransportWrite`] — those are the only variants surfaced
/// when an established stream observes а silently-dropped connection.
/// `TransportOpenSubstream` is **not** included here: it already triggers
/// nerw-core's own eviction в the `open_bi` failure path, so doing it
/// twice would be redundant и could mask а real peer-not-found bug
/// surfacing on the next call. All other variants (`Codec`,
/// `MalformedFrame`, `Handler`, `UnknownMethod`, …) indicate а live
/// connection с an application-layer fault и must NOT force а
/// re-handshake.
const fn is_transport_io_error(err: &RpcError) -> bool {
    matches!(
        err,
        RpcError::TransportRead { .. } | RpcError::TransportWrite { .. }
    )
}

/// Decode а response frame: `[OPCODE_UNARY_RESPONSE | bytes]` (success)
/// or `[OPCODE_UNARY_ERROR | postcard(WireError)]` (failure).
///
/// The error body is the typed [`WireError`] envelope — а 1-byte
/// discriminant followed by the postcard-encoded payload. Reconstruction
/// is total: every wire variant maps к а concrete [`RpcError`] variant
/// без ambiguity. Locale invariant — translating display strings
/// в Russian (or anywhere else) does not affect classification.
///
/// Takes the response frame by reference так the success path can
/// `Bytes::slice` off the opcode byte without copying — the returned
/// [`Bytes`] shares the same underlying allocation as `buf`.
fn decode_response_frame(buf: &Bytes) -> RpcResult<Bytes> {
    let opcode = *buf
        .first()
        .ok_or_else(|| RpcError::MalformedFrame("empty response frame".to_owned()))?;
    match opcode {
        OPCODE_UNARY_RESPONSE => Ok(buf.slice(1..)),
        OPCODE_UNARY_ERROR => {
            let wire: WireError = postcard::from_bytes(&buf[1..]).map_err(RpcError::Codec)?;
            Err(wire.into_rpc_error())
        }
        other => Err(RpcError::MalformedFrame(format!(
            "unexpected response opcode 0x{other:02x}",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::OPCODE_UNARY_REQUEST;

    fn build_buf(prefix: u8, body: &[u8]) -> Bytes {
        let mut v = Vec::with_capacity(1 + body.len());
        v.push(prefix);
        v.extend_from_slice(body);
        Bytes::from(v)
    }

    #[test]
    fn decode_response_frame_success() {
        let buf = build_buf(OPCODE_UNARY_RESPONSE, b"OK-PAYLOAD");
        let decoded = decode_response_frame(&buf).expect("decode ok");
        assert_eq!(&decoded[..], b"OK-PAYLOAD");
    }

    #[test]
    fn decode_response_frame_error_handler() {
        let body = postcard::to_allocvec(&WireError::HandlerError {
            display: "some handler failure".to_owned(),
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::Handler(_) => {}
            other => panic!("expected RpcError::Handler, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_error_unknown_method() {
        let body = postcard::to_allocvec(&WireError::UnknownMethod {
            method_name: "tolki:nope@1.0.0/iface/method".to_owned(),
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::UnknownMethod(name) => {
                assert_eq!(name, "tolki:nope@1.0.0/iface/method");
            }
            other => panic!("expected RpcError::UnknownMethod, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_error_version_mismatch() {
        // Demonstrates the new typed wire format preserves variant + metadata
        // even when the human-readable Display would not survive а string-prefix
        // match (e.g. translated к Russian).
        let body = postcard::to_allocvec(&WireError::VersionMismatch {
            requested: "9.9.9".to_owned(),
            available: vec!["1.0.0".to_owned(), "2.0.0".to_owned()],
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::VersionMismatch {
                requested,
                available,
            } => {
                assert_eq!(requested, "9.9.9");
                assert_eq!(available, vec!["1.0.0".to_owned(), "2.0.0".to_owned()]);
            }
            other => panic!("expected RpcError::VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_empty_buffer() {
        let err = decode_response_frame(&Bytes::new()).expect_err("empty buffer must error");
        assert!(matches!(err, RpcError::MalformedFrame(_)));
    }

    #[test]
    fn decode_response_frame_unexpected_opcode() {
        let buf = build_buf(OPCODE_UNARY_REQUEST, &[0xAA, 0xBB]);
        let err = decode_response_frame(&buf).expect_err("must error");
        let s = err.to_string();
        assert!(s.contains("unexpected response opcode"));
    }
}
