//! [`RpcServer`] — registers an [`nerw_core::client::AlpnHandler`] for
//! [`crate::transport::ALPN_TOLKI_WIRE_PROTOCOL_2_0_0`] and dispatches
//! inbound bidi streams к а shared [`crate::method::MethodRegistry`].
//!
//! ## Inbound flow (per stream)
//!
//! 1. Peer opens а bidi substream к our [`iroh::Endpoint`] negotiated с
//!    `tolki/wire-protocol/2.0.0`.
//! 2. nerw-core's accept loop dispatches the connection к
//!    [`WireDispatchHandler`] via the [`AlpnHandler`] trait.
//! 3. The handler spawns а per-connection task that pumps `accept_bi()`
//!    в а loop. Each accepted bidi stream becomes а fresh
//!    request-handling task.
//! 4. Per-stream task reads the request frame:
//!    `[opcode_unary_request | varint(name_len) | method-name UTF-8 | postcard(payload)]`
//! 5. Looks up the handler in the [`MethodRegistry`].
//! 6. Builds an [`RpcContext`] from the connection's
//!    [`iroh::endpoint::Connection::remote_id`] и timing.
//! 7. Invokes the handler.
//! 8. Writes the response: `[opcode_response | postcard(bytes)]`
//!    on success, or `[opcode_error | postcard(error-string)]` on
//!    failure (handler error / unknown method / decode error).
//! 9. Calls `SendStream::finish()` so the peer's `read_to_end` returns.
//!
//! ## Why а fresh task per stream
//!
//! iroh's `Connection::accept_bi` returns one bidi at а time; each
//! request is independent. Spawning per-stream lets concurrent
//! requests on the same connection (long-running handler + quick poll)
//! не block each other.

use std::sync::Arc;
use std::time::SystemTime;

use iroh::endpoint::Connection;
use nerw_core::client::AlpnHandler;
use tracing::{debug, trace, warn};

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::method::MethodRegistry;
use crate::transport::{ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, IrohTransportClient};
use crate::wire::{
    OPCODE_UNARY_ERROR, OPCODE_UNARY_REQUEST, OPCODE_UNARY_RESPONSE, decode_method_name,
    encode_method_name,
};

/// Maximum bytes we accept on а single inbound RPC stream — protects
/// against а malicious peer trying к exhaust memory by writing forever.
///
/// Large enough to comfortably hold any reasonable RPC payload (typed
/// proto messages are usually well under 1 MiB); requests that need
/// to ship more data should use streaming RPCs (Phase 3+) instead.
const RPC_STREAM_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Server-side dispatcher для bidi RPC streams.
///
/// Owns the shared [`IrohTransportClient`] handle plus the
/// [`MethodRegistry`] populated by application code. Call [`Self::serve`]
/// once at startup к register the [`WireDispatchHandler`] с nerw-core's
/// accept loop.
pub struct RpcServer {
    transport: IrohTransportClient,
    registry: Arc<MethodRegistry>,
}

impl RpcServer {
    /// Wire up the server with the given transport handle и method registry.
    ///
    /// Does NOT start dispatching yet — call [`Self::serve`] once к
    /// register the ALPN handler с nerw-core.
    #[must_use]
    pub const fn new(transport: IrohTransportClient, registry: Arc<MethodRegistry>) -> Self {
        Self {
            transport,
            registry,
        }
    }

    /// Borrow the underlying transport handle (test introspection).
    #[must_use]
    pub const fn transport(&self) -> &IrohTransportClient {
        &self.transport
    }

    /// Borrow the method registry (test introspection).
    #[must_use]
    pub fn registry(&self) -> &Arc<MethodRegistry> {
        &self.registry
    }

    /// Register the wire-protocol handler с nerw-core's accept loop.
    ///
    /// Idempotent — calling twice replaces the previous handler with а
    /// fresh one bound to the same registry. The ALPN
    /// [`ALPN_TOLKI_WIRE_PROTOCOL_2_0_0`] MUST have been declared в
    /// [`nerw_core::client::ClientConfigBuilder::with_alpn`] before
    /// [`nerw_core::client::Client::start`] — runtime extension is not
    /// supported (iroh locks the rustls server config's ALPN list at
    /// builder time).
    ///
    /// # Errors
    ///
    /// - [`RpcError::TransportRegisterAlpn`] when nerw-core rejects the
    ///   registration (ALPN was not pre-declared, or it conflicts с а
    ///   built-in nerw protocol — the message identifies which case).
    pub async fn serve(&self) -> RpcResult<()> {
        let handler: Arc<dyn AlpnHandler> = Arc::new(WireDispatchHandler {
            registry: Arc::clone(&self.registry),
        });
        self.transport
            .inner()
            .register_alpn_handler(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0.to_vec(), handler)
            .await
            .map_err(|e| RpcError::TransportRegisterAlpn {
                alpn: String::from_utf8_lossy(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0).into_owned(),
                reason: format!("{e}"),
            })?;
        debug!(
            alpn = %String::from_utf8_lossy(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0),
            "RpcServer registered ALPN handler",
        );
        Ok(())
    }
}

/// Internal [`AlpnHandler`] that drives а connection's `accept_bi` loop
/// and spawns а task per inbound stream.
///
/// Stored в an `Arc` inside nerw-core's handler registry; cloned per
/// inbound connection. The trait method `handle` is sync — we spawn the
/// async work onto the ambient tokio runtime.
struct WireDispatchHandler {
    registry: Arc<MethodRegistry>,
}

impl AlpnHandler for WireDispatchHandler {
    fn handle(&self, connection: Connection) {
        let registry = Arc::clone(&self.registry);
        tokio::spawn(async move {
            run_connection_loop(connection, registry).await;
        });
    }
}

/// Per-connection accept-bi loop. Fires а fresh handler task per stream
/// so concurrent requests on the same connection do not serialise.
async fn run_connection_loop(connection: Connection, registry: Arc<MethodRegistry>) {
    let remote = connection.remote_id();
    trace!(remote = %remote, "wire-protocol connection accepted, draining accept_bi");
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let registry = Arc::clone(&registry);
                let conn = connection.clone();
                tokio::spawn(async move {
                    handle_unary_stream(conn, send, recv, registry).await;
                });
            }
            Err(e) => {
                trace!(remote = %remote, error = %e, "accept_bi terminated");
                return;
            }
        }
    }
}

/// Handle one inbound unary RPC stream — read request, dispatch, write response.
async fn handle_unary_stream(
    connection: Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    registry: Arc<MethodRegistry>,
) {
    let remote = connection.remote_id();
    let buf = match recv.read_to_end(RPC_STREAM_READ_LIMIT).await {
        Ok(buf) => buf,
        Err(e) => {
            debug!(remote = %remote, error = %e, "inbound RPC stream: read_to_end failed");
            return;
        }
    };

    match dispatch_unary(&buf, connection.clone(), &registry).await {
        Ok(response_bytes) => {
            if let Err(e) = write_response(&mut send, &response_bytes).await {
                debug!(remote = %remote, error = %e, "failed to write success response");
            }
        }
        Err(err) => {
            // Best-effort — ignore write failure on the error frame itself.
            if let Err(e) = write_error(&mut send, &err).await {
                debug!(remote = %remote, error = %e, "failed to write error response");
            }
        }
    }
}

/// Decode the request frame, look up the handler, invoke it, and
/// return its bytes (or an [`RpcError`]).
async fn dispatch_unary(
    buf: &[u8],
    connection: Connection,
    registry: &MethodRegistry,
) -> RpcResult<Vec<u8>> {
    let (opcode, rest) = buf
        .split_first()
        .ok_or_else(|| RpcError::MalformedFrame("empty request frame".to_string()))?;
    if *opcode != OPCODE_UNARY_REQUEST {
        return Err(RpcError::MalformedFrame(format!(
            "expected unary-request opcode 0x{OPCODE_UNARY_REQUEST:02x}, got 0x{opcode:02x}",
        )));
    }

    let (method_name, payload) = decode_method_name(rest)?;
    let handler = registry
        .lookup(method_name)
        .ok_or_else(|| RpcError::UnknownMethod(method_name.to_string()))?;

    let ctx = build_inbound_context(&connection);
    handler.handle(ctx, payload).await
}

/// Build an [`RpcContext`] from а freshly-accepted connection.
fn build_inbound_context(connection: &Connection) -> RpcContext {
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0);

    let peer = PeerMetadata {
        node_id: connection.remote_id(),
        connection_id: 0,
        stream_id: 0,
        alpn: ALPN_TOLKI_WIRE_PROTOCOL_2_0_0.to_vec(),
        handshake_at_ms: now_ms,
        tls_cipher_suite: None,
    };

    RpcContext {
        peer,
        timing: TimingInfo {
            received_at_ms: now_ms,
            received_at_monotonic_ns: 0,
            frame_decode_duration_us: 0,
        },
        auth: None,
        session: None,
        tracing: TracingInfo::fresh(),
    }
}

/// Frame а success response: `[OPCODE_UNARY_RESPONSE | response_bytes]`.
async fn write_response(send: &mut iroh::endpoint::SendStream, response: &[u8]) -> RpcResult<()> {
    let mut buf = Vec::with_capacity(1 + response.len());
    buf.push(OPCODE_UNARY_RESPONSE);
    buf.extend_from_slice(response);
    send.write_all(&buf)
        .await
        .map_err(|e| RpcError::TransportWrite {
            reason: format!("{e}"),
        })?;
    send.finish().map_err(|e| RpcError::TransportWrite {
        reason: format!("finish: {e}"),
    })?;
    Ok(())
}

/// Frame an error response: `[OPCODE_UNARY_ERROR | postcard(error-string)]`.
///
/// Phase 2 ships а minimal error encoding — а single postcard-encoded
/// `String` describing the failure. Phase 3+ may upgrade this к а
/// richer typed-error encoding once the wire format stabilises.
async fn write_error(send: &mut iroh::endpoint::SendStream, err: &RpcError) -> RpcResult<()> {
    let body = err.to_string();
    let body_bytes = postcard::to_allocvec(&body).map_err(RpcError::Codec)?;
    let mut buf = Vec::with_capacity(1 + body_bytes.len());
    buf.push(OPCODE_UNARY_ERROR);
    buf.extend_from_slice(&body_bytes);
    send.write_all(&buf)
        .await
        .map_err(|e| RpcError::TransportWrite {
            reason: format!("{e}"),
        })?;
    if let Err(e) = send.finish() {
        warn!(error = %e, "finishing error response stream failed");
    }
    Ok(())
}

/// Build а complete unary-request frame. Helper used by
/// [`crate::client::RpcClient`] и by integration tests.
///
/// `[OPCODE_UNARY_REQUEST | varint(name_len) | method-name UTF-8 | request_bytes]`
///
/// # Errors
///
/// Returns [`RpcError::MalformedFrame`] if the LEB128 length-prefix
/// encoding fails (effectively never for an in-memory `Vec`, kept honest
/// for forward-compat).
#[allow(dead_code)] // consumed by client.rs (next commit)
pub(crate) fn build_unary_request_frame(
    method_name: &str,
    request_bytes: &[u8],
) -> RpcResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(1 + 5 + method_name.len() + request_bytes.len());
    buf.push(OPCODE_UNARY_REQUEST);
    encode_method_name(method_name, &mut buf)?;
    buf.extend_from_slice(request_bytes);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_unary_request_frame_includes_opcode_name_and_payload() {
        let frame =
            build_unary_request_frame("tolki:hello@1.0.0/test/echo", b"PAYLOAD").expect("frame");
        assert_eq!(frame[0], OPCODE_UNARY_REQUEST);
        // Round-trip: skip opcode, parse method-name, payload should follow.
        let (name, rest) = decode_method_name(&frame[1..]).expect("decode");
        assert_eq!(name, "tolki:hello@1.0.0/test/echo");
        assert_eq!(rest, b"PAYLOAD");
    }

    #[test]
    fn build_unary_request_frame_with_empty_payload() {
        let frame = build_unary_request_frame("tolki:x@1.0.0/i/m", &[]).expect("frame");
        assert_eq!(frame[0], OPCODE_UNARY_REQUEST);
        let (name, rest) = decode_method_name(&frame[1..]).expect("decode");
        assert_eq!(name, "tolki:x@1.0.0/i/m");
        assert!(rest.is_empty());
    }
}
