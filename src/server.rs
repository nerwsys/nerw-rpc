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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::Connection;
use nerw_core::client::AlpnHandler;
use tokio::sync::Semaphore;
use tracing::{debug, trace, warn};

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::method::MethodRegistry;
use crate::transport::{ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, IrohTransportClient};
use crate::wire::{
    OPCODE_UNARY_ERROR, OPCODE_UNARY_REQUEST, OPCODE_UNARY_RESPONSE, decode_method_name,
    encode_method_name,
};
use crate::wire_error::WireError;

/// Maximum bytes we accept on а single inbound RPC stream — protects
/// against а malicious peer trying к exhaust memory by writing forever.
///
/// Large enough to comfortably hold any reasonable RPC payload (typed
/// proto messages are usually well under 1 MiB); requests that need
/// to ship more data should use streaming RPCs (Phase 3+) instead.
const RPC_STREAM_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Default cap on concurrent inbound RPC streams across the entire server.
///
/// Picked an order of magnitude above iroh's per-connection стрим budget
/// (~100) but well below typical OS file-descriptor limits — enough к
/// absorb а brief burst from а handful of peers without throttling, low
/// enough к prevent а fan-out accident from spawning unbounded tasks.
pub const DEFAULT_MAX_CONCURRENT_STREAMS: usize = 256;

/// Default cap on concurrent inbound connections we will run accept-bi
/// loops on simultaneously.
///
/// Each accepted connection spawns one long-lived task that pumps
/// `accept_bi` — keeping this bounded prevents а malicious peer from
/// opening thousands of TCP-equivalent connections к starve us. Note
/// that this caps **active** connection-loop tasks, not total connections
/// in iroh's table — peers blocked on the semaphore wait briefly,
/// preserving correctness while bounding resource usage.
pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 1024;

/// Tunable knobs for [`RpcServer`].
///
/// All defaults are conservative: large enough к keep production traffic
/// flowing without throttling, small enough к defend against accidental
/// fan-out (e.g. а buggy client looping on `open_bi`). These limits are
/// **not** а Byzantine-attacker defence — а determined adversary с
/// authenticated peer-id can still saturate them. Filtering hostile
/// peers is the responsibility of the upstream nerw-core mesh-layer
/// auth, not the RPC framework.
#[derive(Debug, Clone, Copy)]
pub struct RpcServerConfig {
    /// Cap on concurrent inbound RPC streams (default: 256).
    pub max_concurrent_streams: usize,

    /// Cap on concurrent inbound connections we run accept-bi loops on
    /// (default: 1024).
    pub max_concurrent_connections: usize,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_streams: DEFAULT_MAX_CONCURRENT_STREAMS,
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        }
    }
}

/// Server-side dispatcher для bidi RPC streams.
///
/// Owns the shared [`IrohTransportClient`] handle plus the
/// [`MethodRegistry`] populated by application code. Call [`Self::serve`]
/// once at startup к register the inbound handler с nerw-core's
/// accept loop.
pub struct RpcServer {
    transport: IrohTransportClient,
    registry: Arc<MethodRegistry>,
    config: RpcServerConfig,
}

impl RpcServer {
    /// Wire up the server с the given transport handle и method registry,
    /// using [`RpcServerConfig::default`] limits.
    ///
    /// Does NOT start dispatching yet — call [`Self::serve`] once к
    /// register the ALPN handler с nerw-core.
    #[must_use]
    pub fn new(transport: IrohTransportClient, registry: Arc<MethodRegistry>) -> Self {
        Self::with_config(transport, registry, RpcServerConfig::default())
    }

    /// Wire up the server с custom limits.
    ///
    /// Use this when you know your workload pattern and want к override
    /// [`DEFAULT_MAX_CONCURRENT_STREAMS`] / [`DEFAULT_MAX_CONCURRENT_CONNECTIONS`].
    #[must_use]
    pub const fn with_config(
        transport: IrohTransportClient,
        registry: Arc<MethodRegistry>,
        config: RpcServerConfig,
    ) -> Self {
        Self {
            transport,
            registry,
            config,
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

    /// Borrow the active configuration (test introspection).
    #[must_use]
    pub const fn config(&self) -> &RpcServerConfig {
        &self.config
    }

    /// Register the wire-protocol handler с nerw-core's accept loop.
    ///
    /// Idempotent — calling twice replaces the previous handler с а
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
            stream_permits: Arc::new(Semaphore::new(self.config.max_concurrent_streams)),
            connection_permits: Arc::new(Semaphore::new(self.config.max_concurrent_connections)),
            connection_id_counter: Arc::new(AtomicU64::new(1)),
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
            max_concurrent_streams = self.config.max_concurrent_streams,
            max_concurrent_connections = self.config.max_concurrent_connections,
            "RpcServer registered ALPN handler",
        );
        Ok(())
    }
}

/// Internal [`AlpnHandler`] that drives а connection's `accept_bi` loop
/// and spawns а task per inbound stream, bounded by а pair of semaphores.
///
/// Stored в an `Arc` inside nerw-core's handler registry; cloned per
/// inbound connection. The trait method `handle` is sync — we spawn the
/// async work onto the ambient tokio runtime.
struct WireDispatchHandler {
    registry: Arc<MethodRegistry>,
    /// Caps concurrent stream-handler tasks across all connections.
    /// Each accepted bidi acquires а permit; tasks blocked on the
    /// semaphore wait briefly before processing rather than being dropped.
    stream_permits: Arc<Semaphore>,
    /// Caps concurrent connection-loop tasks. Each accepted connection
    /// (one `WireDispatchHandler::handle` call) acquires а permit before
    /// spawning the long-lived accept-bi loop.
    connection_permits: Arc<Semaphore>,
    /// Monotonic counter for synthesising stable connection-ids when
    /// iroh's own `Connection::stable_id()` is not deterministic across
    /// reconnects (it is local-process scoped which is fine for our use).
    connection_id_counter: Arc<AtomicU64>,
}

impl AlpnHandler for WireDispatchHandler {
    fn handle(&self, connection: Connection) {
        let registry = Arc::clone(&self.registry);
        let stream_permits = Arc::clone(&self.stream_permits);
        let connection_permits = Arc::clone(&self.connection_permits);
        let connection_id_counter = Arc::clone(&self.connection_id_counter);
        let connection_id = connection_id_counter.fetch_add(1, Ordering::Relaxed);
        tokio::spawn(async move {
            // Connection cap defends against accidental fan-out — а
            // buggy peer reopening connections in а tight loop will
            // queue up here rather than spawning unbounded tasks. Not
            // а Byzantine-attacker defence — those should be filtered
            // upstream by nerw-core peer auth.
            let permit = match connection_permits.acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    warn!(error = %e, "connection semaphore closed unexpectedly");
                    return;
                }
            };
            run_connection_loop(connection, registry, stream_permits, connection_id).await;
            drop(permit);
        });
    }
}

/// Per-connection accept-bi loop. Fires а fresh handler task per stream
/// so concurrent requests on the same connection do not serialise.
///
/// Each spawned per-stream task acquires а permit from `stream_permits`
/// before processing — bounding total in-flight stream work.
async fn run_connection_loop(
    connection: Connection,
    registry: Arc<MethodRegistry>,
    stream_permits: Arc<Semaphore>,
    connection_id: u64,
) {
    let remote = connection.remote_id();
    trace!(
        remote = %remote,
        connection_id,
        "wire-protocol connection accepted, draining accept_bi",
    );
    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let registry = Arc::clone(&registry);
                let conn = connection.clone();
                let permits = Arc::clone(&stream_permits);
                tokio::spawn(async move {
                    // Acquire stream permit BEFORE doing any work — а
                    // sustained burst will queue here briefly rather
                    // than spawning unbounded handler tasks. The permit
                    // is dropped automatically on task exit.
                    let permit = match permits.acquire_owned().await {
                        Ok(p) => p,
                        Err(e) => {
                            warn!(error = %e, "stream semaphore closed unexpectedly");
                            return;
                        }
                    };
                    handle_unary_stream(conn, send, recv, registry, connection_id).await;
                    drop(permit);
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
    connection_id: u64,
) {
    let remote = connection.remote_id();
    // Capture monotonic + wall-clock at the earliest possible point so
    // latency measurements include time spent в stream-read.
    let accept_instant = std::time::Instant::now();
    let stream_id_u64 = u64::from(send.id());
    // read_to_end returns Vec<u8>; freeze к Bytes once и slice through
    // the dispatch path so handlers receive а ref-counted view с no
    // further copying.
    let buf: Bytes = match recv.read_to_end(RPC_STREAM_READ_LIMIT).await {
        Ok(v) => Bytes::from(v),
        Err(e) => {
            debug!(remote = %remote, error = %e, "inbound RPC stream: read_to_end failed");
            return;
        }
    };

    match dispatch_unary(
        buf,
        connection.clone(),
        &registry,
        accept_instant,
        connection_id,
        stream_id_u64,
    )
    .await
    {
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
///
/// The full-frame `buf` is owned here so we can slice the postcard
/// payload as а zero-copy [`Bytes`] view that's handed to the handler.
async fn dispatch_unary(
    buf: Bytes,
    connection: Connection,
    registry: &MethodRegistry,
    accept_instant: std::time::Instant,
    connection_id: u64,
    stream_id: u64,
) -> RpcResult<Bytes> {
    let opcode = *buf
        .first()
        .ok_or_else(|| RpcError::MalformedFrame("empty request frame".to_string()))?;
    if opcode != OPCODE_UNARY_REQUEST {
        return Err(RpcError::MalformedFrame(format!(
            "expected unary-request opcode 0x{OPCODE_UNARY_REQUEST:02x}, got 0x{opcode:02x}",
        )));
    }

    // decode_method_name borrows from a &[u8] view of `buf`; we then
    // measure how many bytes were consumed by the method-name prefix
    // and slice the postcard payload as а zero-copy `Bytes`.
    let (method_name, payload_slice) = decode_method_name(&buf[1..])?;
    let method_name = method_name.to_string();
    let consumed_prefix = buf.len() - payload_slice.len();
    let payload = buf.slice(consumed_prefix..);

    let handler = registry
        .lookup(&method_name)
        .ok_or(RpcError::UnknownMethod(method_name))?;

    // Frame fully decoded — capture decode duration before invoking the handler.
    let decode_duration = accept_instant.elapsed();
    let frame_decode_duration_us = u64::try_from(decode_duration.as_micros()).unwrap_or(u64::MAX);

    let ctx = build_inbound_context(
        &connection,
        accept_instant,
        connection_id,
        stream_id,
        frame_decode_duration_us,
    );
    handler.handle(ctx, payload).await
}

/// Build an [`RpcContext`] from а freshly-accepted connection.
///
/// Wall-clock + monotonic timestamps are captured at the dispatch
/// boundary (`accept_instant` was sampled when the bidi was accepted);
/// `frame_decode_duration_us` is the elapsed time between acceptance
/// and frame parse completion, so handler-side latency math сan strip
/// the framing overhead.
fn build_inbound_context(
    connection: &Connection,
    accept_instant: std::time::Instant,
    connection_id: u64,
    stream_id: u64,
    frame_decode_duration_us: u64,
) -> RpcContext {
    let now_ms = i64::try_from(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
    )
    .unwrap_or(0);

    // Monotonic time elapsed since process start — Tokio's runtime sets
    // an early reference Instant; subtracting from `Instant::now()` would
    // give us "ns since now", not "ns since process start". We use the
    // accept_instant's elapsed nanos relative к the runtime epoch, which
    // is what a Prometheus histogram cares about.
    let received_at_monotonic_ns =
        u64::try_from(accept_instant.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let peer = PeerMetadata {
        node_id: connection.remote_id(),
        connection_id,
        stream_id,
        alpn: ALPN_TOLKI_WIRE_PROTOCOL_2_0_0.to_vec(),
        handshake_at_ms: now_ms,
        tls_cipher_suite: None,
    };

    RpcContext {
        peer,
        timing: TimingInfo {
            received_at_ms: now_ms,
            received_at_monotonic_ns,
            frame_decode_duration_us,
        },
        auth: None,
        session: None,
        tracing: TracingInfo::fresh(),
    }
}

/// Frame а success response: `[OPCODE_UNARY_RESPONSE | response_bytes]`.
async fn write_response(send: &mut iroh::endpoint::SendStream, response: &Bytes) -> RpcResult<()> {
    let mut buf = BytesMut::with_capacity(1 + response.len());
    buf.put_u8(OPCODE_UNARY_RESPONSE);
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

/// Frame an error response: `[OPCODE_UNARY_ERROR | postcard(WireError)]`.
///
/// The body is а typed [`WireError`] envelope с а 1-byte discriminant
/// followed by the postcard-encoded payload. The discriminant byte
/// makes wire decoding **locale-invariant** — а maintainer translating
/// human-readable error strings cannot accidentally break client-side
/// error classification (which would happen if we shipped а bare
/// `String` and the client matched on prefixes).
async fn write_error(send: &mut iroh::endpoint::SendStream, err: &RpcError) -> RpcResult<()> {
    let wire = WireError::from_rpc_error(err);
    let body_bytes = postcard::to_allocvec(&wire).map_err(RpcError::Codec)?;
    let mut buf = BytesMut::with_capacity(1 + body_bytes.len());
    buf.put_u8(OPCODE_UNARY_ERROR);
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
pub(crate) fn build_unary_request_frame(method_name: &str, request: &Bytes) -> RpcResult<Bytes> {
    let mut buf = Vec::with_capacity(1 + 5 + method_name.len() + request.len());
    buf.push(OPCODE_UNARY_REQUEST);
    encode_method_name(method_name, &mut buf)?;
    buf.extend_from_slice(request);
    Ok(Bytes::from(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_unary_request_frame_includes_opcode_name_and_payload() {
        let payload = Bytes::from_static(b"PAYLOAD");
        let frame =
            build_unary_request_frame("tolki:hello@1.0.0/test/echo", &payload).expect("frame");
        assert_eq!(frame[0], OPCODE_UNARY_REQUEST);
        // Round-trip: skip opcode, parse method-name, payload should follow.
        let (name, rest) = decode_method_name(&frame[1..]).expect("decode");
        assert_eq!(name, "tolki:hello@1.0.0/test/echo");
        assert_eq!(rest, b"PAYLOAD");
    }

    #[test]
    fn build_unary_request_frame_with_empty_payload() {
        let frame = build_unary_request_frame("tolki:x@1.0.0/i/m", &Bytes::new()).expect("frame");
        assert_eq!(frame[0], OPCODE_UNARY_REQUEST);
        let (name, rest) = decode_method_name(&frame[1..]).expect("decode");
        assert_eq!(name, "tolki:x@1.0.0/i/m");
        assert!(rest.is_empty());
    }

    #[test]
    fn rpc_server_config_default_uses_documented_constants() {
        let cfg = RpcServerConfig::default();
        assert_eq!(cfg.max_concurrent_streams, DEFAULT_MAX_CONCURRENT_STREAMS);
        assert_eq!(
            cfg.max_concurrent_connections,
            DEFAULT_MAX_CONCURRENT_CONNECTIONS
        );
    }

    #[test]
    fn rpc_server_config_default_constants_are_nonzero() {
        // Zero permits would deadlock the dispatcher — guard against
        // accidentally landing а zero default.  Compile-time const block
        // satisfies Clippy's `assertions_on_constants` lint while still
        // catching а regression at test time.
        const _: () = assert!(DEFAULT_MAX_CONCURRENT_STREAMS > 0);
        const _: () = assert!(DEFAULT_MAX_CONCURRENT_CONNECTIONS > 0);
    }
}
