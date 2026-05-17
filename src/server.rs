//! [`RpcServer`] — the inbound-side of nerw-rpc.
//!
//! Owns an internal ALPN dispatch table и drives nerw-core's accept
//! loop directly. Inbound connections matching
//! [`crate::transport::ALPN_NERW_RPC_1_0_0`] are dispatched
//! к the private wire-protocol handler, which decodes per-stream RPC
//! frames against а shared [`crate::method::MethodRegistry`]. Advanced
//! callers can additionally register their own
//! [`crate::transport::AlpnHandler`]s for application-specific ALPNs
//! they declared upfront via
//! [`nerw_core::client::ClientConfigBuilder::with_alpn`].
//!
//! ## Inbound flow (per stream)
//!
//! 1. Peer opens а bidi substream к our [`iroh::Endpoint`] negotiated с
//!    `nerw/rpc/1.0.0`.
//! 2. The server's accept loop dispatches the connection к the internal
//!    wire-dispatch handler via the [`AlpnHandler`] trait.
//! 3. The handler spawns а per-connection task that pumps `accept_bi()`
//!    в а loop. Each accepted bidi stream becomes а fresh
//!    request-handling task.
//! 4. Per-stream task reads the request frame:
//!    `[opcode_unary_request | varint(name_len) | method-name UTF-8 | postcard(payload)]`
//! 5. Looks up the handler в the [`MethodRegistry`].
//! 6. Builds an [`RpcContext`] from the connection's
//!    [`iroh::endpoint::Connection::remote_id`] и timing.
//! 7. Invokes the handler.
//! 8. Writes the response: `[opcode_response | postcard(bytes)]`
//!    on success, or `[opcode_error | postcard(error-string)]` on
//!    failure (handler error / unknown method / decode error).
//! 9. Calls `SendStream::finish()` так что the peer's `read_to_end` returns.
//!
//! ## Why а fresh task per stream
//!
//! iroh's `Connection::accept_bi` returns one bidi at а time; each
//! request is independent. Spawning per-stream lets concurrent
//! requests on the same connection (long-running handler + quick poll)
//! не block each other.
//!
//! ## Why а server-owned accept loop (Phase 2.1)
//!
//! After R3 (commit `48ec369`) nerw-core no longer owns an internal
//! accept loop / handler registry — `Client::accept` is а raw
//! delegation к `iroh::Endpoint::accept`. [`RpcServer`] drives that
//! surface directly, dispatching by ALPN against an internal
//! [`DashMap<Vec<u8>, Arc<dyn AlpnHandler>>`]. nerw-daemon's wire layer
//! does the same dance for the mesh-control protocols — the two
//! dispatchers are intentionally independent so RPC framework consumers
//! не link the daemon crate.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use async_trait::async_trait;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use iroh::endpoint::Connection;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::method::MethodRegistry;
use crate::streaming::{
    self, StreamingFrame, StreamingMethodHandler, StreamingOpenResponse, StreamingOpenStatus,
};
use crate::transport::{ALPN_NERW_RPC_1_0_0, AlpnHandler, IrohTransportClient};
use crate::wire::{
    OPCODE_STREAMING_OPEN_REQUEST, OPCODE_UNARY_ERROR, OPCODE_UNARY_REQUEST, OPCODE_UNARY_RESPONSE,
    decode_method_name, encode_method_name,
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

/// QUIC application-layer close code for "no handler registered".
///
/// Peer attempted а connection on an ALPN with no registered handler.
/// The inbound side closes the connection immediately so the peer learns
/// the protocol is unbound rather than hanging on а silently-discarded
/// handshake.
///
/// Surfaced as а named constant so future close-code allocations are
/// visible в one place, and accidental collisions across call sites
/// fail at compile time.
const CLOSE_NO_HANDLER: u32 = 1;

/// Internal type alias for the ALPN handler dispatch table.
///
/// Keyed by ALPN bytes; value is the `Arc<dyn AlpnHandler>` to run на
/// inbound connections that negotiated that ALPN. Shared between
/// [`RpcServer`] (where registration happens) and the accept-loop task
/// (where dispatch happens) via `Arc::clone`.
type AlpnHandlerTable = Arc<DashMap<Vec<u8>, Arc<dyn AlpnHandler>>>;

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

/// Server-side dispatcher для inbound iroh connections.
///
/// Owns the shared [`IrohTransportClient`] handle plus the
/// [`MethodRegistry`] populated by application code. Call [`Self::serve`]
/// once at startup к bind the wire-protocol handler и spawn the
/// accept loop; advanced callers can additionally register their own
/// [`AlpnHandler`]s via [`Self::register_alpn_handler`] before serving.
///
/// The accept loop runs as long as the underlying iroh endpoint is open
/// — calling [`nerw_core::client::Client::shutdown`] terminates it
/// gracefully.  Dropping the server aborts the loop task immediately;
/// production callers should keep the [`RpcServer`] alive for the
/// lifetime of the endpoint.
pub struct RpcServer {
    /// Iroh-backed transport handle shared с the accept loop.
    transport: IrohTransportClient,
    /// Per-method handler registry populated by application code at
    /// startup. `Arc` because the accept loop spawns one task per
    /// connection и each task needs а cheap clone.
    registry: Arc<MethodRegistry>,
    /// Concurrency limits + timeout configuration (see [`RpcServerConfig`]).
    config: RpcServerConfig,
    /// Internal ALPN dispatch table — keyed by negotiated ALPN bytes.
    /// [`Self::serve`] installs the built-in wire-protocol handler;
    /// callers can add more via [`Self::register_alpn_handler`].
    alpn_handlers: AlpnHandlerTable,
    /// Handle к the spawned accept loop task, wrapped в а sync mutex
    /// so [`Self::serve`] takes `&self` (not `&mut self`) и preserves
    /// the Phase 2 public API. `None` before [`Self::serve`] runs;
    /// `Some` afterwards. Aborted on `Drop` so the loop exits cleanly
    /// с the server.
    ///
    /// **Mutex choice rationale:** [`std::sync::Mutex`] (not
    /// [`once_cell::sync::OnceCell`]) — `serve()` returns
    /// [`RpcError::AlreadyServing`] on the second call rather than
    /// panicking, so the slot is logically «check-and-fill» с а typed
    /// failure path. The mutex is locked exactly twice over the server's
    /// lifetime (once в [`Self::serve`], once в [`Drop`]); contention
    /// is statically impossible — no two threads ever race on it.
    accept_loop: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for RpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `accept_loop` is а sync mutex; lock briefly to read the slot.
        // А poisoned guard still yields `Some`/`None` correctly — we
        // use `.lock().ok()` so Debug never panics on poisoning, which
        // would mask the real failure being formatted.
        let running = self
            .accept_loop
            .lock()
            .ok()
            .as_deref()
            .is_some_and(Option::is_some);
        f.debug_struct("RpcServer")
            .field("transport", &self.transport)
            .field("config", &self.config)
            .field("registered_alpns", &self.alpn_handlers.len())
            .field("accept_loop_running", &running)
            .finish_non_exhaustive()
    }
}

impl RpcServer {
    /// Wire up the server с the given transport handle и method registry,
    /// using [`RpcServerConfig::default`] limits.
    ///
    /// Does NOT start dispatching yet — call [`Self::serve`] once к
    /// install the wire-protocol handler и spawn the accept loop.
    #[must_use]
    pub fn new(transport: IrohTransportClient, registry: Arc<MethodRegistry>) -> Self {
        Self::with_config(transport, registry, RpcServerConfig::default())
    }

    /// Wire up the server с custom limits.
    ///
    /// Use this when you know your workload pattern и want к override
    /// [`DEFAULT_MAX_CONCURRENT_STREAMS`] / [`DEFAULT_MAX_CONCURRENT_CONNECTIONS`].
    #[must_use]
    pub fn with_config(
        transport: IrohTransportClient,
        registry: Arc<MethodRegistry>,
        config: RpcServerConfig,
    ) -> Self {
        Self {
            transport,
            registry,
            config,
            alpn_handlers: Arc::new(DashMap::new()),
            accept_loop: Mutex::new(None),
        }
    }

    /// Borrow the underlying transport handle (test introspection).
    #[must_use]
    pub const fn transport(&self) -> &IrohTransportClient {
        &self.transport
    }

    /// Borrow the method registry (test introspection).
    #[must_use]
    pub const fn registry(&self) -> &Arc<MethodRegistry> {
        &self.registry
    }

    /// Borrow the active configuration (test introspection).
    #[must_use]
    pub const fn config(&self) -> &RpcServerConfig {
        &self.config
    }

    /// Number of currently-registered [`AlpnHandler`]s (test
    /// introspection). Includes the built-in wire-protocol handler
    /// once [`Self::serve`] has been called.
    #[must_use]
    pub fn registered_alpn_count(&self) -> usize {
        self.alpn_handlers.len()
    }

    /// Register an additional [`AlpnHandler`] для an application-specific
    /// ALPN. The ALPN MUST have been declared upfront via
    /// [`nerw_core::client::ClientConfigBuilder::with_alpn`] before
    /// [`nerw_core::client::Client::start`] — iroh's rustls server config
    /// locks the ALPN list at builder time.
    ///
    /// Calling this with the wire-protocol ALPN overwrites the built-in
    /// handler — almost certainly а bug, so the framework does not
    /// special-case the collision (the second insertion wins silently,
    /// which is intentional: replacing the wire handler is а legitimate
    /// (if rare) test-fixture use case).
    pub fn register_alpn_handler(&self, alpn: &[u8], handler: Arc<dyn AlpnHandler>) {
        self.alpn_handlers.insert(alpn.to_vec(), handler);
    }

    /// Install the wire-protocol handler и spawn the accept loop.
    ///
    /// Takes `&self` so callers can keep the server behind an `Arc` —
    /// the accept-loop [`JoinHandle`] lives behind an internal
    /// [`std::sync::Mutex`]. Calling [`Self::serve`] а second time on
    /// the same instance returns [`RpcError::AlreadyServing`] rather
    /// than spawning а duplicate loop (two loops would race on
    /// `Client::accept` и leak the prior handle).
    ///
    /// The ALPN [`ALPN_NERW_RPC_1_0_0`] MUST have been declared
    /// в [`nerw_core::client::ClientConfigBuilder::with_alpn`] before
    /// [`nerw_core::client::Client::start`] — runtime extension is not
    /// supported (iroh locks the rustls server config's ALPN list at
    /// builder time). Inbound connections with an undeclared ALPN are
    /// dropped by iroh before they reach our handler table.
    ///
    /// # Errors
    ///
    /// - [`RpcError::AlreadyServing`] — [`Self::serve`] has already
    ///   spawned an accept loop on this instance. Spawning а second
    ///   loop would leak the prior `JoinHandle` and race on
    ///   `Client::accept`.
    ///
    /// The method remains `async` so future variants (e.g. binding to
    /// multiple endpoints, validating that ALPNs are pre-declared) can
    /// surface errors без а wire-breaking change. Phase 2's
    /// implementation awaited `register_alpn_handler` (now gone); the
    /// async signature is preserved so consumers calling
    /// `.serve().await` continue compiling без а wire-breaking change.
    /// Clippy's `unused_async` lint is suppressed at the call site.
    #[allow(clippy::unused_async)]
    pub async fn serve(&self) -> RpcResult<()> {
        // Reserve the accept-loop slot BEFORE installing the wire
        // handler so а second `serve()` call cannot leave the handler
        // table partially mutated. The mutex is locked briefly only
        // for the check-and-fill; no .await happens while holding it.
        //
        // Mutex poisoning surfaces as а panic here only if а prior
        // panic was caught mid-mutation — а separate bug deserving its
        // own crash report. We propagate via `expect` rather than
        // returning а typed error: there is no recoverable action а
        // caller can take, и the poisoning itself is the diagnostic.
        #[allow(clippy::expect_used)] // Poisoning = unrecoverable bug; see above.
        let mut slot = self
            .accept_loop
            .lock()
            .expect("RpcServer accept_loop mutex poisoned");
        if slot.is_some() {
            return Err(RpcError::AlreadyServing);
        }

        // Install the built-in wire-protocol handler.
        let wire_handler: Arc<dyn AlpnHandler> = Arc::new(WireDispatchHandler {
            registry: Arc::clone(&self.registry),
            stream_permits: Arc::new(Semaphore::new(self.config.max_concurrent_streams)),
            connection_permits: Arc::new(Semaphore::new(self.config.max_concurrent_connections)),
            connection_id_counter: Arc::new(AtomicU64::new(1)),
        });
        self.alpn_handlers
            .insert(ALPN_NERW_RPC_1_0_0.to_vec(), wire_handler);

        // Spawn the accept loop. The handle is owned by the server; on
        // drop it aborts so the loop exits cleanly.
        let client = Arc::clone(self.transport.inner());
        let handlers = Arc::clone(&self.alpn_handlers);
        let handle = tokio::spawn(run_accept_loop(client, handlers));
        *slot = Some(handle);
        drop(slot);

        debug!(
            alpn = %String::from_utf8_lossy(ALPN_NERW_RPC_1_0_0),
            max_concurrent_streams = self.config.max_concurrent_streams,
            max_concurrent_connections = self.config.max_concurrent_connections,
            "RpcServer wire handler installed and accept loop spawned",
        );
        Ok(())
    }
}

impl Drop for RpcServer {
    fn drop(&mut self) {
        // `Mutex::get_mut` avoids а lock-acquire on drop — we have
        // exclusive access through `&mut self`, so there cannot be
        // а concurrent owner. Poisoning surfaces only if а prior
        // panic damaged the mutex; `get_mut().ok()` degrades gracefully
        // — а poisoned slot whose handle we cannot reach simply leaks
        // the spawned task to abort itself when iroh closes the endpoint,
        // matching the pre-refactor behaviour on drop-during-panic.
        if let Ok(slot) = self.accept_loop.get_mut()
            && let Some(handle) = slot.take()
        {
            // Aborting is sufficient — the spawned loop holds an
            // `Arc<Client>` clone, не the lone owner, so socket teardown
            // is the caller's responsibility (via `Client::shutdown`).
            handle.abort();
        }
    }
}

/// Drain the iroh endpoint's accept stream, dispatching each inbound
/// connection by negotiated ALPN.
///
/// `handlers` is shared с [`RpcServer`] — registrations land в the
/// same `DashMap`. Lookup is scoped (we don't hold the entry across
/// `.await` on the handler call) so concurrent `register_alpn_handler`
/// calls during accept are safe.
async fn run_accept_loop(client: Arc<nerw_core::client::Client>, handlers: AlpnHandlerTable) {
    loop {
        let Some(incoming) = client.accept().await else {
            debug!("RpcServer accept loop: endpoint closed");
            return;
        };
        let handlers = Arc::clone(&handlers);
        // Fire-and-forget per-connection task — а slow handler cannot
        // starve subsequent inbound arrivals.
        tokio::spawn(async move {
            let mut accepting = match incoming.accept() {
                Ok(a) => a,
                Err(e) => {
                    debug!(error = %e, "incoming.accept() failed");
                    return;
                }
            };
            let alpn = match accepting.alpn().await {
                Ok(a) => a,
                Err(e) => {
                    debug!(error = %e, "accepting.alpn() failed");
                    return;
                }
            };
            let conn = match accepting.await {
                Ok(c) => c,
                Err(e) => {
                    debug!(error = %e, "incoming connection failed handshake");
                    return;
                }
            };

            // Lookup, clone the Arc, drop the DashMap guard BEFORE
            // running the handler.
            let handler = handlers.get(&alpn).map(|entry| Arc::clone(&entry));
            if let Some(h) = handler {
                if let Err(e) = h.handle(conn).await {
                    debug!(
                        alpn = %String::from_utf8_lossy(&alpn),
                        error = %e,
                        "ALPN handler returned an error",
                    );
                }
            } else {
                debug!(
                    alpn = %String::from_utf8_lossy(&alpn),
                    "no nerw-rpc handler registered for ALPN — closing connection",
                );
                conn.close(CLOSE_NO_HANDLER.into(), b"no-handler-registered");
            }
        });
    }
}

/// Internal [`AlpnHandler`] for the `nerw/rpc/1.0.0` ALPN.
///
/// Drives а connection's `accept_bi` loop и spawns а task per inbound
/// stream, bounded by а pair of semaphores. Stored в the
/// `alpn_handlers` `DashMap` inside [`RpcServer`]; cloned per inbound
/// connection.
struct WireDispatchHandler {
    /// Shared handler lookup table populated by application code.
    registry: Arc<MethodRegistry>,
    /// Caps concurrent stream-handler tasks across all connections.
    /// Each accepted bidi acquires а permit; tasks blocked on the
    /// semaphore wait briefly before processing rather than being dropped.
    stream_permits: Arc<Semaphore>,
    /// Caps concurrent connection-loop tasks. Each accepted connection
    /// acquires а permit before spawning the long-lived accept-bi loop.
    connection_permits: Arc<Semaphore>,
    /// Monotonic counter for synthesising stable connection-ids когда
    /// iroh's own `Connection::stable_id()` is not deterministic across
    /// reconnects (it is local-process scoped, which is fine для our use).
    connection_id_counter: Arc<AtomicU64>,
}

#[async_trait]
impl AlpnHandler for WireDispatchHandler {
    async fn handle(&self, connection: Connection) -> RpcResult<()> {
        let registry = Arc::clone(&self.registry);
        let stream_permits = Arc::clone(&self.stream_permits);
        let connection_id = self.connection_id_counter.fetch_add(1, Ordering::Relaxed);
        // Connection cap defends against accidental fan-out — а buggy
        // peer reopening connections в а tight loop will queue up here
        // rather than spawning unbounded tasks. Not а Byzantine-attacker
        // defence — those should be filtered upstream by nerw-core peer
        // auth.
        let permit = match Arc::clone(&self.connection_permits).acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "connection semaphore closed unexpectedly");
                return Ok(());
            }
        };
        run_connection_loop(connection, registry, stream_permits, connection_id).await;
        drop(permit);
        Ok(())
    }
}

/// Per-connection accept-bi loop. Fires а fresh handler task per stream
/// так concurrent requests on the same connection do not serialise.
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
                    handle_inbound_substream(conn, send, recv, registry, connection_id).await;
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

/// Handle one inbound unary RPC stream — read request, dispatch, write
/// response.
///
/// Public entry point so downstream daemon crates can drive the
/// unary-stream protocol from their own ALPN dispatchers без having
/// к re-implement the wire framing. The function reads the request
/// frame off `recv`, looks up the method on `registry`, invokes the
/// handler с а freshly-built [`RpcContext`], and writes either а
/// success или typed-error response frame back на `send`.
///
/// Errors are logged at `debug` level и not propagated — the stream
/// is best-effort; а serialization failure mid-flight is no different
/// from а dropped QUIC stream и handled the same way (the caller's
/// `read_to_end` returns short и they observe the loss).
pub async fn handle_unary_stream_public(
    connection: Connection,
    send: iroh::endpoint::SendStream,
    recv: iroh::endpoint::RecvStream,
    registry: Arc<MethodRegistry>,
    connection_id: u64,
) {
    handle_inbound_substream(connection, send, recv, registry, connection_id).await;
}

/// Dispatch one inbound substream by peeking its first opcode byte.
///
/// `OPCODE_UNARY_REQUEST` (0x00) routes к the unary read-to-end path
/// (existing v0.8.x behaviour). `OPCODE_STREAMING_OPEN_REQUEST` (0x10)
/// routes к the new streaming dispatch (v0.9.0). Any other opening
/// byte yields а malformed-frame error written back as а unary error
/// frame so the client surfaces it cleanly.
async fn handle_inbound_substream(
    connection: Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    registry: Arc<MethodRegistry>,
    connection_id: u64,
) {
    let remote = connection.remote_id();
    let accept_instant = std::time::Instant::now();
    let stream_id_u64 = u64::from(send.id());

    let mut opcode_buf = [0_u8; 1];
    if let Err(e) = recv.read_exact(&mut opcode_buf).await {
        debug!(remote = %remote, error = %e, "inbound RPC stream: failed to read opening opcode");
        return;
    }
    let opcode = opcode_buf[0];

    if opcode == OPCODE_STREAMING_OPEN_REQUEST {
        handle_streaming_substream(
            connection,
            send,
            recv,
            registry,
            accept_instant,
            connection_id,
            stream_id_u64,
        )
        .await;
        return;
    }

    if opcode != OPCODE_UNARY_REQUEST {
        let err = RpcError::MalformedFrame(format!(
            "expected unary-request (0x00) or streaming-open (0x10), got 0x{opcode:02x}"
        ));
        if let Err(e) = write_error(&mut send, &err).await {
            debug!(remote = %remote, error = %e, "failed to write malformed-frame error");
        }
        return;
    }

    handle_unary_stream_with_opcode_consumed(
        connection,
        send,
        recv,
        registry,
        accept_instant,
        connection_id,
        stream_id_u64,
    )
    .await;
}

/// Continue the existing unary dispatch path after the opening opcode
/// byte has already been consumed by [`handle_inbound_substream`].
async fn handle_unary_stream_with_opcode_consumed(
    connection: Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    registry: Arc<MethodRegistry>,
    accept_instant: std::time::Instant,
    connection_id: u64,
    stream_id_u64: u64,
) {
    let remote = connection.remote_id();
    // Read the remainder (method-name + payload). The opcode byte was
    // already consumed so we recover the full frame с а 1-byte prefix
    // recombination — handlers downstream expect the original wire layout.
    let tail: Bytes = match recv.read_to_end(RPC_STREAM_READ_LIMIT).await {
        Ok(v) => Bytes::from(v),
        Err(e) => {
            debug!(remote = %remote, error = %e, "inbound unary stream: read_to_end failed");
            return;
        }
    };
    let mut buf_vec = Vec::with_capacity(tail.len().saturating_add(1));
    buf_vec.push(OPCODE_UNARY_REQUEST);
    buf_vec.extend_from_slice(&tail);
    let buf = Bytes::from(buf_vec);

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

/// Handle one inbound streaming substream after [`OPCODE_STREAMING_OPEN_REQUEST`]
/// has been observed.
///
/// Reads the `StreamingOpenRequest` body off `recv`, looks up the
/// matching streaming handler, writes а [`StreamingOpenResponse`] ack
/// (`Ok` or `Err(reason)`), spawns request- и response-pump tasks, and
/// invokes the handler. На clean handler exit emits
/// [`crate::wire::OPCODE_STREAMING_RESPONSE_END`]; on handler error
/// emits [`crate::wire::OPCODE_STREAMING_ERROR`] с `terminal = true`.
#[allow(clippy::too_many_arguments)]
async fn handle_streaming_substream(
    connection: Connection,
    mut send: iroh::endpoint::SendStream,
    mut recv: iroh::endpoint::RecvStream,
    registry: Arc<MethodRegistry>,
    accept_instant: std::time::Instant,
    connection_id: u64,
    stream_id_u64: u64,
) {
    let remote = connection.remote_id();

    // Phase 1 — read open + lookup handler + write ack.
    let Some((handler, ctx)) = streaming_negotiate_open(
        &connection,
        &mut send,
        &mut recv,
        &registry,
        accept_instant,
        connection_id,
        stream_id_u64,
    )
    .await
    else {
        return;
    };

    // Phase 2 — set up channels.
    let (req_tx, req_rx) = tokio::sync::mpsc::channel::<RpcResult<Bytes>>(16);
    let (resp_tx, resp_rx) = tokio::sync::mpsc::channel::<RpcResult<Bytes>>(16);

    let req_pump = tokio::spawn(pump_inbound_requests(recv, req_tx));
    let requests_stream: futures_util::stream::BoxStream<'static, RpcResult<Bytes>> =
        Box::pin(tokio_stream::wrappers::ReceiverStream::new(req_rx));

    // Phase 3 — invoke handler + pump responses concurrently.
    let handler_join =
        tokio::spawn(async move { handler.handle(ctx, requests_stream, resp_tx).await });
    let wrote_terminal = drain_handler_responses(&mut send, resp_rx, remote).await;

    // Phase 4 — final close frame.
    let handler_result = handler_join.await;
    if !wrote_terminal {
        finalise_streaming(&mut send, handler_result, remote).await;
    }

    // Cancel the request-pump in case it's still draining inbound frames.
    req_pump.abort();
    let _ = send.finish();
}

/// Streaming-substream Phase 1 — open negotiation.
///
/// Reads the open-request, looks up the handler, writes the open-ack
/// frame. Returns the resolved handler + context on success или `None`
/// если the open failed at any step (peer already observes а typed
/// error in that case).
#[allow(clippy::too_many_arguments)]
async fn streaming_negotiate_open(
    connection: &Connection,
    send: &mut iroh::endpoint::SendStream,
    recv: &mut iroh::endpoint::RecvStream,
    registry: &Arc<MethodRegistry>,
    accept_instant: std::time::Instant,
    connection_id: u64,
    stream_id_u64: u64,
) -> Option<(Arc<dyn StreamingMethodHandler>, RpcContext)> {
    let remote = connection.remote_id();

    let open_req = match streaming::read_streaming_frame_after_opcode(
        recv,
        OPCODE_STREAMING_OPEN_REQUEST,
    )
    .await
    {
        Ok(StreamingFrame::OpenRequest(body)) => body,
        Ok(other) => {
            debug!(
                remote = %remote,
                "streaming substream: expected open-request body, got {other:?}"
            );
            return None;
        }
        Err(e) => {
            debug!(remote = %remote, error = %e, "streaming substream: open-request read failed");
            return None;
        }
    };

    let method_name = open_req.method_name.clone();
    let request_id = open_req.request_id;

    let handler = registry.lookup_streaming(&method_name);
    let Some(handler) = handler else {
        let ack = StreamingOpenResponse {
            status: StreamingOpenStatus::Err(format!("unknown streaming method: {method_name}")),
            request_id,
        };
        if let Err(e) = streaming::write_open_response(send, &ack).await {
            debug!(remote = %remote, error = %e, "failed to write streaming open-error ack");
            return None;
        }
        let _ = send.finish();
        return None;
    };

    let ack = StreamingOpenResponse {
        status: StreamingOpenStatus::Ok,
        request_id,
    };
    if let Err(e) = streaming::write_open_response(send, &ack).await {
        debug!(remote = %remote, error = %e, "failed to write streaming open-ack");
        return None;
    }

    let frame_decode_duration_us =
        u64::try_from(accept_instant.elapsed().as_micros()).unwrap_or(u64::MAX);
    let ctx = build_inbound_context(
        connection,
        accept_instant,
        connection_id,
        stream_id_u64,
        frame_decode_duration_us,
    );
    Some((handler, ctx))
}

/// Pump inbound request-side frames off the substream into the channel
/// the handler observes as its `requests` stream.
///
/// Loops until the client emits `STREAMING_REQUEST_END`, а terminal
/// error frame, or the underlying read fails. Errors are forwarded
/// в-band so the handler can decide whether к surface them.
async fn pump_inbound_requests(
    mut recv: iroh::endpoint::RecvStream,
    req_tx: tokio::sync::mpsc::Sender<RpcResult<Bytes>>,
) {
    loop {
        match streaming::read_streaming_frame(&mut recv).await {
            Ok(Some(StreamingFrame::RequestChunk(bytes))) => {
                if req_tx.send(Ok(bytes)).await.is_err() {
                    return;
                }
            }
            // Both а clean end-of-requests frame и а bare-EOF on read
            // map to «no more requests» from the handler's PoV.
            Ok(Some(StreamingFrame::RequestEnd) | None) => return,
            Ok(Some(StreamingFrame::Error(err))) => {
                let surfaced = RpcError::Handler(err.message.clone().into());
                let _ = req_tx.send(Err(surfaced)).await;
                if err.terminal {
                    return;
                }
            }
            Ok(Some(other)) => {
                let _ = req_tx
                    .send(Err(RpcError::MalformedFrame(format!(
                        "unexpected client→server frame: {other:?}"
                    ))))
                    .await;
                return;
            }
            Err(e) => {
                let _ = req_tx.send(Err(e)).await;
                return;
            }
        }
    }
}

/// Drain the handler's response channel и write each item out as
/// either а chunk или а terminal error frame.
///
/// Returns `true` если а terminal frame was already written (handler
/// emitted an `Err` over the response sender или а write itself failed)
/// — the outer dispatch then skips the [`finalise_streaming`] step.
async fn drain_handler_responses(
    send: &mut iroh::endpoint::SendStream,
    mut resp_rx: tokio::sync::mpsc::Receiver<RpcResult<Bytes>>,
    remote: nerw_core::identity::NodeId,
) -> bool {
    while let Some(item) = resp_rx.recv().await {
        match item {
            Ok(chunk) => {
                if let Err(e) = streaming::write_response_chunk(send, &chunk).await {
                    debug!(remote = %remote, error = %e, "failed to write streaming response chunk");
                    return true;
                }
            }
            Err(err) => {
                let body = streaming::handler_err_to_terminal(&err);
                if let Err(e) = streaming::write_streaming_error(send, &body).await {
                    debug!(remote = %remote, error = %e, "failed to write streaming terminal error");
                }
                return true;
            }
        }
    }
    false
}

/// Final close frame after handler-task completion.
///
/// Emits either `STREAMING_RESPONSE_END` (clean handler exit), а
/// terminal error frame (handler returned `Err`), или а join-failure
/// terminal error (handler task panicked / was cancelled).
async fn finalise_streaming(
    send: &mut iroh::endpoint::SendStream,
    handler_result: Result<RpcResult<()>, tokio::task::JoinError>,
    remote: nerw_core::identity::NodeId,
) {
    match handler_result {
        Ok(Ok(())) => {
            if let Err(e) = streaming::write_response_end(send).await {
                debug!(remote = %remote, error = %e, "failed to write streaming response-end");
            }
        }
        Ok(Err(handler_err)) => {
            let body = streaming::handler_err_to_terminal(&handler_err);
            if let Err(e) = streaming::write_streaming_error(send, &body).await {
                debug!(remote = %remote, error = %e, "failed to write handler-error frame");
            }
        }
        Err(join_err) => {
            let body = streaming::StreamingError {
                message: format!("streaming handler join failure: {join_err}"),
                terminal: true,
            };
            if let Err(e) = streaming::write_streaming_error(send, &body).await {
                debug!(remote = %remote, error = %e, "failed to write join-failure frame");
            }
        }
    }
}

/// Decode the request frame, look up the handler, invoke it, and
/// return its bytes (or an [`RpcError`]).
///
/// The full-frame `buf` is owned here так we can slice the postcard
/// payload as а zero-copy [`Bytes`] view that's handed к the handler.
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
        .ok_or_else(|| RpcError::MalformedFrame("empty request frame".to_owned()))?;
    if opcode != OPCODE_UNARY_REQUEST {
        return Err(RpcError::MalformedFrame(format!(
            "expected unary-request opcode 0x{OPCODE_UNARY_REQUEST:02x}, got 0x{opcode:02x}",
        )));
    }

    // decode_method_name borrows from a &[u8] view of `buf`; we then
    // measure how many bytes were consumed by the method-name prefix
    // and slice the postcard payload as а zero-copy `Bytes`.
    let (method_name, payload_slice) = decode_method_name(&buf[1..])?;
    let method_name = method_name.to_owned();
    // `payload_slice` is the tail of `buf[1..]`, so `buf.len() >=
    // payload_slice.len()`. `saturating_sub` makes that proof-by-construction
    // immune to a future refactor that could violate the invariant.
    let consumed_prefix = buf.len().saturating_sub(payload_slice.len());
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

    // Monotonic ns elapsed since the bidi stream был accepted (i.e.
    // since `accept_instant` was sampled at the top of `handle_unary_stream`).
    // This is **not** the same as `frame_decode_duration_us`:
    //   - `frame_decode_duration_us` measures parse cost (microseconds
    //     spent inside `decode_method_name` + opcode validation).
    //   - `received_at_monotonic_ns` is а monotonic timestamp marker
    //     useful as ordering key for events на the handler side
    //     (e.g. correlating multiple metrics emitted within one request)
    //     и as denominator for Prometheus histograms keyed off accept time.
    // The two fields share the same epoch (`accept_instant`) but encode
    // distinct quantities (duration vs timestamp).
    let received_at_monotonic_ns =
        u64::try_from(accept_instant.elapsed().as_nanos()).unwrap_or(u64::MAX);

    let peer = PeerMetadata {
        node_id: connection.remote_id(),
        connection_id,
        stream_id,
        alpn: ALPN_NERW_RPC_1_0_0.to_vec(),
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
    // `saturating_add(1)` for the opcode byte — capacity is а hint, the
    // BytesMut itself grows on demand, so an unlikely usize overflow here
    // is harmless. The lint exists to flag silent wrap-around в release.
    let mut buf = BytesMut::with_capacity(response.len().saturating_add(1));
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
    let mut buf = BytesMut::with_capacity(body_bytes.len().saturating_add(1));
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
    // 1 opcode byte + ≤5 LEB128 method-len bytes + UTF-8 name + payload.
    // `saturating_add` keeps the capacity hint sound even на а pathological
    // `usize::MAX`-near input (which would fail at write time anyway).
    let mut buf = Vec::with_capacity(
        6_usize
            .saturating_add(method_name.len())
            .saturating_add(request.len()),
    );
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
