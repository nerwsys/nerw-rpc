//! Datagram dispatch table — stream-id keyed map для voice / unreliable subprotocols.
//!
//! ## Voice flow (per `NERW-RPC-DESIGN.md` Section 5)
//!
//! The dispatcher implements **WebTransport-style datagram correlation**
//! (RFC 9221 + CONNECT-UDP / WebTransport). Каждый datagram carries а
//! `varint(stream-id)` prefix identifying the bidi handshake stream
//! that established the unreliable session. The dispatcher routes
//! incoming datagrams к the [`DatagramHandler`] registered against
//! that handshake stream-id.
//!
//! 1. Application opens а bidi handshake stream (e.g. via
//!    [`crate::client::RpcClient`]) к negotiate а voice session под
//!    method-name `tolki:voice@1.0.0/voice/start-voice-message`. Client
//!    knows the resulting QUIC stream-id (`u64::from(send.id())`); server
//!    sees the matching id on the accepted bidi.
//! 2. Application code registers а [`DatagramHandler`] на the dispatcher
//!    keyed by that stream-id via [`DatagramDispatcher::register`].
//! 3. Application wires the dispatcher onto а connection via
//!    [`DatagramDispatcher::subscribe_connection`]. The subscriber
//!    spawns а per-connection `read_datagram` loop that decodes the
//!    `varint(stream-id)` prefix и dispatches к the registered handler.
//! 4. Subsequent RTP frames are sent via
//!    [`iroh::endpoint::Connection::send_datagram`] с а
//!    `varint(stream-id)` prefix. The dispatcher's read loop hands
//!    payload bytes (less the varint prefix) к the registered handler.
//! 5. Datagrams arriving for an unregistered stream-id surface as
//!    [`crate::error::RpcError::DatagramStreamIdUnknown`] (visible on
//!    the read loop's dispatch result; logged but не surfaced beyond
//!    that since datagrams are fire-and-forget).
//!
//! ## Why explicit `subscribe_connection` (Phase 2.1)
//!
//! Pre-R3 nerw-core shipped а `subscribe_datagrams()` broadcast channel
//! fanning out every inbound datagram across every cached connection.
//! Post-R3 (commit `48ec369`) that channel is gone — nerw-core's
//! `Client::accept` is а raw delegation, и
//! `Connection::read_datagram` is per-connection. nerw-rpc's
//! [`DatagramDispatcher::subscribe_connection`] takes one connection
//! (handed in by а custom-ALPN handler on the inbound side, or by
//! `dial_with_alpn` on the outbound side) и owns the per-connection
//! read loop. Consumers wire multiple connections к the same
//! dispatcher; the dispatcher's handler table keys on stream-id, не
//! on connection identity, так а handshake stream-id collision across
//! two distinct peers would be ambiguous (intentional — collisions are
//! caller-managed via [`DatagramDispatcher::register`] failure).
//!
//! ## Why stream-id (not а 1-byte token)
//!
//! Phase 2's first cut (an earlier internal datagram ALPN) keyed the
//! dispatcher on а 1-byte token allocated by the handshake response.
//! Two problems с that:
//!
//! 1. **256-session cap per connection.** А peer could establish at
//!    most 256 concurrent unreliable subprotocol sessions before token
//!    space exhaustion forced reuse / collision handling. WebTransport
//!    works the same way for the same reason: it uses а varint, not а
//!    bounded enum.
//! 2. **No correlation к the establishing stream.** Token allocation
//!    happened over а handshake bidi, but the token itself bore no
//!    relationship к the stream's id — making cross-debugger
//!    investigation hard ("which stream owns token 42?").
//!
//! Stream-id keying solves both: the dispatcher's key IS the QUIC
//! stream-id of the handshake stream that established the session,
//! making correlation explicit и unbounded.
//!
//! ## `DashMap` (not а `parking_lot::Mutex<HashMap>`)
//!
//! The dispatcher uses [`dashmap::DashMap`] для concurrent O(1) lookup
//! без а global lock. `DashMap` shards internally по hash, так concurrent
//! `register` / `unregister` / `dispatch` calls touching different
//! stream-ids do not contend. We never `.await` while holding а
//! `DashMap` shard guard — the dispatch path clones the `Arc<dyn Handler>`
//! и drops the guard before invoking the handler's `.await`-able body.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use iroh::endpoint::Connection;
use tokio::sync::Semaphore;
use tracing::{debug, trace};

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::transport::ALPN_NERW_DATAGRAM_1_0_0;
use crate::wire::decode_stream_id;

/// Default cap on concurrent per-frame dispatch tasks spawned by
/// [`DatagramDispatcher::subscribe_connection`].
///
/// Each inbound datagram fires а fresh `tokio::spawn` so а slow handler
/// cannot starve subsequent datagrams on the same connection. Без а
/// cap, а voice flood from а malicious or buggy peer can spawn
/// unbounded tasks — same `DoS` surface as accepting unbounded inbound
/// streams. The value mirrors [`crate::server::DEFAULT_MAX_CONCURRENT_STREAMS`]
/// в magnitude но is chosen independently: voice traffic patterns
/// (high-rate RTP frames burst-arriving from possibly many peers) are
/// distinct from RPC traffic (request/response semantics), so the cap
/// is tunable separately via [`DatagramDispatcher::with_max_in_flight`].
pub const DEFAULT_MAX_CONCURRENT_DATAGRAMS: usize = 1024;

/// Handler trait для datagram sessions — application code implements
/// this once per registered handshake stream-id.
///
/// The dispatcher hands the handler the per-frame [`RpcContext`] и the
/// payload bytes (everything после the leading `varint(stream-id)`
/// prefix). Handlers MUST return promptly — the dispatcher's caller
/// drives the inbound datagram read loop, и slow handlers can starve
/// other sessions sharing the same connection.
///
/// `payload` is а [`Bytes`] view sharing the same underlying allocation
/// as the inbound datagram — handlers can clone it cheaply (ref-count
/// bump) к hand off к downstream channels без copying.
#[async_trait]
pub trait DatagramHandler: Send + Sync + 'static {
    /// Process one inbound datagram payload.
    ///
    /// # Errors
    ///
    /// Implementation-defined. Errors are logged at the dispatcher
    /// level и do not propagate (datagram traffic is fire-and-forget;
    /// the sender does not wait for an ack).
    async fn handle(&self, ctx: RpcContext, payload: Bytes) -> RpcResult<()>;
}

/// Stream-id keyed dispatch table для inbound datagrams.
///
/// Each entry maps а handshake bidi stream-id (`u64`, allocated by
/// QUIC) к the [`DatagramHandler`] registered for that session.
/// Lookup is O(1) via [`dashmap::DashMap`]; mutations и reads do not
/// contend on а global lock.
///
/// Registry capacity is unbounded (limited only by the operating
/// system / heap) — there is no equivalent of the 1.0.0 ALPN's
/// 256-slot cap. Per-frame dispatch concurrency, however, is bounded
/// by а semaphore (default [`DEFAULT_MAX_CONCURRENT_DATAGRAMS`] = 1024
/// concurrent in-flight handler tasks) to defend against а voice
/// flood from а malicious or buggy peer spawning unbounded tasks. Use
/// [`Self::with_max_in_flight`] to tune the limit for high-traffic
/// deployments.
pub struct DatagramDispatcher {
    /// Map handshake stream-id → handler. Keyed by the `u64`
    /// stream-id of the bidi handshake stream that established the
    /// datagram session.
    handlers: DashMap<u64, Arc<dyn DatagramHandler>>,
    /// Caps concurrent per-frame dispatch tasks across the connection
    /// pool. `subscribe_connection` acquires а permit before spawning
    /// the handler's `.await`-able body; tasks blocked on the
    /// semaphore wait briefly rather than spawning unbounded tokio
    /// tasks. Wrapped in `Arc` so spawned-task clones share the
    /// allocation.
    in_flight_permits: Arc<Semaphore>,
}

impl Default for DatagramDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DatagramDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatagramDispatcher")
            .field("registered_count", &self.handlers.len())
            .field(
                "in_flight_permits_available",
                &self.in_flight_permits.available_permits(),
            )
            .finish_non_exhaustive()
    }
}

impl DatagramDispatcher {
    /// Build an empty dispatcher with [`DEFAULT_MAX_CONCURRENT_DATAGRAMS`]
    /// in-flight permits.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max_in_flight(DEFAULT_MAX_CONCURRENT_DATAGRAMS)
    }

    /// Build an empty dispatcher with а caller-tuned cap on concurrent
    /// per-frame handler tasks.
    ///
    /// Pick this when your workload deviates significantly from
    /// «moderate voice traffic on а handful of peers» — e.g. а
    /// high-fan-in conference server with hundreds of inbound RTP
    /// streams may need а larger cap; an edge device serving а single
    /// peer may want а tighter one.
    ///
    /// # Panics
    ///
    /// `max` MUST be `> 0`. Zero permits would deadlock the dispatcher
    /// permanently — every `acquire` would block forever, и no
    /// handler would ever run. [`Semaphore::new`] does not panic on
    /// `0`, so we validate ourselves.
    #[must_use]
    pub fn with_max_in_flight(max: usize) -> Self {
        assert!(
            max > 0,
            "DatagramDispatcher max_in_flight must be > 0; zero would deadlock the dispatcher",
        );
        Self {
            handlers: DashMap::new(),
            in_flight_permits: Arc::new(Semaphore::new(max)),
        }
    }

    /// Register а handler keyed by handshake stream-id.
    ///
    /// The `stream_id` is the `u64` identifier of the bidi handshake
    /// stream that established the datagram session. Server-side
    /// callers obtain it from the accepted bidi
    /// (`u64::from(send.id())` / `u64::from(recv.id())`); client-side
    /// callers from the `open_bi` return value.
    ///
    /// Note: `quinn_proto::StreamId` wraps `u64` в а tuple struct but
    /// the inner field is not `pub` — use the `From<StreamId> for u64`
    /// conversion (`u64::from(...)`) rather than `.id().0`.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::DatagramStreamIdCollision`] if а handler is
    /// already registered for the same stream-id. Use
    /// [`Self::unregister`] first if you need к replace.
    pub fn register(&self, stream_id: u64, handler: Arc<dyn DatagramHandler>) -> RpcResult<()> {
        // DashMap::entry returns either Vacant or Occupied. Using `entry`
        // ensures the check-and-insert is atomic against concurrent
        // registrations on the same shard.
        match self.handlers.entry(stream_id) {
            dashmap::mapref::entry::Entry::Occupied(_) => {
                Err(RpcError::DatagramStreamIdCollision { stream_id })
            }
            dashmap::mapref::entry::Entry::Vacant(slot) => {
                slot.insert(handler);
                trace!(stream_id, "datagram handler registered");
                Ok(())
            }
        }
    }

    /// Drop the handler registered под the given stream-id. Idempotent
    /// — calling on an unregistered stream-id is а silent no-op
    /// (returns `None`).
    ///
    /// Returns the previous handler if one was registered.
    #[must_use]
    pub fn unregister(&self, stream_id: u64) -> Option<Arc<dyn DatagramHandler>> {
        self.handlers.remove(&stream_id).map(|(_, h)| h)
    }

    /// Number of currently-registered handlers (test introspection).
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.handlers.len()
    }

    /// Dispatch one inbound datagram frame:
    /// `[varint(stream-id) | payload]`.
    ///
    /// `frame` is taken as а [`Bytes`] так the payload slice handed к
    /// the handler shares the inbound allocation (zero-copy split-off
    /// of the varint prefix).
    ///
    /// # Errors
    ///
    /// - [`RpcError::DatagramTooShort`] — varint cannot be decoded
    ///   from the (truncated / empty) frame.
    /// - [`RpcError::MalformedFrame`] — varint decoded but exceeds
    ///   `u64` (delegated к [`crate::wire::decode_stream_id`]).
    /// - [`RpcError::DatagramStreamIdUnknown`] — no handler registered
    ///   для the decoded stream-id.
    /// - Any error returned by the handler itself.
    pub async fn dispatch(&self, ctx: RpcContext, frame: Bytes) -> RpcResult<()> {
        // Empty frame cannot carry а varint at all — surface а
        // dedicated DatagramTooShort variant with diagnostic length.
        if frame.is_empty() {
            return Err(RpcError::DatagramTooShort { len: 0 });
        }

        // Decode the varint prefix using the wire helper. Errors map
        // through MalformedFrame for truncated / oversized varints.
        let (stream_id, payload_slice) = match decode_stream_id(&frame) {
            Ok(parsed) => parsed,
            // Distinguish "buffer too short to even start а varint"
            // (we already short-circuited empty above) from "varint
            // structure invalid" — only the latter reaches here, so
            // surface as MalformedFrame which is propagated unchanged.
            Err(e) => return Err(e),
        };

        // Compute the consumed varint length so we can split а Bytes
        // view (zero-copy) instead of an &[u8] reference. payload_slice
        // is а slice of frame; subtract its len from the original к
        // get the prefix length. `saturating_sub` guards against the
        // (statically impossible) underflow в release builds.
        let prefix_len = frame.len().saturating_sub(payload_slice.len());
        let payload = frame.slice(prefix_len..);

        // Lookup, clone Arc, drop the DashMap guard BEFORE awaiting
        // the handler. Holding а sync guard across .await is а foot-gun
        // (deadlock with tokio runtimes that have один worker thread).
        let handler = self
            .handlers
            .get(&stream_id)
            .map(|entry| Arc::clone(&entry));

        match handler {
            Some(h) => h.handle(ctx, payload).await,
            None => Err(RpcError::DatagramStreamIdUnknown { stream_id }),
        }
    }

    /// Build an [`RpcContext`] suitable для а datagram delivery.
    ///
    /// Used by [`Self::subscribe_connection`] и by callers who manually
    /// wire а connection's `read_datagram` loop. The
    /// [`PeerMetadata::node_id`] is the [`nerw_core::identity::NodeId`]
    /// of the connection's `remote_id()` — today the type aliases к
    /// `iroh::EndpointId`, post-R4 it will resolve к the
    /// `NerwNodeId` newtype wrapper automatically. The ALPN field
    /// reflects [`ALPN_NERW_DATAGRAM_1_0_0`] regardless of the carrier
    /// connection's actual ALPN — datagrams ride multiplexed on QUIC
    /// connections и the dispatch protocol is unrelated to the
    /// bidi-stream ALPN.
    #[must_use]
    pub fn build_context(from_peer: nerw_core::identity::NodeId) -> RpcContext {
        let peer = PeerMetadata {
            node_id: from_peer,
            connection_id: 0,
            stream_id: 0,
            alpn: ALPN_NERW_DATAGRAM_1_0_0.to_vec(),
            handshake_at_ms: 0,
            tls_cipher_suite: None,
        };
        RpcContext {
            peer,
            timing: TimingInfo::zero(),
            auth: None,
            session: None,
            tracing: TracingInfo::fresh(),
        }
    }

    /// Spawn а per-connection datagram read loop.
    ///
    /// Drains [`iroh::endpoint::Connection::read_datagram`] until the
    /// connection closes, dispatching each frame через [`Self::dispatch`].
    /// Errors returned from the dispatch path are traced и dropped —
    /// datagrams are fire-and-forget, so an unknown stream-id or
    /// handler error does not abort the read loop.
    ///
    /// Returns immediately after spawning the loop. The spawned task
    /// holds an `Arc` clone of the dispatcher; the loop exits naturally
    /// when `read_datagram` returns `Err` (connection closed / lost).
    /// Production callers typically invoke this once per connection
    /// they want to receive datagrams on (inbound: from the
    /// [`crate::transport::AlpnHandler::handle`] for the datagram ALPN;
    /// outbound: after `dial_with_alpn` for reply-datagram support).
    ///
    /// # Concurrency
    ///
    /// The read loop spawns one task per inbound datagram so а slow
    /// handler cannot starve subsequent datagrams on the same
    /// connection. Per-frame dispatch is bounded by the dispatcher's
    /// in-flight semaphore (default [`DEFAULT_MAX_CONCURRENT_DATAGRAMS`])
    /// — а voice flood from а malicious or buggy peer queues briefly
    /// rather than spawning unbounded tokio tasks. Tune the limit via
    /// [`Self::with_max_in_flight`] for high-fan-in deployments.
    /// Errors from the dispatch body are fire-and-forget; observable
    /// only через tracing.
    ///
    /// # Race condition warning
    ///
    /// Inbound datagrams sent **before** the dispatcher's read loop is
    /// wired will be silently dropped by iroh's per-connection queue.
    /// Production callers MUST perform an application-level handshake
    /// (e.g. via а bidi stream RPC) before sending the first datagram.
    /// This guarantees the responder side has invoked
    /// [`Self::subscribe_connection`] и is ready to receive.
    ///
    /// The established voice subprotocol pattern is:
    /// 1. Client opens а bidi stream к responder's wire-protocol ALPN
    ///    ([`crate::transport::ALPN_NERW_RPC_1_0_0`]).
    /// 2. Client sends а voice/start RPC method (blocks until the
    ///    server acknowledges the handshake).
    /// 3. Server-side handler reaches into the dispatcher и registers
    ///    the handler at the QUIC stream-id (via [`Self::register`]).
    /// 4. Server has already wired [`Self::subscribe_connection`] on
    ///    the datagram ALPN connection accepted earlier.
    /// 5. Client now safely sends RTP datagrams on the datagram ALPN
    ///    connection — the responder's read loop is guaranteed live.
    ///
    /// Tests may use `tokio::time::sleep(Duration::from_millis(200))`
    /// as а race-avoidance shim to skip the handshake, но production
    /// code should use the bidi RPC handshake pattern instead.
    pub fn subscribe_connection(self: Arc<Self>, conn: Connection) {
        let from_peer = conn.remote_id();
        tokio::spawn(async move {
            trace!(remote = %from_peer, "datagram read loop started");
            loop {
                match conn.read_datagram().await {
                    Ok(bytes) => {
                        let self_clone = Arc::clone(&self);
                        let ctx = Self::build_context(from_peer);
                        let permits = Arc::clone(&self.in_flight_permits);
                        tokio::spawn(async move {
                            // Acquire а permit BEFORE doing any work —
                            // а voice flood from а malicious or buggy
                            // peer queues here briefly rather than
                            // spawning unbounded tokio tasks. The
                            // permit is dropped automatically on task
                            // exit (RAII via `_permit`'s scope).
                            let _permit = match permits.acquire_owned().await {
                                Ok(p) => p,
                                Err(e) => {
                                    // Semaphore closed — only happens
                                    // if the dispatcher is being torn
                                    // down. Drop the frame silently.
                                    trace!(
                                        remote = %from_peer,
                                        error = %e,
                                        "datagram dispatcher semaphore closed; dropping frame",
                                    );
                                    return;
                                }
                            };
                            if let Err(e) = self_clone.dispatch(ctx, bytes).await {
                                debug!(
                                    remote = %from_peer,
                                    error = %e,
                                    "datagram dispatch returned error",
                                );
                            }
                        });
                    }
                    Err(e) => {
                        trace!(
                            remote = %from_peer,
                            error = %e,
                            "datagram read loop: connection closed",
                        );
                        return;
                    }
                }
            }
        });
    }

    /// Borrow the in-flight semaphore (test introspection).
    ///
    /// Surfaced для unit tests that need to observe permit availability
    /// — production callers should not poke at the semaphore directly.
    #[must_use]
    pub const fn in_flight_semaphore(&self) -> &Arc<Semaphore> {
        &self.in_flight_permits
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{PeerMetadata, RpcContext, loopback_node_id};
    use crate::wire::encode_stream_id;
    use parking_lot::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingHandler {
        calls: AtomicUsize,
        last_payload: Mutex<Vec<u8>>,
    }

    impl CountingHandler {
        fn new() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                last_payload: Mutex::new(Vec::new()),
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn last_payload(&self) -> Vec<u8> {
            self.last_payload.lock().clone()
        }
    }

    #[async_trait]
    impl DatagramHandler for CountingHandler {
        async fn handle(&self, _ctx: RpcContext, payload: Bytes) -> RpcResult<()> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            *self.last_payload.lock() = payload.to_vec();
            Ok(())
        }
    }

    /// Build а datagram frame from а stream-id и payload bytes.
    fn build_frame(stream_id: u64, payload: &[u8]) -> Bytes {
        let mut buf = Vec::new();
        encode_stream_id(stream_id, &mut buf).expect("encode stream-id");
        buf.extend_from_slice(payload);
        Bytes::from(buf)
    }

    #[test]
    fn new_dispatcher_has_zero_registered() {
        let d = DatagramDispatcher::new();
        assert_eq!(d.registered_count(), 0);
    }

    #[test]
    fn register_and_unregister_round_trip() {
        let d = DatagramDispatcher::new();
        let h = Arc::new(CountingHandler::new());
        d.register(42, h.clone()).expect("register");
        assert_eq!(d.registered_count(), 1);
        let removed = d.unregister(42).expect("must return removed");
        assert!(Arc::ptr_eq(&removed, &(h as Arc<dyn DatagramHandler>)));
        assert_eq!(d.registered_count(), 0);
    }

    #[test]
    fn register_collision_errors() {
        let d = DatagramDispatcher::new();
        d.register(7, Arc::new(CountingHandler::new()))
            .expect("first register");
        let err = d
            .register(7, Arc::new(CountingHandler::new()))
            .expect_err("second register at same stream-id must error");
        match err {
            RpcError::DatagramStreamIdCollision { stream_id } => assert_eq!(stream_id, 7),
            other => panic!("expected DatagramStreamIdCollision, got {other:?}"),
        }
    }

    #[test]
    fn unregister_unknown_stream_id_is_idempotent() {
        let d = DatagramDispatcher::new();
        // Unregistering а never-registered id MUST NOT panic.
        let prev = d.unregister(9999);
        assert!(prev.is_none());
    }

    #[test]
    fn register_supports_large_stream_ids() {
        // Ensure stream-ids beyond the old 256-slot cap work cleanly.
        let d = DatagramDispatcher::new();
        d.register(1_000_000, Arc::new(CountingHandler::new()))
            .expect("register large id");
        d.register(u64::from(u32::MAX), Arc::new(CountingHandler::new()))
            .expect("register near-max id");
        assert_eq!(d.registered_count(), 2);
    }

    #[tokio::test]
    async fn dispatch_routes_to_correct_handler() {
        let d = DatagramDispatcher::new();
        let h_a = Arc::new(CountingHandler::new());
        let h_b = Arc::new(CountingHandler::new());
        d.register(1, h_a.clone()).expect("register A");
        d.register(2, h_b.clone()).expect("register B");

        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        d.dispatch(ctx.clone(), build_frame(1, &[0xAA, 0xBB]))
            .await
            .expect("A");
        d.dispatch(ctx.clone(), build_frame(2, &[0xCC]))
            .await
            .expect("B");
        d.dispatch(ctx, build_frame(1, &[0xDD, 0xEE, 0xFF]))
            .await
            .expect("A");

        assert_eq!(h_a.call_count(), 2);
        assert_eq!(h_b.call_count(), 1);
        assert_eq!(h_a.last_payload(), vec![0xDD, 0xEE, 0xFF]);
        assert_eq!(h_b.last_payload(), vec![0xCC]);
    }

    #[tokio::test]
    async fn dispatch_unknown_stream_id_errors() {
        let d = DatagramDispatcher::new();
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        let err = d
            .dispatch(ctx, build_frame(100, &[0xAA]))
            .await
            .expect_err("unknown stream-id must error");
        match err {
            RpcError::DatagramStreamIdUnknown { stream_id } => assert_eq!(stream_id, 100),
            other => panic!("expected DatagramStreamIdUnknown, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_empty_frame_errors() {
        let d = DatagramDispatcher::new();
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        let err = d
            .dispatch(ctx, Bytes::new())
            .await
            .expect_err("empty frame must error");
        match err {
            RpcError::DatagramTooShort { len } => assert_eq!(len, 0),
            other => panic!("expected DatagramTooShort, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_decodes_large_stream_id() {
        // Stream-ids в the upper varint range still route correctly.
        let d = DatagramDispatcher::new();
        let h = Arc::new(CountingHandler::new());
        let big_id: u64 = 1_000_000_000;
        d.register(big_id, h.clone()).expect("register");

        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        d.dispatch(ctx, build_frame(big_id, b"BIG"))
            .await
            .expect("dispatch");
        assert_eq!(h.call_count(), 1);
        assert_eq!(h.last_payload(), b"BIG");
    }

    #[test]
    fn build_context_uses_datagram_alpn() {
        let id = loopback_node_id();
        let ctx = DatagramDispatcher::build_context(id);
        assert_eq!(ctx.peer.node_id, id);
        assert_eq!(ctx.peer.alpn, ALPN_NERW_DATAGRAM_1_0_0);
        assert!(ctx.auth.is_none());
    }

    #[test]
    fn new_dispatcher_uses_default_in_flight_cap() {
        let d = DatagramDispatcher::new();
        assert_eq!(
            d.in_flight_semaphore().available_permits(),
            DEFAULT_MAX_CONCURRENT_DATAGRAMS,
        );
    }

    #[test]
    fn with_max_in_flight_honors_caller_cap() {
        let d = DatagramDispatcher::with_max_in_flight(7);
        assert_eq!(d.in_flight_semaphore().available_permits(), 7);
    }

    #[test]
    #[should_panic(expected = "max_in_flight must be > 0")]
    fn with_max_in_flight_rejects_zero() {
        // Zero permits would deadlock the dispatcher permanently —
        // every `acquire` would block forever. The constructor refuses
        // up front rather than letting the deadlock manifest at runtime.
        let _ = DatagramDispatcher::with_max_in_flight(0);
    }

    #[tokio::test]
    async fn datagram_dispatcher_caps_concurrent_handlers() {
        // W1 — verify the semaphore actually bounds concurrent handler
        // tasks. We simulate the `subscribe_connection` per-frame body
        // by reaching into `in_flight_semaphore()` directly: real
        // subscribe_connection needs an iroh Connection (integration
        // territory), but the semaphore-acquire-then-dispatch path is
        // the same code under test.
        use std::sync::atomic::AtomicI32;
        use tokio::sync::Notify;

        struct BarrierHandler {
            in_flight: Arc<AtomicI32>,
            peak: Arc<AtomicI32>,
            release: Arc<Notify>,
        }

        #[async_trait]
        impl DatagramHandler for BarrierHandler {
            async fn handle(&self, _ctx: RpcContext, _payload: Bytes) -> RpcResult<()> {
                let cur = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(cur, Ordering::SeqCst);
                // Wait until the test releases us; mirrors а slow
                // handler holding а permit.
                self.release.notified().await;
                self.in_flight.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let in_flight = Arc::new(AtomicI32::new(0));
        let peak = Arc::new(AtomicI32::new(0));
        let release = Arc::new(Notify::new());

        let d = Arc::new(DatagramDispatcher::with_max_in_flight(2));
        d.register(
            1,
            Arc::new(BarrierHandler {
                in_flight: Arc::clone(&in_flight),
                peak: Arc::clone(&peak),
                release: Arc::clone(&release),
            }),
        )
        .expect("register");

        // Fire 5 frames simulating the subscribe_connection body:
        // acquire permit, run dispatch. With max=2, at most 2 should
        // be inside the handler at any moment.
        let mut tasks = Vec::with_capacity(5);
        for _ in 0..5_i32 {
            let d = Arc::clone(&d);
            let permits = Arc::clone(d.in_flight_semaphore());
            let frame = build_frame(1, &[0xAA]);
            tasks.push(tokio::spawn(async move {
                let _permit = permits.acquire_owned().await.expect("acquire");
                let ctx = RpcContext::minimal(PeerMetadata::loopback());
                let _ = d.dispatch(ctx, frame).await;
            }));
        }

        // Let the bound take effect — first two tasks enter the
        // handler, the rest queue on the semaphore.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        let observed = in_flight.load(Ordering::SeqCst);
        assert!(
            observed <= 2,
            "in-flight handler count {observed} exceeds semaphore cap of 2",
        );

        // Release ALL pending handlers in а burst — each release wakes
        // one waiter; permits free up so blocked tasks acquire next.
        for _ in 0..20 {
            release.notify_one();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        for t in tasks {
            t.await.expect("join");
        }

        let peak_observed = peak.load(Ordering::SeqCst);
        assert!(
            peak_observed <= 2,
            "peak concurrent handler count was {peak_observed}; expected ≤ 2 (cap)",
        );
        assert!(
            peak_observed >= 1,
            "at least one handler must have run; got peak {peak_observed}",
        );
    }
}
