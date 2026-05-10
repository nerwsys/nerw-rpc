//! Datagram dispatch table — stream-id keyed map for voice / unreliable subprotocols.
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
//!    knows the resulting QUIC stream-id (`SendStream::id().0`); server
//!    sees the matching id on the accepted bidi.
//! 2. Application code registers а [`DatagramHandler`] на the dispatcher
//!    keyed by that stream-id via [`DatagramDispatcher::register`].
//! 3. Subsequent RTP frames are sent via
//!    [`nerw_core::client::Client::send_datagram`] с а `varint(stream-id)`
//!    prefix instead of the legacy 1-byte token. The varint is decoded
//!    by [`DatagramDispatcher::dispatch`] using
//!    [`crate::wire::decode_stream_id`]; the trailing bytes are handed
//!    к the registered handler.
//! 4. Datagrams arriving for an unregistered stream-id surface as
//!    [`crate::error::RpcError::DatagramStreamIdUnknown`] (visible on
//!    the broadcast loop's dispatch result).
//!
//! ## Why stream-id (not а 1-byte token)
//!
//! Phase 2's first cut (ALPN `tolki/datagram/1.0.0`) keyed the
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
//! без а global lock. `DashMap` shards internally по hash, so concurrent
//! `register` / `unregister` / `dispatch` calls touching different
//! stream-ids do not contend. We never `.await` while holding а
//! `DashMap` shard guard — the dispatch path clones the `Arc<dyn Handler>`
//! и drops the guard before invoking the handler's `.await`-able body.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use tracing::trace;

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::transport::ALPN_TOLKI_DATAGRAM_2_0_0;
use crate::wire::decode_stream_id;

/// Handler trait for datagram sessions — application code implements
/// this once per registered handshake stream-id.
///
/// The dispatcher hands the handler the per-frame [`RpcContext`] и the
/// payload bytes (everything после the leading `varint(stream-id)`
/// prefix). Handlers MUST return promptly — the dispatcher's caller
/// drives the inbound datagram broadcast loop, и slow handlers can
/// starve other sessions sharing the same connection.
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

/// Stream-id keyed dispatch table for inbound datagrams.
///
/// Each entry maps а handshake bidi stream-id (`u64`, allocated by
/// QUIC) к the [`DatagramHandler`] registered for that session.
/// Lookup is O(1) via [`dashmap::DashMap`]; mutations и reads do not
/// contend on а global lock.
///
/// Capacity is unbounded (limited only by the operating system / heap)
/// — there is no equivalent of the 1.0.0 ALPN's 256-slot cap.
pub struct DatagramDispatcher {
    /// Map handshake stream-id → handler. Keyed by the `u64`
    /// stream-id of the bidi handshake stream that established the
    /// datagram session.
    handlers: DashMap<u64, Arc<dyn DatagramHandler>>,
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
            .finish_non_exhaustive()
    }
}

impl DatagramDispatcher {
    /// Build an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            handlers: DashMap::new(),
        }
    }

    /// Register а handler keyed by handshake stream-id.
    ///
    /// The `stream_id` is the `u64` identifier of the bidi handshake
    /// stream that established the datagram session. Server-side
    /// callers obtain it from the accepted bidi
    /// (`SendStream::id().0` / `RecvStream::id().0`); client-side
    /// callers from the `open_bi` return value.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::DatagramStreamIdCollision`] if а handler is
    /// already registered for the same stream-id. Use
    /// [`Self::unregister`] first if you need к replace.
    pub fn register(
        &self,
        stream_id: u64,
        handler: Arc<dyn DatagramHandler>,
    ) -> RpcResult<()> {
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
    /// `frame` is taken as а [`Bytes`] so the payload slice handed к
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
    ///   for the decoded stream-id.
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
        // get the prefix length.
        let prefix_len = frame.len() - payload_slice.len();
        let payload = frame.slice(prefix_len..);

        // Lookup, clone Arc, drop the DashMap guard BEFORE awaiting
        // the handler. Holding а sync guard across .await is а foot-gun
        // (deadlock with tokio runtimes that have один worker thread).
        let handler = self.handlers.get(&stream_id).map(|entry| Arc::clone(&entry));

        match handler {
            Some(h) => h.handle(ctx, payload).await,
            None => Err(RpcError::DatagramStreamIdUnknown { stream_id }),
        }
    }

    /// Build an [`RpcContext`] suitable for а datagram delivery.
    ///
    /// Used by callers wiring the dispatch loop from
    /// [`nerw_core::client::Client::subscribe_datagrams`]. The
    /// [`PeerMetadata::node_id`] is the [`iroh::EndpointId`] copied
    /// from the inbound `DatagramFrame::from_peer`. The ALPN field
    /// reflects [`ALPN_TOLKI_DATAGRAM_2_0_0`] regardless of which QUIC
    /// connection actually carried the datagram — datagrams ride on
    /// the same connection as nerw RPC (Quinn multiplexes streams +
    /// datagrams in one session) but logically belong к the
    /// tolki/datagram/2.0.0 sub-protocol.
    #[must_use]
    pub fn build_context(from_peer: iroh::EndpointId) -> RpcContext {
        let peer = PeerMetadata {
            node_id: from_peer,
            connection_id: 0,
            stream_id: 0,
            alpn: ALPN_TOLKI_DATAGRAM_2_0_0.to_vec(),
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
        assert_eq!(ctx.peer.alpn, ALPN_TOLKI_DATAGRAM_2_0_0);
        assert!(ctx.auth.is_none());
    }
}
