//! Datagram dispatch table — 256 token slots для voice / unreliable subprotocols.
//!
//! ## Voice flow (per `NERW-RPC-DESIGN.md` Section 5)
//!
//! 1. Handshake stream allocates а token (е.g. 42) для а concrete
//!    method-name (tolki:voice@1.0.0/voice/start-voice-message) via the
//!    normal [`crate::server::RpcServer`] flow. The handshake response
//!    carries the allocated token byte.
//! 2. Subsequent RTP frames are sent via
//!    [`nerw_core::client::Client::send_datagram`] с the token prepended:
//!    `[token=42 | postcard(rtp-frame)]`. The 1-byte token IS the
//!    application-level routing prefix — distinct from nerw-core's
//!    8-byte BLAKE3 envelope, which routes between agents.
//! 3. The receiver's [`DatagramDispatcher::dispatch`] reads the leading
//!    byte and forwards к the [`DatagramHandler`] registered at that
//!    slot. Slots без registered handlers drop с
//!    [`RpcError::DatagramTokenUnknown`].
//!
//! ## 256 slots, indexed by token byte
//!
//! Phase 2 ships а `[Option<Arc<dyn DatagramHandler>>; 256]` array
//! protected by а `parking_lot::Mutex`. Lookup is O(1); registration /
//! unregistration is rare. Slots are ALL `None` at startup; the
//! application registers handlers as it negotiates new sub-protocol
//! sessions.
//!
//! ## Why `parking_lot::Mutex` (not tokio's)
//!
//! The lock window is microscopic (single index + `Arc::clone`) и we
//! never `.await` while holding it. `parking_lot::Mutex` is а раз
//! cheaper than `tokio::sync::Mutex` for that workload и does not
//! require `async` к acquire.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tracing::trace;

use crate::context::{PeerMetadata, RpcContext, TimingInfo, TracingInfo};
use crate::error::{RpcError, RpcResult};
use crate::transport::ALPN_TOLKI_DATAGRAM_2_0_0;

/// Handler trait for datagram tokens — application code implements
/// this once per registered sub-protocol slot.
///
/// The dispatcher hands the handler the per-frame [`RpcContext`] и the
/// payload bytes (everything после the leading token byte). Handlers
/// MUST return promptly — the dispatcher's caller drives the inbound
/// datagram broadcast loop, и slow handlers can starve other tokens.
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

/// Number of token slots — one per possible byte value (`0..=255`).
const SLOT_COUNT: usize = 256;

/// One slot per token byte — boxed array so the `Mutex` value is а
/// pointer-sized handle rather than 256 `Option<Arc<...>>` (≈4 KiB
/// inline on 64-bit). `[None; 256]` cannot be used because
/// `Option<Arc<dyn ...>>` is not `Copy`; `array::from_fn` initialises
/// each slot к `None` без а `Copy` bound.
type SlotArray = Box<[Option<Arc<dyn DatagramHandler>>; SLOT_COUNT]>;

/// 256-slot dispatch table keyed on the leading datagram byte.
///
/// The slots array sits behind а `parking_lot::Mutex` because:
///
/// - Mutating registrations would need а write lock anyway (`RwLock`
///   would not buy us anything for the mutation path).
/// - The read path holds the lock for а handful of nanoseconds (а
///   single index + `Arc::clone`); contention с а concurrent
///   `register()` is so unlikely it does not justify the `RwLock`'s
///   extra atomics.
///
/// `Default` impl is hand-rolled because `[None; 256]` requires `Copy`
/// и `Option<Arc<dyn ...>>` is not `Copy`.
pub struct DatagramDispatcher {
    /// One slot per possible token byte. `None` = unregistered.
    slots: Mutex<SlotArray>,
}

impl Default for DatagramDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for DatagramDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registered = self
            .slots
            .lock()
            .iter()
            .filter(|slot| slot.is_some())
            .count();
        f.debug_struct("DatagramDispatcher")
            .field("registered_slots", &registered)
            .finish_non_exhaustive()
    }
}

impl DatagramDispatcher {
    /// Build an empty dispatcher.
    #[must_use]
    pub fn new() -> Self {
        // `array::from_fn` initialises each slot к `None` без requiring
        // `Copy` (which `Option<Arc<dyn DatagramHandler>>` lacks).
        let slots: [Option<Arc<dyn DatagramHandler>>; SLOT_COUNT] = std::array::from_fn(|_| None);
        Self {
            slots: Mutex::new(Box::new(slots)),
        }
    }

    /// Register а handler at the given token slot.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::DatagramTokenCollision`] if the slot is
    /// already occupied. Use [`Self::unregister`] first if you need
    /// к replace.
    pub fn register(&self, token: u8, handler: Arc<dyn DatagramHandler>) -> RpcResult<()> {
        let mut slots = self.slots.lock();
        let idx = usize::from(token);
        if slots[idx].is_some() {
            return Err(RpcError::DatagramTokenCollision { token });
        }
        slots[idx] = Some(handler);
        trace!(token, "datagram handler registered");
        Ok(())
    }

    /// Remove the handler at the given token slot. Idempotent.
    ///
    /// Returns the previous handler if one was registered.
    pub fn unregister(&self, token: u8) -> Option<Arc<dyn DatagramHandler>> {
        let mut slots = self.slots.lock();
        slots[usize::from(token)].take()
    }

    /// Number of currently-registered handlers (test introspection).
    #[must_use]
    pub fn registered_count(&self) -> usize {
        self.slots.lock().iter().filter(|s| s.is_some()).count()
    }

    /// Dispatch one inbound datagram frame: `[token | payload]`.
    ///
    /// `frame` is taken as а [`Bytes`] so the payload slice handed к
    /// the handler shares the inbound allocation (zero-copy split-off
    /// of the leading token byte).
    ///
    /// # Errors
    ///
    /// - [`RpcError::DatagramTooShort`] — `frame.is_empty()` (no token byte).
    /// - [`RpcError::DatagramTokenUnknown`] — slot has no registered handler.
    /// - Any error returned by the handler itself.
    pub async fn dispatch(&self, ctx: RpcContext, frame: Bytes) -> RpcResult<()> {
        let token = *frame
            .first()
            .ok_or(RpcError::DatagramTooShort { len: frame.len() })?;
        let payload = frame.slice(1..);

        // Scoped lock — clone the Arc и drop the lock BEFORE awaiting
        // the handler. Holding а sync mutex across .await is а foot-gun
        // (deadlock with tokio runtimes that have один worker thread).
        let handler = {
            let slots = self.slots.lock();
            slots[usize::from(token)].clone()
        };

        match handler {
            Some(h) => h.handle(ctx, payload).await,
            None => Err(RpcError::DatagramTokenUnknown { token }),
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
            .expect_err("second register at same token must error");
        match err {
            RpcError::DatagramTokenCollision { token } => assert_eq!(token, 7),
            other => panic!("expected DatagramTokenCollision, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_routes_to_correct_handler() {
        let d = DatagramDispatcher::new();
        let h_a = Arc::new(CountingHandler::new());
        let h_b = Arc::new(CountingHandler::new());
        d.register(1, h_a.clone()).expect("register A");
        d.register(2, h_b.clone()).expect("register B");

        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        d.dispatch(ctx.clone(), Bytes::from_static(&[1, 0xAA, 0xBB]))
            .await
            .expect("A");
        d.dispatch(ctx.clone(), Bytes::from_static(&[2, 0xCC]))
            .await
            .expect("B");
        d.dispatch(ctx, Bytes::from_static(&[1, 0xDD, 0xEE, 0xFF]))
            .await
            .expect("A");

        assert_eq!(h_a.call_count(), 2);
        assert_eq!(h_b.call_count(), 1);
        assert_eq!(h_a.last_payload(), vec![0xDD, 0xEE, 0xFF]);
        assert_eq!(h_b.last_payload(), vec![0xCC]);
    }

    #[tokio::test]
    async fn dispatch_unknown_token_errors() {
        let d = DatagramDispatcher::new();
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        let err = d
            .dispatch(ctx, Bytes::from_static(&[100, 0xAA]))
            .await
            .expect_err("unknown token must error");
        match err {
            RpcError::DatagramTokenUnknown { token } => assert_eq!(token, 100),
            other => panic!("expected DatagramTokenUnknown, got {other:?}"),
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

    #[test]
    fn build_context_uses_datagram_alpn() {
        let id = loopback_node_id();
        let ctx = DatagramDispatcher::build_context(id);
        assert_eq!(ctx.peer.node_id, id);
        assert_eq!(ctx.peer.alpn, ALPN_TOLKI_DATAGRAM_2_0_0);
        assert!(ctx.auth.is_none());
    }
}
