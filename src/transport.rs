//! Transport-level integration с iroh + nerw-core.
//!
//! Phase 2.1 binds nerw-rpc's wire format к the post-R3 nerw-core
//! embeddable [`nerw_core::client::Client`] (which itself wraps an iroh
//! [`iroh::Endpoint`]). After R3 (commit `48ec369`) nerw-core sheds
//! every piece of wire-format intelligence — the ALPN handler registry,
//! datagram broadcast pubsub, and inbound-envelope decoder all moved
//! к `nerw-daemon::daemon::wire`. nerw-rpc no longer leans on those
//! gone surfaces; instead it owns its own accept loop, an internal
//! `AlpnHandler` table, and per-connection datagram readers.
//!
//! [`IrohTransportClient`] is the typed handle that lets
//! [`crate::server::RpcServer`] / [`crate::client::RpcClient`] /
//! [`crate::datagram::DatagramDispatcher`] share the same
//! `Arc<nerw_core::client::Client>` без each crate re-wrapping the
//! cache + endpoint машинерию nerw-core already ships.
//!
//! ## ALPN constants
//!
//! Phase 2.1 fixes three ALPN strings — production callers MUST declare
//! all of them upfront via [`nerw_core::client::ClientConfigBuilder::with_alpn`]
//! at endpoint-build time. The convenience constant [`NERW_RPC_ALPNS`]
//! groups them так что callers can configure the endpoint в one shot:
//!
//! ```no_run
//! # use nerw_core::client::ClientConfig;
//! # use nerw_rpc::transport::NERW_RPC_ALPNS;
//! let mut builder = ClientConfig::builder();
//! for alpn in NERW_RPC_ALPNS {
//!     builder = builder.with_alpn(alpn.to_vec());
//! }
//! let _config = builder.build();
//! ```
//!
//! iroh's rustls server config locks the ALPN list at builder time —
//! runtime additions are а programming error.
//!
//! ## ALPN routing (owned by [`crate::server::RpcServer`] internally)
//!
//! - `tolki/wire-protocol/2.0.0` — bidi RPC streams (request/response,
//!   server-streaming, client-streaming, bidi). Dispatched к the
//!   private wire-handler by [`crate::server::RpcServer::serve`]; opened
//!   on demand by [`crate::client::RpcClient::call`] on the client side
//!   via [`nerw_core::client::Client::dial_with_alpn`] +
//!   [`nerw_core::client::Client::open_substream`].
//! - `tolki/datagram/2.0.0`     — unreliable datagrams для voice и
//!   other unreliable subprotocols. Each datagram carries а
//!   `varint(stream-id)` prefix identifying the bidi handshake stream
//!   that established the session (WebTransport-style correlation —
//!   RFC 9221 + CONNECT-UDP / WebTransport). Consumers wire а
//!   [`crate::datagram::DatagramDispatcher`] onto а connection via
//!   [`crate::datagram::DatagramDispatcher::subscribe_connection`].
//! - `nerw/rpc/2.0.0`           — built-in nerw protocol для inter-agent
//!   mesh control (NOT user-facing). Owned by nerw-daemon's wire layer,
//!   NOT the nerw-rpc framework. Listed here so callers building а
//!   single shared endpoint can declare all three ALPNs in one shot.

use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;

use crate::error::RpcResult;

/// Bidi RPC ALPN — request / response / streaming flows.
///
/// Owned by [`crate::server::RpcServer`] on the server side (the server's
/// accept loop dispatches inbound connections matching this ALPN к the
/// internal wire-protocol handler). Opened on demand by
/// [`crate::client::RpcClient::call`] on the client side via
/// [`nerw_core::client::Client::dial_with_alpn`] +
/// [`nerw_core::client::Client::open_substream`].
pub const ALPN_TOLKI_WIRE_PROTOCOL_2_0_0: &[u8] = b"tolki/wire-protocol/2.0.0";

/// Unreliable datagram ALPN — voice / RTP and other unreliable
/// subprotocols.
///
/// ## Wire format (2.0.0 — wire-breaking change vs 1.0.0)
///
/// Each datagram carries а `varint(stream-id)` prefix identifying the
/// bidi handshake stream that established the session, followed by the
/// postcard-encoded payload. This mirrors WebTransport's quarter-stream-id
/// correlation (RFC 9221 + CONNECT-UDP / WebTransport) — datagrams и
/// streams sharing the same logical session are correlated by the
/// handshake stream's QUIC stream-id.
///
/// The 1.0.0 ALPN used а 1-byte token mapped к а 256-slot dispatcher,
/// которое imposed а 256-session cap per connection и could not link
/// datagrams к their establishing stream. 2.0.0 drops the cap и adds
/// stream-handshake correlation в one wire-breaking change.
///
/// Datagrams ride on the same QUIC connection as bidi streams (iroh /
/// Quinn natively multiplexes streams + datagrams within ONE QUIC
/// session). Phase 2.1 exposes this through
/// [`crate::datagram::DatagramDispatcher::subscribe_connection`], которое
/// the application wires к а connection it gets from either а custom
/// `AlpnHandler` (inbound) или а `dial_with_alpn` call (outbound).
pub const ALPN_TOLKI_DATAGRAM_2_0_0: &[u8] = b"tolki/datagram/2.0.0";

/// Built-in nerw mesh-control ALPN — owned by nerw-daemon's wire layer,
/// listed here for the convenience aggregate [`NERW_RPC_ALPNS`].
///
/// nerw-rpc callers MUST NOT register their own [`AlpnHandler`] for this
/// ALPN — collisions с nerw-daemon's built-in dispatch are undefined
/// behaviour. The constant is exposed solely so embedded clients
/// declaring а single endpoint can advertise every ALPN nerw-rpc +
/// nerw-daemon will ever accept в one shot.
pub const ALPN_NERW_RPC_2_0_0: &[u8] = b"nerw/rpc/2.0.0";

/// Aggregate convenience for [`nerw_core::client::ClientConfigBuilder::with_alpn`].
///
/// Callers iterate this slice к declare every ALPN nerw-rpc + nerw-core
/// will ever accept, satisfying the "all ALPNs upfront" iroh constraint
/// в one shot:
///
/// ```no_run
/// # use nerw_core::client::ClientConfig;
/// # use nerw_rpc::transport::NERW_RPC_ALPNS;
/// let mut builder = ClientConfig::builder();
/// for alpn in NERW_RPC_ALPNS {
///     builder = builder.with_alpn(alpn.to_vec());
/// }
/// ```
pub const NERW_RPC_ALPNS: &[&[u8]] = &[
    ALPN_TOLKI_WIRE_PROTOCOL_2_0_0,
    ALPN_TOLKI_DATAGRAM_2_0_0,
    ALPN_NERW_RPC_2_0_0,
];

/// Handler trait for inbound connections that negotiated а custom ALPN.
///
/// Phase 2.1 owns its own ALPN dispatch table — see
/// [`crate::server::RpcServer::register_alpn_handler`]. Internal
/// wire-protocol dispatch (the 2.0.0 RPC frame format) is bound by
/// [`crate::server::RpcServer::serve`]; advanced callers can register
/// additional handlers for application-specific ALPNs they declared
/// upfront via [`nerw_core::client::ClientConfigBuilder::with_alpn`].
///
/// The trait is `async` (returns а future) so handlers can drive
/// `accept_bi` / `read_datagram` loops without blocking the server's
/// accept loop. Handlers MUST NOT panic — а panic on the handler task
/// is logged but does not stop the accept loop.
///
/// # Why local к nerw-rpc
///
/// Post-R3 (commit `48ec369`) nerw-core no longer ships an `AlpnHandler`
/// trait — that surface moved к `nerw_daemon::daemon::wire::AlpnHandler`.
/// nerw-rpc owns its own copy here so the framework does not pull in
/// the daemon-side wire crate just for а trait definition. The two
/// traits are intentionally similar в shape (sync `handle(conn)` in the
/// daemon, async in nerw-rpc) but live в separate ownership domains —
/// daemon dispatches built-in nerw messaging, nerw-rpc dispatches the
/// generic RPC framework.
#[async_trait]
pub trait AlpnHandler: Send + Sync + 'static {
    /// Process an inbound connection that negotiated this handler's ALPN.
    ///
    /// Implementations typically spawn а per-connection accept-bi loop
    /// (for bidi-stream protocols) or а per-connection
    /// [`iroh::endpoint::Connection::read_datagram`] loop (for datagram
    /// protocols). The handler is invoked on its own `tokio::spawn`ed
    /// task — implementations do not need к spawn themselves to avoid
    /// blocking the accept loop.
    ///
    /// # Errors
    ///
    /// Implementation-defined. Returned errors are logged at the
    /// dispatcher level и do not abort the accept loop — а transient
    /// failure on one connection does not affect subsequent inbound
    /// arrivals.
    async fn handle(&self, connection: Connection) -> RpcResult<()>;
}

/// Typed handle wrapping а shared [`nerw_core::client::Client`].
///
/// Phase 2.1 surface — [`crate::server::RpcServer`],
/// [`crate::client::RpcClient`], и
/// [`crate::datagram::DatagramDispatcher`] all take this handle so они
/// share the same underlying iroh `Endpoint` (с its connection cache,
/// peer table). Holding the wrapper as `Arc` lets downstream binaries
/// clone the same handle into multiple service objects without re-binding
/// а new endpoint per service.
///
/// The wrapper does NOT own the lifecycle — the caller (typically the
/// binary's `main()`) owns the `Arc<Client>` и tears it down via
/// [`nerw_core::client::Client::shutdown`] at process exit.
#[derive(Debug, Clone)]
pub struct IrohTransportClient {
    /// Shared owner of the iroh endpoint. `Arc` makes
    /// [`IrohTransportClient`] cheap к clone across spawned tasks.
    inner: Arc<nerw_core::client::Client>,
}

impl IrohTransportClient {
    /// Wrap а shared [`nerw_core::client::Client`].
    ///
    /// The caller is responsible for spawning + tearing down the
    /// underlying endpoint. Cloning [`IrohTransportClient`] is cheap
    /// (single `Arc::clone`).
    #[must_use]
    pub const fn new(client: Arc<nerw_core::client::Client>) -> Self {
        Self { inner: client }
    }

    /// Borrow the underlying nerw-core client (for direct access к
    /// its public surface — e.g. `peer_table().insert(...)` during
    /// test setup, or `dial_with_alpn` для custom ALPN paths).
    #[must_use]
    pub const fn inner(&self) -> &Arc<nerw_core::client::Client> {
        &self.inner
    }

    /// Local endpoint identity (z-base32 Ed25519 public key).
    ///
    /// Returns [`nerw_core::identity::NodeId`] (а type alias for
    /// `iroh::EndpointId` / `iroh::PublicKey` as of R3). When R4 ships
    /// `NerwNodeId(iroh::PublicKey)` newtype wrapper, this signature
    /// will resolve к the wrapper automatically — callers using
    /// `nerw_core::identity::NodeId` import are future-proof.
    #[must_use]
    pub fn node_id(&self) -> nerw_core::identity::NodeId {
        self.inner.node_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nerw_rpc_alpns_covers_every_advertised_constant() {
        assert!(NERW_RPC_ALPNS.contains(&ALPN_TOLKI_WIRE_PROTOCOL_2_0_0));
        assert!(NERW_RPC_ALPNS.contains(&ALPN_TOLKI_DATAGRAM_2_0_0));
        assert!(NERW_RPC_ALPNS.contains(&ALPN_NERW_RPC_2_0_0));
        assert_eq!(NERW_RPC_ALPNS.len(), 3);
    }

    #[test]
    fn alpn_constants_have_expected_byte_strings() {
        assert_eq!(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, b"tolki/wire-protocol/2.0.0");
        assert_eq!(ALPN_TOLKI_DATAGRAM_2_0_0, b"tolki/datagram/2.0.0");
        assert_eq!(ALPN_NERW_RPC_2_0_0, b"nerw/rpc/2.0.0");
    }
}
