//! Transport-level integration с iroh + nerw-core.
//!
//! Phase 2 binds nerw-rpc's wire format к the nerw-core embeddable
//! [`nerw_core::client::Client`] (which itself wraps an iroh
//! [`iroh::Endpoint`]). This module is intentionally thin —
//! [`IrohTransportClient`] is just а typed handle that lets
//! [`crate::server::RpcServer`] / [`crate::client::RpcClient`] /
//! [`crate::datagram::DatagramDispatcher`] share the same
//! `Arc<nerw_core::client::Client>` without each crate re-implementing
//! the cache + handler-registry + datagram-fanout machinery that
//! nerw-core already ships.
//!
//! ## ALPN constants
//!
//! Phase 2 fixes three ALPN strings — production callers MUST declare
//! all of them upfront via [`nerw_core::client::ClientConfigBuilder::with_alpn`]
//! at endpoint-build time. The convenience constant [`NERW_RPC_ALPNS`]
//! groups them так that callers can configure the endpoint в one shot:
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
//! runtime additions are a programming error (see
//! [`nerw_core::client::Client::register_alpn_handler`] docs).
//!
//! ## ALPN routing
//!
//! - `tolki/wire-protocol/2.0.0` — bidi RPC streams (request/response,
//!   server-streaming, client-streaming, bidi). Owned by
//!   [`crate::server::RpcServer`] на server side; opened on demand by
//!   [`crate::client::RpcClient::call`] on client side.
//! - `tolki/datagram/2.0.0`     — unreliable datagrams для voice и
//!   other unreliable subprotocols. Each datagram carries а
//!   `varint(stream-id)` prefix identifying the bidi handshake stream
//!   that established the session (WebTransport-style correlation —
//!   RFC 9221 + CONNECT-UDP / WebTransport). The 1.0.0 ALPN ran а
//!   1-byte token mapped к а 256-slot dispatcher; 2.0.0 dropped that
//!   wire-breaking change в favour of the unbounded stream-id keyed
//!   dispatch. Sent via [`nerw_core::client::Client::send_datagram`];
//!   received via the broadcast channel exposed by `subscribe_datagrams`.
//! - `nerw/rpc/2.0.0`           — built-in nerw protocol для inter-agent
//!   mesh control (NOT user-facing). Owned by nerw-core itself, NOT
//!   the nerw-rpc framework. Listed here so callers building а single
//!   shared endpoint can declare all three ALPNs in one shot.

use std::sync::Arc;

/// Bidi RPC ALPN — request / response / streaming flows.
///
/// Owned by [`crate::server::RpcServer`] on the server side. Opened on
/// demand by [`crate::client::RpcClient::call`] on the client side via
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
/// Datagrams ride on the same QUIC connection as the
/// `nerw/rpc/2.0.0`-multiplexed datagram path в nerw-core (Quinn
/// natively multiplexes streams + datagrams within ONE QUIC session).
/// This ALPN exists для future divergence (e.g. dedicated voice
/// connection с different transport tuning) but Phase 2 currently
/// piggybacks on nerw-core's RPC connection cache.
pub const ALPN_TOLKI_DATAGRAM_2_0_0: &[u8] = b"tolki/datagram/2.0.0";

/// Built-in nerw mesh-control ALPN — owned by nerw-core, listed here
/// for the convenience aggregate [`NERW_RPC_ALPNS`].
///
/// Callers MUST NOT register their own [`nerw_core::client::AlpnHandler`]
/// for this ALPN — nerw-core dispatches it directly via the accept loop
/// and rejects user registrations с
/// [`nerw_core::client::ClientError::AlpnIsBuiltin`].
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

/// Typed handle wrapping a shared [`nerw_core::client::Client`].
///
/// Phase 2 surface — both [`crate::server::RpcServer`] and
/// [`crate::client::RpcClient`] take this handle so они share the same
/// underlying iroh `Endpoint` (with its connection cache, peer table,
/// datagram broadcast channel). Holding the wrapper as `Arc` lets
/// downstream binaries clone the same handle into multiple service
/// objects without re-binding а new endpoint per service.
///
/// The wrapper does NOT own the lifecycle — the caller (typically the
/// binary's `main()`) owns the `Arc<Client>` and tears it down via
/// [`nerw_core::client::Client::shutdown`] at process exit.
#[derive(Debug, Clone)]
pub struct IrohTransportClient {
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
    /// test setup).
    #[must_use]
    pub fn inner(&self) -> &Arc<nerw_core::client::Client> {
        &self.inner
    }

    /// Local endpoint identity (z-base32 Ed25519 public key).
    #[must_use]
    pub fn node_id(&self) -> iroh::EndpointId {
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
