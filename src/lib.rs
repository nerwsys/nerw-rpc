//! nerw-rpc — Mesh-agnostic RPC framework для nerw P2P mesh.
//!
//! ## Design summary
//!
//! - **Wire format:** postcard (positional, no field tags, varint+zigzag)
//! - **Method-id:** text canonical name `package@version/interface/method`
//!   (e.g. `tolki:chat@1.0.0/chat/send-message`). Версия опциональна
//!   (без — server picks latest semver).
//! - **Stream-per-request:** QUIC stream-id correlates request↔response,
//!   no wire-level request-id.
//! - **Transport:** iroh QUIC + datagrams (binding в Phase 2).
//! - **Auth context:** `RpcContext` propagated через handler invocation.
//! - **Schema discoverability:** mandatory `tolki:schema@1.0.0/schema/get`
//!   method returns flattened WIT document.
//!
//! ## Status
//!
//! Phase 3 — bidi streaming surface (v0.9.0). Adds
//! [`StreamingMethodHandler`] + [`MethodRegistry::register_streaming`] +
//! [`RpcClient::call_streaming`] alongside the existing unary path —
//! one streaming call rides one QUIC bidi substream on the same
//! `nerw/rpc/1.0.0` ALPN, no second listener required. Wire envelope
//! documented в `wit/nerw-rpc.wit`.
//!
//! Backward compatibility: existing unary [`RpcClient::call`] и
//! [`MethodHandler`] keep working unchanged — the dispatch layer
//! discriminates на the opening opcode byte
//! ([`wire::OPCODE_UNARY_REQUEST`] vs [`wire::OPCODE_STREAMING_OPEN_REQUEST`]).
//!
//! Earlier phases:
//! - Phase 2.1 — internal refactor onto post-R3 nerw-core surface
//!   (commit `48ec369`); wire-format intelligence (ALPN dispatch table,
//!   accept loop, per-connection datagram readers) lives entirely inside
//!   nerw-rpc.
//!
//! См. authoritative design в
//! `/src/tasks/tolki-server/.artifacts/research/NERW-RPC-DESIGN.md`.

#![doc(html_root_url = "https://docs.rs/nerw-rpc/0.9.0")]
#![cfg_attr(
    test,
    allow(
        // Assertions in tests are explicit by design.
        clippy::expect_used,
        clippy::unwrap_used,
        clippy::panic,
        // `_ => panic!("expected variant X, got {other:?}")` is the
        // idiomatic test pattern for narrow variant assertions. Listing
        // every variant explicitly бы добавил noise без security gain
        // (test code, not production crossing trust boundary).
        clippy::wildcard_enum_match_arm,
        // Numeric literals in test asserts default к i32 which is fine
        // — tests never round-trip to disk/wire, no portability risk.
        clippy::default_numeric_fallback,
        // `Arc::clone(&h)` vs `h.clone()` — test code is exempt; the
        // semantic distinction matters only at production-call sites.
        clippy::clone_on_ref_ptr,
        // `h as Arc<dyn Trait>` upcast в `Arc::ptr_eq` test —
        // unsizing coercion is the language-blessed way.
        clippy::as_conversions,
        // `Vec::with_capacity(1 + body.len())` test buffer builders.
        // Overflow path is statically impossible for fixture-sized inputs.
        clippy::arithmetic_side_effects,
    )
)]

pub mod client;
pub mod codec;
pub mod context;
pub mod datagram;
pub mod error;
pub mod method;
pub mod schema;
pub mod server;
pub mod streaming;
pub mod transit;
pub mod transport;
pub mod wire;
pub mod wire_error;

// Re-exports для конвенции
pub use crate::client::RpcClient;
pub use crate::context::{
    AuthenticatedContext, NodeId, PeerMetadata, RpcContext, SessionInfo, TimingInfo, TracingInfo,
    loopback_node_id,
};
pub use crate::datagram::{DEFAULT_MAX_CONCURRENT_DATAGRAMS, DatagramDispatcher, DatagramHandler};
pub use crate::error::{RpcError, RpcResult};
pub use crate::method::{MethodHandler, MethodName, MethodRegistry};
pub use crate::schema::{
    METHOD_SCHEMA_GET, SchemaError, SchemaHandler, SchemaResponse, register_schema_method,
};
pub use crate::server::{
    DEFAULT_MAX_CONCURRENT_CONNECTIONS, DEFAULT_MAX_CONCURRENT_STREAMS, RpcServer, RpcServerConfig,
};
pub use crate::streaming::{
    StreamingError, StreamingMethodHandler, StreamingOpenRequest, StreamingOpenResponse,
    StreamingOpenStatus,
};
pub use crate::transit::{
    Capabilities, ConnectOutcome, DEFAULT_RESERVATION_TTL_SECS, Limits, ReserveOutcome,
    TransitError, TransitFrame, Voucher, decode_frame, encode_frame,
};
pub use crate::transport::{
    ALPN_NERW_DATAGRAM_1_0_0, ALPN_NERW_MESH_1_0_0, ALPN_NERW_RPC_1_0_0, ALPN_NERW_TRANSIT_1_0_0,
    AlpnHandler, IrohTransportClient, NERW_RPC_ALPNS,
};
pub use crate::wire_error::WireError;
