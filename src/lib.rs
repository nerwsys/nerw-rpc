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
//! Phase 1 — core types, codec, method registry. Transport binding
//! (iroh integration) coming in Phase 2 после nerw Batch 2d merges.
//!
//! См. authoritative design в
//! `/src/tasks/tolki-server/.artifacts/research/NERW-RPC-DESIGN.md`.

#![doc(html_root_url = "https://docs.rs/nerw-rpc/0.3.0")]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod client;
pub mod codec;
pub mod context;
pub mod datagram;
pub mod error;
pub mod method;
pub mod server;
pub mod transport;
pub mod wire;
pub mod wire_error;

// Re-exports для конвенции
pub use crate::client::RpcClient;
pub use crate::context::{
    AuthenticatedContext, NodeId, PeerMetadata, RpcContext, SessionInfo, TimingInfo, TracingInfo,
    loopback_node_id,
};
pub use crate::datagram::{DatagramDispatcher, DatagramHandler};
pub use crate::error::{RpcError, RpcResult};
pub use crate::method::{MethodHandler, MethodName, MethodRegistry};
pub use crate::server::{
    DEFAULT_MAX_CONCURRENT_CONNECTIONS, DEFAULT_MAX_CONCURRENT_STREAMS, RpcServer, RpcServerConfig,
};
pub use crate::transport::{
    ALPN_NERW_RPC_2_0_0, ALPN_TOLKI_DATAGRAM_1_0_0, ALPN_TOLKI_WIRE_PROTOCOL_2_0_0,
    IrohTransportClient, NERW_RPC_ALPNS,
};
pub use crate::wire_error::WireError;
