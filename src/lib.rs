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

#![doc(html_root_url = "https://docs.rs/nerw-rpc/0.1.0")]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used, clippy::panic))]

pub mod codec;
pub mod context;
pub mod error;
pub mod method;
pub mod wire;

// Re-exports для конвенции
pub use crate::context::{
    AuthenticatedContext, NodeId, PeerMetadata, RpcContext, SessionInfo, TimingInfo, TracingInfo,
};
pub use crate::error::{RpcError, RpcResult};
pub use crate::method::{MethodHandler, MethodName, MethodRegistry};
