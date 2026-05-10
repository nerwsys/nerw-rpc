//! Per-request context types propagated to handlers.
//!
//! [`RpcContext`] is the read-only aggregate that every [`crate::method::MethodHandler`]
//! receives along with the request bytes. It bundles four logical groups:
//!
//! 1. [`PeerMetadata`] — transport-level identity (iroh node-id, addresses).
//! 2. [`TimingInfo`]   — wall-clock + monotonic timestamps captured at dispatch.
//! 3. [`AuthenticatedContext`] (через [`RpcContext::auth`]) — application-layer
//!    identity. `None` until middleware verifies credentials.
//! 4. [`SessionInfo`]  — optional long-lived session metadata.
//! 5. [`TracingInfo`]  — distributed tracing ids (trace-id, span-id, …).
//!
//! ## 🔒 Privacy mandate (port from tolki-wire, Pavel directive 2026-05-09)
//!
//! [`RpcContext`] does **not** carry а `client` group. Client metadata
//! (platform / OS / device-model / user-agent / locale) **never** flows
//! through this type. End-to-end encryption design предполагает honest-
//! but-curious server — exposing device characteristics would leak the
//! user behind the encryption layer. Fields here are restricted to opaque
//! cryptographic identifiers (peer-id, master pubkey, opaque UUIDs).
//!
//! ## Phase 2 — iroh integration
//!
//! The transport identity carrier is now [`iroh::EndpointId`] — the
//! z-base32-encoded Ed25519 public key proven by the QUIC/TLS handshake.
//! Phase 1 carried а local placeholder newtype; this module re-exports
//! `iroh::EndpointId` under the alias [`NodeId`] для backward-compat
//! с downstream code that imported the old name.

use uuid::Uuid;

/// Re-export of [`iroh::EndpointId`] — 32-byte Ed25519 public key.
///
/// Phase 1 carried а local placeholder; Phase 2 binds this к the real
/// iroh identity type. The alias is preserved для downstream code that
/// imported `nerw_rpc::NodeId`; new code may use [`iroh::EndpointId`]
/// directly.
pub type NodeId = iroh::EndpointId;

/// Transport-level peer identity captured by the iroh accept loop.
///
/// Built when a new bidi stream / datagram arrives and attached к every
/// [`RpcContext`] handed к а handler. Default values exist so in-memory
/// test transports can satisfy the type without fabricating real iroh
/// identities.
#[derive(Debug, Clone)]
pub struct PeerMetadata {
    /// Remote peer's iroh node-id (ed25519 public key).
    /// **Primary transport identity** — proven by the QUIC/TLS handshake.
    pub node_id: NodeId,

    /// Stable connection id (unique per established QUIC connection on
    /// this endpoint). Pairs with [`Self::stream_id`] for full path identity.
    pub connection_id: u64,

    /// QUIC stream id (unique per substream within а connection).
    pub stream_id: u64,

    /// Negotiated ALPN — е.g. `b"nerw-rpc/1"`.
    pub alpn: Vec<u8>,

    /// Wall-clock timestamp (ms since UNIX epoch) when the QUIC handshake
    /// completed. Useful for latency-budget tracking.
    pub handshake_at_ms: i64,

    /// TLS cipher suite negotiated for this connection
    /// (e.g. `"TLS13_CHACHA20_POLY1305_SHA256"`). `None` for loopback / test.
    pub tls_cipher_suite: Option<String>,
}

impl PeerMetadata {
    /// Build a deterministic placeholder suitable for in-memory tests.
    ///
    /// All fields are filled with stable dummy values so test assertions
    /// can pin them down. The node-id is derived from an all-zero
    /// Ed25519 secret seed — а deterministic, never-used-in-production
    /// public key. Callers cannot replay it as а production identity
    /// because the corresponding secret is the all-zero vector
    /// (publicly known).
    #[must_use]
    pub fn loopback() -> Self {
        Self {
            node_id: loopback_node_id(),
            connection_id: 0,
            stream_id: 0,
            alpn: b"nerw-rpc/1".to_vec(),
            handshake_at_ms: 0,
            tls_cipher_suite: None,
        }
    }
}

/// Deterministic placeholder [`NodeId`] for in-memory tests / loopback
/// transports — derived from the all-zero Ed25519 secret seed.
///
/// Never appears in production: the corresponding secret is publicly
/// known. Tests use it to pin assertions on а stable identity without
/// fabricating real iroh keys.
#[must_use]
pub fn loopback_node_id() -> NodeId {
    iroh::SecretKey::from_bytes(&[0u8; 32]).public()
}

impl Default for PeerMetadata {
    fn default() -> Self {
        Self::loopback()
    }
}

/// Application-layer authentication context (port from tolki-wire — privacy-first).
///
/// Two states:
///
/// - `None` — transport peer-id is known but the application identity
///   (user / device) has not been resolved yet. Handlers that require
///   authentication should reject these calls.
/// - `Some(AuthenticatedContext)` — peer is a known origin. Handlers may
///   inspect [`AuthenticatedContext::scopes`] to enforce permissions.
///
/// Carries ONLY opaque cryptographic identifiers (peer-id, master pubkey,
/// opaque `UUIDv7`s, scopes, timestamps). NO platform / OS / device-model /
/// user-agent / locale fields exist here — the server stays «slepoy» on
/// client metadata as а design invariant.
#[derive(Debug, Clone)]
pub struct AuthenticatedContext {
    /// Transport peer-id (proven by QUIC/TLS handshake).
    pub node_id: NodeId,

    /// Ed25519 master public key registered against this origin in the
    /// identity registry. Opaque cryptographic identifier — does **not**
    /// reveal device / platform metadata.
    pub master_pubkey: [u8; 32],

    /// Resolved user-id (`UUIDv7`, opaque). Generated server-side at first
    /// registration; **not** derived from any hardware identifier.
    pub user_id: Uuid,

    /// Device-id (`UUIDv7`, opaque). Generated client-side on first install
    /// — **no** relation to hardware UUID / IMEI / serial number. Server
    /// uses it only to distinguish different devices of the same user
    /// (message routing, session tracking) — never for fingerprinting.
    pub device_id: Uuid,

    /// Granted scopes — handlers gate sensitive operations by checking
    /// these strings.
    pub scopes: Vec<String>,

    /// Wall-clock ms when this origin first registered.
    pub registered_at_ms: i64,

    /// Wall-clock ms when this origin last successfully called any RPC.
    pub last_seen_at_ms: i64,
    // ⛔ Privacy mandate — DO NOT add platform / os_version / device_model /
    // user_agent / app_build / locale here.
}

impl AuthenticatedContext {
    /// `true` if `scope` appears in [`Self::scopes`].
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// Optional session-level metadata attached to long-lived peer connections.
///
/// `None` for connections that never exchanged keepalive heartbeats.
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    /// Stable session id (`UUIDv7` generated server-side at first contact).
    pub session_id: Uuid,
    /// Wall-clock ms when the session was opened.
    pub session_started_at_ms: i64,
    /// Wall-clock ms of the latest activity on this session.
    pub last_activity_ms: i64,
    /// How many keepalive frames the session has exchanged.
    pub keepalive_count: u32,
}

/// Per-request timing metadata captured at the dispatch boundary.
///
/// Wall-clock + monotonic timestamps live in different fields on purpose:
/// handlers that compute latency must use the monotonic field
/// ([`Self::received_at_monotonic_ns`]) — wall-clock is not monotonic
/// (NTP / DST adjustments). Wall-clock ([`Self::received_at_ms`]) is
/// preserved for log correlation, audit trails, and replay-window checks.
#[derive(Debug, Clone, Copy)]
pub struct TimingInfo {
    /// Wall-clock ms since UNIX epoch when the frame finished decoding.
    pub received_at_ms: i64,

    /// Monotonic ns since process start when the frame finished decoding.
    /// Use this — not [`Self::received_at_ms`] — for latency measurements.
    pub received_at_monotonic_ns: u64,

    /// Hot-path profiling — microseconds spent decoding the inbound frame
    /// before the handler started running. `0` if not measured.
    pub frame_decode_duration_us: u64,
}

impl TimingInfo {
    /// Zero-valued snapshot — used by tests / fallback paths that do not
    /// measure timing.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            received_at_ms: 0,
            received_at_monotonic_ns: 0,
            frame_decode_duration_us: 0,
        }
    }
}

impl Default for TimingInfo {
    fn default() -> Self {
        Self::zero()
    }
}

/// Distributed tracing identifiers attached to every RPC.
///
/// Generated server-side if the caller did not pre-fill any of these
/// fields. Cross-service RPC clients copy parent ids forward to maintain
/// the trace.
#[derive(Debug, Clone, Copy)]
pub struct TracingInfo {
    /// Trace-id propagated across all RPCs that constitute one logical
    /// operation.
    pub trace_id: Uuid,

    /// Span-id unique to this specific RPC call.
    pub span_id: Uuid,

    /// Parent span-id if this call is a child of a larger trace.
    pub parent_span_id: Option<Uuid>,

    /// Caller-supplied correlation-id for debugging cross-service round-trips.
    pub correlation_id: Option<Uuid>,

    /// `true` if this trace should be recorded in the tracing backend.
    /// Hot-path RPCs default to `false`.
    pub sampled: bool,
}

impl TracingInfo {
    /// Build a fresh tracing snapshot — generates new `trace_id` and
    /// `span_id` (`UUIDv4`) and leaves parent / correlation as `None`.
    #[must_use]
    pub fn fresh() -> Self {
        Self {
            trace_id: Uuid::new_v4(),
            span_id: Uuid::new_v4(),
            parent_span_id: None,
            correlation_id: None,
            sampled: false,
        }
    }
}

impl Default for TracingInfo {
    fn default() -> Self {
        Self::fresh()
    }
}

/// Immutable per-request context attached к every dispatched RPC.
///
/// Built by the dispatch layer (Phase 2) from the transport [`PeerMetadata`],
/// the decoded frame, and the server's static / shared state. Handlers
/// borrow it through the trait method on [`crate::method::MethodHandler`].
#[derive(Debug, Clone)]
pub struct RpcContext {
    /// Transport-level identity captured by the accept loop.
    pub peer: PeerMetadata,

    /// Timing snapshot captured at the dispatch boundary.
    pub timing: TimingInfo,

    /// Application identity. `None` until middleware populates it.
    pub auth: Option<AuthenticatedContext>,

    /// Optional long-lived session metadata (heartbeat keepalive only).
    pub session: Option<SessionInfo>,

    /// Distributed tracing ids — generated server-side if caller did not
    /// pre-fill any.
    pub tracing: TracingInfo,
    // ⛔ Privacy mandate — RpcContext does NOT carry а `client` field.
    // No platform / OS / device-model / user-agent / locale ever flows
    // through this type.
}

impl RpcContext {
    /// Build a minimal context suitable for tests / legacy code paths
    /// that have no auth / tracing middleware.
    #[must_use]
    pub fn minimal(peer: PeerMetadata) -> Self {
        Self {
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

    #[test]
    fn loopback_node_id_is_deterministic() {
        let a = loopback_node_id();
        let b = loopback_node_id();
        assert_eq!(a, b, "loopback_node_id must be deterministic");
    }

    #[test]
    fn peer_metadata_loopback_has_alpn() {
        let m = PeerMetadata::loopback();
        assert_eq!(m.alpn, b"nerw-rpc/1");
        assert_eq!(m.node_id, loopback_node_id());
    }

    #[test]
    fn timing_zero_default() {
        let t = TimingInfo::default();
        assert_eq!(t.received_at_ms, 0);
        assert_eq!(t.received_at_monotonic_ns, 0);
    }

    #[test]
    fn tracing_fresh_distinct_ids() {
        let t = TracingInfo::fresh();
        assert_ne!(t.trace_id, Uuid::nil());
        assert_ne!(t.span_id, Uuid::nil());
        assert_ne!(t.trace_id, t.span_id);
        assert!(t.parent_span_id.is_none());
        assert!(!t.sampled);
    }

    #[test]
    fn tracing_fresh_yields_distinct_ids_per_call() {
        let a = TracingInfo::fresh();
        let b = TracingInfo::fresh();
        assert_ne!(a.trace_id, b.trace_id);
        assert_ne!(a.span_id, b.span_id);
    }

    #[test]
    fn authenticated_has_scope() {
        let auth = AuthenticatedContext {
            node_id: loopback_node_id(),
            master_pubkey: [0u8; 32],
            user_id: Uuid::new_v4(),
            device_id: Uuid::new_v4(),
            scopes: vec!["chat:send".to_string(), "profile:read".to_string()],
            registered_at_ms: 0,
            last_seen_at_ms: 0,
        };
        assert!(auth.has_scope("chat:send"));
        assert!(auth.has_scope("profile:read"));
        assert!(!auth.has_scope("admin"));
    }

    #[test]
    fn rpc_context_minimal_anonymous() {
        let ctx = RpcContext::minimal(PeerMetadata::loopback());
        assert!(ctx.auth.is_none());
        assert!(ctx.session.is_none());
        assert_ne!(ctx.tracing.trace_id, Uuid::nil());
    }
}
