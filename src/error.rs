//! Error types для nerw-rpc.
//!
//! [`RpcError`] is the framework's top-level error type. Variants split into:
//!
//! - **Wire errors** ([`RpcError::Codec`], [`RpcError::MalformedFrame`]) —
//!   produced by the codec / wire layer when bytes don't decode.
//! - **Dispatch errors** ([`RpcError::UnknownMethod`],
//!   [`RpcError::InvalidMethodName`], [`RpcError::VersionMismatch`]) —
//!   produced by the method registry when no handler matches.
//! - **Handler errors** ([`RpcError::Handler`]) — opaque wrapper around
//!   user-defined errors returned from a [`crate::method::MethodHandler`].
//! - **Transport errors** ([`RpcError::TransportOpenSubstream`],
//!   [`RpcError::TransportRegisterAlpn`], [`RpcError::TransportRead`],
//!   [`RpcError::TransportWrite`]) — concrete iroh-specific failure modes
//!   surfaced by [`crate::client::RpcClient`] / [`crate::server::RpcServer`].
//! - **Datagram errors** ([`RpcError::DatagramTokenCollision`],
//!   [`RpcError::DatagramTokenUnknown`], [`RpcError::DatagramTooShort`])
//!   — surface for [`crate::datagram::DatagramDispatcher`].

use thiserror::Error;

/// Top-level error type for nerw-rpc operations.
#[derive(Debug, Error)]
pub enum RpcError {
    /// Postcard codec failure — bytes do not deserialize into the expected type.
    #[error("codec error: {0}")]
    Codec(#[from] postcard::Error),

    /// Wire frame structure violated (truncated buffer, bad opcode, …).
    #[error("malformed wire frame: {0}")]
    MalformedFrame(String),

    /// No handler registered for the requested canonical method name.
    #[error("unknown method: {0}")]
    UnknownMethod(String),

    /// Method name string did not match `package[@version]/interface/method` grammar.
    #[error("invalid method-name format: expected `package[@version]/interface/method`, got `{0}`")]
    InvalidMethodName(String),

    /// Caller pinned a specific version that is not available; the registry
    /// reports which versions it knows about.
    #[error("version mismatch: requested {requested}, available {available:?}")]
    VersionMismatch {
        /// Version string the caller asked for.
        requested: String,
        /// Versions the registry has registered for this `package/interface/method` triple.
        available: Vec<String>,
    },

    /// User handler returned an error. The original error type is erased
    /// behind a `Box<dyn Error>` so the framework stays generic over
    /// application error hierarchies.
    #[error("handler error: {0}")]
    Handler(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Failed к open а bidi substream к а peer (peer not in table, dial
    /// failure, ALPN mismatch, …).
    #[error("transport: failed to open substream to peer {node_id}: {reason}")]
    TransportOpenSubstream {
        /// Target peer's [`crate::context::NodeId`] rendered as а string —
        /// `iroh::EndpointId` does not implement `Clone`-friendly Display
        /// preservation for our error type.
        node_id: String,
        /// Underlying error rendered via `format!("{e}")` (iroh's
        /// connect/open errors do not implement `Clone`).
        reason: String,
    },

    /// Failed к register an ALPN handler с the underlying nerw-core
    /// client (е.g. ALPN was not pre-declared в `ClientConfigBuilder::with_alpn`).
    #[error("transport: failed to register ALPN handler '{alpn}': {reason}")]
    TransportRegisterAlpn {
        /// The ALPN bytes rendered via `String::from_utf8_lossy`.
        alpn: String,
        /// Underlying error rendered via `format!("{e}")`.
        reason: String,
    },

    /// Read failure on а QUIC stream (peer reset, idle timeout, malformed framing).
    #[error("transport: read failed: {reason}")]
    TransportRead {
        /// Underlying error rendered via `format!("{e}")`.
        reason: String,
    },

    /// Write failure on а QUIC stream (peer closed receive half, …).
    #[error("transport: write failed: {reason}")]
    TransportWrite {
        /// Underlying error rendered via `format!("{e}")`.
        reason: String,
    },

    /// Caller asked [`crate::datagram::DatagramDispatcher::register`] к
    /// register а handler at а token slot already occupied.
    #[error("datagram: token {token} already registered")]
    DatagramTokenCollision {
        /// The token slot that was already in use.
        token: u8,
    },

    /// Inbound datagram was dispatched к а token slot с no registered handler.
    #[error("datagram: token {token} not registered")]
    DatagramTokenUnknown {
        /// The token byte read from the datagram prefix.
        token: u8,
    },

    /// Inbound datagram was empty — there is no token byte к dispatch on.
    #[error("datagram: too short ({len} bytes), need at least 1 byte for token")]
    DatagramTooShort {
        /// Actual length of the malformed datagram.
        len: usize,
    },
}

/// Convenience alias for `Result<T, RpcError>`.
pub type RpcResult<T> = Result<T, RpcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_method_displays_name() {
        let err = RpcError::UnknownMethod("foo:bar@1.0.0/iface/m".to_string());
        let s = err.to_string();
        assert!(s.contains("foo:bar@1.0.0/iface/m"));
    }

    #[test]
    fn version_mismatch_displays_both() {
        let err = RpcError::VersionMismatch {
            requested: "2.0.0".to_string(),
            available: vec!["1.0.0".to_string(), "1.1.0".to_string()],
        };
        let s = err.to_string();
        assert!(s.contains("2.0.0"));
        assert!(s.contains("1.0.0"));
    }

    #[test]
    fn codec_error_wraps_postcard() {
        // Decoding empty bytes as a struct triggers a postcard error.
        #[derive(Debug, serde::Deserialize)]
        struct Sample {
            _a: u32,
        }
        let res: Result<Sample, _> = postcard::from_bytes(&[]);
        let err: RpcError = res.expect_err("decode of empty buffer must fail").into();
        assert!(matches!(err, RpcError::Codec(_)));
    }

    #[test]
    fn transport_open_substream_displays_node_and_reason() {
        let err = RpcError::TransportOpenSubstream {
            node_id: "abc-deadbeef".to_string(),
            reason: "handshake timeout".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("abc-deadbeef"));
        assert!(s.contains("handshake timeout"));
    }

    #[test]
    fn transport_register_alpn_displays_alpn() {
        let err = RpcError::TransportRegisterAlpn {
            alpn: "tolki/wire-protocol/2.0.0".to_string(),
            reason: "not preregistered".to_string(),
        };
        let s = err.to_string();
        assert!(s.contains("tolki/wire-protocol/2.0.0"));
        assert!(s.contains("not preregistered"));
    }

    #[test]
    fn datagram_token_collision_displays_token() {
        let err = RpcError::DatagramTokenCollision { token: 42 };
        let s = err.to_string();
        assert!(s.contains("42"));
        assert!(s.contains("already registered"));
    }

    #[test]
    fn datagram_token_unknown_displays_token() {
        let err = RpcError::DatagramTokenUnknown { token: 7 };
        let s = err.to_string();
        assert!(s.contains("7"));
        assert!(s.contains("not registered"));
    }

    #[test]
    fn datagram_too_short_displays_len() {
        let err = RpcError::DatagramTooShort { len: 0 };
        let s = err.to_string();
        assert!(s.contains('0'));
        assert!(s.contains("too short"));
    }
}
