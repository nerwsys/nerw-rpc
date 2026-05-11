//! Typed wire-level error envelope для unary RPC failure responses.
//!
//! ## Why а typed envelope (and not just а string)
//!
//! Phase 2's first cut encoded errors as а single postcard-encoded
//! `String` (e.g. the `Display` of [`crate::error::RpcError`]). The
//! client side then matched on string prefixes (`"unknown method:"`)
//! to reconstruct the variant. Two problems с that:
//!
//! 1. **Locale footgun.** Project convention is "all communication в
//!    Russian" — including human-readable strings in code paths.
//!    If а maintainer translates the error message в Russian, the
//!    client's `starts_with("unknown method:")` silently breaks and
//!    every `UnknownMethod` collapses к `RpcError::Handler`. Tests
//!    pass (Display is independent), runtime breaks silently.
//! 2. **No structured payload.** Variants like `VersionMismatch` carry
//!    metadata (requested + available versions) that а string cannot
//!    convey unless the server formats it on encode and the client
//!    parses it back on decode — fragile.
//!
//! ## Wire format
//!
//! `[OPCODE_UNARY_ERROR | postcard(WireError)]`
//!
//! `WireError` is а `#[repr(u8)]` enum, so postcard encodes it as
//! `[discriminant 1B | postcard(payload)]`. The discriminant byte
//! makes the encoding **locale-invariant** — переводы display strings
//! не affect the wire bytes.
//!
//! Variants intentionally mirror [`crate::error::RpcError`]'s public
//! variants that can be triggered by а client request. Internal
//! framework errors (`Codec`, `MalformedFrame`) are also surfaced so
//! the client сan distinguish а server-side decode bug from а
//! handler error.

use serde::{Deserialize, Serialize};

use crate::error::RpcError;

/// Discriminant byte for [`WireError::UnknownMethod`].
pub const WIRE_ERROR_UNKNOWN_METHOD: u8 = 0x00;
/// Discriminant byte for [`WireError::VersionMismatch`].
pub const WIRE_ERROR_VERSION_MISMATCH: u8 = 0x01;
/// Discriminant byte for [`WireError::InvalidMethodName`].
pub const WIRE_ERROR_INVALID_METHOD_NAME: u8 = 0x02;
/// Discriminant byte for [`WireError::MalformedFrame`].
pub const WIRE_ERROR_MALFORMED_FRAME: u8 = 0x03;
/// Discriminant byte for [`WireError::HandlerError`].
pub const WIRE_ERROR_HANDLER_ERROR: u8 = 0x04;
/// Discriminant byte for [`WireError::Codec`].
pub const WIRE_ERROR_CODEC: u8 = 0x05;

/// Typed error payload sent in а `[OPCODE_UNARY_ERROR | …]` response frame.
///
/// Postcard encodes this enum as `[discriminant 1B | postcard(payload)]`.
/// The discriminant byte ensures the wire encoding is independent of
/// the human-readable `Display` strings — translations or rewordings
/// of error messages will not change how variants are reconstructed
/// on the client side.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum WireError {
    /// No handler registered for the requested canonical method name.
    UnknownMethod {
        /// Method name the client sent.
        method_name: String,
    } = WIRE_ERROR_UNKNOWN_METHOD,

    /// Caller pinned а specific version that was not registered.
    VersionMismatch {
        /// Version string the caller requested.
        requested: String,
        /// Versions the registry knows about for this triple.
        available: Vec<String>,
    } = WIRE_ERROR_VERSION_MISMATCH,

    /// Method-name string did not match `package[@version]/interface/method`.
    InvalidMethodName {
        /// The malformed input as received.
        input: String,
    } = WIRE_ERROR_INVALID_METHOD_NAME,

    /// Wire frame structure violated (truncated, bad opcode, oversized name…).
    MalformedFrame {
        /// Free-form reason — а display message for diagnostics.
        reason: String,
    } = WIRE_ERROR_MALFORMED_FRAME,

    /// Handler returned an error. The original concrete type is erased
    /// to the handler's `Display` rendering — application errors do not
    /// cross trust boundaries via the wire.
    HandlerError {
        /// `Display` of the underlying handler error.
        display: String,
    } = WIRE_ERROR_HANDLER_ERROR,

    /// Postcard codec failure on the server side (decoding а request
    /// payload, encoding а response). Indicates а server-side bug or
    /// version skew с the client's stub.
    Codec {
        /// `Display` of the underlying postcard error.
        display: String,
    } = WIRE_ERROR_CODEC,
}

impl WireError {
    /// Map а server-side [`RpcError`] к its wire-level representation.
    ///
    /// Variants that represent server-internal failures
    /// ([`RpcError::TransportRead`], [`RpcError::TransportWrite`], …)
    /// must NOT cross the wire — they signal а local I/O failure that
    /// the peer cannot meaningfully act on. Such variants collapse к
    /// [`WireError::HandlerError`] с the `Display` rendering, matching
    /// the existing "opaque server side error" semantics.
    #[must_use]
    pub fn from_rpc_error(err: &RpcError) -> Self {
        match err {
            RpcError::UnknownMethod(name) => Self::UnknownMethod {
                method_name: name.clone(),
            },
            RpcError::VersionMismatch {
                requested,
                available,
            } => Self::VersionMismatch {
                requested: requested.clone(),
                available: available.clone(),
            },
            RpcError::InvalidMethodName(input) => Self::InvalidMethodName {
                input: input.clone(),
            },
            RpcError::MalformedFrame(reason) => Self::MalformedFrame {
                reason: reason.clone(),
            },
            RpcError::Codec(e) => Self::Codec {
                display: e.to_string(),
            },
            // Anything else (Handler, transport errors, datagram errors)
            // collapses к а handler-error envelope с the Display string.
            // Transport errors на server side never cross the wire in
            // practice — а write_all failure prevents writing the error
            // frame at all — but we keep the mapping total для exhaustiveness.
            other @ (RpcError::Handler(_)
            | RpcError::TransportOpenSubstream { .. }
            | RpcError::TransportRegisterAlpn { .. }
            | RpcError::TransportRead { .. }
            | RpcError::TransportWrite { .. }
            | RpcError::DatagramStreamIdCollision { .. }
            | RpcError::DatagramStreamIdUnknown { .. }
            | RpcError::DatagramTooShort { .. }) => Self::HandlerError {
                display: other.to_string(),
            },
        }
    }

    /// Reconstruct an [`RpcError`] from а wire envelope on the client side.
    ///
    /// This is а total function — every [`WireError`] variant has а
    /// corresponding [`RpcError`] variant.
    #[must_use]
    pub fn into_rpc_error(self) -> RpcError {
        match self {
            Self::UnknownMethod { method_name } => RpcError::UnknownMethod(method_name),
            Self::VersionMismatch {
                requested,
                available,
            } => RpcError::VersionMismatch {
                requested,
                available,
            },
            Self::InvalidMethodName { input } => RpcError::InvalidMethodName(input),
            Self::MalformedFrame { reason } => RpcError::MalformedFrame(reason),
            Self::HandlerError { display } => {
                // Server-side `RpcError::Handler` Display prepends "handler error: "
                // (see thiserror `#[error("handler error: {0}")]` on the variant).
                // Once we re-wrap the wire string into а fresh `RpcError::Handler`
                // here, the client-side Display would prepend "handler error: "
                // again, producing "handler error: handler error: …". Strip the
                // server-side prefix so the client renders а single prefix.
                let inner = display
                    .strip_prefix("handler error: ")
                    .unwrap_or(&display)
                    .to_owned();
                RpcError::Handler(inner.into())
            }
            Self::Codec { display } => {
                // postcard::Error is an opaque-shaped enum without а String
                // constructor; the client surfaces the original display
                // through а handler-error wrapper to preserve diagnostics
                // without fabricating а fake codec failure variant.
                RpcError::Handler(format!("server codec error: {display}").into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_method_roundtrip_via_postcard() {
        let original = WireError::UnknownMethod {
            method_name: "tolki:nope@1.0.0/iface/method".to_owned(),
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        // Discriminant byte must be 0x00 — locale-independent.
        assert_eq!(bytes[0], WIRE_ERROR_UNKNOWN_METHOD);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn version_mismatch_preserves_metadata() {
        let original = WireError::VersionMismatch {
            requested: "2.0.0".to_owned(),
            available: vec!["1.0.0".to_owned(), "1.1.0".to_owned()],
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        assert_eq!(bytes[0], WIRE_ERROR_VERSION_MISMATCH);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        match decoded {
            WireError::VersionMismatch {
                requested,
                available,
            } => {
                assert_eq!(requested, "2.0.0");
                assert_eq!(available, vec!["1.0.0".to_owned(), "1.1.0".to_owned()]);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn invalid_method_name_roundtrip() {
        let original = WireError::InvalidMethodName {
            input: "not-a-valid-name".to_owned(),
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        assert_eq!(bytes[0], WIRE_ERROR_INVALID_METHOD_NAME);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn malformed_frame_roundtrip() {
        let original = WireError::MalformedFrame {
            reason: "truncated buffer".to_owned(),
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        assert_eq!(bytes[0], WIRE_ERROR_MALFORMED_FRAME);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn handler_error_roundtrip() {
        let original = WireError::HandlerError {
            display: "domain error: invalid input".to_owned(),
        };
        let bytes = postcard::to_allocvec(&original).expect("encode");
        assert_eq!(bytes[0], WIRE_ERROR_HANDLER_ERROR);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, original);
    }

    #[test]
    fn from_rpc_error_preserves_unknown_method() {
        let rpc_err = RpcError::UnknownMethod("test:foo@1.0.0/i/m".to_owned());
        let wire = WireError::from_rpc_error(&rpc_err);
        match wire {
            WireError::UnknownMethod { method_name } => {
                assert_eq!(method_name, "test:foo@1.0.0/i/m");
            }
            other => panic!("expected UnknownMethod, got {other:?}"),
        }
    }

    #[test]
    fn from_rpc_error_preserves_version_mismatch() {
        let rpc_err = RpcError::VersionMismatch {
            requested: "9.9.9".to_owned(),
            available: vec!["1.0.0".to_owned()],
        };
        let wire = WireError::from_rpc_error(&rpc_err);
        match wire {
            WireError::VersionMismatch {
                requested,
                available,
            } => {
                assert_eq!(requested, "9.9.9");
                assert_eq!(available, vec!["1.0.0".to_owned()]);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn into_rpc_error_preserves_unknown_method() {
        let wire = WireError::UnknownMethod {
            method_name: "x:y@1.0.0/i/m".to_owned(),
        };
        let rpc = wire.into_rpc_error();
        match rpc {
            RpcError::UnknownMethod(name) => assert_eq!(name, "x:y@1.0.0/i/m"),
            other => panic!("expected UnknownMethod, got {other:?}"),
        }
    }

    #[test]
    fn into_rpc_error_preserves_version_mismatch() {
        let wire = WireError::VersionMismatch {
            requested: "9.9.9".to_owned(),
            available: vec!["1.0.0".to_owned()],
        };
        let rpc = wire.into_rpc_error();
        match rpc {
            RpcError::VersionMismatch {
                requested,
                available,
            } => {
                assert_eq!(requested, "9.9.9");
                assert_eq!(available, vec!["1.0.0".to_owned()]);
            }
            other => panic!("expected VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn handler_error_collapses_transport_errors() {
        // Transport errors should never cross the wire, but the mapping
        // must remain total (we use it server-side as а defensive default
        // for any RpcError shape that does not have а dedicated wire variant).
        let rpc_err = RpcError::TransportRead {
            reason: "io closed".to_owned(),
        };
        let wire = WireError::from_rpc_error(&rpc_err);
        match wire {
            WireError::HandlerError { display } => {
                assert!(display.contains("io closed"));
            }
            other => panic!("expected HandlerError, got {other:?}"),
        }
    }

    #[test]
    fn handler_error_no_doubled_prefix() {
        // Reproduces the round-trip path: server constructs RpcError::Handler,
        // converts к WireError using its Display rendering, ships it over the
        // wire, client decodes and re-wraps. The final client-side Display
        // must contain exactly one "handler error: " prefix — not two.
        let server_err = RpcError::Handler("domain failure".into());
        let wire_msg = server_err.to_string(); // "handler error: domain failure"
        assert_eq!(wire_msg, "handler error: domain failure");

        let wire_err = WireError::HandlerError { display: wire_msg };
        let client_err = wire_err.into_rpc_error();
        let client_display = client_err.to_string();

        assert_eq!(
            client_display.matches("handler error:").count(),
            1,
            "expected single prefix, got {client_display:?}"
        );
        assert_eq!(client_display, "handler error: domain failure");
    }

    #[test]
    fn handler_error_preserves_payload_without_prefix() {
        // If the server-side Display did NOT carry the "handler error: " prefix
        // (е.g. some future variant collapsed into HandlerError), the client
        // must preserve the payload verbatim — strip_prefix on absent prefix
        // returns the input unchanged.
        let wire_err = WireError::HandlerError {
            display: "raw inner failure".to_owned(),
        };
        let client_err = wire_err.into_rpc_error();
        assert_eq!(client_err.to_string(), "handler error: raw inner failure");
    }

    #[test]
    fn locale_invariance_round_trip() {
        // Translate the underlying display message — the wire roundtrip
        // must STILL preserve the variant classification.  In the old
        // string-prefix world, this would silently collapse to Handler.
        //
        // We simulate "translation" by feeding а Russian-language method
        // name into UnknownMethod's payload — the discriminant byte is
        // what carries the variant information, not the human-readable
        // text.
        let rpc_err = RpcError::UnknownMethod("неизвестный:метод@1.0.0/иф/м".to_owned());
        let wire = WireError::from_rpc_error(&rpc_err);
        let bytes = postcard::to_allocvec(&wire).expect("encode");
        // Discriminant byte SHOULD be locale-invariant (always 0x00 для
        // UnknownMethod regardless of payload content).
        assert_eq!(bytes[0], WIRE_ERROR_UNKNOWN_METHOD);
        let decoded: WireError = postcard::from_bytes(&bytes).expect("decode");
        let restored = decoded.into_rpc_error();
        match restored {
            RpcError::UnknownMethod(name) => {
                // Payload roundtrips intact (UTF-8 preserved).
                assert_eq!(name, "неизвестный:метод@1.0.0/иф/м");
            }
            other => panic!(
                "Russian-language method name must STILL classify as UnknownMethod, got {other:?}"
            ),
        }
    }
}
