//! [`RpcClient`] — open а bidi substream к а peer, write а unary
//! request, read the response.
//!
//! Phase 2 surface — only unary call is implemented. Server-streaming /
//! client-streaming / bidi-streaming variants land в Phase 3+ once the
//! WIT codegen pipeline picks the canonical streaming semantics.
//!
//! ## Method-name format (per Pavel ratify D7)
//!
//! - **Pinned version** (production): `tolki:chat@1.0.0/chat/send-message`
//! - **Version omitted** (debug / REPL): `tolki:chat/chat/send-message`
//!   — the server resolves к the latest registered semver under the same
//!   `package/interface/method` triple.

use bytes::Bytes;
use iroh::EndpointId;
use tracing::trace;

use crate::error::{RpcError, RpcResult};
use crate::server::build_unary_request_frame;
use crate::transport::{ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, IrohTransportClient};
use crate::wire::{OPCODE_UNARY_ERROR, OPCODE_UNARY_RESPONSE};
use crate::wire_error::WireError;

/// Maximum bytes we accept from а server response — protects clients
/// against а malicious server trying к exhaust memory by writing forever.
///
/// Same magnitude as the server-side cap; mismatch would manifest as
/// asymmetric truncation behaviour.
const RPC_RESPONSE_READ_LIMIT: usize = 8 * 1024 * 1024;

/// Outbound RPC client.
///
/// Wraps а shared [`IrohTransportClient`] handle. Issuing а call opens
/// (or reuses, via nerw-core's connection cache) а QUIC connection
/// negotiated с [`ALPN_TOLKI_WIRE_PROTOCOL_2_0_0`], opens а fresh bidi
/// substream, writes the framed request, and reads the response.
///
/// Cloning [`RpcClient`] is cheap — both fields wrap `Arc`s under the
/// hood. Multiple concurrent calls share the same connection cache.
#[derive(Debug, Clone)]
pub struct RpcClient {
    /// Iroh-backed transport handle. Cloning is cheap (`Arc` inside);
    /// concurrent calls share the same connection cache.
    transport: IrohTransportClient,
}

impl RpcClient {
    /// Build а new client wrapping а transport handle.
    #[must_use]
    pub const fn new(transport: IrohTransportClient) -> Self {
        Self { transport }
    }

    /// Borrow the underlying transport handle (test introspection).
    #[must_use]
    pub const fn transport(&self) -> &IrohTransportClient {
        &self.transport
    }

    /// Issue а unary RPC call.
    ///
    /// `peer` is the target [`EndpointId`] (z-base32 Ed25519 public key).
    /// `method_name` follows the canonical text format
    /// `package[@version]/interface/method` (D7 — see module docs).
    /// `request_bytes` is the postcard-encoded request body.
    ///
    /// Returns the raw response bytes (postcard-decoded by the caller's
    /// generated stub) on success, or а typed [`RpcError`] on failure.
    ///
    /// # Errors
    ///
    /// - [`RpcError::TransportOpenSubstream`] — peer dial / `open_bi` failure.
    /// - [`RpcError::TransportWrite`]         — `write_all` / `finish` failed.
    /// - [`RpcError::TransportRead`]          — `read_to_end` failed mid-flight.
    /// - [`RpcError::MalformedFrame`]         — response frame had а bad opcode.
    /// - [`RpcError::Codec`]                  — postcard-decoding the error
    ///   body failed (server-side bug).
    /// - [`RpcError::Handler`]                — server returned а handler error.
    /// - [`RpcError::UnknownMethod`]          — server-side registry miss.
    pub async fn call(
        &self,
        peer: &EndpointId,
        method_name: &str,
        request: Bytes,
    ) -> RpcResult<Bytes> {
        let frame = build_unary_request_frame(method_name, &request)?;
        let (mut send, mut recv) = self
            .transport
            .inner()
            .open_substream(peer, ALPN_TOLKI_WIRE_PROTOCOL_2_0_0)
            .await
            .map_err(|e| RpcError::TransportOpenSubstream {
                node_id: format!("{peer}"),
                reason: format!("{e}"),
            })?;
        trace!(
            peer = %peer,
            method = %method_name,
            request_len = request.len(),
            "RpcClient::call - bidi opened, writing request",
        );

        // Write the framed request, signal EOF so the server's
        // read_to_end can complete.
        send.write_all(&frame)
            .await
            .map_err(|e| RpcError::TransportWrite {
                reason: format!("write_all: {e}"),
            })?;
        send.finish().map_err(|e| RpcError::TransportWrite {
            reason: format!("finish: {e}"),
        })?;

        // Read the entire response frame (server finishes its send-half
        // when the response is complete).
        let response_buf = recv
            .read_to_end(RPC_RESPONSE_READ_LIMIT)
            .await
            .map_err(|e| RpcError::TransportRead {
                reason: format!("read_to_end: {e}"),
            })?;

        decode_response_frame(&Bytes::from(response_buf))
    }
}

/// Decode а response frame: `[OPCODE_UNARY_RESPONSE | bytes]` (success)
/// or `[OPCODE_UNARY_ERROR | postcard(WireError)]` (failure).
///
/// The error body is the typed [`WireError`] envelope — а 1-byte
/// discriminant followed by the postcard-encoded payload. Reconstruction
/// is total: every wire variant maps к а concrete [`RpcError`] variant
/// without ambiguity. Locale invariant — translating display strings
/// в Russian (or anywhere else) does not affect classification.
///
/// Takes the response frame by reference so the success path can
/// `Bytes::slice` off the opcode byte without copying — the returned
/// [`Bytes`] shares the same underlying allocation as `buf`.
fn decode_response_frame(buf: &Bytes) -> RpcResult<Bytes> {
    let opcode = *buf
        .first()
        .ok_or_else(|| RpcError::MalformedFrame("empty response frame".to_owned()))?;
    match opcode {
        OPCODE_UNARY_RESPONSE => Ok(buf.slice(1..)),
        OPCODE_UNARY_ERROR => {
            let wire: WireError = postcard::from_bytes(&buf[1..]).map_err(RpcError::Codec)?;
            Err(wire.into_rpc_error())
        }
        other => Err(RpcError::MalformedFrame(format!(
            "unexpected response opcode 0x{other:02x}",
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::OPCODE_UNARY_REQUEST;

    fn build_buf(prefix: u8, body: &[u8]) -> Bytes {
        let mut v = Vec::with_capacity(1 + body.len());
        v.push(prefix);
        v.extend_from_slice(body);
        Bytes::from(v)
    }

    #[test]
    fn decode_response_frame_success() {
        let buf = build_buf(OPCODE_UNARY_RESPONSE, b"OK-PAYLOAD");
        let decoded = decode_response_frame(&buf).expect("decode ok");
        assert_eq!(&decoded[..], b"OK-PAYLOAD");
    }

    #[test]
    fn decode_response_frame_error_handler() {
        let body = postcard::to_allocvec(&WireError::HandlerError {
            display: "some handler failure".to_owned(),
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::Handler(_) => {}
            other => panic!("expected RpcError::Handler, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_error_unknown_method() {
        let body = postcard::to_allocvec(&WireError::UnknownMethod {
            method_name: "tolki:nope@1.0.0/iface/method".to_owned(),
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::UnknownMethod(name) => {
                assert_eq!(name, "tolki:nope@1.0.0/iface/method");
            }
            other => panic!("expected RpcError::UnknownMethod, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_error_version_mismatch() {
        // Demonstrates the new typed wire format preserves variant + metadata
        // even when the human-readable Display would not survive а string-prefix
        // match (e.g. translated к Russian).
        let body = postcard::to_allocvec(&WireError::VersionMismatch {
            requested: "9.9.9".to_owned(),
            available: vec!["1.0.0".to_owned(), "2.0.0".to_owned()],
        })
        .expect("encode");
        let buf = build_buf(OPCODE_UNARY_ERROR, &body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::VersionMismatch {
                requested,
                available,
            } => {
                assert_eq!(requested, "9.9.9");
                assert_eq!(available, vec!["1.0.0".to_owned(), "2.0.0".to_owned()]);
            }
            other => panic!("expected RpcError::VersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_empty_buffer() {
        let err = decode_response_frame(&Bytes::new()).expect_err("empty buffer must error");
        assert!(matches!(err, RpcError::MalformedFrame(_)));
    }

    #[test]
    fn decode_response_frame_unexpected_opcode() {
        let buf = build_buf(OPCODE_UNARY_REQUEST, &[0xAA, 0xBB]);
        let err = decode_response_frame(&buf).expect_err("must error");
        let s = err.to_string();
        assert!(s.contains("unexpected response opcode"));
    }
}
