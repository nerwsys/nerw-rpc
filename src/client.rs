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

use iroh::EndpointId;
use tracing::trace;

use crate::error::{RpcError, RpcResult};
use crate::server::build_unary_request_frame;
use crate::transport::{ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, IrohTransportClient};
use crate::wire::{OPCODE_UNARY_ERROR, OPCODE_UNARY_RESPONSE};

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
        request_bytes: &[u8],
    ) -> RpcResult<Vec<u8>> {
        let frame = build_unary_request_frame(method_name, request_bytes)?;
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
            request_len = request_bytes.len(),
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

        decode_response_frame(&response_buf)
    }
}

/// Decode а response frame: `[OPCODE_UNARY_RESPONSE | bytes]` (success)
/// or `[OPCODE_UNARY_ERROR | postcard(error-string)]` (failure).
fn decode_response_frame(buf: &[u8]) -> RpcResult<Vec<u8>> {
    let (opcode, rest) = buf
        .split_first()
        .ok_or_else(|| RpcError::MalformedFrame("empty response frame".to_string()))?;
    match *opcode {
        OPCODE_UNARY_RESPONSE => Ok(rest.to_vec()),
        OPCODE_UNARY_ERROR => {
            let msg: String = postcard::from_bytes(rest).map_err(RpcError::Codec)?;
            // Distinguish well-known error shapes from generic handler
            // errors so callers can match cleanly. Phase 2 ships а
            // simple string protocol; Phase 3+ will switch к а typed
            // postcard discriminant.
            if msg.starts_with("unknown method:") {
                let name = msg
                    .trim_start_matches("unknown method:")
                    .trim()
                    .to_string();
                Err(RpcError::UnknownMethod(name))
            } else {
                Err(RpcError::Handler(msg.into()))
            }
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

    #[test]
    fn decode_response_frame_success() {
        let mut buf = Vec::new();
        buf.push(OPCODE_UNARY_RESPONSE);
        buf.extend_from_slice(b"OK-PAYLOAD");
        let decoded = decode_response_frame(&buf).expect("decode ok");
        assert_eq!(decoded, b"OK-PAYLOAD");
    }

    #[test]
    fn decode_response_frame_error_handler() {
        let mut buf = Vec::new();
        buf.push(OPCODE_UNARY_ERROR);
        let body = postcard::to_allocvec(&"some handler failure".to_string()).expect("encode");
        buf.extend_from_slice(&body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::Handler(_) => {}
            other => panic!("expected RpcError::Handler, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_error_unknown_method() {
        let mut buf = Vec::new();
        buf.push(OPCODE_UNARY_ERROR);
        let body = postcard::to_allocvec(
            &"unknown method: tolki:nope@1.0.0/iface/method".to_string(),
        )
        .expect("encode");
        buf.extend_from_slice(&body);
        let err = decode_response_frame(&buf).expect_err("must error");
        match err {
            RpcError::UnknownMethod(name) => {
                assert_eq!(name, "tolki:nope@1.0.0/iface/method");
            }
            other => panic!("expected RpcError::UnknownMethod, got {other:?}"),
        }
    }

    #[test]
    fn decode_response_frame_empty_buffer() {
        let err = decode_response_frame(&[]).expect_err("empty buffer must error");
        assert!(matches!(err, RpcError::MalformedFrame(_)));
    }

    #[test]
    fn decode_response_frame_unexpected_opcode() {
        let buf = vec![OPCODE_UNARY_REQUEST, 0xAA, 0xBB];
        let err = decode_response_frame(&buf).expect_err("must error");
        let s = err.to_string();
        assert!(s.contains("unexpected response opcode"));
    }
}
