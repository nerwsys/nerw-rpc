//! Wire frame format constants + helpers.
//!
//! ## Frame layouts (per `NERW-RPC-DESIGN.md` Section 4 + wit/nerw-rpc.wit)
//!
//! ```text
//! UNARY:
//!   Client → Server: [opcode=0x00 | varint(name_len) | method-name UTF-8 | postcard(request)]
//!   Server → Client: [opcode=0x01 | postcard(response)]    # success
//!                    [opcode=0x02 | postcard(error)]       # error
//!
//! STREAMING (single bidi stream, Phase 3 — v0.9.0):
//!   Open req:    [opcode=0x10 | varint(payload_len) | postcard(StreamingOpenRequest)]
//!   Open ack:    [opcode=0x11 | varint(payload_len) | postcard(StreamingOpenResponse)]
//!   Req chunk:   [opcode=0x20 | varint(payload_len) | bytes]
//!   Resp chunk:  [opcode=0x21 | varint(payload_len) | bytes]
//!   Req end:     [opcode=0x30]                              # no payload
//!   Resp end:    [opcode=0x31]                              # no payload
//!   Stream err:  [opcode=0x40 | varint(payload_len) | postcard(StreamingError)]
//!
//! DATAGRAM (WebTransport-style stream-id correlation):
//!   [varint(stream-id) | postcard(item)]
//! ```
//!
//! Phase 1 ships only the framing primitives — opcodes and the method-name
//! length-prefix codec. Full frame encode/decode lives at the transport
//! boundary (Phase 2) where it knows how to emit/consume from a QUIC stream.

use crate::error::{RpcError, RpcResult};

/// Hard upper bound on а single streaming payload-frame body (in bytes).
///
/// Each `[opcode | varint(len) | bytes]` frame on the streaming wire is
/// bounded by this constant before we allocate the read buffer. Picked
/// at 8 MiB to match the unary `RPC_STREAM_READ_LIMIT` so callers can
/// reason about а single «message size» limit across the framework.
/// А malicious peer cannot trick the decoder into pre-allocating
/// gigabytes по а bogus varint.
pub const MAX_STREAMING_PAYLOAD_LEN: usize = 8 * 1024 * 1024;

/// Hard upper bound on method-name length (in bytes) accepted on the wire.
///
/// Canonical method-ids are short — `package@version/interface/method`
/// rarely exceeds ~120 bytes — but the LEB128 length-prefix could in
/// principle declare an attacker-controlled length that exhausts memory
/// before the buffer-bounds check rejects it. We cap at 4 KiB so а
/// malicious peer cannot trick the decoder into pre-allocating gigabytes
/// of memory via а bogus varint.
pub const MAX_METHOD_NAME_LEN: usize = 4096;

/// Unary request opcode.
pub const OPCODE_UNARY_REQUEST: u8 = 0x00;
/// Unary success response opcode.
pub const OPCODE_UNARY_RESPONSE: u8 = 0x01;
/// Unary error response opcode.
pub const OPCODE_UNARY_ERROR: u8 = 0x02;

/// Streaming open-request opcode (client → server, Phase 3).
///
/// First frame on а streaming substream — carries `StreamingOpenRequest`
/// `{ method_name: String, request_id: u64 }` postcard-encoded after а
/// LEB128 length prefix.
pub const OPCODE_STREAMING_OPEN_REQUEST: u8 = 0x10;

/// Streaming open-response opcode (server → client, Phase 3).
///
/// Acknowledgement of `StreamingOpenRequest`. Carries `StreamingOpenResponse`
/// `{ status, request_id }` where `status = ok | error(String)`. If the
/// status is an error the server closes both halves of the substream
/// after writing this frame.
pub const OPCODE_STREAMING_OPEN_RESPONSE: u8 = 0x11;

/// Streaming request-chunk opcode (client → server, Phase 3).
///
/// Wire shape: `[opcode | varint(payload_len) | bytes]`. Payload contents
/// are caller-defined (typically а postcard-encoded application message).
pub const OPCODE_STREAMING_REQUEST_CHUNK: u8 = 0x20;

/// Streaming response-chunk opcode (server → client, Phase 3).
///
/// Same wire shape as [`OPCODE_STREAMING_REQUEST_CHUNK`].
pub const OPCODE_STREAMING_RESPONSE_CHUNK: u8 = 0x21;

/// Streaming request-end opcode (client → server, Phase 3).
///
/// Single byte. Signals «client will send no more request chunks» — the
/// server's request-stream view yields `None` after seeing this frame.
/// The client closes its send half after writing this byte.
pub const OPCODE_STREAMING_REQUEST_END: u8 = 0x30;

/// Streaming response-end opcode (server → client, Phase 3).
///
/// Single byte. Signals clean close — client's response stream ends
/// gracefully without an error. The server closes its send half after
/// writing this byte.
pub const OPCODE_STREAMING_RESPONSE_END: u8 = 0x31;

/// Streaming mid-stream error opcode (either direction, Phase 3).
///
/// Carries `StreamingError` `{ message: String, terminal: bool }`. If
/// `terminal = true` the sender closes its send half after this frame
/// and the receiver surfaces а typed error. If `terminal = false` the
/// stream stays open — the next frame proceeds as if the error were
/// а recoverable per-chunk failure.
pub const OPCODE_STREAMING_ERROR: u8 = 0x40;

/// Encode a method-name prefix as `varint(name_len) || UTF-8 bytes`.
///
/// The encoded bytes are appended to `buf`.
///
/// # Errors
///
/// Returns [`RpcError::MalformedFrame`] if the underlying LEB128 writer fails
/// (only possible on I/O error against an in-memory `Vec`, so practically
/// never — but kept honest for `no_std`-style callers that may use a fixed
/// buffer in the future).
pub fn encode_method_name(name: &str, buf: &mut Vec<u8>) -> RpcResult<()> {
    let bytes = name.as_bytes();
    // `usize → u64` via `try_from`: lossless on every platform Rust runs
    // on today (usize::BITS ≤ 64), but kept honest for hypothetical
    // 128-bit targets where the `as` cast would silently truncate.
    let len = u64::try_from(bytes.len())
        .map_err(|e| RpcError::MalformedFrame(format!("method-name length overflow: {e}")))?;
    leb128::write::unsigned(buf, len)
        .map_err(|e| RpcError::MalformedFrame(format!("leb128 write: {e}")))?;
    buf.extend_from_slice(bytes);
    Ok(())
}

/// Decode a method-name prefix from `[varint(len) || UTF-8 bytes || rest]`.
///
/// Returns the decoded method name and the remaining bytes (suitable for
/// passing to a postcard payload decoder).
///
/// # Errors
///
/// Returns [`RpcError::MalformedFrame`] if the LEB128 length is malformed,
/// the declared length exceeds the buffer, or the bytes are not valid UTF-8.
pub fn decode_method_name(input: &[u8]) -> RpcResult<(&str, &[u8])> {
    let mut cursor = std::io::Cursor::new(input);
    let name_len_u64 = leb128::read::unsigned(&mut cursor)
        .map_err(|e| RpcError::MalformedFrame(format!("leb128 read: {e}")))?;
    let name_len = usize::try_from(name_len_u64)
        .map_err(|e| RpcError::MalformedFrame(format!("name-length overflow: {e}")))?;
    if name_len > MAX_METHOD_NAME_LEN {
        return Err(RpcError::MalformedFrame(format!(
            "method-name length {name_len} exceeds maximum {MAX_METHOD_NAME_LEN}"
        )));
    }
    let consumed = usize::try_from(cursor.position())
        .map_err(|e| RpcError::MalformedFrame(format!("cursor overflow: {e}")))?;
    // Bind the checked sum so subsequent indexing uses the same value
    // — avoids а second `consumed + name_len` that clippy cannot prove
    // safe (we just proved it manually above).
    let name_end = match consumed.checked_add(name_len) {
        Some(end) if end <= input.len() => end,
        _ => {
            return Err(RpcError::MalformedFrame(
                "method-name length exceeds buffer".to_owned(),
            ));
        }
    };
    let name = std::str::from_utf8(&input[consumed..name_end])
        .map_err(|e| RpcError::MalformedFrame(format!("non-UTF-8 method-name: {e}")))?;
    Ok((name, &input[name_end..]))
}

/// Encode а datagram stream-id prefix as а LEB128 varint.
///
/// Used by callers building outbound datagram frames: the wire shape is
/// `[varint(stream-id) | postcard(payload)]`. The stream-id is the
/// `u64` identifier of the bidi handshake stream that established the
/// datagram session (per WebTransport-style correlation, RFC 9221 +
/// CONNECT-UDP / WebTransport).
///
/// The encoded bytes are appended к `buf`.
///
/// # Errors
///
/// Returns [`RpcError::MalformedFrame`] if the underlying LEB128 writer
/// fails (only possible on I/O error against an in-memory `Vec`, so
/// practically never — kept honest для symmetry с
/// [`encode_method_name`] и future `no_std` callers).
pub fn encode_stream_id(stream_id: u64, buf: &mut Vec<u8>) -> RpcResult<()> {
    leb128::write::unsigned(buf, stream_id)
        .map_err(|e| RpcError::MalformedFrame(format!("leb128 write stream-id: {e}")))?;
    Ok(())
}

/// Decode а datagram stream-id prefix from `[varint(stream-id) | rest]`.
///
/// Returns the decoded stream-id и the remaining bytes (typically the
/// postcard-encoded application payload, handed unchanged к the
/// registered [`crate::datagram::DatagramHandler`]).
///
/// # Errors
///
/// Returns [`RpcError::MalformedFrame`] if the LEB128 varint is
/// malformed (truncated buffer, varint overflows `u64`, etc).
pub fn decode_stream_id(input: &[u8]) -> RpcResult<(u64, &[u8])> {
    let mut cursor = std::io::Cursor::new(input);
    let stream_id = leb128::read::unsigned(&mut cursor)
        .map_err(|e| RpcError::MalformedFrame(format!("leb128 read stream-id: {e}")))?;
    let consumed = usize::try_from(cursor.position())
        .map_err(|e| RpcError::MalformedFrame(format!("cursor overflow: {e}")))?;
    Ok((stream_id, &input[consumed..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_name_roundtrip() {
        let name = "tolki:chat@1.0.0/chat/send-message";
        let mut buf = Vec::new();
        encode_method_name(name, &mut buf).expect("encode");

        let (decoded, rest) = decode_method_name(&buf).expect("decode");
        assert_eq!(decoded, name);
        assert!(rest.is_empty());
    }

    #[test]
    fn method_name_with_payload_after() {
        let name = "tolki:schema@1.0.0/schema/get";
        let mut buf = Vec::new();
        encode_method_name(name, &mut buf).expect("encode");
        buf.extend_from_slice(b"PAYLOAD");

        let (decoded, rest) = decode_method_name(&buf).expect("decode");
        assert_eq!(decoded, name);
        assert_eq!(rest, b"PAYLOAD");
    }

    #[test]
    fn rejects_truncated_buffer() {
        // varint says length=16, but no bytes follow.
        let bad = vec![0x10];
        assert!(decode_method_name(&bad).is_err());
    }

    #[test]
    fn rejects_invalid_utf8() {
        // length=2, then two invalid-UTF-8 bytes.
        let bad = vec![0x02, 0xFF, 0xFE];
        let res = decode_method_name(&bad);
        assert!(matches!(res, Err(RpcError::MalformedFrame(_))));
    }

    #[test]
    fn decode_rejects_oversized_method_name() {
        // varint claims length=5000 (5 KiB), exceeding MAX_METHOD_NAME_LEN (4 KiB).
        // The decoder must reject the frame BEFORE attempting to read those bytes.
        let mut bad = Vec::new();
        leb128::write::unsigned(&mut bad, 5000_u64).expect("leb128 write");
        // Don't even bother filling 5000 bytes — the bound check should fire first.
        let res = decode_method_name(&bad);
        match res {
            Err(RpcError::MalformedFrame(msg)) => {
                assert!(
                    msg.contains("5000") && msg.contains("4096"),
                    "error must mention requested vs max: got `{msg}`"
                );
            }
            other => panic!("expected MalformedFrame, got {other:?}"),
        }
    }

    #[test]
    fn decode_accepts_method_name_at_max_len() {
        // Boundary: exactly MAX_METHOD_NAME_LEN bytes must succeed.
        let name = "a".repeat(MAX_METHOD_NAME_LEN);
        let mut buf = Vec::new();
        encode_method_name(&name, &mut buf).expect("encode");
        let (decoded, rest) = decode_method_name(&buf).expect("decode");
        assert_eq!(decoded.len(), MAX_METHOD_NAME_LEN);
        assert!(rest.is_empty());
    }

    #[test]
    fn opcodes_have_expected_values() {
        assert_eq!(OPCODE_UNARY_REQUEST, 0x00);
        assert_eq!(OPCODE_UNARY_RESPONSE, 0x01);
        assert_eq!(OPCODE_UNARY_ERROR, 0x02);
        // Phase 3 streaming opcodes — see wit/nerw-rpc.wit.
        assert_eq!(OPCODE_STREAMING_OPEN_REQUEST, 0x10);
        assert_eq!(OPCODE_STREAMING_OPEN_RESPONSE, 0x11);
        assert_eq!(OPCODE_STREAMING_REQUEST_CHUNK, 0x20);
        assert_eq!(OPCODE_STREAMING_RESPONSE_CHUNK, 0x21);
        assert_eq!(OPCODE_STREAMING_REQUEST_END, 0x30);
        assert_eq!(OPCODE_STREAMING_RESPONSE_END, 0x31);
        assert_eq!(OPCODE_STREAMING_ERROR, 0x40);
    }

    #[test]
    fn stream_id_roundtrip_small() {
        // Stream-ids < 64 fit в а single varint byte (matches old 1-byte
        // token cost для the common case).
        let mut buf = Vec::new();
        encode_stream_id(42, &mut buf).expect("encode");
        assert_eq!(buf.len(), 1, "stream-id 42 must encode к 1 byte");
        let (decoded, rest) = decode_stream_id(&buf).expect("decode");
        assert_eq!(decoded, 42);
        assert!(rest.is_empty());
    }

    #[test]
    fn stream_id_roundtrip_large() {
        // Stream-ids в the upper varint range still roundtrip cleanly.
        let mut buf = Vec::new();
        encode_stream_id(u64::from(u32::MAX), &mut buf).expect("encode");
        let (decoded, rest) = decode_stream_id(&buf).expect("decode");
        assert_eq!(decoded, u64::from(u32::MAX));
        assert!(rest.is_empty());
    }

    #[test]
    fn stream_id_with_payload_after() {
        let mut buf = Vec::new();
        encode_stream_id(7, &mut buf).expect("encode");
        buf.extend_from_slice(b"PAYLOAD");
        let (decoded, rest) = decode_stream_id(&buf).expect("decode");
        assert_eq!(decoded, 7);
        assert_eq!(rest, b"PAYLOAD");
    }

    #[test]
    fn stream_id_decode_rejects_empty_buffer() {
        // Empty buffer cannot carry а varint — leb128 reader signals EOF.
        let res = decode_stream_id(&[]);
        assert!(matches!(res, Err(RpcError::MalformedFrame(_))));
    }

    #[test]
    fn stream_id_decode_rejects_truncated_varint() {
        // 0x80 = continuation bit set but no follow-up byte.
        let bad = [0x80_u8];
        let res = decode_stream_id(&bad);
        assert!(matches!(res, Err(RpcError::MalformedFrame(_))));
    }

    #[test]
    fn stream_id_zero_roundtrip() {
        // Boundary: stream-id 0 must encode к а single zero byte.
        let mut buf = Vec::new();
        encode_stream_id(0, &mut buf).expect("encode");
        assert_eq!(buf, vec![0x00]);
        let (decoded, rest) = decode_stream_id(&buf).expect("decode");
        assert_eq!(decoded, 0);
        assert!(rest.is_empty());
    }
}
