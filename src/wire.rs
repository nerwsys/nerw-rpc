//! Wire frame format constants + helpers.
//!
//! ## Frame layouts (per `NERW-RPC-DESIGN.md` Section 4)
//!
//! ```text
//! UNARY:
//!   Client → Server: [opcode=0x00 | varint(name_len) | method-name UTF-8 | postcard(request)]
//!   Server → Client: [opcode=0x01 | postcard(response)]    # success
//!                    [opcode=0x02 | postcard(error)]       # error
//!
//! STREAMING (single bidi stream):
//!   Open:        [opcode=0x10 | varint(name_len) | method-name | postcard(open)]
//!   Item:        [opcode=0x11 | postcard(item)]
//!   End:         [opcode=0x12 | optional-postcard(trailer)]
//!
//! DATAGRAM:
//!   [token 1B | postcard(item)]
//! ```
//!
//! Phase 1 ships only the framing primitives — opcodes and the method-name
//! length-prefix codec. Full frame encode/decode lives at the transport
//! boundary (Phase 2) where it knows how to emit/consume from a QUIC stream.

use crate::error::{RpcError, RpcResult};

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

/// Streaming "open" opcode — first frame on a bidi stream that names the method.
pub const OPCODE_STREAM_OPEN: u8 = 0x10;
/// Streaming "item" opcode — subsequent payload frames in either direction.
pub const OPCODE_STREAM_ITEM: u8 = 0x11;
/// Streaming "end" opcode — final frame, optionally carries a trailer.
pub const OPCODE_STREAM_END: u8 = 0x12;

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
    leb128::write::unsigned(buf, bytes.len() as u64)
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
    if consumed
        .checked_add(name_len)
        .is_none_or(|end| end > input.len())
    {
        return Err(RpcError::MalformedFrame(
            "method-name length exceeds buffer".to_string(),
        ));
    }
    let name = std::str::from_utf8(&input[consumed..consumed + name_len])
        .map_err(|e| RpcError::MalformedFrame(format!("non-UTF-8 method-name: {e}")))?;
    Ok((name, &input[consumed + name_len..]))
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
        assert_eq!(OPCODE_STREAM_OPEN, 0x10);
        assert_eq!(OPCODE_STREAM_ITEM, 0x11);
        assert_eq!(OPCODE_STREAM_END, 0x12);
    }
}
