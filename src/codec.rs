//! Thin postcard wrappers around the framework's encode/decode boundary.
//!
//! Postcard is the wire format for nerw-rpc payloads (per design D2):
//! positional, no field tags, varint+zigzag — small, fast, and stable as
//! long as struct field order doesn't change. This module is intentionally
//! tiny — it exists so callers can use [`crate::error::RpcError`] uniformly
//! without juggling `postcard::Error` directly.

use crate::error::{RpcError, RpcResult};
use serde::{Deserialize, Serialize};

/// Encode a value to a fresh `Vec<u8>` of postcard bytes.
///
/// # Errors
///
/// Returns [`RpcError::Codec`] if `T`'s `Serialize` impl rejects the value
/// (e.g. unsupported `f64::NAN` keys, unsigned overflow, …).
pub fn encode<T: Serialize>(value: &T) -> RpcResult<Vec<u8>> {
    postcard::to_stdvec(value).map_err(RpcError::from)
}

/// Decode a value from a postcard byte slice.
///
/// # Errors
///
/// Returns [`RpcError::Codec`] if the bytes do not match `T`'s schema.
pub fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> RpcResult<T> {
    postcard::from_bytes(bytes).map_err(RpcError::from)
}

/// Encode a value into an existing buffer (zero-allocation hot-path helper).
///
/// Appends the postcard-encoded bytes to `buf` in place.
///
/// # Errors
///
/// Returns [`RpcError::Codec`] on serialization failure.
pub fn encode_to<T: Serialize>(value: &T, buf: &mut Vec<u8>) -> RpcResult<()> {
    let bytes = postcard::to_stdvec(value)?;
    buf.extend_from_slice(&bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct Sample {
        a: u32,
        b: String,
        c: Vec<u8>,
    }

    #[test]
    fn roundtrip_postcard() {
        let original = Sample {
            a: 42,
            b: "hello".to_string(),
            c: vec![1, 2, 3],
        };
        let bytes = encode(&original).expect("encode succeeds");
        let decoded: Sample = decode(&bytes).expect("decode succeeds");
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_to_appends() {
        let v = Sample {
            a: 7,
            b: "x".to_string(),
            c: vec![],
        };
        let mut buf = vec![0xFFu8, 0xFE]; // existing prefix
        encode_to(&v, &mut buf).expect("encode_to succeeds");
        // Existing prefix preserved.
        assert_eq!(&buf[..2], &[0xFF, 0xFE]);
        // Tail decodes back to the original.
        let decoded: Sample = decode(&buf[2..]).expect("decode tail succeeds");
        assert_eq!(decoded, v);
    }

    #[test]
    fn decode_truncated_fails() {
        let res: RpcResult<Sample> = decode(&[]);
        assert!(matches!(res, Err(RpcError::Codec(_))));
    }
}
