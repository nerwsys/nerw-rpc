//! Peer-as-relay transit protocol — wire frames + signed vouchers.
//!
//! NRW-000045 Phase A1: data structures, codec, and Ed25519 voucher
//! crypto for the decentralized peer-as-relay MVP. No async, no
//! networking, no state — those land in Phase A2 (server handler)
//! and Phase A3 (client API).
//!
//! ## Design — role-discriminated single ALPN
//!
//! libp2p's Circuit Relay v2 splits HOP (client↔relay) and STOP
//! (relay↔target) into two ALPNs because libp2p multiplex was bolted on
//! top of TCP via yamux/mplex. iroh runs over QUIC where each stream
//! is natively multiplexed and the per-stream ALPN is fixed by the
//! connection — so both roles share one ALPN
//! ([`crate::transport::ALPN_NERW_TRANSIT_1_0_0`]) and the **first frame
//! variant** disambiguates intent:
//!
//! | First frame | Role of the opener | Other side responds with |
//! |-------------|--------------------|--------------------------|
//! | [`TransitFrame::Hello`] | introductory handshake (either role) | [`TransitFrame::Hello`] |
//! | [`TransitFrame::ReserveRequest`] | reservee (B) asking R for a slot | [`TransitFrame::ReserveResponse`] |
//! | [`TransitFrame::ConnectRequest`] | dialer (A) asking R to bridge to B | [`TransitFrame::ConnectResponse`] |
//! | [`TransitFrame::Bye`] | clean shutdown from either side | — (stream closes) |
//!
//! See `/src/nerw/nerw-infra/CIRCUIT-RELAY-V2-ARCHITECTURE.md` Section
//! "Что упрощаем благодаря iroh" for the design rationale.
//!
//! ## Wire format — postcard
//!
//! Every frame is a single [`TransitFrame`] enum value, postcard-encoded
//! ([`encode_frame`] / [`decode_frame`]). Postcard's varint+positional
//! layout keeps frame headers compact (4–8 bytes for typical control
//! frames) and reuses the same codec
//! ([`crate::codec`]) used elsewhere in nerw-rpc — no protobuf footprint.
//!
//! Each frame is a self-contained postcard message; framing on the QUIC
//! stream is provided by length-prefixing in Phase A2 (the stream
//! reader/writer wraps each frame with a varint length header). Phase A1
//! exposes only the per-frame codec.
//!
//! ## Vouchers
//!
//! [`Voucher`] is the relay's signed promise to a reservee: *"I, R, hold
//! a slot for peer B until time T"*. Signed with the relay's iroh
//! [`SecretKey`] (the same Ed25519 key proven by the QUIC/TLS handshake
//! — no separate signed-envelope wrapper as in libp2p). Encoded by
//! [`Voucher::signing_bytes`] for deterministic signing.
//!
//! Verifier flow:
//!
//! 1. Reservee receives [`Voucher`] in a [`TransitFrame::ReserveResponse::Granted`].
//! 2. Reservee re-announces in pkarr: *"I'm reachable via relay R, here's
//!    the voucher proving R agreed"*.
//! 3. Dialer A fetches the voucher from pkarr, [`Voucher::verify`]s against
//!    R's public key, then opens a transit stream to R carrying it.
//! 4. R re-validates the voucher (own signature) and the expiry before
//!    bridging.
//!
//! ## Usage example
//!
//! ```
//! use nerw_rpc::transit::{
//!     Capabilities, TransitFrame, Voucher, encode_frame, decode_frame,
//! };
//! use iroh::SecretKey;
//!
//! // Build a peer's introductory frame
//! let secret = SecretKey::from_bytes(&[7u8; 32]);
//! let hello = TransitFrame::Hello {
//!     peer_id: secret.public(),
//!     capabilities: Capabilities::default(),
//! };
//!
//! // Round-trip through postcard
//! let wire = encode_frame(&hello).unwrap();
//! let decoded = decode_frame(&wire).unwrap();
//! assert_eq!(hello, decoded);
//!
//! // Sign + verify a voucher
//! let voucher = Voucher::sign(
//!     &secret,
//!     secret.public(),    // reservee node id
//!     1_700_000_000 + 600 // expires 10 minutes from epoch-1.7B
//! );
//! voucher.verify(&secret.public()).unwrap();
//! ```

use iroh::{PublicKey, SecretKey, Signature};
use serde::{Deserialize, Serialize};

use crate::context::NodeId;

/// Voucher signing-domain tag — prevents cross-protocol signature reuse.
///
/// Prepended to [`Voucher::signing_bytes`] before signing so that a
/// signature produced for a transit voucher can never be replayed as a
/// signature for any other nerw protocol. Constant value chosen to be
/// human-readable in hexdumps + unique to this module.
const VOUCHER_DOMAIN_TAG: &[u8] = b"nerw/transit/voucher/v1";

/// Reservation slot Time-To-Live exposed by [`Limits::default`].
///
/// 600 seconds (10 min) matches `CIRCUIT-RELAY-V2-ARCHITECTURE.md`
/// «короче TTL резервации» recommendation (shorter than libp2p's 1 hour
/// because nerw's pkarr DHT propagates updates within seconds, so cheap
/// failover is preferable to long-lived slot rentals).
pub const DEFAULT_RESERVATION_TTL_SECS: u64 = 600;

/// Peer-advertised capabilities — Phase A1 reserves the type so future
/// phases can add fields without breaking the wire format.
///
/// Postcard's positional layout requires field-add discipline: any new
/// field MUST be appended at the end and MUST tolerate being missing
/// when decoding old peers' frames. Phase A1 ships an empty struct —
/// Phase A4 may add e.g. `max_bandwidth_bps: Option<u64>`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Capabilities {
    /// Reserved bitflags slot — currently always `0`. Permits forward-
    /// compatible feature negotiation without changing the postcard
    /// schema (each bit is owned by a future phase).
    pub reserved_flags: u32,
}

/// Engineering + policy limits the relay advertises with a reservation.
///
/// "Engineering" limits (buffer size, fd headroom) are physical caps —
/// the relay cannot violate them. "Policy" limits (duration, total
/// bytes) are the relay's contractual ceiling for one circuit:
/// `0` means «unlimited» (Pavel's personal mode default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Limits {
    /// Maximum bytes the relay will forward across the circuit before
    /// closing it. `0` = unlimited (personal-mode default).
    pub max_circuit_bytes: u64,

    /// Maximum wall-clock seconds the circuit may stay open. `0` =
    /// unlimited (personal-mode default).
    pub max_circuit_duration_secs: u64,
}

impl Default for Limits {
    /// Personal-mode defaults — unlimited bytes + duration. Caller
    /// MUST tighten these for community / public bootstrap modes
    /// (per `CIRCUIT-RELAY-V2-ARCHITECTURE.md` Section "Защита от
    /// злоупотреблений").
    fn default() -> Self {
        Self {
            max_circuit_bytes: 0,
            max_circuit_duration_secs: 0,
        }
    }
}

/// Reason codes carried in error-bearing response frames.
///
/// Postcard encodes this as a varint; values are stable across the
/// 1.0.x ALPN line. Adding a new variant is a wire-format MINOR bump
/// (consumers MUST handle unknown variants as
/// [`TransitError::MalformedFrame`] — pattern enforced by
/// [`decode_frame`]'s strict deserialization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TransitError {
    /// Reserve/connect denied — caller not in `allowed_reservers` /
    /// `allowed_callers` whitelist.
    WhitelistRejected,

    /// Reserve denied — relay has hit its `max_total_reservations`
    /// engineering cap.
    CapacityFull,

    /// Connect denied — supplied voucher's expiry timestamp is in
    /// the past.
    VoucherExpired,

    /// Connect denied — voucher's signature did not verify against the
    /// expected relay public key (forged or tampered).
    VoucherInvalidSig,

    /// Connect denied — relay has no active reservation for the
    /// requested `target_id`.
    TargetNotFound,

    /// Frame failed to decode (truncated bytes, unknown variant, etc.).
    /// Returned by [`decode_frame`] on the local side too.
    MalformedFrame,

    /// Frame decoded correctly but arrived out of the expected
    /// state-machine order (e.g. `ReserveRequest` after `Bye`).
    UnexpectedFrame,
}

impl core::fmt::Display for TransitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match *self {
            Self::WhitelistRejected => "caller is not in the relay's whitelist",
            Self::CapacityFull => "relay reservation table is full",
            Self::VoucherExpired => "voucher expiry is in the past",
            Self::VoucherInvalidSig => "voucher signature does not verify",
            Self::TargetNotFound => "no active reservation for the requested target",
            Self::MalformedFrame => "frame failed to decode",
            Self::UnexpectedFrame => "frame is valid but unexpected in current state",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for TransitError {}

/// Signed reservation grant — relay's promise that a slot is held.
///
/// Wire format (postcard, positional):
///
/// 1. `relay_node_id` — 32-byte Ed25519 public key of the issuing relay.
/// 2. `peer_node_id`  — 32-byte Ed25519 public key of the reservee.
/// 3. `expire_unix_secs` — varint seconds-since-UNIX-epoch after which
///    the voucher is invalid.
/// 4. `signature` — 64-byte Ed25519 signature over
///    [`Self::signing_bytes`] using the relay's [`SecretKey`].
///
/// The signing-domain tag [`VOUCHER_DOMAIN_TAG`] is prepended to the
/// signed message so a signature produced here can never be replayed
/// as a signature for any other nerw protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Voucher {
    /// Issuing relay's iroh node-id (Ed25519 public key, 32 bytes).
    /// The voucher's signature MUST verify against this key.
    pub relay_node_id: NodeId,

    /// Reservee's iroh node-id — the peer for whom the slot is held.
    pub peer_node_id: NodeId,

    /// Wall-clock seconds since the UNIX epoch after which the voucher
    /// is invalid. Validators MUST reject vouchers where
    /// `expire_unix_secs <= now_unix_secs()`.
    pub expire_unix_secs: u64,

    /// Ed25519 signature over [`Self::signing_bytes`] by the relay's
    /// [`SecretKey`]. Fixed 64 bytes; postcard serializes it as a
    /// fixed-length tuple.
    pub signature: Signature,
}

impl Voucher {
    /// Sign a new voucher with the relay's secret key.
    ///
    /// The relay caller passes its own [`SecretKey`] (which proves the
    /// QUIC/TLS handshake) — no separate signing key, no signed-envelope
    /// wrapper. The resulting [`Voucher::signature`] verifies against
    /// `secret.public()`.
    ///
    /// # Example
    ///
    /// ```
    /// # use iroh::SecretKey;
    /// # use nerw_rpc::transit::Voucher;
    /// let relay = SecretKey::from_bytes(&[1u8; 32]);
    /// let peer = SecretKey::from_bytes(&[2u8; 32]);
    /// let voucher = Voucher::sign(&relay, peer.public(), 1_700_000_600);
    /// voucher.verify(&relay.public()).unwrap();
    /// ```
    #[must_use]
    pub fn sign(relay_secret: &SecretKey, peer_node_id: NodeId, expire_unix_secs: u64) -> Self {
        let relay_node_id = relay_secret.public();
        let to_sign = Self::compose_signing_bytes(&relay_node_id, &peer_node_id, expire_unix_secs);
        let signature = relay_secret.sign(&to_sign);
        Self {
            relay_node_id,
            peer_node_id,
            expire_unix_secs,
            signature,
        }
    }

    /// Verify the voucher's signature against an expected relay key.
    ///
    /// Pass the expected `relay_pub_key` separately (rather than trusting
    /// [`Self::relay_node_id`] in the voucher) so verifiers can pin the
    /// voucher to a known relay identity — preventing a forged voucher
    /// where the attacker substitutes their own key. Callers MUST
    /// additionally check [`Self::is_expired`] before honoring the
    /// voucher.
    ///
    /// # Errors
    ///
    /// Returns [`TransitError::VoucherInvalidSig`] if:
    /// - the voucher's `relay_node_id` doesn't match `relay_pub_key`, or
    /// - the Ed25519 signature does not verify.
    pub fn verify(&self, relay_pub_key: &PublicKey) -> Result<(), TransitError> {
        if self.relay_node_id != *relay_pub_key {
            return Err(TransitError::VoucherInvalidSig);
        }
        let to_verify = Self::compose_signing_bytes(
            &self.relay_node_id,
            &self.peer_node_id,
            self.expire_unix_secs,
        );
        relay_pub_key
            .verify(&to_verify, &self.signature)
            .map_err(|_| TransitError::VoucherInvalidSig)
    }

    /// True iff `now_unix_secs >= self.expire_unix_secs`.
    ///
    /// Caller passes the current time so this stays pure (no system-clock
    /// dependency). Phase A2 handlers will plumb in `tokio::time::Instant`
    /// monotonic-clock conversion at the boundary.
    #[must_use]
    pub const fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.expire_unix_secs
    }

    /// Return the byte-sequence that gets signed / verified.
    ///
    /// Exposed (rather than kept private) so future verifiers — e.g.
    /// a tolki-server doing remote voucher-revocation checks — can
    /// reconstruct the signing input without re-implementing the
    /// domain-tag prefix.
    #[must_use]
    pub fn signing_bytes(&self) -> Vec<u8> {
        Self::compose_signing_bytes(
            &self.relay_node_id,
            &self.peer_node_id,
            self.expire_unix_secs,
        )
    }

    /// Compose the bytes that get fed to Ed25519 sign / verify.
    ///
    /// Layout: `VOUCHER_DOMAIN_TAG || relay_pk(32) || peer_pk(32) ||
    /// expire_be(8)`. Big-endian for the timestamp so the byte
    /// sequence is independent of host endianness — important for
    /// determinism across diverse peers.
    fn compose_signing_bytes(
        relay_node_id: &NodeId,
        peer_node_id: &NodeId,
        expire_unix_secs: u64,
    ) -> Vec<u8> {
        // Statically-known capacity — the constants are fixed and the
        // sum fits in `usize` on every supported target (max ≈ 100).
        // Computed via `saturating_add` so clippy's
        // `arithmetic_side_effects` lint stays clean without an
        // `#[allow]`.
        let capacity = VOUCHER_DOMAIN_TAG
            .len()
            .saturating_add(32)
            .saturating_add(32)
            .saturating_add(8);
        let mut buf = Vec::with_capacity(capacity);
        buf.extend_from_slice(VOUCHER_DOMAIN_TAG);
        buf.extend_from_slice(relay_node_id.as_bytes());
        buf.extend_from_slice(peer_node_id.as_bytes());
        buf.extend_from_slice(&expire_unix_secs.to_be_bytes());
        buf
    }
}

/// Outcome of a [`TransitFrame::ReserveRequest`].
///
/// Modeled as a `Result`-shaped enum so postcard's varint discriminator
/// keeps the success path to a single byte tag + the inline voucher,
/// без an extra layer of Option wrapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReserveOutcome {
    /// Reservation granted — voucher + advertised limits attached.
    Granted {
        /// Signed grant the reservee can attach to its pkarr announcement
        /// and that dialers will replay back to this relay.
        voucher: Voucher,
        /// Limits the relay will enforce on any circuit opened through
        /// this reservation.
        limits: Limits,
    },
    /// Reservation rejected — see [`TransitError`] for the reason.
    Denied(TransitError),
}

/// Outcome of a [`TransitFrame::ConnectRequest`].
///
/// Same shape rationale as [`ReserveOutcome`] — explicit `Granted` /
/// `Denied` variants keep the on-the-wire discriminator dense.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConnectOutcome {
    /// Circuit established — subsequent bytes on the stream are the
    /// opaque relayed payload (no more transit frames).
    Granted,
    /// Connect rejected — see [`TransitError`] for the reason.
    Denied(TransitError),
}

/// Top-level transit frame — every byte on a `nerw/transit/1.0.0`
/// stream (before the relayed-payload phase) is exactly one of these,
/// postcard-encoded.
///
/// Field order is the wire-order discriminator: postcard tags each
/// variant by its declaration index (0, 1, 2, …) as a single-byte
/// varint, so reordering this enum is a wire-breaking change.
///
/// ## Wire layout examples (informal)
///
/// `Hello`:
/// ```text
///   tag=0 | peer_id(32) | capabilities.reserved_flags(varint)
/// ```
///
/// `ReserveRequest`:
/// ```text
///   tag=1 | reservee_id(32) | signature(64)
/// ```
///
/// `ReserveResponse(Granted)`:
/// ```text
///   tag=2 | outcome.tag=0 | voucher.relay_pk(32) | voucher.peer_pk(32)
///         | voucher.expire(varint) | voucher.signature(64)
///         | limits.max_bytes(varint) | limits.max_duration(varint)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum TransitFrame {
    /// Introductory frame — either side sends this immediately after
    /// stream open to identify itself + advertise capabilities. The
    /// receiver's mirrored `Hello` completes the per-stream handshake.
    Hello {
        /// Sender's iroh node-id (Ed25519 public key, 32 bytes).
        /// Cross-checks against the QUIC/TLS handshake identity at the
        /// receiver to detect mis-routing or replay.
        peer_id: NodeId,
        /// Sender's feature-flag bitset — Phase A1 always zero.
        capabilities: Capabilities,
    },

    /// Reservee (B) asks relay (R) to reserve a slot.
    ///
    /// The included `signature` is over the reservee's intent to be
    /// reachable through R, so R can later cite it as proof in pkarr
    /// re-announcements. (Phase A2 may further refine the signing
    /// payload; Phase A1 ships the field as opaque bytes к keep wire
    /// surface stable.)
    ReserveRequest {
        /// Node-id of the reservee — typically equal to the stream's
        /// QUIC/TLS identity, but carried explicitly so relays can
        /// detect mis-binding.
        reservee_id: NodeId,
        /// Reservee's Ed25519 signature over the reservation intent.
        /// Opaque bytes in Phase A1 — verified by [`Phase A2 handler`].
        signature: Vec<u8>,
    },

    /// Relay's response к a [`Self::ReserveRequest`].
    ReserveResponse(ReserveOutcome),

    /// Dialer (A) asks relay (R) к bridge to a target.
    ConnectRequest {
        /// Node-id of the reservee being dialed.
        target_id: NodeId,
        /// Voucher proving the target really did reserve a slot at this
        /// relay. `None` means the dialer trusts the relay's local
        /// state (used in personal-mode where ACL + pkarr already
        /// vouch for the binding).
        voucher: Option<Voucher>,
    },

    /// Relay's response к a [`Self::ConnectRequest`].
    ConnectResponse(ConnectOutcome),

    /// Clean shutdown — either side may send this to signal the peer
    /// that no further transit frames are coming. The stream is closed
    /// после this frame is observed.
    Bye {
        /// Optional human-readable reason — primarily for logs /
        /// metrics, NOT machine-routable (use [`TransitError`] for that).
        reason: Option<String>,
    },
}

/// Encode a single [`TransitFrame`] into a postcard byte vector.
///
/// # Errors
///
/// Returns [`TransitError::MalformedFrame`] if postcard serialization
/// fails — should be unreachable for well-formed inputs, but the
/// surface is fallible to forward parity with [`decode_frame`].
pub fn encode_frame(frame: &TransitFrame) -> Result<Vec<u8>, TransitError> {
    postcard::to_allocvec(frame).map_err(|_| TransitError::MalformedFrame)
}

/// Decode a single [`TransitFrame`] from a postcard byte slice.
///
/// Strict / exact decode: trailing bytes (i.e. `bytes` longer than the
/// minimal frame encoding) cause a [`TransitError::MalformedFrame`]
/// error. Phase A2's stream reader prefixes each frame with a varint
/// length header so the slice handed here always covers exactly one
/// frame.
///
/// # Errors
///
/// Returns [`TransitError::MalformedFrame`] on truncated or otherwise
/// malformed bytes.
pub fn decode_frame(bytes: &[u8]) -> Result<TransitFrame, TransitError> {
    let (frame, rest): (TransitFrame, &[u8]) =
        postcard::take_from_bytes(bytes).map_err(|_| TransitError::MalformedFrame)?;
    if !rest.is_empty() {
        return Err(TransitError::MalformedFrame);
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay_secret() -> SecretKey {
        SecretKey::from_bytes(&[1u8; 32])
    }

    fn peer_secret() -> SecretKey {
        SecretKey::from_bytes(&[2u8; 32])
    }

    fn make_voucher() -> Voucher {
        Voucher::sign(&relay_secret(), peer_secret().public(), 1_700_000_600)
    }

    // ─── Frame round-trip tests ────────────────────────────────────────

    #[test]
    fn hello_frame_roundtrip() {
        let frame = TransitFrame::Hello {
            peer_id: peer_secret().public(),
            capabilities: Capabilities::default(),
        };
        let wire = encode_frame(&frame).unwrap();
        let decoded = decode_frame(&wire).unwrap();
        assert_eq!(frame, decoded);
    }

    #[test]
    fn reserve_request_frame_roundtrip() {
        let frame = TransitFrame::ReserveRequest {
            reservee_id: peer_secret().public(),
            signature: vec![9u8; 64],
        };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn reserve_response_granted_roundtrip() {
        let frame = TransitFrame::ReserveResponse(ReserveOutcome::Granted {
            voucher: make_voucher(),
            limits: Limits::default(),
        });
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn reserve_response_denied_roundtrip() {
        let frame =
            TransitFrame::ReserveResponse(ReserveOutcome::Denied(TransitError::WhitelistRejected));
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn connect_request_with_voucher_roundtrip() {
        let frame = TransitFrame::ConnectRequest {
            target_id: peer_secret().public(),
            voucher: Some(make_voucher()),
        };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn connect_request_without_voucher_roundtrip() {
        let frame = TransitFrame::ConnectRequest {
            target_id: peer_secret().public(),
            voucher: None,
        };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn connect_response_granted_roundtrip() {
        let frame = TransitFrame::ConnectResponse(ConnectOutcome::Granted);
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn connect_response_denied_target_not_found_roundtrip() {
        let frame =
            TransitFrame::ConnectResponse(ConnectOutcome::Denied(TransitError::TargetNotFound));
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn bye_with_reason_roundtrip() {
        let frame = TransitFrame::Bye {
            reason: Some("graceful shutdown".to_owned()),
        };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    #[test]
    fn bye_without_reason_roundtrip() {
        let frame = TransitFrame::Bye { reason: None };
        let wire = encode_frame(&frame).unwrap();
        assert_eq!(decode_frame(&wire).unwrap(), frame);
    }

    // ─── Voucher tests ─────────────────────────────────────────────────

    #[test]
    fn voucher_sign_then_verify_succeeds() {
        let relay = relay_secret();
        let voucher = Voucher::sign(&relay, peer_secret().public(), 1_700_000_600);
        voucher.verify(&relay.public()).unwrap();
    }

    #[test]
    fn voucher_verify_against_wrong_relay_fails() {
        let attacker = SecretKey::from_bytes(&[99u8; 32]);
        let voucher = make_voucher();
        let err = voucher.verify(&attacker.public()).unwrap_err();
        assert_eq!(err, TransitError::VoucherInvalidSig);
    }

    #[test]
    fn voucher_with_tampered_expiry_fails_verification() {
        let mut voucher = make_voucher();
        voucher.expire_unix_secs = voucher.expire_unix_secs.saturating_add(86_400);
        let err = voucher.verify(&voucher.relay_node_id).unwrap_err();
        assert_eq!(err, TransitError::VoucherInvalidSig);
    }

    #[test]
    fn voucher_with_tampered_peer_id_fails_verification() {
        let mut voucher = make_voucher();
        let attacker = SecretKey::from_bytes(&[77u8; 32]);
        voucher.peer_node_id = attacker.public();
        let err = voucher.verify(&voucher.relay_node_id).unwrap_err();
        assert_eq!(err, TransitError::VoucherInvalidSig);
    }

    #[test]
    fn voucher_with_swapped_relay_in_struct_fails_verification() {
        // Attacker swaps the embedded relay_node_id to claim a different
        // relay issued the voucher. Verify against the FAKE key — the
        // check rejects because the signature was produced by the
        // original relay.
        let mut voucher = make_voucher();
        let fake_relay = SecretKey::from_bytes(&[55u8; 32]);
        voucher.relay_node_id = fake_relay.public();
        let err = voucher.verify(&fake_relay.public()).unwrap_err();
        assert_eq!(err, TransitError::VoucherInvalidSig);
    }

    #[test]
    fn voucher_is_expired_check() {
        let voucher = make_voucher();
        assert!(!voucher.is_expired(voucher.expire_unix_secs.saturating_sub(1)));
        assert!(voucher.is_expired(voucher.expire_unix_secs));
        assert!(voucher.is_expired(voucher.expire_unix_secs.saturating_add(1)));
    }

    #[test]
    fn voucher_signing_bytes_includes_domain_tag() {
        let voucher = make_voucher();
        let bytes = voucher.signing_bytes();
        assert!(
            bytes.starts_with(VOUCHER_DOMAIN_TAG),
            "voucher signing input must begin with the domain-separation tag"
        );
        // Layout: tag || relay_pk(32) || peer_pk(32) || expire_be(8)
        assert_eq!(bytes.len(), VOUCHER_DOMAIN_TAG.len() + 32 + 32 + 8);
    }

    #[test]
    fn voucher_postcard_roundtrip_preserves_signature() {
        let voucher = make_voucher();
        let wire = postcard::to_allocvec(&voucher).unwrap();
        let decoded: Voucher = postcard::from_bytes(&wire).unwrap();
        assert_eq!(decoded, voucher);
        decoded.verify(&voucher.relay_node_id).unwrap();
    }

    // ─── Codec robustness ──────────────────────────────────────────────

    #[test]
    fn decode_empty_input_yields_malformed_frame() {
        let err = decode_frame(&[]).unwrap_err();
        assert_eq!(err, TransitError::MalformedFrame);
    }

    #[test]
    fn decode_truncated_input_yields_malformed_frame() {
        let frame = TransitFrame::Hello {
            peer_id: peer_secret().public(),
            capabilities: Capabilities::default(),
        };
        let wire = encode_frame(&frame).unwrap();
        // Drop the last byte — postcard sees premature EOF.
        let truncated = &wire[..wire.len().saturating_sub(1)];
        let err = decode_frame(truncated).unwrap_err();
        assert_eq!(err, TransitError::MalformedFrame);
    }

    #[test]
    fn decode_trailing_garbage_yields_malformed_frame() {
        let frame = TransitFrame::Bye { reason: None };
        let mut wire = encode_frame(&frame).unwrap();
        wire.push(0xAA);
        let err = decode_frame(&wire).unwrap_err();
        assert_eq!(err, TransitError::MalformedFrame);
    }

    #[test]
    fn decode_random_bytes_yields_malformed_frame() {
        // High-tag byte that doesn't map к any variant.
        let err = decode_frame(&[0xFF, 0xFF, 0xFF]).unwrap_err();
        assert_eq!(err, TransitError::MalformedFrame);
    }

    // ─── TransitError surface ──────────────────────────────────────────

    #[test]
    fn transit_error_display_is_human_readable() {
        let cases = [
            TransitError::WhitelistRejected,
            TransitError::CapacityFull,
            TransitError::VoucherExpired,
            TransitError::VoucherInvalidSig,
            TransitError::TargetNotFound,
            TransitError::MalformedFrame,
            TransitError::UnexpectedFrame,
        ];
        for e in cases {
            let rendered = format!("{e}");
            assert!(!rendered.is_empty(), "Display for {e:?} must not be empty");
        }
    }

    #[test]
    fn transit_error_implements_std_error() {
        fn assert_error<E: std::error::Error>(_e: &E) {}
        assert_error(&TransitError::CapacityFull);
    }

    // ─── Limits defaults ───────────────────────────────────────────────

    #[test]
    fn limits_default_is_personal_mode_unlimited() {
        let limits = Limits::default();
        assert_eq!(limits.max_circuit_bytes, 0);
        assert_eq!(limits.max_circuit_duration_secs, 0);
    }

    #[test]
    fn default_reservation_ttl_matches_design_doc() {
        // CIRCUIT-RELAY-V2-ARCHITECTURE.md: «5-10 минут вместо часа libp2p».
        // Pinned at compile time — a bump outside this band must be
        // accompanied by a design-doc update + this band widening.
        const _CHECK_LOWER: () = assert!(DEFAULT_RESERVATION_TTL_SECS >= 300);
        const _CHECK_UPPER: () = assert!(DEFAULT_RESERVATION_TTL_SECS <= 600);
    }
}
