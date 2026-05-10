# nerw-rpc

Mesh-agnostic RPC framework over [iroh](https://www.iroh.computer/) with WIT
contracts and a postcard wire format. Designed for the
[nerw](https://github.com/nerwsys) P2P mesh — chat, storage, and future apps
share one transport, one handshake, and one schema discovery surface.

## Status

**Phase 1 — bootstrap.** This crate ships the core types: `RpcContext`,
`RpcError`, the postcard codec wrappers, the wire framing primitives, and
the `MethodRegistry` with text canonical method names.

Transport binding (iroh QUIC + datagrams) lands in **Phase 2** after the
[nerw](https://github.com/nerwsys) Batch 2d merges.

WIT codegen — generating typed clients/handlers from
[Component Model](https://component-model.bytecodealliance.org/) WIT
documents — comes in **Phase 3**.

## Design summary

- **Wire format:** [postcard](https://crates.io/crates/postcard) — positional,
  no field tags, varint+zigzag. Compact, fast, stable across versions as long
  as struct field order doesn't change.
- **Method-id:** text canonical name `package[@version]/interface/method`
  (e.g. `tolki:chat@1.0.0/chat/send-message`). Version is optional —
  unpinned lookups resolve to the latest registered semver.
- **Stream-per-request:** the QUIC stream-id correlates request ↔ response.
  No wire-level request-id field — saves bytes on every frame.
- **Transport:** [iroh](https://www.iroh.computer/) QUIC for bidi streams,
  iroh datagrams for low-latency / lossy traffic. Single `nerw-rpc/1` ALPN.
- **Auth context:** privacy-first `RpcContext` carries opaque cryptographic
  identifiers only — no platform / OS / device-model / locale fields. The
  server stays blind to client device characteristics by design.
- **Schema discoverability:** every server must implement the mandatory
  `tolki:schema@1.0.0/schema/get` method, returning a flattened WIT document
  describing all registered interfaces. Phase 3 wires this in automatically
  via codegen.

## Authoritative design

The full ratified design (Pavel 2026-05-10) lives at
`/src/tasks/tolki-server/.artifacts/research/NERW-RPC-DESIGN.md` in the
private `tolki` workspace. Sections of interest:

- §2 — goals & non-goals
- §3 — architecture + ratified decisions D1–D8
- §4 — wire format details
- §5 — RPC capabilities (unary, server-stream, bidi, datagrams)
- §11 — iroh integration examples

## License

Apache-2.0. See [`LICENSE`](./LICENSE).
