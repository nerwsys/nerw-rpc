#![allow(
    // Assertions in tests are explicit by design.
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    // `_ => panic!(...)` is the idiomatic narrow-variant assertion form;
    // listing every variant adds noise without trust-boundary value.
    clippy::wildcard_enum_match_arm,
    // Numeric literal defaults are fine in tests — no wire/disk format
    // depends on these values.
    clippy::default_numeric_fallback,
)]

//! End-to-end nerw-rpc Phase 2.1 integration tests.
//!
//! Stand up two `nerw_core::client::Client` instances on loopback, wire
//! them statically via the peer table, and exercise:
//!
//! 1. **Unary RPC roundtrip** — client opens а bidi substream к server,
//!    writes а framed unary request с method-name `test:hello@1.0.0/test/echo`,
//!    reads the postcard-encoded response.
//! 2. **Version-omitted resolution** — server registers handlers under
//!    two versions of the same `package/interface/method` triple; the
//!    client calls с the version omitted и the framework resolves к
//!    the largest registered version.
//! 3. **Unknown method** — client calls а method-name the server has
//!    not registered; the framework returns
//!    [`nerw_rpc::RpcError::UnknownMethod`] cleanly.
//! 4. **Datagram dispatch** — server registers а
//!    [`nerw_rpc::DatagramHandler`] под а handshake stream-id и а
//!    custom `AlpnHandler` для the datagram ALPN; client dials с the
//!    datagram ALPN and sends а datagram with а matching
//!    `varint(stream-id)` prefix; server's per-connection read loop
//!    dispatches к the handler и observes the payload.
//! 5. **ALPN dispatch** — multiple ALPNs route к distinct handlers
//!    (Phase 2.1 N1 — verifies the server's internal dispatch table).
//! 6. **N2 eviction** — transport read/write errors trigger
//!    `evict_cached_connection` (Phase 2.1 N2).
//!
//! TLS strategy mirrors `nerw_core/tests/stream_control_smoke.rs`:
//! rcgen generates а fresh self-signed CA per test run и pins it via
//! `ClientConfigBuilder::with_ca_pem_path`. No relay or DNS server is
//! contacted; endpoints discover each other via loopback IP transport
//! addrs published into each peer table.
//!
//! ## Post-R3 fixture changes
//!
//! Identity now comes from `SecretKey::generate()` instead of а file
//! path (R3 removed `with_identity_path`). Datagram tests dial а
//! connection directly с the datagram ALPN — pre-R3 nerw-core's
//! built-in `send_datagram`/`subscribe_datagrams` channel is gone, и
//! [`DatagramDispatcher::subscribe_connection`] now owns the
//! per-connection read loop.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use iroh::endpoint::Connection;
use iroh::{EndpointAddr, SecretKey, TransportAddr};
use nerw_core::client::{Client, ClientConfig};
use nerw_rpc::{
    ALPN_NERW_RPC_2_0_0, ALPN_TOLKI_DATAGRAM_2_0_0, ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, AlpnHandler,
    DatagramDispatcher, DatagramHandler, IrohTransportClient, MethodHandler, MethodRegistry,
    RpcClient, RpcContext, RpcError, RpcResult, RpcServer, RpcServerConfig, wire::encode_stream_id,
};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Generate а self-signed cert и write it as PEM к `dest`.
fn write_self_signed_ca(dest: &std::path::Path) -> Result<()> {
    let cert = rcgen::generate_simple_self_signed(vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ])
    .context("rcgen generate_simple_self_signed")?;
    let pem = cert.cert.pem();
    std::fs::write(dest, pem.as_bytes())
        .with_context(|| format!("write CA pem to {}", dest.display()))?;
    Ok(())
}

/// Build а multi-ALPN test [`ClientConfig`] suitable для loopback
/// nerw-rpc Phase 2.1 tests. Pre-registers ALL three ALPNs the framework
/// dispatches plus the built-in `nerw/rpc/2.0.0` so the endpoint
/// accepts every protocol nerw-rpc + nerw-core might negotiate.
///
/// Identity is generated in-process via [`SecretKey::generate`] —
/// post-R3 nerw-core does not own filesystem persistence для identity
/// keys.
fn make_test_config(tmp: &TempDir, label: &str) -> Result<(ClientConfig, PathBuf)> {
    let ca_pem = tmp.path().join(format!("{label}-ca.pem"));
    write_self_signed_ca(&ca_pem)?;
    let cfg = ClientConfig::builder()
        .with_secret_key(SecretKey::generate())
        .with_ca_pem_path(&ca_pem)
        .with_relay_url("https://127.0.0.1:1/")
        .with_alpn(ALPN_NERW_RPC_2_0_0.to_vec())
        .with_alpn(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0.to_vec())
        .with_alpn(ALPN_TOLKI_DATAGRAM_2_0_0.to_vec())
        .with_discovery(None)
        .build();
    Ok((cfg, ca_pem))
}

/// Pick the first IP transport addr from `ep.addr().addrs`.
fn first_ip_addr(ep: &iroh::Endpoint) -> Result<std::net::SocketAddr> {
    let addr = ep.addr();
    addr.addrs
        .iter()
        .find_map(|a| {
            if let TransportAddr::Ip(socket) = a {
                Some(*socket)
            } else {
                None
            }
        })
        .context("endpoint reported no IP transport address")
}

/// Echo handler — responds с the request bytes verbatim.
struct EchoMethodHandler;

#[async_trait]
impl MethodHandler for EchoMethodHandler {
    async fn handle(&self, _ctx: RpcContext, request: Bytes) -> RpcResult<Bytes> {
        Ok(request)
    }
}

/// Versioned-tag handler — responds с а tag identifying the version
/// it was registered under, так version-resolution test can verify
/// которую version actually got picked.
struct TagHandler {
    tag: &'static str,
}

#[async_trait]
impl MethodHandler for TagHandler {
    async fn handle(&self, _ctx: RpcContext, _request: Bytes) -> RpcResult<Bytes> {
        Ok(Bytes::from_static(self.tag.as_bytes()))
    }
}

/// Build а pair of (alpha-client, bravo-server) wired-together
/// instances. Returns the underlying transport handles.
struct DuoFixture {
    alpha_transport: IrohTransportClient,
    bravo_transport: IrohTransportClient,
}

async fn build_duo(label_a: &str, label_b: &str) -> Result<(DuoFixture, TempDir, TempDir)> {
    let tmp_a = tempfile::tempdir().context("tempdir A")?;
    let tmp_b = tempfile::tempdir().context("tempdir B")?;
    let (cfg_a, _ca_a) = make_test_config(&tmp_a, label_a)?;
    let (cfg_b, _ca_b) = make_test_config(&tmp_b, label_b)?;
    let alpha = Client::start(cfg_a).await.context("start alpha")?;
    let bravo = Client::start(cfg_b).await.context("start bravo")?;

    // Publish bravo's address into alpha's peer table so dial works
    // без hitting DNS.
    let bravo_ip = first_ip_addr(bravo.endpoint())?;
    let bravo_addr = EndpointAddr::new(bravo.node_id()).with_ip_addr(bravo_ip);
    alpha.peer_table().insert(bravo_addr).await;

    // Symmetric — bravo MAY want к dial alpha back (e.g. for datagram
    // reverse-traffic tests).
    let alpha_ip = first_ip_addr(alpha.endpoint())?;
    let alpha_addr = EndpointAddr::new(alpha.node_id()).with_ip_addr(alpha_ip);
    bravo.peer_table().insert(alpha_addr).await;

    Ok((
        DuoFixture {
            alpha_transport: IrohTransportClient::new(Arc::new(alpha)),
            bravo_transport: IrohTransportClient::new(Arc::new(bravo)),
        },
        tmp_a,
        tmp_b,
    ))
}

#[tokio::test]
async fn unary_rpc_roundtrip() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("rt-alpha", "rt-bravo").await?;

    // Server side: register handler + serve.
    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    // Client side.
    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();
    let response = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/echo",
            Bytes::from_static(b"PAYLOAD"),
        ),
    )
    .await
    .context("call timed out")?
    .context("call returned an error")?;

    assert_eq!(
        &response[..],
        b"PAYLOAD",
        "echo handler must round-trip the request bytes",
    );
    Ok(())
}

#[tokio::test]
async fn version_omitted_resolves_to_latest() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("ver-alpha", "ver-bravo").await?;

    // Register two versions — 1.0.0 returns "v1", 2.0.0 returns "v2".
    let mut registry = MethodRegistry::new();
    registry.register(
        "test:hello@1.0.0/test/version",
        Arc::new(TagHandler { tag: "v1" }),
    );
    registry.register(
        "test:hello@2.0.0/test/version",
        Arc::new(TagHandler { tag: "v2" }),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // Call с the version OMITTED — must resolve к v2 (largest semver).
    let response = timeout(
        Duration::from_secs(15),
        client.call(&bravo_id, "test:hello/test/version", Bytes::new()),
    )
    .await
    .context("call timed out")?
    .context("call errored")?;
    assert_eq!(
        &response[..],
        b"v2",
        "omitted version must pick latest semver"
    );

    // Pinned 1.0.0 still works.
    let response_v1 = timeout(
        Duration::from_secs(15),
        client.call(&bravo_id, "test:hello@1.0.0/test/version", Bytes::new()),
    )
    .await
    .context("v1 call timed out")?
    .context("v1 call errored")?;
    assert_eq!(
        &response_v1[..],
        b"v1",
        "pinned 1.0.0 must still hit v1 handler"
    );

    Ok(())
}

#[tokio::test]
async fn unknown_method_returns_typed_error() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("unk-alpha", "unk-bravo").await?;

    // Register one method so the registry is non-empty (this exercises
    // the "no exact match AND no version-omitted prefix match" path).
    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let err = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:nonexistent@1.0.0/iface/method",
            Bytes::from_static(b"PAYLOAD"),
        ),
    )
    .await
    .context("call timed out")?
    .expect_err("unknown method must surface as RpcError::UnknownMethod");

    match err {
        RpcError::UnknownMethod(name) => {
            assert_eq!(name, "test:nonexistent@1.0.0/iface/method");
        }
        other => panic!("expected RpcError::UnknownMethod, got {other:?}"),
    }
    Ok(())
}

/// Datagram handler that records the bytes it sees через а Tokio Mutex.
struct RecordingDatagramHandler {
    received: Arc<Mutex<Vec<Vec<u8>>>>,
    notify: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl DatagramHandler for RecordingDatagramHandler {
    async fn handle(&self, _ctx: RpcContext, payload: Bytes) -> RpcResult<()> {
        self.received.lock().await.push(payload.to_vec());
        self.notify.notify_one();
        Ok(())
    }
}

/// Custom [`AlpnHandler`] for the datagram ALPN — wires inbound
/// connections to а [`DatagramDispatcher`] via
/// [`DatagramDispatcher::subscribe_connection`]. Phase 2.1's stand-in
/// for the gone `subscribe_datagrams` broadcast channel.
struct DatagramAlpnHandler {
    dispatcher: Arc<DatagramDispatcher>,
}

#[async_trait]
impl AlpnHandler for DatagramAlpnHandler {
    async fn handle(&self, connection: Connection) -> RpcResult<()> {
        Arc::clone(&self.dispatcher).subscribe_connection(connection);
        Ok(())
    }
}

#[tokio::test]
async fn datagram_dispatch_roundtrip() -> Result<()> {
    // Bravo: dispatcher с handler keyed by handshake stream-id 42.
    // В production code, the stream-id is the QUIC stream-id of the
    // bidi handshake stream that established the voice session; here
    // we mock it as а constant since the test does not perform an
    // actual handshake (the dispatch surface itself is what we exercise).
    const HANDSHAKE_STREAM_ID: u64 = 42;

    let (fix, _tmp_a, _tmp_b) = build_duo("dg-alpha", "dg-bravo").await?;

    let dispatcher = Arc::new(DatagramDispatcher::new());
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let notify = Arc::new(tokio::sync::Notify::new());
    let handler = Arc::new(RecordingDatagramHandler {
        received: Arc::clone(&received),
        notify: Arc::clone(&notify),
    });
    dispatcher
        .register(HANDSHAKE_STREAM_ID, handler)
        .expect("register");

    // Bravo serves the RPC ALPN (default) and additionally registers а
    // custom AlpnHandler для the datagram ALPN that wires inbound
    // connections к the dispatcher's per-connection read loop.
    let registry = Arc::new(MethodRegistry::new());
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    let datagram_alpn_handler: Arc<dyn AlpnHandler> = Arc::new(DatagramAlpnHandler {
        dispatcher: Arc::clone(&dispatcher),
    });
    server.register_alpn_handler(ALPN_TOLKI_DATAGRAM_2_0_0, datagram_alpn_handler);
    server.serve().await.context("server.serve")?;

    // Alpha dials с the datagram ALPN — this triggers bravo's accept
    // loop к invoke the DatagramAlpnHandler, which spawns the per-conn
    // read loop on the dispatcher.
    let alpha_inner = Arc::clone(fix.alpha_transport.inner());
    let bravo_id = fix.bravo_transport.node_id();
    let conn = alpha_inner
        .dial_with_alpn(&bravo_id, ALPN_TOLKI_DATAGRAM_2_0_0)
        .await
        .context("dial_with_alpn")?;

    // Give bravo's accept loop а moment к pick up the connection и
    // wire the dispatcher's read loop. Without this, alpha may send
    // before bravo subscribes и the datagram will be dropped by the
    // peer-side stack before our loop sees it.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Send а datagram с varint(stream-id) prefix:
    // [varint(42) | "RTP-FRAME"]
    let mut payload = Vec::new();
    encode_stream_id(HANDSHAKE_STREAM_ID, &mut payload).expect("encode stream-id");
    payload.extend_from_slice(b"RTP-FRAME");

    conn.send_datagram(Bytes::from(payload))
        .context("send_datagram")?;

    // Wait for the handler к observe the frame.
    timeout(Duration::from_secs(10), notify.notified())
        .await
        .context("handler never received the datagram within 10s")?;

    let recorded = received.lock().await;
    assert_eq!(recorded.len(), 1, "exactly one frame should have arrived");
    assert_eq!(
        recorded[0], b"RTP-FRAME",
        "handler must observe the payload AFTER the varint(stream-id) prefix",
    );
    drop(recorded);

    Ok(())
}

/// Datagram correlation tests — verify the dispatcher's stream-id
/// keyed surface integrates cleanly с the transport layer.
///
/// Pure unit-level concerns (collision detection, idempotent
/// unregister, varint encode/decode) are also exercised inline в
/// `src/datagram.rs::tests` и `src/wire.rs::tests`; the integration
/// tests here verify the SAME behaviour at the read-loop level
/// where real datagrams arrive.
#[tokio::test]
async fn datagram_handshake_correlation_roundtrip() -> Result<()> {
    // Verify the WebTransport-style correlation contract end-to-end:
    // dispatcher registers а handler under а handshake stream-id и
    // routes datagrams carrying а matching varint(stream-id) prefix
    // к that handler. We use а large stream-id (1_000_000) к exercise
    // the multi-byte varint path that the legacy 1-byte token could
    // not represent.
    const HANDSHAKE_STREAM_ID: u64 = 1_000_000;
    let (fix, _tmp_a, _tmp_b) = build_duo("hcorr-alpha", "hcorr-bravo").await?;

    let dispatcher = Arc::new(DatagramDispatcher::new());
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let notify = Arc::new(tokio::sync::Notify::new());
    let handler = Arc::new(RecordingDatagramHandler {
        received: Arc::clone(&received),
        notify: Arc::clone(&notify),
    });
    dispatcher
        .register(HANDSHAKE_STREAM_ID, handler)
        .expect("register");

    let registry = Arc::new(MethodRegistry::new());
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    let datagram_alpn_handler: Arc<dyn AlpnHandler> = Arc::new(DatagramAlpnHandler {
        dispatcher: Arc::clone(&dispatcher),
    });
    server.register_alpn_handler(ALPN_TOLKI_DATAGRAM_2_0_0, datagram_alpn_handler);
    server.serve().await.context("server.serve")?;

    let alpha_inner = Arc::clone(fix.alpha_transport.inner());
    let bravo_id = fix.bravo_transport.node_id();
    let conn = alpha_inner
        .dial_with_alpn(&bravo_id, ALPN_TOLKI_DATAGRAM_2_0_0)
        .await
        .context("dial_with_alpn")?;

    tokio::time::sleep(Duration::from_millis(200)).await;

    // [varint(1_000_000) | "VOICE-FRAME"]
    let mut payload = Vec::new();
    encode_stream_id(HANDSHAKE_STREAM_ID, &mut payload).expect("encode stream-id");
    payload.extend_from_slice(b"VOICE-FRAME");

    conn.send_datagram(Bytes::from(payload))
        .context("send_datagram")?;

    timeout(Duration::from_secs(10), notify.notified())
        .await
        .context("handler never received the datagram within 10s")?;

    let recorded = received.lock().await;
    assert_eq!(recorded.len(), 1);
    assert_eq!(
        recorded[0], b"VOICE-FRAME",
        "handler must observe payload after the varint(stream-id) prefix"
    );
    drop(recorded);

    Ok(())
}

#[tokio::test]
async fn datagram_stream_id_collision_rejected() {
    // Pure unit-level surface — exercised through the public dispatcher
    // API без needing а transport. Mirrors src/datagram.rs::tests::
    // register_collision_errors but with the integration-test naming
    // scheme so the suite reads cohesively.
    let dispatcher = DatagramDispatcher::new();
    let h1 = Arc::new(RecordingDatagramHandler {
        received: Arc::new(Mutex::new(Vec::new())),
        notify: Arc::new(tokio::sync::Notify::new()),
    });
    let h2 = Arc::new(RecordingDatagramHandler {
        received: Arc::new(Mutex::new(Vec::new())),
        notify: Arc::new(tokio::sync::Notify::new()),
    });
    dispatcher.register(42, h1).expect("first register");

    let err = dispatcher
        .register(42, h2)
        .expect_err("second register at same stream-id must error");
    match err {
        RpcError::DatagramStreamIdCollision { stream_id } => assert_eq!(stream_id, 42),
        other => panic!("expected DatagramStreamIdCollision, got {other:?}"),
    }
}

#[tokio::test]
async fn datagram_stream_id_unregister_idempotent() {
    // Unregistering а never-registered stream-id is а silent no-op;
    // calling it twice (or on а fresh dispatcher) MUST NOT panic.
    let dispatcher = DatagramDispatcher::new();
    assert!(dispatcher.unregister(9999).is_none());
    assert!(
        dispatcher.unregister(9999).is_none(),
        "second unregister must stay idempotent"
    );

    // Register-then-unregister-twice — second unregister sees None.
    let h = Arc::new(RecordingDatagramHandler {
        received: Arc::new(Mutex::new(Vec::new())),
        notify: Arc::new(tokio::sync::Notify::new()),
    });
    dispatcher.register(7, h).expect("register");
    assert!(
        dispatcher.unregister(7).is_some(),
        "first unregister returns the previous handler"
    );
    assert!(
        dispatcher.unregister(7).is_none(),
        "second unregister of the same id is а no-op"
    );
}

// =============================================================================
// Adversarial scenarios — verify the framework's resilience against:
//  - concurrent fan-out (parallel calls do NOT serialise)
//  - mid-RPC connection drops (client surfaces transport error cleanly)
//  - malformed inbound bytes (server stays alive, returns MalformedFrame)
//  - handler-returned errors (client decodes RpcError::Handler)
//  - large payloads (1 MiB roundtrip stays within 8 MiB read limit)
//  - bounded concurrent streams (Semaphore enforces max_concurrent_streams)
// =============================================================================

/// Sleep-then-respond handler — used к verify parallel calls do not serialise.
struct SlowHandler {
    delay: Duration,
    invocations: Arc<std::sync::atomic::AtomicU32>,
}

#[async_trait]
impl MethodHandler for SlowHandler {
    async fn handle(&self, _ctx: RpcContext, _request: Bytes) -> RpcResult<Bytes> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(Bytes::from_static(b"OK"))
    }
}

#[tokio::test]
async fn concurrent_calls_do_not_serialize() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("conc-alpha", "conc-bravo").await?;

    let invocations = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let mut registry = MethodRegistry::new();
    registry.register(
        "test:hello@1.0.0/test/slow",
        Arc::new(SlowHandler {
            delay: Duration::from_millis(300),
            invocations: Arc::clone(&invocations),
        }),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // Launch 10 parallel calls. Serial execution would take 10 × 300ms = 3 s;
    // parallel must complete well under 2 s wall-clock.
    let start = std::time::Instant::now();
    let mut tasks = Vec::with_capacity(10);
    for _ in 0..10_u32 {
        let client = client.clone();
        let bravo_id_owned = bravo_id;
        tasks.push(tokio::spawn(async move {
            client
                .call(
                    &bravo_id_owned,
                    "test:hello@1.0.0/test/slow",
                    Bytes::from_static(b"REQ"),
                )
                .await
        }));
    }
    let mut all_ok = 0;
    for t in tasks {
        let r = t.await.context("join")?;
        if r.is_ok() {
            all_ok += 1;
        }
    }
    let elapsed = start.elapsed();
    assert_eq!(all_ok, 10, "all parallel calls must succeed");
    assert!(
        elapsed < Duration::from_millis(2000),
        "10 parallel calls с 300ms handler delay must finish < 2s wall-clock; got {elapsed:?}",
    );
    Ok(())
}

#[tokio::test]
async fn mid_rpc_connection_drop_surfaces_transport_error() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("drop-alpha", "drop-bravo").await?;

    // Handler that takes long enough that we can drop the server transport
    // mid-call.
    let mut registry = MethodRegistry::new();
    registry.register(
        "test:hello@1.0.0/test/slow",
        Arc::new(SlowHandler {
            delay: Duration::from_secs(5),
            invocations: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // Spawn the call в background, then drop bravo's transport handle к
    // tear down the QUIC connection before the handler completes.
    let call_handle = {
        let client = client.clone();
        let bravo_id_owned = bravo_id;
        tokio::spawn(async move {
            client
                .call(
                    &bravo_id_owned,
                    "test:hello@1.0.0/test/slow",
                    Bytes::from_static(b"REQ"),
                )
                .await
        })
    };

    // Give the request enough time к hit the server и start the handler.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Tear down the bravo endpoint — this closes its iroh Endpoint и
    // all active connections, signalling CONNECTION_CLOSE к alpha.
    // We close the underlying iroh Endpoint (Endpoint::close takes &self,
    // works through Arc<Client>::endpoint()) rather than calling
    // Client::shutdown() which consumes self.
    let bravo_inner = Arc::clone(fix.bravo_transport.inner());
    bravo_inner.endpoint().close().await;

    // Client side must surface а concrete transport error (TransportRead
    // or similar) — not silently hang or return success.
    let result = timeout(Duration::from_secs(15), call_handle)
        .await
        .context("call wedged after server shutdown")?
        .context("join")?;
    assert!(
        result.is_err(),
        "call must error after mid-RPC server shutdown; got {result:?}",
    );
    Ok(())
}

#[tokio::test]
async fn malformed_inbound_does_not_crash_server() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("mal-alpha", "mal-bravo").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let bravo_id = fix.bravo_transport.node_id();

    // Open the bidi substream directly без RpcClient framing так we
    // can ship garbage opcodes.  We bypass RpcClient::call entirely
    // because it auto-frames с OPCODE_UNARY_REQUEST.
    let alpha_inner = Arc::clone(fix.alpha_transport.inner());
    let (mut send, mut recv) = alpha_inner
        .open_substream(&bravo_id, ALPN_TOLKI_WIRE_PROTOCOL_2_0_0)
        .await
        .context("open_substream")?;

    // Garbage payload — opcode 0x99 is not а legal frame opcode.
    send.write_all(&[0x99, 0xFF, 0xAA, 0xBB])
        .await
        .context("write garbage")?;
    send.finish().context("finish garbage")?;

    // Server must respond с а typed MalformedFrame error frame, not
    // hang or panic.
    let response_buf = timeout(Duration::from_secs(15), recv.read_to_end(8 * 1024))
        .await
        .context("server hung on garbage frame")?
        .context("read_to_end on garbage response")?;
    // The response frame is OPCODE_UNARY_ERROR (0x02) followed by а
    // postcard-encoded WireError::MalformedFrame.  We only assert the
    // opcode byte here — the framework's typed-error contract is
    // covered by the lib tests.
    assert!(
        !response_buf.is_empty(),
        "server must respond с error frame"
    );
    assert_eq!(
        response_buf[0], 0x02,
        "first byte must be OPCODE_UNARY_ERROR",
    );

    // Subsequent legal calls on а fresh stream must STILL succeed —
    // the server task survived the malformed input.
    let client = RpcClient::new(fix.alpha_transport.clone());
    let response = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/echo",
            Bytes::from_static(b"AFTER-GARBAGE"),
        ),
    )
    .await
    .context("post-garbage call timed out")?
    .context("post-garbage call errored")?;
    assert_eq!(
        &response[..],
        b"AFTER-GARBAGE",
        "server must still serve legal calls after rejecting garbage",
    );
    Ok(())
}

/// Handler that always returns an `RpcError::Handler` carrying а domain error.
struct ErroringHandler;

#[async_trait]
impl MethodHandler for ErroringHandler {
    async fn handle(&self, _ctx: RpcContext, _request: Bytes) -> RpcResult<Bytes> {
        Err(RpcError::Handler(
            "domain failure: invalid input".to_owned().into(),
        ))
    }
}

#[tokio::test]
async fn handler_returns_error_propagates() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("herr-alpha", "herr-bravo").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/fail", Arc::new(ErroringHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let err = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/fail",
            Bytes::from_static(b"REQ"),
        ),
    )
    .await
    .context("call timed out")?
    .expect_err("handler error must surface as RpcError::Handler");
    match err {
        RpcError::Handler(inner) => {
            // The Display message should come through verbatim — handler
            // errors are opaque-but-textual at the wire boundary.
            let s = inner.to_string();
            assert!(
                s.contains("domain failure"),
                "handler error display must contain inner message; got `{s}`",
            );
        }
        other => panic!("expected RpcError::Handler, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn large_payload_1mb_roundtrip() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("big-alpha", "big-bravo").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // 1 MiB payload, well under the 8 MiB cap on either side.
    let payload = Bytes::from(vec![0xAB; 1024 * 1024]);
    let response = timeout(
        Duration::from_secs(30),
        client.call(&bravo_id, "test:hello@1.0.0/test/echo", payload.clone()),
    )
    .await
    .context("call timed out")?
    .context("call errored")?;
    assert_eq!(response.len(), payload.len(), "response length mismatch");
    assert_eq!(&response[..], &payload[..], "response payload mismatch");
    Ok(())
}

/// Barrier handler — increments а counter on entry, blocks until
/// notified, decrements on exit. Lets us assert how many concurrent
/// invocations are в flight at any moment.
struct BarrierHandler {
    in_flight: Arc<std::sync::atomic::AtomicU32>,
    max_observed: Arc<std::sync::atomic::AtomicU32>,
    release: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl MethodHandler for BarrierHandler {
    async fn handle(&self, _ctx: RpcContext, _request: Bytes) -> RpcResult<Bytes> {
        let cur = self
            .in_flight
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        // Track the maximum concurrency we ever observed.
        self.max_observed
            .fetch_max(cur, std::sync::atomic::Ordering::SeqCst);
        self.release.notified().await;
        self.in_flight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Bytes::from_static(b"OK"))
    }
}

#[tokio::test]
async fn max_concurrent_streams_enforced() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("sem-alpha", "sem-bravo").await?;

    let in_flight = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let max_observed = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let release = Arc::new(tokio::sync::Notify::new());

    let mut registry = MethodRegistry::new();
    registry.register(
        "test:hello@1.0.0/test/wait",
        Arc::new(BarrierHandler {
            in_flight: Arc::clone(&in_flight),
            max_observed: Arc::clone(&max_observed),
            release: Arc::clone(&release),
        }),
    );
    let registry = Arc::new(registry);

    // Cap at 2 concurrent streams. Connection cap stays at default 1024
    // so it does not interfere с the test.
    let cfg = RpcServerConfig {
        max_concurrent_streams: 2,
        max_concurrent_connections: 1024,
    };
    let server =
        RpcServer::with_config(fix.bravo_transport.clone(), Arc::clone(&registry), cfg);
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // Launch 5 parallel calls. With max_concurrent_streams=2, at most
    // 2 of them can be inside the handler at once until we release them.
    let mut tasks = Vec::with_capacity(5);
    for _ in 0..5_u32 {
        let client = client.clone();
        let bravo_id_owned = bravo_id;
        tasks.push(tokio::spawn(async move {
            client
                .call(
                    &bravo_id_owned,
                    "test:hello@1.0.0/test/wait",
                    Bytes::from_static(b"REQ"),
                )
                .await
        }));
    }

    // Give time for the bound к take effect (semaphore releases on
    // task drop, not on `await` return — but no task can complete until
    // we notify the barrier).
    tokio::time::sleep(Duration::from_millis(800)).await;

    let observed_now = in_flight.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        observed_now <= 2,
        "in-flight handler count {observed_now} exceeds Semaphore cap of 2",
    );

    // Release ALL pending handlers (notify_waiters wakes everyone).
    for _ in 0..10 {
        release.notify_one();
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    // Wake any stragglers that arrived after the first batch released.
    for _ in 0..10 {
        release.notify_one();
    }

    let mut succeeded = 0;
    for t in tasks {
        match timeout(Duration::from_secs(15), t).await {
            Ok(Ok(Ok(_))) => succeeded += 1,
            Ok(Ok(Err(e))) => panic!("call errored: {e:?}"),
            Ok(Err(e)) => panic!("join error: {e:?}"),
            Err(elapsed) => panic!("call timed out after {elapsed:?}"),
        }
    }
    assert_eq!(succeeded, 5, "all 5 calls must complete after release");

    // The peak concurrent in-flight count must be ≤ Semaphore cap.
    let peak = max_observed.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        peak <= 2,
        "max concurrent in-flight handlers was {peak}, expected ≤ 2 (Semaphore cap)",
    );
    Ok(())
}

// =============================================================================
// Phase 2.1 new tests — verify ALPN dispatch table and N2 stale-conn eviction.
// =============================================================================

/// Counter handler — increments on each connection. Used к verify
/// custom [`AlpnHandler`]s receive their inbound connections.
struct ConnectionCountingAlpnHandler {
    invocations: Arc<std::sync::atomic::AtomicU32>,
    notify: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl AlpnHandler for ConnectionCountingAlpnHandler {
    async fn handle(&self, _connection: Connection) -> RpcResult<()> {
        self.invocations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.notify.notify_one();
        // Do not return until the test releases us — keeps the
        // connection open so the inbound side observes it.
        Ok(())
    }
}

#[tokio::test]
async fn accept_loop_dispatches_by_alpn() -> Result<()> {
    // Two ALPNs, two handlers — the dispatcher must route inbound
    // connections к the correct handler based on negotiated ALPN.
    // The wire-protocol ALPN goes к its built-in handler (а full RPC
    // roundtrip exercises it); the datagram ALPN goes к а custom
    // counting handler we register.

    let (fix, _tmp_a, _tmp_b) = build_duo("alpn-disp-alpha", "alpn-disp-bravo").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));

    let datagram_invocations = Arc::new(std::sync::atomic::AtomicU32::new(0));
    let datagram_notify = Arc::new(tokio::sync::Notify::new());
    let datagram_handler: Arc<dyn AlpnHandler> = Arc::new(ConnectionCountingAlpnHandler {
        invocations: Arc::clone(&datagram_invocations),
        notify: Arc::clone(&datagram_notify),
    });
    server.register_alpn_handler(ALPN_TOLKI_DATAGRAM_2_0_0, datagram_handler);
    server.serve().await.context("server.serve")?;

    // After serve(), the built-in wire handler + our custom datagram
    // handler should both be registered (2 entries).
    assert_eq!(
        server.registered_alpn_count(),
        2,
        "serve must install built-in wire handler alongside our custom one",
    );

    let bravo_id = fix.bravo_transport.node_id();

    // 1. Wire-protocol ALPN — full RPC roundtrip routes к the built-in handler.
    let client = RpcClient::new(fix.alpha_transport.clone());
    let response = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/echo",
            Bytes::from_static(b"WIRE-ALPN"),
        ),
    )
    .await
    .context("wire call timed out")?
    .context("wire call errored")?;
    assert_eq!(&response[..], b"WIRE-ALPN");

    // 2. Datagram ALPN — dialing с this ALPN MUST invoke our custom
    // handler, NOT the wire handler. Verify by counter.
    let alpha_inner = Arc::clone(fix.alpha_transport.inner());
    let _conn = alpha_inner
        .dial_with_alpn(&bravo_id, ALPN_TOLKI_DATAGRAM_2_0_0)
        .await
        .context("dial datagram ALPN")?;

    timeout(Duration::from_secs(10), datagram_notify.notified())
        .await
        .context("datagram-ALPN handler never invoked")?;

    let count = datagram_invocations.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        count, 1,
        "datagram ALPN handler must have been invoked exactly once",
    );

    Ok(())
}

#[tokio::test]
async fn evict_cached_connection_on_transport_error() -> Result<()> {
    // N2 stale-conn defence: when а transport read/write error
    // surfaces, the client evicts the cached connection so the next
    // call dials а fresh handshake instead of replaying а dead entry.
    //
    // We verify this via the test-utils-gated `conn_cache_len()` —
    // after а successful call, the cache holds one entry;
    // after а mid-RPC server teardown that triggers TransportRead, the
    // cache must drop back к zero.

    let (fix, _tmp_a, _tmp_b) = build_duo("evict-alpha", "evict-bravo").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoMethodHandler));
    registry.register(
        "test:hello@1.0.0/test/slow",
        Arc::new(SlowHandler {
            delay: Duration::from_secs(5),
            invocations: Arc::new(std::sync::atomic::AtomicU32::new(0)),
        }),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();
    let alpha_inner = Arc::clone(fix.alpha_transport.inner());

    // 1. Baseline — successful call populates the connection cache.
    timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/echo",
            Bytes::from_static(b"WARM-CACHE"),
        ),
    )
    .await
    .context("baseline call timed out")?
    .context("baseline call errored")?;

    let cache_len_after_warmup = alpha_inner.conn_cache_len().await;
    assert_eq!(
        cache_len_after_warmup, 1,
        "successful call should populate the (peer, alpn) cache",
    );

    // 2. Trigger а transport error. Spawn а slow call в background,
    // then close bravo's endpoint mid-flight to provoke TransportRead.
    let call_handle = {
        let client = client.clone();
        let bravo_id_owned = bravo_id;
        tokio::spawn(async move {
            client
                .call(
                    &bravo_id_owned,
                    "test:hello@1.0.0/test/slow",
                    Bytes::from_static(b"DROP"),
                )
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;

    let bravo_inner = Arc::clone(fix.bravo_transport.inner());
    bravo_inner.endpoint().close().await;

    // Drain the call task so the post-error eviction runs.
    let result = timeout(Duration::from_secs(15), call_handle)
        .await
        .context("call wedged after server shutdown")?
        .context("join")?;
    assert!(
        result.is_err(),
        "call must error after mid-RPC server shutdown",
    );

    // 3. After the eviction code runs, the cache should be empty.
    let cache_len_after_error = alpha_inner.conn_cache_len().await;
    assert_eq!(
        cache_len_after_error, 0,
        "transport error must trigger eviction so the (peer, alpn) cache is empty",
    );

    Ok(())
}

#[tokio::test]
async fn serve_twice_errors_with_already_serving() -> Result<()> {
    // Phase 2.1 N3 — `serve()` is single-shot. Calling twice would
    // spawn а duplicate accept loop racing on `Client::accept` и leak
    // the previous `JoinHandle`. The framework rejects the second call
    // with а typed [`RpcError::AlreadyServing`] instead.
    let (fix, _tmp_a, _tmp_b) = build_duo("twice-alpha", "twice-bravo").await?;

    let registry = Arc::new(MethodRegistry::new());
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));

    // First call MUST succeed — installs the wire handler + spawns the loop.
    server.serve().await.context("first serve")?;

    // Second call on the SAME instance MUST surface AlreadyServing.
    let err = server
        .serve()
        .await
        .expect_err("second serve() must error");
    match err {
        RpcError::AlreadyServing => {}
        other => panic!("expected RpcError::AlreadyServing, got {other:?}"),
    }
    Ok(())
}
