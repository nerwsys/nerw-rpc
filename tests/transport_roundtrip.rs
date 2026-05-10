#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

//! End-to-end nerw-rpc Phase 2 integration tests.
//!
//! Stand up two `nerw_core::client::Client` instances on loopback, wire
//! them statically via the peer table, and exercise:
//!
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
//!    [`nerw_rpc::DatagramHandler`] at token 42; client sends а
//!    datagram с the token prefix; server's broadcast loop dispatches
//!    к the handler and observes the payload.
//!
//! TLS strategy mirrors `nerw_core/tests/stream_control_smoke.rs`:
//! rcgen generates а fresh self-signed CA per test run и pins it via
//! `ClientConfigBuilder::with_ca_pem_path`. No relay or DNS server is
//! contacted; endpoints discover each other via loopback IP transport
//! addrs published into each peer table.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use iroh::{EndpointAddr, TransportAddr};
use nerw_core::client::{Client, ClientConfig};
use nerw_core::protocol::ALPN_NERW_RPC;
use nerw_rpc::{
    ALPN_TOLKI_DATAGRAM_1_0_0, ALPN_TOLKI_WIRE_PROTOCOL_2_0_0, DatagramDispatcher, DatagramHandler,
    IrohTransportClient, MethodHandler, MethodRegistry, RpcClient, RpcContext, RpcError, RpcResult,
    RpcServer,
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
/// nerw-rpc Phase 2 tests. Pre-registers ALL three ALPNs the framework
/// dispatches plus the built-in `nerw/rpc/2.0.0` so the endpoint
/// accepts every protocol nerw-rpc + nerw-core might negotiate.
fn make_test_config(tmp: &TempDir, label: &str) -> Result<(ClientConfig, PathBuf)> {
    let identity_path = tmp.path().join(format!("{label}.key"));
    let ca_pem = tmp.path().join(format!("{label}-ca.pem"));
    write_self_signed_ca(&ca_pem)?;
    let cfg = ClientConfig::builder()
        .with_identity_path(&identity_path)
        .with_ca_pem_path(&ca_pem)
        .with_relay_url("https://127.0.0.1:1/")
        .with_alpn(ALPN_NERW_RPC.to_vec())
        .with_alpn(ALPN_TOLKI_WIRE_PROTOCOL_2_0_0.to_vec())
        .with_alpn(ALPN_TOLKI_DATAGRAM_1_0_0.to_vec())
        .with_discovery(None)
        .build();
    Ok((cfg, identity_path))
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
/// it was registered under, so the version-resolution test can verify
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
/// instances. Returns the underlying transport handles plus the bravo
/// `Client` (so the caller can populate alpha's peer table с bravo's
/// address).
struct DuoFixture {
    alpha_transport: IrohTransportClient,
    bravo_transport: IrohTransportClient,
}

async fn build_duo(label_a: &str, label_b: &str) -> Result<(DuoFixture, TempDir, TempDir)> {
    let tmp_a = tempfile::tempdir().context("tempdir A")?;
    let tmp_b = tempfile::tempdir().context("tempdir B")?;
    let (cfg_a, _id_a) = make_test_config(&tmp_a, label_a)?;
    let (cfg_b, _id_b) = make_test_config(&tmp_b, label_b)?;
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

#[tokio::test]
async fn datagram_dispatch_roundtrip() -> Result<()> {
    let (fix, _tmp_a, _tmp_b) = build_duo("dg-alpha", "dg-bravo").await?;

    // Bravo: dispatcher с handler at token 42.
    let dispatcher = Arc::new(DatagramDispatcher::new());
    let received = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let notify = Arc::new(tokio::sync::Notify::new());
    let handler = Arc::new(RecordingDatagramHandler {
        received: Arc::clone(&received),
        notify: Arc::clone(&notify),
    });
    dispatcher.register(42, handler).expect("register");

    // Spawn а subscriber loop that reads from bravo's datagram broadcast
    // и dispatches к the table. Must subscribe BEFORE alpha sends so
    // the broadcast channel does not drop the frame.
    let bravo_inner = Arc::clone(fix.bravo_transport.inner());
    let dispatcher_loop = Arc::clone(&dispatcher);
    let mut rx = bravo_inner.subscribe_datagrams();
    let task = tokio::spawn(async move {
        // Read а handful of frames; tests stop the loop after the
        // first observed payload via the notify channel.
        while let Ok(frame) = rx.recv().await {
            let ctx = DatagramDispatcher::build_context(frame.from_peer);
            // Errors are логированы by the dispatcher; tests assert
            // via the recorded buffer.  frame.payload is already Bytes;
            // .clone() bumps the ref-count, no allocation.
            let _ = dispatcher_loop.dispatch(ctx, frame.payload.clone()).await;
        }
    });

    // Alpha: send а datagram с token prefix [42 | "RTP-FRAME"].
    // We use the nerw-core send_datagram surface; the "agent_name" is
    // the routing prefix at the nerw-mesh layer (8B BLAKE3) — distinct
    // from our application-level 1-byte token. We pick "bravo" as the
    // mesh-layer routing tag; both peers share а connection so the
    // datagram lands.
    let alpha_inner = Arc::clone(fix.alpha_transport.inner());
    let bravo_id = fix.bravo_transport.node_id();
    let mut payload = Vec::new();
    payload.push(42u8);
    payload.extend_from_slice(b"RTP-FRAME");

    // Datagrams require а pre-existing nerw-rpc connection to be cached
    // because nerw-core piggybacks on the ALPN_NERW_RPC connection.
    // Trigger one with а quick send_to_peer-equivalent: the simplest
    // way is к open а bidi (which fails because no handler registered
    // for ALPN_NERW_RPC custom ALPN, но the connection IS cached).
    // Actually nerw-core's send_datagram itself establishes the
    // connection if missing — see Client::get_or_connect_for_datagrams.
    // So we can just call it directly.
    timeout(
        Duration::from_secs(15),
        alpha_inner.send_datagram(&bravo_id, "bravo", &payload),
    )
    .await
    .context("send_datagram timed out")?
    .context("send_datagram errored")?;

    // Wait for the handler к observe the frame.
    timeout(Duration::from_secs(10), notify.notified())
        .await
        .context("handler never received the datagram within 10s")?;

    let recorded = received.lock().await;
    assert_eq!(recorded.len(), 1, "exactly one frame should have arrived");
    assert_eq!(
        recorded[0], b"RTP-FRAME",
        "handler must observe the payload AFTER the token byte",
    );
    drop(recorded);

    task.abort();
    Ok(())
}
