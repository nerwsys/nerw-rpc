#![allow(
    // Assertions in tests are explicit by design.
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::wildcard_enum_match_arm,
    clippy::default_numeric_fallback,
    clippy::arithmetic_side_effects,
    // `Err(_) => panic!("timed out")` is the canonical narrow assertion for
    // tokio::time::timeout in tests — the only error variant `timeout()`
    // produces is `Elapsed`, so the wildcard is a hard upper bound.
    clippy::match_wild_err_arm,
)]

//! Bidi streaming roundtrip tests (Phase 3, NRW-RPC-BIDI-STREAMING-001).
//!
//! Verify the `call_streaming` client + `StreamingMethodHandler` server
//! surface introduced in nerw-rpc 0.9.0:
//!
//! 1. Echo loop — N chunks in, same N chunks out, clean close.
//! 2. Server-side mid-stream error — 2 chunks then `Err`, stream closes.
//! 3. Client-side end signal — client drops sender, handler observes
//!    `None` on its requests stream.
//! 4. Backward compatibility — existing `RpcClient::call` against an
//!    existing `MethodHandler` keeps working (unary path unchanged).
//! 5. Unknown method — `call_streaming` against unregistered method
//!    surfaces `RpcError::UnknownMethod` cleanly.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{BoxStream, StreamExt};
use iroh::{EndpointAddr, SecretKey, TransportAddr};
use nerw_core::client::{Client, ClientConfig};
use nerw_rpc::{
    ALPN_NERW_DATAGRAM_1_0_0, ALPN_NERW_MESH_1_0_0, ALPN_NERW_RPC_1_0_0, IrohTransportClient,
    MethodHandler, MethodRegistry, RpcClient, RpcContext, RpcError, RpcResult, RpcServer,
    StreamingMethodHandler,
};
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Generate a self-signed cert and write it as PEM to `dest`.
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

fn make_test_config(tmp: &TempDir, label: &str) -> Result<(ClientConfig, PathBuf)> {
    let ca_pem = tmp.path().join(format!("{label}-ca.pem"));
    write_self_signed_ca(&ca_pem)?;
    let cfg = ClientConfig::builder()
        .with_secret_key(SecretKey::generate())
        .with_ca_pem_path(&ca_pem)
        .with_relay_url("https://127.0.0.1:1/")
        .with_alpn(ALPN_NERW_MESH_1_0_0.to_vec())
        .with_alpn(ALPN_NERW_RPC_1_0_0.to_vec())
        .with_alpn(ALPN_NERW_DATAGRAM_1_0_0.to_vec())
        .with_discovery(None)
        .build();
    Ok((cfg, ca_pem))
}

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

    let bravo_ip = first_ip_addr(bravo.endpoint())?;
    let bravo_addr = EndpointAddr::new(bravo.node_id()).with_ip_addr(bravo_ip);
    alpha.peer_table().insert(bravo_addr).await;

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

/// Echo streaming handler — for every inbound request chunk, emit the
/// same bytes back on the response side. Stream closes cleanly when
/// the client drops its sender (requests stream yields None).
struct EchoStreamingHandler;

#[async_trait]
impl StreamingMethodHandler for EchoStreamingHandler {
    async fn handle(
        &self,
        _ctx: RpcContext,
        mut requests: BoxStream<'static, RpcResult<Bytes>>,
        responses: mpsc::Sender<RpcResult<Bytes>>,
    ) -> RpcResult<()> {
        while let Some(req) = requests.next().await {
            let chunk = req?;
            if responses.send(Ok(chunk)).await.is_err() {
                // Receiver dropped — client is gone, end cleanly.
                break;
            }
        }
        Ok(())
    }
}

/// Handler that emits 2 chunks then a mid-stream error.
struct ErrAfterTwoHandler;

#[async_trait]
impl StreamingMethodHandler for ErrAfterTwoHandler {
    async fn handle(
        &self,
        _ctx: RpcContext,
        _requests: BoxStream<'static, RpcResult<Bytes>>,
        responses: mpsc::Sender<RpcResult<Bytes>>,
    ) -> RpcResult<()> {
        let _ = responses.send(Ok(Bytes::from_static(b"chunk-1"))).await;
        let _ = responses.send(Ok(Bytes::from_static(b"chunk-2"))).await;
        let _ = responses
            .send(Err(RpcError::Handler(
                "simulated mid-stream failure".to_owned().into(),
            )))
            .await;
        Ok(())
    }
}

/// Handler that records how many request chunks it saw and signals
/// observed-end via a oneshot.
struct CountingHandler {
    seen: Arc<std::sync::atomic::AtomicUsize>,
    end_signal: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl StreamingMethodHandler for CountingHandler {
    async fn handle(
        &self,
        _ctx: RpcContext,
        mut requests: BoxStream<'static, RpcResult<Bytes>>,
        _responses: mpsc::Sender<RpcResult<Bytes>>,
    ) -> RpcResult<()> {
        while let Some(req) = requests.next().await {
            let _chunk = req?;
            self.seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        // Request side ended — signal the test that the handler saw EOF.
        self.end_signal.notify_one();
        Ok(())
    }
}

/// Echo unary handler — used to verify backward compatibility.
struct EchoUnaryHandler;

#[async_trait]
impl MethodHandler for EchoUnaryHandler {
    async fn handle(&self, _ctx: RpcContext, request: Bytes) -> RpcResult<Bytes> {
        Ok(request)
    }
}

#[tokio::test]
async fn streaming_echo_roundtrips_n_messages() -> Result<()> {
    let (fix, _t1, _t2) = build_duo("se-echo-a", "se-echo-b").await?;

    let mut registry = MethodRegistry::new();
    registry.register_streaming("nerw:test@1.0.0/echo/loop", Arc::new(EchoStreamingHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let (tx, mut rx) = timeout(
        Duration::from_secs(15),
        client.call_streaming(&bravo_id, "nerw:test@1.0.0/echo/loop"),
    )
    .await
    .context("call_streaming timed out")?
    .context("call_streaming failed")?;

    // Send 5 chunks then drop the sender.
    for i in 1..=5_u8 {
        let payload = Bytes::from(format!("hello-{i}").into_bytes());
        tx.send(payload).await.context("send chunk")?;
    }
    drop(tx);

    // Collect responses with a per-frame timeout.
    let mut received = Vec::new();
    loop {
        match timeout(Duration::from_secs(15), rx.next()).await {
            Ok(Some(Ok(chunk))) => received.push(chunk),
            Ok(Some(Err(e))) => {
                panic!("unexpected mid-stream error: {e}");
            }
            Ok(None) => break,
            Err(_) => panic!("timed out waiting for response chunk"),
        }
    }

    assert_eq!(received.len(), 5, "must receive exactly 5 echoed chunks");
    for (i, chunk) in received.iter().enumerate() {
        let expected = format!("hello-{}", i + 1);
        assert_eq!(
            chunk.as_ref(),
            expected.as_bytes(),
            "chunk {i} content mismatch",
        );
    }
    Ok(())
}

#[tokio::test]
async fn streaming_mid_stream_server_error_propagates() -> Result<()> {
    let (fix, _t1, _t2) = build_duo("se-err-a", "se-err-b").await?;

    let mut registry = MethodRegistry::new();
    registry.register_streaming(
        "nerw:test@1.0.0/err/after-two",
        Arc::new(ErrAfterTwoHandler),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let (_tx, mut rx) = timeout(
        Duration::from_secs(15),
        client.call_streaming(&bravo_id, "nerw:test@1.0.0/err/after-two"),
    )
    .await
    .context("call_streaming timed out")?
    .context("call_streaming failed")?;

    // First two chunks succeed.
    let first = timeout(Duration::from_secs(15), rx.next())
        .await
        .context("chunk-1 timed out")?
        .context("rx ended before chunk-1")?
        .context("chunk-1 unexpectedly errored")?;
    assert_eq!(first.as_ref(), b"chunk-1");

    let second = timeout(Duration::from_secs(15), rx.next())
        .await
        .context("chunk-2 timed out")?
        .context("rx ended before chunk-2")?
        .context("chunk-2 unexpectedly errored")?;
    assert_eq!(second.as_ref(), b"chunk-2");

    // Third item is an error.
    let third = timeout(Duration::from_secs(15), rx.next())
        .await
        .context("error frame timed out")?
        .context("rx ended before error frame")?;
    match third {
        Err(RpcError::Handler(e)) => {
            let msg = format!("{e}");
            assert!(
                msg.contains("simulated mid-stream failure"),
                "handler-error message must propagate: got `{msg}`",
            );
        }
        Err(other) => panic!("expected RpcError::Handler, got {other:?}"),
        Ok(_) => panic!("expected error frame, got success chunk"),
    }

    // Stream must end after the terminal error.
    let after = timeout(Duration::from_secs(15), rx.next())
        .await
        .context("post-error timed out")?;
    assert!(after.is_none(), "stream must close after terminal error");
    Ok(())
}

#[tokio::test]
async fn streaming_client_drops_sender_signals_end() -> Result<()> {
    let (fix, _t1, _t2) = build_duo("se-end-a", "se-end-b").await?;

    let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let end_signal = Arc::new(tokio::sync::Notify::new());

    let mut registry = MethodRegistry::new();
    registry.register_streaming(
        "nerw:test@1.0.0/count/sink",
        Arc::new(CountingHandler {
            seen: Arc::clone(&seen),
            end_signal: Arc::clone(&end_signal),
        }),
    );
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let (tx, mut rx) = timeout(
        Duration::from_secs(15),
        client.call_streaming(&bravo_id, "nerw:test@1.0.0/count/sink"),
    )
    .await
    .context("call_streaming timed out")?
    .context("call_streaming failed")?;

    // Send 3 chunks and drop the sender.
    for i in 1..=3_u32 {
        tx.send(Bytes::from(format!("c{i}").into_bytes()))
            .await
            .context("send chunk")?;
    }
    drop(tx);

    // Handler must observe end-of-stream within a reasonable window.
    timeout(Duration::from_secs(15), end_signal.notified())
        .await
        .context("handler never observed request-end signal")?;
    assert_eq!(
        seen.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "handler must have seen all 3 request chunks before EOF",
    );

    // The server then closes the response side cleanly (Ok(())).
    let after = timeout(Duration::from_secs(15), rx.next())
        .await
        .context("response stream timed out after handler returned")?;
    assert!(
        after.is_none(),
        "response stream must close after handler returns Ok(())",
    );
    Ok(())
}

#[tokio::test]
async fn streaming_preserves_unary_path() -> Result<()> {
    // Regression: an existing unary `RpcClient::call` against a unary
    // `MethodHandler` MUST keep working unchanged on the same server
    // that also serves streaming methods.
    let (fix, _t1, _t2) = build_duo("se-back-a", "se-back-b").await?;

    let mut registry = MethodRegistry::new();
    registry.register("test:hello@1.0.0/test/echo", Arc::new(EchoUnaryHandler));
    registry.register_streaming("nerw:test@1.0.0/echo/loop", Arc::new(EchoStreamingHandler));
    let registry = Arc::new(registry);
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    // Unary path still works.
    let response = timeout(
        Duration::from_secs(15),
        client.call(
            &bravo_id,
            "test:hello@1.0.0/test/echo",
            Bytes::from_static(b"UNARY-PAYLOAD"),
        ),
    )
    .await
    .context("unary call timed out")?
    .context("unary call errored")?;
    assert_eq!(&response[..], b"UNARY-PAYLOAD");
    Ok(())
}

#[tokio::test]
async fn streaming_unknown_method_returns_clear_error() -> Result<()> {
    let (fix, _t1, _t2) = build_duo("se-unk-a", "se-unk-b").await?;

    // No streaming handler registered.
    let registry = Arc::new(MethodRegistry::new());
    let server = RpcServer::new(fix.bravo_transport.clone(), Arc::clone(&registry));
    server.serve().await.context("server.serve")?;

    let client = RpcClient::new(fix.alpha_transport.clone());
    let bravo_id = fix.bravo_transport.node_id();

    let result = timeout(
        Duration::from_secs(15),
        client.call_streaming(&bravo_id, "nerw:nope@1.0.0/iface/method"),
    )
    .await
    .context("call_streaming timed out")?;

    match result {
        Err(RpcError::UnknownMethod(name)) => {
            assert_eq!(name, "nerw:nope@1.0.0/iface/method");
        }
        Err(other) => panic!("expected RpcError::UnknownMethod, got {other:?}"),
        Ok(_) => panic!("expected error, got channels"),
    }
    Ok(())
}
