// Cerise gRPC gate — initial prototype de-risking spike for the top runtime risk.
//
// The ONE novel runtime unknown for the whole gRPC-on-Fuchsia stack is whether
// `fuchsia_async::net`'s ASYNC readiness path (EventedFd over fuchsia.posix.socket,
// driven by a LocalExecutor) actually accepts + echoes TCP on real netstack3 — only
// the BLOCKING std::net path was ever proven (netstack3_probe). This spike answers
// exactly that, and NOTHING else: it is deliberately hyper-free (no @grpc crates),
// so a compile hiccup in hyper cannot mask the runtime answer.
//
// It uses the shared Fuchsia network-bootstrap adapter for the proven interface
// lifecycle and deliberately requests its static 10.0.2.15/24 address. The ONLY
// component-specific change is the server half: instead of a blocking
// `std::net::TcpListener` accept loop, this uses `fuchsia_async::net::TcpListener::
// bind(...).accept_stream()` and reads/writes each connection through the futures
// AsyncRead/AsyncWrite path — called exactly the way service integration's hyper serve loop will,
// so a GREEN here transfers directly to the real server.
//
// If fasync async accept had misbehaved, the fallback is
// `std::net::TcpListener::from_std` + `fuchsia_async::net::TcpListener::from_std`;
// this spike is what decides fasync-vs-std and locks it in.

use anyhow::{Context, Result};
use cerise_network_bootstrap::BootstrapPolicy;
use cerise_network_bootstrap_fuchsia::{
    bootstrap, FuchsiaBootstrapConfig, InterfaceLifetime, Ipv4Configuration,
};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use futures::stream::StreamExt;

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

fn trace(stage: &str) {
    emit(&format!("CERISE-FASYNC-SPIKE-TRACE-{stage}\n"));
}

// --- interface bringup via the shared Fuchsia adapter -------------------------

async fn bring_up_interface() -> Result<InterfaceLifetime> {
    let result = bootstrap(
        FuchsiaBootstrapConfig {
            interface_name: "cerise-eth0",
            ipv4: Ipv4Configuration::Static {
                address: [10, 0, 2, 15],
                prefix_len: 24,
            },
            // Preserve the original 90 × 5s device-publication wait envelope.
            policy: BootstrapPolicy {
                discovery_attempts: 90,
                retry_delay_seconds: 5,
                reuse_existing_ipv4: false,
            },
            // This spike deliberately tests static address installation before Enable.
            enable_before_address: false,
            observe_slaac: false,
            install_default_route: false,
            check_socket_provider: true,
        },
        Some(trace),
    )
    .await?;
    result
        .lifetime
        .context("adapter unexpectedly reused an interface")
}

// --- the actual de-risk: fasync async TCP accept + echo --------------------------

/// Binds a fuchsia_async TCP listener and echoes each connection's bytes back.
/// This is the exact accept path the hyper server uses (accept_stream + the
/// futures AsyncRead/AsyncWrite the hyper::rt adapter forwards to).
async fn serve_fasync() -> Result<()> {
    let addr: std::net::SocketAddr = "0.0.0.0:50051".parse().unwrap();
    let listener = fuchsia_async::net::TcpListener::bind(&addr)
        .context("fuchsia_async::net::TcpListener::bind failed")?;
    emit("CERISE-FASYNC-SPIKE-LISTENING\n");

    let mut incoming = listener.accept_stream();
    while let Some(conn) = incoming.next().await {
        let (mut stream, _peer) = match conn {
            Ok(pair) => pair,
            Err(_) => continue,
        };
        trace("ACCEPTED");
        let mut buf = [0u8; 4096];
        let n = match stream.read(&mut buf).await {
            Ok(n) if n > 0 => n,
            _ => continue,
        };
        // Echo the received bytes back verbatim — the host Python client sends a
        // known payload and asserts it comes back, proving a full async
        // read->write round-trip over fasync::net on real netstack3.
        if stream.write_all(&buf[..n]).await.is_ok() {
            let _ = stream.flush().await;
            emit("CERISE-FASYNC-SPIKE-OK\n");
        }
    }
    Ok(())
}

#[fuchsia::main(logging_tags = ["fasync_tcp_spike"])]
async fn main() {
    emit("CERISE-FASYNC-SPIKE-START\n");
    let _network = match bring_up_interface().await {
        Ok(network) => network,
        Err(error) => {
            emit(&format!("CERISE-FASYNC-SPIKE-FAIL: bringup: {error:?}\n"));
            return;
        }
    };
    emit("CERISE-FASYNC-SPIKE-INTERFACE-UP\n");

    if let Err(e) = serve_fasync().await {
        emit(&format!("CERISE-FASYNC-SPIKE-FAIL: serve: {e:?}\n"));
    }
}
