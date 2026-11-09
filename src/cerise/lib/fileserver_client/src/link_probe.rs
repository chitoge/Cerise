// Build-and-link proof that the whole file-server client path exists for
// x86_64-unknown-fuchsia.
//
// What this adds over `//src/cerise/lib/hyper_rt:hyper_client_compile_probe`.
// That probe proves `hyper::client::conn::http2::handshake` accepts the
// fuchsia_async adapter, with `Empty<Bytes>` as the body. It never mentions
// tonic. The open question it leaves — ranked as the single build unknown on
// the way to a client-side page fetcher — is whether *tonic's client* works
// here: it is a different module from the server's, the @grpc universe builds
// tonic with `default-features = false, features = ["codegen", "prost"]` (no
// `transport`, no `channel`), and the codegen runs with `no_transport`, which
// drops the `connect()` helper. Whether what remains is a usable client is not
// something the hyper probe can answer.
//
// So this one instantiates the real thing: the generated `FileServerClient`
// over `SendRequestService` over a real `hyper` HTTP/2 connection over a real
// `fuchsia_async::net::TcpStream`, and calls the `RangeReader` methods a
// consumer actually calls. `bazel build` of the stripped fuchsia output is the
// result.
//
// It is safe to stage anywhere and is staged nowhere: with no argument it
// prints its marker and exits.

use std::io;

use cerise_range_reader::RangeReader;
use cerise_fileserver_connect::connect;

fn emit(msg: &str) {
    // SAFETY: a syscall taking a pointer/length pair that describes `msg`.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Never reached at run time. Its body is the proof: it names every type on the
/// route from a socket to a range of bytes.
async fn assert_end_to_end(addr: std::net::SocketAddr) -> io::Result<Vec<u8>> {
    let (client, conn) = connect(addr).await?;
    let (handle, rx) = cerise_fileserver_client::channel();
    // The driver owns both `!Send` halves — the hyper connection and the tonic
    // client — and never lets either escape onto a caller's future.
    fuchsia_async::Task::local(async move {
        let _ = futures::future::join(conn, cerise_fileserver_client::serve(client, rx)).await;
    })
    .detach();
    let size = handle.size_of("images/guest.img").await?;
    handle.read_range("images/guest.img", 0, size.min(4096)).await
}

fn main() {
    emit("CERISE-FILESERVER-CLIENT-LINK-PROBE\n");
    // Reached through a condition the compiler cannot fold away, so the path
    // above is code-generated and *linked* rather than merely type-checked. A
    // dead private function proves the bounds resolve; it does not prove the
    // symbols exist for this triple, and "it links" is the claim this binary is
    // here to make.
    if zx::MonotonicInstant::get().into_nanos() == i64::MIN {
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], 50051));
        let mut exec = fuchsia_async::LocalExecutor::default();
        let _ = exec.run_singlethreaded(assert_end_to_end(addr));
    }
}
