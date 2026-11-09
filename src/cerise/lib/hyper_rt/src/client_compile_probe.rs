// Compile-only proof that hyper's HTTP/2 **client** composes over
// `cerise-hyper-rt` on x86_64-unknown-fuchsia.
//
// Why this exists as a second probe rather than a few lines in the first one.
// `compile_probe.rs` next door proves `FasyncExec: hyper::rt::Executor` and
// `FasyncIo: hyper::rt::Read + Write + Unpin` — the bounds hyper's HTTP/2
// **server** requires. That is not the same claim as this one. hyper's client
// half is a different module (`hyper::client::conn::http2`), reached through a
// different cargo feature (`client`), and it pulls its own `SendRequest` /
// `Connection` machinery. Whether *that* code path builds for the fuchsia
// triple was recorded as an open risk, and "the server works" is not evidence
// about it.
//
// This binary never runs meaningfully. `bazel build` of the fuchsia_stripped
// output is the result: it type-checks and links `handshake`'s bounds and
// monomorphizes `Connection<FasyncIo, Empty<Bytes>, FasyncExec>` for the
// target.
//
// It is deliberately written against the *real* entry point rather than a
// hand-declared bound. A `takes_client_io<T: Read + Write + Unpin>` helper
// would prove the traits are implemented and prove nothing about whether
// `http2::handshake` accepts them — that function has its own bound set
// (including the executor's `Send`-ness and the body type) and it is the one a
// `GrpcPageSource` would call.

use bytes::Bytes;
use cerise_hyper_rt::{FasyncExec, FasyncIo};
use http_body_util::Empty;

fn emit(msg: &str) {
    // SAFETY: a syscall taking a pointer/length pair that describes `msg`.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Names the exact type `hyper::client::conn::http2::handshake` returns for
/// this runtime, which forces the whole client connection type to be
/// instantiated for the fuchsia triple.
type ClientHandshake = std::pin::Pin<
    Box<
        dyn std::future::Future<
            Output = Result<
                (
                    hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
                    hyper::client::conn::http2::Connection<FasyncIo, Empty<Bytes>, FasyncExec>,
                ),
                hyper::Error,
            >,
        >,
    >,
>;

/// Never called. Its body is the proof.
#[allow(dead_code)]
fn _assert_client_handshake(io: FasyncIo) -> ClientHandshake {
    Box::pin(hyper::client::conn::http2::handshake(FasyncExec, io))
}

/// The other half a gRPC client needs: that a request can be *sent* on the
/// resulting `SendRequest`, with the `http` request type tonic builds.
#[allow(dead_code)]
async fn _assert_send_request(
    mut sender: hyper::client::conn::http2::SendRequest<Empty<Bytes>>,
) -> Result<hyper::Response<hyper::body::Incoming>, hyper::Error> {
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri("/cerise.fileserver.v1.FileServer/Read")
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(Empty::<Bytes>::new())
        .expect("static request parts are valid");
    sender.send_request(req).await
}

fn main() {
    emit("CERISE-HYPER-CLIENT-COMPILE-PROBE\n");
}
