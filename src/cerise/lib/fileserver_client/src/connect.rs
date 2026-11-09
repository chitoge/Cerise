//! Opening a file-server connection on the target.
//!
//! Split out of the transport-neutral crate next door because this is the one
//! piece that cannot exist anywhere else: it names `fuchsia_async::net` and the
//! `fuchsia_async` hyper adapter, so it is compiled for the target only. Its
//! caller gets the whole rest of the client — the request driver, the range
//! reassembly, the exactness contract — from a library that builds and is
//! tested on the host.
//!
//! # gRPC here is h2c, and that is the whole transport
//!
//! There is no TLS and no HTTP/1 upgrade: the server speaks HTTP/2 with prior
//! knowledge, which is what the file server's own listener does on the other
//! end. So a connection is a TCP socket, a `hyper` HTTP/2 handshake, and
//! nothing else.

#![forbid(unsafe_code)]

use std::io;

use cerise_fileserver_client::SendRequestService;
use cerise_hyper_rt::FasyncExec;
use cerise_hyper_rt::FasyncIo;
use fileserver_proto::cerise::fileserver::v1::file_server_client::FileServerClient;

/// Maximum wall time for opening the TCP socket and completing the HTTP/2
/// client handshake.
///
/// Callers commonly put their own retry policy around [`connect`]. Keeping one
/// attempt finite is what makes those retry counts a real readiness bound: a
/// peer that accepts TCP but never sends HTTP/2 settings must not retain the
/// caller forever.
pub const CONNECT_ATTEMPT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// A connected client, and the connection future that has to be driven for it
/// to answer anything.
pub type Connected = (
    FileServerClient<SendRequestService>,
    hyper::client::conn::http2::Connection<FasyncIo, tonic::body::BoxBody, FasyncExec>,
);

/// Connects to a file server at `addr`.
///
/// **The returned connection future is not spawned, deliberately.** Spawning it
/// here would make this function depend on an executor already being installed,
/// and would hide the single thing a caller must not forget. Returning it makes
/// "who drives this, and what happens when it ends" a decision at the call
/// site — which is where it belongs, because the caller is the one who knows
/// whether a dropped link should end the program or be retried.
///
/// The usual shape:
///
/// ```ignore
/// let (client, conn) = connect(addr).await?;
/// let (handle, rx) = cerise_fileserver_client::channel();
/// fuchsia_async::Task::local(async move {
///     let _ = futures::future::join(conn, cerise_fileserver_client::serve(client, rx)).await;
/// })
/// .detach();
/// ```
///
/// `handle` is `Send + Sync` and implements `RangeReader`; the client and the
/// connection are not, and never leave that task.
pub async fn connect(addr: std::net::SocketAddr) -> io::Result<Connected> {
    // `hyper::client::conn::http2::SendRequest` requires every request to
    // carry a Host/:authority value.  `FileServerClient::new` uses an empty
    // origin because it normally sits on top of tonic's transport `Channel`,
    // which adds that value itself.  This connector bypasses `Channel`, so it
    // must give the generated client the origin explicitly; otherwise h2
    // rejects the first stream with PROTOCOL_ERROR and tonic collapses the
    // useful server status into `Unknown: http2 error`.
    let origin: tonic::codegen::http::Uri = format!("http://{addr}")
        .parse()
        .map_err(|e| io::Error::other(format!("file-server origin for {addr}: {e}")))?;
    let attempt = async move {
        let stream = fuchsia_async::net::TcpStream::connect(addr)
            .map_err(|e| io::Error::other(format!("connect {addr}: {e}")))?
            .await
            .map_err(|e| io::Error::other(format!("connect {addr}: {e}")))?;
        let (sender, conn) =
            hyper::client::conn::http2::handshake(FasyncExec, FasyncIo::new(stream))
                .await
                .map_err(|e| io::Error::other(format!("HTTP/2 handshake with {addr}: {e}")))?;
        Ok((
            FileServerClient::with_origin(SendRequestService::new(sender), origin),
            conn,
        ))
    };
    let deadline = fuchsia_async::MonotonicInstant::after(CONNECT_ATTEMPT_TIMEOUT.into());
    fuchsia_async::TimeoutExt::on_timeout(async { Some(attempt.await) }, deadline, || None)
        .await
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "file-server TCP/HTTP2 connection to {addr} did not complete within {} seconds",
                    CONNECT_ATTEMPT_TIMEOUT.as_secs()
                ),
            )
        })?
}
