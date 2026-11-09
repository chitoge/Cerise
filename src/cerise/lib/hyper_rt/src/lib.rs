// cerise-hyper-rt: the hyper 1.x runtime adapter that lets a hyper HTTP/2 server
// run directly on Fuchsia's `fuchsia_async` single-threaded executor over a
// `fuchsia_async::net::TcpStream`.
//
// hyper is runtime-agnostic: it never touches tokio/mio directly, it only calls
// through three tiny traits — `hyper::rt::Executor` (to spawn its per-connection
// background tasks), and `hyper::rt::{Read,Write}` (its own uninit-aware I/O
// traits, distinct from tokio's). This crate implements exactly those three over
// `fuchsia_async`, so the whole @grpc stack (which has tokio[io-util] ONLY — pure
// buffers, no mio; verified mio-count=0 on the fuchsia triple) needs no tokio
// reactor at all.
//
// The one concrete type that crosses the @crates/@grpc universe seam is
// `fuchsia_async::net::TcpStream`. That is safe: its
// `futures::io::{AsyncRead,AsyncWrite}` impls come from `@crates//:futures` (the
// same futures `fuchsia-async` itself is built against — see this crate's
// BUILD.bazel `@crates//:futures` dep), and no generic trait bound crosses the
// seam — `FasyncIo` only ever calls the concrete `TcpStream` poll methods and
// re-exposes them through hyper's OWN traits (from `@grpc//:hyper`).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::io::{AsyncRead, AsyncWrite};
use hyper::rt::{Executor, Read, ReadBufCursor, Write};

/// `hyper::rt::Executor` over `fuchsia_async::Task::local`.
///
/// hyper's HTTP/2 server spawns internal per-connection driver tasks through the
/// executor. `fuchsia_async::Task::local` matches the `LocalExecutor` /
/// single-threaded, `!Send` model the whole component uses (same model as
/// netstack3_probe), so no `Send` bound is required or imposed.
#[derive(Clone, Copy, Debug, Default)]
pub struct FasyncExec;

impl<Fut> Executor<Fut> for FasyncExec
where
    Fut: Future + 'static,
{
    fn execute(&self, fut: Fut) {
        // Discard the future's output (hyper's spawned tasks are `Future<Output=()>`
        // in practice; discarding keeps this generic over any output type) and
        // detach — the task lives for as long as it needs, owned by the executor.
        fuchsia_async::Task::local(async move {
            let _ = fut.await;
        })
        .detach();
    }
}

/// `hyper::rt::{Read,Write}` over `fuchsia_async::net::TcpStream`.
///
/// `TcpStream` is `Unpin`, so `FasyncIo` is `Unpin`, satisfying hyper's
/// `serve_connection` bound `io: Read + Write + Unpin + 'static`.
#[derive(Debug)]
pub struct FasyncIo(pub fuchsia_async::net::TcpStream);

impl FasyncIo {
    /// Wraps a connected `fuchsia_async::net::TcpStream` for use as hyper I/O.
    pub fn new(stream: fuchsia_async::net::TcpStream) -> Self {
        FasyncIo(stream)
    }
}

impl Read for FasyncIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        // hyper hands us a possibly-uninitialized cursor; `futures::io::AsyncRead`
        // wants an initialized `&mut [u8]`. Zero-initialize the uninit region, read
        // into it through the concrete TcpStream, then advance the cursor by exactly
        // the number of bytes the read reported. This is the standard uninit->init
        // bridge; the cost is one zeroing pass per read of the (bounded) buffer.
        let n = {
            // SAFETY: `as_mut()` yields the uninitialized destination region. We fully
            // initialize it (`slot.write(0)`) before forming a `&mut [u8]` view over
            // the same memory, so no uninitialized bytes are ever read.
            let dst = unsafe { buf.as_mut() };
            for slot in dst.iter_mut() {
                slot.write(0);
            }
            let view =
                unsafe { std::slice::from_raw_parts_mut(dst.as_mut_ptr().cast::<u8>(), dst.len()) };
            match Pin::new(&mut self.0).poll_read(cx, view) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(n)) => n,
            }
        };
        // SAFETY: `n` bytes at the front of the cursor's region were just initialized
        // by the read above.
        unsafe {
            buf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl Write for FasyncIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // hyper "shutdown" == close the write half; futures `poll_close` on the
        // TcpStream shuts down the write direction (SHUT_WR).
        Pin::new(&mut self.0).poll_close(cx)
    }
}
