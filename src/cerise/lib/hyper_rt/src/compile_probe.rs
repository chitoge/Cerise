// Compile-only proof for cerise-hyper-rt on x86_64-unknown-fuchsia.
//
// This binary never runs meaningfully; it exists so `bazel build` type-checks and
// links the adapter's trait impls for the fuchsia triple — the compile-time half
// of the stack's top risk. The `takes_*` helpers assert, at the type level, that
// `FasyncExec: hyper::rt::Executor<_>` and `FasyncIo: hyper::rt::Read + Write +
// Unpin` — exactly the bounds hyper's `http2::Builder::serve_connection` requires.

use cerise_hyper_rt::{FasyncExec, FasyncIo};

fn emit(msg: &str) {
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

fn takes_executor<E, F>(_exec: E)
where
    E: hyper::rt::Executor<F>,
    F: std::future::Future<Output = ()> + 'static,
{
}

fn takes_io<T>(_io: T)
where
    T: hyper::rt::Read + hyper::rt::Write + Unpin + 'static,
{
}

fn _assert_bounds(io: FasyncIo) {
    takes_executor::<FasyncExec, std::future::Ready<()>>(FasyncExec);
    takes_io(io);
}

fn main() {
    emit("CERISE-HYPER-RT-COMPILE-PROBE\n");
}
