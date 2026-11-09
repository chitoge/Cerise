// Real task_exceptions for Cerise (no longer a stub).
//
// Binds a zircon exception channel to a task (the component job) and exposes incoming
// exceptions as an async Stream, so elf_runner's crash_handler actually observes component
// process crashes. The previous stub registered successfully but its stream was Pending
// forever, silently swallowing every crash.
//
// Faithful to upstream src/sys/lib/task-exceptions: create_exception_channel() ->
// fasync::Channel -> poll recv -> yield the exception handle (and its process/thread).
use fuchsia_async as fasync;
use futures::stream::Stream;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

/// One delivered exception. `exception_handle` must be dropped (after optionally setting
/// its state) to let zircon continue processing the exception.
pub struct ExceptionInfo {
    pub process: zx::Process,
    pub thread: zx::Thread,
    pub exception_handle: zx::Exception,
}

/// Layout of the bytes zircon writes to the exception channel alongside the handle. We
/// don't read them (process/thread come from the handle), but the receive buffer must be
/// sized to accept them.
#[repr(C)]
struct ZxExceptionInfo {
    pid: zx::sys::zx_koid_t,
    tid: zx::sys::zx_koid_t,
    type_: u32,
    padding1: [u8; 4],
}

/// A stream of exceptions delivered to a task's exception channel.
pub struct ExceptionsStream {
    inner: fasync::Channel,
    is_terminated: bool,
}

impl ExceptionsStream {
    /// Create an exception channel on `task` and stream its exceptions.
    pub fn register_with_task<T: zx::Task>(task: &T) -> Result<Self, zx::Status> {
        Ok(Self {
            inner: fasync::Channel::from_channel(task.create_exception_channel()?),
            is_terminated: false,
        })
    }
}

impl Stream for ExceptionsStream {
    type Item = Result<ExceptionInfo, zx::Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        if this.is_terminated {
            return Poll::Ready(None);
        }
        let mut msg_buf = zx::MessageBuf::new();
        msg_buf.ensure_capacity_bytes(mem::size_of::<ZxExceptionInfo>());
        msg_buf.ensure_capacity_handles(1);
        match this.inner.recv_from(cx, &mut msg_buf) {
            Poll::Pending => Poll::Pending,
            // Channel closed: the task is gone. End the stream.
            Poll::Ready(Err(zx::Status::PEER_CLOSED)) => {
                this.is_terminated = true;
                Poll::Ready(None)
            }
            Poll::Ready(Err(status)) => {
                this.is_terminated = true;
                Poll::Ready(Some(Err(status)))
            }
            Poll::Ready(Ok(())) => {
                let Some(handle) = msg_buf.take_handle(0) else {
                    return Poll::Ready(Some(Err(zx::Status::BAD_HANDLE)));
                };
                let exception_handle = zx::Exception::from(handle);
                let process = match exception_handle.get_process() {
                    Ok(p) => p,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                };
                let thread = match exception_handle.get_thread() {
                    Ok(t) => t,
                    Err(e) => return Poll::Ready(Some(Err(e))),
                };
                Poll::Ready(Some(Ok(ExceptionInfo { process, thread, exception_handle })))
            }
        }
    }
}
