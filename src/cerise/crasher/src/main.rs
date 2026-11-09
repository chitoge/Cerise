//! Cerise crasher (post-mortem gate fixture): a component that deliberately
//! dereferences a null pointer so the kernel raises a fatal-page-fault exception.
//! With no closer handler installed, the exception propagates to the root job's
//! channel, where //src/cerise/crash_handler observes it, logs it, and emits
//! symbolizer markup. It is `lazy` in the realm and launched (via its framework
//! Binder) only AFTER crash_handler has attached to the root-job channel.
//!
//! The fault happens inside a named `#[inline(never)]` function so the fault PC
//! symbolizes to a real crasher frame — the exact thing //validation:crash-handler-boot
//! pipes through //src/cerise/tools/symbolize and asserts.

/// Write straight to the kernel debuglog (surfaced on serial) — no LogSink.
fn emit(msg: &str) {
    // SAFETY: zx_debug_write takes (ptr,len) of readable bytes; msg is a live &str.
    unsafe {
        zx::sys::zx_debug_write(msg.as_ptr(), msg.len());
    }
}

/// Dereference a null pointer. `#[inline(never)]` + a distinctive name so the
/// fault PC resolves to `crasher::trigger_null_deref` in the symbolized backtrace.
#[inline(never)]
fn trigger_null_deref() -> u64 {
    let p: *const u64 = std::ptr::null();
    // Volatile read of address 0 -> fatal page fault (not optimized away).
    unsafe { std::ptr::read_volatile(p) }
}

fn main() {
    emit("CERISE-CRASHER-START: dereferencing a null pointer\n");
    let v = trigger_null_deref();
    // Unreachable: the read above faults. Use the value so nothing is elided.
    emit(&format!("CERISE-CRASHER-UNREACHABLE: {v}\n"));
}
