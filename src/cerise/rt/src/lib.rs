//! Cerise userland runtime crate.
//!
//! Provides the three primitives every Cerise Rust binary needs:
//! - `#[panic_handler]`  — writes to debuglog, exits with code 1
//! - `#[global_allocator]` — page-granularity VMO allocator
//! - `_start`            — ELF entry point; calls `cerise_main()`
//!
//! All syscall bindings are raw `extern "C"` vDSO declarations (no libc).
#![no_std]

pub mod zx;

mod panic;
mod alloc;
mod entry;

/// Write bytes to the kernel debuglog.  Callable from binary crates.
pub fn debug_write(msg: &[u8]) {
    zx::debug_write(msg.as_ptr(), msg.len());
}
