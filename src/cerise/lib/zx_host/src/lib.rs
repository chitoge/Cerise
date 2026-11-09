// Copyright 2026 The Cerise Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Host-portable emulated `zx` crate for Cerise unit tests.
//!
//! The real `//src/upstream/fuchsia/sdk/rust/zx:zx` crate is Fuchsia-target
//! only: `zx-sys` gates its entire syscall `extern "C"` block on
//! `#[cfg(target_os = "fuchsia")]`, so a host/Linux compile of `zx` fails with
//! "cannot find function `zx_*` in module `sys`". That blocks host unit tests
//! for every crate that touches `zx` (vfs, fs_management, block_*, key-bag,
//! zxcrypt, socket_parsing, ...), even when the test itself only exercises
//! portable handle operations.
//!
//! This crate is a drop-in `zx`-shaped surface for the host/exec platform. It
//! is `crate_name = "zx"` and is swapped in for the real crate via a
//! `select()` on `@platforms//os:fuchsia` in each consumer's `deps`. The
//! design principle is **one handle
//! table**: rather than standing up a parallel emulator, the handle-bearing
//! types (`Channel`, `Socket`, `Event`, `Handle`, ...) are re-exported
//! straight from `fuchsia-async`'s existing `emulated_handle` backend
//! (`src/lib/fuchsia-async/src/handle/emulated/`). Because `fuchsia_async` and
//! `fidl` already use that same backend on host, a `zx::Channel`/`zx::Socket`
//! created here has the *same identity* as one flowing through
//! `fuchsia_async::Channel::from_channel(..)` or a `fidl` round-trip — handle
//! identity holds across `zx` <-> `fuchsia_async` <-> `fidl`.
//!
//! Scope: only the surface the host-runnable tests need. `Status` (via
//! `zx_status`), the emulated handle vocabulary, `cprng_draw`, and
//! `system_get_page_size`. Fuchsia-only objects with no reasonable userspace
//! emulation (FIFO with the block protocol, real handle transfer semantics)
//! are intentionally absent; crates needing them stay on-target-only.

// The emulated backend already implements the portable handle vocabulary that
// `fidl`/`fuchsia_async` share on host: Channel, Socket, Event, EventPair,
// Handle, HandleRef, Rights, Signals, ObjectType, Koid, AsHandleRef, Peered,
// MessageBuf(Etc), HandleDisposition/Info/Op, SocketOpts, and the raw
// `zx_handle_t` alias. Re-exporting them (rather than re-wrapping) is what
// keeps handle identity intact.
pub use fuchsia_async::emulated_handle::*;

// `Status` and the `ZX_ERR_*`/`Status::*` constants are already host-portable
// (pure Rust, no syscalls) and live in their own crates, exactly as the real
// `zx` crate re-exports them.
pub use zx_status::*;
pub use zx_status_ext::*;

/// Raw syscall-level type/constant surface, mirroring `zx::sys`. `zx-sys`
/// itself compiles for host (only its `extern` block is Fuchsia-gated), so its
/// type/constant re-exports from `zx-types` are available here.
pub mod sys {
    pub use zx_sys::*;
}

/// Prelude containing common utility traits, mirroring `zx::prelude`.
pub mod prelude {
    pub use crate::{AsHandleRef, Peered};
}

/// Fills `buffer` with cryptographically secure random bytes.
///
/// Host stand-in for `zx_cprng_draw`. Backed by the OS CSPRNG via `rand`
/// (`rand::rng()` is seeded from the operating system). Semantically
/// equivalent for tests: distinct, unpredictable bytes.
pub fn cprng_draw(buffer: &mut [u8]) {
    use rand::RngCore;
    rand::rng().fill_bytes(buffer);
}

/// Fills `buffer` (possibly uninitialized) with secure random bytes and
/// returns the now-initialized slice. Host stand-in for
/// `zx_cprng_draw` over a `MaybeUninit` buffer.
pub fn cprng_draw_uninit(buffer: &mut [std::mem::MaybeUninit<u8>]) -> &mut [u8] {
    use rand::RngCore;
    // SAFETY: we are about to fully initialize every byte before returning a
    // reference that treats them as initialized.
    let init: &mut [u8] = unsafe {
        std::slice::from_raw_parts_mut(buffer.as_mut_ptr() as *mut u8, buffer.len())
    };
    rand::rng().fill_bytes(init);
    init
}

/// Returns the system page size in bytes. Host stand-in for
/// `zx_system_get_page_size`; the emulated environment uses a conventional 4K
/// page.
pub fn system_get_page_size() -> u32 {
    4096
}
