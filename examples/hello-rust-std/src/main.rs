//! make-or-break: a `std` Rust BINARY for x86_64-unknown-fuchsia, linked against
//! the ported musl libc.so and run under Cerise. Reaching main proves the
//! upstream Fuchsia `std` runtime (lang_start, the C-runtime handoff) works against
//! our libc. We use std facilities (Vec/format!) so it's genuinely std-linked, then
//! emit the marker via the vDSO's zx_debug_write (serial; needs no handle).
extern "C" {
    fn zx_debug_write(buffer: *const u8, len: usize) -> i32;
}

fn main() {
    // Exercise std (heap + formatting) so this is not secretly no_std.
    let v: Vec<u32> = (1..=3).collect();
    let s = format!("CERISE-RUST-STD-OK n={} sum={}\n", v.len(), v.iter().sum::<u32>());
    unsafe {
        zx_debug_write(s.as_ptr(), s.len());
    }
}
