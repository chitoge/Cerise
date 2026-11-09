//! crate_universe probe: prove a third-party Rust crate from the vendored
//! closure compiles for the x86_64-unknown-fuchsia target. Uses arrayvec (a
//! no_std crate netstack3-core depends on) under #![no_std].
#![no_std]

use arrayvec::ArrayVec;

/// Sums up to 8 values using a no_std fixed-capacity vector from arrayvec.
pub fn small_sum(vals: &[u32]) -> u32 {
    let mut v: ArrayVec<u32, 8> = ArrayVec::new();
    for &x in vals.iter().take(8) {
        v.push(x);
    }
    v.iter().copied().sum()
}
