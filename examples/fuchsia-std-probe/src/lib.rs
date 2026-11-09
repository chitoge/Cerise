//! probe: prove the upstream `x86_64-unknown-fuchsia` Rust
//! `std` target compiles in our hermetic rules_rust setup, ahead of the
//! libc/sysroot port. Deliberately uses `std`-only facilities (heap
//! collections, formatting) so a successful build means `std` is present and
//! usable for the Fuchsia target. This is the compile-half signal only —
//! linking/running a Fuchsia binary needs the ported musl + `-lzircon -lfdio`
//! sysroot and is validated then.

/// Uses std `Vec`, iterators, and `String` formatting — none available under
/// `#![no_std]`. Compiling this for x86_64-unknown-fuchsia exercises std.
pub fn summarize(values: &[u32]) -> String {
    let mut buf: Vec<u32> = Vec::with_capacity(values.len());
    buf.extend_from_slice(values);
    let total: u32 = buf.iter().copied().sum();
    format!("n={} sum={}", buf.len(), total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums() {
        assert_eq!(summarize(&[1, 2, 3]), "n=3 sum=6");
    }
}
