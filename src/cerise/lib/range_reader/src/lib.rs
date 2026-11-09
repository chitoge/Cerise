//! A transport-neutral contract for exact ranged file reads.
//!
//! An implementation returns the exact requested number of bytes or an error.
//! This is deliberately stricter than POSIX `pread`: a short read is reported
//! at the boundary where its path, offset, and requested length are known.

#![forbid(unsafe_code)]

use std::future::Future;
use std::io;

/// Reads byte ranges and file sizes.
///
/// The bound is `Send + Sync + 'static` and the futures are `Send` because
/// storage backends commonly retain readers across executor boundaries.
pub trait RangeReader: Send + Sync + 'static {
    /// Reads `len` bytes of `path` starting at `offset`.
    ///
    /// Returns exactly `len` bytes or an error. A file shorter than
    /// `offset + len` is an error, not a short read.
    fn read_range(
        &self,
        path: &str,
        offset: u64,
        len: u64,
    ) -> impl Future<Output = io::Result<Vec<u8>>> + Send;

    /// Returns the size of `path` in bytes.
    fn size_of(&self, path: &str) -> impl Future<Output = io::Result<u64>> + Send;
}

#[cfg(test)]
mod tests {
    use super::RangeReader;
    use std::future::Future;
    use std::io;

    struct Reader;

    impl RangeReader for Reader {
        fn read_range(
            &self,
            _path: &str,
            _offset: u64,
            _len: u64,
        ) -> impl Future<Output = io::Result<Vec<u8>>> + Send {
            std::future::ready(Ok(Vec::new()))
        }

        fn size_of(&self, _path: &str) -> impl Future<Output = io::Result<u64>> + Send {
            std::future::ready(Ok(0))
        }
    }

    fn accepts_reader<T: RangeReader>(_: &T) {}

    #[test]
    fn implementors_need_only_the_std_contract() {
        accepts_reader(&Reader);
    }
}
