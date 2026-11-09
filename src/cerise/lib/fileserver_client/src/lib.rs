//! A client for the Cerise file server's gRPC contract.
//!
//! The tree has had a file *server* since the gRPC stack landed, and no client
//! at all — the only thing that has ever driven it is a hand-rolled HTTP/2
//! speaker in the validation harness. This crate is the Rust client half, so a
//! component running on the target can be the one asking rather than the one
//! answering.
//!
//! # What it is for
//!
//! Reading a *range* of a large remote file without downloading the file. That
//! is what [`RangeReader`] names, and it is deliberately the whole of the
//! abstraction a consumer sees: a path, an offset, a length, and exactly that
//! many bytes back or an error. Everything gRPC — streams, chunk framing,
//! status codes — is behind it.
//!
//! # The three pieces
//!
//! * [`RangeAssembler`] — pure. Turns the `ReadChunk` sequence a `Read` streams
//!   back into one contiguous buffer, and refuses everything else. It has no
//!   dependency on gRPC, or on this crate's transport, and it is where the
//!   wire's failure modes are decided.
//! * [`SendRequestService`] — the two-line adapter that lets a `hyper` HTTP/2
//!   client connection be used as a `tower` service, which is the shape
//!   `tonic`'s generated client wants.
//! * [`FileServerHandle`] / [`serve`] — a `Send` request handle in front of a
//!   `!Send` driver task that owns the connection. See the note on `Send` in
//!   [`worker`], which is not a stylistic choice.
//!
//! # Exactness is the contract
//!
//! [`RangeReader::read_range`] returns exactly the requested number of bytes or
//! an error, never fewer. That is stricter than POSIX `pread` and stricter than
//! the server's own behaviour — the server clamps a read to the file's end and
//! streams what it has — and it is deliberate. A caller that slices fixed-size
//! records out of the result cannot express "I got 3.5 records"; if the short
//! read were passed through, the truncation would surface later as a
//! *misaligned* record rather than as a missing one, at a place with no way to
//! tell what went wrong. Reject it where it is still describable.

#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::io;

pub mod atomic_file;
pub mod transport;
pub mod worker;

#[cfg(test)]
mod worker_tests;

pub use atomic_file::AtomicFile;
pub use cerise_range_reader::RangeReader;
pub use transport::SendRequestService;
pub use worker::channel;
pub use worker::serve;
pub use worker::FileServerHandle;
pub use worker::MutationSourceFileServerHandle;
pub use worker::Request;
pub use worker::RequestClass;

/// The connection disappeared before the client received a reply.
///
/// This is kept as the source of the returned [`io::Error`] so a supervising
/// transport can distinguish a lost lease from an application status returned
/// by the server.
#[derive(Debug)]
pub struct TransportLost {
    detail: String,
}

impl TransportLost {
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for TransportLost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for TransportLost {}

/// A client-side RPC deadline elapsed without any server reply.
#[derive(Debug)]
pub struct ClientRpcTimeout {
    detail: String,
}

impl ClientRpcTimeout {
    pub(crate) fn new(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

impl fmt::Display for ClientRpcTimeout {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.detail)
    }
}

impl std::error::Error for ClientRpcTimeout {}

/// Returns whether an operation failed without receiving an authoritative
/// application reply from the file server.
pub fn is_transport_loss(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|source| source.is::<TransportLost>() || source.is::<ClientRpcTimeout>())
}

/// Maximum payload carried by one ranged file-service operation.
///
/// This is deliberately below both tonic's ordinary message ceiling and the
/// server's 16 MiB `Read` ceiling.  [`FileServerHandle`] transparently splits a
/// larger logical read at this boundary, while [`AtomicFile`] uses the same
/// boundary for writes.  Keeping the transport limit here prevents consumers
/// such as large Cryostore indexes from having to know a gRPC implementation
/// detail.
pub const FILESERVER_IO_CHUNK_BYTES: usize = 2 * 1024 * 1024;

/// One directory entry returned by [`FileServerHandle::list`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    pub name: String,
    /// Numeric `cerise.fileserver.v1.FileType`; kept transport-neutral here.
    pub kind: i32,
    pub size: u64,
}

/// Durable identity of one mutation-producing execution.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct MutationSourceIdentity {
    pub authority_domain_id: String,
    pub boot_id: u64,
    pub generation: u64,
    pub principal_id: String,
}

/// Durable lifecycle phase of a registered mutation source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationSourcePhase {
    Open,
    Draining,
    Drained,
    Retired,
}

/// Exact replay/query receipt for a registered mutation source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationSourceReceipt {
    pub source: MutationSourceIdentity,
    pub open_request_id: String,
    pub drain_request_id: String,
    pub phase: MutationSourcePhase,
    pub receipt_sha256: String,
    pub ledger_revision: u64,
    pub request_id: String,
    pub closed_generation_floor: u64,
}

/// Result of advancing the durable mutation-source compaction floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationSourceCompaction {
    pub authority_domain_id: String,
    pub closed_through_generation: u64,
    pub request_id: String,
    pub ledger_revision: u64,
}

/// Exact result of durably closing legacy mutation admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LegacyMutationSeal {
    pub request_id: String,
    pub ledger_revision: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StoreUsage {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub protected_reserve_bytes: u64,
    pub reserved_bytes: u64,
    pub image_bytes: u64,
    pub artifact_bytes: u64,
    pub spill_bytes: u64,
    pub control_bytes: u64,
    pub staging_bytes: u64,
    pub other_allocated_bytes: u64,
    pub image_push_capacity_bytes: u64,
}

/// Authoritative resumable offsets for one managed image import.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImageImportState {
    pub import_id: String,
    pub accepted_offset: u64,
    pub durable_offset: u64,
}

/// Immutable image identity returned only after FileServer verification and
/// publication have completed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedImageImport {
    pub path: String,
    pub sha256: String,
    pub encoded_bytes: u64,
    pub cryostore_root_hash: String,
    pub guest_disk_bytes: u64,
    pub format_version: u32,
}

/// Mutates files through the Cerise file server.
///
/// The server flushes the affected object and syncs Fxfs before each successful
/// mutation reply. Callers may therefore use the completion of one method as a
/// durability barrier before issuing the next ordered mutation.
pub trait FileMutator: Send + Sync + 'static {
    /// Writes all of `data` at `offset`.
    fn write_range(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Writes reconstructible staging bytes without a filesystem-wide sync.
    ///
    /// The default remains durable for stores without a separate lazy mode.
    /// Callers must not publish or report success until a later durable
    /// operation orders these bytes; [`AtomicFile`] uses its atomic rename as
    /// that publication barrier.
    fn write_range_lazy(
        &self,
        path: &str,
        offset: u64,
        data: Vec<u8>,
        create: bool,
        truncate: bool,
    ) -> impl Future<Output = io::Result<()>> + Send {
        self.write_range(path, offset, data, create, truncate)
    }

    /// Creates a directory, optionally including missing parents.
    fn mkdir(&self, path: &str, parents: bool) -> impl Future<Output = io::Result<()>> + Send;

    /// Atomically renames one path to another within the served filesystem.
    fn rename(&self, from: &str, to: &str) -> impl Future<Output = io::Result<()>> + Send;
}

/// A durable ranged file store.
///
/// Immutable page packs, mutable sparse heads, and small atomic metadata files
/// share this transport contract while retaining their format-specific
/// interfaces above it.
pub trait DurableFileStore: RangeReader + FileMutator {}

impl<T> DurableFileStore for T where T: RangeReader + FileMutator {}

/// Reassembles the chunks of one ranged read.
///
/// # Why it refuses so much
///
/// A `Read` reply is a stream of `(offset, data)` pairs and the server is free
/// to split it wherever it likes — a chunk boundary is not a record boundary,
/// not a page boundary, and not any boundary the caller chose. So the only
/// thing a consumer can rely on is the *concatenation*, and the only way to
/// know the concatenation is right is to check every chunk lands where the
/// previous one ended.
///
/// This rejects, as distinct errors:
///
/// * a chunk whose offset is not where the last one ended — which covers
///   reordering, a gap, an overlap, and a repeat, because all four present
///   identically at this boundary and none of them is recoverable;
/// * a chunk that would carry the total past the requested end;
/// * a stream that ends before the requested length, which is the shape a
///   truncated file, a truncated transfer, and a dropped connection all take.
///
/// It cannot detect a server that answers the right *shape* from the wrong
/// file, or one whose offsets are internally consistent but shifted as a whole:
/// the first chunk's offset is checked against the request, so a whole-stream
/// shift is caught, but content substitution is not visible here at all and has
/// to be caught by whatever verifies the bytes.
#[derive(Debug)]
pub struct RangeAssembler {
    start: u64,
    len: u64,
    buf: Vec<u8>,
}

impl RangeAssembler {
    /// Starts assembling the reply to `Read(offset = start, length = len)`.
    ///
    /// `len` bytes are reserved up front: the caller already committed to
    /// holding them, and growing incrementally would just make the peak worse.
    pub fn new(start: u64, len: u64) -> Self {
        RangeAssembler {
            start,
            len,
            buf: Vec::with_capacity(len.min(1 << 26) as usize),
        }
    }

    /// The absolute file offset the next chunk must carry.
    pub fn expected_offset(&self) -> u64 {
        self.start + self.buf.len() as u64
    }

    /// Accepts one `ReadChunk`.
    pub fn push(&mut self, offset: u64, data: &[u8]) -> io::Result<()> {
        let want = self.expected_offset();
        if offset != want {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "chunk at offset {offset} where {want} was due, {} of {} bytes in \
                     (a reordered, overlapping, repeated or gapped stream)",
                    self.buf.len(),
                    self.len
                ),
            ));
        }
        let have = self.buf.len() as u64;
        let after = have + data.len() as u64;
        if after > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "chunk at offset {offset} carries {} bytes, {} past the end of a \
                     {}-byte request",
                    data.len(),
                    after - self.len,
                    self.len
                ),
            ));
        }
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Ends the stream and yields the range.
    pub fn finish(self) -> io::Result<Vec<u8>> {
        if self.buf.len() as u64 != self.len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "stream ended after {} of {} bytes at offset {}",
                    self.buf.len(),
                    self.len,
                    self.start
                ),
            ));
        }
        Ok(self.buf)
    }
}

#[cfg(test)]
mod assembler_tests {
    use super::RangeAssembler;

    /// Bytes with a position-dependent value, so a shift by any amount shows up
    /// as a content mismatch rather than as an equal-looking buffer.
    fn pattern(from: u64, n: usize) -> Vec<u8> {
        (0..n)
            .map(|i| ((from as usize + i) * 37 + 11) as u8)
            .collect()
    }

    /// A1: chunk boundaries that fall nowhere in particular still reassemble
    /// byte-exactly. The sizes are chosen to straddle a 4096-byte page: one
    /// byte, one short of a page, one past a page, and a large tail.
    #[test]
    fn odd_chunk_boundaries_reassemble_exactly() {
        const START: u64 = 4096 * 7 + 13;
        let sizes = [1usize, 4095, 4097, 1, 100_000];
        let total: usize = sizes.iter().sum();
        let whole = pattern(START, total);

        let mut a = RangeAssembler::new(START, total as u64);
        let mut pos = 0usize;
        for s in sizes {
            a.push(START + pos as u64, &whole[pos..pos + s])
                .expect("in-order chunk");
            pos += s;
        }
        assert_eq!(a.finish().expect("complete stream"), whole);
    }

    /// An empty chunk at the right offset is a no-op, not an error. The server
    /// is allowed to send one and refusing would be a gratuitous failure.
    #[test]
    fn empty_chunk_is_accepted() {
        let mut a = RangeAssembler::new(0, 4);
        a.push(0, &[1, 2]).unwrap();
        a.push(2, &[]).unwrap();
        a.push(2, &[3, 4]).unwrap();
        assert_eq!(a.finish().unwrap(), vec![1, 2, 3, 4]);
    }

    /// A2: a chunk out of order is refused. Two chunks are sent in the wrong
    /// sequence; the second one names an offset the assembler is not at.
    #[test]
    fn out_of_order_chunk_is_refused() {
        let mut a = RangeAssembler::new(1000, 8);
        a.push(1000, &[0, 1, 2, 3]).expect("first chunk");
        let e = a
            .push(1000, &[4, 5, 6, 7])
            .expect_err("repeat must be refused");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("where 1004 was due"), "{e}");

        let mut a = RangeAssembler::new(1000, 8);
        let e = a
            .push(1004, &[4, 5, 6, 7])
            .expect_err("tail-first must be refused");
        assert!(e.to_string().contains("where 1000 was due"), "{e}");
    }

    /// A gap: the next chunk's offset is *ahead* of where the last one ended.
    ///
    /// Tested separately from reordering because the cheapest wrong assembler —
    /// one that only requires offsets to increase, then concatenates and checks
    /// the total — accepts this and would pass the reordering test. It cannot
    /// be caught by the total either, since the missing bytes make the stream
    /// end short only if the server is honest about the rest.
    #[test]
    fn a_forward_gap_is_refused() {
        let mut a = RangeAssembler::new(0, 12);
        a.push(0, &[0u8; 4]).expect("first chunk");
        let e = a.push(8, &[0u8; 4]).expect_err("a gap must be refused");
        assert!(e.to_string().contains("where 4 was due"), "{e}");
    }

    /// An overlap whose offset is nonetheless increasing — the other case the
    /// increasing-offsets-only assembler accepts.
    #[test]
    fn an_increasing_overlap_is_refused() {
        let mut a = RangeAssembler::new(0, 12);
        a.push(0, &[0u8; 8]).expect("first chunk");
        let e = a
            .push(4, &[0u8; 8])
            .expect_err("an overlap must be refused");
        assert!(e.to_string().contains("where 8 was due"), "{e}");
    }

    /// A whole-stream shift — every chunk self-consistent, all of them at the
    /// wrong place — is caught on the first chunk.
    #[test]
    fn shifted_stream_is_refused() {
        let mut a = RangeAssembler::new(4096, 8192);
        let e = a
            .push(0, &[0u8; 8192])
            .expect_err("a shifted stream must be refused");
        assert!(e.to_string().contains("where 4096 was due"), "{e}");
    }

    /// A3: a stream that stops early is an error, and specifically is not a
    /// short buffer. This is the shape of a truncated file and of a connection
    /// dropped mid-reply.
    #[test]
    fn truncated_stream_is_refused() {
        let mut a = RangeAssembler::new(0, 8192);
        a.push(0, &[7u8; 4096]).unwrap();
        let e = a.finish().expect_err("a short stream must be refused");
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(e.to_string().contains("after 4096 of 8192"), "{e}");
    }

    /// A stream that never delivers anything is the same error, not an empty
    /// success.
    #[test]
    fn empty_stream_is_refused() {
        let e = RangeAssembler::new(0, 4096)
            .finish()
            .expect_err("empty must be refused");
        assert_eq!(e.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    /// A zero-length request is the one case where an empty stream is correct.
    #[test]
    fn zero_length_request_completes_empty() {
        assert!(RangeAssembler::new(9, 0).finish().unwrap().is_empty());
    }

    /// A4: a chunk running past the requested end is refused rather than
    /// silently truncated to fit. Truncating to fit would turn a server that
    /// ignores `length` into a client that appears to work.
    #[test]
    fn overrunning_chunk_is_refused() {
        let mut a = RangeAssembler::new(0, 6);
        a.push(0, &[0u8; 4]).unwrap();
        let e = a.push(4, &[0u8; 4]).expect_err("overrun must be refused");
        assert_eq!(e.kind(), std::io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("2 past the end"), "{e}");
    }
}
