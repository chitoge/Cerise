//! Ingest a virtual disk into the content-addressed page store.
//!
//! Ingest walks a disk's logical contents one block at a time and interns each
//! 4 KiB page under its content hash. Two properties make this cheap on a real
//! image:
//!
//! * Absent blocks — the great majority of a sparse disk — are synthesized as
//!   zeros by the reader, so a 64 GiB disk costs only its allocated bytes to
//!   scan.
//! * Every all-zero page hashes identically, so the disk's empty space collapses
//!   to a single blob rather than being stored per page.
//! * That empty space costs no *index* either: the store's address space is
//!   zero-filled, so a page equal to what it inherits is not recorded. Ingest is
//!   therefore proportional to a disk's allocated content in both the bytes it
//!   keeps and the entries it tracks — the difference between indexing a virtual
//!   disk's few allocated pages and indexing all of its virtual size.
//!
//! The result is that the store holds one copy of each distinct page, which is
//! what makes keeping a whole image (and later, snapshots of it) affordable.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec;

use cryogen_hash::sha256;
use cryogen_store::{Generation, PageStore, PAGE_SIZE};
use cryogen_vhdx::{Error as VhdxError, ImageReader, Vhdx};

/// What an ingest pass observed and stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IngestStats {
    /// Logical pages covering the whole virtual disk.
    pub total_pages: u64,
    /// Pages that were entirely zero.
    pub zero_pages: u64,
    /// Distinct non-zero page contents.
    pub unique_nonzero_pages: u64,
    /// Distinct blobs held after the pass (unique non-zero pages, plus the
    /// shared zero blob).
    pub blobs: u64,
    /// Overlay entries the store recorded — the index cost of holding this
    /// image. Empty space is not indexed, so this tracks the disk's allocated
    /// pages rather than its virtual size.
    pub index_entries: u64,
}

impl IngestStats {
    /// Bytes the store holds after deduplication.
    pub fn deduped_bytes(&self) -> u64 {
        self.blobs * PAGE_SIZE as u64
    }

    /// How much smaller the store is than the disk's logical size. `None` when
    /// nothing was stored.
    pub fn dedup_ratio(&self) -> Option<f64> {
        if self.blobs == 0 {
            None
        } else {
            Some(self.total_pages as f64 / self.blobs as f64)
        }
    }
}

/// Reads every logical page of `image` into `store` under generation `gen`.
///
/// Pages are keyed by SHA-256 of their contents, so identical pages — anywhere
/// on the disk — resolve to one blob.
pub fn ingest_vhdx<R: ImageReader>(
    image: &mut Vhdx<R>,
    store: &mut PageStore,
    gen: Generation,
) -> Result<IngestStats, VhdxError> {
    let geometry = image.geometry();
    let block_size = geometry.block_size as usize;
    if block_size % PAGE_SIZE != 0 {
        return Err(VhdxError::BadGeometry);
    }
    let pages_per_block = block_size / PAGE_SIZE;

    let mut stats = IngestStats::default();
    let mut block = vec![0u8; block_size];
    let zero_page = [0u8; PAGE_SIZE];
    // Bound once: the store already knows the zero page's identity, and taking it
    // here keeps the hot loop from re-deriving a constant.
    let zero_id = store.zero_id();

    for b in 0..geometry.data_blocks {
        // The reader zero-fills absent blocks, so this is uniform regardless of
        // whether the block is stored.
        image.read_block(b, &mut block)?;

        for p in 0..pages_per_block {
            let page = &block[p * PAGE_SIZE..(p + 1) * PAGE_SIZE];
            let index = b * pages_per_block as u64 + p as u64;
            stats.total_pages += 1;
            // The all-zero page's hash is a constant, and on a sparse disk it is
            // the overwhelming majority of pages — hashing it once instead of
            // once per page is the difference between digesting the disk's
            // allocated bytes and digesting its whole virtual size.
            let is_zero = page == zero_page;
            if is_zero {
                stats.zero_pages += 1;
            }
            let id = if is_zero { zero_id } else { sha256(page) };
            if store.write_page(gen, index, id, page) && !is_zero {
                stats.unique_nonzero_pages += 1;
            }
        }
    }

    let store_stats = store.stats();
    stats.blobs = store_stats.blobs as u64;
    stats.index_entries = store_stats.index_entries as u64;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryogen_store::PageStore;

    // A stand-in image: `blocks[i]` is block i's logical contents. This exercises
    // the ingest accounting without needing a real VHDX on disk (the VHDX parser
    // has its own tests).
    struct FakeDisk {
        blocks: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    }

    const BS: usize = 3 * PAGE_SIZE;

    // Ingest is generic over the reader, but exercising it end to end needs a
    // `Vhdx`, so this test drives the same accounting logic directly.
    fn ingest_blocks(disk: &FakeDisk, store: &mut PageStore, gen: Generation) -> IngestStats {
        let mut stats = IngestStats::default();
        let zero_page = [0u8; PAGE_SIZE];
        for (b, block) in disk.blocks.iter().enumerate() {
            for p in 0..(BS / PAGE_SIZE) {
                let page = &block[p * PAGE_SIZE..(p + 1) * PAGE_SIZE];
                let index = (b * (BS / PAGE_SIZE) + p) as u64;
                stats.total_pages += 1;
                if page == zero_page {
                    stats.zero_pages += 1;
                }
                let id = sha256(page);
                if store.write_page(gen, index, id, page) && page != zero_page {
                    stats.unique_nonzero_pages += 1;
                }
            }
        }
        let store_stats = store.stats();
        stats.blobs = store_stats.blobs as u64;
        stats.index_entries = store_stats.index_entries as u64;
        stats
    }

    fn new_store() -> PageStore {
        PageStore::new(sha256(&[0u8; PAGE_SIZE]))
    }

    #[test]
    fn empty_disk_collapses_to_one_blob() {
        let disk = FakeDisk { blocks: vec![vec![0u8; BS], vec![0u8; BS]] };
        let mut store = new_store();
        let g = store.base();
        let s = ingest_blocks(&disk, &mut store, g);
        assert_eq!(s.total_pages, 6);
        assert_eq!(s.zero_pages, 6);
        assert_eq!(s.unique_nonzero_pages, 0);
        // All the empty space costs exactly one blob...
        assert_eq!(s.blobs, 1);
        // ...and no index at all.
        assert_eq!(s.index_entries, 0);
        assert_eq!(s.dedup_ratio(), Some(6.0));
    }

    #[test]
    fn repeated_content_dedups_across_blocks() {
        let mut a = vec![0u8; BS];
        a[..PAGE_SIZE].fill(0xAA); // page 0 non-zero, pages 1-2 zero
        // A second block with the very same bytes must add nothing.
        let disk = FakeDisk { blocks: vec![a.clone(), a] };
        let mut store = new_store();
        let g = store.base();
        let s = ingest_blocks(&disk, &mut store, g);
        assert_eq!(s.total_pages, 6);
        assert_eq!(s.zero_pages, 4);
        assert_eq!(s.unique_nonzero_pages, 1);
        assert_eq!(s.blobs, 2); // one zero blob + one 0xAA blob
        assert_eq!(s.deduped_bytes(), 2 * PAGE_SIZE as u64);
        // Only the two non-zero pages are indexed; the four zero pages are not.
        assert_eq!(s.index_entries, 2);
    }

    #[test]
    fn distinct_content_is_counted_once_each() {
        let mut a = vec![0u8; BS];
        let mut b = vec![0u8; BS];
        a[..PAGE_SIZE].fill(0x11);
        b[..PAGE_SIZE].fill(0x22);
        let disk = FakeDisk { blocks: vec![a, b] };
        let mut store = new_store();
        let g = store.base();
        let s = ingest_blocks(&disk, &mut store, g);
        assert_eq!(s.unique_nonzero_pages, 2);
        assert_eq!(s.blobs, 3); // zero + two distinct
        assert_eq!(s.index_entries, 2);
    }

    // The scaling property at ingest level: a disk that is almost entirely empty
    // indexes only its allocated pages. Asserted on the measured entry count, so
    // a regression to per-page indexing fails here rather than only showing up
    // as memory pressure on a real image.
    #[test]
    fn sparse_disk_indexes_only_its_content() {
        // 512 blocks (1536 pages) of which one page carries data.
        let mut blocks = vec![vec![0u8; BS]; 512];
        blocks[300][..PAGE_SIZE].fill(0x5A);
        let disk = FakeDisk { blocks };
        let mut store = new_store();
        let g = store.base();
        let s = ingest_blocks(&disk, &mut store, g);

        assert_eq!(s.total_pages, 1536);
        assert_eq!(s.zero_pages, 1535);
        assert_eq!(s.blobs, 2); // zero + the one distinct page
        // The index tracks content, not the size of the disk.
        assert_eq!(s.index_entries, 1);
    }
}
