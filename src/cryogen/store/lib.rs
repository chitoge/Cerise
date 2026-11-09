//! cryogen page store: content-addressed 4 KiB page blobs with copy-on-write
//! snapshot generations.
//!
//! A guest's memory or disk is a sequence of fixed-size pages. Each distinct
//! page's bytes are stored once, keyed by a content hash (`BlobId`); identical
//! pages — very common in disk images, where most pages are zero — collapse to
//! a single blob. A *generation* is a snapshot: a parent link plus an overlay
//! recording only the pages that changed relative to the parent, so taking a
//! snapshot is O(1) and it costs only its diverging pages.
//!
//! # The address space is zero-filled
//!
//! A page that no generation on the chain records reads as the all-zero page.
//! This mirrors the thing being modelled — unallocated disk and untouched guest
//! RAM both read as zeros — and it is what keeps the *index* small: a sparse
//! disk's empty space costs no index entries at all, not merely one shared blob.
//!
//! The invariant that follows, and which every write upholds:
//!
//! > A generation's overlay contains an entry for a page **only if** that page
//! > differs from what the generation's parent chain already yields.
//!
//! So absence is never ambiguous: it means "identical to what I inherit", and at
//! the bottom of the chain what is inherited is zero. Note the consequence for
//! writes — storing a *zero* page is not automatically free. A child that zeroes
//! a page its parent wrote must record that explicitly, because absence there
//! would wrongly inherit the parent's content. The rule is not "skip zero
//! writes" but "skip writes that match the inherited value", which degenerates
//! to the former only at the bottom of the chain.
//!
//! The store is hash-agnostic: callers supply the `BlobId` (e.g. Blake3 or
//! SHA-256 of the page bytes), including the identity of the zero page, which is
//! given once at construction. The core is `no_std` (needs `alloc`) and is
//! unit-tested on the build host.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// Page size in bytes — the guest's smallest translation unit.
pub const PAGE_SIZE: usize = 4096;

/// A 256-bit content hash identifying a page blob.
pub type BlobId = [u8; 32];

/// A snapshot generation handle.
pub type Generation = u32;

/// A page's index within the guest image (byte offset / `PAGE_SIZE`).
pub type PageIndex = u64;

struct GenNode {
    parent: Option<Generation>,
    /// Pages this generation changed relative to its parent chain. Per the
    /// module invariant, a page equal to its inherited value is *not* here.
    overlay: BTreeMap<PageIndex, BlobId>,
}

/// Content-addressed page store with copy-on-write snapshot generations.
pub struct PageStore {
    /// Content-addressed blob table. The key *is* the content hash, so two
    /// identical pages map to one entry — dedup is inherent.
    blobs: BTreeMap<BlobId, Vec<u8>>,
    gens: Vec<GenNode>,
    /// Identity of the all-zero page, supplied by the caller since the store
    /// does not know the hash function. Every unrecorded page resolves here.
    zero_id: BlobId,
}

/// Store size accounting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stats {
    /// Distinct page blobs held — the deduped whole-store cost, in pages. The
    /// zero page is always among them; the address space is zero-filled.
    pub blobs: usize,
    /// Total bytes of unique page content.
    pub content_bytes: usize,
    /// Number of snapshot generations.
    pub generations: usize,
    /// Overlay entries across all generations — the index cost. This tracks the
    /// content that actually diverges, not the size of the address space, so a
    /// large sparse image indexes only its allocated pages.
    pub index_entries: usize,
}

impl PageStore {
    /// Creates a store whose address space is zero-filled, with a single empty
    /// base generation (id 0). `zero_id` must be the caller's hash of
    /// `PAGE_SIZE` zero bytes; the store interns that page so an unrecorded read
    /// resolves to real bytes.
    pub fn new(zero_id: BlobId) -> Self {
        let mut blobs = BTreeMap::new();
        blobs.insert(zero_id, vec![0u8; PAGE_SIZE]);
        let gens = vec![GenNode { parent: None, overlay: BTreeMap::new() }];
        PageStore { blobs, gens, zero_id }
    }

    /// The base generation (id 0).
    pub fn base(&self) -> Generation {
        0
    }

    /// The identity of the all-zero page, as supplied at construction.
    pub fn zero_id(&self) -> BlobId {
        self.zero_id
    }

    /// What `gen` inherits for `idx` — the nearest entry strictly above it in
    /// the parent chain, or the zero page if the chain records none. This is the
    /// value an *absent* overlay entry stands for.
    fn inherited(&self, gen: Generation, idx: PageIndex) -> BlobId {
        let mut cur = self.gens[gen as usize].parent;
        while let Some(g) = cur {
            let node = &self.gens[g as usize];
            if let Some(id) = node.overlay.get(&idx) {
                return *id;
            }
            cur = node.parent;
        }
        self.zero_id
    }

    /// Interns `bytes` under `id` (dedup: a second identical page is free) and
    /// makes page `idx` of generation `gen` resolve to it.
    ///
    /// `id` must be the content hash of `bytes`, and `bytes.len()` must be
    /// `PAGE_SIZE`. Returns `true` if the blob was newly stored, `false` if an
    /// identical blob already existed (a dedup hit).
    ///
    /// No overlay entry is recorded when the page already resolves to `id`
    /// through the parent chain — that entry would say nothing, and on a sparse
    /// image saying nothing is the difference between indexing the allocated
    /// pages and indexing the whole virtual disk. Conversely, writing a value
    /// that *does* differ from the inherited one always records, even if the
    /// value is zero.
    pub fn write_page(&mut self, gen: Generation, idx: PageIndex, id: BlobId, bytes: &[u8]) -> bool {
        debug_assert_eq!(bytes.len(), PAGE_SIZE);
        let novel = !self.blobs.contains_key(&id);
        if novel {
            self.blobs.insert(id, bytes.to_vec());
        }
        if self.inherited(gen, idx) == id {
            // Redundant with the parent chain. Drop any entry that has become
            // redundant, so overwriting a page back to its inherited value
            // returns the index to its minimal form rather than growing it.
            self.gens[gen as usize].overlay.remove(&idx);
        } else {
            self.gens[gen as usize].overlay.insert(idx, id);
        }
        novel
    }

    /// The blob backing page `idx` as seen from generation `gen`: the nearest
    /// overlay entry walking `gen` -> parent -> ... -> base, or the zero page if
    /// no generation on that chain recorded it. Total — every page has a value.
    pub fn read_page(&self, gen: Generation, idx: PageIndex) -> BlobId {
        let mut cur = Some(gen);
        while let Some(g) = cur {
            let node = &self.gens[g as usize];
            if let Some(id) = node.overlay.get(&idx) {
                return *id;
            }
            cur = node.parent;
        }
        self.zero_id
    }

    /// Whether `gen` itself records `idx`, i.e. the page diverges from what the
    /// generation inherits. Distinguishes a generation's own changes from the
    /// pages it merely sees through its parent.
    pub fn diverges(&self, gen: Generation, idx: PageIndex) -> bool {
        self.gens[gen as usize].overlay.contains_key(&idx)
    }

    /// The bytes of a stored blob, if held.
    pub fn blob(&self, id: &BlobId) -> Option<&[u8]> {
        self.blobs.get(id).map(|v| v.as_slice())
    }

    /// Forks `parent` into a new child generation (a snapshot). O(1): the child
    /// starts with an empty overlay and inherits every unchanged page from
    /// `parent` by walking the parent chain on read.
    pub fn snapshot(&mut self, parent: Generation) -> Generation {
        let id = self.gens.len() as Generation;
        self.gens.push(GenNode { parent: Some(parent), overlay: BTreeMap::new() });
        id
    }

    /// Overlay entries recorded by `gen` alone — how much this snapshot cost.
    pub fn generation_entries(&self, gen: Generation) -> usize {
        self.gens[gen as usize].overlay.len()
    }

    /// Current store accounting.
    pub fn stats(&self) -> Stats {
        Stats {
            blobs: self.blobs.len(),
            content_bytes: self.blobs.len() * PAGE_SIZE,
            generations: self.gens.len(),
            index_entries: self.gens.iter().map(|g| g.overlay.len()).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A page whose bytes are all `fill`.
    fn page(fill: u8) -> Vec<u8> {
        alloc::vec![fill; PAGE_SIZE]
    }

    // A trivial content-derived id for tests (NOT cryptographic): identical
    // bytes yield identical ids, which is all the store's dedup relies on.
    fn id_of(bytes: &[u8]) -> BlobId {
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for &b in bytes {
            acc = (acc ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3);
        }
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&acc.to_le_bytes());
        id
    }

    fn zero_id() -> BlobId {
        id_of(&page(0))
    }

    fn store() -> PageStore {
        PageStore::new(zero_id())
    }

    fn put(s: &mut PageStore, gen: Generation, idx: PageIndex, fill: u8) -> bool {
        let p = page(fill);
        s.write_page(gen, idx, id_of(&p), &p)
    }

    #[test]
    fn identical_pages_dedup() {
        let mut s = store();
        let b = s.base();
        assert!(put(&mut s, b, 0, 0xAA)); // novel
        assert!(!put(&mut s, b, 1, 0xAA)); // same content at a different page -> dedup hit
        assert!(put(&mut s, b, 2, 0xBB)); // distinct content -> novel
        // Two distinct written contents, plus the zero page the store always holds.
        assert_eq!(s.stats().blobs, 3);
        // Both deduped pages resolve to the same blob id.
        assert_eq!(s.read_page(b, 0), s.read_page(b, 1));
        assert_ne!(s.read_page(b, 0), s.read_page(b, 2));
    }

    #[test]
    fn snapshot_is_copy_on_write() {
        let mut s = store();
        let b = s.base();
        put(&mut s, b, 0, 0xAA);
        put(&mut s, b, 5, 0xCC);

        let child = s.snapshot(b);
        // Child inherits everything unchanged.
        assert_eq!(s.read_page(child, 0), s.read_page(b, 0));
        assert_eq!(s.read_page(child, 5), s.read_page(b, 5));

        // Writing in the child must not disturb the parent (isolation).
        put(&mut s, child, 0, 0xDD);
        assert_eq!(s.read_page(child, 0), id_of(&page(0xDD)));
        assert_eq!(s.read_page(b, 0), id_of(&page(0xAA)));
        // Untouched pages still fall through to the parent.
        assert_eq!(s.read_page(child, 5), id_of(&page(0xCC)));
        // A page nobody wrote reads as zero, and is recorded nowhere.
        assert_eq!(s.read_page(child, 99), zero_id());
        assert!(!s.diverges(child, 99));
        assert!(!s.diverges(b, 99));
    }

    #[test]
    fn snapshot_costs_only_diverging_pages() {
        let mut s = store();
        let b = s.base();
        for i in 0..100u64 {
            // 100 pages but only two distinct contents -> 2 blobs (+ the zero page).
            put(&mut s, b, i, if i % 2 == 0 { 1 } else { 2 });
        }
        let before = s.stats();
        assert_eq!(before.blobs, 3);

        let child = s.snapshot(b);
        // Taking the snapshot adds a generation but no blobs and no index entries.
        assert_eq!(s.stats().blobs, 3);
        assert_eq!(s.stats().generations, before.generations + 1);
        assert_eq!(s.generation_entries(child), 0);

        // One diverging page in the child costs exactly one new blob and one entry.
        put(&mut s, child, 0, 3);
        assert_eq!(s.stats().blobs, 4);
        assert_eq!(s.generation_entries(child), 1);
    }

    // The invariant's load-bearing case: absence means "same as inherited", so a
    // child that zeroes a page its parent wrote MUST record it. If the store
    // treated zero writes as always-elidable, the child would silently keep
    // reading the parent's non-zero content.
    #[test]
    fn zeroing_a_page_the_parent_wrote_is_recorded() {
        let mut s = store();
        let b = s.base();
        put(&mut s, b, 7, 0xAA);

        let child = s.snapshot(b);
        let z = page(0);
        s.write_page(child, 7, zero_id(), &z);

        assert_eq!(s.read_page(child, 7), zero_id(), "child must see the zero it wrote");
        assert_eq!(s.read_page(b, 7), id_of(&page(0xAA)), "parent is untouched");
        assert!(s.diverges(child, 7), "the divergence must be recorded, not elided");
    }

    // Writing a page back to the value it inherits returns the index to its
    // minimal form, rather than leaving a redundant entry behind.
    #[test]
    fn rewriting_the_inherited_value_drops_the_entry() {
        let mut s = store();
        let b = s.base();
        put(&mut s, b, 3, 0xAA);

        let child = s.snapshot(b);
        put(&mut s, child, 3, 0xBB);
        assert!(s.diverges(child, 3));
        assert_eq!(s.generation_entries(child), 1);

        // Back to what the parent holds: the entry is now redundant.
        put(&mut s, child, 3, 0xAA);
        assert!(!s.diverges(child, 3));
        assert_eq!(s.generation_entries(child), 0);
        assert_eq!(s.read_page(child, 3), id_of(&page(0xAA)));
    }

    // The scaling property, asserted on a measured quantity: a vast sparse
    // address space costs index entries proportional to its *content*, not to
    // its size. Without elision this would be a million entries.
    #[test]
    fn sparse_address_space_costs_index_proportional_to_content() {
        let mut s = store();
        let b = s.base();
        let z = page(0);
        let zid = zero_id();

        const PAGES: u64 = 1_000_000;
        for i in 0..PAGES {
            s.write_page(b, i, zid, &z);
        }
        assert_eq!(s.stats().index_entries, 0, "empty space must not be indexed");
        assert_eq!(s.stats().blobs, 1, "empty space is one shared blob");

        // Sprinkle real content through the same space.
        let occupied: [u64; 4] = [0, 17, 4096, PAGES - 1];
        for (n, &i) in occupied.iter().enumerate() {
            put(&mut s, b, i, 0x10 + n as u8);
        }
        assert_eq!(s.stats().index_entries, occupied.len());
        assert_eq!(s.stats().blobs, 1 + occupied.len());

        // Everything still reads back correctly: content where written, zero
        // everywhere else across the whole space.
        for (n, &i) in occupied.iter().enumerate() {
            assert_eq!(s.read_page(b, i), id_of(&page(0x10 + n as u8)));
        }
        assert_eq!(s.read_page(b, 1), zid);
        assert_eq!(s.read_page(b, PAGES / 2), zid);
        assert_eq!(s.read_page(b, u64::MAX), zid, "the space is unbounded and zero-filled");
    }
}
