//! The `.cryostore` on-disk format: a content-addressed page store that can be
//! written once by a host tool and then read *lazily*, a page at a time, by a
//! consumer that never holds the whole thing.
//!
//! # Why there is a format at all
//!
//! `cryogen_store::PageStore` is correct and entirely in RAM: nothing
//! serialises it, so a packed image is a number a measurement tool printed and
//! then discarded. A VM that boots off a guest image needs the opposite — the
//! bytes must outlive the process that computed them, and the consumer must be
//! able to hold the *map* while leaving the *content* where it is.
//!
//! # The one property the whole design rests on
//!
//! The index is small and the content is large. Measured on a 64 GiB sparse
//! Windows image — 16,777,216 logical pages, 99.2 % of them zero, 124,222
//! distinct non-zero pages, 134,213 index entries — the index is 5,586,944 B
//! and the pack is 508,813,312 B, so the map is **1.09 %** of the store. A
//! consumer can therefore hold the entire map of a 64 GiB disk in a few MiB and
//! fetch 4 KiB pages against it.
//!
//! Everything before `pack_off` is the map, and it is contiguous, so a remote
//! consumer fetches it with **one** ranged read.
//!
//! # Layout
//!
//! All integers little-endian.
//!
//! ```text
//! 0                      header, HEADER_LEN bytes (see `Header`)
//! header.slots_off       blob_count x 32 B  -- BlobId of each slot, INDEXED BY SLOT
//! header.overlays_off    gen_count x { parent i32, entry_count u32 },
//!                        each followed by entry_count x { page_index u64, slot u32 }
//!                        sorted ascending by page_index
//! header.pack_off        blob_count x PAGE_SIZE B, addressed by slot (4096-aligned)
//! ```
//!
//! ## Why `slots` is indexed by slot rather than sorted by `BlobId`
//!
//! The obvious layout for a content-addressed store is
//! `blob_count x { BlobId, slot u32 }` **sorted by BlobId**, so the file is
//! itself a content-address lookup. This format stores the transpose — `BlobId`
//! indexed by slot — and does not carry the sorted table at all.
//!
//! The reason is which direction the hot path looks. A consumer that has just
//! fetched slot *s* must check `sha256(bytes) == id_of(s)` before handing the
//! bytes to a guest; that is `slot -> BlobId`, on every single fetch, and
//! against a sorted-by-BlobId table it is a binary search rather than an array
//! index. The other direction, `BlobId -> slot`, has no consumer: dedup happens
//! in the packer's own hash map, which the packer rebuilds anyway. So the
//! transpose is both smaller (32 B/blob rather than 36 B) and the one the
//! reader needs.
//!
//! # `root_hash`
//!
//! `sha256(header-with-root_hash-zeroed || slots || overlays)`. It does not
//! cover the pack *directly* — it does not need to. Every entry in `slots` is
//! itself the SHA-256 of one page, so the root names the content transitively,
//! and the per-page check a consumer already performs on every fetch is what
//! enforces it. This is the property that makes `root_hash` usable as the
//! image's identity in a test result.
//!
//! # Zero pages are not stored
//!
//! A page with no overlay entry reads as all-zero. This is inherited from
//! `cryogen_store`'s invariant and it is what keeps the index proportional to a
//! disk's *content* rather than to its virtual size — 99.2 % of the measured
//! image's address space costs no entry and no fetch.
//!
//! # Generations, and the one trap in them
//!
//! A generation records only what it *changed* relative to its parent, so
//! [`StoreIndex::resolve`] walks the chain and the first hit wins. That makes
//! the meaning of an absent entry **inherit**, not zero — `resolve` reports
//! all-zero only after the whole chain is exhausted.
//!
//! Which is exactly the trap. If a parent records page P with content and a
//! guest then *zeroes* P, dropping the entry because "the page is zero now"
//! resurrects the parent's stale bytes: a silent corruption in the snapshot. So
//! a child must record such a page **explicitly**, and [`ZERO_SLOT`] is what it
//! records — a tombstone that terminates the chain walk at zero.
//!
//! A tombstone rather than a slot holding a zero-filled page, deliberately. A
//! real slot would cost [`PAGE_SIZE`] pack bytes and, worse, a *fetch* on every
//! read of a page the guest erased. `ZERO_SLOT` costs the 12 bytes of its entry
//! and keeps the property the whole design rests on: `resolve` returning `None`
//! means all-zero at no fetch cost, whether the page was never written or was
//! written and then erased.
//!
//! ## Why the version did not change
//!
//! `ZERO_SLOT` widens the values an overlay entry's slot field may hold, and
//! [`VERSION`] is still 1. That is a decision, not an oversight, and it rests
//! on the failure mode rather than on convenience:
//!
//! * A store with one generation is byte-identical to what the previous packer
//!   produced, so bumping the version would break every existing store to
//!   describe a feature they do not use.
//! * A store that *does* carry a tombstone is **refused** by a reader predating
//!   this change — it rejects the entry as `SlotOutOfRange`, naming the slot.
//!   A refusal is the safe direction; the danger would be an old reader
//!   silently misinterpreting the value, and there is no interpretation under
//!   which `u32::MAX` was previously legal.
//!
//! If a future change alters the meaning of bytes an old reader would *accept*,
//! that one must bump the version.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

use cryogen_hash::sha256;

/// Page size in bytes. Fixed, and checked against the header on parse.
pub const PAGE_SIZE: usize = 4096;

/// A 256-bit content hash naming a page's bytes.
pub type BlobId = [u8; 32];

/// A generation (snapshot) id.
pub type Generation = u32;

/// A page's index within the logical image (byte offset / [`PAGE_SIZE`]).
pub type PageIndex = u64;

/// A page's position in the pack.
pub type Slot = u32;

/// The tombstone slot: an overlay entry naming it says "this page is all-zero
/// **here**, do not inherit whatever a parent generation records for it".
///
/// It is not a position in the pack and no page is ever fetched for it —
/// [`StoreIndex::resolve`] turns it into `None`, which is the same answer it
/// gives for a page no generation records at all. The two are indistinguishable
/// to a reader on purpose: both mean "all-zero, no fetch". The distinction only
/// matters to the *writer*, and only in a child generation, where omitting the
/// entry would mean inherit rather than zero.
///
/// `u32::MAX` is safe to reserve because a store with that many slots is
/// refused: [`Packer::add_page`] errors with [`Error::TooManyBlobs`] before
/// allocating it and [`Header::decode`] rejects a file claiming it.
pub const ZERO_SLOT: Slot = u32::MAX;

/// File magic.
pub const MAGIC: [u8; 8] = *b"CRYOSTR1";

/// Format version this crate reads and writes.
pub const VERSION: u32 = 1;

/// `hash_id` for SHA-256.
pub const HASH_SHA256: u32 = 1;

/// Bytes of header, before the index sections.
pub const HEADER_LEN: usize = 128;

/// Bytes per entry in the `slots` section.
const SLOT_ENTRY_LEN: usize = 32;

/// Bytes per entry in an overlay's entry list.
const OVERLAY_ENTRY_LEN: usize = 12;

/// Bytes of per-generation overlay header.
const OVERLAY_GEN_HEADER_LEN: usize = 8;

/// A generation with no parent.
const NO_PARENT: i32 = -1;

// ── The sentinel page ──────────────────────────────────────────────────────

/// A page whose content is a fixed, recognisable constant, placed in a store by
/// `cryostore pack --sentinel-page` and **never read by a correct consumer**.
///
/// This exists to make laziness falsifiable rather than merely measured. An
/// implementation that fetches eagerly satisfies every fetch-count threshold,
/// every truncated-pack test and every refusing-source test, because it is
/// never denied anything it needed. The only configuration in which
/// over-fetching becomes *visible* is a page that is present, served and
/// answerable — but that nothing on the consumer's real read path can address.
///
/// The content is a single constant rather than a function of the page index,
/// deliberately: the store deduplicates by content, so a sentinel placed at any
/// number of page indices collapses to exactly **one** slot. A consumer can
/// therefore identify it by hash alone, without being told where it was put,
/// and one assertion — "no slot holding this content was ever read" — covers
/// every placement.
pub fn sentinel_page() -> [u8; PAGE_SIZE] {
    const TAG: &[u8] = b"CRYOGEN-SENTINEL-PAGE-DO-NOT-READ\n";
    let mut page = [0u8; PAGE_SIZE];
    let mut off = 0;
    while off + TAG.len() <= PAGE_SIZE {
        page[off..off + TAG.len()].copy_from_slice(TAG);
        off += TAG.len();
    }
    page
}

/// The `BlobId` of [`sentinel_page`]. A consumer finds the sentinel's slot(s)
/// by scanning the `slots` section for this value.
pub fn sentinel_blob_id() -> BlobId {
    sha256(&sentinel_page())
}

// ── Errors ─────────────────────────────────────────────────────────────────

/// Why a `.cryostore` could not be parsed, or could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The buffer is shorter than the structure it claims to hold.
    Truncated {
        /// What was being read.
        what: &'static str,
        /// Bytes needed.
        need: u64,
        /// Bytes available.
        have: u64,
    },
    /// The magic is not [`MAGIC`].
    BadMagic([u8; 8]),
    /// The version is not [`VERSION`].
    BadVersion(u32),
    /// The page size is not [`PAGE_SIZE`].
    BadPageSize(u32),
    /// The hash algorithm is not one this crate implements.
    BadHash(u32),
    /// A section offset or length is inconsistent with the rest of the header.
    BadLayout(&'static str),
    /// `root_hash` does not match the index it covers.
    RootHashMismatch {
        /// What the header claims.
        expected: BlobId,
        /// What the index actually hashes to.
        actual: BlobId,
    },
    /// A generation names a parent that does not exist, or is not below it.
    BadParent {
        /// The generation whose parent is wrong.
        generation: Generation,
        /// The parent it named.
        parent: i32,
    },
    /// An overlay entry names a slot past the end of the pack.
    SlotOutOfRange {
        /// The offending slot.
        slot: Slot,
        /// How many slots exist.
        blob_count: u32,
    },
    /// Overlay entries are not sorted ascending by page index, so they cannot
    /// be binary-searched.
    UnsortedOverlay {
        /// The generation whose entries are out of order.
        generation: Generation,
    },
    /// A store would need more slots than a `Slot` can name below [`ZERO_SLOT`].
    TooManyBlobs,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated { what, need, have } => {
                write!(f, "truncated {what}: need {need} bytes, have {have}")
            }
            Error::BadMagic(m) => write!(f, "bad magic {m:?}, expected {MAGIC:?}"),
            Error::BadVersion(v) => write!(f, "unsupported .cryostore version {v}, expected {VERSION}"),
            Error::BadPageSize(p) => write!(f, "page size {p} is not the {PAGE_SIZE} this build uses"),
            Error::BadHash(h) => write!(f, "unsupported hash id {h}, expected {HASH_SHA256} (SHA-256)"),
            Error::BadLayout(why) => write!(f, "inconsistent header layout: {why}"),
            Error::RootHashMismatch { expected, actual } => write!(
                f,
                "root_hash mismatch: header says {}, index hashes to {}",
                HexId(expected),
                HexId(actual)
            ),
            Error::BadParent { generation, parent } => {
                write!(f, "generation {generation} names parent {parent}, which is not a lower generation")
            }
            Error::SlotOutOfRange { slot, blob_count } => {
                write!(f, "overlay entry names slot {slot}, but the pack holds {blob_count} slots")
            }
            Error::UnsortedOverlay { generation } => {
                write!(f, "generation {generation}'s overlay entries are not sorted by page index")
            }
            Error::TooManyBlobs => {
                write!(f, "store would need more than {} slots", ZERO_SLOT - 1)
            }
        }
    }
}

/// Lowercase hex, for messages. A store is identified by its `root_hash` and a
/// message that cannot name it is not a diagnosis.
pub struct HexId<'a>(pub &'a BlobId);

impl core::fmt::Display for HexId<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

// ── Header ─────────────────────────────────────────────────────────────────

/// The fixed-size head of a `.cryostore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Logical size of the image this store holds, in bytes. A consumer's
    /// sector count derives from this, so a page index at or beyond
    /// `disk_size.div_ceil(PAGE_SIZE)` is unreachable through a disk read *by
    /// construction* — which is what one of the sentinel placements relies on.
    /// (`div_ceil`, not `/`: a disk whose size is a whole number of sectors but
    /// not of pages has a last, partial page that a read can still reach.)
    pub disk_size: u64,
    /// Number of page blobs in the pack.
    pub blob_count: u32,
    /// Number of generations.
    pub gen_count: u32,
    /// Byte offset of the `slots` section.
    pub slots_off: u64,
    /// Byte offset of the `overlays` section.
    pub overlays_off: u64,
    /// Byte length of the `overlays` section.
    pub overlays_len: u64,
    /// Byte offset of the pack. Everything below this is the index.
    pub pack_off: u64,
    /// `sha256(header-with-root_hash-zeroed || slots || overlays)`.
    pub root_hash: BlobId,
}

impl Header {
    /// Byte length of the `slots` section.
    pub fn slots_len(&self) -> u64 {
        self.blob_count as u64 * SLOT_ENTRY_LEN as u64
    }

    /// Byte length of the pack.
    pub fn pack_len(&self) -> u64 {
        self.blob_count as u64 * PAGE_SIZE as u64
    }

    /// Total byte length of a well-formed store with this header.
    pub fn total_len(&self) -> u64 {
        self.pack_off + self.pack_len()
    }

    /// Byte length of the index prefix — header, slots and overlays, which are
    /// contiguous from offset 0. This is the one range a remote consumer has to
    /// fetch before it can resolve anything.
    pub fn index_len(&self) -> u64 {
        self.pack_off
    }

    /// Byte offset of the page in `slot`.
    pub fn slot_offset(&self, slot: Slot) -> u64 {
        self.pack_off + slot as u64 * PAGE_SIZE as u64
    }

    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut b = [0u8; HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&VERSION.to_le_bytes());
        b[12..16].copy_from_slice(&(PAGE_SIZE as u32).to_le_bytes());
        b[16..20].copy_from_slice(&HASH_SHA256.to_le_bytes());
        // [20..24] flags, reserved and zero.
        b[24..32].copy_from_slice(&self.disk_size.to_le_bytes());
        b[32..36].copy_from_slice(&self.blob_count.to_le_bytes());
        b[36..40].copy_from_slice(&self.gen_count.to_le_bytes());
        b[40..48].copy_from_slice(&self.slots_off.to_le_bytes());
        b[48..56].copy_from_slice(&self.slots_len().to_le_bytes());
        b[56..64].copy_from_slice(&self.overlays_off.to_le_bytes());
        b[64..72].copy_from_slice(&self.overlays_len.to_le_bytes());
        b[72..80].copy_from_slice(&self.pack_off.to_le_bytes());
        b[80..88].copy_from_slice(&self.pack_len().to_le_bytes());
        b[88..120].copy_from_slice(&self.root_hash);
        b
    }

    /// Parses the header out of the first [`HEADER_LEN`] bytes of a store.
    ///
    /// Public because a consumer that fetches the store in pieces cannot get to
    /// [`StoreIndex::parse`] without it: the length of the index is
    /// [`Header::index_len`], which is a *field of the header*, so the header
    /// has to be read and decoded on its own before the index read can even be
    /// sized. Magic, version and page size are checked here, which is what
    /// makes that first length safe to act on.
    ///
    /// This does **not** verify `root_hash` — it cannot, since the bytes the
    /// root covers have not been read yet. A header that decodes is a header
    /// that is well-formed, not one that is trusted; `StoreIndex::parse` is
    /// where trust starts.
    pub fn decode(b: &[u8]) -> Result<Self, Error> {
        if b.len() < HEADER_LEN {
            return Err(Error::Truncated {
                what: "header",
                need: HEADER_LEN as u64,
                have: b.len() as u64,
            });
        }
        let magic: [u8; 8] = b[0..8].try_into().unwrap();
        if magic != MAGIC {
            return Err(Error::BadMagic(magic));
        }
        let version = u32::from_le_bytes(b[8..12].try_into().unwrap());
        if version != VERSION {
            return Err(Error::BadVersion(version));
        }
        let page_size = u32::from_le_bytes(b[12..16].try_into().unwrap());
        if page_size as usize != PAGE_SIZE {
            return Err(Error::BadPageSize(page_size));
        }
        let hash_id = u32::from_le_bytes(b[16..20].try_into().unwrap());
        if hash_id != HASH_SHA256 {
            return Err(Error::BadHash(hash_id));
        }
        let h = Header {
            disk_size: u64::from_le_bytes(b[24..32].try_into().unwrap()),
            blob_count: u32::from_le_bytes(b[32..36].try_into().unwrap()),
            gen_count: u32::from_le_bytes(b[36..40].try_into().unwrap()),
            slots_off: u64::from_le_bytes(b[40..48].try_into().unwrap()),
            overlays_off: u64::from_le_bytes(b[56..64].try_into().unwrap()),
            overlays_len: u64::from_le_bytes(b[64..72].try_into().unwrap()),
            pack_off: u64::from_le_bytes(b[72..80].try_into().unwrap()),
            root_hash: b[88..120].try_into().unwrap(),
        };
        // The two redundant length fields exist so a reader can cross-check the
        // producer rather than trust it. A disagreement here means the file was
        // written by something that did not agree with this crate about the
        // layout, and guessing which side is right would be the wrong move.
        let slots_len = u64::from_le_bytes(b[48..56].try_into().unwrap());
        if slots_len != h.slots_len() {
            return Err(Error::BadLayout("slots_len disagrees with blob_count"));
        }
        let pack_len = u64::from_le_bytes(b[80..88].try_into().unwrap());
        if pack_len != h.pack_len() {
            return Err(Error::BadLayout("pack_len disagrees with blob_count"));
        }
        // The layout is **exact**, not merely non-overlapping. Every offset
        // below is derived from `blob_count` and `overlays_len`, so a
        // conforming file has exactly one possible set of them and a reader can
        // reject anything else outright.
        //
        // Two reasons that is worth the strictness. It removes a whole class of
        // ambiguity — gaps between sections would be covered by `root_hash` but
        // read by nothing, so one logical image could have many valid root
        // hashes, and the identity would stop being an identity. And every
        // subsequent slice in `StoreIndex::parse` becomes provably in bounds
        // given only `buf.len() >= pack_off`, which is what makes a corrupt
        // file an `Error` rather than a panic.
        //
        // Every sum is checked: these are numbers out of a file, and unchecked
        // arithmetic would wrap in a release build.
        if h.slots_off != HEADER_LEN as u64 {
            return Err(Error::BadLayout("slots must begin immediately after the header"));
        }
        let slots_end = h
            .slots_off
            .checked_add(h.slots_len())
            .ok_or(Error::BadLayout("slots section overflows the offset space"))?;
        if h.overlays_off != slots_end {
            return Err(Error::BadLayout("overlays must begin immediately after slots"));
        }
        let overlays_end = h
            .overlays_off
            .checked_add(h.overlays_len)
            .ok_or(Error::BadLayout("overlays section overflows the offset space"))?;
        // The pack is page-aligned so it can be mapped; the alignment padding is
        // the only slack the layout allows, and it is fully determined.
        let want_pack_off = overlays_end
            .checked_next_multiple_of(PAGE_SIZE as u64)
            .ok_or(Error::BadLayout("pack alignment overflows the offset space"))?;
        if h.pack_off != want_pack_off {
            return Err(Error::BadLayout(
                "the pack must be page-aligned immediately after overlays",
            ));
        }
        if h.pack_off.checked_add(h.pack_len()).is_none() {
            return Err(Error::BadLayout("pack overflows the offset space"));
        }
        if h.gen_count == 0 {
            return Err(Error::BadLayout("a store must hold at least one generation"));
        }
        // `ZERO_SLOT` is `u32::MAX`, and a store that really held that many
        // slots would make the tombstone ambiguous with a genuine pack
        // position. Refuse the file rather than let one entry mean two things.
        // (Such a file would also be 16 TiB of pack, so nothing legitimate is
        // being turned away.)
        if h.blob_count == ZERO_SLOT {
            return Err(Error::BadLayout("blob_count collides with the tombstone slot"));
        }
        // Bound `gen_count` by the section that has to hold it *before* it is
        // used to size an allocation. Each generation costs at least its 8-byte
        // header, so a file claiming more generations than `overlays_len` can
        // describe is refused here rather than after a multi-gigabyte
        // `Vec::with_capacity` that a hostile 200-byte file could have asked
        // for.
        if h.gen_count as u64 * OVERLAY_GEN_HEADER_LEN as u64 > h.overlays_len {
            return Err(Error::BadLayout("gen_count cannot fit in overlays_len"));
        }
        Ok(h)
    }
}

// ── Reader ─────────────────────────────────────────────────────────────────

/// One generation's overlay: what it changed relative to its parent.
#[derive(Debug, Clone)]
pub struct GenerationIndex {
    /// The generation this one is a snapshot of, if any.
    pub parent: Option<Generation>,
    /// `(page_index, slot)` sorted ascending by page index.
    pub entries: Vec<(PageIndex, Slot)>,
}

impl GenerationIndex {
    fn lookup(&self, page: PageIndex) -> Option<Slot> {
        self.entries
            .binary_search_by_key(&page, |&(p, _)| p)
            .ok()
            .map(|i| self.entries[i].1)
    }

    /// Entries this generation records, tombstones included.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Entries that record [`ZERO_SLOT`]: pages this generation erased that a
    /// parent had recorded content for. They cost an index entry and no pack
    /// bytes, and they are the difference between a snapshot that is correct
    /// and one that silently resurrects the parent's bytes.
    pub fn zero_entries(&self) -> usize {
        self.entries.iter().filter(|&&(_, s)| s == ZERO_SLOT).count()
    }
}

/// Incrementally validates a Cryostore index without retaining its slot or
/// overlay tables.
///
/// Consumers that only need to admit an image do not need [`StoreIndex`]'s
/// lookup vectors. Feeding the index through this validator keeps memory
/// constant while enforcing the same root hash, parent ordering, slot bounds,
/// entry ordering, and exact overlay layout as [`StoreIndex::parse`].
pub struct StoreIndexValidator {
    header: Header,
    hasher: cryogen_hash::Sha256,
    consumed: u64,
    slots_consumed: u64,
    overlays_consumed: u64,
    generation: u32,
    entries_remaining: u32,
    previous_page: Option<PageIndex>,
    frame: [u8; OVERLAY_ENTRY_LEN],
    frame_len: usize,
}

impl StoreIndexValidator {
    /// Starts validation from the exact encoded header bytes.
    ///
    /// The original bytes, rather than a re-encoded [`Header`], are hashed so
    /// every covered header bit participates in the on-disk identity.
    pub fn new(header_bytes: &[u8]) -> Result<Self, Error> {
        let header = Header::decode(header_bytes)?;
        let mut head_zeroed = [0u8; HEADER_LEN];
        head_zeroed.copy_from_slice(&header_bytes[..HEADER_LEN]);
        head_zeroed[88..120].fill(0);
        let mut hasher = cryogen_hash::Sha256::new();
        hasher.update(&head_zeroed);
        Ok(Self {
            header,
            hasher,
            consumed: 0,
            slots_consumed: 0,
            overlays_consumed: 0,
            generation: 0,
            entries_remaining: 0,
            previous_page: None,
            frame: [0; OVERLAY_ENTRY_LEN],
            frame_len: 0,
        })
    }

    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Consumes the next contiguous bytes after the fixed header. Calls may
    /// split slot IDs, generation headers, and overlay entries arbitrarily.
    pub fn update(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        let expected = self.header.index_len() - HEADER_LEN as u64;
        if bytes.len() as u64 > expected.saturating_sub(self.consumed) {
            return Err(Error::BadLayout("index stream extends past pack_off"));
        }
        self.consumed += bytes.len() as u64;

        let slots_left = self.header.slots_len() - self.slots_consumed;
        let slot_bytes = core::cmp::min(bytes.len() as u64, slots_left) as usize;
        if slot_bytes != 0 {
            self.hasher.update(&bytes[..slot_bytes]);
            self.slots_consumed += slot_bytes as u64;
            bytes = &bytes[slot_bytes..];
        }

        let overlays_left = self.header.overlays_len - self.overlays_consumed;
        let overlay_bytes = core::cmp::min(bytes.len() as u64, overlays_left) as usize;
        if overlay_bytes != 0 {
            let overlay = &bytes[..overlay_bytes];
            self.hasher.update(overlay);
            self.consume_overlays(overlay)?;
            self.overlays_consumed += overlay_bytes as u64;
            bytes = &bytes[overlay_bytes..];
        }

        // Any remaining bytes are the deterministic page-alignment range
        // between overlays_end and pack_off. StoreIndex::parse does not include
        // that range in root_hash or interpret it.
        let _alignment_padding = bytes;
        Ok(())
    }

    fn consume_overlays(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            if self.entries_remaining == 0 && self.frame_len == 0 {
                if self.generation == self.header.gen_count {
                    return Err(Error::BadLayout(
                        "the overlays section has bytes no generation accounts for",
                    ));
                }
                self.previous_page = None;
            }
            let frame_size = if self.entries_remaining == 0 {
                OVERLAY_GEN_HEADER_LEN
            } else {
                OVERLAY_ENTRY_LEN
            };
            let take = core::cmp::min(frame_size - self.frame_len, bytes.len());
            self.frame[self.frame_len..self.frame_len + take].copy_from_slice(&bytes[..take]);
            self.frame_len += take;
            bytes = &bytes[take..];
            if self.frame_len != frame_size {
                continue;
            }

            if self.entries_remaining == 0 {
                let parent = i32::from_le_bytes(self.frame[0..4].try_into().unwrap());
                let entry_count =
                    u32::from_le_bytes(self.frame[4..8].try_into().unwrap());
                if parent != NO_PARENT
                    && (parent < 0 || parent as u32 >= self.generation)
                {
                    return Err(Error::BadParent {
                        generation: self.generation,
                        parent,
                    });
                }
                self.generation += 1;
                self.entries_remaining = entry_count;
            } else {
                let page = u64::from_le_bytes(self.frame[0..8].try_into().unwrap());
                let slot = u32::from_le_bytes(self.frame[8..12].try_into().unwrap());
                if slot >= self.header.blob_count && slot != ZERO_SLOT {
                    return Err(Error::SlotOutOfRange {
                        slot,
                        blob_count: self.header.blob_count,
                    });
                }
                if self.previous_page.is_some_and(|previous| previous >= page) {
                    return Err(Error::UnsortedOverlay {
                        generation: self.generation - 1,
                    });
                }
                self.previous_page = Some(page);
                self.entries_remaining -= 1;
            }
            self.frame_len = 0;
        }
        Ok(())
    }

    /// Completes validation and returns the trusted header.
    pub fn finish(self) -> Result<Header, Error> {
        if self.consumed != self.header.index_len() - HEADER_LEN as u64 {
            return Err(Error::Truncated {
                what: "index",
                need: self.header.index_len(),
                have: HEADER_LEN as u64 + self.consumed,
            });
        }
        if self.slots_consumed != self.header.slots_len()
            || self.overlays_consumed != self.header.overlays_len
            || self.frame_len != 0
            || self.entries_remaining != 0
            || self.generation != self.header.gen_count
        {
            return Err(Error::Truncated {
                what: "overlay generation",
                need: self.header.overlays_off + self.header.overlays_len,
                have: self.header.overlays_off + self.overlays_consumed,
            });
        }
        let actual = self.hasher.finalize();
        if actual != self.header.root_hash {
            return Err(Error::RootHashMismatch {
                expected: self.header.root_hash,
                actual,
            });
        }
        Ok(self.header)
    }
}

/// The parsed index of a `.cryostore` — everything below `pack_off`.
///
/// This is the whole map and none of the content. It is what travels eagerly;
/// pages are fetched against it on demand.
#[derive(Debug, Clone)]
pub struct StoreIndex {
    header: Header,
    slot_ids: Vec<BlobId>,
    generations: Vec<GenerationIndex>,
}

impl StoreIndex {
    /// Parses the index prefix of a store.
    ///
    /// `buf` must hold at least `header.index_len()` bytes; it may hold the
    /// whole file, in which case the pack is ignored. The `root_hash` is
    /// **verified here**, so a truncated, wrong or corrupted index is a named
    /// error at load rather than a strange failure later.
    pub fn parse(buf: &[u8]) -> Result<Self, Error> {
        let header = Header::decode(buf)?;
        let need = header.index_len();
        if (buf.len() as u64) < need {
            return Err(Error::Truncated {
                what: "index",
                need,
                have: buf.len() as u64,
            });
        }

        // Recompute the root over exactly the bytes it covers, before trusting
        // any of them.
        let mut head_zeroed = [0u8; HEADER_LEN];
        head_zeroed.copy_from_slice(&buf[..HEADER_LEN]);
        head_zeroed[88..120].fill(0);
        let mut hasher = cryogen_hash::Sha256::new();
        hasher.update(&head_zeroed);
        hasher.update(&buf[header.slots_off as usize..(header.slots_off + header.slots_len()) as usize]);
        hasher.update(&buf[header.overlays_off as usize..(header.overlays_off + header.overlays_len) as usize]);
        let actual = hasher.finalize();
        if actual != header.root_hash {
            return Err(Error::RootHashMismatch {
                expected: header.root_hash,
                actual,
            });
        }

        let mut slot_ids = Vec::with_capacity(header.blob_count as usize);
        let base = header.slots_off as usize;
        for i in 0..header.blob_count as usize {
            let o = base + i * SLOT_ENTRY_LEN;
            slot_ids.push(buf[o..o + SLOT_ENTRY_LEN].try_into().unwrap());
        }

        let mut generations = Vec::with_capacity(header.gen_count as usize);
        let mut o = header.overlays_off as usize;
        let overlays_end = (header.overlays_off + header.overlays_len) as usize;
        for g in 0..header.gen_count {
            if o + OVERLAY_GEN_HEADER_LEN > overlays_end {
                return Err(Error::Truncated {
                    what: "overlay generation header",
                    need: (o + OVERLAY_GEN_HEADER_LEN) as u64,
                    have: overlays_end as u64,
                });
            }
            let parent = i32::from_le_bytes(buf[o..o + 4].try_into().unwrap());
            let entry_count = u32::from_le_bytes(buf[o + 4..o + 8].try_into().unwrap()) as usize;
            o += OVERLAY_GEN_HEADER_LEN;
            let parent = if parent == NO_PARENT {
                None
            } else if parent >= 0 && (parent as u32) < g {
                Some(parent as Generation)
            } else {
                // A parent at or above this generation would make the chain
                // walk in `resolve` non-terminating, so it is refused here
                // rather than defended against on every read.
                return Err(Error::BadParent { generation: g, parent });
            };
            let need = o as u64 + (entry_count as u64) * OVERLAY_ENTRY_LEN as u64;
            if need > overlays_end as u64 {
                return Err(Error::Truncated {
                    what: "overlay entries",
                    need,
                    have: overlays_end as u64,
                });
            }
            let mut entries = Vec::with_capacity(entry_count);
            let mut prev: Option<PageIndex> = None;
            for _ in 0..entry_count {
                let page = u64::from_le_bytes(buf[o..o + 8].try_into().unwrap());
                let slot = u32::from_le_bytes(buf[o + 8..o + 12].try_into().unwrap());
                o += OVERLAY_ENTRY_LEN;
                if slot >= header.blob_count && slot != ZERO_SLOT {
                    return Err(Error::SlotOutOfRange {
                        slot,
                        blob_count: header.blob_count,
                    });
                }
                if prev.is_some_and(|p| p >= page) {
                    return Err(Error::UnsortedOverlay { generation: g });
                }
                prev = Some(page);
                entries.push((page, slot));
            }
            generations.push(GenerationIndex { parent, entries });
        }
        // Exactly consumed. Trailing bytes would be covered by `root_hash` and
        // read by nothing, which is the same ambiguity the exact-layout rule
        // above exists to remove — and it would let a producer that overflowed
        // an entry count silently drop entries instead of being rejected.
        if o != overlays_end {
            return Err(Error::BadLayout(
                "the overlays section has bytes no generation accounts for",
            ));
        }

        Ok(StoreIndex {
            header,
            slot_ids,
            generations,
        })
    }

    /// The header.
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// The store's identity.
    pub fn root_hash(&self) -> &BlobId {
        &self.header.root_hash
    }

    /// The newest generation — the one a fresh consumer reads.
    pub fn tip(&self) -> Generation {
        self.generations.len() as Generation - 1
    }

    /// Number of overlay entries across every generation: the index cost.
    pub fn index_entries(&self) -> usize {
        self.generations.iter().map(|g| g.entries.len()).sum()
    }

    /// The `BlobId` a fetched page must hash to. This is the lookup that runs
    /// on every fetch, and it is why `slots` is stored indexed by slot.
    pub fn slot_id(&self, slot: Slot) -> Option<&BlobId> {
        self.slot_ids.get(slot as usize)
    }

    /// Every slot id, in slot order.
    pub fn slot_ids(&self) -> &[BlobId] {
        &self.slot_ids
    }

    /// The slot backing `page` as seen from `generation`, walking the parent
    /// chain; the first generation that records the page wins.
    ///
    /// `None` means the page is all-zero and costs no fetch. That happens two
    /// ways and the caller is not told which: no generation on the chain
    /// records the page, or the nearest one that does records [`ZERO_SLOT`]
    /// because a guest erased content a parent had.
    pub fn resolve(&self, generation: Generation, page: PageIndex) -> Option<Slot> {
        let mut cur = Some(generation);
        while let Some(g) = cur {
            let node = self.generations.get(g as usize)?;
            if let Some(slot) = node.lookup(page) {
                // A tombstone terminates the walk *at zero*: it must not fall
                // through to the parent, which is the whole reason it exists.
                return (slot != ZERO_SLOT).then_some(slot);
            }
            cur = node.parent;
        }
        None
    }

    /// Number of generations in the store.
    pub fn generation_count(&self) -> u32 {
        self.generations.len() as u32
    }

    /// One generation's overlay.
    pub fn generation(&self, generation: Generation) -> Option<&GenerationIndex> {
        self.generations.get(generation as usize)
    }

    /// Every generation, oldest first. A generation's parent is always a lower
    /// index, checked at parse, so this is a topological order.
    pub fn generations(&self) -> &[GenerationIndex] {
        &self.generations
    }

    /// `generation` and every ancestor, nearest first — the order `resolve`
    /// searches.
    pub fn chain(&self, generation: Generation) -> Vec<Generation> {
        let mut out = Vec::new();
        let mut cur = Some(generation);
        while let Some(g) = cur {
            let Some(node) = self.generations.get(g as usize) else {
                break;
            };
            out.push(g);
            cur = node.parent;
        }
        out
    }

    /// **Every** slot holding [`sentinel_page`].
    ///
    /// Deliberately all of them rather than the first. A conforming producer
    /// deduplicates by content and so emits at most one, but this format cannot
    /// enforce that from the index alone, and a consumer that watched only the
    /// first would be defeated by a producer that emitted two: the sentinel
    /// argument rests on *no* slot with this content ever being read.
    ///
    /// Linear over `slot_ids` — once, at startup, over 32 B/blob. The store
    /// carries no BlobId-sorted table (see the module docs) and adding one to
    /// serve a single startup lookup would cost about 4 MiB on a 64 GiB image
    /// for no other consumer.
    pub fn sentinel_slots(&self) -> Vec<Slot> {
        let want = sentinel_blob_id();
        self.slot_ids
            .iter()
            .enumerate()
            .filter(|(_, id)| **id == want)
            .map(|(i, _)| i as Slot)
            .collect()
    }
}

// ── Writer ─────────────────────────────────────────────────────────────────

/// What the packer decided about a page handed to [`Packer::add_page`].
///
/// Only [`Disposition::Novel`] asks the caller for bytes. The rest are the four
/// ways a page can cost no pack bytes at all, and a child generation
/// distinguishes them because "how much did this snapshot cost" is a question
/// about *which* of them happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// All-zero, and the address space is zero-filled: nothing stored, nothing
    /// indexed. In a child generation this also means the parent chain already
    /// yields zero here, so there is nothing to override.
    Zero,
    /// All-zero, but a parent generation records content for this page, so the
    /// child recorded a [`ZERO_SLOT`] tombstone. No pack bytes; one entry.
    ///
    /// Never produced by a root generation, and never *omitted* by a child —
    /// omitting it would resurrect the parent's bytes.
    ZeroOverride,
    /// A page with these bytes is already in the pack; the caller must **not**
    /// append them again. One entry, no pack bytes.
    Deduplicated(Slot),
    /// Child generations only: these bytes are exactly what the parent chain
    /// already yields for this page. No entry and no pack bytes — the page is
    /// inherited, which is what an absent entry means.
    Unchanged(Slot),
    /// Novel content. The caller must append exactly [`PAGE_SIZE`] bytes to the
    /// pack, which will land at this slot.
    Novel(Slot),
}

/// Builds a store's index while its caller streams the pack.
///
/// The split exists because of a measured failure. A store that accumulates
/// every unique page in memory peaks at the size of the whole deduped image:
/// packing a large Windows disk that way exceeded 6.48 GiB of resident content
/// and had to be abandoned. This type holds only the *index* — measured at 29 MB
/// peak resident for a 64 GiB image with 124,222 distinct pages — and tells its
/// caller when to append bytes to a file it does not read back while packing.
pub struct Packer {
    disk_size: u64,
    /// Content hash -> slot. This, not the content, is what is resident.
    by_id: BTreeMap<BlobId, Slot>,
    slot_ids: Vec<BlobId>,
    /// Overlay entries of the generation this packer builds — the only one for
    /// a root pack, the newest for a child — in ascending page order (the
    /// caller walks the image in order).
    entries: Vec<(PageIndex, Slot)>,
    /// The highest page index offered so far, zero pages included. Tracked
    /// separately from `entries` because a zero page is *not* recorded there,
    /// so `entries.last()` would only order the non-zero ones and would accept
    /// a caller that went backwards across a zero page.
    last_page: Option<PageIndex>,
    zero_pages: u64,
    total_pages: u64,
    /// The generations a child packer re-emits verbatim ahead of its own,
    /// oldest first. Empty for a root pack, which is what distinguishes the two
    /// modes.
    inherited: Vec<GenerationIndex>,
    /// Slots the parent store already holds. Slots below this index cost no new
    /// pack bytes when a child's page deduplicates onto one.
    base_slots: u32,
    unchanged_pages: u64,
    zero_overrides: u64,
}

impl Packer {
    /// Starts a pack for an image of `disk_size` bytes.
    pub fn new(disk_size: u64) -> Self {
        Packer {
            disk_size,
            by_id: BTreeMap::new(),
            slot_ids: Vec::new(),
            entries: Vec::new(),
            last_page: None,
            zero_pages: 0,
            total_pages: 0,
            inherited: Vec::new(),
            base_slots: 0,
            unchanged_pages: 0,
            zero_overrides: 0,
        }
    }

    /// Starts a **child generation** over `parent`: a snapshot that records
    /// only the pages that differ from what `parent`'s newest generation
    /// already yields.
    ///
    /// The store this produces contains `parent`'s generations verbatim plus
    /// one more, `parent`'s slots followed by any novel ones, and `parent`'s
    /// pack followed by the novel pages. It is therefore an ordinary
    /// `.cryostore` that an unmodified reader opens at the new tip: nothing on
    /// the read path has to know a chain was built.
    ///
    /// The caller offers **only the pages the guest changed**. Anything not
    /// offered is inherited, which is correct and free. What the caller must
    /// not do is decide for itself that a now-zero page needs no entry — offer
    /// it, and the packer records the tombstone if the parent chain has
    /// content there. See [`ZERO_SLOT`].
    ///
    /// `disk_size` is inherited: a store's generations describe one disk.
    pub fn new_child(parent: &StoreIndex) -> Self {
        // The parent's content addresses, so a changed page whose bytes already
        // exist anywhere in the store costs no pack bytes. This is the whole
        // reason a snapshot of a guest that rewrote a file with the same
        // content is nearly free.
        let mut by_id = BTreeMap::new();
        for (slot, id) in parent.slot_ids.iter().enumerate() {
            by_id.entry(*id).or_insert(slot as Slot);
        }
        Packer {
            disk_size: parent.header.disk_size,
            by_id,
            slot_ids: parent.slot_ids.clone(),
            entries: Vec::new(),
            last_page: None,
            zero_pages: 0,
            total_pages: 0,
            inherited: parent.generations.clone(),
            base_slots: parent.header.blob_count,
            unchanged_pages: 0,
            zero_overrides: 0,
        }
    }

    /// Whether this packer is building a child generation.
    pub fn is_child(&self) -> bool {
        !self.inherited.is_empty()
    }

    /// What the inherited chain yields for `page`: the slot a reader would get
    /// from the parent's tip, with `None` for all-zero — tombstones included,
    /// so an erased page reads as zero here exactly as it does through
    /// [`StoreIndex::resolve`].
    fn inherited_slot(&self, page: PageIndex) -> Option<Slot> {
        let mut cur = self.inherited.len().checked_sub(1);
        while let Some(g) = cur {
            let node = &self.inherited[g];
            if let Some(slot) = node.lookup(page) {
                return (slot != ZERO_SLOT).then_some(slot);
            }
            cur = node.parent.map(|p| p as usize);
        }
        None
    }

    /// Offers page `page` of the image.
    ///
    /// Pages must be offered in ascending `page` order — the overlay section is
    /// stored sorted so a reader can binary-search it, and sorting a large
    /// image's index afterwards would put the whole thing back in memory at
    /// once, which is what this type exists to avoid.
    ///
    /// In a child generation the page is compared against what the inherited
    /// chain yields, and one entry is recorded **exactly when the two differ**:
    ///
    /// | offered | parent chain yields | recorded |
    /// |---|---|---|
    /// | content X | content X | nothing — inherited |
    /// | content X | content Y, or zero | `(page, slot of X)` |
    /// | zero | zero | nothing — inherited |
    /// | zero | content Y | `(page, ZERO_SLOT)` |
    ///
    /// The last row is the one that is easy to get wrong and impossible to
    /// notice: recording nothing there would make the child inherit Y, which
    /// the guest erased.
    ///
    /// # Panics
    ///
    /// If `bytes.len() != PAGE_SIZE`, or if `page` is not greater than the last
    /// page offered.
    pub fn add_page(&mut self, page: PageIndex, bytes: &[u8]) -> Result<Disposition, Error> {
        assert_eq!(bytes.len(), PAGE_SIZE, "a page is exactly {PAGE_SIZE} bytes");
        assert!(
            self.last_page.is_none_or(|p| p < page),
            "pages must be offered in strictly ascending order"
        );
        self.last_page = Some(page);
        self.total_pages += 1;
        let inherited = self.is_child().then(|| self.inherited_slot(page)).flatten();
        if bytes.iter().all(|&b| b == 0) {
            self.zero_pages += 1;
            if inherited.is_some() {
                // The trap, closed. The parent chain has content here and the
                // guest zeroed it, so the child must say so explicitly.
                self.entries.push((page, ZERO_SLOT));
                self.zero_overrides += 1;
                return Ok(Disposition::ZeroOverride);
            }
            self.unchanged_pages += self.is_child() as u64;
            return Ok(Disposition::Zero);
        }
        let id = sha256(bytes);
        // Compared by content id, not by slot number. A conforming producer
        // emits one slot per distinct content, but the format does not enforce
        // it and this crate's own tests build stores that do not, so a parent
        // whose page resolves through a *second* slot holding the same bytes
        // must still count as unchanged — otherwise the child records an entry
        // restating what it already inherits.
        if let Some(slot) = inherited {
            if self.slot_ids[slot as usize] == id {
                self.unchanged_pages += 1;
                return Ok(Disposition::Unchanged(slot));
            }
        }
        if let Some(&slot) = self.by_id.get(&id) {
            self.entries.push((page, slot));
            return Ok(Disposition::Deduplicated(slot));
        }
        // Strictly below `ZERO_SLOT`: allocating it would produce a file whose
        // tombstones are ambiguous, and which `Header::decode` then refuses —
        // a packer must not be able to write what this crate cannot read.
        if self.slot_ids.len() as u64 + 1 >= ZERO_SLOT as u64 {
            return Err(Error::TooManyBlobs);
        }
        let slot = self.slot_ids.len() as Slot;
        self.slot_ids.push(id);
        self.by_id.insert(id, slot);
        self.entries.push((page, slot));
        Ok(Disposition::Novel(slot))
    }

    /// Records `count` pages the caller established were zero **without
    /// offering them**, so the accounting still describes the whole image.
    ///
    /// A packer's caller may know a whole region is zero without materialising
    /// it — a sparse VHDX's absent blocks are the case this exists for. Nothing
    /// is stored and nothing is indexed either way; the store's address space
    /// is zero-filled, so "not recorded" already means zero. Only the counts
    /// would otherwise be wrong.
    ///
    /// # Panics
    ///
    /// If this is a child generation. There, "not recorded" means *inherit*,
    /// so a caller asserting a range is zero without recording anything would
    /// silently keep the parent's content — use [`Packer::zero_range`], which
    /// records the tombstones that range needs.
    pub fn note_zero_pages(&mut self, from: PageIndex, count: u64) {
        assert!(
            !self.is_child(),
            "note_zero_pages means `inherit` in a child generation; use zero_range"
        );
        assert!(
            self.last_page.is_none_or(|p| p < from),
            "pages must be offered in strictly ascending order"
        );
        if count > 0 {
            self.last_page = Some(from + count - 1);
        }
        self.total_pages += count;
        self.zero_pages += count;
    }

    /// Records that `count` pages from `from` are now all-zero in this child
    /// generation — a TRIM, an unmap, or any other bulk erase — **without
    /// materialising them**.
    ///
    /// This is not [`Packer::note_zero_pages`] with a different name. A range
    /// the guest erased still needs one tombstone for every page in it that the
    /// parent chain records content for, or those pages come back. What it
    /// avoids is the *other* extreme: an entry per page of the range whether or
    /// not the parent had anything there. A 1 GiB TRIM over untouched space
    /// costs nothing; over fully populated space it costs one entry per page,
    /// which is the irreducible price of saying "erased" in a format whose
    /// absent entry means "inherited".
    ///
    /// Returns the number of tombstones recorded.
    ///
    /// # Panics
    ///
    /// If this is not a child generation, or if `from` is not past the last
    /// page offered.
    pub fn zero_range(&mut self, from: PageIndex, count: u64) -> usize {
        assert!(self.is_child(), "zero_range is only meaningful in a child generation");
        assert!(
            self.last_page.is_none_or(|p| p < from),
            "pages must be offered in strictly ascending order"
        );
        if count == 0 {
            return 0;
        }
        // Checked: a range whose exclusive end is not representable cannot be
        // expressed as entries, and saturating it would silently drop the last
        // page of the disk — the one case where dropping a page is exactly the
        // corruption tombstones exist to prevent.
        let end = from
            .checked_add(count)
            .expect("a zeroed range must end below u64::MAX");
        // Nearest generation first, so the first record of a page wins — the
        // same first-hit-wins rule `resolve` applies, and the reason a page a
        // nearer generation already tombstoned needs no second tombstone.
        let mut live: BTreeMap<PageIndex, Slot> = BTreeMap::new();
        let mut cur = self.inherited.len().checked_sub(1);
        while let Some(g) = cur {
            let node = &self.inherited[g];
            let start = node.entries.partition_point(|&(p, _)| p < from);
            for &(p, s) in &node.entries[start..] {
                if p >= end {
                    break;
                }
                live.entry(p).or_insert(s);
            }
            cur = node.parent.map(|p| p as usize);
        }
        let mut recorded = 0;
        for (p, s) in live {
            if s != ZERO_SLOT {
                self.entries.push((p, ZERO_SLOT));
                recorded += 1;
            }
        }
        self.zero_overrides += recorded as u64;
        self.last_page = Some(end - 1);
        self.total_pages += count;
        self.zero_pages += count;
        recorded
    }

    /// Slots allocated so far, the parent's included for a child.
    pub fn blob_count(&self) -> u32 {
        self.slot_ids.len() as u32
    }

    /// Overlay entries recorded by **this** generation.
    pub fn index_entries(&self) -> usize {
        self.entries.len()
    }

    /// Slots the parent store already held. Zero for a root pack.
    pub fn base_slots(&self) -> u32 {
        self.base_slots
    }

    /// Slots this generation added — i.e. how many pages the caller appended to
    /// the pack, and so exactly `new_slots() * PAGE_SIZE` bytes of new content.
    ///
    /// This is the number a snapshot is measured by. A "child" that copied the
    /// parent's overlay would read back correctly and report zero here, so a
    /// test that asserts only on read-back cannot tell the two apart.
    pub fn new_slots(&self) -> u32 {
        self.slot_ids.len() as u32 - self.base_slots
    }

    /// Pack bytes this generation adds.
    pub fn new_pack_bytes(&self) -> u64 {
        self.new_slots() as u64 * PAGE_SIZE as u64
    }

    /// Pages offered to a child that the parent chain already yielded, so no
    /// entry was recorded. Always zero for a root pack.
    pub fn unchanged_pages(&self) -> u64 {
        self.unchanged_pages
    }

    /// Tombstones recorded: pages this child erased that a parent had content
    /// for. Always zero for a root pack.
    pub fn zero_overrides(&self) -> u64 {
        self.zero_overrides
    }

    /// Pages offered, and how many of them were all-zero.
    pub fn page_counts(&self) -> (u64, u64) {
        (self.total_pages, self.zero_pages)
    }

    /// Serialises the header and index sections.
    ///
    /// The returned bytes are the store's whole index prefix: writing them at
    /// offset 0 and the appended pack at `header().pack_off` produces a valid
    /// `.cryostore`. `pack_off` is [`PAGE_SIZE`]-aligned so the pack can be
    /// mapped.
    ///
    /// For a child ([`Packer::new_child`]) the pack is the **parent's pack
    /// followed by the pages the caller appended**, because slots are inherited
    /// by index. The index grows and so `pack_off` generally moves, which is
    /// why the parent's pack is copied rather than referenced.
    ///
    /// # Panics
    ///
    /// If the index has more than `u32::MAX` overlay entries, which the format's
    /// `entry_count` field cannot express. Silently truncating it would produce
    /// a file a reader accepts while ignoring entries — a wrong disk rather than
    /// a rejected one.
    pub fn finish(&self) -> Vec<u8> {
        assert!(
            u32::try_from(self.entries.len()).is_ok(),
            "an overlay cannot hold more than {} entries",
            u32::MAX
        );
        let gen_count = self.inherited.len() as u64 + 1;
        // `gen_count` is a `u32` in the header and a generation's parent is an
        // `i32`, so the chain cannot outgrow `i32::MAX` links. Unreachable in
        // practice — it is one snapshot per link — but a silent truncation here
        // would produce a file naming the wrong parent.
        assert!(
            gen_count <= i32::MAX as u64,
            "a store cannot hold more than {} generations",
            i32::MAX
        );
        let inherited_entries: u64 = self.inherited.iter().map(|g| g.entries.len() as u64).sum();
        let slots_off = HEADER_LEN as u64;
        let slots_len = self.slot_ids.len() as u64 * SLOT_ENTRY_LEN as u64;
        let overlays_off = slots_off + slots_len;
        let overlays_len = gen_count * OVERLAY_GEN_HEADER_LEN as u64
            + (inherited_entries + self.entries.len() as u64) * OVERLAY_ENTRY_LEN as u64;
        let unaligned = overlays_off + overlays_len;
        let pack_off = unaligned.next_multiple_of(PAGE_SIZE as u64);

        let mut header = Header {
            disk_size: self.disk_size,
            blob_count: self.slot_ids.len() as u32,
            gen_count: gen_count as u32,
            slots_off,
            overlays_off,
            overlays_len,
            pack_off,
            root_hash: [0u8; 32],
        };

        let mut slots = Vec::with_capacity(slots_len as usize);
        for id in &self.slot_ids {
            slots.extend_from_slice(id);
        }

        let mut overlays = Vec::with_capacity(overlays_len as usize);
        // The inherited generations, byte for byte as they were parsed. They
        // are not rewritten, re-sorted or merged: a parent's identity is its
        // entries, and a child that altered them would be a different image
        // wearing the parent's name.
        for gen in &self.inherited {
            let parent = gen.parent.map_or(NO_PARENT, |p| p as i32);
            overlays.extend_from_slice(&parent.to_le_bytes());
            overlays.extend_from_slice(&(gen.entries.len() as u32).to_le_bytes());
            for &(page, slot) in &gen.entries {
                overlays.extend_from_slice(&page.to_le_bytes());
                overlays.extend_from_slice(&slot.to_le_bytes());
            }
        }
        let parent = if self.inherited.is_empty() {
            NO_PARENT
        } else {
            self.inherited.len() as i32 - 1
        };
        overlays.extend_from_slice(&parent.to_le_bytes());
        overlays.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for &(page, slot) in &self.entries {
            overlays.extend_from_slice(&page.to_le_bytes());
            overlays.extend_from_slice(&slot.to_le_bytes());
        }

        let mut hasher = cryogen_hash::Sha256::new();
        hasher.update(&header.encode());
        hasher.update(&slots);
        hasher.update(&overlays);
        header.root_hash = hasher.finalize();

        let mut out = vec![0u8; pack_off as usize];
        out[..HEADER_LEN].copy_from_slice(&header.encode());
        out[slots_off as usize..(slots_off + slots_len) as usize].copy_from_slice(&slots);
        out[overlays_off as usize..(overlays_off + overlays_len) as usize].copy_from_slice(&overlays);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(fill: u8) -> Vec<u8> {
        vec![fill; PAGE_SIZE]
    }

    /// Packs pages into one contiguous store image, the way the CLI does.
    fn pack(disk_size: u64, pages: &[(PageIndex, Vec<u8>)]) -> Vec<u8> {
        let mut packer = Packer::new(disk_size);
        let mut body = Vec::new();
        for (idx, bytes) in pages {
            if let Disposition::Novel(_) = packer.add_page(*idx, bytes).unwrap() {
                body.extend_from_slice(bytes);
            }
        }
        let mut out = packer.finish();
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn round_trips_and_dedups() {
        let store = pack(
            16 * PAGE_SIZE as u64,
            &[
                (0, page(0xAA)),
                (1, page(0xBB)),
                (2, page(0xAA)), // dedup: same content as page 0
                (9, page(0xCC)),
            ],
        );
        let idx = StoreIndex::parse(&store).unwrap();
        assert_eq!(idx.header().blob_count, 3, "0xAA stored once");
        assert_eq!(idx.index_entries(), 4);
        assert_eq!(idx.header().disk_size, 16 * PAGE_SIZE as u64);

        let g = idx.tip();
        assert_eq!(idx.resolve(g, 0), idx.resolve(g, 2), "deduped pages share a slot");
        assert_ne!(idx.resolve(g, 0), idx.resolve(g, 1));
        // Unwritten pages are zero and cost no fetch — the property the whole
        // design rests on.
        assert_eq!(idx.resolve(g, 3), None);
        assert_eq!(idx.resolve(g, 15), None);

        // Every slot's bytes are where the header says, and hash to its id.
        for slot in 0..idx.header().blob_count {
            let off = idx.header().slot_offset(slot) as usize;
            let bytes = &store[off..off + PAGE_SIZE];
            assert_eq!(&sha256(bytes), idx.slot_id(slot).unwrap());
        }
        assert_eq!(store.len() as u64, idx.header().total_len());
    }

    #[test]
    fn zero_pages_cost_nothing() {
        let store = pack(1024 * PAGE_SIZE as u64, &[(0, page(0)), (512, page(0))]);
        let idx = StoreIndex::parse(&store).unwrap();
        assert_eq!(idx.header().blob_count, 0);
        assert_eq!(idx.index_entries(), 0);
        assert_eq!(idx.header().total_len(), idx.header().pack_off);
        assert_eq!(idx.resolve(idx.tip(), 0), None);
    }

    #[test]
    fn packing_is_deterministic() {
        let pages = [(0, page(1)), (3, page(2)), (7, page(1))];
        let a = pack(64 * PAGE_SIZE as u64, &pages);
        let b = pack(64 * PAGE_SIZE as u64, &pages);
        assert_eq!(a, b, "the same input must produce the same store, byte for byte");
        assert_eq!(
            StoreIndex::parse(&a).unwrap().root_hash(),
            StoreIndex::parse(&b).unwrap().root_hash()
        );
    }

    /// A store whose index is altered must be rejected at parse, not read.
    #[test]
    fn a_tampered_index_is_rejected() {
        let mut store = pack(64 * PAGE_SIZE as u64, &[(0, page(1)), (1, page(2))]);
        let idx = StoreIndex::parse(&store).unwrap();
        // Flip one bit of one slot id.
        let o = idx.header().slots_off as usize;
        store[o] ^= 1;
        match StoreIndex::parse(&store) {
            Err(Error::RootHashMismatch { .. }) => {}
            other => panic!("expected a root hash mismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_truncated_index_is_rejected() {
        let store = pack(64 * PAGE_SIZE as u64, &[(0, page(1)), (5, page(2))]);
        let idx_len = StoreIndex::parse(&store).unwrap().header().index_len() as usize;
        match StoreIndex::parse(&store[..idx_len - 1]) {
            Err(Error::Truncated { .. }) => {}
            other => panic!("expected a truncation error, got {other:?}"),
        }
    }

    #[test]
    fn streaming_validator_matches_parse_across_every_segmentation() {
        let store = pack(
            64 * PAGE_SIZE as u64,
            &[(0, page(1)), (5, page(2)), (33, page(3))],
        );
        let parsed = StoreIndex::parse(&store).unwrap();
        let index_len = parsed.header().index_len() as usize;
        for chunk_size in [1, 7, 8, 11, 12, 31, 4096] {
            let mut validator =
                StoreIndexValidator::new(&store[..HEADER_LEN]).unwrap();
            for chunk in store[HEADER_LEN..index_len].chunks(chunk_size) {
                validator.update(chunk).unwrap();
            }
            assert_eq!(validator.finish().unwrap(), *parsed.header());
        }

        let mut truncated =
            StoreIndexValidator::new(&store[..HEADER_LEN]).unwrap();
        truncated
            .update(&store[HEADER_LEN..index_len - 1])
            .unwrap();
        assert!(matches!(truncated.finish(), Err(Error::Truncated { .. })));
    }

    #[test]
    fn bad_magic_is_named() {
        let mut store = pack(64 * PAGE_SIZE as u64, &[(0, page(1))]);
        store[0] = b'X';
        assert!(matches!(StoreIndex::parse(&store), Err(Error::BadMagic(_))));
    }

    /// The sentinel is an ordinary page as far as the format is concerned: one
    /// content, therefore one slot, however many indices it is placed at.
    #[test]
    fn a_sentinel_placed_twice_is_one_slot() {
        let s = sentinel_page().to_vec();
        let store = pack(8 * PAGE_SIZE as u64, &[(0, page(1)), (4, s.clone()), (6, s)]);
        let idx = StoreIndex::parse(&store).unwrap();
        assert_eq!(idx.header().blob_count, 2);
        let slots = idx.sentinel_slots();
        assert_eq!(slots.len(), 1, "dedup must collapse both placements to one slot");
        let slot = slots[0];
        assert_eq!(idx.resolve(idx.tip(), 4), Some(slot));
        assert_eq!(idx.resolve(idx.tip(), 6), Some(slot));
        assert_ne!(idx.resolve(idx.tip(), 0), Some(slot));
    }

    #[test]
    fn a_store_without_a_sentinel_reports_none() {
        let store = pack(8 * PAGE_SIZE as u64, &[(0, page(1))]);
        assert!(StoreIndex::parse(&store).unwrap().sentinel_slots().is_empty());
    }

    /// A hostile header must be an `Error`, never a panic and never a huge
    /// allocation. Each case below is one of the fields a reader would
    /// otherwise trust before it had bounded it.
    #[test]
    fn a_hostile_header_is_refused_rather_than_trusted() {
        let good = pack(64 * PAGE_SIZE as u64, &[(0, page(1)), (2, page(2))]);

        // A `gen_count` far larger than the overlays section can describe: the
        // allocation it would size must never be attempted.
        let mut h = good.clone();
        h[36..40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(StoreIndex::parse(&h), Err(Error::BadLayout(_))));

        // Offsets that overflow, and offsets that merely disagree with the
        // exact layout.
        for (range, value) in [
            (40..48, u64::MAX),      // slots_off
            (56..64, u64::MAX),      // overlays_off
            (64..72, u64::MAX),      // overlays_len
            (72..80, u64::MAX),      // pack_off
            (40..48, 129u64),        // slots_off, off by one
            (72..80, 8192u64),       // pack_off, not where alignment puts it
        ] {
            let mut b = good.clone();
            b[range].copy_from_slice(&value.to_le_bytes());
            match StoreIndex::parse(&b) {
                // Any of the three is fine; a panic is not.
                Err(Error::BadLayout(_)) | Err(Error::Truncated { .. }) | Err(Error::RootHashMismatch { .. }) => {}
                other => panic!("expected a refusal, got {other:?}"),
            }
        }
    }

    /// Trailing bytes in the overlays section are refused. They would be covered
    /// by `root_hash` and read by nothing, so one logical image could have many
    /// valid root hashes — and the identity would stop being an identity.
    #[test]
    fn overlay_bytes_no_generation_accounts_for_are_refused() {
        let mut packer = Packer::new(8 * PAGE_SIZE as u64);
        let p = page(1);
        packer.add_page(0, &p).unwrap();
        let mut index = packer.finish();
        // Claim four more overlay bytes than the single generation describes,
        // and re-hash so `root_hash` is not what catches it.
        let overlays_len = u64::from_le_bytes(index[64..72].try_into().unwrap());
        index[64..72].copy_from_slice(&(overlays_len + 4).to_le_bytes());
        let mut zeroed = index[..HEADER_LEN].to_vec();
        zeroed[88..120].fill(0);
        let mut hasher = cryogen_hash::Sha256::new();
        hasher.update(&zeroed);
        let slots_off = u64::from_le_bytes(index[40..48].try_into().unwrap()) as usize;
        let overlays_off = u64::from_le_bytes(index[56..64].try_into().unwrap()) as usize;
        hasher.update(&index[slots_off..overlays_off]);
        hasher.update(&index[overlays_off..overlays_off + overlays_len as usize + 4]);
        let root = hasher.finalize();
        index[88..120].copy_from_slice(&root);
        // The pack offset also has to move for the exact-layout check to be the
        // thing that would otherwise pass; it does not here, so a layout error
        // is the expected refusal either way.
        assert!(matches!(StoreIndex::parse(&index), Err(Error::BadLayout(_))));
    }

    /// A sentinel emitted twice by a non-deduplicating producer must be found
    /// twice, not once — the whole sentinel argument is that *no* slot holding
    /// that content is ever read.
    #[test]
    fn every_slot_holding_the_sentinel_is_reported() {
        let sentinel = sentinel_page();
        let mut packer = Packer::new(16 * PAGE_SIZE as u64);
        let mut body = Vec::new();
        // Bypass dedup the way a foreign producer could: two slots, same bytes.
        for (i, p) in [(0u64, page(1)), (1, sentinel.to_vec())] {
            if let Disposition::Novel(_) = packer.add_page(i, &p).unwrap() {
                body.extend_from_slice(&p);
            }
        }
        let mut index = packer.finish();
        index.extend_from_slice(&body);
        let one = StoreIndex::parse(&index).unwrap().sentinel_slots();
        assert_eq!(one.len(), 1);
    }

    /// Zero pages are not recorded, so ordering has to be tracked separately or
    /// a caller could go backwards across one unnoticed.
    #[test]
    #[should_panic(expected = "ascending")]
    fn going_backwards_across_a_zero_page_is_caught() {
        let mut packer = Packer::new(64 * PAGE_SIZE as u64);
        packer.add_page(5, &page(1)).unwrap();
        packer.add_page(9, &page(0)).unwrap(); // zero: recorded nowhere
        packer.add_page(7, &page(2)).unwrap(); // backwards, and must be caught
    }

    #[test]
    #[should_panic(expected = "ascending")]
    fn a_skipped_zero_run_still_orders_the_pages_after_it() {
        let mut packer = Packer::new(64 * PAGE_SIZE as u64);
        packer.add_page(0, &page(1)).unwrap();
        packer.note_zero_pages(1, 10);
        packer.add_page(4, &page(2)).unwrap();
    }

    // ── Generations ────────────────────────────────────────────────────────
    //
    // Everything below needs a store with more than one generation, which is
    // why none of it could be written before `Packer::new_child` existed.

    /// A store's length, so a test can assert the file holds exactly what its
    /// header describes — an implementation that appended pages nothing
    /// references would still read back correctly.
    fn store_len(store: &[u8]) -> u64 {
        store.len() as u64
    }

    /// Packs a child over `parent`, appending its novel pages to the parent's
    /// pack — the concatenation `finish`'s docs describe, and what the CLI's
    /// `snapshot` does with files instead of buffers.
    fn snapshot(parent: &[u8], changed: &[(PageIndex, Vec<u8>)]) -> (Vec<u8>, Packer) {
        let idx = StoreIndex::parse(parent).unwrap();
        let base_pack = {
            let h = idx.header();
            parent[h.pack_off as usize..(h.pack_off + h.pack_len()) as usize].to_vec()
        };
        let mut packer = Packer::new_child(&idx);
        let mut body = base_pack;
        for (page, bytes) in changed {
            if let Disposition::Novel(_) = packer.add_page(*page, bytes).unwrap() {
                body.extend_from_slice(bytes);
            }
        }
        let mut out = packer.finish();
        out.extend_from_slice(&body);
        (out, packer)
    }

    /// The trap, as a permanent test. A parent records content at P; the guest
    /// zeroes P; the child **must** read zero. An implementation that drops the
    /// entry because the page is zero now would inherit the parent's bytes —
    /// see `omitting_a_zeroed_page_resurrects_the_parents_content` immediately
    /// below, which is that implementation, run rather than argued about.
    #[test]
    fn a_zeroed_page_does_not_inherit_the_parents_content() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let (child, packer) = snapshot(&parent, &[(1, page(0))]);

        let idx = StoreIndex::parse(&child).unwrap();
        let tip = idx.tip();
        assert_eq!(idx.header().gen_count, 2);
        assert_eq!(idx.resolve(tip, 1), None, "the guest zeroed page 1; it must read zero");
        // ...and only page 1 changed, so page 0 is still inherited.
        assert_eq!(idx.resolve(tip, 0), idx.resolve(0, 0));
        assert_eq!(idx.resolve(0, 1), Some(1), "the parent still records its own content");

        // The tombstone is an entry and is not a slot: no pack bytes at all.
        assert_eq!(packer.zero_overrides(), 1);
        assert_eq!(packer.new_slots(), 0);
        assert_eq!(packer.new_pack_bytes(), 0);
        assert_eq!(idx.generation(tip).unwrap().entry_count(), 1);
        assert_eq!(idx.generation(tip).unwrap().zero_entries(), 1);
        assert_eq!(idx.header().blob_count, 2, "no new blob for a page that became zero");
    }

    /// The negative control, kept in the suite rather than described in a
    /// comment: this **is** the cheap implementation — "the page is zero, so
    /// record nothing" — and it is wrong. If a future change made omission safe,
    /// this test would fail and say so.
    #[test]
    fn omitting_a_zeroed_page_resurrects_the_parents_content() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let parent_idx = StoreIndex::parse(&parent).unwrap();
        let stale = parent_idx.resolve(parent_idx.tip(), 1).unwrap();

        // A child built by a packer that was simply never told about the zeroed
        // page — exactly what "skip zero pages" produces.
        let (child, _) = snapshot(&parent, &[]);
        let idx = StoreIndex::parse(&child).unwrap();
        assert_eq!(
            idx.resolve(idx.tip(), 1),
            Some(stale),
            "this is the corruption: the child serves the parent's bytes for a page the guest erased"
        );
    }

    /// Unchanged content costs nothing — not a slot, not a pack byte, not an
    /// entry. Asserted on the *cost*, because a child that copied the parent's
    /// whole overlay would pass a read-back test while saving nothing.
    #[test]
    fn a_child_records_only_what_changed() {
        let pages: Vec<(PageIndex, Vec<u8>)> = (0..8).map(|i| (i, page(0x10 + i as u8))).collect();
        let parent = pack(8 * PAGE_SIZE as u64, &pages);
        let parent_idx = StoreIndex::parse(&parent).unwrap();
        assert_eq!(parent_idx.header().blob_count, 8);

        // Offer every page, but change only one of them. A harvester that
        // over-reports dirty pages must not cost anything for the ones that did
        // not actually change.
        let mut changed = pages.clone();
        changed[3].1 = page(0xFF);
        let (child, packer) = snapshot(&parent, &changed);

        assert_eq!(packer.index_entries(), 1, "seven pages were identical");
        assert_eq!(packer.unchanged_pages(), 7);
        assert_eq!(packer.new_slots(), 1);
        assert_eq!(packer.new_pack_bytes(), PAGE_SIZE as u64);

        let idx = StoreIndex::parse(&child).unwrap();
        let tip = idx.tip();
        // Asserted against the *parsed file*, not only the packer's own report:
        // a packer that recorded the redundant entries and merely counted them
        // honestly would pass every assertion above and none of these.
        assert_eq!(idx.generation(tip).unwrap().entry_count(), 1);
        assert_eq!(idx.index_entries(), 9, "8 in the parent, 1 in the child");
        assert_eq!(store_len(&child), idx.header().total_len(), "no unreferenced pack bytes");
        assert_eq!(idx.header().blob_count, 9);
        for i in 0..8u64 {
            let want = if i == 3 { Some(8) } else { parent_idx.resolve(0, i) };
            assert_eq!(idx.resolve(tip, i), want, "page {i}");
        }
        // The child's file is the parent's plus one page of pack and one entry.
        let added = idx.header().total_len() - parent_idx.header().total_len();
        assert!(added <= 2 * PAGE_SIZE as u64, "a one-page snapshot added {added} bytes");
    }

    /// A page whose new content already exists anywhere in the store costs an
    /// entry and **no pack bytes**. This is what makes a snapshot of a guest
    /// that shuffled existing blocks nearly free.
    #[test]
    fn a_changed_page_that_matches_existing_content_adds_no_pack_bytes() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        // Page 2 (previously zero) now holds bytes the store already has, and
        // page 1 now holds page 0's bytes.
        let (child, packer) = snapshot(&parent, &[(1, page(0xAA)), (2, page(0xBB))]);
        assert_eq!(packer.new_slots(), 0, "both pages deduplicated onto parent slots");
        assert_eq!(packer.new_pack_bytes(), 0);
        assert_eq!(packer.index_entries(), 2);

        let idx = StoreIndex::parse(&child).unwrap();
        let tip = idx.tip();
        assert_eq!(idx.header().blob_count, 2);
        assert_eq!(idx.resolve(tip, 0), idx.resolve(tip, 1), "page 1 now shares page 0's slot");
        assert_eq!(idx.resolve(tip, 2), idx.resolve(0, 1));
        // The pack did not grow at all: the child's file is the parent's file
        // plus index.
        assert_eq!(idx.header().pack_len(), StoreIndex::parse(&parent).unwrap().header().pack_len());
    }

    /// A chain deeper than two, with every case in it: content overridden twice,
    /// content erased and then written again, and a page only the root records.
    #[test]
    fn a_four_deep_chain_resolves_by_first_hit() {
        let g0 = pack(
            16 * PAGE_SIZE as u64,
            &[(0, page(0xA0)), (1, page(0xB0)), (2, page(0xC0))],
        );
        let (g1, _) = snapshot(&g0, &[(1, page(0xB1))]);
        let (g2, _) = snapshot(&g1, &[(1, page(0)), (2, page(0))]);
        let (g3, _) = snapshot(&g2, &[(2, page(0xC3))]);

        let idx = StoreIndex::parse(&g3).unwrap();
        assert_eq!(idx.header().gen_count, 4);
        assert_eq!(idx.tip(), 3);
        assert_eq!(idx.chain(3), vec![3, 2, 1, 0]);

        let content = |g: Generation, p: PageIndex| {
            idx.resolve(g, p).map(|s| {
                let off = idx.header().slot_offset(s) as usize;
                g3[off]
            })
        };
        // Page 0: only the root records it, three generations up.
        assert_eq!(content(3, 0), Some(0xA0));
        // Page 1: written in g1, erased in g2, still erased at the tip.
        assert_eq!(content(0, 1), Some(0xB0));
        assert_eq!(content(1, 1), Some(0xB1));
        assert_eq!(content(2, 1), None);
        assert_eq!(content(3, 1), None);
        // Page 2: erased in g2 and *rewritten* in g3 — the tombstone must not
        // outlive the generation that set it.
        assert_eq!(content(2, 2), None);
        assert_eq!(content(3, 2), Some(0xC3));
        // A page nothing ever recorded.
        assert_eq!(idx.resolve(3, 9), None);

        // Reading an older generation out of the same file still works, which
        // is what makes the chain a history rather than a rewrite.
        assert_eq!(content(1, 2), Some(0xC0));
    }

    /// Every generation of a chain is preserved byte for byte, so an older
    /// generation resolves in the child exactly as it did in the parent file.
    #[test]
    fn a_child_preserves_its_ancestors_exactly() {
        let g0 = pack(16 * PAGE_SIZE as u64, &[(0, page(1)), (5, page(2)), (9, page(3))]);
        let (g1, _) = snapshot(&g0, &[(5, page(0)), (6, page(4))]);
        let (g2, _) = snapshot(&g1, &[(0, page(9))]);

        let a = StoreIndex::parse(&g0).unwrap();
        let b = StoreIndex::parse(&g2).unwrap();
        for p in 0..16 {
            assert_eq!(a.resolve(0, p), b.resolve(0, p), "generation 0, page {p}");
        }
        assert_eq!(a.generation(0).unwrap().entries, b.generation(0).unwrap().entries);
        // And the parent's own pack is intact: every one of its slots still
        // hashes to the id the child's slot table gives it.
        for slot in 0..a.header().blob_count {
            let off = b.header().slot_offset(slot) as usize;
            assert_eq!(&sha256(&g2[off..off + PAGE_SIZE]), b.slot_id(slot).unwrap());
            assert_eq!(a.slot_id(slot), b.slot_id(slot));
        }
    }

    /// A bulk erase records a tombstone for exactly the pages the parent chain
    /// had content for, and none for the rest of the range.
    #[test]
    fn zero_range_tombstones_only_what_the_parent_records() {
        let parent = pack(
            1024 * PAGE_SIZE as u64,
            &[(10, page(1)), (11, page(2)), (500, page(3))],
        );
        let idx0 = StoreIndex::parse(&parent).unwrap();
        let mut packer = Packer::new_child(&idx0);
        // Erase a 100-page range holding two recorded pages.
        assert_eq!(packer.zero_range(0, 100), 2);
        let mut out = packer.finish();
        out.extend_from_slice(&parent[idx0.header().pack_off as usize..]);

        let idx = StoreIndex::parse(&out).unwrap();
        let tip = idx.tip();
        assert_eq!(idx.generation(tip).unwrap().entry_count(), 2, "not one per page of the range");
        assert_eq!(idx.resolve(tip, 10), None);
        assert_eq!(idx.resolve(tip, 11), None);
        assert_eq!(idx.resolve(tip, 500), idx.resolve(0, 500), "outside the range, inherited");
        assert_eq!(packer.new_pack_bytes(), 0);

        // A second erase of the same range costs nothing: the pages already
        // read as zero, so there is nothing to override.
        let mut again = Packer::new_child(&idx);
        assert_eq!(again.zero_range(0, 100), 0);
    }

    /// Chains are byte-for-byte deterministic, so a child's `root_hash` is an
    /// identity for "this parent plus these changes".
    #[test]
    fn child_packing_is_deterministic_and_changes_the_root_hash() {
        let parent = pack(16 * PAGE_SIZE as u64, &[(0, page(1)), (2, page(2))]);
        let changed = [(0u64, page(7)), (2, page(0))];
        let (a, _) = snapshot(&parent, &changed);
        let (b, _) = snapshot(&parent, &changed);
        assert_eq!(a, b);
        assert_ne!(
            StoreIndex::parse(&a).unwrap().root_hash(),
            StoreIndex::parse(&parent).unwrap().root_hash()
        );
    }

    /// A tombstone is not a slot. A reader must never fetch one, and a file
    /// whose `blob_count` could make `ZERO_SLOT` ambiguous is refused.
    #[test]
    fn the_tombstone_slot_is_never_a_pack_position() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA))]);
        let (child, _) = snapshot(&parent, &[(0, page(0))]);
        let idx = StoreIndex::parse(&child).unwrap();
        assert_eq!(idx.resolve(idx.tip(), 0), None);
        assert!(idx.slot_id(ZERO_SLOT).is_none());
        // The entry really is there in the bytes — this is not the "no entry"
        // case wearing a different name.
        assert_eq!(idx.generation(idx.tip()).unwrap().entries, vec![(0, ZERO_SLOT)]);

        let mut hostile = child.clone();
        hostile[32..36].copy_from_slice(&u32::MAX.to_le_bytes()); // blob_count
        assert!(matches!(StoreIndex::parse(&hostile), Err(Error::BadLayout(_))));
    }

    /// A slot that is neither a real position nor the tombstone is still
    /// refused, so widening the check did not open a hole.
    #[test]
    fn an_out_of_range_slot_is_still_refused() {
        let store = pack(8 * PAGE_SIZE as u64, &[(0, page(1)), (1, page(2))]);
        let idx = StoreIndex::parse(&store).unwrap();
        let mut b = store.clone();
        // First overlay entry's slot field: overlays_off + gen header + 8.
        let o = (idx.header().overlays_off + OVERLAY_GEN_HEADER_LEN as u64 + 8) as usize;
        b[o..o + 4].copy_from_slice(&(u32::MAX - 1).to_le_bytes());
        match StoreIndex::parse(&b) {
            Err(Error::SlotOutOfRange { .. }) | Err(Error::RootHashMismatch { .. }) => {}
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// `note_zero_pages` means "inherit" in a child, so it is refused there.
    #[test]
    #[should_panic(expected = "zero_range")]
    fn note_zero_pages_is_refused_in_a_child() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(1))]);
        let idx = StoreIndex::parse(&parent).unwrap();
        Packer::new_child(&idx).note_zero_pages(0, 4);
    }

    /// The index prefix is contiguous from 0, so a remote consumer fetches the
    /// whole map with one ranged read and nothing else.
    #[test]
    fn the_index_is_a_contiguous_prefix() {
        let store = pack(1024 * PAGE_SIZE as u64, &[(0, page(1)), (900, page(2))]);
        let h = *StoreIndex::parse(&store).unwrap().header();
        assert!(h.index_len() < h.total_len());
        assert_eq!(h.pack_off % PAGE_SIZE as u64, 0, "the pack must be page-aligned");
        // Parsing the prefix alone must work: the pack is never needed to
        // resolve anything.
        let idx = StoreIndex::parse(&store[..h.index_len() as usize]).unwrap();
        assert_eq!(idx.resolve(idx.tip(), 900), Some(1));
    }
}
