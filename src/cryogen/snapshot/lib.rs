//! Admitting a scratch overlay to a `.cryostore` as a new generation.
//!
//! # The shape of the thing
//!
//! A packed disk image is inherently read-only: it is content-addressed, and a
//! page's address *is* the hash of its bytes, so there is nowhere to put a
//! changed byte. A running guest therefore writes into a scratch overlay
//! stacked above it, which is discarded when the guest shuts down. This crate
//! is the fourth case — the one where the scratch is **not** discarded, because
//! a snapshot was asked for, and its contents have to become a new generation.
//!
//! ```text
//!   scratch overlay (sectors the guest wrote)
//! + parent generation (what every other page reads as)
//! ------------------------------------------------------
//! = child generation: an entry per page that differs, and nothing else
//! ```
//!
//! # Sectors in, pages out
//!
//! The two halves disagree about granularity and neither can move: a guest's
//! sector is 512 bytes and the store's unit of deduplication is a 4096-byte
//! page. So a page with even one dirty sector has to be **reassembled** — the
//! dirty sectors from the scratch, the rest from the parent — before it can be
//! hashed, because a hash of seven parent sectors and one new one is not a hash
//! of anything either side holds. [`BaseImage`] is where those parent bytes
//! come from, and [`SnapshotStats::base_pages_read`] counts how often it was
//! needed: a page whose every sector was written costs no base read at all.
//!
//! # What this crate refuses to do
//!
//! It never scans the disk. A differential snapshot that read the whole image
//! and compared it against the parent would be correct and would defeat the
//! entire point — the cost of a snapshot must be proportional to what changed,
//! not to how big the disk is. Everything here is driven by the scratch's own
//! record of which sectors it holds.
//!
//! # The trap this crate is built around
//!
//! In the store's format, a page a child does not record is **inherited**, not
//! zero. So a page the guest *erased* must be recorded explicitly — see
//! `cryogen_format::ZERO_SLOT`. This crate never decides for itself that a
//! zeroed page needs no entry; it offers every dirty page to the packer, which
//! compares it against the parent chain and records the tombstone when one is
//! needed. The same applies to a region the scratch declares zero without
//! holding sectors for it ([`ScratchHeader::zero_from`]), which is handled by
//! `Packer::zero_range` rather than by silence.
//!
//! That second case has a sharp edge worth naming, because the first version of
//! this crate got it wrong: when the erased region *starts inside a page*, that
//! page has changed — its upper sectors went to zero — while appearing nowhere
//! in the scratch's sector list at all. A harvest driven only by the sectors an
//! overlay holds records nothing for it, and the child then serves the parent's
//! bytes where the guest sees zeros. It is offered explicitly; see
//! `pages_needing_base`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;

use cryogen_format::Disposition;
use cryogen_format::PAGE_SIZE;
use cryogen_format::PageIndex;
use cryogen_format::Packer;

/// The sector size a guest disk presents, and the unit a scratch overlay
/// records.
pub const SECTOR_SIZE: usize = 512;

/// Sectors per store page.
pub const SECTORS_PER_PAGE: u64 = PAGE_SIZE as u64 / SECTOR_SIZE as u64;

/// Magic of a scratch dump.
pub const SCRATCH_MAGIC: [u8; 8] = *b"CRYOSCR1";

/// Format version of a scratch dump.
pub const SCRATCH_VERSION: u32 = 1;

/// Bytes of scratch-dump header.
pub const SCRATCH_HEADER_LEN: usize = 40;

/// `zero_from`'s encoding for "no such boundary".
const NO_ZERO_FROM: u64 = u64::MAX;

// ── The scratch dump ───────────────────────────────────────────────────────

/// What a scratch overlay held when a snapshot was taken.
///
/// This is a container, not a disk: it holds *only* the sectors the overlay
/// actually has, in ascending order, which is the whole reason a snapshot can
/// cost less than a disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScratchHeader {
    /// Bytes per sector. Must be [`SECTOR_SIZE`]; carried explicitly so a dump
    /// written by something that disagreed is refused rather than misread.
    pub sector_size: u32,
    /// Logical size of the disk the overlay sat on, in bytes. Checked against
    /// the store being snapshotted, because a scratch from a different disk
    /// would otherwise produce a plausible and wrong generation.
    pub disk_size: u64,
    /// Number of sector records that follow.
    pub sector_count: u64,
    /// The sector at and above which an *absent* sector reads as zero rather
    /// than falling through to the image below — what a trailing unmap or a
    /// shrink leaves behind.
    ///
    /// `None` is the ordinary case: absent means "not written", so the image
    /// below shows through. When it is `Some`, absence above it means the guest
    /// sees zeros, and a child generation that stayed silent about that region
    /// would keep serving the parent's content. It is recorded because it is
    /// not otherwise recoverable from the sector list — the sectors are simply
    /// *gone* from the overlay.
    pub zero_from: Option<u64>,
}

/// Why a scratch dump could not be parsed or built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScratchError {
    /// The buffer is shorter than the structure it claims to hold.
    Truncated {
        /// Bytes needed.
        need: u64,
        /// Bytes available.
        have: u64,
    },
    /// The magic is not [`SCRATCH_MAGIC`].
    BadMagic([u8; 8]),
    /// The version is not [`SCRATCH_VERSION`].
    BadVersion(u32),
    /// The sector size is not [`SECTOR_SIZE`].
    BadSectorSize(u32),
    /// Sector records are not in strictly ascending order, so they cannot be
    /// walked into pages in one pass.
    Unsorted {
        /// The record that went backwards.
        sector: u64,
    },
    /// A record names a sector past the end of the disk.
    SectorOutOfRange {
        /// The offending sector.
        sector: u64,
        /// Sectors the disk has.
        sector_count: u64,
    },
    /// The disk size is zero or not a whole number of sectors.
    BadDiskSize(u64),
    /// The erased-tail boundary is past the end of the disk.
    BadZeroFrom {
        /// What the header says.
        zero_from: u64,
        /// Sectors the disk has.
        sector_count: u64,
    },
    /// The buffer has bytes after the last record.
    Trailing {
        /// How many.
        bytes: u64,
    },
}

impl core::fmt::Display for ScratchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ScratchError::Truncated { need, have } => {
                write!(f, "truncated scratch dump: need {need} bytes, have {have}")
            }
            ScratchError::BadMagic(m) => write!(f, "bad scratch magic {m:?}"),
            ScratchError::BadVersion(v) => write!(f, "unsupported scratch version {v}"),
            ScratchError::BadSectorSize(s) => {
                write!(f, "scratch sector size {s} is not the {SECTOR_SIZE} this build uses")
            }
            ScratchError::Unsorted { sector } => {
                write!(f, "scratch sector {sector} is not above the record before it")
            }
            ScratchError::SectorOutOfRange { sector, sector_count } => write!(
                f,
                "scratch names sector {sector} on a disk of {sector_count} sectors"
            ),
            ScratchError::BadDiskSize(d) => {
                write!(f, "scratch disk_size {d} is not a non-zero multiple of {SECTOR_SIZE}")
            }
            ScratchError::BadZeroFrom { zero_from, sector_count } => write!(
                f,
                "scratch erases from sector {zero_from} on a disk of {sector_count} sectors"
            ),
            ScratchError::Trailing { bytes } => {
                write!(f, "scratch dump has {bytes} bytes after its last record")
            }
        }
    }
}

/// A parsed scratch dump over a buffer.
///
/// Parsing validates the whole record list — ordering, range and length — so
/// everything downstream can walk it in one pass without re-checking.
#[derive(Debug, Clone)]
pub struct ScratchDump<'a> {
    header: ScratchHeader,
    records: &'a [u8],
}

impl<'a> ScratchDump<'a> {
    /// Parses a dump.
    pub fn parse(buf: &'a [u8]) -> Result<Self, ScratchError> {
        if buf.len() < SCRATCH_HEADER_LEN {
            return Err(ScratchError::Truncated {
                need: SCRATCH_HEADER_LEN as u64,
                have: buf.len() as u64,
            });
        }
        let magic: [u8; 8] = buf[0..8].try_into().unwrap();
        if magic != SCRATCH_MAGIC {
            return Err(ScratchError::BadMagic(magic));
        }
        let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
        if version != SCRATCH_VERSION {
            return Err(ScratchError::BadVersion(version));
        }
        let sector_size = u32::from_le_bytes(buf[12..16].try_into().unwrap());
        if sector_size as usize != SECTOR_SIZE {
            return Err(ScratchError::BadSectorSize(sector_size));
        }
        let disk_size = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        if disk_size == 0 || !disk_size.is_multiple_of(SECTOR_SIZE as u64) {
            return Err(ScratchError::BadDiskSize(disk_size));
        }
        let sector_count = u64::from_le_bytes(buf[24..32].try_into().unwrap());
        let zero_from = u64::from_le_bytes(buf[32..40].try_into().unwrap());
        let zero_from = (zero_from != NO_ZERO_FROM).then_some(zero_from);

        let disk_sectors = disk_size / SECTOR_SIZE as u64;
        if zero_from.is_some_and(|z| z > disk_sectors) {
            return Err(ScratchError::BadZeroFrom {
                zero_from: zero_from.unwrap(),
                sector_count: disk_sectors,
            });
        }
        let record_len = (SECTOR_SIZE + 8) as u64;
        // Checked, not saturating: a hostile `sector_count` saturating to
        // `u64::MAX` and then being added to would panic in a build with
        // overflow checks and wrap in one without.
        let need = sector_count
            .checked_mul(record_len)
            .and_then(|n| n.checked_add(SCRATCH_HEADER_LEN as u64))
            .ok_or(ScratchError::Truncated {
                need: u64::MAX,
                have: buf.len() as u64,
            })?;
        if (buf.len() as u64) < need {
            return Err(ScratchError::Truncated {
                need,
                have: buf.len() as u64,
            });
        }
        if buf.len() as u64 > need {
            return Err(ScratchError::Trailing {
                bytes: buf.len() as u64 - need,
            });
        }
        let records = &buf[SCRATCH_HEADER_LEN..];
        let mut prev: Option<u64> = None;
        for i in 0..sector_count as usize {
            let o = i * record_len as usize;
            let sector = u64::from_le_bytes(records[o..o + 8].try_into().unwrap());
            if prev.is_some_and(|p| p >= sector) {
                return Err(ScratchError::Unsorted { sector });
            }
            if sector >= disk_sectors {
                return Err(ScratchError::SectorOutOfRange {
                    sector,
                    sector_count: disk_sectors,
                });
            }
            prev = Some(sector);
        }
        Ok(ScratchDump {
            header: ScratchHeader {
                sector_size,
                disk_size,
                sector_count,
                zero_from,
            },
            records,
        })
    }

    /// The header.
    pub fn header(&self) -> &ScratchHeader {
        &self.header
    }

    /// Every recorded sector, ascending.
    pub fn sectors(&self) -> impl Iterator<Item = (u64, &'a [u8])> + '_ {
        let record_len = SECTOR_SIZE + 8;
        (0..self.header.sector_count as usize).map(move |i| {
            let o = i * record_len;
            let sector = u64::from_le_bytes(self.records[o..o + 8].try_into().unwrap());
            (sector, &self.records[o + 8..o + record_len])
        })
    }

    /// Sectors the disk has.
    pub fn disk_sectors(&self) -> u64 {
        self.header.disk_size / SECTOR_SIZE as u64
    }

    /// Pages the disk has, the last one partial if the disk is not a whole
    /// number of pages.
    pub fn disk_pages(&self) -> u64 {
        self.header.disk_size.div_ceil(PAGE_SIZE as u64)
    }
}

/// Serialises a scratch dump.
///
/// `sectors` must be ascending and each buffer exactly [`SECTOR_SIZE`] bytes;
/// the result is re-parsed by the caller in every path that matters, so a
/// violation is caught rather than written.
///
/// # Panics
///
/// If a sector buffer is not [`SECTOR_SIZE`] bytes.
pub fn encode_scratch<I, B>(header: &ScratchHeader, sectors: I) -> Vec<u8>
where
    I: IntoIterator<Item = (u64, B)>,
    B: AsRef<[u8]>,
{
    let mut out = Vec::with_capacity(
        SCRATCH_HEADER_LEN + header.sector_count as usize * (SECTOR_SIZE + 8),
    );
    out.extend_from_slice(&SCRATCH_MAGIC);
    out.extend_from_slice(&SCRATCH_VERSION.to_le_bytes());
    out.extend_from_slice(&(SECTOR_SIZE as u32).to_le_bytes());
    out.extend_from_slice(&header.disk_size.to_le_bytes());
    out.extend_from_slice(&header.sector_count.to_le_bytes());
    out.extend_from_slice(&header.zero_from.unwrap_or(NO_ZERO_FROM).to_le_bytes());
    let mut written = 0u64;
    for (sector, bytes) in sectors {
        let bytes = bytes.as_ref();
        assert_eq!(bytes.len(), SECTOR_SIZE, "a scratch record is exactly {SECTOR_SIZE} bytes");
        out.extend_from_slice(&sector.to_le_bytes());
        out.extend_from_slice(bytes);
        written += 1;
    }
    assert_eq!(
        written, header.sector_count,
        "the header's sector_count must match the records supplied"
    );
    out
}

// ── Admission ──────────────────────────────────────────────────────────────

/// The one page a bulk erase can change **without the scratch holding a single
/// sector of it**: the page the `zero_from` boundary falls inside.
///
/// Above the boundary its sectors read as zero; below it they still show the
/// image underneath. So it differs from the parent while appearing nowhere in
/// the scratch's sector list, and a harvest driven only by that list — the
/// obvious implementation — records nothing for it and lets the parent's bytes
/// show through where the guest sees zeros.
///
/// `None` when there is no boundary, when it is page-aligned (then the pages
/// above it are wholly erased and [`Packer::zero_range`] covers them), or when
/// it is at or past the end of the disk — a boundary at the end erases nothing,
/// even on a disk whose last page is partial and whose end therefore falls
/// mid-page.
fn boundary_page(dump: &ScratchDump<'_>) -> Option<PageIndex> {
    let z = dump.header().zero_from?;
    if z >= dump.disk_sectors() {
        return None;
    }
    (!z.is_multiple_of(SECTORS_PER_PAGE)).then(|| z / SECTORS_PER_PAGE)
}

/// The pages [`admit`] will ask [`BaseImage`] for, ascending: the dirty pages
/// the guest wrote only part of, plus the boundary page if there is one.
///
/// A caller whose base image is *asynchronous* — a page source over a network,
/// say — cannot implement [`BaseImage`] directly, so it asks for this first,
/// fetches those pages however it likes, and admits against what it fetched.
/// The rule is stated once, here, and used by `admit` itself, so the two cannot
/// drift apart: a page whose every missing sector is above the erased boundary
/// needs nothing, and a page written in full needs nothing.
pub fn pages_needing_base(dump: &ScratchDump<'_>) -> Vec<PageIndex> {
    let mut out = Vec::new();
    let mut current: Option<u64> = None;
    let mut present = [false; SECTORS_PER_PAGE as usize];
    let boundary = boundary_page(dump);
    let mut boundary_seen = false;
    let finish = |page: u64, present: &mut [bool; SECTORS_PER_PAGE as usize], out: &mut Vec<PageIndex>| {
        if needs_base(dump, page, present) {
            out.push(page);
        }
        present.fill(false);
    };
    for (sector, _) in dump.sectors() {
        let page = sector / SECTORS_PER_PAGE;
        if current != Some(page) {
            if let Some(prev) = current {
                finish(prev, &mut present, &mut out);
            }
            if let Some(b) = boundary {
                if b < page && !boundary_seen {
                    out.push(b);
                }
                boundary_seen |= b <= page;
            }
            current = Some(page);
        }
        present[(sector % SECTORS_PER_PAGE) as usize] = true;
    }
    if let Some(prev) = current {
        finish(prev, &mut present, &mut out);
    }
    if let Some(b) = boundary {
        if !boundary_seen {
            out.push(b);
        }
    }
    out
}

/// Whether any sector this page is missing would show the image below.
fn needs_base(
    dump: &ScratchDump<'_>,
    page: u64,
    present: &[bool; SECTORS_PER_PAGE as usize],
) -> bool {
    let first_sector = page * SECTORS_PER_PAGE;
    present.iter().enumerate().any(|(i, p)| {
        !*p && !dump
            .header()
            .zero_from
            .is_some_and(|z| first_sector + i as u64 >= z)
    })
}

/// The image a scratch overlay sat on: what a page reads as if the guest did
/// not write it.
///
/// This is the parent generation as a reader sees it, so an implementation over
/// a `.cryostore` resolves the page through the chain and reads the slot, and
/// an implementation inside a VMM asks its page source. A page no generation
/// records is all-zero, which every implementation must render as zeros rather
/// than failing.
pub trait BaseImage {
    /// What went wrong reading the base image.
    type Error;

    /// Fills `out` (exactly [`PAGE_SIZE`] bytes) with page `page`.
    fn read_page(&mut self, page: PageIndex, out: &mut [u8]) -> Result<(), Self::Error>;
}

/// What admitting a scratch cost, measured rather than described.
///
/// The fields that matter for "was this really differential" are
/// [`Self::new_pack_bytes`] and [`Self::entries_recorded`]: a child that copied
/// the parent's overlay reads back correctly and is caught by exactly these
/// two.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SnapshotStats {
    /// Sectors the scratch held.
    pub dirty_sectors: u64,
    /// Pages offered to the packer: those at least one held sector touched,
    /// plus the page an erase boundary fell inside if the scratch held none of
    /// it. Not every one of them turns out to have changed — see
    /// [`Self::unchanged_pages`].
    pub dirty_pages: u64,
    /// Pages that had to be reassembled from the parent because the guest wrote
    /// only part of them. A page written whole costs no base read.
    pub base_pages_read: u64,
    /// Overlay entries the child generation recorded.
    pub entries_recorded: usize,
    /// Slots added to the pack.
    pub new_slots: u32,
    /// Pack bytes added: `new_slots * PAGE_SIZE`.
    pub new_pack_bytes: u64,
    /// Dirty pages whose content turned out to equal what the parent already
    /// yields, so nothing was recorded for them.
    pub unchanged_pages: u64,
    /// Dirty pages whose content already existed in the store, so an entry was
    /// recorded and no pack bytes were added.
    pub deduplicated_pages: u64,
    /// Dirty pages with genuinely novel content.
    pub novel_pages: u64,
    /// Pages the guest erased that a parent generation had content for, each
    /// recorded as an explicit zero. Omitting these is the silent corruption
    /// this crate exists to prevent.
    pub zero_overrides: u64,
    /// Pages covered by a bulk erase ([`ScratchHeader::zero_from`]) rather than
    /// by a sector record.
    pub bulk_erased_pages: u64,
}

/// Why an admission failed.
#[derive(Debug)]
pub enum AdmitError<E> {
    /// The base image or the pack sink failed.
    Io(E),
    /// The packer refused the page.
    Format(cryogen_format::Error),
    /// The scratch does not describe the disk the parent store holds.
    DiskSizeMismatch {
        /// What the scratch says.
        scratch: u64,
        /// What the store says.
        store: u64,
    },
    /// The packer was not started with `Packer::new_child`.
    NotAChild,
}

impl<E: core::fmt::Display> core::fmt::Display for AdmitError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AdmitError::Io(e) => write!(f, "{e}"),
            AdmitError::Format(e) => write!(f, "{e}"),
            AdmitError::DiskSizeMismatch { scratch, store } => write!(
                f,
                "the scratch describes a {scratch}-byte disk and the store holds a {store}-byte one"
            ),
            AdmitError::NotAChild => {
                write!(f, "a snapshot must be packed with Packer::new_child")
            }
        }
    }
}

/// Admits `dump` to `packer` as the changed pages of a child generation.
///
/// `base` supplies the parent's bytes for the sectors of a partially written
/// page. `append` receives the bytes of each novel page, in slot order, and is
/// what the caller writes to the pack — the same contract
/// `cryogen_format::Disposition::Novel` has, kept here so a caller streams the
/// pack instead of accumulating it.
///
/// `disk_size` is the store's, and is checked against the scratch's: a scratch
/// harvested from a different disk would otherwise produce a generation that
/// parses, resolves, and is wrong.
pub fn admit<B, F, E>(
    packer: &mut Packer,
    dump: &ScratchDump<'_>,
    base: &mut B,
    mut append: F,
    disk_size: u64,
) -> Result<SnapshotStats, AdmitError<E>>
where
    B: BaseImage<Error = E>,
    F: FnMut(&[u8]) -> Result<(), E>,
{
    if !packer.is_child() {
        return Err(AdmitError::NotAChild);
    }
    if dump.header().disk_size != disk_size {
        return Err(AdmitError::DiskSizeMismatch {
            scratch: dump.header().disk_size,
            store: disk_size,
        });
    }

    let mut stats = SnapshotStats {
        dirty_sectors: dump.header().sector_count,
        ..SnapshotStats::default()
    };
    let disk_pages = dump.disk_pages();
    // The first page that is *entirely* inside the erased tail. A page the
    // boundary falls inside is not bulk-erased: its lower sectors still show
    // the image below, so it is handled as an ordinary page whose upper sectors
    // read as zero.
    let tail_start = dump
        .header()
        .zero_from
        .map_or(disk_pages, |z| z.div_ceil(SECTORS_PER_PAGE));

    let mut page_buf = [0u8; PAGE_SIZE];
    let mut current: Option<u64> = None;
    let mut present = [false; SECTORS_PER_PAGE as usize];
    // The next page the erased tail still owes a tombstone sweep for. Sweeping
    // in the gaps between dirty pages keeps every entry ascending, which the
    // packer requires.
    let mut swept = tail_start;

    let flush = |packer: &mut Packer,
                     page: u64,
                     buf: &mut [u8; PAGE_SIZE],
                     present: &mut [bool; SECTORS_PER_PAGE as usize],
                     base: &mut B,
                     append: &mut F,
                     stats: &mut SnapshotStats|
     -> Result<(), AdmitError<E>> {
        // Any sector the guest did not write is whatever the layer below shows
        // — the parent's page, or zeros if it is above the erased boundary.
        let missing = present.iter().filter(|p| !**p).count();
        if missing > 0 {
            let first_sector = page * SECTORS_PER_PAGE;
            let mut parent = [0u8; PAGE_SIZE];
            // The base is read only if some untouched sector actually shows it
            // through — a page whose gaps are all above the erased boundary is
            // assembled from zeros and costs nothing. Shared with
            // `pages_needing_base` so a caller that prefetched cannot be
            // surprised here.
            if needs_base(dump, page, present) {
                base.read_page(page, &mut parent).map_err(AdmitError::Io)?;
                stats.base_pages_read += 1;
            }
            for (i, p) in present.iter().enumerate() {
                if *p {
                    continue;
                }
                let sector = first_sector + i as u64;
                let above_boundary = dump.header().zero_from.is_some_and(|z| sector >= z);
                let lo = i * SECTOR_SIZE;
                if above_boundary {
                    buf[lo..lo + SECTOR_SIZE].fill(0);
                } else {
                    buf[lo..lo + SECTOR_SIZE].copy_from_slice(&parent[lo..lo + SECTOR_SIZE]);
                }
            }
        }
        stats.dirty_pages += 1;
        match packer.add_page(page, buf).map_err(AdmitError::Format)? {
            Disposition::Novel(_) => {
                stats.novel_pages += 1;
                append(buf).map_err(AdmitError::Io)?;
            }
            Disposition::Deduplicated(_) => stats.deduplicated_pages += 1,
            Disposition::Unchanged(_) => stats.unchanged_pages += 1,
            Disposition::ZeroOverride => stats.zero_overrides += 1,
            Disposition::Zero => stats.unchanged_pages += 1,
        }
        present.fill(false);
        Ok(())
    };

    // The page an unaligned erase boundary falls inside changes even if the
    // scratch holds no sector of it, so it is offered whether or not the sector
    // walk reaches it. It is offered *in page order* like everything else,
    // because the packer takes pages ascending.
    let boundary = boundary_page(dump);
    let mut boundary_done = false;

    for (sector, bytes) in dump.sectors() {
        let page = sector / SECTORS_PER_PAGE;
        if current != Some(page) {
            if let Some(prev) = current {
                flush(packer, prev, &mut page_buf, &mut present, base, &mut append, &mut stats)?;
            }
            if let Some(b) = boundary {
                if !boundary_done && b < page {
                    // No records at all for it: every sector below the boundary
                    // comes from the base and every sector above it is zero,
                    // which is exactly what `flush` does with an empty page.
                    page_buf.fill(0);
                    flush(packer, b, &mut page_buf, &mut present, base, &mut append, &mut stats)?;
                }
                boundary_done |= b <= page;
            }
            // Everything in the erased tail below this page is zero and holds no
            // sectors, so it is swept now, while its pages are still ahead of
            // the packer's cursor.
            if page > swept {
                let count = page - swept;
                let recorded = packer.zero_range(swept, count);
                stats.zero_overrides += recorded as u64;
                stats.bulk_erased_pages += count;
                swept = page;
            }
            page_buf.fill(0);
            current = Some(page);
        }
        if page >= swept {
            swept = page + 1;
        }
        let i = (sector % SECTORS_PER_PAGE) as usize;
        page_buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE].copy_from_slice(bytes);
        present[i] = true;
    }
    if let Some(prev) = current {
        flush(packer, prev, &mut page_buf, &mut present, base, &mut append, &mut stats)?;
    }
    if let Some(b) = boundary {
        if !boundary_done {
            page_buf.fill(0);
            flush(packer, b, &mut page_buf, &mut present, base, &mut append, &mut stats)?;
        }
    }
    if disk_pages > swept {
        let count = disk_pages - swept;
        let recorded = packer.zero_range(swept, count);
        stats.zero_overrides += recorded as u64;
        stats.bulk_erased_pages += count;
    }

    stats.entries_recorded = packer.index_entries();
    stats.new_slots = packer.new_slots();
    stats.new_pack_bytes = packer.new_pack_bytes();
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use cryogen_format::StoreIndex;

    fn page(fill: u8) -> Vec<u8> {
        vec![fill; PAGE_SIZE]
    }

    fn sector(fill: u8) -> Vec<u8> {
        vec![fill; SECTOR_SIZE]
    }

    /// Packs a root store the way the CLI does.
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

    /// A base image over a whole store buffer, counting the pages it was asked
    /// for. Reading the base is the only cost admission has that is
    /// proportional to anything other than the change set, so it is counted.
    struct StoreBase {
        store: Vec<u8>,
        index: StoreIndex,
        generation: u32,
        reads: Vec<PageIndex>,
    }

    impl StoreBase {
        fn new(store: Vec<u8>) -> Self {
            let index = StoreIndex::parse(&store).unwrap();
            let generation = index.tip();
            StoreBase {
                store,
                index,
                generation,
                reads: Vec::new(),
            }
        }
    }

    impl BaseImage for StoreBase {
        type Error = &'static str;

        fn read_page(&mut self, page: PageIndex, out: &mut [u8]) -> Result<(), &'static str> {
            self.reads.push(page);
            match self.index.resolve(self.generation, page) {
                None => out.fill(0),
                Some(slot) => {
                    let off = self.index.header().slot_offset(slot) as usize;
                    out.copy_from_slice(&self.store[off..off + PAGE_SIZE]);
                }
            }
            Ok(())
        }
    }

    /// Builds a scratch dump from `(sector, bytes)` pairs.
    fn scratch(disk_size: u64, zero_from: Option<u64>, recs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        encode_scratch(
            &ScratchHeader {
                sector_size: SECTOR_SIZE as u32,
                disk_size,
                sector_count: recs.len() as u64,
                zero_from,
            },
            recs.iter().map(|(s, b)| (*s, b.clone())),
        )
    }

    /// Runs a whole admission and returns the child store and the stats.
    fn admit_all(parent: &[u8], dump_bytes: &[u8]) -> (Vec<u8>, SnapshotStats, Vec<PageIndex>) {
        let index = StoreIndex::parse(parent).unwrap();
        let h = *index.header();
        let mut packer = Packer::new_child(&index);
        let dump = ScratchDump::parse(dump_bytes).unwrap();
        let mut base = StoreBase::new(parent.to_vec());
        let mut body: Vec<u8> = parent[h.pack_off as usize..(h.pack_off + h.pack_len()) as usize].to_vec();
        let stats = admit(
            &mut packer,
            &dump,
            &mut base,
            |bytes| {
                body.extend_from_slice(bytes);
                Ok(())
            },
            h.disk_size,
        )
        .unwrap();
        let mut out = packer.finish();
        out.extend_from_slice(&body);
        (out, stats, base.reads)
    }

    /// Reads a page out of a store as a guest would see it at `generation`.
    fn read_page(store: &[u8], generation: u32, page: PageIndex) -> Vec<u8> {
        let index = StoreIndex::parse(store).unwrap();
        match index.resolve(generation, page) {
            None => vec![0u8; PAGE_SIZE],
            Some(slot) => {
                let off = index.header().slot_offset(slot) as usize;
                store[off..off + PAGE_SIZE].to_vec()
            }
        }
    }

    // ── The container ──────────────────────────────────────────────────────

    #[test]
    fn a_scratch_dump_round_trips() {
        let bytes = scratch(
            64 * PAGE_SIZE as u64,
            Some(9),
            &[(0, sector(1)), (3, sector(2)), (100, sector(3))],
        );
        let dump = ScratchDump::parse(&bytes).unwrap();
        assert_eq!(dump.header().sector_count, 3);
        assert_eq!(dump.header().zero_from, Some(9));
        assert_eq!(dump.disk_sectors(), 64 * SECTORS_PER_PAGE);
        let got: Vec<_> = dump.sectors().map(|(s, b)| (s, b[0])).collect();
        assert_eq!(got, vec![(0, 1), (3, 2), (100, 3)]);
    }

    #[test]
    fn a_scratch_with_no_erased_tail_says_so() {
        let bytes = scratch(8 * PAGE_SIZE as u64, None, &[(0, sector(1))]);
        assert_eq!(ScratchDump::parse(&bytes).unwrap().header().zero_from, None);
    }

    #[test]
    fn a_malformed_scratch_is_refused() {
        let good = scratch(8 * PAGE_SIZE as u64, None, &[(1, sector(1)), (2, sector(2))]);

        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(matches!(ScratchDump::parse(&bad), Err(ScratchError::BadMagic(_))));

        // Records out of order: the walk into pages is single-pass.
        let mut bad = good.clone();
        bad[SCRATCH_HEADER_LEN..SCRATCH_HEADER_LEN + 8].copy_from_slice(&9u64.to_le_bytes());
        assert!(matches!(ScratchDump::parse(&bad), Err(ScratchError::Unsorted { .. })));

        // A sector past the end of the disk it claims to overlay.
        let bad = scratch(8 * PAGE_SIZE as u64, None, &[(1_000_000, sector(1))]);
        assert!(matches!(
            ScratchDump::parse(&bad),
            Err(ScratchError::SectorOutOfRange { .. })
        ));

        assert!(matches!(
            ScratchDump::parse(&good[..good.len() - 1]),
            Err(ScratchError::Truncated { .. })
        ));

        let mut bad = good.clone();
        bad.push(0);
        assert!(matches!(ScratchDump::parse(&bad), Err(ScratchError::Trailing { .. })));
    }

    // ── Admission ──────────────────────────────────────────────────────────

    /// The whole point, end to end: a guest writes one sector, and the snapshot
    /// costs one page of pack and one index entry — not a disk.
    #[test]
    fn one_dirty_sector_costs_one_page() {
        let pages: Vec<(PageIndex, Vec<u8>)> = (0..64).map(|i| (i, page(1 + i as u8))).collect();
        let parent = pack(64 * PAGE_SIZE as u64, &pages);
        let dump = scratch(64 * PAGE_SIZE as u64, None, &[(9, sector(0xEE))]);
        let (child, stats, base_reads) = admit_all(&parent, &dump);

        assert_eq!(stats.dirty_sectors, 1);
        assert_eq!(stats.dirty_pages, 1);
        assert_eq!(stats.entries_recorded, 1);
        assert_eq!(stats.new_slots, 1);
        assert_eq!(stats.new_pack_bytes, PAGE_SIZE as u64);
        // One page of the parent was read to fill the seven untouched sectors,
        // and *only* one: nothing scanned the disk.
        assert_eq!(base_reads, vec![1]);
        assert_eq!(stats.base_pages_read, 1);

        // The page reads back as seven parent sectors and one new one.
        let index = StoreIndex::parse(&child).unwrap();
        let got = read_page(&child, index.tip(), 1);
        assert!(got[..SECTOR_SIZE].iter().all(|&b| b == 2), "sector 8 is still the parent's");
        assert!(got[SECTOR_SIZE..2 * SECTOR_SIZE].iter().all(|&b| b == 0xEE));
        assert!(got[2 * SECTOR_SIZE..].iter().all(|&b| b == 2));
        // Everything else is inherited, so the file grew by about one page.
        let parent_len = StoreIndex::parse(&parent).unwrap().header().total_len();
        assert!(index.header().total_len() - parent_len <= 2 * PAGE_SIZE as u64);
    }

    /// A page the guest wrote in full costs no base read at all.
    #[test]
    fn a_fully_written_page_needs_no_base_read() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let recs: Vec<(u64, Vec<u8>)> = (8..16).map(|s| (s, sector(0xCD))).collect();
        let dump = scratch(8 * PAGE_SIZE as u64, None, &recs);
        let (child, stats, base_reads) = admit_all(&parent, &dump);
        assert!(base_reads.is_empty(), "every sector of page 1 was written");
        assert_eq!(stats.base_pages_read, 0);
        assert_eq!(stats.new_slots, 1);
        let index = StoreIndex::parse(&child).unwrap();
        assert!(read_page(&child, index.tip(), 1).iter().all(|&b| b == 0xCD));
    }

    /// The trap, through the harvest path rather than the packer's API: a guest
    /// zeroes a page the parent had content for, and the child must read zero.
    #[test]
    fn a_guest_that_zeroes_a_page_does_not_get_the_parents_bytes_back() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let recs: Vec<(u64, Vec<u8>)> = (8..16).map(|s| (s, sector(0))).collect();
        let dump = scratch(8 * PAGE_SIZE as u64, None, &recs);
        let (child, stats, _) = admit_all(&parent, &dump);

        assert_eq!(stats.zero_overrides, 1);
        assert_eq!(stats.new_pack_bytes, 0, "a tombstone is an entry, not a page");
        assert_eq!(stats.entries_recorded, 1);

        let index = StoreIndex::parse(&child).unwrap();
        assert_eq!(index.resolve(index.tip(), 1), None);
        assert!(read_page(&child, index.tip(), 1).iter().all(|&b| b == 0));
        // The parent still says what it always said.
        assert!(read_page(&child, 0, 1).iter().all(|&b| b == 0xBB));
    }

    /// Writing zeros over a page that was *already* zero records nothing: the
    /// tombstone is for overriding a parent, not for every zero the guest
    /// writes.
    #[test]
    fn zeroing_an_already_zero_page_records_nothing() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA))]);
        let recs: Vec<(u64, Vec<u8>)> = (8..16).map(|s| (s, sector(0))).collect();
        let dump = scratch(8 * PAGE_SIZE as u64, None, &recs);
        let (_, stats, _) = admit_all(&parent, &dump);
        assert_eq!(stats.entries_recorded, 0);
        assert_eq!(stats.zero_overrides, 0);
        assert_eq!(stats.unchanged_pages, 1);
        assert_eq!(stats.new_pack_bytes, 0);
    }

    /// A guest that rewrites a page with the bytes it already had costs
    /// nothing. Overlay layers record writes, not changes, so this is the
    /// common case, not a corner one.
    #[test]
    fn rewriting_a_page_with_its_own_bytes_costs_nothing() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let recs: Vec<(u64, Vec<u8>)> = (0..8).map(|s| (s, sector(0xAA))).collect();
        let dump = scratch(8 * PAGE_SIZE as u64, None, &recs);
        let (child, stats, _) = admit_all(&parent, &dump);
        assert_eq!(stats.entries_recorded, 0);
        assert_eq!(stats.unchanged_pages, 1);
        assert_eq!(stats.new_pack_bytes, 0);
        let a = StoreIndex::parse(&parent).unwrap();
        let b = StoreIndex::parse(&child).unwrap();
        assert_eq!(b.header().blob_count, a.header().blob_count);
        assert_eq!(b.header().pack_len(), a.header().pack_len());
    }

    /// A guest that moves content around pays for the entries and not for the
    /// pack: the bytes are already in the store.
    #[test]
    fn relocated_content_adds_entries_and_no_pack_bytes() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        let mut recs: Vec<(u64, Vec<u8>)> = (0..8).map(|s| (s, sector(0xBB))).collect();
        recs.extend((8..16).map(|s| (s, sector(0xAA))));
        let dump = scratch(8 * PAGE_SIZE as u64, None, &recs);
        let (child, stats, _) = admit_all(&parent, &dump);
        assert_eq!(stats.deduplicated_pages, 2);
        assert_eq!(stats.new_slots, 0);
        assert_eq!(stats.new_pack_bytes, 0);
        assert_eq!(stats.entries_recorded, 2);
        let index = StoreIndex::parse(&child).unwrap();
        assert!(read_page(&child, index.tip(), 0).iter().all(|&b| b == 0xBB));
        assert!(read_page(&child, index.tip(), 1).iter().all(|&b| b == 0xAA));
    }

    /// An erased tail — what a trailing unmap leaves in a scratch overlay —
    /// tombstones the parent's pages inside it without holding a single sector
    /// for them. This is the case a harvester that looked only at the sectors
    /// an overlay holds would miss entirely, because the sectors are *gone*.
    #[test]
    fn an_erased_tail_tombstones_what_the_parent_had() {
        let pages: Vec<(PageIndex, Vec<u8>)> = (0..8).map(|i| (i, page(1 + i as u8))).collect();
        let parent = pack(8 * PAGE_SIZE as u64, &pages);
        // The guest erased everything from sector 32 (page 4) up, and wrote one
        // sector below that.
        let dump = scratch(8 * PAGE_SIZE as u64, Some(32), &[(0, sector(0x77))]);
        let (child, stats, _) = admit_all(&parent, &dump);

        assert_eq!(stats.bulk_erased_pages, 4);
        assert_eq!(stats.zero_overrides, 4);
        assert_eq!(stats.new_slots, 1, "only the partially written page is novel");

        let index = StoreIndex::parse(&child).unwrap();
        let tip = index.tip();
        for p in 4..8 {
            assert_eq!(index.resolve(tip, p), None, "page {p} was erased");
            assert!(read_page(&child, 0, p).iter().any(|&b| b != 0), "the parent still has it");
        }
        for p in 1..4 {
            assert_eq!(index.resolve(tip, p), index.resolve(0, p), "page {p} untouched");
        }
    }

    /// The erased boundary can fall inside a page, and then that page is half
    /// parent and half zeros.
    #[test]
    fn an_erased_boundary_inside_a_page_splits_it() {
        let parent = pack(4 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        // Sector 4 is the middle of page 0.
        let dump = scratch(4 * PAGE_SIZE as u64, Some(4), &[(0, sector(0x55))]);
        let (child, _, _) = admit_all(&parent, &dump);
        let index = StoreIndex::parse(&child).unwrap();
        let got = read_page(&child, index.tip(), 0);
        assert!(got[..SECTOR_SIZE].iter().all(|&b| b == 0x55), "the written sector");
        assert!(
            got[SECTOR_SIZE..4 * SECTOR_SIZE].iter().all(|&b| b == 0xAA),
            "below the boundary, the parent shows through"
        );
        assert!(got[4 * SECTOR_SIZE..].iter().all(|&b| b == 0), "above it, zeros");
        assert_eq!(index.resolve(index.tip(), 1), None, "page 1 is wholly erased");
    }

    /// Snapshots compose: a chain built one scratch at a time resolves the same
    /// way a chain built by the packer directly does, and every generation
    /// keeps its own view.
    #[test]
    fn snapshots_chain() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(0xA0)), (1, page(0xB0))]);
        let d1 = scratch(
            8 * PAGE_SIZE as u64,
            None,
            &(0..8).map(|s| (s, sector(0xA1))).collect::<Vec<_>>(),
        );
        let (g1, _, _) = admit_all(&parent, &d1);
        let d2 = scratch(
            8 * PAGE_SIZE as u64,
            None,
            &(8..16).map(|s| (s, sector(0))).collect::<Vec<_>>(),
        );
        let (g2, stats2, _) = admit_all(&g1, &d2);
        let d3 = scratch(
            8 * PAGE_SIZE as u64,
            None,
            &(16..24).map(|s| (s, sector(0xC3))).collect::<Vec<_>>(),
        );
        let (g3, _, _) = admit_all(&g2, &d3);

        let index = StoreIndex::parse(&g3).unwrap();
        assert_eq!(index.header().gen_count, 4);
        assert_eq!(index.chain(3), vec![3, 2, 1, 0]);
        assert_eq!(stats2.zero_overrides, 1);

        assert!(read_page(&g3, 3, 0).iter().all(|&b| b == 0xA1));
        assert!(read_page(&g3, 3, 1).iter().all(|&b| b == 0), "erased in g2");
        assert!(read_page(&g3, 3, 2).iter().all(|&b| b == 0xC3));
        // Older generations still read as they did.
        assert!(read_page(&g3, 0, 0).iter().all(|&b| b == 0xA0));
        assert!(read_page(&g3, 1, 1).iter().all(|&b| b == 0xB0));
        assert!(read_page(&g3, 2, 1).iter().all(|&b| b == 0));
    }

    /// A scratch harvested from a different disk is refused, not admitted into
    /// a plausible-looking generation.
    #[test]
    fn a_scratch_from_another_disk_is_refused() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(1))]);
        let dump_bytes = scratch(16 * PAGE_SIZE as u64, None, &[(0, sector(2))]);
        let index = StoreIndex::parse(&parent).unwrap();
        let mut packer = Packer::new_child(&index);
        let dump = ScratchDump::parse(&dump_bytes).unwrap();
        let mut base = StoreBase::new(parent.clone());
        let r = admit(&mut packer, &dump, &mut base, |_| Ok(()), index.header().disk_size);
        assert!(matches!(r, Err(AdmitError::DiskSizeMismatch { .. })));
    }

    /// Admission into a root packer is refused: it would produce a store with
    /// one generation holding only the changed pages, i.e. an image that is
    /// mostly holes.
    #[test]
    fn admitting_into_a_root_packer_is_refused() {
        let dump_bytes = scratch(8 * PAGE_SIZE as u64, None, &[(0, sector(2))]);
        let dump = ScratchDump::parse(&dump_bytes).unwrap();
        let mut packer = Packer::new(8 * PAGE_SIZE as u64);
        let mut base = StoreBase::new(pack(8 * PAGE_SIZE as u64, &[(0, page(1))]));
        let r = admit(&mut packer, &dump, &mut base, |_| Ok(()), 8 * PAGE_SIZE as u64);
        assert!(matches!(r, Err(AdmitError::NotAChild)));
    }

    /// The boundary page needs no *record* to have changed. If a bulk erase
    /// starts in the middle of a page and the guest wrote nothing in that page,
    /// its upper sectors still went to zero — and nothing in the scratch's
    /// sector list mentions the page at all. A harvest driven only by the
    /// sectors an overlay holds records nothing, and the child then serves the
    /// parent's bytes for sectors the guest sees as erased.
    #[test]
    fn an_erased_boundary_in_a_page_with_no_records_is_still_recorded() {
        let parent = pack(4 * PAGE_SIZE as u64, &[(0, page(0xAA)), (1, page(0xBB))]);
        // Sector 4 is the middle of page 0, and the scratch holds nothing.
        let dump = scratch(4 * PAGE_SIZE as u64, Some(4), &[]);
        let (child, stats, reads) = admit_all(&parent, &dump);

        assert_eq!(reads, vec![0], "the boundary page must be assembled from the parent");
        assert_eq!(stats.new_slots, 1);
        let index = StoreIndex::parse(&child).unwrap();
        let got = read_page(&child, index.tip(), 0);
        assert!(
            got[..4 * SECTOR_SIZE].iter().all(|&b| b == 0xAA),
            "below the boundary the parent still shows through"
        );
        assert!(
            got[4 * SECTOR_SIZE..].iter().all(|&b| b == 0),
            "above the boundary the guest sees zeros, so the child must too"
        );
        assert_eq!(index.resolve(index.tip(), 1), None, "wholly erased");
    }

    /// The same omission, one page further in: the boundary page has no records
    /// but a later page does, so a walk driven by records skips straight past
    /// it.
    #[test]
    fn a_recordless_boundary_page_before_a_dirty_one_is_not_skipped() {
        let pages: Vec<(PageIndex, Vec<u8>)> = (0..8).map(|i| (i, page(0x10 + i as u8))).collect();
        let parent = pack(8 * PAGE_SIZE as u64, &pages);
        // Boundary inside page 2; the only record is in page 5, above it.
        let dump = scratch(
            8 * PAGE_SIZE as u64,
            Some(20),
            &[(40, sector(0x99))],
        );
        let (child, _, reads) = admit_all(&parent, &dump);
        assert!(reads.contains(&2), "the boundary page was never assembled: {reads:?}");
        let index = StoreIndex::parse(&child).unwrap();
        let got = read_page(&child, index.tip(), 2);
        assert!(got[..4 * SECTOR_SIZE].iter().all(|&b| b == 0x12));
        assert!(got[4 * SECTOR_SIZE..].iter().all(|&b| b == 0));
        // Page 5 holds the written sector and zeros above it; pages 3, 4, 6, 7
        // are wholly erased.
        for p in [3u64, 4, 6, 7] {
            assert_eq!(index.resolve(index.tip(), p), None, "page {p}");
        }
        assert_eq!(read_page(&child, index.tip(), 5)[..SECTOR_SIZE], sector(0x99)[..]);
    }

    /// `pages_needing_base` must name exactly the pages `admit` goes on to ask
    /// for. A caller with an asynchronous base image prefetches against the
    /// former and admits against the latter, so a disagreement would be a
    /// missing page at admission time — or, worse, a page quietly filled with
    /// something else.
    #[test]
    fn the_predicted_base_reads_are_the_ones_admission_makes() {
        let pages: Vec<(PageIndex, Vec<u8>)> = (0..16).map(|i| (i, page(1 + i as u8))).collect();
        let parent = pack(16 * PAGE_SIZE as u64, &pages);
        let mut recs: Vec<(u64, Vec<u8>)> = Vec::new();
        recs.push((3, sector(0x11))); // page 0, partial
        recs.extend((8..16).map(|s| (s, sector(0x22)))); // page 1, whole
        recs.push((20, sector(0x33))); // page 2, partial
        recs.extend((80..84).map(|s| (s, sector(0x44)))); // page 10, partial
        // ...and an erased tail that starts inside page 10, so its missing
        // sectors need nothing.
        let dump_bytes = scratch(16 * PAGE_SIZE as u64, Some(84), &recs);

        let dump = ScratchDump::parse(&dump_bytes).unwrap();
        let predicted = pages_needing_base(&dump);
        let (_, stats, actual) = admit_all(&parent, &dump_bytes);
        assert_eq!(predicted, actual);
        // Page 1 was written whole and page 10 is missing only sectors above
        // the boundary, so neither costs a base read.
        assert_eq!(predicted, vec![0, 2]);
        assert_eq!(stats.base_pages_read, 2);
    }

    /// The prediction must include the boundary page even when the scratch
    /// holds nothing for it — an asynchronous caller prefetches against this
    /// list, and a page missing from it is a page `admit` would then be unable
    /// to assemble.
    #[test]
    fn the_prediction_includes_a_recordless_boundary_page() {
        let parent = pack(16 * PAGE_SIZE as u64, &[(0, page(1)), (3, page(2)), (9, page(3))]);
        for (zero_from, records, want) in [
            (Some(28u64), vec![], vec![3u64]),          // boundary in page 3, no records
            (Some(28), vec![0u64], vec![0, 3]),         // a record below it
            // A record *above* the boundary: page 10's untouched sectors are
            // all erased, so it needs nothing from the parent.
            (Some(28), vec![80], vec![3]),
            (Some(24), vec![], vec![]),                 // page-aligned: nothing to assemble
            (None, vec![0], vec![0]),                   // no erase at all
        ] {
            let recs: Vec<(u64, Vec<u8>)> = records.iter().map(|&s| (s, sector(0x11))).collect();
            let bytes = scratch(16 * PAGE_SIZE as u64, zero_from, &recs);
            let dump = ScratchDump::parse(&bytes).unwrap();
            assert_eq!(pages_needing_base(&dump), want, "zero_from {zero_from:?}, records {records:?}");
            let (_, _, actual) = admit_all(&parent, &bytes);
            assert_eq!(actual, want, "admission disagreed: zero_from {zero_from:?}");
        }
    }

    #[test]
    fn an_erase_boundary_past_the_end_of_the_disk_is_refused() {
        let bytes = scratch(8 * PAGE_SIZE as u64, Some(65), &[]);
        assert!(matches!(
            ScratchDump::parse(&bytes),
            Err(ScratchError::BadZeroFrom { .. })
        ));
        // Exactly at the end is fine: it erases nothing.
        let bytes = scratch(8 * PAGE_SIZE as u64, Some(64), &[]);
        assert!(ScratchDump::parse(&bytes).is_ok());
    }

    /// A boundary at the end of a disk whose last page is *partial* is
    /// unaligned, but it still erases nothing — the sectors above it are not on
    /// the disk. Treating it as a boundary would cost a page of pack for a
    /// difference confined to padding no read can reach.
    #[test]
    fn a_boundary_at_the_end_of_a_partial_last_page_erases_nothing() {
        let disk = 10 * SECTOR_SIZE as u64; // one page and a quarter
        let mut packer = Packer::new(disk);
        let mut body = Vec::new();
        for (p, fill) in [(0u64, 0xAAu8), (1, 0xBB)] {
            if let Disposition::Novel(_) = packer.add_page(p, &page(fill)).unwrap() {
                body.extend_from_slice(&page(fill));
            }
        }
        let mut parent = packer.finish();
        parent.extend_from_slice(&body);

        let dump = scratch(disk, Some(10), &[]);
        let (child, stats, reads) = admit_all(&parent, &dump);
        assert!(reads.is_empty(), "nothing to assemble: {reads:?}");
        assert_eq!(stats.entries_recorded, 0);
        assert_eq!(stats.new_pack_bytes, 0);
        let a = StoreIndex::parse(&parent).unwrap();
        let b = StoreIndex::parse(&child).unwrap();
        for p in 0..2 {
            assert_eq!(a.resolve(a.tip(), p), b.resolve(b.tip(), p), "page {p}");
        }
    }

    /// An empty scratch — a guest that wrote nothing — is a generation that
    /// changes nothing and costs nothing.
    #[test]
    fn an_empty_scratch_admits_an_empty_generation() {
        let parent = pack(8 * PAGE_SIZE as u64, &[(0, page(1)), (3, page(2))]);
        let dump = scratch(8 * PAGE_SIZE as u64, None, &[]);
        let (child, stats, reads) = admit_all(&parent, &dump);
        assert_eq!(stats.entries_recorded, 0);
        assert_eq!(stats.new_pack_bytes, 0);
        assert!(reads.is_empty());
        let a = StoreIndex::parse(&parent).unwrap();
        let b = StoreIndex::parse(&child).unwrap();
        assert_eq!(b.header().gen_count, 2);
        for p in 0..8 {
            assert_eq!(a.resolve(a.tip(), p), b.resolve(b.tip(), p), "page {p}");
        }
        // The only growth is one 8-byte generation header.
        assert_eq!(b.header().overlays_len, a.header().overlays_len + 8);
    }
}
