//! Guest RAM snapshot / restore capability.
//!
//! A virtual machine's guest physical RAM is a VMO mapped into the guest
//! address-space VMAR (see [`guest_memory`]).  This crate makes that RAM
//! *snapshottable*: capture a baseline, run the guest, then restore the
//! baseline in time proportional to the pages the guest changed — not to the
//! total size of RAM.  Fast restore is the core primitive a snapshot-driven
//! VMM builds on (rewind-and-replay, checkpoint/rollback, fork-per-branch).
//!
//! The design deliberately separates two things:
//!
//!   * **Semantics** — *what* a restore must produce: guest RAM byte-for-byte
//!     back to the baseline, with every page the guest dirtied since the
//!     baseline discarded.  This is captured by the portable [`AccessTracker`]
//!     + [`restore_dirty`] model, which is `no_std`, allocation-free, and
//!     fully unit-tested on the build host (no hypervisor required).
//!
//!   * **Mechanism** — *how* Cerise realizes it cheaply: Zircon copy-on-write
//!     VMO clones.  The guest runs on a CoW child of an immutable *golden*
//!     VMO; restore drops the child and re-clones the golden, so unchanged
//!     pages are shared by reference and changed pages fault back lazily — no
//!     per-page userspace copy.  This lives in the [`cerise`] module and is
//!     built only for the Cerise target.
//!
//! Both paths are guest-visibly identical; the CoW mechanism is strictly a
//! performance realization of the semantics the portable model defines.  A
//! backend without native CoW memory can implement the same capability with
//! [`restore_dirty`] over two buffers and get the same result, only paying an
//! O(dirty) copy instead of an O(1) clone-swap.
//!
//! ## Access tracking
//!
//! Restore via clone-swap does not itself need to know *which* pages changed —
//! CoW discards divergence wholesale.  Enumerating the dirty set is needed for
//! the adjacent capabilities: incremental *checkpoint* (snapshot only what
//! changed since the last one) and dirty-region export.  [`AccessTracker`] is
//! the portable dirty-set primitive those build on; on Cerise the guest-CPU
//! write set is delivered by the hypervisor and host-side writes by the VMM's
//! own memory accessor, unioned into one tracker.
//!
//! ## In-kernel fast restore
//!
//! Restore is a single in-kernel operation, `ZX_VMO_OP_REVERT_TO_SNAPSHOT`,
//! which reverts only the pages the guest dirtied back to the baseline in place
//! — no userspace unmap/remap and no per-page copy. The guest mapping's
//! affected translations are invalidated through the kernel's normal
//! range-change path, so the guest re-faults from the baseline on next access.
//! The portable [`restore_dirty`] model is the reference semantics this
//! operation preserves. See `SNAPSHOT.md`.

#![cfg_attr(not(test), no_std)]

/// Page size of the snapshot model — matches Zircon's 4 KiB page.
pub const PAGE_SIZE: usize = 4096;

/// Errors from the portable snapshot model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// `baseline` and `working` differ in length.
    LengthMismatch,
    /// A length was not a whole number of [`PAGE_SIZE`] pages.
    Unaligned,
    /// The dirty bitmap is too small for the requested page count.
    BitmapTooSmall,
}

// ─── Portable access tracker (no_std, allocation-free, host-tested) ─────────

/// A dirty-page set backed by a caller-owned bitmap (one bit per page).
///
/// The caller owns the bitmap storage so the type stays allocation-free and
/// usable in `no_std` VMM code; `words_for(page_count)` gives the required
/// length.  Bit `p` set means guest page `p` has diverged from the baseline.
pub struct AccessTracker<'a> {
    bits: &'a mut [u64],
    page_count: usize,
}

/// Number of `u64` words a bitmap needs to track `page_count` pages.
pub const fn words_for(page_count: usize) -> usize {
    page_count.div_ceil(64)
}

impl<'a> AccessTracker<'a> {
    /// Wrap `bits` as a tracker for `page_count` pages.
    ///
    /// Returns [`SnapshotError::BitmapTooSmall`] if `bits` cannot hold
    /// `page_count` bits.  The bitmap is not cleared — call [`clear`] first if
    /// its contents are unknown.
    ///
    /// [`clear`]: AccessTracker::clear
    pub fn new(bits: &'a mut [u64], page_count: usize) -> Result<Self, SnapshotError> {
        if bits.len() < words_for(page_count) {
            return Err(SnapshotError::BitmapTooSmall);
        }
        Ok(Self { bits, page_count })
    }

    /// Number of pages this tracker covers.
    pub fn page_count(&self) -> usize {
        self.page_count
    }

    /// Mark a single page dirty.  Out-of-range pages are ignored.
    pub fn mark_dirty(&mut self, page: usize) {
        if page < self.page_count {
            self.bits[page / 64] |= 1u64 << (page % 64);
        }
    }

    /// Mark every page overlapping the byte range `[offset, offset+len)` dirty.
    ///
    /// This is how a host-side write (the VMM emulating a device into guest
    /// RAM) records what it touched, to be unioned with the hypervisor's
    /// guest-CPU dirty set.
    pub fn mark_range_dirty(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        let first = offset / PAGE_SIZE;
        let last = (offset + len - 1) / PAGE_SIZE;
        for page in first..=last {
            self.mark_dirty(page);
        }
    }

    /// Whether page `page` is marked dirty.
    pub fn is_dirty(&self, page: usize) -> bool {
        page < self.page_count && (self.bits[page / 64] & (1u64 << (page % 64))) != 0
    }

    /// Number of pages currently marked dirty.
    pub fn dirty_count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Clear the whole set (nothing dirty).
    pub fn clear(&mut self) {
        for w in self.bits.iter_mut() {
            *w = 0;
        }
    }

    /// Call `f` with each dirty page index, in ascending order.
    pub fn for_each_dirty(&self, mut f: impl FnMut(usize)) {
        for (word_idx, &word) in self.bits.iter().enumerate() {
            let mut w = word;
            while w != 0 {
                let bit = w.trailing_zeros() as usize;
                let page = word_idx * 64 + bit;
                if page >= self.page_count {
                    return;
                }
                f(page);
                w &= w - 1; // clear lowest set bit
            }
        }
    }
}

/// Restore `working` to `baseline`, copying only the pages `tracker` marks
/// dirty, then clear the tracker.
///
/// This is the software model of the clone-swap fast restore: it produces
/// exactly the guest-visible state a CoW re-clone would, at a cost of
/// O(dirty pages) rather than O(total pages).  A non-CoW backend can use it
/// directly as its restore implementation.
///
/// `baseline` and `working` must be equal length and a whole number of pages;
/// `tracker` must cover that page count.
pub fn restore_dirty(
    baseline: &[u8],
    working: &mut [u8],
    tracker: &mut AccessTracker,
) -> Result<usize, SnapshotError> {
    if baseline.len() != working.len() {
        return Err(SnapshotError::LengthMismatch);
    }
    if baseline.len() % PAGE_SIZE != 0 {
        return Err(SnapshotError::Unaligned);
    }
    let pages = baseline.len() / PAGE_SIZE;
    if tracker.page_count() != pages {
        return Err(SnapshotError::BitmapTooSmall);
    }
    let mut restored = 0usize;
    tracker.for_each_dirty(|page| {
        let start = page * PAGE_SIZE;
        let end = start + PAGE_SIZE;
        working[start..end].copy_from_slice(&baseline[start..end]);
        restored += 1;
    });
    tracker.clear();
    Ok(restored)
}

// ─── Cerise VMO-clone mechanism ─────────────────────────────────────────────

#[cfg(not(test))]
pub mod cerise {
    use cerise_rt::zx::{
        self, Handle, Status, Vaddr, HANDLE_INVALID, RIGHT_SAME_RIGHTS, VMO_CHILD_SNAPSHOT,
        VMO_CHILD_SNAPSHOT_AT_LEAST_ON_WRITE, VMO_OP_QUERY_DIRTY, VMO_OP_REVERT_TO_SNAPSHOT,
        VM_MAP_RANGE, VM_PERM_READ, VM_PERM_WRITE, VM_SPECIFIC, ZX_OK,
    };

    /// Snapshottable guest RAM backed by Zircon copy-on-write VMO clones.
    ///
    /// Invariant: `golden` is the immutable baseline VMO, mapped into the host
    /// at `baseline_vaddr` so the VMM can load the baseline image into it once,
    /// before starting.  The guest runs on `working`, a CoW child of `golden`
    /// mapped into the guest VMAR at `guest_paddr` and into the host at
    /// `host_vaddr` for VMM access.  `working` is [`HANDLE_INVALID`] until
    /// [`start`](GuestRamSnapshot::start).
    pub struct GuestRamSnapshot {
        guest_vmar: Handle,
        guest_paddr: usize,
        size: usize,
        golden: Handle,
        baseline_vaddr: usize,
        working: Handle,
        host_vaddr: usize,
    }

    unsafe impl Send for GuestRamSnapshot {}
    unsafe impl Sync for GuestRamSnapshot {}

    // Guest-VMAR mapping flags: fixed offset (SPECIFIC) + eager population
    // (MAP_RANGE) so the hypervisor sees the pages without first-touch faults.
    const GUEST_MAP: zx::VmOption = VM_PERM_READ | VM_PERM_WRITE | VM_SPECIFIC | VM_MAP_RANGE;
    const HOST_MAP: zx::VmOption = VM_PERM_READ | VM_PERM_WRITE;

    impl GuestRamSnapshot {
        /// Create `size` bytes of snapshottable guest RAM at `guest_paddr`.
        ///
        /// The golden baseline VMO is zero-filled and mapped into the host (see
        /// [`baseline_ptr`]).  Load the initial guest image into that mapping,
        /// then call [`start`]; the guest then runs on a CoW clone of it, and
        /// [`restore`] returns to exactly the loaded baseline.
        ///
        /// # Safety
        /// `guest_vmar` must be a live guest-VMAR handle and `[guest_paddr,
        /// guest_paddr+size)` must be free within it.
        ///
        /// [`baseline_ptr`]: GuestRamSnapshot::baseline_ptr
        /// [`start`]: GuestRamSnapshot::start
        /// [`restore`]: GuestRamSnapshot::restore
        pub unsafe fn new(
            guest_vmar: Handle,
            guest_paddr: usize,
            size: usize,
        ) -> Result<Self, Status> {
            let mut golden = HANDLE_INVALID;
            let s = zx::vmo_create(size as u64, 0, &mut golden);
            if s != ZX_OK {
                return Err(s);
            }
            // Map the golden baseline into the host so the VMM can load the
            // initial image directly into it (writes here define the restore
            // target).  golden is never mapped into the guest — the guest only
            // ever sees CoW clones of it.
            let mut baseline_vaddr: Vaddr = 0;
            let s = zx::vmar_map(
                zx::vmar_root_self(), HOST_MAP, 0, golden, 0, size, &mut baseline_vaddr,
            );
            if s != ZX_OK {
                zx::handle_close(golden);
                return Err(s);
            }
            Ok(Self {
                guest_vmar,
                guest_paddr,
                size,
                golden,
                baseline_vaddr,
                working: HANDLE_INVALID,
                host_vaddr: 0,
            })
        }

        /// Host pointer to the golden baseline, for loading the initial guest
        /// image before [`start`](Self::start).  Whatever is written here is
        /// what [`restore`](Self::restore) returns guest RAM to.
        pub fn baseline_ptr(&self) -> *mut u8 {
            self.baseline_vaddr as *mut u8
        }

        /// Start the guest on a fresh CoW clone of the loaded baseline.
        ///
        /// Idempotent-unsafe: call once after loading the baseline.  Maps the
        /// working clone into the guest VMAR and the host.
        ///
        /// # Safety
        /// Must be called before any VCPU runs, with `working` not yet spawned.
        pub unsafe fn start(&mut self) -> Status {
            match self.spawn_working() {
                Ok(()) => ZX_OK,
                Err(s) => s,
            }
        }

        /// Discard everything the guest changed since [`start`](Self::start),
        /// returning guest RAM to the golden baseline.
        ///
        /// A single in-kernel operation (`ZX_VMO_OP_REVERT_TO_SNAPSHOT`) reverts
        /// only the pages the guest dirtied, in place: the guest and host
        /// mappings stay valid — no unmap/remap — and the guest re-faults the
        /// reverted pages from the baseline on next access.  Cost is O(pages
        /// dirtied since `start`), with no per-page userspace copy.
        ///
        /// # Safety
        /// The guest must be paused (no VCPU executing) for the duration.
        pub unsafe fn restore(&mut self) -> Status {
            if self.working == HANDLE_INVALID {
                return ZX_OK;
            }
            zx::vmo_op_range(
                self.working,
                VMO_OP_REVERT_TO_SNAPSHOT,
                0,
                self.size as u64,
                core::ptr::null_mut(),
                0,
            )
        }

        /// Fill `bitmap` with the set of guest RAM pages dirtied since
        /// [`start`](Self::start) or the last [`restore`](Self::restore) — one
        /// bit per page (bit `p` = page `p`, LSB-first within each byte).
        /// `bitmap` must hold at least `ceil(size / PAGE_SIZE / 8)` bytes.
        ///
        /// The set is the union of guest-CPU and host (VMM device-emulation)
        /// writes, since both fork the shared baseline page. For a coherent
        /// snapshot the guest should be paused.
        ///
        /// # Safety
        /// `bitmap` must be valid for `bitmap.len()` bytes.
        pub unsafe fn dirty_bitmap(&self, bitmap: &mut [u8]) -> Status {
            zx::vmo_op_range(
                self.working,
                VMO_OP_QUERY_DIRTY,
                0,
                self.size as u64,
                bitmap.as_mut_ptr(),
                bitmap.len(),
            )
        }

        /// Promote the guest's current RAM to a new baseline: future
        /// [`restore`](Self::restore)s return here rather than to the image
        /// loaded at [`new`](Self::new).
        ///
        /// Captures the running `working` as a new golden (a full copy-on-write
        /// snapshot) and rebases a fresh `working` onto it. Unlike `restore`,
        /// this remaps the working RAM, so [`host_ptr`](Self::host_ptr) moves.
        ///
        /// This is a *full* snapshot; an incremental (O(pages changed))
        /// checkpoint needs a pager-backed golden — see `SNAPSHOT.md`.
        ///
        /// # Safety
        /// The guest must be paused (no VCPU executing) for the duration.
        pub unsafe fn checkpoint(&mut self) -> Status {
            if self.working == HANDLE_INVALID {
                return ZX_OK;
            }
            // New golden = a full snapshot of the current working state.
            let mut new_golden = HANDLE_INVALID;
            let s = zx::vmo_create_child(
                self.working, VMO_CHILD_SNAPSHOT, 0, self.size as u64, &mut new_golden,
            );
            if s != ZX_OK {
                return s;
            }
            // Drop the current working and the old golden (with its host mapping).
            self.teardown_working();
            if self.baseline_vaddr != 0 {
                zx::vmar_unmap(zx::vmar_root_self(), self.baseline_vaddr, self.size);
                self.baseline_vaddr = 0;
            }
            zx::handle_close(self.golden);
            self.golden = new_golden;
            // Map the new golden into the host (baseline access) and spawn a
            // fresh working clone from it.
            let mut bv: Vaddr = 0;
            let s =
                zx::vmar_map(zx::vmar_root_self(), HOST_MAP, 0, self.golden, 0, self.size, &mut bv);
            if s != ZX_OK {
                return s;
            }
            self.baseline_vaddr = bv;
            match self.spawn_working() {
                Ok(()) => ZX_OK,
                Err(s) => s,
            }
        }

        /// Fork a second, independent branch off the same baseline.
        ///
        /// Returns a new [`GuestRamSnapshot`] sharing this one's golden baseline
        /// (the loaded image) via a duplicated handle, with its own `working`
        /// clone mapped into `guest_vmar` at `guest_paddr`. The two branches
        /// diverge and [`restore`](Self::restore) independently. The fork does
        /// not carry a host baseline mapping (the baseline is shared and already
        /// loaded), so its [`baseline_ptr`](Self::baseline_ptr) is null. The
        /// fork's `working` is already spawned and mapped — do not call
        /// [`start`](Self::start) on it.
        ///
        /// # Safety
        /// `guest_vmar` must be a live guest-VMAR handle with `[guest_paddr,
        /// guest_paddr+size)` free.
        pub unsafe fn fork(&self, guest_vmar: Handle, guest_paddr: usize) -> Result<Self, Status> {
            let mut golden_dup = HANDLE_INVALID;
            let s = zx::handle_duplicate(self.golden, RIGHT_SAME_RIGHTS, &mut golden_dup);
            if s != ZX_OK {
                return Err(s);
            }
            let mut fork = Self {
                guest_vmar,
                guest_paddr,
                size: self.size,
                golden: golden_dup,
                baseline_vaddr: 0,
                working: HANDLE_INVALID,
                host_vaddr: 0,
            };
            match fork.spawn_working() {
                Ok(()) => Ok(fork),
                Err(s) => {
                    zx::handle_close(golden_dup);
                    fork.golden = HANDLE_INVALID;
                    Err(s)
                }
            }
        }

        /// Host-accessible base address of the working guest RAM, for the VMM to
        /// read/write guest memory directly.  Valid from [`start`](Self::start)
        /// until this object is dropped — [`restore`](Self::restore) reverts in
        /// place and does not move it.  Returns null before `start`.
        pub fn host_ptr(&self) -> *mut u8 {
            self.host_vaddr as *mut u8
        }

        pub fn size(&self) -> usize {
            self.size
        }

        // Create a fresh CoW child of `golden` and map it into guest + host.
        unsafe fn spawn_working(&mut self) -> Result<(), Status> {
            let mut working = HANDLE_INVALID;
            let s = zx::vmo_create_child(
                self.golden,
                VMO_CHILD_SNAPSHOT_AT_LEAST_ON_WRITE,
                0,
                self.size as u64,
                &mut working,
            );
            if s != ZX_OK {
                return Err(s);
            }
            // Map into the guest physical address space at the fixed paddr.
            let mut guest_addr: Vaddr = 0;
            let s = zx::vmar_map(
                self.guest_vmar, GUEST_MAP, self.guest_paddr, working, 0, self.size, &mut guest_addr,
            );
            if s != ZX_OK {
                zx::handle_close(working);
                return Err(s);
            }
            // Map into the host for VMM access.
            let mut host_addr: Vaddr = 0;
            let s = zx::vmar_map(
                zx::vmar_root_self(), HOST_MAP, 0, working, 0, self.size, &mut host_addr,
            );
            if s != ZX_OK {
                zx::vmar_unmap(self.guest_vmar, self.guest_paddr, self.size);
                zx::handle_close(working);
                return Err(s);
            }
            self.working = working;
            self.host_vaddr = host_addr;
            Ok(())
        }

        // Unmap and close the current working clone.
        unsafe fn teardown_working(&mut self) {
            if self.working != HANDLE_INVALID {
                zx::vmar_unmap(self.guest_vmar, self.guest_paddr, self.size);
                if self.host_vaddr != 0 {
                    zx::vmar_unmap(zx::vmar_root_self(), self.host_vaddr, self.size);
                }
                zx::handle_close(self.working);
                self.working = HANDLE_INVALID;
                self.host_vaddr = 0;
            }
        }
    }

    impl Drop for GuestRamSnapshot {
        fn drop(&mut self) {
            unsafe {
                self.teardown_working();
                if self.baseline_vaddr != 0 {
                    zx::vmar_unmap(zx::vmar_root_self(), self.baseline_vaddr, self.size);
                }
                if self.golden != HANDLE_INVALID {
                    zx::handle_close(self.golden);
                }
            }
        }
    }
}

#[cfg(not(test))]
pub use cerise::GuestRamSnapshot;

// ─── Unit tests (portable core, host-run, no hypervisor) ────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn words_for_rounds_up() {
        assert_eq!(words_for(0), 0);
        assert_eq!(words_for(1), 1);
        assert_eq!(words_for(64), 1);
        assert_eq!(words_for(65), 2);
    }

    #[test]
    fn mark_and_query() {
        let mut bits = [0u64; 2];
        let mut t = AccessTracker::new(&mut bits, 100).unwrap();
        assert_eq!(t.dirty_count(), 0);
        t.mark_dirty(0);
        t.mark_dirty(63);
        t.mark_dirty(64);
        t.mark_dirty(99);
        assert!(t.is_dirty(0));
        assert!(t.is_dirty(63));
        assert!(t.is_dirty(64));
        assert!(t.is_dirty(99));
        assert!(!t.is_dirty(1));
        assert_eq!(t.dirty_count(), 4);
    }

    #[test]
    fn out_of_range_page_ignored() {
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, 10).unwrap();
        t.mark_dirty(10); // == page_count, out of range
        t.mark_dirty(999);
        assert_eq!(t.dirty_count(), 0);
        assert!(!t.is_dirty(10));
    }

    #[test]
    fn range_marks_all_overlapping_pages() {
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, 8).unwrap();
        // A 1-byte write at the last byte of page 0 and first of page 1.
        t.mark_range_dirty(PAGE_SIZE - 1, 2);
        assert!(t.is_dirty(0));
        assert!(t.is_dirty(1));
        assert_eq!(t.dirty_count(), 2);
    }

    #[test]
    fn range_zero_len_is_noop() {
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, 8).unwrap();
        t.mark_range_dirty(0, 0);
        assert_eq!(t.dirty_count(), 0);
    }

    #[test]
    fn for_each_dirty_ascending_and_bounded() {
        let mut bits = [0u64; 2];
        let mut t = AccessTracker::new(&mut bits, 70).unwrap();
        t.mark_dirty(5);
        t.mark_dirty(64);
        t.mark_dirty(69);
        let mut seen = alloc_vec();
        t.for_each_dirty(|p| seen.push(p));
        assert_eq!(seen, [5, 64, 69]);
    }

    #[test]
    fn bitmap_too_small_is_rejected() {
        let mut bits = [0u64; 1];
        assert_eq!(
            AccessTracker::new(&mut bits, 65).err(),
            Some(SnapshotError::BitmapTooSmall)
        );
    }

    #[test]
    fn restore_copies_only_dirty_pages() {
        let pages = 4;
        let mut baseline = vec![0u8; pages * PAGE_SIZE];
        for (i, b) in baseline.iter_mut().enumerate() {
            *b = (i % 251) as u8; // deterministic distinct baseline
        }
        let mut working = baseline.clone();
        // Guest dirties pages 1 and 3.
        for b in &mut working[PAGE_SIZE..2 * PAGE_SIZE] {
            *b = 0xAA;
        }
        for b in &mut working[3 * PAGE_SIZE..4 * PAGE_SIZE] {
            *b = 0xBB;
        }
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, pages).unwrap();
        t.mark_dirty(1);
        t.mark_dirty(3);

        let restored = restore_dirty(&baseline, &mut working, &mut t).unwrap();
        assert_eq!(restored, 2);
        assert_eq!(working, baseline);
        assert_eq!(t.dirty_count(), 0); // tracker cleared
    }

    #[test]
    fn restore_length_mismatch_rejected() {
        let baseline = vec![0u8; 2 * PAGE_SIZE];
        let mut working = vec![0u8; PAGE_SIZE];
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, 2).unwrap();
        assert_eq!(
            restore_dirty(&baseline, &mut working, &mut t).err(),
            Some(SnapshotError::LengthMismatch)
        );
    }

    #[test]
    fn restore_unaligned_rejected() {
        let baseline = vec![0u8; PAGE_SIZE + 1];
        let mut working = vec![0u8; PAGE_SIZE + 1];
        let mut bits = [0u64; 1];
        let mut t = AccessTracker::new(&mut bits, 1).unwrap();
        assert_eq!(
            restore_dirty(&baseline, &mut working, &mut t).err(),
            Some(SnapshotError::Unaligned)
        );
    }

    // Tiny helper so the test file needs no external alloc imports.
    fn alloc_vec() -> Vec<usize> {
        Vec::new()
    }
}
