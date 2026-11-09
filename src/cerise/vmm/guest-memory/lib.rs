//! Guest physical memory abstraction.
//!
//! `GuestMemoryRegion` wraps a host-accessible byte slice at a known guest
//! physical base address.  It is the core read/write primitive; unit tests
//! use a stack-allocated buffer.
//!
//! `CeriseGuestMemory` allocates a VMO, maps it into both the guest VMAR
//! (so the hypervisor can back guest physical pages) and into the host
//! process VMAR (so the VMM can read/write guest memory directly).

#![cfg_attr(not(test), no_std)]

// ─── Core accessor — no syscalls, testable on any platform ────────────────

/// A contiguous region of guest physical memory accessible from the host.
///
/// The caller is responsible for the lifetime of the backing memory; this
/// struct is just a typed view.
pub struct GuestMemoryRegion {
    ptr: *mut u8,
    size: usize,
}

unsafe impl Send for GuestMemoryRegion {}
unsafe impl Sync for GuestMemoryRegion {}

impl GuestMemoryRegion {
    /// Construct from a raw pointer + byte length.
    ///
    /// # Safety
    /// `ptr` must be valid for reads and writes for `size` bytes for the
    /// lifetime of the returned `GuestMemoryRegion`.
    pub unsafe fn from_raw_parts(ptr: *mut u8, size: usize) -> Self {
        Self { ptr, size }
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr
    }

    /// Read a `u32` from `offset` (little-endian, unaligned).
    pub fn read_u32(&self, offset: usize) -> Option<u32> {
        if offset.checked_add(4)? > self.size {
            return None;
        }
        let val = unsafe { (self.ptr.add(offset) as *const u32).read_unaligned() };
        Some(u32::from_le(val))
    }

    /// Write a `u32` to `offset` (little-endian, unaligned).
    pub fn write_u32(&mut self, offset: usize, val: u32) -> bool {
        if offset.checked_add(4).map_or(true, |end| end > self.size) {
            return false;
        }
        unsafe { (self.ptr.add(offset) as *mut u32).write_unaligned(val.to_le()) };
        true
    }

    /// Copy a byte slice into the region at `offset`.
    pub fn write_bytes(&mut self, offset: usize, src: &[u8]) -> bool {
        if offset.checked_add(src.len()).map_or(true, |end| end > self.size) {
            return false;
        }
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), self.ptr.add(offset), src.len()) };
        true
    }

    /// Copy bytes out of the region at `offset` into `dst`.
    pub fn read_bytes(&self, offset: usize, dst: &mut [u8]) -> bool {
        if offset.checked_add(dst.len()).map_or(true, |end| end > self.size) {
            return false;
        }
        unsafe { core::ptr::copy_nonoverlapping(self.ptr.add(offset), dst.as_mut_ptr(), dst.len()) };
        true
    }
}

// ─── Cerise VMO-backed implementation ───────────────────────────────────

#[cfg(not(test))]
pub mod cerise {
    use super::GuestMemoryRegion;
    use cerise_rt::zx::{self, Handle, Status, ZX_OK, HANDLE_INVALID,
                          VM_PERM_READ, VM_PERM_WRITE, VM_PERM_EXECUTE, VM_SPECIFIC,
                          VM_MAP_RANGE};

    /// Guest physical memory backed by a Zircon VMO.
    ///
    /// The VMO is mapped into both the guest physical VMAR (at `guest_paddr`)
    /// and the host process VMAR for direct host access.
    pub struct CeriseGuestMemory {
        vmo: Handle,
        host_vaddr: usize,
        size: usize,
    }

    impl CeriseGuestMemory {
        /// Allocate `size` bytes, mapped at `guest_paddr` in the guest VMAR.
        pub unsafe fn new(
            guest_vmar: Handle,
            guest_paddr: usize,
            size: usize,
        ) -> Result<Self, Status> {
            let mut vmo = HANDLE_INVALID;
            let s = zx::vmo_create(size as u64, 0, &mut vmo);
            if s != ZX_OK { return Err(s); }

            // A zx_vmo_create handle carries no ZX_RIGHT_EXECUTE, but mapping the
            // guest's RAM with ZX_VM_PERM_EXECUTE (so the guest can fetch
            // instructions out of it) requires it. Re-mint the handle as
            // executable using the SYSTEM resource as the vmex.
            let mut exec_vmo = HANDLE_INVALID;
            let s = zx::vmo_replace_as_executable(vmo, zx::system_resource(), &mut exec_vmo);
            if s != ZX_OK { return Err(s); }
            let vmo = exec_vmo;

            // Map into guest physical address space at exactly `guest_paddr`
            // (ZX_VM_SPECIFIC is 1<<4 — an earlier 0x4 here was PERM_EXECUTE, so
            // the requested GPA was silently ignored). EXECUTE is required for the
            // guest to fetch instructions out of this memory.
            let mut dummy_addr: usize = 0;
            let s = zx::vmar_map(
                guest_vmar,
                VM_PERM_READ | VM_PERM_WRITE | VM_PERM_EXECUTE | VM_SPECIFIC | VM_MAP_RANGE,
                guest_paddr,
                vmo,
                0,
                size,
                &mut dummy_addr,
            );
            if s != ZX_OK {
                zx::handle_close(vmo);
                return Err(s);
            }

            // Map into host process for direct VMM access. Uses the root VMAR
            // handed to us in the bootstrap message rather than
            // `zx_vmar_root_self()`, whose vDSO-side global is only populated by
            // libc startup (absent in this runtime, where it reads back invalid).
            let mut host_vaddr: usize = 0;
            let s = zx::vmar_map(
                zx::vmar_root(),
                VM_PERM_READ | VM_PERM_WRITE,
                0,
                vmo,
                0,
                size,
                &mut host_vaddr,
            );
            if s != ZX_OK {
                zx::handle_close(vmo);
                return Err(s);
            }

            Ok(Self { vmo, host_vaddr, size })
        }

        pub fn region(&mut self) -> GuestMemoryRegion {
            unsafe { GuestMemoryRegion::from_raw_parts(self.host_vaddr as *mut u8, self.size) }
        }

        pub fn size(&self) -> usize { self.size }
    }

    impl Drop for CeriseGuestMemory {
        fn drop(&mut self) {
            unsafe { zx::handle_close(self.vmo) };
        }
    }
}

#[cfg(not(test))]
pub use cerise::CeriseGuestMemory;

// ─── Unit tests (run on host, stack-backed buffer) ─────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_region(buf: &mut [u8]) -> GuestMemoryRegion {
        unsafe { GuestMemoryRegion::from_raw_parts(buf.as_mut_ptr(), buf.len()) }
    }

    #[test]
    fn round_trip_u32() {
        let mut buf = [0u8; 64];
        let mut r = make_region(&mut buf);
        assert!(r.write_u32(0, 0xDEAD_BEEF));
        assert_eq!(r.read_u32(0), Some(0xDEAD_BEEF));
    }

    #[test]
    fn round_trip_at_offset() {
        let mut buf = [0u8; 64];
        let mut r = make_region(&mut buf);
        assert!(r.write_u32(28, 0x1234_5678));
        assert_eq!(r.read_u32(28), Some(0x1234_5678));
    }

    #[test]
    fn out_of_bounds_write() {
        let mut buf = [0u8; 8];
        let mut r = make_region(&mut buf);
        assert!(!r.write_u32(6, 42)); // 6+4 = 10 > 8
    }

    #[test]
    fn out_of_bounds_read() {
        let buf = [0u8; 8];
        let r = unsafe { GuestMemoryRegion::from_raw_parts(buf.as_ptr() as *mut u8, buf.len()) };
        assert_eq!(r.read_u32(6), None);
    }

    #[test]
    fn write_bytes_round_trip() {
        let mut buf = [0u8; 16];
        let mut r = make_region(&mut buf);
        let src = b"hello";
        assert!(r.write_bytes(4, src));
        let mut dst = [0u8; 5];
        assert!(r.read_bytes(4, &mut dst));
        assert_eq!(&dst, src);
    }

    #[test]
    fn write_bytes_out_of_bounds() {
        let mut buf = [0u8; 8];
        let mut r = make_region(&mut buf);
        assert!(!r.write_bytes(6, b"123")); // 6+3 = 9 > 8
    }
}
