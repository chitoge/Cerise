// Page-granularity allocator backed by zx_vmo_create + zx_vmar_map.
// Each allocation creates a private VMO of page-rounded size and maps it R/W.
// Deallocation is a no-op (minimal runtime; pages live until process exit).

use core::alloc::{GlobalAlloc, Layout};

use crate::zx;

struct CeriseAllocator;

unsafe impl GlobalAlloc for CeriseAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = page_round_up(layout.size().max(layout.align()));
        let mut vmo = zx::HANDLE_INVALID;
        if unsafe { zx::vmo_create(size as u64, 0, &mut vmo) } != zx::ZX_OK {
            return core::ptr::null_mut();
        }
        let mut addr: zx::Vaddr = 0;
        let status = unsafe {
            zx::vmar_map(
                zx::vmar_root_self(),
                zx::VM_PERM_READ | zx::VM_PERM_WRITE,
                0,
                vmo,
                0,
                size,
                &mut addr,
            )
        };
        // Close the VMO handle; the VMAR mapping keeps the pages alive.
        unsafe { zx::handle_close(vmo) };
        if status != zx::ZX_OK {
            return core::ptr::null_mut();
        }
        addr as *mut u8
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {
        // Intentional no-op: VMO pages are leaked until the process exits.
    }
}

#[global_allocator]
static ALLOCATOR: CeriseAllocator = CeriseAllocator;

fn page_round_up(n: usize) -> usize {
    const PAGE: usize = 4096;
    n.wrapping_add(PAGE - 1) & !(PAGE - 1)
}
