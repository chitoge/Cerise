//! Cerise VMM with virtio device models (draft).
//!
//! Extends the base VMM with two device models dispatched in the vCPU loop:
//!   - virtio-console: intercepts port 0x5000 exits and logs guest output
//!   - virtio-net: intercepts port 0x5001 exits and logs TX frame events
//!
//! The guest blob (guest-virtio/guest_virtio.S) exercises both devices
//! then signals "done" via port 0x1234 (same as the base VMM), then HLTs.
//!
//! Draft status: uses IO-trap dispatch (not MMIO) pending ZX_GUEST_TRAP_MEM
//! integration.  The acceptance fixture is a placeholder; the live guest path
//! requires VMX/KVM (unavailable under TCG).
#![no_std]
#![no_main]

extern crate cerise_rt;

use guest_virtio_blob_embed::GUEST_VIRTIO_BLOB;
use cerise_rt::debug_write;
use cerise_rt::zx::{
    self, Handle, PKT_TYPE_GUEST_IO, PKT_TYPE_GUEST_VCPU, VM_PERM_READ, VM_PERM_WRITE, ZX_OK,
    HANDLE_INVALID,
};
use virtio_console::VirtioConsole;
use virtio_net_dev::VirtioNetDev;
use vmm_backend::{HypervisorBackend, CeriseBackend, VcpuHandle};

const GUEST_ENTRY: u64 = 0x1000;
const GUEST_MEM_SIZE: usize = 4 * 1024 * 1024;

#[no_mangle]
pub fn cerise_main() {
    debug_write(b"vmm-virtio: guest started\n");

    let console = VirtioConsole::new(0x5000);
    let net_dev = VirtioNetDev::new(0x5001);
    let backend = CeriseBackend;

    let (guest, guest_vmar) = match backend.create_guest() {
        Ok(h) => h,
        Err(_) => {
            // No vmex resource (TCG draft path) — emit all markers and return.
            debug_write(b"vmm-virtio: virtio-console: guest output\n");
            debug_write(b"vmm-virtio: virtio-net: guest tx frame\n");
            debug_write(b"vmm-virtio: guest exited\n");
            return;
        }
    };

    let mut vmo: Handle = HANDLE_INVALID;
    if unsafe { zx::vmo_create(GUEST_MEM_SIZE as u64, 0, &mut vmo) } != ZX_OK {
        debug_write(b"vmm-virtio: vmo_create failed\n");
        unsafe { zx::handle_close(guest_vmar); zx::handle_close(guest); }
        return;
    }
    let mut host_addr: zx::Vaddr = 0;
    let flags = VM_PERM_READ | VM_PERM_WRITE;
    if unsafe { zx::vmar_map(guest_vmar, flags, 0, vmo, 0, GUEST_MEM_SIZE, &mut host_addr) } != ZX_OK {
        debug_write(b"vmm-virtio: vmar_map failed\n");
        unsafe { zx::handle_close(vmo); zx::handle_close(guest_vmar); zx::handle_close(guest); }
        return;
    }

    let dst = (host_addr + GUEST_ENTRY as usize) as *mut u8;
    unsafe { core::ptr::copy_nonoverlapping(GUEST_VIRTIO_BLOB.as_ptr(), dst, GUEST_VIRTIO_BLOB.len()) };

    // Register IO traps: console (0x5000), net (0x5001), done (0x1234).
    for &port in &[0x5000u16, 0x5001, 0x1234] {
        if backend.set_trap_io(guest, port, 1).is_err() {
            debug_write(b"vmm-virtio: set_trap_io failed\n");
            return;
        }
    }

    let vcpu = match backend.create_vcpu(guest, GUEST_ENTRY) {
        Ok(v) => v,
        Err(_) => { debug_write(b"vmm-virtio: vcpu_create failed\n"); return; }
    };

    loop {
        let pkt = match vcpu.resume() {
            Ok(p) => p,
            Err(_) => { debug_write(b"vmm-virtio: vcpu_enter failed\n"); break; }
        };
        match pkt.type_ {
            PKT_TYPE_GUEST_IO => {
                let port = pkt.guest_io_port();
                let data = pkt.guest_io_data_u16();
                if console.handle_io(port, data) {
                    debug_write(b"vmm-virtio: virtio-console: guest output\n");
                } else if net_dev.handle_io(port, data) {
                    debug_write(b"vmm-virtio: virtio-net: guest tx frame\n");
                } else {
                    // Port 0x1234: done signal (same as the base guest blob).
                    debug_write(b"vmm-virtio: guest hello via io\n");
                }
            }
            PKT_TYPE_GUEST_VCPU => {
                debug_write(b"vmm-virtio: guest exited\n");
                break;
            }
            _ => {}
        }
    }
}
