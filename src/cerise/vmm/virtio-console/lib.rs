//! Virtio-console device model — VMM side.
//!
//! In a full implementation the device model manages two virtqueues (RX/TX per
//! port 0) backed by DMA-pinned guest memory.  The draft uses port-IO exits
//! instead of MMIO: the guest writes a byte value to `TRAP_PORT` which the
//! VMM intercepts via `PKT_TYPE_GUEST_IO` and forwards to the debuglog.
//! This lets the vCPU loop in `cerise-vmm-virtio` demonstrate the multi-
//! device dispatch pattern without requiring MMIO trap handling.
//!
//! Draft status: IO-trap path only.  MMIO + virtio ring path is TODO once
//! the VMM has `ZX_GUEST_TRAP_MEM` support wired.
#![no_std]

use cerise_rt::debug_write;

/// Virtio-console device model.
pub struct VirtioConsole {
    /// Port-IO trap address used in draft mode.
    pub trap_port: u16,
}

impl VirtioConsole {
    pub const fn new(trap_port: u16) -> Self { Self { trap_port } }

    /// Handle a `PKT_TYPE_GUEST_IO` exit.
    /// Returns `true` if the port belonged to this device and was consumed.
    pub fn handle_io(&self, port: u16, _data: u16) -> bool {
        if port != self.trap_port { return false; }
        debug_write(b"vmm: virtio-console: guest output\n");
        true
    }
}
