//! Virtio-net device model — VMM side (stub / draft).
//!
//! A full virtio-net device model manages two virtqueues (RX/TX), a MAC
//! address, and bridges guest Ethernet frames to the host network stack
//! (via the netstack).  This stub establishes the type surface and
//! dispatch pattern; actual frame forwarding is deferred until the
//! integration is available in the VMM context.
//!
//! In draft mode the device responds to a port-IO exit on `trap_port`
//! (0x5001) to indicate "guest sent a frame", and logs a marker.
#![no_std]

use cerise_rt::debug_write;

/// Virtio-net device model (VMM side).
pub struct VirtioNetDev {
    pub trap_port: u16,
    pub mac: [u8; 6],
}

impl VirtioNetDev {
    pub const fn new(trap_port: u16) -> Self {
        Self {
            trap_port,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56], // QEMU default OUI
        }
    }

    /// Handle a `PKT_TYPE_GUEST_IO` exit.
    /// Returns `true` if the port belonged to this device and was consumed.
    pub fn handle_io(&self, port: u16, _data: u16) -> bool {
        if port != self.trap_port { return false; }
        debug_write(b"vmm: virtio-net: guest tx frame\n");
        true
    }
}
