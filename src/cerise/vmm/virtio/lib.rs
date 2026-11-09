//! Virtio split-queue ring types — host (VMM) side.
//!
//! Provides the descriptor table, available ring, and used ring structures
//! for managing virtio queues from the VMM's perspective.  The VMM populates
//! used-ring entries in response to guest notifications; the guest driver
//! populates available-ring entries.
//!
//! Draft: types and ring management only; MMIO transport is not wired here
//! (device models compose with these types and supply their own transport).
#![no_std]

// ─── Virtio split-queue flags ─────────────────────────────────────────────

pub const VRING_DESC_F_NEXT: u16  = 0x01;
pub const VRING_DESC_F_WRITE: u16 = 0x02; // device-writable (RX descriptors)

// ─── Virtio 1.x split-queue structures ───────────────────────────────────

/// Virtio descriptor table entry (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioDesc {
    pub addr:  u64,
    pub len:   u32,
    pub flags: u16,
    pub next:  u16,
}

/// Available ring header (precedes the ring[] array in guest memory).
#[repr(C)]
pub struct VirtioAvailHdr {
    pub flags: u16,
    pub idx:   u16,
}

/// Used ring element — returned by the device after consuming a descriptor.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioUsedElem {
    pub id:  u32,
    pub len: u32,
}

/// Used ring header (precedes the ring[] array in guest memory).
#[repr(C)]
pub struct VirtioUsedHdr {
    pub flags: u16,
    pub idx:   u16,
}

// ─── Virtio-net header ────────────────────────────────────────────────────

/// Virtio-net packet header (always prepended to each frame, both TX and RX).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioNetHdr {
    pub flags:       u8,
    pub gso_type:    u8,
    pub hdr_len:     u16,
    pub gso_size:    u16,
    pub csum_start:  u16,
    pub csum_offset: u16,
}

// ─── Virtio console header ────────────────────────────────────────────────

/// virtio-console port-specific control event (simplified).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VirtioConsoleCtrl {
    pub id:    u32,
    pub event: u16,
    pub value: u16,
}

// ─── Host-side queue handle ───────────────────────────────────────────────

/// VMM-side handle to a single virtqueue.
/// Raw pointers into guest-physical memory (host-mapped DMA region).
pub struct VirtioQueue {
    pub descs:      *mut VirtioDesc,
    pub avail_hdr:  *const VirtioAvailHdr,
    pub avail_ring: *const u16,     // avail->ring[queue_size]
    pub used_hdr:   *mut VirtioUsedHdr,
    pub used_ring:  *mut VirtioUsedElem, // used->ring[queue_size]
    pub queue_size: u16,
    pub last_used:  u16,
}

impl VirtioQueue {
    /// Drain all entries the guest has made available.
    /// Calls `handler(desc_id, desc)` for each available descriptor.
    /// Returns how many descriptors were consumed.
    pub unsafe fn drain_avail(&mut self, mut handler: impl FnMut(u16, &VirtioDesc)) -> u16 {
        let avail_idx = (*self.avail_hdr).idx;
        let mut count = 0u16;
        while self.last_used != avail_idx {
            let slot = (self.last_used % self.queue_size) as usize;
            let desc_id = *self.avail_ring.add(slot);
            let desc = &*self.descs.add(desc_id as usize);
            handler(desc_id, desc);
            // Publish used ring entry.
            let used_slot = (self.last_used % self.queue_size) as usize;
            (*self.used_ring.add(used_slot)) = VirtioUsedElem { id: desc_id as u32, len: desc.len };
            (*self.used_hdr).idx = self.last_used.wrapping_add(1);
            self.last_used = self.last_used.wrapping_add(1);
            count += 1;
        }
        count
    }
}
