//! HypervisorBackend trait + Cerise vDSO-backed implementation.
//!
//! The trait surface is deliberately minimal: the VMM owns the
//! higher-level guest lifecycle; this crate only provides the raw object
//! handles and resume/state-read/state-write operations.

#![no_std]

use cerise_rt::zx::{
    self, Handle, PortPacket, Status, VcpuState, HANDLE_INVALID, VCPU_STATE_FULL_KIND,
    VCPU_STATE_KIND, ZX_OK,
};

// ─── Guest trap kind constants ─────────────────────────────────────────────
pub const GUEST_TRAP_IO: u32 = 2; // ZX_GUEST_TRAP_IO

// ─── Traits ───────────────────────────────────────────────────────────────

pub trait VcpuHandle {
    /// Enter the guest and block until the next exit.  Returns the port packet
    /// describing the exit reason.
    fn resume(&self) -> Result<PortPacket, Status>;

    /// Forcibly interrupt a vCPU that is inside the guest.
    fn kick(&self) -> Result<(), Status>;

    /// Read general-purpose register state.
    fn read_state_gp(&self) -> Result<VcpuState, Status>;

    /// Write general-purpose register state.
    fn write_state_gp(&self, regs: &VcpuState) -> Result<(), Status>;

    /// Read the complete architectural state into `buf` as a versioned,
    /// self-describing buffer. Carries what the general registers do not — the
    /// instruction pointer, segment and descriptor-table registers, and control
    /// and mode registers — so a VMM can put a vCPU back where it was rather
    /// than only adjust one that is running.
    fn read_state_full(&self, buf: &mut [u8]) -> Result<(), Status>;

    /// Restore state previously read by `read_state_full`. A buffer this kernel
    /// does not recognise is refused rather than partially applied.
    fn write_state_full(&self, buf: &[u8]) -> Result<(), Status>;
}

pub trait HypervisorBackend {
    type Vcpu: VcpuHandle;

    /// Allocate a guest physical address space.
    /// Returns (guest_handle, vmar_handle).
    fn create_guest(&self) -> Result<(Handle, Handle), Status>;

    /// Register a port-IO trap on `[addr, addr+size)` with no port (synchronous).
    fn set_trap_io(
        &self,
        guest: Handle,
        addr: u16,
        size: usize,
    ) -> Result<(), Status>;

    /// Create a vCPU that starts executing at `entry` (guest physical address).
    fn create_vcpu(
        &self,
        guest: Handle,
        entry: u64,
    ) -> Result<Self::Vcpu, Status>;
}

// ─── Cerise (Zircon vDSO) implementation ────────────────────────────────

pub struct CeriseVcpu {
    handle: Handle,
}

impl Drop for CeriseVcpu {
    fn drop(&mut self) {
        if self.handle != HANDLE_INVALID {
            unsafe { zx::handle_close(self.handle) };
        }
    }
}

impl VcpuHandle for CeriseVcpu {
    fn resume(&self) -> Result<PortPacket, Status> {
        let mut pkt = PortPacket::zeroed();
        let s = unsafe { zx::vcpu_enter(self.handle, &mut pkt) };
        if s == ZX_OK { Ok(pkt) } else { Err(s) }
    }

    fn kick(&self) -> Result<(), Status> {
        let s = unsafe { zx::vcpu_kick(self.handle) };
        if s == ZX_OK { Ok(()) } else { Err(s) }
    }

    fn read_state_gp(&self) -> Result<VcpuState, Status> {
        let mut st = VcpuState {
            rax: 0, rcx: 0, rdx: 0, rbx: 0,
            rsp: 0, rbp: 0, rsi: 0, rdi: 0,
            r8: 0, r9: 0, r10: 0, r11: 0,
            r12: 0, r13: 0, r14: 0, r15: 0,
            rflags: 0,
        };
        let s = unsafe {
            zx::vcpu_read_state(
                self.handle,
                VCPU_STATE_KIND,
                &mut st as *mut VcpuState as *mut u8,
                core::mem::size_of::<VcpuState>(),
            )
        };
        if s == ZX_OK { Ok(st) } else { Err(s) }
    }

    fn write_state_gp(&self, regs: &VcpuState) -> Result<(), Status> {
        let s = unsafe {
            zx::vcpu_write_state(
                self.handle,
                VCPU_STATE_KIND,
                regs as *const VcpuState as *const u8,
                core::mem::size_of::<VcpuState>(),
            )
        };
        if s == ZX_OK { Ok(()) } else { Err(s) }
    }

    fn read_state_full(&self, buf: &mut [u8]) -> Result<(), Status> {
        let s = unsafe {
            zx::vcpu_read_state(self.handle, VCPU_STATE_FULL_KIND, buf.as_mut_ptr(), buf.len())
        };
        if s == ZX_OK { Ok(()) } else { Err(s) }
    }

    fn write_state_full(&self, buf: &[u8]) -> Result<(), Status> {
        let s = unsafe {
            zx::vcpu_write_state(self.handle, VCPU_STATE_FULL_KIND, buf.as_ptr(), buf.len())
        };
        if s == ZX_OK { Ok(()) } else { Err(s) }
    }
}

pub struct CeriseBackend;

impl HypervisorBackend for CeriseBackend {
    type Vcpu = CeriseVcpu;

    fn create_guest(&self) -> Result<(Handle, Handle), Status> {
        // guest_create requires a ZX_RSRC_SYSTEM_HYPERVISOR_BASE resource; use the
        // SYSTEM resource cerise_rt extracted from the bootstrap message (the
        // ranged root for SYSTEM-kind covers the hypervisor base).
        let resource = zx::system_resource();
        let mut guest = HANDLE_INVALID;
        let mut vmar = HANDLE_INVALID;
        let s = unsafe { zx::guest_create(resource, 0, &mut guest, &mut vmar) };
        if s == ZX_OK { Ok((guest, vmar)) } else { Err(s) }
    }

    fn set_trap_io(&self, guest: Handle, addr: u16, size: usize) -> Result<(), Status> {
        let s = unsafe {
            zx::guest_set_trap(guest, GUEST_TRAP_IO, addr as usize, size, HANDLE_INVALID, 0)
        };
        if s == ZX_OK { Ok(()) } else { Err(s) }
    }

    fn create_vcpu(&self, guest: Handle, entry: u64) -> Result<CeriseVcpu, Status> {
        let mut handle = HANDLE_INVALID;
        let s = unsafe { zx::vcpu_create(guest, 0, entry as usize, &mut handle) };
        if s == ZX_OK { Ok(CeriseVcpu { handle }) } else { Err(s) }
    }
}
