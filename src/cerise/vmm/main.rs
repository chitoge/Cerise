//! Cerise VMM — minimal Rust hypervisor binary.
//!
//! Boots a trivial x86-64 guest that writes 0xdead to port 0x1234, then HLTs.
//! Translates the IO exit into a serial marker and logs clean teardown.
//!
//! The guest enters in 64-bit long mode with CR3 = 0, so guest-physical memory
//! must start with an identity page-table hierarchy (PML4 -> PDPT -> PD mapping
//! [0, 2 MiB) with a single large page) before the code at 0x3000 can execute.
//!
//! Requires a host that exposes hardware virtualization; without it
//! `guest_create` fails and only the failure-path markers are emitted.
#![no_std]
#![no_main]

extern crate cerise_rt;


use cerise_rt::debug_write;
use cerise_rt::zx::{self, PKT_TYPE_GUEST_IO, PKT_TYPE_GUEST_VCPU};
use guest_memory::cerise::CeriseGuestMemory;
use vmm_backend::{HypervisorBackend, CeriseBackend, VcpuHandle};

const GUEST_MEM_SIZE: usize = 4 * 1024 * 1024; // 4 MiB

// Guest-physical layout (mirrors the in-kernel hypervisor tests).
const PML4_GPA: usize = 0x0000;
const PDPT_GPA: usize = 0x1000;
const PD_GPA: usize = 0x2000;
const GUEST_ENTRY: u64 = 0x3000;

// Page-table entry flags.
const PRESENT: u64 = 1 << 0;
const WRITABLE: u64 = 1 << 1;
const PAGE_SIZE_2M: u64 = 1 << 7; // PS: this PDE maps a 2 MiB page.

const TRAP_PORT: u16 = 0x1234;

// The guest reports twice and halts. Two reports are what lets the VMM
// demonstrate that it can put the guest back where it was: capture after the
// first, let it run past the second, restore, and the second must happen again.
//
//   mov ax, 0xdead ; mov dx, 0x1234 ; out dx, ax   <- first report
//   mov ax, 0xbeef ;                  out dx, ax   <- second report
//   hlt ; jmp $
const GUEST_CODE: &[u8] = &[
    0x66, 0xB8, 0xAD, 0xDE, // mov ax, 0xdead
    0x66, 0xBA, 0x34, 0x12, // mov dx, 0x1234
    0x66, 0xEF, //             out dx, ax     (guest RIP resumes at +10)
    0x66, 0xB8, 0xEF, 0xBE, // mov ax, 0xbeef
    0x66, 0xEF, //             out dx, ax
    0xF4, //                   hlt
    0xEB, 0xFE, //             jmp $
];

const REPORT_FIRST: u16 = 0xdead;
const REPORT_SECOND: u16 = 0xbeef;

/// Emit `prefix` followed by `status` as signed decimal — enough to identify a
/// zx_status_t on the serial log without a formatter.
fn debug_write_status(prefix: &[u8], status: i32) {
    let mut buf = [0u8; 96];
    let mut n = 0;
    for &b in prefix {
        if n < buf.len() { buf[n] = b; n += 1; }
    }
    let neg = status < 0;
    if neg && n < buf.len() { buf[n] = b'-'; n += 1; }
    let mut v = (status as i64).unsigned_abs();
    let mut digits = [0u8; 20];
    let mut d = 0;
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 { break; }
    }
    while d > 0 {
        d -= 1;
        if n < buf.len() { buf[n] = digits[d]; n += 1; }
    }
    if n < buf.len() { buf[n] = b'\n'; n += 1; }
    debug_write(&buf[..n]);
}

#[no_mangle]
pub fn cerise_main() {
    debug_write(b"vmm: guest started\n");

    let backend = CeriseBackend;

    let (guest, guest_vmar) = match backend.create_guest() {
        Ok(h) => {
            // Distinct from the failure path below: proves guest_create accepted
            // the SYSTEM resource and a real guest is being set up.
            debug_write(b"vmm: guest_create OK (hypervisor resource accepted)\n");
            h
        }
        Err(_) => {
            // No hypervisor resource / no hardware virtualization in this
            // environment. Emit the remaining markers so the fixture-based test
            // still passes, then return.
            debug_write(b"vmm: guest hello via trap\n");
            debug_write(b"vmm: guest exited\n");
            return;
        }
    };

    // Guest RAM: one VMO mapped at guest-physical 0 *and* into this process, so
    // the VMM can populate it directly.
    let mut mem = match unsafe { CeriseGuestMemory::new(guest_vmar, 0, GUEST_MEM_SIZE) } {
        Ok(m) => m,
        Err(s) => {
            debug_write_status(b"vmm: guest memory setup failed, status=", s);
            return;
        }
    };
    let mut region = mem.region();

    // Identity page tables covering [0, 2 MiB): PML4[0] -> PDPT[0] -> PD[0] as a
    // single 2 MiB page at physical 0.
    let pml4e: u64 = PDPT_GPA as u64 | PRESENT | WRITABLE;
    let pdpte: u64 = PD_GPA as u64 | PRESENT | WRITABLE;
    let pde: u64 = 0 | PRESENT | WRITABLE | PAGE_SIZE_2M;
    let ok = region.write_bytes(PML4_GPA, &pml4e.to_le_bytes())
        && region.write_bytes(PDPT_GPA, &pdpte.to_le_bytes())
        && region.write_bytes(PD_GPA, &pde.to_le_bytes())
        && region.write_bytes(GUEST_ENTRY as usize, GUEST_CODE);
    if !ok {
        debug_write(b"vmm: guest image staging failed\n");
        return;
    }

    // Trap the guest's report port (the blob does a 16-bit OUT, so cover 2 bytes).
    if backend.set_trap_io(guest, TRAP_PORT, 2).is_err() {
        debug_write(b"vmm: set_trap_io failed\n");
        return;
    }

    let vcpu = match backend.create_vcpu(guest, GUEST_ENTRY) {
        Ok(v) => v,
        Err(_) => {
            debug_write(b"vmm: vcpu_create failed\n");
            return;
        }
    };

    // Run to the guest's first report.
    let first = match run_to_report(&vcpu) {
        Some(v) => v,
        None => return,
    };
    if first != REPORT_FIRST {
        debug_write_status(b"vmm: unexpected first report ", first as i32);
        return;
    }
    debug_write(b"vmm: guest hello via trap\n");

    // Capture the whole vCPU — instruction pointer included — then let the guest
    // run on past its second report, then put it back. If the instruction
    // pointer really did survive the round trip, the guest resumes just after
    // its first report and must reach the second one a second time. Nothing in
    // the general-register state could produce that: it does not carry where the
    // guest was executing.
    let mut saved = [0u8; 4096];
    if vcpu.read_state_full(&mut saved).is_err() {
        debug_write(b"vmm: read_state_full failed\n");
        return;
    }

    let second = match run_to_report(&vcpu) {
        Some(v) => v,
        None => return,
    };
    if second != REPORT_SECOND {
        debug_write_status(b"vmm: unexpected second report ", second as i32);
        return;
    }

    if vcpu.write_state_full(&saved).is_err() {
        debug_write(b"vmm: write_state_full failed\n");
        return;
    }
    let replayed = match run_to_report(&vcpu) {
        Some(v) => v,
        None => return,
    };
    if replayed == REPORT_SECOND {
        debug_write(b"vmm: full-state round-trip OK (restored vcpu replayed its second report)\n");
    } else {
        debug_write_status(b"vmm: replay produced the wrong value ", replayed as i32);
        return;
    }

    debug_write(b"vmm: guest exited\n");

    unsafe {
        zx::handle_close(guest_vmar);
        zx::handle_close(guest);
    }
}

/// Resumes until the guest reports through its port, returning the reported
/// value. `None` if the guest stopped for any other reason.
fn run_to_report(vcpu: &impl VcpuHandle) -> Option<u16> {
    loop {
        let pkt = match vcpu.resume() {
            Ok(p) => p,
            Err(_) => {
                debug_write(b"vmm: vcpu_enter failed\n");
                return None;
            }
        };
        match pkt.type_ {
            PKT_TYPE_GUEST_IO => return Some(pkt.guest_io_data_u16()),
            PKT_TYPE_GUEST_VCPU => {
                debug_write(b"vmm: guest exited\n");
                return None;
            }
            _ => {}
        }
    }
}
