// Cerise syscall interface via vDSO function pointers.
//
// The vDSO base address is handed to `_start` by userboot.  `init_from_vdso`
// must be called once (before any use of these functions) to walk the vDSO ELF
// and store the resolved function pointers in the globals below.
//
// Direct syscall instructions are NOT used — the kernel validates that
// each `syscall` return address belongs to an approved site inside the vDSO
// (see zircon-syscall-x86.S: CODE_SYSRET_* label guard).

use core::sync::atomic::{AtomicUsize, Ordering};

pub type Handle = u32;
pub type Status = i32;
pub type VmOption = u32;
pub type Vaddr = usize;

pub const HANDLE_INVALID: Handle = 0;
pub const ZX_OK: Status = 0;
pub const VM_PERM_READ: VmOption = 1 << 0;
pub const VM_PERM_WRITE: VmOption = 1 << 1;
pub const VM_PERM_EXECUTE: VmOption = 1 << 2;
// zx_vm_option_t bits (zircon/system/public/zircon/types.h) — kernel-authoritative.
pub const VM_SPECIFIC: VmOption = 1 << 4;
pub const VM_MAP_RANGE: VmOption = 1 << 10;
// zx_vmo_create_child options (zircon/system/public/zircon/types.h).
pub const VMO_CHILD_SNAPSHOT: u32 = 1 << 0;
pub const VMO_CHILD_SNAPSHOT_AT_LEAST_ON_WRITE: u32 = 1 << 4;
pub const VMO_CHILD_SNAPSHOT_MODIFIED: u32 = 1 << 7;
pub const VMO_CHILD_RESIZABLE: u32 = 1 << 2;
pub const VMO_CHILD_NO_WRITE: u32 = 1 << 5;
// zx_vmo_op_range ops (zircon/system/public/zircon/types.h). Reverts a
// copy-on-write child VMO to its parent's baseline content (snapshot restore).
pub const VMO_OP_REVERT_TO_SNAPSHOT: u32 = 15;
// Query the set of pages a CoW child has forked (dirty tracking); buffer
// receives a 1-bit-per-page bitmap.
pub const VMO_OP_QUERY_DIRTY: u32 = 16;
// zx_handle_duplicate rights: keep the source handle's rights.
pub const RIGHT_SAME_RIGHTS: u32 = 0xFFFF_FFFF;

static ZX_DEBUGLOG_CREATE: AtomicUsize = AtomicUsize::new(0);
static ZX_DEBUGLOG_WRITE: AtomicUsize = AtomicUsize::new(0);
static ZX_PROCESS_EXIT: AtomicUsize = AtomicUsize::new(0);
static ZX_VMO_CREATE: AtomicUsize = AtomicUsize::new(0);
static ZX_VMO_CREATE_CHILD: AtomicUsize = AtomicUsize::new(0);
static ZX_VMO_OP_RANGE: AtomicUsize = AtomicUsize::new(0);
static ZX_HANDLE_DUPLICATE: AtomicUsize = AtomicUsize::new(0);
static ZX_VMAR_MAP: AtomicUsize = AtomicUsize::new(0);
static ZX_VMAR_UNMAP: AtomicUsize = AtomicUsize::new(0);
static ZX_HANDLE_CLOSE: AtomicUsize = AtomicUsize::new(0);
static ZX_VMAR_ROOT_SELF: AtomicUsize = AtomicUsize::new(0);
static ZX_GUEST_CREATE: AtomicUsize = AtomicUsize::new(0);
static ZX_GUEST_SET_TRAP: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_CREATE: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_ENTER: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_KICK: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_INTERRUPT: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_READ_STATE: AtomicUsize = AtomicUsize::new(0);
static ZX_VCPU_WRITE_STATE: AtomicUsize = AtomicUsize::new(0);
static ZX_CHANNEL_READ: AtomicUsize = AtomicUsize::new(0);
static ZX_VMO_REPLACE_AS_EXECUTABLE: AtomicUsize = AtomicUsize::new(0);

// Startup handle extracted from the bootstrap processargs message: the SYSTEM
// resource userboot passes to its `next` program (PA_SYSTEM_RESOURCE). It is the
// ranged root for ZX_RSRC_KIND_SYSTEM, so it validates for guest_create's
// hypervisor-base check without needing a create_child.
static SYSTEM_RESOURCE: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(HANDLE_INVALID);

// The process's root VMAR, also taken from the bootstrap message. `zx_vmar_root_self()`
// cannot be used here: it returns a vDSO-side global that libc's startup normally
// initializes from PA_VMAR_ROOT, and this runtime has no libc — so it reads back as
// ZX_HANDLE_INVALID and any vmar_map through it fails with ZX_ERR_BAD_HANDLE.
static VMAR_ROOT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(HANDLE_INVALID);

// processargs (zircon/system/public/zircon/processargs.h).
const ZX_PROCARGS_PROTOCOL: u32 = 0x4150_585d;
pub const PA_SYSTEM_RESOURCE: u32 = 0x54;
pub const PA_VMAR_ROOT: u32 = 0x04;

/// Resolve vDSO function pointers from the ELF mapped at `vdso_base`.
/// Must be called once from `_start` before any syscalls are issued.
pub unsafe fn init_from_vdso(vdso_base: usize) {
    macro_rules! resolve {
        ($global:expr, $name:expr) => {
            $global.store(resolve_symbol(vdso_base, $name), Ordering::Release);
        };
    }
    resolve!(ZX_DEBUGLOG_CREATE,  b"_zx_debuglog_create");
    resolve!(ZX_DEBUGLOG_WRITE,   b"_zx_debuglog_write");
    resolve!(ZX_PROCESS_EXIT,     b"_zx_process_exit");
    resolve!(ZX_VMO_CREATE,       b"_zx_vmo_create");
    resolve!(ZX_VMO_CREATE_CHILD, b"_zx_vmo_create_child");
    resolve!(ZX_VMO_OP_RANGE,     b"_zx_vmo_op_range");
    resolve!(ZX_HANDLE_DUPLICATE, b"_zx_handle_duplicate");
    resolve!(ZX_VMAR_MAP,         b"_zx_vmar_map");
    resolve!(ZX_VMAR_UNMAP,       b"_zx_vmar_unmap");
    resolve!(ZX_HANDLE_CLOSE,     b"_zx_handle_close");
    resolve!(ZX_VMAR_ROOT_SELF,   b"_zx_vmar_root_self");
    resolve!(ZX_GUEST_CREATE,     b"_zx_guest_create");
    resolve!(ZX_GUEST_SET_TRAP,   b"_zx_guest_set_trap");
    resolve!(ZX_VCPU_CREATE,      b"_zx_vcpu_create");
    resolve!(ZX_VCPU_ENTER,       b"_zx_vcpu_enter");
    resolve!(ZX_VCPU_KICK,        b"_zx_vcpu_kick");
    resolve!(ZX_VCPU_INTERRUPT,   b"_zx_vcpu_interrupt");
    resolve!(ZX_VCPU_READ_STATE,  b"_zx_vcpu_read_state");
    resolve!(ZX_VCPU_WRITE_STATE, b"_zx_vcpu_write_state");
    resolve!(ZX_CHANNEL_READ,     b"_zx_channel_read");
    resolve!(ZX_VMO_REPLACE_AS_EXECUTABLE, b"_zx_vmo_replace_as_executable");
}

/// zx_vmo_replace_as_executable — consume `handle` and return a VMO handle that
/// also carries ZX_RIGHT_EXECUTE, which mapping with ZX_VM_PERM_EXECUTE requires.
/// `vmex` must be a ZX_RSRC_KIND_SYSTEM resource covering ZX_RSRC_SYSTEM_VMEX_BASE
/// (the SYSTEM resource from the bootstrap message is the ranged root, so it works).
pub unsafe fn vmo_replace_as_executable(handle: Handle, vmex: Handle, out: *mut Handle) -> Status {
    let ptr = ZX_VMO_REPLACE_AS_EXECUTABLE.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, Handle, *mut Handle) -> Status =
        core::mem::transmute(ptr);
    f(handle, vmex, out)
}

/// zx_channel_read — read the first message (bytes + handles) from a channel.
#[allow(clippy::too_many_arguments)]
pub unsafe fn channel_read(
    handle: Handle,
    options: u32,
    bytes: *mut u8,
    handles: *mut Handle,
    num_bytes: u32,
    num_handles: u32,
    actual_bytes: *mut u32,
    actual_handles: *mut u32,
) -> Status {
    let ptr = ZX_CHANNEL_READ.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(
        Handle, u32, *mut u8, *mut Handle, u32, u32, *mut u32, *mut u32,
    ) -> Status = core::mem::transmute(ptr);
    f(handle, options, bytes, handles, num_bytes, num_handles, actual_bytes, actual_handles)
}

/// Read the bootstrap processargs message and stash the PA_SYSTEM_RESOURCE
/// handle for later use (e.g. guest_create). Best-effort: on any error the
/// system resource simply stays HANDLE_INVALID and guest_create will fail
/// cleanly. Extra handles in the message are left open (closed at process exit).
pub unsafe fn extract_startup_handles(bootstrap: Handle) {
    if bootstrap == HANDLE_INVALID {
        return;
    }
    const MAX_BYTES: usize = 8192;
    const MAX_HANDLES: usize = 128;
    let mut bytes = [0u8; MAX_BYTES];
    let mut handles = [HANDLE_INVALID; MAX_HANDLES];
    let mut nb: u32 = 0;
    let mut nh: u32 = 0;
    let st = channel_read(
        bootstrap,
        0,
        bytes.as_mut_ptr(),
        handles.as_mut_ptr(),
        MAX_BYTES as u32,
        MAX_HANDLES as u32,
        &mut nb,
        &mut nh,
    );
    if st != ZX_OK || (nb as usize) < 36 {
        return;
    }
    let rd32 = |off: usize| -> u32 {
        u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]])
    };
    if rd32(0) != ZX_PROCARGS_PROTOCOL {
        return;
    }
    let handle_info_off = rd32(8) as usize; // zx_proc_args.handle_info_off
    let count = (nh as usize).min(MAX_HANDLES);
    for i in 0..count {
        let off = handle_info_off + i * 4;
        if off + 4 > nb as usize {
            break;
        }
        match rd32(off) & 0xFF {
            PA_SYSTEM_RESOURCE => SYSTEM_RESOURCE.store(handles[i], Ordering::Release),
            PA_VMAR_ROOT => VMAR_ROOT.store(handles[i], Ordering::Release),
            _ => {}
        }
    }
}

/// The process's root VMAR handle from the bootstrap message. Prefer this over
/// `vmar_root_self()`, which needs libc startup to have populated it.
pub fn vmar_root() -> Handle {
    VMAR_ROOT.load(Ordering::Acquire)
}

/// The SYSTEM resource handle extracted from the bootstrap message, or
/// HANDLE_INVALID if none was provided.
pub fn system_resource() -> Handle {
    SYSTEM_RESOURCE.load(Ordering::Acquire)
}

pub fn debug_write(buffer: *const u8, len: usize) -> Status {
    // Create a one-shot debuglog handle and write to it.
    let create_ptr = ZX_DEBUGLOG_CREATE.load(Ordering::Acquire);
    let write_ptr  = ZX_DEBUGLOG_WRITE.load(Ordering::Acquire);
    if create_ptr == 0 || write_ptr == 0 {
        return -1;
    }
    let create: unsafe extern "C" fn(Handle, u32, *mut Handle) -> Status =
        unsafe { core::mem::transmute(create_ptr) };
    let write: unsafe extern "C" fn(Handle, u32, *const u8, usize) -> Status =
        unsafe { core::mem::transmute(write_ptr) };
    let mut log_handle: Handle = HANDLE_INVALID;
    let status = unsafe { create(HANDLE_INVALID, 0, &mut log_handle) };
    if status != ZX_OK {
        return status;
    }
    let status = unsafe { write(log_handle, 0, buffer, len) };
    let _ = unsafe { handle_close(log_handle) };
    status
}

pub fn process_exit(code: i64) -> ! {
    let ptr = ZX_PROCESS_EXIT.load(Ordering::Acquire);
    if ptr == 0 {
        // Should never happen; vDSO always exports zx_process_exit.
        loop {}
    }
    let f: unsafe extern "C" fn(i64) -> ! = unsafe { core::mem::transmute(ptr) };
    unsafe { f(code) }
}

pub unsafe fn vmo_create(size: u64, options: u32, out: *mut Handle) -> Status {
    let ptr = ZX_VMO_CREATE.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(u64, u32, *mut Handle) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(size, options, out)
}

/// zx_vmo_create_child — create a copy-on-write (or full-snapshot) clone of a VMO.
///
/// `options` selects the clone semantics (see `VMO_CHILD_*`).  The returned
/// child captures the parent's current contents; with
/// `VMO_CHILD_SNAPSHOT_AT_LEAST_ON_WRITE` a page is physically copied only when
/// first written, so creating the child is O(1) regardless of size.
pub unsafe fn vmo_create_child(
    handle: Handle, options: u32, offset: u64, size: u64, out: *mut Handle,
) -> Status {
    let ptr = ZX_VMO_CREATE_CHILD.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, u32, u64, u64, *mut Handle) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(handle, options, offset, size, out)
}

/// zx_vmo_op_range — perform an operation over a range of a VMO.
///
/// For `VMO_OP_REVERT_TO_SNAPSHOT`, `buffer` is null and `buffer_size` 0.
pub unsafe fn vmo_op_range(
    handle: Handle, op: u32, offset: u64, size: u64, buffer: *mut u8, buffer_size: usize,
) -> Status {
    let ptr = ZX_VMO_OP_RANGE.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, u32, u64, u64, *mut u8, usize) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(handle, op, offset, size, buffer, buffer_size)
}

pub unsafe fn vmar_map(
    handle: Handle,
    options: VmOption,
    vmar_offset: usize,
    vmo: Handle,
    vmo_offset: u64,
    len: usize,
    mapped_addr: *mut Vaddr,
) -> Status {
    let ptr = ZX_VMAR_MAP.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, VmOption, usize, Handle, u64, usize, *mut Vaddr) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(handle, options, vmar_offset, vmo, vmo_offset, len, mapped_addr)
}

/// zx_vmar_unmap — unmap a range previously mapped with `vmar_map`.
///
/// `addr`/`len` must match a whole mapping (or set of mappings) in `handle`.
pub unsafe fn vmar_unmap(handle: Handle, addr: Vaddr, len: usize) -> Status {
    let ptr = ZX_VMAR_UNMAP.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, Vaddr, usize) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(handle, addr, len)
}

/// zx_handle_duplicate — create a second handle to the same kernel object.
pub unsafe fn handle_duplicate(handle: Handle, rights: u32, out: *mut Handle) -> Status {
    let ptr = ZX_HANDLE_DUPLICATE.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle, u32, *mut Handle) -> Status =
        unsafe { core::mem::transmute(ptr) };
    f(handle, rights, out)
}

pub unsafe fn handle_close(handle: Handle) -> Status {
    let ptr = ZX_HANDLE_CLOSE.load(Ordering::Acquire);
    if ptr == 0 {
        return -1;
    }
    let f: unsafe extern "C" fn(Handle) -> Status = unsafe { core::mem::transmute(ptr) };
    f(handle)
}

pub unsafe fn vmar_root_self() -> Handle {
    let ptr = ZX_VMAR_ROOT_SELF.load(Ordering::Acquire);
    if ptr == 0 {
        return 0;
    }
    let f: unsafe extern "C" fn() -> Handle = unsafe { core::mem::transmute(ptr) };
    f()
}

// ─── Hypervisor syscall wrappers ──────────────────────────────────────────

/// zx_port_packet_t — 48 bytes (key + type + status + 32-byte data union).
#[repr(C, align(8))]
pub struct PortPacket {
    pub key: u64,
    pub type_: u32,
    pub status: i32,
    pub data: [u8; 32],
}

impl PortPacket {
    pub const fn zeroed() -> Self {
        Self { key: 0, type_: 0, status: 0, data: [0u8; 32] }
    }
    pub fn guest_io_port(&self) -> u16 {
        u16::from_le_bytes([self.data[0], self.data[1]])
    }
    pub fn guest_io_access_size(&self) -> u8 {
        self.data[2]
    }
    pub fn guest_io_is_input(&self) -> bool {
        self.data[3] != 0
    }
    pub fn guest_io_data_u16(&self) -> u16 {
        u16::from_le_bytes([self.data[4], self.data[5]])
    }
}

// zx_packet_type_t (zircon/system/public/zircon/syscalls/port.h) — kernel-authoritative.
pub const PKT_TYPE_GUEST_BELL: u32 = 0x03;
pub const PKT_TYPE_GUEST_MEM: u32 = 0x04;
pub const PKT_TYPE_GUEST_IO: u32 = 0x05;
pub const PKT_TYPE_GUEST_VCPU: u32 = 0x06;
pub const PKT_TYPE_GUEST_EXCEPTION: u32 = 0x08;

/// zx_vcpu_state_t — 17 general-purpose registers (rax..r15, rflags).
#[repr(C)]
pub struct VcpuState {
    pub rax: u64, pub rcx: u64, pub rdx: u64, pub rbx: u64,
    pub rsp: u64, pub rbp: u64, pub rsi: u64, pub rdi: u64,
    pub r8:  u64, pub r9:  u64, pub r10: u64, pub r11: u64,
    pub r12: u64, pub r13: u64, pub r14: u64, pub r15: u64,
    pub rflags: u64,
}

pub const VCPU_STATE_KIND: u32 = 0; // ZX_VCPU_STATE
// ZX_VCPU_STATE_FULL — the complete architectural state as a versioned,
// self-describing buffer. Unlike VCPU_STATE_KIND it carries the instruction
// pointer, the segment and descriptor-table registers, and the control and mode
// registers, which is what placing a VCPU at a chosen point of execution needs.
// Provide a buffer at least as large as the kernel requires; a short one is
// refused rather than truncated.
pub const VCPU_STATE_FULL_KIND: u32 = 2;

pub unsafe fn guest_create(
    resource: Handle, options: u32,
    out_guest: *mut Handle, out_vmar: *mut Handle,
) -> Status {
    let ptr = ZX_GUEST_CREATE.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32, *mut Handle, *mut Handle) -> Status =
        core::mem::transmute(ptr);
    f(resource, options, out_guest, out_vmar)
}

pub unsafe fn guest_set_trap(
    guest: Handle, kind: u32, addr: usize, size: usize,
    port: Handle, key: u64,
) -> Status {
    let ptr = ZX_GUEST_SET_TRAP.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32, usize, usize, Handle, u64) -> Status =
        core::mem::transmute(ptr);
    f(guest, kind, addr, size, port, key)
}

pub unsafe fn vcpu_create(
    guest: Handle, options: u32, entry: usize, out: *mut Handle,
) -> Status {
    let ptr = ZX_VCPU_CREATE.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32, usize, *mut Handle) -> Status =
        core::mem::transmute(ptr);
    f(guest, options, entry, out)
}

pub unsafe fn vcpu_enter(vcpu: Handle, packet: *mut PortPacket) -> Status {
    let ptr = ZX_VCPU_ENTER.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, *mut PortPacket) -> Status =
        core::mem::transmute(ptr);
    f(vcpu, packet)
}

pub unsafe fn vcpu_kick(vcpu: Handle) -> Status {
    let ptr = ZX_VCPU_KICK.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle) -> Status = core::mem::transmute(ptr);
    f(vcpu)
}

pub unsafe fn vcpu_interrupt(vcpu: Handle, vector: u32) -> Status {
    let ptr = ZX_VCPU_INTERRUPT.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32) -> Status = core::mem::transmute(ptr);
    f(vcpu, vector)
}

pub unsafe fn vcpu_read_state(
    vcpu: Handle, kind: u32, buf: *mut u8, size: usize,
) -> Status {
    let ptr = ZX_VCPU_READ_STATE.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32, *mut u8, usize) -> Status =
        core::mem::transmute(ptr);
    f(vcpu, kind, buf, size)
}

pub unsafe fn vcpu_write_state(
    vcpu: Handle, kind: u32, buf: *const u8, size: usize,
) -> Status {
    let ptr = ZX_VCPU_WRITE_STATE.load(Ordering::Acquire);
    if ptr == 0 { return -1; }
    let f: unsafe extern "C" fn(Handle, u32, *const u8, usize) -> Status =
        core::mem::transmute(ptr);
    f(vcpu, kind, buf, size)
}

// ─── Minimal ELF64 symbol resolver ────────────────────────────────────────
//
// Mirrors the logic in examples/userboot-smoke/userboot_smoke.cc:ResolveVdsoSymbol.
// Walks PT_DYNAMIC → DT_HASH / DT_STRTAB / DT_SYMTAB to look up a symbol by name.

const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;

// Traditional ELF hash (SYSV hash).
fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(u32::from(c));
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

// Compare null-terminated C string at `ptr` with byte slice `name`
// (which does NOT include a null terminator).
unsafe fn c_str_eq(ptr: *const u8, name: &[u8]) -> bool {
    for (i, &b) in name.iter().enumerate() {
        if *ptr.add(i) != b {
            return false;
        }
    }
    *ptr.add(name.len()) == 0
}

/// Walk the ELF64 vDSO at `base` and return the virtual address of `name`.
/// Returns 0 if not found.
unsafe fn resolve_symbol(base: usize, name: &[u8]) -> usize {
    // Elf64_Ehdr layout (64 bytes total):
    //   +0:  e_ident[16]
    //   +16: e_type(2) + e_machine(2) + e_version(4) + e_entry(8)
    //   +32: e_phoff (u64)
    //   +40: e_shoff(8) + e_flags(4) + e_ehsize(2) + e_phentsize(2)
    //   +56: e_phnum (u16)
    let e_phoff  = *(base as *const u8).add(32).cast::<u64>() as usize;
    let e_phnum  = *(base as *const u8).add(56).cast::<u16>() as usize;

    // Find PT_DYNAMIC.  Elf64_Phdr is 56 bytes:
    //   +0:  p_type(4) + p_flags(4)
    //   +8:  p_offset(8)
    //   +16: p_vaddr(8)
    let mut dyn_vaddr: usize = 0;
    for i in 0..e_phnum {
        let phdr = (base + e_phoff + i * 56) as *const u8;
        let p_type  = *(phdr as *const u32);
        let p_vaddr = *phdr.add(16).cast::<u64>() as usize;
        if p_type == PT_DYNAMIC {
            dyn_vaddr = p_vaddr;
            break;
        }
    }
    if dyn_vaddr == 0 {
        return 0;
    }

    // Walk Elf64_Dyn entries (16 bytes each: d_tag(i64) + d_val/d_ptr(u64)).
    let mut hash_off: usize = 0;
    let mut strtab_off: usize = 0;
    let mut symtab_off: usize = 0;
    let mut dyn_ptr = (base + dyn_vaddr) as *const i64;
    loop {
        let tag = *dyn_ptr;
        let val = *(dyn_ptr.add(1)) as usize;
        match tag {
            DT_NULL   => break,
            DT_HASH   => hash_off = val,
            DT_STRTAB => strtab_off = val,
            DT_SYMTAB => symtab_off = val,
            _         => {}
        }
        dyn_ptr = dyn_ptr.add(2);
    }
    if hash_off == 0 || strtab_off == 0 || symtab_off == 0 {
        return 0;
    }

    // ELF SYSV hash table layout:
    //   [0]:    nbuckets (u32)
    //   [1]:    nchains  (u32)
    //   [2..]:  bucket[nbuckets] (u32)
    //   [2+n]:  chain[nchains]   (u32)
    let hash_ptr   = (base + hash_off) as *const u32;
    let nbuckets   = *hash_ptr as usize;
    let buckets    = hash_ptr.add(2);
    let chains     = buckets.add(nbuckets);

    let h = elf_hash(name);
    let mut idx = *buckets.add(h as usize % nbuckets) as usize;
    while idx != 0 {
        // Elf64_Sym (24 bytes): st_name(u32) + st_info(1) + st_other(1) +
        //   st_shndx(2) + st_value(u64) + st_size(u64)
        let sym = (base + symtab_off + idx * 24) as *const u8;
        let st_name  = *(sym as *const u32) as usize;
        let st_value = *sym.add(8).cast::<u64>() as usize;
        if st_value != 0 && c_str_eq((base + strtab_off + st_name) as *const u8, name) {
            return base + st_value;
        }
        idx = *chains.add(idx) as usize;
    }
    0
}
