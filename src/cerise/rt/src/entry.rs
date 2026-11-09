// ELF entry point for Cerise userland Rust binaries.
//
// Userboot calls `_start(bootstrap, vdso_base)` per the Zircon startup ABI.
// Because hello-rust is a PIE binary, the .got slots are zero in the ELF file;
// no dynamic linker applies R_X86_64_RELATIVE relocations, so we must do it
// ourselves before any GOT-indirect call.
//
// Structure:
//   _start        — pure assembly; applies RELATIVE relocations, then calls ↓
//   _start_rust   — Rust; resolves vDSO symbols, calls cerise_main(), exits

use crate::zx;

/// Rust entry point called by the assembly _start after PIE relocations are applied.
/// At this point all .got entries are valid; normal Rust + GOT-indirect code is safe.
/// Args match the Zircon startup ABI: rdi = bootstrap channel handle, rsi = vdso_base.
#[no_mangle]
pub unsafe extern "C" fn _start_rust(bootstrap: u32, vdso_base: usize) -> ! {
    unsafe { zx::init_from_vdso(vdso_base) };
    // Drain the bootstrap processargs so we can pick up the SYSTEM resource
    // (needed for guest_create). Best-effort; ignored if absent.
    unsafe { zx::extract_startup_handles(bootstrap) };

    extern "Rust" {
        fn cerise_main();
    }
    unsafe { cerise_main() };
    zx::process_exit(0)
}

// Assembly _start: apply R_X86_64_RELATIVE relocations from our own PT_DYNAMIC,
// then tail-call _start_rust(vdso_base).
//
// Invariant: no instruction before .Lrelocations_done may access a .got slot.
// All addresses are obtained via RIP-relative LEA or stack-local arithmetic.
//
// Register usage:
//   rax  — ELF load base (= runtime address of ELF header)
//   rbx  — e_phoff / temporary
//   rbp  — e_phnum (loop bound)
//   r12  — relasz (decremented to 0)
//   r13  — pointer into RELA table
//   r14  — pointer into phdrs / PT_DYNAMIC
//   r15  — dyn_vaddr / rela_vaddr (temporary)
//   rcx  — loop counter
//   r9,r10,r11 — RELA fields
//
// Stack on entry: [rsp]=ret-addr (none; _start is process entry), but by ABI the
// kernel places rsp at a valid 16-byte-aligned stack before calling _start.
// We push two 8-byte values → rsp drops by 16 (remains 16-byte-aligned for the
// subsequent `call _start_rust`).
core::arch::global_asm!(r#"
    .intel_syntax noprefix
    .hidden __ehdr_start
    .global _start
    .type _start, @function
_start:
    // rdi = bootstrap handle, rsi = vdso_base.  The relocation loop below uses
    // only rax/rbx/rbp/rcx/r9-r15, so rdi and rsi are preserved untouched and
    // passed straight to _start_rust(bootstrap, vdso_base).  No pushes → rsp
    // stays 16-byte aligned (kernel entry guarantee) through the `call`.

    // load_base: __ehdr_start is a linker-synthesised hidden symbol at virtual
    // offset 0 (the ELF header).  The .hidden above keeps this RIP-relative.
    lea     rax, [rip + __ehdr_start]

    // --- find PT_DYNAMIC ---
    // Elf64_Ehdr: e_phoff @ +32 (u64), e_phnum @ +56 (u16)
    mov     rbx, qword ptr [rax + 32]
    movzx   rbp, word ptr  [rax + 56]
    lea     r14, [rax + rbx]            // r14 → first Elf64_Phdr
    xor     rcx, rcx                    // i = 0
    xor     r15, r15                    // dyn_vaddr = 0 (not found)

.Lfind_dyn:
    cmp     rcx, rbp
    jae     .Lno_dynamic
    cmp     dword ptr [r14], 2          // p_type == PT_DYNAMIC?
    jne     .Lnext_phdr
    mov     r15, qword ptr [r14 + 16]   // r15 = p_vaddr (dyn section vaddr)
    jmp     .Lgot_dyn
.Lnext_phdr:
    add     r14, 56                     // sizeof Elf64_Phdr
    inc     rcx
    jmp     .Lfind_dyn

    // --- walk PT_DYNAMIC for DT_RELA (7) and DT_RELASZ (8) ---
.Lgot_dyn:
    add     r15, rax                    // absolute address of dynamic section
    xor     r13, r13                    // rela_vaddr = 0
    xor     r12, r12                    // relasz = 0
.Ldyn_loop:
    mov     r9,  qword ptr [r15]        // d_tag
    mov     r10, qword ptr [r15 + 8]   // d_val / d_ptr
    test    r9,  r9
    je      .Ldyn_done                  // DT_NULL
    cmp     r9,  7                      // DT_RELA
    cmove   r13, r10
    cmp     r9,  8                      // DT_RELASZ
    cmove   r12, r10
    add     r15, 16                     // sizeof Elf64_Dyn
    jmp     .Ldyn_loop
.Ldyn_done:
    test    r13, r13
    je      .Lno_dynamic
    test    r12, r12
    je      .Lno_dynamic

    // --- apply R_X86_64_RELATIVE (r_info == 8) ---
    // Elf64_Rela: r_offset(8) + r_info(8) + r_addend(8) = 24 bytes
    add     r13, rax                    // r13 → absolute RELA table
.Lrela_loop:
    cmp     r12, 24
    jb      .Lno_dynamic                // relasz < 24 → done
    mov     r9,  qword ptr [r13]        // r_offset
    mov     r10, qword ptr [r13 + 8]   // r_info
    cmp     r10, 8                      // R_X86_64_RELATIVE?
    jne     .Lrela_next
    mov     r11, qword ptr [r13 + 16]  // r_addend
    add     r9,  rax                    // slot = base + r_offset
    add     r11, rax                    // value = base + r_addend
    mov     qword ptr [r9], r11
.Lrela_next:
    add     r13, 24
    sub     r12, 24
    jmp     .Lrela_loop

.Lno_dynamic:
    // Relocations applied.  rdi = bootstrap, rsi = vdso_base are still live.
    call    _start_rust                 // RIP-relative call; GOT now valid
    ud2                                 // _start_rust is diverging
    .att_syntax prefix
"#);
