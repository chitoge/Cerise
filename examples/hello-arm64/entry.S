// ARM64 PIE entry point.
// ABI from kernel: x0 = bootstrap channel handle, x1 = vdso_base.
// Applies R_AARCH64_RELATIVE relocations before calling C, so that
// any GOT-indirect accesses in C are valid.

.global _start
.type _start, %function
_start:
    // Preserve bootstrap (x0) and vdso_base (x1) across the reloc loop.
    stp x29, x30, [sp, #-48]!
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    mov x29, sp
    mov x19, x0        // bootstrap channel handle
    mov x20, x1        // vdso_base

    // Load base address of this binary (ELF header).
    adrp x21, __ehdr_start
    add  x21, x21, :lo12:__ehdr_start

    // Read Elf64_Ehdr: e_phoff at +32, e_phnum at +56.
    ldr  x0, [x21, #32]    // e_phoff
    ldrh w1, [x21, #56]    // e_phnum

    // Walk phdrs looking for PT_DYNAMIC (type 2). Elf64_Phdr = 56 bytes.
    add  x0, x21, x0       // &phdrs[0]
    mov  x22, xzr          // PT_DYNAMIC p_vaddr (0 = not found)
.Lphdr_loop:
    cbz  w1, .Lphdr_done
    ldr  w2, [x0]          // p_type
    cmp  w2, #2
    b.ne .Lphdr_next
    ldr  x22, [x0, #16]    // p_vaddr
    b    .Lphdr_done
.Lphdr_next:
    sub  w1, w1, #1
    add  x0, x0, #56
    b    .Lphdr_loop
.Lphdr_done:
    cbz  x22, .Lcall        // no PT_DYNAMIC — nothing to relocate

    // Walk _DYNAMIC for DT_RELA (7) and DT_RELASZ (8). Elf64_Dyn = 16 bytes.
    add  x0, x21, x22      // &_DYNAMIC[0]
    mov  x22, xzr          // rela offset (relative to base)
    mov  x2,  xzr          // rela size in bytes
.Ldyn_loop:
    ldr  x3, [x0]          // d_tag
    cbz  x3, .Ldyn_done    // DT_NULL
    ldr  x4, [x0, #8]      // d_val/d_ptr
    cmp  x3, #7
    b.ne .Ldyn_chk8
    mov  x22, x4           // DT_RELA
    b    .Ldyn_next
.Ldyn_chk8:
    cmp  x3, #8
    b.ne .Ldyn_next
    mov  x2, x4            // DT_RELASZ
.Ldyn_next:
    add  x0, x0, #16
    b    .Ldyn_loop
.Ldyn_done:
    cbz  x22, .Lcall        // no RELA table

    // Apply R_AARCH64_RELATIVE (type 1027 = 0x403). Elf64_Rela = 24 bytes.
    add  x0, x21, x22      // absolute rela start
    add  x3, x0, x2        // absolute rela end
.Lrela_loop:
    cmp  x0, x3
    b.ge .Lcall
    ldr  x4, [x0]          // r_offset (relative to base)
    ldr  x5, [x0, #8]      // r_info
    ldr  x6, [x0, #16]     // r_addend
    and  x7, x5, #0xffffffff
    cmp  x7, #1027         // R_AARCH64_RELATIVE
    b.ne .Lrela_next
    add  x4, x21, x4       // absolute target address
    add  x6, x21, x6       // value = base + addend
    str  x6, [x4]
.Lrela_next:
    add  x0, x0, #24
    b    .Lrela_loop

.Lcall:
    mov  x0, x19           // bootstrap
    mov  x1, x20           // vdso_base
    ldp  x21, x22, [sp, #32]
    ldp  x19, x20, [sp, #16]
    ldp  x29, x30, [sp], #48
    b    userland_main      // tail call into C (noreturn)
