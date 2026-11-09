// Minimal arm64 QEMU boot shim.
//
// QEMU arm64 virt loads this as -kernel (Linux arm64 Image format).
// QEMU calls _start with x0=DTB address.
// The ZBI (arm64_kernel_storage.zbi) is passed as -initrd.
//
// This shim scans RAM for the ZBI container, finds the physload
// (ZBI_TYPE_KERNEL_ARM64 item), and jumps to it with x0=ZBI address.
//
// DRAM on QEMU arm64 virt: 0x40000000 to 0xC0000000 (for -m 2048).
// QEMU loads us at: DRAM_BASE + text_offset = 0x40000000 + 0x80000 = 0x40080000.

.text

// ── Linux arm64 Image header (64 bytes) ──────────────────────────────────────
// Reference: Documentation/arm64/booting.rst in Linux kernel.
// Byte 0: code0 — first instruction (B #64 = branch over rest of header)
// Byte 4: code1 — second instruction (NOP = 0xD503201F)
// Byte 8: text_offset — 0x80000 (load at DRAM_BASE + 512KB)
// Byte 16: image_size — 0x10000 (64KB, shim is ~1KB)
// Byte 24: flags — 0x8 (little-endian kernel, 4KB pages, physical)
// Byte 32..55: reserved (zeros)
// Byte 56: magic — 0x644D5241 "ARMd"
// Byte 60: res5 — 0
//
// B #64: ARM64 unconditional branch to PC+64.
//   B encoding: 0b000101|imm26. imm26 = 64/4 = 16 = 0x10.
//   → 0x14000010
.word 0x14000010          // B #64
.word 0xD503201F          // NOP
.quad 0x0000000000080000  // text_offset
.quad 0x0000000000010000  // image_size
.quad 0x0000000000000008  // flags (little-endian kernel)
.quad 0x0000000000000000  // res2
.quad 0x0000000000000000  // res3
.quad 0x0000000000000000  // res4
.word 0x644D5241          // magic "ARMd"
.word 0x00000000          // res5

// ── _start: entry point (offset 64 from image base) ─────────────────────────
//
// x0 = DTB address from QEMU (not used; we scan for ZBI).
// x1 = x2 = x3 = 0.
.global _start
_start:
    // Scan RAM for ZBI container starting at 0x41000000 (past kernel area).
    // Step 4KB at a time; end at 0xC0000000.
    //
    // ZBI_TYPE_CONTAINER = 0x544F4F42 (at offset 0 in ZBI)
    // ZBI_CONTAINER_MAGIC = 0x868CF7E6 (at offset 8 in ZBI container header)
    // ZBI_TYPE_KERNEL_ARM64 = 0x384E524B (type of first item in ZBI)

    movz x1, #0x4100, lsl #16    // x1 = 0x41000000 (scan start)

    // ZBI_TYPE_CONTAINER
    movz x5, #0x4F42
    movk x5, #0x544F, lsl #16

    // ZBI_CONTAINER_MAGIC
    movz x6, #0xF7E6
    movk x6, #0x868C, lsl #16

    // ZBI_TYPE_KERNEL_ARM64
    movz x7, #0x524B
    movk x7, #0x384E, lsl #16

    // RAM end for scan: 0xC0000000
    movz x4, #0xC000, lsl #16

.Lscan:
    cmp x1, x4
    b.hs .Lhang

    // Check offset 0: ZBI_TYPE_CONTAINER?
    ldr w2, [x1]
    cmp w2, w5
    b.ne .Lnext

    // Check offset 8: ZBI_CONTAINER_MAGIC?
    ldr w2, [x1, #8]
    cmp w2, w6
    b.ne .Lnext

    // Verify first item type at offset 32: ZBI_TYPE_KERNEL_ARM64?
    ldr w2, [x1, #32]
    cmp w2, w7
    b.ne .Lnext

    // Found the ZBI at x1!
    // Per the ZBI boot protocol (zbi-format/kernel.h, ARM64 section): the
    // zbi_kernel_t.entry field is an offset from the BEGINNING OF THE IMAGE —
    // the ZBI_TYPE_CONTAINER header — to physload's _start, NOT an offset from
    // the payload.  boot-zbi.h confirms it:
    //   KernelEntryAddress() = KernelLoadAddress() + KernelHeader()->entry
    // where KernelLoadAddress() is the container base.  So _start is at
    // container_base + entry_offset (physload's _start reads the boot timestamp
    // as its first instruction and, critically, resets VBAR_EL1; jumping past
    // it left the exception vectors at 0 and any early fault looped at PC 0x200).
    // The entry field itself lives at container+64 (32B container header +
    // 32B kernel item header), which is where we read it from.
    ldr x2, [x1, #64]       // entry_offset (zbi_kernel_t.entry), read at container+64
    add x3, x1, x2          // x3 = physload _start = container_base + entry_offset

    // x0 = ZBI container address (as required by PhysMain)
    mov x0, x1

    // Clear frame and link registers for clean backtraces
    mov x29, xzr
    mov x30, xzr

    // Jump to physload
    br x3

.Lnext:
    add x1, x1, #0x1000    // advance 4KB
    b .Lscan

.Lhang:
    // No ZBI found — spin forever
    wfe
    b .Lhang
