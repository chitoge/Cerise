// Copyright 2024 The Fuchsia Authors
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT

#include <lib/arch/asm.h>

#include "linuxboot-asm.h"

// The phys.ld linker script places this first in the image.  The linuxboot.ld
// linker script arranges that this means it it is "before" the actual physical
// load address of the bzImage 32-bit code.  That code is skipped over by the
// 64-bit boot path to reach the 64-bit entry point.
.section .boot.header, "awx", %progbits

// This is the putative boot_params object at the start of the image.
// See linuxboot.h for full details about the protocol.  In fact, this
// just corresponds to the boot_params layout for purposes of locating
// the boot_params::setup_header, below.
.org 0
.label zero_page

// This is where ancient MBR code went, so in the abstract, from here on
// starts the 16-bit portion of the code (linuxboot-header.S has a real one).
.code16

// The space before boot_params::hdr is not examined by the boot loader.  A
// boot loader using the 16-bit entry protocol reads hdr.setup_sects and then
// loads this whole file's contents into memory at zero_page before entering
// at setup_header::jump, below.
.org BOOT_PARAMS_HDR

.object setup_header, nosection=nosection
  // This tells the boot loader how many 512-byte sectors after this first
  // one to load.  LINUXBOOT_SETUP_SIZE is defined at the end of the file.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_SETUP_SECTS
  .byte ((LINUXBOOT_SETUP_SIZE >> 9) - 1)

  // This tells the boot loader how many 16-byte units (Intelspeak paragraphs)
  // to load at the fixed load address for the 32-bit kernel image.  The
  // linuxboot.ld linker script calculates the value of LINUXBOOT_SYSSIZE.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_SYSSIZE
  // In the 32-bit case, it's a fixed-position link and so linuxboot-header.S
  // just does `.int LINUXBOOT_SYSSIZE` here and that's fine.  LLD in fact
  // allows that for the 64-bit position-independent case too, but GNU (BFD) ld
  // does not.  It will only allow a PC-relative relocation.  So linuxboot.ld
  // also computes LINUXBOOT_SYSSIZE_RELATIVE as the difference between the
  // LINUXBOOT_SYSSIZE value and the link-time load address (PHYS_LOAD_ADDRESS,
  // aka the zero_page label above); it's not a meaningful address since it's
  // scaled by 16, but it's the right addend for a PC-relative relocation to
  // resolve to exactly LINUXBOOT_SYSSIZE.
  .int LINUXBOOT_SYSSIZE_RELATIVE - zero_page

  // This is a required magic number the boot loader checks for.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_BOOT_FLAG
  .short LINUXBOOT_BOOT_FLAG

  // This is offset 512, where the 16-bit entry point is.  Since there's a
  // required header field right after, this must be a two-byte instruction.
  // This jumps to Phys16Entry at the end of the setup header (same location
  // linuxboot-header.S uses for its 16-bit code).  The SeaBIOS linuxboot_dma
  // ROM always uses this 16-bit real-mode entry path, so Phys16Entry provides
  // a real-mode -> 64-bit-long-mode transition that hands control to
  // Linux64Entry in the loaded kernel image.  The second byte of the JMP
  // opcode is also used by boot loaders to infer the setup header size.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_JUMP
  jmp setup_header + SIZEOF_SETUP_HEADER

  // This is a required magic number the boot loader checks for.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_HEADER
  .ascii "HdrS"

  // This tells the boot loader which precise version of the protocol for
  // encoding bits in these headers this kernel image is compatible with.
  // Version 2.12 is not the newest, but none of the Zircon shim code needs
  // to take advantange of any of the newer features.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_VERSION
  .short 0x020c

  // This indicates "bzImage" format: load the 32-bit code at 1MiB.
  // This is probably ignored when using the 64-bit protocol enabled
  // in xloadflags, below.  But it's the usual baseline, so set it.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_LOADFLAGS
  .byte LOADFLAGS_LOADED_HIGH

  // Preferred alignment for the load address is just 4KiB.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_KERNEL_ALIGNMENT
  .int 0x1000

  // Any load address is fine.  This is probably ignored when using the 64-bit
  // protocol, which stipulates it can always be loaded anywhere.  But it
  // doesn't hurt to set it.  There is no 32-bit entry path here, so it doesn't
  // matter that the actual 32-bit build doesn't support relocatability.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_RELOCATABLE_KERNEL
  .byte 1

  // Load addresses must be aligned to 4KiB (1 << 12).
  .org BOOT_PARAMS_HDR + SETUP_HEADER_MIN_ALIGNMENT
  .byte 12

  // This indicates a 64-bit kernel that can use the 64-bit protocol.
  // This version of the header code supports only the 64-bit protocol.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_XLOADFLAGS
  .short XLF_KERNEL_64 | XLF_CAN_BE_LOADED_ABOVE_4G

   // This constrains the maximum size of kernel command line data passed.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_CMDLINE_SIZE
  .int 0xffffffff

  // This tells the boot loader how much space to leave from the start of the
  // kernel's load image.  This ensures it leaves space for the .bss and not
  // just the image it copies in.
  .org BOOT_PARAMS_HDR + SETUP_HEADER_INIT_SIZE
  .int _end - LINUXBOOT_LOAD_ADDRESS

   // The rest of setup_header contains fields a boot loader might examine
   // or modify though they're not meaningful to the version of the protocol
   // we support if they have zero-initialized values.
  .org BOOT_PARAMS_HDR + SIZEOF_SETUP_HEADER
.end_object

// GDT selector values for the temporary phys16 GDT defined below.
#define PHYS16_GDT_LIMIT (4 * 8 - 1)  // 4 descriptors, 8 bytes each; limit = size - 1
#define PHYS16_CODE32_SEL 0x08         // descriptor[1]: 32-bit flat code
#define PHYS16_DATA32_SEL 0x10         // descriptor[2]: 32-bit flat data
#define PHYS16_CODE64_SEL 0x18         // descriptor[3]: 64-bit code
// Byte offset of code32_start within setup_header (QEMU sets this to the
// actual kernel physical load address before handing off via fw_cfg).
#define SETUP_HEADER_CODE32_START 35

// Phys16Entry is the 16-bit real-mode entry reached from the JMP at
// setup+0x200 (two bytes before the HdrS magic).  The SeaBIOS linuxboot_dma
// ROM always uses this path regardless of the XLF_KERNEL_64 flag.
//
// On entry (as set up by linuxboot_dma):
//   CS  = (setup_addr >> 4) + 0x20  (CS:0 = setup_addr + 0x200)
//   DS = ES = FS = GS = SS = setup_addr >> 4  (DS:0 = setup_addr = &boot_params)
//   SS:SP   = usable stack within the setup area
//   The kernel image has been DMA-loaded to code32_start (at DS:0x214).
//
// This function transitions from 16-bit real mode to 64-bit long mode, then
// jumps to Linux64Entry at (code32_start + ENTRY64_OFFSET) with
//   RSI = setup_addr (= physical address of boot_params)
//   which is what the 64-bit Linux boot protocol mandates.
.code16
.function Phys16Entry, nosection=nosection
  cli
  cld

  // Enumerate E820 memory map via INT 0x15/E820 into a scratch buffer at
  // physical 0x5000 (entry count at physical 0x4FFE).  This must happen in
  // real mode before we switch to protected/long mode.  We cannot write the
  // entries directly into boot_params.e820_table (at setup_addr+0x2D0) here
  // because that region overlaps Protected32Entry/Long64Entry code that has
  // not executed yet.  Long64Entry will copy the scratch data to boot_params
  // once that code is no longer needed.
  xorw %ax, %ax
  movw %ax, %es               // ES = 0 for physical 0x5000 addressing
  movw %ax, %es:0x4FFE        // e820 count = 0
  movw $0x5000, %di           // DI = E820 scratch buffer start
  xorl %ebx, %ebx             // EBX = 0 (first call in E820 chain)
.Le820_loop:
  movl $0xE820, %eax
  movl $E820_MAGIC, %edx      // 'SMAP' signature
  movl $SIZEOF_E820ENTRY, %ecx
  int $0x15
  jc .Le820_done              // carry = error or end-of-list
  cmpl $E820_MAGIC, %eax      // verify BIOS returned 'SMAP'
  jne .Le820_bad
  addw $SIZEOF_E820ENTRY, %di // advance past written entry
  movw %es:0x4FFE, %ax
  incw %ax
  movw %ax, %es:0x4FFE
  cmpw $MAX_E820_TABLE_ENTRIES, %ax
  jge .Le820_done             // table full
  testl %ebx, %ebx            // EBX = 0 means last entry
  jnz .Le820_loop
  jmp .Le820_done
.Le820_bad:
  xorw %ax, %ax
  movw %ax, %es:0x4FFE        // zero count on protocol error
.Le820_done:
  movw %ds, %ax
  movw %ax, %es               // restore ES = DS

  // Compute setup_addr = DS * 16.  This is the physical base of boot_params.
  // The 66-prefixed form zero-extends DS into EAX (32 bits).
  movl %ds, %eax
  shll $4, %eax       // EAX = setup_addr

  // Preserve setup_addr in ESI; it will survive the mode transitions and
  // end up in RSI as the boot_params pointer for Linux64Entry.
  movl %eax, %esi

  // Compute the runtime physical address of Protected32Entry and push it as
  // the EIP target for the far return that activates 32-bit protected mode.
  movl $(Protected32Entry - zero_page), %ecx
  addl %esi, %ecx     // ECX = physical address of Protected32Entry

  // Push far-return address: CS selector first, then EIP.
  // lretl pops EIP first (lower address) then CS (higher address), so push
  // CS first so it lands at a higher stack address.
  pushl $PHYS16_CODE32_SEL
  pushl %ecx          // EIP = physical address of Protected32Entry

  // Build a 6-byte LGDT descriptor on the stack:
  //   [SP-6..SP-5] = 2-byte GDT limit
  //   [SP-4..SP-1] = 4-byte GDT base (physical address)
  movl $(phys16_gdt - zero_page), %ecx
  addl %esi, %ecx     // ECX = physical address of phys16_gdt
  movl %ecx, -4(%esp)
  movw $PHYS16_GDT_LIMIT, -6(%esp)
  lgdtl -6(%esp)

  // Enable protected mode (CR0.PE).
  movl %cr0, %eax
  orb $1, %al
  movl %eax, %cr0

  // Far-return into the 32-bit code segment at Protected32Entry.
  lretl
.end_function

// Execution resumes here in 32-bit protected mode.
.balign 16, 0
.code32
.function Protected32Entry, nosection=nosection
  // Reload all data segment registers (except CS, which the far-return set).
  movw $PHYS16_DATA32_SEL, %ax
  movw %ax, %ds
  movw %ax, %es
  movw %ax, %ss
  xorl %ebx, %ebx
  movw %bx, %fs
  movw %bx, %gs

  // Build minimal identity-map page tables covering 0-4 GiB using 2 MiB
  // pages.  Memory layout (each region 4 KiB):
  //   0x8000  PML4   (1 used entry → PDPT at 0x9000)
  //   0x9000  PDPT   (4 used entries → PD[0..3])
  //   0xA000  PD[0]  identity-maps 0 GiB - 1 GiB
  //   0xB000  PD[1]  identity-maps 1 GiB - 2 GiB
  //   0xC000  PD[2]  identity-maps 2 GiB - 3 GiB
  //   0xD000  PD[3]  identity-maps 3 GiB - 4 GiB
  cld
  xorl %eax, %eax
  movl $0x8000, %edi
  movl $(6 * 1024), %ecx    // 6 pages × 1024 dwords = 6 × 4 KiB
  rep stosl

  // PML4[0] → PDPT at 0x9000 (P | R/W)
  movl $0x00009003, 0x8000
  movl $0, 0x8004

  // PDPT[0..3] → PD[0..3] at 0xA000..0xD000 (P | R/W)
  movl $0x0000A003, 0x9000
  movl $0, 0x9004
  movl $0x0000B003, 0x9008
  movl $0, 0x900C
  movl $0x0000C003, 0x9010
  movl $0, 0x9014
  movl $0x0000D003, 0x9018
  movl $0, 0x901C

  // Fill PD[0..3] with 2 MiB page entries: PD[j][i] = ((j*512+i)<<21)|0x83
  // EDI advances through 0xA000..0xDFFF; ECX=j (0..3); EDX=i (0..511).
  movl $0xA000, %edi
  xorl %ecx, %ecx
.Lpd_outer:
  xorl %edx, %edx
.Lpd_inner:
  movl %ecx, %eax
  shll $9, %eax               // j * 512
  addl %edx, %eax             // j * 512 + i
  shll $21, %eax              // 2 MiB-aligned base address (bits 31:21)
  orl $0x83, %eax             // P | R/W | PS (2 MiB page)
  movl %eax, (%edi)
  movl $0, 4(%edi)            // upper 32 bits = 0 (< 4 GiB)
  addl $8, %edi
  incl %edx
  cmpl $512, %edx
  jl .Lpd_inner
  incl %ecx
  cmpl $4, %ecx
  jl .Lpd_outer

  // Enable PAE (CR4.PAE = bit 5).
  movl %cr4, %eax
  orl $(1 << 5), %eax
  movl %eax, %cr4

  // Point CR3 at the PML4.
  movl $0x8000, %eax
  movl %eax, %cr3

  // Set EFER.LME (bit 8) to request 64-bit long mode.
  movl $0xC0000080, %ecx      // IA32_EFER MSR number
  rdmsr
  orl $(1 << 8), %eax
  wrmsr

  // Enable paging (CR0.PG = bit 31); this also activates long mode.
  movl %cr0, %eax
  orl $(1 << 31), %eax
  movl %eax, %cr0

  // linuxboot_dma DMA-loads the kernel to the address from fw_cfg key
  // FW_CFG_KERNEL_ADDR (0x07), but does NOT write that address back to
  // boot_params.hdr.code32_start.  Read it now via the fw_cfg I/O-port
  // interface (port 0x510 = selector, 0x511 = data) and store it so
  // Long64Entry can find it.  We are in ring 0 without a TSS, so there is
  // no IOPL check; IN/OUT work unconditionally.
  movw $7, %ax
  movw $0x510, %dx
  outw %ax, %dx              // select FW_CFG_KERNEL_ADDR
  movw $0x511, %dx
  inb %dx, %al               // byte 0 (LSB)
  movzbl %al, %eax
  inb %dx, %al               // byte 1
  movzbl %al, %ecx
  shll $8, %ecx
  orl %ecx, %eax
  inb %dx, %al               // byte 2
  movzbl %al, %ecx
  shll $16, %ecx
  orl %ecx, %eax
  inb %dx, %al               // byte 3 (MSB)
  movzbl %al, %ecx
  shll $24, %ecx
  orl %ecx, %eax
  movl %eax, (BOOT_PARAMS_HDR + SETUP_HEADER_CODE32_START)(%esi)

  // Now in 32-bit compatibility submode of 64-bit long mode.  Far-jump to
  // Long64Entry in the 64-bit code segment.  The jump target address is
  //   ESI + (Long64Entry - zero_page)
  // where ESI still holds setup_addr (preserved across the 16-bit -> 32-bit
  // transition).  Build a 6-byte far-pointer on the stack: [EIP(4)|CS(2)].
  movl $(Long64Entry - zero_page), %eax
  addl %esi, %eax             // EAX = physical address of Long64Entry
  movl %eax, -8(%esp)         // far-pointer[0..3] = EIP
  movw $PHYS16_CODE64_SEL, -4(%esp)  // far-pointer[4..5] = CS
  ljmpl *-8(%esp)
.end_function

// Execution resumes here in 64-bit long mode.
.balign 16, 0
.code64
.function Long64Entry, nosection=nosection
  // RSI = setup_addr = physical address of boot_params (set in Phys16Entry,
  //   preserved across all mode transitions).
  // Read code32_start from boot_params->hdr.code32_start (at byte offset
  //   BOOT_PARAMS_HDR + SETUP_HEADER_CODE32_START = 0x1F1 + 35 = 0x214).
  // QEMU sets this field to the actual kernel physical load address.
  // Linux64Entry is at kernel_load_addr + ENTRY64_OFFSET (= +0x200).

  // Copy E820 entries from scratch buffer (physical 0x5000) into boot_params.
  // Protected32Entry and this Long64Entry code have now both executed, so the
  // boot_params.e820_table region (setup_addr+0x2D0 onward) can be overwritten.
  movzwl 0x4FFE, %ecx
  testl %ecx, %ecx
  jz .Lno_e820_copy
  movb %cl, BOOT_PARAMS_E820_ENTRIES(%rsi)
  movq %rsi, %r8                        // save boot_params ptr; RSI reused below
  imull $SIZEOF_E820ENTRY, %ecx
  movq $0x5000, %rsi
  leaq BOOT_PARAMS_E820_TABLE(%r8), %rdi
  rep movsb
  movq %r8, %rsi                        // restore boot_params ptr
.Lno_e820_copy:

  movl (BOOT_PARAMS_HDR + SETUP_HEADER_CODE32_START)(%rsi), %eax
  addl $ENTRY64_OFFSET, %eax
  jmpq *%rax
.end_function

// Temporary GDT used only for the real-mode -> 64-bit-mode transition above.
// Discarded once the kernel reinitialises its own descriptor tables.
.balign 8, 0
.object phys16_gdt, nosection=nosection
  .quad 0x0000000000000000    // [0x00] null descriptor
  .long 0x0000FFFF            // [0x08] 32-bit flat code: base=0, limit=4GiB
  .long 0x00CF9A00            //        G=1, D=1 (32-bit), P=1, type=code R/X
  .long 0x0000FFFF            // [0x10] 32-bit flat data: base=0, limit=4GiB
  .long 0x00CF9200            //        G=1, D=1, P=1, type=data R/W
  .long 0x0000FFFF            // [0x18] 64-bit code: L=1, D=0
  .long 0x00AF9A00            //        G=1, L=1, P=1, type=code R/X
.end_object

// Pad out to a whole number of 512-byte sectors and record that total size (in
// bytes) as the value of the LINUXBOOT_SETUP_SIZE symbol (a SHN_ABS symbol
// that's a size, not an address).  The setup_header::setup_sects field
// initializer is calculated from this value above.  The linuxboot.ld linker
// script also uses this symbol to compute the LINUXBOOT_SYSSIZE symbol that's
// needed for the setup_header::syssize field initializer above.
//
// This also becomes the base address at which the kernel image is loaded.  At
// runtime it will be page-aligned, but can be at any address.  The link-time
// base address (aka PHYS_LOAD_ADDRESS) is zero, but that has to leave space
// for the zero_page (including setup_header) that is never actually part of
// the memory image, only part of the bzImage binary file format.  To make the
// usual assumptions about link-time vs runtime alignment hold true for
// simplicity's sake, we align this to 4KiB in the file too.  It might waste a
// few KiB in the image size and probably things would work fine without it,
// but it makes the address arithmetic easier to understand when debugging.
.p2align 12, 0
.label LINUXBOOT_SETUP_SIZE, global, notype, . - zero_page
.label LINUXBOOT_LOAD_ADDRESS, global

// It's also the entrypoint for bootloaders using the 32-bit boot protocol.
// That's not supported.  This entry code can only be used with boot loaders
// that use the 64-bit Linux boot protocol, so just crash here.
.code32
.function Linux32Entry, nosection=nosection
  ud2
.end_function

// Add the in-kernel config file, which is gzipped.  Some emulators look for
// this file using extract-ikconfig before booting.  The compressed file (and
// even its uncompressed input) is very tiny, so it fits before the fixed
// offset of the entry point code below.
.ascii "IKCFG_ST"
.incbin IKCONFIG_FILE
.ascii "IKCFG_ED"

// The 64-bit boot protocol always jumps here.
.org LINUXBOOT_LOAD_ADDRESS + ENTRY64_OFFSET

// Just jump to the generic start.S code.  The boot_params pointer is in %rsi,
// which is where that code already expects the boot loader's data pointer.
.code64
.function Linux64Entry, nosection=nosection
  jmp _start
.end_function
