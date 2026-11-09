#!/usr/bin/env python3
"""Generate a minimal valid ARM64 PIE ELF stub.

This produces the smallest valid ET_DYN ELF for AArch64 that elfldltl can
parse without errors.  Physboot uses it to satisfy the vdso/userboot presence
check.  The stub contains a single PT_LOAD (read-only, 1 page), a GNU build-id
NOTE, and an entry point that is a single BRK instruction (so any attempt to
run it produces a clean fault rather than undefined behavior).

Usage:
  make_arm64_stub_elf.py --output stub.elf [--name my-stub]
"""

import argparse
import hashlib
import struct
import sys


def make_arm64_stub_elf(name: str = "stub") -> bytes:
    # Constants
    EM_AARCH64 = 183
    ET_DYN = 3
    PT_LOAD = 1
    PT_NOTE = 4
    PT_DYNAMIC = 2
    PT_GNU_STACK = 0x6474e551
    PF_R = 4
    PF_W = 2
    PF_X = 1
    PF_RW = PF_R | PF_W
    PAGE_SIZE = 0x1000

    # AArch64 BRK #0 instruction (4 bytes, LE)
    BRK0 = b'\x00\x00\x20\xd4'

    # GNU build ID NOTE:
    # namesz=4 ("GNU\0"), descsz=20 (SHA1), type=3
    note_name = b'GNU\x00'
    # SHA-1 of the name for a reproducible build ID
    note_desc = hashlib.sha1(name.encode()).digest()  # 20 bytes
    note_type = 3
    note_header = struct.pack('<III', len(note_name), len(note_desc), note_type)
    note_data = note_header + note_name + note_desc

    # Layout (all within a single PT_LOAD at vaddr=0):
    #   0x00  ELF header (64 bytes)
    #   0x40  PHDR table (4 phdrs × 56 bytes = 224 bytes)
    #   0x120 NOTE data (len(note_data) bytes ≈ 32)
    #   0x140 BRK instruction (4 bytes) ← entry point
    #   0x144 DYNAMIC section (1 DT_NULL entry = 16 bytes)
    #   0x154 end

    EHDR_SIZE = 64
    PHENTSIZE = 56
    N_PHDRS = 4  # LOAD, NOTE, DYNAMIC, GNU_STACK
    PHDR_TABLE_OFF = EHDR_SIZE
    PHDR_TABLE_SIZE = N_PHDRS * PHENTSIZE
    NOTE_OFF = PHDR_TABLE_OFF + PHDR_TABLE_SIZE  # 0x40 + 0xe0 = 0x120
    NOTE_SIZE = len(note_data)
    ENTRY_OFF = NOTE_OFF + NOTE_SIZE            # entry = BRK instruction
    # Align to 4 bytes
    ENTRY_OFF = (ENTRY_OFF + 3) & ~3
    DYN_OFF = ENTRY_OFF + 4                    # dynamic section after BRK
    # DT_NULL entry
    DT_NULL_ENTRY = struct.pack('<QQ', 0, 0)   # 16 bytes
    DYN_SIZE = len(DT_NULL_ENTRY)
    TOTAL_SIZE = DYN_OFF + DYN_SIZE
    # Round up to page size
    FILE_SIZE = (TOTAL_SIZE + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)

    # ELF header (64 bytes)
    ehdr = struct.pack(
        '<4sBBBBBxxxxxxx'  # e_ident
        'HHIQQQIHHHHHH',   # rest
        b'\x7fELF',        # magic
        2,                 # EI_CLASS = ELFCLASS64
        1,                 # EI_DATA = ELFDATA2LSB
        1,                 # EI_VERSION
        0,                 # EI_OSABI = ELFOSABI_NONE
        0,                 # EI_ABIVERSION
        ET_DYN,            # e_type
        EM_AARCH64,        # e_machine
        1,                 # e_version
        ENTRY_OFF,         # e_entry (BRK instruction)
        PHDR_TABLE_OFF,    # e_phoff
        0,                 # e_shoff (no section headers)
        0,                 # e_flags
        EHDR_SIZE,         # e_ehsize
        PHENTSIZE,         # e_phentsize
        N_PHDRS,           # e_phnum
        64,                # e_shentsize
        0,                 # e_shnum
        0,                 # e_shstrndx
    )
    assert len(ehdr) == EHDR_SIZE

    def phdr64(p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align):
        return struct.pack('<IIQQQQQQ',
                          p_type, p_flags,
                          p_offset, p_vaddr, p_paddr,
                          p_filesz, p_memsz, p_align)

    # PT_LOAD: covers the entire file, RX (read+exec for code page)
    phdr_load = phdr64(PT_LOAD, PF_R | PF_X, 0, 0, 0, FILE_SIZE, FILE_SIZE, PAGE_SIZE)
    # PT_NOTE: the GNU build-id note
    phdr_note = phdr64(PT_NOTE, PF_R, NOTE_OFF, NOTE_OFF, NOTE_OFF, NOTE_SIZE, NOTE_SIZE, 4)
    # PT_DYNAMIC: single DT_NULL
    phdr_dyn = phdr64(PT_DYNAMIC, PF_R | PF_W, DYN_OFF, DYN_OFF, DYN_OFF, DYN_SIZE, DYN_SIZE, 8)
    # PT_GNU_STACK: required by elfldltl (stack size hint)
    phdr_gnu_stack = phdr64(PT_GNU_STACK, PF_R | PF_W, 0, 0, 0, 0, 0, 0)

    phdrs = phdr_load + phdr_note + phdr_dyn + phdr_gnu_stack
    assert len(phdrs) == PHDR_TABLE_SIZE

    # Assemble the file
    data = bytearray(FILE_SIZE)
    data[0:EHDR_SIZE] = ehdr
    data[PHDR_TABLE_OFF:PHDR_TABLE_OFF + PHDR_TABLE_SIZE] = phdrs
    data[NOTE_OFF:NOTE_OFF + NOTE_SIZE] = note_data
    data[ENTRY_OFF:ENTRY_OFF + 4] = BRK0
    data[DYN_OFF:DYN_OFF + DYN_SIZE] = DT_NULL_ENTRY
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate minimal ARM64 PIE ELF stub')
    parser.add_argument('--output', required=True, help='Output ELF file path')
    parser.add_argument('--name', default='stub', help='Stub name (used for build-ID)')
    args = parser.parse_args()

    elf_data = make_arm64_stub_elf(args.name)
    with open(args.output, 'wb') as f:
        f.write(elf_data)
    print(f'Written {len(elf_data)} bytes to {args.output}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
