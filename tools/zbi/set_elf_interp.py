#!/usr/bin/env python3
"""Patch the PT_INTERP string in a kernel ELF with physboot's build ID.

The arm64 kernel is linked with --dynamic-linker=0000...0000 (40-char placeholder).
This script reads physboot's GNU build-ID NOTE (also 20 bytes = 40 hex chars) and
overwrites the placeholder in the kernel ELF's PT_INTERP segment data in place.

Usage:
  set_elf_interp.py --input kernel.elf --interp-from physboot --output patched.elf
"""

import argparse
import struct
import sys


def read_build_id_note(data: bytes) -> bytes:
    """Return the raw build-ID bytes from an ELF's GNU build-id NOTE, or b''."""
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return b''
    ei_data = data[5]
    if ei_data != 1:
        return b''
    ei_class = data[4]
    if ei_class == 2:
        e_phoff, = struct.unpack_from('<Q', data, 32)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 54)
        phdr_fmt = '<IIQQQQQQ'
    else:
        e_phoff, = struct.unpack_from('<I', data, 28)
        e_phentsize, e_phnum = struct.unpack_from('<HH', data, 42)
        phdr_fmt = '<IIIIIIII'

    PT_NOTE = 4
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        phdr = struct.unpack_from(phdr_fmt, data, off)
        p_type = phdr[0]
        if ei_class == 2:
            p_offset, p_filesz = phdr[2], phdr[5]
        else:
            p_offset, p_filesz = phdr[1], phdr[4]
        if p_type != PT_NOTE:
            continue
        pos = p_offset
        end = p_offset + p_filesz
        while pos + 12 <= end:
            namesz, descsz, note_type = struct.unpack_from('<III', data, pos)
            pos += 12
            name_aligned = (namesz + 3) & ~3
            desc_aligned = (descsz + 3) & ~3
            if pos + name_aligned + desc_aligned > end:
                break
            name = data[pos:pos + namesz]
            pos += name_aligned
            desc = data[pos:pos + descsz]
            pos += desc_aligned
            if note_type == 3 and name.rstrip(b'\x00') == b'GNU' and descsz > 0:
                return desc
    return b''


def patch_pt_interp(kernel_data: bytes, build_id_hex: str) -> bytes:
    """Overwrite the PT_INTERP string in kernel_data with build_id_hex.

    The kernel must already have a PT_INTERP segment (from --dynamic-linker=...).
    The existing interp string must have the same byte length as build_id_hex + 1
    (for the null terminator).
    """
    if kernel_data[:4] != b'\x7fELF':
        raise ValueError('Not an ELF file')
    ei_class = kernel_data[4]
    if ei_class != 2:
        raise ValueError('Only 64-bit ELF supported')
    if kernel_data[5] != 1:
        raise ValueError('Only little-endian ELF supported')

    e_phoff, = struct.unpack_from('<Q', kernel_data, 32)
    e_phentsize, e_phnum = struct.unpack_from('<HH', kernel_data, 54)

    PT_INTERP = 3
    interp_offset = None
    interp_filesz = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, p_flags = struct.unpack_from('<II', kernel_data, off)
        if p_type == PT_INTERP:
            p_offset, = struct.unpack_from('<Q', kernel_data, off + 8)
            p_filesz, = struct.unpack_from('<Q', kernel_data, off + 32)
            interp_offset = p_offset
            interp_filesz = p_filesz
            break

    if interp_offset is None:
        raise ValueError('Kernel ELF has no PT_INTERP segment')

    new_interp = build_id_hex.encode('ascii') + b'\x00'
    if len(new_interp) != interp_filesz:
        raise ValueError(
            f'PT_INTERP size mismatch: kernel has {interp_filesz} bytes, '
            f'new interp needs {len(new_interp)} bytes '
            f'(build_id_hex={build_id_hex!r})'
        )

    data = bytearray(kernel_data)
    data[interp_offset:interp_offset + interp_filesz] = new_interp
    return bytes(data)


def main() -> int:
    parser = argparse.ArgumentParser(description='Patch PT_INTERP in kernel ELF')
    parser.add_argument('--input', required=True, help='Input kernel ELF (with placeholder interp)')
    parser.add_argument('--interp-from', required=True, help='ELF whose build ID to use as interp')
    parser.add_argument('--output', required=True, help='Output patched kernel ELF')
    args = parser.parse_args()

    with open(args.interp_from, 'rb') as f:
        physboot_data = f.read()
    build_id = read_build_id_note(physboot_data)
    if not build_id:
        print(f'ERROR: no GNU build ID found in {args.interp_from}', file=sys.stderr)
        return 1
    build_id_hex = build_id.hex()
    print(f'physboot build ID: {build_id_hex}')

    with open(args.input, 'rb') as f:
        kernel_data = f.read()

    patched = patch_pt_interp(kernel_data, build_id_hex)

    with open(args.output, 'wb') as f:
        f.write(patched)
    print(f'Written {args.output} with PT_INTERP={build_id_hex!r}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
