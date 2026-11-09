#!/usr/bin/env python3
"""Check that an EFI PE/COFF image has reproducible linker timestamps."""

import pathlib
import struct
import sys


def fail(message: str) -> None:
    raise SystemExit(f"efi timestamp check: {message}")


def read_u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        fail(f"truncated u16 at {offset}")
    return struct.unpack_from("<H", data, offset)[0]


def read_u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        fail(f"truncated u32 at {offset}")
    return struct.unpack_from("<I", data, offset)[0]


def check(path: pathlib.Path, rule: pathlib.Path) -> None:
    rule_text = rule.read_text(encoding="utf-8")
    if 'args.add("/Brepro")' not in rule_text:
        fail(f"{rule} does not request lld-link /Brepro")

    data = path.read_bytes()
    if data[:2] != b"MZ":
        fail(f"{path} is not a DOS/PE image")
    pe = read_u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        fail(f"{path} has no PE signature")

    timestamp = read_u32(data, pe + 8)
    sections = read_u16(data, pe + 6)
    optional_size = read_u16(data, pe + 20)
    optional = pe + 24
    if optional + optional_size > len(data):
        fail(f"{path} optional header extends past the image")
    magic = read_u16(data, optional)
    if magic == 0x20B:
        directory_offset = 112
    elif magic == 0x10B:
        directory_offset = 96
    else:
        fail(f"{path} has unknown optional-header magic 0x{magic:04x}")
    directory_end = directory_offset + (6 * 8) + 8
    if optional_size < directory_end:
        fail(f"{path} optional header has no complete debug directory entry")
    debug_directory = optional + directory_offset + (6 * 8)
    debug_rva = read_u32(data, debug_directory)
    debug_size = read_u32(data, debug_directory + 4)
    if debug_size and (debug_size < 28 or debug_size % 28):
        fail(f"{path} has a malformed debug directory size/RVA")

    section_table = optional + optional_size
    section_table_end = section_table + (sections * 40)
    if section_table_end > len(data):
        fail(f"{path} section table extends past the image")
    section_ranges = []
    for index in range(sections):
        section = section_table + (index * 40)
        virtual_size = read_u32(data, section + 8)
        virtual_address = read_u32(data, section + 12)
        raw_size = read_u32(data, section + 16)
        raw_pointer = read_u32(data, section + 20)
        if raw_pointer > len(data) or raw_pointer + raw_size > len(data):
            fail(f"{path} section {index} raw data extends past the image")
        section_ranges.append((virtual_address, virtual_size, raw_size, raw_pointer))
    if not debug_rva and not debug_size:
        print(f"efi timestamp check: {path}: PE timestamp={timestamp}; no debug directory")
        return
    if not debug_rva:
        fail(f"{path} has a malformed debug directory size/RVA")

    # The directory must be both addressable in the section's virtual span and
    # wholly backed by the section's raw bytes. This rejects a directory whose
    # start is in a section but whose tail crosses either boundary.
    debug_rva_end = debug_rva + debug_size
    if debug_rva_end < debug_rva:
        fail(f"{path} debug directory RVA overflows")

    debug_file_offset = None
    debug_section_end = None
    for virtual_address, virtual_size, raw_size, raw_pointer in section_ranges:
        span = max(virtual_size, raw_size)
        virtual_end = virtual_address + span
        if virtual_address <= debug_rva and debug_rva_end <= virtual_end:
            debug_delta = debug_rva - virtual_address
            debug_file_offset = raw_pointer + debug_delta
            debug_section_end = raw_pointer + raw_size
            break
    if debug_file_offset is None:
        fail(f"{path} debug directory RVA is not in a section")
    if debug_file_offset > debug_section_end or debug_file_offset + debug_size > debug_section_end:
        fail(f"{path} debug directory extends past its section")

    for entry in range(debug_size // 28):
        entry_offset = debug_file_offset + (entry * 28)
        debug_timestamp = read_u32(data, entry_offset + 4)
        if debug_timestamp != timestamp:
            fail(
                f"{path} debug entry {entry} timestamp {debug_timestamp}, "
                f"expected PE timestamp {timestamp}"
            )
    print(f"efi timestamp check: {path}: PE/debug timestamps={timestamp}")


if len(sys.argv) != 3:
    raise SystemExit(f"usage: {sys.argv[0]} EFI_IMAGE EFI_RULE")
check(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]))
