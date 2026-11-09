#!/usr/bin/env python3

import argparse
import os
import struct
import sys


def read_build_id(path):
    data = open(path, "rb").read()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError(f"{path}: expected little-endian ELF64")

    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        raise ValueError(f"{path}: ELF section table missing")

    def section(index):
        offset = e_shoff + index * e_shentsize
        return struct.unpack_from("<IIQQQQIIQQ", data, offset)

    shstr = section(e_shstrndx)
    shstr_data = data[shstr[4] : shstr[4] + shstr[5]]

    def section_name(name_offset):
        end = shstr_data.index(b"\0", name_offset)
        return shstr_data[name_offset:end].decode("ascii")

    for index in range(e_shnum):
        sh = section(index)
        if section_name(sh[0]) != ".note.gnu.build-id":
            continue
        note = data[sh[4] : sh[4] + sh[5]]
        namesz, descsz, note_type = struct.unpack_from("<III", note, 0)
        name_offset = 12
        desc_offset = (name_offset + namesz + 3) & ~3
        name = note[name_offset : name_offset + namesz].rstrip(b"\0")
        if name != b"GNU" or note_type != 3:
            raise ValueError(f"{path}: unexpected build-id note")
        return note[desc_offset : desc_offset + descsz].hex()

    raise ValueError(f"{path}: .note.gnu.build-id not found")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    build_id = read_build_id(args.input)
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as output:
        output.write(
            "// Generated from an ELF build ID.\n"
            ".section .interp, \"aR\", %progbits\n"
            ".balign 1\n"
            f".asciz \"{build_id}\"\n"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())