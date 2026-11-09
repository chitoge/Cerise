#!/usr/bin/env python3

import argparse
import hashlib
import os
import struct
import subprocess
import sys
import tempfile


ZBI_ALIGNMENT = 8
ZBI_CONTAINER_MAGIC = 0x868CF7E6
ZBI_ITEM_MAGIC = 0xB5781729
ZBI_FLAGS_VERSION = 1 << 16
# ZBI_FLAGS_STORAGE_COMPRESSED (zbi-format storage.h): the STORAGE_* payload is a
# zstd frame; header.extra holds the decompressed length. userboot decompresses
# STORAGE_BOOTFS at runtime (userboot/zbi.cc -> zbitl CopyStorageItem, real
# static-DCtx zstd in src/lib/zbitl/zstd.cc).
ZBI_FLAGS_STORAGE_COMPRESSED = 1 << 0
ZBI_ITEM_NO_CRC32 = 0x4A87E8D6

# Upstream zbi.cc's default STORAGE compression level (zircon/tools/zbi/zbi.cc
# Zstd::DefaultLevel()). See tools/zstd/zstd_cli.c on why no long-distance
# matching (static-DCtx window safety for the userboot one-shot decode).
ZSTD_DEFAULT_LEVEL = 4

ZBI_TYPE_CONTAINER = 0x544F4F42
ZBI_TYPE_KERNEL_ARM64 = 0x384E524B
ZBI_TYPE_CMDLINE = 0x4C444D43
ZBI_TYPE_MEM_CONFIG = 0x434D454D
ZBI_TYPE_NVRAM = 0x4C4C564E
ZBI_TYPE_STORAGE_BOOTFS = 0x42534642
ZBI_TYPE_STORAGE_KERNEL = 0x5254534B
# Generic kernel-driver item type. The specific driver token (ARM GIC, ARM
# generic timer, RISC-V PLIC, ...) is the item's `extra` field and its packed
# register layout is the payload — BOTH supplied by the caller (--kernel-driver),
# never hardcoded here, so a third-party arch adds a board, not a tool edit.
ZBI_TYPE_KERNEL_DRIVER = 0x5652444B

ZBI_MEM_TYPE_RAM = 1

ZBI_BOOTFS_MAGIC = 0xA56D3FF9
ZBI_BOOTFS_PAGE_SIZE = 4096


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def pad(data, alignment):
    return data + (b"\0" * (align(len(data), alignment) - len(data)))


def zbi_header(item_type, payload_length, extra=0, flags=ZBI_FLAGS_VERSION):
    return struct.pack(
        "<IIIIIIII",
        item_type,
        payload_length,
        extra,
        flags,
        0,
        0,
        ZBI_ITEM_MAGIC,
        ZBI_ITEM_NO_CRC32,
    )


def zbi_item(item_type, payload, extra=0, flags=ZBI_FLAGS_VERSION):
    return zbi_header(item_type, len(payload), extra, flags) + pad(payload, ZBI_ALIGNMENT)


def zstd_compress(payload, zstd_tool, level=ZSTD_DEFAULT_LEVEL):
    """Return `payload` compressed as a single zstd frame via the host zstd CLI.

    Hermetic: shells out to the build's //tools/zstd:zstd_cli (built from the
    vendored zstd sources), never a system zstd. The frame carries its own
    content size, and userboot decompresses it at runtime.
    """
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "in")
        dst = os.path.join(tmp, "out")
        with open(src, "wb") as f:
            f.write(payload)
        subprocess.run([zstd_tool, "compress", src, dst, str(level)], check=True)
        with open(dst, "rb") as f:
            return f.read()


def storage_bootfs_item(bootfs, zstd_tool):
    """Emit a STORAGE_BOOTFS item, zstd-compressed iff `zstd_tool` is set.

    Compressed: payload is the zstd frame, header.length is the compressed byte
    count, header.extra is the UNCOMPRESSED length, and ZBI_FLAGS_STORAGE_COMPRESSED
    is set (zbitl UncompressedLength/DecompressStorage read extra as the decoded
    size). Raw: extra is the uncompressed length too, no compressed flag — the
    exact pre-existing encoding, so uncompressed products stay byte-identical.
    """
    uncompressed_len = len(bootfs)
    if zstd_tool:
        compressed = zstd_compress(bootfs, zstd_tool)
        # Only keep the compression if it actually shrank the payload.
        if len(compressed) < uncompressed_len:
            return zbi_item(
                ZBI_TYPE_STORAGE_BOOTFS,
                compressed,
                extra=uncompressed_len,
                flags=ZBI_FLAGS_VERSION | ZBI_FLAGS_STORAGE_COMPRESSED,
            )
    return zbi_item(ZBI_TYPE_STORAGE_BOOTFS, bootfs, extra=uncompressed_len)


def read_container_payload(path):
    with open(path, "rb") as zbi_file:
        data = zbi_file.read()
    if len(data) < 32:
        raise ValueError(f"{path}: too small for ZBI container")
    item_type, payload_length, extra, flags, _, _, magic, crc32 = struct.unpack_from(
        "<IIIIIIII", data, 0
    )
    if item_type != ZBI_TYPE_CONTAINER or extra != ZBI_CONTAINER_MAGIC:
        raise ValueError(f"{path}: expected ZBI container header")
    if magic != ZBI_ITEM_MAGIC or crc32 != ZBI_ITEM_NO_CRC32:
        raise ValueError(f"{path}: unexpected ZBI container magic")
    if flags & ZBI_FLAGS_VERSION != ZBI_FLAGS_VERSION:
        raise ValueError(f"{path}: missing ZBI version flag")
    payload_end = 32 + align(payload_length, ZBI_ALIGNMENT)
    if len(data) < payload_end:
        raise ValueError(f"{path}: truncated ZBI payload")
    return data[32:payload_end]


def pad_kernel_arm64(item_bytes):
    """Extend a KERNEL_ARM64 item's payload by reserve_memory_size to prevent BSS overlap.

    The physload ELF's BSS extends beyond the KERNEL_ARM64 payload in the ZBI.
    By padding the payload by reserve_memory_size, subsequent items (CMDLINE, etc.)
    are placed after the BSS region and are not overwritten by BSS initialization.
    """
    if len(item_bytes) < 32 + 16:
        return item_bytes
    item_type, item_len = struct.unpack_from('<II', item_bytes, 0)
    if item_type != ZBI_TYPE_KERNEL_ARM64:
        return item_bytes
    # zbi_kernel_t: entry(8B) + reserve_memory_size(8B) at start of payload (offset 32)
    _entry, reserve_size = struct.unpack_from('<QQ', item_bytes, 32)
    if reserve_size == 0:
        return item_bytes
    reserve_aligned = align(reserve_size, ZBI_ALIGNMENT)
    payload = item_bytes[32:32 + item_len]
    padded_payload = payload + b'\x00' * reserve_aligned
    new_len = len(padded_payload)
    new_header = struct.pack(
        '<IIIIIIII',
        item_type, new_len, 0, ZBI_FLAGS_VERSION, 0, 0, ZBI_ITEM_MAGIC, ZBI_ITEM_NO_CRC32,
    )
    original_end = 32 + align(item_len, ZBI_ALIGNMENT)
    return new_header + pad(padded_payload, ZBI_ALIGNMENT) + item_bytes[original_end:]


def read_manifest(path):
    entries = []
    with open(path, "r", encoding="utf-8") as manifest:
        for line_number, line in enumerate(manifest, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"{path}:{line_number}: expected DEST=SOURCE")
            dest, source = line.split("=", 1)
            if not dest or dest.startswith("/") or "\0" in dest:
                raise ValueError(f"{path}:{line_number}: invalid BOOTFS destination {dest!r}")
            entries.append((dest, source))
    return sorted(entries)


def bootfs_dirent(name, data_length, data_offset):
    encoded_name = name.encode("utf-8") + b"\0"
    if not 1 < len(encoded_name) <= 256:
        raise ValueError(f"BOOTFS name length out of range: {name!r}")
    body = struct.pack("<III", len(encoded_name), data_length, data_offset) + encoded_name
    return pad(body, 4)


def parse_bootfs(payload):
    """Parse a raw (uncompressed) STORAGE_BOOTFS payload into [(name, data)]."""
    entries = []
    if len(payload) < 16 or struct.unpack_from("<I", payload, 0)[0] != ZBI_BOOTFS_MAGIC:
        return entries
    dir_size = struct.unpack_from("<I", payload, 4)[0]
    off, end = 16, 16 + dir_size
    while off + 12 <= end:
        namelen, dlen, doff = struct.unpack_from("<III", payload, off)
        name = payload[off + 12:off + 12 + namelen].split(b"\0")[0].decode("utf-8")
        entries.append((name, payload[doff:doff + dlen]))
        off += align(12 + namelen, 4)
    return entries


def iter_zbi_items(blob):
    """Yield (item_bytes, item_type, payload) for each item in a container payload."""
    off, n = 0, len(blob)
    while off + 32 <= n:
        item_type, plen = struct.unpack_from("<II", blob, off)
        total = 32 + align(plen, ZBI_ALIGNMENT)
        yield blob[off:off + total], item_type, blob[off + 32:off + 32 + plen]
        off += total


def build_bootfs(file_data):
    # file_data: list of (name, data_bytes)
    #
    # Content-addressed: entries with identical bytes share ONE page-aligned data
    # block, and every dirent for that content points at the shared data_offset.
    # This is format-legal — a dirent is just (name_len, data_len, data_offset),
    # and nothing requires distinct entries to hold distinct offsets. It folds the
    # heavy literal duplication (libc++.so.1, ld.so.1, libfdio.so, ...) staged at
    # many dests into a single copy each.
    #
    # Determinism: dirent order is preserved exactly (input order is untouched);
    # unique data blocks are emitted in first-appearance order. With no duplicates
    # this is byte-for-byte identical to the naive one-block-per-entry layout.
    #
    # Runtime safety of aliased offsets is deliberate, not incidental: the bootfs
    # VMO is NOT read-only at runtime — userboot moves pages OUT of it via
    # zx_vmo_transfer_data/TakePages when it loads a file. Every consumer that can
    # read a moved-out (decommitted) offset is keyed on data_offset — userboot's
    # own Open cache and component_runner's PostBootfsFiles cache — so all aliases
    # of a decommitted block resolve to the single reissued VMO; blocks that were
    # never loaded stay committed and read back correctly at their shared offset.
    file_data = list(file_data)
    dir_size = 0
    for name, data in file_data:
        dir_size += len(bootfs_dirent(name, len(data), 0))

    base_offset = align(16 + dir_size, ZBI_BOOTFS_PAGE_SIZE)

    # Map content -> shared data_offset. Keyed by SHA-256; the first bytes seen
    # for a key are retained so a (astronomically unlikely) digest collision on
    # differing content is caught instead of silently corrupting the image.
    content = {}  # sha256 digest -> (data_offset, data_bytes)
    data_blocks = []
    next_offset = base_offset
    keyed = []  # parallel to file_data: (name, data, digest)
    for name, data in file_data:
        digest = hashlib.sha256(data).digest()
        existing = content.get(digest)
        if existing is None:
            content[digest] = (next_offset, data)
            padded_data = pad(data, ZBI_BOOTFS_PAGE_SIZE)
            data_blocks.append(padded_data)
            next_offset += len(padded_data)
        elif existing[1] != data:
            raise ValueError(f"SHA-256 collision on BOOTFS entry {name!r}")
        keyed.append((name, data, digest))

    dirents = [
        bootfs_dirent(name, len(data), content[digest][0])
        for name, data, digest in keyed
    ]

    header = struct.pack("<IIII", ZBI_BOOTFS_MAGIC, dir_size, 0, 0)
    directory = b"".join(dirents)
    return pad(header + directory, ZBI_BOOTFS_PAGE_SIZE) + b"".join(data_blocks)


def load_items(args):
    items = []
    # Merge ALL bootfs sources into ONE STORAGE_BOOTFS: userboot/the kernel reads
    # only the first STORAGE_BOOTFS item, so layering extra_bootfs as a separate
    # item (as before) silently dropped those files. Extract bootfs entries from
    # the input ZBIs, pass through every other item verbatim, and re-emit a single
    # merged STORAGE_BOOTFS below.
    bootfs_entries = []  # list of (name, data_bytes)
    for input_zbi in args.input_zbi:
        blob = pad_kernel_arm64(read_container_payload(input_zbi))
        for item_bytes, item_type, payload in iter_zbi_items(blob):
            if item_type == ZBI_TYPE_STORAGE_BOOTFS:
                bootfs_entries.extend(parse_bootfs(payload))
            else:
                items.append(item_bytes)
    for cmdline in args.cmdline:
        items.append(zbi_item(ZBI_TYPE_CMDLINE, cmdline.encode("utf-8")))
    for manifest in args.storage_kernel_manifest:
        kdata = [(name, open(src, "rb").read()) for name, src in read_manifest(manifest)]
        bootfs = build_bootfs(kdata)
        items.append(zbi_item(ZBI_TYPE_STORAGE_KERNEL, bootfs, extra=len(bootfs)))
    for manifest in args.storage_bootfs_manifest:
        for name, src in read_manifest(manifest):
            bootfs_entries.append((name, open(src, "rb").read()))
    if args.bootfs_file:
        for entry in args.bootfs_file:
            if "=" not in entry:
                raise ValueError(f"--bootfs-file: expected DEST=SOURCE, got {entry!r}")
            dest, source = entry.split("=", 1)
            bootfs_entries.append((dest, open(source, "rb").read()))
    if bootfs_entries:
        # De-dup by name (later sources win), deterministic order.
        merged = {}
        for name, data in bootfs_entries:
            merged[name] = data
        bootfs = build_bootfs(sorted(merged.items()))
        items.append(storage_bootfs_item(bootfs, args.zstd_tool if args.compress_bootfs else None))
    for mem_config_str in args.mem_config:
        parts = mem_config_str.split(",")
        if len(parts) != 3:
            raise ValueError(f"--mem-config: expected PADDR,SIZE,TYPE, got {mem_config_str!r}")
        paddr, size, mem_type = (int(p, 0) for p in parts)
        payload = struct.pack("<QQII", paddr, size, mem_type, 0)
        items.append(zbi_item(ZBI_TYPE_MEM_CONFIG, payload))
    # ZBI_TYPE_NVRAM: a persistent-RAM region (zbi_nvram_t{base,length}) the kernel
    # carves out of RAM (memalloc::Type::kNvram) and binds MappedCrashlog to, so a
    # panic's ram-crashlog survives a warm reboot. Only one region is meaningful.
    for nvram_str in args.nvram:
        parts = nvram_str.split(",")
        if len(parts) != 2:
            raise ValueError(f"--nvram: expected BASE,SIZE, got {nvram_str!r}")
        base, size = (int(p, 0) for p in parts)
        payload = struct.pack("<QQ", base, size)
        items.append(zbi_item(ZBI_TYPE_NVRAM, payload))
    # Generic arch kernel-driver items: DRIVER_TYPE=HEXPAYLOAD. The board (not this
    # tool) knows which driver tokens its arch needs and how their register blocks
    # pack; it hands the already-packed payload here. Keeps the tool arch-neutral.
    for kd in args.kernel_driver:
        if "=" not in kd:
            raise ValueError(f"--kernel-driver: expected DRIVER_TYPE=HEXPAYLOAD, got {kd!r}")
        type_str, hexpayload = kd.split("=", 1)
        driver_type = int(type_str, 0)
        payload = bytes.fromhex(hexpayload)
        items.append(zbi_item(ZBI_TYPE_KERNEL_DRIVER, payload, extra=driver_type))
    return items


def main():
    parser = argparse.ArgumentParser(description="Create a minimal uncompressed ZBI image.")
    parser.add_argument("--output", required=True)
    parser.add_argument("--input-zbi", action="append", default=[])
    parser.add_argument("--cmdline", action="append", default=[])
    parser.add_argument("--storage-kernel-manifest", action="append", default=[])
    parser.add_argument("--storage-bootfs-manifest", action="append", default=[])
    parser.add_argument("--bootfs-file", action="append", default=[], metavar="DEST=SOURCE")
    parser.add_argument("--mem-config", action="append", default=[], metavar="PADDR,SIZE,TYPE")
    parser.add_argument("--kernel-driver", action="append", default=[], metavar="DRIVER_TYPE=HEXPAYLOAD")
    parser.add_argument("--compress-bootfs", action="store_true",
                        help="zstd-compress the STORAGE_BOOTFS payload (requires --zstd-tool).")
    parser.add_argument("--zstd-tool", default=None,
                        help="Path to the host zstd CLI (//tools/zstd:zstd_cli) used to compress.")
    parser.add_argument("--nvram", action="append", default=[], metavar="BASE,SIZE")
    args = parser.parse_args()
    if args.compress_bootfs and not args.zstd_tool:
        parser.error("--compress-bootfs requires --zstd-tool")

    payload = b"".join(load_items(args))
    image = zbi_header(ZBI_TYPE_CONTAINER, len(payload), ZBI_CONTAINER_MAGIC) + payload
    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
    with open(args.output, "wb") as output:
        output.write(image)
    return 0


if __name__ == "__main__":
    sys.exit(main())