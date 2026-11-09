#!/usr/bin/env python3
"""Content-dedup tests for tools/zbi/simple_zbi.py's build_bootfs.

Covers: build_bootfs is content-
addressed — identical entry bytes share ONE page-aligned data block and every
dirent for that content points at the shared data_offset.

Tests:
  (a) round-trip + dedup: a bootfs built from synthetic files with known
      duplicates parses back to the exact {name: content} map (every aliased
      dirent resolves to the correct bytes), and each unique blob appears in the
      data section exactly once (payload size == base + Σ unique padded blocks).
      The parse is done with assembly/tools/bootfs_diff.py's parser (the tool the
      task designates) as well as simple_zbi's own, so a shared parser bug cannot
      mask a failure.
  (b) golden safety: with NO duplicate contents, the dedup layout is byte-for-
      byte identical to the naive one-block-per-entry layout (a reference copy of
      the pre-dedup algorithm embedded below).

Paths to simple_zbi.py and bootfs_diff.py are passed on argv so the test is
runfiles-location agnostic.
"""

import argparse
import hashlib
import importlib.util
import struct
import sys


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def reference_build_bootfs_no_dedup(zbi, file_data):
    """Faithful copy of the pre-dedup build_bootfs (one padded block per entry).

    Kept here as the golden oracle for test (b). Uses simple_zbi's own helpers
    (bootfs_dirent/pad/align/constants) so only the data-placement strategy
    differs from the module under test.
    """
    file_data = list(file_data)
    dir_size = 0
    for name, data in file_data:
        dir_size += len(zbi.bootfs_dirent(name, len(data), 0))

    data_offset = zbi.align(16 + dir_size, zbi.ZBI_BOOTFS_PAGE_SIZE)
    dirents = []
    data_blocks = []
    for name, data in file_data:
        dirents.append(zbi.bootfs_dirent(name, len(data), data_offset))
        padded_data = zbi.pad(data, zbi.ZBI_BOOTFS_PAGE_SIZE)
        data_blocks.append(padded_data)
        data_offset += len(padded_data)

    header = struct.pack("<IIII", zbi.ZBI_BOOTFS_MAGIC, dir_size, 0, 0)
    directory = b"".join(dirents)
    return zbi.pad(header + directory, zbi.ZBI_BOOTFS_PAGE_SIZE) + b"".join(data_blocks)


def test_dedup_roundtrip(zbi, diff):
    # Synthetic files with heavy, intentional duplication (mirrors the real
    # libc++.so.1 x18 / ld.so.1 x18 / libfdio.so x5 staging pattern): several
    # distinct dests share the same bytes; some contents are unique.
    libcxx = b"LIBCXX-payload-" + b"\xab" * 5000        # spans >1 page
    ldso = b"LDSO-payload-" + b"\x11" * 9000            # spans >2 pages
    fdio = b"FDIO-payload-" + b"\x7f" * 100
    unique_a = b"only-once-A"
    unique_b = b"only-once-B" * 3
    empty = b""                                          # 0-byte file edge case

    file_data = [
        ("lib/ld.so.1", ldso),
        ("lib/libc++.so.1", libcxx),
        ("lib/libfdio.so", fdio),
        ("driver/a/libc++.so.1", libcxx),      # dup of libc++
        ("driver/a/ld.so.1", ldso),            # dup of ld.so
        ("driver/b/libc++.so.1", libcxx),      # dup of libc++
        ("driver/b/libfdio.so", fdio),         # dup of fdio
        ("bin/unique_a", unique_a),
        ("bin/unique_b", unique_b),
        ("data/empty", empty),
        ("data/empty2", empty),                # dup of empty
    ]
    unique_contents = {ldso, libcxx, fdio, unique_a, unique_b, empty}
    expected = dict(file_data)  # dest -> content (all dests distinct)

    payload = zbi.build_bootfs(file_data)

    # -- Parse with BOTH parsers; they must agree. --
    parsed_zbi = dict(zbi.parse_bootfs(payload))
    parsed_diff = dict(diff.parse_bootfs(payload))
    assert parsed_zbi == parsed_diff, "simple_zbi and bootfs_diff parsers disagree"

    # -- Every dirent (including aliases) resolves to its exact bytes. --
    assert parsed_zbi == expected, (
        "round-trip mismatch:\n  got  %r\n  want %r" % (parsed_zbi, expected))

    # -- Dedup actually happened: each unique blob is stored exactly once. --
    # Recompute the directory to find the data section boundary + shared offsets.
    magic, dir_size, _, _ = struct.unpack_from("<IIII", payload, 0)
    assert magic == zbi.ZBI_BOOTFS_MAGIC
    base_offset = align(16 + dir_size, zbi.ZBI_BOOTFS_PAGE_SIZE)

    # Collect the (data_off, data_len) each dirent points at.
    offsets_by_content = {}
    off, end = 16, 16 + dir_size
    dirent_count = 0
    while off + 12 <= end:
        namelen, dlen, doff = struct.unpack_from("<III", payload, off)
        content = payload[doff:doff + dlen]
        offsets_by_content.setdefault(content, set()).add(doff)
        dirent_count += 1
        off += align(12 + namelen, 4)

    assert dirent_count == len(file_data), "lost/gained dirents"
    # Same content => single shared offset (true dedup, not coincidence).
    for content, offs in offsets_by_content.items():
        assert len(offs) == 1, (
            "content stored at multiple offsets (not deduped): %d copies" % len(offs))
    # Distinct contents => distinct offsets.
    all_offsets = {next(iter(v)) for v in offsets_by_content.values()}
    assert len(all_offsets) == len(offsets_by_content) == len(unique_contents), (
        "unique-content/offset count mismatch")

    # Data section is exactly base + sum of page-padded UNIQUE blocks.
    expected_data_bytes = sum(
        align(len(c), zbi.ZBI_BOOTFS_PAGE_SIZE) for c in unique_contents)
    assert len(payload) == base_offset + expected_data_bytes, (
        "payload size %d != base %d + unique padded blocks %d"
        % (len(payload), base_offset, expected_data_bytes))

    # And it is strictly smaller than the naive (no-dedup) layout would be.
    naive = reference_build_bootfs_no_dedup(zbi, file_data)
    assert len(payload) < len(naive), "dedup did not shrink a duplicated bootfs"

    print("PASS test_dedup_roundtrip: %d dirents, %d unique blocks, "
          "%d bytes (naive %d)"
          % (dirent_count, len(unique_contents), len(payload), len(naive)))


def test_golden_no_dups(zbi):
    # No two entries share content -> dedup must produce byte-identical output to
    # the pre-dedup algorithm (determinism AND old-byte-identity both hold here).
    file_data = [
        ("bin/one", b"content-one"),
        ("lib/two", b"content-two-" + b"\x02" * 8192),
        ("data/three", b"three" * 1000),
        ("z/four", b""),
    ]
    got = zbi.build_bootfs(file_data)
    golden = reference_build_bootfs_no_dedup(zbi, file_data)
    assert got == golden, (
        "no-dup dedup output is not byte-identical to the naive layout "
        "(len %d vs %d)" % (len(got), len(golden)))

    # Determinism: rebuilding yields identical bytes.
    assert zbi.build_bootfs(file_data) == got, "build_bootfs is non-deterministic"

    # Sanity: it still round-trips.
    assert dict(zbi.parse_bootfs(got)) == dict(file_data)
    print("PASS test_golden_no_dups: %d bytes, byte-identical to naive layout"
          % len(got))


def test_collision_guard(zbi, monkeypatchable=True):
    # A digest collision on differing content must raise, not corrupt silently.
    # Force a collision by stubbing hashlib.sha256 within the module to a constant
    # digest, then feed two DIFFERENT contents.
    import hashlib as _h

    class _ConstDigest:
        def __init__(self, *_a, **_k):
            pass

        def digest(self):
            return b"\x00" * 32

    orig = zbi.hashlib.sha256
    zbi.hashlib.sha256 = lambda *a, **k: _ConstDigest()
    try:
        raised = False
        try:
            zbi.build_bootfs([("a", b"alpha"), ("b", b"beta")])
        except ValueError:
            raised = True
        assert raised, "collision on differing content was not detected"
    finally:
        zbi.hashlib.sha256 = orig
    print("PASS test_collision_guard: digest collision on differing content raises")


def test_compressed_roundtrip(zbi, diff, zstd_tool):
    # storage_bootfs_item zstd-compresses the (deduped) build_bootfs
    # output at the zbi_item layer. Verify the compressed STORAGE_BOOTFS item is
    # well-formed (COMPRESSED flag, extra == uncompressed length, zstd frame) and
    # that bootfs_diff decompresses it back to the exact deduped {name: content}.
    payload = b"AAAA" * 4096 + b"BBBB" * 4096  # compressible, spans pages
    file_data = [
        ("lib/dup.so", payload),
        ("bin/dup2.so", payload),  # dedups to one block
        ("bin/uniq", b"unique-content-\x99" * 300),
    ]
    expected = dict(file_data)

    item = zbi.storage_bootfs_item(zbi.build_bootfs(file_data), zstd_tool)
    item_type, plen, extra, flags = struct.unpack_from("<IIII", item, 0)
    assert item_type == zbi.ZBI_TYPE_STORAGE_BOOTFS, "wrong item type"
    assert flags & zbi.ZBI_FLAGS_STORAGE_COMPRESSED, "COMPRESSED flag not set"
    uncompressed = zbi.build_bootfs(file_data)
    assert extra == len(uncompressed), (
        "extra (%d) != uncompressed length (%d)" % (extra, len(uncompressed)))
    frame = item[32:32 + plen]
    assert frame[:4] == b"\x28\xb5\x2f\xfd", "payload is not a zstd frame"
    assert plen < len(uncompressed), "compression did not shrink the payload"

    # bootfs_diff transparently decompresses the frame and parses it.
    diff.ZSTD_CLI = zstd_tool
    parsed = dict(diff.parse_bootfs(frame))
    assert parsed == expected, (
        "compressed round-trip mismatch:\n  got  %r\n  want %r" % (parsed, expected))
    print("PASS test_compressed_roundtrip: %d -> %d bytes, decompresses to %d entries"
          % (len(uncompressed), plen, len(parsed)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--simple-zbi", required=True)
    ap.add_argument("--bootfs-diff", required=True)
    ap.add_argument("--zstd-tool", default=None,
                    help="Host zstd CLI (//tools/zstd:zstd_cli); enables the "
                         "compressed STORAGE_BOOTFS round-trip test.")
    args = ap.parse_args()

    zbi = load_module("simple_zbi", args.simple_zbi)
    diff = load_module("bootfs_diff", args.bootfs_diff)

    test_dedup_roundtrip(zbi, diff)
    test_golden_no_dups(zbi)
    test_collision_guard(zbi)
    if args.zstd_tool:
        test_compressed_roundtrip(zbi, diff, args.zstd_tool)
    else:
        print("SKIP test_compressed_roundtrip: no --zstd-tool provided")
    print("ALL BOOTFS DEDUP TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
