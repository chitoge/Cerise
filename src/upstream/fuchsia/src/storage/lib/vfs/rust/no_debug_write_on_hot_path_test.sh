#!/usr/bin/env bash
# A synchronous zx_debug_write on every VFS operation can flood the serial/debuglog
# and starve driver and network-device bring-up, producing a silent boot hang.
#
# This test is a static (source-text) guard, not a runtime one: this crate's own
# BUILD.bazel documents that vfs's real unit tests can't run as a host test (zx does
# not compile off-Fuchsia; see the "tests excluded (host)" comment below in this
# package's BUILD.bazel), so a runtime regression test would need an on-target
# (zircon-test) or full host-boot-to-serving harness that doesn't exist yet. This
# static check fails if a direct zx_debug_write call appears under the crate's source
# tree.
#
# If you have a genuine need for early/pre-logging serial output (e.g. a true one-time
# boot marker before the structured log subsystem is up, as fshost/fxfs_bin/fxfs-crypt
# main() do), that's legitimate and does NOT belong in this crate - vfs is a per-request
# library invoked on every VFS operation, so anything synchronous here runs on the hot
# path by construction. Route diagnostics through the structured log/inspect facilities
# instead.
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
    echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
    exit 1
fi

PKG="$RUNFILES/_main/src/upstream/fuchsia/src/storage/lib/vfs/rust"

if [[ ! -d "$PKG/src" ]]; then
    echo "ERROR: could not find vfs/rust package sources in runfiles ($RUNFILES)" >&2
    ls "$RUNFILES" 2>/dev/null || true
    exit 1
fi

if hits=$(grep -rn "zx_debug_write" "$PKG/src" 2>/dev/null); then
    echo "FAIL: found a direct zx_debug_write call under vfs/rust/src:" >&2
    echo "$hits" >&2
    echo >&2
    echo "A synchronous per-VFS-op debug write floods the serial line and starves" >&2
    echo "host driver/network bring-up. Remove it, or route" >&2
    echo "the diagnostic through the structured log/inspect facilities instead." >&2
    exit 1
fi

echo "OK: no per-op debug-write instrumentation found under vfs/rust/src."
