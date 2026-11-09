#!/usr/bin/env bash
# `bazel run //validation:<product>-debug` — boot a product
# under QEMU HELD FOR GDB ATTACH on the direct-kernel path, instead of asserting
# boot markers. Thin wrapper over validation/run-qemu.sh with CERISE_GDB=1.
#
# run-qemu.sh is a run-from-repo script (it invokes `bazel build` itself and
# reads bazel-bin), so re-enter the workspace root that `bazel run` exports.
set -euo pipefail

WS="${BUILD_WORKSPACE_DIRECTORY:-}"
if [[ -z "$WS" ]]; then
  # Fall back to the source tree relative to this script (direct ./ invocation).
  WS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fi
cd "$WS"

PRODUCT="${1:?usage: debug_boot.sh <product> [extra run-qemu.sh args]}"
shift || true

export CERISE_GDB=1
# If a symbolize tool + store were built, surface a symbolized tail on failure.
: "${CERISE_SYMBOLIZER:=}"
: "${CERISE_BUILD_ID_DIR:=}"

echo "debug-boot: booting ${PRODUCT} held for gdb attach (CERISE_GDB=1)"
echo "debug-boot: set CERISE_GDB_HALT=1 to freeze at reset; CERISE_GDB_TCG=1 for TCG."
exec validation/run-qemu.sh "$PRODUCT" --gdb "$@"
