#!/usr/bin/env bash
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
  echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
  exit 1
fi

for workspace in cerise _main; do
  TEST_SCRIPT="$RUNFILES/$workspace/bazel/qemu_boot_test_runner_test.py"
  RUNNER_DIR="$RUNFILES/$workspace/bazel"
  if [[ -f "$TEST_SCRIPT" ]]; then
    exec env PYTHONPATH="$RUNNER_DIR${PYTHONPATH:+:$PYTHONPATH}" python3 "$TEST_SCRIPT"
  fi
done

echo "ERROR: qemu boot runner tests not found in runfiles" >&2
exit 1
