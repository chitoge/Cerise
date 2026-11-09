#!/bin/sh
set -eu

checker="$1"
bad_log="$2"
markers="$3"
report="${TEST_TMPDIR}/bad.report.json"

if "$checker" --serial-log "$bad_log" --markers-json "$markers" --report "$report"; then
  echo "expected qemu_boot_test to reject the bad serial log" >&2
  exit 1
fi

echo "qemu_boot_test: negative fixture rejected as expected"
