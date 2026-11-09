#!/usr/bin/env bash
set -euo pipefail

RUNFILES="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$RUNFILES" ]]; then
    echo "ERROR: neither RUNFILES_DIR nor TEST_SRCDIR is set" >&2
    exit 1
fi

SCRIPT=""
for candidate in \
    "$RUNFILES/cerise/build/checks/flag_manifest_golden_test.py" \
    "$RUNFILES/_main/build/checks/flag_manifest_golden_test.py"; do
    if [[ -f "$candidate" ]]; then
        SCRIPT="$candidate"
        break
    fi
done

if [[ -z "$SCRIPT" ]]; then
    echo "ERROR: could not find flag_manifest_golden_test.py in runfiles ($RUNFILES)" >&2
    ls "$RUNFILES" 2>/dev/null || true
    exit 1
fi

exec python3 "$SCRIPT" "$@"
