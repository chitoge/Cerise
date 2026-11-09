#!/usr/bin/env bash
set -euo pipefail

runfiles="${RUNFILES_DIR:-${TEST_SRCDIR:-}}"
if [[ -z "$runfiles" ]]; then
    echo "ota-signer-verify-test: runfiles directory is unavailable" >&2
    exit 1
fi

test_script=""
signer=""
for workspace in cerise _main; do
    candidate="$runfiles/$workspace/src/cerise/ota_updater/ota_signer_verify_test.py"
    if [[ -f "$candidate" ]]; then
        test_script="$candidate"
    fi
    candidate="$runfiles/$workspace/src/cerise/ota_updater/ota_signer"
    if [[ -x "$candidate" ]]; then
        signer="$candidate"
    fi
done

if [[ -z "$test_script" || -z "$signer" ]]; then
    echo "ota-signer-verify-test: test script or signer is absent from runfiles" >&2
    exit 1
fi

exec python3 "$test_script" "$signer"
