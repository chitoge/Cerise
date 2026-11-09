#!/usr/bin/env bash
set -euo pipefail

for manifest in "$@"; do
    if ! grep -Fq 'include: ["root_driver_base.shard.cml"]' "$manifest"; then
        echo "missing root driver base include: $manifest" >&2
        exit 1
    fi
done
