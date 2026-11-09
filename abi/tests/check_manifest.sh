#!/bin/bash

set -euo pipefail

manifest="$1"
fidlc_response="$2"
library_manifest="$3"
staged_fidl_dir="$4"
staged_header_dir="$5"

/usr/bin/python3 - "$manifest" "$fidlc_response" "$library_manifest" "$staged_fidl_dir" "$staged_header_dir" <<'PY'
import json
import os
from pathlib import Path
import sys

manifest_path = Path(sys.argv[1])
response_path = Path(sys.argv[2])
library_manifest_path = Path(sys.argv[3])
staged_fidl_dir = Path(sys.argv[4])
staged_header_dir = Path(sys.argv[5])

with manifest_path.open(encoding="utf-8") as fh:
    manifest = json.load(fh)
with library_manifest_path.open(encoding="utf-8") as fh:
    library_manifest = json.load(fh)

assert manifest["schema_version"] == 2, manifest
assert manifest["status"] == "fidlc-ready-inputs", manifest
assert manifest["main_library"] == "zx", manifest
assert manifest["library_count"] == 1, manifest
assert manifest["vdso_fidl_count"] == 51, manifest
assert manifest["public_header_count"] > 0, manifest
assert len(manifest["fidl_libraries"]) == manifest["library_count"], manifest
assert len(manifest["public_headers"]) == manifest["public_header_count"], manifest
assert manifest["fidl_response_file"].endswith(".fidlc.rsp"), manifest
assert manifest["staged_fidl_dir"], manifest
assert manifest["staged_header_dir"], manifest

fidl_library = manifest["fidl_libraries"][0]
assert fidl_library["name"] == "zx", fidl_library
assert fidl_library["imports"] == [], fidl_library
assert fidl_library["source_count"] == manifest["vdso_fidl_count"], fidl_library
assert fidl_library["sources"] == sorted(fidl_library["sources"], key=lambda item: item["staged_path"]), fidl_library

assert library_manifest["schema_version"] == 1, library_manifest
assert library_manifest["main_library"] == manifest["main_library"], library_manifest
assert library_manifest["libraries"] == [
    {
        "imports": fidl_library["imports"],
        "name": fidl_library["name"],
        "source_count": fidl_library["source_count"],
        "sources": [entry["staged_path"] for entry in fidl_library["sources"]],
    }
], library_manifest

response_lines = [line.strip() for line in response_path.read_text(encoding="utf-8").splitlines() if line.strip()]
expected_response = ["--name", "zx", "--files"] + [entry["staged_path"] for entry in fidl_library["sources"]]
assert response_lines == expected_response, response_lines

staged_fidl_files = []
for root, _, files in os.walk(staged_fidl_dir):
    for file_name in files:
        staged_fidl_files.append(Path(root, file_name).relative_to(staged_fidl_dir).as_posix())
staged_header_files = []
for root, _, files in os.walk(staged_header_dir):
    for file_name in files:
        staged_header_files.append(Path(root, file_name).relative_to(staged_header_dir).as_posix())

staged_fidl_files.sort()
staged_header_files.sort()

assert staged_fidl_files == [entry["staged_path"] for entry in fidl_library["sources"]], staged_fidl_files
assert staged_header_files == [entry["staged_path"] for entry in manifest["public_headers"]], staged_header_files
assert "zircon/vdso/zx_common.fidl" in staged_fidl_files, staged_fidl_files
assert any(path.startswith("zircon/") for path in staged_header_files), staged_header_files
PY
