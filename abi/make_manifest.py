#!/usr/bin/env python3

import argparse
import hashlib
import heapq
import json
from pathlib import Path
import re
import shutil
from typing import Dict, List, Optional, Tuple


FUCHSIA_ROOT = Path("")
PUBLIC_HEADER_ROOTS = (
    FUCHSIA_ROOT / "zircon/public",
    FUCHSIA_ROOT / "zircon/system/public",
)
LIBRARY_PATTERN = re.compile(r"^\s*library\s+([A-Za-z0-9_.]+)\s*;", re.MULTILINE)
USING_PATTERN = re.compile(r"^\s*using\s+([A-Za-z0-9_.]+)(?:\s+as\s+[A-Za-z0-9_]+)?\s*;", re.MULTILINE)


def to_entry(path_str: str, staged_path: str) -> dict:
    path = Path(path_str)
    data = path.read_bytes()
    return {
        "source_path": path_str,
        "staged_path": staged_path,
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def unique_sorted(paths: List[str]) -> List[str]:
    return sorted(set(paths))


def relative_to(path: Path, root: Path) -> Optional[Path]:
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def stage_copy(source_path: str, output_root: Path, staged_relative_path: Path) -> None:
    destination = output_root / staged_relative_path
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source_path, destination)


def staged_fidl_path(path: Path) -> Path:
    # After Cerise collapse: FIDL sources live at repo root; staged path == source path.
    return path


def staged_header_path(path: Path) -> Path:
    for root in PUBLIC_HEADER_ROOTS:
        staged_path = relative_to(path, root)
        if staged_path is not None:
            return staged_path
    raise ValueError(f"Public header is not rooted under a supported public include root: {path}")


def parse_fidl_file(path: Path) -> Tuple[str, List[str]]:
    text = path.read_text(encoding="utf-8")
    libraries = sorted(set(LIBRARY_PATTERN.findall(text)))
    if len(libraries) != 1:
        raise ValueError(f"Expected exactly one library declaration in {path}, found {libraries}")
    library = libraries[0]
    imports = sorted(set(USING_PATTERN.findall(text)) - {library})
    return library, imports


def library_order(libraries: Dict[str, dict], main_library: str) -> List[str]:
    if main_library not in libraries:
        raise ValueError(f"Main library {main_library!r} was not found in the staged FIDL sources")

    known_libraries = set(libraries)
    indegree = {name: 0 for name in libraries}
    reverse_edges = {name: [] for name in libraries}

    for name, data in libraries.items():
        internal_imports = sorted(known_libraries.intersection(data["imports"]))
        data["internal_imports"] = internal_imports
        indegree[name] = len(internal_imports)
        for imported in internal_imports:
            reverse_edges[imported].append(name)

    ready = [name for name, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered = []

    while ready:
        name = heapq.heappop(ready)
        ordered.append(name)
        for dependent in sorted(reverse_edges[name]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)

    if len(ordered) != len(libraries):
        raise ValueError("Cyclic dependency detected while ordering ABI FIDL libraries")
    if ordered[-1] != main_library:
        raise ValueError(
            f"Expected main library {main_library!r} to be final in dependency order, got {ordered}"
        )
    return ordered


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--fidl-list", required=True)
    parser.add_argument("--header-list", required=True)
    parser.add_argument("--fidlc-response", required=True)
    parser.add_argument("--library-manifest", required=True)
    parser.add_argument("--staged-fidl-dir", required=True)
    parser.add_argument("--staged-header-dir", required=True)
    parser.add_argument("--main-library", required=True)
    parser.add_argument("--fidl", action="append", default=[])
    parser.add_argument("--header", action="append", default=[])
    args = parser.parse_args()

    staged_fidl_root = Path(args.staged_fidl_dir)
    staged_header_root = Path(args.staged_header_dir)
    staged_fidl_root.mkdir(parents=True, exist_ok=True)
    staged_header_root.mkdir(parents=True, exist_ok=True)

    fidl_libraries = {}
    seen_fidl_paths = set()
    for path_str in unique_sorted(args.fidl):
        source_path = Path(path_str)
        library_name, imports = parse_fidl_file(source_path)
        staged_path = staged_fidl_path(source_path)
        staged_path_str = staged_path.as_posix()
        if staged_path_str in seen_fidl_paths:
            raise ValueError(f"Duplicate staged FIDL path detected: {staged_path_str}")
        seen_fidl_paths.add(staged_path_str)
        stage_copy(path_str, staged_fidl_root, staged_path)

        library = fidl_libraries.setdefault(
            library_name,
            {
                "imports": set(),
                "sources": [],
            },
        )
        library["imports"].update(imports)
        library["sources"].append(to_entry(path_str, staged_path_str))

    ordered_libraries = library_order(fidl_libraries, args.main_library)
    ordered_fidl_entries = []
    manifest_libraries = []
    response_lines = ["--name", args.main_library]

    for library_name in ordered_libraries:
        library = fidl_libraries[library_name]
        library["sources"].sort(key=lambda entry: entry["staged_path"])
        ordered_fidl_entries.extend(library["sources"])
        response_lines.append("--files")
        response_lines.extend(entry["staged_path"] for entry in library["sources"])
        manifest_libraries.append(
            {
                "imports": sorted(library["imports"]),
                "name": library_name,
                "source_count": len(library["sources"]),
                "sources": library["sources"],
            }
        )

    seen_header_paths = set()
    header_entries = []
    for path_str in unique_sorted(args.header):
        source_path = Path(path_str)
        staged_path = staged_header_path(source_path)
        staged_path_str = staged_path.as_posix()
        if staged_path_str in seen_header_paths:
            raise ValueError(f"Duplicate staged public header path detected: {staged_path_str}")
        seen_header_paths.add(staged_path_str)
        stage_copy(path_str, staged_header_root, staged_path)
        header_entries.append(to_entry(path_str, staged_path_str))

    header_entries.sort(key=lambda entry: entry["staged_path"])

    Path(args.fidl_list).write_text(
        "".join(entry["staged_path"] + "\n" for entry in ordered_fidl_entries),
        encoding="utf-8",
    )
    Path(args.header_list).write_text(
        "".join(entry["staged_path"] + "\n" for entry in header_entries),
        encoding="utf-8",
    )
    Path(args.fidlc_response).write_text("\n".join(response_lines) + "\n", encoding="utf-8")

    library_manifest = {
        "schema_version": 1,
        "main_library": args.main_library,
        "libraries": [
            {
                "imports": library["imports"],
                "name": library["name"],
                "source_count": library["source_count"],
                "sources": [entry["staged_path"] for entry in library["sources"]],
            }
            for library in manifest_libraries
        ],
    }

    manifest = {
        "schema_version": 2,
        "status": "fidlc-ready-inputs",
        "main_library": args.main_library,
        "library_count": len(manifest_libraries),
        "vdso_fidl_count": len(ordered_fidl_entries),
        "public_header_count": len(header_entries),
        "fidl_response_file": Path(args.fidlc_response).name,
        "staged_fidl_dir": staged_fidl_root.name,
        "staged_header_dir": staged_header_root.name,
        "fidl_libraries": manifest_libraries,
        "public_headers": header_entries,
    }

    Path(args.library_manifest).write_text(
        json.dumps(library_manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path(args.manifest).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
