#!/usr/bin/env python3
"""Checks root-realm package metadata against the CML child URLs."""

import ast
import pathlib
import re
import sys


def _mappings(path):
    tree = ast.parse(path.read_text())
    mappings = {}
    names = {
        "ROOT_REALM_BOOT_PACKAGES",
        "ROOT_REALM_RESOLVER_PACKAGES",
    }
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        matching = [
            target.id
            for target in node.targets
            if isinstance(target, ast.Name) and target.id in names
        ]
        if matching:
            mappings[matching[0]] = ast.literal_eval(node.value)
    if "ROOT_REALM_BOOT_PACKAGES" not in mappings:
        raise AssertionError("ROOT_REALM_BOOT_PACKAGES assignment missing")
    mappings.setdefault("ROOT_REALM_RESOLVER_PACKAGES", {})
    return mappings


def _packages(path, seen=None):
    # CML comments often mention package URLs; only declarations count. Inline
    # comments start after whitespace, so this cannot consume fuchsia:/// URLs.
    seen = set() if seen is None else seen
    if path in seen:
        return [], []
    seen.add(path)
    text = re.sub(r"(?m)^\s*//[^\n]*$|\s+//[^\n]*$", "", path.read_text())
    boot = re.findall(r"fuchsia-boot:///([^/#]+)#", text)
    resolver = re.findall(r"fuchsia-pkg://[^/]+/([^/#]+)#", text)
    for include_block in re.findall(r"include\s*:\s*\[(.*?)\]", text, re.S):
        for include in re.findall(r'"([^"]+\.cml)"', include_block):
            included_boot, included_resolver = _packages(path.parent / include, seen)
            boot.extend(included_boot)
            resolver.extend(included_resolver)
    return sorted(set(boot)), sorted(set(resolver))


def main(argv):
    if len(argv) < 3:
        raise AssertionError("usage: root_realm_packages_test.py MAP ROOT_CML...")
    mapping_path = pathlib.Path(argv[1])
    manifests = [pathlib.Path(p) for p in argv[2:]]
    declared = _mappings(mapping_path)
    boot_declared = declared["ROOT_REALM_BOOT_PACKAGES"]
    resolver_declared = declared["ROOT_REALM_RESOLVER_PACKAGES"]
    actual_names = {p.stem for p in manifests}
    if set(boot_declared) != actual_names:
        raise AssertionError(
            "root metadata keys differ from supplied manifests: "
            f"missing={sorted(actual_names - set(boot_declared))} "
            f"extra={sorted(set(boot_declared) - actual_names)}")
    extra_resolver_roots = set(resolver_declared) - actual_names
    if extra_resolver_roots:
        raise AssertionError(
            "resolver metadata names missing root manifests: "
            f"{sorted(extra_resolver_roots)}")
    for manifest in manifests:
        actual_boot, actual_resolver = _packages(manifest)
        expected_boot = sorted(boot_declared[manifest.stem])
        expected_resolver = sorted(resolver_declared.get(manifest.stem, []))
        if actual_boot != expected_boot or actual_resolver != expected_resolver:
            raise AssertionError(
                f"{manifest}: metadata boot={expected_boot!r}, resolver={expected_resolver!r} "
                f"!= child URLs boot={actual_boot!r}, resolver={actual_resolver!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
