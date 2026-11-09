#!/usr/bin/env python3
"""Validate a captured QEMU serial log against a JSON marker contract."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
from typing import Any, Dict, List, Optional


class ContractError(ValueError):
    """The marker contract is not valid for this runner."""


def _string_list(contract: Dict[str, Any], key: str) -> List[str]:
    value = contract.get(key)
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ContractError(f"{key} must be an array of strings")
    return [item for item in value if item]


def load_contract(path: Path) -> Dict[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read marker contract {path}: {error}") from error
    if not isinstance(raw, dict):
        raise ContractError("marker contract must be a JSON object")

    required = _string_list(raw, "required_markers")
    forbidden = _string_list(raw, "forbidden_markers")
    timeout = raw.get("timeout_seconds")
    non_empty = raw.get("non_empty_serial")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout < 0:
        raise ContractError("timeout_seconds must be a non-negative integer")
    if not isinstance(non_empty, bool):
        raise ContractError("non_empty_serial must be a boolean")
    return {
        "required_markers": required,
        "forbidden_markers": forbidden,
        "timeout_seconds": timeout,
        "non_empty_serial": non_empty,
    }


def evaluate(serial: bytes, contract: Dict[str, Any], timeout_expired: bool) -> Dict[str, Any]:
    matched = []  # type: List[str]
    missing = ""
    for marker in contract["required_markers"]:
        if marker.encode("utf-8") in serial:
            matched.append(marker)
        else:
            missing = marker
            break

    forbidden_hit = ""
    if not missing:
        folded_serial = serial.lower()
        for marker in contract["forbidden_markers"]:
            if marker.encode("utf-8").lower() in folded_serial:
                forbidden_hit = marker
                break

    if timeout_expired:
        reason = "timeout"
    elif contract["non_empty_serial"] and not serial:
        reason = "empty_serial"
    elif missing:
        reason = f"missing_marker:{missing}"
    elif forbidden_hit:
        reason = f"forbidden_marker:{forbidden_hit}"
    else:
        reason = "success"

    return {
        "exit_reason": reason,
        # Keep the historical comma-delimited report field while treating each
        # JSON array entry as one marker, including spaces and punctuation.
        "matched_markers": ",".join(matched),
        "missing_marker": missing,
        "forbidden_hit": forbidden_hit,
        "serial_bytes": len(serial),
    }


def write_report(path: Path, report: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, separators=(",", ":"))
        output.write("\n")


def _symbolize_failure(args: argparse.Namespace) -> None:
    if not args.symbolizer:
        return
    symbolizer = Path(args.symbolizer)
    if not symbolizer.is_file() or not symbolizer.stat().st_mode & 0o111:
        return

    command = [str(symbolizer)]
    if args.build_id_store:
        build_ids = Path(args.build_id_store) / ".build-id"
        if build_ids.is_dir():
            command.extend(["--build-id-dir", str(build_ids)])
    if args.llvm_symbolizer:
        llvm_symbolizer = Path(args.llvm_symbolizer)
        if llvm_symbolizer.is_file() and llvm_symbolizer.stat().st_mode & 0o111:
            command.extend(["--llvm-symbolizer", str(llvm_symbolizer)])
    command.append(args.serial_log)

    print("qemu_boot_test: symbolized serial log tail:", file=sys.stderr)
    try:
        result = subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            universal_newlines=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"symbolizer exited {result.returncode}")
        print("\n".join(result.stdout.splitlines()[-60:]), file=sys.stderr)
    except (OSError, RuntimeError) as error:
        print(f"qemu_boot_test: symbolizer unavailable or errored: {error}", file=sys.stderr)


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serial-log", required=True)
    parser.add_argument("--markers-json", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--image", default="")
    parser.add_argument("--symbolizer", default="")
    parser.add_argument("--build-id-store", default="")
    parser.add_argument("--llvm-symbolizer", default="")
    parser.add_argument("--timeout-expired", action="store_true")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    report_path = Path(args.report)
    serial_path = Path(args.serial_log)
    base_report = {  # type: Dict[str, Any]
        "serial_log": args.serial_log,
        "image": args.image,
    }

    if not serial_path.exists():
        write_report(report_path, {"exit_reason": "missing_serial", **base_report})
        print("qemu_boot_test: missing serial log", file=sys.stderr)
        return 1

    try:
        contract = load_contract(Path(args.markers_json))
    except ContractError as error:
        write_report(
            report_path,
            {"exit_reason": "invalid_contract", "error": str(error), **base_report},
        )
        print(f"qemu_boot_test: invalid contract: {error}", file=sys.stderr)
        return 1

    try:
        serial = serial_path.read_bytes()
    except OSError as error:
        write_report(
            report_path,
            {"exit_reason": "serial_read_error", "error": str(error), **base_report},
        )
        print(f"qemu_boot_test: cannot read serial log: {error}", file=sys.stderr)
        return 1

    result = evaluate(serial, contract, args.timeout_expired)
    report = {
        **result,
        **base_report,
        "timeout_seconds": contract["timeout_seconds"],
    }
    write_report(report_path, report)
    if result["exit_reason"] == "success":
        print("qemu_boot_test: success")
        return 0

    print(f"qemu_boot_test: {result['exit_reason']}", file=sys.stderr)
    _symbolize_failure(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
