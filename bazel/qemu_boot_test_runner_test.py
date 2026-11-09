#!/usr/bin/env python3

import json
from pathlib import Path
import tempfile
import unittest

import qemu_boot_test_runner as runner


class QemuBootTestRunnerTest(unittest.TestCase):
    def test_markers_with_spaces_and_punctuation_are_atomic(self):
        contract = {
            "required_markers": ["boot step one", "value=[a,b]"],
            "forbidden_markers": [],
            "timeout_seconds": 10,
            "non_empty_serial": True,
        }
        result = runner.evaluate(b"boot step one\nvalue=[a,b]\n", contract, False)
        self.assertEqual(result["exit_reason"], "success")
        self.assertEqual(result["matched_markers"], "boot step one,value=[a,b]")

    def test_forbidden_markers_remain_case_insensitive(self):
        contract = {
            "required_markers": ["ready"],
            "forbidden_markers": ["Kernel Panic"],
            "timeout_seconds": 10,
            "non_empty_serial": True,
        }
        result = runner.evaluate(b"ready\nKERNEL PANIC\n", contract, False)
        self.assertEqual(result["exit_reason"], "forbidden_marker:Kernel Panic")

    def test_contract_rejects_malformed_json_and_wrong_types(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "markers.json"
            path.write_text("{not json", encoding="utf-8")
            with self.assertRaises(runner.ContractError):
                runner.load_contract(path)
            path.write_text(
                json.dumps(
                    {
                        "required_markers": "not-a-list",
                        "forbidden_markers": [],
                        "timeout_seconds": True,
                        "non_empty_serial": True,
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaises(runner.ContractError):
                runner.load_contract(path)

    def test_report_escapes_paths_and_marker_text(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            serial = root / 'serial"quoted.log'
            markers = root / "markers.json"
            report = root / "report.json"
            serial.write_text('marker "quoted" with spaces\n', encoding="utf-8")
            markers.write_text(
                json.dumps(
                    {
                        "required_markers": ['marker "quoted" with spaces'],
                        "forbidden_markers": [],
                        "timeout_seconds": 3,
                        "non_empty_serial": True,
                    }
                ),
                encoding="utf-8",
            )
            status = runner.main(
                [
                    "--serial-log",
                    str(serial),
                    "--markers-json",
                    str(markers),
                    "--report",
                    str(report),
                    "--image",
                    'image"quoted',
                ]
            )
            self.assertEqual(status, 0)
            decoded = json.loads(report.read_text(encoding="utf-8"))
            self.assertEqual(decoded["image"], 'image"quoted')
            self.assertEqual(decoded["matched_markers"], 'marker "quoted" with spaces')

    def test_timeout_takes_precedence(self):
        contract = {
            "required_markers": ["missing"],
            "forbidden_markers": [],
            "timeout_seconds": 10,
            "non_empty_serial": True,
        }
        result = runner.evaluate(b"", contract, True)
        self.assertEqual(result["exit_reason"], "timeout")


if __name__ == "__main__":
    unittest.main()
