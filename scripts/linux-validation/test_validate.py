#!/usr/bin/env python3
"""Unprivileged regression tests for the validation harness, not the sensor."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("validate", Path(__file__).with_name("validate.py"))
validate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate)


class ReadbackTests(unittest.TestCase):
    def run_readback(self, indexed_marker=True, index_failure=False):
        target = {"id": "test-event", "source": "LinuxAudit",
                  "data": {"record": {"records": []}}}
        calls = []

        def cli(binary, reports, name, *arguments):
            calls.append((name, arguments))
            stdout, stderr = "", ""
            if name == "index-build" and index_failure:
                raise RuntimeError("index-build failed")
            if name.startswith(("query-", "pid-query-")):
                stdout = json.dumps(target) + "\n"
                stderr = "1 event(s) matched"
                if name.endswith("True") and indexed_marker:
                    stderr += " (indexed)"
            elif name.startswith("explain-"):
                stdout = json.dumps({"target_event": target})
            elif name == "analysis-json":
                stdout = json.dumps({"malformed_lines": 0, "findings": [],
                                     "limitations": ["linux_detection_rules_not_implemented"]})
            return subprocess.CompletedProcess(arguments, 0, stdout, stderr)

        self.calls = calls
        with tempfile.TemporaryDirectory() as directory, patch.object(validate, "run_cli", cli):
            data = Path(directory)
            return validate.check_readback(Path("sensor"), data, data, [target],
                                           [{"pid": 42}], [target])

    def test_builds_index_before_indexed_read(self):
        self.assertEqual(self.run_readback(), 1)
        names = [name for name, _ in self.calls]
        self.assertEqual(names[:3], ["query-False", "index-build", "query-True"])
        arguments = dict(self.calls)
        self.assertEqual(arguments["index-build"][0], "index")
        self.assertIn("--no-index", arguments["query-False"])
        self.assertNotIn("--no-index", arguments["query-True"])
        self.assertIn("index-status", names)

    def test_silent_scan_fallback_remains_a_failure(self):
        with self.assertRaisesRegex(RuntimeError, "silently fell back"):
            self.run_readback(indexed_marker=False)

    def test_index_build_failure_stops_validation(self):
        with self.assertRaisesRegex(RuntimeError, "index-build failed"):
            self.run_readback(index_failure=True)
        self.assertNotIn("query-True", [name for name, _ in self.calls])


if __name__ == "__main__":
    unittest.main()
