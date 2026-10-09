"""A failed counterpart must never qualify a performance comparison."""

import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import repeat


class Eligibility(unittest.TestCase):
    def test_retains_failed_baseline_and_disqualifies_its_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            baseline, candidate, output = root / "baseline", root / "candidate", root / "report.json"
            baseline.write_bytes(b"baseline")
            candidate.write_bytes(b"candidate")

            def invoke(command, **kwargs):
                size = int(command[1])
                if Path(command[0]) == baseline and size == 64:
                    raise subprocess.CalledProcessError(1, command, stderr="deliberate failure")
                rows = [
                    {"schema": "coaptic-security-work/1", "phase": phase,
                     "body_bytes": size, "operations": 1, "latencies_ns": [100]}
                    for phase in repeat.PHASES
                ]
                return subprocess.CompletedProcess(command, 0, "\n".join(map(json.dumps, rows)), "")

            argv = ["repeat", "--baseline", str(baseline), "--candidate", str(candidate),
                    "--runs", "1", "--operations", "1", "--output", str(output)]
            with patch.object(sys, "argv", argv), patch.object(repeat.subprocess, "run", invoke), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(repeat.main(), 1)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(len(report["cells"]), 4)
            failures = [cell for cell in report["cells"] if "error" in cell]
            self.assertEqual(len(failures), 1)
            self.assertIn("deliberate failure", failures[0]["stderr"])
            for row in report["summary"]:
                self.assertEqual(row["comparison_eligible"], row["body_bytes"] == 1024)


if __name__ == "__main__":
    unittest.main()
