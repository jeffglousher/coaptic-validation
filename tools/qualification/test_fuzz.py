import unittest
import subprocess
import tempfile
import contextlib
import io
import json
import os
from pathlib import Path
from unittest.mock import patch
import fuzz
from fuzz import evidence, run_campaign


class FuzzEvidenceTests(unittest.TestCase):
    def test_feedback_and_executed_inputs_are_both_required(self):
        valid = "#100 DONE cov: 42 ft: 60\nstat::number_of_executed_units: 100\n"
        self.assertEqual(evidence(valid), {"coverage_points": 42, "features": 60, "executed_inputs": 100})
        for output in ["", "Done 100 runs", "cov: 42 ft: 60", "stat::number_of_executed_units: 100",
                       valid.replace("cov: 42", "cov: 0"), valid.replace("ft: 60", "ft: 0"),
                       valid.replace("units: 100", "units: 0")]:
            with self.assertRaises(ValueError):
                evidence(output)

    def test_success_requires_feedback_and_zero_exit_and_timeout_refuses(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            def execute(command, **kwargs):
                kwargs["stderr"].write(b"cov: 42 ft: 60\nstat::number_of_executed_units: 100\n")
                self.assertEqual(kwargs["timeout"], 901)
                return subprocess.CompletedProcess(command, self.code)
            self.code = 0
            self.assertTrue(run_campaign(["fuzzer"], 1, directory, execute)["passed"])
            self.code = 77
            self.assertFalse(run_campaign(["fuzzer"], 1, directory, execute)["passed"])
            def timeout(command, **kwargs):
                raise subprocess.TimeoutExpired(command, kwargs["timeout"])
            self.assertFalse(run_campaign(["fuzzer"], 1, directory, timeout)["passed"])


class FuzzSourceTests(unittest.TestCase):
    def test_default_source_policy_remains_clean(self):
        clean = dict(dirty=False, suite_dirty=False)
        with patch.object(fuzz, "snapshot", return_value=clean):
            self.assertEqual(fuzz.checked_snapshot(), clean)
        for identity in (dict(dirty=True, suite_dirty=False), dict(dirty=False, suite_dirty=True)):
            with patch.object(fuzz, "snapshot", return_value=identity):
                with self.assertRaisesRegex(ValueError, "clean library and suite"):
                    fuzz.checked_snapshot()

    def test_prepared_source_requires_both_immutable_identities(self):
        with self.assertRaisesRegex(ValueError, "both immutable"):
            fuzz.checked_snapshot(Path("receipt.json"), "a" * 40)
        with self.assertRaisesRegex(ValueError, "requires --prepared-source"):
            fuzz.checked_snapshot(None, "a" * 40, "b" * 40)

    def test_prepared_source_uses_independent_gate_before_snapshot(self):
        identity = dict(dirty=False, suite_dirty=True)
        receipt = Path("receipt.json")
        with patch("macro_lock_selection.verify_prepared") as gate, patch.object(
                fuzz, "snapshot", return_value=identity) as snapshot:
            self.assertEqual(fuzz.checked_snapshot(receipt, "a" * 40, "b" * 40), identity)
            gate.assert_called_once_with(fuzz.ROOT, fuzz.ROOT / "coaptic", "a" * 40, "b" * 40, receipt)
            gate.side_effect = ValueError("foreign tracked edit")
            with self.assertRaisesRegex(ValueError, "foreign tracked edit"):
                fuzz.checked_snapshot(receipt, "a" * 40, "b" * 40)
            self.assertEqual(snapshot.call_count, 1)

    def test_foreign_prepared_source_refuses_before_outputs_or_children(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name) / "new" / "fuzz.json"
            with patch("macro_lock_selection.verify_prepared", side_effect=ValueError("foreign source")), \
                    patch.object(fuzz.subprocess, "run") as child, \
                    patch.object(fuzz.tempfile, "mkdtemp") as work:
                with self.assertRaisesRegex(ValueError, "foreign source"):
                    fuzz.main(["--output", str(output), "--prepared-source", str(Path(name) / "receipt.json"),
                               "--expected-revision", "a" * 40, "--expected-suite-revision", "b" * 40])
                child.assert_not_called()
                work.assert_not_called()
                self.assertFalse(output.parent.exists())

    def test_campaign_source_failure_retains_prefix_and_stops_later_targets(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            output = root / "fuzz.json"
            identity = dict(dirty=False, suite_dirty=True, source="a" * 40, suite_source="b" * 40)
            previous = Path.cwd()
            try:
                with patch.object(fuzz, "ROOT", root), \
                        patch.object(fuzz, "checked_snapshot", side_effect=[identity, identity, AttributeError("malformed receipt")]), \
                        patch.object(fuzz.subprocess, "run") as child, \
                        patch.object(fuzz.subprocess, "check_output", return_value="mock compiler"), \
                        patch.object(fuzz, "run_campaign", return_value=dict(passed=True)) as campaign, \
                        contextlib.redirect_stdout(io.StringIO()):
                    result = fuzz.main(["--output", str(output), "--seconds", "1"])
                self.assertEqual(result, 1)
                child.assert_called_once()
                self.assertIn("--locked", child.call_args.args[0])
                campaign.assert_called_once()
                report = json.loads(output.read_text())
                self.assertFalse(report["passed"])
                self.assertEqual(len(report["campaigns"]), 1)
                self.assertIn("AttributeError: malformed receipt", report["campaigns"][0]["error"])
                self.assertEqual(report["not_run"], ["cbor", "oscore"])
            finally:
                os.chdir(previous)

    def test_source_refusal_does_not_replace_campaign_error(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            output = root / "fuzz.json"
            identity = dict(dirty=False, suite_dirty=True)
            previous = Path.cwd()
            try:
                with patch.object(fuzz, "ROOT", root), \
                        patch.object(fuzz, "checked_snapshot", side_effect=[identity, identity, ValueError("foreign edit")]), \
                        patch.object(fuzz.subprocess, "run"), \
                        patch.object(fuzz.subprocess, "check_output", return_value="mock compiler"), \
                        patch.object(fuzz, "run_campaign", return_value=dict(passed=False, error="original timeout")), \
                        contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(fuzz.main(["--output", str(output), "--seconds", "1"]), 1)
                row = json.loads(output.read_text())["campaigns"][0]
                self.assertEqual(row["error"], "original timeout")
                self.assertIn("ValueError: foreign edit", row["source_error"])
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
