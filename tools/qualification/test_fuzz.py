import unittest
import subprocess
import tempfile
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
