"""Fail-closed host qualification accounting and retained failure evidence."""
import subprocess
import json
import tempfile
from pathlib import Path
import unittest
from host import CASES, run_case, run_matrix, binary_identity


class HostEvidenceTests(unittest.TestCase):
    def test_records_executed_and_ignored_counts(self):
        def execute(command, **kwargs):
            self.assertEqual(command[:5], ["cargo", "+1.97.1", "test", "--locked", "-p"])
            self.assertEqual(kwargs["timeout"], 900)
            return subprocess.CompletedProcess(command, 0,
                "test result: ok. 9 passed; 0 failed; 2 ignored;\ntest result: ok. 3 passed; 0 failed; 0 ignored;", "")
        result = run_case("core", ["--no-default-features"], execute)
        self.assertTrue(result["passed"])
        self.assertEqual((result["executed"], result["ignored"]), (12, 2))

    def test_zero_or_missing_tests_cannot_pass(self):
        for output in ("", "test result: ok. 0 passed; 0 failed; 8 ignored;"):
            result = run_case("core", [], lambda command, **kwargs: subprocess.CompletedProcess(command, 0, output, ""))
            self.assertFalse(result["passed"])

    def test_partial_success_does_not_hide_failure(self):
        for code, suffix in ((1, ""), (0, "test result: FAILED")):
            result = run_case("core", [], lambda command, **kwargs: subprocess.CompletedProcess(command, code,
                "test result: ok. 9 passed; 0 failed; 0 ignored;" + suffix, "retained diagnostic"))
            self.assertFalse(result["passed"])
            self.assertEqual(result["stderr"], "retained diagnostic")

    def test_timeout_retains_partial_output_and_continues_matrix(self):
        calls = []
        def execute(command, **kwargs):
            calls.append(command)
            if len(calls) == 2:
                raise subprocess.TimeoutExpired(command, 900, output=b"partial output", stderr=b"timeout diagnostic")
            return subprocess.CompletedProcess(command, 0, "test result: ok. 1 passed; 0 failed; 0 ignored;", "")
        results = run_matrix(execute)
        self.assertEqual(len(calls), len(CASES))
        self.assertFalse(results[1]["passed"])
        self.assertTrue(results[1]["timed_out"])
        self.assertEqual(results[1]["stdout"], "partial output")
        self.assertEqual(results[1]["stderr"], "timeout diagnostic")
        self.assertEqual(sum(result["passed"] for result in results), len(CASES) - 1)

    def test_missing_executable_is_a_recorded_failure(self):
        def execute(*args, **kwargs):
            raise FileNotFoundError("compiler unavailable")
        result = run_case("core", [], execute)
        self.assertFalse(result["passed"])
        self.assertIn("compiler unavailable", result["stderr"])


class TargetEvidenceTests(unittest.TestCase):
    @staticmethod
    def pe(bits=32):
        data = bytearray(128)
        data[:2] = b"MZ"
        data[60:64] = (64).to_bytes(4, "little")
        data[64:68] = b"PE\0\0"
        data[68:70] = (0x14c if bits == 32 else 0x8664).to_bytes(2, "little")
        data[88:90] = (0x10b if bits == 32 else 0x20b).to_bytes(2, "little")
        return bytes(data)

    def test_headers_distinguish_image_architecture_and_reject_malformed(self):
        self.assertEqual(binary_identity(self.pe()), ("pe", 32, 0x14c, "little"))
        self.assertEqual(binary_identity(self.pe(64)), ("pe", 64, 0x8664, "little"))
        elf = bytearray(64)
        elf[:6] = b"\x7fELF\x01\x01"
        elf[18:20] = (3).to_bytes(2, "little")
        self.assertEqual(binary_identity(elf), ("elf", 32, 3, "little"))
        for malformed in (b"", b"MZ", self.pe()[:80], b"MZ" + b"\xff" * 126):
            with self.assertRaises(ValueError):
                binary_identity(malformed)

    def test_target_requires_executed_tests_and_matching_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "test.exe"
            def execute(command, **kwargs):
                self.assertIn("i686-pc-windows-msvc", command)
                self.assertIn("--message-format=json", command)
                output = json.dumps({"reason": "compiler-artifact", "profile": {"test": True}, "executable": str(path)})
                return subprocess.CompletedProcess(command, 0, output + "\ntest result: ok. 9 passed; 0 failed; 0 ignored;", "")
            path.write_bytes(self.pe())
            result = run_case("core", [], execute, target="i686-pc-windows-msvc")
            self.assertTrue(result["passed"])
            self.assertEqual(result["executables"][0]["bits"], 32)
            path.write_bytes(self.pe(64))
            result = run_case("core", [], execute, target="i686-pc-windows-msvc")
            self.assertFalse(result["passed"])
            self.assertIn("wrong executable architecture", result["executable_error"])
        missing = run_case("core", [], lambda command, **kwargs: subprocess.CompletedProcess(command, 0, "test result: ok. 1 passed; 0 failed; 0 ignored;", ""), target="i686-pc-windows-msvc")
        self.assertFalse(missing["passed"])
        self.assertIn("no compiled test executables", missing["executable_error"])

    def test_big_endian_target_requires_runner_and_matching_byte_order(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "test-elf"
            data = bytearray(64)
            data[:6] = b"\x7fELF\x02\x02"
            data[18:20] = (22).to_bytes(2, "big")
            path.write_bytes(data)
            def execute(command, **kwargs):
                self.assertIn("--lib", command)
                self.assertIn("--tests", command)
                self.assertIn("--test-threads=1", command)
                self.assertEqual(kwargs["env"]["CARGO_TARGET_S390X_UNKNOWN_LINUX_GNU_RUNNER"], "qemu-s390x -L /usr/s390x-linux-gnu")
                output = json.dumps({"reason": "compiler-artifact", "profile": {"test": True}, "executable": str(path)})
                return subprocess.CompletedProcess(command, 0, output + "\ntest result: ok. 9 passed; 0 failed; 0 ignored;", "")
            result = run_case("core", [], execute, target="s390x-unknown-linux-gnu")
            self.assertTrue(result["passed"])
            self.assertEqual(result["executables"][0]["byte_order"], "big")
            data[5] = 1
            data[18:20] = (22).to_bytes(2, "little")
            path.write_bytes(data)
            result = run_case("core", [], execute, target="s390x-unknown-linux-gnu")
            self.assertFalse(result["passed"])
            self.assertIn("wrong executable architecture", result["executable_error"])


if __name__ == "__main__":
    unittest.main()
