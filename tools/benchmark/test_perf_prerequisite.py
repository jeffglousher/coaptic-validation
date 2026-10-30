"""Portable mocks only: never execute perf, sudo, subprocesses or signals."""
from contextlib import ExitStack
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_core_cost_probe as tests


class PerfPrerequisiteTests(unittest.TestCase):
    def setUp(self):
        self.run = self.enterContext(patch.object(tests.probe, "run_owned",
            side_effect=AssertionError("unmocked owned launch forbidden")))
        self.enterContext(patch.object(subprocess, "run", side_effect=AssertionError("launch forbidden")))
        self.enterContext(patch.object(subprocess, "Popen", side_effect=AssertionError("launch forbidden")))

    def launch(self, *, code=0, stdout=b"", stderr=b"", error=None):
        def run(argv, **kwargs):
            self.assertEqual(argv, tests.probe.prefix(tests.probe.META, 3) +
                             ["perf", "stat", "--null", "--", "true"])
            self.assertEqual(set(kwargs), {"timeout", "check", "elevated", "file_limit",
                                           "stdin", "stdout", "stderr"})
            self.assertEqual(kwargs["timeout"], 10)
            self.assertIs(kwargs["check"], False)
            self.assertIs(kwargs["elevated"], True)
            self.assertEqual(kwargs["file_limit"], tests.probe.META)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertIsNot(kwargs["stdout"], kwargs["stderr"])
            self.streams = kwargs["stdout"], kwargs["stderr"]
            kwargs["stdout"].write(stdout)
            kwargs["stderr"].write(stderr)
            if error is not None:
                raise error
            return code
        self.run.side_effect = run

    def test_success_keeps_exact_probe_and_owned_limits_and_closes_output(self):
        self.launch(stdout=b"normal output", stderr=b"normal diagnostic")
        self.assertIsNone(tests.check_perf_prerequisite("/usr/bin/perf"))
        self.run.assert_called_once()
        self.assertTrue(all(stream.closed for stream in self.streams))

    def test_nonzero_remains_assertion_with_separate_output_and_runner_identity(self):
        self.launch(code=129, stdout=b"stdout marker", stderr=b"perf: unknown option --null")
        with self.assertRaises(AssertionError) as raised:
            tests.check_perf_prerequisite("/usr/bin/perf")
        message = str(raised.exception)
        for expected in ("returncode=129", "argv=", "sudo", "--null", "stdout='stdout marker'",
                         "stderr='perf: unknown option --null'", "runner_perf='/usr/bin/perf'",
                         "sudo-selected path/version unverified"):
            self.assertIn(expected, message)
        self.assertTrue(all(stream.closed for stream in self.streams))

    def test_negative_return_is_still_failure(self):
        self.launch(code=-25, stderr=b"file size limit")
        with self.assertRaisesRegex(AssertionError, "returncode=-25"):
            tests.check_perf_prerequisite("/usr/bin/perf")

    def test_oversize_and_non_utf8_fields_have_bounded_escaped_diagnostics(self):
        self.launch(code=1, stdout=b"\xff\x00\n" * 2048, stderr=b"z" * 8192)
        with self.assertRaises(AssertionError) as raised:
            tests.check_perf_prerequisite("\x00\n" * 2048)
        message = str(raised.exception)
        self.assertLess(len(message.encode("utf-8")), 5000)
        self.assertEqual(message.count("[truncated]"), 3)
        self.assertIn("\\ufffd", message)
        self.assertNotIn("\x00", message)
        self.assertNotIn("\n", message)
        self.assertNotIn("z" * 1025, message)

    def test_timeout_preserves_exception_and_cleanup_metadata_and_partial_output(self):
        original = subprocess.TimeoutExpired(["fixed prerequisite"], 10)
        original.cleanup_unresolved = True
        original.add_note("existing cleanup evidence")
        self.launch(stdout=b"partial output", stderr=b"partial error", error=original)
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            tests.check_perf_prerequisite("/usr/bin/perf")
        self.assertIs(raised.exception, original)
        self.assertTrue(original.cleanup_unresolved)
        self.assertEqual(original.__notes__[0], "existing cleanup evidence")
        self.assertIn("returncode=None", original.__notes__[-1])
        self.assertIn("partial error", original.__notes__[-1])
        self.assertTrue(all(stream.closed for stream in self.streams))
        self.run.assert_called_once()  # No follow-up version command or retry.

    def test_launch_error_preserves_original_type_even_if_perf_path_disappears(self):
        original = FileNotFoundError("sudo disappeared")
        self.launch(error=original)
        with self.assertRaises(FileNotFoundError) as raised:
            tests.check_perf_prerequisite(None)
        self.assertIs(raised.exception, original)
        self.assertIn("runner_perf=None", original.__notes__[-1])

    def test_owned_precondition_or_cleanup_refusal_preserves_original_failure(self):
        for original in (RuntimeError("owned leader already reaped"),
                         ValueError("refusing to signal an unowned process group")):
            with self.subTest(error=type(original).__name__):
                original.cleanup_unresolved = True
                self.launch(error=original)
                with self.assertRaises(type(original)) as raised:
                    tests.check_perf_prerequisite("/usr/bin/perf")
                self.assertIs(raised.exception, original)
                self.assertTrue(original.cleanup_unresolved)
                self.assertIn("argv=", original.__notes__[-1])

    def test_diagnostic_failure_does_not_replace_primary_timeout(self):
        original = subprocess.TimeoutExpired("prerequisite", 10)
        self.launch(error=original)
        real_file = tests.tempfile.TemporaryFile

        def closed_file():
            stream = real_file()
            stream.seek = lambda *_: (_ for _ in ()).throw(OSError("synthetic read failure"))
            return stream

        with patch.object(tests.tempfile, "TemporaryFile", side_effect=closed_file):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                tests.check_perf_prerequisite("/usr/bin/perf")
        self.assertIs(raised.exception, original)
        self.assertEqual(original.__notes__[-1], "prerequisite diagnostic unavailable: OSError")

    def preconditions(self, stack):
        stack.enter_context(patch.object(tests.sys, "platform", "linux"))
        for name in ("pidfd_open", "waitid"):
            stack.enter_context(patch.object(tests.os, name, lambda: None, create=True))
        stack.enter_context(patch.object(tests.os, "WNOWAIT", 1, create=True))
        for name in ("getuid", "getgid"):
            stack.enter_context(patch.object(tests.os, name, return_value=1001, create=True))
        stack.enter_context(patch.object(tests.shutil, "which", side_effect=lambda name: "/usr/bin/" + name))

    def test_setup_uses_probe_only_after_all_preconditions_pass(self):
        self.launch()
        with ExitStack() as stack:
            self.preconditions(stack)
            tests.PrivilegedCleanupTests.setUpClass.__func__(SimpleNamespace())
        self.run.assert_called_once()

    def test_precondition_failures_remain_assertions_without_any_command(self):
        cases = (("platform", "win32", "Linux pidfds"),
                 ("pidfd_open", None, "Linux pidfds"),
                 ("waitid", None, "Linux pidfds"),
                 ("getuid", lambda: 0, "ordinary runner"),
                 ("getgid", lambda: 0, "ordinary runner"),
                 ("which", lambda name: None if name == "perf" else "/bin/" + name,
                  "missing prerequisites: perf"))
        for name, value, message in cases:
            with self.subTest(name=name), ExitStack() as stack:
                self.preconditions(stack)
                target = tests.sys if name == "platform" else tests.shutil if name == "which" else tests.os
                stack.enter_context(patch.object(target, name, value, create=True))
                with self.assertRaisesRegex(AssertionError, message):
                    tests.PrivilegedCleanupTests.setUpClass.__func__(SimpleNamespace())
                self.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
