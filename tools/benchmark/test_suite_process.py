"""Finite real-process custody checks; no Cargo, native fixture, or runtime changes."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import suite_process as helper


def command(mode, *arguments):
    # The production caller selects actual Python, with no launcher before its
    # gate. Keep one explicit Windows redirector regression separately below.
    executable = getattr(sys, "_base_executable", None) or sys.executable
    return [executable, "-B", str(Path(__file__).resolve()), "_task", mode, *arguments]


def task(mode, arguments):
    # Match the parent runner contract: no descendants or actions before go.
    if sys.stdin.buffer.readline(4) != b"go\n":
        return 91
    if sys.stdin.buffer.read(1) != b"":
        return 92
    if mode == "result":
        os.write(1, b"out\x00\xff")
        os.write(2, b"err\x00\xfe")
    elif mode == "environment":
        os.write(1, (os.getcwd() + "\n" + os.environ["SUITE_HELPER_TEST"]).encode())
    elif mode == "failure":
        os.write(1, b"before failure")
        os.write(2, b"failure detail")
        return 7
    elif mode == "deadline":
        os.write(1, b"before timeout")
        time.sleep(30)
    elif mode == "cap":
        while True:
            os.write(1, b"a" * 1024)
            os.write(2, b"b" * 1024)
    elif mode == "exact":
        os.write(1, b"a" * 1024)
        os.write(2, b"b" * 1024)
    elif mode in ("descendant", "descendant-timeout"):
        child = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(30)"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL)
        os.write(1, str(child.pid).encode() + b"\n")
        if mode == "descendant-timeout":
            time.sleep(30)
    elif mode == "mark":
        Path(arguments[0]).write_bytes(b"released")
    elif mode == "breakaway":
        try:
            child = subprocess.Popen([sys._base_executable, "-B", "-c",
                                      "import time; time.sleep(1.5)"],
                                     creationflags=subprocess.CREATE_BREAKAWAY_FROM_JOB,
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
        except OSError:
            os.write(1, b"breakaway refused")
        else:
            os.write(1, str(child.pid).encode())
    return 0


@unittest.skipUnless(sys.platform in ("win32", "linux"), "requires supported custody OS")
class ProcessTests(unittest.TestCase):
    def tearDown(self):
        self.assertFalse([t.name for t in threading.enumerate() if t.name.startswith("suite-pipe-")])

    def test_result_preserves_binary_stdout_stderr_and_duration(self):
        result = helper.run_worker(command("result"), timeout=3)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out\x00\xff")
        self.assertEqual(result.stderr, b"err\x00\xfe")
        self.assertGreater(result.duration_seconds, 0)
        self.assertLess(result.duration_seconds, 3)

    def test_cwd_and_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            env = {**os.environ, "SUITE_HELPER_TEST": "chosen"}
            result = helper.run_worker(command("environment"), timeout=3, cwd=directory, env=env)
            current, chosen = result.stdout.decode().splitlines()
            self.assertEqual(Path(current).resolve(), Path(directory).resolve())
            self.assertEqual(chosen, "chosen")

    def test_nonzero_preserves_primary_and_both_streams(self):
        with self.assertRaises(helper.WorkerError) as caught:
            helper.run_worker(command("failure"), timeout=3)
        error = caught.exception
        self.assertIsInstance(error.primary_cause, subprocess.CalledProcessError)
        self.assertEqual(error.returncode, 7)
        self.assertEqual(error.stdout, b"before failure")
        self.assertEqual(error.stderr, b"failure detail")
        self.assertFalse(error.cleanup_unresolved)

    def test_live_combined_cap_stops_unending_output(self):
        with self.assertRaises(helper.WorkerError) as caught:
            helper.run_worker(command("cap"), timeout=3, limit=2048)
        error = caught.exception
        self.assertIsInstance(error.primary_cause, helper.OutputLimitExceeded)
        self.assertEqual(len(error.stdout) + len(error.stderr), 2049)
        self.assertFalse(error.cleanup_unresolved)
        self.assertLess(error.duration_seconds, 3)

    def test_exact_combined_cap_is_success(self):
        result = helper.run_worker(command("exact"), timeout=3, limit=2048)
        self.assertEqual(result.stdout, b"a" * 1024)
        self.assertEqual(result.stderr, b"b" * 1024)

    def test_deadline_preserves_output_and_stops_readers(self):
        with self.assertRaises(helper.WorkerError) as caught:
            helper.run_worker(command("deadline"), timeout=.4)
        error = caught.exception
        self.assertIsInstance(error.primary_cause, subprocess.TimeoutExpired)
        self.assertEqual(error.stdout, b"before timeout")
        self.assertFalse(error.cleanup_unresolved)
        self.assertLess(error.duration_seconds, 2)

    def assert_descendant_stopped(self, pid):
        if sys.platform == "win32":
            # Read-only handle observation, never a numeric cleanup path.
            kernel = helper._kernel
            kernel.OpenProcess.argtypes = [helper.wt.DWORD, helper.wt.BOOL, helper.wt.DWORD]
            kernel.OpenProcess.restype = helper.wt.HANDLE
            handle = kernel.OpenProcess(0x100000, False, pid)  # SYNCHRONIZE
            if handle:
                try:
                    self.assertEqual(kernel.WaitForSingleObject(handle, 0), 0)
                finally:
                    helper._wincheck(kernel.CloseHandle(handle))
        else:
            stat = Path(f"/proc/{pid}/stat")
            if stat.exists():
                self.assertIn(stat.read_bytes().rpartition(b")")[2].split()[0], (b"Z", b"X"))

    def test_normal_worker_exit_with_descendant_is_fatal_and_settled(self):
        with self.assertRaises(helper.WorkerError) as caught:
            helper.run_worker(command("descendant"), timeout=3)
        error = caught.exception
        self.assertIn("remaining descendants", str(error.primary_cause))
        self.assertFalse(error.cleanup_unresolved)
        self.assert_descendant_stopped(int(error.stdout))

    def test_timeout_kills_worker_and_descendant_before_return(self):
        with self.assertRaises(helper.WorkerError) as caught:
            helper.run_worker(command("descendant-timeout"), timeout=.4)
        error = caught.exception
        self.assertIsInstance(error.primary_cause, subprocess.TimeoutExpired)
        self.assertFalse(error.cleanup_unresolved)
        self.assert_descendant_stopped(int(error.stdout))

    def test_unsupported_helper_refuses_before_spawn(self):
        with patch.object(helper.sys, "platform", "unsupported"), patch.object(helper.subprocess, "Popen") as spawn:
            with self.assertRaises(helper.WorkerError) as caught:
                helper.run_worker(command("result"), timeout=1)
        spawn.assert_not_called()
        self.assertEqual(caught.exception.stdout, b"")

    def test_cleanup_failure_keeps_primary_and_output(self):
        real_owner = helper._owner()
        real_settle = real_owner.settle

        def settle_then_report_failure():
            real_settle()
            raise RuntimeError("injected settlement observer failure")

        with patch.object(helper, "_owner", return_value=real_owner), patch.object(
                real_owner, "settle", side_effect=settle_then_report_failure):
            with self.assertRaises(helper.WorkerError) as caught:
                helper.run_worker(command("failure"), timeout=3)
        error = caught.exception
        self.assertIsInstance(error.primary_cause, subprocess.CalledProcessError)
        self.assertEqual(error.stdout, b"before failure")
        self.assertTrue(error.cleanup_unresolved)
        self.assertIn("observer failure", str(error.cleanup_errors[0]))

    @unittest.skipUnless(sys.platform == "win32", "real Windows Job only")
    def test_job_assignment_refusal_does_not_release_worker(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory, "must-not-exist")
            with patch.object(helper._kernel, "AssignProcessToJobObject", return_value=0):
                with self.assertRaises(helper.WorkerError) as caught:
                    helper.run_worker(command("mark", str(marker)), timeout=3)
            self.assertFalse(marker.exists())
            self.assertFalse(caught.exception.cleanup_unresolved)
            self.assertEqual(caught.exception.stdout, b"")

    @unittest.skipUnless(sys.platform == "win32", "real Windows Job only")
    def test_job_has_no_breakaway(self):
        try:
            result = helper.run_worker(command("breakaway"), timeout=3)
        except helper.WorkerError as error:
            # Nested job policy may allow CreateProcess while keeping the child
            # inside our restrictive Job. Creation success is not escape proof.
            self.assertIn("remaining descendants", str(error.primary_cause))
            self.assertFalse(error.cleanup_unresolved)
            self.assert_descendant_stopped(int(error.stdout))
        else:
            self.assertEqual(result.stdout, b"breakaway refused")

    @unittest.skipUnless(sys.platform == "win32", "Windows SDK layout")
    def test_sdk_layout_and_sizes(self):
        pointer = helper.ctypes.sizeof(helper.ctypes.c_void_p)
        self.assertEqual(helper.ctypes.sizeof(helper._BasicLimit), 64 if pointer == 8 else 48)
        self.assertEqual(helper.ctypes.sizeof(helper._ExtendedLimit), 144 if pointer == 8 else 112)
        self.assertEqual(helper._ExtendedLimit.IoInfo.offset, 64 if pointer == 8 else 48)
        self.assertEqual(helper.ctypes.sizeof(helper._Accounting), 48)

    @unittest.skipUnless(sys.platform == "win32", "real Windows Job only")
    def test_job_accounting_exit_grace_is_bounded_and_not_permission_to_keep_members(self):
        if sys.platform != "win32":
            self.skipTest("Windows Job accounting")
        owner = object.__new__(helper._WindowsOwner)
        with patch.object(owner, "active", side_effect=[1, 1, 0]):
            self.assertFalse(owner.descendants())
        started = time.monotonic()
        with patch.object(owner, "active", return_value=1):
            self.assertTrue(owner.descendants())
        self.assertLess(time.monotonic() - started, 1)

    def test_job_policy_is_fixed_16_with_kill_on_close_and_no_breakaway(self):
        owner = helper._WindowsOwner()
        try:
            limits = helper._ExtendedLimit()
            helper._wincheck(helper._kernel.QueryInformationJobObject(
                owner.job, 9, helper.ctypes.byref(limits), helper.ctypes.sizeof(limits), None))
            self.assertEqual(limits.BasicLimitInformation.LimitFlags, 0x2008)
            self.assertEqual(limits.BasicLimitInformation.ActiveProcessLimit, 16)
        finally:
            owner.close()

    @unittest.skipUnless(sys.platform == "win32", "real Windows Job only")
    def test_job_support_refusal_precedes_process_creation(self):
        with patch.object(helper._kernel, "SetInformationJobObject", return_value=0), patch.object(
                helper._winapi, "CreateProcess") as create:
            with self.assertRaises(helper.WorkerError):
                helper.run_worker(command("result"), timeout=1)
        create.assert_not_called()

    @unittest.skipUnless(sys.platform == "win32", "Windows venv startup regression")
    def test_venv_redirector_and_base_worker_timeout_are_both_settled(self):
        if os.path.normcase(sys.executable) == os.path.normcase(sys._base_executable):
            self.skipTest("run this regression from a Windows venv")
        owner = helper._WindowsOwner()
        settle = owner.settle
        handles = []

        def retain_original_members_then_settle():
            ids = helper._ProcessIds()
            helper._wincheck(helper._kernel.QueryInformationJobObject(
                owner.job, 3, helper.ctypes.byref(ids), helper.ctypes.sizeof(ids), None))
            for pid in ids.ProcessIdList[:ids.NumberOfProcessIdsInList]:
                handle = helper._kernel.OpenProcess(0x100000, False, pid)
                helper._wincheck(handle)
                handles.append(handle)
            settle()

        argv = command("deadline")
        argv[0] = sys.executable  # Intentionally exercise the venv redirector.
        try:
            with patch.object(helper, "_owner", return_value=owner), patch.object(
                    owner, "settle", side_effect=retain_original_members_then_settle):
                with self.assertRaises(helper.WorkerError) as caught:
                    helper.run_worker(argv, timeout=.4)
            self.assertIsInstance(caught.exception.primary_cause, subprocess.TimeoutExpired)
            self.assertEqual(caught.exception.stdout, b"before timeout")
            self.assertFalse(caught.exception.cleanup_unresolved)
            self.assertGreaterEqual(len(handles), 2)  # Redirector AND actual Python.
            for handle in handles:
                self.assertEqual(helper._kernel.WaitForSingleObject(handle, 0), 0)
        finally:
            for handle in handles:
                helper._wincheck(helper._kernel.CloseHandle(handle))

    @unittest.skipUnless(sys.platform == "linux", "Linux owned leader only")
    def test_linux_uses_unreaped_owned_leader(self):
        import linux_cpu
        real_settle = helper._LinuxOwner.settle
        seen = []

        def verify(owner):
            self.assertIsInstance(owner.process, linux_cpu.OwnedProcess)
            self.assertIsNone(owner.process.process.returncode)
            self.assertEqual(owner.process.poll(), 0)
            seen.append(True)
            real_settle(owner)

        with patch.object(helper._LinuxOwner, "settle", verify):
            helper.run_worker(command("result"), timeout=3)
        self.assertEqual(seen, [True])


class ValidationTests(unittest.TestCase):
    def test_refuses_invalid_budgets_without_spawning(self):
        with patch.object(helper, "_owner") as owner:
            for timeout in (0, -1, 901, float("inf"), float("nan"), True, "1"):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    helper.run_worker(command("result"), timeout=timeout)
            for limit in (0, -1, helper.MAX_OUTPUT + 1, True, 1.5):
                with self.subTest(limit=limit), self.assertRaises(ValueError):
                    helper.run_worker(command("result"), timeout=1, limit=limit)
            owner.assert_not_called()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "_task":
        raise SystemExit(task(sys.argv[2], sys.argv[3:]))
    unittest.main()
