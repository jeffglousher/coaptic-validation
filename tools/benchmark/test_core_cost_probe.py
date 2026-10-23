"""Isolated stdlib checks. No Cargo, perf, sudo or real child processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import core_cost_probe as probe


def credentials(uid=1001, gid=1002):
    return (f"Uid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\n"
            "Groups:\t\nNoNewPrivs:\t1\n" +
            "".join(name + ":\t00000000\n" for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")))


def bench(security="unprotected"):
    return {"operations": 50000, "warmup": 128, "security": security, "black_box": True,
            "measurement": "poll wall clock", "latencies_ns": [1000] * 50000,
            "clock_calibration_ns": [20] * 4096}


OWNED = {"pid": 12345, "pgrp": 12345, "session": 12000, "starttime": 98765}
USAGE = {"utime": .1, "stime": .02, "minflt": 1, "majflt": 0, "nvcsw": 2, "nivcsw": 1}


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        # A forgotten mock must fail rather than launch a build/profiler/worker.
        for name in ("run_owned", "run_logged", "command", "subprocess.Popen"):
            started = patch("core_cost_probe." + name, side_effect=AssertionError("real launch forbidden"))
            started.start()
            self.addCleanup(started.stop)
        self.enterContext(patch("core_cost_probe.signal.SIGKILL", 9, create=True))

    def test_fixed_plan_counts_and_fresh_context_bound(self):
        self.assertEqual([row[2] for row in probe.PLAN], [1, 1, 8, 8, 1, 1])
        self.assertEqual(sum(row[2] for row in probe.PLAN), 20)
        self.assertEqual(20 * (probe.OPERATIONS + probe.WARMUP), 1_002_560)
        self.assertEqual(sum(n for _, security, n in probe.PLAN if security == "oscore"), 10)
        self.assertLess(probe.OPERATIONS + probe.WARMUP, 65536)
        self.assertEqual(probe.REVIEW["both_50_percent_targets"], "OPEN")

    def test_parent_exec_and_credential_drop_are_fixed(self):
        for phase, (_, _, count) in enumerate(probe.PLAN):
            argv = probe.phase_command(self.root, phase, 1001, 1002)
            self.assertEqual(argv[:4], ["sudo", "-n", "--", "prlimit"])
            for value in ("--reuid=1001", "--regid=1002", "--clear-groups", "--inh-caps=-all",
                          "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs"):
                self.assertIn(value, argv)
            self.assertEqual("perf" in argv, count == 8)
            if count == 8:
                self.assertLess(argv.index("perf"), argv.index("setpriv"))
                self.assertIn("--inherit", argv)
                self.assertIn("fp,64", argv)
                self.assertIn("997", argv)
            self.assertFalse(set(argv) & {"-a", "-p", "--pid", "--uid", "--per-thread", "--control"})

    def test_credentials_refuse_each_privileged_or_mismatched_field(self):
        text = credentials()
        probe.validate_credentials(text, 1001, 1002)
        for bad in (text.replace("1001", "0"), text.replace("1002", "1003"),
                    text.replace("Groups:\t", "Groups:\t7"), text.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.validate_credentials(bad, 1001, 1002)
        for cap in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            with self.subTest(cap=cap), self.assertRaises(ValueError):
                probe.validate_credentials(text.replace(cap + ":\t00000000", cap + ":\t00000001"), 1001, 1002)
        with self.assertRaises(ValueError):
            probe.validate_credentials(credentials(0), 0, 1002)

    def test_benchmark_requires_complete_matching_raw_arrays(self):
        value = bench()
        probe.validate_bench(json.dumps(value), "unprotected")
        for key, bad in (("operations", True), ("warmup", 0), ("security", "oscore"),
                         ("black_box", False), ("latencies_ns", [1]), ("clock_calibration_ns", [1])):
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_bench(json.dumps({**value, key: bad}), "unprotected")
        for sample in (True, -1, 1.2, 2**128):
            value["latencies_ns"][0] = sample
            with self.subTest(sample=sample), self.assertRaises(ValueError):
                probe.validate_bench(json.dumps(value), "unprotected")
        with self.assertRaises(ValueError):
            probe.validate_bench('{"operations":50000', "unprotected")

    def test_cpu_scope_and_failed_work_has_no_verified_denominator(self):
        after = {key: value * 2 for key, value in USAGE.items()}
        receipt = probe.cpu_receipt(USAGE, after)
        self.assertEqual(receipt["delta"], USAGE)
        self.assertIn("client", receipt["scope"])
        self.assertIn("not isolated server CPU", receipt["scope"])
        self.assertNotIn("whole_process_cpu_ns_per_verified_exchange", receipt)
        for bad in (-1, float("nan"), float("inf")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                probe.cpu_receipt(USAGE, {**after, "utime": bad})

    def worker_fixture(self, phase=2, code=0, wait_error=None, privileged=False):
        name, security, count = probe.PLAN[phase]
        directory = self.root / name
        directory.mkdir()
        binary = self.root / "dummy-ELF-never-executed"
        binary.write_bytes(b"synthetic")
        probe.save_new(self.root / "build.json", {"uid": 1001, "gid": 1002,
                       "binary": str(binary), "binary_sha256": probe.digest(binary)})
        children = []

        def spawn(argv, **kwargs):
            self.assertTrue((directory / "worker.json").exists())
            self.assertEqual(probe.load(directory / "worker.json")["pid"], OWNED["pid"])
            self.assertEqual(argv, [str(binary), "50000", security])
            self.assertNotIn("start_new_session", kwargs)
            kwargs["stdout"].write(json.dumps(bench(security)).encode())
            child = Mock(pid=20000 + len(children), args=argv, returncode=code)
            child.wait.side_effect = wait_error
            child.wait.return_value = code
            child.poll.return_value = code
            children.append(child)
            return child

        self.enterContext(patch.dict(sys.modules, {"resource": SimpleNamespace(
            RLIMIT_FSIZE=1, setrlimit=Mock(), getrlimit=lambda _: (probe.DATA, probe.DATA))}))
        self.enterContext(patch("core_cost_probe.bounded_read", side_effect=lambda path, limit:
                          (credentials(0) if privileged else credentials()).encode()
                          if str(path) == "/proc/self/status" else Path(path).read_bytes()))
        self.enterContext(patch("core_cost_probe.os.getpid", return_value=OWNED["pid"]))
        self.enterContext(patch("core_cost_probe.os.getpgrp", return_value=OWNED["pgrp"], create=True))
        self.enterContext(patch("core_cost_probe.proc_identity", return_value=OWNED.copy()))
        self.enterContext(patch("core_cost_probe.signal.signal"))
        self.enterContext(patch("core_cost_probe.usage", side_effect=[USAGE, {k: v * 2 for k, v in USAGE.items()}] * count))
        self.enterContext(patch("core_cost_probe.subprocess.Popen", side_effect=spawn))
        return directory, children

    def test_worker_records_custody_then_eight_fresh_processes(self):
        directory, children = self.worker_fixture()
        probe.worker(self.root, 2)
        self.assertEqual(len(children), 8)
        for i in range(8):
            receipt = probe.load(directory / f"bench-{i}.json")
            self.assertTrue(receipt["complete"])
            self.assertAlmostEqual(receipt["whole_process_cpu_ns_per_verified_exchange"], .12e9 / 50128)
            self.assertEqual(children[i].wait.call_args.kwargs["timeout"], 5)

    def test_worker_refuses_privileged_execution_before_any_child(self):
        directory, children = self.worker_fixture(privileged=True)
        with self.assertRaises(ValueError):
            probe.worker(self.root, 2)
        self.assertFalse(children)
        self.assertFalse((directory / "worker.json").exists())

    def test_oscore_worker_uses_fresh_processes_in_one_recorded_group(self):
        directory, children = self.worker_fixture(phase=3)
        with patch("core_cost_probe.os.getpgrp", return_value=12000, create=True), \
                patch("core_cost_probe.os.setpgid", create=True) as group:
            probe.worker(self.root, 3)
        group.assert_called_once_with(0, 0)
        self.assertEqual(len(children), 8)
        self.assertEqual(probe.load(directory / "worker.json")["pgrp"], OWNED["pid"])
        self.assertEqual(len({child.pid for child in children}), 8)

    def test_failed_child_receipt_retained_without_success_cost(self):
        directory, children = self.worker_fixture(phase=0, code=7)
        with self.assertRaises(subprocess.CalledProcessError):
            probe.worker(self.root, 0)
        receipt = probe.load(directory / "bench-0.json")
        self.assertFalse(receipt["complete"])
        self.assertEqual(receipt["returncode"], 7)
        self.assertNotIn("whole_process_cpu_ns_per_verified_exchange", receipt)

    def test_child_timeout_cleanup_failure_is_fatal_and_retained(self):
        directory, children = self.worker_fixture(phase=0, wait_error=subprocess.TimeoutExpired("synthetic", 5))
        # Factory is called inside worker; customize the returned mock there.
        original = probe.subprocess.Popen.side_effect

        def failing(*args, **kwargs):
            child = original(*args, **kwargs)
            child.poll.return_value = None
            return child

        probe.subprocess.Popen.side_effect = failing
        with self.assertRaises(subprocess.TimeoutExpired):
            probe.worker(self.root, 0)
        self.assertTrue(probe.load(directory / "bench-0.json")["cleanup_unresolved"])
        children[0].terminate.assert_called_once()
        children[0].kill.assert_called_once()

    def test_owned_group_identity_and_unresolved_cleanup(self):
        marker = self.root / "worker.json"
        probe.save_new(marker, OWNED)
        with patch("core_cost_probe.os.getpgrp", return_value=1, create=True), \
                patch("core_cost_probe.proc_identity", return_value={**OWNED, "starttime": 1}), \
                patch("core_cost_probe.os.killpg", create=True) as kill:
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                probe.cleanup_group(marker)
            kill.assert_not_called()
        with patch("core_cost_probe.os.getpgrp", return_value=1, create=True), \
                patch("core_cost_probe.proc_identity", return_value=OWNED), \
                patch("core_cost_probe.os.killpg", create=True), patch("core_cost_probe.time.sleep"):
            with self.assertRaisesRegex(RuntimeError, "survives KILL"):
                probe.cleanup_group(marker)
        with patch("core_cost_probe.os.getpgrp", return_value=1, create=True), \
                patch("core_cost_probe.proc_identity", side_effect=FileNotFoundError), \
                patch("core_cost_probe.os.killpg", side_effect=ProcessLookupError, create=True):
            probe.cleanup_group(marker)

    def test_reports_keep_unfiltered_evidence_and_pid_filtered_callers(self):
        with patch("core_cost_probe.perf_report", return_value={"available": True}) as flat, \
                patch("core_cost_probe.run_owned", return_value=0) as run:
            with (self.root / "perf-command.log").open("xb") as log:
                probe.reports(self.root, [{"pid": 123}, {"pid": 456}], log)
            flat.assert_called_once()
            first, second = [item.args[0] for item in run.call_args_list]
            self.assertEqual(first[first.index("--pid") + 1], "123,456")
            self.assertIn("--children", first)
            self.assertIn("absolute", first)
            self.assertIn("--show-task-events", second)
            self.assertIn("--show-lost-events", second)
            self.assertNotIn("--pid", second)
            for item in run.call_args_list:
                self.assertEqual(item.kwargs["timeout"], 35)
                self.assertTrue(item.kwargs["elevated"])

    def test_unresolved_flat_report_cleanup_stops_other_readouts(self):
        with patch("core_cost_probe.perf_report", return_value={"available": False, "cleanup_unresolved": True}), \
                patch("core_cost_probe.run_owned") as run:
            with (self.root / "perf-command.log").open("xb") as log:
                with self.assertRaisesRegex(RuntimeError, "cleanup unresolved"):
                    probe.reports(self.root, [{"pid": 123}], log)
            run.assert_not_called()
        self.assertTrue(probe.load(self.root / "flat-status.json")["cleanup_unresolved"])

    def test_per_file_and_aggregate_evidence_limits(self):
        (self.root / "unexpected.json").write_bytes(b"x" * (probe.META + 1))
        with self.assertRaisesRegex(ValueError, "exceeds quota"):
            probe.inventory(self.root)
        (self.root / "unexpected.json").unlink()
        (self.root / "bench-0.jsonlog").write_bytes(b"x" * 40000)
        (self.root / "bench-1.jsonlog").write_bytes(b"x" * 40000)
        with patch("core_cost_probe.MIB", 1024), patch("core_cost_probe.META", 16):
            with self.assertRaisesRegex(ValueError, "aggregate"):
                probe.inventory(self.root)

    def test_refuse_non_runner_without_build_or_output(self):
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
            with self.assertRaises(ValueError):
                probe.run(self.root / "absent", self.root / "lane")
        self.assertFalse((self.root / "absent").exists())

    def test_build_watchdog_failure_is_not_reported_success(self):
        with patch("core_cost_probe.run_logged"), \
                patch("core_cost_probe.directory_bytes", return_value=5 * 1024 * probe.MIB):
            with self.assertRaisesRegex(ValueError, "4 GiB"):
                probe.build(self.root, self.root, {}, "x86_64-unknown-linux-gnu")

    def controller_fixture(self, fail=False):
        output, lane = self.root / "output", self.root / "lane"
        host = "x86_64-unknown-linux-gnu"
        compiled = lane / host / "release/bench-core"

        def build(*args):
            compiled.parent.mkdir(parents=True)
            compiled.write_bytes(b"synthetic, never executed")

        def command(argv, **kwargs):
            if argv[-1] == "-Vv":
                return "release: 1.99.0\ncommit-hash: " + "a" * 40 + "\nhost: " + host
            return "synthetic version"

        calls = []

        def launch(argv, **kwargs):
            phase = int(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("CORE_COST_PHASE=")))
            name, security, count = probe.PLAN[phase]
            calls.append(name)
            if fail:
                return 77
            for i in range(count):
                probe.save_new(output / name / f"bench-{i}.json",
                               {"pid": 20000 + 8 * phase + i, "complete": True, "security": security})
            if count == 8:
                (output / name / "perf.data").write_bytes(b"synthetic capture, not a profile")
            return 0

        self.enterContext(patch("core_cost_probe.sys.platform", "linux"))
        self.enterContext(patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "CARGO_ENCODED_RUSTFLAGS": "bad"}))
        self.enterContext(patch("core_cost_probe.os.getuid", return_value=1001, create=True))
        self.enterContext(patch("core_cost_probe.os.getgid", return_value=1002, create=True))
        self.enterContext(patch("core_cost_probe.os.cpu_count", return_value=4))
        self.enterContext(patch("core_cost_probe.os.sysconf", return_value=4096, create=True))
        self.enterContext(patch("core_cost_probe.hardware", return_value={"synthetic": True}))
        self.enterContext(patch("core_cost_probe.identity", side_effect=lambda path:
            {"revision": probe.CORE if path == probe.SUITE / "coaptic" else "b" * 40, "status": ""}))
        self.enterContext(patch("core_cost_probe.digest", return_value="c" * 64))
        self.enterContext(patch("core_cost_probe.command", side_effect=command))
        build_mock = self.enterContext(patch("core_cost_probe.build", side_effect=build))
        self.enterContext(patch("core_cost_probe.run_owned", side_effect=launch))
        self.enterContext(patch("core_cost_probe.cleanup_group"))
        self.enterContext(patch("core_cost_probe.reports", return_value={"flat": {"available": True},
                                                                       "samples.txt": {"returncode": 0}}))
        return output, lane, calls, build_mock

    def test_controller_runs_six_phases_once_and_keeps_review_pending(self):
        output, lane, calls, build = self.controller_fixture()
        probe.run(output, lane)
        self.assertEqual(calls, [name for name, _, _ in probe.PLAN])
        self.assertEqual(sum(len(probe.load(output / name / "phase.json")["benchmarks"])
                             for name, _, _ in probe.PLAN), 20)
        state = probe.load(output / "summary.json")
        self.assertTrue(state["complete"])
        self.assertEqual(state["review"]["both_50_percent_targets"], "OPEN")
        self.assertIn("source-guided", state["review"]["status"])
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", build.call_args.args[2])
        self.assertEqual(build.call_args.args[2]["RUSTFLAGS"], probe.FLAGS["RUSTFLAGS"])
        self.assertEqual(probe.load(output / "index.json")["index_excludes_itself"], True)

    def test_controller_retains_refusal_and_never_replaces_the_phase(self):
        output, lane, calls, _ = self.controller_fixture(fail=True)
        with self.assertRaises(FileNotFoundError):
            probe.run(output, lane)
        self.assertEqual(calls, ["u-before"])
        self.assertFalse(probe.load(output / "summary.json")["complete"])
        self.assertEqual(probe.load(output / "u-before/phase.json")["returncode"], 77)
        self.assertTrue((output / "index.json").exists())

    def test_workflow_is_manual_serial_and_retains_failure_without_installs(self):
        workflow = (Path(probe.__file__).resolve().parents[2] / ".github/workflows/core-cost-probe.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("group: manual-linux-cpu", workflow)
        self.assertIn("timeout-minutes: 25", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("retention-days: 14", workflow)
        self.assertNotIn("pip install", "\n".join(line for line in workflow.splitlines() if not line.lstrip().startswith("#")))
        self.assertNotIn("apt-get", workflow)


if __name__ == "__main__":
    unittest.main()
