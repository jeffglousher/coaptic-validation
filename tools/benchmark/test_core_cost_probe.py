"""Isolated stdlib checks by default. No Cargo, perf or sudo.

Two real custody/EOF checks require an explicitly supplied existing Linux
binary in CORE_COST_BATCH_FAILURE_TEST_BINARY; never built or enabled here.
"""
import hashlib
import io
import json
import os
import stat
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
        for name in ("run_owned", "run_logged", "command", "subprocess.Popen", "spawn", "batch_run_command"):
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
        with patch("core_cost_probe.flat_report", return_value={"available": True}) as flat, \
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
        with patch("core_cost_probe.flat_report", return_value={"available": False, "cleanup_unresolved": True}), \
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

    def capture_permissions(self):
        """Model root:root0600 plus EACCES, not a runner-owned tempfile shortcut."""
        owners = {}
        original_stat, original_open = Path.lstat, Path.open

        def capture_stat(path, *args, **kwargs):
            info = original_stat(path, *args, **kwargs)
            if path in owners:
                values = list(info)
                values[0], values[4], values[5] = stat.S_IFREG | 0o600, *owners[path]
                return os.stat_result(values)
            return info

        def capture_open(path, mode="r", *args, **kwargs):
            if path in owners and "r" in mode and owners[path][0] != 1001:
                raise PermissionError("root-owned0600 capture is unreadable to runner")
            return original_open(path, mode, *args, **kwargs)

        self.enterContext(patch.object(Path, "lstat", capture_stat))
        self.enterContext(patch.object(Path, "open", capture_open))
        return owners

    def test_root_owned_capture_transferred_and_runner_read_is_verified(self):
        path = self.root / "perf.data"
        path.write_bytes(b"partial sample data")
        owners = self.capture_permissions()
        owners[path] = (0, 0)
        self.assertEqual(path.lstat().st_uid, 0)
        self.assertEqual(stat.S_IMODE(path.lstat().st_mode), 0o600)
        with self.assertRaises(PermissionError):
            path.read_bytes()
        untouched = self.root / "unrelated"
        untouched.write_bytes(b"preserve")

        def chown(argv, **kwargs):
            self.assertEqual(argv[-5:], ["chown", "--no-dereference", "--", "1001:1002", str(path)])
            self.assertLess(argv.index("sudo"), argv.index("--as=536870912:536870912"))
            self.assertEqual(kwargs["timeout"], 15)
            owners[path] = (1001, 1002)
            return 0

        state = {}
        with patch("core_cost_probe.run_owned", side_effect=chown), \
                (self.root / "transfer.log").open("xb") as log:
            probe.capture_access(self.root, 1001, 1002, log, state)
        self.assertTrue(state["readable"])
        self.assertEqual(state["owner_before"], 0)
        self.assertEqual(state["owner_after"], 1001)
        self.assertEqual(path.read_bytes(), b"partial sample data")
        self.assertEqual(untouched.read_bytes(), b"preserve")

    def test_success_status_without_runner_readability_is_refused(self):
        path = self.root / "perf.data"
        path.write_bytes(b"partial")
        owners = self.capture_permissions()
        owners[path] = (0, 0)
        with patch("core_cost_probe.run_owned", return_value=0), \
                (self.root / "transfer.log").open("xb") as log:
            with self.assertRaisesRegex(ValueError, "identity/ownership"):
                probe.capture_access(self.root, 1001, 1002, log, {})

    def test_unexpected_capture_is_never_privileged_or_modified(self):
        path = self.root / "perf.data"
        path.write_bytes(b"preserve")
        info = path.lstat()
        for mode, links, owner in ((stat.S_IFLNK, 1, 0), (stat.S_IFREG, 2, 0), (stat.S_IFREG, 1, 7000)):
            values = list(info)
            values[0], values[3], values[4] = mode | 0o600, links, owner
            with self.subTest(mode=mode, links=links, owner=owner), \
                    patch.object(Path, "lstat", return_value=os.stat_result(values)), \
                    patch("core_cost_probe.run_owned") as run, \
                    (self.root / "guard.log").open("ab") as log:
                with self.assertRaisesRegex(ValueError, "unexpected capture"):
                    probe.capture_access(self.root, 1001, 1002, log, {})
                run.assert_not_called()
        self.assertEqual(path.read_bytes(), b"preserve")

    def test_settled_timeout_hands_off_partial_capture_and_preserves_timeout(self):
        path = self.root / "perf.data"
        path.write_bytes(b"partial after timeout")
        owners = self.capture_permissions()
        owners[path] = (0, 0)
        events = []
        error = subprocess.TimeoutExpired("synthetic recorder", 70)

        def launch(argv, **kwargs):
            if "chown" in argv:
                events.append("handoff")
                self.assertEqual(events, ["recorder reaped", "worker cleanup", "handoff"])
                owners[path] = (1001, 1002)
                return 0
            events.append("recorder reaped")
            raise error  # run_owned's successful cleanup leaves no unresolved flag.

        record = {"command": ["synthetic recorder"]}
        with patch("core_cost_probe.run_owned", side_effect=launch), \
                patch("core_cost_probe.cleanup_group", side_effect=lambda _: events.append("worker cleanup")), \
                (self.root / "perf-command.log").open("xb") as log:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                probe.execute_phase(self.root, record, 8, 1001, 1002, log)
        self.assertIs(raised.exception, error)
        self.assertTrue(probe.load(self.root / "capture-access.json")["readable"])
        self.assertEqual(path.read_bytes(), b"partial after timeout")

    def test_all_three_executed_readouts_have_post_elevation_as_bound(self):
        calls = []

        def readout(argv, **kwargs):
            calls.append((argv, kwargs))
            kwargs["stdout"].write(b"retained text; CPU mode/throttling unknown\n")
            return 0

        with patch("core_cost_probe.run_owned", side_effect=readout), \
                (self.root / "perf-command.log").open("xb") as log:
            result = probe.reports(self.root, [{"pid": 123}], log)
        self.assertEqual(calls[0][0], ["perf", "--version"])
        self.assertEqual(calls[0][1]["timeout"], 5)
        self.assertEqual(len(calls), 4)
        for argv, kwargs in calls[1:]:
            self.assertEqual(argv[:4], ["sudo", "-n", "--", "prlimit"])
            self.assertLess(argv.index("prlimit"), argv.index("--as=536870912:536870912"))
            self.assertLess(argv.index("--as=536870912:536870912"), argv.index("perf"))
            self.assertIn("--fsize=", " ".join(argv))
            self.assertTrue(kwargs["elevated"])
        flat, kwargs = calls[1]
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(flat[flat.index("--kill-after=5") + 1], "25")
        self.assertIn("--no-children", flat)
        self.assertIn("--no-inline", flat)
        self.assertEqual(result["flat"]["address_space_limit_bytes"], 512 * probe.MIB)
        self.assertTrue(result["flat"]["available"])

    def test_local_flat_timeout_preserves_cleanup_metadata_and_stops_readouts(self):
        error = subprocess.TimeoutExpired("owned flat report", 30)
        error.cleanup_unresolved = True

        def readout(argv, **kwargs):
            if argv == ["perf", "--version"]:
                return 0
            raise error

        with patch("core_cost_probe.run_owned", side_effect=readout) as run, \
                (self.root / "perf-command.log").open("xb") as log:
            with self.assertRaisesRegex(RuntimeError, "cleanup unresolved"):
                probe.reports(self.root, [{"pid": 123}], log)
        self.assertEqual(run.call_count, 2)
        state = probe.load(self.root / "flat-status.json")
        self.assertTrue(state["deadline_exceeded"])
        self.assertTrue(state["cleanup_unresolved"])
        self.assertFalse(state["available"])

    def controller_fixture(self, fail=False, partial_phase=None, transfer_refused=False):
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
        owners = self.capture_permissions()
        self.capture_owners = owners

        def launch(argv, **kwargs):
            if "chown" in argv:
                if transfer_refused:
                    return 71
                owners[Path(argv[-1])] = (1001, 1002)
                return 0
            phase = int(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("CORE_COST_PHASE=")))
            name, security, count = probe.PLAN[phase]
            calls.append(name)
            if fail:
                return 77
            if partial_phase == phase:
                path = output / name / "perf.data"
                path.write_bytes(b"partial nonzero-return capture")
                owners[path] = (0, 0)
                return 77
            for i in range(count):
                probe.save_new(output / name / f"bench-{i}.json",
                               {"pid": 20000 + 8 * phase + i, "complete": True, "security": security})
            if count == 8:
                path = output / name / "perf.data"
                path.write_bytes(b"synthetic capture, not a profile")
                owners[path] = (0, 0)
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
        original_digest = probe.digest
        self.enterContext(patch("core_cost_probe.digest", side_effect=lambda path:
            original_digest(path) if Path(path).is_relative_to(self.root) else "c" * 64))
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
        self.assertTrue(state["review"]["status"].startswith("inconclusive"))
        self.assertIn("unknown", state["review"]["evidence_limits"])
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", build.call_args.args[2])
        self.assertEqual(build.call_args.args[2]["RUSTFLAGS"], probe.FLAGS["RUSTFLAGS"])
        index = json.loads((output / "index.json").read_bytes())
        self.assertTrue(index["index_excludes_itself"])
        self.assertNotIn("index.json", [row["path"] for row in index["files"]])
        for row in index["files"]:
            data = (output / row["path"]).read_bytes()
            self.assertEqual(row["bytes"], len(data), row["path"])
            self.assertEqual(row["sha256"], hashlib.sha256(data).hexdigest(), row["path"])
        self.assertEqual(index["bytes_before_index"], sum(row["bytes"] for row in index["files"]))

    def test_controller_retains_refusal_and_never_replaces_the_phase(self):
        output, lane, calls, _ = self.controller_fixture(fail=True)
        with self.assertRaises(FileNotFoundError):
            probe.run(output, lane)
        self.assertEqual(calls, ["u-before"])
        self.assertFalse(probe.load(output / "summary.json")["complete"])
        self.assertEqual(probe.load(output / "u-before/phase.json")["returncode"], 77)
        self.assertTrue((output / "index.json").exists())

    def test_partial_nonzero_capture_is_handed_off_before_failure_inventory(self):
        output, lane, calls, _ = self.controller_fixture(partial_phase=2)
        with self.assertRaises(FileNotFoundError):
            probe.run(output, lane)
        self.assertEqual(calls, ["u-before", "os-before", "u-profile"])
        path = output / "u-profile/perf.data"
        self.assertEqual(self.capture_owners[path], (1001, 1002))
        self.assertEqual(path.read_bytes(), b"partial nonzero-return capture")
        self.assertTrue(probe.load(output / "u-profile/capture-access.json")["readable"])
        self.assertEqual(probe.load(output / "u-profile/phase.json")["returncode"], 77)
        self.assertTrue((output / "index.json").exists())

    def test_transfer_refusal_stops_campaign_and_retains_primary_error(self):
        output, lane, calls, _ = self.controller_fixture(transfer_refused=True)
        with self.assertRaisesRegex(PermissionError, "ownership transfer refused"):
            probe.run(output, lane)
        self.assertEqual(calls, ["u-before", "os-before", "u-profile"])
        access = probe.load(output / "u-profile/capture-access.json")
        self.assertFalse(access["readable"])
        self.assertEqual(access["returncode"], 71)
        self.assertEqual(self.capture_owners[output / "u-profile/perf.data"], (0, 0))
        summary = probe.load(output / "summary.json")
        self.assertEqual(summary["error"], "PermissionError")
        self.assertIn("ownership transfer refused", summary["reason"])
        self.assertFalse((output / "index.json").exists())
        self.assertTrue((output / "index-error.json").exists())

    def test_cleanup_failure_remains_primary_if_handoff_and_inventory_also_fail(self):
        output, lane, calls, _ = self.controller_fixture(transfer_refused=True)
        error = RuntimeError("cleanup unresolved: owned worker remains")
        def unresolved(marker):
            if marker.parent.name == "u-profile":
                raise error

        with patch("core_cost_probe.cleanup_group", side_effect=unresolved):
            with self.assertRaises(RuntimeError) as raised:
                probe.run(output, lane)
        self.assertIs(raised.exception, error)
        self.assertEqual(calls, ["u-before", "os-before", "u-profile"])
        self.assertTrue(probe.load(output / "summary.json")["cleanup_unresolved"])
        self.assertTrue(any("ownership transfer refused" in note for note in error.__notes__))
        self.assertEqual(probe.load(output / "u-profile/capture-access.json")["returncode"], 71)

    def test_unsettled_recorder_prevents_any_capture_handoff(self):
        error = RuntimeError("cleanup unresolved: recorder remains")
        record = {"command": ["synthetic recorder"]}
        with patch("core_cost_probe.run_owned", side_effect=error), \
                patch("core_cost_probe.cleanup_group"), patch("core_cost_probe.capture_access") as access, \
                (self.root / "perf-command.log").open("xb") as log:
            with self.assertRaises(RuntimeError) as raised:
                probe.execute_phase(self.root, record, 8, 1001, 1002, log)
        self.assertIs(raised.exception, error)
        access.assert_not_called()
        self.assertFalse(probe.load(self.root / "capture-access.json")["recorder_settled"])

    def test_workflow_is_manual_serial_and_retains_failure_without_installs(self):
        workflow = (Path(probe.__file__).resolve().parents[2] / ".github/workflows/core-cost-probe.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("group: manual-linux-cpu", workflow)
        self.assertIn("timeout-minutes: 25", workflow)
        self.assertIn("if: always()", workflow)
        self.assertIn("retention-days: 14", workflow)
        self.assertNotIn("pip install", "\n".join(line for line in workflow.splitlines() if not line.lstrip().startswith("#")))
        self.assertNotIn("apt-get", workflow)


class BatchProbeTests(unittest.TestCase):
    setUp = ProbeTests.setUp
    worker_fixture = ProbeTests.worker_fixture
    controller_fixture = ProbeTests.controller_fixture
    capture_permissions = ProbeTests.capture_permissions

    @staticmethod
    def receipt():
        return dict(complete=True, returncode=0, cleanup_settled=True, child_cleanup_settled=True,
                    operations=50000, warmup=128, security="unprotected")

    @staticmethod
    def native(security="unprotected"):
        return dict(event="complete", mode="server-app-batch-cpu", security=security,
                    operations=50000, warmup=128, verified=50128, work_batches=1,
                    batch_operations=50000, empty_gates=16, internal_datagrams=100256,
                    udp_datagrams=0, black_box=True)

    @staticmethod
    def fixture(security="unprotected"):
        return dict(event="fixture", security=security, requested_bytes=28_443_568, row_bytes=568,
                    row_metadata_bytes=56, request_ref_bytes=16, optional_request_ref_bytes=17,
                    wire_bytes=25_600_000, capture_datagram_bytes=256, app_datagram_bytes=1472, app_heap_bytes=16000, app_inline_bytes=9600,
                    fixture_inline_bytes=1584, scratch_allowance_bytes=16384, rows=50000, limit_bytes=32 * probe.MIB)

    @staticmethod
    def evidence(security="unprotected"):
        # Exercise the installed process_clock_delta; its ownership/ABI fault
        # coverage remains in test_linux_cpu rather than duplicating that API.
        base = dict(available=True, pid=222, parent_pid=12345, start_ticks=99, group=222,
                    session=222, clock_id=-123, glibc="2.39", reported_resolution_seconds=1e-9)
        windows = []
        for kind, count in (("empty", 16), ("work", 1)):
            for block in range(count):
                before = dict(base, cpu_time_ns=1_000_000, snapshot_started_ns=1, snapshot_finished_ns=2)
                after = dict(base, cpu_time_ns=1_000_000 + (10_000 if kind == "empty" else 20_000_000),
                             snapshot_started_ns=3, snapshot_finished_ns=4)
                windows.append(dict(kind=kind, block=block, before=before, after=after))
        return dict(native=BatchProbeTests.native(security), windows=windows, fixture=BatchProbeTests.fixture(security))

    def test_opt_in_plan_perf_off_and_static_storage_budget(self):
        self.assertEqual([security for _, security, _ in probe.BATCH_PLAN],
                         ["unprotected", "oscore", "oscore", "unprotected"])
        self.assertEqual([count for _, _, count in probe.BATCH_PLAN], [1] * 4)
        self.assertEqual(4 * (probe.OPERATIONS + probe.WARMUP), 200512)
        self.assertEqual(8 * (probe.OPERATIONS + probe.WARMUP), 401024)
        self.assertEqual(probe.WORK_BATCHES * probe.BATCH_OPERATIONS, probe.OPERATIONS)
        self.assertEqual(probe.CORE, "ff08926422d570602069d2231a555559d1154f3f")
        self.assertEqual(probe.BATCH_CORE, "b9b83d8663cbdcb7a80bf143670a05019f25cf25")
        for phase in range(4):
            argv = probe.phase_command(self.root, phase, 1001, 1002, batch_cpu=True)
            self.assertNotIn("perf", argv)
            self.assertIn("CORE_COST_BATCH_CPU=1", argv)
            self.assertIn("--as=536870912:536870912", argv)
            self.assertIn("--fsize=32768:32768", argv)
            self.assertIn("--bounding-set=-all", argv)
        phase_files = ("perf-command.log", "bench-0.jsonlog", "bench-stderr.log", "cpu-windows.json",
                       "bench-0.json", "worker.json", "owned-child.json", "launch-intent.json", "phase.json")
        root_files = set(probe.BATCH_LIMITS) - set(phase_files) - {"bench-core"}
        bound = sum(probe.BATCH_LIMITS[name] for name in root_files)
        bound += 4 * sum(probe.BATCH_LIMITS[name] for name in phase_files) + probe.META  # workflow test log
        self.assertLessEqual(bound, probe.MIB)
        self.assertLessEqual(len(root_files) + 4 * len(phase_files) + 2, 100)
        self.assertLessEqual(bound + probe.ELF, 65 * probe.MIB)
        workflow = (Path(probe.__file__).resolve().parents[2] / ".github/workflows/core-cost-probe.yml").read_text()
        self.assertIn("default: original", workflow)
        self.assertIn("- server-app-batch-cpu", workflow)
        self.assertIn(probe.CORE, workflow)
        self.assertIn(probe.BATCH_CORE, workflow)
        self.assertIn("core_cost_probe.py --batch-cpu", workflow)

    def test_fixture_and_complete_receipts_refuse_partial_or_inconsistent_counts(self):
        probe.validate_fixture(self.fixture(), "unprotected")
        probe.validate_batch_complete(self.native(), "unprotected")
        for key, value in (("row_metadata_bytes", 65), ("requested_bytes", 32 * probe.MIB),
                           ("request_ref_bytes", 100), ("rows", True), ("wire_bytes", 10),
                           ("capture_datagram_bytes", 1472), ("app_datagram_bytes", 256)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_fixture(dict(self.fixture(), **{key: value}), "unprotected")
        for key, value in (("verified", 50000), ("operations", True), ("internal_datagrams", 100257),
                           ("security", "oscore"), ("black_box", False), ("udp_datagrams", 1)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                probe.validate_batch_complete(dict(self.native(), **{key: value}), "unprotected")

    def test_interpret_only_complete_verified_exit_and_settled_cleanup(self):
        receipt = self.receipt()
        result = probe.batch_interpret(self.evidence(), receipt)
        self.assertTrue(result["available"])
        self.assertEqual(result["summed_cpu_ns"], 20_000_000)
        self.assertEqual(result["ns_per_verified_operation"], 400)
        self.assertFalse(result["calibration_subtracted"])
        self.assertIn("server-App driver CPU window", result["scope"])
        for changes in (dict(complete=False), dict(returncode=7), dict(cleanup_settled=False)):
            result = probe.batch_interpret(self.evidence(), dict(receipt, **changes))
            self.assertFalse(result["available"])
            self.assertNotIn("ns_per_verified_operation", result)

    def test_clock_faults_and_fixed_minimums_stay_inconclusive_without_fallback(self):
        receipt = self.receipt()
        faults = [dict(available=False), dict(cpu_time_ns=999999), dict(pid=223),
                  dict(snapshot_started_ns=0), dict(cpu_time_ns=1_000_000 + 9_999_999),
                  dict(reported_resolution_seconds=.001)]
        for changes in faults:
            evidence = self.evidence()
            evidence["windows"][-1]["after"].update(changes)
            if "reported_resolution_seconds" in changes:
                evidence["windows"][-1]["before"].update(changes)
            with self.subTest(changes=changes):
                result = probe.batch_interpret(evidence, receipt)
                self.assertFalse(result["available"])
                self.assertTrue(result["failed_conditions"])
                self.assertNotIn("ns_per_verified_operation", result)
        evidence = self.evidence()
        evidence["windows"][0]["after"]["cpu_time_ns"] += 200_001
        result = probe.batch_interpret(evidence, receipt)
        self.assertIn("largest empty gate", result["failed_conditions"][0])
        self.assertNotIn("summed_cpu_ns", result)
        evidence["windows"].pop()
        with self.assertRaises(ValueError):
            probe.batch_interpret(evidence, receipt)

    def dialogue_values(self):
        values, verified = [self.fixture()], 128
        for kind, count in (("empty", 16), ("work", 1)):
            for block in range(count):
                values.append(dict(event="ready", kind=kind, block=block, verified=verified))
                values.append(dict(event="measured", kind=kind, block=block, verified=verified))
                verified += 50000 if kind == "work" else 0
                values.append(dict(event="verified", kind=kind, block=block, verified=verified))
        return values + [self.native()]

    def dialogue_fixture(self, values=None):
        child = SimpleNamespace(pid=222, args=["synthetic"], stdin=io.BytesIO(), stdout=SimpleNamespace(fileno=lambda: 88),
                                wait=Mock(return_value=0))
        timeline = []
        values = iter(self.dialogue_values() if values is None else values)
        def read(*args):
            value = next(values)
            timeline.append(value["event"])
            return value
        def send(child, value):
            timeline.append(value.decode().strip())
        clock = Mock(status=dict(available=True))
        clock.snapshot.side_effect = lambda: timeline.append("cpu") or dict(available=False)
        self.enterContext(patch("core_cost_probe.batch_read", side_effect=read))
        self.enterContext(patch("core_cost_probe.batch_send", side_effect=send))
        self.enterContext(patch("core_cost_probe.ProcessCpuClock", return_value=clock))
        self.enterContext(patch("core_cost_probe.select.select", return_value=([child.stdout], [], [])))
        self.enterContext(patch("core_cost_probe.os.read", return_value=b""))
        return child, timeline

    def test_gate_order_all_windows_verify_after_cpu_and_no_clock_poll_reap(self):
        child, timeline = self.dialogue_fixture()
        evidence = dict(windows=[])
        self.assertIsNone(probe.batch_dialogue(child, "unprotected", probe.time.monotonic() + 5,
                                              io.BytesIO(), evidence))
        self.assertEqual(len(evidence["windows"]), 17)
        self.assertEqual(timeline[:2], ["start", "fixture"])
        expected = ["ready", "cpu", "run", "measured", "cpu", "verify", "verified"]
        self.assertEqual(timeline[2:-2], expected * 17)
        self.assertEqual(timeline[-2:], ["complete", "exit"])
        child.wait.assert_not_called()  # Only the reserved lifetime reaps after the dialogue.

    def test_wrong_gate_or_failed_verification_aborts_before_later_work(self):
        values = self.dialogue_values()
        values[3] = dict(values[3], event="failed-authentication")
        child, timeline = self.dialogue_fixture(values)
        with self.assertRaisesRegex(ValueError, "gate order"):
            probe.batch_dialogue(child, "unprotected", probe.time.monotonic() + 5, io.BytesIO(), dict(windows=[]))
        self.assertNotIn("exit", timeline)
        child.wait.assert_not_called()

    def test_control_read_refuses_eof_partial_oversize_timeout_and_bad_json(self):
        child = SimpleNamespace(stdout=SimpleNamespace(fileno=lambda: 88))
        cases = [(b"", EOFError), (b'{"event":', EOFError), (b"x" * 2048, ValueError), (b"bad\n", ValueError)]
        for raw, error in cases:
            parts = iter(bytes([byte]) for byte in raw)
            with self.subTest(raw=raw[:20]), patch("core_cost_probe.select.select", return_value=([88], [], [])), \
                    patch("core_cost_probe.os.read", side_effect=lambda *args: next(parts, b"")), self.assertRaises(error):
                probe.batch_read(child, probe.time.monotonic() + 1, io.BytesIO())
        with patch("core_cost_probe.select.select", return_value=([], [], [])), self.assertRaises(TimeoutError):
            probe.batch_read(child, probe.time.monotonic() + 1, io.BytesIO())

    def test_worker_uses_owned_spawn_registration_and_preserves_primary_on_cleanup_failure(self):
        # Reuse credential, resource, clock and launch guards from the old worker fixture.
        old, _ = ProbeTests.worker_fixture(self, phase=0)
        directory = self.root / probe.BATCH_PLAN[0][0]
        old.rename(directory)
        child = SimpleNamespace(pid=222, stdin=io.BytesIO(), stdout=io.BytesIO())
        custody = dict(pid=222, pgrp=222, session=222, starttime=91)
        def launch(*args, **kwargs):
            self.assertTrue((directory / "worker.json").exists())
            self.assertTrue((directory / "launch-intent.json").exists())
            self.assertEqual(args[0][-1], "--batch-cpu")
            self.assertNotIn("start_new_session", kwargs)  # spawn owns session creation.
            self.assertEqual(kwargs["file_limit"], 8192)
            return child
        def dialogue(*args):
            self.assertTrue((directory / "owned-child.json").exists())
            raise EOFError("original verification failure")
        lifetime = Mock()
        lifetime.stop.side_effect = RuntimeError("cleanup failed")
        with patch("core_cost_probe.spawn", side_effect=launch), \
                patch("core_cost_probe.batch_pidfds_required"), \
                patch("core_cost_probe.proc_identity", side_effect=lambda pid: OWNED.copy() if pid == OWNED["pid"] else custody), \
                patch("core_cost_probe.batch_dialogue", side_effect=dialogue), \
                patch("core_cost_probe.BatchLifetime", return_value=lifetime):
            with self.assertRaisesRegex(EOFError, "original verification") as raised:
                probe.batch_worker(self.root, 0)
        self.assertTrue(child.stdin.closed)
        self.assertTrue(raised.exception.cleanup_unresolved)
        receipt = probe.load(directory / "bench-0.json")
        self.assertFalse(receipt["complete"])
        self.assertTrue(receipt["cleanup_unresolved"])
        self.assertNotIn("whole_process_cpu_ns_per_verified_exchange", receipt)
        self.assertTrue((directory / "cpu-windows.json").exists())

    def test_worker_death_before_and_after_registration_cannot_certify_survivors(self):
        directory = self.root / "batch-u-before"
        directory.mkdir()
        probe.save_batch(directory / "worker.json", OWNED)
        probe.save_batch(directory / "launch-intent.json", dict(parent_pid=OWNED["pid"]))
        with patch("core_cost_probe.batch_cleanup_marker") as cleanup:
            with self.assertRaisesRegex(RuntimeError, "during child registration"):
                probe.cleanup_batch(directory, False)
            cleanup.assert_called_once_with(directory / "worker.json")
        probe.save_batch(directory / "owned-child.json", dict(pid=222, pgrp=222, session=222,
                         starttime=91, parent_pid=OWNED["pid"], phase=directory.name))
        with patch("core_cost_probe.batch_cleanup_marker") as cleanup:
            probe.cleanup_batch(directory, False)
            self.assertEqual([call.args[0].name for call in cleanup.call_args_list], ["worker.json", "owned-child.json"])
        original = RuntimeError("cleanup unresolved: worker survives")
        with patch("core_cost_probe.batch_cleanup_marker", side_effect=[original, RuntimeError("child survives")]) as cleanup:
            with self.assertRaises(RuntimeError) as raised:
                probe.cleanup_batch(directory, False)
            self.assertIs(raised.exception, original)
            self.assertEqual(cleanup.call_count, 2)
            self.assertTrue(original.cleanup_unresolved)
            self.assertIn("child survives", original.__notes__[0])

    def test_batch_evidence_rejects_old_perf_quotas_and_keeps_original_inventory(self):
        (self.root / "perf.data").write_bytes(b"old perf evidence")
        probe.inventory(self.root)
        with self.assertRaises(KeyError):
            probe.inventory(self.root, batch_cpu=True)

    def test_controller_runs_exact_four_process_cohort_and_withholds_until_settled(self):
        output, lane, calls, build = self.controller_fixture()
        def launch(argv, **kwargs):
            phase = int(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("CORE_COST_PHASE=")))
            name, security, _ = probe.BATCH_PLAN[phase]
            calls.append(name)
            receipt = dict(self.receipt(), security=security, pid=222 + phase)
            receipt.pop("cleanup_settled")  # Only the controller may add outer group settlement.
            probe.save_batch(output / name / "bench-0.json", receipt)
            probe.save_batch(output / name / "cpu-windows.json", self.evidence(security))
            return 0
        with patch("core_cost_probe.batch_run_command", side_effect=launch), \
                patch("core_cost_probe.identity", side_effect=lambda path:
                    dict(revision=probe.BATCH_CORE if path == probe.SUITE / "coaptic" else "b" * 40, status="")), \
                patch("core_cost_probe.reports", side_effect=AssertionError("perf forbidden")):
            probe.run(output, lane, batch_cpu=True)
        self.assertEqual(calls, [name for name, _, _ in probe.BATCH_PLAN])
        self.assertEqual(build.call_args.args[2]["CORE_COST_BATCH_CPU"], "1")
        summary = probe.load(output / "summary.json")
        self.assertEqual(summary["budget"]["complete_exchanges"], 200512)
        self.assertEqual(summary["budget"]["maximum_live_benchmarks"], 1)
        self.assertTrue(summary["complete"])
        self.assertEqual(len(summary["server_app_driver_cpu"]), 4)
        self.assertTrue(all(item["available"] for item in summary["server_app_driver_cpu"]))
        self.assertEqual(summary["review"]["both_50_percent_targets"], "OPEN")
        self.assertFalse(summary["review"]["performance_acceptance"])

    def test_outer_cleanup_failure_blocks_interpretation_and_later_workers(self):
        output, lane, calls, _ = self.controller_fixture()
        error = RuntimeError("cleanup unresolved: registered child remains")
        with patch("core_cost_probe.identity", side_effect=lambda path:
                    dict(revision=probe.BATCH_CORE if path == probe.SUITE / "coaptic" else "b" * 40, status="")), \
                patch("core_cost_probe.batch_run_command", side_effect=lambda argv, **kwargs: calls.append(argv) or 0), \
                patch("core_cost_probe.cleanup_batch", side_effect=error), \
                patch("core_cost_probe.batch_interpret", side_effect=AssertionError("interpretation forbidden")):
            with self.assertRaises(RuntimeError) as raised:
                probe.run(output, lane, batch_cpu=True)
        self.assertIs(raised.exception, error)
        self.assertEqual(len(calls), 1)
        summary = probe.load(output / "summary.json")
        self.assertFalse(summary["complete"])
        self.assertTrue(summary["cleanup_unresolved"])
        self.assertNotIn("server_app_driver_cpu", summary)


class BatchOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.batch_command = probe.batch_run_command
        ProbeTests.setUp(self)
    worker_fixture = ProbeTests.worker_fixture

    def pidfds(self):
        self.enterContext(patch("core_cost_probe.os.pidfd_open", return_value=57, create=True))
        send = self.enterContext(patch("core_cost_probe.signal.pidfd_send_signal", create=True))
        self.enterContext(patch("core_cost_probe.signal.SIGCHLD", 17, create=True))
        self.enterContext(patch("core_cost_probe.signal.getsignal", return_value=probe.signal.SIG_DFL))
        close = self.enterContext(patch("core_cost_probe.os.close"))
        numeric = self.enterContext(patch("core_cost_probe.os.killpg", side_effect=AssertionError("numeric group signal forbidden"), create=True))
        process = Mock(pid=222, returncode=None)
        def wait(**kwargs):
            process.returncode = 0
            return 0
        process.wait.side_effect = wait
        return probe.OwnedProcess(process), send, close, numeric

    def test_reaped_child_and_reused_group_never_authorize_a_signal(self):
        child, send, close, numeric = self.pidfds()
        lifetime = probe.BatchLifetime(child)
        self.assertEqual(lifetime.wait(1), 0)
        # A new unrelated group can now own the old number; no query or signal.
        with patch("core_cost_probe.proc_identity", side_effect=AssertionError("stale PID consulted")):
            lifetime.stop()
        lifetime.close()
        send.assert_not_called()
        numeric.assert_not_called()
        close.assert_called_once_with(57)

    def test_unexpected_external_reap_is_fatal_without_signaling(self):
        child, send, _, numeric = self.pidfds()
        lifetime = probe.BatchLifetime(child)
        child.process.returncode = 0
        with self.assertRaisesRegex(RuntimeError, "reaped outside"):
            lifetime.stop()
        with self.assertRaisesRegex(RuntimeError, "unreaped owned"):
            probe.BatchLifetime(child)
        lifetime.close()
        send.assert_not_called()
        numeric.assert_not_called()

    def test_all_stop_signals_use_reserved_fd_and_finish_before_reap(self):
        child, send, _, numeric = self.pidfds()
        lifetime = probe.BatchLifetime(child)
        timeline = []
        send.side_effect = lambda fd, sig: timeline.append((fd, sig))
        child.process.wait.side_effect = lambda **kwargs: timeline.append("reap") or 0
        with patch("core_cost_probe.select.select", side_effect=[([], [], []), ([], [], []),
                     ([], [], []), ([57], [], [])]):
            lifetime.stop()
        lifetime.stop()
        self.assertEqual(timeline, [(57, probe.signal.SIGTERM), (57, probe.signal.SIGKILL), "reap"])
        numeric.assert_not_called()
        lifetime.close()

    def test_settled_worker_never_reopens_recycled_pid_markers(self):
        _, send, _, numeric = self.pidfds()
        probe.save_batch(self.root / "bench-0.json", dict(child_cleanup_settled=True))
        probe.save_batch(self.root / "worker.json", OWNED)
        probe.save_batch(self.root / "owned-child.json", dict(OWNED, pid=222))
        with patch("core_cost_probe.proc_identity", side_effect=AssertionError("recycled PID read")), \
                patch("core_cost_probe.batch_cleanup_marker", side_effect=AssertionError("stale marker cleanup")):
            probe.cleanup_batch(self.root, True)
        send.assert_not_called()
        numeric.assert_not_called()

    def test_live_marker_identity_checks_bracket_pidfd_acquisition(self):
        _, send, close, numeric = self.pidfds()
        marker = self.root / "worker.json"
        probe.save_batch(marker, OWNED)
        changed = dict(OWNED, starttime=1)
        with patch("core_cost_probe.proc_identity", return_value=changed), \
                patch("core_cost_probe.os.pidfd_open", create=True) as opened:
            with self.assertRaisesRegex(RuntimeError, "identity changed"):
                probe.batch_cleanup_marker(marker)
            opened.assert_not_called()
        with patch("core_cost_probe.proc_identity", side_effect=[OWNED, changed]):
            with self.assertRaisesRegex(RuntimeError, "during pidfd acquisition"):
                probe.batch_cleanup_marker(marker)
        close.assert_called_once_with(57)
        send.assert_not_called()
        numeric.assert_not_called()

    def test_marker_stop_uses_only_fd_and_does_not_signal_exited_leader(self):
        _, send, _, numeric = self.pidfds()
        marker = self.root / "owned-child.json"
        probe.save_batch(marker, dict(pid=222, pgrp=222, session=222, starttime=91))
        expected = probe.load(marker)
        with patch("core_cost_probe.proc_identity", return_value=expected), \
                patch("core_cost_probe.select.select", return_value=([57], [], [])):
            probe.batch_cleanup_marker(marker)
        send.assert_not_called()
        numeric.assert_not_called()

    def test_unavailable_pidfds_refuse_before_any_phase_child(self):
        with patch("core_cost_probe.os.pidfd_open", None, create=True), self.assertRaisesRegex(RuntimeError, "pidfd APIs"):
            self.batch_command(["never-executed"], timeout=1)
        probe.spawn.assert_not_called()

    def test_successful_phase_wrapper_never_calls_generic_post_reap_stop(self):
        child, send, _, numeric = self.pidfds()
        with patch("core_cost_probe.spawn", return_value=child):
            self.assertEqual(self.batch_command(["synthetic"], timeout=20), 0)
        send.assert_not_called()
        numeric.assert_not_called()
        probe.run_owned.assert_not_called()

    def test_phase_timeout_keeps_primary_and_independent_handle_close(self):
        child, _, _, _ = self.pidfds()
        original = subprocess.TimeoutExpired("fixed batch wrapper", 20)
        lifetime = Mock()
        lifetime.wait.side_effect = original
        lifetime.stop.side_effect = PermissionError("pidfd signal denied")
        with patch("core_cost_probe.spawn", return_value=child), \
                patch("core_cost_probe.BatchLifetime", return_value=lifetime):
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                self.batch_command(["synthetic"], timeout=20)
        self.assertIs(raised.exception, original)
        self.assertTrue(original.cleanup_unresolved)
        self.assertIn("pidfd signal denied", original.__notes__[0])
        lifetime.close.assert_called_once()

    def test_pipe_close_failure_still_stops_original_process_and_closes_handles(self):
        child = SimpleNamespace(stdin=Mock(closed=False), stdout=Mock())
        original = BrokenPipeError("EOF close failed")
        child.stdin.close.side_effect = original
        lifetime = Mock()
        lifetime.stop.side_effect = RuntimeError("native process unresolved")
        with self.assertRaises(BrokenPipeError) as raised:
            probe.batch_release_child(child, lifetime)
        self.assertIs(raised.exception, original)
        self.assertTrue(original.cleanup_unresolved)
        self.assertIn("native process unresolved", original.__notes__[0])
        lifetime.stop.assert_called_once()
        lifetime.close.assert_called_once()
        child.stdout.close.assert_called_once()

    def test_batch_success_retains_lifetime_scope_and_original_default(self):
        old, _ = self.worker_fixture(phase=0)
        directory = self.root / probe.BATCH_PLAN[0][0]
        old.rename(directory)
        child = SimpleNamespace(pid=222, stdin=io.BytesIO(), stdout=io.BytesIO())
        custody = dict(pid=222, pgrp=222, session=222, starttime=91)
        with patch("core_cost_probe.spawn", return_value=child), \
                patch("core_cost_probe.batch_pidfds_required"), \
                patch("core_cost_probe.BatchLifetime") as lifetime, \
                patch("core_cost_probe.proc_identity", side_effect=lambda pid: OWNED.copy() if pid == OWNED["pid"] else custody), \
                patch("core_cost_probe.batch_dialogue"), patch("core_cost_probe.batch_finish", return_value=0):
            probe.batch_worker(self.root, 0)
        receipt = probe.load(directory / "bench-0.json")
        self.assertTrue(receipt["complete"])
        self.assertEqual(receipt["scope"], probe.BATCH_LIFETIME_SCOPE)
        self.assertNotIn("calibration", receipt["scope"])
        self.assertEqual(probe.cpu_receipt(USAGE, {key:value*2 for key,value in USAGE.items()})["scope"], probe.SCOPE)
        lifetime.return_value.stop.assert_called_once()
        lifetime.return_value.close.assert_called_once()


@unittest.skipUnless(sys.platform == "linux" and os.environ.get("CORE_COST_BATCH_FAILURE_TEST_BINARY"),
                     "requires explicit existing Linux batch fixture and runtime grant")
class BatchNativeCustodyTests(unittest.TestCase):
    def killed_worker(self, stage):
        # Real separate-session native child, killed worker and closed control
        # pipe: prove EOF before registration as well as registered group sweep.
        from linux_cpu import spawn
        binary = Path(os.environ["CORE_COST_BATCH_FAILURE_TEST_BINARY"]).resolve(strict=True)
        before = probe.digest(binary)
        script = '''
import json, os, signal, subprocess, sys
from pathlib import Path
from core_cost_probe import proc_identity, save_batch
from linux_cpu import spawn
root, binary, stage = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
child = spawn([binary, "50000", "oscore", "--batch-cpu"], file_limit=8192,
              stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
owned = proc_identity(child.pid)
owned.update(parent_pid=os.getpid(), phase="failure-test")
if stage == "after":
    save_batch(root / "owned-child.json", owned)
print(json.dumps(owned), flush=True)
signal.pause()
'''
        with tempfile.TemporaryDirectory() as temporary:
            directory, worker, observed, primary = Path(temporary), None, None, None
            lifetime, native_fd, native_ended = None, None, False
            try:
                worker = spawn([sys.executable, "-B", "-c", script, str(directory), str(binary), stage],
                               file_limit=8192, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env={**os.environ,
                                   "PYTHONPATH": str(Path(probe.__file__).parent)})
                lifetime = probe.BatchLifetime(worker)
                observed = probe.batch_read(worker, probe.time.monotonic() + 5, io.BytesIO())
                self.assertEqual(observed["parent_pid"], worker.pid)
                self.assertEqual(observed["pid"], observed["pgrp"])
                self.assertEqual(observed["pid"], observed["session"])
                self.assertEqual((directory / "owned-child.json").exists(), stage == "after")
                # Observer custody is independent of the production registration
                # marker; it lets the test prove no unregistered survivor.
                probe.save_new(directory / "observer.json", observed)
                native_fd = os.pidfd_open(observed["pid"], 0)
                self.assertEqual(probe.proc_identity(observed["pid"]),
                                 {key: observed[key] for key in ("pid", "pgrp", "session", "starttime")})
                probe.signal.pidfd_send_signal(lifetime.fd, probe.signal.SIGKILL)
                lifetime.wait(2)
                native_ended = bool(probe.select.select([native_fd], [], [], 3)[0])
                self.assertTrue(native_ended, "single native child survived worker death and control EOF")
                self.assertEqual(probe.digest(binary), before)
            except BaseException as error:
                primary = error
                raise
            finally:
                actions = []
                if lifetime is not None:
                    actions.extend((lifetime.stop, lifetime.close))
                if native_fd is not None:
                    if not native_ended:
                        actions.append(lambda: probe.batch_stop_fd(native_fd))
                    actions.append(lambda: os.close(native_fd))
                for cleanup in actions:
                    try:
                        cleanup()
                    except BaseException as error:
                        if primary is None:
                            raise
                        primary.add_note("failure test cleanup: " + str(error)[:512])
                if worker is not None:
                    worker.stdout.close()

    def test_kill_worker_before_child_registration_leaves_no_survivor(self):
        self.killed_worker("before")

    def test_kill_worker_after_child_registration_leaves_no_survivor(self):
        self.killed_worker("after")


if __name__ == "__main__":
    unittest.main()
