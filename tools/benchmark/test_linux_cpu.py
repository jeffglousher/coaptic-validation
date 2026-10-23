"""Portable validation and conservative aggregation checks; no Cargo or perf."""
import argparse
from contextlib import contextmanager
from copy import deepcopy
import io
import itertools
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock, Mock

import linux_cpu as cpu


HOST = "x86_64-unknown-linux-gnu"
RUSTC_VERSION = (f"rustc 1.99.0 (111111111 2026-10-01)\ncommit-hash: {'1' * 40}\n"
                 f"host: {HOST}\nrelease: 1.99.0\nLLVM version: 22.1.0")
CARGO_VERSION = f"cargo 1.99.0 (222222222 2026-10-01)\ncommit-hash: {'2' * 40}\nrelease: 1.99.0"


def options(**overrides):
    values = dict(sizes="64,1024", rates="100,1000", seconds=10,
                  repeats=4, server_kind="coaptic-reusable", perf=True, concurrency=1, message_type="con",
                  candidate_server_kind=None, baseline_sha="a" * 40, candidate_sha="b" * 40)
    values.update(overrides)
    return argparse.Namespace(**values)


def observation(root, label, repeat, *, security="unprotected", size=64, mode="clean",
                concurrency=1, message_type="con"):
    report = dict(completed=1000, achieved_ops_per_second=100,
                  pacing_missed_period_operations=0, latencies_ns=[1000] * 1000,
                  concurrency=concurrency, message_type=message_type, peak_pending=1)
    path = root / f"{label}-{repeat}-{security}-{size}-{mode}-{concurrency}-{message_type}.json"
    cpu.retain_report(path, json.dumps(report), 1000)
    return dict(revision_label=label, repeat=repeat, security=security, bytes=size,
                mode=mode, rate=100, operations=1000, server_kind="coaptic-reusable", passed=True,
                concurrency=concurrency, message_type=message_type,
                report=cpu.report_summary(report), report_file=str(path),
                cpu_cost={who: dict(user_seconds=.8 if label == "baseline" else .4,
                                    system_seconds=.2 if label == "baseline" else .1,
                                    total_seconds=1 if label == "baseline" else .5)
                          for who in ("server", "client")})


def pairs(root):
    return [observation(root, label, repeat) for repeat in range(2)
            for label in ("baseline", "candidate")]


@contextmanager
def mock_record_control(timeline=None):
    """Keep existing report/cleanup tests independent of the real FIFO seam."""
    def opened(capture, directory):
        capture._control_paths = (directory / "ctl", directory / "ack")
    def command(capture, name):
        if timeline is not None:
            timeline.append(name + "_ack")
    with patch.object(cpu.PerfCapture, "_open_control", autospec=True, side_effect=opened), \
            patch.object(cpu.PerfCapture, "_drain_padding"), \
            patch.object(cpu.PerfCapture, "_command", autospec=True, side_effect=command):
        yield


class ValidationTests(unittest.TestCase):
    def test_only_immutable_full_commits(self):
        self.assertEqual(cpu.sha40("A" * 40), "a" * 40)
        for value in ("main", "a" * 39, "g" * 40, "a" * 41, " a" * 20,
                      "a" * 40 + "\n", "$(touch unwanted)"):
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                cpu.sha40(value)

    def test_default_plan_and_finite_campaign_limits(self):
        args = options()
        self.assertEqual(len(cpu.configuration(args)), 8)
        plan = cpu.rotation(args, cpu.configuration(args))
        self.assertEqual(sum(mode == "clean" for mode, *_ in plan), 64)
        self.assertEqual(sum(mode != "clean" for mode, *_ in plan), 32)
        for override in (dict(sizes="32"), dict(sizes="64,64"), dict(rates="0"),
                         dict(rates="100,0100"), dict(rates="100001"),
                         dict(rates="100000", seconds=2), dict(rates="x"),
                         dict(seconds=31), dict(seconds=1), dict(repeats=9),
                         dict(repeats=1), dict(server_kind="all"),
                         dict(seconds=30, rates="1,2,3", repeats=8),
                         dict(rates="10000", seconds=10, repeats=4)):
            with self.subTest(override=override), self.assertRaises((ValueError, argparse.ArgumentTypeError)):
                cpu.configuration(options(**override))
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="2", server_kind="all"))), 6)

    def test_every_clean_and_profile_window_counts_warmup_and_blocks(self):
        for size, rate, seconds, perf, mode in (("65536", "100", 10, False, "clean"),
                                               ("64", "6000", 10, False, "clean"),
                                               ("65536", "200", 2, True, "record")):
            with self.subTest(size=size, rate=rate, mode=mode), self.assertRaisesRegex(ValueError, mode):
                cpu.configuration(options(sizes=size, rates=rate, seconds=seconds, perf=perf))
        # Clean 400-operation windows fit, but five-second profiles do not.
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="200", seconds=2, perf=False))), 2)
        self.assertEqual(len(cpu.configuration(options(sizes="65536", rates="10,50"))), 4)
        for size, rate, seconds in (("1024", "29990", 2), ("65536", "458", 2)):
            self.assertEqual(len(cpu.configuration(options(sizes=size, rates=rate, seconds=seconds,
                                                           repeats=2, perf=False))), 2)

    def test_invalid_profile_plan_fails_before_platform_checks_or_builds(self):
        with patch.object(cpu, "build") as build, self.assertRaisesRegex(ValueError, "record"):
            cpu.run(options(sizes="65536", rates="200", seconds=2))
        build.assert_not_called()

    def test_parser_defaults_match_valid_documented_workload(self):
        args = cpu.argument_parser().parse_args(["--baseline-sha", "a" * 40,
                                                "--candidate-sha", "b" * 40,
                                                "--build-lane", "unused", "--output", "unused"])
        self.assertEqual(args.sizes, "64,1024")
        self.assertIsNone(args.candidate_server_kind)
        cpu.configuration(args)

    def test_adapter_comparison_requires_one_source_and_explicit_distinct_fixtures(self):
        selected = dict(server_kind="coaptic-ready", candidate_server_kind="coaptic-async",
                        baseline_sha="a" * 40, candidate_sha="a" * 40)
        self.assertEqual(cpu.configuration(options(**selected)),
                         cpu.configuration(options(server_kind="coaptic-ready")))
        for change in (dict(candidate_sha="b" * 40), dict(server_kind="all"),
                       dict(candidate_server_kind="coaptic-ready"), dict(candidate_server_kind="unknown")):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "adapter comparison"):
                cpu.configuration(options(**(selected | change)))
        with patch.object(cpu, "build") as build, self.assertRaisesRegex(ValueError, "identical core"):
            cpu.run(options(**(selected | dict(candidate_sha="b" * 40))))
        build.assert_not_called()

    def test_async_fixture_is_explicit_and_does_not_expand_all(self):
        args = options(sizes="64", rates="100", perf=False, server_kind="all")
        cells = cpu.configuration(args)
        self.assertEqual({cell[3] for cell in cells}, set(cpu.KINDS))
        self.assertNotIn("coaptic-async", {cell[3] for cell in cells})
        selected = cpu.configuration(options(sizes="64", rates="100", perf=False, server_kind="coaptic-async"))
        self.assertEqual({cell[3] for cell in selected}, {"coaptic-async"})

    def test_blocking_fixture_is_explicit_and_keeps_same_core_comparison_rules(self):
        args = options(sizes="64", rates="11900", seconds=5, repeats=2,
                       server_kind="coaptic-ready", candidate_server_kind="coaptic-blocking",
                       candidate_sha="a" * 40)
        plan = cpu.rotation(args, cpu.configuration(args))
        self.assertEqual(sum(mode == "clean" for mode, *_ in plan), 8)
        self.assertEqual(sum(mode != "clean" for mode, *_ in plan), 8)
        self.assertEqual(sum(cell[2] * 5 for _, _, cell, _ in plan), 952_000)
        self.assertEqual(max(cpu.WARMUP + cell[2] * 5 for _, _, cell, _ in plan), 59_520)
        self.assertNotIn("coaptic-blocking", cpu.KINDS)
        standalone = cpu.configuration(options(server_kind="coaptic-blocking", perf=False))
        self.assertEqual({cell[3] for cell in standalone}, {"coaptic-blocking"})
        with self.assertRaisesRegex(ValueError, "identical core"):
            cpu.configuration(options(**(vars(args) | dict(candidate_sha="b" * 40))))

    def test_documented_adapter_plan_keeps_existing_budgets(self):
        args = options(sizes="64,1024", rates="4000", seconds=12, repeats=4, perf=False,
                       server_kind="coaptic-ready", candidate_server_kind="coaptic-async",
                       candidate_sha="a" * 40)
        plan = cpu.rotation(args, cpu.configuration(args))
        self.assertEqual(len(plan), 32)
        self.assertEqual(sum(args.seconds for _ in plan), 384)
        self.assertEqual(sum(cell[2] * args.seconds for _, _, cell, _ in plan), 1_536_000)
        self.assertEqual(max(cpu.WARMUP + cell[2] * args.seconds for _, _, cell, _ in plan), 48_020)

    def test_staged_ready_is_explicit_and_its_paired_plan_keeps_existing_budgets(self):
        args = options(sizes="64,1024", rates="4000", seconds=5, repeats=4, perf=False,
                       server_kind="coaptic-ready", candidate_server_kind="coaptic-staged-ready",
                       candidate_sha="a" * 40)
        cells = cpu.configuration(args)
        plan = cpu.rotation(args, cells)
        self.assertEqual(len(cells), 4)
        self.assertEqual(len(plan), 32)
        self.assertTrue(all(mode == "clean" for mode, *_ in plan))
        self.assertEqual(len(plan) * args.seconds, 160)
        self.assertEqual(sum(cell[2] * args.seconds for _, _, cell, _ in plan), 640_000)
        self.assertEqual(len(plan) * cpu.WARMUP, 640)
        self.assertEqual(max((cpu.WARMUP + cell[2] * args.seconds) * ((cell[1] + 1023) // 1024)
                             for _, _, cell, _ in plan), 20_020)
        self.assertEqual(cpu.metadata_allowance(plan, args.seconds), 22_927_360)
        self.assertNotIn("coaptic-staged-ready", cpu.KINDS)
        all_cells = cpu.configuration(options(server_kind="all", sizes="64", rates="100", perf=False))
        self.assertEqual({cell[3] for cell in all_cells}, set(cpu.KINDS))
        selected = cpu.configuration(options(server_kind="coaptic-staged-ready", perf=False))
        self.assertEqual({cell[3] for cell in selected}, {"coaptic-staged-ready"})
        for change in (dict(candidate_sha="b" * 40), dict(server_kind="all"),
                       dict(server_kind="coaptic-staged-ready")):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "adapter comparison"):
                cpu.configuration(options(**(vars(args) | change)))

    def test_user_profile_density_plan_keeps_existing_budgets(self):
        core = "183b4b9141d4d8a520713292132f3d2608180a1f"
        args = options(sizes="64", rates="11900", seconds=2, repeats=2, perf=True,
                       server_kind="coaptic-ready", candidate_server_kind="coaptic-async",
                       baseline_sha=core, candidate_sha=core)
        cells = cpu.configuration(args)
        self.assertEqual({cell[0] for cell in cells}, {"unprotected", "oscore"})
        plan = cpu.rotation(args, cells)
        self.assertEqual(sum(mode == "clean" for mode, *_ in plan), 8)
        slots = sum(mode != "clean" for mode, *_ in plan)
        self.assertEqual(slots, 8)
        durations = [args.seconds if mode == "clean" else cpu.PROFILE_SECONDS
                     for mode, *_ in plan]
        self.assertEqual(sum(durations), 56)
        operations = [cell[2] * duration for (_, _, cell, _), duration in zip(plan, durations)]
        self.assertEqual(sum(operations), 666_400)
        profile_sends = [cpu.WARMUP + count for (mode, *_), count in zip(plan, operations)
                         if mode != "clean"]
        self.assertEqual(set(profile_sends), {59_520})
        self.assertEqual(cpu.DATAGRAM_BUDGET - max(profile_sends), 480)
        allowance = cpu.metadata_allowance(plan, args.seconds)
        self.assertEqual(allowance, 21_542_080)
        quota = min(8 * cpu.MIB, (cpu.PERF_BUDGET - cpu.METADATA_BUDGET)
                    // (cpu.PERF_FILES_PER_SLOT * slots))
        self.assertEqual(quota, 6_990_506)
        self.assertLessEqual(allowance + cpu.PERF_FILES_PER_SLOT * slots * quota, cpu.PERF_BUDGET)

    def test_user_profile_density_refuses_long_clean_and_oversized_sample_plans(self):
        core = "183b4b9141d4d8a520713292132f3d2608180a1f"
        selected = dict(sizes="64", rates="11900", seconds=2, repeats=2, perf=True,
                        server_kind="coaptic-ready", candidate_server_kind="coaptic-async",
                        baseline_sha=core, candidate_sha=core)
        for changes, reason in ((dict(seconds=10), "clean.*socket budget"),
                                (dict(sizes="64,1024", seconds=5, repeats=4), "2M latency samples")):
            with self.subTest(changes=changes), patch.object(cpu, "build") as build, \
                    self.assertRaisesRegex(ValueError, reason):
                cpu.run(options(**(selected | changes)))
            build.assert_not_called()

    def test_concurrency_requires_explicit_non_without_expanding_campaign(self):
        default = cpu.configuration(options())
        for concurrency in (1, 2, 3, 4):
            self.assertEqual(cpu.configuration(options(concurrency=concurrency, message_type="non")), default)
        for concurrency, message_type in ((2, "con"), (4, "con"), (True, "non"), (5, "non"), (0, "non")):
            with self.subTest(concurrency=concurrency), self.assertRaisesRegex(ValueError, "NSTART"):
                cpu.configuration(options(concurrency=concurrency, message_type=message_type))

    def test_perf_is_pid_scoped_bounded_and_has_no_memory_dump(self):
        for mode in ("record", "stat"):
            argv = cpu.perf_command(mode, 4321, 5, Path("/tmp/profile"), 12345,
                                    control_paths=("/tmp/ctl", "/tmp/ack"))
            self.assertEqual(argv[:11], ["sudo", "-n", "--", "prlimit", "--fsize=12345:12345", "--",
                                        "timeout", "--signal=TERM", "--kill-after=5", "15", "perf"])
            self.assertNotIn("-a", argv)
            self.assertNotIn("dwarf", argv)
            self.assertNotIn("--sample-regs-user", argv)
            if mode == "record":
                self.assertEqual(argv[11:], ["record", "-e", "cpu-clock", "-F", "997",
                                              "--call-graph", "fp", "-m", "128", "--no-buildid-cache",
                                              "-o", str(Path("/tmp/profile")), "-p", "4321",
                                              "-D", "-1", "--control", "fifo:/tmp/ctl,/tmp/ack"])
                self.assertNotIn("sleep", argv)
            else:
                self.assertEqual(argv[-5:], ["-p", "4321", "--", "sleep", "5"])
                self.assertEqual(argv[11:-5], ["stat", "-x", ";", "-e",
                                              "task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults",
                                              "-o", str(Path("/tmp/profile"))])

    def test_refusal_is_retained_without_changing_clean_availability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = unittest.mock.Mock()
            fake.wait.return_value = 255
            fake.returncode = 255
            with mock_record_control(), patch.object(cpu, "spawn", return_value=fake), patch.object(cpu, "stop"):
                with cpu.perf_pass("record", 123, 5, root, 4096) as state:
                    self.assertEqual(state["mode"], "record")
            saved = json.loads((root / "perf.json").read_text())
            self.assertEqual(saved["returncode"], 255)
            self.assertFalse(saved["available"])
            self.assertNotIn("cleanup_error", saved)
            self.assertFalse(cpu.unresolved_cleanup(dict(perf=saved)))
            self.assertTrue((root / "perf-command.log").exists())
            with cpu.perf_pass("clean", 123, 5, root, 4096) as state:
                self.assertEqual(state["mode"], "clean")


class RecordControlTests(unittest.TestCase):
    def capture(self):
        capture = cpu.PerfCapture("record", 5, Mock())
        capture._target.poll.return_value = None
        capture._recorder = Mock()
        capture._recorder.poll.return_value = None
        capture._fds = (101, 102)
        capture.deadline = 25.0
        capture.update(control_ack_bytes=0, control_commands_sent=0, control_acks=0)
        return capture

    def test_split_ack_nul_across_commands_and_finish_is_idempotent(self):
        capture = self.capture()
        replies = [BlockingIOError(), b"a", b"ck\n", BlockingIOError(),
                   BlockingIOError(), b"\0ack\n\0", BlockingIOError(),
                   BlockingIOError(), b"ack\n\0", BlockingIOError()]
        with patch.object(cpu.time, "monotonic", return_value=10), \
                patch.object(cpu.os, "read", side_effect=replies), \
                patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)) as write:
            capture._command("enable")
            capture._enabled = True
            capture.finish_recording()
            capture.finish_recording()
        self.assertEqual([c.args for c in write.call_args_list],
                         [(101, b"enable\n"), (101, b"disable\n"), (101, b"stop\n")])
        self.assertEqual((capture["control_ack_bytes"], capture["control_acks"]), (15, 3))
        self.assertTrue(capture["record_finished"])
        self.assertNotIn("_fds", json.loads(json.dumps(capture)))
        for mode in ("clean", "stat"):
            other = cpu.PerfCapture(mode, 5)
            other.finish_recording()
            self.assertIsNone(other.deadline)
            self.assertEqual(set(other), {"mode", "window_seconds", "boundary"})

    def test_stale_malformed_extra_eof_and_byte_bound_refuse(self):
        for replies, message, already in [
            ([b"ack\n"], "stale", 0),
            ([BlockingIOError(), b"bad\n"], "malformed", 0),
            ([BlockingIOError(), b"ack\nack\n"], "extra", 0),
            ([BlockingIOError(), b"ack\n\0\0"], "extra", 0),
            ([BlockingIOError(), b""], "ended", 0),
            ([], "byte allowance", 64),
        ]:
            with self.subTest(message=message):
                capture = self.capture()
                capture["control_ack_bytes"] = already
                with patch.object(cpu.time, "monotonic", return_value=10), \
                        patch.object(cpu.os, "read", side_effect=replies), \
                        patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                        self.assertRaisesRegex(RuntimeError, message):
                    capture._command("enable")
                self.assertEqual(capture["control_refused_command"], "enable")
                self.assertLessEqual(len(capture.get("control_reply_prefix_hex", "")), 16)
                self.assertLessEqual(capture["control_ack_bytes"], 64)

    def test_short_write_and_dead_process_never_wait_for_ack(self):
        for failure in ("short", "target", "recorder"):
            capture = self.capture()
            if failure != "short":
                getattr(capture, "_" + ("target" if failure == "target" else "recorder")).poll.return_value = 1
            with patch.object(cpu.time, "monotonic", return_value=10), \
                    patch.object(cpu.os, "read", side_effect=BlockingIOError()), \
                    patch.object(cpu.os, "write", return_value=3) as write, \
                    patch.object(cpu.select, "select") as wait, \
                    self.assertRaisesRegex(RuntimeError, "short|exited"):
                capture._command("enable")
            self.assertEqual(write.call_count, int(failure == "short"))
            wait.assert_not_called()

    def test_ack_deadline_is_two_seconds_clamped_to_capture_and_late_ack_refuses(self):
        for total_remaining in (.2, 10):
            capture = self.capture()
            capture.deadline = 10 + total_remaining
            now = [10.0]
            expected_end = 10 + min(total_remaining, 2)
            def waited(read, write, error, timeout):
                self.assertLessEqual(timeout, .05)
                now[0] = expected_end
                return ([], [], [])
            with patch.object(cpu.time, "monotonic", side_effect=lambda: now[0]), \
                    patch.object(cpu.os, "read", side_effect=BlockingIOError()), \
                    patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                    patch.object(cpu.select, "select", side_effect=waited), \
                    self.assertRaises(TimeoutError):
                capture._command("enable")
            self.assertTrue(capture["deadline_exceeded"])
            self.assertEqual(capture["capture_deadline_exceeded"], total_remaining < 2)
            self.assertEqual(capture["control_timeout_boundary"], "capture" if total_remaining < 2 else "ACK")
        capture = self.capture()
        now = [10.0]
        replies = iter([BlockingIOError(), b"ack\n", BlockingIOError()])
        def read(fd, size):
            value = next(replies)
            if isinstance(value, BaseException):
                raise value
            now[0] = 12.01
            return value
        with patch.object(cpu.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cpu.os, "read", side_effect=read), \
                patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                self.assertRaises(TimeoutError):
            capture._command("enable")
        self.assertEqual(capture["control_acks"], 0)

    def test_stop_ack_can_precede_normal_exit_and_order_is_exact(self):
        capture = self.capture()
        capture._phase = 2
        def written(fd, data):
            self.assertEqual(data, b"stop\n")
            capture._recorder.poll.return_value = 0
            return len(data)
        with patch.object(cpu.time, "monotonic", return_value=10), \
                patch.object(cpu.os, "read", side_effect=[BlockingIOError(), b"ack\n\0", BlockingIOError()]), \
                patch.object(cpu.os, "write", side_effect=written):
            capture._command("stop")
        with self.assertRaises(ValueError):
            capture._command("enable")

    def test_event_allowlist_and_exact_stat_command(self):
        for event in ("cpu-clock", "task-clock"):
            argv = cpu.perf_command("record", 123, 5, Path("data"), 99,
                                    event=event, control_paths=("ctl", "ack"))
            self.assertEqual(argv[12:14], ["-e", event])
            self.assertEqual(argv[-4:], ["-D", "-1", "--control", "fifo:ctl,ack"])
        for event in ("cycles", "cpu-clock:u", "", None):
            with self.assertRaises(ValueError):
                cpu.perf_command("record", 123, 5, Path("data"), 99,
                                 event=event, control_paths=("ctl", "ack"))
        for paths in (None, ("ctl",), ("bad,ctl", "ack"), ("ctl", "ack\n")):
            with self.assertRaises(ValueError):
                cpu.perf_command("record", 123, 5, Path("data"), 99, control_paths=paths)
        self.assertEqual(cpu.perf_command("stat", 123, 5, Path("data"), 99),
                         ["sudo", "-n", "--", "prlimit", "--fsize=99:99", "--", "timeout",
                          "--signal=TERM", "--kill-after=5", "15", "perf", "stat", "-x", ";", "-e",
                          "task-clock,cycles,instructions,context-switches,cpu-migrations,page-faults",
                          "-o", "data", "-p", "123", "--", "sleep", "5"])

    def test_startup_refusal_never_yields_and_reaps_before_closing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = Mock(returncode=0)
            recorder.poll.return_value = None
            recorder.wait.return_value = 0
            order = []
            def opened(capture, directory):
                capture._control_paths = (directory / "ctl", directory / "ack")
                capture._fds = (101, 102)
            with patch.object(cpu.PerfCapture, "_open_control", autospec=True, side_effect=opened), \
                    patch.object(cpu.PerfCapture, "_close_control", side_effect=lambda **kw: order.append("close")), \
                    patch.object(cpu, "spawn", return_value=recorder), \
                    patch.object(cpu, "stop", side_effect=lambda *a, **kw: order.append("reaped")), \
                    patch.object(cpu.os, "read", side_effect=[BlockingIOError(), b"bad\n"]), \
                    patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                    self.assertRaisesRegex(RuntimeError, "malformed"):
                with cpu.perf_pass("record", 123, 5, root, 4096):
                    self.fail("startup refusal released the client gate")
            self.assertEqual(order, ["reaped", "close"])
            state = json.loads((root / "perf.json").read_text())
            self.assertFalse(state["available"])
            self.assertEqual(state["control_refused_command"], "enable")
            self.assertNotIn("cleanup_unresolved", state)

    def test_primary_exception_survives_finish_and_cleanup_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = Mock(returncode=0)
            recorder.wait.return_value = 0
            primary = ValueError("client failed")
            with mock_record_control(), \
                    patch.object(cpu.PerfCapture, "finish_recording", side_effect=RuntimeError("finish failed")), \
                    patch.object(cpu, "spawn", return_value=recorder), \
                    patch.object(cpu, "stop", side_effect=PermissionError("kill refused")), \
                    self.assertRaises(ValueError) as failure:
                with cpu.perf_pass("record", 123, 5, root, 4096):
                    raise primary
            self.assertIs(failure.exception, primary)
            self.assertIn("finish failed", primary.__notes__[0])
            state = json.loads((root / "perf.json").read_text())
            self.assertEqual(primary.perf_capture, state)
            self.assertTrue(primary.cleanup_unresolved)
            self.assertIs(type(primary.perf_capture), dict)
            self.assertTrue(cpu.unresolved_cleanup(dict(perf=state)))
            self.assertFalse(state["available"])

    def test_final_padding_is_checked_after_reap_before_descriptor_close(self):
        drain = cpu.PerfCapture._drain_padding
        for extra in (False, True):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                recorder = Mock(returncode=0)
                recorder.wait.return_value = 0
                order, replies = [], iter([b"ack\n"] if extra else [b"\0", BlockingIOError()])
                def read(fd, size):
                    order.append("read")
                    reply = next(replies)
                    if isinstance(reply, BaseException):
                        raise reply
                    return reply
                refused = None
                with mock_record_control(), \
                        patch.object(cpu, "spawn", return_value=recorder), \
                        patch.object(cpu, "stop", side_effect=lambda *a, **kw: order.append("reaped")), \
                        patch.object(cpu.os, "close", side_effect=lambda fd: order.append("close")), \
                        patch.object(cpu.os, "read", side_effect=read):
                    try:
                        with cpu.perf_pass("record", 123, 5, root, 4096) as capture:
                            capture._fds = (101, 102)
                            capture._optional_nul = True
                            # Exercise the real final drain, separate from the fake commands.
                            capture._drain_padding = drain.__get__(capture)
                    except RuntimeError as error:
                        refused = error
                self.assertEqual(refused is not None, extra)
                self.assertEqual(order, ["reaped", "read"] + ([] if extra else ["read"]) + ["close", "close"])
                state = json.loads((root / "perf.json").read_text())
                self.assertEqual("control_error" in state, extra)
                if extra:
                    self.assertIn("extra", str(refused))
                    self.assertFalse(state["available"])

    def test_failed_reap_retains_control_paths_and_attempts_every_close(self):
        capture = self.capture()
        capture._control_dir = Path("owned-control-retained")
        with patch.object(cpu.os, "close", side_effect=[OSError("close refused"), None]) as close, \
                patch.object(Path, "unlink") as unlink, patch.object(Path, "rmdir") as rmdir:
            capture._close_control(remove=False)
        self.assertEqual([call.args for call in close.call_args_list], [(101,), (102,)])
        unlink.assert_not_called()
        rmdir.assert_not_called()
        self.assertEqual(capture._fds, ())
        self.assertEqual(capture["retained_control_directory"], "owned-control-retained")
        self.assertTrue(cpu.unresolved_cleanup(dict(perf=capture)))

    def test_enabled_and_startup_log_markers_never_acknowledge_and_late_bytes_stay_refused(self):
        capture = self.capture()
        capture["file_size_limit_bytes"] = 4096
        capture._control_log = io.BytesIO(b"Events disabled\nEvents enabled\nperf record has started\n")
        now = [10.0]
        def waited(*args):
            now[0] = 12.0
            return ([], [], [])
        with patch.object(cpu.time, "monotonic", side_effect=lambda: now[0]), \
                patch.object(cpu.os, "read", side_effect=BlockingIOError()), \
                patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                patch.object(cpu.select, "select", side_effect=waited), self.assertRaises(TimeoutError):
            capture._command("enable")
        self.assertEqual(capture["control_acks"], 0)
        self.assertFalse(capture._enabled)
        self.assertEqual(capture["enable_attempt_monotonic"], 10)
        self.assertEqual(capture["enable_ack_deadline_monotonic"], 12)
        self.assertEqual(capture["control_refused_monotonic"], 12)
        self.assertEqual(capture["control_timeout_boundary"], "ACK")
        self.assertFalse(capture["capture_deadline_exceeded"])
        self.assertEqual(capture["control_ack_bytes_at_refusal"], 0)
        self.assertEqual(capture["events_enabled_observed_monotonic"], 10)
        self.assertEqual(capture["record_start_observed_monotonic"], 10)
        with patch.object(cpu.time, "monotonic", return_value=20), \
                patch.object(cpu.os, "read", side_effect=[b"ack\n\0", BlockingIOError()]):
            capture._retain_late_reply()
        self.assertEqual(capture["control_late_reply_hex"], b"ack\n\0".hex())
        self.assertEqual(capture["control_late_first_observed_monotonic"], 20)
        self.assertEqual(capture["control_late_reply_bytes"], 5)
        self.assertEqual(capture["control_acks"], 0)
        self.assertNotIn("enable_ack_monotonic", capture)
        self.assertFalse(capture._enabled)

    def test_late_reply_and_split_log_observations_share_fixed_existing_bounds(self):
        capture = self.capture()
        capture["control_ack_bytes"] = 62
        with patch.object(cpu.os, "read", side_effect=lambda fd, size: b"x" * size) as read:
            capture._retain_late_reply()
        self.assertEqual(capture["control_ack_bytes"], 64)
        self.assertEqual(capture["control_late_reply_bytes"], 2)
        self.assertEqual(len(capture["control_late_reply_hex"]), 4)
        self.assertTrue(capture["control_reply_allowance_exhausted"])
        read.assert_called_once_with(102, 2)
        capture["file_size_limit_bytes"] = 8192
        capture._control_log = io.BytesIO(b"x" * 4089 + b"\nEvents enabled\n" + b"x" * 8192)
        with patch.object(cpu.time, "monotonic", return_value=30):
            capture._observe_log()
            self.assertNotIn("events_enabled_observed_monotonic", capture)
            capture._observe_log(final=True)
        self.assertEqual(capture["events_enabled_observed_monotonic"], 30)
        self.assertEqual(capture["control_log_observed_bytes"], 8192)
        self.assertEqual(capture._control_log.tell(), 8192)
        self.assertLessEqual(len(capture._log_tail), 64)
        capture._control_log = io.BytesIO(b"x" * 4096 + b"Events disabled\n")
        capture["control_log_observed_bytes"] = 0
        capture._log_tail = b""
        capture._observe_log(final=True)
        self.assertNotIn("events_disabled_observed_monotonic", capture)

    def test_failed_enter_observes_late_ack_only_after_reap_and_preserves_primary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recorder = Mock(returncode=0)
            recorder.poll.return_value = None
            now, reaped, late = [10.0], [False], [b"ack\n\0"]
            def opened(capture, directory):
                capture._control_paths = (Path("temp/ctl"), Path("temp/ack"))
                capture._fds = (301, 302)
            def waited(*args):
                now[0] = 12
                return ([], [], [])
            def exited(*args, **kwargs):
                now[0] = 20
                (root / "perf-command.log").write_bytes(b"Events disabled\nEvents enabled\n")
                return 0
            def stopped(*args, **kwargs):
                reaped[0] = True
            def read(fd, size):
                if reaped[0] and late:
                    return late.pop(0)
                raise BlockingIOError()
            original_close = cpu.os.close
            recorder.wait.side_effect = exited
            with patch.object(cpu.PerfCapture, "_open_control", autospec=True, side_effect=opened), \
                    patch.object(cpu, "spawn", return_value=recorder), \
                    patch.object(cpu, "stop", side_effect=stopped), \
                    patch.object(cpu.time, "monotonic", side_effect=lambda: now[0]), \
                    patch.object(cpu.select, "select", side_effect=waited), \
                    patch.object(cpu.os, "read", side_effect=read), \
                    patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                    patch.object(cpu.os, "close", side_effect=lambda fd: None if fd in (301, 302)
                                 else original_close(fd)), self.assertRaises(TimeoutError) as failure:
                with cpu.perf_pass("record", 123, 5, root, 4096):
                    self.fail("refused enable released run gate")
            state = json.loads((root / "perf.json").read_text())
            self.assertEqual(str(failure.exception), "record control deadline")
            self.assertEqual(failure.exception.perf_capture, state)
            self.assertEqual(state["control_ack_bytes_at_refusal"], 0)
            self.assertEqual(state["control_timeout_boundary"], "ACK")
            self.assertFalse(state["capture_deadline_exceeded"])
            self.assertEqual(state["control_late_reply_bytes"], 5)
            self.assertEqual(state["recorder_reaped_monotonic"], 20)
            self.assertEqual(state["events_enabled_observed_monotonic"], 20)
            self.assertEqual(state["control_acks"], 0)
            self.assertFalse(state["available"])
            self.assertNotIn("record_finished", state)


@unittest.skipUnless(sys.platform == "linux", "real private FIFO controller requires Linux")
class RecordFifoTests(unittest.TestCase):
    def test_fake_recorder_round_trip_permissions_lifetime_and_owned_cleanup(self):
        script = r'''
import os, select, sys, time
ctl, ack, output = sys.argv[1:]
reader = os.open(ctl, os.O_RDWR | os.O_NONBLOCK)
writer = os.open(ack, os.O_RDWR)
with open(output, 'wb') as stream:
    stream.write(b'fake capture')
end = time.monotonic() + 5
print('Events disabled', flush=True)
for expected in (b'enable', b'disable', b'stop'):
    # v6.17.13 evlist__ctlfd_recv: one byte at a time, either terminator,
    # at most63 command bytes. ACK is written by ctlfd_process, not work.
    command = bytearray()
    while len(command) < 63:
        if not select.select([reader], [], [], max(0, end-time.monotonic()))[0]:
            sys.exit(2)
        byte = os.read(reader, 1)
        if byte in (b'\n', b'\0'):
            break
        command.extend(byte)
    assert command == expected
    print(expected.decode().strip(), flush=True)
    os.write(writer, b'a')
    time.sleep(.001)
    os.write(writer, b'ck\n\0')
os.close(reader)
os.close(writer)
'''
        original_spawn = cpu.spawn
        def spawned(argv, **kwargs):
            paths = argv[argv.index("--control") + 1].removeprefix("fifo:").split(",")
            output = argv[argv.index("-o") + 1]
            return original_spawn([sys.executable, "-u", "-c", script, *paths, output], **kwargs)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(cpu, "spawn", side_effect=spawned), \
                    patch.object(cpu, "run_owned", return_value=0), \
                    patch.object(cpu, "perf_report", return_value=dict(available=True)):
                with cpu.perf_pass("record", os.getpid(), 5, root, 4096) as capture:
                    control = capture._control_dir
                    self.assertFalse(control.is_relative_to(root))
                    self.assertEqual(control.stat().st_mode & 0o777, 0o700)
                    for path in capture._control_paths:
                        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                    self.assertEqual(capture["control_acks"], 1)
                    self.assertGreater(capture.deadline, cpu.time.monotonic())
                    capture.finish_recording()
                    capture.finish_recording()
            self.assertFalse(control.exists())
            self.assertTrue(capture["available"])
            self.assertEqual((capture["control_commands_sent"], capture["control_acks"]), (3, 3))
            self.assertEqual((root / "perf-command.log").read_text().splitlines(),
                             ["Events disabled", "enable", "disable", "stop"])
            self.assertLessEqual(capture["events_disabled_observed_monotonic"], capture["enable_ack_monotonic"])
            self.assertEqual(json.loads((root / "perf.json").read_text()), capture)

    def test_partial_setup_closes_owned_fifo_and_replacement_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capture = cpu.PerfCapture("record", 5)
            original = cpu.os.mkfifo
            def created(path, mode):
                if path.name == "ack":
                    raise PermissionError("second FIFO refused")
                original(path, mode)
            with patch.object(cpu.os, "mkfifo", side_effect=created), self.assertRaises(PermissionError):
                capture._open_control(root)
            fd = capture._fds[0]
            capture._close_control(remove=True)
            self.assertFalse(capture._control_dir.exists())
            with self.assertRaises(OSError):
                os.fstat(fd)
            capture = cpu.PerfCapture("record", 5)
            capture._open_control(root)
            capture._cleanup_failure(PermissionError("recorder cleanup unresolved"))
            capture._close_control(remove=False)
            self.assertFalse(capture._control_dir.is_relative_to(root))
            self.assertEqual(capture["retained_control_directory"], str(capture._control_dir))
            self.assertTrue(all(path.is_fifo() for path in capture._control_paths))
            self.assertEqual(list(root.iterdir()), [])
            path = capture._control_paths[1]
            try:
                path.unlink()
                path.write_bytes(b"replacement must survive")
                capture._close_control(remove=True)
                self.assertEqual(path.read_bytes(), b"replacement must survive")
                self.assertTrue(cpu.unresolved_cleanup(dict(perf=capture)))
            finally:
                # The replacement is this test's regular file, never a live FIFO.
                path.unlink()
                capture._control_dir.rmdir()


class BuildTests(unittest.TestCase):
    def test_explicit_host_target_ignores_configured_target_and_stale_top_level_binaries(self):
        host, configured = "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"
        revision = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, lane, out = root / "source", root / "lane", root / "evidence"
            for directory in (suite / ".cargo", lane / "release", lane / configured / "release", out):
                directory.mkdir(parents=True)
            (suite / ".cargo/config.toml").write_text(f'[build]\ntarget = "{configured}"\n')
            names = ("bench-rust-server", "bench-native-client")
            for name in names:
                (lane / "release" / name).write_bytes(b"stale host binary")
                (lane / configured / "release" / name).write_bytes(b"configured cross binary")

            def compile(argv, stream, **kwargs):
                if argv[0] == "cargo":
                    self.assertEqual(argv[argv.index("--target") + 1], host)
                    self.assertEqual(kwargs["env"]["CARGO_BUILD_TARGET"], configured)
                    destination = lane / host / "release"
                    destination.mkdir(parents=True)
                    for name in names:
                        (destination / name).write_bytes((revision + name).encode("ascii"))

            with patch.object(cpu, "SUITE", suite), \
                    patch.object(cpu, "identity", return_value=dict(status="", revision=revision)), \
                    patch.object(cpu, "command", side_effect=[RUSTC_VERSION, CARGO_VERSION]), \
                    patch.object(cpu, "run_logged", side_effect=compile) as logged, \
                    patch.object(cpu, "digest", return_value="hash"), \
                    patch.dict(os.environ, CARGO_BUILD_TARGET=configured):
                record = cpu.build(options(build_lane=lane), "baseline", revision, out)
            self.assertEqual(logged.call_count, 3)
            self.assertEqual(record["target"], host)
            self.assertEqual(record["rustc"], RUSTC_VERSION)
            self.assertEqual(record["cargo"], CARGO_VERSION)
            self.assertEqual(json.loads((out / "build-baseline.json").read_text())["target"], host)
            for name in names:
                self.assertEqual(Path(record["binaries"][name]["path"]).read_bytes(),
                                 (revision + name).encode("ascii"))
                self.assertEqual((lane / "release" / name).read_bytes(), b"stale host binary")

    def test_missing_duplicate_or_unsafe_rustc_host_fails_before_build(self):
        for rustc in ("rustc 1.99.0", "host: ../release", "host: /tmp/target",
                      "host: a-b\nhost: a-b", "host: a-b/../../release", "host: a-b "):
            with self.subTest(rustc=rustc), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch.object(cpu, "identity", return_value=dict(status="")), \
                        patch.object(cpu, "command", return_value=rustc), \
                        patch.object(cpu, "run_logged") as logged, \
                        self.assertRaisesRegex(ValueError, "host target"):
                    cpu.build(options(build_lane=root), "baseline", "a" * 40, root)
                logged.assert_not_called()
                self.assertFalse((root / "binaries").exists())

    def test_selected_compiler_overrides_ambient_and_root_toolchains_for_versions_and_build(self):
        # A child-process stand-in for rustup selection: env wins over the root file.
        # Exercise real command output capture and Cargo's compiler subprocess.
        proxy = '''
import os, pathlib, subprocess, sys, tomllib
tool, *args = sys.argv[1:]
selected = os.environ.get("RUSTUP_TOOLCHAIN") or tomllib.loads(
    pathlib.Path("rust-toolchain.toml").read_text())["toolchain"]["channel"]
release = {"stable": "1.99.1", "nightly": "1.100.0-nightly"}.get(selected, selected)
if tool == "rustc":
    print(f"rustc {release}\\ncommit-hash: {'1' * 40}\\nhost: x86_64-unknown-linux-gnu\\nrelease: {release}")
elif tool == "cargo" and args == ["-Vv"]:
    print(f"cargo {release}\\ncommit-hash: {'2' * 40}\\nrelease: {release}")
elif tool == "cargo" and args[0] == "build":
    version = subprocess.check_output([sys.executable, "-c", os.environ["TEST_RUSTUP_PROXY"], os.environ["RUSTC"], "-Vv"], text=True)
    dest = pathlib.Path(os.environ["CARGO_TARGET_DIR"]) / args[args.index("--target") + 1] / "release"
    dest.mkdir(parents=True)
    for name in ("bench-rust-server", "bench-native-client"):
        (dest / name).write_text(version)
'''
        for ambient in (None, "nightly"):
            with self.subTest(ambient=ambient), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                suite, lane, out = root / "source", root / "lane", root / "evidence"
                suite.mkdir()
                out.mkdir()
                (suite / "rust-toolchain.toml").write_text('[toolchain]\nchannel = "stable"\n')

                def spawn(argv, *, file_limit, **kwargs):
                    return cpu.OwnedProcess(subprocess.Popen([sys.executable, "-c", proxy, *argv], **kwargs))

                with patch.dict(os.environ, TEST_RUSTUP_PROXY=proxy, RUSTC="wrong-compiler"), \
                        patch.object(cpu, "SUITE", suite), \
                        patch.object(cpu, "identity", return_value=dict(status="", revision="a" * 40)), \
                        patch.object(cpu, "digest", return_value="hash"), \
                        patch.object(cpu, "spawn", side_effect=spawn), \
                        patch.object(cpu, "stop", side_effect=lambda child: child.wait(timeout=5)):
                    if ambient is None:
                        os.environ.pop("RUSTUP_TOOLCHAIN", None)
                    else:
                        os.environ["RUSTUP_TOOLCHAIN"] = ambient
                    control = cpu.command(["rustc", "-Vv"], cwd=suite)
                    self.assertIn("release: " + ("1.99.1" if ambient is None else "1.100.0-nightly"), control)
                    record = cpu.build(options(build_lane=lane), "baseline", "a" * 40, out)
                self.assertIn("release: 1.99.0\n", record["rustc"] + "\n")
                self.assertIn("release: 1.99.0\n", record["cargo"] + "\n")
                for binary in record["binaries"].values():
                    self.assertIn("release: 1.99.0\n", Path(binary["path"]).read_text())
                versions = json.loads((out / "build-baseline.json").read_text())
                self.assertEqual(versions["flags"]["RUSTUP_TOOLCHAIN"], "1.99.0")
                self.assertEqual(versions["rustc"], record["rustc"])

    def test_changed_compiler_or_cargo_commit_is_refused_before_candidate_build(self):
        expected = dict(rustc=RUSTC_VERSION, cargo=CARGO_VERSION, target=HOST, flags=cpu.FLAGS)
        for tool in ("rustc", "cargo"):
            with self.subTest(tool=tool), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                versions = dict(rustc=RUSTC_VERSION, cargo=CARGO_VERSION)
                versions[tool] = versions[tool].replace("commit-hash: " + ("1" if tool == "rustc" else "2") * 40,
                                                      "commit-hash: " + "3" * 40)
                with patch.object(cpu, "identity", return_value=dict(status="")), \
                        patch.object(cpu, "command", side_effect=[versions["rustc"], versions["cargo"]]), \
                        patch.object(cpu, "run_logged") as logged, \
                        self.assertRaisesRegex(ValueError, "before build: " + tool):
                    cpu.build(options(build_lane=root), "candidate", "b" * 40, root, expected=expected)
                logged.assert_not_called()
                self.assertEqual(json.loads((root / "build-candidate.json").read_text())[tool], versions[tool])


class PerfReportTests(unittest.TestCase):
    def capture(self, *, mode="record", returncode=0, data=b"owned raw capture", output=b"hotspots\n",
                report_code=0, error=None, error_command="report", log_full=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "path with spaces; $literal"
            root.mkdir()
            raw = root / ("perf.data" if mode == "record" else "perf-stat.txt")
            if data is not None:
                raw.write_bytes(data)
            profiler = Mock(returncode=returncode)
            profiler.wait.return_value = returncode
            commands = []

            def run(argv, **kwargs):
                commands.append((argv, kwargs))
                if argv == ["sudo", "-n", "--", "chmod", "a+r", str(raw)]:
                    return 0  # Existing capture readability helper only.
                self.assertEqual(kwargs["file_limit"], 4096)
                self.assertIs(kwargs["stdout"], kwargs["stderr"])
                self.assertEqual(kwargs["stdin"], cpu.subprocess.DEVNULL)
                self.assertFalse(kwargs.get("shell", False))
                if argv == ["perf", "--version"]:
                    if error is not None and error_command == "version":
                        raise error
                    kwargs["stdout"].write("x" * 4096 if log_full else "perf version fixture\n")
                    kwargs["stdout"].flush()
                    return 0
                self.assertEqual(argv[12:14], ["perf", "report"])
                kwargs["stdout"].write(output)
                kwargs["stdout"].flush()
                if error is not None:
                    raise error
                return report_code

            with mock_record_control(), patch.object(cpu, "spawn", return_value=profiler), patch.object(cpu, "stop"), \
                    patch.object(cpu, "run_owned", side_effect=run):
                with cpu.perf_pass(mode, 123, 5, root, 4096) as state:
                    pass
            self.assertEqual(json.loads((root / "perf.json").read_text()), state)
            if data is not None:
                self.assertEqual(raw.read_bytes(), data)
            text = (root / "perf-report.txt").read_bytes() if (root / "perf-report.txt").exists() else None
            log = (root / "perf-command.log").read_text()
            return state, commands, text, log

    def test_success_retains_sample_headers_lost_warnings_and_flat_symbol_costs(self):
        text = (b"# first sample time : 1.1\n# last sample time : 5.9\n"
                b"# Total Lost Samples: 2\n# Samples: 99 of event 'cpu-clock'\n"
                b"# Event count (approx.): 1000000000\n"
                b"# Overhead Samples Period Shared Object Symbol\n"
                b"50.00% 49 500000000 [kernel.kallsyms] [k] udp_sendmsg\n"
                b"20.00% 20 200000000 bench-rust-server [.] route_lookup\n"
                b"30.00% 30 300000000 [unknown] [k] 0x1234\n"
                b"Warning: kernel symbols restricted\n")
        state, calls, saved, log = self.capture(output=text)
        self.assertTrue(state["available"])
        self.assertTrue(state["report"]["available"])
        self.assertEqual(saved, text)
        self.assertIn("perf version fixture", log)
        self.assertEqual([argv[:2] for argv, _ in calls],
                         [["sudo", "-n"], ["perf", "--version"], ["sudo", "-n"]])
        self.assertFalse(calls[-2][1].get("elevated", False))
        argv, kwargs = calls[-1]
        self.assertEqual(argv, ["sudo", "-n", "--", "prlimit", "--fsize=4096:4096", "--",
                                "timeout", "--signal=TERM", "--kill-after=5",
                                str(cpu.PERF_REPORT_SECONDS - 5), "env", "DEBUGINFOD_URLS=",
                                "perf", "report", "--stdio", "--header", "--show-nr-samples",
                                "--show-total-period", "--sort", "dso,symbol", "--no-children",
                                "--call-graph", "none", "--percent-limit", "0", "--stdio-color", "never",
                                "--no-inline", "--demangle", "--force", "--input",
                                state["command"][state["command"].index("-o") + 1]])
        self.assertEqual(kwargs["timeout"], cpu.PERF_REPORT_SECONDS)
        self.assertTrue(kwargs["elevated"])
        self.assertEqual(kwargs["env"]["DEBUGINFOD_URLS"], "")
        self.assertEqual(state["report"]["command"], argv)
        self.assertEqual(state["report"]["version_command"], calls[-2][0])
        self.assertFalse(cpu.unresolved_cleanup(dict(perf=state)))

    def test_refused_or_full_report_preserves_capture_and_is_nonfatal(self):
        for code, output, log_full in ((255, b"report refused\n", False),
                                       (124, b"inner report timeout\n", False),
                                       (137, b"inner report killed\n", False),
                                       (127, b"env: perf: No such file or directory\n", False),
                                       (-25, b"partial output\n", False),
                                       (0, b"x" * 4096, False), (0, b"hotspots\n", True)):
            with self.subTest(code=code, size=len(output), log_full=log_full):
                state, _, saved, _ = self.capture(report_code=code, output=output, log_full=log_full)
                self.assertTrue(state["available"])
                self.assertFalse(state["report"]["available"])
                self.assertEqual(state["report"]["returncode"], code)
                self.assertEqual(saved, output)
                self.assertFalse(cpu.unresolved_cleanup(dict(perf=state)))

    def test_report_timeout_keeps_partial_text_and_resolved_cleanup_is_nonfatal(self):
        error = cpu.subprocess.TimeoutExpired("perf report", cpu.PERF_REPORT_SECONDS)
        state, _, saved, _ = self.capture(error=error, output=b"partial report\n")
        self.assertTrue(state["available"])
        self.assertFalse(state["report"]["available"])
        self.assertTrue(state["report"]["deadline_exceeded"])
        self.assertEqual(state["report"]["error_type"], "TimeoutExpired")
        self.assertEqual(state["report"]["output_bytes"], len(saved))
        self.assertEqual(saved, b"partial report\n")
        self.assertFalse(cpu.unresolved_cleanup(dict(perf=state)))

    def test_missing_perf_at_version_or_report_is_retained_without_losing_capture(self):
        for stage in ("version", "report"):
            with self.subTest(stage=stage):
                state, calls, _, _ = self.capture(error=FileNotFoundError("perf unavailable"), error_command=stage)
                self.assertTrue(state["available"])
                self.assertFalse(state["report"]["available"])
                self.assertEqual(state["report"]["error_type"], "FileNotFoundError")
                self.assertEqual(len(calls), 2 if stage == "version" else 3)
                self.assertFalse(cpu.unresolved_cleanup(dict(perf=state)))

    def test_failed_capture_or_stat_never_launches_a_report(self):
        for kwargs in (dict(returncode=255), dict(data=None), dict(data=b""),
                       dict(data=b"x" * 4096), dict(mode="stat")):
            with self.subTest(kwargs=kwargs):
                state, calls, text, _ = self.capture(**kwargs)
                self.assertNotIn("report", state)
                self.assertIsNone(text)
                self.assertTrue(all(argv[0] != "perf" for argv, _ in calls))

    def test_owned_report_timeout_propagates_unresolved_termination(self):
        version, report = Mock(pid=4321, returncode=0), Mock(pid=4322, returncode=None)
        version.wait.return_value = 0
        report.wait.side_effect = cpu.subprocess.TimeoutExpired("perf report", cpu.PERF_REPORT_SECONDS)
        cleanup = PermissionError("report group kill refused")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (root / "perf-command.log").open("w") as log, \
                    patch.object(cpu, "spawn", side_effect=[version, report]) as spawn, \
                    patch.object(cpu, "stop", side_effect=[None, cleanup]) as stop:
                state = cpu.perf_report(root, 4096, log)
            self.assertFalse(state["available"])
            self.assertTrue(state["cleanup_unresolved"])
            self.assertIn("report group kill refused", state["cleanup_reason"])
            self.assertTrue(state["deadline_exceeded"])
            self.assertEqual(state["error_type"], "TimeoutExpired")
            self.assertTrue(all(call.kwargs["file_limit"] == 4096 for call in spawn.call_args_list))
            self.assertEqual(stop.call_args_list, [unittest.mock.call(version, elevated=False),
                                                  unittest.mock.call(report, elevated=True)])


class AggregationTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def pairs(self):
        return pairs(self.root)

    def test_verified_cpu_denominators_and_latency_are_separate(self):
        summary = cpu.aggregate(self.pairs(), repeats=2, tick=.01)[0]
        self.assertTrue(summary["comparable"])
        self.assertEqual(summary["server_cpu_ratio"], .5)
        baseline = summary["cpu_ns_per_verified_operation"]["baseline"]
        self.assertEqual(baseline["server"]["total_ns"], 1_000_000)
        self.assertEqual(baseline["client"]["system_ns"], 200_000)
        self.assertEqual(baseline["verified_operations"], 2000)
        self.assertEqual(baseline["p99_latency_ns"], 1000)
        self.assertEqual(summary["observed_peak_pending"], {"baseline": [1, 1], "candidate": [1, 1]})

    def test_same_source_adapter_pairs_are_explicit_and_reject_wrong_execution(self):
        kinds = ("coaptic-ready", "coaptic-async")
        values = self.pairs()
        for item in values:
            item["server_kind"] = kinds[item["revision_label"] == "candidate"]
            item["core_sha"] = "a" * 40
        summary = cpu.aggregate(values, 2, .01, adapter_pair=kinds)[0]
        self.assertTrue(summary["comparable"])
        self.assertEqual(summary["comparison_type"], "application_scheduling")
        self.assertEqual(summary["server_kinds"], dict(baseline=kinds[0], candidate=kinds[1]))
        self.assertEqual(summary["server_cpu_ratio"], .5)
        for changes in (dict(server_kind="coaptic-mio"), dict(core_sha="b" * 40), dict(core_sha=None)):
            invalid = deepcopy(values)
            invalid[0].update(changes)
            result = cpu.aggregate(invalid, 2, .01, adapter_pair=kinds)[0]
            self.assertFalse(result["comparable"])
            self.assertIsNone(result["server_cpu_ratio"])

    def test_no_ratio_for_failure_missing_duplicate_or_quantized_pairs(self):
        mutations = []
        failed = self.pairs()
        failed[0] = dict(failed[0], passed=False)
        mutations.append(failed)
        mutations.append(self.pairs()[:-1])
        duplicate = self.pairs()
        duplicate[-1]["repeat"] = 0
        mutations.append(duplicate)
        low_cpu = self.pairs()
        low_cpu[1]["cpu_cost"]["server"]["total_seconds"] = .01
        mutations.append(low_cpu)
        late = self.pairs()
        late[0]["report"]["pacing_missed_period_operations"] = 11
        mutations.append(late)
        overloaded = self.pairs()
        overloaded[1]["report"]["achieved_ops_per_second"] = 90
        mutations.append(overloaded)
        unmatched = self.pairs()
        unmatched[0]["report"]["achieved_ops_per_second"] = 104
        unmatched[1]["report"]["achieved_ops_per_second"] = 96
        mutations.append(unmatched)
        for values in mutations:
            with self.subTest(values=values):
                summary = cpu.aggregate(values, repeats=2, tick=.01)[0]
                self.assertFalse(summary["comparable"])
                self.assertIsNone(summary["server_cpu_ratio"])

    def test_security_adapter_body_and_rate_strata_never_pool(self):
        values = self.pairs()
        for changes in (dict(security="oscore"), dict(bytes=1024), dict(rate=1000),
                        dict(server_kind="coaptic-ready")):
            for item in self.pairs():
                item.update(changes)
                values.append(item)
        self.assertEqual(len(cpu.aggregate(values, repeats=2, tick=.01)), 5)

    def test_profiler_timings_are_excluded_even_when_they_look_faster(self):
        values = self.pairs()
        profile = deepcopy(values[1])
        profile.update(mode="record", repeat=0)
        profile["cpu_cost"]["server"]["total_seconds"] = .000001
        profile["report_file"] = "must-never-read-profiling-samples"
        self.assertEqual(cpu.aggregate(values + [profile], 2, .01), cpu.aggregate(values, 2, .01))
        self.assertEqual(cpu.aggregate([profile], 2, .01), [])

    def test_con_non_and_concurrency_cohorts_and_legacy_metadata_stay_separate(self):
        values = self.pairs()
        for concurrency in (1, 2, 3, 4):
            values += [observation(self.root, label, repeat, concurrency=concurrency, message_type="non")
                       for repeat in range(2) for label in ("baseline", "candidate")]
        summaries = cpu.aggregate(values, 2, .01)
        self.assertEqual(len(summaries), 5)
        self.assertTrue(all(s["comparable"] for s in summaries))
        c4 = next(s for s in summaries if s["concurrency"] == 4)
        self.assertEqual(c4["observed_peak_pending"], {"baseline": [1, 1], "candidate": [1, 1]})
        old = self.pairs()
        for item in old:
            item.pop("concurrency")
            item.pop("message_type")
        self.assertFalse(cpu.aggregate(old, 2, .01)[0]["comparable"])
        mismatch = self.pairs()
        mismatch[0]["report"]["concurrency"] = 2
        self.assertFalse(cpu.aggregate(mismatch, 2, .01)[0]["comparable"])

    def test_incomplete_campaign_or_profile_cleanup_invalidates_complete_clean_pairs(self):
        values = self.pairs()
        self.assertTrue(cpu.aggregate(values, 2, .01)[0]["comparable"])
        profile = dict(mode="record", perf=dict(cleanup_error="TimeoutExpired"))
        for summary in (cpu.aggregate(values, 2, .01, campaign_complete=False),
                        cpu.aggregate(values + [profile], 2, .01)):
            self.assertFalse(summary[0]["comparable"])
            self.assertIsNone(summary[0]["server_cpu_ratio"])
            self.assertNotIn("cpu_ns_per_verified_operation", summary[0])


class MetadataTests(unittest.TestCase):
    def test_campaign_maxima_fit_reserve_even_at_maximum_sample_width(self):
        maximum = (22 * 2_000_000 + 192 * (cpu.SUMMARY_LIMIT + 4 * cpu.WINDOW_LIMIT)
                   + 96 * cpu.WINDOW_LIMIT + 7 * cpu.SUMMARY_LIMIT + 2 * cpu.BUILD_LOG_LIMIT)
        self.assertEqual(maximum, 75_391_744)
        self.assertLessEqual(maximum, cpu.METADATA_BUDGET)

    def test_valid_high_sample_campaign_has_explicit_safe_reserve(self):
        args = options(sizes="64", rates="10000", seconds=2, repeats=2, server_kind="all")
        plan = cpu.rotation(args, cpu.configuration(args))
        operations = [cell[2] * (args.seconds if mode == "clean" else cpu.PROFILE_SECONDS)
                      for mode, _, cell, _ in plan]
        self.assertEqual(sum(operations), 1_680_000)
        self.assertEqual(sum(op for op, (mode, *_) in zip(operations, plan) if mode != "clean"), 1_200_000)
        allowance = cpu.metadata_allowance(plan, args.seconds)
        self.assertGreater(sum(cpu.report_limit(op) for op in operations), 4 * cpu.MIB)
        self.assertLessEqual(allowance, 96 * cpu.MIB)
        slots = sum(mode != "clean" for mode, *_ in plan)
        self.assertEqual(cpu.PERF_FILES_PER_SLOT, 3)
        quota = min(8 * cpu.MIB, (cpu.PERF_BUDGET - cpu.METADATA_BUDGET) // (3 * slots))
        self.assertLessEqual(allowance + 3 * slots * quota, cpu.PERF_BUDGET)
        with patch.object(cpu, "METADATA_BUDGET", 1), self.assertRaisesRegex(ValueError, "metadata"):
            cpu.configuration(args)

    def test_max_width_samples_are_retained_once_and_fit_derived_bound(self):
        operations = 59_980
        report = dict(latencies_ns=[2**64 - 1] * operations, completed=operations)
        raw = json.dumps(report)
        self.assertLessEqual(len(raw.encode("utf-8")) + 1, cpu.report_limit(operations))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "client.json"
            cpu.retain_report(path, raw, operations)
            summary = cpu.report_summary(report)
            self.assertNotIn("latencies_ns", summary)
            cpu.save(root / "result.json", dict(report=summary), cpu.WINDOW_LIMIT)
            cpu.save(root / "index.json", dict(report=summary), cpu.WINDOW_LIMIT)
            self.assertEqual(path.read_bytes(), (raw + "\n").encode("utf-8"))
            for name in ("result.json", "index.json"):
                self.assertNotIn(b"18446744073709551615", (root / name).read_bytes())
            self.assertEqual(len(cpu.report_latencies(dict(report_file=str(path), operations=operations,
                                                           report=summary))), operations)

    def test_oversize_encoding_and_raw_reads_are_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "metadata.json"
            path.write_bytes(b"original evidence")
            for value in ({"large": "x" * 1000}, {"unicode": "\U0001f680" * 100}, {"bad": float("nan")}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    cpu.save(path, value, 128)
                self.assertEqual(path.read_bytes(), b"original evidence")
            with self.assertRaises(ValueError):
                cpu.bounded_read(path, 2)
            with self.assertRaises(ValueError):
                cpu.retain_report(path, "x" * (cpu.report_limit(1) + 1), 1)
            self.assertEqual(path.read_bytes(), b"original evidence")
            with self.assertRaisesRegex(ValueError, "u64"):
                cpu.report_summary(dict(latencies_ns=[2**64]))

    def test_oversize_window_metadata_still_retains_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = dict(passed=True, mode="clean", security="oscore", bytes=64,
                          rate=100, server_kind="coaptic-ready", operations=1000,
                          concurrency=4, message_type="non",
                          report={"huge": "x" * cpu.WINDOW_LIMIT})
            cpu.save_window(root, result)
            self.assertFalse(result["passed"])
            self.assertEqual((result["concurrency"], result["message_type"]), (4, "non"))
            self.assertEqual(json.loads((root / "result.json").read_text()), result)
            self.assertLessEqual((root / "result.json").stat().st_size, cpu.WINDOW_LIMIT)

    def test_oversize_fallback_preserves_all_fatal_cleanup_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            errors = [dict(process=name, type="TimeoutExpired", reason="unreaped")
                      for name in ("client", "server")]
            perf = dict(cleanup_error="PermissionError", cleanup_reason="kill refused", returncode=1)
            result = dict(passed=False, mode="record", cleanup_errors=errors, perf=perf,
                          report=dict(huge="x" * cpu.WINDOW_LIMIT))
            cpu.save_window(root, result)
            saved = json.loads((root / "result.json").read_text())
            self.assertTrue(saved["cleanup_unresolved"])
            self.assertEqual(saved["cleanup_errors"], errors)
            self.assertEqual(saved["perf"], perf)
            self.assertLessEqual((root / "result.json").stat().st_size, cpu.WINDOW_LIMIT)


class CampaignTests(unittest.TestCase):
    def exercise(self, *, failure_index=None, oversize=False, target_mismatch=False, report_error=None,
                 report_error_command="report", adapter_comparison=False, startup_refusal=None,
                 adapter_candidate="coaptic-async"):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            suite, lane, out = root / "source", root / "lane", root / "evidence"
            suite.mkdir()
            lane.mkdir()
            args = options(sizes="64", rates="100", repeats=2, build_lane=lane, output=out,
                           baseline_sha="a" * 40, candidate_sha="b" * 40)
            if adapter_comparison:
                args.server_kind, args.candidate_server_kind = "coaptic-ready", adapter_candidate
                args.candidate_sha = args.baseline_sha
            calls = []
            real_window = cpu.window

            def build(args, label, revision, out, *, expected=None):
                return dict(core=dict(revision=revision), native_lock_sha256="lock", flags=cpu.FLAGS,
                            native_manifest_sha256="manifest", rustc="rustc", cargo="cargo",
                            target=label if target_mismatch else "x86_64-unknown-linux-gnu",
                            binaries={name: dict(path=str(out / label / name))
                                      for name in ("bench-rust-server", "bench-native-client")})

            def window(server, client, cell, operations, directory, mode, quota, **kwargs):
                index = len(calls)
                calls.append((server, client, mode))
                if index == 8 and startup_refusal is not None:
                    # Exercise actual window -> perf_pass.__enter__ -> wire
                    # refusal -> cleanup, rather than fabricating a fatal result.
                    sut, client_process = MagicMock(pid=101), MagicMock(pid=102)
                    for process in (sut, client_process):
                        process.poll.return_value = None
                        process.wait.return_value = 0
                    profiler = Mock(returncode=255)
                    profiler.poll.return_value = None
                    profiler.wait.return_value = 255
                    reserve, probe = MagicMock(), MagicMock()
                    reserve.getsockname.return_value = ("127.0.0.1", 12345)
                    probe.bind.side_effect = OSError("bound by fixture")
                    reserve.__enter__.return_value, probe.__enter__.return_value = reserve, probe
                    native = Mock()
                    native.control_line.return_value = "ready"
                    native.server_resources.return_value = None
                    original_close = cpu.os.close
                    def opened(capture, directory):
                        capture._control_paths = (Path("system-temp/ctl"), Path("system-temp/ack"))
                        capture._fds = (301, 302)
                    def stopped(process, **kwargs):
                        if process is profiler and startup_refusal == "unresolved":
                            raise PermissionError("profiler kill refused")
                    with patch.dict(sys.modules, {"psutil": Mock(), "native_diagnostic": native}), \
                            patch.object(cpu.PerfCapture, "_open_control", autospec=True, side_effect=opened), \
                            patch.object(cpu, "spawn", side_effect=[sut, client_process, profiler]), \
                            patch.object(cpu, "stop", side_effect=stopped) as stop, \
                            patch.object(cpu.os, "read", side_effect=[BlockingIOError(), b"bad\n"]), \
                            patch.object(cpu.os, "write", side_effect=lambda fd, data: len(data)), \
                            patch.object(cpu.os, "close", side_effect=lambda fd: None if fd in (301, 302)
                                         else original_close(fd)), \
                            patch.object(cpu, "stderr_tail", return_value=b""), \
                            patch.object(cpu.socket, "socket", side_effect=[reserve, probe]), \
                            patch.object(cpu.os, "getloadavg", return_value=(0, 0, 0), create=True):
                        result = real_window(server, client, cell, operations, directory, mode, quota, **kwargs)
                    client_process.stdin.write.assert_not_called()
                    native.snapshot.assert_not_called()
                    self.assertEqual(result["reason"], "malformed record ACK")
                    self.assertEqual(result["perf"], json.loads((directory / "perf.json").read_text()))
                    self.assertEqual(result["perf"]["control_refused_command"], "enable")
                    self.assertEqual(cpu.unresolved_cleanup(result), startup_refusal == "unresolved")
                    self.assertEqual(stop.call_args_list, [unittest.mock.call(profiler, elevated=True),
                                                          unittest.mock.call(client_process), unittest.mock.call(sut)])
                    return result
                directory.mkdir()
                label = server.parent.name
                result = observation(directory, label, index, security=cell[0], mode=mode)
                result["server_kind"] = cell[3]
                Path(result["report_file"]).rename(directory / "client.json")
                result["report_file"] = str(directory / "client.json")
                if mode != "clean":
                    # Permission refusal with a terminated/reaped process is nonfatal.
                    result["perf"] = dict(available=False, returncode=255)
                if index == 8 and report_error is not None:
                    (directory / "perf.data").write_bytes(b"successful capture")
                    profiler = Mock(returncode=0)
                    profiler.wait.return_value = 0

                    def read_capture(argv, **kwargs):
                        command = argv[12:14] if argv[:3] == ["sudo", "-n", "--"] else argv[:2]
                        if command == ["perf", "report" if report_error_command == "report" else "--version"]:
                            raise report_error
                        return 0

                    with mock_record_control(), patch.object(cpu, "spawn", return_value=profiler), patch.object(cpu, "stop"), \
                            patch.object(cpu, "run_owned", side_effect=read_capture):
                        with cpu.perf_pass(mode, 123, 5, directory, quota) as perf:
                            pass
                    result["perf"] = perf
                    if cpu.unresolved_cleanup(result):
                        result["passed"] = False
                if index == failure_index:
                    if mode == "clean":
                        result["cleanup_errors"] = [dict(process="client", type="TimeoutExpired", reason="unreaped")]
                    else:
                        result["perf"].update(cleanup_error="PermissionError", cleanup_reason="kill refused")
                    result.update(passed=False, cleanup_unresolved=True)
                    if oversize:
                        result["extra"] = "x" * cpu.WINDOW_LIMIT
                if mode != "clean":
                    cpu.save(directory / "perf.json", result["perf"], cpu.WINDOW_LIMIT)
                cpu.save_window(directory, result)
                return result

            with patch.object(cpu, "SUITE", suite), patch.object(cpu.sys, "platform", "linux"), \
                    patch.object(cpu.os, "sysconf", return_value=100, create=True), \
                    patch.object(cpu, "hardware", return_value={}), \
                    patch.object(cpu, "identity", return_value=dict(status="")), \
                    patch.object(cpu.importlib.metadata, "version", return_value="7.0.0"), \
                    patch.object(cpu, "digest", return_value="hash"), \
                    patch.object(cpu, "build", side_effect=build), patch.object(cpu, "window", side_effect=window), \
                    patch("builtins.print"):
                if (failure_index is not None or target_mismatch or getattr(report_error, "cleanup_unresolved", False)
                        or startup_refusal == "unresolved"):
                    with self.assertRaisesRegex((ValueError, RuntimeError), "target|termination unresolved"):
                        cpu.run(args)
                    self.assertTrue((out / "failure.json").exists())
                else:
                    self.assertTrue(cpu.run(args))
            summary = json.loads((out / "summary.json").read_text())
            manifest = json.loads((out / "manifest.json").read_text())
            slots = sum(mode != "clean" for mode, *_ in cpu.rotation(args, cpu.configuration(args)))
            quota = manifest["perf_file_quota_bytes"]
            self.assertEqual(manifest["perf_files_per_slot"], 3)
            self.assertEqual(manifest["artifact_bound_bytes_excluding_binaries"],
                             manifest["metadata_allowance_bytes"] + 3 * slots * quota)
            self.assertLessEqual(3 * slots * quota, cpu.PERF_BUDGET - cpu.METADATA_BUDGET)
            self.assertLessEqual(manifest["artifact_bound_bytes_excluding_binaries"], cpu.PERF_BUDGET)
            if calls:
                entries = [json.loads(line) for line in (out / "windows.jsonl").read_text().splitlines()]
                self.assertEqual(len(entries), len(calls))
                for index in range(len(calls)):
                    directory = out / f"window-{index:03}"
                    if index == 8 and startup_refusal is not None:
                        self.assertFalse((directory / "client.json").exists())
                    else:
                        self.assertEqual(json.loads((directory / "client.json").read_text())["completed"], 1000)
                    result = json.loads((directory / "result.json").read_text())
                    if (index == failure_index or (index == 8 and getattr(report_error, "cleanup_unresolved", False))
                            or (index == 8 and startup_refusal == "unresolved")):
                        self.assertTrue(cpu.unresolved_cleanup(result))
                        self.assertTrue(cpu.unresolved_cleanup(entries[index]))
                self.assertTrue(all(client.parent.name == "baseline" for _, client, _ in calls))
            return summary, calls

    def test_adapter_campaign_executes_both_selected_fixtures_with_one_frozen_client(self):
        for candidate in ("coaptic-async", "coaptic-staged-ready"):
            with self.subTest(candidate=candidate):
                summary, calls = self.exercise(adapter_comparison=True, adapter_candidate=candidate)
                self.assertEqual(len(calls), 16)
                self.assertEqual(summary["comparison_type"], "application_scheduling")
                self.assertTrue(all(item["comparable"] for item in summary["comparisons"]))
                for item in summary["comparisons"]:
                    self.assertEqual(item["server_kinds"], dict(baseline="coaptic-ready", candidate=candidate))

    def test_cleanup_failure_aborts_after_first_window_even_with_oversize_metadata(self):
        for oversize in (False, True):
            with self.subTest(oversize=oversize):
                summary, calls = self.exercise(failure_index=0, oversize=oversize)
                self.assertEqual(len(calls), 1)
                self.assertTrue(summary["cleanup_unresolved"])
                self.assertFalse(summary["campaign_complete"])
                self.assertEqual(summary["failed_windows"], [0])

    def test_profile_cleanup_aborts_and_suppresses_preceding_complete_strata_ratios(self):
        summary, calls = self.exercise(failure_index=8)
        self.assertEqual(len(calls), 9)
        self.assertTrue(summary["cleanup_unresolved"])
        self.assertFalse(summary["campaign_complete"])
        self.assertEqual(len(summary["comparisons"]), 2)
        for comparison in summary["comparisons"]:
            self.assertFalse(comparison["comparable"])
            self.assertIsNone(comparison["server_cpu_ratio"])

    def test_clean_perf_refusal_allows_complete_campaign_and_clean_ratios(self):
        summary, calls = self.exercise()
        self.assertEqual(len(calls), 16)
        self.assertFalse(summary["cleanup_unresolved"])
        self.assertTrue(summary["campaign_complete"])
        self.assertEqual(summary["unavailable_profiles"], list(range(8, 16)))
        self.assertTrue(all(item["comparable"] for item in summary["comparisons"]))

    def test_actual_startup_refusal_with_unresolved_profiler_aborts_and_suppresses_all_ratios(self):
        summary, calls = self.exercise(startup_refusal="unresolved")
        self.assertEqual(len(calls), 9)
        self.assertFalse(summary["campaign_complete"])
        self.assertTrue(summary["cleanup_unresolved"])
        self.assertEqual(summary["failed_windows"], [8])
        self.assertEqual(len(summary["comparisons"]), 2)
        self.assertTrue(all(not item["comparable"] and item["server_cpu_ratio"] is None
                            for item in summary["comparisons"]))

    def test_actual_startup_refusal_with_reaped_profiler_keeps_clean_cohort_comparable(self):
        summary, calls = self.exercise(startup_refusal="resolved")
        self.assertEqual(len(calls), 16)
        self.assertTrue(summary["campaign_complete"])
        self.assertFalse(summary["cleanup_unresolved"])
        self.assertEqual(summary["failed_windows"], [8])
        self.assertTrue(all(item["comparable"] and item["server_cpu_ratio"] is not None
                            for item in summary["comparisons"]))

    def test_report_refusal_or_resolved_timeout_preserves_complete_clean_comparisons(self):
        for error in (FileNotFoundError("perf unavailable"), cpu.subprocess.TimeoutExpired("perf report", 30)):
            with self.subTest(error=error):
                summary, calls = self.exercise(report_error=error)
                self.assertEqual(len(calls), 16)
                self.assertTrue(summary["campaign_complete"])
                self.assertFalse(summary["cleanup_unresolved"])
                self.assertEqual(summary["unavailable_reports"], [8])
                self.assertNotIn(8, summary["unavailable_profiles"])
                self.assertTrue(all(item["comparable"] for item in summary["comparisons"]))

    def test_report_unresolved_termination_aborts_campaign_and_invalidates_clean_pairs(self):
        for stage in ("version", "report"):
            for error in (cpu.subprocess.TimeoutExpired("perf " + stage, 30), PermissionError("kill refused")):
                error.cleanup_unresolved = True
                with self.subTest(error=error, stage=stage):
                    summary, calls = self.exercise(report_error=error, report_error_command=stage)
                    self.assertEqual(len(calls), 9)
                    self.assertFalse(summary["campaign_complete"])
                    self.assertTrue(summary["cleanup_unresolved"])
                    self.assertEqual(summary["failed_windows"], [8])
                    self.assertEqual(summary["unavailable_reports"], [8])
                    self.assertTrue(all(not item["comparable"] and item["server_cpu_ratio"] is None
                                        for item in summary["comparisons"]))

    def test_build_targets_must_match_before_any_window(self):
        summary, calls = self.exercise(target_mismatch=True)
        self.assertEqual(calls, [])
        self.assertFalse(summary["campaign_complete"])
        self.assertEqual(summary["comparisons"], [])


class ProcessTests(unittest.TestCase):
    def setUp(self):
        # Exercise Linux signalling decisions on Windows without sending signals.
        if not hasattr(cpu.signal, "SIGKILL"):
            self.addCleanup(patch.stopall)
            patch.object(cpu.signal, "SIGKILL", 9, create=True).start()
            patch.object(cpu.signal, "Signals", side_effect=lambda value:
                         SimpleNamespace(name="SIGKILL" if value == 9 else "SIGTERM")).start()

    def owned(self):
        process = Mock(pid=4321, returncode=0)
        process.wait.return_value = 0
        return cpu.OwnedProcess(process)

    def test_every_spawn_owns_a_session_and_limits_regular_file_output(self):
        process = Mock(pid=4321)
        resource = Mock(RLIMIT_FSIZE=1)
        with patch.object(cpu.subprocess, "Popen", return_value=process) as popen, \
                patch.dict(sys.modules, {"resource": resource}):
            child = cpu.spawn(["no-command-executed"], file_limit=12345)
            self.assertEqual(child.group, 4321)
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            popen.call_args.kwargs["preexec_fn"]()
        resource.setrlimit.assert_called_once_with(1, (12345, 12345))

    def test_build_log_quota_is_enforced_without_limiting_compiler_artifacts(self):
        for output in (b"small", b"x" * 100):
            with self.subTest(output_bytes=len(output)):
                child = Mock(stdout=io.BytesIO(output))
                child.wait.return_value = 0
                stream = io.BytesIO(b"prefix")
                stream.seek(0, 2)
                with patch.object(cpu, "spawn", return_value=child) as spawn, \
                        patch.object(cpu, "stop") as stop:
                    if len(output) > 10:
                        with self.assertRaisesRegex(ValueError, "build log"):
                            cpu.run_logged(["cargo", "build"], stream, timeout=1, limit=16)
                    else:
                        cpu.run_logged(["cargo", "build"], stream, timeout=1, limit=16)
                self.assertIsNone(spawn.call_args.kwargs["file_limit"])
                self.assertLessEqual(len(stream.getvalue()), 16)
                stop.assert_called_once_with(child)

    def test_timeout_terminates_and_kills_owned_group_then_reaps(self):
        child = self.owned()
        child.process.wait.side_effect = [cpu.subprocess.TimeoutExpired("cargo", 900),
                                          cpu.subprocess.TimeoutExpired("cargo", 5), -9]
        with patch.object(cpu, "spawn", return_value=child), \
                patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            with self.assertRaises(cpu.subprocess.TimeoutExpired):
                cpu.run_owned(["cargo", "build"], timeout=900)
        self.assertEqual(kill.call_args_list, [unittest.mock.call(4321, cpu.signal.SIGTERM),
                                               unittest.mock.call(4321, 0),
                                               unittest.mock.call(4321, cpu.signal.SIGKILL)])
        self.assertEqual(child.process.wait.call_args_list,
                         [unittest.mock.call(timeout=900), unittest.mock.call(timeout=5), unittest.mock.call(timeout=5)])
        self.assertTrue(child.stopped)

    def test_exited_leader_does_not_leave_owned_descendants(self):
        child = self.owned()
        with patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            cpu.stop(child)
            cpu.stop(child)
        self.assertEqual([call.args[1] for call in kill.call_args_list],
                         [cpu.signal.SIGTERM, 0, cpu.signal.SIGKILL])
        self.assertEqual(child.process.wait.call_count, 2)

    def test_unowned_groups_are_never_signalled(self):
        with patch.object(cpu.os, "getpgrp", return_value=4321, create=True), \
                patch.object(cpu.os, "killpg", create=True) as kill:
            with self.assertRaises(ValueError):
                cpu.stop(Mock(pid=4322))
            with self.assertRaises(ValueError):
                cpu.signal_group(self.owned(), cpu.signal.SIGTERM, False)
        kill.assert_not_called()

    def test_elevated_cleanup_targets_only_owned_group_and_escalates(self):
        child = self.owned()
        with patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                patch.object(cpu.os, "killpg", side_effect=PermissionError, create=True), \
                patch.object(cpu, "run_owned") as run:
            cpu.stop(child, elevated=True)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["sudo", "-n", "--", "kill", "-TERM", "--", "-4321"],
                          ["sudo", "-n", "--", "kill", "-KILL", "--", "-4321"]])
        self.assertTrue(all(not call.kwargs.get("elevated", False) for call in run.call_args_list))
        self.assertEqual(child.process.wait.call_count, 2)

    def test_perf_timeout_escalates_reaps_and_retains_failure(self):
        child = self.owned()
        child.process.returncode = -9
        child.process.wait.side_effect = [cpu.subprocess.TimeoutExpired("perf", 15),
                                          cpu.subprocess.TimeoutExpired("perf", 5), -9]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with mock_record_control(), patch.object(cpu, "spawn", return_value=child), \
                    patch.object(cpu.os, "getpgrp", return_value=999, create=True), \
                    patch.object(cpu.os, "killpg", create=True) as kill:
                with cpu.perf_pass("record", 123, 5, root, 4096):
                    pass
            result = json.loads((root / "perf.json").read_text())
        self.assertTrue(result["deadline_exceeded"])
        self.assertFalse(result["available"])
        self.assertEqual(result["returncode"], -9)
        self.assertIn(unittest.mock.call(4321, cpu.signal.SIGKILL), kill.call_args_list)
        self.assertEqual(child.process.wait.call_count, 3)

    def test_run_owned_elevation_is_cleanup_only_on_every_exit(self):
        for elevated in (None, False, True):
            for outcome in (0, 7, cpu.subprocess.TimeoutExpired("helper", 5), KeyboardInterrupt()):
                for check in (False, True):
                    with self.subTest(elevated=elevated, outcome=outcome, check=check):
                        child = Mock()
                        if isinstance(outcome, BaseException):
                            child.wait.side_effect = outcome
                        else:
                            child.wait.return_value = outcome
                        kwargs = {} if elevated is None else dict(elevated=elevated)
                        with patch.object(cpu, "spawn", return_value=child) as spawn, \
                                patch.object(cpu, "stop") as stop:
                            if isinstance(outcome, BaseException):
                                with self.assertRaises(type(outcome)) as failure:
                                    cpu.run_owned(["helper"], timeout=5, check=check, **kwargs)
                                self.assertIs(failure.exception, outcome)
                            elif check and outcome:
                                with self.assertRaises(cpu.subprocess.CalledProcessError) as failure:
                                    cpu.run_owned(["helper"], timeout=5, check=check, **kwargs)
                                self.assertEqual(failure.exception.returncode, outcome)
                                self.assertEqual(failure.exception.cmd, ["helper"])
                            else:
                                self.assertEqual(cpu.run_owned(["helper"], timeout=5, check=check, **kwargs), outcome)
                        spawn.assert_called_once_with(["helper"])
                        stop.assert_called_once_with(child, elevated=bool(elevated))

    def test_run_owned_preserves_fatal_cleanup_status_with_or_without_primary_failure(self):
        for elevated, primary_failure in itertools.product((False, True), repeat=2):
            with self.subTest(elevated=elevated, primary_failure=primary_failure):
                child = Mock()
                primary = cpu.subprocess.TimeoutExpired("helper", 5)
                cleanup = TimeoutError("helper not reaped")
                if primary_failure:
                    child.wait.side_effect = primary
                else:
                    child.wait.return_value = 0
                with patch.object(cpu, "spawn", return_value=child), \
                        patch.object(cpu, "stop", side_effect=cleanup) as stop, \
                        self.assertRaises((TimeoutError, cpu.subprocess.TimeoutExpired)) as failure:
                    cpu.run_owned(["helper"], timeout=5, elevated=elevated)
                self.assertTrue(failure.exception.cleanup_unresolved)
                self.assertIs(failure.exception, primary if primary_failure else cleanup)
                stop.assert_called_once_with(child, elevated=elevated)
                if primary_failure:
                    self.assertIn("helper not reaped", failure.exception.__notes__[0])

    def test_perf_output_helper_refusal_and_resolved_timeout_are_distinct_from_unresolved_cleanup(self):
        for timeout, cleanup_failure in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(timeout=timeout, cleanup_failure=cleanup_failure), \
                    tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "perf.data").write_bytes(b"profile")
                profiler, helper = Mock(returncode=0), Mock(returncode=1)
                profiler.wait.return_value = 0
                helper.wait.return_value = 1
                if timeout:
                    helper.wait.side_effect = cpu.subprocess.TimeoutExpired("chmod", 5)
                cleanup = TimeoutError("chmod not reaped") if cleanup_failure else None
                with mock_record_control(), patch.object(cpu, "spawn", side_effect=[profiler, helper]), \
                        patch.object(cpu, "stop", side_effect=[None, cleanup]) as stop:
                    with cpu.perf_pass("record", 123, 5, root, 4096):
                        pass
                state = json.loads((root / "perf.json").read_text())
                self.assertEqual(cpu.unresolved_cleanup(dict(perf=state)), cleanup_failure)
                self.assertEqual("output_error" in state, timeout or cleanup_failure)
                self.assertEqual(stop.call_args_list,
                                 [unittest.mock.call(profiler, elevated=True),
                                  unittest.mock.call(helper, elevated=False)])


@unittest.skipUnless(sys.platform == "linux", "real session/file-limit checks require Linux")
class LinuxProcessTests(unittest.TestCase):
    def test_real_owned_group_kills_term_resistant_descendant_and_preserves_other_session(self):
        script = ("import signal,subprocess,sys,time; "
                  "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                  "child=subprocess.Popen([sys.executable,'-c',"
                  "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']); "
                  "print(child.pid,flush=True); time.sleep(30)")
        sentinel = cpu.spawn([sys.executable, "-c", "import time; time.sleep(30)"])
        child = None
        try:
            child = cpu.spawn([sys.executable, "-c", script], stdout=cpu.subprocess.PIPE, text=True)
            self.assertTrue(select.select([child.stdout], [], [], 5)[0], "child readiness deadline")
            descendant = int(child.stdout.readline(128))
            self.assertEqual(os.getpgid(child.pid), child.group)
            cpu.stop(child)
            self.assertEqual(child.returncode, -cpu.signal.SIGKILL)
            stat = Path(f"/proc/{descendant}/stat")
            if stat.exists():
                self.assertEqual(stat.read_text().split(") ", 1)[1].split()[0], "Z")
            self.assertIsNone(sentinel.poll())
        finally:
            try:
                cpu.stop(child)
            finally:
                cpu.stop(sentinel)
                if child is not None:
                    child.stdout.close()

    def test_real_child_file_output_cannot_exceed_its_quota(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output.log"
            with path.open("wb") as stream:
                with self.assertRaises(cpu.subprocess.CalledProcessError):
                    cpu.run_owned([sys.executable, "-c", "import os; os.write(1,b'x'*4096); os.write(1,b'y')"],
                                  timeout=5, file_limit=1024, stdout=stream, stderr=cpu.subprocess.DEVNULL)
            self.assertLessEqual(path.stat().st_size, 1024)


class SchedulerAccountingTests(unittest.TestCase):
    @staticmethod
    def stat(pid=123, start=900, threads=1):
        fields = [b"S"] + [b"0"] * 19
        fields[17], fields[19] = str(threads).encode(), str(start).encode()
        return str(pid).encode() + b" (name with ) and ( spaces) " + b" ".join(fields)

    def snapshot(self, values=None):
        values = [self.stat(), b"1000 200 5\n", self.stat()] if values is None else values
        with patch.object(cpu.sys, "platform", "linux"), \
                patch.object(cpu, "bounded_read", side_effect=values) as read, \
                patch.object(cpu.time, "monotonic_ns", side_effect=[10, 20]):
            result = cpu.scheduler_snapshot(123)
        return result, read

    def test_snapshot_brackets_exact_pid_and_bounded_reads(self):
        result, read = self.snapshot()
        self.assertTrue(result["available"])
        self.assertEqual((result["pid"], result["start_ticks"], result["threads"]), (123, 900, 1))
        self.assertEqual((result["runtime_ns"], result["runqueue_wait_ns"], result["timeslices"]), (1000, 200, 5))
        self.assertEqual(read.call_args_list, [unittest.mock.call(Path("/proc/123/stat"), 4096),
                                              unittest.mock.call(Path("/proc/123/schedstat"), 128),
                                              unittest.mock.call(Path("/proc/123/stat"), 4096)])

    def test_missing_denied_malformed_and_out_of_range_are_explicitly_unavailable(self):
        for value in (FileNotFoundError("missing"), PermissionError("denied"), b"bad stat",
                      self.stat(pid=124), self.stat(start=0), self.stat(threads=0)):
            with self.subTest(value=value):
                result, _ = self.snapshot([value])
                self.assertFalse(result["available"])
                self.assertIn("error_type", result)
        for raw in (b"1 2", b"1 2 3 4", b"1 -2 3", b"x 2 3", str(2**64).encode() + b" 2 3"):
            with self.subTest(raw=raw):
                result, _ = self.snapshot([self.stat(), raw])
                self.assertFalse(result["available"])

    def test_identity_change_during_snapshot_is_rejected(self):
        result, _ = self.snapshot([self.stat(), b"1000 200 5", self.stat(start=901)])
        self.assertFalse(result["available"])
        self.assertIn("identity changed", result["reason"])

    @staticmethod
    def readings():
        before = dict(available=True, pid=123, start_ticks=900, threads=1,
                      snapshot_started_ns=100, snapshot_finished_ns=110,
                      runtime_ns=1000, runqueue_wait_ns=200, timeslices=5)
        after = {**before, "snapshot_started_ns": 300, "snapshot_finished_ns": 310,
                 "runtime_ns": 1100, "runqueue_wait_ns": 220, "timeslices": 7}
        return before, after

    def test_delta_reports_separate_attached_thread_counters(self):
        result = cpu.scheduler_delta(*self.readings())
        self.assertTrue(result["available"])
        self.assertEqual((result["runtime_ns"], result["runqueue_wait_ns"], result["timeslices"]), (100, 20, 2))
        self.assertEqual(result["observation_envelope_ns"], 210)
        self.assertNotIn("ns_per_verified_operation", result)

    def test_delta_rejects_unavailable_identity_scope_regression_and_envelope(self):
        for changed in ({"available": False}, {"pid": 124}, {"start_ticks": 901}, {"threads": 2},
                        {"runtime_ns": 999}, {"runqueue_wait_ns": 199}, {"timeslices": 4},
                        {"snapshot_started_ns": 109}, {"runtime_ns": 2000}, {"runtime_ns": 1000}):
            with self.subTest(changed=changed):
                before, after = self.readings()
                after.update(changed)
                result = cpu.scheduler_delta(before, after)
                self.assertFalse(result["available"])
                self.assertNotIn("runtime_ns", result)
        before, after = self.readings()
        before["threads"] = after["threads"] = 2
        self.assertFalse(cpu.scheduler_delta(before, after)["available"])

    @unittest.skipUnless(sys.platform == "linux", "real proc snapshot requires Linux")
    def test_real_self_snapshot_is_bounded_and_identity_matches(self):
        result = cpu.scheduler_snapshot(os.getpid())
        if not result["available"] and result.get("error_type") in ("FileNotFoundError", "PermissionError"):
            self.skipTest(result["reason"])
        self.assertTrue(result["available"], result)
        self.assertEqual(result["pid"], os.getpid())
        self.assertGreaterEqual(result["runtime_ns"], 0)
        self.assertLessEqual(result["snapshot_started_ns"], result["snapshot_finished_ns"])


class RetentionTests(unittest.TestCase):
    def exercise(self, report, *, invalid=True, cleanup_errors=None, tail_error=None, mode="clean", timeline=None,
                 scheduler_snapshots=None):
        report = dict(report, warmup=cpu.WARMUP)
        timeline = [] if timeline is None else timeline
        native = Mock()
        native.server_resources.return_value = None
        replies = iter(["ready", "measured", json.dumps(report)])
        def line(*args):
            value = next(replies)
            timeline.append("read_report" if value.startswith("{") else value)
            return value
        native.control_line.side_effect = line
        native.validate_report.side_effect = ValueError("incomplete operations") if invalid else None
        def snapshot(*args):
            timeline.append("snapshot")
            return {"cpu_user_seconds": 0, "cpu_system_seconds": 0}
        native.snapshot.side_effect = snapshot
        native.cpu_cost.return_value = {"server": {"total_seconds": 1}, "client": {"total_seconds": 1}}
        server, client = MagicMock(), MagicMock()
        for child in (server, client):
            child.poll.return_value = None
            child.wait.return_value = 0
        client.stderr.read.return_value = "raw native failure\n"
        client.stdin.write.side_effect = lambda text: timeline.append(text.rstrip())
        profiler = Mock(returncode=255)
        profiler.wait.return_value = 255
        reserve, probe = MagicMock(), MagicMock()
        reserve.getsockname.return_value = ("127.0.0.1", 12345)
        probe.bind.side_effect = OSError("bound by fixture")
        reserve.__enter__.return_value = reserve
        probe.__enter__.return_value = probe
        original_scheduler = cpu.scheduler_snapshot
        snapshots = iter(scheduler_snapshots) if scheduler_snapshots is not None else None
        def scheduler(pid):
            if snapshots is None:
                return original_scheduler(pid)
            timeline.append("scheduler")
            return next(snapshots)
        with tempfile.TemporaryDirectory() as temporary:
            out = Path(temporary) / "window"
            with mock_record_control(timeline), patch.dict(sys.modules, {"psutil": Mock(), "native_diagnostic": native}), \
                    patch.object(cpu, "spawn", side_effect=[server, client, profiler]), \
                    patch.object(cpu, "stop", side_effect=cleanup_errors) as stop, \
                    patch.object(cpu, "stderr_tail", return_value=b"raw native failure\n", side_effect=tail_error), \
                    patch.object(cpu.socket, "socket", side_effect=[reserve, probe]), \
                    patch.object(cpu, "scheduler_snapshot", side_effect=scheduler), \
                    patch.object(cpu.os, "getloadavg", return_value=(0, 0, 0), create=True):
                result = cpu.window(Path("server"), Path("client"),
                                    ("oscore", 64, 100, "coaptic-reusable"), 10, out, mode=mode)
            self.assertEqual(json.loads((out / "client.json").read_text()), report)
            self.assertEqual(json.loads((out / "result.json").read_text()), json.loads(json.dumps(result)))
            self.assertEqual(result["report"], cpu.report_summary(report))
            self.assertNotIn("latencies_ns", result["report"])
            if not tail_error:
                self.assertIn("raw native failure", (out / "client.stderr").read_text())
            self.assertEqual(stop.call_args_list,
                             ([] if mode == "clean" else [unittest.mock.call(profiler, elevated=True)])
                             + [unittest.mock.call(client), unittest.mock.call(server)])
            if mode != "clean":
                self.assertEqual(json.loads((out / "perf.json").read_text()), result["perf"])
            self.assertNotIn("credentials", {p.name for p in out.iterdir()})
            command = client.stdin.write.call_args_list
            self.assertEqual([call.args[0] for call in command],
                             ["run\n", "report\n"] + ([] if invalid else ["exit\n"]))
            self.assertLessEqual((out / "result.json").stat().st_size, cpu.WINDOW_LIMIT)
            timeout = native.control_line.call_args_list[1].args[1]
            self.assertTrue(0 < timeout < 15 if mode == "record" else timeout == 60)
        return result

    def test_invalid_native_report_keeps_raw_bytes_and_stops_both_children(self):
        result = self.exercise(dict(completed=9, requested_operations=10, failure="body mismatch",
                                    latencies_ns=[1234] * 9))
        self.assertFalse(result["passed"])

    def test_client_and_server_cleanup_errors_do_not_skip_each_other_or_evidence(self):
        errors = [cpu.subprocess.TimeoutExpired("client", 5), RuntimeError("server stop failed")]
        result = self.exercise(dict(completed=9, failure="body mismatch"), cleanup_errors=errors,
                               tail_error=OSError("pipe unavailable"))
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertEqual([error["process"] for error in result["cleanup_errors"]], ["client", "server"])
        self.assertEqual(result["stderr_retention_error"], "OSError")
        self.assertEqual(result["reason"], "incomplete operations")

    def test_perf_cleanup_failure_survives_invalid_report_and_both_other_cleanup_failures(self):
        errors = [PermissionError("perf kill refused"), cpu.subprocess.TimeoutExpired("client", 5),
                  RuntimeError("server stop failed")]
        result = self.exercise(dict(completed=9, failure="body mismatch"), cleanup_errors=errors,
                               mode="record")
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertEqual(result["perf"]["cleanup_error"], "PermissionError")
        self.assertEqual([error["process"] for error in result["cleanup_errors"]], ["client", "server"])
        self.assertEqual(result["reason"], "incomplete operations")

    def test_perf_cleanup_failure_marks_otherwise_successful_window_fatal(self):
        result = self.exercise(dict(completed=10, latencies_ns=[1234] * 10), invalid=False,
                               cleanup_errors=[PermissionError("perf kill refused"), None, None], mode="record")
        self.assertFalse(result["passed"])
        self.assertTrue(result["cleanup_unresolved"])
        self.assertNotIn("cleanup_errors", result)

    def test_successful_window_keeps_samples_only_in_raw_report(self):
        result = self.exercise(dict(completed=10, latencies_ns=[123456789] * 10), invalid=False)
        self.assertTrue(result["passed"])
        self.assertNotIn("123456789", cpu.bounded_bytes(result, cpu.WINDOW_LIMIT).decode("ascii"))

    def test_record_enable_before_snapshots_and_finish_before_report(self):
        timeline = []
        self.exercise(dict(completed=10, latencies_ns=[12] * 10), invalid=False,
                      mode="record", timeline=timeline)
        self.assertEqual(timeline, ["ready", "enable_ack", "snapshot", "snapshot", "run", "measured",
                                    "snapshot", "snapshot", "disable_ack", "stop_ack", "report",
                                    "read_report", "exit"])

    def test_scheduler_snapshots_bracket_record_work_before_stop(self):
        timeline = []
        result = self.exercise(dict(completed=10, latencies_ns=[12] * 10), invalid=False,
                               mode="record", timeline=timeline,
                               scheduler_snapshots=SchedulerAccountingTests.readings())
        self.assertTrue(result["scheduler_delta"]["available"])
        self.assertEqual(timeline, ["ready", "enable_ack", "snapshot", "snapshot", "scheduler", "run", "measured",
                                    "snapshot", "snapshot", "scheduler", "disable_ack", "stop_ack", "report",
                                    "read_report", "exit"])

    def test_scheduler_unavailability_does_not_replace_existing_cpu_or_completion(self):
        result = self.exercise(dict(completed=10, latencies_ns=[12] * 10), invalid=False, mode="record",
                               scheduler_snapshots=[dict(available=False), dict(available=False)])
        self.assertTrue(result["passed"])
        self.assertFalse(result["scheduler_delta"]["available"])
        self.assertEqual(result["cpu_cost"]["server"]["total_seconds"], 1)

    def test_clean_and_stat_do_not_read_scheduler_counters(self):
        for mode in ("clean", "stat"):
            result = self.exercise(dict(completed=10, latencies_ns=[12] * 10), invalid=False,
                                   mode=mode, scheduler_snapshots=[])
            self.assertNotIn("scheduler_before", result)
            self.assertNotIn("scheduler_after", result)


if __name__ == "__main__":
    unittest.main()
